---
title: Responsible Disclosure
description: Ethically reporting discovered vulnerabilities, coordinating with security teams, navigating disclosure timelines, and maximizing positive impact while protecting yourself legally.
navigation:
  icon: i-lucide-handshake
  title: Responsible Disclosure
---

## What is Responsible Disclosure

::note
Responsible Disclosure is the **ethical framework** governing how security researchers communicate discovered vulnerabilities to affected organizations. It balances the researcher's duty to improve security with the vendor's need for time to develop and deploy fixes — all while minimizing risk to the users who remain exposed until a patch exists.
::

Responsible disclosure is not just a courtesy — it is the **foundation** upon which the entire bug bounty ecosystem is built. Without it, there is no trust between researchers and organizations. Without trust, there are no programs, no bounties, and no legal safe harbor for security research.

Every P1 you find, every exploit chain you build, every PoC you develop — none of it matters if you cannot disclose it **responsibly, professionally, and effectively**.

::callout{icon="i-lucide-handshake" color="blue"}
Responsible disclosure is a **skill** that separates professional security researchers from reckless actors. A well-executed disclosure process protects users, rewards the researcher, strengthens the vendor's security posture, and advances the entire security community.
::

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    DISCLOSURE LANDSCAPE                                  │
│                                                                          │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐            │
│  │   FULL         │  │  RESPONSIBLE   │  │  COORDINATED   │            │
│  │   DISCLOSURE   │  │  DISCLOSURE    │  │  DISCLOSURE    │            │
│  │                │  │                │  │                │            │
│  │  Publish       │  │  Report to     │  │  Report to     │            │
│  │  immediately   │  │  vendor with   │  │  vendor via    │            │
│  │  without       │  │  reasonable    │  │  coordinator   │            │
│  │  vendor        │  │  fix timeline  │  │  (CERT, MITRE) │            │
│  │  contact       │  │  before public │  │  with agreed   │            │
│  │                │  │  disclosure    │  │  timeline      │            │
│  │  Risk: HIGH    │  │  Risk: LOW     │  │  Risk: LOWEST  │            │
│  │  Legal: BAD    │  │  Legal: GOOD   │  │  Legal: BEST   │            │
│  │  Ethics: POOR  │  │  Ethics: GOOD  │  │  Ethics: BEST  │            │
│  └────────────────┘  └────────────────┘  └────────────────┘            │
│                              ▲                                          │
│                              │                                          │
│                    THIS IS WHAT WE DO                                   │
│                                                                          │
│  Key Principles:                                                        │
│  ───────────────                                                        │
│  1. Report to the vendor FIRST, always                                  │
│  2. Give reasonable time to fix (typically 90 days)                     │
│  3. Do not access data beyond what's needed for proof                  │
│  4. Do not disrupt services or access real user data                   │
│  5. Do not leverage vulnerabilities for any purpose beyond reporting   │
│  6. Maintain confidentiality until fix is deployed or deadline passes  │
│  7. Coordinate public disclosure timing with the vendor                │
└──────────────────────────────────────────────────────────────────────────┘
```

### Why Responsible Disclosure Matters

::card-group
  ::card
  ---
  title: Protects Real Users
  icon: i-lucide-shield-check
  ---
  Millions of users depend on vulnerable systems daily. Responsible disclosure gives vendors time to patch **before attackers can exploit** the same vulnerabilities, directly preventing real-world breaches, financial losses, and privacy violations.
  ::

  ::card
  ---
  title: Legal Protection for You
  icon: i-lucide-scale
  ---
  Following responsible disclosure processes provides **legal safe harbor** under programs like bug bounties, the CFAA safe harbor provisions, and the DOJ's 2022 charging policy. Irresponsible disclosure can result in criminal prosecution.
  ::

  ::card
  ---
  title: Builds Your Reputation
  icon: i-lucide-trophy
  ---
  Top researchers are known not just for what they find, but **how they disclose**. Professional disclosure builds trust with programs, earns invitations to private programs, gets you featured in Halls of Fame, and opens career opportunities.
  ::

  ::card
  ---
  title: Strengthens the Ecosystem
  icon: i-lucide-globe
  ---
  Every responsible disclosure demonstrates that **security research is a force for good**. This encourages more organizations to launch bug bounty programs, increases bounty payouts industry-wide, and normalizes the researcher-vendor relationship.
  ::
::

---

## The Disclosure Lifecycle

::tip
Every responsible disclosure follows a structured lifecycle from discovery through public disclosure. Understanding each phase and its requirements is essential.
::

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    DISCLOSURE LIFECYCLE                                      │
│                                                                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐         │
│  │DISCOVERY│─▶│DOCUMENT │─▶│ REPORT  │─▶│COORDIN- │─▶│ PUBLIC  │         │
│  │         │  │         │  │         │  │  ATE    │  │DISCLOSE │         │
│  │ Find &  │  │ Build   │  │ Submit  │  │ Work    │  │ Share   │         │
│  │ verify  │  │ PoC &   │  │ to      │  │ with    │  │ with    │         │
│  │ the     │  │ evidence│  │ vendor  │  │ vendor  │  │ the     │         │
│  │ vuln    │  │ package │  │ / prog  │  │ on fix  │  │ world   │         │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘         │
│       │            │            │             │             │               │
│    Day 0        Day 0-2      Day 1-3      Day 3-90      Day 90+           │
│                                                                              │
│  Critical checkpoints:                                                      │
│  ─────────────────────                                                      │
│  ✓ Verify vuln is real (not false positive)                                │
│  ✓ Minimize data access during testing                                      │
│  ✓ Document everything with timestamps                                      │
│  ✓ Report via official channels only                                        │
│  ✓ Respond promptly to vendor questions                                     │
│  ✓ Allow reasonable fix timeline                                            │
│  ✓ Coordinate public disclosure timing                                      │
│  ✓ Credit the vendor's security team in writeup                            │
└──────────────────────────────────────────────────────────────────────────────┘
```

::steps{level="4"}

#### Phase 1 — Discovery & Verification

Confirm the vulnerability is real, reproducible, and impactful before initiating disclosure.

```bash
# ═══════════════════════════════════════════
# PRE-DISCLOSURE VERIFICATION CHECKLIST
# ═══════════════════════════════════════════

# 1. Verify the vulnerability is real (not a false positive)
# Run the exploit multiple times to confirm consistency
for i in $(seq 1 3); do
  echo "=== Attempt $i ==="
  curl -s "https://target.com/api/vulnerable?param=PAYLOAD" \
    -H "Authorization: Bearer TOKEN" | head -c 500
  echo ""
  sleep 2
done

# 2. Verify it's within scope
echo "=== Scope Verification ==="
echo "Check program policy for:"
echo "  - Is this domain in scope? $(echo target.com)"
echo "  - Is this vulnerability type in scope?"
echo "  - Are there any exclusions that apply?"
echo "  - Is this a known/accepted risk listed in the policy?"

# 3. Verify it's not a duplicate (check public disclosures)
echo "=== Duplicate Check ==="
# Search for existing reports
curl -s "https://hackerone.com/reports?q=target.com+xss" 2>/dev/null | head -5
# Check CVE databases
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=target.com" 2>/dev/null | \
  jq '.totalResults' 2>/dev/null

# 4. Confirm the impact is accurately assessed
echo "=== Impact Verification ==="
# Test without auth
curl -s -o /dev/null -w "No auth: %{http_code}\n" \
  "https://target.com/api/vulnerable"
# Test with different user roles
curl -s -o /dev/null -w "User role: %{http_code}\n" \
  "https://target.com/api/vulnerable" -H "Authorization: Bearer USER_TOKEN"
curl -s -o /dev/null -w "Admin role: %{http_code}\n" \
  "https://target.com/api/vulnerable" -H "Authorization: Bearer ADMIN_TOKEN"

# 5. Ensure you haven't caused any damage
echo "=== Damage Assessment ==="
echo "Verify:"
echo "  ✓ No real user data was accessed"
echo "  ✓ No service disruption occurred"
echo "  ✓ No data was modified or deleted"
echo "  ✓ Testing was proportionate and minimally invasive"
echo "  ✓ Only your own test accounts were used for write/delete tests"
```

#### Phase 2 — Documentation & Evidence Preparation

Build a complete, professional evidence package before submitting.

```bash
# ═══════════════════════════════════════════
# EVIDENCE COLLECTION & PACKAGING
# ═══════════════════════════════════════════

REPORT_DIR="disclosure_$(date +%Y%m%d)_target"
mkdir -p "${REPORT_DIR}/evidence"

# 1. Capture timestamped HTTP evidence
echo "=== Capturing HTTP Evidence ==="

# Full verbose request/response
curl -v -X POST "https://target.com/api/vulnerable" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"param":"PAYLOAD"}' \
  2>&1 | tee "${REPORT_DIR}/evidence/http_full.txt"

# Add timestamp header
echo "Capture timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> \
  "${REPORT_DIR}/evidence/http_full.txt"

# 2. Generate reproducible curl commands
cat << 'REPRO' > "${REPORT_DIR}/evidence/reproduction_steps.sh"
#!/bin/bash
# Reproduction Steps
# Target: target.com
# Vulnerability: [TYPE]
# Date: $(date -u)
# Researcher: [YOUR_HANDLE]

echo "Step 1: [Description]"
curl -s -X POST "https://target.com/api/vulnerable" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"param":"PAYLOAD"}'

echo ""
echo "Step 2: [Description]"
curl -s "https://target.com/api/verify-impact" \
  -H "Authorization: Bearer TOKEN"

echo ""
echo "Expected: [What the vulnerable response looks like]"
echo "Normal:   [What a non-vulnerable response looks like]"
REPRO

# 3. Capture screenshots (headless browser)
echo "=== Capturing Screenshots ==="
chromium --headless --screenshot="${REPORT_DIR}/evidence/step1_injection.png" \
  --window-size=1920,1080 \
  "https://target.com/vulnerable?param=PAYLOAD" 2>/dev/null

# 4. Record terminal session
echo "=== Recording Terminal Session ==="
asciinema rec "${REPORT_DIR}/evidence/exploitation_demo.cast" << 'SESSION'
echo "=== Vulnerability Demonstration ==="
echo "Step 1: Inject payload..."
curl -s "https://target.com/api/vulnerable?param=PAYLOAD"
echo ""
echo "Step 2: Verify impact..."
curl -s "https://target.com/api/impact-proof"
echo ""
echo "=== Demonstration Complete ==="
SESSION

# 5. Create evidence hash for integrity
echo "=== Evidence Integrity Hash ==="
find "${REPORT_DIR}/evidence/" -type f -exec sha256sum {} \; > \
  "${REPORT_DIR}/evidence/evidence_hashes.sha256"
echo "Evidence hashes:"
cat "${REPORT_DIR}/evidence/evidence_hashes.sha256"

# 6. Redact sensitive information
echo "=== Redacting Sensitive Data ==="
# Redact real user data in evidence files
sed -i 's/[a-zA-Z0-9._%+-]\+@[a-zA-Z0-9.-]\+\.[a-zA-Z]\{2,\}/[REDACTED_EMAIL]/g' \
  "${REPORT_DIR}/evidence/"*.txt
# Redact phone numbers
sed -i 's/\+\?[0-9]\{10,15\}/[REDACTED_PHONE]/g' \
  "${REPORT_DIR}/evidence/"*.txt
# Keep enough visible to prove data type
echo "NOTE: Data redacted to protect user privacy."
echo "Original unredacted evidence available upon request from security team."
```

#### Phase 3 — Report Submission

Submit through the correct channels with a professional, complete report.

```bash
# ═══════════════════════════════════════════
# FINDING THE RIGHT REPORTING CHANNEL
# ═══════════════════════════════════════════

TARGET_DOMAIN="target.com"

echo "=== Finding Official Reporting Channels ==="

# Method 1: Check security.txt (RFC 9116)
echo "--- security.txt ---"
curl -s "https://${TARGET_DOMAIN}/.well-known/security.txt" 2>/dev/null
curl -s "https://${TARGET_DOMAIN}/security.txt" 2>/dev/null

# Method 2: Check for bug bounty program
echo "--- Bug Bounty Programs ---"
echo "HackerOne: https://hackerone.com/${TARGET_DOMAIN%%.*}"
echo "Bugcrowd: https://bugcrowd.com/${TARGET_DOMAIN%%.*}"
echo "Intigriti: https://app.intigriti.com/programs/${TARGET_DOMAIN%%.*}"
echo "YesWeHack: https://yeswehack.com/programs/${TARGET_DOMAIN%%.*}"

# Method 3: Check responsible disclosure page
echo "--- Disclosure Pages ---"
for path in /security /responsible-disclosure /vulnerability-disclosure \
  /bug-bounty /report-vulnerability /coordinated-disclosure \
  /security/vulnerability-disclosure /.well-known/security.txt; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://${TARGET_DOMAIN}${path}" --max-time 5)
  [ "$STATUS" = "200" ] && echo "[FOUND] https://${TARGET_DOMAIN}${path}"
done

# Method 4: Find security contact via DNS
echo "--- DNS Records ---"
dig TXT "_dmarc.${TARGET_DOMAIN}" +short
dig TXT "${TARGET_DOMAIN}" +short | grep -i "security\|vulnerability\|report"

# Method 5: WHOIS for abuse/security contacts
echo "--- WHOIS ---"
whois "$TARGET_DOMAIN" | grep -iE "abuse|security|contact" | head -5

# Method 6: Common security email addresses
echo "--- Common Email Addresses ---"
echo "security@${TARGET_DOMAIN}"
echo "abuse@${TARGET_DOMAIN}"
echo "cert@${TARGET_DOMAIN}"
echo "vulnerability@${TARGET_DOMAIN}"
echo "responsible-disclosure@${TARGET_DOMAIN}"
echo "bugbounty@${TARGET_DOMAIN}"
echo "infosec@${TARGET_DOMAIN}"

# Verify email addresses exist (MX check)
for prefix in security abuse cert vulnerability responsible-disclosure bugbounty; do
  MX=$(dig MX "${TARGET_DOMAIN}" +short | head -1)
  [ -n "$MX" ] && echo "  ${prefix}@${TARGET_DOMAIN} — MX exists: $MX"
done
```

#### Phase 4 — Coordination & Follow-up

Work with the vendor throughout the remediation process.

```bash
# ═══════════════════════════════════════════
# COORDINATION TRACKING
# ═══════════════════════════════════════════

# Create a tracking document for the disclosure
cat << 'TRACKER' > "${REPORT_DIR}/disclosure_tracker.md"
# Disclosure Tracking Document

## Vulnerability Summary
- **Type:** [Vulnerability class]
- **Target:** [Affected system/endpoint]
- **Severity:** [P1/P2/P3 with CVSS]
- **Researcher:** [Your handle]

## Timeline
| Date | Action | Status |
|------|--------|--------|
| YYYY-MM-DD | Vulnerability discovered | ✅ |
| YYYY-MM-DD | Vulnerability verified | ✅ |
| YYYY-MM-DD | Report submitted via [channel] | ✅ |
| YYYY-MM-DD | Vendor acknowledged receipt | ⏳ |
| YYYY-MM-DD | Vendor confirmed vulnerability | ⏳ |
| YYYY-MM-DD | Vendor requests more info | ⏳ |
| YYYY-MM-DD | Additional info provided | ⏳ |
| YYYY-MM-DD | Fix deployed to staging | ⏳ |
| YYYY-MM-DD | Fix deployed to production | ⏳ |
| YYYY-MM-DD | Bounty awarded | ⏳ |
| YYYY-MM-DD | Public disclosure agreed | ⏳ |
| YYYY-MM-DD | CVE assigned | ⏳ |
| YYYY-MM-DD | Public writeup published | ⏳ |

## Communication Log
| Date | From | To | Summary |
|------|------|----|---------|
| | | | |

## Notes
- 90-day disclosure deadline: YYYY-MM-DD
- Vendor communication quality: [Rating]
- Follow-up needed: [Yes/No]
TRACKER

echo "Tracking document created: ${REPORT_DIR}/disclosure_tracker.md"
echo "Update this document at every communication milestone."
```

#### Phase 5 — Public Disclosure

Share your findings with the community after the fix is deployed.

```bash
# ═══════════════════════════════════════════
# PUBLIC DISCLOSURE PREPARATION
# ═══════════════════════════════════════════

# Verify fix is deployed before public disclosure
echo "=== Fix Verification ==="
curl -s "https://target.com/api/previously-vulnerable?param=PAYLOAD" \
  -H "Authorization: Bearer TOKEN" | head -c 200
echo ""
echo "Expected: The vulnerability should no longer be exploitable"
echo "If still exploitable, DO NOT publicly disclose"

# Create public writeup (sanitized)
cat << 'WRITEUP' > "${REPORT_DIR}/public_writeup.md"
# [Vulnerability Type] in [Target] — Responsible Disclosure

## Summary
[Brief description without sensitive details that could harm users
who haven't updated yet]

## Timeline
- **Discovery:** YYYY-MM-DD
- **Report Submitted:** YYYY-MM-DD
- **Vendor Response:** YYYY-MM-DD
- **Fix Deployed:** YYYY-MM-DD
- **Public Disclosure:** YYYY-MM-DD (this post)

## Technical Details
[Technical description of the vulnerability and exploitation technique.
Include enough detail for educational value but sanitize any
target-specific information that could be used against unpatched systems]

## Impact
[Description of what an attacker could achieve]

## Remediation
[How the vendor fixed the issue]

## Acknowledgments
Thanks to the [Target] security team for their professional response
and timely remediation.

## Bounty
[Amount if you choose to disclose, or "Rewarded" if you prefer privacy]

## Lessons Learned
[What other researchers can learn from this finding]
WRITEUP

echo "Public writeup template created."
echo "IMPORTANT: Get vendor approval before publishing."
echo "IMPORTANT: Verify all user data is redacted."
echo "IMPORTANT: Ensure the fix is fully deployed across all environments."
```

::

---

## Report Writing for Maximum Impact

::badge
Critical Skill
::

### The Anatomy of a Perfect Vulnerability Report

::note
The quality of your report directly determines: how quickly it's triaged, whether the severity is correctly assessed, how much bounty you receive, and whether the vendor can actually fix the issue. A perfect report answers every question the security team might ask before they ask it.
::

::accordion
  ::accordion-item
  ---
  icon: i-lucide-file-text
  label: Report Structure & Template
  ---

  ```
  ═══════════════════════════════════════════════════════════
  VULNERABILITY REPORT TEMPLATE
  ═══════════════════════════════════════════════════════════

  ## Title
  [Specific, descriptive title that identifies the vulnerability type,
  location, and impact in one sentence]

  GOOD: "IDOR on /api/v2/users/{id}/profile allows any authenticated 
        user to read PII of all 2.3M users including email, phone, 
        and payment data"
  
  BAD:  "IDOR vulnerability found"
  BAD:  "Security issue in user API"

  ─────────────────────────────────────────────────────────

  ## Severity Assessment
  
  Severity: P1 / Critical
  CVSS v3.1: 9.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)
  Vector: https://www.first.org/cvss/calculator/3.1#CVSS:3.1/...
  
  Justification:
  - Network accessible (AV:N)
  - No special conditions required (AC:L)
  - Any authenticated user can exploit (PR:L)
  - No user interaction required (UI:N)
  - Full confidentiality impact (C:H) — all user PII accessible
  - Full integrity impact (I:H) — user data modifiable
  - No availability impact (A:N) — service remains operational

  ─────────────────────────────────────────────────────────

  ## Affected Asset
  
  - Domain: target.com
  - Endpoint: POST /api/v2/users/{id}/profile
  - Parameter: {id} path parameter
  - Authentication: Bearer token (any user role)
  - Environment: Production

  ─────────────────────────────────────────────────────────

  ## Description
  
  [2-3 paragraphs explaining:]
  - What the vulnerability is (technical root cause)
  - Where it exists (specific code path / endpoint)
  - Why it's dangerous (what security control is missing)
  - Who is affected (user population, data types)

  ─────────────────────────────────────────────────────────

  ## Steps to Reproduce
  
  Prerequisites:
  - Two accounts on target.com (Account A: attacker, Account B: victim)
  - Account A token: obtained via normal login
  - Account B user ID: obtained from [explain how]

  Step 1: Authenticate as Account A
  [curl command]

  Step 2: Request Account B's profile using Account A's token
  [curl command]

  Step 3: Observe that Account B's full PII is returned
  [expected output with sensitive data redacted]

  Step 4: (Impact escalation) Modify Account B's email
  [curl command]

  ─────────────────────────────────────────────────────────

  ## Proof of Concept
  
  [Working exploit code / script]

  ─────────────────────────────────────────────────────────

  ## Impact Statement
  
  [Detailed impact analysis with quantified blast radius]

  ─────────────────────────────────────────────────────────

  ## Suggested Remediation
  
  [Specific, actionable fix recommendation]

  ─────────────────────────────────────────────────────────

  ## Evidence
  
  [Screenshots, HTTP logs, video, hashes]

  ─────────────────────────────────────────────────────────

  ## References
  
  [OWASP, CWE, related CVEs, similar public reports]
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-pen
  label: Writing Effective Titles
  ---

  The title is the **first thing** a triager reads. It determines whether your report gets immediate attention or sits in a queue.

  **Title Formula:**
  ```
  [Vulnerability Type] in [Location] allows [Actor] to [Action] [Impact Scope]
  ```

  **Examples by severity:**

  | Severity | Title |
  | --- | --- |
  | P1 | `SQL Injection in /api/search allows unauthenticated attacker to dump entire user database (2.3M records with credentials)` |
  | P1 | `Authentication bypass via JWT algorithm confusion grants admin access to any user without credentials` |
  | P1 | `SSRF in /api/proxy enables access to AWS metadata service, leaking IAM credentials with S3 and RDS access` |
  | P1 | `RCE via SSTI in email template rendering allows arbitrary command execution as www-data` |
  | P2 | `Stored XSS in comment field enables session theft and account takeover of any user viewing the post` |
  | P2 | `IDOR on /api/users/{id}/documents allows any authenticated user to download confidential files of other users` |
  | P2 | `Race condition in coupon redemption allows single-use codes to be applied unlimited times (financial impact)` |
  | P2 | `OAuth redirect_uri validation bypass enables one-click account takeover via token theft` |

  **Avoid:**
  - `XSS found` — too vague
  - `Critical vulnerability!!!` — no information
  - `Bug in login page` — undescriptive
  - `Multiple vulnerabilities in target.com` — never combine reports
  ::

  ::accordion-item
  ---
  icon: i-lucide-list-ordered
  label: Writing Clear Reproduction Steps
  ---

  Reproduction steps must be **exact, numbered, and copy-pasteable**. A triager should be able to reproduce your finding in under 5 minutes without asking any questions.

  ```bash
  # GOOD reproduction steps — specific, numbered, with exact commands

  # Prerequisites:
  # - Two accounts on target.com
  # - Account A (attacker): attacker@test.com / TestPass123
  # - Account B (victim): victim@test.com / TestPass456

  # Step 1: Login as Account A and obtain authentication token
  ATTACKER_TOKEN=$(curl -s -X POST "https://target.com/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@test.com","password":"TestPass123"}' | \
    jq -r '.token')
  echo "Attacker token: $ATTACKER_TOKEN"

  # Step 2: Login as Account B and note the user ID
  VICTIM_RESPONSE=$(curl -s -X POST "https://target.com/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@test.com","password":"TestPass456"}')
  VICTIM_ID=$(echo "$VICTIM_RESPONSE" | jq -r '.user.id')
  echo "Victim user ID: $VICTIM_ID"

  # Step 3: Using Account A's token, request Account B's profile
  curl -s "https://target.com/api/v2/users/${VICTIM_ID}/profile" \
    -H "Authorization: Bearer $ATTACKER_TOKEN" | jq '.'

  # Step 4: Observe the response contains Account B's full PII
  # Expected output:
  # {
  #   "id": "VICTIM_ID",
  #   "email": "victim@test.com",      ← Should NOT be visible to Account A
  #   "phone": "+1234567890",           ← Should NOT be visible to Account A  
  #   "address": "123 Main St...",      ← Should NOT be visible to Account A
  #   "ssn_last_four": "1234",          ← Should NOT be visible to Account A
  #   "payment_methods": [...]          ← Should NOT be visible to Account A
  # }

  # Step 5 (Impact Escalation): Modify Account B's email using Account A's token
  curl -s -X PUT "https://target.com/api/v2/users/${VICTIM_ID}/profile" \
    -H "Authorization: Bearer $ATTACKER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker-controlled@evil.com"}'

  # Expected: Account B's email is now changed to attacker-controlled address
  # This enables full account takeover via password reset

  # Normal behavior comparison:
  # When Account A requests its OWN profile → HTTP 200 with Account A's data ✓
  # When Account A requests Account B's profile → Should return HTTP 403 ✗
  # ACTUAL: Returns HTTP 200 with Account B's complete data ← VULNERABILITY
  ```

  ```bash
  # BAD reproduction steps — vague, missing details

  # 1. Login to the site
  # 2. Go to the user profile API
  # 3. Change the user ID
  # 4. You can see other users' data
  #
  # This tells the triager nothing useful.
  # They don't know which API, which parameter, what credentials to use,
  # or what the expected vs actual behavior is.
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-trending-up
  label: Writing Impact Statements
  ---

  The impact statement is what **determines your bounty amount**. It must be specific, quantified, and demonstrate real-world consequences.

  ```bash
  # Impact statement framework
  cat << 'IMPACT'
  ## Impact

  ### What can the attacker do?
  An authenticated user (any role) can access and modify the complete 
  profile data of ANY other user on the platform by manipulating the 
  user ID in the API request path. No special privileges or user 
  interaction is required.

  ### Who is affected?
  - **Total users at risk:** 2,347,891 (verified via pagination API)
  - **User roles affected:** All roles including administrators
  - **Geographic scope:** Users in 47 countries
  - **EU users (GDPR):** ~892,000 users
  - **California users (CCPA):** ~234,000 users

  ### What data is exposed?
  Each user record contains:
  - **Critical:** Password hash (bcrypt), API tokens, OAuth credentials
  - **High:** Email address, phone number, physical address, date of birth
  - **Medium:** Full name, purchase history, IP address log
  - **Record size:** ~2.4 KB per user
  - **Total data at risk:** ~5.6 GB

  ### What is the business impact?
  - **Data breach cost:** $164/record × 2.3M records = ~$377M (IBM benchmark)
  - **GDPR fine exposure:** Up to 4% of global annual revenue or €20M
  - **CCPA fine exposure:** Up to $7,500 × 234,000 = ~$1.75B (intentional)
  - **Extraction timeline:** Full database extractable in ~13 hours at 
    observed rate of 50 records/second (no rate limiting detected)

  ### Exploitation complexity
  - **Attack vector:** Network (any internet user)
  - **Complexity:** Low (single HTTP request)
  - **Privileges required:** Low (any authenticated user)
  - **User interaction:** None
  - **Fully automatable:** Yes
  IMPACT
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-wrench
  label: Writing Remediation Recommendations
  ---

  Providing actionable remediation shows professionalism and helps the vendor fix the issue faster.

  ```bash
  # Remediation recommendation examples by vulnerability class

  cat << 'REMEDIATION'
  ## Suggested Remediation

  ### For IDOR:
  Implement server-side authorization checks on every API endpoint 
  that accesses user-specific resources. Verify that the authenticated 
  user's ID matches the requested resource's owner ID before returning 
  or modifying data.

  Example (pseudocode):
  ```
  function getUserProfile(request, userId):
      authenticatedUser = getAuthenticatedUser(request)
      if authenticatedUser.id != userId AND authenticatedUser.role != 'admin':
          return 403 Forbidden
      return getUserData(userId)
  ```

  Additional recommendations:
  1. Implement rate limiting on user data endpoints (10 req/min)
  2. Add audit logging for cross-user data access attempts
  3. Replace sequential integer IDs with UUIDs to prevent enumeration
  4. Conduct authorization testing across all API endpoints
  5. Consider implementing an API gateway with centralized authz checks

  ### For XSS:
  1. Implement output encoding using context-appropriate functions:
     - HTML context: HTML entity encoding
     - JavaScript context: JavaScript Unicode encoding
     - URL context: URL percent encoding
     - CSS context: CSS hex encoding
  2. Deploy Content Security Policy (CSP) header:
     Content-Security-Policy: default-src 'self'; script-src 'self'
  3. Set HttpOnly and Secure flags on session cookies
  4. Implement DOMPurify for any user-generated HTML rendering
  5. Use templating engines with auto-escaping enabled by default

  ### For SQLi:
  1. Replace string concatenation with parameterized queries/prepared statements
  2. Implement input validation with allowlists (not blocklists)
  3. Apply principle of least privilege to database user accounts
  4. Deploy WAF rules as defense-in-depth (not primary fix)
  5. Enable database query logging for anomaly detection
  REMEDIATION
  ```
  ::
::

### Report Quality Comparison

::tabs
  ::tabs-item{icon="i-lucide-x-circle" label="Bad Report Example"}

  ```
  Title: XSS on target.com

  I found XSS on your website.

  URL: https://target.com/search?q=<script>alert(1)</script>

  Please fix.

  ─────────────────────────────
  Problems with this report:
  ─────────────────────────────
  ✗ Vague title — doesn't specify location, impact, or scope
  ✗ No severity assessment or CVSS score
  ✗ No description of the vulnerability root cause
  ✗ No numbered reproduction steps
  ✗ No evidence (screenshots, HTTP logs, video)
  ✗ Minimal impact — alert(1) demonstrates nothing
  ✗ No remediation suggestion
  ✗ No comparison of expected vs actual behavior
  ✗ No information about affected user population
  ✗ Tone is unprofessional
  
  Result: Likely triaged as Low/Informational, minimal bounty,
          slow response, possible duplicate classification
  ```
  ::

  ::tabs-item{icon="i-lucide-check-circle" label="Good Report Example"}

  ```
  Title: Reflected XSS in /search endpoint via 'q' parameter 
         enables session hijacking and account takeover of any user
         (HttpOnly flag absent on session cookie)

  ## Severity
  P2 / High
  CVSS: 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)
  
  ## Affected Asset
  - Endpoint: GET https://target.com/search?q=[PAYLOAD]
  - Parameter: q (query string)
  - Authentication: Not required for injection
  - Affected users: Any user who clicks a crafted link

  ## Description
  The search functionality at /search reflects the 'q' parameter 
  value directly into the HTML response without encoding or 
  sanitization. The application does not implement a Content 
  Security Policy (CSP) header, and the session cookie lacks 
  the HttpOnly flag, making it accessible to JavaScript.
  
  This combination allows an attacker to:
  1. Inject arbitrary JavaScript via the q parameter
  2. Steal the victim's session cookie
  3. Replay the session to fully impersonate the victim
  4. Change the victim's email and trigger a password reset
  5. Achieve permanent account takeover

  ## Steps to Reproduce
  [Detailed numbered steps with curl commands...]

  ## Proof of Concept
  [Working exploit code with cookie theft + ATO chain...]

  ## Impact
  [Quantified impact with user population, data at risk,
   financial exposure, and regulatory implications...]

  ## Evidence
  - Screenshot 1: Payload injected and executing (attached)
  - Screenshot 2: Cookie stolen on attacker server (attached)
  - Screenshot 3: Session replayed, victim's profile accessed (attached)
  - HTTP Log: Full request/response chain (attached)
  - Video: Complete exploitation demo (attached, 2min)

  ## Suggested Remediation
  1. HTML-encode all output from the 'q' parameter
  2. Implement CSP: default-src 'self'; script-src 'self'
  3. Add HttpOnly flag to session cookies
  4. Add SameSite=Strict to session cookies

  ## References
  - CWE-79: Improper Neutralization of Input During Web Page Generation
  - OWASP XSS Prevention Cheat Sheet

  ─────────────────────────────────────────
  Result: Triaged within hours as P2/High, full bounty awarded,
          vendor grateful for complete report, invited to private programs
  ```
  ::
::

---

## Platform-Specific Disclosure Processes

::badge
Practical Guide
::

### Bug Bounty Platform Workflows

::tabs
  ::tabs-item{icon="i-lucide-shield" label="HackerOne"}

  ```bash
  # ═══════════════════════════════════════════
  # HACKERONE DISCLOSURE WORKFLOW
  # ═══════════════════════════════════════════

  # Report submission checklist for HackerOne
  echo "=== HackerOne Report Checklist ==="
  echo ""
  echo "Before submitting:"
  echo "  ✓ Read the program policy completely"
  echo "  ✓ Check scope — is this asset/vuln type in scope?"
  echo "  ✓ Check for excluded vulnerability types"
  echo "  ✓ Check program's response SLA targets"
  echo "  ✓ Search for existing reports (avoid duplicates)"
  echo ""
  echo "Report fields:"
  echo "  ✓ Title: [Type] in [Location] allows [Impact]"
  echo "  ✓ Severity: Select appropriate rating"
  echo "  ✓ Weakness: Select CWE from dropdown"
  echo "  ✓ Asset: Select the specific asset/domain"
  echo "  ✓ Description: Full technical details"
  echo "  ✓ Steps to reproduce: Numbered, exact steps"
  echo "  ✓ Impact: Quantified impact statement"
  echo "  ✓ Attachments: Screenshots, HTTP logs, PoC scripts"
  echo ""
  echo "After submitting:"
  echo "  ✓ Monitor for triager questions (respond within 24h)"
  echo "  ✓ Don't submit additional reports for the same vuln"
  echo "  ✓ Don't publicly discuss until resolved + agreed"
  echo "  ✓ Update report if you find additional impact"
  echo ""
  echo "HackerOne report states:"
  echo "  New → Triaged → Needs More Info → Bounty → Resolved → Disclosed"
  echo ""
  echo "Mediation:"
  echo "  If you disagree with severity/bounty/decision:"
  echo "  - Comment professionally explaining your reasoning"
  echo "  - If unresolved, request HackerOne mediation"
  echo "  - Never threaten public disclosure as leverage"

  # HackerOne API for tracking reports (if using API)
  # curl -s "https://api.hackerone.com/v1/me/reports" \
  #   -u "username:api_token" | jq '.data[] | {id, title, state}'
  ```

  **HackerOne-specific tips:**

  - Use **Markdown formatting** in reports for readability
  - Attach evidence as **separate files**, not inline base64
  - Use the **CVSS calculator** built into the submission form
  - If the program has a **custom severity scale**, use their scale
  - Always select the correct **asset** from the dropdown
  - Use the **collaboration feature** if working with other researchers
  - Request **CVE assignment** through HackerOne if applicable
  - Use **disclosure request** feature for public writeup approval
  ::

  ::tabs-item{icon="i-lucide-bug" label="Bugcrowd"}

  ```bash
  # ═══════════════════════════════════════════
  # BUGCROWD DISCLOSURE WORKFLOW
  # ═══════════════════════════════════════════

  echo "=== Bugcrowd Report Checklist ==="
  echo ""
  echo "Bugcrowd-specific considerations:"
  echo "  ✓ Check VRT (Vulnerability Rating Taxonomy) for severity mapping"
  echo "  ✓ Use Bugcrowd's severity scale (P1-P5)"
  echo "  ✓ Follow the program's 'Target' definitions carefully"
  echo "  ✓ Check for 'Out of Scope' items in brief"
  echo ""
  echo "Bugcrowd severity mapping (VRT):"
  echo "  P1: Server compromise, significant data breach, financial"
  echo "  P2: Accessing significant data, serious user impact"
  echo "  P3: Accessing limited data, limited impact"
  echo "  P4: Minor data exposure, minimal impact"
  echo "  P5: Informational, no direct impact"
  echo ""
  echo "Report fields:"
  echo "  ✓ Title: Descriptive and specific"
  echo "  ✓ Target: Select the correct target/asset"
  echo "  ✓ VRT Classification: Select the matching VRT entry"
  echo "  ✓ URL/Location: Exact endpoint"
  echo "  ✓ Description: Full details with reproduction steps"
  echo "  ✓ HTTP Request/Response: Include full HTTP interactions"
  echo "  ✓ Attachments: Evidence files"
  echo ""
  echo "Bugcrowd report states:"
  echo "  Unvalidated → Triaged → Priority → Won't Fix → Resolved"
  echo ""
  echo "Key differences from HackerOne:"
  echo "  - Bugcrowd uses its own VRT for classification"
  echo "  - Triage is handled by Bugcrowd's Application Security Engineers"
  echo "  - Response times may differ from program SLA"
  echo "  - Kudos points system in addition to bounties"
  ```
  ::

  ::tabs-item{icon="i-lucide-mail" label="Direct to Vendor"}

  ```bash
  # ═══════════════════════════════════════════
  # DIRECT VENDOR DISCLOSURE WORKFLOW
  # (No bug bounty program exists)
  # ═══════════════════════════════════════════

  echo "=== Direct Vendor Disclosure Process ==="
  echo ""
  echo "When no bug bounty program exists, follow this process:"
  echo ""
  echo "Step 1: Find the security contact"
  # Check security.txt
  curl -s "https://target.com/.well-known/security.txt"
  # Check for security page
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/security"
  # Last resort: general contact
  echo "  Try: security@target.com"
  echo "  Try: Contact form on website"
  echo "  Try: LinkedIn message to CISO/Security team"

  echo ""
  echo "Step 2: Send initial notification"

  cat << 'EMAIL_TEMPLATE'
  Subject: Security Vulnerability Report — [Brief Description]

  Dear [Target] Security Team,

  I am an independent security researcher. During authorized testing,
  I discovered a security vulnerability affecting [target.com/product]
  that I would like to report responsibly.

  **Summary:** [One sentence describing the vulnerability and impact]

  **Severity:** [Critical/High/Medium] based on CVSS v3.1

  **Affected System:** [URL/endpoint]

  I have a complete report with reproduction steps, proof of concept,
  and remediation recommendations ready to share. Please let me know
  the best secure channel to transmit the full details.

  I follow responsible disclosure principles and will:
  - Maintain confidentiality until a fix is deployed
  - Not access any data beyond what was necessary for verification
  - Not exploit this vulnerability for any purpose
  - Provide reasonable time for remediation (90 days)

  I can be reached at [your email] or via [your preferred secure channel].
  My PGP key is available at [URL] if you prefer encrypted communication.

  Best regards,
  [Your Name/Handle]
  [Your website/profile]
  EMAIL_TEMPLATE

  echo ""
  echo "Step 3: Establish secure communication channel"
  echo "  Preferred: Encrypted email (PGP/GPG)"
  echo "  Alternative: Signal, Keybase"
  echo "  Last resort: Regular email with sensitive details omitted"

  # Generate PGP key if you don't have one
  echo "=== PGP Key Setup ==="
  echo "  gpg --full-generate-key"
  echo "  gpg --armor --export your@email.com > public_key.asc"
  echo "  gpg --keyserver hkps://keys.openpgp.org --send-keys KEY_ID"

  echo ""
  echo "Step 4: Set a disclosure deadline"
  echo "  Standard: 90 days from initial report"
  echo "  Critical severity: Consider 30-45 days"
  echo "  Complex fix: May negotiate extension (up to 120 days)"
  echo ""
  echo "Step 5: Follow up if no response"
  echo "  After 7 days: Send follow-up email"
  echo "  After 14 days: Try alternative contact methods"
  echo "  After 30 days: Consider CERT/CC coordination"
  echo "  After 90 days: Public disclosure (see guidelines)"
  ```
  ::

  ::tabs-item{icon="i-lucide-building-2" label="CERT Coordination"}

  ```bash
  # ═══════════════════════════════════════════
  # CERT/CC COORDINATED DISCLOSURE
  # (When vendor is unresponsive)
  # ═══════════════════════════════════════════

  echo "=== CERT/CC Coordination ==="
  echo ""
  echo "Use CERT/CC when:"
  echo "  - Vendor has no security contact"
  echo "  - Vendor is unresponsive after multiple attempts"
  echo "  - Vulnerability affects multiple vendors"
  echo "  - Vulnerability is in a widely-used protocol or library"
  echo "  - You need legal protection / neutral third party"
  echo ""
  echo "CERT/CC Vulnerability Reporting:"
  echo "  URL: https://www.kb.cert.org/vuls/report/"
  echo "  Email: cert@cert.org"
  echo "  PGP Key: Available on their website"
  echo ""
  echo "What CERT/CC provides:"
  echo "  - Acts as neutral coordinator between researcher and vendor"
  echo "  - Assigns CVE numbers"
  echo "  - Contacts the vendor on your behalf"
  echo "  - Publishes advisories"
  echo "  - Standard 45-day disclosure deadline"
  echo ""
  echo "Other national CERTs:"
  echo "  US-CERT/CISA: https://www.cisa.gov/report"
  echo "  NCSC (UK): https://www.ncsc.gov.uk/information/vulnerability-reporting"
  echo "  BSI (Germany): https://www.bsi.bund.de/EN/Vulnerability-Disclosure"
  echo "  JPCERT (Japan): https://www.jpcert.or.jp/english/vh/"
  echo "  AusCERT (Australia): https://www.auscert.org.au"

  # CVE Request (direct to MITRE)
  echo ""
  echo "=== CVE Assignment ==="
  echo "Request a CVE ID:"
  echo "  URL: https://cveform.mitre.org/"
  echo "  Required information:"
  echo "    - Vulnerability type (CWE)"
  echo "    - Affected product/version"
  echo "    - Vendor name"
  echo "    - Description of vulnerability"
  echo "    - Impact"
  echo "    - Discovery date"
  echo "    - Credit information"
  ```
  ::
::

---

## Disclosure Timelines & Deadlines

::badge
Industry Standards
::

### Timeline Standards

::collapsible

**Industry-Standard Disclosure Timelines:**

| Organization | Standard Timeline | Extension Policy |
| --- | --- | --- |
| **Google Project Zero** | 90 days | +14 days if fix scheduled within grace period |
| **CERT/CC** | 45 days | Negotiable based on complexity |
| **ZDI (Trend Micro)** | 120 days | Extended for complex multi-vendor issues |
| **Microsoft MSRC** | 90 days (external reports) | Case-by-case negotiation |
| **HackerOne (general)** | Vendor-defined (typically 90 days) | Per program policy |
| **Bugcrowd (general)** | Vendor-defined | Per program brief |
| **ISO 29147** | "Reasonable time" | No fixed deadline |
| **Common practice** | 90 days | +30 days for good-faith effort |

::

```bash
# ═══════════════════════════════════════════
# DISCLOSURE TIMELINE MANAGEMENT
# ═══════════════════════════════════════════

# Calculate disclosure deadline
REPORT_DATE="2024-01-15"
DEADLINE_90=$(date -d "${REPORT_DATE} + 90 days" +%Y-%m-%d 2>/dev/null || \
  date -v+90d -jf "%Y-%m-%d" "$REPORT_DATE" +%Y-%m-%d 2>/dev/null)
DEADLINE_120=$(date -d "${REPORT_DATE} + 120 days" +%Y-%m-%d 2>/dev/null || \
  date -v+120d -jf "%Y-%m-%d" "$REPORT_DATE" +%Y-%m-%d 2>/dev/null)

echo "=== Disclosure Timeline ==="
echo "Report submitted: $REPORT_DATE"
echo "90-day deadline:  $DEADLINE_90"
echo "120-day maximum:  $DEADLINE_120"
echo ""
echo "Milestone schedule:"
echo "  Day 0:   Report submitted"
echo "  Day 3:   Expected: Vendor acknowledges receipt"
echo "  Day 7:   If no ack: Send follow-up"
echo "  Day 14:  If no ack: Try alternative channels"
echo "  Day 21:  If no ack: Consider CERT coordination"
echo "  Day 30:  Expected: Vendor confirms vulnerability"
echo "  Day 45:  Expected: Vendor provides fix timeline"
echo "  Day 60:  Expected: Fix in staging/testing"
echo "  Day 75:  Expected: Fix deployed to production"
echo "  Day 80:  Send reminder: 10 days until deadline"
echo "  Day 90:  Disclosure deadline"
echo ""
echo "Extension criteria:"
echo "  - Vendor is actively working on fix (demonstrable progress)"
echo "  - Fix is complex and requires architectural changes"
echo "  - Vendor communicates timeline and rationale"
echo "  - Extension is reasonable (max 30 additional days)"
echo "  - Vendor is communicating in good faith"
```

### Handling Timeline Disputes

::accordion
  ::accordion-item
  ---
  icon: i-lucide-clock
  label: When the Vendor Asks for More Time
  ---

  ```bash
  # Decision framework for timeline extension requests

  cat << 'FRAMEWORK'
  ═══════════════════════════════════════════════════════
  EXTENSION REQUEST EVALUATION FRAMEWORK
  ═══════════════════════════════════════════════════════

  GRANT extension when:
  ──────────────────────
  ✓ Vendor is actively communicating
  ✓ Demonstrable fix progress (staging, testing)
  ✓ Complex fix requiring architectural changes
  ✓ Multiple affected systems/versions
  ✓ Reasonable extension (14-30 days)
  ✓ Users are not actively being exploited
  ✓ Vendor provides specific new deadline

  DENY extension when:
  ──────────────────────
  ✗ Vendor has been silent for weeks
  ✗ No evidence of fix progress
  ✗ Requested extension is indefinite
  ✗ Users are being actively exploited in the wild
  ✗ Vendor has already received one extension
  ✗ Vendor is using delay as a suppression tactic
  ✗ Vulnerability is trivial to fix

  RESPONSE TEMPLATES:
  ──────────────────────

  Granting extension:
  "Thank you for the update on the remediation progress. Given the
  complexity of the fix and your demonstrable progress, I'm happy
  to extend the disclosure deadline to [DATE]. Please keep me
  updated on the deployment timeline."

  Denying extension:
  "I appreciate you reaching out. However, [X days/months] have
  passed since the initial report, and I haven't seen evidence
  of active remediation. The vulnerability continues to put
  [user count] users at risk. I will proceed with public
  disclosure on [ORIGINAL_DEADLINE] as previously communicated.
  I'm happy to coordinate the disclosure timing to align with
  your patch deployment if you can commit to a specific date."
  FRAMEWORK
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-alert-triangle
  label: When the Vendor is Unresponsive
  ---

  ```bash
  # Escalation ladder for unresponsive vendors

  cat << 'ESCALATION'
  ═══════════════════════════════════════════════════════
  UNRESPONSIVE VENDOR ESCALATION LADDER
  ═══════════════════════════════════════════════════════

  Day 0:    Submit report via official security channel
            ↓ Wait 7 days
  Day 7:    Send follow-up email
            "Following up on my security report submitted on [DATE].
            Please confirm receipt. Report ID: [ID]"
            ↓ Wait 7 days
  Day 14:   Try alternative contact channels
            - Different email (info@, support@, CTO directly)
            - LinkedIn message to CISO or Head of Security
            - Twitter DM to official security account
            - Contact form on website
            ↓ Wait 7 days
  Day 21:   Formal notification with deadline
            "This is my third attempt to report a security vulnerability.
            Per responsible disclosure standards, I am setting a 90-day
            disclosure deadline from the original report date [DATE].
            The deadline for remediation is [DEADLINE]."
            ↓ Wait until day 30
  Day 30:   Escalate to CERT/CC
            Submit the vulnerability to CERT/CC and notify the vendor:
            "Due to lack of response, I have engaged CERT/CC to
            coordinate this disclosure. Case reference: [VU#XXXXX]"
            ↓ Wait until day 45
  Day 45:   Consider additional escalation
            - Notify relevant ISACs if critical infrastructure
            - Engage additional CERTs in affected regions
            - Document all communication attempts
            ↓ Continue until day 90
  Day 90:   Public disclosure
            Publish advisory with:
            - Full technical details
            - Timeline of communication attempts
            - Evidence of vendor non-response
            - Mitigation recommendations for users
            
  IMPORTANT:
  ──────────
  • Document EVERY communication attempt with timestamps
  • Save copies of all emails, screenshots of DMs, etc.
  • Never use threatening language
  • Focus on protecting users, not punishing the vendor
  • Consider whether public disclosure could cause more harm
    than the vulnerability itself (rare but possible cases)
  ESCALATION
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-shield-alert
  label: When the Vulnerability is Being Actively Exploited
  ---

  ```bash
  # Emergency disclosure process for actively exploited vulnerabilities

  cat << 'EMERGENCY'
  ═══════════════════════════════════════════════════════
  EMERGENCY DISCLOSURE — ACTIVE EXPLOITATION
  ═══════════════════════════════════════════════════════

  When you discover a vulnerability is being actively exploited
  in the wild, the standard 90-day timeline is inappropriate.

  Immediate actions:
  ──────────────────
  1. Notify the vendor IMMEDIATELY with "CRITICAL - ACTIVE EXPLOITATION"
     in the subject line
  
  2. Provide the minimum information needed for the vendor to:
     - Understand the attack
     - Implement emergency mitigations
     - Deploy a hot fix
  
  3. Notify relevant CERTs/ISACs within 24 hours
  
  4. Shortened disclosure timeline: 7-14 days
     - The urgency outweighs the vendor's convenience
     - Users need to know they're at risk
     - Mitigations must be communicated
  
  5. If the vendor deploys a fix quickly:
     - Coordinate public disclosure with the vendor
     - Credit their rapid response
  
  6. If the vendor is unresponsive:
     - Publish an advisory with mitigations (not full exploit)
     - Focus on DEFENSE (how users can protect themselves)
     - Withhold full exploitation details until patch available
     - Notify press/media if significant public risk

  Communication template:
  ──────────────────────
  Subject: CRITICAL — Active exploitation of [vulnerability] in [product]

  [Vendor] Security Team,

  I have evidence that the vulnerability I reported on [DATE] is
  being actively exploited in the wild. [Brief evidence summary].

  Given the active exploitation, I am requesting an emergency
  response. If a patch cannot be deployed within 7 days, I will
  need to publish mitigations to help affected users protect
  themselves.

  I am available immediately to assist with remediation.

  [Contact information]
  EMERGENCY
  ```
  ::
::

---

## Legal Considerations

::badge
Critical Knowledge
::

::caution
**This section provides general information about legal considerations in security research. It is NOT legal advice.** Laws vary by jurisdiction and change over time. Consult a qualified attorney in your jurisdiction before conducting security research, especially for targets without explicit bug bounty programs.
::

### Legal Safe Harbor Framework

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    LEGAL PROTECTION LANDSCAPE                           │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  SAFE HARBOR (Strong Protection)                                 │   │
│  │  ────────────────────────────────                                │   │
│  │  • Bug bounty program with explicit authorization               │   │
│  │  • Written permission / engagement letter                       │   │
│  │  • Program policy defines scope and safe harbor terms           │   │
│  │  • DOJ 2022 CFAA charging policy (US)                          │   │
│  │  • EU Cybersecurity Act protections (where applicable)          │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  GRAY AREA (Limited Protection)                                  │   │
│  │  ──────────────────────────────                                  │   │
│  │  • Responsible disclosure policy exists but no bounty program   │   │
│  │  • security.txt exists with contact but no explicit safe harbor │   │
│  │  • Testing within "good faith" but no written authorization     │   │
│  │  • Academic / research context                                  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  HIGH RISK (Little/No Protection)                                │   │
│  │  ────────────────────────────────                                │   │
│  │  • No bug bounty or disclosure policy exists                    │   │
│  │  • Testing without any form of authorization                    │   │
│  │  • Accessing real user data beyond minimal verification         │   │
│  │  • Causing service disruption during testing                    │   │
│  │  • Threatening to disclose unless paid (extortion)              │   │
│  │  • Selling vulnerability details to third parties               │   │
│  │  • Publicly disclosing before notifying vendor                  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

### Staying Within Legal Boundaries

::accordion
  ::accordion-item
  ---
  icon: i-lucide-check-circle
  label: What You SHOULD Do
  ---

  - **Only test systems you are authorized to test** (bug bounty scope, written permission, your own systems)
  - **Read and follow the program's rules of engagement** before testing
  - **Stay within defined scope** — if a domain or feature is excluded, do not test it
  - **Access only the minimum data necessary** to prove the vulnerability
  - **Use your own test accounts** for any write/delete/modify operations
  - **Document everything** with timestamps — your communications, your testing, your findings
  - **Report through official channels** — bug bounty platform, security@, security.txt contact
  - **Maintain confidentiality** until the vendor agrees to disclosure or deadline passes
  - **Cooperate with the vendor** — answer questions, provide clarification, assist with remediation
  - **Comply with export control laws** if the vulnerability relates to cryptographic systems
  ::

  ::accordion-item
  ---
  icon: i-lucide-x-circle
  label: What You Must NEVER Do
  ---

  - **Never access real user data** beyond what's minimally needed for proof (sample 3-5 records, redact immediately)
  - **Never exfiltrate or store real user data** — counts and field names are sufficient
  - **Never modify or delete production data** that isn't your own test data
  - **Never cause service disruption** — avoid DoS testing unless explicitly authorized
  - **Never use the vulnerability for personal gain** beyond the bug bounty reward
  - **Never sell or share vulnerability details** with unauthorized parties
  - **Never threaten the vendor** with public disclosure to extract payment (this is extortion)
  - **Never publicly disclose** without first notifying the vendor and allowing reasonable time
  - **Never test against a target that explicitly prohibits security testing**
  - **Never access systems outside the defined scope**, even if reachable from in-scope systems
  - **Never use stolen credentials** found during testing to access additional accounts
  - **Never install persistent backdoors** during testing
  - **Never test from shared/public networks** in ways that could implicate others
  ::

  ::accordion-item
  ---
  icon: i-lucide-scale
  label: Key Laws & Regulations
  ---

  ::collapsible

  **Major computer crime laws affecting security researchers:**

  | Jurisdiction | Law | Key Provision | Researcher Relevance |
  | --- | --- | --- | --- |
  | **US** | CFAA (18 U.S.C. § 1030) | Unauthorized access to computers | Most relevant US law; DOJ 2022 policy limits prosecution of good-faith research |
  | **US** | DMCA (17 U.S.C. § 1201) | Anti-circumvention provisions | May apply when bypassing access controls; security research exemption exists |
  | **EU** | NIS2 Directive | Coordinated vulnerability disclosure | Encourages member states to adopt CVD policies |
  | **EU** | GDPR | Data protection | Researchers accessing personal data face obligations |
  | **UK** | Computer Misuse Act 1990 | Unauthorized access | No explicit security research exception |
  | **Netherlands** | Coordinated Vulnerability Disclosure | National CVD policy | One of the most researcher-friendly frameworks |
  | **France** | Digital Republic Act (2016) | Good faith reporting | Protection for good-faith disclosure to ANSSI |
  | **Belgium** | CVD Framework (2023) | National CVD policy | Legal safe harbor for responsible disclosure |
  | **Germany** | StGB § 202a-c | Computer fraud and espionage | Complex landscape; BSI provides CVD guidance |
  | **India** | IT Act 2000, Section 66 | Hacking and computer crimes | Limited researcher protections |
  | **Australia** | Criminal Code Act 1995 | Unauthorized access | Limited researcher protections |
  | **Japan** | UCPL | Unauthorized computer access | JPCERT provides coordination |
  | **Singapore** | Computer Misuse Act | Unauthorized access | Limited researcher protections |

  ::

  ```bash
  # Resources for legal guidance

  echo "=== Legal Resources for Security Researchers ==="
  echo ""
  echo "General:"
  echo "  EFF Legal Guide: https://www.eff.org/issues/coders/vulnerability-reporting-faq"
  echo "  Disclose.io:     https://disclose.io/"
  echo "  CISA VDP:        https://www.cisa.gov/coordinated-vulnerability-disclosure-process"
  echo ""
  echo "US-specific:"
  echo "  DOJ 2022 Policy: https://www.justice.gov/opa/pr/department-justice-announces-new-policy-charging-computer-fraud-and-abuse-act"
  echo "  CFAA reform:     https://www.eff.org/issues/cfaa"
  echo ""
  echo "EU-specific:"
  echo "  ENISA CVD Guide: https://www.enisa.europa.eu/publications/coordinated-vulnerability-disclosure-policies-in-the-eu"
  echo "  NIS2 Directive:  https://eur-lex.europa.eu/eli/dir/2022/2555"
  echo ""
  echo "Frameworks:"
  echo "  ISO/IEC 29147:   Vulnerability Disclosure"
  echo "  ISO/IEC 30111:   Vulnerability Handling Processes"
  echo "  FIRST PSIRT:     https://www.first.org/standards/frameworks/psirts/"
  echo ""
  echo "Legal assistance:"
  echo "  EFF Legal:       info@eff.org"
  echo "  Luta Security:   https://lutasecurity.com/"
  echo "  If you receive legal threats, seek legal counsel IMMEDIATELY"
  ```
  ::
::

---

## Communication Best Practices

::badge
Professional Skill
::

### Communicating with Security Teams

::tabs
  ::tabs-item{icon="i-lucide-message-circle" label="Communication Principles"}

  ```
  ═══════════════════════════════════════════════════════
  COMMUNICATION PRINCIPLES FOR RESEARCHERS
  ═══════════════════════════════════════════════════════

  1. BE PROFESSIONAL
     ─────────────────
     • Write as you would to a colleague
     • No threatening language, ever
     • No aggressive timelines or ultimatums (initially)
     • Use proper grammar and formatting
     • Address the security team, not "hey guys"

  2. BE CLEAR
     ────────
     • One vulnerability per report
     • Structured format with numbered steps
     • Include "expected vs actual" behavior
     • Specify exact versions, endpoints, parameters
     • Avoid jargon that non-security people won't understand

  3. BE PATIENT
     ──────────
     • Triage takes time (often weeks for complex issues)
     • Don't send daily follow-ups
     • Understand that security teams handle many reports
     • Allow at least 5-7 business days before first follow-up
     • Remember that holidays and weekends exist

  4. BE HELPFUL
     ──────────
     • Offer to clarify or provide more details
     • Suggest remediation approaches
     • If you find related issues, update the existing report
     • Acknowledge when the vendor does good work
     • Thank the security team for their response

  5. BE HONEST
     ─────────
     • Don't exaggerate impact
     • Acknowledge limitations of your testing
     • Disclose if you accidentally accessed data
     • Admit if your initial assessment was wrong
     • Don't claim credit for others' work
  ```
  ::

  ::tabs-item{icon="i-lucide-mail" label="Email Templates"}

  ```bash
  # ═══════════════════════════════════════════
  # COMMUNICATION TEMPLATES
  # ═══════════════════════════════════════════

  # Template 1: Initial report (non-platform)
  cat << 'TEMPLATE1'
  Subject: Security Vulnerability Report — [Brief Description] — [Your Handle]

  Dear [Target] Security Team,

  I am writing to report a security vulnerability I discovered in 
  [product/service] during authorized security research.

  **Summary:** [Type of vulnerability] in [location] that allows 
  [what an attacker can do] affecting [scope/impact].

  **Severity:** [Critical/High/Medium] — CVSS: [Score]

  **Affected System:** [URL/endpoint/version]

  [Full reproduction steps, PoC, impact analysis, and remediation 
  recommendations are included below / in the attached document.]

  [... Full report details ...]

  I follow responsible disclosure practices and will maintain 
  confidentiality of this vulnerability for 90 days to allow 
  for remediation. I am happy to assist with any questions 
  about the vulnerability or remediation approach.

  Best regards,
  [Your Name/Handle]
  [Your website/profile]
  [Your PGP key fingerprint]
  TEMPLATE1

  # Template 2: Follow-up (no response)
  cat << 'TEMPLATE2'
  Subject: Re: Security Vulnerability Report — [Brief Description] — Follow-up

  Dear [Target] Security Team,

  I am following up on my security vulnerability report submitted 
  on [DATE]. I have not received an acknowledgment and want to 
  ensure the report was received.

  For reference, the vulnerability is a [brief description] 
  affecting [endpoint/system]. The original report was sent to 
  [email/channel used].

  Could you please confirm receipt? I am happy to resend the 
  report or provide it through an alternative channel.

  Best regards,
  [Your Name/Handle]
  TEMPLATE2

  # Template 3: Responding to severity disagreement
  cat << 'TEMPLATE3'
  Subject: Re: Report #[ID] — Severity Assessment Discussion

  Hi [Triager Name],

  Thank you for triaging this report. I appreciate the thorough 
  review. I'd like to respectfully discuss the severity assessment.

  You've classified this as [their severity]. I believe it should 
  be rated as [your severity] for the following reasons:

  1. [Reason 1 — specific, evidence-based]
  2. [Reason 2 — reference to CVSS metrics]
  3. [Reason 3 — demonstrated impact beyond initial assessment]

  I've attached additional evidence demonstrating [specific impact] 
  that may not have been clear in the original report.

  I understand severity assessments involve judgment, and I respect 
  that the final decision is yours. However, I wanted to ensure 
  the full impact was considered.

  Thank you for your time.

  Best regards,
  [Your Name/Handle]
  TEMPLATE3

  # Template 4: Accepting a decision you disagree with
  cat << 'TEMPLATE4'
  Subject: Re: Report #[ID] — Acknowledged

  Hi [Triager Name],

  Thank you for the detailed explanation of the severity decision. 
  While I believe the impact warrants a higher rating based on 
  [brief reason], I understand and accept the team's assessment.

  I appreciate the professional handling of this report and look 
  forward to continuing to contribute to [Target]'s security.

  Best regards,
  [Your Name/Handle]
  TEMPLATE4

  # Template 5: Disclosure deadline reminder
  cat << 'TEMPLATE5'
  Subject: Security Report #[ID] — 90-Day Disclosure Deadline Approaching

  Dear [Target] Security Team,

  This is a courtesy reminder that the 90-day disclosure deadline 
  for my security report #[ID] ([brief description]) is approaching 
  on [DEADLINE_DATE].

  Current status:
  - Report submitted: [DATE]
  - Acknowledged: [DATE or "No acknowledgment received"]
  - Fix status: [What you know about the fix progress]

  If remediation requires additional time, I am open to discussing 
  a reasonable extension, provided there is demonstrable progress 
  toward a fix.

  If a fix has been deployed, I would appreciate confirmation so 
  I can verify the remediation and coordinate public disclosure.

  Best regards,
  [Your Name/Handle]
  TEMPLATE5
  ```
  ::

  ::tabs-item{icon="i-lucide-shield-alert" label="Handling Difficult Situations"}

  ```bash
  # ═══════════════════════════════════════════
  # HANDLING COMMON DIFFICULT SCENARIOS
  # ═══════════════════════════════════════════

  cat << 'SCENARIOS'
  ═══════════════════════════════════════════════════════
  SCENARIO: Vendor threatens legal action
  ═══════════════════════════════════════════════════════

  DO:
  • Stop all testing immediately
  • Save all communications and evidence
  • Contact a lawyer experienced in computer crime law
  • Contact EFF (info@eff.org) for potential assistance
  • Do NOT delete any evidence or communications
  • Do NOT continue communicating directly with vendor
  • Do NOT publicly discuss the situation
  • Let your lawyer handle all further communication

  DON'T:
  • Don't panic — threats are often bluster
  • Don't respond emotionally
  • Don't apologize or admit wrongdoing without legal advice
  • Don't comply with unreasonable demands without legal counsel
  • Don't delete your report or evidence

  ═══════════════════════════════════════════════════════
  SCENARIO: Vendor marks your report as duplicate unfairly
  ═══════════════════════════════════════════════════════

  DO:
  • Ask for details about the original report (submission date)
  • If using a platform, request mediation
  • Provide evidence that your report is distinct
  • Compare technical details if original report is shared
  • Accept the decision gracefully if truly duplicate

  DON'T:
  • Don't accuse the triager of dishonesty without evidence
  • Don't create multiple reports about the same issue
  • Don't publicly complain without exhausting platform options

  ═══════════════════════════════════════════════════════
  SCENARIO: Vendor downgrades severity unfairly
  ═══════════════════════════════════════════════════════

  DO:
  • Provide additional evidence of impact
  • Reference CVSS scoring guidelines
  • Show comparable reports on other programs (public ones)
  • Request mediation through the platform
  • Provide a clear, evidence-based counter-argument

  DON'T:
  • Don't threaten public disclosure as leverage
  • Don't get emotional or confrontational
  • Don't repeatedly reopen closed reports without new info

  ═══════════════════════════════════════════════════════
  SCENARIO: Vendor silently patches without credit or bounty
  ═══════════════════════════════════════════════════════

  DO:
  • Document the fix (before/after screenshots)
  • Send a professional follow-up asking about bounty/credit
  • If using a platform, raise the issue through the platform
  • If direct disclosure, consider requesting CVE assignment
  • Evaluate whether to continue testing for this vendor

  DON'T:
  • Don't assume malice — it may be an oversight
  • Don't threaten to stop disclosing (just quietly stop if needed)
  • Don't publicly shame the vendor (unless pattern of behavior)
  SCENARIOS
  ```
  ::
::

---

## Secure Communication Methods

::badge
Operational Security
::

### Protecting Your Communications

::tabs
  ::tabs-item{icon="i-lucide-lock" label="Encrypted Email (PGP/GPG)"}

  ```bash
  # ═══════════════════════════════════════════
  # PGP/GPG SETUP FOR SECURE DISCLOSURE
  # ═══════════════════════════════════════════

  # Generate a new PGP key pair
  gpg --full-generate-key
  # Select: RSA and RSA, 4096 bits, expiration 2 years
  # Enter: Your name, email, strong passphrase

  # Export your public key
  gpg --armor --export your@email.com > your_public_key.asc

  # Upload to key server
  gpg --keyserver hkps://keys.openpgp.org --send-keys YOUR_KEY_ID

  # Import vendor's public key (from security.txt or website)
  curl -s "https://target.com/.well-known/security.txt" | \
    grep -i "encryption:" | awk '{print $2}'
  # Download and import the key
  curl -s "https://target.com/pgp-key.asc" | gpg --import

  # Encrypt your report for the vendor
  gpg --armor --encrypt --recipient vendor-security@target.com \
    --sign vulnerability_report.txt

  # Verify a vendor's signed message
  gpg --verify vendor_response.asc

  # Encrypt attachments (evidence files)
  tar czf evidence.tar.gz evidence/
  gpg --armor --encrypt --recipient vendor-security@target.com evidence.tar.gz
  ```
  ::

  ::tabs-item{icon="i-lucide-shield" label="Secure Channels"}

  ```bash
  # ═══════════════════════════════════════════
  # SECURE COMMUNICATION CHANNEL OPTIONS
  # ═══════════════════════════════════════════

  echo "=== Secure Communication Options (Ranked by Security) ==="
  echo ""
  echo "1. Bug bounty platform (HackerOne, Bugcrowd, etc.)"
  echo "   - Encrypted, logged, mediated"
  echo "   - RECOMMENDED for bug bounty submissions"
  echo ""
  echo "2. PGP-encrypted email"
  echo "   - End-to-end encrypted"
  echo "   - Use when vendor provides PGP key in security.txt"
  echo "   - Requires both parties to have PGP setup"
  echo ""
  echo "3. Signal / Wire"
  echo "   - End-to-end encrypted messaging"
  echo "   - Good for real-time coordination after initial report"
  echo "   - Not suitable for initial report (no audit trail)"
  echo ""
  echo "4. Keybase"
  echo "   - Encrypted messaging with identity verification"
  echo "   - Good for verifying vendor identity"
  echo ""
  echo "5. Regular email (TLS)"
  echo "   - Transport encryption only (not end-to-end)"
  echo "   - Acceptable for non-critical communications"
  echo "   - Use for initial contact, PGP for full report"
  echo ""
  echo "6. Web forms"
  echo "   - Check for HTTPS (mandatory)"
  echo "   - Acceptable for initial contact"
  echo "   - Do not submit sensitive technical details via web forms"
  echo "     unless the form is specifically for vulnerability reports"
  echo ""
  echo "NEVER use:"
  echo "  ✗ Social media DMs for full technical details"
  echo "  ✗ Unencrypted channels for exploit code"
  echo "  ✗ Public channels (GitHub issues, forums)"
  echo "  ✗ Shared drives without access controls"
  ```
  ::

  ::tabs-item{icon="i-lucide-user-check" label="Researcher OpSec"}

  ```bash
  # ═══════════════════════════════════════════
  # OPERATIONAL SECURITY FOR RESEARCHERS
  # ═══════════════════════════════════════════

  echo "=== Researcher OpSec Checklist ==="
  echo ""
  echo "Identity Protection:"
  echo "  ✓ Use a pseudonym/handle for bug bounty profiles"
  echo "  ✓ Separate email for security research"
  echo "  ✓ Consider VPN for testing (check program policy first)"
  echo "  ✓ Use dedicated testing environment"
  echo ""
  echo "Evidence Protection:"
  echo "  ✓ Store evidence on encrypted drives"
  echo "  ✓ Hash all evidence files for integrity"
  echo "  ✓ Maintain chain of custody documentation"
  echo "  ✓ Use timestamped screenshots and recordings"
  echo "  ✓ Back up all communications and evidence"
  echo ""
  echo "Testing Environment:"
  echo "  ✓ Use dedicated machine or VM for testing"
  echo "  ✓ Clear browser data between testing sessions"
  echo "  ✓ Don't mix personal browsing with testing"
  echo "  ✓ Use separate browser profiles for target vs attacker accounts"
  echo "  ✓ Log all testing activity (timestamps, URLs, methods)"
  echo ""
  echo "Data Handling:"
  echo "  ✓ Redact all PII in evidence before submission"
  echo "  ✓ Delete any real user data accessed during testing"
  echo "  ✓ Never store unredacted evidence longer than necessary"
  echo "  ✓ Securely delete evidence after disclosure is complete"
  echo ""
  echo "Financial Protection:"
  echo "  ✓ Report bounty income for tax purposes"
  echo "  ✓ Understand tax obligations in your jurisdiction"
  echo "  ✓ Keep records of all bounty payments received"
  echo "  ✓ Consider forming a legal entity for research activity"

  # Securely delete sensitive files after disclosure
  # Linux
  shred -vfz -n 5 sensitive_evidence.txt
  # macOS
  rm -P sensitive_evidence.txt
  # Or use srm (secure-delete package)
  srm -vz sensitive_evidence.txt
  ```
  ::
::

---

## Public Disclosure Writing

::badge
Community Contribution
::

### Writing Effective Public Writeups

::note
Public disclosure serves the security community by sharing knowledge, techniques, and lessons learned. A good writeup educates other researchers, helps other organizations identify similar issues, and demonstrates your expertise.
::

::accordion
  ::accordion-item
  ---
  icon: i-lucide-file-text
  label: Writeup Structure
  ---

  ```bash
  # Public writeup template

  cat << 'WRITEUP_STRUCTURE'
  # [Catchy Title Describing the Finding]
  ## How I Found [Vulnerability Type] in [Target] and What I Learned

  ### TL;DR
  [2-3 sentences summarizing the vulnerability, impact, and outcome]

  ### Timeline
  | Date | Event |
  |------|-------|
  | YYYY-MM-DD | Discovery |
  | YYYY-MM-DD | Report submitted |
  | YYYY-MM-DD | Vendor acknowledged |
  | YYYY-MM-DD | Fix deployed |
  | YYYY-MM-DD | Bounty awarded: $X,XXX |
  | YYYY-MM-DD | Public disclosure (this post) |

  ### The Hunt
  [Tell the story of how you found it]
  - What methodology were you using?
  - What made you look at this specific target/endpoint?
  - What was your initial observation?
  - How did you confirm it was a vulnerability?

  ### Technical Deep-Dive
  [Full technical details]
  - Root cause analysis
  - Exploitation technique
  - Code snippets / HTTP requests
  - Screenshots (redacted)

  ### Impact
  [What an attacker could achieve]
  - Demonstrated capabilities
  - Scope of affected users/data
  - Business impact

  ### The Fix
  [How the vendor remediated the issue]
  - What changed
  - Was the fix complete?
  - Before/after comparison

  ### Lessons Learned
  [Key takeaways for the community]
  - For researchers: What technique/mindset led to this finding
  - For defenders: How to prevent this class of vulnerability
  - For the industry: Broader implications

  ### Acknowledgments
  - Thanks to [Target] security team for [specific praise]
  - Bounty: $X,XXX
  - CVE: CVE-YYYY-XXXXX

  WRITEUP_STRUCTURE
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-shield-check
  label: What to Include vs Exclude
  ---

  ```
  ═══════════════════════════════════════════════════════
  PUBLIC DISCLOSURE CONTENT GUIDELINES
  ═══════════════════════════════════════════════════════

  INCLUDE:
  ────────
  ✓ Vulnerability type and class (CWE reference)
  ✓ General location (endpoint pattern, not exact production URLs)
  ✓ Exploitation technique and methodology
  ✓ Impact analysis (can be generalized if needed)
  ✓ Timeline of disclosure process
  ✓ Remediation approach
  ✓ Lessons learned for other researchers
  ✓ Tools and techniques used
  ✓ Screenshots (with sensitive data redacted)
  ✓ Sanitized HTTP request/response examples
  ✓ Acknowledgment of the vendor's security team
  ✓ CVE number if assigned

  EXCLUDE:
  ────────
  ✗ Exact production URLs (unless vendor consents)
  ✗ Real user data (even partially redacted)
  ✗ Working exploit code targeting production systems
  ✗ Internal infrastructure details (IPs, hostnames)
  ✗ Details that could be used against unpatched systems
  ✗ Credentials, tokens, or API keys (even expired)
  ✗ Negative commentary about the vendor's team
  ✗ Information shared in private with the vendor
  ✗ Details of other unfixed vulnerabilities
  ✗ Bounty amount (unless vendor consents or you choose to share)

  GRAY AREA (use judgment):
  ─────────────────────────
  ◐ Vendor name (usually OK if they consented to disclosure)
  ◐ Specific version numbers (OK if patch is available)
  ◐ PoC code (OK if generalized, not targeting production)
  ◐ CVSS score (OK, but vendor may have their own assessment)
  ◐ Bounty amount (personal choice; some programs restrict this)
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-check-circle
  label: Pre-Publication Checklist
  ---

  ```bash
  # Pre-publication checklist

  echo "=== Pre-Publication Verification ==="
  echo ""
  echo "Authorization:"
  echo "  [ ] Vendor has confirmed the fix is deployed"
  echo "  [ ] Vendor has agreed to public disclosure (or deadline passed)"
  echo "  [ ] If using a platform, disclosure request has been approved"
  echo "  [ ] You are not violating any NDA or program terms"
  echo ""
  echo "Content review:"
  echo "  [ ] No real user data present (even partially)"
  echo "  [ ] No production URLs that could be used for attacks"
  echo "  [ ] No unexpired credentials, tokens, or keys"
  echo "  [ ] No internal infrastructure details"
  echo "  [ ] Screenshots are properly redacted"
  echo "  [ ] Code examples are sanitized/generalized"
  echo "  [ ] No details about unfixed related vulnerabilities"
  echo ""
  echo "Fix verification:"
  echo "  [ ] Original vulnerability is confirmed fixed"
  echo "  [ ] Fix has been deployed to ALL affected environments"
  echo "  [ ] Users have had reasonable time to update (if applicable)"
  echo ""
  echo "Quality check:"
  echo "  [ ] Writeup is technically accurate"
  echo "  [ ] Tone is professional and constructive"
  echo "  [ ] Vendor security team is acknowledged"
  echo "  [ ] Lessons learned section adds value to community"
  echo "  [ ] Grammar and formatting are clean"
  echo "  [ ] All claims are supported by evidence"
  echo ""
  echo "Legal check:"
  echo "  [ ] You are not violating program terms"
  echo "  [ ] Content does not expose you to legal risk"
  echo "  [ ] If uncertain, you have consulted legal counsel"
  ```
  ::
::

### Publishing Platforms

::collapsible

**Where to publish your writeups:**

| Platform | Audience | Best For |
| --- | --- | --- |
| **Personal Blog** | General public, employers | Long-form technical writeups, building personal brand |
| **Medium** | Tech community | Broad reach, good SEO |
| **HackerOne Hacktivity** | Bug bounty community | Platform-specific findings, building HackerOne reputation |
| **Bugcrowd Blog** | Security community | Featured researcher content |
| **GitHub** | Developers, researchers | PoC code, tools, technical documentation |
| **Twitter/X** | Security community | Announcements, thread summaries |
| **Reddit (r/netsec, r/bugbounty)** | Security community | Discussions, feedback |
| **Conference Talks** | Industry professionals | High-impact findings, career building |
| **YouTube** | Broader audience | Video demonstrations, tutorials |
| **InfoSec Write-ups** | Security community | Curated security content |
| **PortSwigger Research** | Security researchers | Advanced web security techniques |

::

---

## Handling Bounty Disputes & Negotiations

::badge
Financial Aspect
::

### Navigating Bounty Disagreements

::tabs
  ::tabs-item{icon="i-lucide-dollar-sign" label="When Bounty is Too Low"}

  ```bash
  cat << 'NEGOTIATION'
  ═══════════════════════════════════════════════════════
  BOUNTY NEGOTIATION FRAMEWORK
  ═══════════════════════════════════════════════════════

  Before disputing, evaluate honestly:
  ──────────────────────────────────
  • Does the bounty align with the program's published range?
  • Is your severity assessment supported by evidence?
  • Did you demonstrate maximum impact?
  • Are there mitigating factors you didn't consider?

  If the bounty is genuinely below fair value:
  ─────────────────────────────────────────────

  Step 1: Respond professionally with evidence
  
    "Thank you for the bounty award. I believe this finding
    warrants a higher reward based on the following:
    
    1. The demonstrated impact includes [specific impact]
    2. [X] users are affected with [data types] at risk
    3. CVSS score is [X.X] based on [metrics]
    4. Similar findings on comparable programs have been 
       awarded [$X-$Y] based on public disclosures
    
    I've attached additional impact evidence for your review.
    I understand the final decision is yours and I appreciate
    the team's consideration."

  Step 2: If denied, consider mediation (platform-specific)
  
    HackerOne: Request mediation through the platform
    Bugcrowd: Contact Bugcrowd support
    Direct: Accept or disengage professionally

  Step 3: Accept the decision
  
    Whether you agree or not, accept gracefully.
    Your reputation matters more than any single bounty.

  NEVER:
  ──────
  • Threaten to disclose publicly or sell the vulnerability
  • Leave aggressive comments on the report
  • Create drama on social media
  • Withhold exploitation details to pressure higher payment
  • Submit inflated or duplicate reports as retaliation
  NEGOTIATION
  ```
  ::

  ::tabs-item{icon="i-lucide-message-square" label="Requesting Reconsideration"}

  ```bash
  # Professional reconsideration request template

  cat << 'RECON_REQUEST'
  Subject: Report #[ID] — Bounty Reconsideration Request

  Hi [Security Team / Triager Name],

  Thank you for reviewing and resolving my report #[ID] — 
  [Vulnerability Title]. I appreciate the bounty awarded.

  I would like to respectfully request reconsideration of the 
  bounty amount based on the following factors that may not 
  have been fully considered:

  **1. Scope of Impact**
  The vulnerability affects [specific scope] — [X] users across 
  [Y] organizations in [Z] countries. This goes beyond typical 
  [severity] findings because [reason].

  **2. Data Sensitivity**
  The exposed data includes [tier 1 / tier 2 data types], which 
  carries regulatory implications under [GDPR/CCPA/etc.] for 
  your [EU/CA/etc.] user base of approximately [X] users.

  **3. Exploitation Complexity**
  While the vulnerability itself is [simple/complex], the 
  demonstrated attack chain shows [specific advanced impact] 
  that I believe elevates this beyond a standard [severity] finding.

  **4. Comparable Awards**
  Public disclosures of similar findings on programs with 
  comparable bounty ranges have been awarded [$X-$Y]:
  - [Link to comparable disclosure 1]
  - [Link to comparable disclosure 2]

  I understand that bounty decisions involve many factors and 
  I respect the team's judgment. I simply wanted to ensure 
  the full impact was considered.

  Thank you for your time and the opportunity to contribute 
  to [Target]'s security.

  Best regards,
  [Your Handle]
  RECON_REQUEST
  ```
  ::
::

---

## Measuring Your Disclosure Effectiveness

::badge
Self-Improvement
::

### Tracking Your Disclosure Performance

```bash
# ═══════════════════════════════════════════
# DISCLOSURE METRICS TRACKER
# ═══════════════════════════════════════════

cat << 'METRICS' > disclosure_metrics.json
{
  "year": "2024",
  "total_reports": 0,
  "accepted": 0,
  "duplicates": 0,
  "informational": 0,
  "not_applicable": 0,
  "severity_distribution": {
    "P1_critical": 0,
    "P2_high": 0,
    "P3_medium": 0,
    "P4_low": 0,
    "P5_info": 0
  },
  "response_times": {
    "average_first_response_days": 0,
    "average_triage_days": 0,
    "average_resolution_days": 0,
    "average_bounty_payment_days": 0
  },
  "communication": {
    "reports_requiring_clarification": 0,
    "severity_disputes": 0,
    "successful_escalations": 0,
    "mediations_requested": 0
  },
  "bounties": {
    "total_earned": 0,
    "average_per_report": 0,
    "highest_single": 0,
    "programs_contributed_to": 0
  },
  "public_disclosures": {
    "writeups_published": 0,
    "cves_assigned": 0,
    "conference_talks": 0
  },
  "quality_indicators": {
    "acceptance_rate_percent": 0,
    "duplicate_rate_percent": 0,
    "first_response_within_sla_percent": 0,
    "reports_with_complete_evidence_percent": 0
  }
}
METRICS

echo "Track these metrics quarterly to measure improvement:"
echo ""
echo "Key performance indicators:"
echo "  Acceptance rate > 80% — your reports are high quality"
echo "  Duplicate rate < 15% — your recon and timing are good"
echo "  Clarification rate < 20% — your reports are clear"
echo "  Avg response < 7 days — you're choosing responsive programs"
echo "  Severity dispute rate < 10% — your assessments are accurate"
```

---

## Disclosure Ethics & Philosophy

::card-group
  ::card
  ---
  title: Users Come First
  icon: i-lucide-users
  ---
  Every disclosure decision should prioritize **user safety**. If disclosing a vulnerability would cause more harm than withholding it temporarily, delay disclosure. If withholding allows ongoing exploitation, accelerate disclosure. Users are not bargaining chips.
  ::

  ::card
  ---
  title: Good Faith Always
  icon: i-lucide-heart
  ---
  Approach every interaction assuming the vendor is acting in good faith until proven otherwise. Security teams are often understaffed, underfunded, and overwhelmed. Patience and understanding go further than demands and threats.
  ::

  ::card
  ---
  title: Transparency in Process
  icon: i-lucide-eye
  ---
  Document your process openly. If you eventually need to disclose despite vendor objections, your documented good-faith efforts — every email, every follow-up, every deadline communicated — protect you ethically and legally.
  ::

  ::card
  ---
  title: Community Over Self
  icon: i-lucide-globe
  ---
  Your disclosure practices reflect on the **entire security research community**. Every professional disclosure makes it easier for the next researcher. Every irresponsible one makes it harder. Be the researcher who makes things better for everyone.
  ::

  ::card
  ---
  title: Proportional Response
  icon: i-lucide-scale
  ---
  Match your disclosure urgency to the risk. A cosmetic information disclosure doesn't need a 7-day deadline. A mass account takeover vulnerability with active exploitation evidence justifies aggressive timelines. **Severity drives urgency**.
  ::

  ::card
  ---
  title: Continuous Learning
  icon: i-lucide-graduation-cap
  ---
  Study how others handle disclosure — both the successes and the failures. Learn from researchers like Google Project Zero, Alex Chapman, Stök, and organizations like CERT/CC. The best disclosure practices evolve with the industry.
  ::
::

::caution
Responsible disclosure is both a technical and a human process. Technical skill gets you the finding. Communication skill gets you the bounty. Ethical conduct gets you the career. Always err on the side of caution — when in doubt, prioritize user safety, seek legal guidance, and communicate professionally. Your reputation as a researcher is built over years and can be destroyed in a single interaction.
::