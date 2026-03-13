---
title: Bug Bounty Recon Strategies
description: Reconnaissance strategies, workflows, attack surface mapping, and intelligence gathering techniques for professional bug bounty hunters.
navigation:
  icon: i-lucide-radar
  title: Bug Bounty Recon Strategies
---

## Recon Philosophy

::badge
**Strategy 0 — Mindset Before Methodology**
::

Reconnaissance is not about running tools — it is about **understanding the target better than the target understands itself**. The hunter who maps the largest attack surface with the deepest context wins.

```text [Recon Hierarchy]
┌─────────────────────────────────────────────────────────────────────┐
│                     RECON STRATEGY HIERARCHY                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ┌───────────────┐                                                 │
│   │  WIDE RECON   │  Discover everything connected to the target    │
│   │  (Breadth)    │  Subdomains, acquisitions, ASN, IP ranges       │
│   └──────┬────────┘                                                 │
│          ▼                                                          │
│   ┌───────────────┐                                                 │
│   │  DEEP RECON   │  Go deep into each discovered asset             │
│   │  (Depth)      │  Ports, services, endpoints, parameters         │
│   └──────┬────────┘                                                 │
│          ▼                                                          │
│   ┌───────────────┐                                                 │
│   │ CONTEXTUAL    │  Understand business logic and data flow        │
│   │  RECON        │  User roles, workflows, integrations            │
│   └──────┬────────┘                                                 │
│          ▼                                                          │
│   ┌───────────────┐                                                 │
│   │ CONTINUOUS    │  Monitor for changes 24/7                       │
│   │  RECON        │  New subdomains, endpoints, technologies        │
│   └───────────────┘                                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

::note
80% of critical bugs are found in assets that other hunters never discovered. Your recon depth directly correlates with your payout.
::

---

## Strategy 1 — Scope Intelligence

::badge
**Know What You're Hunting**
::

Before running any tool, fully understand the scope, business structure, and digital footprint of the target organization.

### Scope Analysis

::tabs
  :::tabs-item{icon="i-lucide-building" label="Organization Mapping"}
  ```bash [Corporate Intelligence]
  # Crunchbase — acquisitions, subsidiaries
  # Search: https://www.crunchbase.com/organization/TARGET
  # Document all acquired companies — their domains are often in scope

  # SEC EDGAR filings (for US companies)
  curl -s "https://efts.sec.gov/LATEST/search-index?q=%22target.com%22&dateRange=custom&startdt=2020-01-01&enddt=2024-12-31" | jq

  # Wikipedia — subsidiaries and brands
  # Google dorking for related entities
  site:linkedin.com "Target Corp" "subsidiary"
  site:crunchbase.com "Target Corp" "acquired"

  # Reverse WHOIS — find all domains by same registrant
  # Using whoxy.com API
  curl "https://api.whoxy.com/?key=API_KEY&reverse=whois&name=Target+Corp" | \
    jq -r '.search_result[].domain_name' | sort -u > reverse_whois_domains.txt

  # Using DOMLink
  python3 domLink.py -D target.com -o domlink_output.txt

  # Amass Intel — organization discovery
  amass intel -org "Target Corporation" -o amass_org.txt
  amass intel -d target.com -whois -o amass_whois.txt

  # Combine all root domains
  cat reverse_whois_domains.txt domlink_output.txt amass_org.txt amass_whois.txt | \
    sort -u > all_root_domains.txt

  echo "[+] Root domains discovered: $(wc -l < all_root_domains.txt)"
  ```
  :::

  :::tabs-item{icon="i-lucide-network" label="ASN & IP Range Discovery"}
  ```bash [ASN Enumeration]
  # Find ASN from organization name
  amass intel -org "Target Corp" -asn -o asn_discovery.txt

  # BGP.he.net lookup
  curl -s "https://bgp.he.net/search?search%5Bsearch%5D=Target+Corp&commit=Search" | \
    grep -oP 'AS\d+' | sort -u > target_asns.txt

  # ASNMap — resolve ASN to IP ranges
  cat target_asns.txt | asnmap -silent > asn_ip_ranges.txt

  # Alternative: whois for IP ranges
  whois -h whois.radb.net -- '-i origin AS12345' | grep -oP '(\d+\.){3}\d+/\d+' > ip_ranges.txt

  # Resolve IP ranges to live hosts
  cat asn_ip_ranges.txt | mapcidr -silent | dnsx -silent -ptr -resp-only | \
    grep "target" > ptr_subdomains.txt

  # Reverse DNS on IP ranges
  cat asn_ip_ranges.txt | mapcidr -silent > all_ips_expanded.txt
  cat all_ips_expanded.txt | dnsx -silent -ptr -resp-only | sort -u > reverse_dns.txt

  # Shodan ASN search
  shodan search "asn:AS12345" --fields ip_str,port,org,hostnames --limit 5000 > shodan_asn.txt

  # Censys ASN search
  censys search "autonomous_system.asn:12345" | jq -r '.[] | .ip' > censys_asn_ips.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-file-search" label="Scope Parsing Automation"}
  ```bash [Scope Parser]
  # Parse scope from bug bounty program page
  # Common formats: *.target.com, target.com, specific URLs

  # Auto-parse HackerOne scope
  # bbscope (Bug Bounty Scope tool)
  bbscope h1 -t YOUR_H1_TOKEN -b -o all_scopes.txt
  bbscope bc -t YOUR_BC_TOKEN -b -o all_bc_scopes.txt

  # Filter wildcard scopes (best targets)
  grep '^\*\.' all_scopes.txt | sed 's/^\*\.//' > wildcard_domains.txt

  # Identify out-of-scope
  grep -i "out" scope_page.txt | grep -oP '[\w\-]+\.[\w\.\-]+' > out_of_scope.txt

  # Create scope-aware scanning list
  comm -23 <(sort all_root_domains.txt) <(sort out_of_scope.txt) > in_scope_domains.txt

  echo "[+] In-scope domains: $(wc -l < in_scope_domains.txt)"
  echo "[+] Wildcard programs: $(wc -l < wildcard_domains.txt)"
  ```
  :::
::

### Google Dorking Strategy

::accordion
  :::accordion-item{icon="i-lucide-search" label="Sensitive File Discovery"}
  ```text [Google Dorks — Files]
  # Configuration files
  site:target.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:env
  site:target.com ext:yml | ext:yaml | ext:toml | ext:json inurl:config
  site:target.com ext:log | ext:bak | ext:old | ext:backup | ext:sql | ext:swp

  # Database files
  site:target.com ext:sql | ext:db | ext:dbf | ext:mdb
  site:target.com "MySQL dump" | "PostgreSQL database dump" | "SQLite"

  # Credential files
  site:target.com ext:env | ext:credentials | ext:key | ext:pem | ext:ppk
  site:target.com filetype:env "DB_PASSWORD" | "SECRET_KEY" | "API_KEY"

  # Source code
  site:target.com ext:php intitle:phpinfo | inurl:phpinfo
  site:target.com ext:py | ext:rb | ext:pl | ext:java | ext:cs
  site:target.com ext:bak | ext:old | ext:orig | ext:save | ext:temp | ext:copy

  # Backup & archive
  site:target.com ext:tar | ext:gz | ext:tgz | ext:zip | ext:rar | ext:7z
  site:target.com inurl:backup | inurl:dump | inurl:export
  ```
  :::

  :::accordion-item{icon="i-lucide-lock-open" label="Login & Admin Panel Discovery"}
  ```text [Google Dorks — Panels]
  # Admin panels
  site:target.com inurl:admin | inurl:administrator | inurl:dashboard
  site:target.com inurl:login | inurl:signin | inurl:auth
  site:target.com intitle:"admin" | intitle:"dashboard" | intitle:"control panel"
  site:target.com inurl:portal | inurl:manage | inurl:console

  # CMS specific
  site:target.com inurl:wp-admin | inurl:wp-login
  site:target.com inurl:administrator/index.php (Joomla)
  site:target.com inurl:user/login (Drupal)
  site:target.com inurl:admin/login.jsp | inurl:admin/login.action

  # API documentation
  site:target.com inurl:swagger | inurl:api-docs | inurl:graphql | inurl:graphiql
  site:target.com intitle:"API Documentation" | intitle:"Swagger UI"
  site:target.com inurl:api/v1 | inurl:api/v2 | inurl:api/v3

  # Debug & status pages
  site:target.com inurl:debug | inurl:status | inurl:health
  site:target.com intitle:"phpMyAdmin" | intitle:"Adminer"
  site:target.com intitle:"Index of" inurl:backup
  site:target.com intitle:"Index of" inurl:conf
  ```
  :::

  :::accordion-item{icon="i-lucide-key" label="Credential & Secret Leaks"}
  ```text [Google Dorks — Secrets]
  # Passwords in URLs
  site:target.com inurl:password | inurl:passwd | inurl:pwd
  site:target.com "password" filetype:log | filetype:txt | filetype:cfg

  # API keys
  site:target.com "api_key" | "api_secret" | "apikey" | "access_token"
  site:target.com "Authorization: Bearer" | "Authorization: Basic"

  # Cloud storage
  site:s3.amazonaws.com "target"
  site:blob.core.windows.net "target"
  site:storage.googleapis.com "target"
  "target.com" site:pastebin.com | site:ghostbin.com | site:hastebin.com

  # GitHub leaks
  site:github.com "target.com" password | secret | token | api_key
  site:github.com "target.com" filename:.env | filename:config
  site:github.com "target.com" extension:pem | extension:key

  # Trello boards
  site:trello.com "target.com"
  site:trello.com "target" password | key | secret

  # Error pages revealing info
  site:target.com "Fatal error" | "Warning:" | "Stack trace" | "Exception"
  site:target.com "ORA-" | "mysql_" | "pg_" | "SQLSTATE"
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="Automated Dorking"}
  ```bash [Dorking Automation]
  # Dorkify — automated Google dorking
  python3 dorkify.py -d target.com -o dorks_output.txt

  # GooFuzz
  goofuzz -t target.com -e pdf,doc,docx,xls,xlsx,txt,log,bak,sql,env -d 5

  # Pagodo — passive Google dork
  python3 pagodo.py -d target.com -g dorks.txt -l 100 -o pagodo_results.txt

  # Custom dork automation
  DOMAIN="target.com"
  DORKS=(
    "site:$DOMAIN ext:env"
    "site:$DOMAIN ext:log"
    "site:$DOMAIN ext:sql"
    "site:$DOMAIN ext:bak"
    "site:$DOMAIN ext:yml"
    "site:$DOMAIN inurl:admin"
    "site:$DOMAIN inurl:api"
    "site:$DOMAIN inurl:swagger"
    "site:$DOMAIN intitle:index.of"
    "site:$DOMAIN \"password\""
    "site:github.com \"$DOMAIN\" password"
    "site:pastebin.com \"$DOMAIN\""
    "site:trello.com \"$DOMAIN\""
    "site:s3.amazonaws.com \"$DOMAIN\""
  )

  for dork in "${DORKS[@]}"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$dork'))")
    echo "[*] Dorking: $dork"
    echo "    https://www.google.com/search?q=$encoded"
    sleep 3
  done
  ```
  :::
::

---

## Strategy 2 — Subdomain Discovery

::badge
**Map the Entire Attack Surface**
::

::tip
Use **multiple sources** and **multiple techniques**. No single tool finds everything. The goal is 100% coverage.
::

### Passive Subdomain Collection

::tabs
  :::tabs-item{icon="i-lucide-eye-off" label="Multi-Source Passive"}
  ```bash [Passive Enumeration Pipeline]
  TARGET="target.com"
  OUTPUT="recon/$TARGET/subs"
  mkdir -p $OUTPUT

  # ─── Source 1: Subfinder (40+ sources) ───
  subfinder -d $TARGET -all -recursive -silent -o $OUTPUT/subfinder.txt
  echo "[+] Subfinder: $(wc -l < $OUTPUT/subfinder.txt)"

  # ─── Source 2: Amass passive ───
  amass enum -passive -d $TARGET -timeout 15 -o $OUTPUT/amass.txt 2>/dev/null
  echo "[+] Amass: $(wc -l < $OUTPUT/amass.txt)"

  # ─── Source 3: Chaos ProjectDiscovery ───
  chaos -d $TARGET -silent -o $OUTPUT/chaos.txt 2>/dev/null
  echo "[+] Chaos: $(wc -l < $OUTPUT/chaos.txt)"

  # ─── Source 4: GitHub subdomains ───
  github-subdomains -d $TARGET -t $GITHUB_TOKEN -o $OUTPUT/github.txt 2>/dev/null
  echo "[+] GitHub: $(wc -l < $OUTPUT/github.txt)"

  # ─── Source 5: CRT.sh (Certificate Transparency) ───
  curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
    jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > $OUTPUT/crtsh.txt
  echo "[+] CRT.sh: $(wc -l < $OUTPUT/crtsh.txt)"

  # ─── Source 6: SecurityTrails ───
  curl -s "https://api.securitytrails.com/v1/domain/$TARGET/subdomains" \
    -H "APIKEY: $SECURITYTRAILS_KEY" | jq -r '.subdomains[]' | \
    sed "s/$/.$TARGET/" > $OUTPUT/sectrails.txt
  echo "[+] SecurityTrails: $(wc -l < $OUTPUT/sectrails.txt)"

  # ─── Source 7: Shodan ───
  shodan search "hostname:$TARGET" --fields hostnames --limit 5000 | \
    tr ',' '\n' | grep "$TARGET" | sort -u > $OUTPUT/shodan.txt
  echo "[+] Shodan: $(wc -l < $OUTPUT/shodan.txt)"

  # ─── Source 8: Censys ───
  censys search "services.tls.certificates.leaf.names: $TARGET" | \
    jq -r '.[] | .services[].tls.certificates.leaf.names[]' 2>/dev/null | \
    grep "$TARGET" | sort -u > $OUTPUT/censys.txt
  echo "[+] Censys: $(wc -l < $OUTPUT/censys.txt)"

  # ─── Source 9: VirusTotal ───
  curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=$VT_KEY&domain=$TARGET" | \
    jq -r '.subdomains[]' 2>/dev/null > $OUTPUT/virustotal.txt
  echo "[+] VirusTotal: $(wc -l < $OUTPUT/virustotal.txt)"

  # ─── Source 10: AlienVault OTX ───
  curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/passive_dns" | \
    jq -r '.passive_dns[].hostname' | grep "$TARGET" | sort -u > $OUTPUT/alienvault.txt
  echo "[+] AlienVault: $(wc -l < $OUTPUT/alienvault.txt)"

  # ─── Source 11: Wayback Machine ───
  curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" | \
    unfurl domains | sort -u > $OUTPUT/wayback.txt
  echo "[+] Wayback: $(wc -l < $OUTPUT/wayback.txt)"

  # ─── Source 12: RapidDNS ───
  curl -s "https://rapiddns.io/subdomain/$TARGET#result" | \
    grep -oP '[\w\-]+\.target\.com' | sort -u > $OUTPUT/rapiddns.txt
  echo "[+] RapidDNS: $(wc -l < $OUTPUT/rapiddns.txt)"

  # ─── MERGE ALL ───
  cat $OUTPUT/*.txt | sed 's/\*\.//g' | sort -u > $OUTPUT/all_passive.txt
  echo ""
  echo "══════════════════════════════════════"
  echo "[+] TOTAL UNIQUE PASSIVE SUBDOMAINS: $(wc -l < $OUTPUT/all_passive.txt)"
  echo "══════════════════════════════════════"
  ```
  :::

  :::tabs-item{icon="i-lucide-git-branch" label="GitHub Recon"}
  ```bash [GitHub Intelligence]
  TARGET="target.com"

  # ─── GitHub subdomains ───
  github-subdomains -d $TARGET -t $GITHUB_TOKEN -o github_subs.txt

  # ─── Manual GitHub search queries ───
  # Search in GitHub:
  # "target.com" password
  # "target.com" secret
  # "target.com" api_key
  # "target.com" token
  # "target.com" filename:.env
  # "target.com" filename:config.yml
  # "target.com" filename:docker-compose.yml
  # "target.com" filename:.npmrc _auth
  # "target.com" filename:id_rsa
  # "target.com" filename:.htpasswd
  # "target.com" extension:pem private
  # org:targetcorp password
  # org:targetcorp secret
  # org:targetcorp aws_access_key

  # ─── Trufflehog — scan org repos ───
  trufflehog github --org=targetcorp --only-verified --json > trufflehog_results.json

  # ─── GitDorker ───
  python3 GitDorker.py -t $GITHUB_TOKEN -d dorks.txt -q target.com -o gitdorker_results.txt

  # ─── gitleaks ───
  gitleaks detect --source /path/to/cloned/repo --report-format json --report-path gitleaks_report.json

  # ─── Clone all org repos ───
  gh repo list targetcorp --limit 1000 --json nameWithOwner -q '.[].nameWithOwner' | \
    while read repo; do
      git clone "https://github.com/$repo" repos/$repo 2>/dev/null
      echo "[+] Cloned: $repo"
    done

  # ─── Scan cloned repos for secrets ───
  find repos/ -name "*.py" -o -name "*.js" -o -name "*.yml" -o -name "*.env" -o -name "*.conf" | \
    xargs grep -lE "(password|secret|api_key|token|AWS_ACCESS|PRIVATE_KEY)" 2>/dev/null | \
    tee github_secrets_files.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-globe" label="Certificate Transparency"}
  ```bash [CT Log Mining]
  TARGET="target.com"

  # ─── CRT.sh deep query ───
  # Current certificates
  curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
    jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ct_current.txt

  # Expired certificates (historical subdomains)
  curl -s "https://crt.sh/?q=%25.$TARGET&output=json&exclude=expired" | \
    jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ct_all.txt

  # ─── CertSpotter ───
  curl -s "https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names" | \
    jq -r '.[].dns_names[]' | sort -u > certspotter.txt

  # ─── Facebook CT ───
  curl -s "https://graph.facebook.com/certificates?query=$TARGET&access_token=$FB_TOKEN&fields=domains&limit=10000" | \
    jq -r '.data[].domains[]' | sort -u > fb_ct.txt

  # ─── Google CT ───
  # Via Censys
  censys search "parsed.names: $TARGET" --index-type certificates | \
    jq -r '.[] | .parsed.names[]' | grep "$TARGET" | sort -u > censys_ct.txt

  # ─── Extract organization info from certs ───
  curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
    jq -r '.[].issuer_name' | sort | uniq -c | sort -rn | head -20
  # Reveals CA patterns and certificate management practices

  # ─── Find related domains from same cert (SAN) ───
  curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
    jq -r '.[].name_value' | grep -v "$TARGET" | sort -u > san_related_domains.txt
  echo "[+] Related domains from SAN: $(wc -l < san_related_domains.txt)"
  ```
  :::
::

### Active Subdomain Discovery

::accordion
  :::accordion-item{icon="i-lucide-hammer" label="DNS Brute Force Strategy"}
  ```bash [DNS Brute Force]
  TARGET="target.com"

  # ─── Wordlist selection strategy ───
  # Small scope (< 100 known subs): Use large wordlists
  # Large scope (> 1000 known subs): Use targeted/custom wordlists

  # ─── Puredns — fastest resolver ───
  # Best wordlists:
  # - best-dns-wordlist.txt (9 million entries)
  # - n0kovo_subdomains_huge.txt (3 million)
  # - SecLists dns wordlists

  puredns bruteforce /usr/share/wordlists/best-dns-wordlist.txt $TARGET \
    -r resolvers.txt \
    --wildcard-batch 100000 \
    -w brute_puredns.txt

  echo "[+] Puredns brute: $(wc -l < brute_puredns.txt)"

  # ─── Shuffledns — massdns wrapper ───
  shuffledns -d $TARGET \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
    -r resolvers.txt \
    -o brute_shuffledns.txt

  # ─── Custom resolver list ───
  # Always use fresh, validated resolvers
  dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt
  echo "[+] Valid resolvers: $(wc -l < resolvers.txt)"

  # ─── Multi-level brute force ───
  # Level 1: Direct brute
  puredns bruteforce wordlist.txt $TARGET -r resolvers.txt -w level1.txt

  # Level 2: Brute force discovered subdomains
  cat level1.txt | while read sub; do
    puredns bruteforce wordlist_small.txt "$sub" -r resolvers.txt
  done | sort -u > level2.txt

  # Level 3: Brute force level 2 discoveries
  cat level2.txt | while read sub; do
    puredns bruteforce wordlist_tiny.txt "$sub" -r resolvers.txt
  done | sort -u > level3.txt

  cat level1.txt level2.txt level3.txt | sort -u > brute_all_levels.txt
  echo "[+] Multi-level brute: $(wc -l < brute_all_levels.txt)"
  ```
  :::

  :::accordion-item{icon="i-lucide-shuffle" label="Permutation & Mutation Strategy"}
  ```bash [Permutation Techniques]
  TARGET="target.com"
  KNOWN_SUBS="all_passive.txt"

  # ─── Strategy: Generate intelligent permutations from known subdomains ───
  # If you know: api.target.com, dev.target.com, staging.target.com
  # Generate: api-dev, api-staging, dev-api, staging-api, etc.

  # ─── Gotator — pattern-based permutations ───
  gotator -sub $KNOWN_SUBS -perm /usr/share/wordlists/permutation_words.txt \
    -depth 2 -numbers 3 -mindup -adl -md | sort -u > permuted_gotator.txt
  echo "[+] Gotator permutations: $(wc -l < permuted_gotator.txt)"

  # ─── DNSGen — AI-like domain generation ───
  cat $KNOWN_SUBS | dnsgen -w /usr/share/wordlists/dns_words.txt - | sort -u > permuted_dnsgen.txt
  echo "[+] DNSGen permutations: $(wc -l < permuted_dnsgen.txt)"

  # ─── Altdns — classic permutation ───
  altdns -i $KNOWN_SUBS -o altdns_output.txt \
    -w /usr/share/wordlists/altdns_words.txt
  echo "[+] Altdns permutations: $(wc -l < altdns_output.txt)"

  # ─── Regulator — regex pattern extraction ───
  cat $KNOWN_SUBS | python3 regulator.py $TARGET | sort -u > permuted_regulator.txt
  echo "[+] Regulator patterns: $(wc -l < permuted_regulator.txt)"

  # ─── Resolve all permutations ───
  cat permuted_gotator.txt permuted_dnsgen.txt altdns_output.txt permuted_regulator.txt | \
    sort -u > all_permutations.txt

  puredns resolve all_permutations.txt -r resolvers.txt -w resolved_permutations.txt
  echo "[+] Resolved permutations: $(wc -l < resolved_permutations.txt)"

  # ─── Custom permutation words (most effective) ───
  cat > permutation_words.txt << 'EOF'
  dev
  staging
  stage
  stg
  uat
  test
  testing
  qa
  pre
  prod
  production
  demo
  sandbox
  beta
  alpha
  internal
  private
  corp
  vpn
  admin
  api
  app
  web
  www
  portal
  dashboard
  console
  panel
  manage
  cms
  cdn
  static
  assets
  media
  mail
  smtp
  pop
  imap
  ftp
  ssh
  git
  svn
  ci
  cd
  jenkins
  gitlab
  jira
  confluence
  wiki
  docs
  doc
  help
  support
  status
  monitor
  grafana
  kibana
  elastic
  redis
  mongo
  db
  database
  mysql
  postgres
  mssql
  backup
  bak
  old
  new
  v1
  v2
  v3
  int
  ext
  EOF
  ```
  :::

  :::accordion-item{icon="i-lucide-scan" label="DNS Zone Walking & DNSSEC"}
  ```bash [DNSSEC Zone Walking]
  TARGET="target.com"

  # ─── NSEC zone walking ───
  # If DNSSEC is misconfigured with NSEC (not NSEC3), you can enumerate all records
  ldns-walk @ns1.$TARGET $TARGET > nsec_walk.txt
  dnsrecon -d $TARGET -t zonewalk -o zonewalk.txt

  # ─── NSEC3 hash cracking ───
  # Collect NSEC3 hashes
  dnsrecon -d $TARGET -t zonewalk -n ns1.$TARGET > nsec3_hashes.txt

  # Crack with nsec3walker
  collect $TARGET > $TARGET.collect
  unhash < $TARGET.collect > $TARGET.unhash

  # ─── DNS zone transfer attempt ───
  # Check all nameservers
  dig ns $TARGET +short | while read ns; do
    echo "[*] Testing zone transfer on $ns"
    dig @$ns $TARGET axfr +noall +answer
  done

  # Batch zone transfer
  for ns in $(dig ns $TARGET +short); do
    result=$(dig @$ns $TARGET axfr 2>/dev/null | grep -v "^;")
    if [ -n "$result" ]; then
      echo "[VULN] Zone transfer successful on $ns!"
      echo "$result" > zone_transfer_$ns.txt
    fi
  done

  # ─── DNS record enumeration ───
  # Check all record types
  RECORDS="A AAAA CNAME MX NS TXT SRV SOA CAA PTR NAPTR DNSKEY DS NSEC NSEC3 RRSIG TLSA"
  for type in $RECORDS; do
    result=$(dig $TARGET $type +short 2>/dev/null)
    if [ -n "$result" ]; then
      echo "[$type] $result"
    fi
  done

  # ─── TXT record intelligence ───
  dig $TARGET TXT +short
  # Look for: SPF records (email infrastructure), DKIM, DMARC
  # Cloud provider verification: google-site-verification, facebook-domain-verification
  # These reveal third-party integrations
  ```
  :::

  :::accordion-item{icon="i-lucide-wifi" label="Reverse DNS & PTR Strategy"}
  ```bash [Reverse DNS Intelligence]
  TARGET="target.com"

  # ─── Get all IPs from resolved subdomains ───
  cat resolved_subs.txt | dnsx -silent -a -resp-only | sort -u > target_ips.txt

  # ─── Identify IP ranges ───
  cat target_ips.txt | mapcidr -aggregate -silent > target_ranges.txt

  # ─── Reverse PTR on IP ranges ───
  cat target_ranges.txt | mapcidr -silent | dnsx -silent -ptr -resp-only | \
    grep -iE "$TARGET|target" | sort -u > ptr_discovered.txt

  echo "[+] PTR discovered: $(wc -l < ptr_discovered.txt)"

  # ─── Favicon hash hunting (Shodan) ───
  # Calculate favicon hash
  curl -s "https://target.com/favicon.ico" | python3 -c "
  import mmh3, sys, codecs, requests
  favicon = codecs.encode(sys.stdin.buffer.read(), 'base64')
  hash = mmh3.hash(favicon)
  print(f'Favicon hash: {hash}')
  print(f'Shodan query: http.favicon.hash:{hash}')
  "

  # Search Shodan with favicon hash
  shodan search "http.favicon.hash:HASH_VALUE" --fields ip_str,hostnames,port | \
    tee shodan_favicon.txt

  # ─── TLS certificate hunting ───
  # Find hosts sharing same certificate
  censys search "services.tls.certificates.leaf.subject.common_name: target.com" | \
    jq -r '.[] | .ip' > cert_shared_hosts.txt

  # SSL certificate SAN extraction
  echo | openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -noout -text | grep -oP '(?<=DNS:)[^,]+' | sort -u > san_domains.txt
  ```
  :::
::

### Subdomain Merge & Resolution

```bash [Final Resolution Pipeline]
TARGET="target.com"

# ─── Merge ALL sources ───
cat \
  subs/subfinder.txt \
  subs/amass.txt \
  subs/chaos.txt \
  subs/github.txt \
  subs/crtsh.txt \
  subs/sectrails.txt \
  subs/shodan.txt \
  subs/censys.txt \
  subs/virustotal.txt \
  subs/alienvault.txt \
  subs/wayback.txt \
  subs/rapiddns.txt \
  brute_all_levels.txt \
  resolved_permutations.txt \
  ptr_discovered.txt \
  san_domains.txt \
  2>/dev/null | \
  sed 's/\*\.//g' | \
  grep -E "^[a-zA-Z0-9]" | \
  grep "\.$TARGET$" | \
  sort -u > all_subs_merged.txt

echo "═══════════════════════════════════════════"
echo "[+] TOTAL MERGED SUBDOMAINS: $(wc -l < all_subs_merged.txt)"
echo "═══════════════════════════════════════════"

# ─── Resolve with puredns ───
puredns resolve all_subs_merged.txt \
  -r resolvers.txt \
  --wildcard-batch 100000 \
  -w resolved_final.txt

echo "[+] RESOLVED SUBDOMAINS: $(wc -l < resolved_final.txt)"

# ─── DNS record extraction for resolved subs ───
# A records
cat resolved_final.txt | dnsx -silent -a -resp -o dns_a_records.txt
# AAAA records
cat resolved_final.txt | dnsx -silent -aaaa -resp -o dns_aaaa_records.txt
# CNAME records (for takeover detection)
cat resolved_final.txt | dnsx -silent -cname -resp -o dns_cname_records.txt
# MX records
cat resolved_final.txt | dnsx -silent -mx -resp -o dns_mx_records.txt
# TXT records
cat resolved_final.txt | dnsx -silent -txt -resp -o dns_txt_records.txt

# ─── Extract unique IPs ───
cat dns_a_records.txt | awk '{print $NF}' | sort -u > unique_ips.txt
echo "[+] Unique IPs: $(wc -l < unique_ips.txt)"
```

---

## Strategy 3 — HTTP Probing & Fingerprinting

::badge
**Identify Live Services & Technologies**
::

### Alive Host Discovery

::tabs
  :::tabs-item{icon="i-lucide-activity" label="httpx Deep Probing"}
  ```bash [httpx Comprehensive Scan]
  # ─── Basic alive check ───
  cat resolved_final.txt | httpx -silent -o alive_basic.txt

  # ─── Full metadata extraction ───
  cat resolved_final.txt | httpx \
    -silent \
    -status-code \
    -title \
    -tech-detect \
    -web-server \
    -content-length \
    -content-type \
    -follow-redirects \
    -location \
    -method \
    -ip \
    -cname \
    -cdn \
    -hash sha256 \
    -jarm \
    -favicon \
    -tls-grab \
    -tls-probe \
    -pipeline \
    -http2 \
    -vhost \
    -json \
    -o httpx_full.json

  # ─── Parse interesting results ───
  # Find unique technologies
  cat httpx_full.json | jq -r '.technologies[]?' 2>/dev/null | sort | uniq -c | sort -rn > tech_summary.txt

  # Find unique web servers
  cat httpx_full.json | jq -r '.webserver // empty' 2>/dev/null | sort | uniq -c | sort -rn > servers_summary.txt

  # Find 401/403 pages (potential bypass targets)
  cat httpx_full.json | jq -r 'select(.status_code == 401 or .status_code == 403) | .url' > restricted_pages.txt

  # Find pages with forms (login/input targets)
  cat httpx_full.json | jq -r 'select(.title | test("login|sign|register|admin|dashboard"; "i")) | .url' > login_pages.txt

  # Find non-standard ports
  cat httpx_full.json | jq -r '.url' | grep -oP ':\d+' | sort | uniq -c | sort -rn > port_distribution.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-layers" label="Multi-Port Probing"}
  ```bash [Port-Based Service Discovery]
  # ─── Probe common web ports ───
  PORTS="80,443,8080,8443,8000,8888,3000,3001,4443,5000,5001,7443,9000,9090,9443,10000"

  cat resolved_final.txt | httpx \
    -ports $PORTS \
    -silent \
    -status-code \
    -title \
    -tech-detect \
    -follow-redirects \
    -o alive_multiport.txt

  echo "[+] Alive multi-port services: $(wc -l < alive_multiport.txt)"

  # ─── Naabu + httpx pipeline ───
  naabu -list resolved_final.txt \
    -top-ports 1000 \
    -silent | \
    httpx -silent -status-code -title -tech-detect -o naabu_httpx.txt

  # ─── Full port scan on priority targets ───
  # Identify priority targets first
  cat alive_multiport.txt | grep -iE "(admin|staging|dev|test|internal|corp|vpn)" > priority_targets.txt

  # Deep port scan on priority targets
  cat priority_targets.txt | unfurl domains | sort -u > priority_domains.txt
  naabu -list priority_domains.txt -p - -rate 3000 -silent | \
    httpx -silent -status-code -title -o priority_deep_scan.txt

  # ─── Non-HTTP service detection ───
  nmap -sV -sC -p 21,22,23,25,53,110,111,135,139,143,161,389,445,465,587,636,993,995,1433,1521,2049,3306,3389,5432,5900,5985,6379,8009,11211,27017 \
    -iL unique_ips.txt -oA nmap_services --open -T4

  # Parse nmap for interesting services
  grep -E "open" nmap_services.gnmap | \
    awk -F'/' '{print $1}' | sort | uniq -c | sort -rn > service_summary.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-fingerprint" label="Technology Fingerprinting"}
  ```bash [Deep Fingerprinting]
  # ─── WhatWeb — detailed fingerprinting ───
  whatweb -i alive_basic.txt --color=never --log-json=whatweb.json -a 3

  # ─── Wappalyzer CLI ───
  cat alive_basic.txt | while read url; do
    wappalyzer "$url" 2>/dev/null
  done | tee wappalyzer_results.txt

  # ─── Nuclei tech detection ───
  nuclei -l alive_basic.txt -tags tech -silent -json -o nuclei_tech.json

  # ─── webanalyze ───
  webanalyze -hosts alive_basic.txt -crawl 2 -output json > webanalyze.json

  # ─── Custom header analysis ───
  cat alive_basic.txt | while read url; do
    headers=$(curl -s -D - -o /dev/null "$url" -m 10 2>/dev/null)
    server=$(echo "$headers" | grep -i "^server:" | head -1)
    powered=$(echo "$headers" | grep -i "^x-powered-by:" | head -1)
    aspnet=$(echo "$headers" | grep -i "^x-aspnet" | head -1)
    framework=$(echo "$headers" | grep -i "^x-framework" | head -1)
    
    echo "$url | $server | $powered | $aspnet | $framework" | grep -v "| *|"
  done | tee custom_headers.txt

  # ─── CMS detection ───
  # WordPress
  cat alive_basic.txt | httpx -silent -path "/wp-login.php" -mc 200 -o wordpress_sites.txt
  cat alive_basic.txt | httpx -silent -path "/wp-json/wp/v2/users" -mc 200 -o wp_user_enum.txt

  # Joomla
  cat alive_basic.txt | httpx -silent -path "/administrator/" -mc 200 -o joomla_sites.txt

  # Drupal
  cat alive_basic.txt | httpx -silent -path "/user/login" -mc 200 -mr "Drupal" -o drupal_sites.txt

  # Laravel
  cat alive_basic.txt | httpx -silent -path "/.env" -mc 200 -mr "APP_KEY" -o laravel_env.txt

  echo "═══════════════════════════════"
  echo "[+] WordPress: $(wc -l < wordpress_sites.txt)"
  echo "[+] Joomla: $(wc -l < joomla_sites.txt)"
  echo "[+] Drupal: $(wc -l < drupal_sites.txt)"
  echo "[+] Laravel .env: $(wc -l < laravel_env.txt)"
  echo "═══════════════════════════════"
  ```
  :::
::

### Visual Recon

::collapsible
---
label: "Screenshot & Visual Discovery"
---

```bash [Visual Reconnaissance]
# ─── Gowitness — bulk screenshots ───
gowitness file -f alive_basic.txt -P screenshots/ --threads 10
gowitness report serve  # View results in browser

# ─── Aquatone — visual recon ───
cat alive_basic.txt | aquatone -out aquatone_output/ -threads 10 -scan-timeout 500

# ─── Eyewitness ───
python3 EyeWitness.py -f alive_basic.txt --web -d eyewitness_output/ --threads 10

# ─── httpx screenshot ───
cat alive_basic.txt | httpx -silent -screenshot -store-response -output httpx_screenshots/

# ─── Visual similarity clustering ───
# After screenshots, look for:
# - Default pages (Apache, Nginx, IIS default)
# - Login pages
# - Admin panels
# - Error pages revealing tech stack
# - API documentation (Swagger, GraphQL)
# - Development/staging environments
# - Internal tools exposed

# ─── Mass title analysis ───
cat httpx_full.json | jq -r '[.url, .title] | @tsv' | sort -t$'\t' -k2 | \
  awk -F'\t' '{
    if ($2 == prev) count++; 
    else { if (count > 1) print count" "$2; count=1; }
    prev=$2
  }' | sort -rn > title_clusters.txt

# Unique titles = potentially interesting custom applications
cat httpx_full.json | jq -r '.title // empty' | sort | uniq -c | sort -rn | head -50
```
::

---

## Strategy 4 — URL & Endpoint Intelligence

::badge
**Discover Every Endpoint**
::

### Historical URL Mining

::tabs
  :::tabs-item{icon="i-lucide-history" label="Wayback & Archive Mining"}
  ```bash [Historical URL Collection]
  TARGET="target.com"

  # ─── Multi-source URL collection ───
  # Waybackurls
  echo $TARGET | waybackurls | tee urls_wayback.txt
  echo "[+] Wayback: $(wc -l < urls_wayback.txt)"

  # GAU (GetAllUrls) — Wayback + Common Crawl + OTX + URLScan
  echo $TARGET | gau --threads 5 --subs --providers wayback,commoncrawl,otx,urlscan | \
    tee urls_gau.txt
  echo "[+] GAU: $(wc -l < urls_gau.txt)"

  # Waymore — extended historical mining
  python3 waymore.py -i $TARGET -mode U -oU urls_waymore.txt
  echo "[+] Waymore: $(wc -l < urls_waymore.txt)"

  # Web Archive direct API
  curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=json&fl=original&collapse=urlkey&limit=100000" | \
    jq -r '.[][0]' | tail -n +2 | sort -u > urls_webarchive.txt
  echo "[+] Web Archive API: $(wc -l < urls_webarchive.txt)"

  # Common Crawl
  INDEX="CC-MAIN-2024-10"
  curl -s "https://index.commoncrawl.org/$INDEX-index?url=*.$TARGET&output=json" | \
    jq -r '.url' | sort -u > urls_commoncrawl.txt

  # ─── Merge all historical URLs ───
  cat urls_wayback.txt urls_gau.txt urls_waymore.txt urls_webarchive.txt urls_commoncrawl.txt | \
    sort -u > urls_all_historical.txt

  echo "═══════════════════════════════════"
  echo "[+] TOTAL HISTORICAL URLS: $(wc -l < urls_all_historical.txt)"
  echo "═══════════════════════════════════"
  ```
  :::

  :::tabs-item{icon="i-lucide-filter" label="URL Filtering & Classification"}
  ```bash [Smart URL Filtering]
  URLS="urls_all_historical.txt"

  # ─── Remove junk (static assets, tracking) ───
  cat $URLS | grep -viE "\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|avi|mov|webp|webm)(\?|$)" | \
    grep -viE "(google-analytics|doubleclick|facebook\.com/tr|cdn\.segment)" | \
    sort -u > urls_filtered.txt

  # ─── Extract URLs with parameters (injection targets) ───
  cat urls_filtered.txt | grep "=" | sort -u > urls_with_params.txt
  echo "[+] URLs with parameters: $(wc -l < urls_with_params.txt)"

  # ─── Extract unique parameters ───
  cat urls_with_params.txt | unfurl keys | sort | uniq -c | sort -rn > param_frequency.txt
  echo "[+] Unique parameters: $(cat param_frequency.txt | wc -l)"

  # ─── Classify by extension ───
  cat urls_filtered.txt | unfurl path | grep -oP '\.[a-zA-Z0-9]+$' | \
    sort | uniq -c | sort -rn > extension_distribution.txt

  # ─── Interesting file extensions ───
  cat urls_filtered.txt | grep -iE "\.(php|asp|aspx|jsp|jspx|do|action|cgi|pl|py|rb|cfm)(\?|$)" | \
    sort -u > urls_dynamic.txt
  echo "[+] Dynamic URLs: $(wc -l < urls_dynamic.txt)"

  # ─── Sensitive file patterns ───
  cat urls_filtered.txt | grep -iE "\.(env|bak|sql|config|conf|cfg|ini|log|old|backup|swp|sav|orig|dist|yml|yaml|toml|json|xml|key|pem|ppk|p12|pfx|jks|keystore)(\?|$)" | \
    sort -u > urls_sensitive.txt
  echo "[+] Sensitive files: $(wc -l < urls_sensitive.txt)"

  # ─── API endpoints ───
  cat urls_filtered.txt | grep -iE "(api/|/v[0-9]+/|graphql|rest/|soap/|json|xml)" | \
    sort -u > urls_api.txt
  echo "[+] API endpoints: $(wc -l < urls_api.txt)"

  # ─── Authentication endpoints ───
  cat urls_filtered.txt | grep -iE "(login|signin|auth|register|signup|forgot|reset|password|token|session|oauth|sso|saml|callback|logout)" | \
    sort -u > urls_auth.txt
  echo "[+] Auth endpoints: $(wc -l < urls_auth.txt)"

  # ─── Admin/management endpoints ───
  cat urls_filtered.txt | grep -iE "(admin|manage|dashboard|console|panel|portal|control|cms|backend)" | \
    sort -u > urls_admin.txt
  echo "[+] Admin endpoints: $(wc -l < urls_admin.txt)"

  # ─── Upload endpoints ───
  cat urls_filtered.txt | grep -iE "(upload|import|attach|file|image|media|document)" | \
    sort -u > urls_upload.txt
  echo "[+] Upload endpoints: $(wc -l < urls_upload.txt)"

  # ─── Redirect endpoints ───
  cat urls_filtered.txt | grep -iE "(redirect|return|next|url|dest|redir|target|continue|go|out|link|view|callback)" | \
    sort -u > urls_redirect.txt
  echo "[+] Redirect endpoints: $(wc -l < urls_redirect.txt)"
  ```
  :::

  :::tabs-item{icon="i-lucide-crosshair" label="GF Pattern Matching"}
  ```bash [GF Patterns for Bug Classes]
  # ─── Install GF patterns ───
  # git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf

  # ─── Classify URLs by vulnerability type ───
  cat urls_with_params.txt | gf xss | sort -u > gf_xss.txt
  cat urls_with_params.txt | gf sqli | sort -u > gf_sqli.txt
  cat urls_with_params.txt | gf ssrf | sort -u > gf_ssrf.txt
  cat urls_with_params.txt | gf lfi | sort -u > gf_lfi.txt
  cat urls_with_params.txt | gf rce | sort -u > gf_rce.txt
  cat urls_with_params.txt | gf redirect | sort -u > gf_redirect.txt
  cat urls_with_params.txt | gf idor | sort -u > gf_idor.txt
  cat urls_with_params.txt | gf ssti | sort -u > gf_ssti.txt
  cat urls_with_params.txt | gf debug_logic | sort -u > gf_debug.txt

  echo "═══════════════════════════════"
  echo "[+] XSS candidates: $(wc -l < gf_xss.txt)"
  echo "[+] SQLi candidates: $(wc -l < gf_sqli.txt)"
  echo "[+] SSRF candidates: $(wc -l < gf_ssrf.txt)"
  echo "[+] LFI candidates: $(wc -l < gf_lfi.txt)"
  echo "[+] RCE candidates: $(wc -l < gf_rce.txt)"
  echo "[+] Redirect candidates: $(wc -l < gf_redirect.txt)"
  echo "[+] IDOR candidates: $(wc -l < gf_idor.txt)"
  echo "[+] SSTI candidates: $(wc -l < gf_ssti.txt)"
  echo "═══════════════════════════════"
  ```
  :::
::

### Active Crawling

::code-collapse
---
label: "Active Web Crawling Strategies"
---

```bash [Katana — Advanced Crawling]
# ─── Standard crawl ───
katana -list alive_basic.txt \
  -d 5 \
  -jc \
  -kf all \
  -aff \
  -ef css,png,jpg,gif,svg,woff,ttf,eot,ico \
  -silent \
  -o katana_standard.txt

# ─── Headless crawl (JavaScript rendering) ───
katana -list alive_basic.txt \
  -d 5 \
  -jc \
  -headless \
  -no-sandbox \
  -known-files all \
  -automatic-form-fill \
  -form-extraction \
  -silent \
  -o katana_headless.txt

# ─── Authenticated crawl ───
katana -list alive_basic.txt \
  -d 5 \
  -jc \
  -headless \
  -headers "Cookie: session=YOUR_SESSION; token=YOUR_TOKEN" \
  -headers "Authorization: Bearer YOUR_JWT" \
  -silent \
  -o katana_authenticated.txt

# ─── Scope-restricted crawl ───
katana -list alive_basic.txt \
  -d 5 \
  -jc \
  -cs "target.com" \
  -do \
  -silent \
  -o katana_scoped.txt

# ─── Extract form actions ───
katana -list alive_basic.txt \
  -d 3 \
  -jc \
  -headless \
  -field-config form_action \
  -silent \
  -o katana_forms.txt
```

```bash [Gospider — Fast Crawling]
# ─── Concurrent crawl ───
gospider -S alive_basic.txt \
  -c 10 \
  -d 3 \
  --other-source \
  --include-subs \
  --include-other-source \
  -o gospider_output/

# ─── Extract from gospider output ───
cat gospider_output/* | grep -oP 'https?://[^\s"]+' | sort -u > gospider_urls.txt

# ─── With authentication ───
gospider -S alive_basic.txt \
  -c 5 \
  -d 3 \
  --cookie "session=YOUR_SESSION" \
  --header "Authorization: Bearer YOUR_JWT" \
  -o gospider_auth/
```

```bash [Hakrawler — Lightweight Crawl]
# ─── Standard ───
cat alive_basic.txt | hakrawler -d 3 -insecure -subs | sort -u > hakrawler_urls.txt

# ─── With scope ───
cat alive_basic.txt | hakrawler -d 3 -scope "target.com" -insecure | sort -u

# ─── Merge all crawled URLs ───
cat katana_standard.txt katana_headless.txt gospider_urls.txt hakrawler_urls.txt | \
  sort -u > urls_crawled.txt

echo "[+] Total crawled URLs: $(wc -l < urls_crawled.txt)"

# ─── Final merge: Historical + Crawled ───
cat urls_all_historical.txt urls_crawled.txt | sort -u > urls_master.txt
echo "[+] MASTER URL LIST: $(wc -l < urls_master.txt)"
```
::

### JavaScript Recon Strategy

::warning
JavaScript files are gold mines. They contain API endpoints, secret keys, internal paths, business logic, and hidden functionality that are invisible from the UI.
::

::tabs
  :::tabs-item{icon="i-lucide-file-code" label="JS File Collection"}
  ```bash [JavaScript Discovery]
  TARGET="target.com"

  # ─── Extract JS from all URL sources ───
  cat urls_master.txt | grep -iE "\.js(\?|$)" | sort -u > js_urls_all.txt

  # ─── Find JS via httpx ───
  cat alive_basic.txt | httpx -silent -mc 200 | while read url; do
    curl -s "$url" | grep -oP 'src="[^"]*\.js[^"]*"' | grep -oP '"[^"]*"' | tr -d '"' | \
      sed "s|^//|https://|;s|^/|$url/|"
  done | sort -u >> js_urls_all.txt

  # ─── Find JS from source maps ───
  cat js_urls_all.txt | while read url; do
    # Check for .map file
    map_url="${url}.map"
    status=$(curl -s -o /dev/null -w "%{http_code}" "$map_url" -m 5)
    [ "$status" = "200" ] && echo "[SOURCEMAP] $map_url"
  done | tee js_sourcemaps.txt

  # ─── Probe JS files for alive ───
  cat js_urls_all.txt | sort -u | httpx -silent -mc 200 -content-type | \
    grep "javascript\|application/js" > js_alive.txt

  echo "[+] Alive JS files: $(wc -l < js_alive.txt)"

  # ─── Download all JS files ───
  mkdir -p js_downloaded
  cat js_alive.txt | while read url; do
    filename=$(echo "$url" | md5sum | cut -d' ' -f1)
    curl -s "$url" -o "js_downloaded/${filename}.js" -m 10
  done

  echo "[+] Downloaded: $(ls js_downloaded/ | wc -l) JS files"
  ```
  :::

  :::tabs-item{icon="i-lucide-key" label="JS Secret Extraction"}
  ```bash [Secret Mining from JavaScript]
  # ─── LinkFinder — endpoint extraction ───
  cat js_alive.txt | while read url; do
    python3 linkfinder.py -i "$url" -o cli 2>/dev/null
  done | sort -u > js_endpoints.txt
  echo "[+] JS endpoints: $(wc -l < js_endpoints.txt)"

  # ─── SecretFinder — secrets in JS ───
  cat js_alive.txt | while read url; do
    python3 SecretFinder.py -i "$url" -o cli 2>/dev/null
  done | sort -u > js_secrets.txt
  echo "[+] JS secrets: $(wc -l < js_secrets.txt)"

  # ─── Mantra — pattern-based secret detection ───
  cat js_alive.txt | mantra -s | tee js_mantra.txt

  # ─── Custom regex extraction ───
  find js_downloaded/ -name "*.js" -exec cat {} \; | \
    grep -oP '(?i)(api[_\-]?key|api[_\-]?secret|access[_\-]?key|secret[_\-]?key|auth[_\-]?token|private[_\-]?key|client[_\-]?secret|consumer[_\-]?key|bearer|jwt|token)\s*[=:]\s*["\x27][a-zA-Z0-9_\-\.\/\+]{8,}["\x27]' | \
    sort -u > js_regex_secrets.txt

  # ─── AWS keys ───
  find js_downloaded/ -name "*.js" -exec cat {} \; | \
    grep -oP '(AKIA[0-9A-Z]{16})' | sort -u > aws_access_keys.txt

  # ─── Private keys ───
  find js_downloaded/ -name "*.js" -exec cat {} \; | \
    grep -oP '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----' | sort -u > private_keys.txt

  # ─── Google Maps API keys ───
  find js_downloaded/ -name "*.js" -exec cat {} \; | \
    grep -oP 'AIza[0-9A-Za-z_\-]{35}' | sort -u > google_api_keys.txt

  # ─── Slack tokens ───
  find js_downloaded/ -name "*.js" -exec cat {} \; | \
    grep -oP 'xox[baprs]-[0-9a-zA-Z\-]+' | sort -u > slack_tokens.txt

  # ─── Internal URLs / domains ───
  find js_downloaded/ -name "*.js" -exec cat {} \; | \
    grep -oP 'https?://[a-zA-Z0-9\.\-]+\.(internal|corp|local|dev|staging|test)[a-zA-Z0-9\.\-/]*' | \
    sort -u > internal_urls.txt
  echo "[+] Internal URLs found: $(wc -l < internal_urls.txt)"

  # ─── Hardcoded credentials ───
  find js_downloaded/ -name "*.js" -exec cat {} \; | \
    grep -oP '(?i)(password|passwd|pwd|credentials)\s*[=:]\s*["\x27][^\x27"]{4,}["\x27]' | \
    sort -u > hardcoded_creds.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-route" label="JS Endpoint Analysis"}
  ```bash [Deep JS Endpoint Mining]
  # ─── Extract all API paths from JS ───
  find js_downloaded/ -name "*.js" -exec cat {} \; | \
    grep -oP '["'"'"'](\/api\/[a-zA-Z0-9_\-\/\{\}\.]+)["'"'"']' | \
    tr -d "\"'" | sort -u > js_api_paths.txt

  # ─── Extract relative paths ───
  find js_downloaded/ -name "*.js" -exec cat {} \; | \
    grep -oP '["'"'"'](\/[a-zA-Z0-9_\-\/]{2,})["'"'"']' | \
    tr -d "\"'" | sort -u > js_relative_paths.txt

  # ─── Extract full URLs ───
  find js_downloaded/ -name "*.js" -exec cat {} \; | \
    grep -oP 'https?://[a-zA-Z0-9\.\-]+[a-zA-Z0-9\.\-\/\?\&\=\_\%\#]*' | \
    sort -u > js_full_urls.txt

  # ─── Probe discovered endpoints ───
  cat js_api_paths.txt | while read path; do
    cat alive_basic.txt | while read base; do
      echo "${base}${path}"
    done
  done | httpx -silent -mc 200,201,204,301,302,401,403,405 -o js_endpoints_alive.txt

  echo "[+] Alive JS endpoints: $(wc -l < js_endpoints_alive.txt)"

  # ─── Webpack/build analysis ───
  # Look for webpack chunk manifests
  find js_downloaded/ -name "*.js" -exec grep -l "webpackChunk\|__webpack_require__" {} \; > webpack_files.txt

  # Extract webpack chunk names (reveal all routes)
  find js_downloaded/ -name "*.js" -exec cat {} \; | \
    grep -oP '(?:path|route)\s*:\s*["'"'"']([^"'"'"']+)["'"'"']' | \
    sort -u > webpack_routes.txt

  # ─── React/Vue/Angular route extraction ───
  find js_downloaded/ -name "*.js" -exec cat {} \; | \
    grep -oP '(?:path|component|route|to)\s*:\s*["'"'"'](/[a-zA-Z0-9_\-\/\:]+)["'"'"']' | \
    sort -u > frontend_routes.txt
  echo "[+] Frontend routes: $(wc -l < frontend_routes.txt)"
  ```
  :::
::

---

## Strategy 5 — Parameter Discovery

::badge
**Find Every Input Vector**
::

### Parameter Mining

::tabs
  :::tabs-item{icon="i-lucide-search-code" label="Parameter Discovery Tools"}
  ```bash [Parameter Enumeration]
  # ─── Arjun — smart parameter discovery ───
  # GET parameters
  arjun -u https://target.com/api/endpoint -m GET -t 50 -o arjun_get.json

  # POST parameters
  arjun -u https://target.com/api/endpoint -m POST -t 50 -o arjun_post.json

  # JSON body parameters
  arjun -u https://target.com/api/endpoint -m JSON -t 50 -o arjun_json.json

  # With authentication
  arjun -u https://target.com/api/endpoint -m GET \
    --headers "Cookie: session=YOUR_SESSION" \
    --headers "Authorization: Bearer TOKEN" \
    -t 50

  # Multiple URLs
  arjun -i alive_basic.txt -m GET -t 50 -o arjun_batch.json

  # Custom wordlist
  arjun -u https://target.com/endpoint -m GET \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

  # ─── ParamSpider — URL-based parameter discovery ───
  paramspider -d target.com --exclude woff,css,js,png,svg,jpg,gif -o paramspider.txt

  # ─── x8 — fast hidden parameter discovery ───
  x8 -u "https://target.com/api/endpoint" -w /usr/share/wordlists/params.txt

  # ─── Custom parameter wordlist from historical URLs ───
  cat urls_with_params.txt | unfurl keys | sort | uniq -c | sort -rn | \
    awk '{print $2}' > custom_param_wordlist.txt
  echo "[+] Custom param wordlist: $(wc -l < custom_param_wordlist.txt) parameters"
  ```
  :::

  :::tabs-item{icon="i-lucide-braces" label="Hidden Parameter Strategies"}
  ```bash [Hidden Parameter Techniques]
  # ─── Strategy 1: Wordlist-based fuzzing ───
  ffuf -u "https://target.com/api/users?FUZZ=test" \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -mc all -ac -t 100 -o hidden_params_get.json -of json

  # ─── Strategy 2: POST body parameter fuzzing ───
  ffuf -u "https://target.com/api/users" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "FUZZ=test" \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -mc all -ac -t 100 -o hidden_params_post.json -of json

  # ─── Strategy 3: JSON property fuzzing ───
  ffuf -u "https://target.com/api/users" -X POST \
    -H "Content-Type: application/json" \
    -d '{"FUZZ":"test"}' \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -mc all -ac -t 100

  # ─── Strategy 4: Header parameter fuzzing ───
  ffuf -u "https://target.com/api/users" \
    -H "FUZZ: 127.0.0.1" \
    -w /usr/share/seclists/Discovery/Web-Content/BurpSuite-ParamMiner/uppercase-headers.txt \
    -mc all -ac -t 100

  # ─── Strategy 5: Mass assignment testing ───
  # Collect all known parameters from registration/profile
  # Then add extra fields to update requests
  # Common mass assignment params:
  MASS_PARAMS="role,admin,is_admin,isAdmin,is_staff,isStaff,privilege,\
  permissions,group,user_type,userType,account_type,accountType,\
  verified,is_verified,isVerified,approved,is_approved,\
  balance,credits,points,\
  email_verified,phone_verified,two_factor,2fa,mfa"

  echo $MASS_PARAMS | tr ',' '\n' | while read param; do
    response=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
      "https://target.com/api/profile" -X PUT \
      -H "Cookie: session=YOUR_SESSION" \
      -H "Content-Type: application/json" \
      -d "{\"name\":\"test\",\"$param\":true}")
    echo "$param → $response"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-list" label="Parameter Pollution"}
  ```text [HTTP Parameter Pollution (HPP)]
  # ─── Server-side HPP ───
  # Duplicate parameters — different servers handle differently
  
  # PHP: Takes LAST value
  GET /page?id=1&id=2  → id=2
  
  # ASP.NET: Concatenates
  GET /page?id=1&id=2  → id=1,2
  
  # Flask/Django: Takes FIRST value
  GET /page?id=1&id=2  → id=1
  
  # Express.js: Returns array
  GET /page?id=1&id=2  → id=[1,2]

  # ─── Bypass techniques ───
  # WAF sees:          Backend sees:
  id=safe&id=payload   id=payload (PHP)
  id=payload&id=safe   id=payload (Flask)

  # ─── Array injection ───
  id[]=1&id[]=2
  id=1&id=2
  {"id": [1, 2]}
  {"id": "1", "id": "2"}

  # ─── Different encoding for same param ───
  id=1&%69%64=2
  id=1&ID=2
  id=1&Id=2
  ```
  :::
::

---

## Strategy 6 — Content Discovery

::badge
**Find Hidden Files & Directories**
::

### Smart Wordlist Strategy

::accordion
  :::accordion-item{icon="i-lucide-book-open" label="Wordlist Selection Guide"}
  | Target Type | Recommended Wordlist | Tool |
  | ----------- | -------------------- | ---- |
  | General web | `raft-large-directories.txt` | feroxbuster |
  | PHP application | `PHP.fuzz.txt` + `raft-large-files.txt` | ffuf |
  | ASP.NET application | `iis-shortname.txt` + `raft-large-words.txt` | gobuster |
  | Java/Spring | `spring-boot.txt` + `raft-large-directories.txt` | feroxbuster |
  | API endpoints | `api-endpoints.txt` + `api-seen-in-wild.txt` | ffuf |
  | CMS (WordPress) | `wp-plugins.fuzz.txt` + `wp-themes.fuzz.txt` | wpscan |
  | Backup files | `raft-large-files.txt` | ffuf |
  | Node.js | `nodejs-common.txt` | feroxbuster |
  | Ruby on Rails | `rails-common.txt` | ffuf |
  | Cloud/DevOps | `cloud-metadata.txt` + `devops-common.txt` | nuclei |

  ```bash [Custom Wordlist Generation]
  # ─── CeWL — custom wordlist from target ───
  cewl https://target.com -d 3 -m 5 -w cewl_wordlist.txt

  # ─── Generate wordlist from discovered URLs ───
  cat urls_master.txt | unfurl paths | \
    tr '/' '\n' | sort | uniq -c | sort -rn | \
    awk '{print $2}' | grep -v '^$' > custom_dirs.txt

  # ─── Combine with standard wordlists ───
  cat custom_dirs.txt \
    /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
    /usr/share/seclists/Discovery/Web-Content/common.txt | \
    sort -u > combined_wordlist.txt
  ```
  :::

  :::accordion-item{icon="i-lucide-hard-drive" label="Recursive Directory Brute Force"}
  ```bash [Deep Content Discovery]
  # ─── Feroxbuster — recursive by default ───
  feroxbuster -u https://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
    -x php,asp,aspx,jsp,html,js,json,xml,txt,bak,old,conf,yml,env,log,sql \
    -t 100 \
    -d 4 \
    --smart \
    --auto-tune \
    --collect-words \
    --collect-backups \
    --collect-extensions \
    --dont-scan "logout|signout|exit" \
    --silent \
    -o ferox_deep.txt

  # ─── Targeted extension discovery ───
  # Step 1: Find directories
  ffuf -u https://target.com/FUZZ/ \
    -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
    -mc 200,301,302,403 -ac -t 100 -o dirs.json -of json

  # Step 2: Fuzz extensions in discovered directories
  cat dirs.json | jq -r '.results[].url' | while read dir; do
    ffuf -u "${dir}FUZZ" \
      -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt \
      -mc 200 -ac -t 50
  done

  # ─── Backup file discovery ───
  cat alive_basic.txt | while read url; do
    domain=$(echo "$url" | unfurl domain)
    base=$(echo "$url" | unfurl apexes)
    
    BACKUP_PATHS=(
      "/${domain}.zip" "/${domain}.tar.gz" "/${domain}.rar"
      "/${base}.zip" "/${base}.tar.gz" "/${base}.sql"
      "/backup.zip" "/backup.tar.gz" "/backup.sql"
      "/db.sql" "/database.sql" "/dump.sql"
      "/site.zip" "/www.zip" "/web.zip"
      "/.git/HEAD" "/.svn/entries" "/.hg/dirstate"
      "/.DS_Store" "/Thumbs.db"
      "/wp-config.php.bak" "/wp-config.php.old"
      "/web.config.old" "/web.config.bak"
      "/.env" "/.env.bak" "/.env.production" "/.env.staging"
      "/config.php.bak" "/settings.py.bak"
    )
    
    for path in "${BACKUP_PATHS[@]}"; do
      code=$(curl -s -o /dev/null -w "%{http_code}" "${url}${path}" -m 5)
      [ "$code" = "200" ] && echo "[FOUND] ${url}${path}"
    done
  done | tee backup_files.txt
  ```
  :::

  :::accordion-item{icon="i-lucide-git-branch" label="Git & Source Code Exposure"}
  ```bash [Source Code Discovery]
  # ─── Git exposure detection ───
  cat alive_basic.txt | while read url; do
    git_check=$(curl -s -o /dev/null -w "%{http_code}" "${url}/.git/HEAD" -m 5)
    if [ "$git_check" = "200" ]; then
      echo "[GIT EXPOSED] $url"
      
      # Dump the git repository
      python3 git-dumper.py "${url}/.git/" "git_dumps/$(echo $url | md5sum | cut -d' ' -f1)/"
    fi
  done | tee git_exposed.txt

  # ─── GitTools — extraction ───
  bash gitdumper.sh https://target.com/.git/ git_output/
  bash extractor.sh git_output/ extracted_source/

  # ─── Search extracted source for secrets ───
  trufflehog filesystem --directory extracted_source/ --json > git_secrets.json
  gitleaks detect --source extracted_source/ --report-format json --report-path gitleaks.json

  # ─── SVN exposure ───
  cat alive_basic.txt | while read url; do
    svn_check=$(curl -s -o /dev/null -w "%{http_code}" "${url}/.svn/entries" -m 5)
    [ "$svn_check" = "200" ] && echo "[SVN EXPOSED] $url"
  done

  # ─── DS_Store parsing ───
  cat alive_basic.txt | while read url; do
    ds_check=$(curl -s -o /dev/null -w "%{http_code}" "${url}/.DS_Store" -m 5)
    if [ "$ds_check" = "200" ]; then
      curl -s "${url}/.DS_Store" -o ds_store_temp
      python3 ds_store_parser.py ds_store_temp
    fi
  done

  # ─── Nuclei exposure checks ───
  nuclei -l alive_basic.txt -tags exposure,config -silent -o exposure_nuclei.txt
  ```
  :::
::

### VHOST & Virtual Host Discovery

```bash [Virtual Host Enumeration]
TARGET="target.com"
IP=$(dig +short $TARGET | head -1)

# ─── Gobuster VHOST ───
gobuster vhost -u https://$TARGET \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50 --append-domain -o vhost_gobuster.txt

# ─── ffuf VHOST ───
ffuf -u https://$IP -H "Host: FUZZ.$TARGET" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -ac -mc 200,301,302,401,403 -t 100 -o vhost_ffuf.json -of json

# ─── ffuf VHOST with TLS SNI ───
ffuf -u https://FUZZ.$TARGET \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -ac -mc 200,301,302,401,403 -t 100

# ─── Custom VHOST bruteforce ───
cat > vhost_words.txt << 'EOF'
admin
api
app
beta
blog
cdn
cms
console
dashboard
demo
dev
docs
git
grafana
internal
jenkins
jira
kibana
legacy
mail
manage
monitor
ops
panel
portal
private
prometheus
qa
sandbox
sentry
staging
status
test
tools
vpn
wiki
EOF

ffuf -u https://$IP -H "Host: FUZZ.$TARGET" \
  -w vhost_words.txt -ac -t 50

# ─── Reverse IP lookup ───
# Find other domains on same IP
curl -s "https://api.hackertarget.com/reverseiplookup/?q=$IP" > reverse_ip.txt
```

---

## Strategy 7 — Cloud & Infrastructure Recon

::badge
**Map Cloud Attack Surface**
::

::card-group
  :::card
  ---
  icon: i-lucide-cloud
  title: AWS Recon
  ---
  S3 buckets, Lambda functions, EC2 instances, API Gateway, CloudFront, Cognito pools, ELB endpoints
  :::

  :::card
  ---
  icon: i-lucide-cloud
  title: Azure Recon
  ---
  Blob storage, App Services, Azure AD, Function Apps, Traffic Manager, Key Vault references
  :::

  :::card
  ---
  icon: i-lucide-cloud
  title: GCP Recon
  ---
  Cloud Storage buckets, Firebase databases, App Engine, Cloud Functions, BigQuery datasets
  :::

  :::card
  ---
  icon: i-lucide-cloud
  title: Generic Cloud
  ---
  DigitalOcean Spaces, Heroku apps, Netlify sites, Vercel deployments, Cloudflare Workers
  :::
::

### Cloud Storage Discovery

::tabs
  :::tabs-item{icon="i-lucide-database" label="S3 Bucket Hunting"}
  ```bash [AWS S3 Enumeration]
  TARGET="target"

  # ─── Generate bucket name permutations ───
  cat > s3_permutations.txt << EOF
  $TARGET
  $TARGET-dev
  $TARGET-staging
  $TARGET-prod
  $TARGET-production
  $TARGET-test
  $TARGET-backup
  $TARGET-backups
  $TARGET-data
  $TARGET-assets
  $TARGET-media
  $TARGET-static
  $TARGET-uploads
  $TARGET-files
  $TARGET-logs
  $TARGET-db
  $TARGET-database
  $TARGET-internal
  $TARGET-private
  $TARGET-public
  $TARGET-cdn
  $TARGET-web
  $TARGET-app
  $TARGET-api
  $TARGET-config
  $TARGET-archive
  dev-$TARGET
  staging-$TARGET
  prod-$TARGET
  backup-$TARGET
  ${TARGET}app
  ${TARGET}web
  ${TARGET}api
  ${TARGET}cdn
  EOF

  # ─── Check bucket existence and permissions ───
  cat s3_permutations.txt | while read bucket; do
    # Check if bucket exists
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com" -m 5)
    
    case $status in
      200) echo "[PUBLIC] https://${bucket}.s3.amazonaws.com" ;;
      403) echo "[EXISTS] https://${bucket}.s3.amazonaws.com (Access Denied)" ;;
      301) echo "[EXISTS] https://${bucket}.s3.amazonaws.com (Redirect)" ;;
    esac
  done | tee s3_results.txt

  # ─── S3Scanner ───
  python3 s3scanner.py --list s3_permutations.txt --dump-permissions

  # ─── cloud_enum ───
  python3 cloud_enum.py -k $TARGET -l cloud_enum_output.txt

  # ─── Check bucket permissions (if accessible) ───
  aws s3 ls s3://bucket-name --no-sign-request
  aws s3 ls s3://bucket-name --no-sign-request --recursive

  # ─── Try uploading (write permissions) ───
  echo "test" > test.txt
  aws s3 cp test.txt s3://bucket-name/test.txt --no-sign-request

  # ─── Check bucket policy ───
  aws s3api get-bucket-policy --bucket bucket-name --no-sign-request
  aws s3api get-bucket-acl --bucket bucket-name --no-sign-request
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="Azure & GCP Storage"}
  ```bash [Azure Blob Storage]
  TARGET="target"

  # ─── Azure blob enumeration ───
  # Format: https://<account>.blob.core.windows.net/<container>
  AZURE_PERMS=(
    "$TARGET" "${TARGET}dev" "${TARGET}staging" "${TARGET}prod"
    "${TARGET}backup" "${TARGET}data" "${TARGET}assets"
  )

  for account in "${AZURE_PERMS[@]}"; do
    # Check storage account
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://${account}.blob.core.windows.net/?comp=list" -m 5)
    [ "$status" != "000" ] && echo "[AZURE] ${account}.blob.core.windows.net → $status"
    
    # Common container names
    for container in "data" "backup" "uploads" "public" "assets" "files" "media" "www"; do
      status=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://${account}.blob.core.windows.net/${container}?restype=container&comp=list" -m 5)
      [ "$status" = "200" ] && echo "[PUBLIC CONTAINER] ${account}/${container}"
    done
  done | tee azure_results.txt
  ```

  ```bash [GCP Storage & Firebase]
  TARGET="target"

  # ─── GCP bucket enumeration ───
  GCP_PERMS=(
    "$TARGET" "${TARGET}-dev" "${TARGET}-staging" "${TARGET}-prod"
    "${TARGET}-backup" "${TARGET}.appspot.com"
  )

  for bucket in "${GCP_PERMS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://storage.googleapis.com/${bucket}" -m 5)
    case $status in
      200) echo "[PUBLIC] https://storage.googleapis.com/${bucket}" ;;
      403) echo "[EXISTS] https://storage.googleapis.com/${bucket}" ;;
    esac
  done | tee gcp_results.txt

  # ─── Firebase database enumeration ───
  FIREBASE_NAMES=("$TARGET" "${TARGET}-app" "${TARGET}-prod" "${TARGET}-dev")
  for name in "${FIREBASE_NAMES[@]}"; do
    response=$(curl -s "https://${name}-default-rtdb.firebaseio.com/.json")
    if echo "$response" | grep -qv "null\|Permission denied\|not found"; then
      echo "[FIREBASE EXPOSED] https://${name}-default-rtdb.firebaseio.com/.json"
      echo "$response" | head -100
    fi
  done | tee firebase_results.txt
  ```
  :::
::

### Shodan & Censys Intelligence

::code-collapse
---
label: "Internet-Wide Scanner Queries"
---

```bash [Shodan Queries]
TARGET="target.com"
ORG="Target Corporation"

# ─── Organization search ───
shodan search "org:\"$ORG\"" --fields ip_str,port,hostnames,product,os --limit 10000 > shodan_org.txt

# ─── Hostname search ───
shodan search "hostname:$TARGET" --fields ip_str,port,product,version --limit 5000 > shodan_hostname.txt

# ─── SSL certificate search ───
shodan search "ssl.cert.subject.cn:$TARGET" --fields ip_str,port,hostnames --limit 5000 > shodan_ssl.txt

# ─── Favicon hash search (find hidden infrastructure) ───
shodan search "http.favicon.hash:HASH" --fields ip_str,port,hostnames > shodan_favicon.txt

# ─── Specific service queries ───
shodan search "hostname:$TARGET port:9200"    # Elasticsearch
shodan search "hostname:$TARGET port:27017"   # MongoDB
shodan search "hostname:$TARGET port:6379"    # Redis
shodan search "hostname:$TARGET port:5432"    # PostgreSQL
shodan search "hostname:$TARGET port:3306"    # MySQL
shodan search "hostname:$TARGET port:11211"   # Memcached
shodan search "hostname:$TARGET port:9090"    # Prometheus
shodan search "hostname:$TARGET port:3000"    # Grafana/Node
shodan search "hostname:$TARGET port:8080"    # Various
shodan search "hostname:$TARGET port:8443"    # Alt HTTPS
shodan search "hostname:$TARGET has_screenshot:true"  # With screenshots

# ─── Vulnerable service queries ───
shodan search "hostname:$TARGET vuln:CVE-2021-44228"  # Log4j
shodan search "hostname:$TARGET http.component:jenkins"
shodan search "hostname:$TARGET http.component:gitlab"
shodan search "hostname:$TARGET http.title:\"Dashboard\""
shodan search "hostname:$TARGET http.title:\"Index of\""
```

```bash [Censys Queries]
TARGET="target.com"

# ─── Host search ───
censys search "services.tls.certificates.leaf.names: $TARGET" | \
  jq -r '.[] | [.ip, (.services[] | "\(.port)/\(.service_name)")] | @tsv'

# ─── Certificate search ───
censys search "parsed.names: $TARGET" --index-type certificates | \
  jq -r '.[].parsed.names[]' | sort -u

# ─── Specific services ───
censys search "services.http.response.headers.server: nginx AND services.tls.certificates.leaf.names: $TARGET"
censys search "services.software.product: Apache AND services.tls.certificates.leaf.names: $TARGET"

# ─── JARM fingerprinting ───
censys search "services.jarm.fingerprint: JARM_HASH AND services.tls.certificates.leaf.names: $TARGET"
```

```bash [FOFA & ZoomEye]
# ─── FOFA queries ───
# domain="target.com"
# host="target.com"
# cert="target.com"
# icon_hash="HASH"
# body="target.com"
# header="target.com"
# server="nginx" && domain="target.com"

# ─── ZoomEye queries ───
# hostname:"target.com"
# site:"target.com" +port:8080
# ssl:"target.com"
```
::

---

## Strategy 8 — Continuous Monitoring

::badge
**Never Stop Watching**
::

::caution
The best bugs are found on newly deployed assets. A subdomain that appeared 5 minutes ago is worth more than a subdomain that has existed for 5 years.
::

### Change Detection Pipeline

::code-tree{default-value="monitor.sh"}
```bash [monitor.sh]
#!/bin/bash
# Continuous recon monitoring script
# Run via cron: 0 */6 * * * /path/to/monitor.sh target.com

TARGET=$1
DATE=$(date +%Y%m%d_%H%M)
BASE="monitor/$TARGET"
mkdir -p $BASE/diffs

# ─── Subdomain monitoring ───
subfinder -d $TARGET -all -silent | sort -u > $BASE/subs_${DATE}.txt

# Compare with previous run
PREV=$(ls -t $BASE/subs_*.txt 2>/dev/null | sed -n '2p')
if [ -n "$PREV" ]; then
  NEW_SUBS=$(comm -13 "$PREV" "$BASE/subs_${DATE}.txt")
  if [ -n "$NEW_SUBS" ]; then
    echo "$NEW_SUBS" > $BASE/diffs/new_subs_${DATE}.txt
    
    # Probe new subdomains immediately
    echo "$NEW_SUBS" | httpx -silent -status-code -title -tech-detect | \
      tee $BASE/diffs/new_alive_${DATE}.txt
    
    # Run nuclei on new subdomains
    echo "$NEW_SUBS" | httpx -silent | \
      nuclei -severity critical,high -silent | \
      tee $BASE/diffs/new_vulns_${DATE}.txt
    
    # Send notification
    COUNT=$(echo "$NEW_SUBS" | wc -l)
    notify -silent -data "[NEW SUBS] $TARGET: $COUNT new subdomains found!
$(echo "$NEW_SUBS" | head -20)"
  fi
fi
```

```bash [url_monitor.sh]
#!/bin/bash
# URL change monitoring
TARGET=$1
DATE=$(date +%Y%m%d_%H%M)
BASE="monitor/$TARGET/urls"
mkdir -p $BASE/diffs

# Collect current URLs
echo $TARGET | gau --subs 2>/dev/null | sort -u > $BASE/urls_${DATE}.txt

PREV=$(ls -t $BASE/urls_*.txt 2>/dev/null | sed -n '2p')
if [ -n "$PREV" ]; then
  NEW_URLS=$(comm -13 "$PREV" "$BASE/urls_${DATE}.txt")
  if [ -n "$NEW_URLS" ]; then
    echo "$NEW_URLS" > $BASE/diffs/new_urls_${DATE}.txt
    
    # Check for interesting new URLs
    echo "$NEW_URLS" | grep -iE "\.(env|bak|sql|config|log|key|pem)" | \
      tee $BASE/diffs/interesting_${DATE}.txt
    
    # Parameter analysis
    echo "$NEW_URLS" | grep "=" | sort -u > $BASE/diffs/new_params_${DATE}.txt
    
    COUNT=$(echo "$NEW_URLS" | wc -l)
    notify -silent -data "[NEW URLs] $TARGET: $COUNT new URLs found!"
  fi
fi
```

```bash [tech_monitor.sh]
#!/bin/bash
# Technology change monitoring
TARGET=$1
DATE=$(date +%Y%m%d_%H%M)
BASE="monitor/$TARGET/tech"
mkdir -p $BASE

cat $BASE/../alive.txt | httpx -silent -tech-detect -json 2>/dev/null | \
  jq -r '[.url, (.technologies | join(","))] | @tsv' | \
  sort > $BASE/tech_${DATE}.txt

PREV=$(ls -t $BASE/tech_*.txt 2>/dev/null | sed -n '2p')
if [ -n "$PREV" ]; then
  CHANGES=$(diff "$PREV" "$BASE/tech_${DATE}.txt")
  if [ -n "$CHANGES" ]; then
    echo "$CHANGES" > $BASE/tech_diff_${DATE}.txt
    notify -silent -data "[TECH CHANGE] $TARGET: Technology stack changes detected!"
  fi
fi
```

```yaml [crontab.yml]
# Cron schedule for continuous monitoring
# ─────────────────────────────────────────
# Every 6 hours: Subdomain monitoring
# 0 */6 * * * /path/to/monitor.sh target.com
#
# Every 12 hours: URL monitoring
# 0 */12 * * * /path/to/url_monitor.sh target.com
#
# Every 24 hours: Technology monitoring
# 0 2 * * * /path/to/tech_monitor.sh target.com
#
# Weekly: Full deep recon
# 0 0 * * 0 /path/to/full_recon.sh target.com
```
::

### Notification Integration

```bash [Notification Setup]
# ─── notify configuration ───
# ~/.config/notify/provider-config.yaml

cat > ~/.config/notify/provider-config.yaml << 'EOF'
slack:
  - id: "slack_bug_bounty"
    slack_channel: "bug-bounty-alerts"
    slack_token: "xoxb-YOUR-TOKEN"
    slack_format: "{{data}}"

discord:
  - id: "discord_recon"
    discord_channel: "recon-alerts"
    discord_webhook_url: "https://discord.com/api/webhooks/YOUR_WEBHOOK"
    discord_format: "{{data}}"

telegram:
  - id: "telegram_alerts"
    telegram_api_key: "YOUR_BOT_TOKEN"
    telegram_chat_id: "YOUR_CHAT_ID"
    telegram_format: "{{data}}"
EOF

# ─── Usage examples ───
echo "Critical finding on target.com" | notify -silent
echo "New subdomain: admin.target.com" | notify -silent -provider slack
nuclei -l targets.txt -severity critical -silent | notify -silent -bulk
```

---

## Strategy 9 — Recon Data Organization

::badge
**Structure Your Intelligence**
::

### Recon Directory Structure

```text [Directory Layout]
recon/
└── target.com/
    ├── scope/
    │   ├── in_scope.txt
    │   ├── out_of_scope.txt
    │   └── root_domains.txt
    ├── subs/
    │   ├── passive/
    │   │   ├── subfinder.txt
    │   │   ├── amass.txt
    │   │   ├── chaos.txt
    │   │   ├── crtsh.txt
    │   │   └── github.txt
    │   ├── active/
    │   │   ├── brute.txt
    │   │   ├── permutations.txt
    │   │   └── vhosts.txt
    │   ├── all_merged.txt
    │   └── resolved_final.txt
    ├── dns/
    │   ├── a_records.txt
    │   ├── cname_records.txt
    │   ├── mx_records.txt
    │   └── txt_records.txt
    ├── hosts/
    │   ├── alive.txt
    │   ├── alive_full.json
    │   ├── ips.txt
    │   └── ip_ranges.txt
    ├── ports/
    │   ├── naabu.txt
    │   ├── nmap/
    │   └── masscan/
    ├── urls/
    │   ├── historical/
    │   ├── crawled/
    │   ├── urls_master.txt
    │   ├── params.txt
    │   └── classified/
    │       ├── gf_xss.txt
    │       ├── gf_sqli.txt
    │       ├── gf_ssrf.txt
    │       └── gf_redirect.txt
    ├── js/
    │   ├── js_urls.txt
    │   ├── downloaded/
    │   ├── endpoints.txt
    │   └── secrets.txt
    ├── content/
    │   ├── feroxbuster.txt
    │   ├── ffuf.json
    │   └── sensitive_files.txt
    ├── tech/
    │   ├── whatweb.json
    │   ├── httpx_tech.json
    │   └── summary.txt
    ├── cloud/
    │   ├── s3_buckets.txt
    │   ├── azure_blobs.txt
    │   └── firebase.txt
    ├── screenshots/
    │   └── gowitness/
    ├── vulns/
    │   ├── nuclei/
    │   ├── takeover.txt
    │   └── manual_findings.txt
    └── monitor/
        ├── diffs/
        └── logs/
```

### Recon Workflow Diagram

```text [Complete Recon Workflow]
┌─────────────────────────────────────────────────────────────────────────┐
│                      COMPLETE RECON WORKFLOW                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐                                                        │
│  │   SCOPE      │                                                        │
│  │  ANALYSIS    │──┐                                                     │
│  └─────────────┘  │                                                     │
│                    ▼                                                     │
│  ┌──────────────────────────────────────────────┐                       │
│  │            SUBDOMAIN DISCOVERY                │                       │
│  │  ┌────────┐  ┌────────┐  ┌──────────────┐   │                       │
│  │  │Passive │  │ Active │  │ Permutation  │   │                       │
│  │  │12+ src │  │ Brute  │  │  & Mutation  │   │                       │
│  │  └───┬────┘  └───┬────┘  └──────┬───────┘   │                       │
│  │      └───────────┼──────────────┘            │                       │
│  │                  ▼                            │                       │
│  │         ┌──────────────┐                      │                       │
│  │         │  RESOLVE &   │                      │                       │
│  │         │  DEDUPLICATE │                      │                       │
│  │         └──────┬───────┘                      │                       │
│  └────────────────┼──────────────────────────────┘                       │
│                   ▼                                                      │
│  ┌──────────────────────────────────────────────┐                       │
│  │             HTTP PROBING                      │                       │
│  │  ┌─────────┐  ┌───────────┐  ┌───────────┐  │                       │
│  │  │ Alive   │  │  Tech     │  │Screenshots│  │                       │
│  │  │ Check   │  │  Detect   │  │  Visual   │  │                       │
│  │  └────┬────┘  └─────┬─────┘  └─────┬─────┘  │                       │
│  └───────┼─────────────┼───────────────┼────────┘                       │
│          ▼             ▼               ▼                                 │
│  ┌──────────────────────────────────────────────┐                       │
│  │           ENDPOINT DISCOVERY                  │                       │
│  │  ┌─────────┐ ┌────────┐ ┌────────┐ ┌──────┐ │                       │
│  │  │Historical│ │Crawling│ │  JS    │ │Content│ │                       │
│  │  │  URLs   │ │ Active │ │Analysis│ │ Disc. │ │                       │
│  │  └────┬────┘ └───┬────┘ └───┬────┘ └──┬───┘ │                       │
│  └───────┼──────────┼──────────┼─────────┼──────┘                       │
│          └──────────┼──────────┘         │                               │
│                     ▼                    ▼                               │
│  ┌──────────────────────────────────────────────┐                       │
│  │          PARAMETER & INPUT MAPPING            │                       │
│  │  ┌────────┐  ┌────────┐  ┌────────────────┐  │                       │
│  │  │ Param  │  │  GF    │  │  Hidden Param  │  │                       │
│  │  │ Mining │  │Patterns│  │  Discovery     │  │                       │
│  │  └───┬────┘  └───┬────┘  └───────┬────────┘  │                       │
│  └──────┼───────────┼───────────────┼────────────┘                       │
│         └───────────┼───────────────┘                                    │
│                     ▼                                                    │
│  ┌──────────────────────────────────────────────┐                       │
│  │         VULNERABILITY SCANNING                │                       │
│  │  ┌────────┐  ┌────────┐  ┌────────────────┐  │                       │
│  │  │ Nuclei │  │Takeover│  │  Manual Test   │  │                       │
│  │  │Templates│  │ Check │  │  Prioritized   │  │                       │
│  │  └───┬────┘  └───┬────┘  └───────┬────────┘  │                       │
│  └──────┼───────────┼───────────────┼────────────┘                       │
│         └───────────┼───────────────┘                                    │
│                     ▼                                                    │
│             ┌───────────────┐                                            │
│             │   FINDINGS    │                                            │
│             │   & REPORT    │                                            │
│             └───────────────┘                                            │
│                                                                         │
│  ┌──────────────────────────────────────────────┐                       │
│  │         CONTINUOUS MONITORING (24/7)          │                       │
│  │  New subs → Probe → Scan → Alert → Repeat    │                       │
│  └──────────────────────────────────────────────┘                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Strategy 10 — Target Prioritization

::badge
**Hunt Smart, Not Hard**
::

::tip
Not all assets are equal. Prioritize targets that are most likely to have vulnerabilities and highest impact.
::

### Priority Matrix

| Priority | Asset Type | Why |
| -------- | ---------- | --- |
| :icon{name="i-lucide-flame"} **P0** | New subdomains (< 7 days old) | Freshly deployed, likely untested |
| :icon{name="i-lucide-flame"} **P0** | Staging/dev/test environments | Weaker security controls |
| :icon{name="i-lucide-alert-triangle"} **P1** | Admin panels and dashboards | High-value targets, often misconfigured |
| :icon{name="i-lucide-alert-triangle"} **P1** | API endpoints with auth | Business logic vulnerabilities |
| :icon{name="i-lucide-alert-triangle"} **P1** | File upload functionality | RCE potential |
| :icon{name="i-lucide-info"} **P2** | Legacy applications | Outdated frameworks, unpatched |
| :icon{name="i-lucide-info"} **P2** | Third-party integrations | OAuth, SSO, webhooks |
| :icon{name="i-lucide-info"} **P2** | Non-standard ports | Overlooked services |
| :icon{name="i-lucide-minus"} **P3** | Static content sites | Lower impact surface |
| :icon{name="i-lucide-minus"} **P3** | CDN-fronted main domain | Heavily tested by others |

### Automated Prioritization

```bash [Target Scoring]
#!/bin/bash
# Auto-prioritize targets based on characteristics
INPUT="alive_full.json"

echo "═══════════════════════════════════════════"
echo "           TARGET PRIORITIZATION            "
echo "═══════════════════════════════════════════"

# ─── P0: Staging/Dev/Test environments ───
echo ""
echo "[P0] STAGING/DEV/TEST ENVIRONMENTS:"
cat $INPUT | jq -r '.url' | grep -iE "(staging|stage|stg|dev|test|uat|qa|sandbox|demo|beta|alpha|preprod|pre-prod|internal)" | \
  sort -u | tee priority_p0_dev.txt
echo "  Count: $(wc -l < priority_p0_dev.txt)"

# ─── P1: Admin/Login panels ───
echo ""
echo "[P1] ADMIN & LOGIN PANELS:"
cat $INPUT | jq -r 'select(.title | test("admin|dashboard|login|sign.in|control.panel|management|console|portal"; "i")) | .url' | \
  sort -u | tee priority_p1_admin.txt
echo "  Count: $(wc -l < priority_p1_admin.txt)"

# ─── P1: API endpoints ───
echo ""
echo "[P1] API ENDPOINTS:"
cat $INPUT | jq -r '.url' | grep -iE "(api\.|/api/|/v[0-9]/|/graphql|/rest/)" | \
  sort -u | tee priority_p1_api.txt
echo "  Count: $(wc -l < priority_p1_api.txt)"

# ─── P1: Interesting technologies ───
echo ""
echo "[P1] INTERESTING TECHNOLOGIES:"
cat $INPUT | jq -r 'select(.technologies[]? | test("WordPress|Joomla|Drupal|Laravel|Django|Rails|Spring|Struts|Jenkins|GitLab|Grafana|Kibana|Elasticsearch|Tomcat|JBoss|WebLogic"; "i")) | [.url, (.technologies | join(","))] | @tsv' | \
  sort -u | tee priority_p1_tech.txt
echo "  Count: $(wc -l < priority_p1_tech.txt)"

# ─── P2: 401/403 pages (bypass targets) ───
echo ""
echo "[P2] RESTRICTED PAGES (BYPASS TARGETS):"
cat $INPUT | jq -r 'select(.status_code == 401 or .status_code == 403) | .url' | \
  sort -u | tee priority_p2_restricted.txt
echo "  Count: $(wc -l < priority_p2_restricted.txt)"

# ─── P2: Non-standard ports ───
echo ""
echo "[P2] NON-STANDARD PORTS:"
cat $INPUT | jq -r '.url' | grep -oP ':\d+' | grep -vE ":(80|443)$" | \
  sort | uniq -c | sort -rn
cat $INPUT | jq -r 'select(.url | test(":\\d+"; "")) | select(.url | test(":80/|:443/"; "") | not) | .url' | \
  sort -u | tee priority_p2_ports.txt
echo "  Count: $(wc -l < priority_p2_ports.txt)"

echo ""
echo "═══════════════════════════════════════════"
echo "  TOTAL P0 TARGETS: $(cat priority_p0_*.txt 2>/dev/null | sort -u | wc -l)"
echo "  TOTAL P1 TARGETS: $(cat priority_p1_*.txt 2>/dev/null | sort -u | wc -l)"
echo "  TOTAL P2 TARGETS: $(cat priority_p2_*.txt 2>/dev/null | sort -u | wc -l)"
echo "═══════════════════════════════════════════"
```

---

## Strategy 11 — Recon Automation Framework

::badge
**Full Automated Pipeline**
::

### Master Recon Script

::code-collapse
---
label: "Complete Automated Recon Framework"
---

```bash [full_recon.sh]
#!/bin/bash
#═══════════════════════════════════════════════════════
#  FULL AUTOMATED RECON FRAMEWORK
#  Usage: ./full_recon.sh target.com
#═══════════════════════════════════════════════════════

set -e

TARGET=$1
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE="recon/${TARGET}_${TIMESTAMP}"
THREADS=50
RESOLVERS="resolvers.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "═══════════════════════════════════════════"
  echo "  $1"
  echo "═══════════════════════════════════════════"
  echo -e "${NC}"
}

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

# ─── Setup ───
mkdir -p $BASE/{subs,dns,hosts,ports,urls,js,content,tech,vulns,screenshots}

banner "STARTING RECON FOR: $TARGET"

# ══════════════════════════════════════
# PHASE 1: SUBDOMAIN ENUMERATION
# ══════════════════════════════════════
banner "PHASE 1: SUBDOMAIN ENUMERATION"

log "Running subfinder..."
subfinder -d $TARGET -all -recursive -silent > $BASE/subs/subfinder.txt 2>/dev/null

log "Running amass passive..."
timeout 600 amass enum -passive -d $TARGET -o $BASE/subs/amass.txt 2>/dev/null || true

log "Running chaos..."
chaos -d $TARGET -silent > $BASE/subs/chaos.txt 2>/dev/null || true

log "Querying crt.sh..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > $BASE/subs/crtsh.txt

log "Running wayback subdomain extraction..."
echo $TARGET | waybackurls 2>/dev/null | unfurl domains 2>/dev/null | sort -u > $BASE/subs/wayback.txt

log "Running gau..."
echo $TARGET | gau --subs 2>/dev/null | unfurl domains 2>/dev/null | sort -u > $BASE/subs/gau.txt

# Merge
cat $BASE/subs/*.txt 2>/dev/null | sed 's/\*\.//g' | grep "\.$TARGET$" | sort -u > $BASE/subs/merged.txt
log "Total subdomains collected: $(wc -l < $BASE/subs/merged.txt)"

# Resolve
log "Resolving subdomains..."
if [ -f "$RESOLVERS" ]; then
  puredns resolve $BASE/subs/merged.txt -r $RESOLVERS -w $BASE/subs/resolved.txt 2>/dev/null
else
  cat $BASE/subs/merged.txt | dnsx -silent > $BASE/subs/resolved.txt 2>/dev/null
fi
log "Resolved subdomains: $(wc -l < $BASE/subs/resolved.txt)"

# ══════════════════════════════════════
# PHASE 2: HTTP PROBING
# ══════════════════════════════════════
banner "PHASE 2: HTTP PROBING & FINGERPRINTING"

log "Probing alive hosts..."
cat $BASE/subs/resolved.txt | httpx \
  -silent \
  -status-code \
  -title \
  -tech-detect \
  -web-server \
  -follow-redirects \
  -json \
  -o $BASE/hosts/alive.json 2>/dev/null

cat $BASE/hosts/alive.json | jq -r '.url' > $BASE/hosts/alive.txt 2>/dev/null
log "Alive hosts: $(wc -l < $BASE/hosts/alive.txt)"

# Extract IPs
cat $BASE/subs/resolved.txt | dnsx -silent -a -resp-only 2>/dev/null | sort -u > $BASE/hosts/ips.txt
log "Unique IPs: $(wc -l < $BASE/hosts/ips.txt)"

# Screenshots
log "Taking screenshots..."
gowitness file -f $BASE/hosts/alive.txt -P $BASE/screenshots/ --threads 10 2>/dev/null || true

# ══════════════════════════════════════
# PHASE 3: PORT SCANNING
# ══════════════════════════════════════
banner "PHASE 3: PORT SCANNING"

log "Running port scan..."
naabu -list $BASE/subs/resolved.txt -top-ports 1000 -silent -o $BASE/ports/naabu.txt 2>/dev/null
log "Open ports found: $(wc -l < $BASE/ports/naabu.txt)"

# ══════════════════════════════════════
# PHASE 4: URL COLLECTION
# ══════════════════════════════════════
banner "PHASE 4: URL & ENDPOINT DISCOVERY"

log "Collecting historical URLs..."
echo $TARGET | waybackurls 2>/dev/null > $BASE/urls/wayback.txt
echo $TARGET | gau 2>/dev/null > $BASE/urls/gau.txt

log "Active crawling..."
katana -list $BASE/hosts/alive.txt -d 3 -jc -silent -o $BASE/urls/katana.txt 2>/dev/null || true

# Merge URLs
cat $BASE/urls/*.txt 2>/dev/null | sort -u > $BASE/urls/master.txt
log "Total URLs: $(wc -l < $BASE/urls/master.txt)"

# Classify
cat $BASE/urls/master.txt | grep "=" | sort -u > $BASE/urls/params.txt
cat $BASE/urls/master.txt | grep -iE "\.js(\?|$)" | sort -u > $BASE/js/urls.txt
log "URLs with parameters: $(wc -l < $BASE/urls/params.txt)"
log "JavaScript files: $(wc -l < $BASE/js/urls.txt)"

# GF patterns
log "Classifying parameters by vulnerability type..."
cat $BASE/urls/params.txt | gf xss 2>/dev/null | sort -u > $BASE/urls/gf_xss.txt
cat $BASE/urls/params.txt | gf sqli 2>/dev/null | sort -u > $BASE/urls/gf_sqli.txt
cat $BASE/urls/params.txt | gf ssrf 2>/dev/null | sort -u > $BASE/urls/gf_ssrf.txt
cat $BASE/urls/params.txt | gf lfi 2>/dev/null | sort -u > $BASE/urls/gf_lfi.txt
cat $BASE/urls/params.txt | gf redirect 2>/dev/null | sort -u > $BASE/urls/gf_redirect.txt

# ══════════════════════════════════════
# PHASE 5: JS ANALYSIS
# ══════════════════════════════════════
banner "PHASE 5: JAVASCRIPT ANALYSIS"

log "Extracting endpoints from JS..."
cat $BASE/js/urls.txt | httpx -silent -mc 200 2>/dev/null | while read url; do
  python3 linkfinder.py -i "$url" -o cli 2>/dev/null
done | sort -u > $BASE/js/endpoints.txt
log "JS endpoints: $(wc -l < $BASE/js/endpoints.txt)"

# ══════════════════════════════════════
# PHASE 6: VULNERABILITY SCANNING
# ══════════════════════════════════════
banner "PHASE 6: VULNERABILITY SCANNING"

log "Running Nuclei..."
nuclei -l $BASE/hosts/alive.txt \
  -severity critical,high,medium \
  -c $THREADS \
  -silent \
  -o $BASE/vulns/nuclei.txt 2>/dev/null
log "Nuclei findings: $(wc -l < $BASE/vulns/nuclei.txt)"

log "Checking subdomain takeover..."
nuclei -l $BASE/subs/resolved.txt -tags takeover -silent -o $BASE/vulns/takeover.txt 2>/dev/null
log "Takeover candidates: $(wc -l < $BASE/vulns/takeover.txt)"

# ══════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════
banner "RECON COMPLETE — SUMMARY"

echo "  Target:              $TARGET"
echo "  Output:              $BASE/"
echo "  ─────────────────────────────"
echo "  Subdomains found:    $(wc -l < $BASE/subs/merged.txt)"
echo "  Resolved:            $(wc -l < $BASE/subs/resolved.txt)"
echo "  Alive hosts:         $(wc -l < $BASE/hosts/alive.txt)"
echo "  Unique IPs:          $(wc -l < $BASE/hosts/ips.txt)"
echo "  Open ports:          $(wc -l < $BASE/ports/naabu.txt)"
echo "  Total URLs:          $(wc -l < $BASE/urls/master.txt)"
echo "  Parameterized URLs:  $(wc -l < $BASE/urls/params.txt)"
echo "  JS files:            $(wc -l < $BASE/js/urls.txt)"
echo "  JS endpoints:        $(wc -l < $BASE/js/endpoints.txt)"
echo "  Nuclei findings:     $(wc -l < $BASE/vulns/nuclei.txt)"
echo "  Takeover candidates: $(wc -l < $BASE/vulns/takeover.txt)"
echo "  ─────────────────────────────"
echo "  Completed at:        $(date)"

# Send notification
notify -silent -data "Recon complete for $TARGET
Subdomains: $(wc -l < $BASE/subs/resolved.txt)
Alive: $(wc -l < $BASE/hosts/alive.txt)
URLs: $(wc -l < $BASE/urls/master.txt)
Findings: $(wc -l < $BASE/vulns/nuclei.txt)" 2>/dev/null || true
```
::

---

## Quick Reference — Tool Cheatsheet

::card-group
  :::card
  ---
  icon: i-lucide-radar
  title: Subdomain Tools
  ---
  `subfinder` · `amass` · `chaos` · `puredns` · `shuffledns` · `dnsx` · `gotator` · `dnsgen` · `altdns` · `github-subdomains` · `crt.sh` · `dnsvalidator`
  :::

  :::card
  ---
  icon: i-lucide-globe
  title: HTTP Probing
  ---
  `httpx` · `naabu` · `masscan` · `nmap` · `whatweb` · `webanalyze` · `gowitness` · `aquatone` · `eyewitness`
  :::

  :::card
  ---
  icon: i-lucide-link
  title: URL Discovery
  ---
  `waybackurls` · `gau` · `waymore` · `katana` · `gospider` · `hakrawler` · `paramspider` · `linkfinder` · `secretfinder`
  :::

  :::card
  ---
  icon: i-lucide-folder-search
  title: Content Discovery
  ---
  `feroxbuster` · `ffuf` · `gobuster` · `dirsearch` · `arjun` · `x8` · `git-dumper` · `trufflehog` · `gitleaks`
  :::

  :::card
  ---
  icon: i-lucide-cloud
  title: Cloud & OSINT
  ---
  `cloud_enum` · `s3scanner` · `shodan` · `censys` · `asnmap` · `mapcidr` · `bbscope` · `goofuzz`
  :::

  :::card
  ---
  icon: i-lucide-wrench
  title: Utility Tools
  ---
  `unfurl` · `qsreplace` · `anew` · `gf` · `jq` · `notify` · `interactsh` · `mapcidr` · `cewl` · `mantra`
  :::
::