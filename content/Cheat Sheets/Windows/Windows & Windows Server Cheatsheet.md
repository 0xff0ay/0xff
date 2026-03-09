---
title: Windows & Server Cheatsheet
description: Comprehensive command reference for Windows Desktop and Windows Server covering CMD, PowerShell, system administration, networking, Active Directory, and security.
navigation:
  icon: i-lucide-monitor
---

## Overview

This cheatsheet provides an in-depth reference for essential commands and configurations across **Windows Desktop** (10/11) and **Windows Server** (2016/2019/2022/2025). It covers system administration, networking, user management, Active Directory, Group Policy, security, and PowerShell automation.

> Windows environments power the majority of enterprise networks worldwide. Mastering both **CMD** and **PowerShell** across desktop and server editions is critical for system administrators, penetration testers, and IT professionals.

---

## Edition Comparison

| Feature                    | Windows 10/11              | Windows Server 2019/2022        |
| -------------------------- | -------------------------- | ------------------------------- |
| **Purpose**                | Desktop / Workstation      | Enterprise Server               |
| **GUI**                    | Full Desktop Experience    | Desktop Experience / Server Core |
| **Active Directory**       | Join domain only           | Domain Controller capable       |
| **Hyper-V**                | Limited                    | Full featured                   |
| **Max RAM**                | 2 TB (Pro/Enterprise)      | 24 TB+                          |
| **Max CPUs**               | 2 sockets                  | 64 sockets                      |
| **RDP Connections**        | 1 concurrent               | Unlimited (with CALs)           |
| **Group Policy**           | Local only                 | Domain-wide (GPMC)              |
| **IIS**                    | Limited                    | Full featured                   |
| **DHCP / DNS Server**      | No                         | Yes                             |
| **Failover Clustering**    | No                         | Yes                             |
| **Windows Admin Center**   | Limited                    | Full featured                   |
| **Nano Server**            | No                         | Yes                             |
| **Storage Spaces Direct**  | No                         | Yes                             |

---

## System Information

### Basic System Details

::code-preview
---
class: "[&>div]:*:my-0"
---
Gather system information using CMD.

#code
```cmd
:: System information summary
systeminfo

:: Computer name
hostname

:: OS version
ver
winver

:: Environment variables
set

:: System architecture
echo %PROCESSOR_ARCHITECTURE%

:: Windows edition
wmic os get caption,version,buildnumber,osarchitecture

:: Serial number
wmic bios get serialnumber

:: Installed hotfixes
wmic qfe list

:: Last boot time
systeminfo | findstr /i "Boot Time"
net statistics workstation
```
::

### PowerShell System Information

::code-preview
---
class: "[&>div]:*:my-0"
---
Gather system information using PowerShell.

#code
```powershell
# Detailed OS information
Get-ComputerInfo

# OS details
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture

# Computer system
Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, Manufacturer, Model, TotalPhysicalMemory

# BIOS information
Get-CimInstance Win32_BIOS

# Processor information
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed

# Installed hotfixes
Get-HotFix | Sort-Object InstalledOn -Descending

# Environment variables
Get-ChildItem Env:
$env:COMPUTERNAME
$env:USERNAME
$env:USERPROFILE
$env:PATH

# Uptime
(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

# Installed software
Get-CimInstance Win32_Product | Select-Object Name, Version, Vendor | Sort-Object Name

# Installed programs (registry - faster)
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName
```
::

### Hardware Information

::code-preview
---
class: "[&>div]:*:my-0"
---
Query hardware details.

#code
```powershell
# Disk drives
Get-CimInstance Win32_DiskDrive | Select-Object Model, Size, MediaType
Get-PhysicalDisk

# Memory modules
Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer, Capacity, Speed

# Network adapters
Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter } | Select-Object Name, MACAddress, Speed

# GPU
Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, AdapterRAM

# Battery (laptops)
Get-CimInstance Win32_Battery

# Motherboard
Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product, SerialNumber
```
::

---

## User and Group Management

### Local User Management (CMD)

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage local users using CMD.

#code
```cmd
:: List all users
net user

:: Detailed user info
net user <username>

:: Create new user
net user <username> <password> /add

:: Create user with options
net user <username> <password> /add /fullname:"Full Name" /comment:"Description"

:: Delete user
net user <username> /delete

:: Change password
net user <username> <newpassword>

:: Force password change at next logon
net user <username> /logonpasswordchg:yes

:: Disable account
net user <username> /active:no

:: Enable account
net user <username> /active:yes

:: Set password to never expire
net user <username> /expires:never

:: Set account expiry
net user <username> /expires:12/31/2025

:: Set logon hours
net user <username> /times:M-F,8am-6pm

:: Current logged-in user
whoami
whoami /all
whoami /priv
whoami /groups
```
::

### Local User Management (PowerShell)

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage local users using PowerShell.

#code
```powershell
# List all local users
Get-LocalUser

# Detailed user info
Get-LocalUser -Name <username> | Select-Object *

# Create new user
$Password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
New-LocalUser -Name "newuser" -Password $Password -FullName "New User" -Description "Test Account"

# Delete user
Remove-LocalUser -Name "newuser"

# Enable / Disable user
Enable-LocalUser -Name <username>
Disable-LocalUser -Name <username>

# Change password
$NewPass = ConvertTo-SecureString "NewP@ss123!" -AsPlainText -Force
Set-LocalUser -Name <username> -Password $NewPass

# Set password never expires
Set-LocalUser -Name <username> -PasswordNeverExpires $true

# Set account expiry
Set-LocalUser -Name <username> -AccountExpires (Get-Date "2025-12-31")

# Rename user
Rename-LocalUser -Name "oldname" -NewName "newname"
```
::

### Local Group Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage local groups.

#code
```cmd
:: List all groups
net localgroup

:: View group members
net localgroup Administrators
net localgroup "Remote Desktop Users"

:: Create group
net localgroup <groupname> /add

:: Delete group
net localgroup <groupname> /delete

:: Add user to group
net localgroup Administrators <username> /add
net localgroup "Remote Desktop Users" <username> /add

:: Remove user from group
net localgroup Administrators <username> /delete
```
::

### PowerShell Group Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage local groups using PowerShell.

#code
```powershell
# List all groups
Get-LocalGroup

# View group members
Get-LocalGroupMember -Group "Administrators"
Get-LocalGroupMember -Group "Remote Desktop Users"

# Create group
New-LocalGroup -Name "CustomGroup" -Description "Custom security group"

# Delete group
Remove-LocalGroup -Name "CustomGroup"

# Add user to group
Add-LocalGroupMember -Group "Administrators" -Member "username"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "username"

# Remove user from group
Remove-LocalGroupMember -Group "Administrators" -Member "username"
```
::

### Important Built-in Groups

| Group                      | Purpose                                      |
| -------------------------- | -------------------------------------------- |
| `Administrators`           | Full system control                          |
| `Users`                    | Standard user access                         |
| `Guests`                   | Minimal temporary access                     |
| `Remote Desktop Users`     | RDP access                                   |
| `Power Users`              | Legacy elevated access                       |
| `Backup Operators`         | Backup and restore files                     |
| `Network Configuration Operators` | Manage network settings               |
| `Event Log Readers`        | Read event logs                              |
| `Hyper-V Administrators`   | Manage Hyper-V                               |
| `IIS_IUSRS`               | IIS worker process identity                  |

---

## File and Directory Operations

### CMD File Operations

::code-preview
---
class: "[&>div]:*:my-0"
---
Essential file commands using CMD.

#code
```cmd
:: List files and directories
dir
dir /a                     :: All including hidden
dir /s                     :: Recursive
dir /b                     :: Bare format (names only)
dir /o:s                   :: Sort by size
dir /o:d                   :: Sort by date
dir /q                     :: Show ownership

:: Create directory
mkdir dirname
md parent\child\grandchild

:: Remove directory
rmdir dirname
rd /s /q dirname           :: Force recursive delete

:: Copy files
copy source destination
copy *.txt C:\destination\
xcopy source destination /s /e /h /i /y
robocopy source destination /E /Z /MIR

:: Move / Rename
move oldname newname
ren oldname newname

:: Delete files
del file.txt
del /f /q *.tmp            :: Force quiet delete
del /s /q C:\path\*.log    :: Recursive delete

:: File attributes
attrib file.txt
attrib +h file.txt          :: Set hidden
attrib -h file.txt          :: Remove hidden
attrib +r file.txt          :: Set read-only
attrib +s file.txt          :: Set system
attrib +h +s file.txt       :: Hidden and system

:: View file content
type file.txt
more file.txt

:: Find text in files
find "searchtext" file.txt
find /i "searchtext" file.txt       :: Case-insensitive
find /n "searchtext" file.txt       :: Show line numbers
findstr /s /i "pattern" *.txt       :: Recursive regex search
findstr /r "regex" file.txt         :: Regular expression

:: Create symbolic link
mklink linkname target              :: File symlink
mklink /d linkname target           :: Directory symlink
mklink /h linkname target           :: Hard link
mklink /j linkname target           :: Junction

:: Compare files
fc file1.txt file2.txt
comp file1.txt file2.txt
```
::

### PowerShell File Operations

::code-preview
---
class: "[&>div]:*:my-0"
---
File operations using PowerShell.

#code
```powershell
# List files
Get-ChildItem
Get-ChildItem -Force                    # Include hidden
Get-ChildItem -Recurse                  # Recursive
Get-ChildItem -Filter *.txt             # Filter by extension
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 100MB }

# Create directory
New-Item -ItemType Directory -Path "dirname"

# Create file
New-Item -ItemType File -Path "newfile.txt"
New-Item -ItemType File -Path "newfile.txt" -Value "Content"

# Copy
Copy-Item -Path source -Destination dest
Copy-Item -Path source -Destination dest -Recurse

# Move / Rename
Move-Item -Path oldname -Destination newname
Rename-Item -Path oldname -NewName newname

# Delete
Remove-Item -Path file.txt
Remove-Item -Path directory -Recurse -Force

# Read file
Get-Content file.txt
Get-Content file.txt -Head 10           # First 10 lines
Get-Content file.txt -Tail 10           # Last 10 lines
Get-Content file.txt -Wait              # Follow (like tail -f)

# Write file
Set-Content -Path file.txt -Value "Content"
Add-Content -Path file.txt -Value "Appended"
"Content" | Out-File file.txt

# Search in files
Select-String -Path *.txt -Pattern "searchtext"
Select-String -Path *.txt -Pattern "searchtext" -CaseSensitive
Get-ChildItem -Recurse -Filter *.log | Select-String "error"

# File hash
Get-FileHash file.txt -Algorithm MD5
Get-FileHash file.txt -Algorithm SHA256

# File properties
Get-Item file.txt | Select-Object *
(Get-Item file.txt).Length
(Get-Item file.txt).LastWriteTime

# Permissions
Get-Acl file.txt | Format-List
icacls file.txt
```
::

### Robocopy (Robust File Copy)

::code-preview
---
class: "[&>div]:*:my-0"
---
Advanced file copying with Robocopy.

#code
```cmd
:: Basic copy
robocopy C:\source D:\destination

:: Mirror (exact copy, deletes extras)
robocopy C:\source D:\destination /MIR

:: Copy with subdirectories
robocopy C:\source D:\destination /E

:: Copy with retry and wait
robocopy C:\source D:\destination /E /R:3 /W:5

:: Copy with logging
robocopy C:\source D:\destination /E /LOG:copy.log

:: Copy with progress
robocopy C:\source D:\destination /E /ETA

:: Exclude files/directories
robocopy C:\source D:\destination /E /XF *.tmp *.log /XD Temp Cache

:: Copy only specific files
robocopy C:\source D:\destination *.docx *.pdf

:: Move files (delete from source)
robocopy C:\source D:\destination /MOVE /E

:: Multithreaded copy
robocopy C:\source D:\destination /E /MT:16

:: Copy with permissions
robocopy C:\source D:\destination /E /COPY:DATSOU

:: Resume interrupted copy
robocopy C:\source D:\destination /E /Z
```
::

### Robocopy Flags Reference

| Flag       | Description                              |
| ---------- | ---------------------------------------- |
| `/E`       | Copy subdirectories including empty      |
| `/S`       | Copy subdirectories excluding empty      |
| `/MIR`     | Mirror directory tree                    |
| `/Z`       | Restartable mode                         |
| `/B`       | Backup mode                              |
| `/MT:n`    | Multithreaded (n threads)                |
| `/R:n`     | Number of retries                        |
| `/W:n`     | Wait time between retries (seconds)      |
| `/LOG:f`   | Log output to file                       |
| `/XF`      | Exclude files                            |
| `/XD`      | Exclude directories                      |
| `/MOVE`    | Move files (delete source)               |
| `/PURGE`   | Delete destination files not in source   |
| `/COPY:`   | Copy flags (D=Data, A=Attributes, T=Timestamps, S=Security, O=Owner, U=Auditing) |

---

## NTFS Permissions

### icacls

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage NTFS permissions with icacls.

#code
```cmd
:: View permissions
icacls C:\path\to\file
icacls C:\path\to\directory

:: Grant permissions
icacls C:\path /grant username:(F)              :: Full control
icacls C:\path /grant username:(M)              :: Modify
icacls C:\path /grant username:(R)              :: Read
icacls C:\path /grant username:(W)              :: Write
icacls C:\path /grant username:(RX)             :: Read & Execute
icacls C:\path /grant "Domain Users":(R)        :: Domain group

:: Grant with inheritance
icacls C:\path /grant username:(OI)(CI)(F)      :: Full control, inherit

:: Remove permissions
icacls C:\path /remove username

:: Deny permissions
icacls C:\path /deny username:(W)

:: Reset permissions to inherited
icacls C:\path /reset

:: Disable inheritance
icacls C:\path /inheritance:d                   :: Disable, copy inherited
icacls C:\path /inheritance:r                   :: Disable, remove inherited

:: Take ownership
takeown /f C:\path /r /d y
icacls C:\path /setowner username /t

:: Backup and restore permissions
icacls C:\path /save permissions.txt /t
icacls C:\path /restore permissions.txt
```
::

### NTFS Permission Levels

| Permission       | Code  | Description                              |
| ---------------- | ----- | ---------------------------------------- |
| Full Control     | `F`   | Read, write, modify, delete, change perms |
| Modify           | `M`   | Read, write, modify, delete              |
| Read & Execute   | `RX`  | Read and run files                       |
| Read             | `R`   | View contents                            |
| Write            | `W`   | Create files and folders                 |
| List Folder      | `L`   | List directory contents                  |

### Inheritance Flags

| Flag   | Meaning                               |
| ------ | ------------------------------------- |
| `OI`   | Object Inherit (files)                |
| `CI`   | Container Inherit (subdirectories)    |
| `IO`   | Inherit Only                          |
| `NP`   | No Propagate                          |

---

## Networking

### Network Configuration (CMD)

::code-preview
---
class: "[&>div]:*:my-0"
---
Network configuration commands.

#code
```cmd
:: IP configuration
ipconfig
ipconfig /all
ipconfig /release
ipconfig /renew
ipconfig /flushdns
ipconfig /displaydns
ipconfig /registerdns

:: Ping
ping <target>
ping -t <target>                       :: Continuous
ping -n 10 <target>                    :: Count
ping -l 1500 <target>                  :: Packet size
ping -a <ip-address>                   :: Resolve hostname

:: Traceroute
tracert <target>
tracert -d <target>                    :: No DNS resolution
pathping <target>                      :: Combined ping + tracert

:: DNS lookup
nslookup <domain>
nslookup -type=mx <domain>
nslookup -type=ns <domain>
nslookup -type=txt <domain>
nslookup <domain> 8.8.8.8             :: Specific DNS server

:: ARP table
arp -a
arp -d *                               :: Clear ARP cache

:: Routing table
route print
route add <network> mask <mask> <gateway>
route delete <network>
route -p add <network> mask <mask> <gateway>   :: Persistent

:: Netstat
netstat -an                            :: All connections
netstat -ano                           :: With PIDs
netstat -ab                            :: With process names
netstat -r                             :: Routing table
netstat -s                             :: Statistics
netstat -an | findstr LISTENING
netstat -an | findstr :445

:: Hostname
hostname
nbtstat -A <ip-address>                :: NetBIOS info
nbtstat -n                             :: Local names

:: Network shares
net share
net use
net view \\<computername>
```
::

### PowerShell Networking

::code-preview
---
class: "[&>div]:*:my-0"
---
Network commands using PowerShell.

#code
```powershell
# IP configuration
Get-NetIPAddress
Get-NetIPAddress -AddressFamily IPv4
Get-NetIPConfiguration
Get-NetAdapter

# Set static IP
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.1.100 -PrefixLength 24 -DefaultGateway 192.168.1.1

# Set DNS
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8, 8.8.4.4

# Set DHCP
Set-NetIPInterface -InterfaceAlias "Ethernet" -Dhcp Enabled

# DNS cache
Get-DnsClientCache
Clear-DnsClientCache

# DNS resolution
Resolve-DnsName <domain>
Resolve-DnsName <domain> -Type MX
Resolve-DnsName <domain> -Type NS
Resolve-DnsName <domain> -Server 8.8.8.8

# Test connectivity
Test-Connection <target>
Test-Connection <target> -Count 4
Test-NetConnection <target> -Port 443
Test-NetConnection <target> -Port 22 -InformationLevel Detailed
Test-NetConnection <target> -TraceRoute

# Active connections
Get-NetTCPConnection
Get-NetTCPConnection -State Established
Get-NetTCPConnection -State Listen
Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 445 }

# Network adapters
Get-NetAdapter
Get-NetAdapter | Select-Object Name, Status, LinkSpeed, MacAddress
Enable-NetAdapter -Name "Ethernet"
Disable-NetAdapter -Name "Ethernet"

# Routing
Get-NetRoute
New-NetRoute -DestinationPrefix "10.0.0.0/8" -NextHop "192.168.1.1" -InterfaceAlias "Ethernet"
Remove-NetRoute -DestinationPrefix "10.0.0.0/8"

# ARP
Get-NetNeighbor
Remove-NetNeighbor -InterfaceAlias "Ethernet"

# Network profiles
Get-NetConnectionProfile
Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private
```
::

### Windows Firewall (CMD)

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage Windows Firewall using netsh.

#code
```cmd
:: Show firewall status
netsh advfirewall show allprofiles

:: Enable / Disable firewall
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles state off
netsh advfirewall set domainprofile state on
netsh advfirewall set privateprofile state on
netsh advfirewall set publicprofile state on

:: Show all rules
netsh advfirewall firewall show rule name=all

:: Add inbound rule (allow)
netsh advfirewall firewall add rule name="Allow SSH" dir=in action=allow protocol=TCP localport=22
netsh advfirewall firewall add rule name="Allow HTTP" dir=in action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="Allow HTTPS" dir=in action=allow protocol=TCP localport=443

:: Add outbound rule (block)
netsh advfirewall firewall add rule name="Block Telnet" dir=out action=block protocol=TCP remoteport=23

:: Allow specific program
netsh advfirewall firewall add rule name="Allow App" dir=in action=allow program="C:\path\app.exe"

:: Allow from specific IP
netsh advfirewall firewall add rule name="Allow Trusted" dir=in action=allow protocol=TCP localport=3389 remoteip=192.168.1.0/24

:: Delete rule
netsh advfirewall firewall delete rule name="Allow SSH"

:: Reset firewall to defaults
netsh advfirewall reset

:: Export / Import rules
netsh advfirewall export "C:\firewall_backup.wfw"
netsh advfirewall import "C:\firewall_backup.wfw"
```
::

### PowerShell Firewall Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage Windows Firewall using PowerShell.

#code
```powershell
# View firewall profiles
Get-NetFirewallProfile

# Enable / Disable
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Public -Enabled False

# List all rules
Get-NetFirewallRule | Select-Object Name, Enabled, Direction, Action

# List enabled rules
Get-NetFirewallRule -Enabled True

# Create inbound allow rule
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Protocol TCP -LocalPort 80,443 -Action Allow

# Create outbound block rule
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Outbound -Protocol TCP -RemotePort 23 -Action Block

# Allow from specific IP range
New-NetFirewallRule -DisplayName "Allow Trusted" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 192.168.1.0/24 -Action Allow

# Allow specific program
New-NetFirewallRule -DisplayName "Allow App" -Direction Inbound -Program "C:\path\app.exe" -Action Allow

# Remove rule
Remove-NetFirewallRule -DisplayName "Allow SSH"

# Enable / Disable rule
Enable-NetFirewallRule -DisplayName "Allow RDP"
Disable-NetFirewallRule -DisplayName "Allow RDP"

# Get rule with port info
Get-NetFirewallRule -Enabled True -Direction Inbound |
  Get-NetFirewallPortFilter | Where-Object { $_.LocalPort -ne $null }
```
::

---

## Service Management

### CMD Service Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage Windows services using CMD.

#code
```cmd
:: List all services
sc query
sc query state= all
net start

:: Query specific service
sc query <servicename>
sc qc <servicename>

:: Start / Stop / Restart
net start <servicename>
net stop <servicename>
sc start <servicename>
sc stop <servicename>

:: Pause / Resume
sc pause <servicename>
sc continue <servicename>

:: Set startup type
sc config <servicename> start= auto
sc config <servicename> start= demand
sc config <servicename> start= disabled
sc config <servicename> start= delayed-auto

:: Create a service
sc create <servicename> binPath= "C:\path\to\service.exe" start= auto

:: Delete a service
sc delete <servicename>

:: Change service description
sc description <servicename> "Service description"

:: Set service account
sc config <servicename> obj= ".\LocalSystem"
sc config <servicename> obj= "domain\user" password= "password"

:: Service dependencies
sc qc <servicename>
sc config <servicename> depend= "service1/service2"

:: Show running services
tasklist /svc
```
::

### PowerShell Service Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage services using PowerShell.

#code
```powershell
# List all services
Get-Service
Get-Service | Where-Object { $_.Status -eq "Running" }
Get-Service | Where-Object { $_.Status -eq "Stopped" }

# Query specific service
Get-Service -Name "wuauserv"
Get-Service -DisplayName "*Windows Update*"

# Start / Stop / Restart
Start-Service -Name <servicename>
Stop-Service -Name <servicename>
Restart-Service -Name <servicename>

# Set startup type
Set-Service -Name <servicename> -StartupType Automatic
Set-Service -Name <servicename> -StartupType Manual
Set-Service -Name <servicename> -StartupType Disabled

# Create a service
New-Service -Name "MyService" -BinaryPathName "C:\path\service.exe" -DisplayName "My Custom Service" -StartupType Automatic -Description "Custom service"

# Remove a service
Remove-Service -Name "MyService"     # PowerShell 6+
sc.exe delete "MyService"            # Legacy

# Service dependencies
Get-Service -Name <servicename> | Select-Object -ExpandProperty DependentServices
Get-Service -Name <servicename> | Select-Object -ExpandProperty ServicesDependedOn

# Export service list
Get-Service | Export-Csv -Path services.csv -NoTypeInformation
```
::

### Important Windows Services

| Service Name       | Display Name                    | Purpose                      |
| ------------------ | ------------------------------- | ---------------------------- |
| `wuauserv`         | Windows Update                  | System updates               |
| `WinRM`            | Windows Remote Management       | Remote management            |
| `TermService`      | Remote Desktop Services         | RDP access                   |
| `W32Time`          | Windows Time                    | Time synchronization         |
| `Spooler`          | Print Spooler                   | Print management             |
| `LanmanServer`     | Server                          | SMB file sharing             |
| `LanmanWorkstation`| Workstation                     | SMB client                   |
| `BITS`             | Background Intelligent Transfer | File transfer                |
| `Dnscache`         | DNS Client                      | DNS caching                  |
| `EventLog`         | Windows Event Log               | Logging                      |
| `MpsSvc`           | Windows Firewall                | Firewall service             |
| `WinDefend`        | Windows Defender                | Antivirus                    |
| `NTDS`             | Active Directory Domain Services| AD DS (Server)               |
| `DNS`              | DNS Server                      | DNS (Server)                 |
| `DHCPServer`       | DHCP Server                     | DHCP (Server)                |
| `W3SVC`            | World Wide Web Publishing       | IIS (Server)                 |

---

## Process Management

::code-preview
---
class: "[&>div]:*:my-0"
---
View and manage processes.

#code
```cmd
:: List all processes
tasklist
tasklist /v                            :: Verbose
tasklist /svc                          :: Services per process
tasklist /fi "imagename eq notepad.exe"

:: Kill process by name
taskkill /im notepad.exe
taskkill /im notepad.exe /f            :: Force kill

:: Kill process by PID
taskkill /pid 1234
taskkill /pid 1234 /f

:: Kill process tree
taskkill /im chrome.exe /t /f

:: Find process using a port
netstat -ano | findstr :80
tasklist /fi "pid eq <pid>"

:: WMIC process management
wmic process list brief
wmic process where name="notepad.exe" get processid,commandline
wmic process where processid=1234 delete
```
::

### PowerShell Process Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Process management using PowerShell.

#code
```powershell
# List all processes
Get-Process
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10

# Find specific process
Get-Process -Name "notepad"
Get-Process | Where-Object { $_.ProcessName -like "*chrome*" }

# Detailed process info
Get-Process -Name "notepad" | Select-Object *
Get-Process -Id 1234 | Select-Object *

# Process with command line
Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine

# Kill process
Stop-Process -Name "notepad"
Stop-Process -Id 1234
Stop-Process -Name "notepad" -Force

# Start process
Start-Process "notepad.exe"
Start-Process "notepad.exe" -ArgumentList "file.txt"
Start-Process "cmd.exe" -Verb RunAs                # Run as admin
Start-Process "powershell.exe" -Verb RunAs

# Wait for process
Start-Process "setup.exe" -Wait
Wait-Process -Name "setup"

# Process CPU and memory usage
Get-Process | Select-Object Name, CPU, @{Name="MemoryMB";Expression={[math]::Round($_.WorkingSet64/1MB,2)}} | Sort-Object MemoryMB -Descending
```
::

---

## Disk Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage disks, partitions, and volumes.

#code
```cmd
:: Disk space usage
dir C:\ /s
wmic logicaldisk get size,freespace,caption

:: DiskPart
diskpart
list disk
select disk 0
list partition
list volume
select volume 1
assign letter=E
format fs=ntfs quick

:: Check disk
chkdsk C:
chkdsk C: /f                          :: Fix errors
chkdsk C: /r                          :: Locate bad sectors

:: Disk defragment
defrag C: /O                           :: Optimize
defrag C: /U /V                        :: Verbose

:: Disk cleanup
cleanmgr /d C:
```
::

### PowerShell Disk Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Disk management using PowerShell.

#code
```powershell
# List disks
Get-Disk
Get-PhysicalDisk

# List partitions
Get-Partition
Get-Partition -DiskNumber 0

# List volumes
Get-Volume

# Disk space
Get-Volume | Select-Object DriveLetter, FileSystemLabel, @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}}, @{Name="FreeGB";Expression={[math]::Round($_.SizeRemaining/1GB,2)}}

# Initialize disk
Initialize-Disk -Number 1 -PartitionStyle GPT

# Create partition
New-Partition -DiskNumber 1 -UseMaximumSize -AssignDriveLetter

# Format volume
Format-Volume -DriveLetter E -FileSystem NTFS -NewFileSystemLabel "Data"

# Resize partition
Resize-Partition -DriveLetter C -Size (Get-PartitionSupportedSize -DriveLetter C).SizeMax

# Storage Spaces (Server)
Get-StoragePool
New-StoragePool -FriendlyName "Pool1" -StorageSubsystemFriendlyName "Windows Storage*" -PhysicalDisks (Get-PhysicalDisk -CanPool $true)
```
::

---

## Registry Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage Windows Registry.

#code
```cmd
:: Query registry
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
reg query HKCU\Software
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName

:: Add registry value
reg add HKLM\SOFTWARE\MyApp /v Setting1 /t REG_SZ /d "Value" /f
reg add HKLM\SOFTWARE\MyApp /v Number1 /t REG_DWORD /d 1 /f

:: Delete registry value
reg delete HKLM\SOFTWARE\MyApp /v Setting1 /f

:: Delete registry key
reg delete HKLM\SOFTWARE\MyApp /f

:: Export registry
reg export HKLM\SOFTWARE\MyApp backup.reg

:: Import registry
reg import backup.reg

:: Compare registry
reg compare HKLM\SOFTWARE\MyApp HKLM\SOFTWARE\MyApp2
```
::

### PowerShell Registry

::code-preview
---
class: "[&>div]:*:my-0"
---
Registry management using PowerShell.

#code
```powershell
# Navigate registry
Set-Location HKLM:\SOFTWARE\Microsoft
Get-ChildItem HKLM:\SOFTWARE\Microsoft
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion

# Read specific value
Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ProductName"

# Create registry key
New-Item -Path "HKLM:\SOFTWARE\MyApp"

# Set registry value
Set-ItemProperty -Path "HKLM:\SOFTWARE\MyApp" -Name "Setting1" -Value "MyValue"
New-ItemProperty -Path "HKLM:\SOFTWARE\MyApp" -Name "Number1" -PropertyType DWORD -Value 1

# Remove registry value
Remove-ItemProperty -Path "HKLM:\SOFTWARE\MyApp" -Name "Setting1"

# Remove registry key
Remove-Item -Path "HKLM:\SOFTWARE\MyApp" -Recurse

# Search registry
Get-ChildItem -Path HKLM:\SOFTWARE -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*keyword*" }
```
::

### Important Registry Locations

| Path                                                          | Purpose                         |
| ------------------------------------------------------------- | ------------------------------- |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`          | Auto-start programs (all users) |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`          | Auto-start programs (user)      |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`    | Installed programs              |
| `HKLM\SYSTEM\CurrentControlSet\Services`                      | Windows services                |
| `HKLM\SAM\SAM`                                                | Security Account Manager        |
| `HKLM\SECURITY`                                               | Security policies               |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`           | Windows version info            |
| `HKLM\SYSTEM\CurrentControlSet\Control\ComputerName`          | Computer name                   |
| `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`     | TCP/IP settings                 |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer`     | Explorer settings               |

---

## Scheduled Tasks

### CMD Task Scheduler

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage scheduled tasks using schtasks.

#code
```cmd
:: List all tasks
schtasks /query
schtasks /query /fo LIST /v

:: Create task - run daily
schtasks /create /tn "MyTask" /tr "C:\scripts\backup.bat" /sc daily /st 02:00

:: Create task - run at startup
schtasks /create /tn "StartupTask" /tr "C:\scripts\startup.bat" /sc onstart /ru SYSTEM

:: Create task - run every 5 minutes
schtasks /create /tn "FrequentTask" /tr "C:\scripts\check.bat" /sc minute /mo 5

:: Create task - run on logon
schtasks /create /tn "LogonTask" /tr "C:\scripts\logon.bat" /sc onlogon

:: Create task with credentials
schtasks /create /tn "MyTask" /tr "C:\scripts\task.bat" /sc daily /st 03:00 /ru domain\user /rp password

:: Run task immediately
schtasks /run /tn "MyTask"

:: End running task
schtasks /end /tn "MyTask"

:: Delete task
schtasks /delete /tn "MyTask" /f

:: Change existing task
schtasks /change /tn "MyTask" /st 04:00

:: Enable / Disable
schtasks /change /tn "MyTask" /enable
schtasks /change /tn "MyTask" /disable

:: Export / Import task
schtasks /query /tn "MyTask" /xml > task.xml
schtasks /create /tn "ImportedTask" /xml task.xml
```
::

### PowerShell Task Scheduler

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage scheduled tasks using PowerShell.

#code
```powershell
# List all tasks
Get-ScheduledTask
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" }

# Get task info
Get-ScheduledTaskInfo -TaskName "MyTask"

# Create task
$Action = New-ScheduledTaskAction -Execute "C:\scripts\backup.bat"
$Trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries
Register-ScheduledTask -TaskName "BackupTask" -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM"

# Multiple triggers
$Trigger1 = New-ScheduledTaskTrigger -AtStartup
$Trigger2 = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "MultiTask" -Action $Action -Trigger $Trigger1, $Trigger2

# Start / Stop task
Start-ScheduledTask -TaskName "MyTask"
Stop-ScheduledTask -TaskName "MyTask"

# Enable / Disable
Enable-ScheduledTask -TaskName "MyTask"
Disable-ScheduledTask -TaskName "MyTask"

# Delete task
Unregister-ScheduledTask -TaskName "MyTask" -Confirm:$false

# Export / Import
Export-ScheduledTask -TaskName "MyTask" | Out-File task.xml
Register-ScheduledTask -TaskName "ImportedTask" -Xml (Get-Content task.xml | Out-String)
```
::

---

## Active Directory (Windows Server)

### AD DS Installation

::code-preview
---
class: "[&>div]:*:my-0"
---
Install and configure Active Directory.

#code
```powershell
# Install AD DS role
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller (new forest)
Install-ADDSForest -DomainName "domain.local" -DomainNetbiosName "DOMAIN" -InstallDns:$true -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)

# Promote to additional DC
Install-ADDSDomainController -DomainName "domain.local" -InstallDns:$true -Credential (Get-Credential) -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)

# Add new child domain
Install-ADDSDomain -NewDomainName "child" -ParentDomainName "domain.local" -DomainType ChildDomain -InstallDns:$true

# Verify installation
Get-ADDomainController
Get-ADDomain
Get-ADForest
```
::

### AD User Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage Active Directory users.

#code
```powershell
# Import AD module
Import-Module ActiveDirectory

# List all users
Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled

# Search users
Get-ADUser -Filter { Name -like "*john*" }
Get-ADUser -Filter { Department -eq "IT" }
Get-ADUser -Identity "jsmith" -Properties *

# Create user
New-ADUser -Name "John Smith" `
  -GivenName "John" `
  -Surname "Smith" `
  -SamAccountName "jsmith" `
  -UserPrincipalName "jsmith@domain.local" `
  -Path "OU=Users,DC=domain,DC=local" `
  -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) `
  -Enabled $true `
  -ChangePasswordAtLogon $true

# Bulk create users from CSV
Import-Csv users.csv | ForEach-Object {
    New-ADUser -Name $_.Name `
      -SamAccountName $_.Username `
      -UserPrincipalName "$($_.Username)@domain.local" `
      -Path "OU=Users,DC=domain,DC=local" `
      -AccountPassword (ConvertTo-SecureString $_.Password -AsPlainText -Force) `
      -Enabled $true
}

# Modify user
Set-ADUser -Identity "jsmith" -Title "Manager" -Department "IT" -Office "HQ"

# Disable / Enable user
Disable-ADAccount -Identity "jsmith"
Enable-ADAccount -Identity "jsmith"

# Unlock account
Unlock-ADAccount -Identity "jsmith"

# Reset password
Set-ADAccountPassword -Identity "jsmith" -Reset -NewPassword (ConvertTo-SecureString "NewP@ss!" -AsPlainText -Force)

# Delete user
Remove-ADUser -Identity "jsmith" -Confirm:$false

# Move user to different OU
Move-ADObject -Identity "CN=John Smith,OU=Users,DC=domain,DC=local" -TargetPath "OU=Managers,DC=domain,DC=local"

# Find locked accounts
Search-ADAccount -LockedOut | Select-Object Name, SamAccountName

# Find disabled accounts
Search-ADAccount -AccountDisabled | Select-Object Name, SamAccountName

# Find expired accounts
Search-ADAccount -AccountExpired | Select-Object Name, SamAccountName

# Find inactive accounts (90 days)
Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 | Select-Object Name, LastLogonDate

# Export users
Get-ADUser -Filter * -Properties * | Export-Csv -Path ad_users.csv -NoTypeInformation
```
::

### AD Group Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage Active Directory groups.

#code
```powershell
# List all groups
Get-ADGroup -Filter *

# Get group members
Get-ADGroupMember -Identity "Domain Admins"
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# Create group
New-ADGroup -Name "IT-Staff" `
  -GroupScope Global `
  -GroupCategory Security `
  -Path "OU=Groups,DC=domain,DC=local" `
  -Description "IT Department Staff"

# Add member to group
Add-ADGroupMember -Identity "IT-Staff" -Members "jsmith", "jdoe"

# Remove member from group
Remove-ADGroupMember -Identity "IT-Staff" -Members "jsmith" -Confirm:$false

# Find user group memberships
Get-ADPrincipalGroupMembership -Identity "jsmith" | Select-Object Name

# Nested group membership
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object Name, objectClass
```
::

### AD Organizational Units

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage Organizational Units.

#code
```powershell
# List all OUs
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName

# Create OU
New-ADOrganizationalUnit -Name "IT-Department" -Path "DC=domain,DC=local" -ProtectedFromAccidentalDeletion $true

# Create nested OU
New-ADOrganizationalUnit -Name "Servers" -Path "OU=IT-Department,DC=domain,DC=local"

# Delete OU
Set-ADOrganizationalUnit -Identity "OU=OldOU,DC=domain,DC=local" -ProtectedFromAccidentalDeletion $false
Remove-ADOrganizationalUnit -Identity "OU=OldOU,DC=domain,DC=local" -Confirm:$false

# Move objects between OUs
Move-ADObject -Identity "CN=John Smith,OU=Users,DC=domain,DC=local" -TargetPath "OU=IT-Department,DC=domain,DC=local"
```
::

### AD Computer Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage Active Directory computers.

#code
```powershell
# List all computers
Get-ADComputer -Filter * | Select-Object Name, Enabled, OperatingSystem

# Search computers
Get-ADComputer -Filter { OperatingSystem -like "*Server*" }
Get-ADComputer -Filter { Name -like "WS-*" }

# Detailed info
Get-ADComputer -Identity "SERVER01" -Properties *

# Disable computer account
Disable-ADAccount -Identity "CN=OLDPC,OU=Computers,DC=domain,DC=local"

# Find inactive computers (90 days)
Search-ADAccount -ComputersOnly -AccountInactive -TimeSpan 90.00:00:00

# Remove computer
Remove-ADComputer -Identity "OLDPC" -Confirm:$false
```
::

---

## Group Policy (Windows Server)

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
Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime

# Get specific GPO
Get-GPO -Name "Default Domain Policy"

# Create new GPO
New-GPO -Name "Security-Policy" -Comment "Custom security settings"

# Link GPO to OU
New-GPLink -Name "Security-Policy" -Target "OU=Workstations,DC=domain,DC=local"

# Unlink GPO
Remove-GPLink -Name "Security-Policy" -Target "OU=Workstations,DC=domain,DC=local"

# GPO report
Get-GPOReport -Name "Security-Policy" -ReportType HTML -Path "C:\gpo_report.html"
Get-GPOReport -All -ReportType HTML -Path "C:\all_gpo_report.html"

# Backup GPO
Backup-GPO -Name "Security-Policy" -Path "C:\GPO_Backup"
Backup-GPO -All -Path "C:\GPO_Backup"

# Restore GPO
Restore-GPO -Name "Security-Policy" -Path "C:\GPO_Backup"

# Delete GPO
Remove-GPO -Name "Security-Policy" -Confirm:$false

# Force Group Policy update
gpupdate /force
Invoke-GPUpdate -Computer "WORKSTATION01" -Force -RandomDelayInMinutes 0

# View applied GPOs
gpresult /r
gpresult /h C:\gp_report.html
gpresult /r /scope:computer
gpresult /r /scope:user

# RSoP (Resultant Set of Policy)
Get-GPResultantSetOfPolicy -ReportType HTML -Path "C:\rsop.html"
```
::

### Common Group Policy Settings

| Setting                                    | Path                                                    |
| ------------------------------------------ | ------------------------------------------------------- |
| Password Policy                            | Computer > Policies > Windows Settings > Security > Account Policies |
| Account Lockout                            | Computer > Policies > Windows Settings > Security > Account Policies > Account Lockout |
| Audit Policy                               | Computer > Policies > Windows Settings > Security > Local Policies > Audit Policy |
| User Rights Assignment                     | Computer > Policies > Windows Settings > Security > Local Policies > User Rights Assignment |
| Windows Firewall                           | Computer > Policies > Windows Settings > Security > Windows Firewall |
| Software Restriction                       | Computer > Policies > Windows Settings > Security > Software Restriction Policies |
| Drive Mapping                              | User > Preferences > Windows Settings > Drive Maps |
| Logon Scripts                              | User > Policies > Windows Settings > Scripts > Logon |
| Desktop Wallpaper                          | User > Policies > Administrative Templates > Desktop > Desktop Wallpaper |
| Disable USB                                | Computer > Policies > Administrative Templates > System > Removable Storage Access |
| Windows Update                             | Computer > Policies > Administrative Templates > Windows Components > Windows Update |

---

## DNS Server (Windows Server)

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage DNS Server.

#code
```powershell
# Install DNS role
Install-WindowsFeature DNS -IncludeManagementTools

# List DNS zones
Get-DnsServerZone

# Create forward lookup zone
Add-DnsServerPrimaryZone -Name "domain.local" -ZoneFile "domain.local.dns"

# Create reverse lookup zone
Add-DnsServerPrimaryZone -NetworkID "192.168.1.0/24" -ZoneFile "1.168.192.in-addr.arpa.dns"

# Add A record
Add-DnsServerResourceRecordA -ZoneName "domain.local" -Name "server01" -IPv4Address "192.168.1.10"

# Add CNAME record
Add-DnsServerResourceRecordCName -ZoneName "domain.local" -Name "www" -HostNameAlias "server01.domain.local"

# Add MX record
Add-DnsServerResourceRecordMX -ZoneName "domain.local" -Name "." -MailExchange "mail.domain.local" -Preference 10

# Add PTR record
Add-DnsServerResourceRecordPtr -ZoneName "1.168.192.in-addr.arpa" -Name "10" -PtrDomainName "server01.domain.local"

# List records in zone
Get-DnsServerResourceRecord -ZoneName "domain.local"

# Remove record
Remove-DnsServerResourceRecord -ZoneName "domain.local" -RRType A -Name "oldserver" -Force

# DNS forwarders
Add-DnsServerForwarder -IPAddress 8.8.8.8
Get-DnsServerForwarder

# Clear DNS cache
Clear-DnsServerCache

# DNS statistics
Get-DnsServerStatistics
```
::

---

## DHCP Server (Windows Server)

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage DHCP Server.

#code
```powershell
# Install DHCP role
Install-WindowsFeature DHCP -IncludeManagementTools

# Authorize DHCP in AD
Add-DhcpServerInDC -DnsName "dc01.domain.local" -IPAddress 192.168.1.1

# Create scope
Add-DhcpServerv4Scope -Name "LAN Scope" -StartRange 192.168.1.100 -EndRange 192.168.1.200 -SubnetMask 255.255.255.0 -State Active

# Set scope options
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -DnsServer 192.168.1.1 -Router 192.168.1.1 -DnsDomain "domain.local"

# Add exclusion range
Add-DhcpServerv4ExclusionRange -ScopeId 192.168.1.0 -StartRange 192.168.1.1 -EndRange 192.168.1.10

# Add reservation
Add-DhcpServerv4Reservation -ScopeId 192.168.1.0 -IPAddress 192.168.1.50 -ClientId "AA-BB-CC-DD-EE-FF" -Name "Printer01"

# List scopes
Get-DhcpServerv4Scope

# List leases
Get-DhcpServerv4Lease -ScopeId 192.168.1.0

# List reservations
Get-DhcpServerv4Reservation -ScopeId 192.168.1.0

# Remove scope
Remove-DhcpServerv4Scope -ScopeId 192.168.1.0 -Force

# DHCP statistics
Get-DhcpServerv4Statistics
Get-DhcpServerv4ScopeStatistics -ScopeId 192.168.1.0
```
::

---

## IIS Web Server (Windows Server)

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage IIS Web Server.

#code
```powershell
# Install IIS
Install-WindowsFeature Web-Server -IncludeManagementTools -IncludeAllSubFeature

# Import IIS module
Import-Module WebAdministration

# List websites
Get-Website
Get-IISSite

# Create website
New-Website -Name "MyWebsite" -PhysicalPath "C:\inetpub\mysite" -Port 80 -HostHeader "www.mysite.com"

# Start / Stop website
Start-Website -Name "MyWebsite"
Stop-Website -Name "MyWebsite"

# Create application pool
New-WebAppPool -Name "MyAppPool"

# Set app pool settings
Set-ItemProperty "IIS:\AppPools\MyAppPool" -Name "managedRuntimeVersion" -Value "v4.0"
Set-ItemProperty "IIS:\AppPools\MyAppPool" -Name "startMode" -Value "AlwaysRunning"

# Assign app pool to site
Set-ItemProperty "IIS:\Sites\MyWebsite" -Name "applicationPool" -Value "MyAppPool"

# List app pools
Get-IISAppPool

# Create virtual directory
New-WebVirtualDirectory -Site "MyWebsite" -Name "images" -PhysicalPath "C:\images"

# Create application
New-WebApplication -Site "MyWebsite" -Name "api" -PhysicalPath "C:\inetpub\api" -ApplicationPool "MyAppPool"

# SSL binding
New-WebBinding -Name "MyWebsite" -Protocol https -Port 443 -HostHeader "www.mysite.com"

# Remove website
Remove-Website -Name "MyWebsite"

# IIS reset
iisreset
iisreset /restart
iisreset /stop
iisreset /start
```
::

---

## Hyper-V (Windows Server)

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage Hyper-V virtual machines.

#code
```powershell
# Install Hyper-V
Install-WindowsFeature Hyper-V -IncludeManagementTools -Restart

# List all VMs
Get-VM

# Create VM
New-VM -Name "TestVM" -MemoryStartupBytes 2GB -Generation 2 -NewVHDPath "C:\VMs\TestVM.vhdx" -NewVHDSizeBytes 50GB -SwitchName "Default Switch"

# Start / Stop / Restart VM
Start-VM -Name "TestVM"
Stop-VM -Name "TestVM"
Restart-VM -Name "TestVM"
Stop-VM -Name "TestVM" -Force                # Force shutdown
Save-VM -Name "TestVM"                       # Hibernate

# VM settings
Set-VM -Name "TestVM" -ProcessorCount 4 -DynamicMemory -MemoryMinimumBytes 1GB -MemoryMaximumBytes 4GB

# Snapshots (Checkpoints)
Checkpoint-VM -Name "TestVM" -SnapshotName "BeforeUpdate"
Get-VMSnapshot -VMName "TestVM"
Restore-VMSnapshot -VMName "TestVM" -Name "BeforeUpdate"
Remove-VMSnapshot -VMName "TestVM" -Name "BeforeUpdate"

# Virtual switches
Get-VMSwitch
New-VMSwitch -Name "InternalSwitch" -SwitchType Internal
New-VMSwitch -Name "ExternalSwitch" -NetAdapterName "Ethernet" -AllowManagementOS $true

# Attach ISO
Set-VMDvdDrive -VMName "TestVM" -Path "C:\ISOs\windows.iso"

# Add virtual disk
Add-VMHardDiskDrive -VMName "TestVM" -Path "C:\VMs\data.vhdx"

# VM replication
Enable-VMReplication -VMName "TestVM" -ReplicaServerName "replica-server" -ReplicaServerPort 443 -AuthenticationType Kerberos

# Export / Import VM
Export-VM -Name "TestVM" -Path "C:\VMExports"
Import-VM -Path "C:\VMExports\TestVM\Virtual Machines\*.vmcx"

# Live migration
Move-VM -Name "TestVM" -DestinationHost "Server02" -IncludeStorage -DestinationStoragePath "C:\VMs"
```
::

---

## Windows Event Logs

### CMD Event Log

::code-preview
---
class: "[&>div]:*:my-0"
---
Query event logs using CMD.

#code
```cmd
:: List log sources
wevtutil el

:: Query specific log
wevtutil qe System /c:10 /f:text
wevtutil qe Security /c:10 /f:text
wevtutil qe Application /c:10 /f:text

:: Export log
wevtutil epl Security C:\security_log.evtx

:: Clear log
wevtutil cl System
wevtutil cl Security

:: Event log statistics
wevtutil gli System
wevtutil gli Security
```
::

### PowerShell Event Logs

::code-preview
---
class: "[&>div]:*:my-0"
---
Query event logs using PowerShell.

#code
```powershell
# List available logs
Get-EventLog -List
Get-WinEvent -ListLog *

# Query System log
Get-EventLog -LogName System -Newest 20
Get-WinEvent -LogName System -MaxEvents 20

# Query Security log
Get-EventLog -LogName Security -Newest 20
Get-WinEvent -LogName Security -MaxEvents 20

# Filter by event ID
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4624}         # Successful logon
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4625}         # Failed logon
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4648}         # Explicit credential logon
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4720}         # User created
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4726}         # User deleted
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4732}         # User added to group
Get-WinEvent -FilterHashtable @{LogName="System"; ID=7045}           # Service installed

# Filter by date
Get-WinEvent -FilterHashtable @{LogName="Security"; StartTime=(Get-Date).AddDays(-1)}
Get-WinEvent -FilterHashtable @{LogName="Security"; StartTime="2024-01-01"; EndTime="2024-01-02"}

# Filter by level (1=Critical, 2=Error, 3=Warning)
Get-WinEvent -FilterHashtable @{LogName="System"; Level=2}

# Search event message
Get-WinEvent -LogName Security | Where-Object { $_.Message -like "*failed*" } | Select-Object TimeCreated, Message -First 10

# Export events
Get-WinEvent -LogName Security -MaxEvents 1000 | Export-Csv -Path security_events.csv -NoTypeInformation

# Clear log
Clear-EventLog -LogName Application
wevtutil cl Security
```
::

### Important Security Event IDs

| Event ID | Description                              |
| -------- | ---------------------------------------- |
| `4624`   | Successful logon                         |
| `4625`   | Failed logon                             |
| `4634`   | Account logoff                           |
| `4648`   | Logon using explicit credentials         |
| `4672`   | Special privileges assigned to logon     |
| `4688`   | Process creation                         |
| `4689`   | Process termination                      |
| `4697`   | Service installed on system              |
| `4698`   | Scheduled task created                   |
| `4699`   | Scheduled task deleted                   |
| `4700`   | Scheduled task enabled                   |
| `4720`   | User account created                     |
| `4722`   | User account enabled                     |
| `4723`   | Password change attempt                  |
| `4724`   | Password reset attempt                   |
| `4725`   | User account disabled                    |
| `4726`   | User account deleted                     |
| `4728`   | Member added to security group           |
| `4732`   | Member added to local group              |
| `4738`   | User account changed                     |
| `4740`   | Account locked out                       |
| `4756`   | Member added to universal group          |
| `4767`   | Account unlocked                         |
| `4776`   | NTLM authentication                      |
| `7045`   | New service installed                    |
| `1102`   | Audit log cleared                        |

---

## Windows Server Roles and Features

::code-preview
---
class: "[&>div]:*:my-0"
---
Install and manage server roles.

#code
```powershell
# List all available features
Get-WindowsFeature

# List installed features
Get-WindowsFeature | Where-Object { $_.Installed }

# Install features
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Install-WindowsFeature -Name DNS -IncludeManagementTools
Install-WindowsFeature -Name DHCP -IncludeManagementTools
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools
Install-WindowsFeature -Name File-Services
Install-WindowsFeature -Name RSAT-AD-Tools
Install-WindowsFeature -Name GPMC
Install-WindowsFeature -Name Failover-Clustering
Install-WindowsFeature -Name Windows-Server-Backup
Install-WindowsFeature -Name Telnet-Client

# Remove features
Uninstall-WindowsFeature -Name Telnet-Client

# Install from installation media (Server Core)
Install-WindowsFeature -Name NET-Framework-Core -Source D:\sources\sxs
```
::

### Common Server Roles

| Role                          | Feature Name              | Purpose                        |
| ----------------------------- | ------------------------- | ------------------------------ |
| Active Directory              | `AD-Domain-Services`      | Domain controller              |
| DNS Server                    | `DNS`                     | Name resolution                |
| DHCP Server                   | `DHCP`                    | IP address management          |
| IIS Web Server                | `Web-Server`              | Web hosting                    |
| Hyper-V                       | `Hyper-V`                 | Virtualization                 |
| File Server                   | `File-Services`           | File sharing                   |
| Print Server                  | `Print-Services`          | Print management               |
| WSUS                          | `UpdateServices`          | Patch management               |
| Remote Desktop Services       | `Remote-Desktop-Services` | Terminal services              |
| Failover Clustering           | `Failover-Clustering`     | High availability              |
| Network Policy Server         | `NPAS`                    | RADIUS / NAP                   |
| Windows Server Backup         | `Windows-Server-Backup`   | Backup solution                |
| Certificate Services          | `AD-Certificate`          | PKI / Certificate Authority    |
| RSAT Tools                    | `RSAT-AD-Tools`           | Remote administration tools    |

---

## Remote Management

### WinRM / PSRemoting

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure and use PowerShell Remoting.

#code
```powershell
# Enable PSRemoting
Enable-PSRemoting -Force

# Check WinRM status
Test-WSMan <target>
Get-Service WinRM

# Configure WinRM
winrm quickconfig
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*"           # Trust all (lab only)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.*" # Trust subnet

# Interactive remote session
Enter-PSSession -ComputerName <target> -Credential (Get-Credential)

# Execute remote command
Invoke-Command -ComputerName <target> -ScriptBlock { Get-Process } -Credential (Get-Credential)

# Execute on multiple computers
Invoke-Command -ComputerName Server01, Server02, Server03 -ScriptBlock { Get-Service }

# Copy file to remote machine
Copy-Item -Path "C:\file.txt" -Destination "C:\remote\" -ToSession (New-PSSession -ComputerName <target>)

# Persistent session
$session = New-PSSession -ComputerName <target> -Credential (Get-Credential)
Invoke-Command -Session $session -ScriptBlock { Get-Process }
Enter-PSSession -Session $session
Remove-PSSession -Session $session

# PSSessions to multiple machines
$servers = "Server01", "Server02", "Server03"
$sessions = New-PSSession -ComputerName $servers -Credential (Get-Credential)
Invoke-Command -Session $sessions -ScriptBlock { hostname }
```
::

### Remote Desktop (RDP)

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure Remote Desktop.

#code
```powershell
# Enable RDP
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

# Allow through firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Add user to Remote Desktop Users
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "username"

# Set Network Level Authentication
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1

# Connect via CMD
mstsc /v:<target>
mstsc /v:<target>:3389

# Check RDP port
Test-NetConnection <target> -Port 3389
```
::

### SSH Server (Windows Server 2019+)

::code-preview
---
class: "[&>div]:*:my-0"
---
Install and configure OpenSSH Server.

#code
```powershell
# Check available
Get-WindowsCapability -Online | Where-Object { $_.Name -like "*SSH*" }

# Install OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Install OpenSSH Client
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Start and enable SSH
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# Allow through firewall
New-NetFirewallRule -Name "SSH" -DisplayName "OpenSSH Server" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# Configure SSH
notepad C:\ProgramData\ssh\sshd_config

# Set default shell to PowerShell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

# Restart SSH after config change
Restart-Service sshd
```
::

---

## Windows Defender / Security

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage Windows Defender and security settings.

#code
```powershell
# Check Defender status
Get-MpComputerStatus

# Update signatures
Update-MpSignature

# Quick scan
Start-MpScan -ScanType QuickScan

# Full scan
Start-MpScan -ScanType FullScan

# Custom scan
Start-MpScan -ScanType CustomScan -ScanPath "C:\Users"

# View threats
Get-MpThreat
Get-MpThreatDetection

# Add exclusion
Add-MpPreference -ExclusionPath "C:\Tools"
Add-MpPreference -ExclusionExtension ".ps1"
Add-MpPreference -ExclusionProcess "process.exe"

# View exclusions
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess

# Remove exclusion
Remove-MpPreference -ExclusionPath "C:\Tools"

# Disable real-time protection (requires admin)
Set-MpPreference -DisableRealtimeMonitoring $true

# Enable real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Configure automatic sample submission
Set-MpPreference -SubmitSamplesConsent 0    # Never
Set-MpPreference -SubmitSamplesConsent 1    # Always

# History
Get-MpThreatDetection | Select-Object ThreatID, InitialDetectionTime, Resources
```
::

### Windows Security Audit Policy

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure audit policies.

#code
```cmd
:: View current audit policy
auditpol /get /category:*

:: Enable logon auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

:: Enable process creation auditing
auditpol /set /subcategory:"Process Creation" /success:enable

:: Enable account management auditing
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

:: Enable object access auditing
auditpol /set /subcategory:"File System" /success:enable /failure:enable

:: Export audit policy
auditpol /backup /file:C:\audit_backup.csv

:: Restore audit policy
auditpol /restore /file:C:\audit_backup.csv

:: Clear audit policy
auditpol /clear /y
```
::

---

## SMB File Sharing

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage SMB file shares.

#code
```powershell
# List shares
Get-SmbShare
net share

# Create share
New-SmbShare -Name "SharedDocs" -Path "C:\SharedDocs" -FullAccess "Administrators" -ReadAccess "Everyone"

# Create with CMD
net share SharedDocs=C:\SharedDocs /grant:Everyone,READ /grant:Administrators,FULL

# Remove share
Remove-SmbShare -Name "SharedDocs" -Force
net share SharedDocs /delete

# Map network drive
New-PSDrive -Name "Z" -Root "\\server\share" -PSProvider FileSystem -Persist
net use Z: \\server\share
net use Z: \\server\share /user:domain\username password

# Disconnect network drive
Remove-PSDrive -Name "Z"
net use Z: /delete

# View mapped drives
Get-PSDrive -PSProvider FileSystem
net use

# SMB connections
Get-SmbConnection
Get-SmbSession
Get-SmbOpenFile

# Close SMB session
Close-SmbSession -SessionId <id> -Force

# SMB configuration
Get-SmbServerConfiguration
Set-SmbServerConfiguration -EnableSMB1Protocol $false    # Disable SMBv1
Set-SmbServerConfiguration -EnableSMB2Protocol $true     # Enable SMBv2

# SMB security
Set-SmbServerConfiguration -EncryptData $true            # Require encryption
Set-SmbServerConfiguration -RequireSecuritySignature $true
```
::

---

## Windows Backup

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage Windows Server Backup.

#code
```powershell
# Install Windows Server Backup
Install-WindowsFeature Windows-Server-Backup

# Create backup policy
$policy = New-WBPolicy
$volume = Get-WBVolume -AllVolumes | Where-Object { $_.MountPoint -eq "C:" }
Add-WBVolume -Policy $policy -Volume $volume
$target = New-WBBackupTarget -NetworkPath "\\backup-server\backups" -Credential (Get-Credential)
Add-WBBackupTarget -Policy $policy -Target $target
Set-WBSchedule -Policy $policy -Schedule 02:00
Set-WBPolicy -Policy $policy

# Manual backup
Start-WBBackup -Policy (Get-WBPolicy)

# System state backup
wbadmin start systemstatebackup -backuptarget:E:

# List backups
Get-WBBackupSet
wbadmin get versions

# Bare metal backup
wbadmin start backup -backuptarget:E: -include:C: -allCritical -quiet
```
::

---

## Useful One-Liners

::code-preview
---
class: "[&>div]:*:my-0"
---
Handy Windows one-liner commands.

#code
```powershell
# Find large files
Get-ChildItem C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 100MB } | Sort-Object Length -Descending | Select-Object FullName, @{Name="SizeMB";Expression={[math]::Round($_.Length/1MB,2)}}

# Find recently modified files (24 hours)
Get-ChildItem C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) }

# Get external IP
(Invoke-WebRequest -Uri "https://ifconfig.me" -UseBasicParsing).Content

# Generate random password
[System.Web.Security.Membership]::GeneratePassword(16, 3)
-join ((65..90) + (97..122) + (48..57) + (33..47) | Get-Random -Count 20 | ForEach-Object { [char]$_ })

# Base64 encode / decode
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Hello World"))
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("SGVsbG8gV29ybGQ="))

# Quick HTTP server (Python)
python -m http.server 8080

# Download file
Invoke-WebRequest -Uri "https://url/file" -OutFile "file.exe"
(New-Object Net.WebClient).DownloadFile("https://url/file", "C:\file.exe")
certutil -urlcache -split -f "https://url/file" "C:\file.exe"
bitsadmin /transfer job /download /priority high "https://url/file" "C:\file.exe"

# Port scan (basic)
1..1024 | ForEach-Object { Test-NetConnection -ComputerName <target> -Port $_ -WarningAction SilentlyContinue | Where-Object { $_.TcpTestSucceeded } }

# List all installed software
Get-CimInstance Win32_Product | Select-Object Name, Version | Sort-Object Name

# System resource snapshot
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, CPU, @{Name="MemMB";Expression={[math]::Round($_.WorkingSet64/1MB)}}

# Find string in files recursively
Get-ChildItem -Recurse -Filter *.txt | Select-String -Pattern "password"

# Flush all network caches
ipconfig /flushdns; arp -d *; nbtstat -R; netsh int ip reset; netsh winsock reset

# List all auto-start programs
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
::

---

## CMD vs PowerShell Quick Reference

| Task                      | CMD                                  | PowerShell                                |
| ------------------------- | ------------------------------------ | ----------------------------------------- |
| List files                | `dir`                                | `Get-ChildItem`                           |
| Copy file                 | `copy`                               | `Copy-Item`                               |
| Move file                 | `move`                               | `Move-Item`                               |
| Delete file               | `del`                                | `Remove-Item`                             |
| Create directory          | `mkdir`                              | `New-Item -ItemType Directory`            |
| View file                 | `type`                               | `Get-Content`                             |
| Find text                 | `findstr`                            | `Select-String`                           |
| IP config                 | `ipconfig`                           | `Get-NetIPAddress`                        |
| Ping                      | `ping`                               | `Test-Connection`                         |
| DNS lookup                | `nslookup`                           | `Resolve-DnsName`                         |
| Open ports                | `netstat -ano`                       | `Get-NetTCPConnection`                    |
| Services                  | `sc query`                           | `Get-Service`                             |
| Processes                 | `tasklist`                           | `Get-Process`                             |
| Kill process              | `taskkill`                           | `Stop-Process`                            |
| Users                     | `net user`                           | `Get-LocalUser`                           |
| Groups                    | `net localgroup`                     | `Get-LocalGroup`                          |
| Scheduled tasks           | `schtasks`                           | `Get-ScheduledTask`                       |
| Registry                  | `reg query`                          | `Get-ItemProperty`                        |
| Firewall                  | `netsh advfirewall`                  | `Get-NetFirewallRule`                     |
| Event logs                | `wevtutil`                           | `Get-WinEvent`                            |

---

## References

- [Microsoft PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/)
- [Microsoft Windows Server Documentation](https://learn.microsoft.com/en-us/windows-server/)
- [Microsoft Active Directory Documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/)
- [SS64 Windows CMD Reference](https://ss64.com/nt/)
- [SS64 PowerShell Reference](https://ss64.com/ps/)
- [Windows Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [HackTricks Windows](https://book.hacktricks.xyz/windows-hardening/)
- [SANS Windows Command Line Cheat Sheet](https://www.sans.org/)
- [Windows Sysinternals](https://learn.microsoft.com/en-us/sysinternals/)

::tip
Mastering both **CMD** and **PowerShell** is essential. PowerShell is far more powerful for automation and remote management, while CMD remains useful for quick tasks, legacy systems, and environments where PowerShell is restricted.
::
:::