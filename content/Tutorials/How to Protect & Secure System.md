---
title: System-Level Protection & Security Hardening
description: OS hardening, file system path security, firewall rules, port management, user access control, kernel protection, service hardening, logging, patch management, and encryption — for both Linux and Windows systems.
navigation:
  icon: i-lucide-shield-check
  title: System Security Hardening
---

## Introduction

System-level security is the **foundation** of your entire defense posture. No application security, WAF, or monitoring tool can compensate for a poorly hardened operating system. This guide covers every layer of OS-level protection — from kernel parameters to firewall rules to encryption at rest.

::note
This guide follows the **defense-in-depth** principle — multiple overlapping layers of security so that if one layer fails, others still protect the system.
::

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEFENSE IN DEPTH MODEL                       │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Layer 7: Application Security                            │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  Layer 6: Data Encryption & Protection              │  │  │
│  │  │  ┌───────────────────────────────────────────────┐  │  │  │
│  │  │  │  Layer 5: Logging, Monitoring & Auditing      │  │  │  │
│  │  │  │  ┌─────────────────────────────────────────┐  │  │  │  │
│  │  │  │  │  Layer 4: Service & Process Hardening    │  │  │  │  │
│  │  │  │  │  ┌───────────────────────────────────┐  │  │  │  │  │
│  │  │  │  │  │  Layer 3: User & Access Control    │  │  │  │  │  │
│  │  │  │  │  │  ┌─────────────────────────────┐  │  │  │  │  │  │
│  │  │  │  │  │  │ Layer 2: Firewall & Ports   │  │  │  │  │  │  │
│  │  │  │  │  │  │  ┌───────────────────────┐  │  │  │  │  │  │  │
│  │  │  │  │  │  │  │ Layer 1: OS & Kernel  │  │  │  │  │  │  │  │
│  │  │  │  │  │  │  │     Hardening         │  │  │  │  │  │  │  │
│  │  │  │  │  │  │  └───────────────────────┘  │  │  │  │  │  │  │
│  │  │  │  │  │  └─────────────────────────────┘  │  │  │  │  │  │
│  │  │  │  │  └───────────────────────────────────┘  │  │  │  │  │
│  │  │  │  └─────────────────────────────────────────┘  │  │  │  │
│  │  │  └───────────────────────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Foundation: Physical Security & Hardware Trust            │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

::card-group
  ::card
  ---
  title: CIS Benchmarks
  icon: i-lucide-shield
  to: https://www.cisecurity.org/cis-benchmarks
  target: _blank
  ---
  Industry-standard security configuration benchmarks for every major OS and platform.
  ::

  ::card
  ---
  title: NIST SP 800-123
  icon: i-lucide-book-open
  to: https://csrc.nist.gov/publications/detail/sp/800-123/final
  target: _blank
  ---
  Guide to General Server Security — NIST guidelines for securing server operating systems.
  ::

  ::card
  ---
  title: DISA STIGs
  icon: i-lucide-lock
  to: https://public.cyber.mil/stigs/
  target: _blank
  ---
  Security Technical Implementation Guides from the U.S. Department of Defense.
  ::

  ::card
  ---
  title: Linux Hardening Guide
  icon: i-simple-icons-linux
  to: https://madaidans-insecurities.github.io/guides/linux-hardening.html
  target: _blank
  ---
  Community-driven comprehensive Linux kernel and OS hardening reference.
  ::
::

::badge
**Tags: tutorials · system-security · os-hardening · firewall · port-management · access-control · encryption · kernel-security · patch-management · logging**
::

---

## Layer 1 — OS & Kernel Hardening

::caution
Kernel-level hardening is your **last line of defense**. If an attacker reaches kernel level, it's already game over. These configurations prevent common kernel exploitation techniques.
::

### Linux Kernel Hardening (sysctl)

::steps{level="4"}

#### Step 1: Understand sysctl

`sysctl` controls Linux kernel parameters at runtime. Security-relevant parameters prevent common attack vectors like buffer overflows, IP spoofing, and ICMP attacks.

#### Step 2: Apply Hardened Kernel Parameters

::

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [/etc/sysctl.d/99-security-hardening.conf]
# ============================================
# NETWORK SECURITY
# ============================================

# Disable IP forwarding (unless this is a router/gateway)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing (prevent IP spoofing)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable ICMP redirect acceptance (prevent MITM)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable ICMP redirect sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable TCP SYN cookies (prevent SYN flood DoS)
net.ipv4.tcp_syncookies = 1

# Ignore ICMP broadcast requests (prevent Smurf attacks)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log martian packets (impossible source addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# TCP hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_syn_backlog = 4096

# ============================================
# MEMORY & PROCESS SECURITY
# ============================================

# Restrict kernel pointer exposure (prevent KASLR bypass)
kernel.kptr_restrict = 2

# Restrict dmesg access to root only
kernel.dmesg_restrict = 1

# Restrict access to kernel profiling
kernel.perf_event_paranoid = 3

# Enable ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2

# Restrict ptrace (prevent process debugging/injection)
kernel.yama.ptrace_scope = 2

# Restrict unprivileged access to BPF
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Restrict loading kernel modules after boot
# kernel.modules_disabled = 1  # CAUTION: Cannot load modules after setting

# Disable SysRq key combinations (prevent console attacks)
kernel.sysrq = 0

# Restrict core dumps
fs.suid_dumpable = 0

# Restrict unprivileged user namespaces (container escape prevention)
kernel.unprivileged_userns_clone = 0

# ============================================
# FILE SYSTEM SECURITY
# ============================================

# Restrict hardlink/symlink creation
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Protect FIFOs and regular files
fs.protected_fifos = 2
fs.protected_regular = 2
```

#code
```bash
# Apply all settings
sudo sysctl -p /etc/sysctl.d/99-security-hardening.conf

# Verify specific setting
sysctl kernel.randomize_va_space
```
::

### Windows OS Hardening

::tabs
  :::tabs-item{icon="i-simple-icons-windows" label="Registry Hardening"}
  ```powershell [Windows Registry Security Settings]
  # ============================================
  # DISABLE UNNECESSARY FEATURES
  # ============================================
  
  # Disable AutoRun/AutoPlay (prevent USB attacks)
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1
  
  # Disable Remote Desktop (if not needed)
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
  
  # Disable WDigest (prevent cleartext password caching)
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
  
  # Disable LLMNR (prevent name resolution poisoning)
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0
  
  # Disable NetBIOS over TCP/IP (prevent NBNS poisoning)
  $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
  foreach ($adapter in $adapters) {
      $adapter.SetTcpipNetbios(2)  # 2 = Disable
  }
  
  # Disable SMBv1 (WannaCry/EternalBlue prevention)
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
  
  # Enable SMB signing (prevent relay attacks)
  Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
  Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
  
  # ============================================
  # CREDENTIAL PROTECTION
  # ============================================
  
  # Enable LSA Protection (RunAsPPL)
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
  
  # Enable Credential Guard (Windows 10 Enterprise / Server 2016+)
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1
  
  # Restrict anonymous SAM enumeration
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
  
  # Disable cached logon credentials (or limit)
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 0
  
  # ============================================
  # NETWORK SECURITY
  # ============================================
  
  # Disable WPAD (Web Proxy Auto-Discovery)
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHTTPAutoProxySvc" -Name "Start" -Value 4
  
  # Disable IPv6 if not needed
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 255
  
  # Enable DEP (Data Execution Prevention) for all programs
  bcdedit /set nx AlwaysOn
  
  # Enable ASLR
  Set-ProcessMitigation -System -Enable ForceRelocateImages
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="Group Policy Hardening"}
  ```powershell [Group Policy Security Settings]
  # ============================================
  # AUDIT POLICY (enable comprehensive logging)
  # ============================================
  
  # Enable advanced audit policies
  auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
  auditpol /set /category:"Account Logon" /success:enable /failure:enable
  auditpol /set /category:"Account Management" /success:enable /failure:enable
  auditpol /set /category:"DS Access" /success:enable /failure:enable
  auditpol /set /category:"Object Access" /success:enable /failure:enable
  auditpol /set /category:"Policy Change" /success:enable /failure:enable
  auditpol /set /category:"Privilege Use" /success:enable /failure:enable
  auditpol /set /category:"Process Tracking" /success:enable /failure:enable
  auditpol /set /category:"System" /success:enable /failure:enable
  
  # ============================================
  # PASSWORD POLICY
  # ============================================
  
  # Set via Local Security Policy or GPO
  net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:24 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
  
  # ============================================
  # USER RIGHTS ASSIGNMENTS
  # ============================================
  
  # Restrict who can log on locally
  # Computer Configuration → Windows Settings → Security Settings
  # → Local Policies → User Rights Assignment
  # "Allow log on locally" → Only Administrators
  # "Deny log on as a service" → Guests
  # "Deny access from network" → Guests, Local account
  
  # ============================================
  # SECURITY OPTIONS
  # ============================================
  
  # Accounts: Rename administrator account
  wmic useraccount where name='Administrator' rename 'SysAdmin'
  
  # Accounts: Rename guest account
  wmic useraccount where name='Guest' rename 'Visitor'
  
  # Accounts: Disable guest account
  net user Guest /active:no
  
  # Interactive logon: Don't display last user name
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1
  
  # Interactive logon: Machine inactivity limit (900 seconds = 15 min)
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="PowerShell Security"}
  ```powershell [PowerShell Hardening]
  # ============================================
  # POWERSHELL SECURITY HARDENING
  # ============================================
  
  # Enable PowerShell script block logging
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
  
  # Enable PowerShell module logging
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
  
  # Enable PowerShell transcription (log all PS activity)
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PSTranscripts"
  
  # Set execution policy
  Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine
  
  # Enable Constrained Language Mode (blocks most attack tools)
  [System.Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')
  
  # Disable PowerShell v2 (bypasses modern security controls)
  Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart
  Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
  ```
  :::
::

### GRUB & Boot Security (Linux)

::collapsible
**Boot Loader Security**

```bash [GRUB & Boot Hardening]
# ============================================
# SET GRUB PASSWORD (prevent boot parameter tampering)
# ============================================

# Generate password hash
grub-mkpasswd-pbkdf2
# Enter password → get PBKDF2 hash

# Add to GRUB config
sudo nano /etc/grub.d/40_custom

# Add these lines:
# set superusers="grubadmin"
# password_pbkdf2 grubadmin grub.pbkdf2.sha512.10000.HASH_HERE

# Update GRUB
sudo update-grub

# ============================================
# PROTECT SINGLE-USER MODE
# ============================================

# Require root password for single-user mode
# /etc/systemd/system/rescue.service.d/override.conf
# [Service]
# ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue

# ============================================
# SECURE BOOT PERMISSIONS
# ============================================

# Restrict GRUB config permissions
sudo chmod 600 /boot/grub/grub.cfg
sudo chown root:root /boot/grub/grub.cfg

# Restrict kernel and initramfs
sudo chmod 600 /boot/vmlinuz-*
sudo chmod 600 /boot/initrd.img-*

# ============================================
# ENABLE UEFI SECURE BOOT
# ============================================
# Ensure Secure Boot is enabled in BIOS/UEFI
# Verify: mokutil --sb-state
# Should output: "SecureBoot enabled"
```
::

---

## Layer 2 — Firewall & Port Management

::warning
A firewall is your **primary network perimeter defense** at the OS level. The principle is simple: **deny everything, allow only what's explicitly needed**.
::

### Firewall Philosophy

```
┌─────────────────────────────────────────────┐
│           FIREWALL DESIGN PRINCIPLES         │
│                                             │
│  1. DEFAULT DENY — Block everything first   │
│  2. ALLOW MINIMUM — Only required services  │
│  3. RESTRICT SOURCE — Limit by source IP    │
│  4. LOG DENIED — Log all blocked traffic    │
│  5. EGRESS FILTER — Control outbound too    │
│  6. STATEFUL — Track connection state       │
│  7. REVIEW — Audit rules regularly          │
└─────────────────────────────────────────────┘
```

### Linux Firewall — UFW (Uncomplicated Firewall)

::steps{level="4"}

#### Step 1: Install and Enable UFW

```bash [UFW Setup]
# Install UFW
sudo apt install -y ufw

# Set default policies — DENY ALL incoming, ALLOW outgoing
sudo ufw default deny incoming
sudo ufw default allow outgoing

# IMPORTANT: Allow SSH BEFORE enabling (don't lock yourself out!)
sudo ufw allow from YOUR_IP/32 to any port 22 proto tcp comment "SSH from admin IP"

# Enable UFW
sudo ufw enable

# Check status
sudo ufw status verbose
```

#### Step 2: Configure Service Rules

```bash [UFW Service Rules]
# ============================================
# WEB SERVER RULES
# ============================================

# Allow HTTP/HTTPS from anywhere
sudo ufw allow 80/tcp comment "HTTP"
sudo ufw allow 443/tcp comment "HTTPS"

# Allow HTTP/HTTPS only from specific network
sudo ufw allow from 10.0.0.0/24 to any port 80 proto tcp comment "HTTP from internal"
sudo ufw allow from 10.0.0.0/24 to any port 443 proto tcp comment "HTTPS from internal"

# ============================================
# DATABASE RULES (NEVER expose to public)
# ============================================

# MySQL — only from application server
sudo ufw allow from 10.0.0.20/32 to any port 3306 proto tcp comment "MySQL from app server"

# PostgreSQL — only from application server
sudo ufw allow from 10.0.0.20/32 to any port 5432 proto tcp comment "PostgreSQL from app server"

# Redis — only localhost
sudo ufw allow from 127.0.0.1 to any port 6379 proto tcp comment "Redis localhost only"

# ============================================
# MANAGEMENT RULES
# ============================================

# SSH — only from admin network
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp comment "SSH from admin network"

# Monitoring (SNMP, Zabbix agent)
sudo ufw allow from 10.0.0.5/32 to any port 10050 proto tcp comment "Zabbix agent"
```

#### Step 3: Rate Limiting & Advanced Rules

```bash [UFW Advanced Rules]
# ============================================
# RATE LIMITING (brute-force protection)
# ============================================

# Rate limit SSH (deny if >6 connections in 30 seconds)
sudo ufw limit 22/tcp comment "SSH rate limit"

# ============================================
# DENY SPECIFIC SOURCES
# ============================================

# Block a known attacker IP
sudo ufw deny from 203.0.113.100 comment "Blocked attacker"

# Block an entire country range
sudo ufw deny from 192.0.2.0/24 comment "Blocked network"

# ============================================
# EGRESS FILTERING (control outbound)
# ============================================

# Change default outgoing policy to deny
sudo ufw default deny outgoing

# Allow only necessary outbound
sudo ufw allow out 53/udp comment "DNS"
sudo ufw allow out 53/tcp comment "DNS TCP"
sudo ufw allow out 80/tcp comment "HTTP out"
sudo ufw allow out 443/tcp comment "HTTPS out"
sudo ufw allow out 123/udp comment "NTP"
sudo ufw allow out 25/tcp comment "SMTP out"
sudo ufw allow out 587/tcp comment "SMTP submission"

# ============================================
# LOGGING
# ============================================

# Enable logging
sudo ufw logging on

# Set log level (low, medium, high, full)
sudo ufw logging high

# View logs
sudo tail -f /var/log/ufw.log

# ============================================
# MANAGEMENT COMMANDS
# ============================================

# List rules with numbers
sudo ufw status numbered

# Delete a rule by number
sudo ufw delete 5

# Delete a rule by specification
sudo ufw delete allow 8080/tcp

# Reset all rules
sudo ufw reset

# Reload rules
sudo ufw reload
```

::

### Linux Firewall — iptables / nftables (Advanced)

::tabs
  :::tabs-item{icon="i-lucide-shield" label="iptables Rules"}
  ```bash [iptables Hardened Ruleset]
  #!/bin/bash
  # ============================================
  # HARDENED IPTABLES FIREWALL SCRIPT
  # Save as: /etc/iptables/rules.sh
  # ============================================
  
  # Flush existing rules
  iptables -F
  iptables -X
  iptables -t nat -F
  iptables -t mangle -F
  
  # ============================================
  # DEFAULT POLICIES — DROP EVERYTHING
  # ============================================
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT DROP
  
  # ============================================
  # LOOPBACK — Allow localhost
  # ============================================
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT
  
  # ============================================
  # ESTABLISHED CONNECTIONS — Allow existing
  # ============================================
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  
  # ============================================
  # DROP INVALID PACKETS
  # ============================================
  iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
  
  # ============================================
  # ANTI-SPOOFING
  # ============================================
  iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
  iptables -A INPUT -s 0.0.0.0/8 -j DROP
  iptables -A INPUT -s 169.254.0.0/16 -j DROP
  iptables -A INPUT -s 224.0.0.0/4 -j DROP
  iptables -A INPUT -s 240.0.0.0/5 -j DROP
  
  # ============================================
  # ANTI-SCANNING (drop common scan patterns)
  # ============================================
  # Drop NULL packets
  iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
  
  # Drop XMAS packets
  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
  
  # Drop SYN-FIN (impossible combination)
  iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
  
  # Drop SYN-RST
  iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
  
  # Drop FIN without ACK
  iptables -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP
  
  # ============================================
  # SYN FLOOD PROTECTION
  # ============================================
  iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
  iptables -A INPUT -p tcp --syn -j DROP
  
  # ============================================
  # PING RATE LIMITING
  # ============================================
  iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
  iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
  
  # ============================================
  # INBOUND RULES
  # ============================================
  
  # SSH — Admin IP only
  iptables -A INPUT -p tcp -s ADMIN_IP/32 --dport 22 -m conntrack --ctstate NEW -j ACCEPT
  
  # HTTP/HTTPS
  iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
  
  # MySQL — App server only
  iptables -A INPUT -p tcp -s APP_SERVER_IP/32 --dport 3306 -m conntrack --ctstate NEW -j ACCEPT
  
  # ============================================
  # OUTBOUND RULES
  # ============================================
  iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT    # DNS
  iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT    # DNS TCP
  iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT    # HTTP
  iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT   # HTTPS
  iptables -A OUTPUT -p udp --dport 123 -m conntrack --ctstate NEW -j ACCEPT   # NTP
  
  # ============================================
  # LOGGING — Log dropped packets
  # ============================================
  iptables -A INPUT -j LOG --log-prefix "IPT-DROP-IN: " --log-level 4
  iptables -A OUTPUT -j LOG --log-prefix "IPT-DROP-OUT: " --log-level 4
  iptables -A FORWARD -j LOG --log-prefix "IPT-DROP-FWD: " --log-level 4
  
  # ============================================
  # SAVE RULES
  # ============================================
  iptables-save > /etc/iptables/rules.v4
  
  echo "[✓] Firewall rules applied successfully"
  ```
  :::

  :::tabs-item{icon="i-lucide-layers" label="nftables Rules"}
  ```bash [/etc/nftables.conf]
  #!/usr/sbin/nft -f
  # ============================================
  # HARDENED NFTABLES FIREWALL
  # Modern replacement for iptables
  # ============================================
  
  # Flush existing rules
  flush ruleset
  
  table inet firewall {
      # ============================================
      # SETS — Define reusable IP/port groups
      # ============================================
      set admin_ips {
          type ipv4_addr
          elements = { 192.168.1.10, 10.0.0.5 }
      }
  
      set blocked_ips {
          type ipv4_addr
          flags interval
          elements = { 203.0.113.0/24, 198.51.100.0/24 }
      }
  
      set allowed_tcp_ports {
          type inet_service
          elements = { 80, 443 }
      }
  
      # ============================================
      # INPUT CHAIN
      # ============================================
      chain input {
          type filter hook input priority 0; policy drop;
  
          # Allow loopback
          iif "lo" accept
  
          # Allow established/related
          ct state established,related accept
  
          # Drop invalid
          ct state invalid drop
  
          # Drop blocked IPs
          ip saddr @blocked_ips drop
  
          # Anti-scan: drop TCP with no flags
          tcp flags & (fin|syn|rst|ack) == 0 drop
  
          # Rate limit ICMP
          ip protocol icmp limit rate 4/second accept
          ip protocol icmp drop
  
          # SSH — admin IPs only with rate limiting
          tcp dport 22 ip saddr @admin_ips ct state new limit rate 3/minute accept
  
          # Web services
          tcp dport @allowed_tcp_ports ct state new accept
  
          # Log dropped packets
          log prefix "NFT-DROP-IN: " flags all counter drop
      }
  
      # ============================================
      # FORWARD CHAIN
      # ============================================
      chain forward {
          type filter hook forward priority 0; policy drop;
          log prefix "NFT-DROP-FWD: " flags all counter drop
      }
  
      # ============================================
      # OUTPUT CHAIN
      # ============================================
      chain output {
          type filter hook output priority 0; policy drop;
  
          # Allow loopback
          oif "lo" accept
  
          # Allow established
          ct state established,related accept
  
          # DNS
          tcp dport 53 ct state new accept
          udp dport 53 ct state new accept
  
          # HTTP/HTTPS (for updates)
          tcp dport { 80, 443 } ct state new accept
  
          # NTP
          udp dport 123 ct state new accept
  
          # SMTP
          tcp dport { 25, 587 } ct state new accept
  
          # Log dropped
          log prefix "NFT-DROP-OUT: " flags all counter drop
      }
  }
  ```
  :::
::

### Windows Firewall Hardening

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```powershell [Windows Firewall Hardening]
# ============================================
# ENABLE AND CONFIGURE WINDOWS FIREWALL
# ============================================

# Enable firewall on ALL profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Set default policies — Block inbound, Allow outbound
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow `
    -LogAllowed True `
    -LogBlocked True `
    -LogMaxSizeKilobytes 32768 `
    -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"

# ============================================
# REMOVE DEFAULT ALLOW RULES (clean slate)
# ============================================

# Disable all pre-existing inbound allow rules
Get-NetFirewallRule -Direction Inbound -Action Allow | Disable-NetFirewallRule

# ============================================
# INBOUND RULES — Only what's needed
# ============================================

# SSH (OpenSSH) — Admin IP only
New-NetFirewallRule -DisplayName "SSH-Admin" `
    -Direction Inbound -Protocol TCP -LocalPort 22 `
    -RemoteAddress "192.168.1.10/32" `
    -Action Allow -Profile Any `
    -Description "SSH from admin workstation only"

# RDP — Admin network only
New-NetFirewallRule -DisplayName "RDP-Admin" `
    -Direction Inbound -Protocol TCP -LocalPort 3389 `
    -RemoteAddress "192.168.1.0/24" `
    -Action Allow -Profile Domain `
    -Description "RDP from admin network only"

# HTTP/HTTPS — Web server
New-NetFirewallRule -DisplayName "HTTP" `
    -Direction Inbound -Protocol TCP -LocalPort 80 `
    -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "HTTPS" `
    -Direction Inbound -Protocol TCP -LocalPort 443 `
    -Action Allow -Profile Any

# ICMP (Ping) — Internal only
New-NetFirewallRule -DisplayName "ICMP-Internal" `
    -Direction Inbound -Protocol ICMPv4 `
    -RemoteAddress "10.0.0.0/8" `
    -Action Allow -Profile Domain

# ============================================
# BLOCK SPECIFIC DANGEROUS PORTS
# ============================================

# Block SMB from external (prevent EternalBlue)
New-NetFirewallRule -DisplayName "Block-SMB-External" `
    -Direction Inbound -Protocol TCP -LocalPort 445 `
    -RemoteAddress "Any" `
    -Action Block -Profile Public

# Block RPC
New-NetFirewallRule -DisplayName "Block-RPC-External" `
    -Direction Inbound -Protocol TCP -LocalPort 135 `
    -RemoteAddress "Any" `
    -Action Block -Profile Public

# Block NetBIOS
New-NetFirewallRule -DisplayName "Block-NetBIOS" `
    -Direction Inbound -Protocol TCP -LocalPort 137-139 `
    -Action Block -Profile Public
New-NetFirewallRule -DisplayName "Block-NetBIOS-UDP" `
    -Direction Inbound -Protocol UDP -LocalPort 137-139 `
    -Action Block -Profile Public

# ============================================
# OUTBOUND RULES (if restricting egress)
# ============================================

# Change default outbound to Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block

# Allow DNS
New-NetFirewallRule -DisplayName "DNS-Out" `
    -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow
New-NetFirewallRule -DisplayName "DNS-TCP-Out" `
    -Direction Outbound -Protocol TCP -RemotePort 53 -Action Allow

# Allow HTTP/HTTPS
New-NetFirewallRule -DisplayName "HTTP-Out" `
    -Direction Outbound -Protocol TCP -RemotePort 80 -Action Allow
New-NetFirewallRule -DisplayName "HTTPS-Out" `
    -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow

# Allow NTP
New-NetFirewallRule -DisplayName "NTP-Out" `
    -Direction Outbound -Protocol UDP -RemotePort 123 -Action Allow

# Allow Windows Update
New-NetFirewallRule -DisplayName "WinUpdate-Out" `
    -Direction Outbound -Protocol TCP -RemotePort 443 `
    -RemoteAddress "13.107.4.50","13.107.4.52" -Action Allow
```

#code
```powershell
# Quick hardening — enable firewall, block inbound
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block
```
::

### Port Management

::tip
Every open port is a potential **attack surface**. Regularly audit which ports are open, which services are listening, and whether they are necessary.
::

::tabs
  :::tabs-item{icon="i-simple-icons-linux" label="Linux Port Audit"}
  ```bash [Linux Port Management]
  # ============================================
  # DISCOVER OPEN PORTS
  # ============================================
  
  # Show all listening ports with process info
  sudo ss -tlnp
  
  # Show all listening ports (TCP + UDP)
  sudo ss -tulnp
  
  # Alternative: netstat
  sudo netstat -tlnp
  sudo netstat -tulnp
  
  # Show which process owns a specific port
  sudo lsof -i :80
  sudo lsof -i :3306
  sudo fuser 80/tcp
  
  # Scan yourself from another machine
  nmap -sV -p- localhost
  
  # ============================================
  # CLOSE UNNECESSARY PORTS
  # ============================================
  
  # Identify and stop unnecessary services
  sudo systemctl list-units --type=service --state=running
  
  # Stop and disable a service
  sudo systemctl stop cups          # Print service (rarely needed on servers)
  sudo systemctl disable cups
  sudo systemctl mask cups          # Prevent re-enabling
  
  # Common services to disable on servers:
  sudo systemctl disable --now avahi-daemon     # mDNS (Bonjour)
  sudo systemctl disable --now cups             # Printing
  sudo systemctl disable --now bluetooth        # Bluetooth
  sudo systemctl disable --now ModemManager     # Modem
  sudo systemctl disable --now whoopsie         # Error reporting
  sudo systemctl disable --now apport           # Crash reporting
  
  # ============================================
  # BIND SERVICES TO SPECIFIC INTERFACES
  # ============================================
  
  # MySQL — bind to localhost only
  # /etc/mysql/mysql.conf.d/mysqld.cnf
  # bind-address = 127.0.0.1
  sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf
  sudo systemctl restart mysql
  
  # PostgreSQL — bind to localhost only
  # /etc/postgresql/*/main/postgresql.conf
  # listen_addresses = 'localhost'
  sudo sed -i "s/^#listen_addresses.*/listen_addresses = 'localhost'/" /etc/postgresql/*/main/postgresql.conf
  sudo systemctl restart postgresql
  
  # Redis — bind to localhost only
  # /etc/redis/redis.conf
  # bind 127.0.0.1 ::1
  sudo sed -i 's/^bind.*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf
  sudo systemctl restart redis
  
  # ============================================
  # PORT AUDIT SCRIPT
  # ============================================
  echo "=== Open Ports Audit ==="
  echo ""
  echo "--- TCP Listening ---"
  ss -tlnp | awk 'NR>1 {print $4, $6}' | column -t
  echo ""
  echo "--- UDP Listening ---"
  ss -ulnp | awk 'NR>1 {print $4, $6}' | column -t
  echo ""
  echo "--- Ports accessible externally ---"
  ss -tlnp | grep -v '127.0.0.1' | grep -v '::1' | awk 'NR>1 {print $4, $6}'
  ```
  :::

  :::tabs-item{icon="i-simple-icons-windows" label="Windows Port Audit"}
  ```powershell [Windows Port Management]
  # ============================================
  # DISCOVER OPEN PORTS
  # ============================================
  
  # Show all listening ports with process
  Get-NetTCPConnection -State Listen | 
    Select-Object LocalAddress, LocalPort, OwningProcess, 
    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |
    Sort-Object LocalPort |
    Format-Table -AutoSize
  
  # Show UDP listeners
  Get-NetUDPEndpoint |
    Select-Object LocalAddress, LocalPort, OwningProcess,
    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |
    Format-Table -AutoSize
  
  # Quick view with netstat
  netstat -ano | findstr LISTENING
  
  # Find process using specific port
  netstat -ano | findstr ":445"
  Get-Process -Id (Get-NetTCPConnection -LocalPort 445).OwningProcess
  
  # ============================================
  # DISABLE UNNECESSARY SERVICES
  # ============================================
  
  # List running services
  Get-Service | Where-Object {$_.Status -eq 'Running'} | Sort-Object DisplayName
  
  # Disable unnecessary services
  # Remote Registry (information disclosure)
  Stop-Service RemoteRegistry -Force
  Set-Service RemoteRegistry -StartupType Disabled
  
  # Windows Remote Management (if not needed)
  Stop-Service WinRM -Force
  Set-Service WinRM -StartupType Disabled
  
  # Print Spooler (PrintNightmare prevention)
  Stop-Service Spooler -Force
  Set-Service Spooler -StartupType Disabled
  
  # SNMP (if not needed)
  Stop-Service SNMP -Force -ErrorAction SilentlyContinue
  Set-Service SNMP -StartupType Disabled -ErrorAction SilentlyContinue
  
  # Xbox services (on servers)
  Get-Service Xbox* | Stop-Service -Force
  Get-Service Xbox* | Set-Service -StartupType Disabled
  
  # ============================================
  # PORT AUDIT REPORT
  # ============================================
  
  Write-Host "=== Windows Port Audit Report ===" -ForegroundColor Green
  Write-Host ""
  Write-Host "--- Externally Accessible Ports ---" -ForegroundColor Yellow
  Get-NetTCPConnection -State Listen |
    Where-Object { $_.LocalAddress -ne '127.0.0.1' -and $_.LocalAddress -ne '::1' } |
    Select-Object LocalAddress, LocalPort,
    @{Name='Process';Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |
    Sort-Object LocalPort | Format-Table -AutoSize
  ```
  :::
::

### Dangerous Ports Reference

| Port | Service | Risk | Recommendation |
| --- | --- | --- | --- |
| `21` | FTP | `Critical` | Disable or replace with SFTP |
| `22` | SSH | `Medium` | Restrict source IPs, use keys |
| `23` | Telnet | `Critical` | Disable completely, use SSH |
| `25` | SMTP | `High` | Restrict to mail servers only |
| `53` | DNS | `Medium` | Restrict to DNS servers only |
| `80` | HTTP | `Medium` | Redirect to HTTPS |
| `110` | POP3 | `High` | Use POP3S (995) instead |
| `135` | RPC | `Critical` | Block externally |
| `137-139` | NetBIOS | `Critical` | Block externally, disable |
| `143` | IMAP | `High` | Use IMAPS (993) instead |
| `161` | SNMP | `High` | Use SNMPv3 or disable |
| `389` | LDAP | `High` | Use LDAPS (636) |
| `445` | SMB | `Critical` | Block externally, patch |
| `1433` | MSSQL | `Critical` | Never expose publicly |
| `3306` | MySQL | `Critical` | Bind to localhost |
| `3389` | RDP | `Critical` | Restrict IPs, use VPN |
| `5432` | PostgreSQL | `Critical` | Bind to localhost |
| `5900` | VNC | `Critical` | Use SSH tunnel only |
| `6379` | Redis | `Critical` | Bind to localhost, auth |
| `8080` | HTTP-Alt | `Medium` | Treat as HTTP |
| `27017` | MongoDB | `Critical` | Bind to localhost, auth |

---

## Layer 3 — User & Access Control

### Linux User Hardening

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [Linux User & Access Control]
# ============================================
# SSH HARDENING (/etc/ssh/sshd_config)
# ============================================

# Backup original config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Apply hardened settings
sudo tee /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
# Disable root login
PermitRootLogin no

# Disable password authentication (use keys only)
PasswordAuthentication no
ChallengeResponseAuthentication no

# Use only SSH Protocol 2
Protocol 2

# Restrict to specific users/groups
AllowUsers admin deploy
# AllowGroups ssh-users

# Change default port (security through obscurity — optional)
# Port 2222

# Limit authentication attempts
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30

# Disable empty passwords
PermitEmptyPasswords no

# Disable X11 forwarding
X11Forwarding no

# Disable agent/TCP forwarding (unless needed)
AllowAgentForwarding no
AllowTcpForwarding no

# Set idle timeout (5 minutes)
ClientAliveInterval 300
ClientAliveCountMax 0

# Use strong ciphers only
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org

# Logging
LogLevel VERBOSE

# Banner
Banner /etc/ssh/banner
EOF

# Create login banner
sudo tee /etc/ssh/banner << 'EOF'
╔══════════════════════════════════════════════════════╗
║  AUTHORIZED ACCESS ONLY                              ║
║  All activity is monitored and logged.               ║
║  Unauthorized access will be prosecuted.             ║
╚══════════════════════════════════════════════════════╝
EOF

# Restart SSH
sudo systemctl restart sshd

# Test BEFORE closing your current session!
# Open a NEW terminal and test SSH login
```

#code
```bash
# Key settings to change
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
ClientAliveInterval 300
```
::

### Password Policy & PAM

::collapsible
**Linux Password Policy Configuration**

```bash [Password Policy & PAM Hardening]
# ============================================
# PASSWORD AGING (/etc/login.defs)
# ============================================
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# Apply to existing users
sudo chage -M 90 -m 7 -W 14 username

# ============================================
# PAM PASSWORD COMPLEXITY
# ============================================
sudo apt install -y libpam-pwquality

# /etc/security/pwquality.conf
sudo tee /etc/security/pwquality.conf << 'EOF'
# Minimum password length
minlen = 14

# Require at least 1 digit
dcredit = -1

# Require at least 1 uppercase
ucredit = -1

# Require at least 1 lowercase
lcredit = -1

# Require at least 1 special character
ocredit = -1

# Maximum consecutive identical characters
maxrepeat = 3

# Maximum consecutive characters from same class
maxclassrepeat = 4

# Reject passwords containing username
usercheck = 1

# Enforce root password policy too
enforce_for_root

# Remember last N passwords
remember = 12

# Minimum different characters from old password
difok = 4
EOF

# ============================================
# ACCOUNT LOCKOUT (/etc/pam.d/common-auth)
# ============================================

# Add to /etc/pam.d/common-auth (before pam_unix.so)
# auth required pam_faillock.so preauth deny=5 unlock_time=900 audit
# auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900 audit

# /etc/security/faillock.conf
sudo tee /etc/security/faillock.conf << 'EOF'
# Lock account after 5 failed attempts
deny = 5

# Unlock after 15 minutes (900 seconds)
unlock_time = 900

# Reset failure counter after 15 minutes
fail_interval = 900

# Log failures
audit

# Root is also subject to lockout
even_deny_root
root_unlock_time = 900
EOF

# ============================================
# RESTRICT su TO WHEEL GROUP
# ============================================
# /etc/pam.d/su
# auth required pam_wheel.so use_uid
sudo sed -i 's/^#.*pam_wheel.so/auth required pam_wheel.so/' /etc/pam.d/su

# Add user to wheel group
sudo usermod -aG sudo username

# ============================================
# UMASK (default file permissions)
# ============================================
# Set restrictive default: files 640, dirs 750
echo "umask 027" | sudo tee -a /etc/profile.d/umask.sh
```
::

### Sudo Hardening

```bash [Sudo Security Configuration]
# ============================================
# SUDO HARDENING (/etc/sudoers.d/hardening)
# ============================================
sudo visudo -f /etc/sudoers.d/hardening

# Content:
# ============================================

# Require password for sudo (no NOPASSWD in production)
Defaults    env_reset
Defaults    mail_badpass
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Log all sudo commands
Defaults    logfile="/var/log/sudo.log"
Defaults    log_input, log_output
Defaults    iolog_dir="/var/log/sudo-io/%{user}"

# Timeout — require re-authentication after 5 minutes
Defaults    timestamp_timeout=5

# Require tty (prevent automated sudo abuse)
Defaults    requiretty

# Restrict sudo to specific commands (principle of least privilege)
# Instead of: user ALL=(ALL:ALL) ALL
# Use: user ALL=(ALL:ALL) /usr/bin/systemctl restart nginx, /usr/bin/journalctl

# ============================================
# AUDIT SUDO USAGE
# ============================================
# View sudo log
sudo cat /var/log/sudo.log

# View recent sudo usage
sudo journalctl _COMM=sudo --since "1 hour ago"
```

---

## Layer 4 — File System & Path Security

::warning
Incorrect file permissions are one of the **most common privilege escalation vectors**. An attacker with low-level access can exploit writable scripts, SUID binaries, or world-readable credentials to escalate to root.
::

### Critical Path Permissions

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [Linux File System Hardening]
# ============================================
# CRITICAL FILE PERMISSIONS
# ============================================

# System configuration files
sudo chmod 644 /etc/passwd             # World-readable (needed)
sudo chmod 640 /etc/shadow             # Root and shadow group only
sudo chmod 644 /etc/group              # World-readable (needed)
sudo chmod 640 /etc/gshadow            # Root and shadow group only
sudo chmod 600 /etc/sudoers            # Root only
sudo chmod 700 /etc/sudoers.d          # Root only
sudo chmod 600 /etc/ssh/sshd_config    # Root only
sudo chmod 600 /etc/crontab            # Root only
sudo chmod 700 /etc/cron.d             # Root only
sudo chmod 700 /etc/cron.daily         # Root only
sudo chmod 700 /etc/cron.hourly        # Root only
sudo chmod 700 /etc/cron.weekly        # Root only
sudo chmod 700 /etc/cron.monthly       # Root only

# SSH keys
sudo chmod 700 ~/.ssh                  # Owner only
sudo chmod 600 ~/.ssh/id_rsa           # Private key — owner only
sudo chmod 644 ~/.ssh/id_rsa.pub       # Public key — readable
sudo chmod 600 ~/.ssh/authorized_keys  # Owner only
sudo chmod 644 ~/.ssh/known_hosts      # Readable

# Log files
sudo chmod 640 /var/log/auth.log
sudo chmod 640 /var/log/syslog
sudo chmod 640 /var/log/kern.log

# ============================================
# OWNERSHIP
# ============================================
sudo chown root:root /etc/passwd
sudo chown root:shadow /etc/shadow
sudo chown root:root /etc/group
sudo chown root:shadow /etc/gshadow
sudo chown root:root /etc/ssh/sshd_config
sudo chown root:root /etc/crontab
```

#code
```bash
# Quick audit of critical file permissions
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/ssh/sshd_config
```
::

### SUID/SGID/Sticky Bit Audit

::caution
**SUID binaries** run with the file owner's privileges (usually root). Attackers abuse misconfigured SUID binaries for privilege escalation. Audit and minimize these regularly.
::

```bash [SUID SGID Audit & Hardening]
# ============================================
# FIND ALL SUID BINARIES
# ============================================
sudo find / -perm -u=s -type f 2>/dev/null | sort

# ============================================
# FIND ALL SGID BINARIES
# ============================================
sudo find / -perm -g=s -type f 2>/dev/null | sort

# ============================================
# COMPARE AGAINST KNOWN-GOOD LIST
# ============================================

# Generate baseline (do this on a clean system)
sudo find / -perm -u=s -type f 2>/dev/null | sort > /root/suid_baseline.txt

# Compare later
sudo find / -perm -u=s -type f 2>/dev/null | sort > /tmp/suid_current.txt
diff /root/suid_baseline.txt /tmp/suid_current.txt

# ============================================
# REMOVE UNNECESSARY SUID BITS
# ============================================

# Common SUID binaries that are often unnecessary:
sudo chmod u-s /usr/bin/mount        # If users don't need to mount
sudo chmod u-s /usr/bin/umount       # If users don't need to unmount
sudo chmod u-s /usr/bin/chfn         # Change finger info
sudo chmod u-s /usr/bin/chsh         # Change shell
sudo chmod u-s /usr/bin/newgrp       # Change group
sudo chmod u-s /usr/bin/pkexec       # PolicyKit (PwnKit CVE-2021-4034)

# KEEP these SUID (usually required):
# /usr/bin/sudo
# /usr/bin/passwd
# /usr/bin/su
# /usr/lib/openssh/ssh-keysign

# ============================================
# FIND WORLD-WRITABLE FILES (DANGEROUS!)
# ============================================
sudo find / -xdev -type f -perm -o+w 2>/dev/null | grep -v '/proc\|/sys\|/dev'

# ============================================
# FIND WORLD-WRITABLE DIRECTORIES (without sticky bit)
# ============================================
sudo find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null

# ============================================
# FIND FILES WITHOUT OWNER
# ============================================
sudo find / -xdev -nouser -o -nogroup 2>/dev/null
```

### Mount Options Hardening

::tabs
  :::tabs-item{icon="i-lucide-hard-drive" label="/etc/fstab Hardening"}
  ```bash [/etc/fstab Security Mount Options]
  # ============================================
  # MOUNT OPTION DEFINITIONS
  # ============================================
  # noexec  — Prevent execution of binaries
  # nosuid  — Ignore SUID/SGID bits
  # nodev   — Ignore device files
  # ro      — Mount read-only
  # hidepid — Hide process info from other users
  
  # ============================================
  # HARDENED /etc/fstab EXAMPLE
  # ============================================
  
  # Root filesystem (minimal restrictions needed)
  # UUID=xxx  /          ext4    defaults,errors=remount-ro    0 1
  
  # /tmp — No execution, no SUID, no devices
  # tmpfs     /tmp       tmpfs   defaults,noexec,nosuid,nodev,size=2G  0 0
  
  # /var/tmp — Same as /tmp
  # tmpfs     /var/tmp   tmpfs   defaults,noexec,nosuid,nodev,size=1G  0 0
  
  # /home — No SUID, no devices
  # UUID=xxx  /home      ext4    defaults,nosuid,nodev         0 2
  
  # /var — No SUID (if separate partition)
  # UUID=xxx  /var       ext4    defaults,nosuid               0 2
  
  # /var/log — No execution, no SUID, no devices
  # UUID=xxx  /var/log   ext4    defaults,noexec,nosuid,nodev  0 2
  
  # /boot — Read-only (mount rw only for kernel updates)
  # UUID=xxx  /boot      ext4    defaults,nosuid,nodev,noexec  0 2
  
  # Shared memory — Restrict
  # none      /dev/shm   tmpfs   defaults,noexec,nosuid,nodev  0 0
  
  # /proc — Hide process info from other users
  # proc      /proc      proc    defaults,hidepid=2            0 0
  
  # ============================================
  # APPLY TEMPORARY MOUNT OPTIONS (without reboot)
  # ============================================
  sudo mount -o remount,noexec,nosuid,nodev /tmp
  sudo mount -o remount,noexec,nosuid,nodev /dev/shm
  sudo mount -o remount,hidepid=2 /proc
  
  # Verify
  mount | grep -E '/tmp|/dev/shm|/proc'
  ```
  :::

  :::tabs-item{icon="i-simple-icons-windows" label="Windows NTFS Security"}
  ```powershell [Windows File System Hardening]
  # ============================================
  # AUDIT CRITICAL FOLDER PERMISSIONS
  # ============================================
  
  # Check permissions on Windows directory
  icacls "C:\Windows"
  icacls "C:\Windows\System32"
  
  # Check permissions on program files
  icacls "C:\Program Files"
  icacls "C:\Program Files (x86)"
  
  # ============================================
  # REMOVE EXCESSIVE PERMISSIONS
  # ============================================
  
  # Remove "Everyone" from sensitive directories
  icacls "C:\SensitiveData" /remove "Everyone"
  
  # Set restrictive permissions on a directory
  icacls "C:\SecureFolder" /inheritance:r
  icacls "C:\SecureFolder" /grant "BUILTIN\Administrators:(OI)(CI)F"
  icacls "C:\SecureFolder" /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F"
  
  # ============================================
  # FIND WEAK PERMISSIONS (PrivEsc vectors)
  # ============================================
  
  # Find writable service directories
  Get-WmiObject Win32_Service | ForEach-Object {
      $path = $_.PathName -replace '"','' -replace ' \/.*','' -replace ' \-.*',''
      if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
          $acl = Get-Acl $path -ErrorAction SilentlyContinue
          if ($acl) {
              $acl.Access | Where-Object {
                  $_.IdentityReference -match "Users|Everyone|Authenticated" -and
                  $_.FileSystemRights -match "Write|FullControl|Modify"
              } | ForEach-Object {
                  Write-Host "[VULN] $path - $($_.IdentityReference): $($_.FileSystemRights)" -ForegroundColor Red
              }
          }
      }
  }
  
  # ============================================
  # ENABLE FILE AUDITING
  # ============================================
  
  # Audit access to sensitive files
  $acl = Get-Acl "C:\Windows\System32\config\SAM"
  $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
      "Everyone",
      "ReadData,WriteData,Delete",
      "None",
      "None",
      "Success,Failure"
  )
  $acl.AddAuditRule($auditRule)
  Set-Acl "C:\Windows\System32\config\SAM" $acl
  ```
  :::
::

---

## Layer 5 — Service & Process Hardening

### Disable Unnecessary Services

::tabs
  :::tabs-item{icon="i-simple-icons-linux" label="Linux Services"}
  ```bash [Linux Service Hardening]
  # ============================================
  # LIST ALL RUNNING SERVICES
  # ============================================
  systemctl list-units --type=service --state=running
  
  # ============================================
  # SERVICES TO DISABLE ON SERVERS
  # ============================================
  
  # Desktop/GUI services (if server)
  sudo systemctl disable --now gdm
  sudo systemctl disable --now lightdm
  
  # Network discovery
  sudo systemctl disable --now avahi-daemon
  sudo systemctl disable --now cups-browsed
  
  # Print services
  sudo systemctl disable --now cups
  
  # Bluetooth
  sudo systemctl disable --now bluetooth
  
  # Modem
  sudo systemctl disable --now ModemManager
  
  # Error/crash reporting
  sudo systemctl disable --now whoopsie
  sudo systemctl disable --now apport
  
  # NFS (if not used)
  sudo systemctl disable --now nfs-server
  sudo systemctl disable --now rpcbind
  
  # Telnet (NEVER use on production)
  sudo systemctl disable --now telnet
  sudo apt remove --purge telnetd
  
  # FTP (replace with SFTP)
  sudo systemctl disable --now vsftpd
  sudo systemctl disable --now proftpd
  
  # SNMP (if not needed)
  sudo systemctl disable --now snmpd
  
  # ============================================
  # MASK SERVICES (prevent re-enabling)
  # ============================================
  sudo systemctl mask telnet
  sudo systemctl mask avahi-daemon
  sudo systemctl mask cups
  
  # ============================================
  # REMOVE UNNECESSARY PACKAGES
  # ============================================
  sudo apt remove --purge telnetd rsh-server rsh-client xinetd tftp-hpa
  sudo apt autoremove
  ```
  :::

  :::tabs-item{icon="i-simple-icons-windows" label="Windows Services"}
  ```powershell [Windows Service Hardening]
  # ============================================
  # SERVICES TO DISABLE ON SERVERS
  # ============================================
  
  $servicesToDisable = @(
      'RemoteRegistry',       # Remote Registry (information disclosure)
      'Spooler',              # Print Spooler (PrintNightmare)
      'lfsvc',                # Geolocation
      'MapsBroker',           # Downloaded Maps Manager
      'SharedAccess',         # Internet Connection Sharing
      'lltdsvc',              # Link-Layer Topology Discovery Mapper
      'wlidsvc',              # Microsoft Account Sign-in Assistant
      'NgcSvc',               # Microsoft Passport
      'WSearch',              # Windows Search (if not needed)
      'XblAuthManager',       # Xbox Auth
      'XblGameSave',          # Xbox Game Save
      'XboxNetApiSvc',        # Xbox Net API
      'DiagTrack',            # Connected User Experiences and Telemetry
      'dmwappushservice',     # WAP Push Message Service
      'RetailDemo',           # Retail Demo Service
      'WMPNetworkSvc',        # Windows Media Player Network
      'icssvc',               # Windows Mobile Hotspot
      'WpcMonSvc',            # Parental Controls
      'PhoneSvc',             # Phone Service
      'Fax'                   # Fax Service
  )
  
  foreach ($svc in $servicesToDisable) {
      $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
      if ($service) {
          Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
          Set-Service -Name $svc -StartupType Disabled
          Write-Host "[✓] Disabled: $svc ($($service.DisplayName))" -ForegroundColor Green
      }
  }
  
  # ============================================
  # VERIFY NO UNNECESSARY SERVICES ON PORTS
  # ============================================
  Get-Service | Where-Object {$_.Status -eq 'Running'} |
      Sort-Object DisplayName |
      Format-Table Name, DisplayName, Status -AutoSize
  ```
  :::
::

### Process & Execution Control

::accordion
  :::accordion-item{icon="i-simple-icons-linux" label="Linux Process Hardening"}
  ```bash [Linux Process Security]
  # ============================================
  # APPARMOR (Mandatory Access Control)
  # ============================================
  
  # Check AppArmor status
  sudo aa-status
  
  # Enable AppArmor
  sudo systemctl enable apparmor
  sudo systemctl start apparmor
  
  # Set profiles to enforce mode
  sudo aa-enforce /etc/apparmor.d/*
  
  # ============================================
  # RESTRICT CRON ACCESS
  # ============================================
  
  # Only allow specific users to use cron
  sudo touch /etc/cron.allow
  sudo echo "root" > /etc/cron.allow
  sudo echo "admin" >> /etc/cron.allow
  
  # Remove cron.deny (cron.allow takes precedence)
  sudo rm -f /etc/cron.deny
  
  # Same for at
  sudo touch /etc/at.allow
  sudo echo "root" > /etc/at.allow
  sudo rm -f /etc/at.deny
  
  # ============================================
  # RESTRICT COMPILER ACCESS
  # ============================================
  
  # Remove compilers from production servers
  sudo apt remove --purge gcc g++ make
  
  # Or restrict access
  sudo chmod 750 /usr/bin/gcc
  sudo chmod 750 /usr/bin/g++
  sudo chmod 750 /usr/bin/make
  
  # ============================================
  # RESTRICT SCRIPT INTERPRETERS
  # ============================================
  
  # Limit who can run Python/Perl/Ruby
  sudo chmod 750 /usr/bin/python3
  sudo chmod 750 /usr/bin/perl
  sudo chmod 750 /usr/bin/ruby
  
  # ============================================
  # PROCESS NAMESPACE ISOLATION
  # ============================================
  
  # Hide other users' processes
  # Mount /proc with hidepid=2
  echo "proc /proc proc defaults,hidepid=2 0 0" | sudo tee -a /etc/fstab
  sudo mount -o remount,hidepid=2 /proc
  
  # Verify (non-root users can only see their own processes)
  sudo -u nobody ps aux  # Should show only their processes
  ```
  :::

  :::accordion-item{icon="i-simple-icons-windows" label="Windows Application Control"}
  ```powershell [Windows Application Whitelisting]
  # ============================================
  # WINDOWS DEFENDER APPLICATION CONTROL (WDAC)
  # ============================================
  
  # Create a base policy (allow Microsoft-signed only)
  New-CIPolicy -Level Publisher -Fallback Hash `
      -FilePath "C:\Policies\BasePolicy.xml" `
      -UserPEs
  
  # Convert to binary
  ConvertFrom-CIPolicy -XmlFilePath "C:\Policies\BasePolicy.xml" `
      -BinaryFilePath "C:\Policies\BasePolicy.p7b"
  
  # ============================================
  # APPLOCKER (Alternative to WDAC)
  # ============================================
  
  # Enable AppLocker service
  Set-Service -Name AppIDSvc -StartupType Automatic
  Start-Service AppIDSvc
  
  # Create default rules (via GPO or PowerShell)
  # Computer Configuration → Windows Settings → Security Settings
  # → Application Control Policies → AppLocker
  
  # Block executables from user-writable locations
  # Block: %USERPROFILE%\*
  # Block: %APPDATA%\*
  # Block: %LOCALAPPDATA%\*
  # Block: %TEMP%\*
  
  # ============================================
  # ATTACK SURFACE REDUCTION (ASR) RULES
  # ============================================
  
  # Enable ASR rules (Windows 10/11 with Defender)
  
  # Block executable content from email and webmail
  Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
  
  # Block all Office applications from creating child processes
  Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
  
  # Block Office applications from injecting code
  Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
  
  # Block JavaScript or VBScript from launching downloaded content
  Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
  
  # Block execution of potentially obfuscated scripts
  Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
  
  # Block credential stealing from LSASS
  Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
  
  # Block process creations from PSExec and WMI
  Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
  ```
  :::
::

---

## Layer 6 — Logging, Monitoring & Auditing

::tip
**You can't protect what you can't see.** Comprehensive logging and monitoring enables detection of breaches, forensic investigation, and compliance evidence.
::

### Linux Logging Configuration

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash [Linux Logging & Auditing]
# ============================================
# AUDITD — Linux Audit Framework
# ============================================

# Install auditd
sudo apt install -y auditd audispd-plugins

# Enable and start
sudo systemctl enable auditd
sudo systemctl start auditd

# ============================================
# AUDIT RULES (/etc/audit/rules.d/hardening.rules)
# ============================================
sudo tee /etc/audit/rules.d/hardening.rules << 'EOF'
# Delete all existing rules
-D

# Set buffer size
-b 8192

# Failure mode (1=printk, 2=panic)
-f 1

# ============================================
# FILE INTEGRITY MONITORING
# ============================================

# Monitor passwd/shadow changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/ -p wa -k ssh_keys

# Monitor cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Monitor network configuration
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/resolv.conf -p wa -k dns

# ============================================
# PRIVILEGE ESCALATION MONITORING
# ============================================

# Monitor su/sudo usage
-w /usr/bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/pkexec -p x -k privilege_escalation

# Monitor setuid/setgid calls
-a always,exit -F arch=b64 -S setuid -S setgid -k privilege_escalation
-a always,exit -F arch=b64 -S setreuid -S setregid -k privilege_escalation

# ============================================
# PROCESS & EXECUTION MONITORING
# ============================================

# Monitor process execution
-a always,exit -F arch=b64 -S execve -k exec

# Monitor module loading
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules

# Monitor failed access attempts
-a always,exit -F arch=b64 -S open -S creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open -S creat -F exit=-EPERM -k access_denied

# ============================================
# USER SESSION MONITORING
# ============================================

# Monitor login/logout
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Monitor user/group management
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k hostname

# ============================================
# MAKE RULES IMMUTABLE (requires reboot to change)
# ============================================
-e 2
EOF

# Restart auditd to apply rules
sudo systemctl restart auditd

# Verify rules loaded
sudo auditctl -l
```

#code
```bash
# Quick audit check
sudo auditctl -l | wc -l   # Count active rules
sudo ausearch -k identity   # Search identity-related events
```
::

### Centralized Log Management

::collapsible
**rsyslog Centralized Logging Configuration**

```bash [Centralized Logging Setup]
# ============================================
# LOG ROTATION (/etc/logrotate.d/custom)
# ============================================
sudo tee /etc/logrotate.d/security-logs << 'EOF'
/var/log/auth.log
/var/log/sudo.log
/var/log/ufw.log
{
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF

# ============================================
# REMOTE SYSLOG (send logs to central server)
# ============================================

# /etc/rsyslog.d/50-remote.conf
sudo tee /etc/rsyslog.d/50-remote.conf << 'EOF'
# Send all auth logs to central syslog server
auth,authpriv.*    @@syslog.company.com:514

# Send all logs (use with caution — high volume)
# *.*    @@syslog.company.com:514

# Send with TLS encryption
# $DefaultNetstreamDriverCAFile /etc/ssl/certs/ca.pem
# $ActionSendStreamDriver gtls
# $ActionSendStreamDriverMode 1
# $ActionSendStreamDriverAuthMode anon
# *.* @@syslog.company.com:6514
EOF

sudo systemctl restart rsyslog

# ============================================
# LOG INTEGRITY — Protect logs from tampering
# ============================================

# Make log files append-only
sudo chattr +a /var/log/auth.log
sudo chattr +a /var/log/syslog
sudo chattr +a /var/log/sudo.log

# Verify
lsattr /var/log/auth.log
# Should show: -----a--------e--- /var/log/auth.log

# Send logs to remote server for tamper-proof storage
# Use ELK Stack, Graylog, or Splunk
```
::

### Windows Event Logging

::collapsible
**Windows Advanced Logging Configuration**

```powershell [Windows Event Logging Hardening]
# ============================================
# ENABLE ADVANCED AUDIT POLICIES
# ============================================

# Logon Events
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable

# Object Access
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable

# Process Tracking (critical for detecting attacks)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable

# ============================================
# ENABLE COMMAND LINE AUDITING (critical!)
# ============================================
# Shows FULL command lines in Event ID 4688
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

# ============================================
# INCREASE LOG SIZES
# ============================================
wevtutil sl Security /ms:1073741824      # 1 GB
wevtutil sl System /ms:268435456         # 256 MB
wevtutil sl Application /ms:268435456    # 256 MB
wevtutil sl "Windows PowerShell" /ms:268435456

# ============================================
# ENABLE SYSMON (Advanced Process Monitoring)
# ============================================
# Download: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
# Config: https://github.com/SwiftOnSecurity/sysmon-config

# Install Sysmon with SwiftOnSecurity config
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml

# ============================================
# KEY EVENT IDS TO MONITOR
# ============================================
# 4624  - Successful Logon
# 4625  - Failed Logon
# 4634  - Logoff
# 4648  - Logon with Explicit Credentials (RunAs)
# 4672  - Special Privileges Assigned (Admin logon)
# 4688  - Process Creation (with command line)
# 4698  - Scheduled Task Created
# 4720  - User Account Created
# 4722  - User Account Enabled
# 4724  - Password Reset Attempt
# 4728  - Member Added to Security Group
# 4732  - Member Added to Local Admins
# 4768  - Kerberos TGT Requested
# 4769  - Kerberos Service Ticket Requested
# 4776  - NTLM Authentication
# 7045  - New Service Installed
```
::

---

## Layer 7 — Patch Management & Updates

::warning
**Unpatched systems are the #1 attack vector.** A fully hardened system with missing patches is still vulnerable. Automate updates wherever possible.
::

### Linux Patch Management

::tabs
  :::tabs-item{icon="i-simple-icons-ubuntu" label="Ubuntu/Debian"}
  ```bash [Ubuntu Patch Management]
  # ============================================
  # AUTOMATIC SECURITY UPDATES
  # ============================================
  
  # Install unattended-upgrades
  sudo apt install -y unattended-upgrades apt-listchanges
  
  # Enable automatic security updates
  sudo dpkg-reconfigure -plow unattended-upgrades
  
  # Configure: /etc/apt/apt.conf.d/50unattended-upgrades
  sudo tee /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
  Unattended-Upgrade::Allowed-Origins {
      "${distro_id}:${distro_codename}";
      "${distro_id}:${distro_codename}-security";
      "${distro_id}ESMApps:${distro_codename}-apps-security";
      "${distro_id}ESM:${distro_codename}-infra-security";
  };
  
  // Auto-reboot if required (set time to minimize impact)
  Unattended-Upgrade::Automatic-Reboot "true";
  Unattended-Upgrade::Automatic-Reboot-Time "03:00";
  
  // Remove unused dependencies
  Unattended-Upgrade::Remove-Unused-Dependencies "true";
  
  // Email notification
  Unattended-Upgrade::Mail "admin@company.com";
  Unattended-Upgrade::MailReport "on-change";
  
  // Log
  Unattended-Upgrade::SyslogEnable "true";
  EOF
  
  # Configure update schedule: /etc/apt/apt.conf.d/20auto-upgrades
  sudo tee /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
  APT::Periodic::Update-Package-Lists "1";
  APT::Periodic::Download-Upgradeable-Packages "1";
  APT::Periodic::AutocleanInterval "7";
  APT::Periodic::Unattended-Upgrade "1";
  EOF
  
  # ============================================
  # MANUAL UPDATE COMMANDS
  # ============================================
  
  # Update package lists
  sudo apt update
  
  # Security updates only
  sudo unattended-upgrade --dry-run    # Preview
  sudo unattended-upgrade              # Apply
  
  # Full system upgrade
  sudo apt upgrade -y
  
  # Distribution upgrade
  sudo apt full-upgrade -y
  
  # Check for available updates
  apt list --upgradable
  
  # Check kernel version and available updates
  uname -r
  apt list --installed | grep linux-image
  
  # ============================================
  # VERIFY UPDATES ARE WORKING
  # ============================================
  sudo cat /var/log/unattended-upgrades/unattended-upgrades.log
  ```
  :::

  :::tabs-item{icon="i-simple-icons-redhat" label="RHEL/CentOS"}
  ```bash [RHEL Patch Management]
  # ============================================
  # AUTOMATIC UPDATES (dnf-automatic)
  # ============================================
  
  # Install dnf-automatic
  sudo dnf install -y dnf-automatic
  
  # Configure: /etc/dnf/automatic.conf
  sudo sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
  sudo sed -i 's/^upgrade_type.*/upgrade_type = security/' /etc/dnf/automatic.conf
  
  # Enable timer
  sudo systemctl enable --now dnf-automatic-install.timer
  
  # Verify timer
  sudo systemctl status dnf-automatic-install.timer
  
  # ============================================
  # MANUAL UPDATES
  # ============================================
  
  # Check for security updates
  sudo dnf updateinfo list security
  
  # Apply security updates only
  sudo dnf update --security -y
  
  # Full update
  sudo dnf update -y
  
  # Check installed patches
  sudo dnf history list
  ```
  :::

  :::tabs-item{icon="i-simple-icons-windows" label="Windows Updates"}
  ```powershell [Windows Patch Management]
  # ============================================
  # WINDOWS UPDATE CONFIGURATION
  # ============================================
  
  # Install PSWindowsUpdate module
  Install-Module PSWindowsUpdate -Force
  Import-Module PSWindowsUpdate
  
  # Check for available updates
  Get-WindowsUpdate
  
  # Install all updates
  Install-WindowsUpdate -AcceptAll -AutoReboot
  
  # Install security updates only
  Install-WindowsUpdate -Category "Security Updates" -AcceptAll
  
  # ============================================
  # CONFIGURE AUTOMATIC UPDATES (GPO)
  # ============================================
  
  # Enable auto updates via registry
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4  # Auto download and install
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0  # Every day
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3  # 3 AM
  
  # ============================================
  # VERIFY PATCH STATUS
  # ============================================
  
  # List installed hotfixes
  Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20
  
  # Check last update time
  (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
  
  # Check for missing critical patches
  $UpdateSession = New-Object -ComObject Microsoft.Update.Session
  $Searcher = $UpdateSession.CreateUpdateSearcher()
  $Results = $Searcher.Search("IsInstalled=0 and Type='Software'")
  $Results.Updates | Select-Object Title, MsrcSeverity | Format-Table -AutoSize
  ```
  :::
::

---

## Layer 8 — Encryption & Data Protection

### Disk Encryption

::tabs
  :::tabs-item{icon="i-simple-icons-linux" label="Linux LUKS"}
  ```bash [Linux Full Disk Encryption]
  # ============================================
  # LUKS ENCRYPTION (new partition)
  # ============================================
  
  # Encrypt a partition
  sudo cryptsetup luksFormat /dev/sdb1
  
  # Open encrypted partition
  sudo cryptsetup luksOpen /dev/sdb1 secure_data
  
  # Create filesystem
  sudo mkfs.ext4 /dev/mapper/secure_data
  
  # Mount
  sudo mount /dev/mapper/secure_data /mnt/secure
  
  # ============================================
  # AUTO-MOUNT AT BOOT (/etc/crypttab)
  # ============================================
  # secure_data /dev/sdb1 /etc/keys/disk.key luks
  
  # Generate key file
  sudo dd if=/dev/urandom of=/etc/keys/disk.key bs=4096 count=1
  sudo chmod 400 /etc/keys/disk.key
  sudo cryptsetup luksAddKey /dev/sdb1 /etc/keys/disk.key
  
  # ============================================
  # CHECK ENCRYPTION STATUS
  # ============================================
  sudo cryptsetup status secure_data
  lsblk -f
  ```
  :::

  :::tabs-item{icon="i-simple-icons-windows" label="Windows BitLocker"}
  ```powershell [Windows BitLocker Encryption]
  # ============================================
  # ENABLE BITLOCKER
  # ============================================
  
  # Check BitLocker status
  Get-BitLockerVolume
  
  # Enable BitLocker on C: drive with TPM
  Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -TpmProtector
  
  # Add recovery password
  Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
  
  # Backup recovery key to AD
  Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId (Get-BitLockerVolume -MountPoint "C:").KeyProtector[1].KeyProtectorId
  
  # Enable BitLocker on data drive with password
  Enable-BitLocker -MountPoint "D:" -EncryptionMethod XtsAes256 -PasswordProtector
  
  # Verify encryption status
  manage-bde -status
  
  # ============================================
  # GROUP POLICY FOR BITLOCKER
  # ============================================
  # Computer Configuration → Administrative Templates
  # → Windows Components → BitLocker Drive Encryption
  # - Require AES-256 encryption
  # - Store recovery keys in Active Directory
  # - Require BitLocker on all fixed drives
  ```
  :::
::

### TLS/SSL Configuration

::collapsible
**Web Server TLS Hardening**

```bash [TLS/SSL Hardening]
# ============================================
# NGINX TLS HARDENING
# ============================================
# /etc/nginx/conf.d/ssl-hardening.conf

ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

# HSTS (Strict Transport Security)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;

# Session tickets
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;

# DH parameters (generate: openssl dhparam -out /etc/nginx/dhparam.pem 4096)
ssl_dhparam /etc/nginx/dhparam.pem;

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

# ============================================
# GENERATE STRONG DH PARAMETERS
# ============================================
# openssl dhparam -out /etc/nginx/dhparam.pem 4096

# ============================================
# TEST YOUR TLS CONFIGURATION
# ============================================
# https://www.ssllabs.com/ssltest/
# Target: A+ rating
```
::

---

## Automated Hardening Scripts

### Linux Full Hardening Script

::collapsible
**Complete Linux Hardening Script**

```bash [linux-hardening.sh]
#!/bin/bash
# ============================================
# COMPREHENSIVE LINUX HARDENING SCRIPT
# Target: Ubuntu 22.04 / Debian 12
# Run as root
# ============================================

set -e

LOG="/var/log/hardening.log"
echo "$(date) — Starting system hardening" | tee -a $LOG

# ============================================
# 1. SYSTEM UPDATES
# ============================================
echo "[1/10] Applying system updates..." | tee -a $LOG
apt update && apt upgrade -y
apt install -y unattended-upgrades auditd libpam-pwquality ufw fail2ban

# ============================================
# 2. KERNEL HARDENING
# ============================================
echo "[2/10] Applying kernel hardening..." | tee -a $LOG
cat > /etc/sysctl.d/99-hardening.conf << 'SYSCTL'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 2
kernel.sysrq = 0
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
net.ipv6.conf.all.disable_ipv6 = 1
SYSCTL
sysctl -p /etc/sysctl.d/99-hardening.conf

# ============================================
# 3. FIREWALL
# ============================================
echo "[3/10] Configuring firewall..." | tee -a $LOG
ufw default deny incoming
ufw default allow outgoing
ufw limit 22/tcp
ufw --force enable

# ============================================
# 4. SSH HARDENING
# ============================================
echo "[4/10] Hardening SSH..." | tee -a $LOG
cat > /etc/ssh/sshd_config.d/hardening.conf << 'SSH'
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
MaxSessions 3
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 30
PermitEmptyPasswords no
LogLevel VERBOSE
SSH
systemctl restart sshd

# ============================================
# 5. PASSWORD POLICY
# ============================================
echo "[5/10] Configuring password policy..." | tee -a $LOG
cat > /etc/security/pwquality.conf << 'PWQUAL'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
enforce_for_root
PWQUAL
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs

# ============================================
# 6. FILE PERMISSIONS
# ============================================
echo "[6/10] Fixing file permissions..." | tee -a $LOG
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow
chmod 600 /etc/ssh/sshd_config
chmod 600 /etc/crontab
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
chown root:root /etc/passwd /etc/shadow /etc/group /etc/gshadow

# ============================================
# 7. DISABLE UNNECESSARY SERVICES
# ============================================
echo "[7/10] Disabling unnecessary services..." | tee -a $LOG
for svc in avahi-daemon cups bluetooth ModemManager; do
    systemctl disable --now $svc 2>/dev/null || true
    systemctl mask $svc 2>/dev/null || true
done

# ============================================
# 8. FAIL2BAN (brute-force protection)
# ============================================
echo "[8/10] Configuring Fail2Ban..." | tee -a $LOG
cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 3
bantime = 86400
F2B
systemctl enable --now fail2ban

# ============================================
# 9. AUDITD
# ============================================
echo "[9/10] Configuring audit rules..." | tee -a $LOG
cat > /etc/audit/rules.d/hardening.rules << 'AUDIT'
-D
-b 8192
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /usr/bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /var/log/lastlog -p wa -k logins
-w /var/log/auth.log -p wa -k auth_log
-e 2
AUDIT
systemctl restart auditd

# ============================================
# 10. MOUNT HARDENING
# ============================================
echo "[10/10] Hardening mount options..." | tee -a $LOG
mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null || true
mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null || true
mount -o remount,hidepid=2 /proc 2>/dev/null || true

# ============================================
# FINAL REPORT
# ============================================
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║     SYSTEM HARDENING COMPLETE                ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  [✓] Kernel parameters hardened              ║"
echo "║  [✓] Firewall enabled (UFW)                  ║"
echo "║  [✓] SSH hardened                            ║"
echo "║  [✓] Password policy enforced                ║"
echo "║  [✓] File permissions secured                ║"
echo "║  [✓] Unnecessary services disabled           ║"
echo "║  [✓] Fail2Ban active                         ║"
echo "║  [✓] Audit logging enabled                   ║"
echo "║  [✓] Mount options hardened                  ║"
echo "║  [✓] Automatic updates configured            ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  ⚠  TEST SSH ACCESS BEFORE DISCONNECTING!   ║"
echo "║  ⚠  Review /var/log/hardening.log            ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "$(date) — Hardening complete" | tee -a $LOG
```
::

---

## Security Audit Checklist

::field-group
  ::field{name="OS Updates" type="boolean"}
  All security patches applied, automatic updates enabled, kernel up to date.
  ::

  ::field{name="Kernel Hardening" type="boolean"}
  sysctl parameters applied — ASLR, ptrace restrictions, network hardening, kptr_restrict.
  ::

  ::field{name="Firewall Active" type="boolean"}
  Default deny policy, only required ports open, egress filtering enabled, logging active.
  ::

  ::field{name="SSH Hardened" type="boolean"}
  Root login disabled, key-only authentication, strong ciphers, rate limiting, idle timeout.
  ::

  ::field{name="Password Policy" type="boolean"}
  Minimum 14 characters, complexity requirements, account lockout, password aging.
  ::

  ::field{name="User Access" type="boolean"}
  Principle of least privilege, no shared accounts, sudo restricted, inactive accounts disabled.
  ::

  ::field{name="File Permissions" type="boolean"}
  Critical files secured, no world-writable files, SUID audit complete, mount options hardened.
  ::

  ::field{name="Services Minimized" type="boolean"}
  Unnecessary services disabled/masked, services bound to localhost where possible.
  ::

  ::field{name="Logging Enabled" type="boolean"}
  Auditd active, comprehensive rules, log rotation, centralized logging, log integrity.
  ::

  ::field{name="Encryption" type="boolean"}
  Disk encryption enabled, TLS 1.2+ enforced, strong ciphers, HSTS enabled.
  ::

  ::field{name="Brute-Force Protection" type="boolean"}
  Fail2Ban or equivalent active, account lockout configured, SSH rate limiting.
  ::

  ::field{name="Backup & Recovery" type="boolean"}
  Regular backups tested, recovery procedures documented, snapshots available.
  ::

  ::field{name="Network Segmentation" type="boolean"}
  Database servers isolated, management network separated, VLANs configured.
  ::

  ::field{name="Monitoring & Alerting" type="boolean"}
  Real-time alerts for critical events, anomaly detection, incident response plan.
  ::
::

---

## References & Resources

::card-group
  ::card
  ---
  title: CIS Benchmarks
  icon: i-lucide-shield
  to: https://www.cisecurity.org/cis-benchmarks
  target: _blank
  ---
  Free, consensus-based security configuration guides for 25+ OS families and applications.
  ::

  ::card
  ---
  title: NIST Cybersecurity Framework
  icon: i-lucide-book-open
  to: https://www.nist.gov/cyberframework
  target: _blank
  ---
  Framework for improving critical infrastructure cybersecurity — Identify, Protect, Detect, Respond, Recover.
  ::

  ::card
  ---
  title: Linux Audit Documentation
  icon: i-simple-icons-linux
  to: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/
  target: _blank
  ---
  Red Hat comprehensive security hardening guide applicable to all RHEL-based distributions.
  ::

  ::card
  ---
  title: Microsoft Security Baselines
  icon: i-simple-icons-windows
  to: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines
  target: _blank
  ---
  Microsoft recommended security configuration baselines for Windows OS and services.
  ::

  ::card
  ---
  title: OWASP Server Security
  icon: i-simple-icons-owasp
  to: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
  target: _blank
  ---
  OWASP cheat sheet series covering server-side security best practices.
  ::

  ::card
  ---
  title: Lynis — Security Auditing Tool
  icon: i-simple-icons-github
  to: https://github.com/CISOfy/lynis
  target: _blank
  ---
  Open-source security auditing tool for Linux, macOS, and Unix — automated hardening assessment.
  ::
::

::tip
**Run automated auditing tools regularly:**
```bash
# Lynis — comprehensive security audit
sudo apt install lynis
sudo lynis audit system

# OpenSCAP — compliance checking
sudo apt install libopenscap8
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_level1_server /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
```
::

::warning
**Important Notes:**
- Always **test changes in a staging environment** before applying to production
- **Keep a backup SSH session open** when modifying SSH or firewall settings
- **Document all changes** with dates, reasons, and responsible personnel
- **Review and update** hardening configurations quarterly
- Some settings may break application functionality — test thoroughly
::