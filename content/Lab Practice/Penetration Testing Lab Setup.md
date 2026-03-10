---
title: Penetration Testing Lab Setup
description: Complete guide to building your own pentesting lab — hardware, hypervisors, network architecture, vulnerable machines, Active Directory, cloud labs, diagrams, and tools.
navigation:
  icon: i-lucide-server
---

## Why Build a Lab?

::card
---
icon: i-lucide-info
title: The Pentesting Lab
---
A **penetration testing lab** is your personal **safe, legal, isolated environment** to practice hacking techniques, test exploits, learn tools, prepare for certifications (OSCP, CEH, PNPT, eJPT), and develop your skills — without touching real-world systems. **Every professional pentester and bug bounty hunter has a lab.** It's not optional — it's **foundational**. You break things here so you don't break things in production.
::

::callout
---
icon: i-lucide-lightbulb
color: primary
---
**"You can't become a surgeon by reading books. You need a cadaver lab."** — The same applies to hacking. You need a **safe environment** to cut, break, and learn. Your pentesting lab is that environment.
::

### What You'll Learn in a Lab

::card-group
  ::card
  ---
  icon: i-lucide-scan
  title: "Reconnaissance & Scanning"
  ---
  Practice Nmap, Masscan, Recon-ng, subdomain enumeration, and service fingerprinting against real targets you control.
  ::

  ::card
  ---
  icon: i-lucide-syringe
  title: "Exploitation Techniques"
  ---
  Test Metasploit modules, manual exploits, buffer overflows, web application attacks, and privilege escalation — safely.
  ::

  ::card
  ---
  icon: i-lucide-network
  title: "Network Attacks"
  ---
  Practice ARP spoofing, MITM, VLAN hopping, DNS poisoning, and pivoting across network segments.
  ::

  ::card
  ---
  icon: i-lucide-shield
  title: "Active Directory Attacks"
  ---
  Build a full AD environment to practice Kerberoasting, Pass-the-Hash, DCSync, Golden Tickets, BloodHound, and domain escalation.
  ::

  ::card
  ---
  icon: i-lucide-globe
  title: "Web Application Hacking"
  ---
  Deploy DVWA, bWAPP, Juice Shop, WebGoat, and custom apps to practice SQLi, XSS, SSRF, IDOR, and more.
  ::

  ::card
  ---
  icon: i-lucide-trophy
  title: "Certification Prep"
  ---
  Build environments that mirror OSCP, CEH, PNPT, eJPT, and CRTP exam scenarios for realistic practice.
  ::
::

---

## Lab Architecture Overview

### Network Topology Diagram

::callout
---
icon: i-lucide-layout-dashboard
color: blue
---
Below is the **complete lab network architecture** showing all segments, machines, and connectivity.
::

::code-collapse
```text [Lab Network Topology]
═══════════════════════════════════════════════════════════════════════════
                    PENETRATION TESTING LAB — NETWORK TOPOLOGY
═══════════════════════════════════════════════════════════════════════════

                          ┌──────────────────┐
                          │   HOST MACHINE   │
                          │  (Your Physical  │
                          │    Computer)     │
                          │                  │
                          │  OS: Windows/Mac │
                          │     /Linux       │
                          │                  │
                          │  Hypervisor:     │
                          │  VMware/VBox/    │
                          │  Proxmox         │
                          └────────┬─────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
              ┌─────▼─────┐ ┌─────▼─────┐ ┌─────▼─────┐
              │  vSwitch   │ │  vSwitch   │ │  vSwitch   │
              │  (NAT)     │ │ (Internal) │ │ (Internal) │
              │            │ │            │ │            │
              │ 10.0.0.0   │ │ 192.168.1  │ │ 172.16.0   │
              │   /24      │ │   .0/24    │ │   .0/24    │
              └─────┬──────┘ └─────┬──────┘ └─────┬──────┘
                    │              │              │
         ┌──────── │ ─────────────│──────────────│────────────┐
         │         │              │              │            │
         │  ATTACK NETWORK    TARGET NETWORK   AD NETWORK    │
         │  (10.0.0.0/24)   (192.168.1.0/24) (172.16.0.0/24)│
         │         │              │              │            │
         │  ┌──────▼──────┐      │              │            │
         │  │   KALI      │      │              │            │
         │  │  LINUX      │      │              │            │
         │  │ 10.0.0.10   │      │              │            │
         │  │ + 192.168.  │      │              │            │
         │  │   1.10      │      │              │            │
         │  │ + 172.16.   │      │              │            │
         │  │   0.10      │      │              │            │
         │  │ (3 NICs)    │      │              │            │
         │  └─────────────┘      │              │            │
         │                       │              │            │
         │  ┌──────▼──────┐      │              │            │
         │  │   PARROT    │      │              │            │
         │  │   OS        │      │              │            │
         │  │ 10.0.0.11   │      │              │            │
         │  └─────────────┘      │              │            │
         │                       │              │            │
         │         ┌─────────────▼────────┐     │            │
         │         │                      │     │            │
         │  ┌──────▼──────┐  ┌────────────▼─┐   │            │
         │  │ METASPLOIT- │  │   VULNERABLE │   │            │
         │  │ ABLE 2      │  │   WEB APPS   │   │            │
         │  │ 192.168.    │  │ 192.168.     │   │            │
         │  │  1.100      │  │  1.200       │   │            │
         │  │             │  │              │   │            │
         │  │ ∙ FTP       │  │ ∙ DVWA       │   │            │
         │  │ ∙ SSH       │  │ ∙ bWAPP      │   │            │
         │  │ ∙ Telnet    │  │ ∙ Juice Shop │   │            │
         │  │ ∙ HTTP      │  │ ∙ WebGoat    │   │            │
         │  │ ∙ MySQL     │  │ ∙ Mutillidae │   │            │
         │  │ ∙ Samba     │  │ ∙ HackTheBox │   │            │
         │  │ ∙ IRC       │  │              │   │            │
         │  │ ∙ More...   │  │ Apache/Nginx │   │            │
         │  └─────────────┘  │ PHP/Node.js  │   │            │
         │                   │ MySQL/Mongo  │   │            │
         │  ┌─────────────┐  └──────────────┘   │            │
         │  │ VULNHUB     │                     │            │
         │  │ MACHINES    │  ┌──────────────┐    │            │
         │  │ 192.168.    │  │  WINDOWS     │    │            │
         │  │  1.101-199  │  │  TARGET      │    │            │
         │  │             │  │ 192.168.     │    │            │
         │  │ ∙ Kioptrix  │  │  1.201       │    │            │
         │  │ ∙ DC Series │  │              │    │            │
         │  │ ∙ Mr Robot  │  │ ∙ IIS        │    │            │
         │  │ ∙ Brainpan  │  │ ∙ MSSQL      │    │            │
         │  │ ∙ SickOS    │  │ ∙ SMB        │    │            │
         │  │ ∙ More...   │  │ ∙ RDP        │    │            │
         │  └─────────────┘  └──────────────┘    │            │
         │                                       │            │
         │              ┌────────────────────────▼──────┐     │
         │              │                               │     │
         │       ┌──────▼──────┐  ┌──────────────┐      │     │
         │       │  DOMAIN     │  │  WINDOWS     │      │     │
         │       │ CONTROLLER  │  │  SERVER 2    │      │     │
         │       │ (DC01)      │  │  (DC02)      │      │     │
         │       │ 172.16.     │  │ 172.16.      │      │     │
         │       │  0.1        │  │  0.2         │      │     │
         │       │             │  │              │      │     │
         │       │ Win Server  │  │ Win Server   │      │     │
         │       │ 2019/2022   │  │ 2016/2019    │      │     │
         │       │             │  │              │      │     │
         │       │ ∙ AD DS     │  │ ∙ AD DS      │      │     │
         │       │ ∙ DNS       │  │ ∙ DNS        │      │     │
         │       │ ∙ DHCP      │  │ ∙ File Srvr  │      │     │
         │       │ ∙ GPO       │  │ ∙ MSSQL      │      │     │
         │       │ ∙ CA        │  │ ∙ IIS        │      │     │
         │       └─────────────┘  └──────────────┘      │     │
         │                                              │     │
         │       ┌─────────────┐  ┌──────────────┐      │     │
         │       │  WORKSTATION│  │  WORKSTATION │      │     │
         │       │  (WS01)    │  │  (WS02)      │      │     │
         │       │ 172.16.    │  │ 172.16.      │      │     │
         │       │  0.100     │  │  0.101       │      │     │
         │       │            │  │              │      │     │
         │       │ Win 10/11  │  │ Win 10/11    │      │     │
         │       │ Pro        │  │ Pro          │      │     │
         │       │            │  │              │      │     │
         │       │ ∙ Domain   │  │ ∙ Domain     │      │     │
         │       │   Joined   │  │   Joined     │      │     │
         │       │ ∙ Local    │  │ ∙ Local      │      │     │
         │       │   Admin    │  │   Admin      │      │     │
         │       │ ∙ Users    │  │ ∙ Users      │      │     │
         │       └─────────────┘  └──────────────┘      │     │
         │                                              │     │
         └──────────────────────────────────────────────┘     │
                                                              │
═══════════════════════════════════════════════════════════════════════════
```
::

### Simplified Network Segments

::tabs
  :::tabs-item{icon="i-lucide-swords" label="Attack Network"}
  ```text
  ┌─────────────────────────────────────────────────────────┐
  │                 ATTACK NETWORK (10.0.0.0/24)            │
  │                                                         │
  │   ┌──────────┐    ┌──────────┐    ┌──────────┐         │
  │   │  KALI    │    │  PARROT  │    │ COMMANDO │         │
  │   │  LINUX   │    │  OS      │    │ VM       │         │
  │   │ .10      │    │ .11      │    │ .12      │         │
  │   │          │    │          │    │          │         │
  │   │ Primary  │    │ Backup/  │    │ Windows  │         │
  │   │ Attack   │    │ Alt      │    │ Attack   │         │
  │   │ Machine  │    │ Attack   │    │ Platform │         │
  │   └──────────┘    └──────────┘    └──────────┘         │
  │                                                         │
  │   Purpose: Attack machines with all tools installed     │
  │   Network: NAT (internet) + Internal (target access)   │
  └─────────────────────────────────────────────────────────┘
  ```
  :::

  :::tabs-item{icon="i-lucide-target" label="Target Network"}
  ```text
  ┌─────────────────────────────────────────────────────────┐
  │              TARGET NETWORK (192.168.1.0/24)            │
  │                                                         │
  │   ┌──────────┐  ┌──────────┐  ┌──────────┐             │
  │   │ Metaspl. │  │ VulnHub  │  │ Web Apps │             │
  │   │ 2/3     │  │ Machines │  │ Server   │             │
  │   │ .100    │  │ .101-199 │  │ .200     │             │
  │   └──────────┘  └──────────┘  └──────────┘             │
  │                                                         │
  │   ┌──────────┐  ┌──────────┐  ┌──────────┐             │
  │   │ Windows  │  │ Linux    │  │ Custom   │             │
  │   │ Target   │  │ Target   │  │ Docker   │             │
  │   │ .201    │  │ .202    │  │ Host     │             │
  │   │         │  │         │  │ .210     │             │
  │   └──────────┘  └──────────┘  └──────────┘             │
  │                                                         │
  │   Purpose: Vulnerable machines to attack                │
  │   Network: Internal only (NO internet access)           │
  └─────────────────────────────────────────────────────────┘
  ```
  :::

  :::tabs-item{icon="i-lucide-building" label="AD Network"}
  ```text
  ┌─────────────────────────────────────────────────────────┐
  │           ACTIVE DIRECTORY NETWORK (172.16.0.0/24)      │
  │                                                         │
  │   ┌──────────┐  ┌──────────┐                            │
  │   │   DC01   │  │   DC02   │     Domain:               │
  │   │  .1      │◄─►  .2      │     lab.local             │
  │   │ WinSrv   │  │ WinSrv   │     or                    │
  │   │ 2019     │  │ 2016     │     pentest.corp          │
  │   └────┬─────┘  └────┬─────┘                            │
  │        │              │                                  │
  │   ┌────▼─────┐  ┌────▼─────┐  ┌──────────┐             │
  │   │  WS01    │  │  WS02    │  │  WS03    │             │
  │   │  .100    │  │  .101    │  │  .102    │             │
  │   │ Win 10   │  │ Win 11   │  │ Win 10   │             │
  │   │ Domain   │  │ Domain   │  │ Domain   │             │
  │   │ Joined   │  │ Joined   │  │ Joined   │             │
  │   └──────────┘  └──────────┘  └──────────┘             │
  │                                                         │
  │   Purpose: Active Directory attack practice             │
  │   Network: Internal only (isolated AD domain)           │
  └─────────────────────────────────────────────────────────┘
  ```
  :::
::

---

## Hardware Requirements

### Minimum vs Recommended Specs

::tabs
  :::tabs-item{icon="i-lucide-cpu" label="Minimum (Basic Lab)"}
  ```text
  ┌─────────────────────────────────────────────┐
  │          MINIMUM HARDWARE SPECS             │
  │         (2-3 VMs simultaneously)            │
  ├─────────────────────────────────────────────┤
  │                                             │
  │  CPU:     4 cores (Intel i5 / AMD Ryzen 5)  │
  │  RAM:     16 GB DDR4                        │
  │  Storage: 256 GB SSD                        │
  │  Network: 1 NIC (Wi-Fi or Ethernet)         │
  │                                             │
  │  Can Run:                                   │
  │  ✓ 1x Kali Linux (2 GB RAM)                │
  │  ✓ 1x Metasploitable (512 MB RAM)          │
  │  ✓ 1x DVWA/Web App (1 GB RAM)              │
  │  ✗ Active Directory lab (not enough RAM)    │
  │                                             │
  │  Budget: $0 (use existing laptop)           │
  └─────────────────────────────────────────────┘
  ```
  :::

  :::tabs-item{icon="i-lucide-cpu" label="Recommended (Full Lab)"}
  ```text
  ┌─────────────────────────────────────────────┐
  │        RECOMMENDED HARDWARE SPECS           │
  │         (5-8 VMs simultaneously)            │
  ├─────────────────────────────────────────────┤
  │                                             │
  │  CPU:     8 cores (Intel i7 / AMD Ryzen 7)  │
  │  RAM:     32 GB DDR4/DDR5                   │
  │  Storage: 1 TB NVMe SSD                     │
  │  Network: 1 NIC (Ethernet preferred)        │
  │                                             │
  │  Can Run:                                   │
  │  ✓ 1x Kali Linux (4 GB RAM)                │
  │  ✓ 1x Parrot OS (2 GB RAM)                 │
  │  ✓ 2x Vulnerable Linux VMs (1 GB each)     │
  │  ✓ 1x Windows DC (4 GB RAM)                │
  │  ✓ 2x Windows Workstations (2 GB each)     │
  │  ✓ 1x Web App Server (2 GB RAM)            │
  │                                             │
  │  Budget: ~$800-1200 (laptop/desktop)        │
  └─────────────────────────────────────────────┘
  ```
  :::

  :::tabs-item{icon="i-lucide-cpu" label="Optimal (Enterprise Lab)"}
  ```text
  ┌─────────────────────────────────────────────┐
  │          OPTIMAL HARDWARE SPECS             │
  │        (10-20 VMs simultaneously)           │
  ├─────────────────────────────────────────────┤
  │                                             │
  │  CPU:     12-16 cores (i9 / Ryzen 9 /       │
  │           Threadripper / Xeon)              │
  │  RAM:     64-128 GB DDR4/DDR5              │
  │  Storage: 2 TB NVMe SSD + 4 TB HDD        │
  │  Network: 2+ NICs (for network segments)   │
  │                                             │
  │  Can Run:                                   │
  │  ✓ Full AD forest (multiple domains)        │
  │  ✓ Multiple attack machines                 │
  │  ✓ 10+ vulnerable VMs                       │
  │  ✓ Network security devices (pfSense, IDS)  │
  │  ✓ Docker containers (50+)                  │
  │  ✓ Cloud simulation                         │
  │                                             │
  │  Options:                                   │
  │  ∙ Dedicated server / homelab               │
  │  ∙ Used Dell/HP server (~$300-500)          │
  │  ∙ Proxmox on dedicated hardware            │
  │  Budget: $1500-3000                         │
  └─────────────────────────────────────────────┘
  ```
  :::
::

### Budget Lab Options

::card-group
  ::card
  ---
  icon: i-lucide-wallet
  title: "$0 — Free Lab"
  color: green
  ---
  Use your **existing laptop/desktop**. Install VirtualBox (free). Download Kali + Metasploitable + DVWA. Minimum 16GB RAM. This is how **most people start**.
  ::

  ::card
  ---
  icon: i-lucide-wallet
  title: "$100-300 — Used Server"
  color: blue
  ---
  Buy a **used Dell PowerEdge / HP ProLiant** from eBay. 64GB+ RAM, dual Xeon CPUs. Install Proxmox. Run 15+ VMs. Best **bang for buck**.
  ::

  ::card
  ---
  icon: i-lucide-wallet
  title: "$0-50/month — Cloud Lab"
  color: orange
  ---
  **AWS / Azure / GCP free tier** or student credits. Spin up instances on demand. Great for AD labs without local hardware. **Destroy when done** to avoid charges.
  ::
::

---

## Hypervisor Setup

### Choosing Your Hypervisor

::tabs
  :::tabs-item{icon="i-lucide-box" label="VirtualBox (Free)"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  VIRTUALBOX — FREE, CROSS-PLATFORM
  # ═══════════════════════════════════════

  # ─── INSTALLATION ───
  # Download: https://www.virtualbox.org/wiki/Downloads

  # Linux (Ubuntu/Debian)
  sudo apt update
  sudo apt install virtualbox virtualbox-ext-pack -y

  # Linux (Fedora/RHEL)
  sudo dnf install VirtualBox -y

  # macOS (Homebrew)
  brew install --cask virtualbox

  # Windows: Download installer from website

  # ─── EXTENSION PACK (Important!) ───
  # Adds: USB 2.0/3.0, RDP, disk encryption, NVMe
  # Download from VirtualBox website → File → Preferences → Extensions → Add

  # ─── VERIFY INSTALLATION ───
  VBoxManage --version

  # ─── PERFORMANCE TIPS ───
  # 1. Enable VT-x/AMD-V in BIOS
  # 2. Allocate fixed-size disks (faster than dynamic)
  # 3. Use SSD for VM storage
  # 4. Install Guest Additions in each VM
  # 5. Use paravirtualized network adapter
  ```

  ```text
  VirtualBox Network Modes:
  ─────────────────────────────────────────
  NAT:           VM → Internet (isolated from host network)
  Bridged:       VM = separate device on host network
  Host-Only:     VM ↔ Host only (no internet)
  Internal:      VM ↔ VM only (isolated)
  NAT Network:   Multiple VMs share NAT (VM ↔ VM + Internet)

  RECOMMENDED LAB SETUP:
  ─────────────────────────────────────────
  Kali:     NIC1 = NAT (internet) + NIC2 = Internal (targets)
  Targets:  NIC1 = Internal only (no internet)
  AD Lab:   NIC1 = Internal only (isolated domain)
  ```
  :::

  :::tabs-item{icon="i-lucide-box" label="VMware (Pro)"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  VMWARE — PROFESSIONAL GRADE
  # ═══════════════════════════════════════

  # Products:
  # VMware Workstation Pro (Windows/Linux) — Now FREE for personal use!
  # VMware Fusion (macOS) — Now FREE for personal use!
  # VMware Player (Free, limited features)

  # ─── INSTALLATION ───
  # Download: https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion

  # Linux
  chmod +x VMware-Workstation-Full-*.bundle
  sudo ./VMware-Workstation-Full-*.bundle

  # Verify
  vmware --version

  # ─── ADVANTAGES OVER VIRTUALBOX ───
  # ✓ Better performance (especially with snapshots)
  # ✓ Better networking (custom virtual networks)
  # ✓ Better snapshot management
  # ✓ Better USB passthrough
  # ✓ VMware Tools (better than Guest Additions)
  # ✓ Linked clones (save disk space)
  # ✓ Network simulation features

  # ─── VIRTUAL NETWORK EDITOR ───
  # Edit → Virtual Network Editor (Windows/Linux)
  # Create custom networks:
  # VMnet1:  Host-Only  (192.168.1.0/24)  — Target Network
  # VMnet2:  Host-Only  (172.16.0.0/24)   — AD Network
  # VMnet8:  NAT        (10.0.0.0/24)     — Attack Network + Internet
  ```

  ```text
  VMware Network Modes:
  ─────────────────────────────────────────
  NAT (VMnet8):     VM → Internet via host (default)
  Bridged (VMnet0): VM on host network (gets real IP)
  Host-Only (VMnet1): VM ↔ Host only
  Custom:           Create additional VMnets

  RECOMMENDED LAB SETUP:
  ─────────────────────────────────────────
  VMnet8 (NAT):       10.0.0.0/24    — Kali internet access
  VMnet1 (Host-Only): 192.168.1.0/24 — Target machines
  VMnet2 (Host-Only): 172.16.0.0/24  — AD lab
  VMnet3 (Host-Only): 10.10.10.0/24  — IoT/Special lab

  Kali: NIC1=VMnet8, NIC2=VMnet1, NIC3=VMnet2
  ```
  :::

  :::tabs-item{icon="i-lucide-box" label="Proxmox (Server)"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  PROXMOX VE — ENTERPRISE HOMELAB
  # ═══════════════════════════════════════

  # Best for: Dedicated server/homelab hardware
  # Free, open-source, Type 1 hypervisor
  # Runs VMs AND containers (LXC)
  # Web-based management UI

  # ─── INSTALLATION ───
  # Download ISO: https://www.proxmox.com/en/downloads
  # Boot from USB → Install on dedicated hardware
  # Access web UI: https://<server-ip>:8006

  # ─── POST-INSTALL ───
  # Remove enterprise repo (if no subscription)
  sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/pve-enterprise.list
  echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" > \
    /etc/apt/sources.list.d/pve-no-subscription.list
  apt update && apt upgrade -y

  # ─── NETWORK SETUP ───
  # Create Linux bridges for each network segment:
  # vmbr0: Management (host access)
  # vmbr1: Attack Network (10.0.0.0/24)
  # vmbr2: Target Network (192.168.1.0/24)
  # vmbr3: AD Network (172.16.0.0/24)

  # Configure in: Datacenter → Node → Network

  # ─── ADVANTAGES ───
  # ✓ Type 1 (bare-metal) — better performance
  # ✓ Web UI management
  # ✓ LXC containers (lightweight targets)
  # ✓ ZFS storage (snapshots, compression)
  # ✓ Multiple nodes / clustering
  # ✓ Backup/restore built-in
  # ✓ API for automation
  # ✓ Template system (clone VMs instantly)
  ```
  :::
::

### Hypervisor Comparison

::collapsible

| Feature | VirtualBox | VMware Workstation | Proxmox VE |
|---------|------------|-------------------|------------|
| **Cost** | Free | Free (personal) | Free |
| **Type** | Type 2 (hosted) | Type 2 (hosted) | Type 1 (bare-metal) |
| **OS Support** | Win/Mac/Linux | Win/Linux (Fusion for Mac) | Linux (bare-metal) |
| **Performance** | Good | Very Good | Excellent |
| **Snapshots** | Yes | Yes (better) | Yes (ZFS) |
| **Networking** | Good | Excellent | Excellent |
| **GUI** | Desktop | Desktop | Web UI |
| **Containers** | No | No | Yes (LXC) |
| **Best For** | Beginners | Professionals | Homelabs/Servers |
| **RAM Overhead** | ~2 GB | ~2 GB | ~1 GB |
| **Linked Clones** | No | Yes | Yes |
| **Max VMs** | Limited by RAM | Limited by RAM | Limited by hardware |

::

---

## Attack Machines Setup

### Kali Linux — Primary Attack Machine

::steps{level="4"}

#### Download & Install

```bash [Terminal]
# ─── DOWNLOAD ───
# Official: https://www.kali.org/get-kali/
# Options:
# 1. ISO (full install) — recommended
# 2. Pre-built VM (VMware/VBox) — easiest
# 3. Docker image
# 4. WSL2 (Windows Subsystem for Linux)
# 5. ARM (Raspberry Pi)

# Pre-built VM (fastest setup):
# VMware: https://www.kali.org/get-kali/#kali-virtual-machines
# VirtualBox: https://www.kali.org/get-kali/#kali-virtual-machines

# ─── VM SETTINGS ───
# CPU:    2-4 cores
# RAM:    4 GB (minimum 2 GB)
# Disk:   80 GB (minimum 40 GB)
# NIC 1:  NAT (internet access)
# NIC 2:  Internal/Host-Only (target network)
# NIC 3:  Internal/Host-Only (AD network)
```

#### Post-Install Configuration

```bash [Terminal]
# ─── UPDATE SYSTEM ───
sudo apt update && sudo apt full-upgrade -y

# ─── CHANGE DEFAULT PASSWORD ───
passwd

# ─── INSTALL ADDITIONAL TOOLS ───
# Core tools (may already be installed)
sudo apt install -y \
  nmap masscan nikto gobuster feroxbuster ffuf \
  sqlmap burpsuite metasploit-framework \
  hydra medusa ncrack john hashcat \
  seclists wordlists exploitdb \
  bloodhound neo4j crackmapexec \
  impacket-scripts evil-winrm chisel \
  ligolo-ng responder mitm6 \
  nuclei subfinder httpx amass \
  python3-pip golang-go

# ─── INSTALL EXTRA TOOLS ───
# AutoRecon (automated recon)
pip3 install autorecon

# Rustscan (fast port scanner)
wget https://github.com/RustScan/RustScan/releases/latest/download/rustscan_amd64.deb
sudo dpkg -i rustscan_amd64.deb

# LinPEAS / WinPEAS
mkdir -p /opt/privesc
wget -O /opt/privesc/linpeas.sh \
  https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
wget -O /opt/privesc/winPEASx64.exe \
  https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe

# PayloadsAllTheThings
git clone https://github.com/swisskyrepo/PayloadsAllTheThings /opt/payloads

# SecLists
sudo apt install seclists -y
# Or: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists

# ─── CONFIGURE NETWORK INTERFACES ───
# Verify interfaces
ip addr show

# Static IP for target network (NIC 2)
sudo cat >> /etc/network/interfaces << 'EOF'
auto eth1
iface eth1 inet static
  address 192.168.1.10
  netmask 255.255.255.0

auto eth2
iface eth2 inet static
  address 172.16.0.10
  netmask 255.255.255.0
EOF

sudo systemctl restart networking

# ─── CREATE WORKING DIRECTORY STRUCTURE ───
mkdir -p ~/pentesting/{recon,exploits,loot,notes,reports,tools,wordlists}
mkdir -p ~/pentesting/targets/{target1,target2,target3}
```

#### Install Burp Suite Professional (Optional)

```bash [Terminal]
# Burp Suite Community comes with Kali
# For Professional (paid):
# Download: https://portswigger.net/burp/pro
# Install:
chmod +x burpsuite_pro_linux_v*.sh
./burpsuite_pro_linux_v*.sh

# Configure Firefox proxy:
# Preferences → Network → Manual Proxy → 127.0.0.1:8080
# Install Burp CA certificate: http://burp → CA Certificate

# Useful Burp Extensions:
# - ActiveScan++
# - Autorize
# - Param Miner
# - Hackvertor
# - JWT Editor
# - Logger++
# - Turbo Intruder
```

::

### Additional Attack Machines

::card-group
  ::card
  ---
  icon: i-lucide-bird
  title: "Parrot OS"
  to: https://parrotsec.org
  target: _blank
  ---
  Alternative to Kali. Lighter, privacy-focused, Debian-based. Includes most of the same tools. Good as a **backup attack machine**.

  - **Download:** parrotsec.org
  - **VM Settings:** 2 cores, 2 GB RAM, 40 GB disk
  - **Best For:** When you want a different perspective
  ::

  ::card
  ---
  icon: i-lucide-terminal
  title: "Commando VM (Windows)"
  to: https://github.com/mandiant/commando-vm
  target: _blank
  ---
  **Windows-based** attack platform by Mandiant. Turns Windows 10/11 into a pentesting machine. Essential for **Active Directory attacks** and **Windows exploitation**.

  - **Base:** Windows 10/11 (bring your own license)
  - **VM Settings:** 4 cores, 4 GB RAM, 80 GB disk
  - **Best For:** AD attacks, Windows tools, .NET exploits
  ::

  ::card
  ---
  icon: i-lucide-terminal
  title: "REMnux (Malware Analysis)"
  to: https://remnux.org
  target: _blank
  ---
  Linux toolkit for **reverse engineering and malware analysis**. Pre-configured with analysis tools, debuggers, and sandboxing capabilities.

  - **VM Settings:** 2 cores, 4 GB RAM, 60 GB disk
  - **Best For:** Malware analysis, reverse engineering
  ::
::

---

## Vulnerable Target Machines

### Linux Vulnerable Machines

::tabs
  :::tabs-item{icon="i-lucide-target" label="Metasploitable 2/3"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  METASPLOITABLE 2 — THE CLASSIC
  # ═══════════════════════════════════════

  # Download: https://sourceforge.net/projects/metasploitable/
  # Format: VMware .vmdk (works in VBox too)
  # Default creds: msfadmin / msfadmin

  # ─── VM SETTINGS ───
  # CPU:     1 core
  # RAM:     512 MB
  # Disk:    8 GB (included)
  # Network: Internal/Host-Only (192.168.1.100)
  # DO NOT give internet access!

  # ─── VULNERABLE SERVICES ───
  # Port 21   — vsftpd 2.3.4 (BACKDOOR!)
  # Port 22   — OpenSSH 4.7p1
  # Port 23   — Telnet
  # Port 25   — Postfix SMTP
  # Port 80   — Apache 2.2.8 (PHP, DVWA, Mutillidae, phpMyAdmin)
  # Port 111  — RPCbind
  # Port 139  — Samba 3.x (SMB)
  # Port 445  — Samba 3.x (SMB)
  # Port 512  — rexecd
  # Port 513  — rlogin
  # Port 514  — rsh
  # Port 1099 — Java RMI
  # Port 1524 — Ingreslock (backdoor)
  # Port 2049 — NFS
  # Port 2121 — ProFTPD 1.3.1
  # Port 3306 — MySQL 5.0
  # Port 3632 — distccd
  # Port 5432 — PostgreSQL 8.3
  # Port 5900 — VNC
  # Port 6000 — X11
  # Port 6667 — UnrealIRCd (BACKDOOR!)
  # Port 8009 — Apache Tomcat AJP
  # Port 8180 — Apache Tomcat 5.5
  # Port 8787 — Ruby DRb

  # ─── IMPORT INTO VIRTUALBOX ───
  # 1. Create new VM → Linux → Ubuntu 32-bit
  # 2. Use existing virtual hard disk → select .vmdk
  # 3. Set network to Internal/Host-Only
  # 4. Boot → login: msfadmin / msfadmin
  # 5. Check IP: ifconfig

  # ─── IMPORT INTO VMWARE ───
  # 1. File → Open → select .vmx file
  # 2. Set network adapter to Host-Only/Custom
  # 3. Boot → login: msfadmin / msfadmin

  # ═══════════════════════════════════════
  #  METASPLOITABLE 3 — ADVANCED
  # ═══════════════════════════════════════

  # Build with Vagrant + Packer
  # https://github.com/rapid7/metasploitable3

  # Includes both Linux AND Windows targets
  # More realistic than Metasploitable 2

  # Prerequisites
  # Install: VirtualBox + Vagrant + Packer

  # Build
  git clone https://github.com/rapid7/metasploitable3.git
  cd metasploitable3
  vagrant up
  ```
  :::

  :::tabs-item{icon="i-lucide-target" label="VulnHub Machines"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  VULNHUB — 700+ VULNERABLE VMs
  # ═══════════════════════════════════════

  # Website: https://www.vulnhub.com
  # Free downloadable VMs designed to be hacked
  # Each has a specific goal (capture the flag)

  # ─── RECOMMENDED PROGRESSION ───

  # BEGINNER (Start Here):
  # ─────────────────────────────────────
  # 1. Kioptrix Level 1        — Classic beginner box
  # 2. Kioptrix Level 2        — Web app + SQLi
  # 3. Kioptrix Level 3        — CMS exploitation
  # 4. Basic Pentesting 1      — Guided learning
  # 5. Basic Pentesting 2      — Web + Linux privesc
  # 6. Stapler                 — Multiple attack vectors
  # 7. Tr0ll 1                 — Fun beginner box
  # 8. Mr Robot                — Themed CTF
  # 9. SickOS 1.1              — Web app + privesc
  # 10. Bulldog                — Django exploitation

  # INTERMEDIATE:
  # ─────────────────────────────────────
  # 11. DC Series (DC-1 to DC-9) — Drupal, WordPress, etc.
  # 12. HackLAB: Vulnix         — NFS, SSH, privesc
  # 13. Brainpan                 — Buffer overflow
  # 14. FristiLeaks             — Web + Linux
  # 15. Wintermute              — Multi-machine pivoting
  # 16. Lampiao                 — Drupalgeddon
  # 17. Sunset Series           — Various difficulties
  # 18. Breach Series           — Corporate simulation

  # ADVANCED:
  # ─────────────────────────────────────
  # 19. Raven 1 & 2            — WordPress + MySQL
  # 20. Symfonos Series        — Multi-layered attacks
  # 21. Sar                    — Newer technologies
  # 22. InfoSec Prep           — OSCP-like
  # 23. Funbox Series          — Various techniques

  # ─── DOWNLOAD & IMPORT ───
  # 1. Download .ova/.vmdk from VulnHub
  # 2. Import into VirtualBox/VMware
  # 3. Set network to Internal/Host-Only
  # 4. Boot the VM
  # 5. Discover IP with: netdiscover -i eth1 (from Kali)
  # 6. Start hacking!

  # ─── TIPS ───
  # - ALWAYS snapshot before starting
  # - Take detailed notes
  # - Try WITHOUT walkthroughs first
  # - If stuck for 2+ hours, check hints (not full solution)
  # - After completing, read OTHER people's writeups
  #   (learn different approaches)
  ```
  :::

  :::tabs-item{icon="i-lucide-target" label="Custom Linux Target"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  BUILD YOUR OWN VULNERABLE LINUX VM
  # ═══════════════════════════════════════

  # Start with Ubuntu Server 20.04/22.04 minimal install

  # ─── VM SETTINGS ───
  # CPU:     1-2 cores
  # RAM:     1-2 GB
  # Disk:    20 GB
  # Network: Internal/Host-Only only

  # ─── INSTALL VULNERABLE SERVICES ───

  # --- SSH (weak config) ---
  sudo apt install openssh-server -y
  # Edit /etc/ssh/sshd_config:
  # PermitRootLogin yes
  # PasswordAuthentication yes
  echo "root:toor" | sudo chpasswd
  sudo useradd -m -s /bin/bash user1
  echo "user1:password123" | sudo chpasswd

  # --- FTP (vsftpd with anonymous) ---
  sudo apt install vsftpd -y
  sudo sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf
  echo "write_enable=YES" | sudo tee -a /etc/vsftpd.conf
  echo "anon_upload_enable=YES" | sudo tee -a /etc/vsftpd.conf
  sudo systemctl restart vsftpd

  # --- Web Server (Apache + PHP) ---
  sudo apt install apache2 php php-mysql libapache2-mod-php -y
  # Create vulnerable PHP page
  cat > /var/www/html/vuln.php << 'VULN'
  <?php
  // SQL Injection vulnerable
  $id = $_GET['id'];
  $conn = mysqli_connect("localhost","root","root","vuln_db");
  $result = mysqli_query($conn, "SELECT * FROM users WHERE id=$id");
  while($row = mysqli_fetch_assoc($result)) {
    echo "User: " . $row['username'] . " - " . $row['password'] . "<br>";
  }
  // Command Injection vulnerable
  if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
  }
  // LFI vulnerable
  if(isset($_GET['page'])) {
    include($_GET['page']);
  }
  ?>
  VULN

  # --- MySQL (weak password) ---
  sudo apt install mysql-server -y
  sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'root';"
  sudo mysql -e "CREATE DATABASE vuln_db;"
  sudo mysql -e "USE vuln_db; CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(50));"
  sudo mysql -e "USE vuln_db; INSERT INTO users VALUES (1,'admin','admin123'),(2,'user','password'),(3,'root','toor');"
  sudo mysql -e "CREATE USER 'root'@'%' IDENTIFIED BY 'root'; GRANT ALL ON *.* TO 'root'@'%';"

  # --- Samba (open share) ---
  sudo apt install samba -y
  mkdir -p /srv/share
  chmod 777 /srv/share
  echo "Sensitive data: password=Secret123!" > /srv/share/credentials.txt
  cat >> /etc/samba/smb.conf << 'SMB'
  [public]
    path = /srv/share
    browsable = yes
    writable = yes
    guest ok = yes
  SMB
  sudo systemctl restart smbd

  # --- Telnet ---
  sudo apt install telnetd xinetd -y
  sudo systemctl enable xinetd
  sudo systemctl start xinetd

  # --- SUID binaries for privesc ---
  sudo cp /usr/bin/python3 /usr/local/bin/python3-suid
  sudo chmod u+s /usr/local/bin/python3-suid
  sudo cp /usr/bin/find /usr/local/bin/find-suid
  sudo chmod u+s /usr/local/bin/find-suid

  # --- Cron job privesc ---
  echo "#!/bin/bash" > /opt/cleanup.sh
  echo "# Cleanup script" >> /opt/cleanup.sh
  chmod 777 /opt/cleanup.sh
  echo "* * * * * root /opt/cleanup.sh" >> /etc/crontab

  # --- Sudo misconfiguration ---
  echo "user1 ALL=(ALL) NOPASSWD: /usr/bin/vim" >> /etc/sudoers
  echo "user1 ALL=(ALL) NOPASSWD: /usr/bin/find" >> /etc/sudoers
  ```
  :::
::

### Web Application Targets

::tabs
  :::tabs-item{icon="i-lucide-globe" label="Docker Web Apps (Easy)"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  VULNERABLE WEB APPS VIA DOCKER
  #  (Fastest setup — run on any machine)
  # ═══════════════════════════════════════

  # ─── INSTALL DOCKER ───
  sudo apt install docker.io docker-compose -y
  sudo systemctl enable docker
  sudo systemctl start docker
  sudo usermod -aG docker $USER
  # Logout and login again

  # ─── DVWA (Damn Vulnerable Web App) ───
  docker run -d -p 8081:80 --name dvwa vulnerables/web-dvwa
  # Access: http://localhost:8081
  # Login: admin / password
  # Click "Create / Reset Database"
  # Set security level to "Low" to start

  # ─── bWAPP (Buggy Web Application) ───
  docker run -d -p 8082:80 --name bwapp raesene/bwapp
  # Access: http://localhost:8082/install.php
  # Click install → login: bee / bug

  # ─── OWASP Juice Shop ───
  docker run -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
  # Access: http://localhost:3000
  # Modern, realistic vulnerable app (Node.js)

  # ─── OWASP WebGoat ───
  docker run -d -p 8083:8080 -p 9090:9090 --name webgoat \
    webgoat/webgoat
  # Access: http://localhost:8083/WebGoat
  # Register a new account

  # ─── Mutillidae II ───
  docker run -d -p 8084:80 --name mutillidae \
    citizenstig/nowasp
  # Access: http://localhost:8084/mutillidae/

  # ─── HackTheBox / OWASP Broken Web Apps ───
  # NodeGoat (OWASP Node.js)
  docker run -d -p 4000:4000 --name nodegoat \
    cider/nodegoat
  # Access: http://localhost:4000

  # ─── VulnLab (Multiple apps) ───
  docker run -d -p 8085:80 --name vulnlab \
    hmlio/vaas-cve-2014-6271  # Shellshock
  docker run -d -p 8086:80 --name heartbleed \
    hmlio/vaas-cve-2014-0160  # Heartbleed

  # ─── WordPress (Vulnerable plugins) ───
  cat > docker-compose-wp.yml << 'EOF'
  version: '3'
  services:
    wp-db:
      image: mysql:5.7
      environment:
        MYSQL_ROOT_PASSWORD: password
        MYSQL_DATABASE: wordpress
    wordpress:
      image: wordpress:latest
      ports:
        - "8087:80"
      environment:
        WORDPRESS_DB_HOST: wp-db:3306
        WORDPRESS_DB_PASSWORD: password
      depends_on:
        - wp-db
  EOF
  docker-compose -f docker-compose-wp.yml up -d
  # Install vulnerable plugins manually

  # ─── STOP ALL ───
  docker stop $(docker ps -q)

  # ─── START ALL ───
  docker start $(docker ps -aq)

  # ─── VIEW RUNNING CONTAINERS ───
  docker ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}"
  ```
  :::

  :::tabs-item{icon="i-lucide-globe" label="Dedicated Web VM"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  DEDICATED WEB APPLICATION SERVER VM
  # ═══════════════════════════════════════

  # Base: Ubuntu 22.04 Server
  # CPU:  2 cores
  # RAM:  2-4 GB
  # Disk: 40 GB
  # Net:  Internal/Host-Only (192.168.1.200)

  # ─── INSTALL LAMP STACK ───
  sudo apt update
  sudo apt install -y apache2 mysql-server \
    php php-mysql php-gd php-xml php-mbstring \
    php-curl libapache2-mod-php unzip git curl

  # ─── INSTALL DVWA ───
  cd /var/www/html
  sudo git clone https://github.com/digininja/DVWA.git dvwa
  sudo cp dvwa/config/config.inc.php.dist dvwa/config/config.inc.php
  sudo sed -i "s/'root'/'root'/;s/''/'password'/" dvwa/config/config.inc.php
  sudo chown -R www-data:www-data dvwa
  sudo chmod -R 755 dvwa
  sudo mysql -e "CREATE DATABASE dvwa; CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd'; GRANT ALL ON dvwa.* TO 'dvwa'@'localhost';"

  # ─── INSTALL BWAPP ───
  cd /var/www/html
  sudo wget https://sourceforge.net/projects/bwapp/files/latest/download -O bwapp.zip
  sudo unzip bwapp.zip -d bwapp
  sudo chown -R www-data:www-data bwapp

  # ─── INSTALL MUTILLIDAE ───
  cd /var/www/html
  sudo git clone https://github.com/webpwnized/mutillidae.git
  sudo chown -R www-data:www-data mutillidae

  # ─── INSTALL NODE.JS APPS ───
  curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
  sudo apt install -y nodejs

  # Juice Shop
  cd /opt
  sudo git clone https://github.com/juice-shop/juice-shop.git
  cd juice-shop
  sudo npm install
  # Run: node app.js (port 3000)

  # ─── INSTALL PHPMYADMIN (intentionally) ───
  sudo apt install phpmyadmin -y
  # Accessible at: http://192.168.1.200/phpmyadmin
  # root / password

  # ─── APACHE VIRTUAL HOSTS ───
  # Each app gets its own URL for realism
  sudo a2enmod rewrite
  sudo systemctl restart apache2
  ```
  :::

  :::tabs-item{icon="i-lucide-globe" label="API Targets"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  VULNERABLE API TARGETS
  # ═══════════════════════════════════════

  # ─── OWASP crAPI (Completely Ridiculous API) ───
  # Best API hacking practice platform
  git clone https://github.com/OWASP/crAPI.git
  cd crAPI
  docker-compose up -d
  # Access: http://localhost:8888
  # Mail:   http://localhost:8025

  # ─── OWASP Pixi ───
  docker run -d -p 8090:8000 --name pixi \
    deadpixelsociety/pixi
  # Access: http://localhost:8090

  # ─── VAmPI (Vulnerable API) ───
  docker run -d -p 5001:5000 --name vampi \
    erev0s/vampi
  # Access: http://localhost:5001

  # ─── DVGA (Damn Vulnerable GraphQL App) ───
  docker run -d -p 5013:5013 --name dvga \
    dolevf/dvga
  # Access: http://localhost:5013

  # ─── Juice Shop API ───
  # Already included in Juice Shop
  # API docs at: http://localhost:3000/api-docs

  # ─── Generic REST API ───
  docker run -d -p 8091:3000 --name restapi \
    clarkio/vulnerable-api
  ```
  :::
::

---

## Active Directory Lab

::warning
An Active Directory lab is **essential** for pentesting Windows environments. This is what you'll encounter in **90%+ of enterprise penetration tests** and is heavily tested in **OSCP, CRTP, and PNPT** certifications.
::

### AD Lab Architecture

```text
═══════════════════════════════════════════════════════════════════
              ACTIVE DIRECTORY LAB ARCHITECTURE
═══════════════════════════════════════════════════════════════════

  DOMAIN: lab.local (or pentest.corp)
  FOREST: Single forest, single domain (basic)
          Multi-domain with trust (advanced)

  ┌─────────────────────────────────────────────────────────────┐
  │                    172.16.0.0/24 Network                    │
  │                                                             │
  │  ┌──────────────┐        ┌──────────────┐                   │
  │  │    DC01       │        │    DC02       │                   │
  │  │ 172.16.0.1   │◄──────►│ 172.16.0.2   │                   │
  │  │              │  Repl   │              │                   │
  │  │ Win Srv 2019 │        │ Win Srv 2016 │                   │
  │  │              │        │              │                   │
  │  │ Roles:       │        │ Roles:       │                   │
  │  │ ∙ AD DS      │        │ ∙ AD DS      │                   │
  │  │ ∙ DNS        │        │ ∙ DNS        │                   │
  │  │ ∙ DHCP       │        │ ∙ File Server│                   │
  │  │ ∙ CA (ADCS)  │        │ ∙ MSSQL 2019 │                   │
  │  │ ∙ GPO        │        │ ∙ IIS        │                   │
  │  └──────┬───────┘        └──────┬───────┘                   │
  │         │                       │                            │
  │  ┌──────▼───────┐  ┌───────────▼──┐  ┌──────────────┐      │
  │  │   WS01        │  │   WS02        │  │   WS03        │      │
  │  │ 172.16.0.100  │  │ 172.16.0.101  │  │ 172.16.0.102  │      │
  │  │               │  │               │  │               │      │
  │  │ Win 10 Pro    │  │ Win 11 Pro    │  │ Win 10 Pro    │      │
  │  │               │  │               │  │               │      │
  │  │ Users:        │  │ Users:        │  │ Users:        │      │
  │  │ ∙ jsmith      │  │ ∙ agarcia     │  │ ∙ bwilson     │      │
  │  │   (IT Admin)  │  │   (HR)        │  │   (Finance)   │      │
  │  │ ∙ LocalAdmin  │  │ ∙ LocalAdmin  │  │ ∙ LocalAdmin  │      │
  │  │               │  │               │  │               │      │
  │  │ Software:     │  │ Software:     │  │ Software:     │      │
  │  │ ∙ Office      │  │ ∙ Office      │  │ ∙ Office      │      │
  │  │ ∙ Browser     │  │ ∙ Browser     │  │ ∙ Browser     │      │
  │  │ ∙ Putty       │  │ ∙ FileZilla   │  │ ∙ KeePass     │      │
  │  └───────────────┘  └───────────────┘  └───────────────┘      │
  │                                                               │
  │  ┌──────────────────────────────────────────┐                 │
  │  │  KALI LINUX (Attack Machine)             │                 │
  │  │  172.16.0.10                             │                 │
  │  │  Connected to this network via NIC3      │                 │
  │  └──────────────────────────────────────────┘                 │
  └───────────────────────────────────────────────────────────────┘

  AD USERS & GROUPS:
  ─────────────────────────────────────────
  Domain Admins:    administrator / P@ssw0rd2024!
  IT Admins:        jsmith / FallSeason2024!
  HR:               agarcia / Welcome2024!
  Finance:          bwilson / Summer2024!
  Service Account:  svc_sql / SQLServiceP@ss!
  Service Account:  svc_backup / Backup2024!

  MISCONFIGURATIONS (Intentional):
  ─────────────────────────────────────────
  ∙ SPN on svc_sql (Kerberoastable)
  ∙ AS-REP Roasting on agarcia (no preauth)
  ∙ Unconstrained delegation on WS01
  ∙ LAPS not deployed
  ∙ GPP passwords in SYSVOL
  ∙ Weak password policy (min 7 chars)
  ∙ WDigest enabled (cleartext creds in memory)
  ∙ PrintNightmare vulnerable
  ∙ SMB signing not required
  ∙ LLMNR/NBT-NS enabled
  ∙ ADCS misconfigured templates (ESC1)
```

### Building the AD Lab

::steps{level="4"}

#### DC01 — Primary Domain Controller

```powershell [PowerShell (Admin)]
# ═══════════════════════════════════════
#  DC01 SETUP — Windows Server 2019/2022
# ═══════════════════════════════════════

# VM Settings:
# CPU:  2 cores
# RAM:  4 GB
# Disk: 60 GB
# Net:  Internal/Host-Only (172.16.0.0/24)

# ─── STEP 1: Set Static IP ───
New-NetIPAddress -InterfaceAlias "Ethernet0" `
  -IPAddress 172.16.0.1 `
  -PrefixLength 24 `
  -DefaultGateway 172.16.0.254
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" `
  -ServerAddresses 172.16.0.1, 8.8.8.8

# ─── STEP 2: Rename Computer ───
Rename-Computer -NewName "DC01" -Restart

# ─── STEP 3: Install AD DS Role ───
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# ─── STEP 4: Promote to Domain Controller ───
Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -ForestMode "WinThreshold" `
  -DomainMode "WinThreshold" `
  -InstallDNS:$true `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "Dsrm@P@ssw0rd!" -AsPlainText -Force) `
  -Force:$true
# Server will restart automatically

# ─── STEP 5: Create Organizational Units ───
New-ADOrganizationalUnit -Name "Corp" -Path "DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Users" -Path "OU=Corp,DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Groups" -Path "OU=Corp,DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Computers" -Path "OU=Corp,DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Corp,DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Service Accounts" -Path "OU=Corp,DC=lab,DC=local"

# ─── STEP 6: Create Users ───
# IT Admin
New-ADUser -Name "John Smith" -SamAccountName "jsmith" `
  -UserPrincipalName "jsmith@lab.local" `
  -Path "OU=Users,OU=Corp,DC=lab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "FallSeason2024!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true
Add-ADGroupMember -Identity "Domain Admins" -Members "jsmith"

# HR User
New-ADUser -Name "Ana Garcia" -SamAccountName "agarcia" `
  -UserPrincipalName "agarcia@lab.local" `
  -Path "OU=Users,OU=Corp,DC=lab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Welcome2024!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

# Finance User
New-ADUser -Name "Bob Wilson" -SamAccountName "bwilson" `
  -UserPrincipalName "bwilson@lab.local" `
  -Path "OU=Users,OU=Corp,DC=lab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

# SQL Service Account (Kerberoastable)
New-ADUser -Name "SQL Service" -SamAccountName "svc_sql" `
  -UserPrincipalName "svc_sql@lab.local" `
  -Path "OU=Service Accounts,OU=Corp,DC=lab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "SQLServiceP@ss!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true
# Set SPN for Kerberoasting
Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add="MSSQLSvc/DC02.lab.local:1433"}

# Backup Service Account
New-ADUser -Name "Backup Service" -SamAccountName "svc_backup" `
  -UserPrincipalName "svc_backup@lab.local" `
  -Path "OU=Service Accounts,OU=Corp,DC=lab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Backup2024!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

# ─── STEP 7: Configure Vulnerabilities ───

# AS-REP Roasting (disable preauth for agarcia)
Set-ADAccountControl -Identity "agarcia" -DoesNotRequirePreAuth $true

# Weak Password Policy
Set-ADDefaultDomainPasswordPolicy -Identity "lab.local" `
  -MinPasswordLength 7 `
  -ComplexityEnabled $false `
  -MaxPasswordAge "365.00:00:00"

# Enable WDigest (cleartext passwords in memory)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
  -Name "UseLogonCredential" -Value 1

# Disable SMB Signing (enable relay attacks)
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
Set-SmbClientConfiguration -RequireSecuritySignature $false -Force

# Install ADCS (Certificate Services — for ESC attacks)
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa `
  -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
  -KeyLength 2048 -HashAlgorithmName SHA256 -Force

# ─── STEP 8: Create Groups ───
New-ADGroup -Name "IT-Admins" -GroupScope Global `
  -Path "OU=Groups,OU=Corp,DC=lab,DC=local"
New-ADGroup -Name "HR-Team" -GroupScope Global `
  -Path "OU=Groups,OU=Corp,DC=lab,DC=local"
New-ADGroup -Name "Finance-Team" -GroupScope Global `
  -Path "OU=Groups,OU=Corp,DC=lab,DC=local"

Add-ADGroupMember -Identity "IT-Admins" -Members "jsmith"
Add-ADGroupMember -Identity "HR-Team" -Members "agarcia"
Add-ADGroupMember -Identity "Finance-Team" -Members "bwilson"
```

#### WS01 — Windows 10 Workstation (Domain Joined)

```powershell [PowerShell (Admin)]
# ═══════════════════════════════════════
#  WS01 SETUP — Windows 10/11 Pro
# ═══════════════════════════════════════

# VM Settings:
# CPU:  2 cores
# RAM:  2-4 GB
# Disk: 60 GB
# Net:  Internal/Host-Only (172.16.0.0/24)

# NOTE: You need Windows 10/11 Pro (not Home) for domain join
# Evaluation: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise
# 90-day free trial

# ─── STEP 1: Set Static IP ───
New-NetIPAddress -InterfaceAlias "Ethernet0" `
  -IPAddress 172.16.0.100 `
  -PrefixLength 24 `
  -DefaultGateway 172.16.0.254
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" `
  -ServerAddresses 172.16.0.1

# ─── STEP 2: Rename and Join Domain ───
Rename-Computer -NewName "WS01"
Add-Computer -DomainName "lab.local" `
  -Credential (Get-Credential) `
  -Restart
# Use LAB\Administrator credentials

# ─── STEP 3: Enable Local Admin ───
Set-LocalUser -Name "Administrator" -Password `
  (ConvertTo-SecureString "LocalAdmin2024!" -AsPlainText -Force)
Enable-LocalUser -Name "Administrator"

# ─── STEP 4: Disable Windows Defender (for lab) ───
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
# Or via GPO on DC01 (better approach)

# ─── STEP 5: Disable Firewall (for lab) ───
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# ─── STEP 6: Enable RDP ───
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
  -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# ─── STEP 7: Enable WDigest ───
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest `
  /v UseLogonCredential /t REG_DWORD /d 1 /f

# ─── STEP 8: Install Vulnerable Software ───
# Download and install:
# - PuTTY (old version with stored creds)
# - FileZilla (saved sessions)
# - KeePass (if testing credential access)
# - Office (for macro attacks)
# - Java (old version)
# - Adobe Reader (old version)

# ─── STEP 9: Create Local Users ───
New-LocalUser -Name "localadmin" `
  -Password (ConvertTo-SecureString "Admin123!" -AsPlainText -Force) `
  -PasswordNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member "localadmin"

# ─── STEP 10: Simulate User Activity ───
# Login as domain users to cache credentials
# Start > Switch User > LAB\jsmith
# This creates cached credentials for mimikatz to find
```

#### Verify AD Lab

```powershell [PowerShell (from DC01)]
# ─── VERIFY DOMAIN ───
Get-ADDomain
Get-ADForest
Get-ADDomainController -Filter *
Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled
Get-ADGroup -Filter * | Select-Object Name
Get-ADComputer -Filter * | Select-Object Name, DNSHostName

# ─── VERIFY VULNERABILITIES ───
# Check Kerberoastable accounts
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Check AS-REP Roastable
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}

# Check unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true}

# Check password policy
Get-ADDefaultDomainPasswordPolicy
```

::

### AD Lab Automation Scripts

::accordion
  :::accordion-item
  ---
  icon: i-lucide-zap
  label: "GOAD — Game of Active Directory (Automated)"
  ---

  ```bash [Terminal]
  # GOAD creates a full AD lab automatically!
  # https://github.com/Orange-Cyberdefense/GOAD

  # Includes:
  # - 5 VMs (2 DCs, 2 Servers, 1 Workstation)
  # - Multiple domains with trusts
  # - 30+ AD misconfigurations
  # - Pre-configured for BloodHound
  # - Kerberoasting, AS-REP, Delegation, ADCS, etc.

  # Prerequisites
  # VirtualBox or VMware + Vagrant + Ansible

  git clone https://github.com/Orange-Cyberdefense/GOAD.git
  cd GOAD

  # Check requirements
  ./goad.sh -t check -l GOAD -p virtualbox

  # Install (takes 1-2 hours)
  ./goad.sh -t install -l GOAD -p virtualbox

  # Lab environments available:
  # GOAD      — 5 VMs, 2 domains, full misconfigs
  # GOAD-Light — 3 VMs, 1 domain, essential misconfigs
  # SCCM      — SCCM lab
  # NHA       — Network Hacking Academy
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-zap
  label: "DetectionLab (Blue + Red Team)"
  ---

  ```bash [Terminal]
  # DetectionLab — AD lab with logging/SIEM
  # https://github.com/clong/DetectionLab

  # Includes:
  # - DC, WEF Server, 2 Workstations
  # - Splunk for logging
  # - Sysmon deployed
  # - OSQuery
  # - Great for purple team practice

  git clone https://github.com/clong/DetectionLab.git
  cd DetectionLab/Vagrant
  vagrant up --provider=virtualbox
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-zap
  label: "PurpleCloud (Azure AD Lab)"
  ---

  ```bash [Terminal]
  # PurpleCloud — Deploy AD lab in Azure
  # https://github.com/iknowjason/PurpleCloud

  # Includes:
  # - Full AD environment in Azure
  # - Terraform automation
  # - Multiple attack scenarios
  # - Sentinel SIEM integration

  git clone https://github.com/iknowjason/PurpleCloud.git
  cd PurpleCloud
  # Follow README for Azure deployment
  ```
  :::
::

---

## Network Security Lab

### Adding Security Devices

::tabs
  :::tabs-item{icon="i-lucide-shield" label="pfSense Firewall"}
  ```text
  ┌─────────────────────────────────────────────────┐
  │              pfSense FIREWALL VM                │
  │                                                 │
  │  Purpose: Practice firewall bypass, network     │
  │           segmentation, IDS evasion             │
  │                                                 │
  │  VM Settings:                                   │
  │  ∙ CPU:  1 core                                 │
  │  ∙ RAM:  1 GB                                   │
  │  ∙ Disk: 10 GB                                  │
  │  ∙ NIC1: NAT (WAN — internet)                   │
  │  ∙ NIC2: Internal (LAN — 192.168.1.0/24)        │
  │  ∙ NIC3: Internal (DMZ — 10.10.10.0/24)         │
  │                                                 │
  │  Download: https://www.pfsense.org/download/    │
  │                                                 │
  │  Setup:                                         │
  │  1. Install pfSense on VM                       │
  │  2. Assign WAN (NIC1) and LAN (NIC2)            │
  │  3. Access WebGUI: https://192.168.1.1          │
  │  4. Default: admin / pfsense                    │
  │  5. Configure rules, NAT, IDS                   │
  │                                                 │
  │  Install Packages:                              │
  │  ∙ Snort/Suricata (IDS/IPS)                     │
  │  ∙ pfBlockerNG (DNS filtering)                  │
  │  ∙ OpenVPN                                      │
  │  ∙ Squid (proxy)                                │
  └─────────────────────────────────────────────────┘
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="Security Onion (IDS/SIEM)"}
  ```text
  ┌─────────────────────────────────────────────────┐
  │           SECURITY ONION VM                     │
  │                                                 │
  │  Purpose: Network monitoring, IDS, log          │
  │           analysis, blue team practice          │
  │                                                 │
  │  VM Settings:                                   │
  │  ∙ CPU:  4 cores                                │
  │  ∙ RAM:  8-16 GB                                │
  │  ∙ Disk: 200 GB                                 │
  │  ∙ NIC1: Management (access)                    │
  │  ∙ NIC2: Monitor (span/mirror port)             │
  │                                                 │
  │  Download: https://securityonionsolutions.com   │
  │                                                 │
  │  Includes:                                      │
  │  ∙ Suricata (IDS/IPS)                           │
  │  ∙ Zeek (network analysis)                      │
  │  ∙ Elasticsearch + Kibana (SIEM)                │
  │  ∙ Wazuh (host-based IDS)                       │
  │  ∙ TheHive (incident response)                  │
  │  ∙ Strelka (file analysis)                      │
  │                                                 │
  │  Use: See your attacks from defender perspective│
  └─────────────────────────────────────────────────┘
  ```
  :::
::

### Full Lab Network Diagram with Security

::code-collapse
```text [Complete Lab with Security Devices]
═══════════════════════════════════════════════════════════════════════
           COMPLETE PENTESTING LAB — WITH SECURITY DEVICES
═══════════════════════════════════════════════════════════════════════

                        ┌────���────────┐
                        │  INTERNET   │
                        │  (NAT)      │
                        └──────┬──────┘
                               │
                        ┌──────▼──────┐
                        │  pfSense    │
                        │  FIREWALL   │
                        │             │
                        │ WAN: NAT    │
                        │ LAN: .1     │
                        │ DMZ: .1     │
                        └──┬───┬───┬──┘
                           │   │   │
              ┌────────────┘   │   └────────────┐
              │                │                │
     ┌────────▼──────┐  ┌─────▼──────┐  ┌──────▼────────┐
     │   LAN NETWORK │  │ DMZ NETWORK│  │ SECURITY      │
     │ 192.168.1.0   │  │ 10.10.10.0 │  │ MONITORING    │
     │    /24        │  │   /24      │  │               │
     │               │  │            │  │ ┌───────────┐ │
     │ ∙ Kali (.10)  │  │ ∙ Web Srv  │  │ │  Security │ │
     │ ∙ Parrot (.11)│  │   (.100)   │  │ │  Onion    │ │
     │ ∙ Targets     │  │ ∙ Mail Srv │  │ │  (SIEM)   │ │
     │   (.100-.199) │  │   (.101)   │  │ └───────────┘ │
     │ ∙ Win Targets │  │ ∙ DNS Srv  │  │               │
     │   (.200-.250) │  │   (.102)   │  │ Monitors all  │
     │               │  │            │  │ traffic via    │
     └───────────────┘  └────────────┘  │ span port     │
                                        └───────────────┘
              │
     ┌────────▼───────────────────────────────────────┐
     │            AD NETWORK (172.16.0.0/24)          │
     │                                                │
     │  ┌────────┐  ┌────────┐  ┌────────┐           │
     │  │  DC01  │  │  DC02  │  │  WS01  │ ...       │
     │  │  .1    │  │  .2    │  │  .100  │           │
     │  └────────┘  └────────┘  └────────┘           │
     └────────────────────────────────────────────────┘
```
::

---

## Cloud Lab Setup

::note
Cloud labs are ideal when you **lack local hardware** or need to practice **cloud-specific attacks**. Many offer **free tiers** or **student credits**.
::

::tabs
  :::tabs-item{icon="i-lucide-cloud" label="AWS Lab"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  AWS PENTESTING LAB
  # ═══════════════════════════════════════

  # Free Tier: 12 months, t2.micro instances
  # Student: $100 credit via AWS Educate

  # ─── VPC SETUP ───
  # Create VPC: 10.0.0.0/16
  # Subnet 1 (Public):  10.0.1.0/24  — Kali (attack)
  # Subnet 2 (Private): 10.0.2.0/24  — Targets
  # Subnet 3 (Private): 10.0.3.0/24  — AD Lab
  # Internet Gateway → attached to VPC
  # NAT Gateway → for private subnet internet (updates only)

  # ─── KALI INSTANCE ───
  # AMI: Search "Kali" in AWS Marketplace (official)
  # Instance: t2.medium (2 vCPU, 4 GB RAM)
  # Network: Public subnet
  # Security Group: Allow SSH (22) from your IP only
  # Storage: 30 GB gp3

  # ─── TARGET INSTANCES ───
  # Launch in private subnet
  # Security Group: Allow ALL traffic from Kali's SG only
  # Instance types: t2.micro or t2.small

  # ─── IMPORTANT NOTES ───
  # ✓ AWS allows pentesting YOUR OWN resources
  # ✓ No permission needed for your own account
  # ✗ Do NOT attack other AWS customers
  # ✗ Do NOT perform DDoS
  # ✗ Destroy resources when not in use ($$$!)

  # ─── COST CONTROL ───
  # Set billing alerts
  # Use t2.micro where possible (free tier)
  # Stop instances when not testing
  # Use spot instances for non-persistent labs
  # Terminate everything when done!
  ```
  :::

  :::tabs-item{icon="i-lucide-cloud" label="Azure Lab"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  AZURE PENTESTING LAB
  # ═══════════════════════════════════════

  # Free: $200 credit for 30 days (new accounts)
  # Student: $100/year via Azure for Students
  # Best for: Active Directory labs (native AD support)

  # ─── AZURE AD LAB ───
  # Azure Active Directory is cloud-native
  # Create Azure AD tenant (free)
  # Add users, groups, applications
  # Practice Azure AD attacks:
  #   - Password spraying
  #   - Token manipulation
  #   - Consent grant attacks
  #   - Privileged role abuse

  # ─── VIRTUAL NETWORK ───
  # VNet: 10.0.0.0/16
  # Subnet-Attack:  10.0.1.0/24
  # Subnet-Targets: 10.0.2.0/24
  # Subnet-AD:      10.0.3.0/24
  # NSG: Restrict inbound to your IP

  # ─── AD DS IN AZURE ───
  # Deploy Windows Server VMs
  # Install AD DS role
  # Create domain (same as local lab)
  # Join Windows 10/11 VMs to domain

  # ─── COST CONTROL ───
  # Use B-series VMs (burstable, cheap)
  # Auto-shutdown at night
  # Deallocate when not testing
  # Delete resource group when done
  ```
  :::

  :::tabs-item{icon="i-lucide-cloud" label="Linode/DigitalOcean"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  BUDGET CLOUD LAB ($5-20/month)
  # ═══════════════════════════════════════

  # Linode: $100 free credit (60 days)
  # DigitalOcean: $200 free credit (60 days)
  # Vultr: $100 free credit (30 days)

  # ─── SETUP ───
  # 1. Create account with free credits
  # 2. Deploy Kali droplet/linode
  # 3. Deploy target VMs
  # 4. Use private networking (VLAN)
  # 5. Access via SSH / VNC

  # ─── KALI ON LINODE/DO ───
  # Option 1: Deploy Ubuntu → install Kali tools
  apt update && apt install kali-linux-default -y

  # Option 2: Upload Kali ISO (custom image)
  # Option 3: Use Linode's Kali marketplace image

  # ─── TARGET MACHINES ───
  # Deploy Ubuntu/Debian/CentOS droplets
  # Install vulnerable services manually
  # Or use Docker containers

  # ─── ADVANTAGES ───
  # ✓ Very cheap ($5/month per VM)
  # ✓ No local hardware needed
  # ✓ Fast deployment
  # ✓ Good for quick practice
  # ✗ Limited to Linux (no Windows usually)
  # ✗ No GUI (SSH only)
  ```
  :::
::

---

## Online Practice Platforms

::note
These platforms provide **pre-built labs** you can practice on without building anything yourself. Great for learning and certification prep.
::

::card-group
  ::card
  ---
  icon: i-lucide-terminal
  title: "HackTheBox"
  to: https://hackthebox.com
  target: _blank
  ---
  **The gold standard** for practice machines. 300+ machines of varying difficulty. Active machines (competitive) + retired (with walkthroughs). Free tier available.

  - **Cost:** Free (limited) / $14/month (VIP)
  - **Best For:** OSCP prep, realistic pentesting
  - **Machines:** Windows, Linux, AD, Web, Mobile
  ::

  ::card
  ---
  icon: i-lucide-book-open
  title: "TryHackMe"
  to: https://tryhackme.com
  target: _blank
  ---
  **Best for beginners.** Guided learning paths with browser-based VMs. No local setup needed. Structured from beginner to advanced.

  - **Cost:** Free (limited) / $14/month (Premium)
  - **Best For:** Complete beginners, structured learning
  - **Paths:** "Pre Security", "Jr Penetration Tester", "Red Teaming"
  ::

  ::card
  ---
  icon: i-lucide-flask-conical
  title: "PortSwigger Academy"
  to: https://portswigger.net/web-security
  target: _blank
  ---
  **Best for web security.** 200+ free labs covering every web vulnerability. Created by Burp Suite developers. **Completely free.**

  - **Cost:** FREE
  - **Best For:** Web application security, BSCP certification
  - **Labs:** SQLi, XSS, SSRF, CSRF, XXE, Deserialization, etc.
  ::

  ::card
  ---
  icon: i-lucide-target
  title: "PentesterLab"
  to: https://pentesterlab.com
  target: _blank
  ---
  Progressive exercises from beginner to advanced. Each exercise teaches a specific technique. Great for building skills systematically.

  - **Cost:** Free (basics) / $20/month (Pro)
  - **Best For:** Systematic skill building, web + infrastructure
  ::

  ::card
  ---
  icon: i-lucide-server
  title: "Offensive Security Proving Grounds"
  to: https://www.offsec.com/labs/
  target: _blank
  ---
  Official OSCP practice machines from OffSec. **Play** (community) and **Practice** (OSCP-like) tiers. Essential for OSCP exam prep.

  - **Cost:** Free (Play, limited) / $19/month (Practice)
  - **Best For:** OSCP preparation
  ::

  ::card
  ---
  icon: i-lucide-trophy
  title: "VulnHub"
  to: https://vulnhub.com
  target: _blank
  ---
  **700+ free downloadable VMs** designed to be hacked. Download → import → hack. No subscription needed. Community-created content.

  - **Cost:** FREE
  - **Best For:** Offline practice, variety of challenges
  ::
::

---

## Lab Maintenance Cheat Sheet

::code-collapse
```bash [lab-management.sh]
#!/bin/bash
# ═══════════════════════════════════════════════════════
#  PENTESTING LAB MANAGEMENT CHEAT SHEET
# ═══════════════════════════════════════════════════════

# ═══════════════════════════════════════
# VIRTUALBOX MANAGEMENT
# ═══════════════════════════════════════
# List all VMs
VBoxManage list vms
VBoxManage list runningvms

# Start VM (headless = no GUI window)
VBoxManage startvm "Kali" --type headless
VBoxManage startvm "Metasploitable2" --type headless

# Stop VM
VBoxManage controlvm "Kali" poweroff
VBoxManage controlvm "Kali" savestate  # hibernate

# Snapshot management
VBoxManage snapshot "Kali" take "clean-install"
VBoxManage snapshot "Kali" restore "clean-install"
VBoxManage snapshot "Kali" list

# Clone VM
VBoxManage clonevm "Kali" --name "Kali-Backup" --register

# ═══════════════════════════════════════
# VMWARE MANAGEMENT (vmrun)
# ═══════════════════════════════════════
# Start VM
vmrun start "/path/to/vm.vmx" nogui

# Stop VM
vmrun stop "/path/to/vm.vmx"

# Suspend
vmrun suspend "/path/to/vm.vmx"

# Snapshot
vmrun snapshot "/path/to/vm.vmx" "clean-install"
vmrun revertToSnapshot "/path/to/vm.vmx" "clean-install"
vmrun listSnapshots "/path/to/vm.vmx"

# List running
vmrun list

# ═══════════════════════════════════════
# DOCKER MANAGEMENT
# ═══════════════════════════════════════
# Start all lab containers
docker-compose -f lab-compose.yml up -d

# Stop all
docker-compose -f lab-compose.yml down

# View logs
docker logs <container_name>

# Shell into container
docker exec -it <container_name> /bin/bash

# Clean up
docker system prune -a  # Remove unused images/containers

# ═══════════════════════════════════════
# NETWORK VERIFICATION
# ═══════════════════════════════════════
# From Kali — verify connectivity to all networks
ping -c 1 192.168.1.100  # Target network
ping -c 1 172.16.0.1     # AD network
ping -c 1 8.8.8.8        # Internet (NAT)

# Discover hosts on target network
netdiscover -i eth1 -r 192.168.1.0/24
nmap -sn 192.168.1.0/24

# Discover hosts on AD network
netdiscover -i eth2 -r 172.16.0.0/24
nmap -sn 172.16.0.0/24

# ═══════════════════════════════════════
# LAB RESET PROCEDURE
# ═══════════════════════════════════════
# 1. Revert all target VMs to clean snapshots
# 2. Restart networking on all VMs
# 3. Verify connectivity from Kali
# 4. Clear Kali working directories
# 5. Ready to practice!

# ═══════════════════════════════════════
# BACKUP PROCEDURE
# ═══════════════════════════════════════
# 1. Shutdown all VMs
# 2. Copy VM directories to external drive
# 3. Export as .ova for portability:
VBoxManage export "Kali" -o kali-backup.ova
# 4. Snapshot clean states for quick revert
```
::

---

## Quick Start — Your First Lab in 30 Minutes

::tip
Don't overthink it. Start **small** and **expand** as you learn. Here's the absolute fastest path to a working lab.
::

::steps{level="4"}

#### Download (5 minutes)

```text
1. Download VirtualBox: https://www.virtualbox.org
2. Download Kali VM:    https://www.kali.org/get-kali/#kali-virtual-machines
3. Download Metasploitable 2: https://sourceforge.net/projects/metasploitable/
```

#### Import (10 minutes)

```text
1. Install VirtualBox
2. Import Kali .ova:
   File → Import Appliance → Select Kali .ova → Import
3. Create Metasploitable VM:
   New → Linux → Ubuntu (32-bit) → Use existing .vmdk → Create
```

#### Network (5 minutes)

```text
1. Kali Network:
   Settings → Network → Adapter 1: NAT
   Settings → Network → Adapter 2: Internal Network (name: "pentest-lab")

2. Metasploitable Network:
   Settings → Network → Adapter 1: Internal Network (name: "pentest-lab")
```

#### Boot & Hack (10 minutes)

```bash [Terminal]
# Boot both VMs
# Kali: kali / kali
# Metasploitable: msfadmin / msfadmin

# On Kali — set IP for internal network
sudo ip addr add 192.168.1.10/24 dev eth1
sudo ip link set eth1 up

# On Metasploitable — check IP
ifconfig  # Note the IP (should be on 192.168.x.x)

# From Kali — scan your first target!
nmap -sV -sC 192.168.1.0/24

# Start Metasploit
msfconsole

# Exploit vsftpd backdoor
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <METASPLOITABLE_IP>
exploit

# 🎉 YOU HAVE A SHELL! Your lab is working!
```

::

---

::caution
**Important Reminders:**
- **NEVER** connect vulnerable VMs to the internet or your real network
- **ALWAYS** use Internal/Host-Only networking for targets
- **SNAPSHOT** everything before testing (easy revert)
- **ONLY** practice on systems you own or have explicit permission to test
- **DESTROY** cloud lab resources when not in use (avoid unexpected charges)
::