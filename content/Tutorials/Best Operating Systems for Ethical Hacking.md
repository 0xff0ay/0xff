---
title: Best Operating Systems for Ethical Hacking
description: Best operating systems for ethical hacking, penetration testing, reverse engineering, exploit development, kernel exploitation, OSINT, digital forensics, and CTF/lab platforms like HTB, THM, and OffSec.
navigation:
  icon: i-lucide-monitor-cog
  title: Best OS for Hackers
---

## Why Your OS Choice Matters

Your operating system is your **primary weapon**. Choosing the right OS for your specific discipline — whether it's web pentesting, binary exploitation, malware analysis, or OSINT — can mean the difference between hours of setup frustration and immediately diving into work.

::note
There is no single "best" OS for everything. Expert practitioners typically maintain **multiple specialized VMs** for different tasks. This guide helps you pick the right OS for each discipline.
::

```text [The Ethical Hacker's Workstation]

  ┌─────────────────────────────────────────────────────────────────┐
  │                    HOST MACHINE                                  │
  │              (Windows 11 / macOS / Linux)                        │
  │                                                                  │
  │  ┌─────────────────────────────────────────────────────────────┐│
  │  │                   HYPERVISOR                                 ││
  │  │            (VMware / VirtualBox / Proxmox)                   ││
  │  │                                                              ││
  │  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌────────────┐  ││
  │  │  │  🐉 Kali  │ │ 🦜 Parrot │ │ 🔬 REMnux │ │ 🪟 FlareVM │  ││
  │  │  │  Linux    │ │ Security  │ │ Malware   │ │ Windows RE │  ││
  │  │  │           │ │           │ │ Analysis  │ │            │  ││
  │  │  │ Pentesting│ │ Daily +   │ │ Reverse   │ │ Reverse    │  ││
  │  │  │ CTF Labs  │ │ Privacy   │ │ Engineer  │ │ Engineer   │  ││
  │  │  └───────────┘ └───────────┘ └───────────┘ └────────────┘  ││
  │  │                                                              ││
  │  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌────────────┐  ││
  │  │  │ 🏴 Black  │ │ 🔍 CSI   │ │ 🔎 SIFT   │ │ 🛡️ Whonix  │  ││
  │  │  │ Arch      │ │ Linux    │ │ Workstat  │ │            │  ││
  │  │  │           │ │           │ │           │ │ Anonymous  │  ││
  │  │  │ Advanced  │ │ OSINT    │ │ Digital   │ │ Operations │  ││
  │  │  │ Pentesting│ │ Recon    │ │ Forensics │ │            │  ││
  │  │  └───────────┘ └───────────┘ └───────────┘ └────────────┘  ││
  │  └─────────────────────────────────────────────────────────────┘│
  │                                                                  │
  │  ┌───────────┐ ┌─────────┐ ┌──────────┐ ┌───────────────────┐  │
  │  │ 🌐 VPN    │ │ 📁 Shared│ │ 🔗 NAT / │ │ 📸 Snapshots     │  │
  │  │ (HTB/THM) │ │ Folders │ │ Internal │ │ (Before exploits) │  │
  │  └───────────┘ └─────────┘ └──────────┘ └───────────────────┘  │
  └─────────────────────────────────────────────────────────────────┘
```

---

## Quick Recommendation Matrix

::tip
Use this table to find the best OS for your specific focus area. Most professionals run **2-4 of these** simultaneously.
::

| Discipline                    | Primary OS                    | Secondary OS              | Why                                                 |
| ----------------------------- | ----------------------------- | ------------------------- | --------------------------------------------------- |
| **General Pentesting**        | Kali Linux                    | Parrot Security           | Most tools pre-installed, largest community          |
| **Web App Testing**           | Kali Linux                    | Parrot Security           | Burp Suite, SQLMap, all web tools ready              |
| **Network Pentesting**        | Kali Linux                    | BlackArch                 | Wireshark, Nmap, Responder, all network tools        |
| **Active Directory**          | Kali Linux                    | Commando VM (Windows)     | Need both Linux + Windows tools                     |
| **Reverse Engineering**       | REMnux                        | FlareVM (Windows)         | Specialized RE toolchains for both platforms         |
| **Malware Analysis**          | REMnux                        | FlareVM                   | Isolated analysis environments                       |
| **Exploit Development**       | Kali Linux                    | Custom Ubuntu/Fedora      | GDB, pwntools, compiler toolchains                  |
| **Kernel Exploitation**       | Custom Ubuntu/Fedora          | Kali Linux                | Need specific kernel versions for target matching    |
| **OSINT**                     | CSI Linux / Trace Labs        | Tails                     | Specialized OSINT tools + anonymity                  |
| **Digital Forensics**         | SIFT Workstation              | CAINE / Tsurugi           | Forensic-grade tools, evidence preservation          |
| **Mobile Pentesting**         | Kali Linux + Genymotion       | Santoku                   | Android/iOS toolchains                               |
| **IoT Hacking**               | AttifyOS                      | Kali Linux                | Firmware analysis, hardware tools                    |
| **CTF / Labs (HTB/THM)**      | Kali Linux                    | Parrot Security           | Perfect balance of tools and community support       |
| **OffSec (OSCP/OSEP/OSED)**   | Kali Linux (Official)        | Custom tooled Kali        | OffSec provides official Kali VM                     |
| **Bug Bounty**                | Parrot Security               | Kali Linux                | Lighter, better for daily driving                    |
| **Privacy / Anonymous Ops**   | Tails                         | Whonix                    | Tor routing, anti-forensics                          |
| **Red Teaming**               | Kali Linux + Commando VM     | Parrot + FlareVM          | Need full Windows + Linux attack capability          |
| **Cloud Pentesting**          | Kali Linux                    | Custom (Pacu, ScoutSuite) | Cloud tools + standard pentesting                    |

---

## Penetration Testing Operating Systems

### Kali Linux

```text [Kali Linux Overview]
  ██╗  ██╗ █████╗ ██╗     ██╗    ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗
  ██║ ██╔╝██╔══██╗██║     ██║    ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝
  █████╔╝ ███████║██║     ██║    ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝
  ██╔═██╗ ██╔══██║██║     ██║    ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗
  ██║  ██╗██║  ██║███████╗██║    ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝    ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
```

::tabs
  :::tabs-item{icon="i-lucide-info" label="Overview"}
  | Detail              | Value                                                    |
  | ------------------- | -------------------------------------------------------- |
  | **Base**            | Debian (Testing)                                         |
  | **Maintainer**      | OffSec (Offensive Security)                              |
  | **First Release**   | March 13, 2013 (successor to BackTrack)                  |
  | **Desktop**         | Xfce (default), GNOME, KDE, i3, MATE                    |
  | **Architecture**    | x86_64, ARM, Apple Silicon (M1/M2)                       |
  | **Pre-installed Tools** | 600+ security tools                                  |
  | **Package Manager** | APT (Debian-based)                                       |
  | **Official Site**   | https://www.kali.org                                     |
  | **License**         | Free / Open Source (GPL)                                 |
  | **Default Shell**   | ZSH                                                      |
  | **Platforms**       | VM, Bare Metal, WSL2, Docker, Cloud, USB Live, Android (NetHunter) |

  **Kali Linux is THE industry standard** for penetration testing. It is the **official OS** for OffSec certifications (OSCP, OSEP, OSED, OSWE, OSMR) and the most widely used OS on platforms like HackTheBox, TryHackMe, and PentesterLab.
  :::

  :::tabs-item{icon="i-lucide-package" label="Pre-installed Tools"}
  ```text [Key Tool Categories — 600+ Total]
  INFORMATION GATHERING          WEB APPLICATION
  ─────────────────────          ───────────────
  • Nmap                         • Burp Suite (Community)
  • Masscan                      • OWASP ZAP
  • Recon-ng                     • SQLMap
  • theHarvester                 • Nikto
  • Maltego                      • WPScan
  • Amass                        • Gobuster / Feroxbuster
  • Subfinder                    • Nuclei
  • Shodan CLI                   • Wfuzz / ffuf

  EXPLOITATION                   PASSWORD ATTACKS
  ────────────                   ────────────────
  • Metasploit Framework         • John the Ripper
  • SearchSploit / ExploitDB     • Hashcat
  • BeEF                         • Hydra
  • RouterSploit                 • Medusa
  • Social Engineering Toolkit   • CeWL
                                 • Crunch

  WIRELESS                       REVERSE ENGINEERING
  ────────                       ───────────────────
  • Aircrack-ng Suite            • Ghidra
  • Wifite                       • Radare2 / Rizin
  • Kismet                       • GDB + GEF/pwndbg
  • Fern WiFi Cracker            • objdump / readelf
  • Bully / Reaver               • strace / ltrace

  POST-EXPLOITATION              FORENSICS
  ─────────────────              ─────────
  • Empire                       • Autopsy
  • Mimikatz (via Wine)          • Binwalk
  • Impacket Suite               • Volatility
  • CrackMapExec / NetExec       • Foremost
  • Evil-WinRM                   • Sleuth Kit
  • BloodHound                   • bulk_extractor

  SNIFFING / SPOOFING            REPORTING
  ─────────────────              ─────────
  • Wireshark                    • Dradis Framework
  • Responder                    • Faraday
  • Bettercap                    • Pipal
  • mitmproxy                    • CherryTree
  • Ettercap                     • Sysreptor
  ```
  :::

  :::tabs-item{icon="i-lucide-download" label="Installation"}
  ```bash [Download Kali Linux]
  # Official download
  # https://www.kali.org/get-kali/

  # Pre-built VM images available for:
  # • VMware    (.vmx)
  # • VirtualBox (.ova)
  # • Hyper-V   (.vhdx)
  # • QEMU      (.qcow2)
  # • UTM/Parallels (Apple Silicon)
  ```

  ```bash [Docker]
  docker pull kalilinux/kali-rolling
  docker run -it kalilinux/kali-rolling /bin/bash

  # Install tool meta-packages
  apt update && apt install -y kali-linux-headless
  ```

  ```bash [WSL2 (Windows)]
  wsl --install -d kali-linux
  ```

  ```bash [Cloud (AWS)]
  # Kali Linux is available on AWS Marketplace
  # Search: "Kali Linux" in AWS Marketplace
  # Launch as EC2 instance
  ```

  ```bash [Kali Meta-Packages]
  # Install specific tool groups
  sudo apt install -y kali-linux-default       # Standard tools (~8GB)
  sudo apt install -y kali-linux-large         # Extended tools (~15GB)
  sudo apt install -y kali-linux-everything    # ALL tools (~25GB)
  sudo apt install -y kali-tools-web           # Web testing only
  sudo apt install -y kali-tools-exploitation  # Exploitation only
  sudo apt install -y kali-tools-forensics     # Forensics only
  sudo apt install -y kali-tools-passwords     # Password tools only
  sudo apt install -y kali-tools-reverse-engineering  # RE tools
  sudo apt install -y kali-tools-wireless      # Wireless tools
  sudo apt install -y kali-tools-sniffing-spoofing    # Network tools
  ```
  :::

  :::tabs-item{icon="i-lucide-star" label="Best For"}
  - ✅ **HTB / TryHackMe / OffSec labs** — The default and best-supported OS
  - ✅ **OSCP / OSEP / OSWE / OSED** — Official OffSec exam environment
  - ✅ **General penetration testing** — Everything pre-installed
  - ✅ **Network pentesting** — Complete toolchain
  - ✅ **Web application testing** — Burp, SQLMap, Nuclei, etc.
  - ✅ **Active Directory attacks** — Impacket, BloodHound, CrackMapExec
  - ✅ **CTF competitions** — Most writeups/guides assume Kali
  - ✅ **Learning** — Massive community, tutorials, and documentation
  - ⚠️ Not ideal as a daily driver desktop OS
  - ⚠️ Heavy resource usage with full tool installs
  :::
::

### Parrot Security OS

```text [Parrot Security Logo]
  ██████╗  █████╗ ██████╗ ██████╗  ██████╗ ████████╗
  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝
  ██████╔╝███████║██████╔╝██████╔╝██║   ██║   ██║
  ██╔═══╝ ██╔══██║██╔══██╗██╔══██╗██║   ██║   ██║
  ██║     ██║  ██║██║  ██║██║  ██║╚██████╔╝   ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝
            Security  🦜  OS
```

::tabs
  :::tabs-item{icon="i-lucide-info" label="Overview"}
  | Detail              | Value                                                    |
  | ------------------- | -------------------------------------------------------- |
  | **Base**            | Debian (Stable)                                          |
  | **Maintainer**      | Parrot Security CIC                                      |
  | **First Release**   | April 10, 2013                                           |
  | **Desktop**         | MATE (default), KDE, Xfce                                |
  | **Architecture**    | x86_64, ARM                                              |
  | **Pre-installed Tools** | 600+ security tools                                  |
  | **Package Manager** | APT                                                      |
  | **Official Site**   | https://parrotsec.org                                    |
  | **Editions**        | Security, Home, HTB, Cloud, Architect                    |
  | **Unique Feature**  | AnonSurf (Tor integration), lighter than Kali            |

  Parrot is the **best alternative to Kali** and many consider it superior for **daily driving**. It's lighter, more privacy-focused, and includes AnonSurf for Tor-based anonymization. Parrot also has an official **HackTheBox edition**.
  :::

  :::tabs-item{icon="i-lucide-shield" label="Why Choose Parrot"}
  ```text [Kali vs Parrot Comparison]
  Feature                    Kali Linux        Parrot Security
  ───────────────────────    ──────────        ───────────────
  Base                       Debian Testing    Debian Stable
  Stability                  Good              Better (Stable base)
  RAM Usage (idle)           ~800 MB           ~400 MB
  Disk Space (default)       ~15 GB            ~10 GB
  Privacy Tools              Basic             AnonSurf, Tor, I2P
  Daily Driver               ⚠️ Not ideal      ✅ Designed for it
  Tool Count                 600+              600+
  Community Size             Massive           Large
  OffSec Certification       ✅ Official        ⚠️ Works but not official
  HackTheBox Edition         ❌                 ✅ Official HTB Edition
  Sandbox / Firejail         ❌                 ✅ Built-in
  Crypto Tools               Basic             ✅ Enhanced
  Development Tools          Basic             ✅ Full dev environment
  ```
  :::

  :::tabs-item{icon="i-lucide-download" label="Editions"}
  | Edition           | Use Case                                           |
  | ----------------- | -------------------------------------------------- |
  | **Security**      | Full pentesting suite (equivalent to Kali default)  |
  | **Home**          | Daily driver with privacy tools (no hacking tools)  |
  | **HTB Edition**   | Tailored for HackTheBox with Pwnbox integration     |
  | **Cloud**         | Server edition for cloud pentesting environments    |
  | **Architect**     | Minimal installer for custom builds                 |
  | **Raspberry Pi**  | ARM edition for portable pentesting                 |

  ```bash [Install Parrot]
  # Download from https://parrotsec.org/download/
  # Available as ISO, OVA, Docker

  # Docker
  docker pull parrotsec/security
  docker run -it parrotsec/security /bin/bash
  ```
  :::

  :::tabs-item{icon="i-lucide-star" label="Best For"}
  - ✅ **Daily driver** + pentesting in one OS
  - ✅ **Privacy-conscious** operations with AnonSurf
  - ✅ **HackTheBox** — Official HTB Pwnbox edition
  - ✅ **Bug bounty** hunting — lightweight, always ready
  - ✅ **Development** + pentesting simultaneously
  - ✅ **Lower-spec hardware** — runs well on 2GB RAM
  - ✅ **Anonymized** reconnaissance and OSINT
  :::
::

### BlackArch Linux

```text [BlackArch Logo]
  ██████╗ ██╗      █████╗  ██████╗██╗  ██╗ █████╗ ██████╗  ██████╗██╗  ██╗
  ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔══██╗██╔════╝██║  ██║
  ██████╔╝██║     ███████║██║     █████╔╝ ███████║██████╔╝██║     ███████║
  ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██║██╔══██╗██║     ██╔══██║
  ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║  ██║██║  ██║╚██████╗██║  ██║
  ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

::tabs
  :::tabs-item{icon="i-lucide-info" label="Overview"}
  | Detail              | Value                                                    |
  | ------------------- | -------------------------------------------------------- |
  | **Base**            | Arch Linux                                               |
  | **Maintainer**      | BlackArch Linux Team                                     |
  | **Architecture**    | x86_64                                                   |
  | **Pre-installed Tools** | **2800+** security tools (largest collection)         |
  | **Package Manager** | pacman                                                   |
  | **Official Site**   | https://blackarch.org                                    |
  | **Install Method**  | Full ISO or add repository to existing Arch              |
  | **Unique Feature**  | Can be layered on top of any Arch installation           |

  BlackArch has the **largest security tool collection** of any OS — over **2800 tools**. It is based on Arch Linux, giving you access to the bleeding-edge software via the AUR.
  :::

  :::tabs-item{icon="i-lucide-download" label="Installation"}
  ```bash [Add BlackArch to Existing Arch Linux]
  # This is the recommended approach — add BlackArch repos to your Arch install
  curl -O https://blackarch.org/strap.sh
  echo "5ea40d49ecd14c2e024deecf90605426db97571a strap.sh" | sha1sum -c
  chmod +x strap.sh
  sudo ./strap.sh

  # Now install tools via pacman
  sudo pacman -Syu

  # Install all BlackArch tools (~50GB)
  sudo pacman -S blackarch

  # Or install by category
  sudo pacman -S blackarch-webapp
  sudo pacman -S blackarch-exploitation
  sudo pacman -S blackarch-recon
  sudo pacman -S blackarch-forensic
  sudo pacman -S blackarch-reversing
  sudo pacman -S blackarch-cracker
  sudo pacman -S blackarch-scanner
  sudo pacman -S blackarch-wireless
  sudo pacman -S blackarch-malware
  ```
  :::

  :::tabs-item{icon="i-lucide-star" label="Best For"}
  - ✅ **Advanced users** who want Arch's flexibility + security tools
  - ✅ **Largest tool collection** — 2800+ tools
  - ✅ **Bleeding-edge software** via Arch repos + AUR
  - ✅ **Custom builds** — pick exactly what you need
  - ✅ **Rolling release** — always up to date
  - ⚠️ Steep learning curve (Arch-based)
  - ⚠️ Not beginner-friendly
  - ⚠️ Requires manual configuration
  :::
::

### Commando VM

```text [Commando VM Logo]
   ██████╗ ██████╗ ███╗   ███╗███╗   ███╗ █████╗ ███╗   ██╗██████╗  ██████╗
  ██╔════╝██╔═══██╗████╗ ████║████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔═══██╗
  ██║     ██║   ██║██╔████╔██║██╔████╔██║███████║██╔██╗ ██║██║  ██║██║   ██║
  ██║     ██║   ██║██║╚██╔╝██║██║╚██╔╝██║██╔══██║██║╚██╗██║██║  ██║██║   ██║
  ╚██████╗╚██████╔╝██║ ╚═╝ ██║██║ ╚═╝ ██║██║  ██║██║ ╚████║██████╔╝╚██████╔╝
   ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝  ╚═════╝
                          VM  🪟  (Windows-Based)
```

::tabs
  :::tabs-item{icon="i-lucide-info" label="Overview"}
  | Detail              | Value                                                    |
  | ------------------- | -------------------------------------------------------- |
  | **Base**            | Windows 10/11                                            |
  | **Maintainer**      | Mandiant (FireEye)                                       |
  | **Architecture**    | x86_64                                                   |
  | **Pre-installed Tools** | 200+ Windows-based security tools                    |
  | **Package Manager** | Chocolatey + custom scripts                              |
  | **Official Site**   | https://github.com/mandiant/commando-vm                  |
  | **Install Method**  | PowerShell script on existing Windows VM                 |
  | **Unique Feature**  | Full Windows pentesting environment                      |

  Commando VM transforms a **Windows machine into a pentesting platform**. Essential for Active Directory attacks, Windows exploitation, .NET reverse engineering, and running native Windows security tools.
  :::

  :::tabs-item{icon="i-lucide-package" label="Tools Included"}
  ```text [Commando VM Tool Categories]
  ACTIVE DIRECTORY               RECONNAISSANCE
  ────────────────               ──────────────
  • BloodHound                   • Nmap
  • Rubeus                       • Advanced IP Scanner
  • SharpHound                   • Angry IP Scanner
  • PowerView                    • Fping
  • ADModule                     • Wireshark
  • Certify                      • NetworkMiner
  • Whisker

  EXPLOITATION                   REVERSE ENGINEERING
  ────────────                   ───────────────────
  • Metasploit                   • IDA Free
  • Covenant                     • x64dbg / x32dbg
  • CobaltStrike (if licensed)   • dnSpy
  • PowerSploit                  • Ghidra
  • Impacket                     • PE-bear
                                 • HxD Hex Editor
  PASSWORD                       • dotPeek
  ────────
  • Hashcat                      UTILITIES
  • John the Ripper              ─────────
  • Mimikatz (native!)           • 7-Zip
  • LaZagne                      • Sysinternals Suite
  • KeeThief                     • Process Hacker
  • Responder-Windows            • CyberChef
                                 • Git / Python / Go
  WEB TESTING
  ───────────
  • Burp Suite
  • OWASP ZAP
  • Fiddler
  • Postman
  ```
  :::

  :::tabs-item{icon="i-lucide-download" label="Installation"}
  ```powershell [Install Commando VM]
  # Prerequisites:
  # 1. Fresh Windows 10/11 VM (60GB+ disk)
  # 2. Windows Defender disabled
  # 3. Windows Updates current

  # Step 1: Open PowerShell as Administrator
  Set-ExecutionPolicy Unrestricted -Force

  # Step 2: Download installer
  iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/mandiant/commando-vm/main/install.ps1'))

  # Step 3: Follow the GUI installer
  # Installation takes 2-4 hours depending on internet speed
  ```
  :::

  :::tabs-item{icon="i-lucide-star" label="Best For"}
  - ✅ **Active Directory** pentesting (native Windows tools)
  - ✅ **Mimikatz** runs natively (no Wine needed)
  - ✅ **.NET reverse engineering** with dnSpy, dotPeek
  - ✅ **Windows exploit development** with Visual Studio
  - ✅ **Malware analysis** (Windows-native samples)
  - ✅ **Sysinternals Suite** for post-exploitation
  - ✅ Pairs perfectly with Kali for dual-OS red teaming
  :::
::

---

## Reverse Engineering & Malware Analysis

### REMnux

```text [REMnux Logo]
  ██████╗ ███████╗███╗   ███╗███╗   ██╗██╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝████╗ ████║████╗  ██║██║   ██║╚██╗██╔╝
  ██████╔╝█████╗  ██╔████╔██║██╔██╗ ██║██║   ██║ ╚███╔╝
  ██╔══██╗██╔══╝  ██║╚██╔╝██║██║╚██╗██║██║   ██║ ██╔██╗
  ██║  ██║███████╗██║ ╚═╝ ██║██║ ╚████║╚██████╔╝██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
                    🔬 Malware Analysis Toolkit
```

::tabs
  :::tabs-item{icon="i-lucide-info" label="Overview"}
  | Detail              | Value                                                    |
  | ------------------- | -------------------------------------------------------- |
  | **Base**            | Ubuntu 20.04 LTS                                         |
  | **Maintainer**      | Lenny Zeltser (SANS Instructor)                          |
  | **Purpose**         | Malware analysis & reverse engineering                   |
  | **Architecture**    | x86_64                                                   |
  | **Official Site**   | https://remnux.org                                       |
  | **Install Method**  | OVA VM, standalone installer, or Docker                  |
  | **Unique Feature**  | Purpose-built for analyzing malicious software           |

  REMnux is the **gold standard for malware analysis** on Linux. Created by SANS instructor Lenny Zeltser, it provides a curated collection of tools specifically designed for examining malicious software, reverse engineering binaries, and analyzing network traffic from malware.
  :::

  :::tabs-item{icon="i-lucide-package" label="Tools Included"}
  ```text [REMnux Tool Categories]
  STATIC ANALYSIS                DYNAMIC ANALYSIS
  ───────────────                ────────────────
  • Ghidra                       • Cuckoo Sandbox
  • Radare2 / Rizin              • YARA rules
  • RetDec (Decompiler)          • Fakenet-NG
  • Binary Ninja (if licensed)   • INetSim
  • objdump / readelf            • mitmproxy
  • file / strings / xxd         • Wireshark
  • FLOSS (FireEye)              • PolarProxy
  • die (Detect It Easy)

  DOCUMENT ANALYSIS              MEMORY FORENSICS
  ─────────────────              ────────────────
  • olevba (Office macros)       • Volatility 2 & 3
  • pdf-parser                   • Rekall
  • pdfid                        • Volatility plugins
  • XLMDeobfuscator
  • oletools suite               NETWORK ANALYSIS
                                 ────────────────
  PE/ELF ANALYSIS                • Wireshark
  ─────────────                  • NetworkMiner
  • pev / readpe                 • ngrep
  • PE-sieve                     • Bro/Zeek
  • UPX (unpacker)               • Suricata
  • peframe
  • CAPEv2 integration           SCRIPTING
                                 ──���──────
  JAVASCRIPT/WEB                 • Python 3 + libraries
  ───────────────                • CyberChef
  • SpiderMonkey                 • Didier Stevens tools
  • Node.js                      • REMnux Docker images
  • de4js (deobfuscator)
  • box-js (JScript analysis)
  ```
  :::

  :::tabs-item{icon="i-lucide-download" label="Installation"}
  ```bash [Install REMnux]
  # Option 1: Download pre-built VM
  # https://remnux.org/#distro (OVA format)

  # Option 2: Install on existing Ubuntu 20.04
  wget https://REMnux.org/remnux-cli
  mv remnux-cli /usr/local/bin/remnux
  chmod +x /usr/local/bin/remnux
  sudo remnux install

  # Option 3: Docker
  docker pull remnux/remnux-distro
  docker run -it remnux/remnux-distro /bin/bash
  ```
  :::

  :::tabs-item{icon="i-lucide-star" label="Best For"}
  - ✅ **Malware analysis** — the definitive Linux environment
  - ✅ **Reverse engineering** Linux/ELF binaries
  - ✅ **Network traffic analysis** from malware samples
  - ✅ **Document analysis** — Office macros, PDFs, scripts
  - ✅ **SANS FOR610** (Reverse-Engineering Malware) course
  - ✅ **Memory forensics** with Volatility
  - ✅ Pair with **FlareVM** for complete Windows + Linux RE
  :::
::

### FlareVM

```text [FlareVM Logo]
  ███████╗██╗      █████╗ ██████╗ ███████╗    ██╗   ██╗███╗   ███╗
  ██╔════╝██║     ██╔══██╗██╔══██╗██╔════╝    ██║   ██║████╗ ████║
  █████╗  ██║     ███████║██████╔╝█████╗      ██║   ██║██╔████╔██║
  ██╔══╝  ██║     ██╔══██║██╔══██╗██╔══╝      ╚██╗ ██╔╝██║╚██╔╝██║
  ██║     ███████╗██║  ██║██║  ██║███████╗      ╚████╔╝ ██║ ╚═╝ ██║
  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝       ╚═══╝  ╚═╝     ╚═╝
                    🔥 Windows Reverse Engineering
```

| Detail              | Value                                                    |
| ------------------- | -------------------------------------------------------- |
| **Base**            | Windows 10/11                                            |
| **Maintainer**      | Mandiant (Google)                                        |
| **Purpose**         | Windows malware analysis & reverse engineering           |
| **Official Site**   | https://github.com/mandiant/flare-vm                     |
| **Install Method**  | PowerShell script on Windows VM                          |
| **Key Difference**  | FlareVM = RE/Malware Analysis, Commando = Pentesting     |

```text [FlareVM Key Tools]
DISASSEMBLERS / DECOMPILERS      DEBUGGERS
───────────────────────────      ─────────
• IDA Free / IDA Pro             • x64dbg / x32dbg
• Ghidra                         • WinDbg
• Binary Ninja                   • OllyDbg
• Cutter (Rizin GUI)             • dnSpy (.NET debugger)
• JD-GUI (Java decompiler)       • Immunity Debugger

PE ANALYSIS                      UTILITIES
───────────                      ─────────
• PE-bear                        • Sysinternals Suite
• CFF Explorer                   • Process Monitor
• Detect It Easy (die)           • Process Hacker
• Resource Hacker                • HxD Hex Editor
• PEiD                           • CyberChef
• pestudio                       • Fiddler / Burp Suite

MALWARE ANALYSIS                 SCRIPTING
────────────────                 ─────────
• YARA                           • Python 3
• Cuckoo Sandbox                 • PowerShell
• Fakenet-NG                     • Ruby
• Floss (string extraction)      • Go
• CAPE integration               • Node.js
```

```powershell [Install FlareVM]
# Prerequisites:
# 1. Fresh Windows 10/11 VM
# 2. Disable Windows Defender & Updates
# 3. Take a snapshot first!

# Install
Set-ExecutionPolicy Unrestricted -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1'))

# Installation takes 1-3 hours
```

::tip
**REMnux + FlareVM** is the **ultimate reverse engineering combination**. Use REMnux for Linux/ELF analysis and network simulation, and FlareVM for Windows PE analysis and debugging. Run them on the same internal network for malware traffic capture.
::

---

## OSINT Operating Systems

### CSI Linux

```text [CSI Linux Logo]
   ██████╗███████╗██╗    ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗
  ██╔════╝██╔════╝██║    ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝
  ██║     ███████╗██║    ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝
  ██║     ╚════██║██║    ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗
  ╚██████╗███████║██║    ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗
   ╚═════╝╚══════╝╚═╝    ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
                   🔍 OSINT Investigation Platform
```

::tabs
  :::tabs-item{icon="i-lucide-info" label="Overview"}
  | Detail              | Value                                                    |
  | ------------------- | -------------------------------------------------------- |
  | **Base**            | Ubuntu                                                   |
  | **Maintainer**      | CSI Linux / Information Warfare Center                   |
  | **Purpose**         | OSINT, cyber investigation, digital forensics            |
  | **Official Site**   | https://csilinux.com                                     |
  | **Editions**        | Analyst (OSINT), Investigator (Full), Gateway (TOR)      |
  | **Unique Feature**  | Case management + Tor gateway + Dark web investigation   |
  :::

  :::tabs-item{icon="i-lucide-package" label="Tools Included"}
  ```text [CSI Linux OSINT Tools]
  SOCIAL MEDIA OSINT             DARK WEB INVESTIGATION
  ────────────────               ──────────────────────
  • Sherlock                     • Tor Browser
  • Social Analyzer              • OnionScan
  • Twint (Twitter)              • Dark Web Crawlers
  • Instagram Scraper            • .onion Discovery
  • Facebook Toolkit             • Tor Gateway (isolated)
  • SpiderFoot

  EMAIL / IDENTITY               GEO / IMAGE
  ──────────────                 ────────────
  • theHarvester                 • ExifTool
  • h8mail                       • Geolocation tools
  • Holehe                       • Image forensics
  • GHunt (Google)               • Reverse image search
  • Maigret                      • Satellite imagery tools

  DOMAIN / NETWORK               CASE MANAGEMENT
  ──────────────                 ────────────────
  • Maltego                      • Autopsy
  • Recon-ng                     • CaseFile
  • Amass                        • Timeline tools
  • WHOIS / DNS tools            • Report generators
  • Shodan CLI                   • Evidence management
  ```
  :::

  :::tabs-item{icon="i-lucide-star" label="Best For"}
  - ✅ **OSINT investigations** — the most complete OSINT platform
  - ✅ **Dark web research** — isolated Tor gateway
  - ✅ **Law enforcement** investigations
  - ✅ **Missing persons** investigations
  - ✅ **Social media** intelligence gathering
  - ✅ **Case management** with evidence tracking
  - ✅ **Trace Labs OSINT CTF** competitions
  :::
::

### Trace Labs OSINT VM

| Detail              | Value                                                    |
| ------------------- | -------------------------------------------------------- |
| **Base**            | Kali Linux                                               |
| **Maintainer**      | Trace Labs                                               |
| **Purpose**         | OSINT for missing persons investigations                 |
| **Official Site**   | https://www.tracelabs.org/initiatives/osint-vm            |
| **Unique Feature**  | Pre-configured for Trace Labs OSINT CTF events           |

```text [Trace Labs OSINT Tools]
• Maltego          • Spiderfoot       • theHarvester
• Recon-ng         • Shodan           • Metagoofil
• ExifTool         • Sherlock         • h8mail
• Twint            • Photon           • WebHTTrack
• Creepy           • Instaloader      • YouTube-dl
• Sublist3r        • GHunt            • Maigret
```

```bash [Install Trace Labs VM]
# Download OVA from https://www.tracelabs.org/initiatives/osint-vm
# Or build from Kali:
git clone https://github.com/tracelabs/tlosint-live
cd tlosint-live
./build.sh
```

---

## Digital Forensics Operating Systems

### SANS SIFT Workstation

```text [SIFT Workstation Logo]
  ███████╗██╗███████╗████████╗
  ██╔════╝██║██╔════╝╚══██╔══╝
  ███████╗██║█████╗     ██║
  ╚════██║██║██╔══╝     ██║
  ███████║██║██║        ██║
  ╚══════╝╚═╝╚═╝        ╚═╝
  SANS Investigative Forensics Toolkit 🔎
```

::tabs
  :::tabs-item{icon="i-lucide-info" label="Overview"}
  | Detail              | Value                                                    |
  | ------------------- | -------------------------------------------------------- |
  | **Base**            | Ubuntu 20.04 LTS                                         |
  | **Maintainer**      | SANS Digital Forensics & Incident Response               |
  | **Purpose**         | Digital forensics and incident response (DFIR)           |
  | **Official Site**   | https://www.sans.org/tools/sift-workstation/              |
  | **Install Method**  | OVA VM or CAST installer on Ubuntu                       |
  | **Used In**         | SANS FOR500, FOR508, FOR572, FOR498 courses              |
  | **Unique Feature**  | Forensic-grade evidence handling and chain of custody     |
  :::

  :::tabs-item{icon="i-lucide-package" label="Tools Included"}
  ```text [SIFT Forensics Tools]
  DISK / FILE FORENSICS          MEMORY FORENSICS
  ─────────────────────          ────────────────
  • Autopsy                      • Volatility 2 & 3
  • Sleuth Kit (TSK)             • Rekall
  • FTK Imager (via Wine)        • Volatility plugins
  • dc3dd / dcfldd               • LiME (Linux Memory)
  • Foremost / Scalpel
  • bulk_extractor               NETWORK FORENSICS
  • plaso (log2timeline)         ────────────────
  • YARA                         • Wireshark
                                 • NetworkMiner
  ARTIFACT ANALYSIS              • Zeek (Bro)
  ─────────────────              • ngrep
  • RegRipper                    • tcpflow
  • Prefetch Parser
  • ShimCache Parser             TIMELINE ANALYSIS
  • NTFS artifacts               ─────────────────
  • Event Log parsers            • log2timeline (plaso)
  • Browser forensics            • Timesketch
  • Email parsers                • mactime (TSK)
  ```
  :::

  :::tabs-item{icon="i-lucide-star" label="Best For"}
  - ✅ **SANS DFIR courses** — official lab environment
  - ✅ **Professional digital forensics** — court-admissible evidence
  - ✅ **Incident response** — analyze compromised systems
  - ✅ **Memory forensics** — Volatility integration
  - ✅ **Timeline analysis** — plaso/log2timeline workflows
  - ✅ **Disk imaging** and artifact recovery
  - ✅ **GIAC certifications** (GCFE, GCFA, GNFA)
  :::
::

### CAINE

| Detail              | Value                                                    |
| ------------------- | -------------------------------------------------------- |
| **Base**            | Ubuntu                                                   |
| **Maintainer**      | Nanni Bassetti                                           |
| **Purpose**         | Computer forensics (Italian-origin project)              |
| **Official Site**   | https://www.caine-live.net                               |
| **Unique Feature**  | Boot in forensic mode — never auto-mounts evidence drives |
| **Boot Options**    | Live USB forensic mode (read-only by default)            |

```text [CAINE Key Features]
• Forensic boot mode (no auto-mount, no swap, no write)
• Autopsy / Sleuth Kit integration
• Guymager for disk imaging
• HashDeep / md5deep for verification
• Wireshark for network forensics
• Timeline analysis tools
• Evidence reporting templates
• Italian & English interface
```

### Tsurugi Linux

| Detail              | Value                                                    |
| ------------------- | -------------------------------------------------------- |
| **Base**            | Ubuntu LTS                                               |
| **Maintainer**      | Tsurugi Linux Project (Italian team)                     |
| **Purpose**         | DFIR, malware analysis, OSINT, threat intelligence       |
| **Official Site**   | https://tsurugi-linux.org                                |
| **Editions**        | Lab (full), Acquire (imaging only), Bento (portable)     |
| **Unique Feature**  | Combines forensics + OSINT + malware analysis            |

```text [Tsurugi Editions]
┌────────────────┐  ┌────────────────┐  ┌────────────────┐
│  TSURUGI LAB   │  │ TSURUGI ACQUIRE│  │  BENTO         │
│                │  │                │  │                │
│ Full DFIR suite│  │ Imaging-only   │  │ Portable       │
│ + Malware      │  │ boot disk      │  │ collection of  │
│ + OSINT        │  │ for evidence   │  │ Windows DFIR   │
│ + Threat Intel │  │ acquisition    │  │ tools          │
│                │  │                │  │                │
│ ~15GB          │  │ ~2GB           │  │ ~5GB           │
└────────────────┘  └────────────────┘  └────────────────┘
```

---

## Privacy & Anonymity

### Tails

```text [Tails Logo]
  ████████╗ █████╗ ██╗██╗     ███████╗
  ╚══██╔══╝██╔══██╗██║██║     ██╔════╝
     ██║   ███████║██║██║     ███████╗
     ██║   ██╔══██║██║██║     ╚════██║
     ██║   ██║  ██║██║███████╗███████║
     ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
     The Amnesic Incognito Live System 🕵️
```

| Detail              | Value                                                    |
| ------------------- | -------------------------------------------------------- |
| **Base**            | Debian                                                   |
| **Maintainer**      | Tails Project                                            |
| **Purpose**         | Privacy, anonymity, anti-surveillance                    |
| **Official Site**   | https://tails.net                                        |
| **Boot Method**     | USB only (amnesic — leaves no trace)                     |
| **Network**         | ALL traffic routed through Tor                           |
| **Unique Feature**  | Forgets everything on shutdown (amnesic)                 |
| **Endorsed By**     | Edward Snowden, EFF, journalists, whistleblowers         |

```text [Tails Security Model]
  ┌─────────────────────────────────────────────────────┐
  │                    TAILS OS                          │
  │                                                     │
  │  ┌───────────────────────────────────────────────┐  │
  │  │              ALL TRAFFIC                      │  │
  │  │                   │                           │  │
  │  │                   ▼                           │  │
  │  │           ┌──────────────┐                    │  │
  │  │           │  TOR NETWORK │                    │  │
  │  │           │  ┌──┐ ┌──┐ ┌──┐                  │  │
  │  │           │  │E1│→│R1│→│E2│→ Internet        │  │
  │  │           │  └──┘ └──┘ └──┘                  │  │
  │  │           │  Entry  Relay  Exit              │  │
  │  │           └──────────────┘                    │  │
  │  │                                               │  │
  │  │  • No data written to disk                    │  │
  │  │  • RAM wiped on shutdown                      │  │
  │  │  • MAC address spoofed                        │  │
  │  │  • No direct internet (Tor only)              │  │
  │  │  • Encrypted persistent storage (optional)    │  │
  │  └───────────────────────────────────────────────┘  │
  │                                                     │
  │  On Shutdown: 💨 Everything disappears              │
  └─────────────────────────────────────────────────────┘
```

::warning
Tails is designed for **privacy and anonymity**, NOT for active pentesting. Use it for OSINT reconnaissance, anonymous research, and protecting your identity during information gathering phases.
::

### Whonix

```text [Whonix Logo]
  ██╗    ██╗██╗  ██╗ ██████╗ ███╗   ██╗██╗██╗  ██╗
  ██║    ██║██║  ██║██╔═══██╗████╗  ██║██║╚██╗██╔╝
  ██║ █╗ ██║███████║██║   ██║██╔██╗ ██║██║ ╚███╔╝
  ██║███╗██║██╔══██║██║   ██║██║╚██╗██║██║ ██╔██╗
  ╚███╔███╔╝██║  ██║╚██████╔╝██║ ╚████║██║██╔╝ ██╗
   ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
                    🛡️ Anonymous by Design
```

| Detail              | Value                                                    |
| ------------------- | -------------------------------------------------------- |
| **Base**            | Debian + KVM/VirtualBox                                  |
| **Maintainer**      | Whonix Project                                           |
| **Purpose**         | Maximum anonymity through Tor isolation                  |
| **Official Site**   | https://www.whonix.org                                   |
| **Architecture**    | Two-VM design (Gateway + Workstation)                    |
| **Unique Feature**  | IP/DNS leak impossible by design                         |

```text [Whonix Two-VM Architecture]

  ┌──────────────────────────────────────────────────────────┐
  │                     HOST MACHINE                          │
  │                                                          │
  │  ┌────────────────────┐    ┌─────────────────────────┐  │
  │  │  WHONIX GATEWAY    │    │  WHONIX WORKSTATION     │  │
  │  │                    │    │                          │  │
  │  │  • Runs Tor        │◄──►│  • Your work happens    │  │
  │  │  • Routes ALL      │    │    here                  │  │
  │  │    traffic thru Tor│    │  • Cannot access         │  │
  │  │  • Firewall blocks │    │    internet directly     │  │
  │  │    non-Tor traffic │    │  • ALL traffic goes      │  │
  │  │                    │    │    through Gateway        │  │
  │  │  IP: 10.152.152.10 │    │  IP: 10.152.152.11      │  │
  │  └────────┬───────────┘    └──────────────────────────┘  │
  │           │                                               │
  │           ▼                                               │
  │     ┌──────────┐                                         │
  │     │ Internet │ ◄── Only via Tor. IP leaks impossible.  │
  │     └──────────┘                                         │
  └──────────────────────────────────────────────────────────┘
```

### Qubes OS

| Detail              | Value                                                    |
| ------------------- | -------------------------------------------------------- |
| **Base**            | Xen Hypervisor + Fedora/Debian VMs                       |
| **Maintainer**      | Invisible Things Lab (Joanna Rutkowska)                  |
| **Purpose**         | Security through compartmentalization                    |
| **Official Site**   | https://www.qubes-os.org                                 |
| **Unique Feature**  | Every application runs in its own isolated VM            |
| **Endorsed By**     | Edward Snowden, EFF, Freedom of the Press Foundation     |

```text [Qubes OS Architecture]

  ┌───────────────────────────────────────────────────────────┐
  │                     QUBES OS                               │
  │                  (Xen Hypervisor)                           │
  │                                                            │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
  │  │ 🔴 UNTRUST│  │ 🟡 WORK   │  │ 🟢 PERSONAL│  │ 🔵 VAULT │ │
  │  │          │  │          │  │          │  │          │ │
  │  │ Browser  │  │ Office   │  │ Email    │  │ Passwords│ │
  │  │ Random   │  │ Documents│  │ Social   │  │ Keys     │ │
  │  │ Browsing │  │ Code     │  │ Banking  │  │ KeePass  │ │
  │  │          │  │          │  │          │  │ GPG keys │ │
  │  │ ⚠️ If     │  │          │  │          │  │          │ │
  │  │ compromised│ │          │  │          │  │ 🔒 No net │ │
  │  │ others   │  │          │  │          │  │ access   │ │
  │  │ are SAFE │  │          │  │          │  │          │ │
  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │
  │                                                            │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
  │  │ 🟣 WHONIX │  │ 🟠 KALI   │  │ ⚫ DISPOSABLE│             │
  │  │ Gateway  │  │ Pentest  │  │ One-time │               │
  │  │ + Workst │  │ VM       │  │ use VMs  │               │
  │  └──────────┘  └──────────┘  └──────────┘               │
  └───────────────────────────────────────────────────────────┘
```

::tip
Qubes OS is the **most secure desktop OS available**. For pentesters, it allows running **Kali, Whonix, Windows, and disposable VMs** simultaneously, each in complete isolation. If one VM is compromised, others remain safe.
::

---

## Exploit Development & Kernel Hacking

### Custom Build for Exploit Development

::note
There is no single "exploit development OS." Exploit developers typically build **custom environments** tailored to their target. The key is matching the target's exact software versions, kernel, and architecture.
::

```text [Exploit Development Workstation]

  ┌──────────────────────────────────────────────────────────┐
  │              EXPLOIT DEVELOPER'S SETUP                    │
  │                                                          │
  │  HOST: Ubuntu 22.04 / Fedora 40                          │
  │  ├── GDB + pwndbg/GEF/peda                              │
  │  ├── pwntools (Python)                                   │
  │  ├── ROPgadget / ropper                                  │
  │  ├── one_gadget                                          │
  │  ├── Ghidra / IDA Free                                   │
  │  ├── radare2 / rizin + cutter                            │
  │  ├── gcc / g++ / nasm / make / cmake                     │
  │  ├── clang + LLVM                                        │
  │  ├── qemu-system (for kernel debugging)                  │
  │  ├── Docker (for version-specific targets)               │
  │  └── Multiple kernel source trees                        │
  │                                                          │
  │  VMs:                                                    │
  │  ├── Ubuntu 18.04 (older glibc targets)                  │
  │  ├── Ubuntu 20.04 (common CTF target)                    │
  │  ├── Ubuntu 22.04 (modern targets)                       │
  │  ├── Debian 10/11/12                                     │
  │  ├── CentOS 7/8 (enterprise targets)                     │
  │  ├── Windows 10/11 (Windows exploit dev)                 │
  │  └── Custom kernel VMs (for kernel exploits)             │
  └──────────────────────────────────────────────────────────┘
```

### Essential Exploit Development Tools

::tabs
  :::tabs-item{icon="i-lucide-bug" label="Userland Exploitation"}
  ```bash [Setup Exploit Development Environment]
  # Ubuntu/Debian base
  sudo apt update && sudo apt install -y \
      build-essential gcc g++ gcc-multilib g++-multilib \
      nasm cmake make gdb gdbserver \
      python3 python3-pip python3-dev python3-venv \
      libssl-dev libffi-dev zlib1g-dev \
      git curl wget tmux strace ltrace \
      binutils file xxd hexedit \
      qemu-user qemu-user-static \
      libc6-dbg libc6-i386

  # GDB Enhancement — pwndbg (recommended for exploit dev)
  git clone https://github.com/pwndbg/pwndbg ~/pwndbg
  cd ~/pwndbg && ./setup.sh

  # OR GEF (GDB Enhanced Features)
  # bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

  # pwntools
  pip3 install pwntools

  # ROPgadget
  pip3 install ROPgadget

  # ropper
  pip3 install ropper

  # one_gadget (Ruby)
  sudo apt install -y ruby ruby-dev
  sudo gem install one_gadget

  # Seccomp tools
  sudo gem install seccomp-tools

  # Heap analysis
  pip3 install heapinspect

  # Ghidra
  sudo apt install -y ghidra

  # Radare2
  git clone https://github.com/radareorg/radare2 ~/radare2
  cd ~/radare2 && sys/install.sh
  ```
  :::

  :::tabs-item{icon="i-lucide-cpu" label="Kernel Exploitation"}
  ```bash [Setup Kernel Exploit Development]
  # Build essentials for kernel development
  sudo apt install -y \
      build-essential libncurses-dev bison flex libssl-dev \
      libelf-dev bc dwarves pahole \
      qemu-system-x86 qemu-system-arm \
      debootstrap cpio initramfs-tools \
      linux-source linux-headers-$(uname -r) \
      busybox-static

  # Download kernel source
  git clone --depth=1 https://github.com/torvalds/linux.git ~/linux-src

  # Build a minimal kernel for testing
  cd ~/linux-src
  make defconfig
  # Enable debug info
  scripts/config --enable CONFIG_DEBUG_INFO
  scripts/config --enable CONFIG_DEBUG_INFO_DWARF5
  scripts/config --enable CONFIG_GDB_SCRIPTS
  scripts/config --enable CONFIG_KGDB
  scripts/config --enable CONFIG_FRAME_POINTER
  # Disable security features for testing
  scripts/config --disable CONFIG_RANDOMIZE_BASE  # Disable KASLR
  scripts/config --disable CONFIG_STRICT_DEVMEM
  make -j$(nproc)

  # Create a minimal rootfs
  mkdir -p ~/rootfs
  debootstrap --arch amd64 bookworm ~/rootfs

  # Boot with QEMU
  qemu-system-x86_64 \
      -kernel ~/linux-src/arch/x86/boot/bzImage \
      -append "console=ttyS0 root=/dev/sda rw nokaslr" \
      -drive file=rootfs.img,format=raw \
      -nographic \
      -m 2G \
      -smp 2 \
      -s -S  # Wait for GDB connection

  # In another terminal, attach GDB
  gdb ~/linux-src/vmlinux \
      -ex "target remote :1234" \
      -ex "continue"
  ```
  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows Exploitation"}
  ```text [Windows Exploit Dev Setup (on Commando/FlareVM)]
  REQUIRED SOFTWARE
  ─────────────────
  • Visual Studio 2022 (Community — free)
  • Windows SDK + WDK (kernel dev)
  • WinDbg Preview (Microsoft Store)
  • x64dbg / x32dbg
  • IDA Pro / IDA Free
  • Ghidra
  • mona.py (Immunity Debugger plugin)
  • Process Hacker / Process Monitor
  • VMMap / Handle (Sysinternals)
  • ROPgadget / ropper (via Python)
  • Compilers: MSVC, MinGW, NASM

  KERNEL DEBUGGING
  ────────────────
  • Two VMs: Debugger + Debuggee
  • bcdedit /debug on (debuggee)
  • WinDbg connected via named pipe or network
  • Symbols: srv*c:\symbols*https://msdl.microsoft.com/download/symbols

  EXPLOIT FRAMEWORKS
  ──────────────────
  • msfvenom (payload generation)
  • Donut (shellcode from .NET assemblies)
  • ScareCrow (EDR bypass)
  • Nim / Rust (for custom loaders)
  ```
  :::
::

---

## Mobile Security

### Kali NetHunter

| Detail              | Value                                                    |
| ------------------- | -------------------------------------------------------- |
| **Base**            | Android + Kali Linux chroot                              |
| **Maintainer**      | OffSec                                                   |
| **Purpose**         | Mobile penetration testing                               |
| **Official Site**   | https://www.kali.org/get-kali/#kali-mobile               |
| **Editions**        | NetHunter, NetHunter Lite, NetHunter Rootless            |
| **Unique Feature**  | Wireless attacks from a phone/tablet                     |

```text [NetHunter Capabilities]
• Wireless frame injection (with compatible adapters)
• MITM attacks via USB OTG Ethernet
• HID keyboard attacks (BadUSB)
• Full Kali chroot environment
• Metasploit Framework
• Nmap, Hydra, SQLMap
• WPS Pixie Dust attacks
• Bluetooth exploitation
• NFC cloning
• Custom kernel with monitor mode support
```

### Santoku Linux

| Detail              | Value                                                    |
| ------------------- | -------------------------------------------------------- |
| **Base**            | Ubuntu                                                   |
| **Maintainer**      | NowSecure                                                |
| **Purpose**         | Mobile security, forensics, and malware analysis         |
| **Official Site**   | https://santoku-linux.com                                |
| **Focus**           | Android and iOS security testing                         |

```text [Santoku Mobile Security Tools]
• Android SDK / ADB / Fastboot       • Androguard
• APKTool (decompile APKs)           • Dex2Jar
• JADX (Java decompiler)             • Frida
• MobSF (Mobile Security Framework)  • Objection
• Drozer                             • Burp Suite Mobile
• iOS deployment tools               • SSL Kill Switch
• Firmware extraction                • Needle
```

---

## IoT & Hardware Hacking

### AttifyOS

| Detail              | Value                                                    |
| ------------------- | -------------------------------------------------------- |
| **Base**            | Ubuntu                                                   |
| **Maintainer**      | Attify                                                   |
| **Purpose**         | IoT and embedded device pentesting                       |
| **Official Site**   | https://github.com/adi0x90/attifyos                      |
| **Unique Feature**  | Firmware analysis, UART, JTAG, SPI, I2C tools           |

```text [AttifyOS IoT Tools]
FIRMWARE ANALYSIS                HARDWARE INTERFACES
─────────────────                ────────────────────
• Binwalk                        • OpenOCD (JTAG/SWD)
• Firmware Mod Kit               • Flashrom (SPI/I2C)
• FACT (Firmware Analysis)       • UART tools
• firmware-analysis-toolkit      • Bus Pirate drivers
• Jefferson (JFFS2)              • Saleae Logic Analyzer
• Sasquatch (SquashFS)           • sigrok / PulseView

RADIO / WIRELESS                 EMULATION
────────────────                 ─────────
• GNU Radio                      • QEMU (ARM/MIPS/etc.)
• HackRF tools                   • Firmadyne
• RTL-SDR                        • FAT (Firmware Analysis)
• Bluetooth tools                • ARM/MIPS cross-compilers
• Zigbee tools
• Z-Wave tools
```

---

## Additional Security Distributions

::card-group

::card
---
title: BackBox Linux
icon: i-lucide-box
---
**Base:** Ubuntu LTS | **Focus:** Penetration testing

Lightweight, Ubuntu-based pentesting distribution. Simple, clean interface with essential security tools. Good alternative for Ubuntu users who want a familiar environment.

**Site:** https://www.backbox.org
::

::card
---
title: Pentoo Linux
icon: i-lucide-pentagon
---
**Base:** Gentoo | **Focus:** Advanced pentesting

Gentoo-based security distribution with optimized compilation. For users who want maximum performance and control. Can be used as a Gentoo overlay.

**Site:** https://www.pentoo.ch
::

::card
---
title: Fedora Security Lab
icon: i-lucide-shield
---
**Base:** Fedora | **Focus:** Security auditing

Official Fedora Spin focused on security auditing and forensics. Uses SELinux, provides a clean Fedora experience with security tools. Good for Red Hat ecosystem users.

**Site:** https://labs.fedoraproject.org/security/
::

::card
---
title: Network Security Toolkit (NST)
icon: i-lucide-network
---
**Base:** Fedora | **Focus:** Network security

Bootable live USB/DVD focused on network security analysis. Includes ntopng, Wireshark, Snort, NetworkMiner. Web-based management interface.

**Site:** https://www.networksecuritytoolkit.org
::

::card
---
title: ArchStrike
icon: i-lucide-swords
---
**Base:** Arch Linux | **Focus:** Penetration testing

Arch Linux repository for security professionals. Like BlackArch but lighter — add only the categories you need. Rolling release with latest tools.

**Site:** https://archstrike.org
::

::card
---
title: Demon Linux
icon: i-lucide-flame
---
**Base:** Debian | **Focus:** Pentesting + aesthetics

Visually striking pentesting distribution with dark theme. Custom panel, integrated tools, and screenshot/recording capabilities. Good for demo/presentation environments.

**Site:** https://www.demonlinux.com
::

::card
---
title: Predator OS
icon: i-lucide-crosshair
---
**Base:** Ubuntu | **Focus:** Pentesting + anonymity

Combines offensive security tools with privacy features. Includes Tor integration, cryptocurrency tools, and standard pentesting arsenal. Good middle ground between Kali and Tails.

**Site:** https://predator-os.com
::

::card
---
title: Garuda Linux (Security Edition)
icon: i-lucide-bird
---
**Base:** Arch Linux | **Focus:** Beautiful pentesting

Arch-based with stunning UI (dr460nized theme). Security edition includes BlackArch tools. BTRFS with automatic snapshots. For users who want aesthetics + functionality.

**Site:** https://garudalinux.org
::

::

---

## OS Comparison — By Lab Platform

### HackTheBox (HTB)

::tabs
  :::tabs-item{icon="i-lucide-trophy" label="Recommended Setup"}
  ```text [HTB Optimal Setup]
  PRIMARY:   Kali Linux (VM or Pwnbox)
  SECONDARY: Parrot HTB Edition
  WINDOWS:   Commando VM (for AD boxes)

  Why Kali for HTB:
  ✅ Official Pwnbox is Parrot-based (similar to Kali)
  ✅ 99% of HTB writeups use Kali
  ✅ All required tools pre-installed
  ✅ HTB VPN (.ovpn) works out of the box
  ✅ Community support assumes Kali

  HTB VPN Setup:
  $ sudo openvpn lab_username.ovpn

  Must-Have Tools for HTB:
  • Nmap, Rustscan (fast port scan)
  • Gobuster, Feroxbuster, ffuf
  • SQLMap, Burp Suite
  • Metasploit, searchsploit
  • John, Hashcat
  • Impacket suite (for AD)
  • BloodHound (for AD)
  • Evil-WinRM, CrackMapExec
  • LinPEAS, WinPEAS (privesc)
  • pwntools (for pwn challenges)
  • Ghidra (for reversing challenges)
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="HTB Machine Categories"}
  | HTB Category      | Best OS               | Key Tools                              |
  | ----------------- | --------------------- | -------------------------------------- |
  | Linux Machines    | Kali Linux            | Nmap, Gobuster, LinPEAS, GTFOBins     |
  | Windows Machines  | Kali + Commando VM    | Impacket, Evil-WinRM, Mimikatz        |
  | Active Directory  | Kali + Commando VM    | BloodHound, CrackMapExec, Rubeus      |
  | Web Challenges    | Kali / Parrot         | Burp Suite, SQLMap, ffuf              |
  | Pwn Challenges    | Kali / Ubuntu         | pwntools, GDB+pwndbg, ROPgadget      |
  | Reverse Eng       | Kali + FlareVM        | Ghidra, IDA, x64dbg, Cutter          |
  | Crypto Challenges | Any Linux             | Python, SageMath, CyberChef           |
  | Forensics         | Kali + SIFT           | Volatility, Autopsy, Wireshark        |
  | Hardware          | Kali                  | Binwalk, Firmwalker, QEMU             |
  :::
::

### TryHackMe (THM)

| Aspect            | Recommendation                                          |
| ----------------- | -------------------------------------------------------- |
| **Primary OS**    | Kali Linux                                               |
| **Alternative**   | Parrot Security, THM AttackBox (browser-based)           |
| **For Beginners** | Use the in-browser AttackBox first, then switch to Kali  |
| **VPN**           | `sudo openvpn username.ovpn`                             |

```text [THM Learning Paths vs OS]
THM Path                          Recommended OS
─────────────────────────         ──────────────
Pre-Security                      AttackBox / Any
Introduction to Cyber Security    AttackBox / Kali
Complete Beginner                 Kali Linux
Jr Penetration Tester             Kali Linux
Offensive Pentesting              Kali Linux
Web Fundamentals                  Kali / Parrot
Cyber Defense                     Kali + SIFT
Red Teaming                       Kali + Commando VM
SOC Level 1                       Kali + SIFT
CompTIA Pentest+                  Kali Linux
```

### OffSec (OSCP / OSEP / OSED / OSWE / OSMR)

::warning
OffSec certifications **require Kali Linux**. The exam environment provides a Kali VM. Practice with Kali to ensure familiarity with the exact environment you'll use during the exam.
::

| Certification | Required OS     | Additional OS Needed     | Focus Area                    |
| ------------- | --------------- | ------------------------ | ----------------------------- |
| **OSCP**      | Kali Linux      | Windows VM (for targets) | Pentesting fundamentals       |
| **OSEP**      | Kali Linux      | Commando VM / Windows    | Advanced exploitation         |
| **OSED**      | Windows (WinDbg)| Kali Linux               | Exploit development           |
| **OSWE**      | Kali Linux      | —                        | Web app exploitation          |
| **OSMR**      | Kali Linux      | macOS VM                 | macOS research                |
| **OSDA**      | Kali / SIFT     | —                        | Defense analysis              |

---

## How to Set Up Your Multi-OS Lab

### Recommended Virtualization

::tabs
  :::tabs-item{icon="i-lucide-server" label="VMware Workstation Pro"}
  ```text [VMware Advantages for Security Labs]
  ✅ Best performance for multiple VMs
  ✅ Snapshot management (critical for exploit dev)
  ✅ NAT + Host-Only + Internal networking
  ✅ Shared folders between VMs
  ✅ USB passthrough for hardware hacking
  ✅ Linked clones (save disk space)
  ✅ Now FREE for personal use (2024+)
  ```

  ```bash [Download]
  # VMware Workstation Pro is now FREE for personal use
  # https://www.vmware.com/products/workstation-pro.html
  ```
  :::

  :::tabs-item{icon="i-lucide-box" label="VirtualBox"}
  ```text [VirtualBox Advantages]
  ✅ Completely free and open source
  ✅ Cross-platform (Windows, macOS, Linux)
  ✅ Good for beginners
  ✅ Extension Pack adds USB 3.0, encryption
  ✅ Snapshots and cloning
  ⚠️ Slower than VMware for heavy workloads
  ⚠️ Occasional compatibility issues
  ```

  ```bash [Install VirtualBox]
  # Ubuntu/Debian
  sudo apt install -y virtualbox virtualbox-ext-pack

  # Or download from https://www.virtualbox.org/
  ```
  :::

  :::tabs-item{icon="i-lucide-container" label="Proxmox VE"}
  ```text [Proxmox for Dedicated Lab Server]
  ✅ Free enterprise-grade hypervisor
  ✅ Run dozens of VMs simultaneously
  ✅ Web-based management interface
  ✅ ZFS storage with snapshots
  ✅ Clustering support
  ✅ Perfect for dedicated lab hardware
  ✅ Container (LXC) + VM support
  ⚠️ Requires dedicated hardware (bare-metal)
  ```

  ```bash [Install Proxmox]
  # Download ISO from https://www.proxmox.com/en/downloads
  # Install on bare metal (dedicated lab server)
  # Access web UI at https://<server-ip>:8006
  ```
  :::
::

### Recommended Lab Configuration

```text [Complete Lab Setup — All Disciplines]

  ┌────────────────────────────────────────────────────────────┐
  │                    YOUR LAB MACHINE                         │
  │              (16GB+ RAM, SSD, GPU optional)                │
  │                                                            │
  │  HYPERVISOR: VMware Workstation Pro (Free) / VirtualBox    │
  │                                                            │
  │  ┌─────── ALWAYS RUNNING ──────┐                          │
  │  │                              │                          │
  │  │  🐉 Kali Linux               │  4GB RAM, 80GB disk     │
  │  │  Your daily pentesting VM    │  NAT + Host-Only        │
  │  │  HTB/THM/OffSec VPN here    │  Snapshot: "Clean"      │
  │  │                              │                          │
  │  └──────────────────────────────┘                          │
  │                                                            │
  │  ┌─────── START AS NEEDED ─────┐                          │
  │  │                              │                          │
  │  │  🪟 Commando VM              │  4GB RAM, 60GB disk     │
  │  │  Windows AD attacks          │  Host-Only only         │
  │  │  .NET reversing              │  Snapshot: "Clean"      │
  │  │                              │                          │
  │  │  🔬 REMnux                   │  4GB RAM, 40GB disk     │
  │  │  Malware analysis            │  Host-Only (isolated!)  │
  │  │  Linux RE                    │  Snapshot: "Clean"      │
  │  │                              │                          │
  │  │  🔥 FlareVM                  │  4GB RAM, 60GB disk     │
  │  │  Windows RE / Malware        │  Host-Only (isolated!)  │
  │  │  Debugging                   │  Snapshot: "Clean"      │
  │  │                              │                          │
  │  │  🔍 CSI Linux                │  4GB RAM, 40GB disk     │
  │  │  OSINT investigations       │  NAT only               │
  │  │                              │  Snapshot: "Clean"      │
  │  │                              │                          │
  │  │  🔎 SIFT Workstation         │  4GB RAM, 40GB disk     │
  │  │  Digital forensics           │  Host-Only              │
  │  │                              │  Snapshot: "Clean"      │
  │  │                              │                          │
  │  └──────────────────────────────┘                          │
  │                                                            │
  │  ┌─────── NETWORKING ──────────┐                          │
  │  │                              │                          │
  │  │  NAT:       Internet access  │                          │
  │  │  Host-Only: Lab isolation    │  172.16.0.0/24          │
  │  │  Internal:  VM-to-VM only   │  10.10.10.0/24          │
  │  │                              │                          │
  │  └──────────────────────────────┘                          │
  └────────────────────────────────────────────────────────────┘
```

---

## Post-Installation Essentials

### Kali Linux — First Things to Do

```bash [Essential Post-Install Commands]
# Update everything
sudo apt update && sudo apt full-upgrade -y

# Install additional tools
sudo apt install -y \
    seclists wordlists \
    gobuster feroxbuster ffuf \
    crackmapexec evil-winrm \
    bloodhound neo4j \
    chisel ligolo-ng \
    rlwrap \
    pipx \
    golang-go \
    rustup \
    jq yq

# Install Python tools
pipx install impacket
pipx install certipy-ad
pipx install bloodyad
pipx install coercer

# Install Go tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/ffuf/ffuf/v2@latest

# Install Rust tools
cargo install rustscan

# Configure Git
git config --global user.name "Your Name"
git config --global user.email "you@example.com"

# Set up tmux
cat > ~/.tmux.conf << 'EOF'
set -g mouse on
set -g history-limit 50000
set -g default-terminal "screen-256color"
bind | split-window -h
bind - split-window -v
EOF

# Create workspace
mkdir -p ~/htb ~/thm ~/oscp ~/tools ~/wordlists ~/vpn

# Download additional wordlists
git clone https://github.com/danielmiessler/SecLists.git ~/wordlists/seclists

# Take a snapshot now!
echo "Take a VM snapshot named 'Fresh-Install' now!"
```

### Optimize VM Performance

```bash [VM Performance Tuning]
# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups
sudo systemctl disable ModemManager

# Reduce swappiness (use RAM more aggressively)
echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Increase file descriptors
echo '* soft nofile 65535' | sudo tee -a /etc/security/limits.conf
echo '* hard nofile 65535' | sudo tee -a /etc/security/limits.conf

# Install VM guest tools (VMware)
sudo apt install -y open-vm-tools open-vm-tools-desktop

# Or VirtualBox Guest Additions
sudo apt install -y virtualbox-guest-x11 virtualbox-guest-utils
```

---

## Decision Flowchart

```text [Which OS Should I Use? — Decision Tree]

  START
    │
    ├── Are you a complete beginner?
    │   ├── YES → Kali Linux (most tutorials/guides assume Kali)
    │   └── NO ──┐
    │            │
    ├── What is your primary focus?
    │   │
    │   ├── Pentesting (general) ──────────────► Kali Linux
    │   │
    │   ├── Bug Bounty ─────────────────────────► Parrot Security (lighter, daily driver)
    │   │
    │   ├── Active Directory ───────────────────► Kali + Commando VM (need both)
    │   │
    │   ├── Reverse Engineering
    │   │   ├── Linux binaries ─────────────────► REMnux
    │   │   ├── Windows binaries ───────────────► FlareVM
    │   │   └── Both ──────────────────────────► REMnux + FlareVM
    │   │
    │   ├── Malware Analysis ───────────────────► REMnux + FlareVM (isolated network!)
    │   │
    │   ├── Exploit Development
    │   │   ├── Userland (Linux) ───────────────► Ubuntu + pwntools + GDB
    │   │   ├── Kernel (Linux) ─────────────────► Ubuntu + QEMU + kernel source
    │   │   └── Windows ────────────────────────► Commando VM + WinDbg
    │   │
    │   ├── OSINT ──────────────────────────────► CSI Linux / Trace Labs VM
    │   │
    │   ├── Digital Forensics ──────────────────► SIFT Workstation / CAINE
    │   │
    │   ├── Privacy / Anonymity ────────────────► Tails (portable) / Whonix (persistent)
    │   │
    │   ├── Maximum Security ───────────────────► Qubes OS
    │   │
    │   ├── IoT / Hardware ─────────────────────► AttifyOS / Kali
    │   │
    │   ├── Mobile Security ────────────────────► Kali NetHunter / Santoku
    │   │
    │   ├── I want ALL the tools ───────────────► BlackArch (2800+ tools)
    │   │
    │   └── CTF / Lab Platforms
    │       ├── HackTheBox ─────────────────────► Kali Linux / Parrot HTB
    │       ├── TryHackMe ──────────────────────► Kali Linux
    │       ├── OffSec (OSCP) ──────────────────► Kali Linux (required)
    │       ├── PentesterLab ───────────────────► Kali Linux
    │       └── VulnHub ────────────────────────► Kali Linux
    │
    └── "I still can't decide"
        └── Just start with Kali Linux. Seriously. Add more later.
```

---

## All Operating Systems Summary

::collapsible

```text [Complete OS Reference Table]
╔══════════════════════════╦══════════════╦══════════════════════════╦══════════════════╗
║ Operating System         ║ Base         ║ Primary Focus            ║ Tool Count       ║
╠══════��═══════════════════╬══════════════╬══════════════════════════╬══════════════════╣
║ Kali Linux               ║ Debian       ║ Penetration Testing      ║ 600+             ║
║ Parrot Security          ║ Debian       ║ Pentesting + Privacy     ║ 600+             ║
║ BlackArch                ║ Arch         ║ Advanced Pentesting      ║ 2800+            ║
║ Commando VM              ║ Windows      ║ Windows Pentesting       ║ 200+             ║
║ BackBox                  ║ Ubuntu       ║ Pentesting (Lightweight) ║ 200+             ║
║ Pentoo                   ║ Gentoo       ║ Advanced Pentesting      ║ 400+             ║
║ ArchStrike               ║ Arch         ║ Pentesting (Minimal)     ║ 500+             ║
║ Fedora Security Lab      ║ Fedora       ║ Security Auditing        ║ 150+             ║
║ NST                      ║ Fedora       ║ Network Security         ║ 200+             ║
║ Demon Linux              ║ Debian       ║ Pentesting + Aesthetics  ║ 300+             ║
║ Predator OS              ║ Ubuntu       ║ Pentesting + Privacy     ║ 400+             ║
║ Garuda Security          ║ Arch         ║ Beautiful Pentesting     ║ 500+ (BlackArch) ║
╠══════════════════════════╬══════════════╬══════════════════════════╬══════════════════╣
║ REMnux                   ║ Ubuntu       ║ Malware Analysis (Linux) ║ 200+             ║
║ FlareVM                  ║ Windows      ║ Malware Analysis (Win)   ║ 150+             ║
╠══════════════════════════╬══════════════╬══════════════════════════╬══════════════════╣
║ CSI Linux                ║ Ubuntu       ║ OSINT Investigation      ║ 200+             ║
║ Trace Labs OSINT VM      ║ Kali         ║ OSINT (Missing Persons)  ║ 100+             ║
╠══════════════════════════╬══════════════╬══════════════════════════╬══════════════════╣
║ SIFT Workstation         ║ Ubuntu       ║ Digital Forensics        ║ 200+             ║
║ CAINE                    ║ Ubuntu       ║ Digital Forensics        ║ 150+             ║
║ Tsurugi Linux            ║ Ubuntu       ║ DFIR + OSINT             ║ 250+             ║
╠══════════════════════════╬══════════════╬══════════════════════════╬══════════════════╣
║ Tails                    ║ Debian       ║ Privacy / Anonymity      ║ 50+              ║
║ Whonix                   ║ Debian       ║ Anonymity (Tor VM)       ║ 50+              ║
║ Qubes OS                 ║ Xen/Fedora   ║ Compartmentalized Sec    ║ VM-dependent     ║
╠══════════════════════════╬══════════════╬══════════════════════════╬══════════════════╣
║ Kali NetHunter           ║ Android      ║ Mobile Pentesting        ║ 200+             ║
║ Santoku                  ║ Ubuntu       ║ Mobile Security          ║ 100+             ║
║ AttifyOS                 ║ Ubuntu       ║ IoT / Hardware Hacking   ║ 100+             ║
╚══════════════════════════╩══════════════╩══════════════════════════╩══════════════════╝
```

::

---

## Resources & Downloads

::card-group

::card
---
title: Kali Linux
icon: i-simple-icons-kalilinux
to: https://www.kali.org/get-kali/
target: _blank
---
The industry standard for penetration testing. Download ISO, VM images, Docker containers, WSL, cloud instances, and NetHunter for mobile.
::

::card
---
title: Parrot Security
icon: i-simple-icons-parrotsecurity
to: https://parrotsec.org/download/
target: _blank
---
Privacy-focused pentesting distribution. Available in Security, Home, HTB, and Cloud editions. Lighter than Kali with AnonSurf integration.
::

::card
---
title: BlackArch Linux
icon: i-simple-icons-archlinux
to: https://blackarch.org/downloads.html
target: _blank
---
2800+ security tools on Arch Linux. Download full ISO or add the BlackArch repository to your existing Arch installation.
::

::card
---
title: REMnux
icon: i-simple-icons-ubuntu
to: https://remnux.org/
target: _blank
---
The definitive Linux distribution for malware analysis and reverse engineering. Download OVA, install on Ubuntu, or use Docker.
::

::card
---
title: FlareVM
icon: i-simple-icons-windows
to: https://github.com/mandiant/flare-vm
target: _blank
---
Windows-based reverse engineering and malware analysis environment by Mandiant. Install via PowerShell on a Windows 10/11 VM.
::

::card
---
title: Commando VM
icon: i-simple-icons-windows
to: https://github.com/mandiant/commando-vm
target: _blank
---
Windows-based penetration testing VM by Mandiant. Essential for Active Directory attacks and native Windows exploitation.
::

::card
---
title: CSI Linux
icon: i-lucide-search
to: https://csilinux.com/
target: _blank
---
Complete OSINT investigation platform with case management, dark web tools, and social media intelligence capabilities.
::

::card
---
title: SIFT Workstation
icon: i-lucide-hard-drive
to: https://www.sans.org/tools/sift-workstation/
target: _blank
---
SANS digital forensics and incident response toolkit. The gold standard for professional forensic investigations.
::

::card
---
title: Tails OS
icon: i-lucide-eye-off
to: https://tails.net/
target: _blank
---
The Amnesic Incognito Live System. Boots from USB, routes everything through Tor, and leaves no trace on shutdown.
::

::card
---
title: Whonix
icon: i-lucide-shield
to: https://www.whonix.org/
target: _blank
---
Two-VM anonymity system. Gateway VM routes all traffic through Tor. Workstation VM cannot leak your real IP by design.
::

::card
---
title: Qubes OS
icon: i-lucide-layers
to: https://www.qubes-os.org/
target: _blank
---
Security through compartmentalization. Every application runs in its own isolated VM. The most secure desktop OS available.
::

::card
---
title: Trace Labs OSINT VM
icon: i-lucide-user-search
to: https://www.tracelabs.org/initiatives/osint-vm
target: _blank
---
Pre-configured Kali-based VM for OSINT investigations, specifically designed for Trace Labs missing persons CTF events.
::

::