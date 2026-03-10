---
title: GitHub Resources
description: Curated collection of the most essential GitHub repositories for penetration testing, bug bounty, red teaming, reverse engineering, OSINT, wordlists, cheatsheets, and cybersecurity learning.
navigation:
  icon: i-simple-icons-github
  title: GitHub Resources
---

GitHub is the **largest open-source repository** of cybersecurity tools, payloads, cheatsheets, and learning resources. This curated collection covers the most starred, most maintained, and most practical repositories used by penetration testers, bug bounty hunters, red teamers, and security researchers worldwide.

::note
Repositories are organized by **category and use case**. Star counts are approximate as of 2024–2025. Always verify tool legitimacy and review source code before running anything in production environments.
::

---

## :icon{name="i-lucide-book-open"} Knowledge Bases & References

### PayloadsAllTheThings

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Reference" color="neutral"}
  :badge{label="Payloads" color="green"}
  :badge{label="Web Security" color="blue"}
  :badge{label="Bypass" color="orange"}
  :badge{label="Cheatsheets" color="red"}
  :badge{label="Community" color="purple"}
::

![GitHub Stars](https://img.shields.io/github/stars/swisskyrepo/PayloadsAllTheThings?style=for-the-badge&logo=github&color=yellow) ![Last Commit](https://img.shields.io/github/last-commit/swisskyrepo/PayloadsAllTheThings?style=for-the-badge&logo=github)

The **single most valuable repository** for any penetration tester or bug bounty hunter. PayloadsAllTheThings is a massive collection of ready-to-use payloads, bypass techniques, and methodology references organized by vulnerability class.

Covers **every major web vulnerability** — SQL Injection, XSS, SSRF, XXE, SSTI, IDOR, command injection, file inclusion, deserialization, authentication bypass, and dozens more. Each category includes explanations, payloads, filter bypass techniques, and real-world examples.

This repository should be your **first stop** when testing for any vulnerability type.

::card-group
  ::card
  ---
  title: PayloadsAllTheThings
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings
  target: _blank
  ---
  65K+ ⭐ — The ultimate payload and bypass reference for web security testing.
  ::

  ::card
  ---
  title: Web Version
  icon: i-lucide-globe
  to: https://swisskyrepo.github.io/PayloadsAllTheThings/
  target: _blank
  ---
  Searchable web interface for browsing all payloads and techniques.
  ::
::

---

### HackTricks

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Reference" color="neutral"}
  :badge{label="Pentesting" color="green"}
  :badge{label="Methodology" color="blue"}
  :badge{label="Linux" color="orange"}
  :badge{label="Windows" color="red"}
  :badge{label="AD" color="purple"}
::

![GitHub Stars](https://img.shields.io/github/stars/HackTricks-wiki/hacktricks?style=for-the-badge&logo=github&color=yellow)

The **most comprehensive pentesting wiki** in existence. HackTricks covers every phase of a penetration test — reconnaissance, enumeration, exploitation, privilege escalation, lateral movement, and post-exploitation — with copy-paste commands and detailed explanations.

Created by Carlos Polop (creator of **linPEAS/winPEAS**), this wiki is regularly updated and covers Linux, Windows, Active Directory, cloud (AWS/Azure/GCP), web, mobile, and more. There's also **HackTricks Cloud** for cloud-specific attacks.

::card-group
  ::card
  ---
  title: HackTricks
  icon: i-simple-icons-github
  to: https://github.com/HackTricks-wiki/hacktricks
  target: _blank
  ---
  6K+ ⭐ — Comprehensive pentesting methodology wiki with commands and techniques.
  ::

  ::card
  ---
  title: HackTricks Website
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/
  target: _blank
  ---
  Searchable web version covering all pentesting phases.
  ::

  ::card
  ---
  title: HackTricks Cloud
  icon: i-lucide-cloud
  to: https://cloud.hacktricks.wiki/
  target: _blank
  ---
  Cloud security — AWS, Azure, GCP attack techniques and enumeration.
  ::
::

---

### The Book of Secret Knowledge

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Reference" color="neutral"}
  :badge{label="Mega Collection" color="green"}
  :badge{label="Tools" color="blue"}
  :badge{label="CLI" color="orange"}
  :badge{label="Sysadmin" color="red"}
  :badge{label="Security" color="purple"}
::

![GitHub Stars](https://img.shields.io/github/stars/trimstray/the-book-of-secret-knowledge?style=for-the-badge&logo=github&color=yellow)

A massive curated list of **tools, CLI commands, one-liners, and resources** for sysadmins, DevOps, network engineers, and security professionals. Think of it as a giant bookmark collection organized by category — web tools, terminal utilities, network scanners, security resources, blogs, and more.

::card-group
  ::card
  ---
  title: The Book of Secret Knowledge
  icon: i-simple-icons-github
  to: https://github.com/trimstray/the-book-of-secret-knowledge
  target: _blank
  ---
  155K+ ⭐ — Curated list of inspiring lists, manuals, cheatsheets, and tools.
  ::
::

---

### Awesome Hacking

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Reference" color="neutral"}
  :badge{label="Awesome List" color="green"}
  :badge{label="All Categories" color="blue"}
  :badge{label="Curated" color="orange"}
::

![GitHub Stars](https://img.shields.io/github/stars/Hack-with-Github/Awesome-Hacking?style=for-the-badge&logo=github&color=yellow)

A curated list of **awesome hacking resources** organized by category — tools, tutorials, CTF platforms, courses, books, and communities. This is a **meta-list** that links to other specialized awesome lists for deep dives into specific topics.

::card-group
  ::card
  ---
  title: Awesome Hacking
  icon: i-simple-icons-github
  to: https://github.com/Hack-with-Github/Awesome-Hacking
  target: _blank
  ---
  85K+ ⭐ — Meta-list linking to curated hacking resource collections.
  ::

  ::card
  ---
  title: Awesome Security
  icon: i-simple-icons-github
  to: https://github.com/sbilly/awesome-security
  target: _blank
  ---
  12K+ ⭐ — Curated collection of security software, libraries, and resources.
  ::

  ::card
  ---
  title: Awesome Pentest
  icon: i-simple-icons-github
  to: https://github.com/enaqx/awesome-pentest
  target: _blank
  ---
  22K+ ⭐ — Penetration testing resources, tools, and references.
  ::
::

---

### OWASP CheatSheet Series

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Reference" color="neutral"}
  :badge{label="OWASP" color="green"}
  :badge{label="Secure Coding" color="blue"}
  :badge{label="Defense" color="orange"}
  :badge{label="Best Practices" color="red"}
::

![GitHub Stars](https://img.shields.io/github/stars/OWASP/CheatSheetSeries?style=for-the-badge&logo=github&color=yellow)

Official **OWASP Cheat Sheet Series** — concise reference guides for secure development practices. Covers authentication, session management, input validation, cryptography, API security, and dozens of other security topics. Essential for both offensive testing (understanding defenses) and defensive development.

::card-group
  ::card
  ---
  title: OWASP CheatSheet Series
  icon: i-simple-icons-github
  to: https://github.com/OWASP/CheatSheetSeries
  target: _blank
  ---
  28K+ ⭐ — Security cheatsheets for developers from OWASP.
  ::

  ::card
  ---
  title: Web Version
  icon: i-lucide-globe
  to: https://cheatsheetseries.owasp.org/
  target: _blank
  ---
  Searchable website for all OWASP cheatsheets.
  ::
::

---

### GTFOBins & LOLBAS

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Reference" color="neutral"}
  :badge{label="LOLBins" color="green"}
  :badge{label="Privilege Escalation" color="blue"}
  :badge{label="Linux" color="orange"}
  :badge{label="Windows" color="red"}
  :badge{label="File Transfer" color="purple"}
::

![GitHub Stars](https://img.shields.io/github/stars/GTFOBins/GTFOBins.github.io?style=for-the-badge&logo=github&color=yellow)

**GTFOBins** (Linux) and **LOLBAS** (Windows) document legitimate system binaries that can be abused for privilege escalation, file transfers, reverse shells, and command execution. These are essential references for post-exploitation when you need to **live off the land**.

Every binary is documented with exact commands for each capability — shell escape, file read/write, SUID exploitation, sudo bypass, and more.

::card-group
  ::card
  ---
  title: GTFOBins
  icon: i-simple-icons-github
  to: https://github.com/GTFOBins/GTFOBins.github.io
  target: _blank
  ---
  11K+ ⭐ — Linux binaries exploitable for privilege escalation and file operations.
  ::

  ::card
  ---
  title: GTFOBins Website
  icon: i-lucide-globe
  to: https://gtfobins.github.io/
  target: _blank
  ---
  Searchable website — filter by capability (shell, file upload, SUID, sudo).
  ::

  ::card
  ---
  title: LOLBAS Project
  icon: i-simple-icons-github
  to: https://github.com/LOLBAS-Project/LOLBAS
  target: _blank
  ---
  1.8K+ ⭐ — Windows Living Off The Land Binaries, Scripts, and Libraries.
  ::

  ::card
  ---
  title: LOLBAS Website
  icon: i-lucide-globe
  to: https://lolbas-project.github.io/
  target: _blank
  ---
  Searchable reference for Windows LOLBins — download, execute, compile, and more.
  ::
::

---

### WADComs & LOLDRIVERS

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Reference" color="neutral"}
  :badge{label="Active Directory" color="green"}
  :badge{label="Windows" color="blue"}
  :badge{label="Drivers" color="orange"}
::

Additional specialized references for Windows and Active Directory environments.

::card-group
  ::card
  ---
  title: WADComs
  icon: i-simple-icons-github
  to: https://github.com/WADComs/WADComs.github.io
  target: _blank
  ---
  Interactive cheatsheet for Windows/AD environment commands — searchable by tool and technique.
  ::

  ::card
  ---
  title: WADComs Website
  icon: i-lucide-globe
  to: https://wadcoms.github.io/
  target: _blank
  ---
  Searchable web interface for Windows and Active Directory offensive commands.
  ::

  ::card
  ---
  title: LOLDrivers
  icon: i-simple-icons-github
  to: https://github.com/magicsword-io/LOLDrivers
  target: _blank
  ---
  Vulnerable and malicious Windows drivers used for kernel exploitation and EDR bypass.
  ::

  ::card
  ---
  title: LOLDrivers Website
  icon: i-lucide-globe
  to: https://www.loldrivers.io/
  target: _blank
  ---
  Searchable database of vulnerable kernel drivers.
  ::
::

---

## :icon{name="i-lucide-scan-search"} Reconnaissance & Enumeration

### Nmap

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Recon" color="neutral"}
  :badge{label="Port Scanner" color="green"}
  :badge{label="Network" color="blue"}
  :badge{label="NSE Scripts" color="orange"}
  :badge{label="Industry Standard" color="red"}
::

![GitHub Stars](https://img.shields.io/github/stars/nmap/nmap?style=for-the-badge&logo=github&color=yellow) ![Language](https://img.shields.io/badge/C/C++-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)

The **most essential network scanning tool** in cybersecurity. Nmap performs host discovery, port scanning, service detection, OS fingerprinting, and vulnerability scanning through its Nmap Scripting Engine (NSE). Used in virtually every penetration test as the first step in network reconnaissance.

Includes **Ncat** (modern netcat), **Nping** (packet crafting), and **Ndiff** (scan comparison).

::card-group
  ::card
  ---
  title: Nmap
  icon: i-simple-icons-github
  to: https://github.com/nmap/nmap
  target: _blank
  ---
  10K+ ⭐ — Network discovery, port scanning, and security auditing.
  ::

  ::card
  ---
  title: Nmap Documentation
  icon: i-lucide-book-open
  to: https://nmap.org/book/
  target: _blank
  ---
  Complete Nmap reference guide — the official book available free online.
  ::
::

---

### Recon Tools Collection

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Recon" color="neutral"}
  :badge{label="Subdomain" color="green"}
  :badge{label="Bug Bounty" color="blue"}
  :badge{label="Automation" color="orange"}
  :badge{label="Go" color="red"}
::

![ProjectDiscovery](https://img.shields.io/badge/ProjectDiscovery-7C3AED?style=for-the-badge) ![tomnomnom](https://img.shields.io/badge/tomnomnom-333?style=for-the-badge)

The **bug bounty reconnaissance ecosystem** is built on these tools. ProjectDiscovery and tomnomnom have created the backbone of modern recon workflows — subdomain enumeration, HTTP probing, vulnerability scanning, and content discovery.

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Subdomain Enumeration"}
  ::card-group
    ::card
    ---
    title: Subfinder
    icon: i-simple-icons-github
    to: https://github.com/projectdiscovery/subfinder
    target: _blank
    ---
    10K+ ⭐ — Fast passive subdomain discovery using dozens of sources (crt.sh, SecurityTrails, Shodan, etc).
    ::

    ::card
    ---
    title: Amass
    icon: i-simple-icons-github
    to: https://github.com/owasp-amass/amass
    target: _blank
    ---
    12K+ ⭐ — OWASP's in-depth attack surface mapping and asset discovery tool.
    ::

    ::card
    ---
    title: Sublist3r
    icon: i-simple-icons-github
    to: https://github.com/aboul3la/Sublist3r
    target: _blank
    ---
    9.5K+ ⭐ — Python subdomain enumeration using search engines and DNS.
    ::

    ::card
    ---
    title: Knockpy
    icon: i-simple-icons-github
    to: https://github.com/guelfoweb/knock
    target: _blank
    ---
    3.5K+ ⭐ — Subdomain enumeration with DNS zone transfer detection.
    ::
  ::
  :::

  :::tabs-item{icon="i-lucide-globe" label="HTTP Probing & Crawling"}
  ::card-group
    ::card
    ---
    title: httpx
    icon: i-simple-icons-github
    to: https://github.com/projectdiscovery/httpx
    target: _blank
    ---
    7.5K+ ⭐ — Fast multi-purpose HTTP toolkit — probe, title extraction, status codes, tech detection.
    ::

    ::card
    ---
    title: httprobe
    icon: i-simple-icons-github
    to: https://github.com/tomnomnom/httprobe
    target: _blank
    ---
    2.8K+ ⭐ — Probe domains for working HTTP/HTTPS servers.
    ::

    ::card
    ---
    title: katana
    icon: i-simple-icons-github
    to: https://github.com/projectdiscovery/katana
    target: _blank
    ---
    12K+ ⭐ — Next-generation web crawling and spidering framework.
    ::

    ::card
    ---
    title: gospider
    icon: i-simple-icons-github
    to: https://github.com/jaeles-project/gospider
    target: _blank
    ---
    2.5K+ ⭐ — Fast web spider for link discovery and JavaScript parsing.
    ::
  ::
  :::

  :::tabs-item{icon="i-lucide-folder-search" label="Content Discovery"}
  ::card-group
    ::card
    ---
    title: feroxbuster
    icon: i-simple-icons-github
    to: https://github.com/epi052/feroxbuster
    target: _blank
    ---
    6K+ ⭐ — Fast, recursive content discovery written in Rust.
    ::

    ::card
    ---
    title: dirsearch
    icon: i-simple-icons-github
    to: https://github.com/maurosoria/dirsearch
    target: _blank
    ---
    12K+ ⭐ — Web path brute-forcer with extensive features and wordlist support.
    ::

    ::card
    ---
    title: gobuster
    icon: i-simple-icons-github
    to: https://github.com/OJ/gobuster
    target: _blank
    ---
    10K+ ⭐ — Directory/file, DNS, and VHost busting tool written in Go.
    ::

    ::card
    ---
    title: ffuf
    icon: i-simple-icons-github
    to: https://github.com/ffuf/ffuf
    target: _blank
    ---
    13K+ ⭐ — Fast web fuzzer for directory, parameter, and header fuzzing.
    ::
  ::
  :::

  :::tabs-item{icon="i-lucide-filter" label="URL & Parameter Tools"}
  ::card-group
    ::card
    ---
    title: waybackurls
    icon: i-simple-icons-github
    to: https://github.com/tomnomnom/waybackurls
    target: _blank
    ---
    3.5K+ ⭐ — Fetch URLs from the Wayback Machine for a domain.
    ::

    ::card
    ---
    title: gau (GetAllURLs)
    icon: i-simple-icons-github
    to: https://github.com/lc/gau
    target: _blank
    ---
    4K+ ⭐ — Fetch URLs from AlienVault, Wayback, Common Crawl, and URLScan.
    ::

    ::card
    ---
    title: Arjun
    icon: i-simple-icons-github
    to: https://github.com/s0md3v/Arjun
    target: _blank
    ---
    4.5K+ ⭐ — HTTP parameter discovery suite — finds hidden GET/POST parameters.
    ::

    ::card
    ---
    title: ParamSpider
    icon: i-simple-icons-github
    to: https://github.com/devanshbatham/ParamSpider
    target: _blank
    ---
    2.5K+ ⭐ — Mining URLs from web archives for parameter discovery.
    ::
  ::
  :::
::

---

### AutoRecon

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Recon" color="neutral"}
  :badge{label="Automation" color="green"}
  :badge{label="OSCP" color="blue"}
  :badge{label="Multi-threaded" color="orange"}
  :badge{label="Python" color="red"}
::

![GitHub Stars](https://img.shields.io/github/stars/Tib3rius/AutoRecon?style=for-the-badge&logo=github&color=yellow)

Created by **Tib3rius**, AutoRecon automates the initial reconnaissance phase by running Nmap, Gobuster, Nikto, and other tools concurrently based on discovered services. Designed specifically for **OSCP exam** and lab environments where time is critical.

::card-group
  ::card
  ---
  title: AutoRecon
  icon: i-simple-icons-github
  to: https://github.com/Tib3rius/AutoRecon
  target: _blank
  ---
  5K+ ⭐ — Multi-threaded network reconnaissance tool for OSCP and pentesting.
  ::
::

---

## :icon{name="i-lucide-scan"} Vulnerability Scanning

### Nuclei

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Scanner" color="neutral"}
  :badge{label="Vulnerability" color="green"}
  :badge{label="Template Based" color="blue"}
  :badge{label="Fast" color="orange"}
  :badge{label="Community Templates" color="red"}
  :badge{label="ProjectDiscovery" color="purple"}
::

![GitHub Stars](https://img.shields.io/github/stars/projectdiscovery/nuclei?style=for-the-badge&logo=github&color=yellow) ![Language](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)

The **most popular open-source vulnerability scanner** in the bug bounty community. Nuclei uses YAML-based templates to send requests and detect vulnerabilities, misconfigurations, exposed panels, and CVEs across web applications, networks, DNS, and more.

The **nuclei-templates** repository contains **8,000+ community-contributed templates** covering CVEs, default credentials, exposed panels, misconfigurations, and technology detection. New templates are added daily by the community.

::card-group
  ::card
  ---
  title: Nuclei
  icon: i-simple-icons-github
  to: https://github.com/projectdiscovery/nuclei
  target: _blank
  ---
  21K+ ⭐ — Fast, customizable vulnerability scanner based on YAML templates.
  ::

  ::card
  ---
  title: Nuclei Templates
  icon: i-simple-icons-github
  to: https://github.com/projectdiscovery/nuclei-templates
  target: _blank
  ---
  9.5K+ ⭐ — 8,000+ community vulnerability detection templates.
  ::

  ::card
  ---
  title: Nuclei Documentation
  icon: i-lucide-book-open
  to: https://docs.projectdiscovery.io/tools/nuclei/
  target: _blank
  ---
  Official documentation with template writing guide and usage examples.
  ::
::

---

### Web Application Scanners

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Scanner" color="neutral"}
  :badge{label="Web" color="green"}
  :badge{label="SQLi" color="blue"}
  :badge{label="XSS" color="orange"}
  :badge{label="CMS" color="red"}
::

::card-group
  ::card
  ---
  title: SQLMap
  icon: i-simple-icons-github
  to: https://github.com/sqlmapproject/sqlmap
  target: _blank
  ---
  33K+ ⭐ — Automatic SQL injection detection and exploitation. Supports every major database.
  ::

  ::card
  ---
  title: XSStrike
  icon: i-simple-icons-github
  to: https://github.com/s0md3v/XSStrike
  target: _blank
  ---
  13K+ ⭐ — Advanced XSS detection suite with fuzzing, crawling, and WAF bypass.
  ::

  ::card
  ---
  title: Nikto
  icon: i-simple-icons-github
  to: https://github.com/sullo/nikto
  target: _blank
  ---
  8.5K+ ⭐ — Web server scanner testing for dangerous files, outdated software, and misconfigurations.
  ::

  ::card
  ---
  title: WPScan
  icon: i-simple-icons-github
  to: https://github.com/wpscanteam/wpscan
  target: _blank
  ---
  8.5K+ ⭐ — WordPress security scanner — plugins, themes, users, and vulnerability enumeration.
  ::

  ::card
  ---
  title: Wapiti
  icon: i-simple-icons-github
  to: https://github.com/wapiti-scanner/wapiti
  target: _blank
  ---
  2K+ ⭐ — Web application vulnerability scanner — SQLi, XSS, SSRF, XXE, and more.
  ::

  ::card
  ---
  title: Dalfox
  icon: i-simple-icons-github
  to: https://github.com/hahwul/dalfox
  target: _blank
  ---
  3.5K+ ⭐ — Parameter analysis and XSS scanner optimized for automation pipelines.
  ::
::

---

## :icon{name="i-lucide-swords"} Exploitation Frameworks & Tools

### Metasploit Framework

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Framework" color="neutral"}
  :badge{label="Exploitation" color="green"}
  :badge{label="Post-Exploitation" color="blue"}
  :badge{label="Industry Standard" color="orange"}
  :badge{label="Ruby" color="red"}
  :badge{label="Rapid7" color="purple"}
::

![GitHub Stars](https://img.shields.io/github/stars/rapid7/metasploit-framework?style=for-the-badge&logo=github&color=yellow) ![Language](https://img.shields.io/badge/Ruby-CC342D?style=for-the-badge&logo=ruby&logoColor=white)

The **world's most used penetration testing framework**. Metasploit provides exploit modules, payloads (Meterpreter, reverse shells), encoders, auxiliary scanners, and post-exploitation modules for every phase of an engagement. Contains over **2,000 exploits** and **600 payloads**.

::card-group
  ::card
  ---
  title: Metasploit Framework
  icon: i-simple-icons-github
  to: https://github.com/rapid7/metasploit-framework
  target: _blank
  ---
  34K+ ⭐ — The most widely used penetration testing and exploitation framework.
  ::

  ::card
  ---
  title: Metasploit Documentation
  icon: i-lucide-book-open
  to: https://docs.metasploit.com/
  target: _blank
  ---
  Official Metasploit docs with module writing guide and usage reference.
  ::
::

---

### Impacket

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Framework" color="neutral"}
  :badge{label="Windows" color="green"}
  :badge{label="Active Directory" color="blue"}
  :badge{label="SMB/WMI/DCOM" color="orange"}
  :badge{label="Python" color="red"}
  :badge{label="Essential" color="purple"}
::

![GitHub Stars](https://img.shields.io/github/stars/fortra/impacket?style=for-the-badge&logo=github&color=yellow) ![Language](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)

The **most important toolkit for Active Directory attacks**. Impacket provides Python implementations of Windows network protocols — SMB, MSRPC, NTLM, Kerberos, WMI, DCOM, LDAP, and more. Essential tools include:

- **secretsdump.py** — Extract hashes from SAM, NTDS.dit, LSA secrets
- **psexec.py** — Remote command execution via SMB
- **wmiexec.py** — Command execution through WMI
- **smbserver.py** — SMB file sharing server
- **GetNPUsers.py** — AS-REP Roasting
- **GetUserSPNs.py** — Kerberoasting

::card-group
  ::card
  ---
  title: Impacket
  icon: i-simple-icons-github
  to: https://github.com/fortra/impacket
  target: _blank
  ---
  14K+ ⭐ — Python collection for working with Windows network protocols.
  ::

  ::card
  ---
  title: Impacket Tools Reference
  icon: i-lucide-book-open
  to: https://tools.thehacker.recipes/impacket
  target: _blank
  ---
  Detailed usage guide for every Impacket script.
  ::
::

---

### Exploitation Tools Collection

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Exploitation" color="neutral"}
  :badge{label="Shells" color="green"}
  :badge{label="C2" color="blue"}
  :badge{label="Web Shells" color="orange"}
::

::card-group
  ::card
  ---
  title: Cobalt Strike (Community Kit)
  icon: i-simple-icons-github
  to: https://github.com/Cobalt-Strike/community_kit
  target: _blank
  ---
  Community extensions, BOFs, and aggressor scripts for Cobalt Strike C2.
  ::

  ::card
  ---
  title: Sliver C2
  icon: i-simple-icons-github
  to: https://github.com/BishopFox/sliver
  target: _blank
  ---
  8.5K+ ⭐ — Open-source cross-platform C2 framework by BishopFox. Alternative to Cobalt Strike.
  ::

  ::card
  ---
  title: Havoc C2
  icon: i-simple-icons-github
  to: https://github.com/HavocFramework/Havoc
  target: _blank
  ---
  7K+ ⭐ — Modern, malleable post-exploitation C2 framework.
  ::

  ::card
  ---
  title: Villain
  icon: i-simple-icons-github
  to: https://github.com/t3l3machus/Villain
  target: _blank
  ---
  4K+ ⭐ — Backdoor generator and multi-session handler for Windows and Linux.
  ::

  ::card
  ---
  title: Reverse Shell Generator
  icon: i-simple-icons-github
  to: https://github.com/0dayCTF/reverse-shell-generator
  target: _blank
  ---
  Source for revshells.com — generate reverse shell payloads in every language.
  ::

  ::card
  ---
  title: webshell
  icon: i-simple-icons-github
  to: https://github.com/tennc/webshell
  target: _blank
  ---
  10K+ ⭐ — Collection of web shells in PHP, ASP, ASPX, JSP, and more.
  ::
::

---

## :icon{name="i-lucide-arrow-up-circle"} Privilege Escalation

### PEASS-ng (linPEAS / winPEAS)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="PrivEsc" color="neutral"}
  :badge{label="Linux" color="green"}
  :badge{label="Windows" color="blue"}
  :badge{label="Enumeration" color="orange"}
  :badge{label="Automated" color="red"}
  :badge{label="Essential" color="purple"}
::

![GitHub Stars](https://img.shields.io/github/stars/peass-ng/PEASS-ng?style=for-the-badge&logo=github&color=yellow)

The **most essential privilege escalation enumeration tool**. PEASS-ng includes:
- **linPEAS** — Linux privilege escalation enumeration (Bash)
- **winPEAS** — Windows privilege escalation enumeration (C#/.NET)
- **macPEAS** — macOS enumeration

These scripts automatically search for misconfigurations, weak permissions, stored credentials, kernel vulnerabilities, and dozens of other privilege escalation vectors. Color-coded output highlights critical findings.

Created by **Carlos Polop** (HackTricks author).

::card-group
  ::card
  ---
  title: PEASS-ng
  icon: i-simple-icons-github
  to: https://github.com/peass-ng/PEASS-ng
  target: _blank
  ---
  16K+ ⭐ — linPEAS, winPEAS, macPEAS — privilege escalation enumeration suite.
  ::

  ::card
  ---
  title: HackTricks — Linux PrivEsc
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html
  target: _blank
  ---
  Comprehensive Linux privilege escalation reference — companion to linPEAS.
  ::

  ::card
  ---
  title: HackTricks — Windows PrivEsc
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html
  target: _blank
  ---
  Comprehensive Windows privilege escalation reference — companion to winPEAS.
  ::
::

---

### Linux Privilege Escalation Tools

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="PrivEsc" color="neutral"}
  :badge{label="Linux" color="green"}
  :badge{label="Kernel" color="blue"}
  :badge{label="SUID" color="orange"}
  :badge{label="Enumeration" color="red"}
::

::card-group
  ::card
  ---
  title: LinEnum
  icon: i-simple-icons-github
  to: https://github.com/rebootuser/LinEnum
  target: _blank
  ---
  7K+ ⭐ — Linux enumeration and privilege escalation checker script.
  ::

  ::card
  ---
  title: linux-exploit-suggester
  icon: i-simple-icons-github
  to: https://github.com/The-Z-Labs/linux-exploit-suggester
  target: _blank
  ---
  2K+ ⭐ — Suggest kernel exploits based on OS release and kernel version.
  ::

  ::card
  ---
  title: linux-smart-enumeration (lse)
  icon: i-simple-icons-github
  to: https://github.com/diego-treitos/linux-smart-enumeration
  target: _blank
  ---
  3K+ ⭐ — Smart Linux enumeration with different verbosity levels.
  ::

  ::card
  ---
  title: pspy
  icon: i-simple-icons-github
  to: https://github.com/DominicBreuker/pspy
  target: _blank
  ---
  5K+ ⭐ — Monitor Linux processes without root — discover cron jobs and running commands.
  ::

  ::card
  ---
  title: traitor
  icon: i-simple-icons-github
  to: https://github.com/liamg/traitor
  target: _blank
  ---
  6.5K+ ⭐ — Automatic Linux privilege escalation — finds and exploits weaknesses.
  ::
::

---

### Windows Privilege Escalation Tools

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="PrivEsc" color="neutral"}
  :badge{label="Windows" color="blue"}
  :badge{label="Token" color="orange"}
  :badge{label="Service" color="red"}
  :badge{label=".NET" color="purple"}
::

::card-group
  ::card
  ---
  title: PowerUp
  icon: i-simple-icons-github
  to: https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
  target: _blank
  ---
  Part of PowerSploit — automated Windows privilege escalation checks in PowerShell.
  ::

  ::card
  ---
  title: PrivescCheck
  icon: i-simple-icons-github
  to: https://github.com/itm4n/PrivescCheck
  target: _blank
  ---
  3K+ ⭐ — Modern Windows privilege escalation enumeration script (PowerShell).
  ::

  ::card
  ---
  title: BeRoot
  icon: i-simple-icons-github
  to: https://github.com/AlessandroZ/BeRoot
  target: _blank
  ---
  2.5K+ ⭐ — Windows/Linux/Mac privilege escalation path finder.
  ::

  ::card
  ---
  title: GodPotato
  icon: i-simple-icons-github
  to: https://github.com/BeichenDream/GodPotato
  target: _blank
  ---
  1.8K+ ⭐ — Windows privilege escalation from Service to SYSTEM via potato technique.
  ::

  ::card
  ---
  title: PrintSpoofer
  icon: i-simple-icons-github
  to: https://github.com/itm4n/PrintSpoofer
  target: _blank
  ---
  1.5K+ ⭐ — SeImpersonatePrivilege to SYSTEM exploitation tool.
  ::

  ::card
  ---
  title: Seatbelt
  icon: i-simple-icons-github
  to: https://github.com/GhostPack/Seatbelt
  target: _blank
  ---
  3.5K+ ⭐ — C# project for performing security-oriented host-survey (GhostPack).
  ::
::

---

## :icon{name="i-lucide-network"} Active Directory & Windows

### BloodHound

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Active Directory" color="neutral"}
  :badge{label="Graph" color="green"}
  :badge{label="Attack Paths" color="blue"}
  :badge{label="Visualization" color="orange"}
  :badge{label="Essential" color="red"}
  :badge{label="SpecterOps" color="purple"}
::

![GitHub Stars](https://img.shields.io/github/stars/SpecterOps/BloodHound?style=for-the-badge&logo=github&color=yellow)

BloodHound uses **graph theory** to reveal hidden and unintended relationships within Active Directory environments. It maps out attack paths from any compromised user to Domain Admin, visualizing complex privilege escalation chains that would be impossible to find manually.

**SharpHound** is the data collector that runs on target systems to gather AD data. BloodHound then ingests this data and presents interactive attack path graphs.

::card-group
  ::card
  ---
  title: BloodHound CE
  icon: i-simple-icons-github
  to: https://github.com/SpecterOps/BloodHound
  target: _blank
  ---
  10K+ ⭐ — AD attack path visualization and analysis — Community Edition.
  ::

  ::card
  ---
  title: BloodHound Legacy
  icon: i-simple-icons-github
  to: https://github.com/BloodHoundAD/BloodHound
  target: _blank
  ---
  10K+ ⭐ — Original BloodHound version with Neo4j backend.
  ::

  ::card
  ---
  title: SharpHound
  icon: i-simple-icons-github
  to: https://github.com/BloodHoundAD/SharpHound
  target: _blank
  ---
  Official BloodHound data collector for Active Directory environments.
  ::
::

---

### Active Directory Attack Tools

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Active Directory" color="neutral"}
  :badge{label="Kerberos" color="green"}
  :badge{label="NTLM" color="blue"}
  :badge{label="Credentials" color="orange"}
  :badge{label="Lateral Movement" color="red"}
::

::card-group
  ::card
  ---
  title: Mimikatz
  icon: i-simple-icons-github
  to: https://github.com/gentilkiwi/mimikatz
  target: _blank
  ---
  20K+ ⭐ — THE Windows credential extraction tool. LSASS dumping, pass-the-hash, golden tickets, DCSync.
  ::

  ::card
  ---
  title: Rubeus
  icon: i-simple-icons-github
  to: https://github.com/GhostPack/Rubeus
  target: _blank
  ---
  4K+ ⭐ — C# Kerberos interaction — AS-REP Roasting, Kerberoasting, ticket manipulation.
  ::

  ::card
  ---
  title: Certipy
  icon: i-simple-icons-github
  to: https://github.com/ly4k/Certipy
  target: _blank
  ---
  6K+ ⭐ — Active Directory Certificate Services (AD CS) exploitation tool.
  ::

  ::card
  ---
  title: CrackMapExec / NetExec
  icon: i-simple-icons-github
  to: https://github.com/Pennyw0rth/NetExec
  target: _blank
  ---
  3K+ ⭐ — Network service exploitation — SMB, WinRM, LDAP, MSSQL credential testing and enumeration.
  ::

  ::card
  ---
  title: Evil-WinRM
  icon: i-simple-icons-github
  to: https://github.com/Hackplayers/evil-winrm
  target: _blank
  ---
  3.5K+ ⭐ — WinRM shell with file upload/download, DLL injection, and PowerShell bypass.
  ::

  ::card
  ---
  title: Responder
  icon: i-simple-icons-github
  to: https://github.com/lgandx/Responder
  target: _blank
  ---
  5.5K+ ⭐ — LLMNR/NBT-NS/mDNS poisoner — capture NTLM hashes on the network.
  ::

  ::card
  ---
  title: PowerView (PowerSploit)
  icon: i-simple-icons-github
  to: https://github.com/PowerShellMafia/PowerSploit
  target: _blank
  ---
  12K+ ⭐ — PowerShell offensive toolkit — AD enumeration, exploitation, and post-exploitation.
  ::

  ::card
  ---
  title: enum4linux-ng
  icon: i-simple-icons-github
  to: https://github.com/cddmp/enum4linux-ng
  target: _blank
  ---
  1.2K+ ⭐ — Next-gen SMB enumeration — users, shares, groups, password policies.
  ::
::

---

### The Hacker Recipes

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Active Directory" color="neutral"}
  :badge{label="Reference" color="green"}
  :badge{label="Methodology" color="blue"}
  :badge{label="Comprehensive" color="orange"}
::

![GitHub Stars](https://img.shields.io/github/stars/ShutdownRepo/The-Hacker-Recipes?style=for-the-badge&logo=github&color=yellow)

An incredible **AD-focused knowledge base** covering every Active Directory attack technique in detail — Kerberos attacks, NTLM relay, AD CS exploitation, delegation attacks, trust abuse, and more. Each technique includes tool commands, theory, and detection information.

::card-group
  ::card
  ---
  title: The Hacker Recipes
  icon: i-simple-icons-github
  to: https://github.com/ShutdownRepo/The-Hacker-Recipes
  target: _blank
  ---
  5K+ ⭐ — Comprehensive AD attack reference with detailed methodology.
  ::

  ::card
  ---
  title: Website
  icon: i-lucide-globe
  to: https://www.thehacker.recipes/
  target: _blank
  ---
  Searchable web version of The Hacker Recipes.
  ::
::

---

## :icon{name="i-lucide-key-round"} Password Attacks & Cracking

### Hashcat & John

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Password Cracking" color="neutral"}
  :badge{label="GPU" color="green"}
  :badge{label="Hash Cracking" color="blue"}
  :badge{label="Rules" color="orange"}
  :badge{label="Essential" color="red"}
::

![GitHub Stars](https://img.shields.io/github/stars/hashcat/hashcat?style=for-the-badge&logo=github&color=yellow)

The two **essential password cracking tools**. Hashcat uses GPU acceleration to crack hashes at incredible speeds, while John the Ripper is more versatile for various hash formats and supports CPU-based cracking.

::card-group
  ::card
  ---
  title: Hashcat
  icon: i-simple-icons-github
  to: https://github.com/hashcat/hashcat
  target: _blank
  ---
  21K+ ⭐ — World's fastest GPU-based password recovery utility. Supports 350+ hash types.
  ::

  ::card
  ---
  title: John the Ripper (Jumbo)
  icon: i-simple-icons-github
  to: https://github.com/openwall/john
  target: _blank
  ---
  10K+ ⭐ — Versatile password cracker with format-specific crackers (ssh2john, zip2john, etc).
  ::

  ::card
  ---
  title: Hashcat Rules
  icon: i-simple-icons-github
  to: https://github.com/NotSoSecure/password_cracking_rules
  target: _blank
  ---
  3K+ ⭐ — OneRuleToRuleThemAll — comprehensive hashcat rule for password cracking.
  ::

  ::card
  ---
  title: CeWL
  icon: i-simple-icons-github
  to: https://github.com/digininja/CeWL
  target: _blank
  ---
  Custom wordlist generator — spider a website to create targeted wordlists.
  ::
::

---

### Hydra & Brute Force

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Brute Force" color="neutral"}
  :badge{label="Online" color="green"}
  :badge{label="Multi-Protocol" color="blue"}
  :badge{label="SSH/FTP/HTTP" color="orange"}
::

::card-group
  ::card
  ---
  title: THC-Hydra
  icon: i-simple-icons-github
  to: https://github.com/vanhauser-thc/thc-hydra
  target: _blank
  ---
  10K+ ⭐ — Online password brute-forcer — SSH, FTP, HTTP, SMB, RDP, MySQL, and 50+ protocols.
  ::

  ::card
  ---
  title: Medusa
  icon: i-simple-icons-github
  to: https://github.com/jmk-foofus/medusa
  target: _blank
  ---
  Parallel network login brute-forcer — alternative to Hydra.
  ::

  ::card
  ---
  title: Patator
  icon: i-simple-icons-github
  to: https://github.com/lanjelot/patator
  target: _blank
  ---
  3.5K+ ⭐ — Multi-purpose brute-forcer with modular design and detailed logging.
  ::
::

---

## :icon{name="i-lucide-file-text"} Wordlists

### SecLists

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Wordlists" color="neutral"}
  :badge{label="Passwords" color="green"}
  :badge{label="Directories" color="blue"}
  :badge{label="Usernames" color="orange"}
  :badge{label="Fuzzing" color="red"}
  :badge{label="Essential" color="purple"}
::

![GitHub Stars](https://img.shields.io/github/stars/danielmiessler/SecLists?style=for-the-badge&logo=github&color=yellow)

The **single most important wordlist collection** in cybersecurity. SecLists contains hundreds of categorized wordlists for every type of security testing:

- **Passwords** — Common passwords, leaked database compilations, default credentials
- **Usernames** — Common usernames, email formats, name lists
- **Discovery** — Web content, DNS subdomains, API endpoints
- **Fuzzing** — SQLi, XSS, command injection, path traversal payloads
- **Pattern Matching** — Regex patterns for sensitive data discovery

Pre-installed on Kali Linux at `/usr/share/seclists/`.

::card-group
  ::card
  ---
  title: SecLists
  icon: i-simple-icons-github
  to: https://github.com/danielmiessler/SecLists
  target: _blank
  ---
  60K+ ⭐ — The security tester's companion — massive wordlist collection for all use cases.
  ::
::

---

### Additional Wordlists

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Wordlists" color="neutral"}
  :badge{label="Specialized" color="green"}
  :badge{label="Content Discovery" color="blue"}
  :badge{label="Passwords" color="orange"}
::

::card-group
  ::card
  ---
  title: RobotsDisallowed
  icon: i-simple-icons-github
  to: https://github.com/danielmiessler/RobotsDisallowed
  target: _blank
  ---
  Wordlists compiled from robots.txt disallowed directories — hidden paths.
  ::

  ::card
  ---
  title: fuzzdb
  icon: i-simple-icons-github
  to: https://github.com/fuzzdb-project/fuzzdb
  target: _blank
  ---
  8K+ ⭐ — Attack patterns, predictable resource locations, and fuzzing strings.
  ::

  ::card
  ---
  title: Assetnote Wordlists
  icon: i-simple-icons-github
  to: https://github.com/assetnote/wordlists
  target: _blank
  ---
  Automated wordlists generated from real-world web application data at scale.
  ::

  ::card
  ---
  title: OneListForAll
  icon: i-simple-icons-github
  to: https://github.com/six2dez/OneListForAll
  target: _blank
  ---
  Combined and deduplicated mega wordlist for web content discovery.
  ::

  ::card
  ---
  title: rockyou2024.txt
  icon: i-lucide-file-text
  to: https://github.com/brannondorsey/naive-hashcat/releases
  target: _blank
  ---
  Updated massive password list — evolved from the original RockYou breach.
  ::

  ::card
  ---
  title: DefaultCreds-cheat-sheet
  icon: i-simple-icons-github
  to: https://github.com/ihebski/DefaultCreds-cheat-sheet
  target: _blank
  ---
  3.5K+ ⭐ — Default credentials for hundreds of products, devices, and services.
  ::
::

---

## :icon{name="i-lucide-shield"} Red Team & Post-Exploitation

### GhostPack

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Post-Exploitation" color="neutral"}
  :badge{label="C#" color="green"}
  :badge{label="Windows" color="blue"}
  :badge{label=".NET" color="orange"}
  :badge{label="SpecterOps" color="red"}
::

The **GhostPack** collection from SpecterOps provides C#/.NET offensive tools designed to run in-memory through `execute-assembly` in C2 frameworks. These tools avoid dropping files to disk and integrate seamlessly with Cobalt Strike, Sliver, and other C2 platforms.

::card-group
  ::card
  ---
  title: Seatbelt
  icon: i-simple-icons-github
  to: https://github.com/GhostPack/Seatbelt
  target: _blank
  ---
  3.5K+ ⭐ — Host security survey — checks for interesting files, credentials, system configs.
  ::

  ::card
  ---
  title: Rubeus
  icon: i-simple-icons-github
  to: https://github.com/GhostPack/Rubeus
  target: _blank
  ---
  4K+ ⭐ — Kerberos abuse — Kerberoast, AS-REP Roast, ticket requests, S4U.
  ::

  ::card
  ---
  title: Certify
  icon: i-simple-icons-github
  to: https://github.com/GhostPack/Certify
  target: _blank
  ---
  1K+ ⭐ — AD Certificate Services enumeration and exploitation.
  ::

  ::card
  ---
  title: SharpUp
  icon: i-simple-icons-github
  to: https://github.com/GhostPack/SharpUp
  target: _blank
  ---
  C# port of PowerUp — Windows privilege escalation checks via execute-assembly.
  ::

  ::card
  ---
  title: SharpDPAPI
  icon: i-simple-icons-github
  to: https://github.com/GhostPack/SharpDPAPI
  target: _blank
  ---
  C# DPAPI credential recovery — browser passwords, Windows Credential Manager.
  ::
::

---

### Evasion & AV Bypass

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Evasion" color="neutral"}
  :badge{label="AV Bypass" color="green"}
  :badge{label="AMSI" color="blue"}
  :badge{label="EDR" color="orange"}
  :badge{label="Obfuscation" color="red"}
::

::card-group
  ::card
  ---
  title: AMSI.fail
  icon: i-simple-icons-github
  to: https://github.com/Flangvik/AMSI.fail
  target: _blank
  ---
  AMSI bypass payload generator for PowerShell sessions.
  ::

  ::card
  ---
  title: Nim-Reverse-Shell
  icon: i-simple-icons-github
  to: https://github.com/Dvd848/Nim-Reverse-Shell
  target: _blank
  ---
  Reverse shell written in Nim — often bypasses AV due to uncommon language.
  ::

  ::card
  ---
  title: ScareCrow
  icon: i-simple-icons-github
  to: https://github.com/Tylous/ScareCrow
  target: _blank
  ---
  4K+ ⭐ — Payload creation framework for EDR bypass — side-loading, process injection.
  ::

  ::card
  ---
  title: Freeze
  icon: i-simple-icons-github
  to: https://github.com/Tylous/Freeze
  target: _blank
  ---
  Payload toolkit for bypassing EDR using suspended processes and syscalls.
  ::

  ::card
  ---
  title: Invoke-Obfuscation
  icon: i-simple-icons-github
  to: https://github.com/danielbohannon/Invoke-Obfuscation
  target: _blank
  ---
  3.5K+ ⭐ — PowerShell script obfuscator to evade detection.
  ::

  ::card
  ---
  title: DefenderCheck
  icon: i-simple-icons-github
  to: https://github.com/matterpreter/DefenderCheck
  target: _blank
  ---
  Identify the exact bytes triggering Windows Defender detection in your payload.
  ::
::

---

### Phishing & Social Engineering

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Social Engineering" color="neutral"}
  :badge{label="Phishing" color="green"}
  :badge{label="Credential Harvest" color="blue"}
  :badge{label="Email" color="orange"}
::

::card-group
  ::card
  ---
  title: Gophish
  icon: i-simple-icons-github
  to: https://github.com/gophish/gophish
  target: _blank
  ---
  12K+ ⭐ — Open-source phishing framework — campaign management, tracking, and reporting.
  ::

  ::card
  ---
  title: Evilginx2
  icon: i-simple-icons-github
  to: https://github.com/kgretzky/evilginx2
  target: _blank
  ---
  11K+ ⭐ — Man-in-the-middle attack framework for phishing credentials AND session cookies (MFA bypass).
  ::

  ::card
  ---
  title: SET (Social-Engineer Toolkit)
  icon: i-simple-icons-github
  to: https://github.com/trustedsec/social-engineer-toolkit
  target: _blank
  ---
  11K+ ⭐ — TrustedSec's social engineering framework — phishing, payloads, and attack vectors.
  ::

  ::card
  ---
  title: King Phisher
  icon: i-simple-icons-github
  to: https://github.com/rsmusllp/king-phisher
  target: _blank
  ---
  2.5K+ ⭐ — Phishing campaign toolkit with detailed analytics and templates.
  ::
::

---

## :icon{name="i-lucide-search"} OSINT (Open Source Intelligence)

### OSINT Frameworks & Collections

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="OSINT" color="neutral"}
  :badge{label="Reconnaissance" color="green"}
  :badge{label="Intelligence" color="blue"}
  :badge{label="People Search" color="orange"}
  :badge{label="Email" color="red"}
::

::card-group
  ::card
  ---
  title: OSINT Framework
  icon: i-simple-icons-github
  to: https://github.com/lockfale/osint-framework
  target: _blank
  ---
  7.5K+ ⭐ — Interactive OSINT tool tree organized by category — the starting point for all OSINT.
  ::

  ::card
  ---
  title: OSINT Framework Website
  icon: i-lucide-globe
  to: https://osintframework.com/
  target: _blank
  ---
  Interactive clickable tree of OSINT tools and resources.
  ::

  ::card
  ---
  title: theHarvester
  icon: i-simple-icons-github
  to: https://github.com/laramies/theHarvester
  target: _blank
  ---
  12K+ ⭐ — Email, subdomain, and name harvesting from public sources.
  ::

  ::card
  ---
  title: Sherlock
  icon: i-simple-icons-github
  to: https://github.com/sherlock-project/sherlock
  target: _blank
  ---
  61K+ ⭐ — Hunt usernames across 400+ social networks simultaneously.
  ::

  ::card
  ---
  title: SpiderFoot
  icon: i-simple-icons-github
  to: https://github.com/smicallef/spiderfoot
  target: _blank
  ---
  13K+ ⭐ — Automated OSINT collection with 200+ modules and web UI.
  ::

  ::card
  ---
  title: Maltego (CE)
  icon: i-lucide-globe
  to: https://www.maltego.com/
  target: _blank
  ---
  Visual link analysis and OSINT platform — Community Edition available free.
  ::

  ::card
  ---
  title: Holehe
  icon: i-simple-icons-github
  to: https://github.com/megadose/holehe
  target: _blank
  ---
  7K+ ⭐ — Check if an email is used on 120+ websites (account enumeration).
  ::

  ::card
  ---
  title: Photon
  icon: i-simple-icons-github
  to: https://github.com/s0md3v/Photon
  target: _blank
  ---
  11K+ ⭐ — Fast web crawler designed for OSINT — extract URLs, emails, files, and accounts.
  ::
::

---

## :icon{name="i-lucide-cpu"} Reverse Engineering

### Ghidra

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Reverse Engineering" color="neutral"}
  :badge{label="Disassembler" color="green"}
  :badge{label="Decompiler" color="blue"}
  :badge{label="NSA" color="orange"}
  :badge{label="Free" color="red"}
  :badge{label="Java" color="purple"}
::

![GitHub Stars](https://img.shields.io/github/stars/NationalSecurityAgency/ghidra?style=for-the-badge&logo=github&color=yellow)

**Ghidra** is a free, open-source software reverse engineering framework developed by the **NSA**. It includes a disassembler, decompiler, scripting, and collaboration features comparable to IDA Pro (which costs thousands of dollars). Supports x86, ARM, MIPS, PowerPC, and dozens of other architectures.

Since its release in 2019, Ghidra has become the **standard free alternative** to IDA Pro and is widely used in malware analysis, vulnerability research, and CTF competitions.

::card-group
  ::card
  ---
  title: Ghidra
  icon: i-simple-icons-github
  to: https://github.com/NationalSecurityAgency/ghidra
  target: _blank
  ---
  53K+ ⭐ — NSA's software reverse engineering framework with decompiler.
  ::

  ::card
  ---
  title: Ghidra Documentation
  icon: i-lucide-book-open
  to: https://ghidra-sre.org/
  target: _blank
  ---
  Official Ghidra website with installation guide and documentation.
  ::

  ::card
  ---
  title: Awesome Ghidra
  icon: i-simple-icons-github
  to: https://github.com/AllsafeCyberSecurity/awesome-ghidra
  target: _blank
  ---
  Curated list of Ghidra scripts, plugins, and resources.
  ::
::

---

### Reverse Engineering Tools

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Reverse Engineering" color="neutral"}
  :badge{label="Binary Analysis" color="green"}
  :badge{label="Debugging" color="blue"}
  :badge{label="Decompilation" color="orange"}
::

::card-group
  ::card
  ---
  title: radare2
  icon: i-simple-icons-github
  to: https://github.com/radareorg/radare2
  target: _blank
  ---
  21K+ ⭐ — UNIX-like reverse engineering framework and command-line toolset.
  ::

  ::card
  ---
  title: Cutter
  icon: i-simple-icons-github
  to: https://github.com/rizinorg/cutter
  target: _blank
  ---
  16K+ ⭐ — Qt-based GUI for radare2/rizin — user-friendly RE interface.
  ::

  ::card
  ---
  title: Binary Ninja (Cloud)
  icon: i-lucide-globe
  to: https://cloud.binary.ninja/
  target: _blank
  ---
  Free cloud version of Binary Ninja — modern binary analysis platform.
  ::

  ::card
  ---
  title: pwntools
  icon: i-simple-icons-github
  to: https://github.com/Gallopsled/pwntools
  target: _blank
  ---
  12K+ ⭐ — CTF framework and exploit development library for Python.
  ::

  ::card
  ---
  title: GEF (GDB Enhanced Features)
  icon: i-simple-icons-github
  to: https://github.com/hugsy/gef
  target: _blank
  ---
  7K+ ⭐ — GDB extension for exploit development and reverse engineering.
  ::

  ::card
  ---
  title: pwndbg
  icon: i-simple-icons-github
  to: https://github.com/pwndbg/pwndbg
  target: _blank
  ---
  7.5K+ ⭐ — GDB plugin for exploit development — heap visualization, context display.
  ::

  ::card
  ---
  title: x64dbg
  icon: i-simple-icons-github
  to: https://github.com/x64dbg/x64dbg
  target: _blank
  ---
  45K+ ⭐ — Open-source x64/x32 Windows debugger — modern alternative to OllyDbg.
  ::

  ::card
  ---
  title: dnSpy
  icon: i-simple-icons-github
  to: https://github.com/dnSpy/dnSpy
  target: _blank
  ---
  26K+ ⭐ — .NET debugger, decompiler, and assembly editor.
  ::
::

---

## :icon{name="i-lucide-wifi"} Network & Wireless

### Network Tools

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Network" color="neutral"}
  :badge{label="WiFi" color="green"}
  :badge{label="MitM" color="blue"}
  :badge{label="Proxy" color="orange"}
  :badge{label="Tunnel" color="red"}
::

::card-group
  ::card
  ---
  title: Wireshark
  icon: i-simple-icons-github
  to: https://github.com/wireshark/wireshark
  target: _blank
  ---
  7.5K+ ⭐ — World's foremost network protocol analyzer — packet capture and analysis.
  ::

  ::card
  ---
  title: Bettercap
  icon: i-simple-icons-github
  to: https://github.com/bettercap/bettercap
  target: _blank
  ---
  17K+ ⭐ — Swiss Army knife for network attacks — ARP spoofing, WiFi, BLE, HID, and more.
  ::

  ::card
  ---
  title: mitmproxy
  icon: i-simple-icons-github
  to: https://github.com/mitmproxy/mitmproxy
  target: _blank
  ---
  37K+ ⭐ — Interactive TLS-capable man-in-the-middle proxy for HTTP/HTTPS traffic.
  ::

  ::card
  ---
  title: Aircrack-ng
  icon: i-simple-icons-github
  to: https://github.com/aircrack-ng/aircrack-ng
  target: _blank
  ---
  5.5K+ ⭐ — WiFi security auditing — WEP/WPA/WPA2 cracking, packet injection, monitoring.
  ::

  ::card
  ---
  title: Chisel
  icon: i-simple-icons-github
  to: https://github.com/jpillora/chisel
  target: _blank
  ---
  13K+ ⭐ — Fast TCP/UDP tunnel over HTTP — pivoting and port forwarding through firewalls.
  ::

  ::card
  ---
  title: Ligolo-ng
  icon: i-simple-icons-github
  to: https://github.com/nicocha30/ligolo-ng
  target: _blank
  ---
  3K+ ⭐ — Advanced tunneling/pivoting tool using TUN interfaces — modern alternative to SSH tunnels.
  ::

  ::card
  ---
  title: proxychains-ng
  icon: i-simple-icons-github
  to: https://github.com/rofl0r/proxychains-ng
  target: _blank
  ---
  10K+ ⭐ — Force any TCP connection through SOCKS4/5 or HTTP proxies.
  ::

  ::card
  ---
  title: Wifite2
  icon: i-simple-icons-github
  to: https://github.com/derv82/wifite2
  target: _blank
  ---
  3.5K+ ⭐ — Automated wireless attack tool — WPS, WPA, WEP auditing.
  ::
::

---

## :icon{name="i-lucide-smartphone"} Web Proxy & Application Testing

### Burp Suite Ecosystem

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Web Testing" color="neutral"}
  :badge{label="Proxy" color="green"}
  :badge{label="Extensions" color="blue"}
  :badge{label="Burp Suite" color="orange"}
::

::card-group
  ::card
  ---
  title: Awesome Burp Extensions
  icon: i-simple-icons-github
  to: https://github.com/snoopysecurity/awesome-burp-extensions
  target: _blank
  ---
  2.5K+ ⭐ — Curated list of Burp Suite extensions for every testing scenario.
  ::

  ::card
  ---
  title: BurpSuite-For-Pentester
  icon: i-simple-icons-github
  to: https://github.com/Jeenali-Jeenali/BurpSuite-For-Pentester
  target: _blank
  ---
  Burp Suite usage guides and tips organized by vulnerability type.
  ::

  ::card
  ---
  title: Caido
  icon: i-lucide-globe
  to: https://caido.io/
  target: _blank
  ---
  Modern, lightweight web security testing tool — alternative to Burp Suite.
  ::
::

---

## :icon{name="i-lucide-graduation-cap"} Learning & CTF Resources

### Vulnerable Applications

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Learning" color="neutral"}
  :badge{label="Vulnerable Apps" color="green"}
  :badge{label="Practice" color="blue"}
  :badge{label="Web Security" color="orange"}
  :badge{label="Safe Environment" color="red"}
::

Practice environments with **intentionally vulnerable** applications for safe, legal security testing.

::card-group
  ::card
  ---
  title: DVWA
  icon: i-simple-icons-github
  to: https://github.com/digininja/DVWA
  target: _blank
  ---
  10K+ ⭐ — Damn Vulnerable Web Application — classic PHP/MySQL training app.
  ::

  ::card
  ---
  title: Juice Shop
  icon: i-simple-icons-github
  to: https://github.com/juice-shop/juice-shop
  target: _blank
  ---
  10.5K+ ⭐ — OWASP's modern insecure web app — Node.js with 100+ challenges.
  ::

  ::card
  ---
  title: WebGoat
  icon: i-simple-icons-github
  to: https://github.com/WebGoat/WebGoat
  target: _blank
  ---
  7K+ ⭐ — OWASP's deliberately insecure Java web application for learning.
  ::

  ::card
  ---
  title: VulnHub
  icon: i-lucide-globe
  to: https://www.vulnhub.com/
  target: _blank
  ---
  Downloadable vulnerable VMs for offline practice — hundreds of machines.
  ::

  ::card
  ---
  title: GOAD (Game of Active Directory)
  icon: i-simple-icons-github
  to: https://github.com/Orange-Cyberdefense/GOAD
  target: _blank
  ---
  4.5K+ ⭐ — Deploy a vulnerable Active Directory lab with Vagrant — 5 VMs, 2 forests, 3 domains.
  ::

  ::card
  ---
  title: Vulnerable-AD
  icon: i-simple-icons-github
  to: https://github.com/WazeHell/vulnerable-AD
  target: _blank
  ---
  Create an intentionally vulnerable Active Directory environment for testing.
  ::
::

---

### CTF Tools & Write-ups

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="CTF" color="neutral"}
  :badge{label="Write-ups" color="green"}
  :badge{label="Tools" color="blue"}
  :badge{label="Challenges" color="orange"}
::

::card-group
  ::card
  ---
  title: CTF Write-ups Collection
  icon: i-simple-icons-github
  to: https://github.com/ctfs
  target: _blank
  ---
  Massive collection of CTF write-ups organized by competition and year.
  ::

  ::card
  ---
  title: CTF Tools
  icon: i-simple-icons-github
  to: https://github.com/zardus/ctf-tools
  target: _blank
  ---
  4.5K+ ⭐ — Automated installer for CTF tools — one script to set up everything.
  ::

  ::card
  ---
  title: RsaCtfTool
  icon: i-simple-icons-github
  to: https://github.com/RsaCtfTool/RsaCtfTool
  target: _blank
  ---
  5.5K+ ⭐ — RSA attack toolkit for CTF challenges — multiple attack methods.
  ::

  ::card
  ---
  title: CyberChef
  icon: i-simple-icons-github
  to: https://github.com/gchq/CyberChef
  target: _blank
  ---
  29K+ ⭐ — GCHQ's "Cyber Swiss Army Knife" — encoding, encryption, compression, data analysis in browser.
  ::

  ::card
  ---
  title: CyberChef Online
  icon: i-lucide-globe
  to: https://gchq.github.io/CyberChef/
  target: _blank
  ---
  Use CyberChef directly in your browser — drag-and-drop data operations.
  ::

  ::card
  ---
  title: pwntools
  icon: i-simple-icons-github
  to: https://github.com/Gallopsled/pwntools
  target: _blank
  ---
  12K+ ⭐ — CTF framework and exploit development library — essential for pwn challenges.
  ::
::

---

### Roadmaps & Study Guides

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Learning" color="neutral"}
  :badge{label="Career" color="green"}
  :badge{label="Roadmap" color="blue"}
  :badge{label="OSCP" color="orange"}
  :badge{label="Beginner" color="red"}
::

::card-group
  ::card
  ---
  title: Hacker Roadmap
  icon: i-simple-icons-github
  to: https://github.com/sundowndev/hacker-roadmap
  target: _blank
  ---
  14K+ ⭐ — Guide for amateur pentesters — from beginner to advanced with tool recommendations.
  ::

  ::card
  ---
  title: OSCP Preparation Guide
  icon: i-simple-icons-github
  to: https://github.com/0xsyr0/OSCP
  target: _blank
  ---
  OSCP exam preparation — commands, cheatsheets, and methodology.
  ::

  ::card
  ---
  title: Awesome OSCP
  icon: i-simple-icons-github
  to: https://github.com/0x4D31/awesome-oscp
  target: _blank
  ---
  Curated list of OSCP resources, walkthroughs, and preparation materials.
  ::

  ::card
  ---
  title: Pentesting Bible
  icon: i-simple-icons-github
  to: https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE
  target: _blank
  ---
  Extensive penetration testing references, tools, and articles organized by topic.
  ::

  ::card
  ---
  title: Beginner Network Pentesting
  icon: i-simple-icons-github
  to: https://github.com/hmaverickadams/Beginner-Network-Pentesting
  target: _blank
  ---
  TCM Security's beginner course companion — network pentesting fundamentals.
  ::
::

---

## :icon{name="i-lucide-container"} Distributions & Environments

### Security Distributions

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Distribution" color="neutral"}
  :badge{label="Linux" color="green"}
  :badge{label="Pre-configured" color="blue"}
  :badge{label="Tools" color="orange"}
::

::card-group
  ::card
  ---
  title: Kali Linux
  icon: i-simple-icons-github
  to: https://gitlab.com/kalilinux
  target: _blank
  ---
  The most popular penetration testing distribution — 600+ pre-installed tools.
  ::

  ::card
  ---
  title: Kali Website
  icon: i-lucide-globe
  to: https://www.kali.org/
  target: _blank
  ---
  Official Kali Linux downloads, documentation, and tool listings.
  ::

  ::card
  ---
  title: Parrot OS
  icon: i-lucide-globe
  to: https://www.parrotsec.org/
  target: _blank
  ---
  Security-focused GNU/Linux distribution — lighter alternative to Kali.
  ::

  ::card
  ---
  title: BlackArch Linux
  icon: i-simple-icons-github
  to: https://github.com/BlackArch/blackarch
  target: _blank
  ---
  Arch Linux-based pentesting distribution with 2,800+ tools.
  ::

  ::card
  ---
  title: Commando VM
  icon: i-simple-icons-github
  to: https://github.com/mandiant/commando-vm
  target: _blank
  ---
  7K+ ⭐ — Mandiant's Windows-based penetration testing virtual machine.
  ::

  ::card
  ---
  title: Exegol
  icon: i-simple-icons-github
  to: https://github.com/ThePorgs/Exegol
  target: _blank
  ---
  3K+ ⭐ — Docker-based hacking environment — pre-configured with all tools.
  ::
::

---

## :icon{name="i-lucide-scroll-text"} Cheatsheets & Quick References

### Comprehensive Cheatsheets

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Cheatsheet" color="neutral"}
  :badge{label="Quick Reference" color="green"}
  :badge{label="Commands" color="blue"}
  :badge{label="Printable" color="orange"}
::

::card-group
  ::card
  ---
  title: Reverse Shell Cheatsheet
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
  target: _blank
  ---
  Every reverse shell one-liner — Bash, Python, PHP, PowerShell, Java, and more.
  ::

  ::card
  ---
  title: RevShells.com
  icon: i-lucide-globe
  to: https://www.revshells.com/
  target: _blank
  ---
  Interactive reverse shell generator — select language, encoding, and listener.
  ::

  ::card
  ---
  title: Pentest Cheatsheets
  icon: i-simple-icons-github
  to: https://github.com/coreb1t/awesome-pentest-cheat-sheets
  target: _blank
  ---
  4.5K+ ⭐ — Collection of cheatsheets for OSCP, Nmap, Metasploit, and more.
  ::

  ::card
  ---
  title: RTFM (Red Team Field Manual)
  icon: i-simple-icons-github
  to: https://github.com/leostat/rtfm
  target: _blank
  ---
  Searchable database of common pentesting commands and one-liners.
  ::

  ::card
  ---
  title: explainshell.com
  icon: i-lucide-globe
  to: https://explainshell.com/
  target: _blank
  ---
  Paste any Linux command and get a visual breakdown of what each part does.
  ::

  ::card
  ---
  title: Nmap Cheatsheet
  icon: i-simple-icons-github
  to: https://github.com/jasonniebauer/Nmap-Cheatsheet
  target: _blank
  ---
  Quick reference for Nmap scan types, scripts, and output formats.
  ::
::

---

## :icon{name="i-lucide-list-checks"} Category Quick Reference

::collapsible

| Category | Top Repositories |
| -------- | ---------------- |
| **Knowledge Base** | PayloadsAllTheThings · HackTricks · Book of Secret Knowledge · OWASP CheatSheets |
| **Recon** | Nmap · Subfinder · Amass · httpx · ffuf · katana · feroxbuster · AutoRecon |
| **Scanning** | Nuclei · SQLMap · XSStrike · Nikto · WPScan · Dalfox |
| **Exploitation** | Metasploit · Impacket · Sliver C2 · Havoc · webshell |
| **PrivEsc** | PEASS-ng · pspy · traitor · GodPotato · PrintSpoofer · Seatbelt |
| **Active Directory** | BloodHound · Mimikatz · Rubeus · Certipy · Responder · NetExec |
| **Password** | Hashcat · John the Ripper · Hydra · CeWL · DefaultCreds |
| **Wordlists** | SecLists · fuzzdb · Assetnote · OneListForAll |
| **Red Team** | ScareCrow · Freeze · Evilginx2 · Gophish · SET |
| **OSINT** | Sherlock · SpiderFoot · theHarvester · Holehe · Photon |
| **Reverse Engineering** | Ghidra · radare2 · x64dbg · pwntools · GEF · dnSpy |
| **Network** | Wireshark · Bettercap · Chisel · Ligolo-ng · Aircrack-ng |
| **CTF** | CyberChef · pwntools · RsaCtfTool · CTF-tools |
| **Learning** | DVWA · Juice Shop · GOAD · Hacker Roadmap · Awesome OSCP |
| **Distributions** | Kali Linux · Parrot OS · BlackArch · Commando VM · Exegol |
| **LOLBins** | GTFOBins · LOLBAS · WADComs · LOLDrivers |

::

---

## :icon{name="i-lucide-route"} Learning Path by GitHub Repos

::steps{level="4"}

#### Stage 1 — Foundations

| What to Learn | Repository |
| ------------- | ---------- |
| Linux commands | [explainshell.com](https://explainshell.com/) |
| Networking | [Nmap](https://github.com/nmap/nmap) |
| Web security concepts | [OWASP CheatSheets](https://github.com/OWASP/CheatSheetSeries) |
| Practice safely | [DVWA](https://github.com/digininja/DVWA) / [Juice Shop](https://github.com/juice-shop/juice-shop) |

#### Stage 2 — Core Skills

| What to Learn | Repository |
| ------------- | ---------- |
| Methodology reference | [HackTricks](https://book.hacktricks.wiki/) |
| Payloads & bypasses | [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| Enumeration | [linPEAS / winPEAS](https://github.com/peass-ng/PEASS-ng) |
| Content discovery | [SecLists](https://github.com/danielmiessler/SecLists) + [ffuf](https://github.com/ffuf/ffuf) |

#### Stage 3 — Specialization

| Focus Area | Key Repositories |
| ---------- | --------------- |
| Web / Bug Bounty | Nuclei · Subfinder · httpx · Burp Extensions |
| Active Directory | BloodHound · Impacket · Mimikatz · Rubeus |
| Binary / RE | Ghidra · pwntools · GEF · x64dbg |
| Red Team | Sliver · ScareCrow · Evilginx2 |

#### Stage 4 — Advanced

| Focus Area | Key Repositories |
| ---------- | --------------- |
| CVE research | Nuclei Templates · Exploit-DB |
| Custom tooling | pwntools · Impacket · Go/Rust tools |
| Evasion | ScareCrow · AMSI.fail · DefenderCheck |
| AD labs | GOAD · Vulnerable-AD |

::

---

## :icon{name="i-lucide-bookmark"} Platforms & Communities

::card-group
  ::card
  ---
  title: Hack The Box
  icon: i-lucide-swords
  to: https://www.hackthebox.com/
  target: _blank
  ---
  Gamified cybersecurity training — machines, challenges, and pro labs.
  ::

  ::card
  ---
  title: TryHackMe
  icon: i-lucide-graduation-cap
  to: https://tryhackme.com/
  target: _blank
  ---
  Beginner-friendly guided cybersecurity learning paths.
  ::

  ::card
  ---
  title: PortSwigger Academy
  icon: i-lucide-globe
  to: https://portswigger.net/web-security
  target: _blank
  ---
  Free world-class web security training with interactive labs.
  ::

  ::card
  ---
  title: PentesterLab
  icon: i-lucide-flask-conical
  to: https://pentesterlab.com/
  target: _blank
  ---
  Hands-on web security exercises from basic to advanced.
  ::

  ::card
  ---
  title: VulnHub
  icon: i-lucide-monitor
  to: https://www.vulnhub.com/
  target: _blank
  ---
  Free downloadable vulnerable VMs for offline practice.
  ::

  ::card
  ---
  title: CTFtime
  icon: i-lucide-trophy
  to: https://ctftime.org/
  target: _blank
  ---
  CTF competition calendar, team rankings, and write-up archive.
  ::

  ::card
  ---
  title: Exploit-DB
  icon: i-lucide-bug
  to: https://www.exploit-db.com/
  target: _blank
  ---
  Public exploit database maintained by OffSec — searchable CVE archive.
  ::

  ::card
  ---
  title: ippsec.rocks
  icon: i-lucide-search
  to: https://ippsec.rocks/
  target: _blank
  ---
  Search across all IppSec HTB walkthrough videos by keyword.
  ::
::
