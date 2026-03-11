---
title: From Script Kiddie to Hacker
description: A complete 12-month transformation roadmap to evolve from running other people's tools to understanding systems deeply enough to break them yourself — covering mindset, methodology, thinking patterns, free courses, YouTube channels, books, labs, and the daily habits that build real hackers.
navigation:
  icon: i-lucide-graduation-cap
  title: Script Kiddie to Hacker
---

## Introduction

There is a **fundamental difference** between a script kiddie and a hacker. A script kiddie downloads tools and runs them without understanding what happens underneath. A hacker **understands the systems** deeply enough to find their own vulnerabilities, write their own tools, and think creatively about problems nobody has solved before.

This guide is your **12-month transformation roadmap** — entirely free.

::note
This is not about memorizing commands or collecting tools. This is about **rewiring how your brain approaches technology**. By the end of this year, you won't need someone else's tutorial to hack something — you'll understand the system well enough to figure it out yourself.
::

```
┌─────────────────────────────────────────────────────────────────────┐
│                THE TRANSFORMATION JOURNEY                           │
│                                                                     │
│  SCRIPT KIDDIE                              HACKER                  │
│  ─────────────                              ──────                  │
│  • Runs tools blindly                       • Understands WHY       │
│  • Copies commands                          • Writes own tools      │
│  • Follows tutorials step-by-step           • Creates methodology   │
│  • Panics when tool fails                   • Debugs and adapts     │
│  • Knows WHAT buttons to press              • Knows HOW systems work│
│  • Collects 100 tools                       • Masters 10 tools      │
│  • "It didn't work"                         • "Let me check why"    │
│  • Skips fundamentals                       • Built on fundamentals │
│  • Wants quick results                      • Values deep learning  │
│  • Gives up at first error                  • Errors are clues      │
│                                                                     │
│  Month 1 ──────────────────────────────────────────────── Month 12  │
│  ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 100%  │
│                                                                     │
│  The gap is not talent. It's UNDERSTANDING.                         │
└─────────────────────────────────────────────────────────────────────┘
```

::card-group
  ::card
  ---
  title: The Hacker Mindset
  icon: i-lucide-brain
  to: https://www.ted.com/talks/bruce_schneier_the_security_mindset
  target: _blank
  ---
  Bruce Schneier's TED Talk on the security mindset — how hackers think differently about systems and trust.
  ::

  ::card
  ---
  title: How to Become a Hacker (ESR)
  icon: i-lucide-book-open
  to: http://www.catb.org/~esr/faqs/hacker-howto.html
  target: _blank
  ---
  Eric S. Raymond's classic essay on the hacker attitude, skills, and culture. Written in 2001, still perfectly relevant.
  ::

  ::card
  ---
  title: Teach Yourself CS
  icon: i-lucide-graduation-cap
  to: https://teachyourselfcs.com/
  target: _blank
  ---
  The best free computer science curriculum. Covers the fundamentals that separate real hackers from tool-runners.
  ::

  ::card
  ---
  title: OSINT Framework
  icon: i-lucide-search
  to: https://osintframework.com/
  target: _blank
  ---
  Complete collection of free OSINT tools and resources organized by category. Master research before exploitation.
  ::
::

::badge
**Tags: tutorials · study-guide · beginner · hacking · mindset · free-courses · youtube · books · learning-path · career · cybersecurity**
::

---

## The Hacker Mindset — What Changes Everything

::warning
**The single biggest difference** between a script kiddie and a hacker is not knowledge — it's *how they think*. You can memorize every tool on Kali Linux and still be a script kiddie. Or you can deeply understand TCP/IP and HTTP and find vulnerabilities nobody has seen before.
::

### The 7 Principles of Hacker Thinking

::accordion
  :::accordion-item{icon="i-lucide-lightbulb" label="1. Understand the System Before Attacking It"}
  ```
  SCRIPT KIDDIE APPROACH:
  ───────────────────────
  "I found a tool called SQLMap. Let me run it against this website."
  → sqlmap -u "http://target.com/page?id=1" --dbs
  → "It says no injection found. This site isn't vulnerable."
  → Gives up. Moves to next target.
  
  HACKER APPROACH:
  ────────────────
  "How does this application handle user input?"
  → Opens browser DevTools → Examines HTTP requests
  → "This parameter goes to a PHP backend"
  → "PHP often uses MySQL. Let me understand the query structure"
  → Manually tests: ' → gets error → reads error message
  → "It's using PDO but this endpoint uses string concatenation"
  → "The WAF blocks UNION but not stacked queries via encoding"
  → Crafts custom payload based on understanding
  → Extracts data
  
  THE DIFFERENCE: Understanding > Tools
  ```
  :::

  :::accordion-item{icon="i-lucide-search" label="2. Read Error Messages — They Are Your Friends"}
  ```
  A script kiddie sees an error and thinks: "It's broken."
  A hacker sees an error and thinks: "It's telling me something."
  
  EXAMPLES:
  ─────────
  Error: "Connection refused on port 3306"
  → HACKER: "MySQL is running but only accepting localhost.
             Let me check if there's a web app that connects to it.
             Maybe I can reach it through SSRF."
  
  Error: "Permission denied"
  → HACKER: "What permissions DO I have? What user am I?
             What groups am I in? What can that group access?"
  
  Error: "500 Internal Server Error"
  → HACKER: "The backend crashed processing my input.
             That means my input REACHED the backend logic.
             Let me fuzz this parameter more carefully."
  
  Error: "Segmentation fault"
  → HACKER: "I caused a memory corruption. This might be
             exploitable. Let me analyze the crash."
  
  HABIT: Never ignore error messages. Copy them.
         Google them. Understand them. They are CLUES.
  ```
  :::

  :::accordion-item{icon="i-lucide-layers" label="3. Think in Layers — Everything is Built on Something"}
  ```
  A web application is not just "a website."
  It's layers upon layers:
  
  ┌─────────────────────────────────────┐
  │  User clicks a button               │ ← Browser / DOM
  ├─────────────────────────────────────┤
  │  JavaScript sends AJAX request      │ ← Client-side code
  ├─────────────────────────────────────┤
  │  HTTPS request over TLS 1.3         │ ← Encryption layer
  ├─────────────────────────────────────┤
  │  Nginx reverse proxy receives it    │ ← Web server
  ├─────────────────────────────────────┤
  │  Passes to PHP-FPM / Node.js        │ ← Application runtime
  ├─────────────────────────────────────┤
  │  Application processes input        │ ← Business logic
  ├─────────────────────────────────────┤
  │  Queries MySQL database             │ ← Data layer
  ├─────────────────────────────────────┤
  │  MySQL runs on Linux as mysql user  │ ← Operating system
  ├─────────────────────────────────────┤
  │  Linux kernel manages resources     │ ← Kernel
  ├─────────────────────────────────────┤
  │  Physical server in a data center   │ ← Hardware
  └─────────────────────────────────────┘
  
  EVERY LAYER is an attack surface.
  EVERY LAYER has its own vulnerabilities.
  UNDERSTANDING EACH LAYER = Finding vulns others miss.
  ```
  :::

  :::accordion-item{icon="i-lucide-repeat" label="4. Ask 'What If?' Constantly"}
  ```
  The hacker's brain runs a constant loop:
  
  "What if I change this value?"
  "What if I send a negative number?"
  "What if I send a really long string?"
  "What if I change the HTTP method?"
  "What if I access this as a different user?"
  "What if I remove this cookie?"
  "What if I add a header that shouldn't be there?"
  "What if I send the request twice, really fast?"
  "What if the validation is only client-side?"
  "What if I access the API endpoint directly?"
  "What if I use IPv6 instead of IPv4?"
  "What if there's a race condition here?"
  "What if the backup file is still on the server?"
  "What if the staging server has weaker security?"
  "What if this error message leaks internal paths?"
  
  This is not random guessing.
  This is SYSTEMATIC HYPOTHESIS TESTING.
  
  Every "what if" has a reason behind it —
  a pattern you learned from understanding systems.
  ```
  :::

  :::accordion-item{icon="i-lucide-book-open" label="5. Read Source Code — Even If It Hurts"}
  ```
  Script kiddies avoid reading code.
  Hackers READ EVERYTHING:
  
  • Open-source application code (GitHub)
  • JavaScript source in web applications
  • Decompiled Android APKs
  • Configuration files
  • Documentation and comments
  • Commit histories (secrets in old commits!)
  • Dockerfiles and docker-compose.yml
  • CI/CD pipeline configurations
  • Error logs and stack traces
  • RFC documents for protocols
  
  WHY?
  ─────
  → Vulnerabilities LIVE in code
  → Understanding code = understanding the attack surface
  → Comments reveal developer assumptions
  → Old commits reveal secrets
  → Configuration reveals architecture
  
  You don't need to be a senior developer.
  You need to READ code and spot patterns:
  - user input going into SQL queries
  - missing authentication checks
  - hardcoded credentials
  - unsafe deserialization
  - path concatenation without sanitization
  ```
  :::

  :::accordion-item{icon="i-lucide-puzzle" label="6. Build Things to Understand How to Break Them"}
  ```
  THE PARADOX: The best hackers are also good builders.
  
  You cannot effectively break what you don't understand.
  
  BUILD THESE (even simple versions):
  ────────────────────────────────────
  1. A web application with a login page
     → Now you understand auth vulnerabilities
  
  2. A REST API with a database
     → Now you understand injection attacks
  
  3. A client-server chat application
     → Now you understand network protocols
  
  4. A simple firewall rule set
     → Now you understand bypass techniques
  
  5. A basic port scanner in Python
     → Now you understand what Nmap actually does
  
  6. A reverse shell in Python
     → Now you understand post-exploitation
  
  7. A web scraper
     → Now you understand web application structure
  
  8. A packet sniffer
     → Now you understand network traffic
  
  EVERY THING YOU BUILD teaches you
  HOW IT CAN BE BROKEN.
  ```
  :::

  :::accordion-item{icon="i-lucide-flame" label="7. Embrace the Struggle — Frustration = Growth"}
  ```
  IF YOU ARE NOT STRUGGLING, YOU ARE NOT LEARNING.
  
  The uncomfortable truth:
  ─────────────────────────
  • You WILL spend hours on problems that seem simple
  • You WILL feel stupid compared to others
  • You WILL fail CTF challenges that "everyone" solved
  • You WILL break your own lab environment
  • You WILL read documentation that makes no sense
  • You WILL get stuck on concepts for DAYS
  
  THIS IS NORMAL. THIS IS THE PROCESS.
  
  Every expert hacker went through this exact phase.
  The only difference between them and people who quit?
  
  THEY KEPT GOING.
  
  ┌─────────────────────────────────────────┐
  │  Comfort Zone → Learning Zone →         │
  │  Panic Zone → Back to Learning Zone →   │
  │  New Comfort Zone (bigger)              │
  │                                         │
  │  Repeat for 12 months.                  │
  │  You will be unrecognizable.            │
  └─────────────────────────────────────────┘
  ```
  :::
::

---

## The Daily Habits That Build Hackers

::tip
Consistency beats intensity. **30 minutes every day** is better than 8 hours once a week. Your brain needs repetition to build neural pathways for technical thinking.
::

### Daily Learning Framework

```
┌─────────────────────────────────────────────────────────────┐
│                 DAILY STUDY TEMPLATE                         │
│                 (2-4 hours per day)                          │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  30 min │ READ — Articles, docs, write-ups            │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │  60 min │ STUDY — Course material, videos, books      │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │  60 min │ PRACTICE — Labs, CTFs, challenges           │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │  30 min │ BUILD — Code something, automate something  │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │  15 min │ REFLECT — Write notes, document learnings   │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  WEEKENDS: Deep dive into one topic for 4-6 hours           │
│  (CTF participation, longer labs, building projects)        │
└─────────────────────────────────────────────────────────────┘
```

### The Note-Taking System

::caution
**If you don't take notes, you don't learn.** Your brain forgets 80% of what you read within 48 hours. Notes are your external brain.
::

::card-group
  ::card
  ---
  title: Obsidian
  icon: i-simple-icons-obsidian
  to: https://obsidian.md/
  target: _blank
  ---
  Free, local-first Markdown note-taking app. Graph view connects your knowledge. The most popular choice among pentesters for building a personal knowledge base.
  ::

  ::card
  ---
  title: Notion
  icon: i-simple-icons-notion
  to: https://www.notion.so/
  target: _blank
  ---
  All-in-one workspace for notes, databases, and project management. Free personal plan. Good for structured study plans and checklists.
  ::

  ::card
  ---
  title: CherryTree
  icon: i-lucide-tree-pine
  to: https://www.giuspen.com/cherrytree/
  target: _blank
  ---
  Hierarchical note-taking app popular with CTF players and pentesters. Supports code blocks, images, and rich text. Completely free and open-source.
  ::

  ::card
  ---
  title: Joplin
  icon: i-simple-icons-joplin
  to: https://joplinapp.org/
  target: _blank
  ---
  Open-source Markdown note-taking with end-to-end encryption. Syncs across devices. Good alternative to Obsidian with cloud sync built-in.
  ::
::

```markdown
## Note Template — Every Topic You Study

### Topic: [e.g., SQL Injection]
**Date:** 2025-01-15
**Source:** [Course/Video/Article URL]

### What is it?
[Explain in YOUR OWN WORDS — not copy-paste]

### How does it work?
[Technical explanation — the WHY behind it]

### Key Commands/Payloads
```
[Code blocks with actual commands you tested]
```

### What I struggled with
[Be honest — this is where real learning happens]

### What I learned
[Key takeaways — what clicked?]

### Questions I still have
[Write them down — research later]

### Related topics
[Links to other notes — build connections]
```

---

## 12-Month Study Plan

### Overview

::steps{level="4"}

#### Months 1-3: Foundation — Understand How Things Work

Linux, Networking, Programming fundamentals. **No hacking yet.** Build the foundation that everything else stands on.

#### Months 4-6: Web & Network Basics — Start Breaking Things

Web application security, network protocols, basic exploitation. Start CTFs and easy challenges.

#### Months 7-9: Intermediate — Think Like an Attacker

Active Directory, privilege escalation, real-world methodology. Harder CTFs and practice labs.

#### Months 10-12: Advanced — Create Your Own Methodology

Tool development, exploit writing, bug bounty, advanced topics. Build your portfolio and identity.

::

---

## Months 1-3 — The Foundation

::warning
**DO NOT SKIP THIS.** This is where script kiddies and hackers diverge forever. Script kiddies skip fundamentals and are forever limited. Hackers who build strong foundations have unlimited growth potential.
::

### Month 1: Linux Mastery

::note
You cannot be a hacker without being comfortable in Linux. Period. The terminal is your home. The command line is your language.
::

#### What to Learn

::field-group
  ::field{name="Linux File System" type="week 1"}
  Understand `/etc`, `/var`, `/home`, `/proc`, `/dev`, `/tmp`. Know what every directory is for. Navigate without thinking.
  ::

  ::field{name="Command Line Mastery" type="week 2"}
  Master `grep`, `find`, `awk`, `sed`, `cut`, `sort`, `uniq`, `xargs`, `tee`, `pipes`, `redirects`. Chain commands together.
  ::

  ::field{name="Users, Groups, Permissions" type="week 3"}
  Understand `chmod`, `chown`, `SUID`, `SGID`, `sticky bit`, `/etc/passwd`, `/etc/shadow`, `sudo`, `su`. This is directly relevant to privilege escalation.
  ::

  ::field{name="Services & Processes" type="week 4"}
  Understand `systemctl`, `ps`, `top`, `netstat`/`ss`, `cron`, `journalctl`. Know how Linux runs services and how to monitor them.
  ::
::

#### Free Resources — Linux

::card-group
  ::card
  ---
  title: "Linux Journey"
  icon: i-simple-icons-linux
  to: https://linuxjourney.com/
  target: _blank
  ---
  Free, interactive Linux learning from zero. Covers command line, file system, processes, networking, and more. Best starting point for beginners.
  ::

  ::card
  ---
  title: "OverTheWire: Bandit"
  icon: i-lucide-terminal
  to: https://overthewire.org/wargames/bandit/
  target: _blank
  ---
  Learn Linux through a wargame. 34 levels that teach essential command-line skills through challenges. The BEST way to learn Linux for hacking.
  ::

  ::card
  ---
  title: "Linux Basics for Hackers (Book)"
  icon: i-lucide-book-open
  to: https://nostarch.com/linuxbasicsforhackers
  target: _blank
  ---
  By OccupyTheWeb. THE book for learning Linux specifically for hacking. Covers the exact Linux skills pentesters need. Available at libraries or free previews online.
  ::

  ::card
  ---
  title: "The Linux Command Line (Free Book)"
  icon: i-lucide-book-open
  to: https://linuxcommand.org/tlcl.php
  target: _blank
  ---
  Free, complete book on the Linux command line by William Shotts. 500+ pages. Covers everything from basic navigation to shell scripting.
  ::
::

#### YouTube — Linux

::card-group
  ::card
  ---
  title: "NetworkChuck — Linux for Hackers"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/playlist?list=PLIhvC56v63IJIujb5cyE13oLuyORZpdkL
  target: _blank
  ---
  Beginner-friendly Linux tutorial series. Entertaining presentation style that makes learning Linux fun. Covers command line, networking, and security.
  ::

  ::card
  ---
  title: "The Cyber Mentor — Linux for Beginners"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/watch?v=U1w4T03B30I
  target: _blank
  ---
  4+ hour comprehensive Linux tutorial specifically for ethical hacking. Covers everything you need before starting pentesting.
  ::

  ::card
  ---
  title: "John Hammond — Linux Privilege Escalation"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/c/JohnHammond010
  target: _blank
  ---
  Excellent CTF walkthroughs and Linux hacking content. Learn Linux by watching someone hack with it. Great for seeing real-world application.
  ::

  ::card
  ---
  title: "LearnLinuxTV"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@LearnLinuxTV
  target: _blank
  ---
  Deep Linux system administration content. Server setup, networking, troubleshooting. Builds the sysadmin knowledge that enables better hacking.
  ::
::

#### Month 1 Practice

```bash [Month 1 — Daily Practice]
# ============================================
# WEEK 1: Navigate and explore
# ============================================
# Complete OverTheWire Bandit Levels 0-10
# ssh bandit0@bandit.labs.overthewire.org -p 2220
# Password: bandit0

# Practice these until they're muscle memory:
ls -la
cd /etc && cat passwd
find / -name "*.conf" -type f 2>/dev/null
grep -r "password" /etc/ 2>/dev/null
cat /etc/os-release

# ============================================
# WEEK 2: Text processing and pipes
# ============================================
# Complete Bandit Levels 10-20

# Practice command chaining:
cat /etc/passwd | cut -d: -f1 | sort
ps aux | grep root | awk '{print $2, $11}'
find / -perm -u=s -type f 2>/dev/null | head -20
netstat -tlnp | grep LISTEN
ls -la /tmp | grep -v "^total"

# ============================================
# WEEK 3: Permissions and users
# ============================================
# Complete Bandit Levels 20-27

# Understand these deeply:
id
whoami
groups
sudo -l
cat /etc/shadow  # Why can't you read this?
ls -la /usr/bin/sudo  # What makes sudo special?
find / -perm -4000 -type f 2>/dev/null  # What are SUID files?

# ============================================
# WEEK 4: Services and processes
# ============================================
# Complete Bandit Levels 27-34

# System enumeration:
systemctl list-units --type=service --state=running
ps aux --forest
ss -tlnp
crontab -l
cat /etc/crontab
journalctl -xe --no-pager | tail -50
```

### Month 2: Networking Fundamentals

::note
**Networking is the language of hacking.** If you don't understand TCP/IP, HTTP, DNS, and how packets flow between systems, you cannot understand network attacks, web attacks, or exploitation. This month is CRITICAL.
::

#### What to Learn

::field-group
  ::field{name="OSI & TCP/IP Model" type="week 1"}
  Understand all 7 layers. Know what happens at each layer when you type a URL in your browser. Understand encapsulation and de-encapsulation.
  ::

  ::field{name="TCP, UDP, IP, ICMP" type="week 2"}
  Understand TCP 3-way handshake, UDP statelessness, IP addressing, subnetting, CIDR notation, ARP, ICMP. Analyze packets in Wireshark.
  ::

  ::field{name="DNS, DHCP, HTTP/HTTPS" type="week 3"}
  Understand DNS resolution process, record types, HTTP methods, status codes, headers, cookies, TLS handshake. Use `dig`, `nslookup`, `curl`.
  ::

  ::field{name="Firewalls, NAT, Routing" type="week 4"}
  Understand how firewalls filter traffic, how NAT works, routing tables, VLANs, VPNs. Understand what network segmentation means.
  ::
::

#### Free Resources — Networking

::card-group
  ::card
  ---
  title: "Computer Networking — Kurose & Ross (Free)"
  icon: i-lucide-book-open
  to: https://gaia.cs.umass.edu/kurose_ross/online_lectures.htm
  target: _blank
  ---
  Free video lectures from the authors of the top networking textbook. Covers application, transport, network, and link layers with animations and examples.
  ::

  ::card
  ---
  title: "Professor Messer — CompTIA Network+"
  icon: i-simple-icons-youtube
  to: https://www.professormesser.com/network-plus/n10-009/n10-009-video/n10-009-training-course/
  target: _blank
  ---
  Completely free Network+ training course. 100+ videos covering every networking fundamental. The most recommended free networking course.
  ::

  ::card
  ---
  title: "Practical Networking"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@PracticalNetworking
  target: _blank
  ---
  Deep networking concept explanations. Subnetting, routing, TCP/IP, ARP — explained visually and practically. Excellent for building deep understanding.
  ::

  ::card
  ---
  title: "Wireshark User Guide"
  icon: i-simple-icons-wireshark
  to: https://www.wireshark.org/docs/wsug_html_chunked/
  target: _blank
  ---
  Official Wireshark documentation. Learn packet analysis — the skill that lets you SEE what's happening on the network.
  ::
::

#### YouTube — Networking

::card-group
  ::card
  ---
  title: "NetworkChuck — Networking"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/playlist?list=PLIhvC56v63IKrRHh3gvZZBAGvsvOhdenC
  target: _blank
  ---
  Fun, accessible networking tutorials. Subnetting, DNS, DHCP, firewalls, and VLANs explained for beginners. Great energy and clear explanations.
  ::

  ::card
  ---
  title: "David Bombal — Networking"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@davidbombal
  target: _blank
  ---
  CCNA-level networking content with hacking integration. Packet analysis, Wireshark, network attacks, and protocol deep dives. 1M+ subscribers.
  ::

  ::card
  ---
  title: "Chris Greer — Wireshark"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@ChrisGreer
  target: _blank
  ---
  The best Wireshark content on YouTube. Packet analysis tutorials, troubleshooting, and security analysis. Learn to read packets like a book.
  ::

  ::card
  ---
  title: "Ben Eater — Networking from Scratch"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/playlist?list=PLowKtXNTBypH19whXTVoG3oKSuOcw_XeW
  target: _blank
  ---
  Build networking knowledge from the ground up. How the Internet works, explained visually with real hardware and packet captures.
  ::
::

### Month 3: Programming Fundamentals

::tip
You don't need to be a software engineer. But you MUST be able to read code, write scripts, and automate tasks. **Python** is your primary weapon. **Bash** is your secondary.
::

#### What to Learn

::field-group
  ::field{name="Python Basics" type="week 1-2"}
  Variables, data types, loops, conditionals, functions, file I/O, error handling. Write 10+ small scripts. Automate something you do manually.
  ::

  ::field{name="Python for Networking/Security" type="week 3"}
  Socket programming, HTTP requests with `requests`, web scraping with `BeautifulSoup`, subprocess module, argparse for CLI tools.
  ::

  ::field{name="Bash Scripting" type="week 4"}
  Variables, loops, conditionals, functions, text processing (`grep`, `awk`, `sed`), file operations. Automate recon and enumeration tasks.
  ::
::

#### Free Resources — Programming

::card-group
  ::card
  ---
  title: "Automate the Boring Stuff with Python"
  icon: i-simple-icons-python
  to: https://automatetheboringstuff.com/
  target: _blank
  ---
  Completely free online book. The best introduction to Python for practical automation. Web scraping, file operations, and more. Perfect for security beginners.
  ::

  ::card
  ---
  title: "Python for Everybody"
  icon: i-simple-icons-python
  to: https://www.py4e.com/
  target: _blank
  ---
  Free Python course by Dr. Chuck (University of Michigan). Video lectures, textbook, and exercises. Covers fundamentals through web development.
  ::

  ::card
  ---
  title: "Codecademy — Python (Free Tier)"
  icon: i-lucide-code
  to: https://www.codecademy.com/learn/learn-python-3
  target: _blank
  ---
  Interactive Python course with browser-based coding environment. Free tier covers basics. Good for absolute beginners who need guided exercises.
  ::

  ::card
  ---
  title: "Violent Python (Free Resources)"
  icon: i-lucide-book-open
  to: https://github.com/tanc7/hacking-books
  target: _blank
  ---
  Security-focused Python programming. Build port scanners, SSH brute-forcers, packet sniffers, and exploit scripts. The bridge between programming and hacking.
  ::
::

#### Build These Projects (Month 3)

::collapsible
**Month 3 Coding Projects**

```python [Project 1: Port Scanner]
#!/usr/bin/env python3
"""
Project 1: Build your own port scanner
This teaches you: sockets, TCP, threading, and what Nmap does
"""
import socket
import threading
from datetime import datetime

def scan_port(target, port, results):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                banner = sock.recv(1024).decode().strip()
            except:
                banner = "No banner"
            results.append((port, banner))
        sock.close()
    except:
        pass

def main():
    target = input("Target IP: ")
    print(f"\nScanning {target}...")
    print(f"Started at: {datetime.now()}\n")
    
    results = []
    threads = []
    
    for port in range(1, 1025):
        t = threading.Thread(target=scan_port, args=(target, port, results))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    for port, banner in sorted(results):
        print(f"  Port {port:5d} OPEN  | {banner}")
    
    print(f"\n{len(results)} open ports found")

if __name__ == "__main__":
    main()
```

```python [Project 2: Directory Brute-Forcer]
#!/usr/bin/env python3
"""
Project 2: Web directory brute-forcer
This teaches you: HTTP, web servers, status codes, threading
"""
import requests
import sys
from concurrent.futures import ThreadPoolExecutor

def check_path(url, path):
    """Check if a path exists"""
    full_url = f"{url.rstrip('/')}/{path.strip()}"
    try:
        r = requests.get(full_url, timeout=5, allow_redirects=False)
        if r.status_code in [200, 301, 302, 403]:
            print(f"  [{r.status_code}] {full_url}")
            return (full_url, r.status_code)
    except:
        pass
    return None

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <URL> <wordlist>")
        sys.exit(1)
    
    url = sys.argv[1]
    wordlist = sys.argv[2]
    
    with open(wordlist, 'r') as f:
        paths = f.read().splitlines()
    
    print(f"Scanning {url} with {len(paths)} paths...\n")
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_path, url, path) for path in paths]
        results = [f.result() for f in futures if f.result()]
    
    print(f"\nFound {len(results)} paths")

if __name__ == "__main__":
    main()
```

```bash [Project 3: Recon Automation Script]
#!/bin/bash
# Project 3: Automated recon script
# This teaches you: Bash scripting, tool chaining, automation

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

OUTDIR="./recon/$TARGET"
mkdir -p "$OUTDIR"

echo "[*] Starting recon for $TARGET"
echo "[*] Output: $OUTDIR"
echo ""

# DNS Enumeration
echo "[1/5] DNS Enumeration..."
dig ANY $TARGET +short > "$OUTDIR/dns_any.txt"
dig MX $TARGET +short > "$OUTDIR/dns_mx.txt"
dig NS $TARGET +short > "$OUTDIR/dns_ns.txt"
dig TXT $TARGET +short > "$OUTDIR/dns_txt.txt"

# Whois
echo "[2/5] WHOIS..."
whois $TARGET > "$OUTDIR/whois.txt"

# HTTP Headers
echo "[3/5] HTTP Headers..."
curl -sI "https://$TARGET" > "$OUTDIR/headers.txt"

# Technology Detection
echo "[4/5] Technology Detection..."
whatweb -q "https://$TARGET" > "$OUTDIR/whatweb.txt" 2>/dev/null

# Port Scan (top 100)
echo "[5/5] Port Scan..."
nmap -sV --top-ports 100 $TARGET -oN "$OUTDIR/nmap.txt" 2>/dev/null

echo ""
echo "[✓] Recon complete! Results in $OUTDIR"
ls -la "$OUTDIR"
```
::

---

## Months 4-6 — Start Breaking Things

### Month 4: Web Application Security

::note
Web apps are where most beginners find their first real vulnerabilities. This month, you learn to see web applications the way an attacker does — as a collection of inputs, logic, and trust assumptions waiting to be violated.
::

#### Free Courses — Web Security

::card-group
  ::card
  ---
  title: "PortSwigger Web Security Academy"
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security
  target: _blank
  ---
  **THE #1 FREE WEB SECURITY COURSE.** Created by the Burp Suite team. Interactive labs covering SQL injection, XSS, CSRF, SSRF, authentication, access control, and more. Do EVERY lab.
  ::

  ::card
  ---
  title: "OWASP WebGoat"
  icon: i-simple-icons-owasp
  to: https://owasp.org/www-project-webgoat/
  target: _blank
  ---
  Deliberately insecure web application for learning. Interactive lessons on injection, authentication flaws, XSS, and more. Practice without any setup.
  ::

  ::card
  ---
  title: "TryHackMe — Web Fundamentals"
  icon: i-lucide-graduation-cap
  to: https://tryhackme.com/path/outline/web
  target: _blank
  ---
  Guided web hacking learning path. Browser-based labs with step-by-step instructions. Free rooms cover HTTP, Burp Suite, OWASP Top 10, and more.
  ::

  ::card
  ---
  title: "Hacker101 (HackerOne)"
  icon: i-lucide-bug
  to: https://www.hacker101.com/
  target: _blank
  ---
  Free web security class from HackerOne. Video lessons and CTF challenges. Completing challenges earns invitations to private bug bounty programs.
  ::
::

#### YouTube — Web Hacking

::card-group
  ::card
  ---
  title: "The Cyber Mentor — Web App Pentesting"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/watch?v=X4eRbHgRawI
  target: _blank
  ---
  15+ hour complete web application pentesting course. Free on YouTube. Covers Burp Suite, SQL injection, XSS, file upload, command injection. ESSENTIAL viewing.
  ::

  ::card
  ---
  title: "STÖK — Bug Bounty"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@STOKfredrik
  target: _blank
  ---
  Bug bounty hunter's perspective on web security. Methodology, tools, mindset, and live hacking. Inspiring and educational.
  ::

  ::card
  ---
  title: "NahamSec — Bug Bounty"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@NahamSec
  target: _blank
  ---
  One of the top bug bounty educators. Recon methodology, web vulnerabilities, live hacking, and interviews with top hunters. Free Recon course on YouTube.
  ::

  ::card
  ---
  title: "PwnFunction — Web Security Animated"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@PwnFunction
  target: _blank
  ---
  Beautifully animated explanations of web vulnerabilities. XSS, CSRF, SSRF, prototype pollution — complex topics made visual and understandable.
  ::

  ::card
  ---
  title: "LiveOverflow"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@LiveOverflow
  target: _blank
  ---
  Deep technical hacking content. Binary exploitation, web security, CTF walkthroughs. Teaches you to THINK like a hacker, not just follow steps.
  ::

  ::card
  ---
  title: "InsiderPhD — Bug Bounty for Beginners"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@InsiderPhD
  target: _blank
  ---
  Bug bounty content specifically for beginners. Finding your first bug, recon methodology, and vulnerability classes explained simply.
  ::
::

### Month 5: Network Pentesting

#### Free Resources — Network Hacking

::card-group
  ::card
  ---
  title: "The Cyber Mentor — Ethical Hacking Full Course"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/watch?v=3FNYvj2U0HM
  target: _blank
  ---
  12+ hour complete ethical hacking course. Free on YouTube. Covers scanning, enumeration, exploitation, post-exploitation, and AD attacks. Watch this ENTIRE course.
  ::

  ::card
  ---
  title: "HackTheBox Academy — Penetration Tester Path"
  icon: i-simple-icons-hackthebox
  to: https://academy.hackthebox.com/path/preview/penetration-tester
  target: _blank
  ---
  Structured pentesting learning path. Many modules have free tiers. Interactive labs with real machines. Build towards CPTS certification.
  ::

  ::card
  ---
  title: "TryHackMe — Jr Penetration Tester"
  icon: i-lucide-graduation-cap
  to: https://tryhackme.com/path/outline/jrpenetrationtester
  target: _blank
  ---
  Beginner penetration testing path. Covers Nmap, Metasploit, privilege escalation, and web exploitation. Many rooms are free.
  ::

  ::card
  ---
  title: "IppSec — HackTheBox Walkthroughs"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@ippsec
  target: _blank
  ---
  THE gold standard for CTF/HTB walkthroughs. Methodical, educational, explains every step and why. Watch retired HTB machine walkthroughs. Over 400 videos.
  ::
::

### Month 6: CTF Competitions & Practice

::card-group
  ::card
  ---
  title: "TryHackMe"
  icon: i-lucide-flag
  to: https://tryhackme.com/
  target: _blank
  ---
  Beginner-friendly guided labs. Start with free rooms: "Basic Pentesting", "Kenobi", "Blue", "Ice", "Vulnversity". Browser-based — no setup needed.
  ::

  ::card
  ---
  title: "HackTheBox"
  icon: i-simple-icons-hackthebox
  to: https://www.hackthebox.com/
  target: _blank
  ---
  More challenging than TryHackMe. Start with "Easy" retired machines. Watch IppSec walkthroughs after attempting. Free tier available.
  ::

  ::card
  ---
  title: "PicoCTF"
  icon: i-lucide-flag
  to: https://picoctf.org/
  target: _blank
  ---
  Beginner CTF by Carnegie Mellon. Year-round practice challenges in web, forensics, crypto, reverse engineering, and binary exploitation. Completely free.
  ::

  ::card
  ---
  title: "OverTheWire Wargames"
  icon: i-lucide-terminal
  to: https://overthewire.org/wargames/
  target: _blank
  ---
  Progressive wargames. After completing Bandit, try Natas (web), Leviathan (Linux), and Narnia (exploitation). Free and self-paced.
  ::

  ::card
  ---
  title: "VulnHub"
  icon: i-lucide-download
  to: https://www.vulnhub.com/
  target: _blank
  ---
  Download vulnerable VMs for offline practice. Boot-to-root challenges. Great for practicing without internet. Start with "Kioptrix" series.
  ::

  ::card
  ---
  title: "CTFtime"
  icon: i-lucide-calendar
  to: https://ctftime.org/
  target: _blank
  ---
  Global CTF competition calendar. Find upcoming CTFs to participate in. Join a team or compete solo. Real competitions accelerate learning.
  ::
::

---

## Months 7-9 — Intermediate Skills

### Month 7: Active Directory & Windows

#### Free Resources — AD Hacking

::card-group
  ::card
  ---
  title: "The Cyber Mentor — AD Hacking"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/watch?v=VXxH4n684HE
  target: _blank
  ---
  Complete Active Directory hacking course. Free on YouTube. LLMNR poisoning, relay attacks, Kerberoasting, pass-the-hash, and domain enumeration.
  ::

  ::card
  ---
  title: "Hackers Academy — Active Directory"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/playlist?list=PLBf0hzazHTGMGBz-muYmVLMgQGAYoToAk
  target: _blank
  ---
  Step-by-step AD attack methodology. Building your own AD lab, enumeration, exploitation, and persistence techniques.
  ::

  ::card
  ---
  title: "DVAD — Damn Vulnerable Active Directory"
  icon: i-simple-icons-github
  to: https://github.com/WazeHell/vulnerable-AD
  target: _blank
  ---
  Script to create a vulnerable Active Directory lab. Practice Kerberoasting, AS-REP roasting, delegation attacks, and ACL abuse in your own environment.
  ::

  ::card
  ---
  title: "WADComs"
  icon: i-lucide-terminal
  to: https://wadcoms.github.io/
  target: _blank
  ---
  Interactive cheat sheet for Windows and AD commands. Filter by attack type and tool. Essential reference during engagements and practice.
  ::
::

### Month 8: Privilege Escalation Deep Dive

#### YouTube — Privilege Escalation

::card-group
  ::card
  ---
  title: "Tib3rius — Linux Privilege Escalation"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/watch?v=ZTnBjMQB4c0
  target: _blank
  ---
  Complete Linux privilege escalation course. SUID, capabilities, cron jobs, NFS, kernel exploits, and more. By the creator of the popular Udemy PrivEsc courses.
  ::

  ::card
  ---
  title: "Tib3rius — Windows Privilege Escalation"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/watch?v=uTcrbNBcoxQ
  target: _blank
  ---
  Complete Windows privilege escalation course. Service exploitation, registry, AlwaysInstallElevated, token impersonation, and more.
  ::

  ::card
  ---
  title: "The Cyber Mentor — Windows PrivEsc"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/watch?v=uTcrbNBcoxQ
  target: _blank
  ---
  Practical Windows privilege escalation. Token abuse, Potato attacks, DLL hijacking, and automated enumeration.
  ::

  ::card
  ---
  title: "GTFOBins"
  icon: i-lucide-book-open
  to: https://gtfobins.github.io/
  target: _blank
  ---
  Your BIBLE for Linux privilege escalation. Searchable database of Unix binaries that can be exploited through sudo, SUID, and capabilities.
  ::
::

### Month 9: Real-World Methodology

::note
By now you have individual skills. This month is about **combining them into a methodology** — the systematic approach that professional pentesters use.
::

#### Study Methodology

::collapsible
**The Penetration Testing Methodology**

```
┌─────────────────────────────────────────────────────────────────┐
│            PROFESSIONAL PENTESTING METHODOLOGY                   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ PHASE 1: RECONNAISSANCE (40% of time)                   │    │
│  │ ─────────────────────────────────────                   │    │
│  │ • Passive OSINT (no touching the target)                │    │
│  │ • Subdomain enumeration                                 │    │
│  │ • Technology fingerprinting                             │    │
│  │ • Employee enumeration (LinkedIn, email)                │    │
│  │ • Historical data (Wayback, DNS history)                │    │
│  │ • GitHub/GitLab repo searching                          │    │
│  │                                                         │    │
│  │ OUTPUT: Target list, technology stack, email list,      │    │
│  │         potential usernames, exposed services           │    │
│  └─────────────────────────────────────────────────────────┘    │
│                          │                                      │
│                          ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ PHASE 2: SCANNING & ENUMERATION (20% of time)           │    │
│  │ ────────────────────────────────────                    │    │
│  │ • Port scanning (Nmap, RustScan)                        │    │
│  │ • Service version detection                             │    │
│  │ • Vulnerability scanning (Nuclei, Nessus)               │    │
│  │ • Web application scanning (Burp, ZAP)                  │    │
│  │ • Directory/file brute-forcing                          │    │
│  │ • SMB/LDAP/SNMP enumeration                             │    │
│  │                                                         │    │
│  │ OUTPUT: Open ports, services, versions, potential       │    │
│  │         vulnerabilities, directory listings             │    │
│  └─────────────────────────────────────────────────────────┘    │
│                          │                                      │
│                          ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ PHASE 3: EXPLOITATION (15% of time)                      │    │
│  │ ──────────────────────────────────                      │    │
│  │ • Exploit known vulnerabilities                         │    │
│  │ • Web application attacks (SQLi, XSS, etc.)             │    │
│  │ • Password attacks (brute-force, spraying)              │    │
│  │ • Social engineering (if in scope)                      │    │
│  │ • Custom exploit development                            │    │
│  │                                                         │    │
│  │ OUTPUT: Initial access to systems, user credentials,    │    │
│  │         web application compromise                      │    │
│  └─────────────────────────────────────────────────────────┘    │
│                          │                                      │
│                          ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ PHASE 4: POST-EXPLOITATION (20% of time)                 │    │
│  │ ───────────────────────────────────                     │    │
│  │ • Privilege escalation                                  │    │
│  │ • Credential harvesting                                 │    │
│  │ • Lateral movement                                      │    │
│  │ • Pivoting to internal networks                         │    │
│  │ • Data exfiltration (proof of impact)                   │    │
│  │ • Persistence (if authorized)                           │    │
│  │                                                         │    │
│  │ OUTPUT: Root/Admin access, domain admin,                │    │
│  │         sensitive data access proof                      │    │
│  └─────────────────────────────────────────────────────────┘    │
│                          │                                      │
│                          ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ PHASE 5: REPORTING (5% of time)                          │    │
│  │ ─────────────────────────────                           │    │
│  │ • Document everything with evidence                     │    │
│  │ • Write clear reproduction steps                        │    │
│  │ • Provide remediation guidance                          │    │
│  │ • Rate severity accurately                              │    │
│  │ • Executive summary for management                      │    │
│  │                                                         │    │
│  │ OUTPUT: Professional penetration test report            │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```
::

---

## Months 10-12 — Advanced & Specialization

### Month 10: Tool Development & Automation

::note
This is where you stop being a consumer of tools and start being a **creator**. Build tools that solve YOUR specific problems. Automate YOUR methodology.
::

#### YouTube — Advanced & Tool Building

::card-group
  ::card
  ---
  title: "John Hammond"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@JohnHammond010
  target: _blank
  ---
  CTF solutions, malware analysis, tool development, and deep technical content. Shows the process of building custom tools and solving complex challenges.
  ::

  ::card
  ---
  title: "LiveOverflow"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@LiveOverflow
  target: _blank
  ---
  Deep hacking methodology. Browser exploitation, binary exploitation, hardware hacking, and CTF analysis. Teaches you to THINK, not just follow steps.
  ::

  ::card
  ---
  title: "Gynvael Coldwind"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/@GynvaelEN
  target: _blank
  ---
  Former Google Security Team. Advanced reverse engineering, exploit development, and CTF challenge creation. World-class technical content.
  ::

  ::card
  ---
  title: "0xdf — HTB Walkthroughs"
  icon: i-lucide-book-open
  to: https://0xdf.gitlab.io/
  target: _blank
  ---
  The most detailed HackTheBox write-ups on the internet. Shows multiple solution paths, explains methodology, and teaches thinking processes.
  ::
::

### Month 11: Bug Bounty & Real-World Practice

::card-group
  ::card
  ---
  title: "NahamSec — Recon & Bug Bounty"
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/watch?v=MIujSpuDtFY
  target: _blank
  ---
  Complete bug bounty recon methodology. Free on YouTube. Learn how professional bug bounty hunters approach targets systematically.
  ::

  ::card
  ---
  title: "Bugcrowd University"
  icon: i-lucide-graduation-cap
  to: https://www.bugcrowd.com/hackers/bugcrowd-university/
  target: _blank
  ---
  Free bug bounty training from Bugcrowd. Covers methodology, vulnerability classes, and how to write good reports.
  ::

  ::card
  ---
  title: "HackerOne Hacktivity"
  icon: i-lucide-activity
  to: https://hackerone.com/hacktivity
  target: _blank
  ---
  Public disclosed bug reports. Read real vulnerability reports that earned bounties. Learn what good findings look like and how to write reports.
  ::

  ::card
  ---
  title: "Pentester Land Write-ups"
  icon: i-lucide-book-open
  to: https://pentester.land/list-of-bug-bounty-writeups.html
  target: _blank
  ---
  Curated collection of bug bounty write-ups. Hundreds of real-world vulnerability discoveries explained in detail. Essential reading.
  ::
::

### Month 12: Build Your Identity & Portfolio

::steps{level="4"}

#### Create Your Blog

Write about what you learn. Explain CTF solutions. Share your methodology. Teaching forces you to truly understand topics.

```
Free blogging platforms:
- GitHub Pages (free, custom domain)
- Medium (free, built-in audience)
- Hashnode (free, developer-focused)
- Hugo/Jekyll (free, static site generators)
```

#### Build a GitHub Portfolio

```
Your GitHub should contain:
- Custom security tools you've built
- CTF write-ups and solutions
- Automation scripts
- Your methodology documentation
- Contributions to open-source security projects
```

#### Start Bug Bounty Hunting

```
Start with these programs:
1. HackerOne — Start with "Managed" programs
2. Bugcrowd — Start with VDP (Vulnerability Disclosure Programs)
3. Open Bug Bounty — Good for XSS practice
4. Google VRP — High prestige, well-documented scope
```

#### Network with the Community

```
Join these communities:
- Discord: NahamSec, The Cyber Mentor, HackTheBox, TryHackMe
- Reddit: r/netsec, r/hacking, r/bugbounty, r/oscp
- Twitter/X: Follow security researchers
- Local meetups: BSides conferences, OWASP chapters, DEF CON groups
```

::

---

## Complete Free Resource Library

### Free Books (Legal Downloads)

::card-group
  ::card
  ---
  title: "The Linux Command Line"
  icon: i-lucide-book-open
  to: https://linuxcommand.org/tlcl.php
  target: _blank
  ---
  Free PDF. 500+ pages covering everything about the Linux command line. From basic navigation to advanced Bash scripting.
  ::

  ::card
  ---
  title: "Automate the Boring Stuff with Python"
  icon: i-lucide-book-open
  to: https://automatetheboringstuff.com/
  target: _blank
  ---
  Free online. The best practical Python book. Web scraping, file operations, and automation. Perfect for security scripting foundations.
  ::

  ::card
  ---
  title: "The Hacker Playbook (Resources)"
  icon: i-lucide-book-open
  to: https://github.com/tanc7/hacking-books
  target: _blank
  ---
  Collection of free security books and resources. Covers pentesting methodology, exploit development, and red team operations.
  ::

  ::card
  ---
  title: "OWASP Testing Guide"
  icon: i-lucide-book-open
  to: https://owasp.org/www-project-web-security-testing-guide/
  target: _blank
  ---
  Free. The comprehensive web application security testing methodology. Used by professional pentesters worldwide. Essential reference.
  ::

  ::card
  ---
  title: "Penetration Testing with Kali Linux (PWK) Syllabus"
  icon: i-lucide-book-open
  to: https://www.offsec.com/courses/pen-200/
  target: _blank
  ---
  Review the OSCP syllabus for free. Use it as a study checklist. The topics listed are exactly what you need to learn.
  ::

  ::card
  ---
  title: "Computer Networking: A Top-Down Approach"
  icon: i-lucide-book-open
  to: https://gaia.cs.umass.edu/kurose_ross/online_lectures.htm
  target: _blank
  ---
  Free video lectures from the textbook authors. Complete networking course covering application, transport, network, and link layers.
  ::

  ::card
  ---
  title: "How Linux Works (Preview)"
  icon: i-lucide-book-open
  to: https://nostarch.com/howlinuxworks3
  target: _blank
  ---
  Essential Linux internals book. Understanding how Linux works under the hood is critical for exploitation. Check libraries or free chapters online.
  ::

  ::card
  ---
  title: "Web Application Hacker's Handbook"
  icon: i-lucide-book-open
  to: https://portswigger.net/web-security
  target: _blank
  ---
  The classic web app security book's content is now largely available through PortSwigger's free Web Security Academy. Same authors, updated content.
  ::
::

### Complete YouTube Channel Collection

::tabs
  :::tabs-item{icon="i-lucide-star" label="Must-Watch (Top 10)"}
  ```yaml [Top 10 YouTube Channels for Hackers]
  Essential Channels:
    1:
      Name: "The Cyber Mentor (TCM Security)"
      URL: "https://www.youtube.com/@TCMSecurityAcademy"
      Why: "Full free courses on ethical hacking, web apps, AD, and PrivEsc. Best starting point."
      
    2:
      Name: "IppSec"
      URL: "https://www.youtube.com/@ippsec"
      Why: "400+ HTB walkthroughs. Teaches METHODOLOGY not just solutions. The gold standard."
      
    3:
      Name: "John Hammond"
      URL: "https://www.youtube.com/@JohnHammond010"
      Why: "CTFs, malware analysis, tool development. Energetic and educational."
      
    4:
      Name: "NetworkChuck"
      URL: "https://www.youtube.com/@NetworkChuck"
      Why: "Makes networking and Linux fun. Great for beginners. High energy."
      
    5:
      Name: "LiveOverflow"
      URL: "https://www.youtube.com/@LiveOverflow"
      Why: "Deep technical content. Teaches you to THINK like a hacker."
      
    6:
      Name: "NahamSec"
      URL: "https://www.youtube.com/@NahamSec"
      Why: "Bug bounty methodology, recon, and live hacking. Real-world focus."
      
    7:
      Name: "David Bombal"
      URL: "https://www.youtube.com/@davidbombal"
      Why: "Networking, ethical hacking, and career advice. Interviews with experts."
      
    8:
      Name: "HackerSploit"
      URL: "https://www.youtube.com/@HackerSploit"
      Why: "Structured penetration testing tutorials. Clear and methodical."
      
    9:
      Name: "Professor Messer"
      URL: "https://www.youtube.com/@professormesser"
      Why: "Free CompTIA certification training. Security+, Network+, A+."
      
    10:
      Name: "STÖK"
      URL: "https://www.youtube.com/@STOKfredrik"
      Why: "Bug bounty mindset and methodology. Inspiring and practical."
  ```
  :::

  :::tabs-item{icon="i-lucide-list" label="Extended List (30+)"}
  ```yaml [Complete YouTube Channel Directory]
  Beginner-Friendly:
    - Name: "NetworkChuck"
      URL: "https://www.youtube.com/@NetworkChuck"
      Focus: "Linux, Networking, Hacking basics"
      
    - Name: "The Cyber Mentor"
      URL: "https://www.youtube.com/@TCMSecurityAcademy"
      Focus: "Full pentesting courses, free"
      
    - Name: "HackerSploit"
      URL: "https://www.youtube.com/@HackerSploit"
      Focus: "Structured pentesting tutorials"
      
    - Name: "Computerphile"
      URL: "https://www.youtube.com/@Computerphile"
      Focus: "CS concepts explained simply"
      
    - Name: "Professor Messer"
      URL: "https://www.youtube.com/@professormesser"
      Focus: "CompTIA certifications (free)"
      
    - Name: "InsiderPhD"
      URL: "https://www.youtube.com/@InsiderPhD"
      Focus: "Bug bounty for beginners"
      
    - Name: "Rana Khalil"
      URL: "https://www.youtube.com/@RanaKhalil101"
      Focus: "PortSwigger lab walkthroughs"

  Intermediate:
    - Name: "IppSec"
      URL: "https://www.youtube.com/@ippsec"
      Focus: "HackTheBox walkthroughs"
      
    - Name: "John Hammond"
      URL: "https://www.youtube.com/@JohnHammond010"
      Focus: "CTFs, malware, tool dev"
      
    - Name: "NahamSec"
      URL: "https://www.youtube.com/@NahamSec"
      Focus: "Bug bounty, recon"
      
    - Name: "STÖK"
      URL: "https://www.youtube.com/@STOKfredrik"
      Focus: "Bug bounty mindset"
      
    - Name: "David Bombal"
      URL: "https://www.youtube.com/@davidbombal"
      Focus: "Networking + hacking"
      
    - Name: "Tib3rius"
      URL: "https://www.youtube.com/@Tib3rius"
      Focus: "Privilege escalation"
      
    - Name: "Conda"
      URL: "https://www.youtube.com/@c0nd4"
      Focus: "Pentesting methodology"
      
    - Name: "TheCyberMentor"
      URL: "https://www.youtube.com/@TCMSecurityAcademy"
      Focus: "AD hacking, PrivEsc, courses"
      
    - Name: "zSecurity"
      URL: "https://www.youtube.com/@zaborona"
      Focus: "Web hacking, Kali Linux"

  Advanced:
    - Name: "LiveOverflow"
      URL: "https://www.youtube.com/@LiveOverflow"
      Focus: "Deep technical, binary, web"
      
    - Name: "Gynvael Coldwind"
      URL: "https://www.youtube.com/@GynvaelEN"
      Focus: "RE, exploit dev, CTF creation"
      
    - Name: "stacksmashing"
      URL: "https://www.youtube.com/@stacksmashing"
      Focus: "Hardware hacking, RE"
      
    - Name: "PwnFunction"
      URL: "https://www.youtube.com/@PwnFunction"
      Focus: "Animated web security"
      
    - Name: "Seytonic"
      URL: "https://www.youtube.com/@Seytonic"
      Focus: "Hacking news, tools"
      
    - Name: "13Cubed"
      URL: "https://www.youtube.com/@13Cubed"
      Focus: "DFIR, forensics"
      
    - Name: "MalwareTech"
      URL: "https://www.youtube.com/@MalwareTechBlog"
      Focus: "Malware analysis, RE"
      
    - Name: "Fireship"
      URL: "https://www.youtube.com/@Fireship"
      Focus: "CS concepts in 100 seconds"

  Career & Mindset:
    - Name: "Gerald Auger (SimplyCyber)"
      URL: "https://www.youtube.com/@yourssimply"
      Focus: "Cybersecurity career advice"
      
    - Name: "The XSS Rat"
      URL: "https://www.youtube.com/@TheXSSrat"
      Focus: "Bug bounty, career building"
      
    - Name: "Cyberspatial"
      URL: "https://www.youtube.com/@yourssimply"
      Focus: "Breaking into cybersecurity"
      
    - Name: "Day Cyberwox"
      URL: "https://www.youtube.com/@yourssimply"
      Focus: "SOC analyst, blue team career"
  ```
  :::
::

### Free Online Courses & Platforms

::card-group
  ::card
  ---
  title: PortSwigger Web Security Academy
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security
  target: _blank
  ---
  **#1 FREE** web security course. Interactive labs, detailed explanations. Covers ALL OWASP Top 10 and beyond. Complete this entirely.
  ::

  ::card
  ---
  title: TryHackMe (Free Rooms)
  icon: i-lucide-graduation-cap
  to: https://tryhackme.com/
  target: _blank
  ---
  Guided cybersecurity training. Many rooms are free. Browser-based — no setup needed. Start with "Pre Security" and "Complete Beginner" paths.
  ::

  ::card
  ---
  title: HackTheBox Academy (Free Modules)
  icon: i-simple-icons-hackthebox
  to: https://academy.hackthebox.com/
  target: _blank
  ---
  Structured modules with hands-on labs. Several modules are free. More technical depth than TryHackMe. Build towards CPTS certification.
  ::

  ::card
  ---
  title: Hacker101 (HackerOne)
  icon: i-lucide-bug
  to: https://www.hacker101.com/
  target: _blank
  ---
  Free web security video course + CTF from HackerOne. Completing CTFs earns invitations to private bug bounty programs.
  ::

  ::card
  ---
  title: Cybrary (Free Tier)
  icon: i-lucide-graduation-cap
  to: https://www.cybrary.it/
  target: _blank
  ---
  Free cybersecurity courses including CompTIA prep, ethical hacking basics, and career paths. Some courses require premium for full access.
  ::

  ::card
  ---
  title: SANS Cyber Aces
  icon: i-lucide-shield
  to: https://www.cyberaces.org/
  target: _blank
  ---
  Free cybersecurity foundation courses from SANS Institute. Covers operating systems, networking, and system administration basics.
  ::

  ::card
  ---
  title: CS50 — Harvard (Free)"
  icon: i-lucide-graduation-cap
  to: https://cs50.harvard.edu/x/
  target: _blank
  ---
  Harvard's famous computer science introduction. Free on edX. Builds the CS fundamentals that separate real hackers from tool-runners.
  ::

  ::card
  ---
  title: Khan Academy — Computing"
  icon: i-lucide-graduation-cap
  to: https://www.khanacademy.org/computing
  target: _blank
  ---
  Free computing fundamentals. Cryptography, internet protocols, and information theory. Build mathematical thinking for security.
  ::
::

### Free Certifications

::note
These certifications are completely free and demonstrate your knowledge to employers and the community.
::

::card-group
  ::card
  ---
  title: "CompTIA Security+ (Study for Free)"
  icon: i-lucide-award
  to: https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/
  target: _blank
  ---
  Professor Messer's complete Security+ course is FREE. The exam costs $392, but the knowledge is invaluable regardless of taking the exam.
  ::

  ::card
  ---
  title: "Google Cybersecurity Certificate"
  icon: i-simple-icons-google
  to: https://www.coursera.org/professional-certificates/google-cybersecurity
  target: _blank
  ---
  Free with Coursera financial aid. 6-month program covering security fundamentals, incident response, Linux, SQL, Python, and SIEM tools.
  ::

  ::card
  ---
  title: "ISC2 CC (Certified in Cybersecurity)"
  icon: i-lucide-award
  to: https://www.isc2.org/certifications/cc
  target: _blank
  ---
  Free entry-level cybersecurity certification from ISC2. Free self-paced training AND free exam. Great for your first certification.
  ::

  ::card
  ---
  title: "PNPT (Study Path — Free Resources)"
  icon: i-lucide-award
  to: https://certifications.tcm-sec.com/pnpt/
  target: _blank
  ---
  TCM Security's Practical Network Penetration Tester certification. While the exam costs $399, ALL study material is available free on YouTube.
  ::
::

---

## Practice Lab Platforms

::card-group
  ::card
  ---
  title: TryHackMe
  icon: i-lucide-flag
  to: https://tryhackme.com/
  target: _blank
  ---
  Best for beginners. Browser-based machines. Guided learning paths. Many free rooms. Start here if you're new.
  ::

  ::card
  ---
  title: HackTheBox
  icon: i-simple-icons-hackthebox
  to: https://www.hackthebox.com/
  target: _blank
  ---
  More challenging. Real pentesting scenarios. Free tier with active machines. Watch IppSec walkthroughs for retired machines.
  ::

  ::card
  ---
  title: PicoCTF
  icon: i-lucide-flag
  to: https://picoctf.org/
  target: _blank
  ---
  Beginner CTF platform by Carnegie Mellon. Year-round challenges. Web, forensics, crypto, reverse engineering, binary exploitation.
  ::

  ::card
  ---
  title: OverTheWire
  icon: i-lucide-terminal
  to: https://overthewire.org/wargames/
  target: _blank
  ---
  Progressive wargames. Bandit (Linux), Natas (Web), Leviathan (Linux exploitation). Free and self-paced. Terminal-based challenges.
  ::

  ::card
  ---
  title: VulnHub
  icon: i-lucide-download
  to: https://www.vulnhub.com/
  target: _blank
  ---
  Downloadable vulnerable VMs. Practice offline. Boot-to-root challenges. Start with Kioptrix, Mr. Robot, and DC series.
  ::

  ::card
  ---
  title: DVWA
  icon: i-lucide-shield-alert
  to: https://github.com/digininja/DVWA
  target: _blank
  ---
  Damn Vulnerable Web Application. Run locally with Docker. Practice SQL injection, XSS, file inclusion, and more at different difficulty levels.
  ::

  ::card
  ---
  title: PortSwigger Labs
  icon: i-lucide-flask-conical
  to: https://portswigger.net/web-security/all-labs
  target: _blank
  ---
  240+ interactive web security labs. Covers every web vulnerability class. Free, browser-based, with detailed solutions. Complete ALL of these.
  ::

  ::card
  ---
  title: Hack The Box Academy
  icon: i-simple-icons-hackthebox
  to: https://academy.hackthebox.com/
  target: _blank
  ---
  Structured learning with hands-on labs. Free cubes (credits) for some modules. More guided than main HTB platform.
  ::

  ::card
  ---
  title: CyberDefenders
  icon: i-lucide-shield
  to: https://cyberdefenders.org/
  target: _blank
  ---
  Blue team / DFIR challenges. Analyze packet captures, memory dumps, and disk images. Good for understanding the defender's perspective.
  ::

  ::card
  ---
  title: Damn Vulnerable GraphQL Application
  icon: i-lucide-code
  to: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application
  target: _blank
  ---
  Practice GraphQL API hacking. Modern API vulnerability testing practice.
  ::

  ::card
  ---
  title: OWASP Juice Shop
  icon: i-simple-icons-owasp
  to: https://owasp.org/www-project-juice-shop/
  target: _blank
  ---
  Modern deliberately vulnerable web application. 100+ challenges covering OWASP Top 10 and beyond. Gamified with score board.
  ::

  ::card
  ---
  title: Metasploitable 3
  icon: i-lucide-server
  to: https://github.com/rapid7/metasploitable3
  target: _blank
  ---
  Deliberately vulnerable VM for Metasploit practice. Windows and Linux versions. Multiple vulnerability types and attack paths.
  ::
::

---

## Weekly Study Schedule Template

::collapsible
**Detailed Weekly Schedule (Adaptable)**

```yaml [Weekly Study Schedule]
# ════════════════════════════════════════════
# WEEKLY STUDY SCHEDULE — 15-20 HOURS/WEEK
# Adjust based on your availability
# ════════════════════════════════════════════

Monday (2-3 hours):
  Morning (30 min):
    - Read 2-3 security articles/news
    - Sources: The Hacker News, BleepingComputer, Dark Reading
  
  Evening (2 hours):
    - Course material / video lectures
    - Take notes in Obsidian
    - Review yesterday's notes (spaced repetition)

Tuesday (2-3 hours):
  Evening:
    - Hands-on lab practice
    - TryHackMe rooms or HTB machines
    - Document what you learn and struggle with

Wednesday (2-3 hours):
  Evening:
    - Continue lab practice
    - If stuck, watch walkthrough AFTER attempting
    - Write up your solution (even failed attempts)

Thursday (2-3 hours):
  Evening:
    - Programming / scripting practice
    - Build or modify a tool
    - Automate something you did manually this week

Friday (2-3 hours):
  Evening:
    - CTF practice (PicoCTF, OverTheWire, or weekly CTF)
    - Or bug bounty hunting
    - Community engagement (Discord, Reddit, Twitter)

Saturday (4-6 hours):
  Deep Dive Day:
    - Pick ONE topic and go deep
    - Read RFC/documentation for a protocol
    - Complete an entire TryHackMe path section
    - Or attempt a harder HTB machine
    - Build a project related to the week's learning

Sunday (2-3 hours):
  Review & Plan:
    - Review all week's notes
    - Update your personal cheat sheets
    - Write a blog post or tweet about what you learned
    - Plan next week's focus areas
    - Rest — burnout is real

# ════════════════════════════════════════════
# KEY PRINCIPLES
# ════════════════════════════════════════════
# 
# 1. CONSISTENCY > INTENSITY
#    30 min daily beats 8 hours once a week
#
# 2. ACTIVE LEARNING > PASSIVE WATCHING
#    Watching videos ≠ learning
#    Doing labs = learning
#
# 3. STRUGGLE IS LEARNING
#    If it's easy, you're not growing
#    Spend 30 min stuck before looking at hints
#
# 4. TEACH TO LEARN
#    Explain concepts to others (blog, Discord)
#    If you can't explain it, you don't understand it
#
# 5. SPACED REPETITION
#    Review notes from 1 day, 3 days, 7 days ago
#    Your brain forgets without reinforcement
```
::

---

## Progress Tracking & Milestones

### Month-by-Month Milestones

::field-group
  ::field{name="Month 1 ✓" type="checkpoint"}
  Complete OverTheWire Bandit. Navigate Linux without Google. Write a bash script that automates file operations. Comfortable with `grep`, `find`, `awk`, `pipes`.
  ::

  ::field{name="Month 2 ✓" type="checkpoint"}
  Explain TCP 3-way handshake from memory. Subnet a /24 network. Capture and analyze packets in Wireshark. Understand HTTP request/response cycle completely.
  ::

  ::field{name="Month 3 ✓" type="checkpoint"}
  Write a Python port scanner. Build a web directory brute-forcer. Create a Bash recon script. Read and understand Python code in security tools.
  ::

  ::field{name="Month 4 ✓" type="checkpoint"}
  Complete 50+ PortSwigger labs. Explain SQL injection, XSS, CSRF, SSRF without notes. Find and exploit vulnerabilities in DVWA at all difficulty levels.
  ::

  ::field{name="Month 5 ✓" type="checkpoint"}
  Complete 5+ TryHackMe easy machines. Run Nmap scans and understand every flag. Use Metasploit to exploit a known vulnerability. Enumerate SMB/FTP/SSH services.
  ::

  ::field{name="Month 6 ✓" type="checkpoint"}
  Complete 5+ HackTheBox easy machines. Participate in 2+ CTF competitions. Root a VulnHub machine without hints. Write a detailed walkthrough/write-up.
  ::

  ::field{name="Month 7 ✓" type="checkpoint"}
  Build an Active Directory lab. Perform LLMNR poisoning and relay attacks. Kerberoast a service account. Enumerate AD with BloodHound.
  ::

  ::field{name="Month 8 ✓" type="checkpoint"}
  Escalate privileges on 10+ Linux machines using different techniques. Escalate on 5+ Windows machines. Explain SUID, capabilities, token impersonation.
  ::

  ::field{name="Month 9 ✓" type="checkpoint"}
  Complete a full simulated pentest (scan → exploit → privesc → report). Complete 10+ HTB medium machines. Develop your own methodology checklist.
  ::

  ::field{name="Month 10 ✓" type="checkpoint"}
  Write a custom security tool in Python. Automate your recon pipeline. Modify an existing exploit for a specific target. Contribute to an open-source security project.
  ::

  ::field{name="Month 11 ✓" type="checkpoint"}
  Submit your first bug bounty report. Or complete an HTB Pro Lab. Or pass a practice OSCP exam. Apply methodology independently.
  ::

  ::field{name="Month 12 ✓" type="checkpoint"}
  Have a blog with 10+ technical posts. GitHub with custom tools. A clear specialization interest. Ability to approach ANY system and create an attack plan.
  ::
::

---

## What NOT to Do (Common Mistakes)

::caution
These mistakes waste months of your time. Avoid them.
::

::accordion
  :::accordion-item{icon="i-lucide-x-circle" label="❌ Collecting tools instead of learning fundamentals"}
  ```
  THE TRAP:
  "I'll install every tool on Kali and learn them all!"
  
  REALITY:
  You have 600 tools and understand none of them.
  
  THE FIX:
  Master 5 tools deeply:
  1. Nmap — Network scanning
  2. Burp Suite — Web testing
  3. Metasploit — Exploitation
  4. SQLMap — SQL injection
  5. Python — Custom everything
  
  Understand WHAT each tool does under the hood.
  Then add tools as you need them for specific tasks.
  ```
  :::

  :::accordion-item{icon="i-lucide-x-circle" label="❌ Following tutorials without understanding"}
  ```
  THE TRAP:
  Typing commands from a tutorial, getting the result,
  thinking you "learned" something.
  
  REALITY:
  You can't reproduce it without the tutorial.
  
  THE FIX:
  After following ANY tutorial:
  1. Close it
  2. Try to do it again from MEMORY
  3. If you can't, identify what you don't understand
  4. Research THAT specific gap
  5. Try again
  
  If you can't explain WHY each command works,
  you haven't learned it.
  ```
  :::

  :::accordion-item{icon="i-lucide-x-circle" label="❌ Skipping networking and jumping to 'hacking'"}
  ```
  THE TRAP:
  "Networking is boring. I want to hack things NOW."
  
  REALITY:
  Every exploit, every tool, every technique
  relies on networking concepts.
  
  Without networking knowledge:
  - You can't understand port scanning
  - You can't understand firewalls or how to bypass them
  - You can't understand web requests
  - You can't pivot through networks
  - You can't understand DNS attacks
  - You can't debug "why isn't my exploit connecting back?"
  
  THE FIX:
  Spend the time. It's an investment.
  Month 2 of this guide is NOT optional.
  ```
  :::

  :::accordion-item{icon="i-lucide-x-circle" label="❌ Comparing yourself to experienced hackers"}
  ```
  THE TRAP:
  "This person on Twitter found a critical bug in 5 minutes.
   I've been at this for months and found nothing."
  
  REALITY:
  That person has been doing this for 5-15 YEARS.
  They've failed thousands of times.
  They only show the wins.
  
  THE FIX:
  Compare yourself to YOU from 3 months ago.
  That's the only comparison that matters.
  
  Month 1 you: "What's a port?"
  Month 6 you: "This is running Apache 2.4.49, which is
                vulnerable to path traversal CVE-2021-41773"
  
  That's MASSIVE growth. Celebrate it.
  ```
  :::

  :::accordion-item{icon="i-lucide-x-circle" label="❌ Not taking notes or writing things down"}
  ```
  THE TRAP:
  "I'll remember this."
  
  REALITY:
  You won't. Nobody does.
  
  PROOF:
  Think about what you learned last Tuesday.
  Can you recall the specific commands?
  The exact technique?
  The error message you debugged?
  
  Probably not.
  
  THE FIX:
  - Use Obsidian, CherryTree, or Notion
  - Write notes DURING learning (not after)
  - Include screenshots of important steps
  - Write in YOUR WORDS (not copy-paste)
  - Review notes weekly (spaced repetition)
  - Build a personal cheat sheet for each topic
  ```
  :::
::

---

## The Hacker's Reading List (Free)

::collapsible
**Essential Articles & Write-Ups to Read**

```yaml [Essential Reading List]
# ════════════════════════════════════════════
# READ THESE — They Will Change How You Think
# ════════════════════════════════════════════

Mindset & Philosophy:
  - Title: "How to Become a Hacker"
    Author: "Eric S. Raymond"
    URL: "http://www.catb.org/~esr/faqs/hacker-howto.html"
    Why: "The original essay on hacker culture and mindset"
    
  - Title: "Teach Yourself Programming in Ten Years"
    Author: "Peter Norvig"
    URL: "https://norvig.com/21-days.html"
    Why: "Patience and depth over speed and breadth"
    
  - Title: "The Security Mindset"
    Author: "Bruce Schneier"
    URL: "https://www.schneier.com/blog/archives/2008/03/the_security_mi_1.html"
    Why: "How security professionals think differently"

Technical References:
  - Title: "HackTricks"
    URL: "https://book.hacktricks.wiki/"
    Why: "The most comprehensive pentesting reference — bookmark this"
    
  - Title: "PayloadsAllTheThings"
    URL: "https://github.com/swisskyrepo/PayloadsAllTheThings"
    Why: "Every payload and bypass technique organized by vulnerability"
    
  - Title: "The Hacker Recipes"
    URL: "https://www.thehacker.recipes/"
    Why: "Structured attack recipes for AD, web, and network"
    
  - Title: "GTFOBins"
    URL: "https://gtfobins.github.io/"
    Why: "Linux privilege escalation reference"
    
  - Title: "LOLBAS"
    URL: "https://lolbas-project.github.io/"
    Why: "Windows privilege escalation reference"

Bug Bounty Write-Ups:
  - Title: "Pentester Land — Bug Bounty Write-ups List"
    URL: "https://pentester.land/list-of-bug-bounty-writeups.html"
    Why: "Hundreds of real vulnerabilities found by real hunters"
    
  - Title: "HackerOne Hacktivity"
    URL: "https://hackerone.com/hacktivity"
    Why: "Disclosed reports from real bug bounty programs"
    
  - Title: "InfoSecWriteups (Medium)"
    URL: "https://infosecwriteups.com/"
    Why: "Community write-ups on Medium — learn from peers"
    
  - Title: "0xdf HackTheBox Write-ups"
    URL: "https://0xdf.gitlab.io/"
    Why: "The most detailed HTB solutions on the internet"

Career & Community:
  - Title: "Breaking into Cybersecurity"
    URL: "https://www.youtube.com/@yourssimply"
    Why: "SimplyCyber — realistic career advice"
    
  - Title: "Reddit r/netsec"
    URL: "https://www.reddit.com/r/netsec/"
    Why: "Daily security news and research"
    
  - Title: "Reddit r/AskNetsec"
    URL: "https://www.reddit.com/r/AskNetsec/"
    Why: "Ask questions, get answers from professionals"
```
::

---

## Final Words — The Hacker's Promise to Yourself

::steps{level="4"}

#### Commit to the Process

```
I commit to:
□ Learning every day, even if only 30 minutes
□ Taking notes on everything I study
□ Building things, not just consuming content
□ Struggling through problems before looking at solutions
□ Understanding WHY, not just HOW
□ Being patient with my progress
□ Helping others who are behind me on the path
□ Using my skills ethically and legally
□ Never stopping — this is a lifelong journey
```

#### Remember Why You Started

```
When it gets hard (and it WILL get hard):

Remember the first time you rooted a machine.
Remember the first time you understood an exploit.
Remember the first time you read code and SAW the vulnerability.
Remember the feeling of "I actually understand this."

That feeling multiplies every month.
After 12 months, you won't recognize yourself.

The script kiddie runs tools.
The hacker UNDERSTANDS systems.

You're becoming the hacker.
One day at a time.
```

::

---

## References & Starting Points

::card-group
  ::card
  ---
  title: Start Here — TryHackMe
  icon: i-lucide-play
  to: https://tryhackme.com/path/outline/presecurity
  target: _blank
  ---
  Begin your journey with TryHackMe's Pre-Security path. Covers networking, Linux, and web fundamentals. Free rooms to get started.
  ::

  ::card
  ---
  title: Then Here — PortSwigger Academy
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/learning-path
  target: _blank
  ---
  Follow the Web Security Academy learning path. Complete every lab. This single resource will make you dangerous at web security.
  ::

  ::card
  ---
  title: Watch This — TCM Ethical Hacking Course
  icon: i-simple-icons-youtube
  to: https://www.youtube.com/watch?v=3FNYvj2U0HM
  target: _blank
  ---
  The Cyber Mentor's complete ethical hacking course. Free. 12+ hours. Covers the entire pentesting workflow from recon to reporting.
  ::

  ::card
  ---
  title: Practice Here — HackTheBox
  icon: i-simple-icons-hackthebox
  to: https://www.hackthebox.com/
  target: _blank
  ---
  After building foundations, graduate to HackTheBox. Start with Easy machines. Watch IppSec walkthroughs for retired machines.
  ::

  ::card
  ---
  title: Read This — HackTricks
  icon: i-simple-icons-gitbook
  to: https://book.hacktricks.wiki/
  target: _blank
  ---
  Your permanent reference. Bookmark it. Search it when you're stuck. Covers every technique, tool, and methodology.
  ::

  ::card
  ---
  title: Join This — NahamSec Discord
  icon: i-simple-icons-discord
  to: https://discord.gg/nahamsec
  target: _blank
  ---
  Active community of bug bounty hunters and hackers. Ask questions, share findings, and learn from others on the same journey.
  ::
::

::warning
**Ethics & Legality Reminder:** Everything in this guide is intended for **legal, ethical, and authorized** security testing and education. Never test systems you don't own or have explicit written permission to test. Using these skills illegally will destroy your career and freedom. The best hackers are **ethical** hackers — they protect systems, find vulnerabilities responsibly, and make the internet safer for everyone.
::