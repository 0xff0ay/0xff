---
title: Load Balancer
description: Load Balancers — what they are, how they work, types, algorithms, Nginx setup with multiple servers, Docker Compose implementation, WAF, security hardening, high availability, and real-world deployment patterns.
navigation:
  icon: i-lucide-scale
  title: Load Balancer
---

## What is a Load Balancer?

A **Load Balancer** is a network device or software that distributes incoming client requests across multiple backend servers. It acts as a **traffic cop** sitting in front of your server fleet, ensuring no single server bears too much load while maximizing speed, capacity, and reliability.

::note
Think of a load balancer like a **restaurant host** — when guests arrive, the host doesn't seat everyone at the same table. Instead, they distribute guests across available tables to ensure efficient service for everyone.
::

```text [How a Load Balancer Works — Visual Flow]

                        ┌─────────────────────────────────────────┐
                        │            INTERNET / CLIENTS            │
                        │                                          │
                        │   👤        👤        👤        👤       │
                        │  User A   User B   User C   User D      │
                        └────┬────────┬────────┬────────┬─────────┘
                             │        │        │        │
                             ▼        ▼        ▼        ▼
                     ════════════════════════════════════════
                     ║                                      ║
                     ║     ⚖️  LOAD BALANCER (Nginx)        ║
                     ║                                      ║
                     ║  ┌──────────────────────────────┐    ║
                     ║  │  • Health Checks   ❤️ ❤️ ❤️  │    ║
                     ║  │  • SSL Termination  🔒       │    ║
                     ║  │  • Rate Limiting    ⏱️       │    ║
                     ║  │  • WAF Protection   🛡️       │    ║
                     ║  │  • Session Persist  📌       │    ║
                     ║  │  • Algorithm: RR    🔄       │    ║
                     ║  └──────────────────────────────┘    ║
                     ║                                      ║
                     ════════════════════════════════════════
                        │            │            │
              ┌─────────▼──┐  ┌─────▼──────┐  ┌──▼─────────┐
              │            │  │            │  │            │
              │  🖥️ Server │  │  🖥️ Server │  │  🖥️ Server │
              │    #1      │  │    #2      │  │    #3      │
              │            │  │            │  │            │
              │  App: 3000 │  │  App: 3000 │  │  App: 3000 │
              │  CPU: 35%  │  │  CPU: 42%  │  │  CPU: 28%  │
              │  RAM: 60%  │  │  RAM: 55%  │  │  RAM: 45%  │
              │  ❤️ Healthy │  │  ❤️ Healthy │  │  ❤️ Healthy │
              └────────────┘  └────────────┘  └────────────┘
                    │               │               │
              ┌─────▼───────────────▼───────────────▼─────┐
              │          💾  SHARED DATABASE               │
              │         (Primary + Replicas)               │
              └────────────────────────────────────────────┘
```

### Core Concepts

::card-group

::card
---
title: Traffic Distribution
icon: i-lucide-split
---
Incoming requests are split across multiple servers based on algorithms like Round Robin, Least Connections, or IP Hash — ensuring even workload distribution.
::

::card
---
title: Health Monitoring
icon: i-lucide-heart-pulse
---
The load balancer continuously checks if backend servers are alive and responsive. Unhealthy servers are automatically removed from the pool until they recover.
::

::card
---
title: Single Entry Point
icon: i-lucide-door-open
---
Clients connect to **one IP address** (the load balancer). They never know about the backend servers — this simplifies DNS, SSL certificates, and firewall rules.
::

::card
---
title: Horizontal Scaling
icon: i-lucide-layers
---
Instead of upgrading one server (vertical scaling), add more servers behind the load balancer (horizontal scaling). This is cheaper and virtually limitless.
::

::

---

## Why We Need Load Balancers

```text [Without vs With Load Balancer]

  ❌ WITHOUT LOAD BALANCER              ✅ WITH LOAD BALANCER
  ═══════════════════════               ═══════════════════════

  👤👤👤👤👤👤👤👤👤👤                  👤👤👤👤👤👤👤👤👤👤
  ││││││││││                             ││││││││││
  ▼▼▼▼▼▼▼▼▼▼                             ▼▼▼▼▼▼▼▼▼▼
  ┌──────────┐                          ┌──────────────┐
  │  Single  │                          │    ⚖️ Load    │
  │  Server  │ ← 💀 Single             │   Balancer   │
  │          │    Point of              └──┬────┬───┬──┘
  │ CPU:100% │    Failure                  │    │   │
  │ RAM:95%  │                          ┌──▼─┐┌─▼──┐┌▼───┐
  │ 🔥 SLOW  │                          │ S1 ││ S2 ││ S3 │
  └──────────┘                          │30% ││35% ││35% │
                                        │ ❤️  ││ ❤️  ││ ❤️  │
  • Single point of failure             └────┘└────┘└────┘
  • Cannot handle traffic spikes
  • No redundancy                       • High availability
  • Downtime during updates             • Auto-failover
  • Limited capacity                    • Zero-downtime deploys
                                        • Unlimited scaling
```

::tabs
  :::tabs-item{icon="i-lucide-shield-check" label="High Availability"}
  **Problem:** If your single server crashes, your entire application goes down.

  **Solution:** With a load balancer, if one server fails, traffic is automatically redirected to the remaining healthy servers. Users experience zero downtime.

  ```text [Failover Scenario]
  Normal Operation:          Server 2 Fails:          Server 2 Recovers:

  LB ──┬── S1 ❤️              LB ──┬── S1 ❤️           LB ──┬── S1 ❤️
       ├── S2 ❤️                   ├── S2 ❌ (removed)       ├── S2 ❤️ (re-added)
       └── S3 ❤️                   └── S3 ❤️                └── S3 ❤️

  Traffic: 33% each          Traffic: 50% each        Traffic: 33% each
  ```
  :::

  :::tabs-item{icon="i-lucide-trending-up" label="Scalability"}
  **Problem:** Black Friday sale — traffic jumps from 1,000 to 100,000 requests/second.

  **Solution:** Spin up more servers behind the load balancer. No code changes, no DNS changes, no downtime.

  ```text [Scaling Scenario]
  Normal Day (3 servers):    Black Friday (10 servers):

  LB ──┬── S1                LB ──┬── S1
       ├── S2                     ├── S2
       └── S3                     ├── S3
                                  ├── S4  ← new
  ~3,000 req/s capacity          ├── S5  ← new
                                  ├── S6  ← new
                                  ├── S7  ← new
                                  ├── S8  ← new
                                  ├── S9  ← new
                                  └── S10 ← new

                             ~10,000 req/s capacity
  ```
  :::

  :::tabs-item{icon="i-lucide-gauge" label="Performance"}
  **Problem:** All users hitting one server causes slow response times.

  **Solution:** Distribute load evenly, keep each server running at optimal capacity (30-60% utilization).

  | Metric             | Single Server  | 3 Servers + LB  | Improvement |
  | ------------------ | -------------- | --------------- | ----------- |
  | Avg Response Time  | 2,400 ms       | 180 ms          | **13x**     |
  | Max Concurrent     | 500            | 5,000           | **10x**     |
  | Uptime             | 99.5%          | 99.99%          | **~5x**     |
  | CPU Utilization    | 95%            | 35%             | **Optimal** |
  :::

  :::tabs-item{icon="i-lucide-wrench" label="Zero-Downtime Deploys"}
  **Problem:** Deploying a new version requires taking the server offline.

  **Solution:** Rolling deployments — update one server at a time while others continue serving traffic.

  ```text [Rolling Deploy Flow]
  Step 1: Remove S1     Step 2: Update S1     Step 3: Re-add S1
  LB ──┬── S1 (drain)   LB ──┬── S1 (deploy)   LB ──┬── S1 v2 ❤️
       ├── S2 ❤️ ◄───        ├── S2 ❤️ ◄───          ├── S2 ❤️
       └── S3 ❤️ ◄───        └── S3 ❤️ ◄───          └── S3 ❤️

  Step 4: Remove S2     Step 5: Update S2     Step 6: All v2
  LB ──┬── S1 v2 ❤️     LB ──┬── S1 v2 ❤️     LB ──┬── S1 v2 ❤️
       ├── S2 (drain)        ├── S2 (deploy)        ├── S2 v2 ❤️
       └── S3 ❤️ ◄───        └── S3 ❤️ ◄───          └── S3 v2 ❤️

  → Zero downtime throughout the entire process!
  ```
  :::
::

---

## Load Balancer Architecture

```text [Complete Load Balancer Architecture]

  ┌─────────────────────────────────────────────────────────────────────┐
  │                          INTERNET                                   │
  │                                                                     │
  │  📱 Mobile   💻 Desktop   🖥️ API Client   🌐 Browser               │
  └───────────────────────────┬─────────────────────────────────────────┘
                              │
                              ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │                    🌐 CDN (CloudFlare / AWS CloudFront)           │
  │                   Static assets, edge caching, DDoS shield        │
  └───────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │                    🔥 FIREWALL / WAF                              │
  │               ModSecurity, rate limiting, IP filtering            │
  └───────────────────────────┬───────────────────────────────────────┘
                              │
                ┌─────────────▼──────────────┐
                │                            │
        ┌───────▼───────┐           ┌────────▼──────┐
        │  ⚖️  ACTIVE    │◄─ VRRP ─►│  ⚖️  STANDBY   │
        │  Load Balancer │  Keepalive │  Load Balancer │
        │  (Primary)     │           │  (Backup)      │
        │  VIP: x.x.x.x │           │  VIP: x.x.x.x │
        └───────┬────────┘           └────────────────┘
                │
     ┌──────────┼──────────┬───────────┐
     │          │          │           │
     ▼          ▼          ▼           ▼
  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────────┐
  │ Web  │  │ Web  │  │ Web  │  │ Web      │
  │ S1   │  │ S2   │  │ S3   │  │ S4 (hot  │
  │ :8001│  │ :8002│  │ :8003│  │  standby)│
  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───────┘
     │         │         │          │
     └─────────┼─────────┘          │
               ▼                    │
     ┌─────────────────┐            │
     │   🔄 Cache Layer │            │
     │   (Redis/Memcached)          │
     └────────┬────────┘            │
              │                     │
     ┌────────▼─────────────────────▼─────────────┐
     │              💾 Database Layer               │
     │                                              │
     │   ┌──────────┐  ┌──────────┐  ┌──────────┐ │
     │   │ Primary  │──│ Replica  │──│ Replica  │ │
     │   │ (Write)  │  │ (Read)   │  │ (Read)   │ │
     │   └──────────┘  └──────────┘  └──────────┘ │
     └──────────────────────────────────────────────┘
```

---

## Types of Load Balancers

### Layer 4 vs Layer 7

```text [OSI Model — Where Load Balancers Operate]

  Layer 7 ─ Application  ─── HTTP, HTTPS, WebSocket, gRPC
            │                 ▲
            │    L7 Load Balancer operates HERE
            │    Can inspect: URLs, headers, cookies,
            │    content type, HTTP methods
            │
  Layer 6 ─ Presentation ─── SSL/TLS, Encryption
  Layer 5 ─ Session ───────── Sessions, Connections
            │
  Layer 4 ─ Transport ─────── TCP, UDP
            │                  ▲
            │    L4 Load Balancer operates HERE
            │    Can inspect: IP addresses, ports,
            │    TCP/UDP protocol only
            │
  Layer 3 ─ Network ────────── IP, ICMP
  Layer 2 ─ Data Link ──────── MAC, Ethernet
  Layer 1 ─ Physical ───────── Cables, Signals
```

::tabs
  :::tabs-item{icon="i-lucide-network" label="Layer 4 (Transport)"}
  **How it works:** Routes traffic based on **IP address and TCP/UDP port** without inspecting the packet contents.

  ```text [Layer 4 Flow]
  Client ──TCP SYN──► L4 LB ──TCP SYN──► Server
                       │
                       │  Decision based on:
                       │  • Source IP
                       │  • Destination IP
                       │  • Source Port
                       │  • Destination Port
                       │  • Protocol (TCP/UDP)
                       │
                       │  CANNOT see:
                       │  ✗ URL path
                       │  ✗ HTTP headers
                       │  ✗ Cookies
                       │  ✗ Request body
  ```

  | Aspect         | Layer 4                            |
  | -------------- | ---------------------------------- |
  | Speed          | **Very fast** (no content parsing)  |
  | CPU Usage      | Low                                |
  | Intelligence   | Basic (IP + Port only)             |
  | SSL            | Pass-through (no termination)       |
  | Use Cases      | TCP services, databases, gaming     |
  | Tools          | Nginx (stream), HAProxy, LVS        |
  :::

  :::tabs-item{icon="i-lucide-globe" label="Layer 7 (Application)"}
  **How it works:** Inspects the **full HTTP request** — URL, headers, cookies, body — to make intelligent routing decisions.

  ```text [Layer 7 Flow]
  Client ──HTTP GET /api/users──► L7 LB ──routes──► API Server
  Client ──HTTP GET /images/──────► L7 LB ──routes──► Static Server
  Client ──HTTP POST /upload──────► L7 LB ──routes──► Upload Server
                                    │
                                    │  Decision based on:
                                    │  ✓ URL path (/api, /static, /ws)
                                    │  ✓ HTTP headers (Host, User-Agent)
                                    │  ✓ Cookies (session affinity)
                                    │  ✓ HTTP method (GET, POST)
                                    │  ✓ Query parameters
                                    │  ✓ Request body content
  ```

  | Aspect         | Layer 7                             |
  | -------------- | ----------------------------------- |
  | Speed          | Slightly slower (content parsing)   |
  | CPU Usage      | Higher                              |
  | Intelligence   | **Advanced** (full HTTP inspection)  |
  | SSL            | Terminates SSL (decrypts traffic)   |
  | Use Cases      | Web apps, APIs, microservices        |
  | Tools          | Nginx, HAProxy, Envoy, Traefik       |
  :::
::

### Hardware vs Software vs Cloud

::card-group

::card
---
title: 🔧 Hardware Load Balancers
icon: i-lucide-hard-drive
---
Physical appliances with dedicated ASICs for packet processing.

**Examples:** F5 BIG-IP, Citrix ADC, A10 Thunder

**Pros:** Extreme performance, dedicated support, FIPS compliance

**Cons:** Expensive ($10K-$500K+), vendor lock-in, physical maintenance

**Best for:** Enterprise data centers, financial institutions
::

::card
---
title: 💻 Software Load Balancers
icon: i-lucide-code
---
Software running on standard servers or VMs.

**Examples:** Nginx, HAProxy, Envoy, Traefik, Caddy

**Pros:** Free/cheap, flexible, easy to automate, containerizable

**Cons:** Shares resources with OS, requires tuning

**Best for:** Most applications, startups, cloud-native
::

::card
---
title: ☁️ Cloud Load Balancers
icon: i-lucide-cloud
---
Managed services from cloud providers.

**Examples:** AWS ALB/NLB/GLB, GCP Cloud LB, Azure LB

**Pros:** Fully managed, auto-scaling, global distribution, no maintenance

**Cons:** Vendor lock-in, cost at scale, less customization

**Best for:** Cloud-native apps, global distribution
::

::

---

## Load Balancing Algorithms

```text [Algorithm Comparison Visual]

  🔄 ROUND ROBIN                 📊 LEAST CONNECTIONS
  ══════════════                  ══════════════════════

  Request 1 ──► S1               Request ──► LB checks:
  Request 2 ──► S2                 S1: 15 connections
  Request 3 ──► S3                 S2: 8 connections  ◄── Winner!
  Request 4 ──► S1 (repeat)       S3: 12 connections
  Request 5 ──► S2 (repeat)
                                  Routes to S2 (fewest)


  #️⃣ IP HASH                     ⚖️ WEIGHTED ROUND ROBIN
  ══════════════                  ══════════════════════

  IP: 10.0.0.1 ──► always S2     S1 (weight=5): gets 5 of 8 requests
  IP: 10.0.0.2 ──► always S1     S2 (weight=2): gets 2 of 8 requests
  IP: 10.0.0.3 ──► always S3     S3 (weight=1): gets 1 of 8 requests

  hash(IP) % servers = index     More powerful servers get more traffic


  🎯 LEAST TIME                   🎲 RANDOM
  ══════════════                  ══════════════

  Request ──► LB checks:          Request ──► LB picks randomly
    S1: 45ms response               Any server with equal probability
    S2: 12ms response ◄── Winner!   Simple but surprisingly effective
    S3: 67ms response               at large scale
```

::accordion

  :::accordion-item{icon="i-lucide-refresh-cw" label="Round Robin — Simple & Equal Distribution"}
  Distributes requests sequentially to each server in rotation. The simplest and most widely used algorithm.

  ```nginx [nginx.conf — Round Robin]
  upstream backend {
      # Round Robin is the default — no directive needed
      server 192.168.1.101:8080;
      server 192.168.1.102:8080;
      server 192.168.1.103:8080;
  }
  ```

  ```text [Visual Flow]
  Time ──►

  Request:  R1   R2   R3   R4   R5   R6   R7   R8   R9
  Server:   S1   S2   S3   S1   S2   S3   S1   S2   S3
            ▲              ▲              ▲
            └── Cycle 1 ──►└── Cycle 2 ──►└── Cycle 3
  ```

  **Best for:** Servers with identical hardware and similar request processing times.

  **Limitation:** Doesn't account for server load or request complexity.
  :::

  :::accordion-item{icon="i-lucide-bar-chart-3" label="Least Connections — Smart Load Awareness"}
  Routes each new request to the server with the **fewest active connections**. Adapts to real-time server load.

  ```nginx [nginx.conf — Least Connections]
  upstream backend {
      least_conn;
      server 192.168.1.101:8080;
      server 192.168.1.102:8080;
      server 192.168.1.103:8080;
  }
  ```

  ```text [Visual Flow]
  Current State:
    S1: ████████████░░░░  12 connections
    S2: ████░░░░░░░░░░░░   4 connections  ◄── Next request goes here
    S3: ██████████░░░░░░  10 connections

  After routing:
    S1: ████████████░░░░  12 connections
    S2: █████░░░░░░░░░░░   5 connections
    S3: ██████████░░░░░░  10 connections
  ```

  **Best for:** Requests with varying processing times (some fast, some slow).
  :::

  :::accordion-item{icon="i-lucide-hash" label="IP Hash — Session Persistence Without Cookies"}
  Uses the **client's IP address** to determine which server receives the request. The same client always reaches the same server.

  ```nginx [nginx.conf — IP Hash]
  upstream backend {
      ip_hash;
      server 192.168.1.101:8080;
      server 192.168.1.102:8080;
      server 192.168.1.103:8080;
  }
  ```

  ```text [Visual Flow]
  hash("10.0.0.1") % 3 = 1  ──► Always goes to S2
  hash("10.0.0.2") % 3 = 0  ──► Always goes to S1
  hash("10.0.0.3") % 3 = 2  ──► Always goes to S3
  hash("10.0.0.4") % 3 = 1  ──► Always goes to S2
  ```

  **Best for:** Applications with server-side sessions that can't be shared.

  **Limitation:** Users behind NAT/proxy all go to the same server.
  :::

  :::accordion-item{icon="i-lucide-weight" label="Weighted Algorithms — Heterogeneous Server Fleets"}
  Assign **weights** to servers based on capacity. Higher-weight servers receive proportionally more requests.

  ```nginx [nginx.conf — Weighted Round Robin]
  upstream backend {
      server 192.168.1.101:8080 weight=5;  # 8-core, 32GB — gets 5x traffic
      server 192.168.1.102:8080 weight=3;  # 4-core, 16GB — gets 3x traffic
      server 192.168.1.103:8080 weight=1;  # 2-core, 8GB  — gets 1x traffic
  }
  ```

  ```text [Traffic Distribution]
  Total weight: 5 + 3 + 1 = 9

  S1 (weight=5): ██████████████████████████████████████████████████████  55.6%
  S2 (weight=3): ████████████████████████████████                        33.3%
  S3 (weight=1): ███████████                                             11.1%
  ```

  **Best for:** Mixed server fleet with different hardware specifications.
  :::

  :::accordion-item{icon="i-lucide-shuffle" label="Random — Simple & Statistically Fair"}
  Selects a random server for each request. Statistically even distribution at scale.

  ```nginx [nginx.conf — Random with Two Choices]
  upstream backend {
      random two least_conn;  # Pick 2 random servers, choose one with fewer connections
      server 192.168.1.101:8080;
      server 192.168.1.102:8080;
      server 192.168.1.103:8080;
      server 192.168.1.104:8080;
  }
  ```

  **Best for:** Large server fleets where statistical distribution works well. The "power of two choices" variant is surprisingly effective.
  :::

::

---

## Nginx Load Balancer Setup

### Basic Configuration

::steps{level="4"}

#### Install Nginx

::code-group

```bash [Debian/Ubuntu]
sudo apt update
sudo apt install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
nginx -v
```

```bash [RHEL/CentOS]
sudo dnf install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx
nginx -v
```

```bash [macOS]
brew install nginx
brew services start nginx
nginx -v
```

::

#### Create the main load balancer configuration

```nginx [/etc/nginx/nginx.conf]
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

error_log /var/log/nginx/error.log warn;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    # ─── Basic Settings ────────────────────────────────
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 1000;
    types_hash_max_size 2048;
    server_tokens off;           # Hide Nginx version
    client_max_body_size 50M;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # ─── Logging ───────────────────────────────────────
    log_format main '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" '
                    'upstream=$upstream_addr '
                    'response_time=$upstream_response_time '
                    'request_time=$request_time';

    access_log /var/log/nginx/access.log main;

    # ─── Gzip Compression ─────────────────────────────
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 4;
    gzip_min_length 256;
    gzip_types text/plain text/css application/json application/javascript
               text/xml application/xml application/xml+rss text/javascript
               application/vnd.ms-fontobject application/x-font-ttf
               font/opentype image/svg+xml image/x-icon;

    # ─── Include site configs ──────────────────────────
    include /etc/nginx/conf.d/*.conf;
}
```

#### Configure the upstream backend servers

```nginx [/etc/nginx/conf.d/loadbalancer.conf]
# ═══════════════════════════════════════════════════════
#  UPSTREAM DEFINITIONS — Backend Server Pools
# ═══════════════════════════════════════════════════════

# Primary application servers
upstream app_servers {
    # Algorithm: Least Connections (best for varying response times)
    least_conn;

    # Backend servers with health check parameters
    server 192.168.1.101:8080 weight=5 max_fails=3 fail_timeout=30s;
    server 192.168.1.102:8080 weight=5 max_fails=3 fail_timeout=30s;
    server 192.168.1.103:8080 weight=3 max_fails=3 fail_timeout=30s;

    # Backup server — only used when all primary servers are down
    server 192.168.1.104:8080 backup;

    # Connection pooling to upstream
    keepalive 32;
    keepalive_requests 1000;
    keepalive_timeout 60s;
}

# API servers (separate pool)
upstream api_servers {
    least_conn;
    server 192.168.1.111:3000 weight=3 max_fails=3 fail_timeout=30s;
    server 192.168.1.112:3000 weight=3 max_fails=3 fail_timeout=30s;
    keepalive 16;
}

# WebSocket servers
upstream ws_servers {
    ip_hash;  # Sticky sessions required for WebSocket
    server 192.168.1.121:8081;
    server 192.168.1.122:8081;
}

# Static asset servers
upstream static_servers {
    server 192.168.1.131:80;
    server 192.168.1.132:80;
}


# ═══════════════════════════════════════════════════════
#  SERVER BLOCK — HTTPS (Port 443)
# ═══════════════════════════════════════════════════════

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com www.example.com;

    # ─── SSL/TLS Configuration ─────────────────────────
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_trusted_certificate /etc/nginx/ssl/chain.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;

    # ─── Security Headers ──────────────────────────────
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # ─── Rate Limiting Zones ───────────────────────────
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=3r/s;
    limit_conn_zone $binary_remote_addr zone=connlimit:10m;

    # ─── Main Application ──────────────────────────────
    location / {
        limit_req zone=general burst=20 nodelay;
        limit_conn connlimit 50;

        proxy_pass http://app_servers;
        proxy_http_version 1.1;

        # Required proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_set_header Connection "";

        # Timeouts
        proxy_connect_timeout 10s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;

        # Buffering
        proxy_buffering on;
        proxy_buffer_size 8k;
        proxy_buffers 8 8k;

        # Error handling — try next upstream on failure
        proxy_next_upstream error timeout http_502 http_503 http_504;
        proxy_next_upstream_tries 3;
        proxy_next_upstream_timeout 10s;
    }

    # ─── API Routes ────────────────────────────────────
    location /api/ {
        limit_req zone=api burst=50 nodelay;

        proxy_pass http://api_servers;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";

        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # ─── WebSocket Endpoint ────────────────────────────
    location /ws/ {
        proxy_pass http://ws_servers;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # ─── Static Assets ─────────────────────────────────
    location /static/ {
        proxy_pass http://static_servers;
        proxy_cache_valid 200 7d;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }

    # ─── Login Rate Limiting ───────────────────────────
    location /auth/login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://app_servers;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ─── Health Check Endpoint ─────────────────────────
    location /health {
        access_log off;
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }

    # ─── Deny Hidden Files ─────────────────────────────
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}


# ═══════════════════════════════════════════════════════
#  HTTP → HTTPS Redirect
# ═══════════════════════════════════════════════════════

server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;

    # ACME challenge for Let's Encrypt
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    # Redirect everything else to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}


# ═══════════════════════════════════════════════════════
#  STATUS PAGE — Monitoring
# ═══════════════════════════════════════════════════════

server {
    listen 8080;
    server_name localhost;
    allow 127.0.0.1;
    allow 10.0.0.0/8;
    deny all;

    location /nginx_status {
        stub_status on;
        access_log off;
    }
}
```

#### Test and apply configuration

```bash [Terminal]
# Test configuration syntax
sudo nginx -t

# Reload without downtime
sudo nginx -s reload

# Or restart entirely
sudo systemctl restart nginx

# Check status
sudo systemctl status nginx
```

::

### Session Persistence (Sticky Sessions)

```text [Sticky Sessions — Visual]

  WITHOUT Sticky Sessions:          WITH Sticky Sessions:
  ═══════════════════════           ════════════════════════

  👤 User A ─R1─► S1               👤 User A ─R1─► S1 ◄─ always
  👤 User A ─R2─► S3  ❌ lost      👤 User A ─R2─► S1 ◄─ always
  👤 User A ─R3─► S2  ❌ session   👤 User A ─R3─► S1 ◄─ always

  User's shopping cart              User's shopping cart
  is on S1 but they hit             stays on S1 every time!
  S2 and S3 — cart empty!
```

::tabs
  :::tabs-item{icon="i-lucide-cookie" label="Cookie-Based (Recommended)"}
  ```nginx [Sticky Cookie Configuration]
  upstream app_servers {
      # Nginx Plus feature — or use sticky_cookie_insert with OSS modules
      # For Nginx OSS, use ip_hash as alternative

      # With nginx-sticky-module-ng (compiled module):
      sticky cookie srv_id expires=1h domain=.example.com path=/;

      server 192.168.1.101:8080;
      server 192.168.1.102:8080;
      server 192.168.1.103:8080;
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-hash" label="IP Hash (OSS Built-in)"}
  ```nginx [IP Hash Configuration]
  upstream app_servers {
      ip_hash;
      server 192.168.1.101:8080;
      server 192.168.1.102:8080;
      server 192.168.1.103:8080;
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-key" label="Route-Based (Custom Header)"}
  ```nginx [Custom Header Routing]
  # Route based on a custom header (e.g., X-Server-ID from app)
  upstream app_servers {
      server 192.168.1.101:8080;
      server 192.168.1.102:8080;
      server 192.168.1.103:8080;
  }

  map $cookie_SERVERID $backend {
      server1 192.168.1.101:8080;
      server2 192.168.1.102:8080;
      server3 192.168.1.103:8080;
      default app_servers;
  }
  ```
  :::
::

### Health Checks

```text [Health Check — Visual Flow]

  Load Balancer Health Monitor
  ════════════════════════════

  Every 10 seconds:

  LB ──GET /health──► S1    Response: 200 OK     ──► ❤️ HEALTHY
  LB ──GET /health──► S2    Response: 200 OK     ──► ❤️ HEALTHY
  LB ──GET /health──► S3    Response: 503 Error  ──► 💔 UNHEALTHY (1/3 fails)
  LB ──GET /health──► S3    Response: timeout    ──► 💔 UNHEALTHY (2/3 fails)
  LB ──GET /health──► S3    Response: timeout    ──► ❌ REMOVED (3/3 fails)

  After fail_timeout (30s):
  LB ──GET /health──► S3    Response: 200 OK     ──► ❤️ RE-ADDED
```

```nginx [Health Check — Passive (Nginx OSS)]
upstream app_servers {
    least_conn;

    # Passive health checks (built into Nginx OSS)
    # max_fails: number of failed attempts before marking server as down
    # fail_timeout: time window for max_fails AND how long to wait before retrying
    server 192.168.1.101:8080 max_fails=3 fail_timeout=30s;
    server 192.168.1.102:8080 max_fails=3 fail_timeout=30s;
    server 192.168.1.103:8080 max_fails=3 fail_timeout=30s;
    server 192.168.1.104:8080 backup;  # Only used when all others fail
}
```

```nginx [Health Check — Active (Nginx Plus)]
upstream app_servers {
    zone backend 64k;
    server 192.168.1.101:8080;
    server 192.168.1.102:8080;
    server 192.168.1.103:8080;

    # Active health checks (Nginx Plus only)
    # Proactively checks servers even without traffic
}

server {
    location / {
        proxy_pass http://app_servers;
        health_check interval=10 fails=3 passes=2 uri=/health;
    }
}
```

---

## Docker Compose — Complete Multi-Server Setup

### Application Architecture

```text [Docker Compose Architecture]

  ┌─────────────────────────────────────────────────────────────┐
  │                    Docker Network: lb_network                │
  │                                                             │
  │  ┌──────────────────────────────────────────────────────┐  │
  │  │              🔒 Nginx Load Balancer                   │  │
  │  │              Port 80 → 443 (SSL)                     │  │
  │  │              + ModSecurity WAF                        │  │
  │  │              + Rate Limiting                          │  │
  │  └───────┬──────────┬──────────┬────────────────────────┘  │
  │          │          │          │                            │
  │   ┌──────▼───┐ ┌────▼─────┐ ┌─▼────────┐                 │
  │   │  App 1   │ │  App 2   │ │  App 3   │                 │
  │   │  :3000   │ │  :3000   │ │  :3000   │                 │
  │   │  Node.js │ │  Node.js │ │  Node.js │                 │
  │   └────┬─────┘ └────┬─────┘ └────┬─────┘                 │
  │        │            │            │                         │
  │   ┌────▼────────────▼────────────▼─────┐                  │
  │   │         🔴 Redis (Cache/Session)    │                  │
  │   │         Port 6379                   │                  │
  │   └────────────────┬───────────────────┘                  │
  │                    │                                       │
  │   ┌────────────────▼───────────────────┐                  │
  │   │         🐘 PostgreSQL (Database)    │                  │
  │   │         Port 5432                   │                  │
  │   └────────────────────────────────────┘                  │
  │                                                            │
  │   ┌────────────────────────────────────┐                  │
  │   │    📊 Prometheus + Grafana          │                  │
  │   │    Monitoring & Dashboards          │                  │
  │   └────────────────────────────────────┘                  │
  └─────────────────────────────────────────────────────────────┘
```

### Project Structure

```text [Project Directory Structure]
load-balancer-project/
├── docker-compose.yml
├── docker-compose.prod.yml
├── .env
│
├── nginx/
│   ├── nginx.conf
│   ├── conf.d/
│   │   ├── default.conf
│   │   ├── security.conf
│   │   └── rate-limiting.conf
│   ├── ssl/
│   │   ├── fullchain.pem
│   │   └── privkey.pem
│   ├── modsecurity/
│   │   ├── modsecurity.conf
│   │   └── crs-setup.conf
│   └── Dockerfile
│
├── app/
│   ├── Dockerfile
│   ├── package.json
│   ├── server.js
│   └── .dockerignore
│
├── monitoring/
│   ├── prometheus/
│   │   └── prometheus.yml
│   └── grafana/
│       └── dashboards/
│
└── scripts/
    ├── deploy.sh
    ├── scale.sh
    └── health-check.sh
```

### Docker Compose File

```yaml [docker-compose.yml]
version: '3.9'

# ═══════════════════════════════════════════════════════
#  Load Balancer + Multi-Server Application Stack
#  With Security, WAF, Monitoring, and SSL
# ═══════════════════════════════════════════════════════

services:

  # ─────────────────────────────────────────────────────
  #  NGINX LOAD BALANCER (with ModSecurity WAF)
  # ─────────────────────────────────────────────────────
  nginx-lb:
    build:
      context: ./nginx
      dockerfile: Dockerfile
    container_name: nginx-loadbalancer
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"    # Status page (internal)
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./nginx/modsecurity:/etc/nginx/modsecurity:ro
      - nginx_logs:/var/log/nginx
      - certbot_www:/var/www/certbot:ro
      - certbot_conf:/etc/letsencrypt:ro
    depends_on:
      app-1:
        condition: service_healthy
      app-2:
        condition: service_healthy
      app-3:
        condition: service_healthy
    networks:
      - frontend
      - backend
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 128M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 10s
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

  # ─────────────────────────────────────────────────────
  #  APPLICATION SERVERS (x3)
  # ─────────────────────────────────────────────────────
  app-1:
    build:
      context: ./app
      dockerfile: Dockerfile
    container_name: app-server-1
    environment:
      - NODE_ENV=production
      - APP_PORT=3000
      - SERVER_ID=app-1
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql://app:${DB_PASSWORD}@postgres:5432/appdb
    expose:
      - "3000"
    networks:
      - backend
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
        reservations:
          cpus: '0.1'
          memory: 64M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 20s
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy

  app-2:
    build:
      context: ./app
      dockerfile: Dockerfile
    container_name: app-server-2
    environment:
      - NODE_ENV=production
      - APP_PORT=3000
      - SERVER_ID=app-2
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql://app:${DB_PASSWORD}@postgres:5432/appdb
    expose:
      - "3000"
    networks:
      - backend
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 20s
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy

  app-3:
    build:
      context: ./app
      dockerfile: Dockerfile
    container_name: app-server-3
    environment:
      - NODE_ENV=production
      - APP_PORT=3000
      - SERVER_ID=app-3
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql://app:${DB_PASSWORD}@postgres:5432/appdb
    expose:
      - "3000"
    networks:
      - backend
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 20s
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy

  # ─────────────────────────────────────────────────────
  #  REDIS — Session Store & Cache
  # ─────────────────────────────────────────────────────
  redis:
    image: redis:7-alpine
    container_name: redis-cache
    command: >
      redis-server
      --requirepass ${REDIS_PASSWORD}
      --maxmemory 256mb
      --maxmemory-policy allkeys-lru
      --appendonly yes
      --protected-mode yes
    expose:
      - "6379"
    volumes:
      - redis_data:/data
    networks:
      - backend
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.25'
          memory: 300M
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD}", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3

  # ─────────────────────────────────────────────────────
  #  POSTGRESQL — Primary Database
  # ─────────────────────────────────────────────────────
  postgres:
    image: postgres:16-alpine
    container_name: postgres-db
    environment:
      POSTGRES_DB: appdb
      POSTGRES_USER: app
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_INITDB_ARGS: "--auth-host=scram-sha-256"
    expose:
      - "5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - backend
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U app -d appdb"]
      interval: 10s
      timeout: 5s
      retries: 5
    shm_size: '256mb'

  # ─────────────────────────────────────────────────────
  #  CERTBOT — Let's Encrypt SSL
  # ─────────────────────────────────────────────────────
  certbot:
    image: certbot/certbot:latest
    container_name: certbot
    volumes:
      - certbot_www:/var/www/certbot
      - certbot_conf:/etc/letsencrypt
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait $${!}; done;'"
    networks:
      - frontend

  # ─────────────────────────────────────────────────────
  #  PROMETHEUS — Metrics Collection
  # ─────────────────────────────────────────────────────
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    volumes:
      - ./monitoring/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    expose:
      - "9090"
    networks:
      - backend
      - monitoring
    restart: unless-stopped
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.retention.time=30d'

  # ─────────────────────────────────────────────────────
  #  GRAFANA — Monitoring Dashboard
  # ─────────────────────────────────────────────────────
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana_data:/var/lib/grafana
    networks:
      - monitoring
    restart: unless-stopped
    depends_on:
      - prometheus

  # ─────────────────────────────────────────────────────
  #  NGINX EXPORTER — Prometheus Metrics for Nginx
  # ─────────────────────────────────────────────────────
  nginx-exporter:
    image: nginx/nginx-prometheus-exporter:latest
    container_name: nginx-exporter
    command:
      - '-nginx.scrape-uri=http://nginx-lb:8080/nginx_status'
    expose:
      - "9113"
    networks:
      - backend
      - monitoring
    depends_on:
      - nginx-lb
    restart: unless-stopped


# ═══════════════════════════════════════════════════════
#  VOLUMES
# ═══════════════════════════════════════════════════════
volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local
  nginx_logs:
    driver: local
  prometheus_data:
    driver: local
  grafana_data:
    driver: local
  certbot_www:
    driver: local
  certbot_conf:
    driver: local


# ═══════════════════════════════════════════════════════
#  NETWORKS
# ═══════════════════════════════════════════════════════
networks:
  frontend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
  backend:
    driver: bridge
    internal: true    # No external access — only inter-container
    ipam:
      config:
        - subnet: 172.20.1.0/24
  monitoring:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.20.2.0/24
```

### Environment File

```bash [.env]
# Database
DB_PASSWORD=SuperSecureDbPassword2024!

# Redis
REDIS_PASSWORD=SuperSecureRedisPassword2024!

# Grafana
GRAFANA_PASSWORD=admin123secure

# SSL Domain
DOMAIN=example.com

# Application
NODE_ENV=production
```

### Sample Application (Node.js)

```javascript [app/server.js]
const express = require('express');
const os = require('os');

const app = express();
const PORT = process.env.APP_PORT || 3000;
const SERVER_ID = process.env.SERVER_ID || os.hostname();

// Middleware
app.use(express.json());

// Request logging
app.use((req, res, next) => {
    console.log(`[${SERVER_ID}] ${req.method} ${req.url} from ${req.ip}`);
    next();
});

// Main route
app.get('/', (req, res) => {
    res.json({
        message: 'Hello from load-balanced server!',
        server: SERVER_ID,
        hostname: os.hostname(),
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: {
            total: Math.round(os.totalmem() / 1024 / 1024) + 'MB',
            free: Math.round(os.freemem() / 1024 / 1024) + 'MB',
            usage: Math.round((1 - os.freemem() / os.totalmem()) * 100) + '%'
        },
        cpu: os.loadavg()
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        server: SERVER_ID,
        uptime: process.uptime()
    });
});

// API example
app.get('/api/data', (req, res) => {
    res.json({
        data: [1, 2, 3, 4, 5],
        served_by: SERVER_ID,
        timestamp: Date.now()
    });
});

// Simulated heavy endpoint (for testing load distribution)
app.get('/api/heavy', async (req, res) => {
    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, Math.random() * 2000));
    res.json({
        result: 'Heavy computation complete',
        server: SERVER_ID,
        processing_time: 'variable'
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`[${SERVER_ID}] Server running on port ${PORT}`);
});
```

```json [app/package.json]
{
  "name": "lb-demo-app",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}
```

```dockerfile [app/Dockerfile]
FROM node:20-alpine

WORKDIR /app

# Install curl for healthcheck
RUN apk add --no-cache curl

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy application code
COPY server.js .

# Non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup
USER appuser

EXPOSE 3000

CMD ["node", "server.js"]
```

### Nginx Load Balancer Dockerfile (with ModSecurity WAF)

```dockerfile [nginx/Dockerfile]
FROM owasp/modsecurity-crs:nginx-alpine

# Copy Nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/ /etc/nginx/conf.d/

# Copy ModSecurity configuration
COPY modsecurity/modsecurity.conf /etc/modsecurity.d/modsecurity.conf
COPY modsecurity/crs-setup.conf /etc/modsecurity.d/crs-setup.conf

# Copy SSL certificates (if available)
COPY ssl/ /etc/nginx/ssl/

# Create required directories
RUN mkdir -p /var/log/nginx /var/cache/nginx /var/www/certbot

# Health check
HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

EXPOSE 80 443 8080

CMD ["nginx", "-g", "daemon off;"]
```

### Nginx Load Balancer Configuration (Docker)

```nginx [nginx/conf.d/default.conf]
# ═══════════════════════════════════════════════════════
#  UPSTREAM DEFINITIONS — Docker Service Discovery
# ═══════════════════════════════════════════════════════

upstream app_backend {
    least_conn;

    # Docker container names resolve via Docker DNS
    server app-1:3000 weight=3 max_fails=3 fail_timeout=30s;
    server app-2:3000 weight=3 max_fails=3 fail_timeout=30s;
    server app-3:3000 weight=3 max_fails=3 fail_timeout=30s;

    keepalive 32;
}


# ═══════════════════════════════════════════════════════
#  MAIN SERVER BLOCK
# ═══════════════════════════════════════════════════════

server {
    listen 80;
    server_name _;

    # ─── Security Headers ──────────────────────────────
    include /etc/nginx/conf.d/security.conf;

    # ─── Rate Limiting ─────────────────────────────────
    include /etc/nginx/conf.d/rate-limiting.conf;

    # ─── Health Check ──────────────────────────────────
    location /health {
        access_log off;
        return 200 '{"status":"healthy","lb":"nginx"}\n';
        add_header Content-Type application/json;
    }

    # ─── Main Application ──────────────────────────────
    location / {
        limit_req zone=general burst=20 nodelay;

        proxy_pass http://app_backend;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-ID $request_id;
        proxy_set_header Connection "";

        proxy_connect_timeout 10s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;

        proxy_next_upstream error timeout http_502 http_503 http_504;
        proxy_next_upstream_tries 3;

        # Add server identifier header for debugging
        add_header X-Upstream-Server $upstream_addr always;
        add_header X-Request-ID $request_id always;
    }

    # ─── API Routes ────────────────────────────────────
    location /api/ {
        limit_req zone=api burst=50 nodelay;

        proxy_pass http://app_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
    }

    # ─── Deny hidden files ─────────────────────────────
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}


# ═══════════════════════════════════════════════════════
#  STATUS PAGE — Internal Only
# ═══════════════════════════════════════════════════════

server {
    listen 8080;
    server_name localhost;

    location /nginx_status {
        stub_status on;
        access_log off;
        allow 172.20.0.0/16;   # Docker networks
        allow 127.0.0.1;
        deny all;
    }

    location /health {
        access_log off;
        return 200 "OK\n";
    }
}
```

---

## Security & Protection

### Security Headers Configuration

```nginx [nginx/conf.d/security.conf]
# ═══════════════════════════════════════════════════════
#  SECURITY HEADERS & HARDENING
# ═══════════════════════════════════════════════════════

# Hide Nginx version
server_tokens off;
more_clear_headers Server;

# Security Headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'self';" always;

# HSTS (only enable when SSL is confirmed working)
# add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# Prevent clickjacking
add_header X-Permitted-Cross-Domain-Policies "none" always;

# Disable content sniffing
add_header X-Download-Options "noopen" always;

# Block common attack patterns in URI
if ($request_uri ~* "(eval\(|base64|localhost|loopback|127\.0\.0\.1)") {
    return 403;
}

# Block common exploit scanners
if ($http_user_agent ~* "(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wpscan|nuclei)") {
    return 403;
}

# Block requests with no User-Agent
if ($http_user_agent = "") {
    return 403;
}

# Limit request body size
client_max_body_size 10M;
client_body_buffer_size 128k;

# Limit header size
large_client_header_buffers 4 8k;
```

### Rate Limiting Configuration

```nginx [nginx/conf.d/rate-limiting.conf]
# ═══════════════════════════════════════════════════════
#  RATE LIMITING & DDoS PROTECTION
# ═══════════════════════════════════════════════════════

# ─── Rate Limit Zones ─────────────────────────────────

# General requests: 10 requests/second per IP
limit_req_zone $binary_remote_addr zone=general:20m rate=10r/s;

# API requests: 30 requests/second per IP
limit_req_zone $binary_remote_addr zone=api:20m rate=30r/s;

# Login/Auth: 3 requests/second per IP (anti brute-force)
limit_req_zone $binary_remote_addr zone=login:10m rate=3r/s;

# Search: 5 requests/second per IP
limit_req_zone $binary_remote_addr zone=search:10m rate=5r/s;

# Per-server rate limit (total requests to a single upstream)
limit_req_zone $server_name zone=server_total:10m rate=1000r/s;

# ─── Connection Limits ────────────────────────────────

# Max 100 concurrent connections per IP
limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;

# Max total connections to upstream
limit_conn_zone $server_name zone=conn_total:10m;

# ─── Rate Limit Response ──────────────────────────────

# Return 429 (Too Many Requests) instead of 503
limit_req_status 429;
limit_conn_status 429;

# Custom error page for rate limiting
error_page 429 = @rate_limited;

# ─── Rate Limit Log Level ─────────────────────────────
limit_req_log_level warn;
limit_conn_log_level warn;
```

```text [Rate Limiting — Visual Flow]

  📊 Rate Limit: 10 requests/second (burst=20)

  Time:    0s    0.1s   0.2s   0.3s   0.4s   ... 1.0s
  Bucket:  [10]  [9]    [8]    [7]    [6]    ... [10] (refills)

  Normal traffic (8 req/s):
  ├── R1 ✅  R2 ✅  R3 ✅  R4 ✅  R5 ✅  R6 ✅  R7 ✅  R8 ✅
  └── All pass! Bucket never empties.

  Burst traffic (25 req/s):
  ├── R1-R10 ✅ (rate allowance)
  ├── R11-R20 ✅ (burst buffer of 20)
  ├── R21 ❌ 429 Too Many Requests
  ├── R22 ❌ 429 Too Many Requests
  └── R23 ❌ 429 Too Many Requests

  DDoS traffic (1000 req/s):
  ├── R1-R10 ✅ (rate allowance)
  ├── R11-R30 ✅ (burst buffer)
  ├── R31-R1000 ❌❌❌ All blocked with 429
  └── Attacker's bandwidth wasted! Server protected ✅
```

### ModSecurity WAF Configuration

```conf [nginx/modsecurity/modsecurity.conf]
# ═══════════════════════════════════════════════════════
#  ModSecurity WAF Configuration
# ═══════════════════════════════════════════════════════

# Enable ModSecurity
SecRuleEngine On

# Set default action
SecDefaultAction "phase:1,log,auditlog,deny,status:403"

# Request body handling
SecRequestBodyAccess On
SecRequestBodyLimit 13107200           # 12.5 MB
SecRequestBodyNoFilesLimit 131072      # 128 KB

# Response body handling
SecResponseBodyAccess Off

# Audit logging
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/nginx/modsec_audit.log

# Debug log (disable in production)
SecDebugLog /var/log/nginx/modsec_debug.log
SecDebugLogLevel 0

# Temporary files
SecTmpDir /tmp/modsecurity/tmp
SecDataDir /tmp/modsecurity/data

# ─── Custom Rules ──────────────────────────────────────

# Block SQL Injection patterns
SecRule ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS \
    "@rx (?i:(?:union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set))" \
    "id:1001,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,\
    log,\
    msg:'SQL Injection Detected',\
    severity:'CRITICAL',\
    tag:'attack-sqli'"

# Block XSS patterns
SecRule ARGS|ARGS_NAMES|REQUEST_BODY \
    "@rx (?i:<script[^>]*>|javascript:|on\w+\s*=|<\s*img[^>]+onerror)" \
    "id:1002,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:htmlEntityDecode,\
    log,\
    msg:'XSS Attack Detected',\
    severity:'CRITICAL',\
    tag:'attack-xss'"

# Block Path Traversal
SecRule ARGS|REQUEST_URI \
    "@rx (?:(?:\.\.[\\/]){2,}|(?:etc[\\/](?:passwd|shadow|hosts))|(?:proc[\\/]self))" \
    "id:1003,\
    phase:1,\
    block,\
    t:none,t:urlDecodeUni,\
    log,\
    msg:'Path Traversal Detected',\
    severity:'CRITICAL',\
    tag:'attack-lfi'"

# Block common webshell patterns
SecRule REQUEST_URI|ARGS|REQUEST_BODY \
    "@rx (?i:(?:cmd|command|exec|execute|shell|system|passthru|popen)\s*[\(=])" \
    "id:1004,\
    phase:2,\
    block,\
    t:none,t:urlDecodeUni,t:htmlEntityDecode,\
    log,\
    msg:'Webshell/Command Injection Detected',\
    severity:'CRITICAL',\
    tag:'attack-rce'"

# Block scanner user agents
SecRule REQUEST_HEADERS:User-Agent \
    "@rx (?i:nikto|sqlmap|nessus|openvas|w3af|acunetix|nmap|masscan|burp|zap|dirbuster)" \
    "id:1005,\
    phase:1,\
    block,\
    log,\
    msg:'Security Scanner Detected',\
    severity:'WARNING',\
    tag:'scanner-detection'"

# Rate limit by IP (WAF level)
SecRule IP:REQUEST_RATE "@gt 100" \
    "id:1006,\
    phase:1,\
    block,\
    log,\
    msg:'Rate Limit Exceeded (WAF)',\
    severity:'WARNING',\
    tag:'rate-limit'"

# Block requests with empty Host header
SecRule REQUEST_HEADERS:Host "@rx ^$" \
    "id:1007,\
    phase:1,\
    block,\
    log,\
    msg:'Empty Host Header',\
    severity:'WARNING'"

# Include OWASP Core Rule Set
Include /etc/modsecurity.d/owasp-crs/crs-setup.conf
Include /etc/modsecurity.d/owasp-crs/rules/*.conf
```

```text [WAF Protection — Visual Flow]

  🛡️ WAF PROTECTION LAYERS
  ═══════════════════════════

  Incoming Request
       │
       ▼
  ┌────────────────────────┐
  │  Layer 1: IP Filtering  │  Block known bad IPs, GeoIP blocking
  │  ✅ Pass / ❌ Block      │
  └──────────┬─────────────┘
             │
  ┌──────────▼─────────────┐
  │  Layer 2: Rate Limiting │  Token bucket algorithm
  │  ✅ Pass / ❌ 429 Error  │
  └──────────┬─────────────┘
             │
  ┌──────────▼─────────────┐
  │  Layer 3: Protocol      │  Valid HTTP, headers, methods
  │  Validation             │
  │  ✅ Pass / ❌ 400 Error  │
  └──────────┬─────────────┘
             │
  ┌──────────▼─────────────┐
  │  Layer 4: ModSecurity   │  OWASP CRS rules
  │  WAF Rules              │  SQLi, XSS, LFI, RCE detection
  │  ✅ Pass / ❌ 403 Error  │
  └──────────┬─────────────┘
             │
  ┌──────────▼─────────────┐
  │  Layer 5: Custom Rules  │  Application-specific rules
  │  ✅ Pass / ❌ 403 Error  │
  └──────────┬─────────────┘
             │
             ▼
  ┌────────────────────────┐
  │  ⚖️ Load Balancer       │  Route to healthy backend
  └────────────────────────┘
             │
             ▼
  ┌────────────────────────┐
  │  🖥️ Application Server  │  Process clean request
  └────────────────────────┘
```

### IP Whitelisting/Blacklisting

```nginx [nginx/conf.d/ip-access.conf]
# ═══════════════════════════════════════════════════════
#  IP ACCESS CONTROL
# ═══════════════════════════════════════════════════════

# ─── GeoIP Blocking (requires ngx_http_geoip2_module) ──
# geoip2 /usr/share/GeoIP/GeoLite2-Country.mmdb {
#     $geoip2_data_country_iso_code country iso_code;
# }
# map $geoip2_data_country_iso_code $allowed_country {
#     US 1; CA 1; GB 1; DE 1; FR 1;
#     default 0;
# }

# ─── IP Blacklist ──────────────────────────────────────
# Create a file with denied IPs
# Usage: include /etc/nginx/conf.d/ip-blacklist.conf;

# Deny specific IPs
deny 192.168.100.1;
deny 10.0.0.0/8;

# Deny ranges
deny 123.45.67.0/24;

# ─── IP Whitelist (Admin panel) ────────────────────────
geo $admin_whitelist {
    default 0;
    127.0.0.1/32 1;
    10.10.0.0/16 1;
    192.168.1.0/24 1;
    # Add your office/VPN IPs
}

# Admin panel — whitelist only
# location /admin {
#     if ($admin_whitelist = 0) {
#         return 403;
#     }
#     proxy_pass http://app_backend;
# }
```

### SSL/TLS Best Practices

```bash [Generate SSL Certificates with Let's Encrypt]
# Initial certificate generation
docker compose run --rm certbot certonly \
  --webroot \
  --webroot-path=/var/www/certbot \
  -d example.com \
  -d www.example.com \
  --email admin@example.com \
  --agree-tos \
  --no-eff-email

# Or generate self-signed for development
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/privkey.pem \
  -out nginx/ssl/fullchain.pem \
  -subj "/CN=localhost"
```

```nginx [SSL/TLS Configuration Block]
# ═══════════════════════════════════════════════════════
#  SSL/TLS BEST PRACTICES
# ═══════════════════════════════════════════════════════

ssl_protocols TLSv1.2 TLSv1.3;

ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

ssl_prefer_server_ciphers off;

# DH parameters (generate with: openssl dhparam -out dhparam.pem 4096)
ssl_dhparam /etc/nginx/ssl/dhparam.pem;

# Session caching
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

---

## Advanced Features

### Blue-Green Deployment

```text [Blue-Green Deployment — Visual]

  STEP 1: Blue is LIVE, deploy to Green
  ═══════════════════════════════════════

                    LB ──100%──► 🔵 BLUE (v1.0 — LIVE)
                         0% ──► 🟢 GREEN (v2.0 — deploying...)


  STEP 2: Test Green internally
  ═══════════════════════════════════════

                    LB ──100%──► 🔵 BLUE (v1.0 — LIVE)
                         0% ──► 🟢 GREEN (v2.0 — testing ✅)
                                     ↑
                    QA Team ─────────┘ (internal test URL)


  STEP 3: Switch traffic to Green
  ═══════════════════════════════════════

                    LB ───0%──► 🔵 BLUE (v1.0 — standby)
                       100%──► 🟢 GREEN (v2.0 — LIVE 🎉)


  STEP 4: Rollback if needed (instant!)
  ═══════════════════════════════════════

                    LB ──100%──► 🔵 BLUE (v1.0 — LIVE again)
                         0% ──► 🟢 GREEN (v2.0 — rolled back)
```

```nginx [Blue-Green Nginx Configuration]
# Blue environment
upstream blue {
    server app-blue-1:3000;
    server app-blue-2:3000;
}

# Green environment
upstream green {
    server app-green-1:3000;
    server app-green-2:3000;
}

# Map to control active environment
# Change this variable to switch: blue or green
map $host $active_backend {
    default "blue";     # ← Change to "green" to switch
}

server {
    listen 80;

    location / {
        # Dynamic upstream selection
        proxy_pass http://$active_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Internal test endpoint for inactive environment
    location /test-green/ {
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://green/;
    }

    location /test-blue/ {
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://blue/;
    }
}
```

### Canary Releases

```text [Canary Release — Visual]

  Stage 1: 5% Canary                    Stage 2: 25% Canary
  ════════════════════                  ════════════════════

  ████████████████████  95% → v1.0     ███████████████░░░░░  75% → v1.0
  █░░░░░░░░░░░░░░░░░░░   5% → v2.0     █████░░░░░░░░░░░░░░  25% → v2.0


  Stage 3: 50% Canary                    Stage 4: 100% Rollout
  ════════════════════                  ════════════════════

  ██████████░░░░░░░░░░  50% → v1.0     ░░░░░░░░░░░░░░░░░░░░   0% → v1.0
  ██████████░░░░░░░░░░  50% → v2.0     ████████████████████ 100% → v2.0 🎉
```

```nginx [Canary Release Configuration]
# Stable servers (v1.0) — weight controls traffic percentage
upstream stable {
    server app-stable-1:3000 weight=10;
    server app-stable-2:3000 weight=10;
}

# Canary servers (v2.0)
upstream canary {
    server app-canary-1:3000;
}

# Split traffic: use split_clients for percentage-based routing
split_clients "${remote_addr}${request_uri}" $upstream_variant {
    5%     canary;     # 5% of traffic goes to canary
    *      stable;     # 95% goes to stable
}

server {
    listen 80;

    location / {
        proxy_pass http://$upstream_variant;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # Add header to identify which version served the request
        add_header X-Served-By $upstream_variant always;
    }
}
```

### Graceful Reload (Zero-Downtime)

```bash [Zero-Downtime Reload]
# Test configuration before reload
nginx -t

# Graceful reload — existing connections continue, new config takes effect
nginx -s reload

# Or with systemd
sudo systemctl reload nginx
```

```bash [scripts/deploy.sh]
#!/bin/bash
# Zero-downtime deployment script

set -e

echo "🚀 Starting zero-downtime deployment..."

# Pull latest images
docker compose pull

# Scale up new containers
docker compose up -d --no-deps --scale app-1=2 app-1
sleep 10

# Health check new containers
for i in {1..10}; do
    if curl -sf http://localhost/health > /dev/null; then
        echo "✅ Health check passed"
        break
    fi
    echo "⏳ Waiting for health check... ($i/10)"
    sleep 3
done

# Scale down old containers
docker compose up -d --no-deps --scale app-1=1 app-1

# Reload Nginx to pick up changes
docker compose exec nginx-lb nginx -s reload

echo "🎉 Deployment complete!"
```

### Auto-Scaling Script

```bash [scripts/scale.sh]
#!/bin/bash
# Auto-scaling based on CPU/connection metrics

SCALE_UP_THRESHOLD=70    # CPU percentage
SCALE_DOWN_THRESHOLD=30  # CPU percentage
MIN_INSTANCES=2
MAX_INSTANCES=10
CHECK_INTERVAL=30        # seconds

while true; do
    # Get average CPU usage across app containers
    AVG_CPU=$(docker stats --no-stream --format "{{.CPUPerc}}" \
        $(docker ps -q --filter "name=app-") | \
        sed 's/%//' | awk '{sum+=$1; n++} END {print int(sum/n)}')

    CURRENT=$(docker ps -q --filter "name=app-" | wc -l)

    echo "[$(date)] CPU: ${AVG_CPU}% | Instances: ${CURRENT}"

    if [ "$AVG_CPU" -gt "$SCALE_UP_THRESHOLD" ] && [ "$CURRENT" -lt "$MAX_INSTANCES" ]; then
        NEW_COUNT=$((CURRENT + 1))
        echo "📈 Scaling UP to ${NEW_COUNT} instances..."
        docker compose up -d --scale app=${NEW_COUNT} --no-recreate
        docker compose exec nginx-lb nginx -s reload
    fi

    if [ "$AVG_CPU" -lt "$SCALE_DOWN_THRESHOLD" ] && [ "$CURRENT" -gt "$MIN_INSTANCES" ]; then
        NEW_COUNT=$((CURRENT - 1))
        echo "📉 Scaling DOWN to ${NEW_COUNT} instances..."
        docker compose up -d --scale app=${NEW_COUNT}
        docker compose exec nginx-lb nginx -s reload
    fi

    sleep $CHECK_INTERVAL
done
```

---

## High Availability

### Keepalived — Load Balancer Failover

```text [HA Architecture with Keepalived]

  ┌──────────────────────────────────────────────────────────┐
  │                     VIRTUAL IP (VIP)                      │
  │                    vip: 192.168.1.100                     │
  │              (DNS points here — never changes)            │
  └──────────────┬───────────────────────┬───────────────────┘
                 │                       │
      ┌──────────▼──────────┐  ┌─────────▼───────────┐
      │   ⚖️  LB PRIMARY     │  │   ⚖️  LB SECONDARY   │
      │   192.168.1.10      │  │   192.168.1.11      │
      │                     │  │                     │
      │   MASTER (holds VIP)│  │   BACKUP (standby)  │
      │   Priority: 101     │  │   Priority: 100     │
      │   ❤️ VRRP heartbeat ◄──►  ❤️ VRRP heartbeat  │
      └──────────┬──────────┘  └─────────┬───────────┘
                 │                       │
                 └───────────┬───────────┘
                             │
              ┌──────────────▼────────────────┐
              │       Backend Servers          │
              │   S1       S2       S3        │
              └───────────────────────────────┘


  FAILOVER SCENARIO:
  ══════════════════

  Normal:     PRIMARY (VIP) ──► Backend        SECONDARY (idle)
                    │
  Primary dies:     PRIMARY ❌                  SECONDARY takes VIP ──► Backend
                                                     │
  Primary recovers: PRIMARY (takes VIP back) ──► Backend     SECONDARY (idle again)
```

```conf [/etc/keepalived/keepalived.conf — PRIMARY]
# ═══════════════════════════════════════════════════════
#  Keepalived Configuration — PRIMARY Load Balancer
# ═══════════════════════════════════════════════════════

global_defs {
    router_id LB_PRIMARY
    script_user root
    enable_script_security
}

# Health check script for Nginx
vrrp_script check_nginx {
    script "/usr/bin/curl -sf http://localhost/health || exit 1"
    interval 3        # Check every 3 seconds
    weight -20        # Reduce priority by 20 if script fails
    fall 3            # Mark failed after 3 consecutive failures
    rise 2            # Mark recovered after 2 consecutive successes
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 101              # Higher priority = MASTER
    advert_int 1              # VRRP advertisement interval

    authentication {
        auth_type PASS
        auth_pass SecureVRRP2024!
    }

    virtual_ipaddress {
        192.168.1.100/24      # Virtual IP address
    }

    track_script {
        check_nginx
    }

    # Notification scripts
    notify_master "/etc/keepalived/scripts/master.sh"
    notify_backup "/etc/keepalived/scripts/backup.sh"
    notify_fault  "/etc/keepalived/scripts/fault.sh"
}
```

```conf [/etc/keepalived/keepalived.conf — SECONDARY]
# ═══════════════════════════════════════════════════════
#  Keepalived Configuration — SECONDARY Load Balancer
# ═══════════════════════════════════════════════════════

global_defs {
    router_id LB_SECONDARY
    script_user root
    enable_script_security
}

vrrp_script check_nginx {
    script "/usr/bin/curl -sf http://localhost/health || exit 1"
    interval 3
    weight -20
    fall 3
    rise 2
}

vrrp_instance VI_1 {
    state BACKUP
    interface eth0
    virtual_router_id 51
    priority 100              # Lower priority = BACKUP
    advert_int 1

    authentication {
        auth_type PASS
        auth_pass SecureVRRP2024!
    }

    virtual_ipaddress {
        192.168.1.100/24
    }

    track_script {
        check_nginx
    }

    notify_master "/etc/keepalived/scripts/master.sh"
    notify_backup "/etc/keepalived/scripts/backup.sh"
    notify_fault  "/etc/keepalived/scripts/fault.sh"
}
```

```bash [Install and Start Keepalived]
# Install
sudo apt install -y keepalived

# Enable and start
sudo systemctl enable keepalived
sudo systemctl start keepalived

# Check VIP assignment
ip addr show eth0 | grep "192.168.1.100"

# Check status
sudo systemctl status keepalived
```

---

## Monitoring & Logging

### Prometheus Configuration

```yaml [monitoring/prometheus/prometheus.yml]
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']
    metrics_path: /metrics

  - job_name: 'app-servers'
    static_configs:
      - targets: ['app-1:3000', 'app-2:3000', 'app-3:3000']
    metrics_path: /metrics

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
```

### Nginx Access Log Analysis

```bash [Useful Log Analysis Commands]
# Real-time log watching
docker compose logs -f nginx-lb

# Top IPs by request count
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20

# Response codes distribution
awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c | sort -rn

# Upstream server distribution (verify load balancing)
grep -oP 'upstream=\K[^ ]+' /var/log/nginx/access.log | sort | uniq -c | sort -rn

# Slowest requests
awk '$NF > 2.0 {print $0}' /var/log/nginx/access.log | tail -20

# Requests per second
awk '{print $4}' /var/log/nginx/access.log | cut -d: -f1-3 | uniq -c | tail -10

# 4xx and 5xx errors
awk '$9 >= 400' /var/log/nginx/access.log | tail -50
```

---

## Real-World Scenarios

### Microservices Load Balancing

```text [Microservices Architecture]

                          ⚖️ API GATEWAY / LOAD BALANCER
                         ┌─────────────────────────────┐
                         │         Nginx / Envoy        │
                         │                              │
                         │  /api/users  → user-service  │
                         │  /api/orders → order-service │
                         │  /api/products → product-svc │
                         │  /api/payments → payment-svc │
                         └──┬────┬────┬────┬───────────┘
                            │    │    │    │
               ┌────────────▼┐ ┌─▼────┴─┐ ├────────────┐
               │ User Service│ │ Order  │ │ Product    │
               │ ┌──┐ ┌──┐  │ │ Service│ │ Service    │
               │ │S1│ │S2│  │ │ ┌──┐   │ │ ┌──┐ ┌──┐ │
               │ └──┘ └──┘  │ │ │S1│   │ │ │S1│ │S2│ │
               └─────────────┘ │ └──┘   │ │ └──┘ └──┘ │
                               └────────┘ └────────────┘
```

```nginx [Microservices Nginx Configuration]
# User service — 3 replicas
upstream user_service {
    least_conn;
    server user-svc-1:3000;
    server user-svc-2:3000;
    server user-svc-3:3000;
}

# Order service — 2 replicas
upstream order_service {
    least_conn;
    server order-svc-1:3000;
    server order-svc-2:3000;
}

# Product service — 2 replicas
upstream product_service {
    server product-svc-1:3000;
    server product-svc-2:3000;
}

server {
    listen 80;

    # Route by URL path to different services
    location /api/users {
        proxy_pass http://user_service;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api/orders {
        proxy_pass http://order_service;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api/products {
        proxy_pass http://product_service;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Database Read Replica Load Balancing

```text [Database Read/Write Split]

  Application Layer:
  ══════════════════

  WRITE Operations (INSERT/UPDATE/DELETE)
       │
       ▼
  ┌──────────────┐
  │ 🐘 PRIMARY    │ ──replication──►  ┌──────────────┐
  │  (Read/Write) │                   │ 🐘 REPLICA 1  │
  └──────────────┘ ──replication──►  │  (Read Only)  │
                                      └──────────────┘
                    ──replication──►  ┌──────────────┐
                                      │ 🐘 REPLICA 2  │
  READ Operations (SELECT)            │  (Read Only)  │
       │                              └──────────────┘
       ▼
  ┌──────────────┐
  │ ⚖️ LB (Nginx  │──► Replica 1
  │  Stream mode) │──► Replica 2
  └──────────────┘
```

```nginx [Database Load Balancing — Nginx Stream Module]
# This goes in nginx.conf, NOT in http block
stream {
    # PostgreSQL read replicas
    upstream postgres_read {
        least_conn;
        server postgres-replica-1:5432 weight=5;
        server postgres-replica-2:5432 weight=5;
        server postgres-primary:5432 backup;  # Fallback to primary
    }

    # PostgreSQL primary (writes)
    upstream postgres_write {
        server postgres-primary:5432;
    }

    # Read replica load balancer
    server {
        listen 5433;  # App connects here for reads
        proxy_pass postgres_read;
        proxy_connect_timeout 10s;
        proxy_timeout 300s;
    }

    # Write connection (pass-through)
    server {
        listen 5432;  # App connects here for writes
        proxy_pass postgres_write;
        proxy_connect_timeout 10s;
        proxy_timeout 300s;
    }

    # Redis Sentinel
    upstream redis_cluster {
        server redis-1:6379;
        server redis-2:6379;
        server redis-3:6379;
    }

    server {
        listen 6380;
        proxy_pass redis_cluster;
    }
}
```

---

## Operations Commands

### Deployment & Management

```bash [Start Everything]
docker compose up -d
```

```bash [Check All Service Health]
docker compose ps
docker compose exec nginx-lb curl -s http://localhost/health
docker compose exec nginx-lb curl -s http://app-1:3000/health
docker compose exec nginx-lb curl -s http://app-2:3000/health
docker compose exec nginx-lb curl -s http://app-3:3000/health
```

```bash [Scale Application Servers]
docker compose up -d --scale app-1=1 --scale app-2=1 --scale app-3=1
# Note: For dynamic scaling, use named service with replicas:
# docker compose up -d --scale app=5
```

```bash [Reload Nginx Without Downtime]
docker compose exec nginx-lb nginx -t && docker compose exec nginx-lb nginx -s reload
```

```bash [View Logs]
docker compose logs -f nginx-lb
docker compose logs -f app-1 app-2 app-3
```

```bash [Test Load Distribution]
for i in $(seq 1 20); do
    curl -s http://localhost/ | jq -r '.server'
done | sort | uniq -c
```

```bash [Benchmark with wrk]
wrk -t4 -c100 -d30s http://localhost/
```

```bash [Benchmark with ab]
ab -n 10000 -c 100 http://localhost/
```

```bash [Check SSL Configuration]
openssl s_client -connect localhost:443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -text | head -20
```

```bash [Monitor Nginx Status]
watch -n 1 'curl -s http://localhost:8080/nginx_status'
```

---

## Security Checklist

::collapsible

```text [Production Security Checklist]
═══════════════════════════════════════════════════════════
  LOAD BALANCER SECURITY CHECKLIST
═══════════════════════════════════════════════════════════

  NGINX HARDENING
  ───────────────
  ☐ server_tokens off (hide version)
  ☐ Remove Server header completely
  ☐ Disable unnecessary modules
  ☐ Set worker_rlimit_nofile
  ☐ Configure worker_connections appropriately
  ☐ Set client_max_body_size
  ☐ Limit large_client_header_buffers

  SSL/TLS
  ───────
  ☐ TLS 1.2+ only (disable SSLv3, TLS 1.0, 1.1)
  ☐ Strong cipher suite configured
  ☐ ssl_prefer_server_ciphers on
  ☐ DH parameters generated (4096-bit)
  ☐ HSTS header enabled
  ☐ OCSP stapling enabled
  ☐ SSL session cache configured
  ☐ Certificate auto-renewal (Let's Encrypt)
  ☐ Certificate chain complete

  SECURITY HEADERS
  ────────────────
  ☐ X-Frame-Options: SAMEORIGIN
  ☐ X-Content-Type-Options: nosniff
  ☐ X-XSS-Protection: 1; mode=block
  ☐ Referrer-Policy: strict-origin-when-cross-origin
  ☐ Content-Security-Policy configured
  ☐ Permissions-Policy configured
  ☐ Strict-Transport-Security (HSTS)

  RATE LIMITING
  ─────────────
  ☐ General rate limit configured
  ☐ API-specific rate limits
  ☐ Login/auth endpoint rate limits
  ☐ Connection limits per IP
  ☐ Custom 429 error page
  ☐ Burst settings tuned for legitimate traffic

  WAF
  ───
  ☐ ModSecurity installed and enabled
  ☐ OWASP Core Rule Set (CRS) loaded
  ☐ Custom rules for application-specific attacks
  ☐ SQLi protection rules active
  ☐ XSS protection rules active
  ☐ Path traversal rules active
  ☐ Scanner/bot detection rules
  ☐ Audit logging enabled

  ACCESS CONTROL
  ──────────────
  ☐ Admin panels IP-whitelisted
  ☐ Status page restricted to internal
  ☐ Hidden files denied (location ~ /\.)
  ☐ Sensitive paths blocked (.git, .env, etc.)
  ☐ GeoIP blocking (if applicable)
  ☐ Malicious UA blocking

  DOCKER
  ──────
  ☐ Non-root containers
  ☐ Read-only file systems where possible
  ☐ Resource limits (CPU, memory) set
  ☐ Internal networks for backend
  ☐ No unnecessary port exposures
  ☐ Health checks configured
  ☐ Log rotation configured
  ☐ Secrets via environment variables (not in compose file)

  HIGH AVAILABILITY
  ─────────────────
  ☐ Multiple load balancer instances
  ☐ Keepalived/VRRP for failover
  ☐ Health checks on all upstreams
  ☐ Backup servers configured
  ☐ proxy_next_upstream configured
  ☐ Graceful reload tested
  ☐ Rollback procedure documented

  MONITORING
  ──────────
  ☐ Prometheus metrics collection
  ☐ Grafana dashboards configured
  ☐ Alerting rules (5xx spikes, latency, etc.)
  ☐ Access log analysis automated
  ☐ Error log monitoring
  ☐ Upstream health monitoring
  ☐ Certificate expiry monitoring
```

::

---

## Tool Resources

::card-group

::card
---
title: Nginx
icon: i-simple-icons-nginx
to: https://nginx.org/en/docs/
target: _blank
---
The most popular open-source load balancer and reverse proxy. Powers over 30% of all websites. Supports L4/L7 load balancing, SSL termination, caching, and WebSocket proxying.
::

::card
---
title: HAProxy
icon: i-simple-icons-github
to: https://www.haproxy.org/
target: _blank
---
High-performance TCP/HTTP load balancer. Trusted by major platforms like GitHub, Reddit, and Stack Overflow. Excellent for high-throughput, low-latency scenarios.
::

::card
---
title: Traefik
icon: i-simple-icons-traefikproxy
to: https://traefik.io/traefik/
target: _blank
---
Cloud-native edge router. Auto-discovers services from Docker, Kubernetes, and other orchestrators. Automatic SSL via Let's Encrypt. Built for microservices.
::

::card
---
title: Envoy Proxy
icon: i-simple-icons-envoyproxy
to: https://www.envoyproxy.io/
target: _blank
---
Modern L7 proxy designed for cloud-native applications. Powers Istio service mesh. Advanced load balancing, circuit breaking, and observability built-in.
::

::card
---
title: Caddy
icon: i-simple-icons-github
to: https://caddyserver.com/
target: _blank
---
Modern web server with automatic HTTPS. Zero-config SSL via Let's Encrypt. Simple configuration syntax. Great for smaller deployments and development.
::

::card
---
title: ModSecurity
icon: i-simple-icons-github
to: https://github.com/owasp-modsecurity/ModSecurity
target: _blank
---
Open-source WAF engine. Works with Nginx, Apache, and IIS. OWASP Core Rule Set provides comprehensive protection against web attacks.
::

::card
---
title: Keepalived
icon: i-simple-icons-linux
to: https://www.keepalived.org/
target: _blank
---
High-availability framework using VRRP protocol. Provides automatic failover between load balancer instances with virtual IP management.
::

::card
---
title: Prometheus + Grafana
icon: i-simple-icons-prometheus
to: https://prometheus.io/
target: _blank
---
Industry-standard monitoring stack. Prometheus collects metrics, Grafana visualizes them. Essential for monitoring load balancer performance and health.
::

::card
---
title: wrk — HTTP Benchmarking
icon: i-simple-icons-github
to: https://github.com/wg/wrk
target: _blank
---
Modern HTTP benchmarking tool. Test your load balancer's throughput and latency under various concurrency levels. Essential for capacity planning.
::

::card
---
title: Certbot — Let's Encrypt
icon: i-simple-icons-letsencrypt
to: https://certbot.eff.org/
target: _blank
---
Free, automated SSL certificate management. Auto-renew certificates for your load balancer. Supports Nginx and Apache plugins for seamless integration.
::

::card
---
title: GoAccess — Log Analyzer
icon: i-simple-icons-github
to: https://goaccess.io/
target: _blank
---
Real-time web log analyzer. Provides visual dashboards for Nginx access logs. Monitor traffic patterns, response codes, and visitor statistics.
::

::card
---
title: OWASP CRS
icon: i-simple-icons-owasp
to: https://coreruleset.org/
target: _blank
---
OWASP Core Rule Set for ModSecurity. Provides generic attack detection rules for SQL Injection, XSS, LFI, RCE, and more. The industry standard WAF ruleset.
::

::

---

## Quick Reference

| Action                          | Command                                                                     |
| ------------------------------- | --------------------------------------------------------------------------- |
| Start all services              | `docker compose up -d`                                                      |
| Stop all services               | `docker compose down`                                                       |
| Test Nginx config               | `docker compose exec nginx-lb nginx -t`                                     |
| Reload Nginx (zero-downtime)    | `docker compose exec nginx-lb nginx -s reload`                              |
| Scale app to 5 instances        | `docker compose up -d --scale app=5`                                        |
| View load balancer logs         | `docker compose logs -f nginx-lb`                                           |
| Test load distribution          | `for i in {1..20}; do curl -s localhost \| jq .server; done \| sort \| uniq -c` |
| Check upstream health           | `curl -s http://localhost/health`                                           |
| Nginx status                    | `curl http://localhost:8080/nginx_status`                                   |
| Benchmark (wrk)                 | `wrk -t4 -c100 -d30s http://localhost/`                                     |
| Benchmark (ab)                  | `ab -n 10000 -c 100 http://localhost/`                                      |
| Check SSL cert                  | `openssl s_client -connect localhost:443 </dev/null 2>/dev/null`            |
| SSL test                        | `testssl.sh https://example.com`                                            |
| Watch logs in real-time         | `docker compose logs -f --tail 50`                                          |
| View resource usage             | `docker stats`                                                              |
| Generate SSL cert               | `certbot certonly --webroot -w /var/www/certbot -d example.com`              |
| Generate DH params              | `openssl dhparam -out dhparam.pem 4096`                                     |