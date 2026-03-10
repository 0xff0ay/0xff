---
title: Network Ports Reference
description: Complete reference guide for 25 commonly used network ports with Docker Compose configurations, use cases, and official documentation resources.
navigation:
  icon: i-lucide-network
  title: Ports Reference
---

A comprehensive guide to **25 essential network ports** used across databases, web servers, message queues, monitoring stacks, and infrastructure services. Each port includes Docker Compose configurations, usage details, and links to official documentation.

## Quick Reference

| Port | Service | Category | Protocol |
| ---- | ------- | -------- | -------- |
| `22` | OpenSSH | Infrastructure | TCP |
| `25` | Mailhog (SMTP) | Infrastructure | TCP |
| `53` | CoreDNS | Infrastructure | TCP/UDP |
| `80` | Nginx (HTTP) | Web Server | TCP |
| `443` | Nginx (HTTPS) | Web Server | TCP |
| `1433` | Microsoft SQL Server | Database | TCP |
| `2181` | Apache Zookeeper | Messaging | TCP |
| `3000` | Nuxt / Node.js | Web Application | TCP |
| `3100` | Grafana Loki | Monitoring | TCP |
| `3306` | MySQL / MariaDB | Database | TCP |
| `4222` | NATS | Messaging | TCP |
| `5000` | Docker Registry | Infrastructure | TCP |
| `5432` | PostgreSQL | Database | TCP |
| `5601` | Kibana | Monitoring | TCP |
| `5672` | RabbitMQ (AMQP) | Messaging | TCP |
| `6379` | Redis | Database | TCP |
| `8080` | Traefik | Web Server | TCP |
| `8086` | InfluxDB | Monitoring | TCP |
| `9000` | MinIO | Storage | TCP |
| `9042` | Apache Cassandra | Database | TCP |
| `9090` | Prometheus | Monitoring | TCP |
| `9092` | Apache Kafka | Messaging | TCP |
| `9200` | Elasticsearch | Monitoring | TCP |
| `15672` | RabbitMQ Management | Messaging | TCP |
| `27017` | MongoDB | Database | TCP |

---

## :icon{name="i-lucide-database"} Database Ports

### Port 5432 — PostgreSQL

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Database" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="SQL" color="green"}
  :badge{label="ACID" color="orange"}
  :badge{label="Open Source" color="purple"}
::

![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)

PostgreSQL is a powerful, open-source object-relational database system with over 35 years of active development. It runs on **port 5432** by default and supports advanced data types, full-text search, JSON/JSONB, and extensibility through custom functions and extensions.

PostgreSQL is widely used in production environments for its reliability, data integrity, and standards compliance. It supports MVCC (Multi-Version Concurrency Control), point-in-time recovery, tablespaces, and asynchronous replication.

::tip
PostgreSQL supports both **password** and **certificate-based** authentication. In production, always configure `pg_hba.conf` to restrict access by IP range and use SSL connections.
::

::code-collapse

```yaml [docker-compose.yml]
services:
  postgres:
    image: postgres:17-alpine
    container_name: postgres
    restart: unless-stopped
    ports:
      - "5432:5432"
    environment:
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: secretpassword
      POSTGRES_DB: myapp
      PGDATA: /var/lib/postgresql/data/pgdata
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U admin -d myapp"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - backend

volumes:
  postgres_data:
    driver: local

networks:
  backend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Official Documentation
  icon: i-lucide-book-open
  to: https://www.postgresql.org/docs/current/
  target: _blank
  ---
  Complete PostgreSQL reference documentation including SQL commands, configuration, and administration guides.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/_/postgres
  target: _blank
  ---
  Official PostgreSQL Docker image with Alpine and Debian variants.
  ::

  ::card
  ---
  title: PostgreSQL Wiki
  icon: i-lucide-globe
  to: https://wiki.postgresql.org/
  target: _blank
  ---
  Community-maintained wiki with tips, performance tuning, and best practices.
  ::
::

---

### Port 3306 — MySQL / MariaDB

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Database" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="SQL" color="green"}
  :badge{label="Relational" color="orange"}
  :badge{label="Open Source" color="purple"}
::

![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=mysql&logoColor=white) ![MariaDB](https://img.shields.io/badge/MariaDB-003545?style=for-the-badge&logo=mariadb&logoColor=white)

MySQL is the world's most popular open-source relational database, running on **port 3306** by default. MariaDB is a community-developed, commercially supported fork of MySQL that maintains protocol compatibility.

Both databases support InnoDB storage engine with ACID compliance, replication (master-slave and group replication), partitioning, and stored procedures. MySQL is widely used in LAMP stacks, WordPress installations, and enterprise applications.

::note
MariaDB uses the same default port `3306` and is wire-compatible with MySQL. You can use the same client libraries and connection strings for both.
::

::code-collapse

```yaml [docker-compose.yml]
services:
  mysql:
    image: mysql:8.4
    container_name: mysql
    restart: unless-stopped
    ports:
      - "3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: myapp
      MYSQL_USER: appuser
      MYSQL_PASSWORD: apppassword
    volumes:
      - mysql_data:/var/lib/mysql
      - ./my.cnf:/etc/mysql/conf.d/custom.cnf
    command: --default-authentication-plugin=caching_sha2_password
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - backend

  # Alternative: MariaDB
  # mariadb:
  #   image: mariadb:11
  #   container_name: mariadb
  #   restart: unless-stopped
  #   ports:
  #     - "3306:3306"
  #   environment:
  #     MARIADB_ROOT_PASSWORD: rootpassword
  #     MARIADB_DATABASE: myapp
  #     MARIADB_USER: appuser
  #     MARIADB_PASSWORD: apppassword
  #   volumes:
  #     - mariadb_data:/var/lib/mysql

volumes:
  mysql_data:
    driver: local

networks:
  backend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: MySQL Documentation
  icon: i-lucide-book-open
  to: https://dev.mysql.com/doc/
  target: _blank
  ---
  Official MySQL reference manual covering installation, SQL syntax, and administration.
  ::

  ::card
  ---
  title: MariaDB Documentation
  icon: i-lucide-book-open
  to: https://mariadb.com/kb/en/documentation/
  target: _blank
  ---
  MariaDB knowledge base with migration guides and compatibility notes.
  ::

  ::card
  ---
  title: Docker Hub — MySQL
  icon: i-simple-icons-docker
  to: https://hub.docker.com/_/mysql
  target: _blank
  ---
  Official MySQL Docker image maintained by the Docker community.
  ::
::

---

### Port 27017 — MongoDB

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Database" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="NoSQL" color="green"}
  :badge{label="Document Store" color="orange"}
  :badge{label="JSON/BSON" color="purple"}
::

![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)

MongoDB is a document-oriented NoSQL database that stores data in flexible, JSON-like BSON documents. Running on **port 27017** by default, MongoDB supports dynamic schemas, horizontal scaling through sharding, replica sets for high availability, and a rich query language with aggregation pipelines.

MongoDB excels in applications requiring flexible data models, rapid prototyping, content management systems, IoT data collection, and real-time analytics. It supports transactions (multi-document ACID since v4.0), change streams, and full-text search.

::warning
MongoDB's default installation does **not** require authentication. Always enable authentication and configure role-based access control (RBAC) before exposing to any network.
::

::code-collapse

```yaml [docker-compose.yml]
services:
  mongodb:
    image: mongo:7
    container_name: mongodb
    restart: unless-stopped
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: secretpassword
      MONGO_INITDB_DATABASE: myapp
    volumes:
      - mongodb_data:/data/db
      - mongodb_config:/data/configdb
      - ./mongo-init.js:/docker-entrypoint-initdb.d/mongo-init.js:ro
    command: mongod --auth --bind_ip_all
    healthcheck:
      test: echo 'db.runCommand("ping").ok' | mongosh --quiet
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - backend

  mongo-express:
    image: mongo-express:latest
    container_name: mongo-express
    restart: unless-stopped
    ports:
      - "8081:8081"
    environment:
      ME_CONFIG_MONGODB_ADMINUSERNAME: admin
      ME_CONFIG_MONGODB_ADMINPASSWORD: secretpassword
      ME_CONFIG_MONGODB_URL: mongodb://admin:secretpassword@mongodb:27017/
    depends_on:
      mongodb:
        condition: service_healthy
    networks:
      - backend

volumes:
  mongodb_data:
    driver: local
  mongodb_config:
    driver: local

networks:
  backend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: MongoDB Documentation
  icon: i-lucide-book-open
  to: https://www.mongodb.com/docs/manual/
  target: _blank
  ---
  Official MongoDB manual with CRUD operations, aggregation, indexing, and security guides.
  ::

  ::card
  ---
  title: MongoDB University
  icon: i-lucide-graduation-cap
  to: https://learn.mongodb.com/
  target: _blank
  ---
  Free courses and certifications for MongoDB developers and administrators.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/_/mongo
  target: _blank
  ---
  Official MongoDB Docker image with replica set and sharding support.
  ::
::

---

### Port 6379 — Redis

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Database" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="In-Memory" color="green"}
  :badge{label="Key-Value" color="orange"}
  :badge{label="Cache" color="red"}
  :badge{label="Pub/Sub" color="purple"}
::

![Redis](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)

Redis is an open-source, in-memory data structure store used as a database, cache, message broker, and streaming engine. Running on **port 6379**, Redis supports strings, hashes, lists, sets, sorted sets, bitmaps, HyperLogLogs, streams, and geospatial indexes.

Redis provides sub-millisecond response times and supports persistence (RDB snapshots and AOF logs), replication, Redis Sentinel for high availability, and Redis Cluster for automatic partitioning. It's commonly used for session storage, rate limiting, leaderboards, real-time analytics, and caching layers.

::tip
Redis 7.x introduced **Redis Functions** (replacing Lua scripting) and **ACL improvements**. Use `requirepass` and ACL rules to secure your Redis instance.
::

::code-collapse

```yaml [docker-compose.yml]
services:
  redis:
    image: redis:7-alpine
    container_name: redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    command: redis-server --requirepass secretpassword --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "secretpassword", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - backend

  redis-insight:
    image: redis/redisinsight:latest
    container_name: redis-insight
    restart: unless-stopped
    ports:
      - "5540:5540"
    depends_on:
      redis:
        condition: service_healthy
    networks:
      - backend

volumes:
  redis_data:
    driver: local

networks:
  backend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Redis Documentation
  icon: i-lucide-book-open
  to: https://redis.io/docs/
  target: _blank
  ---
  Official Redis documentation with command reference, data types, and administration guides.
  ::

  ::card
  ---
  title: Redis Commands
  icon: i-lucide-terminal
  to: https://redis.io/commands/
  target: _blank
  ---
  Complete reference of all Redis commands with examples and complexity analysis.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/_/redis
  target: _blank
  ---
  Official Redis Docker image with Alpine variant for minimal footprint.
  ::
::

---

### Port 1433 — Microsoft SQL Server

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Database" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="SQL" color="green"}
  :badge{label="Enterprise" color="orange"}
  :badge{label="Microsoft" color="purple"}
::

![MSSQL](https://img.shields.io/badge/SQL_Server-CC2927?style=for-the-badge&logo=microsoftsqlserver&logoColor=white)

Microsoft SQL Server is an enterprise-grade relational database management system running on **port 1433**. It provides advanced features like columnstore indexes, in-memory OLTP, Always On availability groups, transparent data encryption, and comprehensive business intelligence capabilities.

The Linux-compatible Docker image (`mssql/server`) runs SQL Server Developer or Express editions, making it accessible for development and testing without Windows infrastructure.

::note
SQL Server Developer Edition is **free** for development and testing. For production workloads, Standard or Enterprise licenses are required. The Express edition is free with limitations (10 GB database size, 1 GB RAM).
::

::code-collapse

```yaml [docker-compose.yml]
services:
  mssql:
    image: mcr.microsoft.com/mssql/server:2022-latest
    container_name: mssql
    restart: unless-stopped
    ports:
      - "1433:1433"
    environment:
      ACCEPT_EULA: "Y"
      MSSQL_SA_PASSWORD: "YourStrong@Password123"
      MSSQL_PID: Developer
      MSSQL_COLLATION: SQL_Latin1_General_CP1_CI_AS
    volumes:
      - mssql_data:/var/opt/mssql
    healthcheck:
      test: /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "YourStrong@Password123" -Q "SELECT 1" -C -b
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - backend

volumes:
  mssql_data:
    driver: local

networks:
  backend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: SQL Server Documentation
  icon: i-lucide-book-open
  to: https://learn.microsoft.com/en-us/sql/sql-server/
  target: _blank
  ---
  Microsoft's official SQL Server documentation and tutorials.
  ::

  ::card
  ---
  title: Container Registry
  icon: i-simple-icons-docker
  to: https://mcr.microsoft.com/en-us/artifact/mar/mssql/server
  target: _blank
  ---
  Official SQL Server container image from Microsoft Container Registry.
  ::
::

---

### Port 9042 — Apache Cassandra

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Database" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="NoSQL" color="green"}
  :badge{label="Wide Column" color="orange"}
  :badge{label="Distributed" color="red"}
  :badge{label="Apache" color="purple"}
::

![Cassandra](https://img.shields.io/badge/Cassandra-1287B1?style=for-the-badge&logo=apachecassandra&logoColor=white)

Apache Cassandra is a distributed, wide-column NoSQL database designed for handling large amounts of data across many commodity servers with no single point of failure. The **CQL native transport** runs on **port 9042**, while the legacy Thrift interface uses port 9160.

Cassandra provides linear scalability, tunable consistency levels, masterless architecture, and is optimized for write-heavy workloads. It's used by companies like Netflix, Apple, and Discord for time-series data, messaging systems, and IoT applications.

::warning
Cassandra requires careful data modeling based on **query patterns** rather than relationships. Design your tables around the queries you need to perform — denormalization is expected and encouraged.
::

::code-collapse

```yaml [docker-compose.yml]
services:
  cassandra:
    image: cassandra:5
    container_name: cassandra
    restart: unless-stopped
    ports:
      - "9042:9042"
      - "7000:7000"   # Inter-node cluster communication
    environment:
      CASSANDRA_CLUSTER_NAME: MyCluster
      CASSANDRA_DC: dc1
      CASSANDRA_RACK: rack1
      CASSANDRA_ENDPOINT_SNITCH: GossipingPropertyFileSnitch
      MAX_HEAP_SIZE: 512M
      HEAP_NEWSIZE: 100M
    volumes:
      - cassandra_data:/var/lib/cassandra
    healthcheck:
      test: ["CMD-SHELL", "cqlsh -e 'describe cluster'"]
      interval: 30s
      timeout: 10s
      retries: 10
    networks:
      - backend

volumes:
  cassandra_data:
    driver: local

networks:
  backend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Cassandra Documentation
  icon: i-lucide-book-open
  to: https://cassandra.apache.org/doc/latest/
  target: _blank
  ---
  Official Apache Cassandra documentation with CQL reference and architecture overview.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/_/cassandra
  target: _blank
  ---
  Official Apache Cassandra Docker image.
  ::
::

---

## :icon{name="i-lucide-globe"} Web & Application Ports

### Port 80 — Nginx (HTTP)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Web Server" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="HTTP" color="green"}
  :badge{label="Reverse Proxy" color="orange"}
  :badge{label="Load Balancer" color="red"}
::

![Nginx](https://img.shields.io/badge/Nginx-009639?style=for-the-badge&logo=nginx&logoColor=white)

Nginx is a high-performance HTTP server, reverse proxy, and load balancer running on **port 80** for HTTP traffic. Known for its low memory footprint, high concurrency handling (event-driven architecture), and stability, Nginx powers over 30% of all websites globally.

Nginx is commonly used as a reverse proxy in front of application servers (Node.js, Python, PHP), static file server, API gateway, and SSL termination point. It supports WebSocket proxying, gzip compression, rate limiting, and caching.

::code-collapse

```yaml [docker-compose.yml]
services:
  nginx:
    image: nginx:alpine
    container_name: nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./conf.d:/etc/nginx/conf.d:ro
      - ./html:/usr/share/nginx/html:ro
      - ./certs:/etc/nginx/certs:ro
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
      interval: 10s
      timeout: 5s
      retries: 3
    networks:
      - frontend

networks:
  frontend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Nginx Documentation
  icon: i-lucide-book-open
  to: https://nginx.org/en/docs/
  target: _blank
  ---
  Official Nginx documentation with directive reference and configuration examples.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/_/nginx
  target: _blank
  ---
  Official Nginx Docker image with Alpine and Debian variants.
  ::
::

---

### Port 443 — HTTPS (SSL/TLS)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Web Server" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="HTTPS" color="green"}
  :badge{label="SSL/TLS" color="orange"}
  :badge{label="Encrypted" color="red"}
::

![HTTPS](https://img.shields.io/badge/HTTPS-009639?style=for-the-badge&logo=letsencrypt&logoColor=white)

Port **443** is the standard port for HTTPS (HTTP Secure) traffic, encrypting communication between clients and servers using SSL/TLS protocols. All modern web applications should serve traffic over HTTPS to protect data integrity, confidentiality, and authentication.

In Docker environments, HTTPS termination is typically handled by a reverse proxy (Nginx, Traefik, Caddy) that manages SSL certificates. Let's Encrypt provides free, automated SSL certificates that can be auto-renewed.

::tip
Use **Certbot** or **acme.sh** with Let's Encrypt for automatic SSL certificate management. Traefik and Caddy handle this automatically with zero configuration.
::

::code-collapse

```yaml [docker-compose.yml]
services:
  nginx-ssl:
    image: nginx:alpine
    container_name: nginx-ssl
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
      - certbot_www:/var/www/certbot:ro
    networks:
      - frontend

  certbot:
    image: certbot/certbot:latest
    container_name: certbot
    volumes:
      - ./certs:/etc/letsencrypt
      - certbot_www:/var/www/certbot
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait $${!}; done;'"
    depends_on:
      - nginx-ssl

volumes:
  certbot_www:
    driver: local

networks:
  frontend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Let's Encrypt
  icon: i-lucide-shield-check
  to: https://letsencrypt.org/docs/
  target: _blank
  ---
  Free, automated SSL certificates for securing your web applications.
  ::

  ::card
  ---
  title: Mozilla SSL Configuration
  icon: i-lucide-lock
  to: https://ssl-config.mozilla.org/
  target: _blank
  ---
  Generate secure SSL configurations for Nginx, Apache, and other servers.
  ::
::

---

### Port 3000 — Nuxt / Node.js

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Application" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="JavaScript" color="green"}
  :badge{label="SSR" color="orange"}
  :badge{label="Full Stack" color="purple"}
::

![Nuxt](https://img.shields.io/badge/Nuxt-00DC82?style=for-the-badge&logo=nuxtdotjs&logoColor=white) ![Node.js](https://img.shields.io/badge/Node.js-5FA04E?style=for-the-badge&logo=nodedotjs&logoColor=white)

Port **3000** is the default development port for **Nuxt.js**, **Node.js** applications, and many JavaScript frameworks. Nuxt is a full-stack Vue.js framework providing server-side rendering (SSR), static site generation (SSG), hybrid rendering, and API routes.

In production, Node.js applications on port 3000 are typically placed behind a reverse proxy (Nginx, Traefik) that handles SSL termination, load balancing, and static asset serving.

::note
Port 3000 is also the default for **Grafana**, **React (Create React App)**, and **Ruby on Rails**. When running multiple services, remap ports to avoid conflicts.
::

::code-collapse

```yaml [docker-compose.yml]
services:
  nuxt-app:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: nuxt-app
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      NUXT_PUBLIC_API_BASE: https://api.example.com
      NITRO_PORT: 3000
      NITRO_HOST: 0.0.0.0
      DATABASE_URL: postgresql://admin:password@postgres:5432/myapp
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/health"]
      interval: 15s
      timeout: 5s
      retries: 3
    networks:
      - frontend
      - backend

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Nuxt Documentation
  icon: i-simple-icons-nuxtdotjs
  to: https://nuxt.com/docs
  target: _blank
  ---
  Official Nuxt documentation for building full-stack Vue applications.
  ::

  ::card
  ---
  title: Node.js Documentation
  icon: i-simple-icons-nodedotjs
  to: https://nodejs.org/docs/latest/api/
  target: _blank
  ---
  Node.js API reference documentation.
  ::

  ::card
  ---
  title: Nuxt UI
  icon: i-lucide-palette
  to: https://ui.nuxt.com/
  target: _blank
  ---
  Beautiful UI components for building Nuxt applications.
  ::
::

---

### Port 8080 — Traefik

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Reverse Proxy" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="Load Balancer" color="green"}
  :badge{label="Auto Discovery" color="orange"}
  :badge{label="Let's Encrypt" color="red"}
  :badge{label="Cloud Native" color="purple"}
::

![Traefik](https://img.shields.io/badge/Traefik-24A1C1?style=for-the-badge&logo=traefikproxy&logoColor=white)

Traefik is a modern, cloud-native reverse proxy and load balancer that uses **port 8080** for its dashboard and API. It automatically discovers services through Docker labels, Kubernetes ingress, and other providers — eliminating the need for manual configuration file management.

Traefik supports automatic HTTPS via Let's Encrypt, middleware chains (rate limiting, authentication, headers), TCP/UDP routing, canary deployments, and real-time metrics. The dashboard on port 8080 provides visibility into routers, services, and middlewares.

::warning
The Traefik dashboard on port `8080` should **never** be exposed publicly without authentication. Use BasicAuth middleware or restrict access to internal networks only.
::

::code-collapse

```yaml [docker-compose.yml]
services:
  traefik:
    image: traefik:v3.0
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"    # Dashboard
    command:
      - "--api.dashboard=true"
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - letsencrypt:/letsencrypt
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.dashboard.rule=Host(`traefik.localhost`)"
      - "traefik.http.routers.dashboard.service=api@internal"
    networks:
      - proxy

  # Example application behind Traefik
  app:
    image: nginx:alpine
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`app.localhost`)"
      - "traefik.http.routers.app.entrypoints=web"
    networks:
      - proxy

volumes:
  letsencrypt:
    driver: local

networks:
  proxy:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Traefik Documentation
  icon: i-lucide-book-open
  to: https://doc.traefik.io/traefik/
  target: _blank
  ---
  Official Traefik documentation with Docker, Kubernetes, and file provider guides.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/_/traefik
  target: _blank
  ---
  Official Traefik Docker image.
  ::
::

---

## :icon{name="i-lucide-mail"} Messaging & Streaming Ports

### Port 5672 — RabbitMQ (AMQP)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Message Broker" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="AMQP" color="green"}
  :badge{label="Queue" color="orange"}
  :badge{label="Pub/Sub" color="red"}
  :badge{label="Erlang" color="purple"}
::

![RabbitMQ](https://img.shields.io/badge/RabbitMQ-FF6600?style=for-the-badge&logo=rabbitmq&logoColor=white)

RabbitMQ is the most widely deployed open-source message broker, using **port 5672** for the AMQP 0-9-1 protocol. It supports multiple messaging protocols (AMQP, STOMP, MQTT), message routing through exchanges (direct, topic, fanout, headers), persistent queues, dead-letter exchanges, and priority queues.

RabbitMQ is ideal for decoupling microservices, task queues, event-driven architectures, and workload distribution. It provides reliable delivery guarantees with publisher confirms and consumer acknowledgments.

### Port 15672 — RabbitMQ Management

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Management UI" color="neutral"}
  :badge{label="HTTP" color="blue"}
  :badge{label="Dashboard" color="green"}
  :badge{label="REST API" color="orange"}
::

Port **15672** serves the RabbitMQ Management Plugin, providing a web-based UI and HTTP API for monitoring queues, exchanges, connections, channels, and cluster status. The management API enables programmatic administration and monitoring integration.

::code-collapse

```yaml [docker-compose.yml]
services:
  rabbitmq:
    image: rabbitmq:3-management-alpine
    container_name: rabbitmq
    restart: unless-stopped
    ports:
      - "5672:5672"     # AMQP
      - "15672:15672"   # Management UI
    environment:
      RABBITMQ_DEFAULT_USER: admin
      RABBITMQ_DEFAULT_PASS: secretpassword
      RABBITMQ_DEFAULT_VHOST: /
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq
      - ./rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf:ro
    healthcheck:
      test: rabbitmq-diagnostics -q ping
      interval: 15s
      timeout: 10s
      retries: 5
    networks:
      - backend

volumes:
  rabbitmq_data:
    driver: local

networks:
  backend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: RabbitMQ Documentation
  icon: i-lucide-book-open
  to: https://www.rabbitmq.com/docs
  target: _blank
  ---
  Official RabbitMQ documentation with tutorials, clustering, and plugin guides.
  ::

  ::card
  ---
  title: RabbitMQ Tutorials
  icon: i-lucide-graduation-cap
  to: https://www.rabbitmq.com/tutorials
  target: _blank
  ---
  Step-by-step messaging pattern tutorials in multiple languages.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/_/rabbitmq
  target: _blank
  ---
  Official RabbitMQ Docker image with management plugin variant.
  ::
::

---

### Port 9092 — Apache Kafka

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Streaming" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="Event Streaming" color="green"}
  :badge{label="Distributed Log" color="orange"}
  :badge{label="High Throughput" color="red"}
  :badge{label="Apache" color="purple"}
::

![Kafka](https://img.shields.io/badge/Apache_Kafka-231F20?style=for-the-badge&logo=apachekafka&logoColor=white)

Apache Kafka is a distributed event streaming platform running on **port 9092**. It provides high-throughput, low-latency, fault-tolerant messaging with persistent storage. Kafka organizes data into topics with configurable partitions and replication factors.

Kafka is used for real-time data pipelines, event sourcing, log aggregation, stream processing (with Kafka Streams or ksqlDB), and as a backbone for microservice communication. It handles millions of messages per second with ordered, exactly-once delivery semantics.

### Port 2181 — Apache Zookeeper

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Coordination" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="Consensus" color="green"}
  :badge{label="Apache" color="purple"}
::

![Zookeeper](https://img.shields.io/badge/Zookeeper-D22128?style=for-the-badge&logo=apache&logoColor=white)

Apache Zookeeper runs on **port 2181** and provides distributed coordination services including configuration management, naming, synchronization, and group services. Kafka traditionally uses Zookeeper for broker metadata and leader election.

::note
**KRaft mode** (Kafka Raft) removes the Zookeeper dependency starting with Kafka 3.3+. New deployments should consider using KRaft mode for simplified architecture.
::

::code-collapse

```yaml [docker-compose.yml]
services:
  # KRaft mode (no Zookeeper)
  kafka:
    image: apache/kafka:3.8.0
    container_name: kafka
    restart: unless-stopped
    ports:
      - "9092:9092"
    environment:
      KAFKA_NODE_ID: 1
      KAFKA_PROCESS_ROLES: broker,controller
      KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_CONTROLLER_LISTENER_NAMES: CONTROLLER
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
      KAFKA_CONTROLLER_QUORUM_VOTERS: 1@kafka:9093
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_LOG_DIRS: /var/lib/kafka/data
      CLUSTER_ID: "MkU3OEVBNTcwNTJENDM2Qk"
    volumes:
      - kafka_data:/var/lib/kafka/data
    healthcheck:
      test: /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092
      interval: 15s
      timeout: 10s
      retries: 5
    networks:
      - backend

  # Traditional mode with Zookeeper (legacy)
  # zookeeper:
  #   image: confluentinc/cp-zookeeper:7.6.0
  #   container_name: zookeeper
  #   ports:
  #     - "2181:2181"
  #   environment:
  #     ZOOKEEPER_CLIENT_PORT: 2181
  #     ZOOKEEPER_TICK_TIME: 2000
  #   volumes:
  #     - zookeeper_data:/var/lib/zookeeper/data

  kafka-ui:
    image: provectuslabs/kafka-ui:latest
    container_name: kafka-ui
    restart: unless-stopped
    ports:
      - "8090:8080"
    environment:
      KAFKA_CLUSTERS_0_NAME: local
      KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS: kafka:9092
    depends_on:
      kafka:
        condition: service_healthy
    networks:
      - backend

volumes:
  kafka_data:
    driver: local

networks:
  backend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Kafka Documentation
  icon: i-lucide-book-open
  to: https://kafka.apache.org/documentation/
  target: _blank
  ---
  Official Apache Kafka documentation with quickstart, configuration, and API reference.
  ::

  ::card
  ---
  title: Confluent Docs
  icon: i-lucide-layers
  to: https://docs.confluent.io/platform/current/overview.html
  target: _blank
  ---
  Confluent Platform documentation with Kafka ecosystem tools and connectors.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/r/apache/kafka
  target: _blank
  ---
  Official Apache Kafka Docker image with KRaft support.
  ::
::

---

### Port 4222 — NATS

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Messaging" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="Pub/Sub" color="green"}
  :badge{label="Request/Reply" color="orange"}
  :badge{label="Cloud Native" color="red"}
  :badge{label="Go" color="purple"}
::

![NATS](https://img.shields.io/badge/NATS-27AAE1?style=for-the-badge&logo=natsdotio&logoColor=white)

NATS is a lightweight, high-performance messaging system running on **port 4222**. Written in Go, NATS provides at-most-once (core NATS) and at-least-once/exactly-once (JetStream) delivery. It supports publish/subscribe, request/reply, and queue groups for load balancing.

NATS excels in cloud-native environments with its small footprint (~15MB), zero-configuration clustering via gossip protocol, multi-tenancy through accounts, and leaf node connections for edge computing. JetStream adds persistence, stream processing, and key-value storage.

::code-collapse

```yaml [docker-compose.yml]
services:
  nats:
    image: nats:2-alpine
    container_name: nats
    restart: unless-stopped
    ports:
      - "4222:4222"     # Client connections
      - "6222:6222"     # Cluster routing
      - "8222:8222"     # HTTP monitoring
    command: "--jetstream --store_dir /data --http_port 8222 --name nats-server"
    volumes:
      - nats_data:/data
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:8222/healthz"]
      interval: 10s
      timeout: 5s
      retries: 3
    networks:
      - backend

volumes:
  nats_data:
    driver: local

networks:
  backend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: NATS Documentation
  icon: i-lucide-book-open
  to: https://docs.nats.io/
  target: _blank
  ---
  Official NATS documentation with JetStream, security, and clustering guides.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/_/nats
  target: _blank
  ---
  Official NATS Docker image with Alpine variant.
  ::
::

---

## :icon{name="i-lucide-activity"} Monitoring & Observability Ports

### Port 9090 — Prometheus

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Monitoring" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="Metrics" color="green"}
  :badge{label="Time Series" color="orange"}
  :badge{label="Pull-based" color="red"}
  :badge{label="CNCF" color="purple"}
::

![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?style=for-the-badge&logo=prometheus&logoColor=white)

Prometheus is an open-source monitoring and alerting toolkit running on **port 9090**. It uses a pull-based model to scrape metrics from instrumented targets, stores time-series data with a powerful query language (PromQL), and provides built-in alerting via Alertmanager.

Prometheus is the de-facto standard for cloud-native monitoring, a graduated CNCF project, and integrates seamlessly with Grafana for visualization. It supports service discovery (Kubernetes, Docker, DNS), recording rules, and federated queries.

::code-collapse

```yaml [docker-compose.yml]
services:
  prometheus:
    image: prom/prometheus:v2.53.0
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus"
      - "--storage.tsdb.retention.time=30d"
      - "--web.enable-lifecycle"
      - "--web.enable-admin-api"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./alert.rules.yml:/etc/prometheus/alert.rules.yml:ro
      - prometheus_data:/prometheus
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:9090/-/healthy"]
      interval: 10s
      timeout: 5s
      retries: 3
    networks:
      - monitoring

volumes:
  prometheus_data:
    driver: local

networks:
  monitoring:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Prometheus Documentation
  icon: i-lucide-book-open
  to: https://prometheus.io/docs/
  target: _blank
  ---
  Official Prometheus documentation with PromQL reference and configuration guides.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/r/prom/prometheus
  target: _blank
  ---
  Official Prometheus Docker image.
  ::
::

---

### Port 9200 — Elasticsearch

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Search Engine" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="Full-Text Search" color="green"}
  :badge{label="RESTful" color="orange"}
  :badge{label="Distributed" color="red"}
  :badge{label="Elastic" color="purple"}
::

![Elasticsearch](https://img.shields.io/badge/Elasticsearch-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)

Elasticsearch is a distributed, RESTful search and analytics engine running on **port 9200** (HTTP) and **port 9300** (transport/inter-node). Built on Apache Lucene, it provides near-real-time full-text search, structured queries, analytics, and aggregations across large datasets.

Elasticsearch is the core of the ELK/Elastic Stack (Elasticsearch, Logstash, Kibana) and is widely used for log analysis, application search, security analytics (SIEM), and observability.

::caution
Elasticsearch requires significant memory. Set `ES_JAVA_OPTS` appropriately and never run with less than **2GB heap** in production. Disable swap to prevent JVM garbage collection pauses.
::

::code-collapse

```yaml [docker-compose.yml]
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.14.0
    container_name: elasticsearch
    restart: unless-stopped
    ports:
      - "9200:9200"
      - "9300:9300"
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - xpack.security.enrollment.enabled=false
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
      - cluster.name=docker-cluster
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    healthcheck:
      test: curl -f http://localhost:9200/_cluster/health || exit 1
      interval: 15s
      timeout: 10s
      retries: 5
    ulimits:
      memlock:
        soft: -1
        hard: -1
    networks:
      - monitoring

volumes:
  elasticsearch_data:
    driver: local

networks:
  monitoring:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Elasticsearch Documentation
  icon: i-lucide-book-open
  to: https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html
  target: _blank
  ---
  Official Elasticsearch reference with REST API, query DSL, and cluster management.
  ::

  ::card
  ---
  title: Elastic Docker Hub
  icon: i-simple-icons-docker
  to: https://www.docker.elastic.co/
  target: _blank
  ---
  Elastic's official Docker image registry.
  ::
::

---

### Port 5601 — Kibana

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Visualization" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="Dashboard" color="green"}
  :badge{label="Analytics" color="orange"}
  :badge{label="Elastic" color="purple"}
::

![Kibana](https://img.shields.io/badge/Kibana-005571?style=for-the-badge&logo=kibana&logoColor=white)

Kibana is the visualization and exploration tool for Elasticsearch data, running on **port 5601**. It provides interactive dashboards, Lens (drag-and-drop visualization), Discover (log exploration), Maps, Canvas, and machine learning anomaly detection UIs.

Kibana is essential for log analysis workflows, infrastructure monitoring, APM (Application Performance Monitoring), and security analytics (SIEM) within the Elastic Stack.

::code-collapse

```yaml [docker-compose.yml]
services:
  kibana:
    image: docker.elastic.co/kibana/kibana:8.14.0
    container_name: kibana
    restart: unless-stopped
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - XPACK_SECURITY_ENABLED=false
    depends_on:
      elasticsearch:
        condition: service_healthy
    healthcheck:
      test: curl -f http://localhost:5601/api/status || exit 1
      interval: 15s
      timeout: 10s
      retries: 5
    networks:
      - monitoring

networks:
  monitoring:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Kibana Documentation
  icon: i-lucide-book-open
  to: https://www.elastic.co/guide/en/kibana/current/index.html
  target: _blank
  ---
  Official Kibana guide with dashboard creation, Lens, and Discover tutorials.
  ::

  ::card
  ---
  title: Docker Image
  icon: i-simple-icons-docker
  to: https://www.docker.elastic.co/r/kibana
  target: _blank
  ---
  Official Kibana Docker image from Elastic's container registry.
  ::
::

---

### Port 3100 — Grafana Loki

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Logging" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="Log Aggregation" color="green"}
  :badge{label="Label-based" color="orange"}
  :badge{label="Grafana" color="red"}
  :badge{label="CNCF" color="purple"}
::

![Loki](https://img.shields.io/badge/Grafana_Loki-F46800?style=for-the-badge&logo=grafana&logoColor=white)

Grafana Loki is a horizontally scalable, highly available log aggregation system running on **port 3100**. Inspired by Prometheus, Loki indexes only metadata (labels) rather than full log content, making it significantly cheaper to operate than Elasticsearch-based logging.

Loki integrates natively with Grafana for visualization and uses LogQL (similar to PromQL) for querying. It pairs with Promtail, Alloy, or Fluentd as log collection agents.

::code-collapse

```yaml [docker-compose.yml]
services:
  loki:
    image: grafana/loki:3.1.0
    container_name: loki
    restart: unless-stopped
    ports:
      - "3100:3100"
    command: -config.file=/etc/loki/local-config.yaml
    volumes:
      - loki_data:/loki
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:3100/ready"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - monitoring

  promtail:
    image: grafana/promtail:3.1.0
    container_name: promtail
    restart: unless-stopped
    volumes:
      - /var/log:/var/log:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./promtail-config.yml:/etc/promtail/config.yml:ro
    command: -config.file=/etc/promtail/config.yml
    depends_on:
      - loki
    networks:
      - monitoring

volumes:
  loki_data:
    driver: local

networks:
  monitoring:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Loki Documentation
  icon: i-lucide-book-open
  to: https://grafana.com/docs/loki/latest/
  target: _blank
  ---
  Official Grafana Loki documentation with LogQL reference and deployment guides.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/r/grafana/loki
  target: _blank
  ---
  Official Grafana Loki Docker image.
  ::
::

---

### Port 8086 — InfluxDB

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Time Series DB" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="Metrics" color="green"}
  :badge{label="IoT" color="orange"}
  :badge{label="Flux/SQL" color="red"}
::

![InfluxDB](https://img.shields.io/badge/InfluxDB-22ADF6?style=for-the-badge&logo=influxdb&logoColor=white)

InfluxDB is a purpose-built time-series database running on **port 8086**. It provides high-performance ingestion and querying of time-stamped data using Flux query language (v2) or SQL (v3). InfluxDB is optimized for IoT sensor data, application metrics, real-time analytics, and DevOps monitoring.

InfluxDB v2 includes a built-in UI, task engine for scheduled queries, alerting/notifications, and Telegraf integration for data collection from hundreds of sources.

::code-collapse

```yaml [docker-compose.yml]
services:
  influxdb:
    image: influxdb:2.7-alpine
    container_name: influxdb
    restart: unless-stopped
    ports:
      - "8086:8086"
    environment:
      DOCKER_INFLUXDB_INIT_MODE: setup
      DOCKER_INFLUXDB_INIT_USERNAME: admin
      DOCKER_INFLUXDB_INIT_PASSWORD: secretpassword
      DOCKER_INFLUXDB_INIT_ORG: myorg
      DOCKER_INFLUXDB_INIT_BUCKET: mybucket
      DOCKER_INFLUXDB_INIT_ADMIN_TOKEN: my-super-secret-auth-token
    volumes:
      - influxdb_data:/var/lib/influxdb2
      - influxdb_config:/etc/influxdb2
    healthcheck:
      test: ["CMD", "influx", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - monitoring

volumes:
  influxdb_data:
    driver: local
  influxdb_config:
    driver: local

networks:
  monitoring:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: InfluxDB Documentation
  icon: i-lucide-book-open
  to: https://docs.influxdata.com/influxdb/v2/
  target: _blank
  ---
  Official InfluxDB v2 documentation with Flux query language reference.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/_/influxdb
  target: _blank
  ---
  Official InfluxDB Docker image with Alpine variant.
  ::
::

---

## :icon{name="i-lucide-server"} Infrastructure Ports

### Port 22 — OpenSSH

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Infrastructure" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="SSH" color="green"}
  :badge{label="Encrypted" color="orange"}
  :badge{label="Remote Access" color="red"}
::

![SSH](https://img.shields.io/badge/OpenSSH-000000?style=for-the-badge&logo=openssh&logoColor=white)

Port **22** is the standard port for **SSH (Secure Shell)** protocol, providing encrypted remote login, command execution, file transfer (SCP/SFTP), and port forwarding. OpenSSH is the most widely used SSH implementation and is included in virtually all Linux distributions.

SSH supports key-based authentication (recommended over passwords), agent forwarding, ProxyJump for bastion hosts, X11 forwarding, and dynamic port forwarding (SOCKS proxy). In containerized environments, SSH is typically used for accessing host machines rather than individual containers.

::caution
**Never expose SSH port 22 directly to the internet** without:
- Disabling password authentication (`PasswordAuthentication no`)
- Using key-based authentication only
- Implementing fail2ban or similar brute-force protection
- Consider changing the default port for obscurity
::

::code-collapse

```yaml [docker-compose.yml]
# SSH is rarely containerized, but useful for bastion/jump hosts
services:
  ssh-bastion:
    image: linuxserver/openssh-server:latest
    container_name: ssh-bastion
    restart: unless-stopped
    ports:
      - "2222:2222"
    environment:
      PUID: 1000
      PGID: 1000
      TZ: UTC
      PUBLIC_KEY_FILE: /config/.ssh/authorized_keys
      SUDO_ACCESS: "false"
      PASSWORD_ACCESS: "false"
      USER_NAME: devops
    volumes:
      - ./ssh_keys:/config/.ssh:ro
      - ssh_config:/config
    networks:
      - infrastructure

volumes:
  ssh_config:
    driver: local

networks:
  infrastructure:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: OpenSSH Documentation
  icon: i-lucide-book-open
  to: https://www.openssh.com/manual.html
  target: _blank
  ---
  Official OpenSSH manual pages and configuration reference.
  ::

  ::card
  ---
  title: SSH Hardening Guide
  icon: i-lucide-shield-check
  to: https://www.ssh-audit.com/hardening_guides.html
  target: _blank
  ---
  Best practices for hardening SSH server configuration.
  ::
::

---

### Port 25 — SMTP / Mailhog

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Email" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="SMTP" color="green"}
  :badge{label="Development" color="orange"}
  :badge{label="Testing" color="purple"}
::

![SMTP](https://img.shields.io/badge/SMTP-EA4335?style=for-the-badge&logo=gmail&logoColor=white)

Port **25** is the standard SMTP (Simple Mail Transfer Protocol) port for email transmission. In development environments, **Mailhog** or **Mailpit** captures outgoing emails for testing without actually delivering them, providing a web UI to inspect messages.

::tip
For development, use **Mailpit** (modern, actively maintained successor to Mailhog) which listens on port `1025` for SMTP and port `8025` for the web UI.
::

::code-collapse

```yaml [docker-compose.yml]
services:
  mailpit:
    image: axllent/mailpit:latest
    container_name: mailpit
    restart: unless-stopped
    ports:
      - "1025:1025"   # SMTP
      - "8025:8025"   # Web UI
    environment:
      MP_MAX_MESSAGES: 5000
      MP_SMTP_AUTH_ACCEPT_ANY: 1
      MP_SMTP_AUTH_ALLOW_INSECURE: 1
    volumes:
      - mailpit_data:/data
    networks:
      - backend

volumes:
  mailpit_data:
    driver: local

networks:
  backend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Mailpit GitHub
  icon: i-simple-icons-github
  to: https://github.com/axllent/mailpit
  target: _blank
  ---
  Mailpit — email and SMTP testing tool with API.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/r/axllent/mailpit
  target: _blank
  ---
  Official Mailpit Docker image.
  ::
::

---

### Port 53 — CoreDNS

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="DNS" color="neutral"}
  :badge{label="TCP/UDP" color="blue"}
  :badge{label="Name Resolution" color="green"}
  :badge{label="CNCF" color="orange"}
  :badge{label="Kubernetes" color="purple"}
::

![DNS](https://img.shields.io/badge/CoreDNS-1F3B4D?style=for-the-badge&logo=coredns&logoColor=white)

Port **53** is the standard port for DNS (Domain Name System) services using both TCP and UDP. **CoreDNS** is a flexible, extensible DNS server written in Go and a graduated CNCF project. It's the default DNS server in Kubernetes clusters.

CoreDNS uses a plugin-based architecture supporting service discovery, caching, forwarding, load balancing, DNSSEC, and custom record management through a simple Corefile configuration.

::code-collapse

```yaml [docker-compose.yml]
services:
  coredns:
    image: coredns/coredns:1.11
    container_name: coredns
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "53:53/tcp"
    volumes:
      - ./Corefile:/root/Corefile:ro
      - ./zones:/root/zones:ro
    command: -conf /root/Corefile
    networks:
      - infrastructure

networks:
  infrastructure:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: CoreDNS Documentation
  icon: i-lucide-book-open
  to: https://coredns.io/manual/toc/
  target: _blank
  ---
  Official CoreDNS manual with plugin reference and configuration examples.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/r/coredns/coredns
  target: _blank
  ---
  Official CoreDNS Docker image.
  ::
::

---

### Port 9000 — MinIO

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Object Storage" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="S3 Compatible" color="green"}
  :badge{label="High Performance" color="orange"}
  :badge{label="Cloud Native" color="red"}
  :badge{label="Open Source" color="purple"}
::

![MinIO](https://img.shields.io/badge/MinIO-C72E49?style=for-the-badge&logo=minio&logoColor=white)

MinIO is a high-performance, S3-compatible object storage system running on **port 9000** (API) and **port 9001** (console). It provides a drop-in replacement for Amazon S3, supporting bucket operations, multipart uploads, versioning, lifecycle policies, and server-side encryption.

MinIO is ideal for storing unstructured data (images, videos, backups, logs) and can operate in standalone or distributed mode with erasure coding for data protection.

::code-collapse

```yaml [docker-compose.yml]
services:
  minio:
    image: minio/minio:latest
    container_name: minio
    restart: unless-stopped
    ports:
      - "9000:9000"    # S3 API
      - "9001:9001"    # Console UI
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: admin
      MINIO_ROOT_PASSWORD: secretpassword
      MINIO_BROWSER_REDIRECT_URL: http://localhost:9001
    volumes:
      - minio_data:/data
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - backend

  # MinIO Client for bucket initialization
  minio-init:
    image: minio/mc:latest
    container_name: minio-init
    depends_on:
      minio:
        condition: service_healthy
    entrypoint: >
      /bin/sh -c "
      mc alias set myminio http://minio:9000 admin secretpassword;
      mc mb myminio/uploads --ignore-existing;
      mc mb myminio/backups --ignore-existing;
      mc anonymous set download myminio/uploads;
      exit 0;
      "
    networks:
      - backend

volumes:
  minio_data:
    driver: local

networks:
  backend:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: MinIO Documentation
  icon: i-lucide-book-open
  to: https://min.io/docs/minio/container/index.html
  target: _blank
  ---
  Official MinIO documentation for container deployments with S3 API reference.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/r/minio/minio
  target: _blank
  ---
  Official MinIO Docker image.
  ::

  ::card
  ---
  title: S3 API Compatibility
  icon: i-lucide-plug
  to: https://min.io/docs/minio/linux/reference/s3-api-compatibility.html
  target: _blank
  ---
  S3 API compatibility reference for MinIO operations.
  ::
::

---

### Port 5000 — Docker Registry

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Container Registry" color="neutral"}
  :badge{label="TCP" color="blue"}
  :badge{label="Docker" color="green"}
  :badge{label="OCI" color="orange"}
  :badge{label="Private" color="purple"}
::

![Registry](https://img.shields.io/badge/Docker_Registry-2496ED?style=for-the-badge&logo=docker&logoColor=white)

Port **5000** is the default port for a **private Docker Registry**, allowing you to store and distribute Docker images within your infrastructure. The registry supports OCI image format, content-addressable storage, webhook notifications, and can use various storage backends (filesystem, S3, Azure Blob, GCS).

A private registry is essential for CI/CD pipelines, air-gapped environments, and organizations that need control over their container image distribution.

::tip
For production use, consider adding **TLS certificates** and **authentication** (htpasswd or token-based). Alternatively, use **Harbor** for an enterprise-grade registry with vulnerability scanning, RBAC, and replication.
::

::code-collapse

```yaml [docker-compose.yml]
services:
  registry:
    image: registry:2
    container_name: registry
    restart: unless-stopped
    ports:
      - "5000:5000"
    environment:
      REGISTRY_STORAGE_DELETE_ENABLED: "true"
      REGISTRY_HTTP_HEADERS_Access-Control-Allow-Origin: '["*"]'
    volumes:
      - registry_data:/var/lib/registry
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:5000/v2/"]
      interval: 10s
      timeout: 5s
      retries: 3
    networks:
      - infrastructure

  registry-ui:
    image: joxit/docker-registry-ui:latest
    container_name: registry-ui
    restart: unless-stopped
    ports:
      - "8088:80"
    environment:
      REGISTRY_TITLE: Private Docker Registry
      REGISTRY_URL: http://registry:5000
      DELETE_IMAGES: "true"
      SINGLE_REGISTRY: "true"
    depends_on:
      - registry
    networks:
      - infrastructure

volumes:
  registry_data:
    driver: local

networks:
  infrastructure:
    driver: bridge
```

::

::card-group
  ::card
  ---
  title: Registry Documentation
  icon: i-lucide-book-open
  to: https://distribution.github.io/distribution/
  target: _blank
  ---
  Official Docker Distribution (Registry) documentation with configuration and API reference.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/_/registry
  target: _blank
  ---
  Official Docker Registry image.
  ::
::

---

## :icon{name="i-lucide-layers"} Full Stack Compose

Combine multiple services into a complete development or production stack. Below is a full-stack Docker Compose configuration that wires together several of the ports documented above.

::code-collapse

```yaml [docker-compose.full-stack.yml]
# Full Stack Development Environment
# Includes: Nuxt App, PostgreSQL, Redis, MinIO, Mailpit, Traefik

services:
  # ─── Reverse Proxy (Port 80, 443, 8080) ───
  traefik:
    image: traefik:v3.0
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    command:
      - "--api.dashboard=true"
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - proxy

  # ─── Application (Port 3000) ───
  app:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: nuxt-app
    restart: unless-stopped
    environment:
      DATABASE_URL: postgresql://admin:password@postgres:5432/myapp
      REDIS_URL: redis://:redispassword@redis:6379
      S3_ENDPOINT: http://minio:9000
      S3_ACCESS_KEY: admin
      S3_SECRET_KEY: secretpassword
      S3_BUCKET: uploads
      SMTP_HOST: mailpit
      SMTP_PORT: 1025
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`app.localhost`)"
      - "traefik.http.services.app.loadbalancer.server.port=3000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - proxy
      - backend

  # ─── Database (Port 5432) ───
  postgres:
    image: postgres:17-alpine
    container_name: postgres
    restart: unless-stopped
    ports:
      - "5432:5432"
    environment:
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: password
      POSTGRES_DB: myapp
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U admin -d myapp"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - backend

  # ─── Cache (Port 6379) ───
  redis:
    image: redis:7-alpine
    container_name: redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    command: redis-server --requirepass redispassword --appendonly yes
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "redispassword", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - backend

  # ─── Object Storage (Port 9000, 9001) ───
  minio:
    image: minio/minio:latest
    container_name: minio
    restart: unless-stopped
    ports:
      - "9000:9000"
      - "9001:9001"
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: admin
      MINIO_ROOT_PASSWORD: secretpassword
    volumes:
      - minio_data:/data
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - backend

  # ─── Email Testing (Port 1025, 8025) ───
  mailpit:
    image: axllent/mailpit:latest
    container_name: mailpit
    restart: unless-stopped
    ports:
      - "1025:1025"
      - "8025:8025"
    networks:
      - backend

volumes:
  postgres_data:
  redis_data:
  minio_data:

networks:
  proxy:
    driver: bridge
  backend:
    driver: bridge
```

::

---

## Port Conflict Resolution

When running multiple services, port conflicts are common. Use these strategies:

::steps{level="4"}

#### Identify conflicting ports

```bash [Terminal]
# Check which ports are in use
sudo lsof -i -P -n | grep LISTEN
# or
sudo ss -tulpn | grep LISTEN
```

#### Remap ports in Docker Compose

Change the **host port** (left side) while keeping the container port (right side):

```yaml [docker-compose.yml]
ports:
  - "5433:5432"  # Host port 5433 → Container port 5432
  - "3001:3000"  # Host port 3001 → Container port 3000
```

#### Use environment variables for flexibility

```yaml [docker-compose.yml]
ports:
  - "${POSTGRES_PORT:-5432}:5432"
  - "${APP_PORT:-3000}:3000"
```

#### Create a `.env` file

```bash [.env]
POSTGRES_PORT=5433
APP_PORT=3001
REDIS_PORT=6380
```

::

---

## Security Best Practices

::card-group
  ::card
  ---
  title: Never Expose Unnecessary Ports
  icon: i-lucide-shield-alert
  color: red
  ---
  Only map ports that need external access. Internal services should communicate through Docker networks without port mapping.
  ::

  ::card
  ---
  title: Use Docker Networks
  icon: i-lucide-network
  color: blue
  ---
  Services on the same Docker network can communicate using container names as hostnames without exposing ports to the host.
  ::

  ::card
  ---
  title: Bind to Localhost
  icon: i-lucide-lock
  color: green
  ---
  For development, bind to `127.0.0.1` instead of `0.0.0.0` to prevent external access: `"127.0.0.1:5432:5432"`.
  ::

  ::card
  ---
  title: Always Set Passwords
  icon: i-lucide-key-round
  color: orange
  ---
  Never run databases or message brokers with default or empty credentials. Use strong, unique passwords and rotate them regularly.
  ::
::

::warning
In production, use a reverse proxy (Traefik, Nginx) as the **single entry point** and keep all other service ports internal to the Docker network. Only ports `80` and `443` should face the internet.
::
