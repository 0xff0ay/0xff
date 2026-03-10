---
title: How to Run Multi-Container Apps Using Docker Compose
description: Learn how to orchestrate multiple Docker containers as a single application stack using Docker Compose — from basics to production-ready configurations.
navigation:
  icon: i-simple-icons-docker
---

## Introduction

Docker Compose is a tool for defining and running **multi-container Docker applications**. Instead of running each container manually, you describe your entire application stack in a single `compose.yml` file and bring everything up with one command.

::note
Docker Compose uses a declarative YAML file to configure your application's services, networks, and volumes — all in one place.
::

::card-group
  ::card
  ---
  title: What You'll Learn
  icon: i-lucide-book-open
  ---
  - Define multi-container apps in YAML
  - Link services with networks
  - Persist data using volumes
  - Scale and manage your stack
  ::

  ::card
  ---
  title: Prerequisites
  icon: i-lucide-clipboard-check
  ---
  - Docker Engine installed
  - Docker Compose v2+
  - Basic terminal knowledge
  - A code editor (VS Code recommended)
  ::
::

---

## Why Docker Compose?

Running containers individually with `docker run` quickly becomes **unmanageable** as your application grows.

::tabs
  :::tabs-item{icon="i-lucide-x-circle" label="Without Compose"}
  ```bash [Terminal]
  # Start database
  docker run -d --name db \
    -e POSTGRES_PASSWORD=secret \
    -v pgdata:/var/lib/postgresql/data \
    --network mynet \
    postgres:16

  # Start Redis cache
  docker run -d --name cache \
    --network mynet \
    redis:7-alpine

  # Start backend API
  docker run -d --name api \
    -e DATABASE_URL=postgres://postgres:secret@db:5432/app \
    -e REDIS_URL=redis://cache:6379 \
    --network mynet \
    -p 3000:3000 \
    myapp-api:latest

  # Start frontend
  docker run -d --name web \
    --network mynet \
    -p 8080:80 \
    myapp-web:latest
  ```
  :::

  :::tabs-item{icon="i-lucide-check-circle" label="With Compose"}
  ```bash [Terminal]
  docker compose up -d
  ```
  :::
::

::tip
One command replaces dozens of flags. Compose handles **networking**, **volume mounts**, **environment variables**, and **startup order** automatically.
::

---

## Core Concepts

Before diving in, understand the building blocks of Docker Compose:

::card-group
  ::card
  ---
  title: Services
  icon: i-lucide-boxes
  ---
  Each container in your app (API, database, cache) is a **service**. Services are defined under the `services:` key in your compose file.
  ::

  ::card
  ---
  title: Networks
  icon: i-lucide-network
  ---
  Compose creates a **default network** so all services can communicate by service name. You can also define custom networks for isolation.
  ::

  ::card
  ---
  title: Volumes
  icon: i-lucide-hard-drive
  ---
  **Named volumes** persist data beyond container lifecycle. Essential for databases and file storage that must survive restarts.
  ::

  ::card
  ---
  title: Environment
  icon: i-lucide-settings
  ---
  Pass configuration via **environment variables** or `.env` files. Keep secrets out of your compose file in production.
  ::
::

---

## Architecture Overview

Here's the multi-container architecture we'll build:

![Docker Compose Multi-Container Architecture](https://docs.docker.com/compose/images/compose-application-model.webp)

::note
Our stack includes **4 services**: a Nuxt.js frontend, a Node.js API, a PostgreSQL database, and a Redis cache — all connected through a shared Docker network.
::

| Service    | Image              | Port   | Role                    |
| ---------- | ------------------ | ------ | ----------------------- |
| `web`      | `node:20-alpine`   | `8080` | Nuxt.js Frontend        |
| `api`      | `node:20-alpine`   | `3000` | Express/Fastify Backend |
| `db`       | `postgres:16`      | `5432` | PostgreSQL Database     |
| `cache`    | `redis:7-alpine`   | `6379` | Redis Cache Layer       |

---

## Step-by-Step Guide

::steps{level="3"}

### Install Docker Compose

Docker Compose v2 comes bundled with Docker Desktop. For Linux servers, install the plugin separately:

::code-group
```bash [Docker Desktop (macOS/Windows)]
# Already included — verify with:
docker compose version
```

```bash [Linux (Plugin)]
sudo apt-get update
sudo apt-get install docker-compose-plugin
docker compose version
```

```bash [Standalone Binary]
# Download latest release
DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker}
mkdir -p $DOCKER_CONFIG/cli-plugins
curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
  -o $DOCKER_CONFIG/cli-plugins/docker-compose
chmod +x $DOCKER_CONFIG/cli-plugins/docker-compose
```
::

::warning
Make sure you're using **Compose V2** (`docker compose` with a space) instead of the legacy V1 (`docker-compose` with a hyphen). V1 is deprecated.
::

### Create Your Project Structure

Set up the folder layout for a clean multi-service project:

::code-tree{default-value="compose.yml"}
```yaml [compose.yml]
# We'll fill this in the next step
```

```dockerfile [api/Dockerfile]
FROM node:20-alpine AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
```

```js [api/server.js]
const express = require('express')
const { Pool } = require('pg')
const Redis = require('ioredis')

const app = express()
const pool = new Pool({ connectionString: process.env.DATABASE_URL })
const redis = new Redis(process.env.REDIS_URL)

app.get('/api/health', async (req, res) => {
  const dbResult = await pool.query('SELECT NOW()')
  const cacheResult = await redis.ping()
  res.json({
    status: 'healthy',
    database: dbResult.rows[0].now,
    cache: cacheResult
  })
})

app.get('/api/posts', async (req, res) => {
  const cached = await redis.get('posts')
  if (cached) return res.json(JSON.parse(cached))

  const { rows } = await pool.query('SELECT * FROM posts ORDER BY created_at DESC')
  await redis.set('posts', JSON.stringify(rows), 'EX', 60)
  res.json(rows)
})

app.listen(3000, () => console.log('API running on :3000'))
```

```json [api/package.json]
{
  "name": "api",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.21.0",
    "pg": "^8.13.0",
    "ioredis": "^5.4.0"
  }
}
```

```dockerfile [web/Dockerfile]
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS production
WORKDIR /app
COPY --from=build /app/.output .output
EXPOSE 3000
CMD ["node", ".output/server/index.mjs"]
```

```env [.env]
POSTGRES_USER=appuser
POSTGRES_PASSWORD=supersecret123
POSTGRES_DB=myapp
DATABASE_URL=postgres://appuser:supersecret123@db:5432/myapp
REDIS_URL=redis://cache:6379
NODE_ENV=production
```

```sql [db/init.sql]
CREATE TABLE IF NOT EXISTS posts (
  id SERIAL PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  content TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO posts (title, content) VALUES
  ('Hello Docker Compose', 'This is our first post!'),
  ('Multi-Container Apps', 'Running multiple services together.');
```
::

::caution
Never commit your `.env` file with real secrets to version control. Add it to `.gitignore` and use `.env.example` as a reference template.
::

### Write the Docker Compose File

This is the heart of your multi-container setup:

::code-collapse

```yaml [compose.yml]
# Docker Compose - Multi-Container Application
# Usage: docker compose up -d

services:
  # ──────────────────────────────────────
  # PostgreSQL Database
  # ──────────────────────────────────────
  db:
    image: postgres:16-alpine
    container_name: app-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./db/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    ports:
      - "5432:5432"
    networks:
      - backend
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s

  # ──────────────────────────────────────
  # Redis Cache
  # ──────────────────────────────────────
  cache:
    image: redis:7-alpine
    container_name: app-cache
    restart: unless-stopped
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    networks:
      - backend
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # ──────────────────────────────────────
  # Backend API (Node.js)
  # ──────────────────────────────────────
  api:
    build:
      context: ./api
      dockerfile: Dockerfile
    container_name: app-api
    restart: unless-stopped
    environment:
      DATABASE_URL: ${DATABASE_URL}
      REDIS_URL: ${REDIS_URL}
      NODE_ENV: ${NODE_ENV:-production}
    ports:
      - "3000:3000"
    networks:
      - backend
      - frontend
    depends_on:
      db:
        condition: service_healthy
      cache:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:3000/api/health"]
      interval: 15s
      timeout: 5s
      retries: 3

  # ──────────────────────────────────────
  # Frontend Web (Nuxt.js)
  # ──────────────────────────────────────
  web:
    build:
      context: ./web
      dockerfile: Dockerfile
    container_name: app-web
    restart: unless-stopped
    environment:
      NUXT_API_URL: http://api:3000
    ports:
      - "8080:3000"
    networks:
      - frontend
    depends_on:
      api:
        condition: service_healthy

# ──────────────────────────────────────
# Persistent Volumes
# ──────────────────────────────────────
volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local

# ──────────────────────────────────────
# Custom Networks
# ──────────────────────────────────────
networks:
  backend:
    driver: bridge
  frontend:
    driver: bridge
```

::

### Understanding Each Section

Let's break down the key parts of the compose file:

::accordion
  :::accordion-item{icon="i-lucide-database" label="Services — Defining Your Containers"}
  Each entry under `services:` becomes a running container. The key properties are:

  ::field-group
    ::field{name="image" type="string"}
    The Docker image to pull from a registry (e.g., `postgres:16-alpine`).
    ::

    ::field{name="build" type="object"}
    Build from a local `Dockerfile` instead of pulling an image. Specify `context` and `dockerfile`.
    ::

    ::field{name="environment" type="object | array"}
    Environment variables passed into the container. Use `${VAR}` syntax to reference `.env` file values.
    ::

    ::field{name="ports" type="array"}
    Map `host:container` ports. Format: `"HOST_PORT:CONTAINER_PORT"`.
    ::

    ::field{name="restart" type="string"}
    Restart policy. Options: `no`, `always`, `on-failure`, `unless-stopped`.
    ::
  ::
  

  :::accordion-item{icon="i-lucide-arrow-down-up" label="depends_on — Startup Order & Health"}
  Control the order services start and wait for dependencies to be healthy:

  ```yaml
  depends_on:
    db:
      condition: service_healthy    # Wait until DB healthcheck passes
    cache:
      condition: service_started    # Just wait until container starts
  ```

  Without `condition: service_healthy`, Compose only waits for the container to **start**, not for the application inside to be **ready**.
  :::

  :::accordion-item{icon="i-lucide-heart-pulse" label="Healthchecks — Monitoring Container Health"}
  Healthchecks let Compose verify a service is actually working, not just running:

  ```yaml
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U myuser"]
    interval: 10s      # Check every 10 seconds
    timeout: 5s        # Fail if check takes > 5s
    retries: 5         # Mark unhealthy after 5 failures
    start_period: 30s  # Grace period on startup
  ```
  :::

  :::accordion-item{icon="i-lucide-hard-drive" label="Volumes — Persistent Data Storage"}
  Named volumes persist data even when containers are destroyed:

  ```yaml
  volumes:
    postgres_data:           # Named volume (managed by Docker)
      driver: local

  services:
    db:
      volumes:
        - postgres_data:/var/lib/postgresql/data   # Named volume mount
        - ./db/init.sql:/docker-entrypoint-initdb.d/init.sql:ro  # Bind mount (read-only)
  ```

  | Type | Syntax | Use Case |
  |------|--------|----------|
  | Named Volume | `volume_name:/path` | Database storage, persistent data |
  | Bind Mount | `./local:/container` | Source code, config files |
  | tmpfs | `tmpfs: /path` | Temporary, in-memory data |
  :::

  :::accordion-item{icon="i-lucide-network" label="Networks — Service Isolation"}
  Custom networks control which services can communicate:

  ```yaml
  networks:
    backend:     # DB + Cache + API can talk
      driver: bridge
    frontend:    # API + Web can talk
      driver: bridge
  ```

  In our setup, the **web** service can reach the **api** but **cannot** directly access **db** or **cache** — providing network-level security.
  :::


### Run Your Application

Bring everything up with a single command:

```bash [Terminal]
# Start all services in detached mode
docker compose up -d
```

You should see output similar to:

```bash [Output]
[+] Running 5/5
 ✔ Network app_backend   Created    0.1s
 ✔ Network app_frontend  Created    0.1s
 ✔ Container app-db      Healthy    30.2s
 ✔ Container app-cache   Healthy    10.5s
 ✔ Container app-api     Started    31.0s
 ✔ Container app-web     Started    32.1s
```

::tip
The `depends_on` with health conditions ensures containers start in the correct order: **db** → **cache** → **api** → **web**.
::

### Verify Everything Works

Check that all services are running and healthy:

```bash [Terminal]
# Check service status
docker compose ps
```

```bash [Expected Output]
NAME        IMAGE              STATUS                  PORTS
app-db      postgres:16        Up 2 minutes (healthy)  0.0.0.0:5432->5432/tcp
app-cache   redis:7-alpine     Up 2 minutes (healthy)  0.0.0.0:6379->6379/tcp
app-api     myapp-api          Up 1 minute  (healthy)  0.0.0.0:3000->3000/tcp
app-web     myapp-web          Up 1 minute             0.0.0.0:8080->3000/tcp
```

Test the health endpoint:

```bash [Terminal]
curl http://localhost:3000/api/health | jq
```

```json [Response]
{
  "status": "healthy",
  "database": "2025-01-15T10:30:00.000Z",
  "cache": "PONG"
}
```

---

## Essential Commands

Manage your multi-container app with these commands:

::tabs
  :::tabs-item{icon="i-lucide-play" label="Lifecycle"}
  ```bash [Terminal]
  # Start services (build if needed)
  docker compose up -d

  # Start and force rebuild images
  docker compose up -d --build

  # Stop all services (keep volumes)
  docker compose down

  # Stop and remove everything including volumes
  docker compose down -v --rmi all

  # Restart a specific service
  docker compose restart api
  ```
  :::

  :::tabs-item{icon="i-lucide-monitor" label="Monitoring"}
  ```bash [Terminal]
  # View running containers
  docker compose ps

  # Follow logs from all services
  docker compose logs -f

  # Follow logs from specific service
  docker compose logs -f api

  # Show last 100 lines
  docker compose logs --tail 100 api
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Debugging"}
  ```bash [Terminal]
  # Open shell in a running container
  docker compose exec api sh

  # Run a one-off command
  docker compose exec db psql -U appuser -d myapp

  # Check Redis
  docker compose exec cache redis-cli ping

  # View resource usage
  docker compose top
  docker stats
  ```
  :::

  :::tabs-item{icon="i-lucide-arrow-up-circle" label="Scaling"}
  ```bash [Terminal]
  # Scale API to 3 instances (remove container_name first)
  docker compose up -d --scale api=3

  # View scaled services
  docker compose ps

  # Scale back down
  docker compose up -d --scale api=1
  ```
  :::
::

---

## Environment Configuration

::badge
**Best Practice**
::

Manage configuration across environments using `.env` files:

::code-group
```env [.env.example]
# Database
POSTGRES_USER=appuser
POSTGRES_PASSWORD=changeme
POSTGRES_DB=myapp

# Connection URLs
DATABASE_URL=postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB}
REDIS_URL=redis://cache:6379

# App
NODE_ENV=development
```

```env [.env.production]
# Database
POSTGRES_USER=produser
POSTGRES_PASSWORD=ultra-secure-password-here
POSTGRES_DB=myapp_prod

# Connection URLs
DATABASE_URL=postgres://produser:ultra-secure-password-here@db:5432/myapp_prod
REDIS_URL=redis://cache:6379

# App
NODE_ENV=production
```
::

Use a specific env file:

```bash [Terminal]
docker compose --env-file .env.production up -d
```

::warning
For production secrets, consider using Docker Secrets or an external vault (like HashiCorp Vault) instead of `.env` files.
::

---

## Production Considerations

::card-group
  ::card
  ---
  title: Resource Limits
  icon: i-lucide-gauge
  ---
  Always set CPU and memory limits to prevent a single container from consuming all host resources.

  ```yaml
  services:
    api:
      deploy:
        resources:
          limits:
            cpus: '1.0'
            memory: 512M
          reservations:
            cpus: '0.25'
            memory: 128M
  ```
  ::

  ::card
  ---
  title: Logging
  icon: i-lucide-scroll-text
  ---
  Configure log rotation to prevent disk space exhaustion from container logs.

  ```yaml
  services:
    api:
      logging:
        driver: json-file
        options:
          max-size: "10m"
          max-file: "3"
  ```
  ::

  ::card
  ---
  title: Security
  icon: i-lucide-shield-check
  ---
  Run containers as non-root users and use read-only filesystems where possible.

  ```yaml
  services:
    api:
      user: "1000:1000"
      read_only: true
      tmpfs:
        - /tmp
  ```
  ::

  ::card
  ---
  title: Backup Strategy
  icon: i-lucide-database-backup
  ---
  Regularly back up your named volumes, especially database volumes.

  ```bash
  docker compose exec db \
    pg_dump -U appuser myapp > \
    backup_$(date +%Y%m%d).sql
  ```
  ::
::

---

## Common Patterns

### Adding a Reverse Proxy

Add **Nginx** or **Traefik** as a reverse proxy to handle SSL, load balancing, and routing:

::code-collapse

```yaml [compose.yml — with Nginx proxy]
services:
  proxy:
    image: nginx:alpine
    container_name: app-proxy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
    networks:
      - frontend
    depends_on:
      - web
      - api

  web:
    build: ./web
    # Remove port mapping — proxy handles it
    expose:
      - "3000"
    networks:
      - frontend

  api:
    build: ./api
    expose:
      - "3000"
    networks:
      - frontend
      - backend
```

::

### Adding Monitoring with Healthcheck Dashboard

![Docker Compose Monitoring](https://docs.docker.com/engine/images/architecture.svg)

```yaml [compose.yml — monitoring snippet]
services:
  # ... your existing services ...

  adminer:
    image: adminer:latest
    container_name: app-adminer
    restart: unless-stopped
    ports:
      - "8888:8080"
    networks:
      - backend
    depends_on:
      - db
```

::tip
Access Adminer at `http://localhost:8888` to visually manage your PostgreSQL database during development.
::

---

## Troubleshooting

::accordion
  :::accordion-item{icon="i-lucide-alert-triangle" label="Port already in use"}
  ```bash [Terminal]
  # Find what's using port 5432
  lsof -i :5432
  # or
  netstat -tulnp | grep 5432

  # Change the host port in compose.yml
  ports:
    - "5433:5432"   # Use 5433 on host instead
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Container keeps restarting"}
  ```bash [Terminal]
  # Check container logs
  docker compose logs api --tail 50

  # Inspect exit code
  docker inspect app-api --format='{{.State.ExitCode}}'

  # Common fixes:
  # 1. Check environment variables
  # 2. Verify depends_on health conditions
  # 3. Ensure Dockerfile CMD is correct
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Cannot connect between services"}
  ```bash [Terminal]
  # Verify both services are on the same network
  docker network inspect app_backend

  # Test connectivity from inside a container
  docker compose exec api ping db
  docker compose exec api wget -qO- http://cache:6379

  # Remember: use SERVICE NAMES as hostnames, not container names
  # ✅ postgres://user:pass@db:5432/myapp
  # ❌ postgres://user:pass@app-db:5432/myapp
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Volume data not persisting"}
  ```bash [Terminal]
  # List volumes
  docker volume ls

  # Inspect a volume
  docker volume inspect app_postgres_data

  # ⚠️ Make sure you're NOT using `docker compose down -v`
  # The -v flag removes volumes!
  ```
  :::
::

---

## Compose File Reference

Quick reference for the most important `compose.yml` keys:

::field-group
  ::field{name="services" type="object"}
  **Required.** Defines each container in your application. Each key becomes a service name and DNS hostname.
  ::

  ::field{name="image" type="string"}
  Docker image to use. Format: `name:tag` (e.g., `postgres:16-alpine`).
  ::

  ::field{name="build" type="string | object"}
  Build from Dockerfile. Can be a path string or object with `context` and `dockerfile`.
  ::

  ::field{name="ports" type="array"}
  Port mappings. Format: `"HOST:CONTAINER"` or `"HOST:CONTAINER/protocol"`.
  ::

  ::field{name="volumes" type="array"}
  Mount volumes or bind mounts. Format: `source:target[:mode]`.
  ::

  ::field{name="environment" type="object | array"}
  Set environment variables. Supports `${VAR}` interpolation from `.env` files.
  ::

  ::field{name="depends_on" type="object | array"}
  Define startup dependencies. Use `condition: service_healthy` for health-aware ordering.
  ::

  ::field{name="networks" type="array"}
  Attach service to specific networks. Services on the same network can communicate.
  ::

  ::field{name="restart" type="string"}
  Restart policy: `no` | `always` | `on-failure` | `unless-stopped`.
  ::

  ::field{name="healthcheck" type="object"}
  Container health check configuration with `test`, `interval`, `timeout`, `retries`.
  ::

  ::field{name="deploy.resources" type="object"}
  Resource limits and reservations for CPU and memory.
  ::
::

---

## Reference & Resources

::card-group
  ::card
  ---
  title: Docker Compose Docs
  icon: i-simple-icons-docker
  to: https://docs.docker.com/compose/
  target: _blank
  ---
  Official Docker Compose documentation — comprehensive guide to all features and configuration options.
  ::

  ::card
  ---
  title: Compose File Specification
  icon: i-lucide-file-code
  to: https://docs.docker.com/reference/compose-file/
  target: _blank
  ---
  Complete YAML reference for every key, attribute, and option available in `compose.yml`.
  ::

  ::card
  ---
  title: Docker Hub
  icon: i-simple-icons-docker
  to: https://hub.docker.com/
  target: _blank
  ---
  Browse official and community Docker images for databases, caches, web servers, and more.
  ::

  ::card
  ---
  title: Awesome Compose
  icon: i-simple-icons-github
  to: https://github.com/docker/awesome-compose
  target: _blank
  ---
  Curated list of Docker Compose samples — real-world examples for React, Django, Spring Boot, and more.
  ::

  ::card
  ---
  title: Docker Compose CLI Reference
  icon: i-lucide-terminal
  to: https://docs.docker.com/reference/cli/docker/compose/
  target: _blank
  ---
  All available `docker compose` commands with usage, flags, and examples.
  ::

  ::card
  ---
  title: Networking in Compose
  icon: i-lucide-network
  to: https://docs.docker.com/compose/how-tos/networking/
  target: _blank
  ---
  Deep dive into how Docker Compose networking works — DNS resolution, custom networks, and isolation.
  ::
::

---

::tip{to="/guides/docker-basics"}
**New to Docker?** Start with our Docker fundamentals guide before diving into multi-container orchestration.
::