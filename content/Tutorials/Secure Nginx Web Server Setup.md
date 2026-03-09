---
title: Secure Nginx Web Server Setup
description: Comprehensive guide covering Nginx installation, security hardening, SSL/TLS configuration, domain setup, reverse proxy, performance optimization, and production deployment.
navigation:
  icon: i-lucide-server
tags:
  - tutorial
---

## Overview

**Nginx** (pronounced "engine-x") is a high-performance HTTP server, reverse proxy, load balancer, and mail proxy. It powers over **34% of all websites worldwide** and is the preferred web server for modern web applications due to its speed, stability, and low resource consumption.

> Properly securing Nginx is critical — a misconfigured web server is one of the most common entry points for attackers.

### Why Nginx?

| Feature                  | Nginx                              | Apache                             |
| ------------------------ | ---------------------------------- | ---------------------------------- |
| Architecture             | Event-driven, asynchronous         | Process/Thread-based               |
| Concurrency              | Handles 10,000+ connections        | Limited by thread count            |
| Static content           | Extremely fast                     | Fast                               |
| Memory usage             | Very low                           | Higher                             |
| Configuration            | Centralized config files           | `.htaccess` per directory          |
| Reverse proxy            | Native, built-in                   | Requires `mod_proxy`               |
| Load balancing           | Built-in                           | Requires `mod_proxy_balancer`      |
| WebSocket support        | Native                             | Requires modules                   |
| HTTP/2 support           | Native                             | Requires `mod_http2`               |
| Market share             | ~34%                               | ~31%                               |

### Nginx Architecture

::code-preview
---
class: "[&>div]:*:my-0"
---
How Nginx handles requests.

#code
```
Nginx Architecture:

┌─────────────────────────────────────────────────┐
│                  Master Process                  │
│         (reads config, manages workers)          │
├─────────┬─────────┬─────────┬───────────────────┤
│ Worker 1│ Worker 2│ Worker 3│    Worker N        │
│ (events)│ (events)│ (events)│    (events)        │
│         │         │         │                    │
│ ┌─────┐ │ ┌─────┐ │ ┌─────┐ │                    │
│ │Conn1│ │ │Conn4│ │ │Conn7│ │                    │
│ │Conn2│ │ │Conn5│ │ │Conn8│ │                    │
│ │Conn3│ │ │Conn6│ │ │Conn9│ │                    │
│ └─────┘ │ └─────┘ │ └─────┘ │                    │
└─────────┴─────────┴─────────┴───────────────────┘
              │
              ▼
┌──────────────────────────┐
│     Backend Services     │
│  ┌─────┐ ┌─────┐ ┌────┐ │
│  │PHP  │ │Node │ │DB  │ │
│  │FPM  │ │.js  │ │    │ │
│  └─────┘ └─────┘ └────┘ │
└──────────────────────────┘
```
::

---

## Installation

### Install Nginx on Ubuntu

::code-preview
---
class: "[&>div]:*:my-0"
---
Install the latest stable Nginx.

#code
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Nginx
sudo apt install nginx -y

# Verify installation
nginx -v

# Check Nginx status
sudo systemctl status nginx

# Enable on boot
sudo systemctl enable nginx

# Start Nginx
sudo systemctl start nginx

# Test configuration
sudo nginx -t
```
::

### Install Latest Stable from Official Repository

::code-preview
---
class: "[&>div]:*:my-0"
---
Install latest Nginx from official repo.

#code
```bash
# Install prerequisites
sudo apt install curl gnupg2 ca-certificates lsb-release ubuntu-keyring -y

# Import Nginx GPG key
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null

# Add Nginx stable repository
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list

# Pin Nginx packages to official repo
echo -e "Package: *\nPin: origin nginx.org\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx

# Install
sudo apt update
sudo apt install nginx -y

# Verify version
nginx -v
```
::

### Nginx Directory Structure

| Path                               | Purpose                                |
| ---------------------------------- | -------------------------------------- |
| `/etc/nginx/`                      | Main configuration directory           |
| `/etc/nginx/nginx.conf`            | Main configuration file                |
| `/etc/nginx/sites-available/`      | Available virtual host configs         |
| `/etc/nginx/sites-enabled/`        | Enabled virtual host configs (symlinks)|
| `/etc/nginx/conf.d/`              | Additional configuration files         |
| `/etc/nginx/snippets/`            | Reusable configuration snippets        |
| `/etc/nginx/modules-available/`    | Available modules                      |
| `/etc/nginx/modules-enabled/`      | Enabled modules                        |
| `/etc/nginx/mime.types`           | MIME type mappings                     |
| `/var/www/html/`                  | Default web root                       |
| `/var/log/nginx/access.log`       | Access log                             |
| `/var/log/nginx/error.log`        | Error log                              |
| `/run/nginx.pid`                  | Process ID file                        |

---

## Core Configuration

### Main nginx.conf

::code-preview
---
class: "[&>div]:*:my-0"
---
Optimized and secured main nginx.conf.

#code
```nginx
# /etc/nginx/nginx.conf
# ============================================================
# MAIN CONTEXT - Global Settings
# ============================================================

# Run as www-data user (never as root)
user www-data;

# Auto-detect CPU cores for worker processes
# Set to number of CPU cores: nproc
worker_processes auto;

# Process ID file location
pid /run/nginx.pid;

# Error log level
error_log /var/log/nginx/error.log warn;

# Maximum number of open files per worker
worker_rlimit_nofile 65535;

# Include dynamic modules
include /etc/nginx/modules-enabled/*.conf;

# ============================================================
# EVENTS CONTEXT - Connection Processing
# ============================================================
events {
    # Maximum simultaneous connections per worker
    worker_connections 4096;

    # Accept multiple connections at once
    multi_accept on;

    # Use the most efficient connection method (Linux)
    use epoll;
}

# ============================================================
# HTTP CONTEXT - Web Server Settings
# ============================================================
http {
    # ========================================================
    # BASIC SETTINGS
    # ========================================================

    # MIME types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Character encoding
    charset utf-8;

    # ========================================================
    # PERFORMANCE SETTINGS
    # ========================================================

    # Enable sendfile for static content
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;

    # Connection timeouts
    keepalive_timeout 30;
    keepalive_requests 1000;
    send_timeout 30;
    client_body_timeout 30;
    client_header_timeout 30;
    reset_timedout_connection on;

    # Buffer sizes
    client_body_buffer_size 16k;
    client_header_buffer_size 1k;
    client_max_body_size 16m;
    large_client_header_buffers 4 8k;

    # File descriptor caching
    open_file_cache max=200000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    # Hash bucket sizes
    types_hash_max_size 2048;
    server_names_hash_bucket_size 128;

    # ========================================================
    # SECURITY HEADERS
    # ========================================================

    # Hide Nginx version
    server_tokens off;

    # Prevent MIME type sniffing
    add_header X-Content-Type-Options "nosniff" always;

    # Prevent clickjacking
    add_header X-Frame-Options "SAMEORIGIN" always;

    # XSS Protection
    add_header X-XSS-Protection "1; mode=block" always;

    # Referrer Policy
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Permissions Policy
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

    # Content Security Policy (customize per site)
    # add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;

    # ========================================================
    # LOGGING
    # ========================================================

    # Custom log format with detailed info
    log_format main '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" '
                    '$request_time $upstream_response_time';

    # JSON log format (for log aggregation)
    log_format json_combined escape=json
        '{'
            '"time":"$time_iso8601",'
            '"remote_addr":"$remote_addr",'
            '"remote_user":"$remote_user",'
            '"request":"$request",'
            '"status":"$status",'
            '"body_bytes_sent":"$body_bytes_sent",'
            '"request_time":"$request_time",'
            '"http_referrer":"$http_referer",'
            '"http_user_agent":"$http_user_agent",'
            '"upstream_response_time":"$upstream_response_time",'
            '"ssl_protocol":"$ssl_protocol",'
            '"ssl_cipher":"$ssl_cipher",'
            '"request_method":"$request_method",'
            '"server_name":"$server_name"'
        '}';

    # Access logging
    access_log /var/log/nginx/access.log main;

    # ========================================================
    # GZIP COMPRESSION
    # ========================================================

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_min_length 256;
    gzip_types
        text/plain
        text/css
        text/javascript
        text/xml
        application/json
        application/javascript
        application/xml
        application/xml+rss
        application/atom+xml
        application/vnd.ms-fontobject
        application/x-font-ttf
        application/x-web-app-manifest+json
        application/xhtml+xml
        font/opentype
        image/svg+xml
        image/x-icon;

    # ========================================================
    # RATE LIMITING
    # ========================================================

    # Rate limiting zones
    # 10 requests per second per IP
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;

    # Login page rate limiting (stricter)
    limit_req_zone $binary_remote_addr zone=login:10m rate=3r/s;

    # API rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;

    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

    # Rate limit response code
    limit_req_status 429;
    limit_conn_status 429;

    # ========================================================
    # SSL/TLS GLOBAL SETTINGS
    # ========================================================

    # SSL session caching
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Modern TLS only
    ssl_protocols TLSv1.2 TLSv1.3;

    # Strong cipher suites
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';

    # Prefer server ciphers
    ssl_prefer_server_ciphers off;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # DNS resolver for OCSP
    resolver 1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # DH parameters (generate: openssl dhparam -out /etc/nginx/dhparam.pem 4096)
    # ssl_dhparam /etc/nginx/dhparam.pem;

    # ========================================================
    # PROXY SETTINGS (for reverse proxy)
    # ========================================================

    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Port $server_port;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";

    # Proxy timeouts
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;

    # Proxy buffering
    proxy_buffering on;
    proxy_buffer_size 4k;
    proxy_buffers 8 4k;

    # ========================================================
    # INCLUDE SITE CONFIGURATIONS
    # ========================================================

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
```
::

---

## Domain Setup

### Single Domain Configuration

::code-preview
---
class: "[&>div]:*:my-0"
---
Create a virtual host for a single domain.

#code
```bash
# Create web root directory
sudo mkdir -p /var/www/example.com/public
sudo mkdir -p /var/www/example.com/logs

# Set ownership
sudo chown -R www-data:www-data /var/www/example.com
sudo chmod -R 755 /var/www/example.com

# Create a test page
sudo nano /var/www/example.com/public/index.html
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Test HTML page.

#code
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to example.com</title>
</head>
<body>
    <h1>Success! example.com is working.</h1>
    <p>Nginx is serving this page securely.</p>
</body>
</html>
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Create Nginx virtual host configuration.

#code
```bash
sudo nano /etc/nginx/sites-available/example.com
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Basic domain server block (HTTP only — before SSL).

#code
```nginx
# /etc/nginx/sites-available/example.com

server {
    listen 80;
    listen [::]:80;

    server_name example.com www.example.com;

    root /var/www/example.com/public;
    index index.html index.htm;

    # Logging
    access_log /var/www/example.com/logs/access.log main;
    error_log /var/www/example.com/logs/error.log warn;

    # Main location
    location / {
        try_files $uri $uri/ =404;
    }

    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Favicon and robots
    location = /favicon.ico {
        access_log off;
        log_not_found off;
    }

    location = /robots.txt {
        access_log off;
        log_not_found off;
    }
}
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Enable the site.

#code
```bash
# Create symbolic link to enable site
sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/

# Remove default site (optional)
sudo rm /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```
::

### Multiple Domains Setup

::code-preview
---
class: "[&>div]:*:my-0"
---
Setup multiple domains on one server.

#code
```bash
# Create directories for each domain
sudo mkdir -p /var/www/domain1.com/{public,logs}
sudo mkdir -p /var/www/domain2.com/{public,logs}
sudo mkdir -p /var/www/domain3.com/{public,logs}

# Set ownership
sudo chown -R www-data:www-data /var/www/domain1.com
sudo chown -R www-data:www-data /var/www/domain2.com
sudo chown -R www-data:www-data /var/www/domain3.com

# Create configs for each domain
sudo nano /etc/nginx/sites-available/domain1.com
sudo nano /etc/nginx/sites-available/domain2.com
sudo nano /etc/nginx/sites-available/domain3.com

# Enable each site
sudo ln -s /etc/nginx/sites-available/domain1.com /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/domain2.com /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/domain3.com /etc/nginx/sites-enabled/

# Test and reload
sudo nginx -t
sudo systemctl reload nginx
```
::

### Subdomain Configuration

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure subdomains.

#code
```nginx
# /etc/nginx/sites-available/subdomains.example.com

# API subdomain
server {
    listen 80;
    listen [::]:80;
    server_name api.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Admin subdomain
server {
    listen 80;
    listen [::]:80;
    server_name admin.example.com;

    root /var/www/admin.example.com/public;
    index index.html;

    # Restrict to specific IPs
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;

    location / {
        try_files $uri $uri/ =404;
    }
}

# Blog subdomain
server {
    listen 80;
    listen [::]:80;
    server_name blog.example.com;

    root /var/www/blog.example.com/public;
    index index.html index.php;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }
}

# Wildcard subdomain (catch-all)
server {
    listen 80;
    listen [::]:80;
    server_name *.example.com;

    return 404;
}
```
::

---

## SSL/TLS Configuration

### Generate DH Parameters

::code-preview
---
class: "[&>div]:*:my-0"
---
Generate strong Diffie-Hellman parameters.

#code
```bash
# Generate 4096-bit DH parameters (takes several minutes)
sudo openssl dhparam -out /etc/nginx/dhparam.pem 4096

# Or faster 2048-bit (still secure)
sudo openssl dhparam -out /etc/nginx/dhparam.pem 2048

# Set permissions
sudo chmod 600 /etc/nginx/dhparam.pem
```
::

### Let's Encrypt SSL with Certbot

::code-preview
---
class: "[&>div]:*:my-0"
---
Install and configure Let's Encrypt SSL.

#code
```bash
# Install Certbot and Nginx plugin
sudo apt install certbot python3-certbot-nginx -y

# Obtain SSL certificate (interactive)
sudo certbot --nginx -d example.com -d www.example.com

# Obtain certificate (non-interactive)
sudo certbot --nginx \
    -d example.com \
    -d www.example.com \
    --non-interactive \
    --agree-tos \
    --email admin@example.com \
    --redirect

# Obtain wildcard certificate (requires DNS validation)
sudo certbot certonly \
    --manual \
    --preferred-challenges dns \
    -d "*.example.com" \
    -d example.com \
    --agree-tos \
    --email admin@example.com

# Obtain certificate without modifying Nginx config
sudo certbot certonly --nginx -d example.com -d www.example.com

# Test certificate renewal
sudo certbot renew --dry-run

# Force renewal
sudo certbot renew --force-renewal

# View certificate info
sudo certbot certificates

# Revoke a certificate
sudo certbot revoke --cert-path /etc/letsencrypt/live/example.com/cert.pem
```
::

### Auto-Renewal Setup

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure automatic SSL certificate renewal.

#code
```bash
# Certbot auto-renewal timer (usually auto-configured)
sudo systemctl status certbot.timer

# If timer doesn't exist, add cron job
sudo crontab -e

# Add these lines (renew twice daily)
0 0,12 * * * /usr/bin/certbot renew --quiet --deploy-hook "systemctl reload nginx"

# Test renewal
sudo certbot renew --dry-run

# View renewal configuration
cat /etc/letsencrypt/renewal/example.com.conf
```
::

### SSL Configuration Snippet

::code-preview
---
class: "[&>div]:*:my-0"
---
Create a reusable SSL configuration snippet.

#code
```bash
sudo nano /etc/nginx/snippets/ssl-params.conf
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
SSL parameters snippet content.

#code
```nginx
# /etc/nginx/snippets/ssl-params.conf
# ============================================================
# SSL/TLS Security Configuration
# ============================================================

# TLS Protocols (disable old insecure versions)
ssl_protocols TLSv1.2 TLSv1.3;

# Strong cipher suites
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';

# Let the server choose the best cipher
ssl_prefer_server_ciphers off;

# DH parameters
ssl_dhparam /etc/nginx/dhparam.pem;

# SSL session caching
ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;

# Trusted certificate for OCSP
ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;

# DNS resolver
resolver 1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# HSTS (HTTP Strict Transport Security) - 1 year
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Additional Security Headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

# Content Security Policy (customize per site)
# add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:;" always;
```
::

### Complete HTTPS Server Block

::code-preview
---
class: "[&>div]:*:my-0"
---
Production-ready HTTPS virtual host.

#code
```nginx
# /etc/nginx/sites-available/example.com

# ============================================================
# HTTP → HTTPS Redirect
# ============================================================
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;

    # Redirect ALL HTTP to HTTPS
    return 301 https://$host$request_uri;
}

# ============================================================
# WWW → Non-WWW Redirect (choose one)
# ============================================================
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name www.example.com;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # Include SSL params
    include /etc/nginx/snippets/ssl-params.conf;

    # Redirect www to non-www
    return 301 https://example.com$request_uri;
}

# ============================================================
# Main HTTPS Server Block
# ============================================================
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com;

    # ========================================================
    # SSL CERTIFICATES
    # ========================================================
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # Include SSL security params
    include /etc/nginx/snippets/ssl-params.conf;

    # ========================================================
    # DOCUMENT ROOT
    # ========================================================
    root /var/www/example.com/public;
    index index.html index.htm index.php;

    # ========================================================
    # LOGGING
    # ========================================================
    access_log /var/www/example.com/logs/access.log main;
    error_log /var/www/example.com/logs/error.log warn;

    # ========================================================
    # MAIN LOCATION
    # ========================================================
    location / {
        try_files $uri $uri/ /index.html;
    }

    # ========================================================
    # STATIC FILE CACHING
    # ========================================================
    location ~* \.(jpg|jpeg|png|gif|ico|svg|webp)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    location ~* \.(css|js)$ {
        expires 7d;
        add_header Cache-Control "public";
        access_log off;
    }

    location ~* \.(woff|woff2|ttf|eot|otf)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        add_header Access-Control-Allow-Origin "*";
        access_log off;
    }

    location ~* \.(pdf|doc|docx|xls|xlsx)$ {
        expires 7d;
        add_header Cache-Control "public";
    }

    # ========================================================
    # SECURITY - DENY ACCESS
    # ========================================================

    # Deny access to hidden files (.htaccess, .git, .env, etc.)
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Deny access to sensitive files
    location ~* \.(engine|inc|install|make|module|profile|po|sh|sql|theme|twig|tpl(\.php)?|xtmpl|yml|yaml|conf|ini|log|bak|old|orig|save|dist|config)$ {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Block common exploit patterns
    location ~* (eval\(|base64_encode|php://input|proc/self) {
        deny all;
    }

    # ========================================================
    # FAVICON AND ROBOTS
    # ========================================================
    location = /favicon.ico {
        access_log off;
        log_not_found off;
        expires 30d;
    }

    location = /robots.txt {
        access_log off;
        log_not_found off;
    }

    # ========================================================
    # ERROR PAGES
    # ========================================================
    error_page 404 /404.html;
    location = /404.html {
        root /var/www/example.com/public/errors;
        internal;
    }

    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /var/www/example.com/public/errors;
        internal;
    }
}
```
::

### Self-Signed SSL (Development)

::code-preview
---
class: "[&>div]:*:my-0"
---
Generate self-signed SSL certificate for development.

#code
```bash
# Create SSL directory
sudo mkdir -p /etc/nginx/ssl

# Generate self-signed certificate (valid for 365 days)
sudo openssl req -x509 -nodes \
    -days 365 \
    -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/selfsigned.key \
    -out /etc/nginx/ssl/selfsigned.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Generate with Subject Alternative Names
sudo openssl req -x509 -nodes \
    -days 365 \
    -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/selfsigned.key \
    -out /etc/nginx/ssl/selfsigned.crt \
    -subj "/C=US/ST=State/L=City/O=Dev/CN=dev.local" \
    -addext "subjectAltName=DNS:dev.local,DNS:*.dev.local,IP:127.0.0.1"

# Set permissions
sudo chmod 600 /etc/nginx/ssl/selfsigned.key
sudo chmod 644 /etc/nginx/ssl/selfsigned.crt
```
::

### SSL/TLS Testing

::code-preview
---
class: "[&>div]:*:my-0"
---
Test SSL configuration.

#code
```bash
# Test with OpenSSL
openssl s_client -connect example.com:443 -servername example.com

# Check certificate details
openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -text -noout

# Check certificate expiry
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -enddate

# Check supported protocols
nmap --script ssl-enum-ciphers -p 443 example.com

# Check with curl
curl -vI https://example.com 2>&1 | grep -i "ssl\|tls\|certificate"

# Online tools:
# - https://www.ssllabs.com/ssltest/ (SSL Labs)
# - https://www.immuniweb.com/ssl/ (ImmuniWeb)
# - https://observatory.mozilla.org/ (Mozilla Observatory)
# - https://securityheaders.com/ (Security Headers)
```
::

---

## Security Hardening

### Security Configuration Snippet

::code-preview
---
class: "[&>div]:*:my-0"
---
Create a reusable security snippet.

#code
```bash
sudo nano /etc/nginx/snippets/security.conf
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Comprehensive security configuration.

#code
```nginx
# /etc/nginx/snippets/security.conf
# ============================================================
# SECURITY HARDENING
# ============================================================

# Hide Nginx version from Server header
server_tokens off;

# Prevent MIME type sniffing
add_header X-Content-Type-Options "nosniff" always;

# Clickjacking protection
add_header X-Frame-Options "SAMEORIGIN" always;

# XSS filter
add_header X-XSS-Protection "1; mode=block" always;

# Referrer policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Permissions policy (formerly Feature-Policy)
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()" always;

# Cross-Origin policies
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;

# ============================================================
# CONTENT SECURITY POLICY (customize per application)
# ============================================================
# Basic CSP - modify based on your application needs
add_header Content-Security-Policy "
    default-src 'self';
    script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net;
    style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
    img-src 'self' data: https:;
    font-src 'self' https://fonts.gstatic.com;
    connect-src 'self' https://api.example.com;
    media-src 'self';
    object-src 'none';
    frame-src 'self';
    frame-ancestors 'self';
    form-action 'self';
    base-uri 'self';
    upgrade-insecure-requests;
" always;

# ============================================================
# BLOCK COMMON ATTACKS
# ============================================================

# Block access to hidden files and directories
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}

# Block access to backup and config files
location ~* \.(bak|conf|dist|env|fla|in[ci]|log|orig|psd|sh|sql|sw[op])$ {
    deny all;
}

# Block access to version control
location ~ /\.(git|svn|hg|bzr) {
    deny all;
}

# Block access to sensitive directories
location ~* /(wp-admin|wp-login|administrator|admin|phpmyadmin|pma|myadmin) {
    # Uncomment to restrict to specific IPs
    # allow 192.168.1.0/24;
    # deny all;
}

# Block common exploit paths
location ~* /(eval|shell|phpinfo|cgi-bin|etc/passwd|proc/self) {
    deny all;
}

# Block PHP execution in upload directories
location ~* /(?:uploads|files|images|media|tmp)/.*\.php$ {
    deny all;
}

# Block xmlrpc (WordPress)
location = /xmlrpc.php {
    deny all;
    access_log off;
    log_not_found off;
}
```
::

### Block Bad User Agents

::code-preview
---
class: "[&>div]:*:my-0"
---
Block malicious bots and scanners.

#code
```nginx
# /etc/nginx/snippets/block-bots.conf

# Map to detect bad bots
map $http_user_agent $bad_bot {
    default 0;

    # Vulnerability scanners
    ~*nikto           1;
    ~*nessus          1;
    ~*sqlmap          1;
    ~*nmap            1;
    ~*masscan         1;
    ~*zgrab           1;
    ~*nuclei          1;
    ~*dirbuster       1;
    ~*gobuster        1;
    ~*wfuzz           1;
    ~*ffuf            1;
    ~*burpsuite       1;

    # Bad crawlers
    ~*AhrefsBot       1;
    ~*SemrushBot      1;
    ~*MJ12bot         1;
    ~*DotBot          1;
    ~*BLEXBot         1;
    ~*PetalBot        1;

    # Content scrapers
    ~*HTTrack         1;
    ~*WebCopier       1;
    ~*WebZIP          1;
    ~*TeleportPro     1;

    # Empty user agents
    ""                1;

    # Suspicious agents
    ~*python-requests 1;
    ~*Go-http-client  1;
    ~*curl            1;
    ~*wget            1;
    ~*libwww-perl     1;
    ~*lwp-trivial     1;
}

# Use in server block:
# if ($bad_bot) {
#     return 403;
# }
```
::

### Block Bad Referrers

::code-preview
---
class: "[&>div]:*:my-0"
---
Block spam referrers.

#code
```nginx
# /etc/nginx/snippets/block-referrers.conf

map $http_referer $bad_referer {
    default 0;

    ~*spamdomain1\.com    1;
    ~*spamdomain2\.com    1;
    ~*casino              1;
    ~*poker               1;
    ~*viagra              1;
    ~*pharma              1;
    ~*cheap               1;
}

# Use in server block:
# if ($bad_referer) {
#     return 403;
# }
```
::

### Rate Limiting

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure rate limiting for different zones.

#code
```nginx
# Define in http {} context (already in nginx.conf above)
# limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
# limit_req_zone $binary_remote_addr zone=login:10m rate=3r/s;
# limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;

# Apply in server/location blocks:

server {
    # General rate limiting
    location / {
        limit_req zone=general burst=20 nodelay;
        limit_conn conn_limit 25;
        try_files $uri $uri/ =404;
    }

    # Strict rate limiting for login pages
    location /login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://backend;
    }

    location /api/auth {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://backend;
    }

    # API rate limiting
    location /api/ {
        limit_req zone=api burst=50 nodelay;
        proxy_pass http://backend;
    }

    # No rate limiting for static files
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff|woff2)$ {
        expires 30d;
        access_log off;
    }
}
```
::

### Rate Limiting Parameters

| Parameter  | Description                                              |
| ---------- | -------------------------------------------------------- |
| `zone`     | Reference to defined `limit_req_zone`                    |
| `burst`    | Maximum burst requests above the rate limit              |
| `nodelay`  | Process burst requests immediately instead of delaying   |
| `delay`    | Number of requests to process without delay              |
| `rate`     | Requests per second (e.g., `10r/s`) or minute (`60r/m`) |

### IP-Based Access Control

::code-preview
---
class: "[&>div]:*:my-0"
---
Restrict access by IP address.

#code
```nginx
# Whitelist specific IPs for admin areas
location /admin {
    allow 192.168.1.0/24;          # Office network
    allow 10.0.0.0/8;              # VPN network
    allow 203.0.113.50;            # Admin home IP
    deny all;

    proxy_pass http://backend;
}

# Block specific IPs
location / {
    deny 192.168.1.100;            # Blocked IP
    deny 10.0.0.0/8;              # Blocked range
    allow all;                      # Allow everyone else
}

# GeoIP blocking (requires ngx_http_geoip2_module)
# geoip2 /usr/share/GeoIP/GeoLite2-Country.mmdb {
#     $geoip2_data_country_iso_code country iso_code;
# }
#
# map $geoip2_data_country_iso_code $allowed_country {
#     default no;
#     US yes;
#     CA yes;
#     GB yes;
#     DE yes;
# }
#
# server {
#     if ($allowed_country = no) {
#         return 403;
#     }
# }
```
::

### HTTP Basic Authentication

::code-preview
---
class: "[&>div]:*:my-0"
---
Setup password-protected areas.

#code
```bash
# Install apache2-utils for htpasswd
sudo apt install apache2-utils -y

# Create password file with first user
sudo htpasswd -c /etc/nginx/.htpasswd admin

# Add additional users
sudo htpasswd /etc/nginx/.htpasswd user2

# Verify the file
cat /etc/nginx/.htpasswd

# Set permissions
sudo chmod 640 /etc/nginx/.htpasswd
sudo chown root:www-data /etc/nginx/.htpasswd
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Apply authentication to a location.

#code
```nginx
# Password-protect an entire location
location /admin {
    auth_basic "Administrator Area";
    auth_basic_user_file /etc/nginx/.htpasswd;

    proxy_pass http://backend;
}

# Password-protect a specific file
location = /status {
    auth_basic "Status Page";
    auth_basic_user_file /etc/nginx/.htpasswd;

    stub_status on;
    access_log off;
}

# Combine IP restriction with password
location /secure {
    satisfy any;                    # "any" = IP OR password
                                   # "all" = IP AND password

    allow 192.168.1.0/24;
    deny all;

    auth_basic "Secure Area";
    auth_basic_user_file /etc/nginx/.htpasswd;

    proxy_pass http://backend;
}
```
::

### Request Size Limits

::code-preview
---
class: "[&>div]:*:my-0"
---
Limit request sizes to prevent abuse.

#code
```nginx
# In http, server, or location context

# Maximum allowed request body size
client_max_body_size 16m;

# For file upload endpoints, allow larger
location /api/upload {
    client_max_body_size 100m;
    client_body_timeout 120s;
    proxy_pass http://backend;
}

# For API endpoints, keep small
location /api/ {
    client_max_body_size 1m;
    proxy_pass http://backend;
}

# Buffer size limits
client_body_buffer_size 16k;
client_header_buffer_size 1k;
large_client_header_buffers 4 8k;
```
::

### Block HTTP Methods

::code-preview
---
class: "[&>div]:*:my-0"
---
Allow only needed HTTP methods.

#code
```nginx
server {
    # Allow only specific methods
    if ($request_method !~ ^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$) {
        return 405;
    }

    # Block TRACE method (prevents XST attacks)
    if ($request_method = TRACE) {
        return 405;
    }

    # For static sites, allow only GET and HEAD
    location / {
        limit_except GET HEAD {
            deny all;
        }
        try_files $uri $uri/ =404;
    }
}
```
::

---

## Reverse Proxy Setup

### Node.js Application

::code-preview
---
class: "[&>div]:*:my-0"
---
Reverse proxy to Node.js backend.

#code
```nginx
# /etc/nginx/sites-available/nodeapp.example.com

# Upstream backend servers
upstream nodejs_backend {
    server 127.0.0.1:3000;

    # For multiple instances (load balancing)
    # server 127.0.0.1:3001;
    # server 127.0.0.1:3002;

    # Load balancing methods
    # least_conn;          # Least connections
    # ip_hash;             # Session persistence
    # hash $request_uri;   # URI-based

    # Health check
    keepalive 32;
}

# HTTP → HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name app.example.com;
    return 301 https://$host$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name app.example.com;

    # SSL
    ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;
    include /etc/nginx/snippets/ssl-params.conf;

    # Logging
    access_log /var/log/nginx/nodeapp-access.log main;
    error_log /var/log/nginx/nodeapp-error.log warn;

    # Security headers
    include /etc/nginx/snippets/security.conf;

    # Proxy to Node.js
    location / {
        proxy_pass http://nodejs_backend;
        proxy_http_version 1.1;

        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;

        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    # WebSocket endpoint
    location /ws {
        proxy_pass http://nodejs_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }

    # API rate limiting
    location /api/ {
        limit_req zone=api burst=50 nodelay;
        proxy_pass http://nodejs_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Serve static files directly (bypass Node.js)
    location /static/ {
        alias /var/www/app.example.com/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
}
```
::

### Python / Django / Flask

::code-preview
---
class: "[&>div]:*:my-0"
---
Reverse proxy to Python application (Gunicorn).

#code
```nginx
# /etc/nginx/sites-available/pythonapp.example.com

upstream python_backend {
    server unix:/run/gunicorn/gunicorn.sock fail_timeout=0;
    # Or TCP socket:
    # server 127.0.0.1:8000;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name pythonapp.example.com;

    ssl_certificate /etc/letsencrypt/live/pythonapp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pythonapp.example.com/privkey.pem;
    include /etc/nginx/snippets/ssl-params.conf;
    include /etc/nginx/snippets/security.conf;

    # Static files (Django collectstatic)
    location /static/ {
        alias /var/www/pythonapp/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Media files (user uploads)
    location /media/ {
        alias /var/www/pythonapp/media/;
        expires 7d;

        # Block PHP execution in media
        location ~* \.php$ {
            deny all;
        }
    }

    # Proxy to Gunicorn
    location / {
        proxy_pass http://python_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;

        # Upload size
        client_max_body_size 20m;
    }
}
```
::

### PHP-FPM (WordPress, Laravel)

::code-preview
---
class: "[&>div]:*:my-0"
---
Nginx with PHP-FPM configuration.

#code
```bash
# Install PHP-FPM
sudo apt install php-fpm php-mysql php-curl php-gd php-mbstring php-xml php-zip -y

# Check PHP-FPM version and socket
php -v
ls /var/run/php/
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
PHP-FPM virtual host configuration.

#code
```nginx
# /etc/nginx/sites-available/phpapp.example.com

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name phpapp.example.com;

    ssl_certificate /etc/letsencrypt/live/phpapp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/phpapp.example.com/privkey.pem;
    include /etc/nginx/snippets/ssl-params.conf;
    include /etc/nginx/snippets/security.conf;

    root /var/www/phpapp.example.com/public;
    index index.php index.html index.htm;

    access_log /var/log/nginx/phpapp-access.log main;
    error_log /var/log/nginx/phpapp-error.log warn;

    # Main location
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    # PHP-FPM processing
    location ~ \.php$ {
        # Prevent PHP execution in uploads
        location ~* /uploads/.*\.php$ {
            deny all;
        }

        # Ensure file exists before passing to PHP
        try_files $uri =404;

        # FastCGI settings
        fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;

        # FastCGI buffering
        fastcgi_buffers 16 16k;
        fastcgi_buffer_size 32k;

        # FastCGI timeouts
        fastcgi_connect_timeout 60s;
        fastcgi_send_timeout 60s;
        fastcgi_read_timeout 60s;

        # Security
        fastcgi_param PHP_VALUE "
            open_basedir=/var/www/phpapp.example.com/:/tmp/
            upload_max_filesize=16M
            post_max_size=16M
            max_execution_time=30
            max_input_time=30
            memory_limit=128M
            display_errors=Off
            log_errors=On
            expose_php=Off
        ";
    }

    # Deny access to .htaccess files
    location ~ /\.ht {
        deny all;
    }

    # Static files caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
}
```
::

### WordPress-Specific Configuration

::code-preview
---
class: "[&>div]:*:my-0"
---
Hardened WordPress Nginx configuration.

#code
```nginx
# /etc/nginx/sites-available/wordpress.example.com

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name wordpress.example.com;

    ssl_certificate /etc/letsencrypt/live/wordpress.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wordpress.example.com/privkey.pem;
    include /etc/nginx/snippets/ssl-params.conf;

    root /var/www/wordpress.example.com;
    index index.php;

    # Rate limiting for login
    location = /wp-login.php {
        limit_req zone=login burst=3 nodelay;

        # Optional: IP restriction
        # allow 192.168.1.0/24;
        # deny all;

        fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Block xmlrpc
    location = /xmlrpc.php {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Protect wp-config.php
    location = /wp-config.php {
        deny all;
    }

    # Protect wp-includes
    location ~* wp-includes/.*\.php$ {
        deny all;
    }

    # Block PHP in uploads
    location ~* /wp-content/uploads/.*\.php$ {
        deny all;
    }

    # Block PHP in plugins/themes (optional, may break some)
    # location ~* /wp-content/(plugins|themes)/.*\.php$ {
    #     deny all;
    # }

    # Restrict wp-admin access
    location /wp-admin {
        # allow 192.168.1.0/24;
        # deny all;

        location ~* \.php$ {
            fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            include fastcgi_params;
        }
    }

    # WordPress permalinks
    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    # PHP processing
    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Static files
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Deny access to sensitive files
    location ~ /\.(ht|git|svn|env) {
        deny all;
    }

    location ~* (readme\.html|readme\.txt|license\.txt|wp-config-sample\.php) {
        deny all;
    }
}
```
::

---

## Load Balancing

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure load balancing across backends.

#code
```nginx
# /etc/nginx/conf.d/load-balancer.conf

# ============================================================
# Round Robin (default) - Equal distribution
# ============================================================
upstream app_round_robin {
    server 10.0.0.1:3000;
    server 10.0.0.2:3000;
    server 10.0.0.3:3000;
}

# ============================================================
# Least Connections - Send to server with fewest connections
# ============================================================
upstream app_least_conn {
    least_conn;
    server 10.0.0.1:3000;
    server 10.0.0.2:3000;
    server 10.0.0.3:3000;
}

# ============================================================
# IP Hash - Session persistence (same client → same server)
# ============================================================
upstream app_ip_hash {
    ip_hash;
    server 10.0.0.1:3000;
    server 10.0.0.2:3000;
    server 10.0.0.3:3000;
}

# ============================================================
# Weighted - Distribute by server capacity
# ============================================================
upstream app_weighted {
    server 10.0.0.1:3000 weight=5;    # Handles 5x traffic
    server 10.0.0.2:3000 weight=3;    # Handles 3x traffic
    server 10.0.0.3:3000 weight=1;    # Handles 1x traffic
}

# ============================================================
# With Health Checks and Failover
# ============================================================
upstream app_production {
    least_conn;

    # Primary servers
    server 10.0.0.1:3000 weight=3 max_fails=3 fail_timeout=30s;
    server 10.0.0.2:3000 weight=3 max_fails=3 fail_timeout=30s;
    server 10.0.0.3:3000 weight=3 max_fails=3 fail_timeout=30s;

    # Backup server (used when all primary servers are down)
    server 10.0.0.4:3000 backup;

    # Keep connections alive
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;
    include /etc/nginx/snippets/ssl-params.conf;

    location / {
        proxy_pass http://app_production;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Response timeout
        proxy_next_upstream error timeout http_502 http_503 http_504;
        proxy_next_upstream_timeout 30s;
        proxy_next_upstream_tries 3;
    }
}
```
::

### Load Balancing Methods Comparison

| Method         | Description                         | Best For                          |
| -------------- | ----------------------------------- | --------------------------------- |
| Round Robin    | Equal distribution in order         | Homogeneous servers               |
| Least Conn     | Fewest active connections           | Variable request processing time  |
| IP Hash        | Same client → same server           | Session persistence needed        |
| Weighted       | Distribution by server capacity     | Heterogeneous server hardware     |
| Random         | Random server selection             | Large server pools                |
| Hash           | Hash-based (URI, header, etc.)      | Cache optimization                |

---

## Performance Optimization

### Caching Configuration

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure proxy caching and browser caching.

#code
```nginx
# In http {} context — Proxy cache zone
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m max_size=1g inactive=60m use_temp_path=off;

server {
    # ========================================================
    # PROXY CACHING
    # ========================================================
    location / {
        proxy_pass http://backend;

        # Enable caching
        proxy_cache my_cache;
        proxy_cache_valid 200 302 60m;
        proxy_cache_valid 404 1m;
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
        proxy_cache_lock on;
        proxy_cache_min_uses 2;

        # Cache key
        proxy_cache_key "$scheme$request_method$host$request_uri";

        # Add cache status header
        add_header X-Cache-Status $upstream_cache_status;
    }

    # ========================================================
    # BYPASS CACHE
    # ========================================================
    # Don't cache authenticated requests
    proxy_cache_bypass $http_authorization;
    proxy_no_cache $http_authorization;

    # Don't cache POST requests
    proxy_cache_bypass $request_method;

    # ========================================================
    # BROWSER CACHING - Static Assets
    # ========================================================

    # Images - cache for 30 days
    location ~* \.(jpg|jpeg|png|gif|ico|svg|webp|avif)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        add_header Vary "Accept-Encoding";
        access_log off;
    }

    # CSS and JavaScript - cache for 7 days
    location ~* \.(css|js)$ {
        expires 7d;
        add_header Cache-Control "public";
        add_header Vary "Accept-Encoding";
        access_log off;
    }

    # Fonts - cache for 30 days
    location ~* \.(woff|woff2|ttf|eot|otf)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        add_header Access-Control-Allow-Origin "*";
        access_log off;
    }

    # Media - cache for 7 days
    location ~* \.(mp4|mp3|webm|ogg|avi)$ {
        expires 7d;
        add_header Cache-Control "public";
    }

    # HTML - short cache with revalidation
    location ~* \.html$ {
        expires 1h;
        add_header Cache-Control "public, must-revalidate";
    }

    # API responses - no caching
    location /api/ {
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        proxy_pass http://backend;
    }
}
```
::

### Brotli Compression (Better than Gzip)

::code-preview
---
class: "[&>div]:*:my-0"
---
Install and configure Brotli compression.

#code
```bash
# Install Brotli module
sudo apt install libnginx-mod-http-brotli-filter libnginx-mod-http-brotli-static -y

# Or compile from source if not available
# sudo apt install nginx-module-brotli -y
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Brotli configuration.

#code
```nginx
# Add to http {} context in nginx.conf

# Brotli compression (better than gzip)
brotli on;
brotli_comp_level 6;
brotli_static on;
brotli_types
    text/plain
    text/css
    text/javascript
    text/xml
    application/json
    application/javascript
    application/xml
    application/xml+rss
    application/atom+xml
    application/vnd.ms-fontobject
    application/x-font-ttf
    application/x-web-app-manifest+json
    application/xhtml+xml
    font/opentype
    image/svg+xml
    image/x-icon;
```
::

### HTTP/2 and HTTP/3

::code-preview
---
class: "[&>div]:*:my-0"
---
Enable HTTP/2 and HTTP/3 (QUIC).

#code
```nginx
server {
    # HTTP/2 (requires SSL)
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    # HTTP/3 / QUIC (Nginx 1.25+)
    # listen 443 quic reuseport;
    # listen [::]:443 quic reuseport;

    # Add Alt-Svc header for HTTP/3
    # add_header Alt-Svc 'h3=":443"; ma=86400';

    server_name example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # HTTP/2 push (preload critical assets)
    # http2_push /css/style.css;
    # http2_push /js/app.js;
    # http2_push /images/logo.webp;

    location / {
        try_files $uri $uri/ =404;
    }
}
```
::

---

## CORS Configuration

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure Cross-Origin Resource Sharing.

#code
```nginx
# /etc/nginx/snippets/cors.conf

# Simple CORS configuration
map $http_origin $cors_origin {
    default "";
    "~^https://frontend\.example\.com$"     $http_origin;
    "~^https://app\.example\.com$"          $http_origin;
    "~^https://admin\.example\.com$"        $http_origin;
    "~^http://localhost:3000$"              $http_origin;  # Development
}

# Apply in location blocks:
location /api/ {
    # CORS headers
    if ($cors_origin) {
        add_header Access-Control-Allow-Origin $cors_origin always;
        add_header Access-Control-Allow-Methods "GET, POST, PUT, PATCH, DELETE, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Authorization, Content-Type, Accept, Origin, X-Requested-With" always;
        add_header Access-Control-Allow-Credentials "true" always;
        add_header Access-Control-Max-Age 86400 always;
    }

    # Handle preflight OPTIONS request
    if ($request_method = OPTIONS) {
        add_header Access-Control-Allow-Origin $cors_origin always;
        add_header Access-Control-Allow-Methods "GET, POST, PUT, PATCH, DELETE, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Authorization, Content-Type, Accept, Origin, X-Requested-With" always;
        add_header Access-Control-Allow-Credentials "true" always;
        add_header Access-Control-Max-Age 86400 always;
        add_header Content-Length 0;
        add_header Content-Type text/plain;
        return 204;
    }

    proxy_pass http://backend;
}
```
::

---

## WebSocket Configuration

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure WebSocket proxy.

#code
```nginx
# WebSocket upgrade map
map $http_upgrade $connection_upgrade {
    default upgrade;
    ""      close;
}

server {
    listen 443 ssl http2;
    server_name ws.example.com;

    ssl_certificate /etc/letsencrypt/live/ws.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ws.example.com/privkey.pem;
    include /etc/nginx/snippets/ssl-params.conf;

    # WebSocket endpoint
    location /ws {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket timeouts (keep connection alive)
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;

        # Disable buffering for real-time
        proxy_buffering off;
    }

    # Socket.IO endpoint
    location /socket.io/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_read_timeout 86400s;
        proxy_buffering off;
    }

    # Regular HTTP
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```
::

---

## Monitoring and Logging

### Nginx Status Module

::code-preview
---
class: "[&>div]:*:my-0"
---
Enable Nginx status monitoring.

#code
```nginx
# /etc/nginx/conf.d/status.conf

server {
    listen 127.0.0.1:8080;
    server_name localhost;

    # Basic status page
    location /nginx_status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        allow 10.0.0.0/8;
        deny all;
    }

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }
}
```
::

### Log Rotation

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure log rotation for Nginx.

#code
```bash
sudo nano /etc/logrotate.d/nginx
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Logrotate configuration.

#code
```
# /etc/logrotate.d/nginx

/var/log/nginx/*.log
/var/www/*/logs/*.log
{
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    prerotate
        if [ -d /etc/logrotate.d/httpd-prerotate ]; then \
            run-parts /etc/logrotate.d/httpd-prerotate; \
        fi \
    endscript
    postrotate
        invoke-rc.d nginx rotate >/dev/null 2>&1
    endscript
}
```
::

### Custom Error Pages

::code-preview
---
class: "[&>div]:*:my-0"
---
Create and configure custom error pages.

#code
```bash
# Create error pages directory
sudo mkdir -p /var/www/errors
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Custom 404 error page.

#code
```html
<!-- /var/www/errors/404.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found</title>
    <style>
        body { font-family: -apple-system, sans-serif; text-align: center; padding: 50px; background: #f8f9fa; }
        h1 { font-size: 4em; color: #333; margin-bottom: 0; }
        p { font-size: 1.2em; color: #666; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>404</h1>
    <p>The page you're looking for doesn't exist.</p>
    <p><a href="/">← Back to Homepage</a></p>
</body>
</html>
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure custom error pages in Nginx.

#code
```nginx
server {
    # Custom error pages
    error_page 400 /errors/400.html;
    error_page 401 /errors/401.html;
    error_page 403 /errors/403.html;
    error_page 404 /errors/404.html;
    error_page 405 /errors/405.html;
    error_page 429 /errors/429.html;
    error_page 500 /errors/500.html;
    error_page 502 /errors/502.html;
    error_page 503 /errors/503.html;
    error_page 504 /errors/504.html;

    location /errors/ {
        alias /var/www/errors/;
        internal;
    }
}
```
::

---

## Development Server Configuration

::code-preview
---
class: "[&>div]:*:my-0"
---
Nginx configuration optimized for local development.

#code
```nginx
# /etc/nginx/sites-available/dev.local

server {
    listen 80;
    listen [::]:80;
    server_name dev.local *.dev.local;

    root /home/developer/projects;
    index index.html index.php;

    # Disable caching for development
    add_header Cache-Control "no-store, no-cache, must-revalidate";
    expires off;
    etag off;

    # Enable directory listing for development
    autoindex on;
    autoindex_exact_size off;
    autoindex_localtime on;

    # Relaxed security for development
    add_header Access-Control-Allow-Origin "*";
    add_header Access-Control-Allow-Methods "GET, POST, PUT, PATCH, DELETE, OPTIONS";
    add_header Access-Control-Allow-Headers "*";

    # PHP processing (development)
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;

        # Show errors in development
        fastcgi_param PHP_VALUE "
            display_errors=On
            error_reporting=E_ALL
            log_errors=On
        ";
    }

    # Proxy for frontend dev servers
    location /api/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Hot reload WebSocket (Vite, Webpack, etc.)
    location /ws {
        proxy_pass http://127.0.0.1:5173;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Add dev.local to hosts file.

#code
```bash
# Add local development domain
echo "127.0.0.1 dev.local" | sudo tee -a /etc/hosts
echo "127.0.0.1 api.dev.local" | sudo tee -a /etc/hosts
echo "127.0.0.1 admin.dev.local" | sudo tee -a /etc/hosts
```
::

---

## UFW Firewall Configuration for Nginx

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure UFW firewall for Nginx.

#code
```bash
# Check available Nginx profiles
sudo ufw app list

# Allow Nginx through firewall
sudo ufw allow 'Nginx Full'           # HTTP + HTTPS
# OR individually:
sudo ufw allow 'Nginx HTTP'           # HTTP only
sudo ufw allow 'Nginx HTTPS'          # HTTPS only

# Allow SSH (don't lock yourself out!)
sudo ufw allow ssh

# Enable UFW
sudo ufw enable

# Check status
sudo ufw status verbose

# View Nginx profile details
sudo ufw app info 'Nginx Full'

# Additional rules
sudo ufw allow from 192.168.1.0/24 to any port 8080     # Internal monitoring
sudo ufw allow from 10.0.0.0/8 to any port 8080         # VPN access
sudo ufw deny from 203.0.113.0/24                        # Block IP range

# Rate limiting on SSH
sudo ufw limit ssh

# Verify rules
sudo ufw status numbered

# Remove a rule
sudo ufw delete allow 8080
```
::

---

## Nginx Management Commands

::code-preview
---
class: "[&>div]:*:my-0"
---
Essential Nginx commands.

#code
```bash
# ============ SERVICE CONTROL ============
sudo systemctl start nginx            # Start
sudo systemctl stop nginx             # Stop
sudo systemctl restart nginx          # Restart (drops connections)
sudo systemctl reload nginx           # Reload config (graceful)
sudo systemctl status nginx           # Check status

# ============ CONFIGURATION ============
sudo nginx -t                          # Test configuration syntax
sudo nginx -T                         # Test and dump full config
sudo nginx -V                         # Show compile-time options
nginx -v                              # Show version

# ============ GRACEFUL OPERATIONS ============
sudo nginx -s reload                   # Graceful reload
sudo nginx -s quit                    # Graceful shutdown
sudo nginx -s stop                    # Fast shutdown
sudo nginx -s reopen                  # Reopen log files

# ============ SITE MANAGEMENT ============
# Enable site
sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/

# Disable site
sudo rm /etc/nginx/sites-enabled/example.com

# List enabled sites
ls -la /etc/nginx/sites-enabled/

# List available sites
ls -la /etc/nginx/sites-available/

# ============ LOG MANAGEMENT ============
sudo tail -f /var/log/nginx/access.log      # Watch access log
sudo tail -f /var/log/nginx/error.log       # Watch error log
sudo tail -100 /var/log/nginx/access.log    # Last 100 entries

# Count requests by IP
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20

# Count requests by status code
awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c | sort -rn

# Count requests per URL
awk '{print $7}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20

# Find 404 errors
grep " 404 " /var/log/nginx/access.log | awk '{print $7}' | sort | uniq -c | sort -rn

# Find large requests
awk '$10 > 1000000' /var/log/nginx/access.log

# ============ PROCESS MANAGEMENT ============
ps aux | grep nginx                    # View Nginx processes
sudo kill -HUP $(cat /run/nginx.pid)  # Reload via signal

# ============ PERMISSIONS ============
sudo chown -R www-data:www-data /var/www/
sudo find /var/www -type d -exec chmod 755 {} \;
sudo find /var/www -type f -exec chmod 644 {} \;
```
::

---

## Security Audit Checklist

| Check                              | Command / Action                                        | Status |
| ---------------------------------- | ------------------------------------------------------- | ------ |
| Nginx version hidden               | `server_tokens off;`                                    | ☐      |
| HTTPS enforced                     | HTTP → HTTPS redirect on all sites                      | ☐      |
| TLS 1.2+ only                     | `ssl_protocols TLSv1.2 TLSv1.3;`                       | ☐      |
| Strong ciphers                     | Modern cipher suite configured                          | ☐      |
| HSTS enabled                       | `Strict-Transport-Security` header                      | ☐      |
| X-Content-Type-Options             | `nosniff`                                               | ☐      |
| X-Frame-Options                    | `SAMEORIGIN` or `DENY`                                  | ☐      |
| Content-Security-Policy            | Configured per application                              | ☐      |
| Referrer-Policy                    | `strict-origin-when-cross-origin`                       | ☐      |
| Permissions-Policy                 | Configured                                              | ☐      |
| OCSP stapling                      | `ssl_stapling on;`                                      | ☐      |
| DH parameters                      | 2048+ bit `dhparam.pem`                                 | ☐      |
| SSL certificates valid             | `certbot certificates`                                  | ☐      |
| Auto-renewal configured            | `certbot renew --dry-run`                               | ☐      |
| Hidden files blocked               | `location ~ /\. { deny all; }`                          | ☐      |
| Rate limiting enabled              | `limit_req_zone` configured                             | ☐      |
| Request size limited               | `client_max_body_size` set                              | ☐      |
| Bad bots blocked                   | User-agent filtering                                    | ☐      |
| Admin areas restricted             | IP whitelist or auth on `/admin`                        | ☐      |
| Upload directory protected         | PHP execution blocked in uploads                        | ☐      |
| Sensitive files blocked            | `.env`, `.git`, etc. denied                             | ☐      |
| HTTP methods restricted            | Only needed methods allowed                             | ☐      |
| Firewall configured                | UFW/iptables rules set                                  | ☐      |
| Fail2ban configured                | Nginx jails enabled                                     | ☐      |
| Logs rotated                       | Logrotate configured                                    | ☐      |
| File permissions correct           | Directories 755, files 644                              | ☐      |
| Running as www-data                | `user www-data;` in nginx.conf                          | ☐      |
| Unnecessary modules disabled       | Remove unused modules                                   | ☐      |
| Error pages customized             | No stack traces exposed                                 | ☐      |
| Directory listing disabled         | `autoindex off;` (default)                              | ☐      |
| SSL Labs grade A+                  | Test at ssllabs.com                                     | ☐      |

---

## Troubleshooting

::code-preview
---
class: "[&>div]:*:my-0"
---
Common Nginx troubleshooting commands.

#code
```bash
# ============ CONFIG ISSUES ============
# Test configuration for errors
sudo nginx -t

# Show full configuration with includes
sudo nginx -T

# Check for syntax errors
sudo nginx -t 2>&1

# ============ SERVICE ISSUES ============
# Check if Nginx is running
sudo systemctl status nginx
ps aux | grep nginx

# Check what's listening on port 80/443
sudo ss -tulnp | grep -E ':80|:443'
sudo lsof -i :80
sudo lsof -i :443

# Check if another service is blocking the port
sudo fuser 80/tcp
sudo fuser 443/tcp

# ============ PERMISSION ISSUES ============
# Check file ownership
ls -la /var/www/
ls -la /etc/nginx/

# Fix permissions
sudo chown -R www-data:www-data /var/www/
sudo find /var/www -type d -exec chmod 755 {} \;
sudo find /var/www -type f -exec chmod 644 {} \;

# Check SELinux (if enabled)
getenforce
# If enforcing, allow Nginx
# setsebool -P httpd_can_network_connect 1

# ============ SSL ISSUES ============
# Check certificate
sudo openssl x509 -in /etc/letsencrypt/live/example.com/fullchain.pem -text -noout

# Check certificate chain
openssl s_client -connect example.com:443 -servername example.com

# Verify certificate matches key
openssl x509 -noout -modulus -in cert.pem | openssl md5
openssl rsa -noout -modulus -in key.pem | openssl md5
# Both should match

# ============ LOG ANALYSIS ============
# Check error log
sudo tail -50 /var/log/nginx/error.log

# Real-time error monitoring
sudo tail -f /var/log/nginx/error.log

# Find 502 errors
grep "502" /var/log/nginx/error.log | tail -20

# Find upstream connection errors
grep "upstream" /var/log/nginx/error.log | tail -20

# ============ PERFORMANCE ============
# Check number of worker connections
grep worker /etc/nginx/nginx.conf

# Check open files limit
ulimit -n
cat /proc/$(cat /run/nginx.pid)/limits | grep "Max open files"

# Check memory usage
ps aux --sort=-rss | grep nginx

# Check active connections
curl http://127.0.0.1:8080/nginx_status 2>/dev/null
```
::

---

## References

- [Nginx Official Documentation](https://nginx.org/en/docs/)
- [Nginx Admin Guide](https://docs.nginx.com/nginx/admin-guide/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [Security Headers](https://securityheaders.com/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Certbot Documentation](https://certbot.eff.org/docs/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Nginx Security Advisories](https://nginx.org/en/security_advisories.html)
- [DigitalOcean Nginx Tutorials](https://www.digitalocean.com/community/tags/nginx)
- [Nginx Performance Tuning](https://www.nginx.com/blog/tuning-nginx/)

::tip
**Security is a continuous process.** Regularly update Nginx, renew SSL certificates, review logs, and test your configuration against tools like **SSL Labs**, **Mozilla Observatory**, and **SecurityHeaders.com**. Always test configuration changes with `nginx -t` before applying them in production.
::
